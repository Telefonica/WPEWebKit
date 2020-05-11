#include "config.h"
#include "CDMWidevine.h"

#if ENABLE(ENCRYPTED_MEDIA)

#include "GStreamerEMEUtilities.h"
#include "CDMKeySystemConfiguration.h"
#include "CDMRestrictions.h"
#include "CDMSessionType.h"
#include "SharedBuffer.h"
#include <wtf/JSONValues.h>
#include <wtf/MainThread.h>
#include <wtf/text/Base64.h>

namespace WebCore {

class WidevineState {
    using KeyStore = HashMap<String, Vector<CDMInstanceWidevine::Key>>;

public:
    static WidevineState& singleton();

    KeyStore& keys() { return m_keys; }
    HashSet<String>& persistentSessions() { return m_persistentSessions; }

private:
    WidevineState();
    KeyStore m_keys;
    HashSet<String> m_persistentSessions;
};

WidevineState& WidevineState::singleton()
{
    static WidevineState s_state;
    return s_state;
}

WidevineState::WidevineState() = default;

RefPtr<JSON::Object> parseJSONObject(const SharedBuffer& buffer)
{
    // Fail on large buffers whose size doesn't fit into a 32-bit unsigned integer.
    size_t size = buffer.size();
    if (size > std::numeric_limits<unsigned>::max())
        return nullptr;

    // Parse the buffer contents as JSON, returning the root object (if any).
    String json { buffer.data(), static_cast<unsigned>(size) };
    RefPtr<JSON::Value> value;
    RefPtr<JSON::Object> object;
    if (!JSON::Value::parseJSON(json, value) || !value->asObject(object))
        return nullptr;

    return object;
}

std::optional<Vector<CDMInstanceWidevine::Key>> parseLicenseFormat(const JSON::Object& root)
{
    // If the 'keys' key is present in the root object, parse the JSON further
    // according to the specified 'license' format.
    auto it = root.find("keys");
    if (it == root.end())
        return std::nullopt;

    // Retrieve the keys array.
    RefPtr<JSON::Array> keysArray;
    if (!it->value->asArray(keysArray))
        return std::nullopt;

    Vector<CDMInstanceWidevine::Key> decodedKeys;
    bool validFormat = std::all_of(keysArray->begin(), keysArray->end(),
        [&decodedKeys] (const auto& value) {
            RefPtr<JSON::Object> keyObject;
            if (!value->asObject(keyObject))
                return false;

            String keyType;
            if (!keyObject->getString("kty", keyType) || !equalLettersIgnoringASCIICase(keyType, "oct"))
                return false;

            String keyID, keyValue;
            if (!keyObject->getString("kid", keyID) || !keyObject->getString("k", keyValue))
                return false;

            Vector<char> keyIDData, keyValueData;
            if (!WTF::base64URLDecode(keyID, { keyIDData }) || !WTF::base64URLDecode(keyValue, { keyValueData }))
                return false;

            decodedKeys.append({ CDMInstanceWidevine::KeyStatus::Usable, SharedBuffer::create(WTFMove(keyIDData)), SharedBuffer::create(WTFMove(keyValueData)) });
            return true;
        });
    if (!validFormat)
        return std::nullopt;

    return decodedKeys;
}

bool parseLicenseReleaseAcknowledgementFormat(const JSON::Object& root)
{
    // If the 'kids' key is present in the root object, parse the JSON further
    // according to the specified 'license release acknowledgement' format.
    auto it = root.find("kids");
    if (it == root.end())
        return false;

    // Retrieve the kids array.
    RefPtr<JSON::Array> kidsArray;
    if (!it->value->asArray(kidsArray))
        return false;

    // FIXME: Return the key IDs and validate them.
    return true;
}

CDMFactoryWidevine& CDMFactoryWidevine::singleton()
{
    static CDMFactoryWidevine s_factory;
    return s_factory;
}

CDMFactoryWidevine::CDMFactoryWidevine() = default;
CDMFactoryWidevine::~CDMFactoryWidevine() = default;

std::unique_ptr<CDMPrivate> CDMFactoryWidevine::createCDM(const String& keySystem)
{
#ifdef NDEBUG
    UNUSED_PARAM(keySystem);
#else
    ASSERT(supportsKeySystem(keySystem));
#endif
    return std::unique_ptr<CDMPrivate>(new CDMPrivateWidevine);
}

bool CDMFactoryWidevine::supportsKeySystem(const String& keySystem)
{
    // `Widevine` is the only supported key system.
    return equalLettersIgnoringASCIICase(keySystem, "widevine");
}

CDMPrivateWidevine::CDMPrivateWidevine() = default;
CDMPrivateWidevine::~CDMPrivateWidevine() = default;

bool CDMPrivateWidevine::supportsInitDataType(const AtomicString& initDataType) const
{
    // `keyids` is the only supported init data type.
    return equalLettersIgnoringASCIICase(initDataType, "keyids");
}

bool containsPersistentLicenseType(const Vector<CDMSessionType>& types)
{
    return std::any_of(types.begin(), types.end(),
        [] (auto& sessionType) { return sessionType == CDMSessionType::PersistentLicense; });
}

bool CDMPrivateWidevine::supportsConfiguration(const CDMKeySystemConfiguration& configuration) const
{
    // Reject any configuration that marks distinctive identifier as required.
    if (configuration.distinctiveIdentifier == CDMRequirement::Required)
        return false;

    // Reject any configuration that marks persistent state as required, unless
    // the 'persistent-license' session type has to be supported.
    if (configuration.persistentState == CDMRequirement::Required && !containsPersistentLicenseType(configuration.sessionTypes))
        return false;

    return true;
}

bool CDMPrivateWidevine::supportsConfigurationWithRestrictions(const CDMKeySystemConfiguration& configuration, const CDMRestrictions& restrictions) const
{
    // Reject any configuration that marks distincitive identifier as required, or that marks
    // distinctive identifier as optional even when restrictions mark it as denied.
    if ((configuration.distinctiveIdentifier == CDMRequirement::Optional && restrictions.distinctiveIdentifierDenied)
        || configuration.distinctiveIdentifier == CDMRequirement::Required)
        return false;

    // Reject any configuration that marks persistent state as optional even when
    // restrictions mark it as denied.
    if (configuration.persistentState == CDMRequirement::Optional && restrictions.persistentStateDenied)
        return false;

    // Reject any configuration that marks persistent state as required, unless
    // the 'persistent-license' session type has to be supported.
    if (configuration.persistentState == CDMRequirement::Required && !containsPersistentLicenseTypePR(configuration.sessionTypes))
        return false;

    return true;
}

bool CDMPrivateWidevine::supportsSessionTypeWithConfiguration(CDMSessionType& sessionType, const CDMKeySystemConfiguration& configuration) const
{
    // Only support the 'temporary' and 'persistent-license' session types.
    if (sessionType != CDMSessionType::Temporary && sessionType != CDMSessionType::PersistentLicense)
        return false;
    return supportsConfiguration(configuration);
}

bool CDMPrivateWidevine::supportsRobustness(const String& robustness) const
{
    // Only empty `robustness` string is supported.
    return robustness.isEmpty();
}

CDMRequirement CDMPrivateWidevine::distinctiveIdentifiersRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions& restrictions) const
{
    // Distinctive identifier is not allowed if it's been denied, otherwise it's optional.
    if (restrictions.distinctiveIdentifierDenied)
        return CDMRequirement::NotAllowed;
    return CDMRequirement::Optional;
}

CDMRequirement CDMPrivateWidevine::persistentStateRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions& restrictions) const
{
    // Persistent state is not allowed if it's been denied, otherwise it's optional.
    if (restrictions.persistentStateDenied)
        return CDMRequirement::NotAllowed;
    return CDMRequirement::Optional;
}

bool CDMPrivateWidevine::distinctiveIdentifiersAreUniquePerOriginAndClearable(const CDMKeySystemConfiguration&) const
{
    return false;
}

RefPtr<CDMInstance> CDMPrivateWidevine::createInstance()
{
    return adoptRef(new CDMInstanceWidevine);
}

void CDMPrivateWidevine::loadAndInitialize()
{
    // No-op.
}

bool CDMPrivateWidevine::supportsServerCertificates() const
{
    // Server certificates are not supported.
    return false;
}

bool CDMPrivateWidevine::supportsSessions() const
{
    // Sessions are supported.
    return true;
}

bool CDMPrivateWidevine::supportsInitData(const AtomicString& initDataType, const SharedBuffer& initData) const
{
    // Fail for init data types other than 'keyids'.
    if (!equalLettersIgnoringASCIICase(initDataType, "keyids"))
        return false;

    // Validate the initData buffer as an JSON object.
    if (!parseJSONObjectPR(initData))
        return false;

    return true;
}

RefPtr<SharedBuffer> CDMPrivateWidevine::sanitizeResponse(const SharedBuffer& response) const
{
    // Validate the response buffer as an JSON object.
    if (!parseJSONObjectPR(response))
        return nullptr;

    return response.copy();
}

std::optional<String> CDMPrivateWidevine::sanitizeSessionId(const String& sessionId) const
{
    // Validate the session ID string as an 32-bit integer.
    bool ok;
    sessionId.toUIntStrict(&ok);
    if (!ok)
        return std::nullopt;

    return sessionId;
}

CDMInstanceWidevine::CDMInstanceWidevine()
{
    GST_ERROR_OBJECT(nullptr, "Create CDMInstanceWidevine");
}

CDMInstanceWidevine::~CDMInstanceWidevine() = default;

CDMInstance::SuccessValue CDMInstanceWidevine::initializeWithConfiguration(const CDMKeySystemConfiguration&)
{
    // No-op.
    return Succeeded;
}

CDMInstance::SuccessValue CDMInstanceWidevine::setDistinctiveIdentifiersAllowed(bool allowed)
{
    // Reject setting distinctive identifiers as allowed.
    return !allowed ? Succeeded : Failed;
}

CDMInstance::SuccessValue CDMInstanceWidevine::setPersistentStateAllowed(bool allowed)
{
    // Reject setting persistent state as allowed.
    return !allowed ? Succeeded : Failed;
}

CDMInstance::SuccessValue CDMInstanceWidevine::setServerCertificate(Ref<SharedBuffer>&&)
{
    // Reject setting any server certificate.
    return Failed;
}

void CDMInstanceWidevine::requestLicense(LicenseType, const AtomicString&, Ref<SharedBuffer>&& initData, Ref<SharedBuffer>&& customData, LicenseCallback callback)
{
    //TODO: Improve the request license system, with default values for test content and working for all kind of content
    GST_ERROR_OBJECT(nullptr, "request licenses for Widevine");
    static uint32_t s_sessionIdValue = 0;
    ++s_sessionIdValue;

    callOnMainThread(
        [weakThis = m_weakPtrFactory.createWeakPtr(*this), callback = WTFMove(callback), initData = WTFMove(initData), sessionIdValue = s_sessionIdValue]() mutable {
            if (!weakThis)
                return;

            callback(WTFMove(initData), String::number(sessionIdValue), false, Succeeded);
        });
}

void CDMInstanceWidevine::updateLicense(const String& sessionId, LicenseType, const SharedBuffer& response, LicenseUpdateCallback callback)
{
    //TODO: Improve the update license system, with default values for test content and working for all kind of content
    // Use a helper functor that schedules the callback dispatch, avoiding
    // duplicated callOnMainThread() calls.
    GST_ERROR_OBJECT(nullptr, "update licenses for Widevine");
    auto dispatchCallback =
        [this, &callback](bool sessionWasClosed, std::optional<KeyStatusVector>&& changedKeys, SuccessValue succeeded) {
            callOnMainThread(
                [weakThis = m_weakPtrFactory.createWeakPtr(*this), callback = WTFMove(callback), sessionWasClosed, changedKeys = WTFMove(changedKeys), succeeded] () mutable {
                    if (!weakThis)
                        return;

                    callback(sessionWasClosed, WTFMove(changedKeys), std::nullopt, std::nullopt, succeeded);
                });
        };

    // Parse the response buffer as an JSON object.
    RefPtr<JSON::Object> root = parseJSONObject(response);
    if (!root) {
        dispatchCallback(false, std::nullopt, SuccessValue::Failed);
        return;
    }

    // Parse the response using 'license' formatting, if possible.
    if (auto decodedKeys = parseLicenseFormat(*root)) {
        // Retrieve the target Vector of Key objects for this session.
        auto& keyVector = WidevineState::singleton().keys().ensure(sessionId, [] { return Vector<Key> { }; }).iterator->value;

        // For each decoded key, find an existing item for the decoded key's ID. If none exist,
        // the key is decoded. Otherwise, the key is updated in case there's a mismatch between
        // the size or data of the existing and proposed key.
        bool keysChanged = false;
        for (auto& key : *decodedKeys) {
            auto it = std::find_if(keyVector.begin(), keyVector.end(),
                [&key] (const Key& containedKey) {
                    return containedKey.keyIDData->size() == key.keyIDData->size()
                        && !std::memcmp(containedKey.keyIDData->data(), key.keyIDData->data(), containedKey.keyIDData->size());
                });
            if (it != keyVector.end()) {
                auto& existingKey = it->keyValueData;
                auto& proposedKey = key.keyValueData;

                // Update the existing Key if it differs from the proposed key in key value.
                if (existingKey->size() != proposedKey->size() || std::memcmp(existingKey->data(), proposedKey->data(), existingKey->size())) {
                    *it = WTFMove(key);
                    keysChanged = true;
                }
            } else {
                // In case a Key for this key ID doesn't exist yet, append the new one to keyVector.
                keyVector.append(WTFMove(key));
                keysChanged = true;
            }
        }

        // In case of changed keys, we have to provide a KeyStatusVector of all the keys for
        // this session.
        std::optional<KeyStatusVector> changedKeys;
        if (keysChanged) {
            // First a helper Vector is constructed, cotaining pairs of SharedBuffer RefPtrs
            // representint key ID data, and the corresponding key statuses.
            // We can't use KeyStatusVector here because this Vector has to be sorted, which
            // is not possible to do on Ref<> objects.
            Vector<std::pair<RefPtr<SharedBuffer>, KeyStatus>> keys;
            keys.reserveInitialCapacity(keyVector.size());
            for (auto& it : keyVector)
                keys.uncheckedAppend(std::pair<RefPtr<SharedBuffer>, KeyStatus> { it.keyIDData, it.status });

            // Sort first by size, second by data.
            std::sort(keys.begin(), keys.end(),
                [] (const auto& a, const auto& b) {
                    if (a.first->size() != b.first->size())
                        return a.first->size() < b.first->size();

                    return std::memcmp(a.first->data(), b.first->data(), a.first->size()) < 0;
                });

            // Finally construct the mirroring KeyStatusVector object and move it into the
            // std::optional<> object that will be passed to the callback.
            KeyStatusVector keyStatusVector;
            keyStatusVector.reserveInitialCapacity(keys.size());
            for (auto& it : keys)
                keyStatusVector.uncheckedAppend(std::pair<Ref<SharedBuffer>, KeyStatus> { *it.first, it.second });

            changedKeys = WTFMove(keyStatusVector);
        }

        // Cache the key information Vector on CDMInstance for easier access from the pipeline.
        m_keys = keyVector;

        dispatchCallback(false, WTFMove(changedKeys), SuccessValue::Succeeded);
        return;
    }

    // Parse the response using 'license release acknowledgement' formatting, if possible.
    if (parseLicenseReleaseAcknowledgement(*root)) {
        // FIXME: Retrieve the key ID information and use it to validate the keys for this sessionId.
        WidevineState::singleton().keys().remove(sessionId);
        m_keys.clear();
        dispatchCallback(true, std::nullopt, SuccessValue::Succeeded);
        return;
    }

    // Bail in case no format was recognized.
    dispatchCallback(false, std::nullopt, SuccessValue::Failed);
}

void CDMInstanceWidevine::loadSession(LicenseType, const String& sessionId, const String&, LoadSessionCallback callback)
{
    // Use a helper functor that schedules the callback dispatch, avoiding duplicated callOnMainThread() calls.
    auto dispatchCallback =
        [this, &callback](std::optional<KeyStatusVector>&& existingKeys, SuccessValue success, SessionLoadFailure loadFailure) {
            callOnMainThread(
                [weakThis = m_weakPtrFactory.createWeakPtr(*this), callback = WTFMove(callback), existingKeys = WTFMove(existingKeys), success, loadFailure]() mutable {
                    if (!weakThis)
                        return;

                    callback(WTFMove(existingKeys), std::nullopt, std::nullopt, success, loadFailure);
                });
        };

    // Construct the KeyStatusVector object, representing all the known keys for this session.
    KeyStatusVector keyStatusVector;
    {
        auto& keys = WidevineState::singleton().keys();
        auto it = keys.find(sessionId);
        if (it == keys.end()) {
            dispatchCallback(std::nullopt, Failed, SessionLoadFailure::NoSessionData);
            return;
        }

        auto& keyVector = it->value;
        keyStatusVector.reserveInitialCapacity(keyVector.size());
        for (auto& key : keyVector)
            keyStatusVector.uncheckedAppend(std::pair<Ref<SharedBuffer>, KeyStatus> { *key.keyIDData, key.status });
    }

    dispatchCallback(WTFMove(keyStatusVector), Succeeded, SessionLoadFailure::None);
}

void CDMInstanceWidevine::closeSession(const String&, CloseSessionCallback callback)
{
    callOnMainThread(
        [weakThis = m_weakPtrFactory.createWeakPtr(*this), callback = WTFMove(callback)] {
            if (!weakThis)
                return;

            callback();
        });
}

void CDMInstanceWidevine::removeSessionData(const String& sessionId, LicenseType, RemoveSessionDataCallback callback)
{
    // Use a helper functor that schedules the callback dispatch, avoiding duplicated callOnMainThread() calls.
    auto dispatchCallback =
        [this, &callback](KeyStatusVector&& keyStatusVector, std::optional<Ref<SharedBuffer>>&& message, SuccessValue success) {
            callOnMainThread(
                [weakThis = m_weakPtrFactory.createWeakPtr(*this), callback = WTFMove(callback), keyStatusVector = WTFMove(keyStatusVector), message = WTFMove(message), success]() mutable {
                    if (!weakThis)
                        return;

                    callback(WTFMove(keyStatusVector), WTFMove(message), success);
                });
        };

    // Construct the KeyStatusVector object, representing released keys, and the message in the
    // 'license release' format.
    KeyStatusVector keyStatusVector;
    RefPtr<SharedBuffer> message;
    {
        // Retrieve information for the given session ID, bailing if none is found.
        auto& keys = WidevineState::singleton().keys();
        auto it = keys.find(sessionId);
        if (it == keys.end()) {
            dispatchCallback(KeyStatusVector { }, std::nullopt, SuccessValue::Failed);
            return;
        }

        // Retrieve the Key vector, containing all the keys for this session, and
        // then remove the key map entry for this session.
        auto keyVector = WTFMove(it->value);
        keys.remove(it);

        // Construct the KeyStatusVector object, pairing key IDs with the 'released' status.
        keyStatusVector.reserveInitialCapacity(keyVector.size());
        for (auto& key : keyVector)
            keyStatusVector.uncheckedAppend(std::pair<Ref<SharedBuffer>, KeyStatus> { *key.keyIDData, KeyStatus::Released });

        // Construct JSON that represents the 'license release' format, creating a 'kids' array
        // of base64URL-encoded key IDs for all keys that were associated with this session.
        auto rootObject = JSON::Object::create();
        {
            auto array = JSON::Array::create();
            for (auto& key : keyVector) {
                ASSERT(key.keyIDData->size() <= std::numeric_limits<unsigned>::max());
                array->pushString(WTF::base64URLEncode(key.keyIDData->data(), static_cast<unsigned>(key.keyIDData->size())));
            }
            rootObject->setArray("kids", WTFMove(array));
        }

        // Copy the JSON data into a SharedBuffer object.
        String messageString = rootObject->toJSONString();
        CString messageCString = messageString.utf8();
        message = SharedBuffer::create(messageCString.data(), messageCString.length());
    }

    dispatchCallback(WTFMove(keyStatusVector), Ref<SharedBuffer>(*message), SuccessValue::Succeeded);
}

void CDMInstanceWidevine::storeRecordOfKeyUsage(const String&)
{
}

const String& CDMInstanceWidevine::keySystem() const
{
    static const String s_keySystem("Widevine");

    return s_keySystem;
}

} // namespace WebCore

#endif // ENABLE(ENCRYPTED_MEDIA)
