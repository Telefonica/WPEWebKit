/* GStreamer OpenCDM decryptor
 *
 * Copyright (C) 2016-2017 TATA ELXSI
 * Copyright (C) 2016-2017 Metrological
 * Copyright (C) 2016-2017 Igalia S.L
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Suite 500,
 * Boston, MA 02110-1335, USA.
 */

#include "config.h"
#include "CDMOpenCDM.h"

#if ENABLE(ENCRYPTED_MEDIA) && USE(OPENCDM)

#include "CDMPrivate.h"
#include "GenericTaskQueue.h"
#include "MediaKeyMessageType.h"
#include "MediaKeysRequirement.h"
#include "MediaPlayerPrivateGStreamerBase.h"

#include <gst/gst.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/text/Base64.h>

GST_DEBUG_CATEGORY_EXTERN(webkit_media_opencdm_decrypt_debug_category);
#define GST_CAT_DEFAULT webkit_media_opencdm_decrypt_debug_category

namespace WebCore {

class CDMPrivateOpenCDM : public CDMPrivate {
private:
    CDMPrivateOpenCDM() = delete;
    CDMPrivateOpenCDM(const CDMPrivateOpenCDM&) = delete;
    CDMPrivateOpenCDM& operator=(const CDMPrivateOpenCDM&) = delete;

public:
    CDMPrivateOpenCDM(const String& keySystem)
        : m_openCDMKeySystem(keySystem)
        , m_openCDMAccessor(opencdm_create_system(), opencdm_destruct_system) { }
    virtual ~CDMPrivateOpenCDM() = default;

public:
    bool supportsInitDataType(const AtomicString& initDataType) const final { return equalLettersIgnoringASCIICase(initDataType, "cenc"); }
    bool supportsConfiguration(const MediaKeySystemConfiguration& config) const final;
    bool supportsConfigurationWithRestrictions(const MediaKeySystemConfiguration& config, const MediaKeysRestrictions&) const final { return supportsConfiguration(config); }
    bool supportsSessionTypeWithConfiguration(MediaKeySessionType&, const MediaKeySystemConfiguration& config) const final { return supportsConfiguration(config); }
    bool supportsRobustness(const String& robustness) const final { return !robustness.isEmpty(); }
    MediaKeysRequirement distinctiveIdentifiersRequirement(const MediaKeySystemConfiguration&, const MediaKeysRestrictions&) const final { return MediaKeysRequirement::Optional; }
    MediaKeysRequirement persistentStateRequirement(const MediaKeySystemConfiguration&, const MediaKeysRestrictions&) const final { return MediaKeysRequirement::Optional; }
    bool distinctiveIdentifiersAreUniquePerOriginAndClearable(const MediaKeySystemConfiguration&) const final { return false; }
    RefPtr<CDMInstance> createInstance() final { return adoptRef(new CDMInstanceOpenCDM(m_openCDMAccessor.get(), m_openCDMKeySystem)); }
    void loadAndInitialize() final { }
    bool supportsServerCertificates() const final { return true; }
    bool supportsSessions() const final { return true; }
    bool supportsInitData(const AtomicString& initDataType, const SharedBuffer&) const final { return equalLettersIgnoringASCIICase(initDataType, "cenc"); }
    RefPtr<SharedBuffer> sanitizeResponse(const SharedBuffer& response) const final { return response.copy(); }
    std::optional<String> sanitizeSessionId(const String& sessionId) const final { return sessionId; }

private:
    String m_openCDMKeySystem;
    // This owns OCDM Accessor and passes a bare pointer further because it's owned by CDMInstance
    // which lives as long as any MediaKeySession lives.
    ScopedOCDMAccessor m_openCDMAccessor;
};

namespace {

class OCDMSessionCallbacksNotifier {
    WTF_MAKE_NONCOPYABLE(OCDMSessionCallbacksNotifier);
public:
    class Observer {
    public:
        virtual ~Observer() { }
        virtual void didGenerateChallenge(const std::string& challenge) = 0;
        virtual void didUpdateKey(const std::string& status) = 0;
        virtual void didReceiveMessage(const std::string& status) = 0;
    };

    static OCDMSessionCallbacksNotifier& singleton();
    OpenCDMSessionCallbacks* callbacks() { return &m_calbacks; }
    void addObserver(OpenCDMSession* session, Observer*);
    void removeObserver(Observer*);

private:
    using Notification = void (Observer::*)(const std::string&);
    OCDMSessionCallbacksNotifier()
    {
        m_calbacks.process_challenge = &OCDMSessionCallbacksNotifier::didGenerateChallenge;
        m_calbacks.key_update = &OCDMSessionCallbacksNotifier::didUpdateKey;
        m_calbacks.message = &OCDMSessionCallbacksNotifier::didReceiveMessage;
    }

    static void didGenerateChallenge(OpenCDMSession*, const char[], const uint8_t[], const uint16_t);
    static void didUpdateKey(OpenCDMSession*, const uint8_t[], const uint8_t);
    static void didReceiveMessage(OpenCDMSession*, const char[]);
    static bool tryNotify(OpenCDMSession*, Notification, const uint8_t[], uint16_t);
    static void notify(OpenCDMSession*, Notification, const uint8_t[], uint16_t);

    friend class NeverDestroyed<OCDMSessionCallbacksNotifier>;
    OpenCDMSessionCallbacks m_calbacks;
    HashMap<OpenCDMSession*, Observer*> m_observers;
    GenericTaskQueue<Timer> m_taskQueue;
};

OCDMSessionCallbacksNotifier& OCDMSessionCallbacksNotifier::singleton()
{
    static NeverDestroyed<OCDMSessionCallbacksNotifier> instance;
    return instance;
}

void OCDMSessionCallbacksNotifier::addObserver(OpenCDMSession* session, Observer* observer)
{
    m_observers.set(session, observer);
}

void OCDMSessionCallbacksNotifier::removeObserver(Observer* observer)
{
    m_observers.removeIf([observer](const auto& keyAndValue) { return observer == keyAndValue.value; });
}

bool OCDMSessionCallbacksNotifier::tryNotify(OpenCDMSession* session, Notification method, const uint8_t message[], uint16_t messageLength)
{
    if (!isMainThread()) {
        // Make sure all happens on the main thread to avoid locking.
        callOnMainThread([session, method, message, messageLength]() {
            OCDMSessionCallbacksNotifier::tryNotify(session, method, message, messageLength);
        });
        return false;
    }

    OCDMSessionCallbacksNotifier& self = OCDMSessionCallbacksNotifier::singleton();
    auto entry = self.m_observers.find(session);
    if (entry != self.m_observers.end()) {
        (entry->value->*method)(std::string(&message[0], &message[messageLength]));
        return true;
    }

    return false;
}

void OCDMSessionCallbacksNotifier::notify(OpenCDMSession* session, Notification method, const uint8_t message[], uint16_t messageLength)
{
    if (OCDMSessionCallbacksNotifier::tryNotify(session, method, message, messageLength))
        return;

    // It looks like there's no observer interested in the notification. It might be due to the fact it hasn't had chance
    // to register yet because e.g. the notification is sent synchronously.
    // Currently this happens for opencdm_create_session() which synchronously calls the process_challenge() callback and
    // the only way to figure out who is the receiver is by OpenCMDSession. Problem however is that the caller can't know
    // what's its sesssion at this point - it's creating one now.
    auto& self = OCDMSessionCallbacksNotifier::singleton();
    self.m_taskQueue.enqueueTask([session, method, message, messageLength]() {
        OCDMSessionCallbacksNotifier::tryNotify(session, method, message, messageLength);
    });
}

void OCDMSessionCallbacksNotifier::didGenerateChallenge(OpenCDMSession* session, const char /*url*/[], const uint8_t challenge[], const uint16_t challengeLength)
{
    OCDMSessionCallbacksNotifier::notify(session, &Observer::didGenerateChallenge, challenge, challengeLength);
}

void OCDMSessionCallbacksNotifier::didUpdateKey(OpenCDMSession* session, const uint8_t key[], const uint8_t keyLength)
{
    OCDMSessionCallbacksNotifier::notify(session, &Observer::didUpdateKey, key, keyLength);
}

void OCDMSessionCallbacksNotifier::didReceiveMessage(OpenCDMSession* session, const char message[])
{
    OCDMSessionCallbacksNotifier::notify(session, &Observer::didReceiveMessage, reinterpret_cast<const uint8_t*>(message), strlen(message));
}

}  // namespace

class CDMInstanceOpenCDM::Session : public ThreadSafeRefCounted<CDMInstanceOpenCDM::Session> , public OCDMSessionCallbacksNotifier::Observer {
public:
    using DidGenerateChallenge = Function<void(Session*)>;
    using DidUpdateKey = Function<void(Session*, ::KeyStatus, const String&)>;
    using DidChangeData = Function<void(Session*, bool success, const String&)>;

    static Ref<Session> create(CDMInstanceOpenCDM::AccessorHandle, const String&, const char*, Ref<WebCore::SharedBuffer>&&, LicenseType, Ref<WebCore::SharedBuffer>&&);
    ~Session() override;

    bool isValid() const { return m_session.get() && m_message && !m_message->isEmpty(); }
    const String& Id() const { return m_id; }
    Ref<SharedBuffer> message() const { ASSERT(m_message); return Ref<SharedBuffer>(*m_message.get()); }
    bool needsIndividualization() const { return m_needsIndividualization; }
    const Ref<WebCore::SharedBuffer>& initData() const { return m_initData; }
    void generateChallenge(DidGenerateChallenge&& callback);
    void update(const uint8_t* data, unsigned length, DidUpdateKey&&);
    void load(DidChangeData&&);
    void remove(DidChangeData&&);
    bool close() { return !opencdm_session_close(m_session.get()); }
    ::KeyStatus lastStatus() const { return m_lastStatus; }
    bool containsInitData(const InitData& initData) const {
        return m_initData->size() >= initData.sizeInBytes() && memmem(m_initData->data(), m_initData->size(), initData.characters8(), initData.sizeInBytes());
    }

private:
    using ScopedSession = std::unique_ptr<OpenCDMSession, WTF::Function<void(OpenCDMSession*)>>;
    struct KeyUpdateData {
        KeyUpdateData(DidUpdateKey&& callback, const uint8_t* data, const unsigned length)
            : m_callback(WTFMove(callback))
            , m_keySize(length)
        {
            m_key = std::make_unique<uint8_t[]>(m_keySize);
            std::copy_n(data, m_keySize, m_key.get());
        }
        KeyUpdateData(KeyUpdateData&& other)
        {
            m_callback = WTFMove(other.m_callback);
            m_key = WTFMove(other.m_key);
        }
        DidUpdateKey m_callback;
        std::unique_ptr<uint8_t[]> m_key;
        size_t m_keySize;
        WTF_MAKE_NONCOPYABLE(KeyUpdateData);
    };
    typedef struct KeyUpdateData KeyUpdateData;

    Session() = delete;
    Session(CDMInstanceOpenCDM::AccessorHandle, const String&, const char*, Ref<WebCore::SharedBuffer>&&, LicenseType, Ref<WebCore::SharedBuffer>&&);
    void didGenerateChallenge(const std::string& challenge) override;
    void didUpdateKey(const std::string& status) override;
    void didReceiveMessage(const std::string& status) override;

    WTF_MAKE_NONCOPYABLE(Session);

    ScopedSession m_session;
    RefPtr<SharedBuffer> m_message;
    String m_id;
    bool m_needsIndividualization { false };
    Ref<WebCore::SharedBuffer> m_initData;
    ::KeyStatus m_lastStatus { StatusPending };
    Vector<DidGenerateChallenge> m_challengeCallbacks;
    Vector<KeyUpdateData> m_keyStatusDatas;
    Vector<DidChangeData> m_loadCallbacks;
    Vector<DidChangeData> m_removeCallbacks;
};

bool CDMPrivateOpenCDM::supportsConfiguration(const MediaKeySystemConfiguration& config) const
{
    for (auto& audioCapability : config.audioCapabilities)
        if (opencdm_is_type_supported(m_openCDMAccessor.get(), m_openCDMKeySystem.utf8().data(), audioCapability.contentType.utf8().data()))
            return false;
    for (auto& videoCapability : config.videoCapabilities)
        if (opencdm_is_type_supported(m_openCDMAccessor.get(), m_openCDMKeySystem.utf8().data(), videoCapability.contentType.utf8().data()))
            return false;
    return true;
}

CDMFactoryOpenCDM& CDMFactoryOpenCDM::singleton()
{
    static CDMFactoryOpenCDM s_factory;
    return s_factory;
}

std::unique_ptr<CDMPrivate> CDMFactoryOpenCDM::createCDM(const String& keySystem)
{
    return std::unique_ptr<CDMPrivate>(new CDMPrivateOpenCDM(keySystem));
}

bool CDMFactoryOpenCDM::supportsKeySystem(const String& keySystem)
{
    std::string emptyString;

    return !opencdm_is_type_supported(m_openCDMAccessor.get(), keySystem.utf8().data(), emptyString.c_str());
}

static LicenseType openCDMLicenseType(CDMInstance::LicenseType licenseType)
{
    switch (licenseType) {
    case CDMInstance::LicenseType::Temporary:
        return Temporary;
    case CDMInstance::LicenseType::PersistentUsageRecord:
        return PersistentUsageRecord;
    case CDMInstance::LicenseType::PersistentLicense:
        return PersistentLicense;
    default:
        ASSERT_NOT_REACHED();
        return Temporary;
    }
}

static CDMInstance::KeyStatus keyStatusFromOpenCDM(KeyStatus keyStatus)
{
    switch (keyStatus) {
    case Usable:
        return CDMInstance::KeyStatus::Usable;
    case Expired:
        return CDMInstance::KeyStatus::Expired;
    case Released:
        return CDMInstance::KeyStatus::Released;
    case OutputRestricted:
        return CDMInstance::KeyStatus::OutputRestricted;
    case OutputDownscaled:
        return CDMInstance::KeyStatus::OutputDownscaled;
    case StatusPending:
        return CDMInstance::KeyStatus::StatusPending;
    case InternalError:
        return CDMInstance::KeyStatus::InternalError;
    default:
        ASSERT_NOT_REACHED();
        return CDMInstance::KeyStatus::InternalError;
    }
}

static CDMInstance::SessionLoadFailure sessionLoadFailureFromOpenCDM(const String& loadStatus)
{
    if (loadStatus != "None")
        return CDMInstance::SessionLoadFailure::None;
    if (loadStatus == "SessionNotFound")
        return CDMInstance::SessionLoadFailure::NoSessionData;
    if (loadStatus == "MismatchedSessionType")
        return CDMInstance::SessionLoadFailure::MismatchedSessionType;
    if (loadStatus == "QuotaExceeded")
        return CDMInstance::SessionLoadFailure::QuotaExceeded;
    return CDMInstance::SessionLoadFailure::Other;
}

static MediaKeyStatus mediaKeyStatusFromOpenCDM(const String& keyStatus)
{
    if (keyStatus == "KeyUsable")
        return MediaKeyStatus::Usable;
    if (keyStatus == "KeyExpired")
        return MediaKeyStatus::Expired;
    if (keyStatus == "KeyReleased")
        return MediaKeyStatus::Released;
    if (keyStatus == "KeyOutputRestricted")
        return MediaKeyStatus::OutputRestricted;
    if (keyStatus == "KeyOutputDownscaled")
        return MediaKeyStatus::OutputDownscaled;
    if (keyStatus == "KeyStatusPending")
        return MediaKeyStatus::StatusPending;
    return MediaKeyStatus::InternalError;
}

static RefPtr<SharedBuffer> parseResponseMessage(const String& message)
{
    const char messageKey[] = "message:";
    if (!message.startsWith(messageKey))
        return { };

    // Check the following 5 characters, if they are Type: we skip them as well.
    const char typeKey[] = "Type:";
    unsigned offset = sizeof(messageKey) - 1;
    if (message.contains(typeKey, offset))
        offset += sizeof(typeKey) - 1;

    return SharedBuffer::create(message.characters8() + offset, message.sizeInBytes() - offset);
}

Ref<CDMInstanceOpenCDM::Session> CDMInstanceOpenCDM::Session::create(CDMInstanceOpenCDM::AccessorHandle source, const String& keySystem, const char* type, Ref<WebCore::SharedBuffer>&& initData, LicenseType licenseType, Ref<WebCore::SharedBuffer>&& customData)
{
    return adoptRef(*new Session(source, keySystem, type, WTFMove(initData), licenseType, WTFMove(customData)));
}

CDMInstanceOpenCDM::Session::Session(CDMInstanceOpenCDM::AccessorHandle source, const String& keySystem, const char* mimeType, Ref<WebCore::SharedBuffer>&& initData, LicenseType licenseType, Ref<WebCore::SharedBuffer>&& customData)
    : m_initData(WTFMove(initData))
{
    if (source == InvalidAccessorHandle)
        return;

    auto& sessonCallbacks = OCDMSessionCallbacksNotifier::singleton();

    OpenCDMSession* session = nullptr;
    opencdm_create_session(source, keySystem.utf8().data(), openCDMLicenseType(licenseType), mimeType, reinterpret_cast<const uint8_t*>(m_initData->data()), m_initData->size(),
                           !customData->isEmpty() ? reinterpret_cast<const uint8_t*>(customData->data()) : nullptr, customData->size(), sessonCallbacks.callbacks(), &session);
    if (!session)
        return;
    m_session = ScopedSession(session, [](OpenCDMSession* session) {
        opencdm_session_close(session);
        opencdm_destruct_session(session);
    });
    m_id = String::fromUTF8(opencdm_session_id(m_session.get()));
    sessonCallbacks.addObserver(m_session.get(), this);
}

CDMInstanceOpenCDM::Session::~Session()
{
    OCDMSessionCallbacksNotifier::singleton().removeObserver(this);
}

void CDMInstanceOpenCDM::Session::didGenerateChallenge(const std::string& message)
{
    // We could do all operations with String but this way we can save some copies.
    size_t typePosition = message.find(":Type:");
    String requestType(message.c_str(), typePosition != std::string::npos ? typePosition : 0);
    unsigned offset = 0;
    if (!requestType.isEmpty() && requestType.length() != message.size())
        offset = typePosition + 6;

    m_message = SharedBuffer::create(message.c_str() + offset, message.size() - offset);
    m_needsIndividualization = requestType.length() == 1 && static_cast<WebCore::MediaKeyMessageType>(requestType.toInt()) == CDMInstance::MessageType::IndividualizationRequest;
    for (const auto& challengeCallback : m_challengeCallbacks)
        challengeCallback(this);
    m_challengeCallbacks.clear();
}

void CDMInstanceOpenCDM::Session::didUpdateKey(const std::string& status)
{
    for (auto& keyStatusData : m_keyStatusDatas) {
        m_lastStatus = opencdm_session_status(m_session.get(), keyStatusData.m_key.get(), keyStatusData.m_keySize);
        keyStatusData.m_callback(this, m_lastStatus, String(status.c_str(), status.empty() ? 0 : status.size()));
    }
    m_keyStatusDatas.clear();

    for (auto& loadCallback : m_loadCallbacks) {
        loadCallback(this, true, String(status.c_str(), status.empty() ? 0 : status.size()));
    }
    m_loadCallbacks.clear();

    for (auto& removeCallback : m_removeCallbacks) {
        removeCallback(this, true, String(status.c_str(), status.empty() ? 0 : status.size()));
    }
    m_removeCallbacks.clear();
}

void CDMInstanceOpenCDM::Session::didReceiveMessage(const std::string& message)
{
}

void CDMInstanceOpenCDM::Session::generateChallenge(DidGenerateChallenge&& callback)
{
    if (isValid()) {
        callback(this);
        return;
    }

    m_challengeCallbacks.append(WTFMove(callback));
}

void CDMInstanceOpenCDM::Session::update(const uint8_t* data, const unsigned length, DidUpdateKey&& callback)
{
    KeyUpdateData updateData(WTFMove(callback), data, length);
    m_keyStatusDatas.append(WTFMove(updateData));
    if (opencdm_session_update(m_session.get(), data, length)) {
        didUpdateKey(std::string());
    }
}

void CDMInstanceOpenCDM::Session::load(DidChangeData&& callback)
{
    m_loadCallbacks.append(WTFMove(callback));
    if (!opencdm_session_load(m_session.get()))
         didUpdateKey(std::string());
}

void CDMInstanceOpenCDM::Session::remove(DidChangeData&& callback)
{
    m_removeCallbacks.append(WTFMove(callback));
    if (!opencdm_session_remove(m_session.get()))
         didUpdateKey(std::string());
}

CDMInstanceOpenCDM::CDMInstanceOpenCDM(AccessorHandle accessorHandle, const String& keySystem)
    : m_keySystem(keySystem)
    , m_mimeType("video/x-h264")
    , m_openCDMAccessorHandle(accessorHandle)
{
    MediaPlayerPrivateGStreamerBase::ensureWebKitGStreamerElements();
}

CDMInstance::SuccessValue CDMInstanceOpenCDM::setServerCertificate(Ref<SharedBuffer>&& certificate)
{
    return !opencdm_system_set_server_certificate(m_openCDMAccessorHandle, m_keySystem.utf8().data(), reinterpret_cast<unsigned char*>(const_cast<char*>(certificate->data())), certificate->size())
        ? WebCore::CDMInstance::SuccessValue::Succeeded : WebCore::CDMInstance::SuccessValue::Failed;
}

void CDMInstanceOpenCDM::requestLicense(LicenseType licenseType, const AtomicString&, Ref<SharedBuffer>&& rawInitData, Ref<SharedBuffer>&& rawCustomData, LicenseCallback callback)
{
    InitData initData = InitData(reinterpret_cast<const uint8_t*>(rawInitData->data()), rawInitData->size());

    GST_TRACE("Going to request a new session id, init data size %u and MD5 %s", initData.sizeInBytes(), GStreamerEMEUtilities::initDataMD5(initData).utf8().data());
    GST_MEMDUMP("init data", initData.characters8(), initData.sizeInBytes());
    auto generateChallengeLambda = [this, callback = WTFMove(callback)](Session* session) {
        auto sessionId = session->Id();
        if (!session->isValid()) {
            Ref<SharedBuffer> rawInitData = Ref<SharedBuffer>(*session->initData().ptr());
            GST_WARNING("created invalid session %s", sessionId.utf8().data());
            callback(WTFMove(rawInitData), session->Id(), false, Failed);
            removeSession(sessionId);
            return;
        }

        GST_DEBUG("created valid session %s", sessionId.utf8().data());
        callback(session->message(), sessionId, session->needsIndividualization(), Succeeded);
    };

    String sessionIdAsString = sessionIdByInitData(initData);
    if (!sessionIdAsString.isEmpty()) {
        auto session = lookupSession(sessionIdAsString);
        if (session->isValid()) {
            GST_DEBUG("session %s exists and is valid, we can return now", sessionIdAsString.utf8().data());
            generateChallengeLambda(session.get());
        } else {
            // Created but waits on challenge.
            session->generateChallenge(WTFMove(generateChallengeLambda));
        }
        return;
    }

    Ref<Session> newSession = Session::create(m_openCDMAccessorHandle, m_keySystem, m_mimeType, WTFMove(rawInitData), licenseType, WTFMove(rawCustomData));
    String sessionId = newSession->Id();
    if (sessionId.isEmpty()) {
        GST_ERROR("could not create session id");
        callback(WTFMove(rawInitData), { }, false, Failed);
        return;
    }
    GST_DEBUG("Created session with id %s", sessionId.utf8().data());
    newSession->generateChallenge(WTFMove(generateChallengeLambda));

    if (!addSession(sessionId, newSession.ptr()))
        GST_WARNING("Failed to add session %s, the session might already exist, or the allocation failed", sessionId.utf8().data());
}

void CDMInstanceOpenCDM::updateLicense(const String& sessionId, LicenseType, const SharedBuffer& response, LicenseUpdateCallback callback)
{
    auto session = lookupSession(sessionId);
    if (!session) {
        GST_WARNING("cannot update the session %s cause we can't find it", sessionId.utf8().data());
        return;
    }

    session->update(reinterpret_cast<const uint8_t*>(response.data()), response.size(), [callback = WTFMove(callback)](Session* session, ::KeyStatus keyStatus, const String& response) {
        GST_DEBUG("session id %s, key status is %d (usable: %s)", session->Id().utf8().data(),keyStatus, boolForPrinting(keyStatus == Usable));

        if (keyStatus == Usable) {
            KeyStatusVector changedKeys;
            SharedBuffer& initData(session->initData());
            // FIXME: Why are we passing initData here, we are supposed to be passing key ids.
            changedKeys.append(std::pair<Ref<SharedBuffer>, MediaKeyStatus>{initData, keyStatusFromOpenCDM(keyStatus)});
            callback(false, WTFMove(changedKeys), std::nullopt, std::nullopt, SuccessValue::Succeeded);
        } else if (keyStatus != InternalError) {
            // FIXME: Using JSON reponse messages is much cleaner than using string prefixes, I believe there
            // will even be other parts of the spec where not having structured data will be bad.
            RefPtr<SharedBuffer> cleanMessage = parseResponseMessage(response);
            if (cleanMessage) {
                GST_DEBUG("got message of size %u", cleanMessage->size());
                GST_MEMDUMP("message", reinterpret_cast<const uint8_t*>(cleanMessage->data()), cleanMessage->size());
                callback(false, std::nullopt, std::nullopt, std::make_pair(MediaKeyMessageType::LicenseRequest, cleanMessage.releaseNonNull()), SuccessValue::Succeeded);
            } else {
                GST_ERROR("message of size %u incorrectly formatted", response.sizeInBytes());
                callback(false, std::nullopt, std::nullopt, std::nullopt, SuccessValue::Failed);
            }
        } else {
            GST_ERROR("update license reported error state");
            callback(false, std::nullopt, std::nullopt, std::nullopt, SuccessValue::Failed);
        }
    });
}

void CDMInstanceOpenCDM::loadSession(LicenseType, const String& sessionId, const String&, LoadSessionCallback callback)
{
    auto session = lookupSession(sessionId);
    if (!session) {
        GST_WARNING("cannot load the session %s cause we can't find it", sessionId.utf8().data());
        return;
    }
    session->load([callback = WTFMove(callback)](Session* session, bool success, const String& response) {
        SessionLoadFailure sessionFailure = SessionLoadFailure::None;
        if (success) {
            if (!response.startsWith("message:")) {
                SharedBuffer& initData(session->initData());
                KeyStatusVector knownKeys;
                MediaKeyStatus keyStatus = mediaKeyStatusFromOpenCDM(response);
                knownKeys.append(std::pair<Ref<SharedBuffer>, MediaKeyStatus>{initData, keyStatus});
                GST_DEBUG("session %s loaded, status %s", session->Id().utf8().data(), response.utf8().data());
                callback(WTFMove(knownKeys), std::nullopt, std::nullopt, SuccessValue::Succeeded, sessionFailure);
            } else {
                GST_WARNING("session %s loaded, status unknown, message length %u", session->Id().utf8().data(), response.sizeInBytes());
                callback(std::nullopt, std::nullopt, std::nullopt, SuccessValue::Succeeded, sessionFailure);
            }
        } else {
            sessionFailure = sessionLoadFailureFromOpenCDM(response);
            GST_ERROR("session %s not loaded, reason %s", session->Id().utf8().data(), response.utf8().data());
            callback(std::nullopt, std::nullopt, std::nullopt, SuccessValue::Failed, sessionFailure);
        }
    });
}

void CDMInstanceOpenCDM::removeSessionData(const String& sessionId, LicenseType, RemoveSessionDataCallback callback)
{
    auto session = lookupSession(sessionId);
    if (!session) {
        GST_WARNING("cannot remove non-existing session %s data", sessionId.utf8().data());
        return;
    }

    session->remove([callback = WTFMove(callback)](Session* session, bool success, const String& response) {
        KeyStatusVector keys;
        if (success) {
            RefPtr<SharedBuffer> cleanMessage = parseResponseMessage(response);
            if (cleanMessage) {
                SharedBuffer& initData = session->initData();
                keys.append(std::pair<Ref<SharedBuffer>, MediaKeyStatus>{initData, MediaKeyStatus::Released});
                GST_DEBUG("session %s removed, message length %u", session->Id().utf8().data(), cleanMessage->size());
                callback(WTFMove(keys), cleanMessage.releaseNonNull(), SuccessValue::Succeeded);
            } else {
                GST_WARNING("message of size %u incorrectly formatted as session %s removal answer", response.sizeInBytes(), session->Id().utf8().data());
                callback(WTFMove(keys), std::nullopt, SuccessValue::Failed);
            }
        } else {
            SharedBuffer& initData(session->initData());
            MediaKeyStatus keyStatus = mediaKeyStatusFromOpenCDM(response);
            keys.append(std::pair<Ref<SharedBuffer>, MediaKeyStatus>{initData, keyStatus});
            GST_WARNING("could not remove session %s", session->Id().utf8().data());
            callback(WTFMove(keys), std::nullopt, SuccessValue::Failed);
        }
    });

#ifndef NDEBUG
    bool removeSessionResult =
#endif
        removeSession(sessionId);
    ASSERT(removeSessionResult);
}

void CDMInstanceOpenCDM::closeSession(const String& sessionId, CloseSessionCallback callback)
{
    auto session = lookupSession(sessionId);
    if (!session) {
        GST_WARNING("cannot close non-existing session %s", sessionId.utf8().data());
        return;
    }
    session->close();

#ifndef NDEBUG
    bool removeSessionResult =
#endif
        removeSession(sessionId);
    ASSERT(removeSessionResult);

    callback();
}

String CDMInstanceOpenCDM::sessionIdByInitData(const InitData& initData) const
{
    LockHolder locker(m_sessionMapMutex);

    if (!m_sessionsMap.size()) {
        GST_WARNING("no sessions");
        return { };
    }

    GST_TRACE("init data MD5 %s", GStreamerEMEUtilities::initDataMD5(initData).utf8().data());
    GST_MEMDUMP("init data", reinterpret_cast<const uint8_t*>(initData.characters8()), initData.length());

    String result;

    for (const auto& pair : m_sessionsMap) {
        const String& sessionId = pair.key;
        const RefPtr<Session>& session = pair.value;
        if (session->containsInitData(initData)) {
            result = sessionId;
            break;
        }
    }

    if (result.isEmpty())
        GST_WARNING("Unknown session, nothing will be returned");
    else
        GST_DEBUG("Found session for initdata: %s", result.utf8().data());

    return result;
}

bool CDMInstanceOpenCDM::isSessionIdUsable(const String& sessionId) const
{
    auto session = lookupSession(sessionId);
    return session && session->lastStatus() == Usable;
}

bool CDMInstanceOpenCDM::addSession(const String& sessionId, Session* session)
{
    LockHolder locker(m_sessionMapMutex);
    ASSERT(session);
    return m_sessionsMap.set(sessionId, session).isNewEntry;
}

bool CDMInstanceOpenCDM::removeSession(const String& sessionId)
{
    LockHolder locker(m_sessionMapMutex);
    return m_sessionsMap.remove(sessionId);
}

RefPtr<CDMInstanceOpenCDM::Session> CDMInstanceOpenCDM::lookupSession(const String& sessionId) const
{
    LockHolder locker(m_sessionMapMutex);
    auto session = m_sessionsMap.find(sessionId);
    return session == m_sessionsMap.end() ? nullptr : session->value;
}

} // namespace WebCore

#endif // ENABLE(ENCRYPTED_MEDIA) && USE(OPENCDM)
