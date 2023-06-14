
#include "config.h"
#include "CDMOpenCDM.h"

#if ENABLE(ENCRYPTED_MEDIA)

#include "CDMKeySystemConfiguration.h"
#include "CDMRestrictions.h"
#include "CDMSessionType.h"
/* TODO: Why not CDMKeyStatus.h */
#include "MediaKeyStatus.h"
#include "MediaKeyMessageType.h"
#include "SharedBuffer.h"
#include "GStreamerEMEUtilities.h"

namespace {

using OCDMKeyStatus = KeyStatus;

}

namespace WebCore {

CDMFactoryOpenCDM& CDMFactoryOpenCDM::singleton()
{
    static NeverDestroyed<CDMFactoryOpenCDM> s_factory;
    return s_factory;
}

CDMFactoryOpenCDM::CDMFactoryOpenCDM() = default;
CDMFactoryOpenCDM::~CDMFactoryOpenCDM() = default;

std::unique_ptr<CDMPrivate> CDMFactoryOpenCDM::createCDM(const String& keySystem)
{
    return std::unique_ptr<CDMPrivate>(new CDMPrivateOpenCDM(keySystem));
}

bool CDMFactoryOpenCDM::supportsKeySystem(const String& keySystem)
{
    std::string emptyString;

    return !opencdm_is_type_supported(keySystem.utf8().data(), emptyString.c_str());
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

static WebCore::MediaKeyStatus mediaKeyStatusFromOpenCDM(const String& keyStatus)
{
    if (keyStatus == "KeyUsable")
        return WebCore::MediaKeyStatus::Usable;
    if (keyStatus == "KeyExpired")
        return WebCore::MediaKeyStatus::Expired;
    if (keyStatus == "KeyReleased")
        return WebCore::MediaKeyStatus::Released;
    if (keyStatus == "KeyOutputRestricted")
        return WebCore::MediaKeyStatus::OutputRestricted;
    if (keyStatus == "KeyOutputDownscaled")
        return WebCore::MediaKeyStatus::OutputDownscaled;
    if (keyStatus == "KeyStatusPending")
        return WebCore::MediaKeyStatus::StatusPending;
    return WebCore::MediaKeyStatus::InternalError;
}

static WebCore::MediaKeyStatus mediaKeyStatusFromOpenCDM(const SharedBuffer& keyStatusBuffer)
{
    String keyStatus(StringImpl::createWithoutCopying(reinterpret_cast<const LChar*>(keyStatusBuffer.data()), keyStatusBuffer.size()));
    return mediaKeyStatusFromOpenCDM(keyStatus);
}

static CDMInstance::KeyStatusVector copyAndMaybeReplaceValue(CDMInstance::KeyStatusVector& keyStatuses, std::optional<MediaKeyStatus> newStatus = std::nullopt)
{
    CDMInstance::KeyStatusVector copy;
    for (auto& keyStatus : keyStatuses) {
        keyStatus.second = newStatus.value_or(keyStatus.second);
        copy.append(std::pair<Ref<SharedBuffer>, MediaKeyStatus> { keyStatus.first.copyRef(), keyStatus.second });
    }

    return copy;
}

static RefPtr<SharedBuffer> parseResponseMessage(const SharedBuffer& buffer, std::optional<WebCore::MediaKeyMessageType>& messageType)
{
    String message(StringImpl::createWithoutCopying(reinterpret_cast<const LChar*>(buffer.data()), buffer.size()));
    size_t typePosition = message.find(":Type:");
    String requestType(message.characters8(), typePosition != notFound ? typePosition : 0);
    unsigned offset = 0u;
    if (!requestType.isEmpty() && requestType.length() != message.length())
        offset = typePosition + 6;

    if (requestType.length() == 1)
        messageType = static_cast<WebCore::MediaKeyMessageType>(requestType.toInt());
    return SharedBuffer::create(message.characters8() + offset, message.sizeInBytes() - offset);
}


CDMPrivateOpenCDM::CDMPrivateOpenCDM(const String& keySystem)
    : m_keySystem(keySystem)
    , m_openCDMSystem(opencdm_create_system(keySystem.utf8().data()))
{
}

CDMPrivateOpenCDM::~CDMPrivateOpenCDM() = default;

bool CDMPrivateOpenCDM::supportsInitDataType(const AtomicString& initDataType) const
{
    return equalLettersIgnoringASCIICase(initDataType, "cenc") || equalLettersIgnoringASCIICase(initDataType, "webm") || equalLettersIgnoringASCIICase(initDataType, "keyids");
}

bool CDMPrivateOpenCDM::supportsConfiguration(const CDMKeySystemConfiguration& config) const
{
    // TODO: Fix that... default can't be true

    for (auto& audioCapability : config.audioCapabilities)
        if (opencdm_is_type_supported(m_keySystem.utf8().data(), audioCapability.contentType.utf8().data()))
            return false;
    for (auto& videoCapability : config.videoCapabilities)
        if (opencdm_is_type_supported(m_keySystem.utf8().data(), videoCapability.contentType.utf8().data()))
            return false;
    return true;
}

bool CDMPrivateOpenCDM::supportsConfigurationWithRestrictions(const CDMKeySystemConfiguration& config, const CDMRestrictions&) const
{
    // TODO: Check the restrictions
    return supportsConfiguration(config);
}

bool CDMPrivateOpenCDM::supportsSessionTypeWithConfiguration(CDMSessionType&, const CDMKeySystemConfiguration& config) const
{
    // TODO: What about session?
    return supportsConfiguration(config);
}

bool CDMPrivateOpenCDM::supportsRobustness(const String& robustness) const
{
    // TODO: Add comments
    return !robustness.isEmpty();
}

CDMRequirement CDMPrivateOpenCDM::distinctiveIdentifiersRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions&) const
{
    // TODO: Why? Add comments;
    return CDMRequirement::Optional;
}

CDMRequirement CDMPrivateOpenCDM::persistentStateRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions&) const
{
    // TODO: Why? Add comments;
    return CDMRequirement::Optional;
}

bool CDMPrivateOpenCDM::distinctiveIdentifiersAreUniquePerOriginAndClearable(const CDMKeySystemConfiguration&) const
{
    // TODO: Why? Add comments;
    return false;
}

RefPtr<CDMInstance> CDMPrivateOpenCDM::createInstance()
{
    return adoptRef(new CDMInstanceOpenCDM(*m_openCDMSystem, m_keySystem));
}

void CDMPrivateOpenCDM::loadAndInitialize()
{
    // No-op.
}

bool CDMPrivateOpenCDM::supportsServerCertificates() const
{
    // TODO: Why? Add comments;
    return true;
}

bool CDMPrivateOpenCDM::supportsSessions() const
{
    // TODO: Why? Add comments; supportsSessionTypeWithConfiguration doesn't take care of sessions?????
    return true;
}

bool CDMPrivateOpenCDM::supportsInitData(const AtomicString& initDataType, const SharedBuffer& initData) const
{
    // TODO: Sure? What about "initData"???
    return supportsInitDataType(initDataType);
}

RefPtr<SharedBuffer> CDMPrivateOpenCDM::sanitizeResponse(const SharedBuffer& response) const
{
    // TODO: Not validation about the JSON object????
    return response.copy();
}

std::optional<String> CDMPrivateOpenCDM::sanitizeSessionId(const String& sessionId) const
{
    // TODO: Please, do something
    return sessionId;
}


class CDMInstanceOpenCDM::Session : public ThreadSafeRefCounted<CDMInstanceOpenCDM::Session> {
public:
    using Notification = void (Session::*)(RefPtr<WebCore::SharedBuffer>&&);
    using ChallengeGeneratedCallback = Function<void(Session*)>;
    using SessionChangedCallback = Function<void(Session*, bool, RefPtr<SharedBuffer>&&, KeyStatusVector&)>;

    static Ref<Session> create(CDMInstanceOpenCDM*, OpenCDMSystem&, const String&, const AtomicString&, Ref<WebCore::SharedBuffer>&&, LicenseType, Ref<WebCore::SharedBuffer>&&);
    ~Session();

    bool isValid() const { return m_session.get() && m_message && !m_message->isEmpty(); }
    const String& id() const { return m_id; }
    Ref<SharedBuffer> message() const { ASSERT(m_message); return Ref<SharedBuffer>(*m_message.get()); }
    bool needsIndividualization() const { return m_needsIndividualization; }
    const Ref<WebCore::SharedBuffer>& initData() const { return m_initData; }
    void generateChallenge(ChallengeGeneratedCallback&&);
    void update(const uint8_t*, unsigned, SessionChangedCallback&&);
    void load(SessionChangedCallback&&);
    void remove(SessionChangedCallback&&);

    bool close()
    {
        return m_session && !id().isEmpty() ? !opencdm_session_close(m_session.get()) : true;
    }

    OCDMKeyStatus status(const SharedBuffer& keyId) const
    {
        return m_session && !id().isEmpty() ? opencdm_session_status(m_session.get(), reinterpret_cast<const uint8_t*>(keyId.data()), keyId.size()) : StatusPending;
    }

    bool containsKeyId(const SharedBuffer& keyId) const
    {
        if (!keyId.data())
            return false;

        auto index = m_keyStatuses.findMatching([&keyId](const std::pair<Ref<SharedBuffer>, KeyStatus>& item) {
            return memmem(keyId.data(), keyId.size(), item.first->data(), item.first->size());
        });

        if (index == notFound && GStreamerEMEUtilities::isPlayReadyKeySystem(m_keySystem)) {
            GST_DEBUG("Trying to match the playready session indirectly");
            // PlayReady corner case: It happens that the keyid required by the stream and reported by the CDM
            // have different endianness of the 4-2-2 GUID components. OCDM caters for that so ask it if it knows a session
            // with the given key id and compare session ids if it matches the session owned by this instance.
            WebCore::ScopedSession session { opencdm_get_system_session(&m_ocdmSystem, reinterpret_cast<const uint8_t*>(keyId.data()), keyId.size(), 0) };
            GST_TRACE("Session %p with id %s", session.get(), session.get() ? opencdm_session_id(session.get()) : "NA");
            if (session.get() && !strcmp(opencdm_session_id(session.get()), m_id.utf8().data()))
                return true;
        }

        return index != notFound;
    }

    static void openCDMNotification(const OpenCDMSession*, void*, Notification, const char* name, const uint8_t[], uint16_t);

private:
    Session() = delete;
    Session(CDMInstanceOpenCDM*, OpenCDMSystem&, const String&, const AtomicString&, Ref<WebCore::SharedBuffer>&&, LicenseType, Ref<WebCore::SharedBuffer>&&);
    void challengeGeneratedCallback(RefPtr<SharedBuffer>&&);
    void keyUpdatedCallback(RefPtr<SharedBuffer>&& = nullptr);
    // This doesn't need any params but it's made like this to fit the notification mechanism in place.
    void keysUpdateDoneCallback(RefPtr<SharedBuffer>&& = nullptr);
    void errorCallback(RefPtr<SharedBuffer>&&);
    void loadFailure() { updateFailure(); }
    void removeFailure() { updateFailure(); }
    void updateFailure()
    {
        for (auto& sessionChangedCallback : m_sessionChangedCallbacks)
            sessionChangedCallback(this, false, nullptr, m_keyStatuses);
        m_sessionChangedCallbacks.clear();
    }

    WTF_MAKE_NONCOPYABLE(Session);

    ScopedSession m_session;
    RefPtr<SharedBuffer> m_message;
    String m_id;
    bool m_needsIndividualization { false };
    Ref<WebCore::SharedBuffer> m_initData;
    OpenCDMSessionCallbacks m_openCDMSessionCallbacks { };
    Vector<ChallengeGeneratedCallback> m_challengeCallbacks;
    Vector<SessionChangedCallback> m_sessionChangedCallbacks;
    String m_keySystem;
    OpenCDMSystem& m_ocdmSystem;
    CDMInstanceOpenCDM* m_parent;
    // Accessed only on the main thread allowing to track if the Session is still valid and could be used.
    // Needed due to the fact the Session pointer is passed to the OCDM as the userData for notifications which are no
    // warranted to be called on the main thread the Session lives on.
    static HashSet<Session*> m_validSessions;
    KeyStatusVector m_keyStatuses;
};

CDMInstanceOpenCDM::Session::~Session()
{
    close();
    Session::m_validSessions.remove(this);
}

CDMInstanceOpenCDM::Session::Session(CDMInstanceOpenCDM* parent, OpenCDMSystem& source, const String& keySystem, const AtomicString& initDataType, Ref<WebCore::SharedBuffer>&& initData, LicenseType licenseType, Ref<WebCore::SharedBuffer>&& customData)
    : m_initData(WTFMove(initData))
    , m_keySystem(keySystem)
    , m_ocdmSystem(source)
    , m_parent(parent)
{
    OpenCDMSession* session = nullptr;
    m_openCDMSessionCallbacks.process_challenge_callback = [](OpenCDMSession* session, void* userData, const char[], const uint8_t challenge[], const uint16_t challengeLength) {
        Session::openCDMNotification(session, userData, &Session::challengeGeneratedCallback, "challenge", challenge, challengeLength);
    };
    m_openCDMSessionCallbacks.key_update_callback = [](OpenCDMSession* session, void* userData, const uint8_t key[], const uint8_t keyLength) {
        Session::openCDMNotification(session, userData, &Session::keyUpdatedCallback, "key updated", key, keyLength);
    };
    m_openCDMSessionCallbacks.keys_updated_callback = [](const OpenCDMSession* session, void* userData) {
        if (userData) {
            static_cast<Session*>(userData)->m_parent->setAllKeysReceived(true);
        }
        Session::openCDMNotification(session, userData, &Session::keysUpdateDoneCallback, "all keys updated", nullptr, 0);
    };
    m_openCDMSessionCallbacks.error_message_callback = [](OpenCDMSession* session, void* userData, const char message[]) {
        Session::openCDMNotification(session, userData, &Session::errorCallback, "error", reinterpret_cast<const uint8_t*>(message), strlen(message));
    };

    GST_DEBUG("Creating session for '%s' keySystem and '%s' initDataType\n", keySystem.utf8().data(), initDataType.string().utf8().data());
    opencdm_construct_session(&source,
                              openCDMLicenseType(licenseType),
                              initDataType.string().utf8().data(),
                              reinterpret_cast<const uint8_t*>(m_initData->data()),
                              m_initData->size(),
                              !customData->isEmpty() ? reinterpret_cast<const uint8_t*>(customData->data()) : nullptr,
                              customData->size(),
                              &m_openCDMSessionCallbacks,
                              this,
                              &session);
    if (!session) {
        GST_ERROR("Could not create session");
        return;
    }
    m_session.reset(session);
    m_id = String::fromUTF8(opencdm_session_id(m_session.get()));
    Session::m_validSessions.add(this);
}

Ref<CDMInstanceOpenCDM::Session> CDMInstanceOpenCDM::Session::create(CDMInstanceOpenCDM* parent, OpenCDMSystem& source, const String& keySystem, const AtomicString& initDataType, Ref<WebCore::SharedBuffer>&& initData, LicenseType licenseType, Ref<WebCore::SharedBuffer>&& customData)
{
    return adoptRef(*new Session(parent, source, keySystem, initDataType, WTFMove(initData), licenseType, WTFMove(customData)));
}

void CDMInstanceOpenCDM::Session::openCDMNotification(const OpenCDMSession*, void* userData, Notification method, const char* name, const uint8_t message[], uint16_t messageLength)
{
    GST_DEBUG("Got '%s' OCDM notification", name);
    Session* session = reinterpret_cast<Session*>(userData);
    RefPtr<WebCore::SharedBuffer> sharedBuffer = WebCore::SharedBuffer::create(message, messageLength);
    if (!isMainThread()) {
        // Make sure all happens on the main thread to avoid locking.
        callOnMainThread([session, method, buffer = WTFMove(sharedBuffer)]() mutable {
            if (!Session::m_validSessions.contains(session)) {
                // Became invalid in the meantime. It's possible due to leaping through the different threads.
                return;
            }
            (session->*method)(WTFMove(buffer));
        });
        return;
    }

    (session->*method)(WTFMove(sharedBuffer));
}

void CDMInstanceOpenCDM::Session::challengeGeneratedCallback(RefPtr<SharedBuffer>&& buffer)
{
    std::optional<WebCore::MediaKeyMessageType> requestType;
    auto message = buffer ? parseResponseMessage(*buffer, requestType) : nullptr;

    // This call can be called just before a requestLicense and before
    // the session was fully created, see CDMInstanceOpenCDM::requestLicense.
    // So saving the message for later...
    // TODO: If a new session callback is generated, what to do with an old message...
    //       perhaps m_parent->client()->enqueueMessageWithTask because no one has consumed...
    if (id().isEmpty()) {
        GST_INFO("Challenge generated in a session without id");
        m_message = WTFMove(message);
        m_needsIndividualization = requestType == CDMInstance::MessageType::IndividualizationRequest;
        return;
    }

    // This can be called as a result of e.g. requestLicense() but update() or remove() as well.
    // This called not as a response to API call is also possible.
    if (!m_challengeCallbacks.isEmpty()) {
        std::optional<WebCore::MediaKeyMessageType> requestType;
        m_message = WTFMove(message);
        m_needsIndividualization = requestType == CDMInstance::MessageType::IndividualizationRequest;

        for (const auto& challengeCallback : m_challengeCallbacks)
            challengeCallback(this);
        m_challengeCallbacks.clear();
    } else if (!m_sessionChangedCallbacks.isEmpty()) {
        for (auto& sessionChangedCallback : m_sessionChangedCallbacks)
            sessionChangedCallback(this, true, message.copyRef(), m_keyStatuses);
        m_sessionChangedCallbacks.clear();
    } else {
        if (m_parent->client() && requestType.has_value())
            m_parent->client()->enqueueMessageWithTask(static_cast<CDMInstanceClient::MessageType>(requestType.value()), message.releaseNonNull());
    }
}

void CDMInstanceOpenCDM::Session::keyUpdatedCallback(RefPtr<SharedBuffer>&& buffer)
{
    GST_MEMDUMP("Updated key", reinterpret_cast<const guint8*>(buffer->data()), buffer->size());
    auto index = m_keyStatuses.findMatching([&buffer](const std::pair<Ref<SharedBuffer>, KeyStatus>& item) {
        return memmem(buffer->data(), buffer->size(), item.first->data(), item.first->size());
    });

    auto keyStatus = keyStatusFromOpenCDM(status(*buffer));
    if (index != notFound)
        m_keyStatuses[index].second = keyStatus;
    else
        m_keyStatuses.append(std::pair<Ref<SharedBuffer>, MediaKeyStatus> { buffer.releaseNonNull(), keyStatus });
}

void CDMInstanceOpenCDM::Session::keysUpdateDoneCallback(RefPtr<SharedBuffer>&&)
{
    bool appliesToApiCall = !m_sessionChangedCallbacks.isEmpty();
    if (!appliesToApiCall && m_parent && m_parent->client()) {
        m_parent->client()->updateKeyStatuses(copyAndMaybeReplaceValue(m_keyStatuses));
        return;
    }

    for (auto& sessionChangedCallback : m_sessionChangedCallbacks)
        sessionChangedCallback(this, true, nullptr, m_keyStatuses);
    m_sessionChangedCallbacks.clear();
}

void CDMInstanceOpenCDM::Session::errorCallback(RefPtr<SharedBuffer>&& message)
{
    for (const auto& challengeCallback : m_challengeCallbacks)
        challengeCallback(this);
    m_challengeCallbacks.clear();

    for (auto& sessionChangedCallback : m_sessionChangedCallbacks)
        sessionChangedCallback(this, false, WTFMove(message), m_keyStatuses);
    m_sessionChangedCallbacks.clear();
}

void CDMInstanceOpenCDM::Session::generateChallenge(ChallengeGeneratedCallback&& callback)
{
    if (isValid()) {
        callback(this);
        return;
    }

    m_challengeCallbacks.append(WTFMove(callback));
}

void CDMInstanceOpenCDM::Session::update(const uint8_t* data, const unsigned length, SessionChangedCallback&& callback)
{
    m_keyStatuses.clear();
    m_sessionChangedCallbacks.append(WTFMove(callback));
    if (!m_session || id().isEmpty() || opencdm_session_update(m_session.get(), data, length))
        updateFailure();

    // Assumption: should report back either with a message to be sent to the license server or key statuses updates.
}

void CDMInstanceOpenCDM::Session::load(SessionChangedCallback&& callback)
{
    m_keyStatuses.clear();
    m_sessionChangedCallbacks.append(WTFMove(callback));
    if (!m_session || id().isEmpty() || opencdm_session_load(m_session.get()))
        loadFailure();

    // Assumption: should report back either with a message to be sent to the license server or key status updates.
}

void CDMInstanceOpenCDM::Session::remove(SessionChangedCallback&& callback)
{
    // m_keyStatuses are not cleared here not to rely on CDM callbacks with Released status.
    m_sessionChangedCallbacks.append(WTFMove(callback));
    if (!m_session || id().isEmpty() || opencdm_session_remove(m_session.get()))
        removeFailure();

    // Assumption: should report back either with a message to be sent to the license server or key updates with "KeyReleased" status.
}

HashSet<CDMInstanceOpenCDM::Session*> CDMInstanceOpenCDM::Session::m_validSessions;

CDMInstanceOpenCDM::CDMInstanceOpenCDM(OpenCDMSystem& system, const String& keySystem)
    : m_openCDMSystem(system)
    , m_keySystem(keySystem)
    , m_allKeysReceived(false)
{
}

CDMInstanceOpenCDM::~CDMInstanceOpenCDM() = default;

CDMInstance::SuccessValue CDMInstanceOpenCDM::initializeWithConfiguration(const CDMKeySystemConfiguration&)
{
    // TODO: Please, review
    return CDMInstance::Succeeded;
}

CDMInstance::SuccessValue CDMInstanceOpenCDM::setDistinctiveIdentifiersAllowed(bool)
{
    // TODO: Please, review
    return CDMInstance::Succeeded;
}

CDMInstance::SuccessValue CDMInstanceOpenCDM::setPersistentStateAllowed(bool)
{
    // TODO: Please, review
    return CDMInstance::Succeeded;
}

CDMInstance::SuccessValue CDMInstanceOpenCDM::setServerCertificate(Ref<SharedBuffer>&& certificate)
{
    return !opencdm_system_set_server_certificate(&m_openCDMSystem, reinterpret_cast<unsigned char*>(const_cast<char*>(certificate->data())), certificate->size())
        ? WebCore::CDMInstance::SuccessValue::Succeeded
        : WebCore::CDMInstance::SuccessValue::Failed;
}

CDMInstance::SuccessValue CDMInstanceOpenCDM::setStorageDirectory(const String& storageDirectory)
{
    // TODO: Sure??!?!?!?!?!?
    return CDMInstance::Succeeded;
}

void CDMInstanceOpenCDM::requestLicense(LicenseType licenseType, const AtomicString& initDataType, Ref<SharedBuffer>&& rawInitData, Ref<SharedBuffer>&& rawCustomData, LicenseCallback callback)
{
    InitData initData = InitData(reinterpret_cast<const uint8_t*>(rawInitData->data()), rawInitData->size());

    GST_TRACE("Going to request a new session id, init data size %u and MD5 %s", initData.sizeInBytes(), GStreamerEMEUtilities::initDataMD5(initData).utf8().data());
    GST_MEMDUMP("init data", initData.characters8(), initData.sizeInBytes());
    auto generateChallenge = [this, callback = WTFMove(callback)](Session* session) {
        auto sessionId = session->id();
        if (sessionId.isEmpty()) {
            GST_ERROR("could not create session id");
            callback(session->initData().copyRef(), { }, false, Failed);
            return;
        }

        if (!session->isValid()) {
            GST_WARNING("created invalid session %s", sessionId.utf8().data());
            callback(session->initData().copyRef(), session->id(), false, Failed);
            removeSession(sessionId);
            return;
        }

        GST_DEBUG("created valid session %s", sessionId.utf8().data());
        callback(session->message(), sessionId, session->needsIndividualization(), Succeeded);
    };

    Ref<Session> newSession = Session::create(this,
                                              m_openCDMSystem,
                                              m_keySystem,
                                              initDataType,
                                              WTFMove(rawInitData),
                                              licenseType,
                                              WTFMove(rawCustomData));
    String sessionId = newSession->id();
    if (sessionId.isEmpty()) {
        generateChallenge(newSession.ptr());
        return;
    }
    GST_DEBUG("Created session with id %s", sessionId.utf8().data());
    newSession->generateChallenge(WTFMove(generateChallenge));
    addSession(sessionId, WTFMove(newSession));
}

void CDMInstanceOpenCDM::updateLicense(const String& sessionId, LicenseType, const SharedBuffer& response, LicenseUpdateCallback callback)
{
    auto session = lookupSession(sessionId);
    if (!session) {
        callback(false, std::nullopt, std::nullopt, std::nullopt, SuccessValue::Failed);
        return;
    }

    session->update(reinterpret_cast<const uint8_t*>(response.data()), response.size(), [callback = WTFMove(callback)](Session* session, bool success, RefPtr<SharedBuffer>&& buffer, KeyStatusVector& keyStatuses) {
        if (success) {
            if (!buffer) {
                ASSERT(!keyStatuses.isEmpty());
                callback(false, copyAndMaybeReplaceValue(keyStatuses), std::nullopt, std::nullopt, SuccessValue::Succeeded);
            } else {
                // FIXME: Using JSON reponse messages is much cleaner than using string prefixes, I believe there
                // will even be other parts of the spec where not having structured data will be bad.
                std::optional<WebCore::MediaKeyMessageType> requestType;
                RefPtr<SharedBuffer> cleanMessage = parseResponseMessage(*buffer, requestType);
                if (cleanMessage) {
                    callback(false, std::nullopt, std::nullopt, std::make_pair(requestType.value_or(MediaKeyMessageType::LicenseRequest), cleanMessage.releaseNonNull()), SuccessValue::Succeeded);
                } else {
                    callback(false, std::nullopt, std::nullopt, std::nullopt, SuccessValue::Failed);
                }
            }
        } else {
            callback(false, std::nullopt, std::nullopt, std::nullopt, SuccessValue::Failed);
        }
    });
}

void CDMInstanceOpenCDM::loadSession(LicenseType, const String& sessionId, const String&, LoadSessionCallback callback)
{
    auto session = lookupSession(sessionId);

    if (!session) {
        callback(std::nullopt, std::nullopt, std::nullopt, SuccessValue::Failed, SessionLoadFailure::NoSessionData);
        return;
    }
    session->load([callback = WTFMove(callback)](Session* session, bool success, RefPtr<SharedBuffer>&& buffer, KeyStatusVector& keyStatuses) {
        if (success) {
            if (!buffer)
                callback(copyAndMaybeReplaceValue(keyStatuses), std::nullopt, std::nullopt, SuccessValue::Succeeded, SessionLoadFailure::None);
            else {
                // FIXME: Using JSON reponse messages is much cleaner than using string prefixes, I believe there
                // will even be other parts of the spec where not having structured data will be bad.
                std::optional<WebCore::MediaKeyMessageType> requestType;
                RefPtr<SharedBuffer> cleanMessage = parseResponseMessage(*buffer, requestType);
                if (cleanMessage) {
                    callback(std::nullopt, std::nullopt, std::make_pair(requestType.value_or(MediaKeyMessageType::LicenseRequest), cleanMessage.releaseNonNull()), SuccessValue::Succeeded, SessionLoadFailure::None);
                } else {
                    callback(std::nullopt, std::nullopt, std::nullopt, SuccessValue::Failed, SessionLoadFailure::Other);
                }
            }
        } else {
            auto bufferData = buffer ? buffer->data() : nullptr;
            auto bufferSize = buffer ? buffer->size() : 0;
            String response(StringImpl::createWithoutCopying(reinterpret_cast<const LChar*>(bufferData), bufferSize));
            callback(std::nullopt, std::nullopt, std::nullopt, SuccessValue::Failed, sessionLoadFailureFromOpenCDM(response));
        }
    });
}

void CDMInstanceOpenCDM::removeSessionData(const String& sessionId, LicenseType, RemoveSessionDataCallback callback)
{
    auto session = lookupSession(sessionId);

    if (!session) {
        callback(KeyStatusVector(), std::nullopt, SuccessValue::Failed);
        return;
    }

    session->remove([callback = WTFMove(callback)](Session* session, bool success, RefPtr<SharedBuffer>&& buffer, KeyStatusVector& keys) {
        if (success) {
            if (!buffer)
                callback(copyAndMaybeReplaceValue(keys, MediaKeyStatus::Released), std::nullopt, SuccessValue::Succeeded);
            else {
                std::optional<WebCore::MediaKeyMessageType> requestType;
                RefPtr<SharedBuffer> cleanMessage = buffer ? parseResponseMessage(*buffer, requestType) : nullptr;
                if (cleanMessage) {
                    callback(copyAndMaybeReplaceValue(keys, MediaKeyStatus::Released), cleanMessage.releaseNonNull(), SuccessValue::Succeeded);
                } else {
                    callback(copyAndMaybeReplaceValue(keys, MediaKeyStatus::InternalError), std::nullopt, SuccessValue::Failed);
                }
            }
        } else {
            callback(copyAndMaybeReplaceValue(keys, MediaKeyStatus::InternalError), std::nullopt, SuccessValue::Failed);
        }
    });

    removeSession(sessionId);
}

void CDMInstanceOpenCDM::closeSession(const String& sessionId, CloseSessionCallback callback)
{
    auto session = lookupSession(sessionId);
    if (!session) {
        GST_WARNING("cannot close non-existing session %s", sessionId.utf8().data());
        return;
    }
    session->close();

    removeSession(sessionId);

    callback();
}

void CDMInstanceOpenCDM::storeRecordOfKeyUsage(const String&)
{
}

const String& CDMInstanceOpenCDM::keySystem() const
{
    return m_keySystem;
}

bool CDMInstanceOpenCDM::areAllKeysReceived() const
{
    return m_allKeysReceived;
}

void CDMInstanceOpenCDM::setAllKeysReceived(bool allKeysReceived)
{
    m_allKeysReceived = allKeysReceived;
}

String CDMInstanceOpenCDM::sessionIdByKeyId(const SharedBuffer& keyId) const
{
    LockHolder locker(m_sessionMapMutex);

    GST_MEMDUMP("kid", reinterpret_cast<const uint8_t*>(keyId.data()), keyId.size());
    if (!m_sessionsMap.size() || !keyId.data()) {
        GST_WARNING("no sessions");
        return { };
    }

    String result;

    for (const auto& pair : m_sessionsMap) {
        const String& sessionId = pair.key;
        const RefPtr<Session>& session = pair.value;
        if (session->containsKeyId(keyId)) {
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

bool CDMInstanceOpenCDM::isKeyIdInSessionUsable(const SharedBuffer& keyId, const String& sessionId) const
{
    auto session = lookupSession(sessionId);
    return session && session->status(keyId) == Usable;
}

bool CDMInstanceOpenCDM::addSession(const String& sessionId, RefPtr<Session>&& session)
{
    LockHolder locker(m_sessionMapMutex);
    ASSERT(session);
    GST_DEBUG("Adding session for %s", sessionId.utf8().data());
    return m_sessionsMap.set(sessionId, session).isNewEntry;
}

bool CDMInstanceOpenCDM::removeSession(const String& sessionId)
{
    LockHolder locker(m_sessionMapMutex);
    GST_DEBUG("Removing session for %s", sessionId.utf8().data());
    return m_sessionsMap.remove(sessionId);
}

RefPtr<CDMInstanceOpenCDM::Session> CDMInstanceOpenCDM::lookupSession(const String& sessionId) const
{
    LockHolder locker(m_sessionMapMutex);
    auto session = m_sessionsMap.find(sessionId);
    return session == m_sessionsMap.end() ? nullptr : session->value;
}

} // namespace WebCore

#endif // ENABLE(ENCRYPTED_MEDIA)
