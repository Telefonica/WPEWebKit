/*
 * Author: Álvaro Peña <alvaropg@gmail.com>
 * Copyright (C) 2020 Telefónica S.A.
 *
 * Adapted CDM implementation for OpenCDM
 */

#pragma once

#if ENABLE(ENCRYPTED_MEDIA)

#include "CDMFactory.h"
#include "CDMInstance.h"
#include "CDMPrivate.h"
#include "SharedBuffer.h"

#include <wtf/WeakPtr.h>
#include <wtf/HashMap.h>
#include <wtf/text/StringHash.h>

#include <open_cdm.h>

namespace WebCore {

struct OCDMSystemDeleter {
    OpenCDMError operator()(OpenCDMSystem* ptr) const { return opencdm_destruct_system(ptr); }
};

using ScopedOCDMSystem = std::unique_ptr<OpenCDMSystem, OCDMSystemDeleter>;

struct SessionDeleter {
    OpenCDMError operator()(OpenCDMSession* ptr) const { return opencdm_destruct_session(ptr); }
};
    
using ScopedSession = std::unique_ptr<OpenCDMSession, SessionDeleter>;

class CDMFactoryOpenCDM final : public CDMFactory {
private:
    friend class NeverDestroyed<CDMFactoryOpenCDM>;
    CDMFactoryOpenCDM();

public:
    static CDMFactoryOpenCDM& singleton();

    virtual ~CDMFactoryOpenCDM();

    virtual std::unique_ptr<CDMPrivate> createCDM(const String&) final;
    virtual bool supportsKeySystem(const String&) final;
};

class CDMPrivateOpenCDM final : public CDMPrivate {
private:
    CDMPrivateOpenCDM() = delete;
    CDMPrivateOpenCDM(const CDMPrivateOpenCDM&) = delete;
    CDMPrivateOpenCDM& operator=(const CDMPrivateOpenCDM&) = delete;

public:
    CDMPrivateOpenCDM(const String& keySystem);
    virtual ~CDMPrivateOpenCDM();

    bool supportsInitDataType(const AtomicString&) const override;
    bool supportsConfiguration(const CDMKeySystemConfiguration&) const override;
    bool supportsConfigurationWithRestrictions(const CDMKeySystemConfiguration&, const CDMRestrictions&) const override;
    bool supportsSessionTypeWithConfiguration(CDMSessionType&, const CDMKeySystemConfiguration&) const override;
    bool supportsRobustness(const String&) const override;
    CDMRequirement distinctiveIdentifiersRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions&) const override;
    CDMRequirement persistentStateRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions&) const override;
    bool distinctiveIdentifiersAreUniquePerOriginAndClearable(const CDMKeySystemConfiguration&) const override;
    RefPtr<CDMInstance> createInstance() override;
    void loadAndInitialize() override;
    bool supportsServerCertificates() const override;
    bool supportsSessions() const override;
    bool supportsInitData(const AtomicString&, const SharedBuffer&) const override;
    RefPtr<SharedBuffer> sanitizeResponse(const SharedBuffer&) const override;
    std::optional<String> sanitizeSessionId(const String&) const override;

private:
    String m_keySystem;
    // This owns OCDM System and passes a bare pointer further because it's owned by CDMInstance
    // which lives as long as any MediaKeySession lives.
    ScopedOCDMSystem m_openCDMSystem;
};

class CDMInstanceOpenCDM final : public CDMInstance, public CanMakeWeakPtr<CDMInstanceOpenCDM> {
private:
    CDMInstanceOpenCDM() = delete;
    CDMInstanceOpenCDM(const CDMInstanceOpenCDM&) = delete;
    CDMInstanceOpenCDM& operator=(const CDMInstanceOpenCDM&) = delete;

    class Session;

public:
    CDMInstanceOpenCDM(OpenCDMSystem&, const String&);
    virtual ~CDMInstanceOpenCDM();

    // Metadata getters, just for some DRM characteristics.
    const String& keySystem() const final;
    bool areAllKeysReceived() const override final;
    void setAllKeysReceived(bool allKeysReceived);

    ImplementationType implementationType() const final { return ImplementationType::OpenCDM; }
    SuccessValue initializeWithConfiguration(const CDMKeySystemConfiguration&) override;
    SuccessValue setDistinctiveIdentifiersAllowed(bool) override;
    SuccessValue setPersistentStateAllowed(bool) override;

    // Operations on the DRM system.
    SuccessValue setServerCertificate(Ref<SharedBuffer>&&) override;
    SuccessValue setStorageDirectory(const String&) override;

    // Request License will automagically create a Session. The session is later on referred to with its session id.
    void requestLicense(LicenseType, const AtomicString&, Ref<SharedBuffer>&&, Ref<SharedBuffer>&&, LicenseCallback) final;

    // Operations on the DRM system -> Session.
    void updateLicense(const String&, LicenseType, const SharedBuffer&, LicenseUpdateCallback) override;
    void loadSession(LicenseType, const String&, const String&, LoadSessionCallback) override;
    void closeSession(const String&, CloseSessionCallback) override;
    void removeSessionData(const String&, LicenseType, RemoveSessionDataCallback) override;
    void storeRecordOfKeyUsage(const String&) override;

    void setClient(CDMInstanceClient& client) override { m_client = &client; }
    void clearClient() override { m_client = nullptr; }
    CDMInstanceClient* client() const { return m_client; }

    String sessionIdByKeyId(const SharedBuffer&) const;
    bool isKeyIdInSessionUsable(const SharedBuffer&, const String&) const;

    OpenCDMSystem* ocdmSystem() const { return &m_openCDMSystem; }

private:
    bool addSession(const String& sessionId, RefPtr<Session>&& session);
    bool removeSession(const String& sessionId);
    RefPtr<Session> lookupSession(const String& sessionId) const;

    mutable Lock m_sessionMapMutex;
    HashMap<String, RefPtr<Session>> m_sessionsMap;
    OpenCDMSystem& m_openCDMSystem;
    String m_keySystem;
    CDMInstanceClient* m_client { nullptr };
    bool m_allKeysReceived;
};

} // namespace WebCore

SPECIALIZE_TYPE_TRAITS_CDM_INSTANCE(WebCore::CDMInstanceOpenCDM, WebCore::CDMInstance::ImplementationType::OpenCDM);

#endif // ENABLE(ENCRYPTED_MEDIA)
