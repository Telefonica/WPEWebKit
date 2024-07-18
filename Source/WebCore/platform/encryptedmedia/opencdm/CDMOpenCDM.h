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
#include "CDMProxy.h"
#include "SharedBuffer.h"

#include <wtf/WeakPtr.h>
#include <wtf/HashMap.h>
#include <wtf/text/StringHash.h>
#include "CDMInstanceSession.h"
#include "GStreamerEMEUtilities.h"

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

class CDMFactoryOpenCDM final : public CDMFactory, public CDMProxyFactory {
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

    Vector<AtomString> supportedInitDataTypes() const override;    
    bool supportsConfiguration(const CDMKeySystemConfiguration&) const override;
    Vector<AtomString> supportedRobustnesses() const override;
    bool supportsConfigurationWithRestrictions(const CDMKeySystemConfiguration&, const CDMRestrictions&) const override;
    bool supportsSessionTypeWithConfiguration(const CDMSessionType&, const CDMKeySystemConfiguration&) const override;
    
    CDMRequirement distinctiveIdentifiersRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions&) const override;
    CDMRequirement persistentStateRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions&) const override;
    bool distinctiveIdentifiersAreUniquePerOriginAndClearable(const CDMKeySystemConfiguration&) const override;
    RefPtr<CDMInstance> createInstance() override;
    void loadAndInitialize() override;
    bool supportsServerCertificates() const override;
    bool supportsSessions() const override;
    bool supportsInitData(const AtomString&, const SharedBuffer&) const override;
    RefPtr<SharedBuffer> sanitizeResponse(const SharedBuffer&) const override;
    std::optional<String> sanitizeSessionId(const String&) const override;

private:
    String m_keySystem;
    // This owns OCDM System and passes a bare pointer further because it's owned by CDMInstance
    // which lives as long as any MediaKeySession lives.
    ScopedOCDMSystem m_openCDMSystem;
};

class CDMInstanceOpenCDM final : public CDMInstanceProxy {
private:
    CDMInstanceOpenCDM() = delete;
    CDMInstanceOpenCDM(const CDMInstanceOpenCDM&) = delete;
    CDMInstanceOpenCDM& operator=(const CDMInstanceOpenCDM&) = delete;

   

public:
    class Session;
    CDMInstanceOpenCDM(OpenCDMSystem&, const String&);
    virtual ~CDMInstanceOpenCDM();

    // Metadata getters, just for some DRM characteristics.
    const String& keySystem() const final;
    ImplementationType implementationType() const final { return ImplementationType::OpenCDM; }
    void initializeWithConfiguration(const CDMKeySystemConfiguration&, AllowDistinctiveIdentifiers, AllowPersistentState, SuccessCallback&&) final;

    // Operations on the DRM system.
    void setServerCertificate(Ref<SharedBuffer>&&, SuccessCallback&& callback) override;
    void setStorageDirectory(const String&) override;

    void clearClient() override { m_client = nullptr; }
    CDMInstanceClient* client() const { return m_client; }

    String sessionIdByKeyId(const SharedBuffer&) const;
    bool isKeyIdInSessionUsable(const SharedBuffer&, const String&) const;

    OpenCDMSystem* ocdmSystem() const { return &m_openCDMSystem; }
    RefPtr<CDMInstanceSession> createSession() final;

private:
    bool addSession(const String& sessionId, RefPtr<Session>&& session);
    bool removeSession(const String& sessionId);
    RefPtr<Session> lookupSession(const String& sessionId) const;
    String getKeySystem();

    mutable Lock m_sessionMapMutex;
    HashMap<String, RefPtr<Session>> m_sessionsMap;
    OpenCDMSystem& m_openCDMSystem;
    String m_keySystem;
    CDMInstanceClient* m_client { nullptr };
};
class CDMInstanceSessionOpenCDM final : public CDMInstanceSessionProxy {
public:
    CDMInstanceSessionOpenCDM(CDMInstanceOpenCDM&);

    // Request License will automatically create a Session. The session is later on referred to with its session id.
    void requestLicense(LicenseType, const AtomString& initDataType, Ref<SharedBuffer>&& initData, Ref<SharedBuffer>&& customData, LicenseCallback&&) final;
     // Operations on the DRM system -> Session.
    void updateLicense(const String&, LicenseType, Ref<SharedBuffer>&&, LicenseUpdateCallback&&) final;
    void loadSession(LicenseType, const String&, const String&, LoadSessionCallback&&) final;
    void closeSession(const String&, CloseSessionCallback&&) final;
    void removeSessionData(const String&, LicenseType, RemoveSessionDataCallback&&) final;
    void storeRecordOfKeyUsage(const String&) final;

    bool isValid() const;

    void setClient(WeakPtr<CDMInstanceSessionClient>&& client) final;
    void clearClient() final { m_client.clear(); }
    WeakPtr<CDMInstanceSessionClient> client(){ return m_client;}

    private:
        InitData m_initData;
        Ref<CDMInstanceOpenCDM::Session> m_session;
        String m_sessionId;
        WeakPtr<CDMInstanceSessionClient> m_client;
};

} // namespace WebCore

SPECIALIZE_TYPE_TRAITS_CDM_INSTANCE(WebCore::CDMInstanceOpenCDM, WebCore::CDMInstance::ImplementationType::OpenCDM);

#endif // ENABLE(ENCRYPTED_MEDIA)
