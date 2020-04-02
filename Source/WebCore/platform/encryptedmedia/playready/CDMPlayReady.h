/*
 * 
 * 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#if ENABLE(ENCRYPTED_MEDIA)

#include "CDMFactory.h"
#include "CDMInstance.h"
#include "CDMPrivate.h"
#include "SharedBuffer.h"
#include <wtf/WeakPtr.h>

//includes from BSEAV Playready 3.0
/*#include <oemcommon.h>
#include <drmmanager.h>
#include <drmmathsafe.h>
#include <drmtypes.h>
#include <drmerr.h>*/

// The following two values determine the initial size of the in-memory license
// store. If more licenses are used concurrently, Playready will resize the
// to make room. However, the resizing action is inefficient in both CPU and
// memory, so it is useful to get the max size right and set it here.
/*const DRM_DWORD LICENSE_SIZE_BYTES = 512;  // max possible license size (ask the server team)
const DRM_DWORD MAX_NUM_LICENSES = 200;    // max number of licenses (ask the RefApp team)

struct OutputProtection {
    uint16_t compressedDigitalVideoLevel;   //!< Compressed digital video output protection level.
    uint16_t uncompressedDigitalVideoLevel; //!< Uncompressed digital video output protection level.
    uint16_t analogVideoLevel;              //!< Analog video output protection level.
    uint16_t compressedDigitalAudioLevel;   //!< Compressed digital audio output protection level.
    uint16_t uncompressedDigitalAudioLevel; //!< Uncompressed digital audio output protection level.
    uint32_t maxResDecodeWidth;             //!< Max res decode width in pixels.
    uint32_t maxResDecodeHeight;            //!< Max res decode height in pixels.
    OutputProtection();
    void setOutputLevels(const DRM_MINIMUM_OUTPUT_PROTECTION_LEVELS& mopLevels);
    void setMaxResDecode(uint32_t width, uint32_t height);
};*/

namespace WebCore {

class CDMFactoryPlayReady final : public CDMFactory {
public:
    static CDMFactoryPlayReady& singleton();

    virtual ~CDMFactoryPlayReady();

    std::unique_ptr<CDMPrivate> createCDM(const String&) override;
    bool supportsKeySystem(const String&) override;

private:
    CDMFactoryPlayReady();
};

class CDMPrivatePlayReady final : public CDMPrivate {
public:
    CDMPrivatePlayReady();
    virtual ~CDMPrivatePlayReady();

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
  
};

class CDMInstancePlayReady final : public CDMInstance {
public:
    CDMInstancePlayReady();
    virtual ~CDMInstancePlayReady();

    ImplementationType implementationType() const final { return ImplementationType::PlayReady; }

    SuccessValue initializeWithConfiguration(const CDMKeySystemConfiguration&) override;
    SuccessValue setDistinctiveIdentifiersAllowed(bool) override;
    SuccessValue setPersistentStateAllowed(bool) override;
    SuccessValue setServerCertificate(Ref<SharedBuffer>&&) override;

    void requestLicense(LicenseType, const AtomicString& initDataType, Ref<SharedBuffer>&& initData, Ref<SharedBuffer>&& customData, LicenseCallback) override;
    void updateLicense(const String&, LicenseType, const SharedBuffer&, LicenseUpdateCallback) override;
    void loadSession(LicenseType, const String&, const String&, LoadSessionCallback) override;
    void closeSession(const String&, CloseSessionCallback) override;
    void removeSessionData(const String&, LicenseType, RemoveSessionDataCallback) override;
    void storeRecordOfKeyUsage(const String&) override;

    const String& keySystem() const final;

    struct Key {
        KeyStatus status;
        RefPtr<SharedBuffer> keyIDData;
        RefPtr<SharedBuffer> keyValueData;
    };

    enum KeyState {
        // Has been initialized.
        KEY_INIT = 0,
        // Has a key message pending to be processed.
        KEY_PENDING = 1,
        // Has a usable key.
        KEY_READY = 2,
        // Has an error.
        KEY_ERROR = 3,
        // Has been closed.
        KEY_CLOSED = 4
    };
    enum MessageType {
        LicenseRequest = 0,
        LicenseRenewal = 1,
        LicenseRelease = 2,
        IndividualizationRequest = 3
    };
    
    typedef enum SessionType {
        session_type_eTemporary = 0,
        session_type_ePersistent,
        session_type_ePersistentUsageRecord
    } SessionType;



    const Vector<Key>& keys() const { return m_keys; }

    struct CallbackInfo
    {
    	//IMediaKeySessionCallback * _callback;
	    uint16_t _compressedVideo;
	    uint16_t _uncompressedVideo;
	    uint16_t _analogVideo;
	    uint16_t _compressedAudio;
	    uint16_t _uncompressedAudio;
    };

    /*static void * PlayLevelUpdateCallback(void * data)
    {
    	CallbackInfo * callbackInfo = static_cast<CallbackInfo *>(data);
	    std::string keyMessage;
	    keyMessage << "{";
	    keyMessage << "\"compressed-video\": " << callbackInfo->_compressedVideo << ",";
	    keyMessage << "\"uncompressed-video\": " << callbackInfo->_uncompressedVideo << ",";
	    keyMessage << "\"analog-video\": " << callbackInfo->_analogVideo << ",";
	    keyMessage << "\"compressed-audio\": " << callbackInfo->_compressedAudio << ",";
	    keyMessage << "\"uncompressed-audio\": " << callbackInfo->_uncompressedAudio;
	    keyMessage << "}";

	    std::string keyMessageStr = keyMessage.c_str();
	    const uint8_t * messageBytes = reinterpret_cast<const uint8_t *>(keyMessageStr.c_str());

	    char urlBuffer[64];
	    strcpy(urlBuffer, "properties");
	    //callbackInfo->_callback->OnKeyMessage(messageBytes, keyMessageStr.length() + 1, urlBuffer);

	    delete callbackInfo;
	    return nullptr;
    }*/

    bool GenerateKeyRequest(std::string initData, SessionType type = session_type_eTemporary);
    std::string GetKeyRequestResponse(std::string url);
    bool m_valid;
    std::string m_wrmheader;
    std::string m_initData;
    std::string m_keyId;
    uint32_t m_systemCode;

private:
    WeakPtrFactory<CDMInstancePlayReady> m_weakPtrFactory;
    Vector<Key> m_keys;
    //DRM_RESULT GetKeyIdsFromHeader(DRM_CGP_HEADER_KIDS_DATA **pKIDsData);   /* Allocates memory for KeyIds; Caller is responsible for freeing them */
    //RM_RESULT DeleteStoredLicenses();

};

} // namespace WebCore

SPECIALIZE_TYPE_TRAITS_CDM_INSTANCE(WebCore::CDMInstancePlayReady, WebCore::CDMInstance::ImplementationType::PlayReady);

#endif // ENABLE(ENCRYPTED_MEDIA)
