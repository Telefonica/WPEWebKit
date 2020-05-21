/* GStreamer PlayReady common encryption decryptor
 *
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
#include "WebKitPlayReadyDecryptorGStreamer.h"


#if ENABLE(ENCRYPTED_MEDIA) && USE(GSTREAMER)

#include "SharedBuffer.h"
#include <CDMInstance.h>
#include <wtf/Condition.h>
#include <wtf/PrintStream.h>
#include <wtf/RunLoop.h>
#include <wtf/text/StringHash.h>

#include "CDMPlayReady.h"
#include "GStreamerCommon.h"
#include "GStreamerEMEUtilities.h"
#include <gcrypt.h>
#include <gst/base/gstbytereader.h>
#include <wtf/RunLoop.h>
#include <gst/gst.h>
#include <gst/base/gstbasetransform.h>

#define PLAYREADY_SIZE 16

struct Key {
    GRefPtr<GstBuffer> keyID;
    GRefPtr<GstBuffer> keyValue;
};

#define WEBKIT_MEDIA_PR_DECRYPT_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE((obj), WEBKIT_TYPE_MEDIA_PR_DECRYPT, WebKitMediaPlayReadyDecryptPrivate))
struct _WebKitMediaPlayReadyDecryptPrivate {
    Vector<Key> keys;
    gcry_cipher_hd_t handle;
};

enum SessionResult {
    InvalidSession,
    NewSession,
    OldSession
};

static void webKitMediaPlayReadyDecryptorFinalize(GObject*);
static bool webKitMediaPlayReadyDecryptorSetupCipher(WebKitMediaCommonEncryptionDecrypt*, GstBuffer*);
static bool webKitMediaPlayReadyDecryptorDecrypt(WebKitMediaCommonEncryptionDecrypt*, GstBuffer* keyIDBuffer, GstBuffer* iv, GstBuffer* sample, unsigned subSamplesCount, GstBuffer* subSamples);
static void webKitMediaPlayReadyDecryptorReleaseCipher(WebKitMediaCommonEncryptionDecrypt*);

static bool webKitMediaPlayReadyDecryptorHandleKeyId(WebKitMediaCommonEncryptionDecrypt* self, const WebCore::SharedBuffer&);
static bool webKitMediaPlayReadyDecryptorAttemptToDecryptWithLocalInstance(WebKitMediaCommonEncryptionDecrypt* self, const WebCore::SharedBuffer&);


GST_DEBUG_CATEGORY_STATIC(webkit_media_play_ready_decrypt_debug_category);
#define GST_CAT_DEFAULT webkit_media_play_ready_decrypt_debug_category

static GstStaticPadTemplate srcTemplate =
        GST_STATIC_PAD_TEMPLATE("src", GST_PAD_SRC, GST_PAD_ALWAYS,
        GST_STATIC_CAPS("video/x-h264;audio/mpeg;video/x-h265;audio/x-eac3;audio/x-gst-fourcc-ec_3"));

static GstStaticPadTemplate sinkTemplate =
        GST_STATIC_PAD_TEMPLATE("sink", GST_PAD_SINK, GST_PAD_ALWAYS,
                GST_STATIC_CAPS(
                        "application/x-cenc, original-media-type=(string)video/x-h264, protection-system=(string)" WEBCORE_GSTREAMER_EME_UTILITIES_PLAYREADY_UUID "; "
                        "application/x-cenc, original-media-type=(string)video/x-h265, protection-system=(string)" WEBCORE_GSTREAMER_EME_UTILITIES_PLAYREADY_UUID "; "
                        "application/x-cenc, original-media-type=(string)audio/x-eac3, protection-system=(string)" WEBCORE_GSTREAMER_EME_UTILITIES_PLAYREADY_UUID "; "
                        "application/x-cenc, original-media-type=(string)audio/x-gst-fourcc-ec_3, protection-system=(string)" WEBCORE_GSTREAMER_EME_UTILITIES_PLAYREADY_UUID "; "
                        "application/x-cenc, original-media-type=(string)audio/mpeg, protection-system=(string)" WEBCORE_GSTREAMER_EME_UTILITIES_PLAYREADY_UUID));

#define webkit_media_play_ready_decrypt_parent_class parent_class
G_DEFINE_TYPE(WebKitMediaPlayReadyDecrypt, webkit_media_play_ready_decrypt, WEBKIT_TYPE_MEDIA_CENC_DECRYPT);

static void webkit_media_play_ready_decrypt_class_init(WebKitMediaPlayReadyDecryptClass* klass)
{
    GST_ERROR_OBJECT(klass, "webkit_media_play_ready_decrypt_class_init");
    GObjectClass* gobjectClass = G_OBJECT_CLASS(klass);
    GstElementClass* elementClass = GST_ELEMENT_CLASS(klass);

    gobjectClass->finalize = webKitMediaPlayReadyDecryptorFinalize;

    /* Setting up pads and setting metadata should be moved to
    base_class_init if you intend to subclass this class. */

    gst_element_class_add_pad_template(elementClass, gst_static_pad_template_get(&sinkTemplate));
    gst_element_class_add_pad_template(elementClass, gst_static_pad_template_get(&srcTemplate));

    gst_element_class_set_static_metadata(elementClass,
        "Decrypt PlayReady encrypted contents",
        GST_ELEMENT_FACTORY_KLASS_DECRYPTOR,
        "Decrypts streams encrypted using PlayReady Encryption.",
	"Telefonica");

    GST_DEBUG_CATEGORY_INIT(webkit_media_play_ready_decrypt_debug_category,
        "webkitplayready", 0, "PlayReady decryptor");

    WebKitMediaCommonEncryptionDecryptClass* cencClass = WEBKIT_MEDIA_CENC_DECRYPT_CLASS(klass);
    cencClass->setupCipher = GST_DEBUG_FUNCPTR(webKitMediaPlayReadyDecryptorSetupCipher);
    cencClass->decrypt = GST_DEBUG_FUNCPTR(webKitMediaPlayReadyDecryptorDecrypt);
    cencClass->releaseCipher = GST_DEBUG_FUNCPTR(webKitMediaPlayReadyDecryptorReleaseCipher);
    cencClass->attemptToDecryptWithLocalInstance = GST_DEBUG_FUNCPTR(webKitMediaPlayReadyDecryptorDecrypt);
    cencClass->handleKeyId = GST_DEBUG_FUNCPTR(webKitMediaPlayReadyDecryptorHandleKeyId);


    g_type_class_add_private(klass, sizeof(WebKitMediaPlayReadyDecryptPrivate));
//////////////////////
}

static void webkit_media_play_ready_decrypt_init(WebKitMediaPlayReadyDecrypt* self)
{
    GST_ERROR_OBJECT(self, "webkit_media_play_ready_decrypt_init");
    WebKitMediaPlayReadyDecryptPrivate* priv = WEBKIT_MEDIA_PR_DECRYPT_GET_PRIVATE(self);

    /*self->priv = priv;
    new (priv) WebKitMediaPlayReadyDecryptPrivate();*/
    priv->~WebKitMediaPlayReadyDecryptPrivate();
}

static void webKitMediaPlayReadyDecryptorFinalize(GObject* object)
{
    GST_ERROR_OBJECT(object, "webKitMediaPlayReadyDecryptorFinalize");
    WebKitMediaPlayReadyDecrypt* self = WEBKIT_MEDIA_PR_DECRYPT(object);
    WebKitMediaPlayReadyDecryptPrivate* priv = self->priv;

    priv->~WebKitMediaPlayReadyDecryptPrivate();

    GST_CALL_PARENT(G_OBJECT_CLASS, finalize, (object));
}

static bool webKitMediaPlayReadyDecryptorSetupCipher(WebKitMediaCommonEncryptionDecrypt* self, GstBuffer* keyIDBuffer)
{
    GST_ERROR_OBJECT(self, "webKitMediaPlayReadyDecryptorSetupCipher");
    if (!keyIDBuffer) {
        GST_ERROR_OBJECT(self, "got no key id buffer");
        return false;
    }

    WebKitMediaPlayReadyDecryptPrivate* priv = WEBKIT_MEDIA_PR_DECRYPT_GET_PRIVATE(WEBKIT_MEDIA_PR_DECRYPT(self));
    gcry_error_t error;

    GRefPtr<GstBuffer> keyBuffer;
    GstMappedBuffer mappedKeyIDBuffer(keyIDBuffer, GST_MAP_READ);
    if (!mappedKeyIDBuffer) {
            GST_ERROR_OBJECT(self, "Failed to map key ID buffer");
            return false;
    }

#if ENABLE(ENCRYPTED_MEDIA)
        for (auto& key : priv->keys) {
            if (!gst_buffer_memcmp(key.keyID.get(), 0, mappedKeyIDBuffer.data(), mappedKeyIDBuffer.size())) {
                keyBuffer = key.keyValue;
                break;
            }
        }
#endif

    if (!keyBuffer) {
        GST_ERROR_OBJECT(self, "Failed to find an appropriate key buffer");
        return false;
    }

    error = gcry_cipher_open(&(priv->handle), GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (error) {
        GST_ERROR_OBJECT(self, "Failed to create AES 128 CTR cipher handle: %s", gpg_strerror(error));
        return false;
    }

    GstMappedBuffer mappedKeyBuffer(keyBuffer.get(), GST_MAP_READ);
    if (!mappedKeyBuffer) {
        GST_ERROR_OBJECT(self, "Failed to map decryption key");
        return false;
    }

    ASSERT(mappedKeyBuffer.size() == PLAYREADY_SIZE);
    error = gcry_cipher_setkey(priv->handle, mappedKeyBuffer.data(), mappedKeyBuffer.size());
    if (error) {
        GST_ERROR_OBJECT(self, "gcry_cipher_setkey failed: %s", gpg_strerror(error));
        return false;
    }

    return true;
}

static bool webKitMediaPlayReadyDecryptorDecrypt(WebKitMediaCommonEncryptionDecrypt* self, GstBuffer* keyIDBuffer, GstBuffer* ivBuffer, GstBuffer* buffer, unsigned subSampleCount, GstBuffer* subSamplesBuffer)
{
    GST_ERROR_OBJECT(self, "webKitMediaPlayReadyDecryptorDecrypt");
    UNUSED_PARAM(keyIDBuffer);
    GstMappedBuffer mappedIVBuffer(ivBuffer, GST_MAP_READ);
    if (!mappedIVBuffer) {
        GST_ERROR_OBJECT(self, "Failed to map IV");
        return false;
    }

    uint8_t ctr[PLAYREADY_SIZE];
    if (mappedIVBuffer.size() == 8) {
        memset(ctr + 8, 0, 8);
        memcpy(ctr, mappedIVBuffer.data(), 8);
    } else {
        ASSERT(mappedIVBuffer.size() == PLAYREADY_SIZE);
        memcpy(ctr, mappedIVBuffer.data(), PLAYREADY_SIZE);
    }

    WebKitMediaPlayReadyDecryptPrivate* priv = WEBKIT_MEDIA_PR_DECRYPT_GET_PRIVATE(WEBKIT_MEDIA_PR_DECRYPT(self));
    gcry_error_t error = gcry_cipher_setctr(priv->handle, ctr, PLAYREADY_SIZE);
    if (error) {
        GST_ERROR_OBJECT(self, "gcry_cipher_setctr failed: %s", gpg_strerror(error));
        return false;
    }

    GstMappedBuffer mappedBuffer(buffer, GST_MAP_READWRITE);
    if (!mappedBuffer) {
        GST_ERROR_OBJECT(self, "Failed to map buffer");
        return false;
    }

    GstMappedBuffer mappedSubsamplesBuffer(subSamplesBuffer, GST_MAP_READ);
    if (!mappedSubsamplesBuffer) {
        GST_ERROR_OBJECT(self, "Failed to map subsample buffer");
        return false;
    }

    GstByteReader* reader = gst_byte_reader_new(mappedSubsamplesBuffer.data(), mappedSubsamplesBuffer.size());
    unsigned position = 0;
    unsigned sampleIndex = 0;

    GST_DEBUG_OBJECT(self, "position: %d, size: %zu", position, mappedBuffer.size());

    while (position < mappedBuffer.size()) {
        guint16 nBytesClear = 0;
        guint32 nBytesEncrypted = 0;

        if (sampleIndex < subSampleCount) {
            if (!gst_byte_reader_get_uint16_be(reader, &nBytesClear)
                || !gst_byte_reader_get_uint32_be(reader, &nBytesEncrypted)) {
                GST_DEBUG_OBJECT(self, "unsupported");
                gst_byte_reader_free(reader);
                return false;
            }

            sampleIndex++;
        } else {
            nBytesClear = 0;
            nBytesEncrypted = mappedBuffer.size() - position;
        }

        GST_TRACE_OBJECT(self, "%d bytes clear (todo=%zu)", nBytesClear, mappedBuffer.size() - position);
        position += nBytesClear;
        if (nBytesEncrypted) {
            GST_TRACE_OBJECT(self, "%d bytes encrypted (todo=%zu)", nBytesEncrypted, mappedBuffer.size() - position);
            error = gcry_cipher_decrypt(priv->handle, mappedBuffer.data() + position, nBytesEncrypted, 0, 0);
            if (error) {
                GST_ERROR_OBJECT(self, "decryption failed: %s", gpg_strerror(error));
                gst_byte_reader_free(reader);
                return false;
            }
            position += nBytesEncrypted;
        }
    }

    gst_byte_reader_free(reader);
    return true;
}

static void webKitMediaPlayReadyDecryptorReleaseCipher(WebKitMediaCommonEncryptionDecrypt* self)
{
    GST_ERROR_OBJECT(self, "webKitMediaPlayReadyDecryptorReleaseCipher");
    WebKitMediaPlayReadyDecryptPrivate* priv = WEBKIT_MEDIA_PR_DECRYPT_GET_PRIVATE(WEBKIT_MEDIA_PR_DECRYPT(self));
    gcry_cipher_close(priv->handle);
}

static SessionResult webKitMediaPlayReadyDecryptorResetSessionFromKeyIdIfNeeded(WebKitMediaCommonEncryptionDecrypt* self, const WebCore::SharedBuffer& keyId)
{
    GST_ERROR_OBJECT(self, "webKitMediaPlaywebKitMediaPlaywebKitMediaPlayReadyDecryptorResetSessionFromKeyIdIfNeededdd");
    WebKitMediaPlayReadyDecryptPrivate* priv = WEBKIT_MEDIA_PR_DECRYPT_GET_PRIVATE(WEBKIT_MEDIA_PR_DECRYPT(self));

    RefPtr<WebCore::CDMInstance> cdmInstance = webKitMediaCommonEncryptionDecryptCDMInstance(self);
    ASSERT(cdmInstance && is<WebCore::CDMInstancePlayReady>(*cdmInstance));
    auto& cdmInstancePlayReady = downcast<WebCore::CDMInstancePlayReady>(*cdmInstance);

    SessionResult returnValue = InvalidSession;
    /*String session = cdmInstancePlayReady.sessionIdByKeyId(keyId);
    if (session.isEmpty() || !cdmInstancePlayReady.isKeyIdInSessionUsable(keyId, session)) {
        GST_DEBUG_OBJECT(self, "session %s is empty or unusable, resetting", session.utf8().data());
        priv->m_session = String();
        priv->m_openCdmSession = nullptr;
    } else if (session != priv->m_session) {
        priv->m_session = session;
        priv->m_playReadySession = nullptr;
        GST_DEBUG_OBJECT(self, "new session %s is usable", session.utf8().data());
        returnValue = NewSession;
    } else {
        GST_DEBUG_OBJECT(self, "same session %s", session.utf8().data());
        returnValue = OldSession;
    }*/

    return returnValue;
}

static bool webKitMediaPlayReadyDecryptorHandleKeyId(WebKitMediaCommonEncryptionDecrypt* self, const WebCore::SharedBuffer& keyId)
{
    return webKitMediaPlayReadyDecryptorResetSessionFromKeyIdIfNeeded(self, keyId) == InvalidSession;
}

static bool webKitMediaPlayReadyDecryptorAttemptToDecryptWithLocalInstance(WebKitMediaCommonEncryptionDecrypt* self, const WebCore::SharedBuffer& keyId)
{
    return webKitMediaPlayReadyDecryptorResetSessionFromKeyIdIfNeeded(self, keyId) != InvalidSession;
}

#endif // ENABLE(ENCRYPTED_MEDIA) && USE(GSTREAMER)
