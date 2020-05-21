/*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Library General Public
* License as published by the Free Software Foundation, version 2
* of the license.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Library General Public License for more details.
*
* You should have received a copy of the GNU Library General Public
* License along with this library; if not, write to the
* Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
* Boston, MA 02110-1301, USA.
*/

#include <gst/gst.h>
#include <gst/base/gstbasetransform.h>
#include "WebKitCDMDecryptor.h"

#ifndef USE_OPENCDM_ADAPTER
#include <gst/base/gstbytereader.h>
#ifdef USE_SAGE_SVP
#include "gst_brcm_svp_meta.h"
#ifdef USE_OPENCDM
#include "b_secbuf.h"

struct Rpc_Secbuf_Info {
    uint8_t *ptr;
    uint32_t type;
    size_t   size;
    void    *token;
};
#endif //USE_OPENCDM
#endif //USE_SAGE_SVP
#endif //USE_OPENCDM_ADAPTER

#include <stdio.h>

GST_DEBUG_CATEGORY_STATIC ( gst_aampcdmidecryptor_debug_category);
#define GST_CAT_DEFAULT  gst_aampcdmidecryptor_debug_category
#define DECRYPT_FAILURE_THRESHOLD 5

enum
{
    PROP_0, PROP_AAMP
};

//#define FUNCTION_DEBUG 1
#ifdef FUNCTION_DEBUG
#define DEBUG_FUNC()    g_warning("####### %s : %d ####\n", __FUNCTION__, __LINE__);
#else
#define DEBUG_FUNC()
#endif

/* prototypes */
static void gst_aampcdmidecryptor_dispose(GObject*);
static GstCaps *gst_aampcdmidecryptor_transform_caps(
        GstBaseTransform * trans, GstPadDirection direction, GstCaps * caps,
        GstCaps * filter);
static gboolean gst_aampcdmidecryptor_sink_event(GstBaseTransform * trans,
        GstEvent * event);
static GstFlowReturn gst_aampcdmidecryptor_transform_ip(
        GstBaseTransform * trans, GstBuffer * buf);
static GstStateChangeReturn gst_aampcdmidecryptor_changestate(
        GstElement* element, GstStateChange transition);
static void gst_aampcdmidecryptor_set_property(GObject * object,
        guint prop_id, const GValue * value, GParamSpec * pspec);


/* class initialization */
G_DEFINE_TYPE_WITH_CODE (GstAampCDMIDecryptor, gst_aampcdmidecryptor, GST_TYPE_BASE_TRANSFORM,
        GST_DEBUG_CATEGORY_INIT (gst_aampcdmidecryptor_debug_category, "aampcdmidecryptor", 0,
                "debug category for aampcdmidecryptor element"));


static void gst_aampcdmidecryptor_class_init(
        GstAampCDMIDecryptorClass * klass)
{
    DEBUG_FUNC();

    GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
    GstBaseTransformClass *base_transform_class = GST_BASE_TRANSFORM_CLASS(klass);

    gobject_class->set_property = gst_aampcdmidecryptor_set_property;
    gobject_class->dispose = gst_aampcdmidecryptor_dispose;

    g_object_class_install_property(gobject_class, PROP_AAMP,
            g_param_spec_pointer("aamp", "AAMP",
                    "AAMP instance to do profiling", G_PARAM_WRITABLE));

    GST_ELEMENT_CLASS(klass)->change_state =
            gst_aampcdmidecryptor_changestate;

    base_transform_class->transform_caps = GST_DEBUG_FUNCPTR(
            gst_aampcdmidecryptor_transform_caps);
    base_transform_class->sink_event = GST_DEBUG_FUNCPTR(
            gst_aampcdmidecryptor_sink_event);
    base_transform_class->transform_ip = GST_DEBUG_FUNCPTR(
            gst_aampcdmidecryptor_transform_ip);
    base_transform_class->transform_ip_on_passthrough = FALSE;

    gst_element_class_set_static_metadata(GST_ELEMENT_CLASS(klass),
            "Decrypt encrypted content with CDMi",
            GST_ELEMENT_FACTORY_KLASS_DECRYPTOR,
            "Decrypts streams encrypted using Encryption.",
            "comcast");
    //GST_DEBUG_OBJECT(aampcdmidecryptor, "Inside custom plugin init\n");
}

static void gst_aampcdmidecryptor_init(
        GstAampCDMIDecryptor *aampcdmidecryptor)
{
    DEBUG_FUNC();

    GstBaseTransform* base = GST_BASE_TRANSFORM(aampcdmidecryptor);

    gst_base_transform_set_in_place(base, TRUE);
    gst_base_transform_set_passthrough(base, FALSE);
    gst_base_transform_set_gap_aware(base, FALSE);

    g_mutex_init(&aampcdmidecryptor->mutex);
    //GST_DEBUG_OBJECT(aampcdmidecryptor, "\n Initialized plugin mutex\n");
    g_cond_init(&aampcdmidecryptor->condition);
    aampcdmidecryptor->streamReceived = false;
    aampcdmidecryptor->canWait = false;
    aampcdmidecryptor->protectionEvent = NULL;
    aampcdmidecryptor->sessionManager = NULL;
    aampcdmidecryptor->drmSession = NULL;
    aampcdmidecryptor->aamp = NULL;
    aampcdmidecryptor->streamtype = eMEDIATYPE_MANIFEST;
    aampcdmidecryptor->firstsegprocessed = false;
    aampcdmidecryptor->selectedProtection = NULL;
    aampcdmidecryptor->decryptFailCount = 0;
    aampcdmidecryptor->hdcpOpProtectionFailCount = 0;
    aampcdmidecryptor->notifyDecryptError = true;
    aampcdmidecryptor->streamEncryped = false;
    aampcdmidecryptor->ignoreSVP = false;

    //GST_DEBUG_OBJECT(aampcdmidecryptor, "******************Init called**********************\n");
}

void gst_aampcdmidecryptor_dispose(GObject * object)
{
    DEBUG_FUNC();

    GstAampCDMIDecryptor *aampcdmidecryptor =
            GST_AAMP_CDMI_DECRYPTOR(object);

    GST_DEBUG_OBJECT(aampcdmidecryptor, "dispose");

    if (aampcdmidecryptor->protectionEvent)
    {
        gst_event_unref(aampcdmidecryptor->protectionEvent);
        aampcdmidecryptor->protectionEvent = NULL;
    }

    g_mutex_clear(&aampcdmidecryptor->mutex);
    g_cond_clear(&aampcdmidecryptor->condition);

    G_OBJECT_CLASS(gst_aampcdmidecryptor_parent_class)->dispose(object);
}

/*
 Append modified caps to dest, but only if it does not already exist in updated caps.
 */
static void gst_aampcdmicapsappendifnotduplicate(GstCaps* destCaps,
        GstStructure* cap)
{
    DEBUG_FUNC();

    bool duplicate = false;
    unsigned size = gst_caps_get_size(destCaps);
    for (unsigned index = 0; !duplicate && index < size; ++index)
    {
        GstStructure* tempCap = gst_caps_get_structure(destCaps, index);
        if (gst_structure_is_equal(tempCap, cap))
            duplicate = true;
    }

    if (!duplicate)
        gst_caps_append_structure(destCaps, cap);
    else
        gst_structure_free(cap);
}

static GstCaps *
gst_aampcdmidecryptor_transform_caps(GstBaseTransform * trans,
        GstPadDirection direction, GstCaps * caps, GstCaps * filter)
{
    DEBUG_FUNC();
	GstAampCDMIDecryptor *aampcdmidecryptor = GST_AAMP_CDMI_DECRYPTOR(trans);
    g_return_val_if_fail(direction != GST_PAD_UNKNOWN, NULL);
    unsigned size = gst_caps_get_size(caps);
    GstCaps* transformedCaps = gst_caps_new_empty();

    GST_DEBUG_OBJECT(trans, "direction: %s, caps: %" GST_PTR_FORMAT " filter:"
            " %" GST_PTR_FORMAT, (direction == GST_PAD_SRC) ? "src" : "sink", caps, filter);

    if(!aampcdmidecryptor->selectedProtection)
    {
		GstStructure *capstruct = gst_caps_get_structure(caps, 0);
		const gchar* capsinfo = gst_structure_get_string(capstruct, "protection-system");
		if(!g_strcmp0(capsinfo, PLAYREADY_PROTECTION_SYSTEM_ID))
		{
			aampcdmidecryptor->selectedProtection = PLAYREADY_PROTECTION_SYSTEM_ID;
		}
		else if(!g_strcmp0(capsinfo, WIDEVINE_PROTECTION_SYSTEM_ID))
		{
			aampcdmidecryptor->selectedProtection = WIDEVINE_PROTECTION_SYSTEM_ID;
		}
		else if(!g_strcmp0(capsinfo, CLEARKEY_PROTECTION_SYSTEM_ID))
		{
			aampcdmidecryptor->selectedProtection = CLEARKEY_PROTECTION_SYSTEM_ID;
			aampcdmidecryptor->ignoreSVP = true;
		}
	}

    for (unsigned i = 0; i < size; ++i)
    {
        GstStructure* in = gst_caps_get_structure(caps, i);
        GstStructure* out = NULL;

        if (direction == GST_PAD_SRC)
        {

            out = gst_structure_copy(in);
            /* filter out the video related fields from the up-stream caps,
             because they are not relevant to the input caps of this element and
             can cause caps negotiation failures with adaptive bitrate streams */
            for (int index = gst_structure_n_fields(out) - 1; index >= 0;
                    --index)
            {
                const gchar* fieldName = gst_structure_nth_field_name(out,
                        index);

                if (g_strcmp0(fieldName, "base-profile")
                        && g_strcmp0(fieldName, "codec_data")
                        && g_strcmp0(fieldName, "height")
                        && g_strcmp0(fieldName, "framerate")
                        && g_strcmp0(fieldName, "level")
                        && g_strcmp0(fieldName, "pixel-aspect-ratio")
                        && g_strcmp0(fieldName, "profile")
                        && g_strcmp0(fieldName, "rate")
                        && g_strcmp0(fieldName, "width"))
                {
                    continue;
                } else
                {
                    gst_structure_remove_field(out, fieldName);
                    GST_TRACE_OBJECT(aampcdmidecryptor, "Removing field %s", fieldName);
                }
            }

            gst_structure_set(out, "protection-system", G_TYPE_STRING,
					aampcdmidecryptor->selectedProtection, "original-media-type",
                    G_TYPE_STRING, gst_structure_get_name(in), NULL);

            gst_structure_set_name(out, "application/x-cenc");

        } else
        {
            if (!gst_structure_has_field(in, "original-media-type"))
                continue;

            out = gst_structure_copy(in);
            gst_structure_set_name(out,
                    gst_structure_get_string(out, "original-media-type"));

            /* filter out the DRM related fields from the down-stream caps */
            for (int j = 0; j < gst_structure_n_fields(in); ++j)
            {
                const gchar* fieldName = gst_structure_nth_field_name(in, j);

                if (g_str_has_prefix(fieldName, "protection-system")
                        || g_str_has_prefix(fieldName, "original-media-type"))
                    gst_structure_remove_field(out, fieldName);
            }

        }

        gst_aampcdmicapsappendifnotduplicate(transformedCaps, out);
    }

    if (filter)
    {
        GstCaps* intersection;

        GST_LOG_OBJECT(trans, "Using filter caps %" GST_PTR_FORMAT, filter);
        intersection = gst_caps_intersect_full(transformedCaps, filter,
                GST_CAPS_INTERSECT_FIRST);
        gst_caps_unref(transformedCaps);
        transformedCaps = intersection;
    }

    GST_LOG_OBJECT(trans, "returning %" GST_PTR_FORMAT, transformedCaps);
    return transformedCaps;
}

#ifdef USE_OPENCDM_ADAPTER

static GstFlowReturn gst_aampcdmidecryptor_transform_ip(
        GstBaseTransform * trans, GstBuffer * buffer)
{
    DEBUG_FUNC();

    GstAampCDMIDecryptor *aampcdmidecryptor =
            GST_AAMP_CDMI_DECRYPTOR(trans);

    GstFlowReturn result = GST_FLOW_OK;

    guint subSampleCount;
    guint ivSize;
    gboolean encrypted;
    const GValue* value;
    GstBuffer* ivBuffer = NULL;
    GstBuffer* keyIDBuffer = NULL;
    GstBuffer* subsamplesBuffer = NULL;
    GstMapInfo subSamplesMap;
    GstProtectionMeta* protectionMeta = NULL;
    gboolean mutexLocked = FALSE;
    int errorCode;

    GST_DEBUG_OBJECT(aampcdmidecryptor, "Processing buffer");

    if (!buffer)
    {
        GST_ERROR_OBJECT(aampcdmidecryptor,"Failed to get writable buffer");
        result = GST_FLOW_NOT_SUPPORTED;
        goto free_resources;
    }

    protectionMeta =
            reinterpret_cast<GstProtectionMeta*>(gst_buffer_get_protection_meta(buffer));

    if (!protectionMeta)
    {
        GST_DEBUG_OBJECT(aampcdmidecryptor,
                "Failed to get GstProtection metadata from buffer %p, could be clear buffer",buffer);
        goto free_resources;
    }

    g_mutex_lock(&aampcdmidecryptor->mutex);
    mutexLocked = TRUE;
    GST_TRACE_OBJECT(aampcdmidecryptor,
            "Mutex acquired, stream received: %s",
            aampcdmidecryptor->streamReceived ? "yes" : "no");

    if (!aampcdmidecryptor->canWait
            && !aampcdmidecryptor->streamReceived)
    {
        result = GST_FLOW_NOT_SUPPORTED;
        goto free_resources;
    }

    if (!aampcdmidecryptor->firstsegprocessed)
    {
        GST_DEBUG_OBJECT(aampcdmidecryptor, "\n\nWaiting for key\n");
    }
    // The key might not have been received yet. Wait for it.
    if (!aampcdmidecryptor->streamReceived)
        g_cond_wait(&aampcdmidecryptor->condition,
                &aampcdmidecryptor->mutex);

    if (!aampcdmidecryptor->streamReceived)
    {
        GST_DEBUG_OBJECT(aampcdmidecryptor,
                "Condition signaled from state change transition. Aborting.");
        result = GST_FLOW_NOT_SUPPORTED;
        goto free_resources;
    }

    /* If drmSession creation failed, then the call will be aborted here */
    if (aampcdmidecryptor->drmSession == NULL)
    {
        GST_DEBUG_OBJECT(aampcdmidecryptor, "drmSession is invalid **** NULL ****. Aborting.");
        result = GST_FLOW_NOT_SUPPORTED;
        goto free_resources;
    }

    GST_TRACE_OBJECT(aampcdmidecryptor, "Got key event ; Proceeding with decryption");

    if (!gst_structure_get_uint(protectionMeta->info, "iv_size", &ivSize))
    {
        GST_ERROR_OBJECT(aampcdmidecryptor, "failed to get iv_size");
        result = GST_FLOW_NOT_SUPPORTED;
        goto free_resources;
    }

    if (!gst_structure_get_boolean(protectionMeta->info, "encrypted",
            &encrypted))
    {
        GST_ERROR_OBJECT(aampcdmidecryptor,
                "failed to get encrypted flag");
        result = GST_FLOW_NOT_SUPPORTED;
        goto free_resources;
    }

    // Unencrypted sample.
    if (!ivSize || !encrypted)
        goto free_resources;

    GST_TRACE_OBJECT(trans, "protection meta: %" GST_PTR_FORMAT, protectionMeta->info);
    if (!gst_structure_get_uint(protectionMeta->info, "subsample_count",
            &subSampleCount))
    {
        GST_ERROR_OBJECT(aampcdmidecryptor,
                "failed to get subsample_count");
        result = GST_FLOW_NOT_SUPPORTED;
        goto free_resources;
    }

    value = gst_structure_get_value(protectionMeta->info, "iv");
    if (!value)
    {
        GST_ERROR_OBJECT(aampcdmidecryptor, "Failed to get IV for sample");
        result = GST_FLOW_NOT_SUPPORTED;
        goto free_resources;
    }

    ivBuffer = gst_value_get_buffer(value);

    value = gst_structure_get_value(protectionMeta->info, "kid");
    if (!value) {
        GST_ERROR_OBJECT(aampcdmidecryptor, "Failed to get kid for sample");
        result = GST_FLOW_NOT_SUPPORTED;
        goto free_resources;
    }

    keyIDBuffer = gst_value_get_buffer(value);

    if (subSampleCount)
    {
        value = gst_structure_get_value(protectionMeta->info, "subsamples");
        if (!value)
        {
            GST_ERROR_OBJECT(aampcdmidecryptor,
                    "Failed to get subsamples");
            result = GST_FLOW_NOT_SUPPORTED;
            goto free_resources;
        }
        subsamplesBuffer = gst_value_get_buffer(value);
        if (!gst_buffer_map(subsamplesBuffer, &subSamplesMap, GST_MAP_READ))
        {
            GST_ERROR_OBJECT(aampcdmidecryptor,
                    "Failed to map subsample buffer");
            result = GST_FLOW_NOT_SUPPORTED;
            goto free_resources;
        }
    }

    errorCode = aampcdmidecryptor->drmSession->decrypt(keyIDBuffer, ivBuffer, buffer, subSampleCount, subsamplesBuffer);

    aampcdmidecryptor->streamEncryped = true;
    if (errorCode != 0 || aampcdmidecryptor->hdcpOpProtectionFailCount)
    {
	if(errorCode == HDCP_OUTPUT_PROTECTION_FAILURE)
	{
		aampcdmidecryptor->hdcpOpProtectionFailCount++;
	}
	else if(aampcdmidecryptor->hdcpOpProtectionFailCount)
	{
		if(aampcdmidecryptor->hdcpOpProtectionFailCount >= DECRYPT_FAILURE_THRESHOLD) {
			GstStructure *newmsg = gst_structure_new("HDCPProtectionFailure", "message", G_TYPE_STRING,"HDCP Output Protection Error", NULL);
			gst_element_post_message(reinterpret_cast<GstElement*>(aampcdmidecryptor),gst_message_new_application (GST_OBJECT (aampcdmidecryptor), newmsg));
		}
		aampcdmidecryptor->hdcpOpProtectionFailCount = 0;
	}
	else
	{
		GST_ERROR_OBJECT(aampcdmidecryptor, "decryption failed; error code %d\n",errorCode);
		aampcdmidecryptor->decryptFailCount++;
		if(aampcdmidecryptor->decryptFailCount >= DECRYPT_FAILURE_THRESHOLD && aampcdmidecryptor->notifyDecryptError )
		{
			aampcdmidecryptor->notifyDecryptError = false;
			GError *error;
			if(errorCode == HDCP_COMPLIANCE_CHECK_FAILURE)
			{
				// Failure - 2.2 vs 1.4 HDCP
				error = g_error_new(GST_STREAM_ERROR , GST_STREAM_ERROR_FAILED, "HDCP Compliance Check Failure");
			}
			else
			{
				error = g_error_new(GST_STREAM_ERROR , GST_STREAM_ERROR_FAILED, "Decrypt Error: code %d", errorCode);
			}
			gst_element_post_message(reinterpret_cast<GstElement*>(aampcdmidecryptor), gst_message_new_error (GST_OBJECT (aampcdmidecryptor), error, "Decrypt Failed"));
			result = GST_FLOW_ERROR;
		}
		goto free_resources;
	}
    }
    else
    {
        aampcdmidecryptor->decryptFailCount = 0;
	aampcdmidecryptor->hdcpOpProtectionFailCount = 0;
        if (aampcdmidecryptor->streamtype == eMEDIATYPE_AUDIO)
        {
            GST_DEBUG_OBJECT(aampcdmidecryptor, "Decryption successful for Audio packets");
        }
        else
        {
            GST_DEBUG_OBJECT(aampcdmidecryptor, "Decryption successful for Video packets");
        }
    }

    if (!aampcdmidecryptor->firstsegprocessed
            && aampcdmidecryptor->aamp)
    {
        if (aampcdmidecryptor->streamtype == eMEDIATYPE_VIDEO)
        {
            aampcdmidecryptor->aamp->profiler.ProfileEnd(
                    PROFILE_BUCKET_DECRYPT_VIDEO);
        } else if (aampcdmidecryptor->streamtype == eMEDIATYPE_AUDIO)
        {
            aampcdmidecryptor->aamp->profiler.ProfileEnd(
                    PROFILE_BUCKET_DECRYPT_AUDIO);
        }
        aampcdmidecryptor->firstsegprocessed = true;
    }

    free_resources:

    if (!aampcdmidecryptor->firstsegprocessed
            && aampcdmidecryptor->aamp)
    {
	if(!aampcdmidecryptor->streamEncryped)
	{
		if (aampcdmidecryptor->streamtype == eMEDIATYPE_VIDEO)
		{
			aampcdmidecryptor->aamp->profiler.ProfileEnd(
					PROFILE_BUCKET_DECRYPT_VIDEO);
		} else if (aampcdmidecryptor->streamtype == eMEDIATYPE_AUDIO)
		{
			aampcdmidecryptor->aamp->profiler.ProfileEnd(
					PROFILE_BUCKET_DECRYPT_AUDIO);
		}
	}
	else
	{
		if (aampcdmidecryptor->streamtype == eMEDIATYPE_VIDEO)
		{
			aampcdmidecryptor->aamp->profiler.ProfileError(PROFILE_BUCKET_DECRYPT_VIDEO, (int)result);
		} else if (aampcdmidecryptor->streamtype == eMEDIATYPE_AUDIO)
		{
			aampcdmidecryptor->aamp->profiler.ProfileError(PROFILE_BUCKET_DECRYPT_AUDIO, (int)result);
		}
	}
	    aampcdmidecryptor->firstsegprocessed = true;
    }

    if (subsamplesBuffer)
        gst_buffer_unmap(subsamplesBuffer, &subSamplesMap);

    if (protectionMeta)
        gst_buffer_remove_meta(buffer,
                reinterpret_cast<GstMeta*>(protectionMeta));

    if (mutexLocked)
        g_mutex_unlock(&aampcdmidecryptor->mutex);
    return result;
}

#else

	static void gst_add_svp_meta_data(GstBuffer* gstBuffer, uint8_t* pOpaqueData, uint32_t cbData, guint subSampleCount, GstByteReader* reader)
	{
	#ifdef USE_SAGE_SVP
	    brcm_svp_meta_data_t *  ptr         = (brcm_svp_meta_data_t *) g_malloc(sizeof(brcm_svp_meta_data_t));
	    svp_chunk_info *        ci          = NULL;
	    uint32_t                clear_start = 0;
	    guint16                 nBytesClear = 0;
	    guint32                 nBytesEncrypted = 0;

	    if (ptr)
	    {
	        // Reset reader position
	        gst_byte_reader_set_pos(reader, 0);
	        // Set up SVP meta data.
	        memset((uint8_t *)ptr, 0, sizeof(brcm_svp_meta_data_t));
	        ptr->sub_type = GST_META_BRCM_SVP_TYPE_2;
	        ptr->u.u2.secbuf_ptr = reinterpret_cast<unsigned int>(pOpaqueData);
	        ptr->u.u2.chunks_cnt = subSampleCount;
	        //printf("%s  secure data = %p user buff size %d chunks = %d\n", __FUNCTION__, ptr->u.u2.secbuf_ptr, cbData, ptr->u.u2.chunks_cnt);
	        if (subSampleCount)
	        {
	            ci = (svp_chunk_info *)g_malloc(subSampleCount * sizeof(svp_chunk_info));
	            ptr->u.u2.chunk_info = ci;
	            for (int i = 0; i < subSampleCount; i++)
	            {
	                if (!gst_byte_reader_get_uint16_be(reader, &nBytesClear)
	                        || !gst_byte_reader_get_uint32_be(reader, &nBytesEncrypted))
	                {
	                    // fail
	                    printf("%s ---- ERROR ----  Failed to acquire subsample data at index %d (%d, %d)\n",
	                            __FUNCTION__, i, nBytesClear, nBytesEncrypted);
	                    break;
	                }
	                ci[i].clear_size = nBytesClear;
	                ci[i].encrypted_size = nBytesEncrypted;
	                //printf("%s chunk %d clear size %d encrypted size %d\n", __FUNCTION__, i, ci[i].clear_size, ci[i].encrypted_size);
	            }
	        }
	        else {
	            // the SVP data is the whole buffer
	            ptr->u.u2.chunks_cnt = 1;
	            ci = (svp_chunk_info *)g_malloc( sizeof(svp_chunk_info));
	            ptr->u.u2.chunk_info = ci;
	            ci[0].clear_size = 0;
	            ci[0].encrypted_size = cbData;
	            //printf("%s single buffer -> clear size %d encrypted size %d\n", __FUNCTION__, ci[0].clear_size, ci[0].encrypted_size);
	        }
	    }
	    gst_buffer_add_brcm_svp_meta(gstBuffer, ptr);

	#else
	    printf("%s USE_SAGE_SVP not defined\n", __FUNCTION__);
	#endif

	    return;
	}

	static GstFlowReturn gst_aampcdmidecryptor_transform_ip(
	        GstBaseTransform * trans, GstBuffer * buffer)
	{
	    DEBUG_FUNC();

	    GstAampCDMIDecryptor *aampcdmidecryptor =
	            GST_AAMP_CDMI_DECRYPTOR(trans);

	    GstFlowReturn result = GST_FLOW_OK;

	    GstMapInfo map, ivMap;
	    unsigned position = 0;
	    guint subSampleCount;
	    guint ivSize;
	    gboolean encrypted;
	    const GValue* value;
	    GstBuffer* ivBuffer = NULL;
	    GstBuffer* subsamplesBuffer = NULL;
	    GstMapInfo subSamplesMap;
	    GstByteReader* reader = NULL;
	    GstProtectionMeta* protectionMeta = NULL;
	    gboolean bufferMapped = FALSE;
	    gboolean mutexLocked = FALSE;
	    int errorCode;
	    int i;
	    guint16 nBytesClear = 0;
	    guint32 nBytesEncrypted = 0;
	    gpointer pbData = NULL;
	    uint32_t cbData = 0;
	    uint8_t * pOpaqueData = NULL;

	    GST_DEBUG_OBJECT(aampcdmidecryptor, "Processing buffer");

	    if (!buffer)
	    {
	        GST_ERROR_OBJECT(aampcdmidecryptor,"Failed to get writable buffer");
	        result = GST_FLOW_NOT_SUPPORTED;
	        goto free_resources;
	    }

	    protectionMeta =
	            reinterpret_cast<GstProtectionMeta*>(gst_buffer_get_protection_meta(buffer));

	    if (!protectionMeta)
	    {
	        GST_DEBUG_OBJECT(aampcdmidecryptor,
	                "Failed to get GstProtection metadata from buffer %p, could be clear buffer",buffer);
	        goto free_resources;
	    }

	    g_mutex_lock(&aampcdmidecryptor->mutex);
	    mutexLocked = TRUE;
	    GST_TRACE_OBJECT(aampcdmidecryptor,
	            "Mutex acquired, stream received: %s",
	            aampcdmidecryptor->streamReceived ? "yes" : "no");

	    if (!aampcdmidecryptor->canWait
	            && !aampcdmidecryptor->streamReceived)
	    {
	        result = GST_FLOW_NOT_SUPPORTED;
	        goto free_resources;
	    }

	    if (!aampcdmidecryptor->firstsegprocessed)
	    {
	        GST_DEBUG_OBJECT(aampcdmidecryptor, "\n\nWaiting for key\n");
	    }
	    // The key might not have been received yet. Wait for it.
	    if (!aampcdmidecryptor->streamReceived)
	        g_cond_wait(&aampcdmidecryptor->condition,
	                &aampcdmidecryptor->mutex);

	    if (!aampcdmidecryptor->streamReceived)
	    {
	        GST_DEBUG_OBJECT(aampcdmidecryptor,
	                "Condition signaled from state change transition. Aborting.");
	        result = GST_FLOW_NOT_SUPPORTED;
	        goto free_resources;
	    }

    /* If drmSession creation failed, then the call will be aborted here */
    if (aampcdmidecryptor->drmSession == NULL)
    {
        GST_DEBUG_OBJECT(aampcdmidecryptor, "drmSession is invalid **** NULL ****. Aborting.");
        result = GST_FLOW_NOT_SUPPORTED;
        goto free_resources;
    }

	    GST_TRACE_OBJECT(aampcdmidecryptor, "Got key event ; Proceeding with decryption");

	    bufferMapped = gst_buffer_map(buffer, &map,
	            static_cast<GstMapFlags>(GST_MAP_READWRITE));
	    if (!bufferMapped)
	    {
	        GST_ERROR_OBJECT(aampcdmidecryptor, "Failed to map buffer");
	        result = GST_FLOW_NOT_SUPPORTED;
	        goto free_resources;
	    }

	    if (!gst_structure_get_uint(protectionMeta->info, "iv_size", &ivSize))
	    {
	        GST_ERROR_OBJECT(aampcdmidecryptor, "failed to get iv_size");
	        result = GST_FLOW_NOT_SUPPORTED;
	        goto free_resources;
	    }

	    if (!gst_structure_get_boolean(protectionMeta->info, "encrypted",
	            &encrypted))
	    {
	        GST_ERROR_OBJECT(aampcdmidecryptor,
	                "failed to get encrypted flag");
	        result = GST_FLOW_NOT_SUPPORTED;
	        goto free_resources;
	    }

	    // Unencrypted sample.
	    if (!ivSize || !encrypted)
	        goto free_resources;

	    GST_TRACE_OBJECT(trans, "protection meta: %" GST_PTR_FORMAT, protectionMeta->info);
	    if (!gst_structure_get_uint(protectionMeta->info, "subsample_count",
	            &subSampleCount))
	    {
	        GST_ERROR_OBJECT(aampcdmidecryptor,
	                "failed to get subsample_count");
	        result = GST_FLOW_NOT_SUPPORTED;
	        goto free_resources;
	    }

	    value = gst_structure_get_value(protectionMeta->info, "iv");
	    if (!value)
	    {
	        GST_ERROR_OBJECT(aampcdmidecryptor, "Failed to get IV for sample");
	        result = GST_FLOW_NOT_SUPPORTED;
	        goto free_resources;
	    }

	    ivBuffer = gst_value_get_buffer(value);
	    if (!gst_buffer_map(ivBuffer, &ivMap, GST_MAP_READ))
	    {
	        GST_ERROR_OBJECT(aampcdmidecryptor, "Failed to map IV");
	        result = GST_FLOW_NOT_SUPPORTED;
	        goto free_resources;
	    }

	    if (subSampleCount)
	    {
	        value = gst_structure_get_value(protectionMeta->info, "subsamples");
	        if (!value)
	        {
	            GST_ERROR_OBJECT(aampcdmidecryptor,
	                    "Failed to get subsamples");
	            result = GST_FLOW_NOT_SUPPORTED;
	            goto free_resources;
	        }
	        subsamplesBuffer = gst_value_get_buffer(value);
	        if (!gst_buffer_map(subsamplesBuffer, &subSamplesMap, GST_MAP_READ))
	        {
	            GST_ERROR_OBJECT(aampcdmidecryptor,
	                    "Failed to map subsample buffer");
	            result = GST_FLOW_NOT_SUPPORTED;
	            goto free_resources;
	        }
	    }

	    reader = gst_byte_reader_new(subSamplesMap.data, subSamplesMap.size);
	    if (!reader)
	    {
	        GST_ERROR_OBJECT(aampcdmidecryptor,
	                "Failed to allocate subsample reader");
	        result = GST_FLOW_NOT_SUPPORTED;
	        goto free_resources;
	    }

	    GST_TRACE_OBJECT(aampcdmidecryptor, "position: %d, size: %d", position,
	            map.size);

	    // collect all the encrypted bytes into one contiguous buffer
	    // we need to call decrypt once for all encrypted bytes.
	    if (subSampleCount > 0)
	    {
	        pbData = g_malloc0(map.size);
	        uint8_t *pbCurrTarget = (uint8_t *) pbData;

	        uint32_t iCurrSource = 0;

	        for (i = 0; i < subSampleCount; i++)
	        {
	            if (!gst_byte_reader_get_uint16_be(reader, &nBytesClear)
	                    || !gst_byte_reader_get_uint32_be(reader, &nBytesEncrypted))
	            {
	                result = GST_FLOW_NOT_SUPPORTED;
	                GST_INFO_OBJECT(aampcdmidecryptor, "unsupported");
	                goto free_resources;
	            }
	            // Skip the clear byte range from source buffer.
	            iCurrSource += nBytesClear;

	            // Copy cipher bytes from f_pbData to target buffer.
	            memcpy(pbCurrTarget, (uint8_t*)map.data + iCurrSource, nBytesEncrypted);

	            // Adjust current pointer of target buffer.
	            pbCurrTarget += nBytesEncrypted;

	            // Adjust current offset of source buffer.
	            iCurrSource += nBytesEncrypted;
	            cbData += nBytesEncrypted;
	        }
	    } else
	    {
	        cbData = map.size;
	        pbData = map.data;
	    }

	    if (cbData == 0)
	    {
		// Free resources for unencrypted bytes.
	        goto free_resources;
	    }

	    //TODO fixme
	    /*errorCode = aampcdmidecryptor->drmSession->decrypt(
	            static_cast<uint8_t *>(ivMap.data), static_cast<uint32_t>(ivMap.size),
	            (uint8_t *)pbData, cbData, &pOpaqueData);*/
	    errorCode=0;
	    if (errorCode != 0 && aampcdmidecryptor->hdcpOpProtectionFailCount)
	    {

			if(errorCode == HDCP_OUTPUT_PROTECTION_FAILURE)
			{
				aampcdmidecryptor->hdcpOpProtectionFailCount++;
			}
			else if(aampcdmidecryptor->hdcpOpProtectionFailCount)
			{
				if(aampcdmidecryptor->hdcpOpProtectionFailCount >= DECRYPT_FAILURE_THRESHOLD) {
					GstStructure *newmsg = gst_structure_new("HDCPProtectionFailure", "message", G_TYPE_STRING,"HDCP Output Protection Error", NULL);
					gst_element_post_message(reinterpret_cast<GstElement*>(aampcdmidecryptor),gst_message_new_application (GST_OBJECT (aampcdmidecryptor), newmsg));
				}
				aampcdmidecryptor->hdcpOpProtectionFailCount = 0;
			}
			else
			{
				GST_ERROR_OBJECT(aampcdmidecryptor, "decryption failed; error code %d\n",errorCode);
				aampcdmidecryptor->decryptFailCount++;
				if(aampcdmidecryptor->decryptFailCount >= DECRYPT_FAILURE_THRESHOLD && aampcdmidecryptor->notifyDecryptError )
				{
					aampcdmidecryptor->notifyDecryptError = false;
					GError *error;
					if(errorCode == HDCP_COMPLIANCE_CHECK_FAILURE)
					{
						// Failure - 2.2 vs 1.4 HDCP
						error = g_error_new(GST_STREAM_ERROR , GST_STREAM_ERROR_FAILED, "HDCP Compliance Check Failure");
					}
					else
					{
						error = g_error_new(GST_STREAM_ERROR , GST_STREAM_ERROR_FAILED, "Decrypt Error: code %d", errorCode);
					}
					gst_element_post_message(reinterpret_cast<GstElement*>(aampcdmidecryptor), gst_message_new_error (GST_OBJECT (aampcdmidecryptor), error, "Decrypt Failed"));
					result = GST_FLOW_ERROR;
				}
				goto free_resources;
			}
	    }
	    else
	    {
	        aampcdmidecryptor->decryptFailCount = 0;
		aampcdmidecryptor->hdcpOpProtectionFailCount = 0;
	        if (aampcdmidecryptor->streamtype == eMEDIATYPE_AUDIO)
	        {
	            GST_DEBUG_OBJECT(aampcdmidecryptor, "Decryption successful for Audio packets");
	        }
	        else
	        {
	            GST_DEBUG_OBJECT(aampcdmidecryptor, "Decryption successful for Video packets");
	        }
	    }

	    if (!aampcdmidecryptor->firstsegprocessed
	            && aampcdmidecryptor->aamp)
	    {
	        if (aampcdmidecryptor->streamtype == eMEDIATYPE_VIDEO)
	        {
	            aampcdmidecryptor->aamp->profiler.ProfileEnd(
	                    PROFILE_BUCKET_DECRYPT_VIDEO);
	        } else if (aampcdmidecryptor->streamtype == eMEDIATYPE_AUDIO)
	        {
	            aampcdmidecryptor->aamp->profiler.ProfileEnd(
	                    PROFILE_BUCKET_DECRYPT_AUDIO);
	        }
	        aampcdmidecryptor->firstsegprocessed = true;
	    }

	    if(pOpaqueData)
	    {
	#if defined(USE_SAGE_SVP) && defined(USE_OPENCDM)
			//Need the real size for the following call.
			cbData -= sizeof(Rpc_Secbuf_Info);
	#endif
	        // If there is opaque data then SVP is enabled and append
	        // the sample buffer with the SVP data.  There is no encryped
	        // data that can be copied back into host memory

	        gst_add_svp_meta_data(buffer, pOpaqueData, cbData, subSampleCount, reader);
	    }
	    else if (subSampleCount > 0)
	    {
	        // If subsample mapping is used, copy decrypted bytes back
	        // to the original buffer.
	        gst_byte_reader_set_pos(reader, 0);

	        uint8_t *pbCurrTarget = map.data;
	        uint32_t iCurrSource = 0;

	        for (int i = 0; i < subSampleCount; i++)
	        {
	            if (!gst_byte_reader_get_uint16_be(reader, &nBytesClear)
	                    || !gst_byte_reader_get_uint32_be(reader, &nBytesEncrypted))
	            {
	                result = GST_FLOW_NOT_SUPPORTED;
	                GST_INFO_OBJECT(aampcdmidecryptor, "unsupported");
	                goto free_resources;
	            }
	            // Skip the clear byte range from target buffer.
	            pbCurrTarget += nBytesClear;

	            //gst_util_dump_mem(pbData,cbData);
	            // Copy decrypted bytes from pbData to target buffer.
	            memcpy(pbCurrTarget, (uint8_t*)pbData + iCurrSource, nBytesEncrypted);

	            // Adjust current pointer of target buffer.
	            pbCurrTarget += nBytesEncrypted;

	            // Adjust current offset of source buffer.
	            iCurrSource += nBytesEncrypted;
	        }
	    }

	    free_resources:

	    if (!aampcdmidecryptor->firstsegprocessed
	            && aampcdmidecryptor->aamp)
	    {
           if (aampcdmidecryptor->streamtype == eMEDIATYPE_VIDEO)
           {
               aampcdmidecryptor->aamp->profiler.ProfileError(PROFILE_BUCKET_DECRYPT_VIDEO, (int)result);
           }
           else if (aampcdmidecryptor->streamtype == eMEDIATYPE_AUDIO)
           {
               aampcdmidecryptor->aamp->profiler.ProfileError(PROFILE_BUCKET_DECRYPT_AUDIO, (int)result);
           }
	       aampcdmidecryptor->firstsegprocessed = true;
        }

	    if (bufferMapped)
	        gst_buffer_unmap(buffer, &map);

	    if (reader)
	        gst_byte_reader_free(reader);

	    if (subsamplesBuffer)
	        gst_buffer_unmap(subsamplesBuffer, &subSamplesMap);

	    if (ivBuffer)
	        gst_buffer_unmap(ivBuffer, &ivMap);

	    if (protectionMeta)
	        gst_buffer_remove_meta(buffer,
	                reinterpret_cast<GstMeta*>(protectionMeta));

	#if defined(USE_SAGE_SVP) && defined(USE_OPENCDM)
	    if ((pbData && !(aampcdmidecryptor->ignoreSVP)) || (subSampleCount > 0 ))
	        g_free(pbData);
	#else
	    if (subSampleCount > 0)
	        g_free(pbData);
	#endif
	    if (mutexLocked)
	        g_mutex_unlock(&aampcdmidecryptor->mutex);
	    return result;
	}

#endif



static GstStateChangeReturn gst_aampcdmidecryptor_changestate(
        GstElement* element, GstStateChange transition)
{
    DEBUG_FUNC();

    GstStateChangeReturn ret = GST_STATE_CHANGE_SUCCESS;
    GstAampCDMIDecryptor* aampcdmidecryptor =
            GST_AAMP_CDMI_DECRYPTOR(element);

    switch (transition)
    {
    case GST_STATE_CHANGE_READY_TO_PAUSED:
        GST_DEBUG_OBJECT(aampcdmidecryptor, "READY->PAUSED");
        g_mutex_lock(&aampcdmidecryptor->mutex);
        aampcdmidecryptor->canWait = true;
        g_mutex_unlock(&aampcdmidecryptor->mutex);
        break;
    case GST_STATE_CHANGE_PAUSED_TO_READY:
        GST_DEBUG_OBJECT(aampcdmidecryptor, "PAUSED->READY");
        g_mutex_lock(&aampcdmidecryptor->mutex);
        aampcdmidecryptor->canWait = false;
        g_cond_signal(&aampcdmidecryptor->condition);
        g_mutex_unlock(&aampcdmidecryptor->mutex);
        break;
    default:
        break;
    }

    ret =
            GST_ELEMENT_CLASS(gst_aampcdmidecryptor_parent_class)->change_state(
                    element, transition);
    return ret;
}

static void gst_aampcdmidecryptor_set_property(GObject * object,
        guint prop_id, const GValue * value, GParamSpec * pspec)
{
    DEBUG_FUNC();

    GstAampCDMIDecryptor* aampcdmidecryptor =
            GST_AAMP_CDMI_DECRYPTOR(object);
    switch (prop_id)
    {
    case PROP_AAMP:
        GST_OBJECT_LOCK(aampcdmidecryptor);
        aampcdmidecryptor->aamp =
                (PrivateInstanceAAMP*) g_value_get_pointer(value);
        GST_DEBUG_OBJECT(aampcdmidecryptor,
                "Received aamp instance from appsrc\n");
        GST_OBJECT_UNLOCK(aampcdmidecryptor);
        break;

    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

