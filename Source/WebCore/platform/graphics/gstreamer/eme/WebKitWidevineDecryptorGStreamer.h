/* GStreamer PlayReady common encryption decryptor
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
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#pragma once

#if ENABLE(ENCRYPTED_MEDIA) && USE(GSTREAMER) && USE(PLAYREADY)

#include "WebKitCommonEncryptionDecryptorGStreamer.h"

G_BEGIN_DECLS

#define WEBKIT_TYPE_MEDIA_PR_DECRYPT          (webkit_media_play_ready_decrypt_get_type())
#define WEBKIT_MEDIA_PR_DECRYPT(obj)          (G_TYPE_CHECK_INSTANCE_CAST((obj), WEBKIT_TYPE_MEDIA_PR_DECRYPT, WebKitMediaPlayReadyDecrypt))
#define WEBKIT_MEDIA_PR_DECRYPT_CLASS(klass)  (G_TYPE_CHECK_CLASS_CAST((klass), WEBKIT_TYPE_MEDIA_PR_DECRYPT, WebKitMediaPlayReadyDecryptClass))
#define WEBKIT_IS_MEDIA_PR_DECRYPT(obj)       (G_TYPE_CHECK_INSTANCE_TYPE((obj), WEBKIT_TYPE_MEDIA_PR_DECRYPT))
#define WEBKIT_IS_MEDIA_PR_DECRYPT_CLASS(obj) (G_TYPE_CHECK_CLASS_TYPE((klass), WEBKIT_TYPE_MEDIA_PR_DECRYPT))

typedef struct _WebKitMediaPlayReadyDecrypt        WebKitMediaPlayReadyDecrypt;
typedef struct _WebKitMediaPlayReadyDecryptClass   WebKitMediaPlayReadyDecryptClass;
typedef struct _WebKitMediaPlayReadyDecryptPrivate WebKitMediaPlayReadyDecryptPrivate;

GType webkit_media_play_ready_decrypt_get_type(void);

struct _WebKitMediaPlayReadyDecrypt {
    WebKitMediaCommonEncryptionDecrypt parent;

    WebKitMediaPlayReadyDecryptPrivate* priv;
};

struct _WebKitMediaPlayReadyDecryptClass {
    WebKitMediaCommonEncryptionDecryptClass parentClass;
};

G_END_DECLS

#endif // ENABLE(ENCRYPTED_MEDIA) && USE(GSTREAMER)
