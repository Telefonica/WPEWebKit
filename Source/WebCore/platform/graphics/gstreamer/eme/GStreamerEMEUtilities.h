/* GStreamer EME Utilities class
 *
 * Copyright (C) 2017 Metrological
 * Copyright (C) 2017 Igalia S.L
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

#if ENABLE(ENCRYPTED_MEDIA) && USE(GSTREAMER)

#include "GStreamerCommon.h"
#include <gst/gst.h>
#include <wtf/text/WTFString.h>
#include <array>
#include <wtf/Seconds.h>
#include <wtf/MD5.h>
#include <wtf/text/Base64.h>

#define WEBCORE_GSTREAMER_EME_UTILITIES_CLEARKEY_UUID  "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b"
#define WEBCORE_GSTREAMER_EME_UTILITIES_PLAYREADY_UUID "9a04f079-9840-4286-ab92-e65be0885f95"
#define WEBCORE_GSTREAMER_EME_UTILITIES_WIDEVINE_UUID  "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"

// NOTE: YouTube 2018 EME conformance tests expect this to be >=5s.
const WTF::Seconds WEBCORE_GSTREAMER_EME_LICENSE_KEY_RESPONSE_TIMEOUT = WTF::Seconds(6);

namespace WebCore {

using InitData = String;

class GStreamerEMEUtilities {

public:
    static constexpr char const* s_ClearKeyUUID = WEBCORE_GSTREAMER_EME_UTILITIES_CLEARKEY_UUID;
    static constexpr char const* s_ClearKeyKeySystem = "org.w3.clearkey";

    static constexpr char const* s_PlayReadyUUID = WEBCORE_GSTREAMER_EME_UTILITIES_PLAYREADY_UUID;
    static constexpr char const* s_PlayReadyKeySystemMS = "com.microsoft.playready";
    static constexpr char const* s_PlayReadyKeySystemYT = "com.youtube.playready";

    static constexpr char const* s_WidevineUUID = WEBCORE_GSTREAMER_EME_UTILITIES_WIDEVINE_UUID;
    static constexpr char const* s_WidevineKeySystem = "com.widevine.alpha";

    static constexpr char const* s_UnspecifiedUUID = GST_PROTECTION_UNSPECIFIED_SYSTEM_ID;
    static constexpr char const* s_UnspecifiedKeySystem = "org.webkit.unspecifiedkeysystem";

    static bool isClearKeyKeySystem(const String& keySystem)
    {
        return equalIgnoringASCIICase(keySystem, s_ClearKeyKeySystem);
    }

    static bool isUnspecifiedKeySystem(const String& keySystem)
    {
        return equalIgnoringASCIICase(keySystem, s_UnspecifiedKeySystem);
    }

    static bool isPlayReadyKeySystem(const String& keySystem)
    {
        return equalIgnoringASCIICase(keySystem, s_PlayReadyKeySystemMS)
            || equalIgnoringASCIICase(keySystem, s_PlayReadyKeySystemYT);
    }
    static bool isWidevineKeySystem(const String& keySystem)
    {
        return equalIgnoringASCIICase(keySystem, s_WidevineKeySystem);
    }

    static const char* keySystemToUuid(const String& keySystem)
    {
        if (isClearKeyKeySystem(keySystem))
            return s_ClearKeyUUID;

        if (isUnspecifiedKeySystem(keySystem))
            return s_WidevineUUID;

        if (isPlayReadyKeySystem(keySystem))
            return s_PlayReadyUUID;

        if (isWidevineKeySystem(keySystem))
            return s_WidevineUUID;

        ASSERT_NOT_REACHED();
        return { };
    }

    static const char* uuidToKeySystem(const String& uuid)
    {
        if (uuid == s_ClearKeyUUID)
            return s_ClearKeyKeySystem;

        if (uuid == s_UnspecifiedUUID)
            return s_WidevineKeySystem;

        if (uuid == s_PlayReadyUUID)
            return s_PlayReadyKeySystemMS;

        if (uuid == s_WidevineUUID)
            return s_WidevineKeySystem;

        ASSERT_NOT_REACHED();
        return nullptr;
    }

#if (!defined(GST_DISABLE_GST_DEBUG))
static String initDataMD5(const InitData& initData) {
    WTF::MD5 md5;
    md5.addBytes(static_cast<const uint8_t*>(initData.characters8()), initData.length());

    WTF::MD5::Digest digest;
    md5.checksum(digest);

    return WTF::base64URLEncode(&digest[0], WTF::MD5::hashSize);
}
#endif
};

}

#endif // ENABLE(ENCRYPTED_MEDIA) && USE(GSTREAMER)
