/*
 * Copyright (C) 2016 Apple Inc. All rights reserved.
 * Copyright (C) 2017 Metrological Group B.V.
 * Copyright (C) 2017 Igalia S.L.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "CDMFactory.h"

#if ENABLE(ENCRYPTED_MEDIA)

#include <mutex>
#include <wtf/NeverDestroyed.h>
#include <wtf/Vector.h>

namespace WebCore {

Vector<CDMFactory*>& CDMFactory::registeredFactories()
{
    printf("[%s:%d] ++%s()\n", __FILE__, __LINE__, __func__);
    static NeverDestroyed<Vector<CDMFactory*>> factories;
    static std::once_flag once;
    std::call_once(once, [&] { platformRegisterFactories(factories); });

    printf("--%s()\n", __func__);
    return factories;
}

void CDMFactory::registerFactory(CDMFactory& factory)
{
    printf("[%s:%d] ++%s()\n", __FILE__, __LINE__, __func__);
    ASSERT(!registeredFactories().contains(&factory));
    registeredFactories().append(&factory);
    printf("--%s()\n", __func__);
}

void CDMFactory::unregisterFactory(CDMFactory& factory)
{
    printf("[%s:%d] ++%s()\n", __FILE__, __LINE__, __func__);
    ASSERT(registeredFactories().contains(&factory));
    registeredFactories().removeAll(&factory);
    printf("--%s()\n", __func__);
}

#if !USE(GSTREAMER)
void CDMFactory::platformRegisterFactories()
{
}
#endif

} // namespace WebCore

#endif // ENABLE(ENCRYPTED_MEDIA)
