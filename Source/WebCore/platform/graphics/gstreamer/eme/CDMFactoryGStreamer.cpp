/*
 * Copyright (C) 2016 Metrological Group B.V.
 * Copyright (C) 2016 Igalia S.L.
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

#include "config.h"
#include "CDMFactory.h"


#if ENABLE(ENCRYPTED_MEDIA)

#include "CDMProxy.h"

#if ENABLE(THUNDER)
#include "CDMThunder.h"
#endif

#if ENABLE(CLEARKEY)
#include "CDMClearKey.h"
#endif

#if ENABLE(OPENCDM)
#include "CDMOpenCDM.h"
#endif

namespace WebCore {

void CDMFactory::platformRegisterFactories(Vector<CDMFactory*>& factories)
{
#if ENABLE(THUNDER)
    factories.append(&CDMFactoryThunder::singleton());
    GST_DEBUG("THUNDER CDM factory added");
#else

#if ENABLE(CLEARKEY)
    factories.append(&CDMFactoryClearKey::singleton());
    GST_DEBUG("CLEARKEY CDM factory added");
#endif

#if ENABLE(OPENCDM)
    factories.append(&CDMFactoryOpenCDM::singleton());
    GST_DEBUG("OPENCDM CDM factory added");
#endif

#if !ENABLE(CLEARKEY) && !ENABLE(OPENCDM)
    UNUSED_PARAM(factories);
#endif

#endif
}

Vector<CDMProxyFactory*> CDMProxyFactory::platformRegisterFactories()
{
    Vector<CDMProxyFactory*> factories;
#if ENABLE(THUNDER)
    factories.reserveInitialCapacity(1);
    factories.uncheckedAppend(&CDMFactoryThunder::singleton());
    GST_DEBUG("THUNDER CDM factory added unchecked");
#else
    int num_factories=0;

#if ENABLE(CLEARKEY)
    ++num_factories;
#endif

#if ENABLE(OPENCDM)
    ++num_factories;
#endif

    if(num_factories>0){
         factories.reserveInitialCapacity(num_factories);
    }

#if ENABLE(CLEARKEY)
    factories.uncheckedAppend(&CDMFactoryClearKey::singleton());
    GST_DEBUG("CLEARKEY CDM factory added unchecked");
#endif

#if ENABLE(OPENCDM)
    factories.uncheckedAppend(&CDMFactoryOpenCDM::singleton());
    GST_DEBUG("OPENCDM CDM factory added unchecked");
#endif

#endif
    return factories;
}

} // namespace WebCore

#endif // ENABLE(ENCRYPTED_MEDIA)
