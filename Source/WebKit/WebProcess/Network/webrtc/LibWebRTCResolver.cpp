/*
 * Copyright (C) 2017 Apple Inc. All rights reserved.
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
#include "LibWebRTCResolver.h"

#if USE(LIBWEBRTC)

#include "LibWebRTCNetwork.h"
#include "NetworkProcessConnection.h"
#include "NetworkRTCProviderMessages.h"
#include "WebProcess.h"
#include <wtf/MainThread.h>

namespace WebKit {

void LibWebRTCResolver::sendOnMainThread(Function<void(IPC::Connection&)>&& callback)
{
    callOnMainRunLoop([callback = WTFMove(callback)]() {
        callback(WebProcess::singleton().ensureNetworkProcessConnection().connection());
    });
}

void LibWebRTCResolver::Start(const rtc::SocketAddress& address,
                     absl::AnyInvocable<void()> callback)
{
    m_isResolving = true;
    m_addressToResolve = address;
    m_port = address.port();

    sendOnMainThread([identifier = m_identifier, address](IPC::Connection& connection) {
        auto addressString = address.HostAsURIString();
        connection.send(Messages::NetworkRTCProvider::CreateResolver(identifier, String(addressString.data(), addressString.length())), 0);
    });
}

void LibWebRTCResolver::Start(const rtc::SocketAddress& addr,
                     int family,
                     absl::AnyInvocable<void()> callback)
{
    // TBI
}

class MyAsyncDnsResolverResult: public webrtc::AsyncDnsResolverResult
{
public:

    int m_error = 0;

    virtual bool GetResolvedAddress(int family,
                                  rtc::SocketAddress* addr) const final
    {
        return true;
    }

    // Returns error from resolver.
    virtual int GetError() const final
    {
        return m_error;
    }


};

const webrtc::AsyncDnsResolverResult& LibWebRTCResolver::result() const
{
    // TBI
    // ACF ??
    return MyAsyncDnsResolverResult{};
}

void LibWebRTCResolver::doDestroy()
{
    // Let's take the resolver so that it gets destroyed at the end of this function.
    auto resolver = WebProcess::singleton().libWebRTCNetwork().socketFactory().takeResolver(m_identifier);
    ASSERT(resolver);
}

void LibWebRTCResolver::setResolvedAddress(const Vector<rtc::IPAddress>& addresses)
{
    m_addresses = addresses;
    m_isProvidingResults = true;
    //SignalDone(this);
    m_isProvidingResults = false;
    if (m_shouldDestroy)
        doDestroy();
}

void LibWebRTCResolver::setError(int error)
{
    m_error = error;
    m_isProvidingResults = true;
    //SignalDone(this);
    m_isProvidingResults = false;
    if (m_shouldDestroy)
        doDestroy();
}

} // namespace WebKit

#endif // USE(LIBWEBRTC)
