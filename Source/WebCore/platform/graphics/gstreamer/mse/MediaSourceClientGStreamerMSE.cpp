/*
 * Copyright (C) 2016 Metrological Group B.V.
 * Copyright (C) 2016 Igalia S.L
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
 * You should have received a copy of the GNU Library General Public License
 * aint with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "config.h"
#include "MediaSourceClientGStreamerMSE.h"

#include "AppendPipeline.h"
#include "MediaPlayerPrivateGStreamerMSE.h"
#include "WebKitMediaSourceGStreamer.h"
#include <gst/gst.h>

GST_DEBUG_CATEGORY_EXTERN(webkit_mse_debug);
#define GST_CAT_DEFAULT webkit_mse_debug

#if ENABLE(VIDEO) && USE(GSTREAMER) && ENABLE(MEDIA_SOURCE)

namespace WebCore {

Ref<MediaSourceClientGStreamerMSE> MediaSourceClientGStreamerMSE::create(MediaPlayerPrivateGStreamerMSE& playerPrivate)
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    // No return adoptRef(new MediaSourceClientGStreamerMSE(playerPrivate)) because the ownership has already been transferred to MediaPlayerPrivateGStreamerMSE.
    Ref<MediaSourceClientGStreamerMSE> client(adoptRef(*new MediaSourceClientGStreamerMSE(playerPrivate)));
    playerPrivate.setMediaSourceClient(client.get());
    GST_TRACE("--%s()", __FUNCTION__);
    return client;
}

MediaSourceClientGStreamerMSE::MediaSourceClientGStreamerMSE(MediaPlayerPrivateGStreamerMSE& playerPrivate)
    : m_playerPrivate(&playerPrivate)
    , m_duration(MediaTime::invalidTime())
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());
    GST_TRACE("--%s()", __FUNCTION__);
}

MediaSourceClientGStreamerMSE::~MediaSourceClientGStreamerMSE()
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());
    GST_TRACE("--%s()", __FUNCTION__);
}

MediaSourcePrivate::AddStatus MediaSourceClientGStreamerMSE::addSourceBuffer(RefPtr<SourceBufferPrivateGStreamer> sourceBufferPrivate, const ContentType&)
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    if (!m_playerPrivate)
        return MediaSourcePrivate::AddStatus::NotSupported;

    ASSERT(m_playerPrivate->m_playbackPipeline);
    ASSERT(sourceBufferPrivate);

    RefPtr<AppendPipeline> appendPipeline = adoptRef(new AppendPipeline(*this, *sourceBufferPrivate, *m_playerPrivate));
    GST_TRACE("Adding SourceBuffer to AppendPipeline: this=%p sourceBuffer=%p appendPipeline=%p", this, sourceBufferPrivate.get(), appendPipeline.get());
    m_playerPrivate->m_appendPipelinesMap.add(sourceBufferPrivate, appendPipeline);

    GST_TRACE("--%s()", __FUNCTION__);
    return m_playerPrivate->m_playbackPipeline->addSourceBuffer(sourceBufferPrivate);
}

const MediaTime& MediaSourceClientGStreamerMSE::duration()
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    GST_TRACE("--%s()", __FUNCTION__);
    return m_duration;
}

void MediaSourceClientGStreamerMSE::durationChanged(const MediaTime& duration)
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    GST_TRACE("duration: %s", duration.toString().utf8().data());
    if (!duration.isValid() || duration.isNegativeInfinite())
        return;

    m_duration = duration;
    if (m_playerPrivate)
        m_playerPrivate->durationChanged();
    GST_TRACE("--%s()", __FUNCTION__);
}

void MediaSourceClientGStreamerMSE::abort(RefPtr<SourceBufferPrivateGStreamer> sourceBufferPrivate)
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    GST_DEBUG("aborting");

    if (!m_playerPrivate)
        return;

    RefPtr<AppendPipeline> appendPipeline = m_playerPrivate->m_appendPipelinesMap.get(sourceBufferPrivate);

    ASSERT(appendPipeline);

    appendPipeline->abort();
    GST_TRACE("--%s()", __FUNCTION__);
}

void MediaSourceClientGStreamerMSE::resetParserState(RefPtr<SourceBufferPrivateGStreamer> sourceBufferPrivate)
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    GST_DEBUG("resetting parser state");

    if (!m_playerPrivate)
        return;

    RefPtr<AppendPipeline> appendPipeline = m_playerPrivate->m_appendPipelinesMap.get(sourceBufferPrivate);

    ASSERT(appendPipeline);

    appendPipeline->abort();
    GST_TRACE("--%s()", __FUNCTION__);
}

bool MediaSourceClientGStreamerMSE::append(RefPtr<SourceBufferPrivateGStreamer> sourceBufferPrivate, const unsigned char* data, unsigned length)
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    GST_DEBUG("Appending %u bytes", length);

    if (!m_playerPrivate)
        return false;

    RefPtr<AppendPipeline> appendPipeline = m_playerPrivate->m_appendPipelinesMap.get(sourceBufferPrivate);

    ASSERT(appendPipeline);

    void* bufferData = fastMalloc(length);
    GstBuffer* buffer = gst_buffer_new_wrapped_full(static_cast<GstMemoryFlags>(0), bufferData, length, 0, length, bufferData, fastFree);
    gst_buffer_fill(buffer, 0, data, length);

    GST_TRACE("--%s()", __FUNCTION__);
    return appendPipeline->pushNewBuffer(buffer) == GST_FLOW_OK;
}

void MediaSourceClientGStreamerMSE::markEndOfStream(MediaSourcePrivate::EndOfStreamStatus status)
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    if (!m_playerPrivate)
        return;

    m_playerPrivate->markEndOfStream(status);
    GST_TRACE("--%s()", __FUNCTION__);
}

void MediaSourceClientGStreamerMSE::unmarkEndOfStream()
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    if (!m_playerPrivate)
        return;

    m_playerPrivate->unmarkEndOfStream();
    GST_TRACE("--%s()", __FUNCTION__);
}

void MediaSourceClientGStreamerMSE::removedFromMediaSource(RefPtr<SourceBufferPrivateGStreamer> sourceBufferPrivate)
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    if (!m_playerPrivate)
        return;

    ASSERT(m_playerPrivate->m_playbackPipeline);

    RefPtr<AppendPipeline> appendPipeline = m_playerPrivate->m_appendPipelinesMap.get(sourceBufferPrivate);

    ASSERT(appendPipeline);

    appendPipeline->clearPlayerPrivate();
    m_playerPrivate->m_appendPipelinesMap.remove(sourceBufferPrivate);
    // AppendPipeline destructor will take care of cleaning up when appropriate.

    m_playerPrivate->m_playbackPipeline->removeSourceBuffer(sourceBufferPrivate);
    GST_TRACE("--%s()", __FUNCTION__);
}

void MediaSourceClientGStreamerMSE::flush(AtomicString trackId)
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    // This is only for on-the-fly reenqueues after appends. When seeking, the seek will do its own flush.
    if (m_playerPrivate && !m_playerPrivate->m_seeking)
        m_playerPrivate->m_playbackPipeline->flush(trackId);
    GST_TRACE("--%s()", __FUNCTION__);
}

void MediaSourceClientGStreamerMSE::enqueueSample(Ref<MediaSample>&& sample)
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    if (m_playerPrivate)
        m_playerPrivate->m_playbackPipeline->enqueueSample(WTFMove(sample));
    GST_TRACE("--%s()", __FUNCTION__);
}

GRefPtr<WebKitMediaSrc> MediaSourceClientGStreamerMSE::webKitMediaSrc()
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    if (!m_playerPrivate)
        return nullptr;

    WebKitMediaSrc* source = WEBKIT_MEDIA_SRC(m_playerPrivate->m_source.get());

    ASSERT(WEBKIT_IS_MEDIA_SRC(source));

    GST_TRACE("--%s()", __FUNCTION__);
    return source;
}

void MediaSourceClientGStreamerMSE::clearPlayerPrivate()
{
    GST_TRACE("++%s()", __FUNCTION__);
    ASSERT(WTF::isMainThread());

    m_playerPrivate = nullptr;
    GST_TRACE("--%s()", __FUNCTION__);
}

} // namespace WebCore.

#endif // USE(GSTREAMER)
