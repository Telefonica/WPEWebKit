/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 * Copyright (C) 2015-2017 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "InspectorPageAgent.h"

#include "CachedCSSStyleSheet.h"
#include "CachedFont.h"
#include "CachedImage.h"
#include "CachedResource.h"
#include "CachedResourceLoader.h"
#include "CachedScript.h"
#include "Cookie.h"
#include "CookieJar.h"
#include "DOMWrapperWorld.h"
#include "Document.h"
#include "DocumentLoader.h"
#include "Frame.h"
#include "FrameLoadRequest.h"
#include "FrameLoader.h"
#include "FrameSnapshotting.h"
#include "FrameView.h"
#include "HTMLFrameOwnerElement.h"
#include "HTMLNames.h"
#include "ImageBuffer.h"
#include "InspectorClient.h"
#include "InspectorDOMAgent.h"
#include "InspectorNetworkAgent.h"
#include "InspectorOverlay.h"
#include "InstrumentingAgents.h"
#include "MIMETypeRegistry.h"
#include "MainFrame.h"
#include "MemoryCache.h"
#include "Page.h"
#include "RenderObject.h"
#include "ScriptController.h"
#include "SecurityOrigin.h"
#include "Settings.h"
#include "StyleScope.h"
#include "TextEncoding.h"
#include "TextResourceDecoder.h"
#include "UserGestureIndicator.h"
#include <inspector/ContentSearchUtilities.h>
#include <inspector/IdentifiersFactory.h>
#include <wtf/ListHashSet.h>
#include <wtf/Stopwatch.h>
#include <wtf/text/Base64.h>
#include <wtf/text/StringBuilder.h>
#include <yarr/RegularExpression.h>

#if ENABLE(WEB_ARCHIVE) && USE(CF)
#include "LegacyWebArchive.h"
#endif

using namespace Inspector;

namespace WebCore {

static bool decodeBuffer(const char* buffer, unsigned size, const String& textEncodingName, String* result)
{
    if (buffer) {
        TextEncoding encoding(textEncodingName);
        if (!encoding.isValid())
            encoding = WindowsLatin1Encoding();
        *result = encoding.decode(buffer, size);
        return true;
    }
    return false;
}

static bool hasTextContent(CachedResource* cachedResource)
{
    // FIXME: <https://webkit.org/b/165495> Web Inspector: XHR / Fetch for non-text content should not show garbled text
    // We should not assume XHR / Fetch have text content.

    InspectorPageAgent::ResourceType type = InspectorPageAgent::cachedResourceType(*cachedResource);
    return type == InspectorPageAgent::DocumentResource
        || type == InspectorPageAgent::StylesheetResource
        || type == InspectorPageAgent::ScriptResource
        || type == InspectorPageAgent::XHRResource
        || type == InspectorPageAgent::FetchResource;
}

bool InspectorPageAgent::cachedResourceContent(CachedResource* cachedResource, String* result, bool* base64Encoded)
{
    if (!cachedResource)
        return false;

    *base64Encoded = !hasTextContent(cachedResource);

    if (!cachedResource->encodedSize()) {
        *result = emptyString();
        return true;
    }

    if (*base64Encoded) {
        if (auto* buffer = cachedResource->resourceBuffer()) {
            *result = base64Encode(buffer->data(), buffer->size());
            return true;
        }
        return false;
    }

    if (cachedResource) {
        switch (cachedResource->type()) {
        case CachedResource::CSSStyleSheet:
            // This can return a null String if the MIME type is invalid.
            *result = downcast<CachedCSSStyleSheet>(*cachedResource).sheetText();
            return !result->isNull();
        case CachedResource::Script:
            *result = downcast<CachedScript>(*cachedResource).script().toString();
            return true;
        case CachedResource::MediaResource:
        case CachedResource::Icon:
        case CachedResource::RawResource: {
            auto* buffer = cachedResource->resourceBuffer();
            if (!buffer)
                return false;
            RefPtr<TextResourceDecoder> decoder = InspectorPageAgent::createTextDecoder(cachedResource->response().mimeType(), cachedResource->response().textEncodingName());
            // We show content for raw resources only for certain mime types (text, html and xml). Otherwise decoder will be null.
            if (!decoder)
                return false;
            *result = decoder->decodeAndFlush(buffer->data(), buffer->size());
            return true;
        }
        default:
            auto* buffer = cachedResource->resourceBuffer();
            return decodeBuffer(buffer ? buffer->data() : nullptr, buffer ? buffer->size() : 0, cachedResource->encoding(), result);
        }
    }
    return false;
}

bool InspectorPageAgent::mainResourceContent(Frame* frame, bool withBase64Encode, String* result)
{
    RefPtr<SharedBuffer> buffer = frame->loader().documentLoader()->mainResourceData();
    if (!buffer)
        return false;
    return InspectorPageAgent::dataContent(buffer->data(), buffer->size(), frame->document()->encoding(), withBase64Encode, result);
}

bool InspectorPageAgent::sharedBufferContent(RefPtr<SharedBuffer>&& buffer, const String& textEncodingName, bool withBase64Encode, String* result)
{
    return dataContent(buffer ? buffer->data() : nullptr, buffer ? buffer->size() : 0, textEncodingName, withBase64Encode, result);
}

bool InspectorPageAgent::dataContent(const char* data, unsigned size, const String& textEncodingName, bool withBase64Encode, String* result)
{
    if (withBase64Encode) {
        *result = base64Encode(data, size);
        return true;
    }

    return decodeBuffer(data, size, textEncodingName, result);
}

void InspectorPageAgent::resourceContent(ErrorString& errorString, Frame* frame, const URL& url, String* result, bool* base64Encoded)
{
    DocumentLoader* loader = assertDocumentLoader(errorString, frame);
    if (!loader)
        return;

    RefPtr<SharedBuffer> buffer;
    bool success = false;
    if (equalIgnoringFragmentIdentifier(url, loader->url())) {
        *base64Encoded = false;
        success = mainResourceContent(frame, *base64Encoded, result);
    }

    if (!success)
        success = cachedResourceContent(cachedResource(frame, url), result, base64Encoded);

    if (!success)
        errorString = ASCIILiteral("No resource with given URL found");
}

//static
String InspectorPageAgent::sourceMapURLForResource(CachedResource* cachedResource)
{
    static NeverDestroyed<String> sourceMapHTTPHeader(MAKE_STATIC_STRING_IMPL("SourceMap"));
    static NeverDestroyed<String> sourceMapHTTPHeaderDeprecated(MAKE_STATIC_STRING_IMPL("X-SourceMap"));

    if (!cachedResource)
        return String();

    // Scripts are handled in a separate path.
    if (cachedResource->type() != CachedResource::CSSStyleSheet)
        return String();

    String sourceMapHeader = cachedResource->response().httpHeaderField(sourceMapHTTPHeader);
    if (!sourceMapHeader.isEmpty())
        return sourceMapHeader;

    sourceMapHeader = cachedResource->response().httpHeaderField(sourceMapHTTPHeaderDeprecated);
    if (!sourceMapHeader.isEmpty())
        return sourceMapHeader;

    String content;
    bool base64Encoded;
    if (InspectorPageAgent::cachedResourceContent(cachedResource, &content, &base64Encoded) && !base64Encoded)
        return ContentSearchUtilities::findStylesheetSourceMapURL(content);

    return String();
}

CachedResource* InspectorPageAgent::cachedResource(Frame* frame, const URL& url)
{
    if (url.isNull())
        return nullptr;

    CachedResource* cachedResource = frame->document()->cachedResourceLoader().cachedResource(MemoryCache::removeFragmentIdentifierIfNeeded(url));
    if (!cachedResource) {
        ResourceRequest request(url);
        request.setDomainForCachePartition(frame->document()->topOrigin().domainForCachePartition());
        cachedResource = MemoryCache::singleton().resourceForRequest(request, frame->page()->sessionID());
    }

    return cachedResource;
}

Inspector::Protocol::Page::ResourceType InspectorPageAgent::resourceTypeJson(InspectorPageAgent::ResourceType resourceType)
{
    switch (resourceType) {
    case DocumentResource:
        return Inspector::Protocol::Page::ResourceType::Document;
    case ImageResource:
        return Inspector::Protocol::Page::ResourceType::Image;
    case FontResource:
        return Inspector::Protocol::Page::ResourceType::Font;
    case StylesheetResource:
        return Inspector::Protocol::Page::ResourceType::Stylesheet;
    case ScriptResource:
        return Inspector::Protocol::Page::ResourceType::Script;
    case XHRResource:
        return Inspector::Protocol::Page::ResourceType::XHR;
    case FetchResource:
        return Inspector::Protocol::Page::ResourceType::Fetch;
    case WebSocketResource:
        return Inspector::Protocol::Page::ResourceType::WebSocket;
    case OtherResource:
        return Inspector::Protocol::Page::ResourceType::Other;
    }
    return Inspector::Protocol::Page::ResourceType::Other;
}

InspectorPageAgent::ResourceType InspectorPageAgent::cachedResourceType(const CachedResource& cachedResource)
{
    switch (cachedResource.type()) {
    case CachedResource::ImageResource:
        return InspectorPageAgent::ImageResource;
#if ENABLE(SVG_FONTS)
    case CachedResource::SVGFontResource:
#endif
    case CachedResource::FontResource:
        return InspectorPageAgent::FontResource;
#if ENABLE(XSLT)
    case CachedResource::XSLStyleSheet:
#endif
    case CachedResource::CSSStyleSheet:
        return InspectorPageAgent::StylesheetResource;
    case CachedResource::Script:
        return InspectorPageAgent::ScriptResource;
    case CachedResource::MainResource:
        return InspectorPageAgent::DocumentResource;
    case CachedResource::MediaResource:
    case CachedResource::Icon:
    case CachedResource::RawResource: {
        switch (cachedResource.resourceRequest().requester()) {
        case ResourceRequest::Requester::Fetch:
            return InspectorPageAgent::FetchResource;
        case ResourceRequest::Requester::Main:
            return InspectorPageAgent::DocumentResource;
        default:
            return InspectorPageAgent::XHRResource;
        }
    }
    default:
        break;
    }
    return InspectorPageAgent::OtherResource;
}

Inspector::Protocol::Page::ResourceType InspectorPageAgent::cachedResourceTypeJson(const CachedResource& cachedResource)
{
    return resourceTypeJson(cachedResourceType(cachedResource));
}

RefPtr<TextResourceDecoder> InspectorPageAgent::createTextDecoder(const String& mimeType, const String& textEncodingName)
{
    if (!textEncodingName.isEmpty())
        return TextResourceDecoder::create(ASCIILiteral("text/plain"), textEncodingName);

    if (MIMETypeRegistry::isTextMIMEType(mimeType))
        return TextResourceDecoder::create(mimeType, "UTF-8");

    if (MIMETypeRegistry::isXMLMIMEType(mimeType)) {
        RefPtr<TextResourceDecoder> decoder = TextResourceDecoder::create(ASCIILiteral("application/xml"));
        decoder->useLenientXMLDecoding();
        return decoder;
    }

    return TextResourceDecoder::create(ASCIILiteral("text/plain"), "UTF-8");
}

InspectorPageAgent::InspectorPageAgent(PageAgentContext& context, InspectorClient* client, InspectorOverlay* overlay)
    : InspectorAgentBase(ASCIILiteral("Page"), context)
    , m_frontendDispatcher(std::make_unique<Inspector::PageFrontendDispatcher>(context.frontendRouter))
    , m_backendDispatcher(Inspector::PageBackendDispatcher::create(context.backendDispatcher, this))
    , m_page(context.inspectedPage)
    , m_client(client)
    , m_overlay(overlay)
{
}

void InspectorPageAgent::didCreateFrontendAndBackend(Inspector::FrontendRouter*, Inspector::BackendDispatcher*)
{
}

void InspectorPageAgent::willDestroyFrontendAndBackend(Inspector::DisconnectReason)
{
    ErrorString unused;
    disable(unused);
}

double InspectorPageAgent::timestamp()
{
    return m_environment.executionStopwatch()->elapsedTime();
}

void InspectorPageAgent::enable(ErrorString&)
{
    m_enabled = true;
    m_instrumentingAgents.setInspectorPageAgent(this);

    auto stopwatch = m_environment.executionStopwatch();
    stopwatch->reset();
    stopwatch->start();
}

void InspectorPageAgent::disable(ErrorString&)
{
    m_enabled = false;
    m_instrumentingAgents.setInspectorPageAgent(nullptr);

    ErrorString unused;
    setShowPaintRects(unused, false);
    setEmulatedMedia(unused, emptyString());
}

void InspectorPageAgent::reload(ErrorString&, const bool* const optionalReloadFromOrigin, const bool* const optionalRevalidateAllResources, const String* optionalScriptToEvaluateOnLoad)
{
    m_pendingScriptToEvaluateOnLoadOnce = optionalScriptToEvaluateOnLoad ? *optionalScriptToEvaluateOnLoad : emptyString();

    bool reloadFromOrigin = optionalReloadFromOrigin && *optionalReloadFromOrigin;
    bool revalidateAllResources = optionalRevalidateAllResources && *optionalRevalidateAllResources;

    OptionSet<ReloadOption> reloadOptions;
    if (reloadFromOrigin)
        reloadOptions |= ReloadOption::FromOrigin;
    if (!revalidateAllResources)
        reloadOptions |= ReloadOption::ExpiredOnly;

    m_page.mainFrame().loader().reload(reloadOptions);
}

void InspectorPageAgent::navigate(ErrorString&, const String& url)
{
    UserGestureIndicator indicator { ProcessingUserGesture };
    Frame& frame = m_page.mainFrame();

    ResourceRequest resourceRequest { frame.document()->completeURL(url) };
    FrameLoadRequest frameLoadRequest { *frame.document(), frame.document()->securityOrigin(), resourceRequest, ASCIILiteral("_self"), LockHistory::No, LockBackForwardList::No, MaybeSendReferrer, AllowNavigationToInvalidURL::No, NewFrameOpenerPolicy::Allow, ShouldOpenExternalURLsPolicy::ShouldNotAllow, InitiatedByMainFrame::Unknown };
    frame.loader().changeLocation(WTFMove(frameLoadRequest));
}

static Ref<Inspector::Protocol::Page::Cookie> buildObjectForCookie(const Cookie& cookie)
{
    return Inspector::Protocol::Page::Cookie::create()
        .setName(cookie.name)
        .setValue(cookie.value)
        .setDomain(cookie.domain)
        .setPath(cookie.path)
        .setExpires(cookie.expires)
        .setSize((cookie.name.length() + cookie.value.length()))
        .setHttpOnly(cookie.httpOnly)
        .setSecure(cookie.secure)
        .setSession(cookie.session)
        .release();
}

static Ref<JSON::ArrayOf<Inspector::Protocol::Page::Cookie>> buildArrayForCookies(ListHashSet<Cookie>& cookiesList)
{
    auto cookies = JSON::ArrayOf<Inspector::Protocol::Page::Cookie>::create();

    for (const auto& cookie : cookiesList)
        cookies->addItem(buildObjectForCookie(cookie));

    return cookies;
}

static Vector<CachedResource*> cachedResourcesForFrame(Frame* frame)
{
    Vector<CachedResource*> result;

    for (auto& cachedResourceHandle : frame->document()->cachedResourceLoader().allCachedResources().values()) {
        auto* cachedResource = cachedResourceHandle.get();
        if (cachedResource->resourceRequest().hiddenFromInspector())
            continue;

        switch (cachedResource->type()) {
        case CachedResource::ImageResource:
            // Skip images that were not auto loaded (images disabled in the user agent).
#if ENABLE(SVG_FONTS)
        case CachedResource::SVGFontResource:
#endif
        case CachedResource::FontResource:
            // Skip fonts that were referenced in CSS but never used/downloaded.
            if (cachedResource->stillNeedsLoad())
                continue;
            break;
        default:
            // All other CachedResource types download immediately.
            break;
        }

        result.append(cachedResource);
    }

    return result;
}

static Vector<URL> allResourcesURLsForFrame(Frame* frame)
{
    Vector<URL> result;

    result.append(frame->loader().documentLoader()->url());

    for (auto* cachedResource : cachedResourcesForFrame(frame))
        result.append(cachedResource->url());

    return result;
}

void InspectorPageAgent::getCookies(ErrorString&, RefPtr<JSON::ArrayOf<Inspector::Protocol::Page::Cookie>>& cookies)
{
    // If we can get raw cookies.
    ListHashSet<Cookie> rawCookiesList;

    // If we can't get raw cookies - fall back to String representation
    StringBuilder stringCookiesList;

    // Return value to getRawCookies should be the same for every call because
    // the return value is platform/network backend specific, and the call will
    // always return the same true/false value.
    bool rawCookiesImplemented = false;

    for (Frame* frame = &mainFrame(); frame; frame = frame->tree().traverseNext()) {
        Document* document = frame->document();
        if (!document)
            continue;

        for (auto& url : allResourcesURLsForFrame(frame)) {
            Vector<Cookie> docCookiesList;
            rawCookiesImplemented = getRawCookies(*document, URL(ParsedURLString, url), docCookiesList);

            if (!rawCookiesImplemented) {
                // FIXME: We need duplication checking for the String representation of cookies.
                // Exceptions are thrown by cookie() in sandboxed frames. That won't happen here
                // because "document" is the document of the main frame of the page.
                stringCookiesList.append(document->cookie().releaseReturnValue());
            } else {
                for (auto& cookie : docCookiesList) {
                    if (!rawCookiesList.contains(cookie))
                        rawCookiesList.add(cookie);
                }
            }
        }
    }

    // FIXME: Do not return empty string/empty array. Make returns optional instead. https://bugs.webkit.org/show_bug.cgi?id=80855
    if (rawCookiesImplemented)
        cookies = buildArrayForCookies(rawCookiesList);
    else
        cookies = JSON::ArrayOf<Inspector::Protocol::Page::Cookie>::create();
}

void InspectorPageAgent::deleteCookie(ErrorString&, const String& cookieName, const String& url)
{
    URL parsedURL(ParsedURLString, url);
    for (Frame* frame = &m_page.mainFrame(); frame; frame = frame->tree().traverseNext()) {
        if (auto* document = frame->document())
            WebCore::deleteCookie(*document, parsedURL, cookieName);
    }
}

void InspectorPageAgent::getResourceTree(ErrorString&, RefPtr<Inspector::Protocol::Page::FrameResourceTree>& object)
{
    object = buildObjectForFrameTree(&m_page.mainFrame());
}

void InspectorPageAgent::getResourceContent(ErrorString& errorString, const String& frameId, const String& url, String* content, bool* base64Encoded)
{
    Frame* frame = assertFrame(errorString, frameId);
    if (!frame)
        return;

    resourceContent(errorString, frame, URL(ParsedURLString, url), content, base64Encoded);
}

static bool textContentForCachedResource(CachedResource* cachedResource, String* result)
{
    if (hasTextContent(cachedResource)) {
        bool base64Encoded;
        if (InspectorPageAgent::cachedResourceContent(cachedResource, result, &base64Encoded)) {
            ASSERT(!base64Encoded);
            return true;
        }
    }
    return false;
}

void InspectorPageAgent::searchInResource(ErrorString& errorString, const String& frameId, const String& url, const String& query, const bool* const optionalCaseSensitive, const bool* const optionalIsRegex, const String* optionalRequestId, RefPtr<JSON::ArrayOf<Inspector::Protocol::GenericTypes::SearchMatch>>& results)
{
    results = JSON::ArrayOf<Inspector::Protocol::GenericTypes::SearchMatch>::create();

    bool isRegex = optionalIsRegex ? *optionalIsRegex : false;
    bool caseSensitive = optionalCaseSensitive ? *optionalCaseSensitive : false;

    if (optionalRequestId) {
        if (InspectorNetworkAgent* networkAgent = m_instrumentingAgents.inspectorNetworkAgent()) {
            networkAgent->searchInRequest(errorString, *optionalRequestId, query, caseSensitive, isRegex, results);
            return;
        }
    }

    Frame* frame = assertFrame(errorString, frameId);
    if (!frame)
        return;

    DocumentLoader* loader = assertDocumentLoader(errorString, frame);
    if (!loader)
        return;

    URL kurl(ParsedURLString, url);

    String content;
    bool success = false;
    if (equalIgnoringFragmentIdentifier(kurl, loader->url()))
        success = mainResourceContent(frame, false, &content);

    if (!success) {
        CachedResource* resource = cachedResource(frame, kurl);
        if (resource)
            success = textContentForCachedResource(resource, &content);
    }

    if (!success)
        return;

    results = ContentSearchUtilities::searchInTextByLines(content, query, caseSensitive, isRegex);
}

static Ref<Inspector::Protocol::Page::SearchResult> buildObjectForSearchResult(const String& frameId, const String& url, int matchesCount)
{
    return Inspector::Protocol::Page::SearchResult::create()
        .setUrl(url)
        .setFrameId(frameId)
        .setMatchesCount(matchesCount)
        .release();
}

void InspectorPageAgent::searchInResources(ErrorString&, const String& text, const bool* const optionalCaseSensitive, const bool* const optionalIsRegex, RefPtr<JSON::ArrayOf<Inspector::Protocol::Page::SearchResult>>& result)
{
    result = JSON::ArrayOf<Inspector::Protocol::Page::SearchResult>::create();

    bool isRegex = optionalIsRegex ? *optionalIsRegex : false;
    bool caseSensitive = optionalCaseSensitive ? *optionalCaseSensitive : false;
    JSC::Yarr::RegularExpression regex = ContentSearchUtilities::createSearchRegex(text, caseSensitive, isRegex);

    for (Frame* frame = &m_page.mainFrame(); frame; frame = frame->tree().traverseNext()) {
        String content;

        for (auto* cachedResource : cachedResourcesForFrame(frame)) {
            if (textContentForCachedResource(cachedResource, &content)) {
                int matchesCount = ContentSearchUtilities::countRegularExpressionMatches(regex, content);
                if (matchesCount)
                    result->addItem(buildObjectForSearchResult(frameId(frame), cachedResource->url(), matchesCount));
            }
        }

        if (mainResourceContent(frame, false, &content)) {
            int matchesCount = ContentSearchUtilities::countRegularExpressionMatches(regex, content);
            if (matchesCount)
                result->addItem(buildObjectForSearchResult(frameId(frame), frame->document()->url(), matchesCount));
        }
    }

    if (InspectorNetworkAgent* networkAgent = m_instrumentingAgents.inspectorNetworkAgent())
        networkAgent->searchOtherRequests(regex, result);
}

void InspectorPageAgent::setShowPaintRects(ErrorString&, bool show)
{
    m_showPaintRects = show;
    m_client->setShowPaintRects(show);

    if (m_client->overridesShowPaintRects())
        return;

    m_overlay->setShowingPaintRects(show);
}

void InspectorPageAgent::didClearWindowObjectInWorld(Frame* frame, DOMWrapperWorld& world)
{
    if (&world != &mainThreadNormalWorld())
        return;

    if (!m_scriptToEvaluateOnLoadOnce.isEmpty())
        frame->script().executeScript(m_scriptToEvaluateOnLoadOnce);
}

void InspectorPageAgent::domContentEventFired()
{
    m_isFirstLayoutAfterOnLoad = true;
    m_frontendDispatcher->domContentEventFired(timestamp());
}

void InspectorPageAgent::loadEventFired()
{
    m_frontendDispatcher->loadEventFired(timestamp());
}

void InspectorPageAgent::frameNavigated(Frame& frame)
{
    if (frame.isMainFrame()) {
        m_scriptToEvaluateOnLoadOnce = m_pendingScriptToEvaluateOnLoadOnce;
        m_pendingScriptToEvaluateOnLoadOnce = String();
    }
    m_frontendDispatcher->frameNavigated(buildObjectForFrame(&frame));
}

void InspectorPageAgent::frameDetached(Frame& frame)
{
    HashMap<Frame*, String>::iterator iterator = m_frameToIdentifier.find(&frame);
    if (iterator != m_frameToIdentifier.end()) {
        m_frontendDispatcher->frameDetached(iterator->value);
        m_identifierToFrame.remove(iterator->value);
        m_frameToIdentifier.remove(iterator);
    }
}

MainFrame& InspectorPageAgent::mainFrame()
{
    return m_page.mainFrame();
}

Frame* InspectorPageAgent::frameForId(const String& frameId)
{
    return frameId.isEmpty() ? nullptr : m_identifierToFrame.get(frameId);
}

String InspectorPageAgent::frameId(Frame* frame)
{
    if (!frame)
        return emptyString();
    String identifier = m_frameToIdentifier.get(frame);
    if (identifier.isNull()) {
        identifier = IdentifiersFactory::createIdentifier();
        m_frameToIdentifier.set(frame, identifier);
        m_identifierToFrame.set(identifier, frame);
    }
    return identifier;
}

bool InspectorPageAgent::hasIdForFrame(Frame* frame) const
{
    return frame && m_frameToIdentifier.contains(frame);
}

String InspectorPageAgent::loaderId(DocumentLoader* loader)
{
    if (!loader)
        return emptyString();
    String identifier = m_loaderToIdentifier.get(loader);
    if (identifier.isNull()) {
        identifier = IdentifiersFactory::createIdentifier();
        m_loaderToIdentifier.set(loader, identifier);
    }
    return identifier;
}

Frame* InspectorPageAgent::findFrameWithSecurityOrigin(const String& originRawString)
{
    for (Frame* frame = &m_page.mainFrame(); frame; frame = frame->tree().traverseNext()) {
        Ref<SecurityOrigin> documentOrigin = frame->document()->securityOrigin();
        if (documentOrigin->toRawString() == originRawString)
            return frame;
    }
    return nullptr;
}

Frame* InspectorPageAgent::assertFrame(ErrorString& errorString, const String& frameId)
{
    Frame* frame = frameForId(frameId);
    if (!frame)
        errorString = ASCIILiteral("No frame for given id found");
    return frame;
}

DocumentLoader* InspectorPageAgent::assertDocumentLoader(ErrorString& errorString, Frame* frame)
{
    FrameLoader& frameLoader = frame->loader();
    DocumentLoader* documentLoader = frameLoader.documentLoader();
    if (!documentLoader)
        errorString = ASCIILiteral("No documentLoader for given frame found");
    return documentLoader;
}

void InspectorPageAgent::loaderDetachedFromFrame(DocumentLoader& loader)
{
    m_loaderToIdentifier.remove(&loader);
}

void InspectorPageAgent::frameStartedLoading(Frame& frame)
{
    m_frontendDispatcher->frameStartedLoading(frameId(&frame));
}

void InspectorPageAgent::frameStoppedLoading(Frame& frame)
{
    m_frontendDispatcher->frameStoppedLoading(frameId(&frame));
}

void InspectorPageAgent::frameScheduledNavigation(Frame& frame, Seconds delay)
{
    m_frontendDispatcher->frameScheduledNavigation(frameId(&frame), delay.value());
}

void InspectorPageAgent::frameClearedScheduledNavigation(Frame& frame)
{
    m_frontendDispatcher->frameClearedScheduledNavigation(frameId(&frame));
}

void InspectorPageAgent::didPaint(RenderObject& renderer, const LayoutRect& rect)
{
    if (!m_enabled || !m_showPaintRects)
        return;

    LayoutRect absoluteRect = LayoutRect(renderer.localToAbsoluteQuad(FloatRect(rect)).boundingBox());
    FrameView* view = renderer.document().view();

    LayoutRect rootRect = absoluteRect;
    if (!view->frame().isMainFrame()) {
        IntRect rootViewRect = view->contentsToRootView(snappedIntRect(absoluteRect));
        rootRect = view->frame().mainFrame().view()->rootViewToContents(rootViewRect);
    }

    if (m_client->overridesShowPaintRects()) {
        m_client->showPaintRect(rootRect);
        return;
    }

    m_overlay->showPaintRect(rootRect);
}

void InspectorPageAgent::didLayout()
{
    bool isFirstLayout = m_isFirstLayoutAfterOnLoad;
    if (isFirstLayout)
        m_isFirstLayoutAfterOnLoad = false;

    if (!m_enabled)
        return;

    m_overlay->update();
}

void InspectorPageAgent::didScroll()
{
    if (m_enabled)
        m_overlay->update();
}

void InspectorPageAgent::didRecalculateStyle()
{
    if (m_enabled)
        m_overlay->update();
}

Ref<Inspector::Protocol::Page::Frame> InspectorPageAgent::buildObjectForFrame(Frame* frame)
{
    ASSERT_ARG(frame, frame);

    auto frameObject = Inspector::Protocol::Page::Frame::create()
        .setId(frameId(frame))
        .setLoaderId(loaderId(frame->loader().documentLoader()))
        .setUrl(frame->document()->url().string())
        .setMimeType(frame->loader().documentLoader()->responseMIMEType())
        .setSecurityOrigin(frame->document()->securityOrigin().toRawString())
        .release();
    if (frame->tree().parent())
        frameObject->setParentId(frameId(frame->tree().parent()));
    if (frame->ownerElement()) {
        String name = frame->ownerElement()->getNameAttribute();
        if (name.isEmpty())
            name = frame->ownerElement()->attributeWithoutSynchronization(HTMLNames::idAttr);
        frameObject->setName(name);
    }

    return frameObject;
}

Ref<Inspector::Protocol::Page::FrameResourceTree> InspectorPageAgent::buildObjectForFrameTree(Frame* frame)
{
    ASSERT_ARG(frame, frame);

    Ref<Inspector::Protocol::Page::Frame> frameObject = buildObjectForFrame(frame);
    auto subresources = JSON::ArrayOf<Inspector::Protocol::Page::FrameResource>::create();
    auto result = Inspector::Protocol::Page::FrameResourceTree::create()
        .setFrame(WTFMove(frameObject))
        .setResources(subresources.copyRef())
        .release();

    for (auto* cachedResource : cachedResourcesForFrame(frame)) {
        auto resourceObject = Inspector::Protocol::Page::FrameResource::create()
            .setUrl(cachedResource->url())
            .setType(cachedResourceTypeJson(*cachedResource))
            .setMimeType(cachedResource->response().mimeType())
            .release();
        if (cachedResource->wasCanceled())
            resourceObject->setCanceled(true);
        else if (cachedResource->status() == CachedResource::LoadError || cachedResource->status() == CachedResource::DecodeError)
            resourceObject->setFailed(true);
        String sourceMappingURL = InspectorPageAgent::sourceMapURLForResource(cachedResource);
        if (!sourceMappingURL.isEmpty())
            resourceObject->setSourceMapURL(sourceMappingURL);
        String targetId = cachedResource->resourceRequest().initiatorIdentifier();
        if (!targetId.isEmpty())
            resourceObject->setTargetId(targetId);
        subresources->addItem(WTFMove(resourceObject));
    }

    RefPtr<JSON::ArrayOf<Inspector::Protocol::Page::FrameResourceTree>> childrenArray;
    for (Frame* child = frame->tree().firstChild(); child; child = child->tree().nextSibling()) {
        if (!childrenArray) {
            childrenArray = JSON::ArrayOf<Inspector::Protocol::Page::FrameResourceTree>::create();
            result->setChildFrames(childrenArray);
        }
        childrenArray->addItem(buildObjectForFrameTree(child));
    }
    return result;
}

void InspectorPageAgent::setEmulatedMedia(ErrorString&, const String& media)
{
    if (media == m_emulatedMedia)
        return;

    m_emulatedMedia = media;
    Document* document = m_page.mainFrame().document();
    if (document) {
        document->styleScope().didChangeStyleSheetEnvironment();
        document->updateLayout();
    }
}

void InspectorPageAgent::applyEmulatedMedia(String& media)
{
    if (!m_emulatedMedia.isEmpty())
        media = m_emulatedMedia;
}

void InspectorPageAgent::getCompositingBordersVisible(ErrorString&, bool* outParam)
{
    *outParam = m_page.settings().showDebugBorders() || m_page.settings().showRepaintCounter();
}

void InspectorPageAgent::setCompositingBordersVisible(ErrorString&, bool visible)
{
    m_page.settings().setShowDebugBorders(visible);
    m_page.settings().setShowRepaintCounter(visible);
}

void InspectorPageAgent::snapshotNode(ErrorString& errorString, int nodeId, String* outDataURL)
{
    Frame& frame = mainFrame();

    InspectorDOMAgent* domAgent = m_instrumentingAgents.inspectorDOMAgent();
    ASSERT(domAgent);
    Node* node = domAgent->assertNode(errorString, nodeId);
    if (!node)
        return;

    std::unique_ptr<ImageBuffer> snapshot = WebCore::snapshotNode(frame, *node);
    if (!snapshot) {
        errorString = ASCIILiteral("Could not capture snapshot");
        return;
    }

    *outDataURL = snapshot->toDataURL(ASCIILiteral("image/png"));
}

void InspectorPageAgent::snapshotRect(ErrorString& errorString, int x, int y, int width, int height, const String& coordinateSystem, String* outDataURL)
{
    Frame& frame = mainFrame();

    SnapshotOptions options = SnapshotOptionsNone;
    if (coordinateSystem == "Viewport")
        options |= SnapshotOptionsInViewCoordinates;

    IntRect rectangle(x, y, width, height);
    std::unique_ptr<ImageBuffer> snapshot = snapshotFrameRect(frame, rectangle, options);

    if (!snapshot) {
        errorString = ASCIILiteral("Could not capture snapshot");
        return;
    }

    *outDataURL = snapshot->toDataURL(ASCIILiteral("image/png"));
}

void InspectorPageAgent::archive(ErrorString& errorString, String* data)
{
#if ENABLE(WEB_ARCHIVE) && USE(CF)
    Frame& frame = mainFrame();
    RefPtr<LegacyWebArchive> archive = LegacyWebArchive::create(frame);
    if (!archive) {
        errorString = ASCIILiteral("Could not create web archive for main frame");
        return;
    }

    RetainPtr<CFDataRef> buffer = archive->rawDataRepresentation();
    *data = base64Encode(CFDataGetBytePtr(buffer.get()), CFDataGetLength(buffer.get()));
#else
    UNUSED_PARAM(data);
    errorString = ASCIILiteral("No support for creating archives");
#endif
}

} // namespace WebCore
