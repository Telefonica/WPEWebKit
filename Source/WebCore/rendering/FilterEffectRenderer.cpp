/*
 * Copyright (C) 2011-2017 Apple Inc. All rights reserved.
 * Copyright (C) 2013 Google Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

#include "config.h"
#include "FilterEffectRenderer.h"

#include "CachedSVGDocument.h"
#include "CachedSVGDocumentReference.h"
#include "ElementIterator.h"
#include "FEColorMatrix.h"
#include "FEComponentTransfer.h"
#include "FEDropShadow.h"
#include "FEGaussianBlur.h"
#include "FEMerge.h"
#include "RenderLayer.h"
#include "SVGElement.h"
#include "SVGFilterBuilder.h"
#include "SVGFilterPrimitiveStandardAttributes.h"
#include "SourceGraphic.h"
#include <algorithm>
#include <wtf/MathExtras.h>

#if USE(DIRECT2D)
#include <d2d1.h>
#endif

namespace WebCore {

static inline void endMatrixRow(Vector<float>& parameters)
{
    parameters.append(0);
    parameters.append(0);
}

static inline void lastMatrixRow(Vector<float>& parameters)
{
    parameters.append(0);
    parameters.append(0);
    parameters.append(0);
    parameters.append(1);
    parameters.append(0);
}

inline FilterEffectRenderer::FilterEffectRenderer()
    : Filter(FloatSize { 1, 1 })
    , m_sourceGraphic(SourceGraphic::create(*this))
{
}

Ref<FilterEffectRenderer> FilterEffectRenderer::create()
{
    return adoptRef(*new FilterEffectRenderer);
}

FilterEffectRenderer::~FilterEffectRenderer()
{
}

GraphicsContext* FilterEffectRenderer::inputContext()
{
    return sourceImage() ? &sourceImage()->context() : nullptr;
}

RefPtr<FilterEffect> FilterEffectRenderer::buildReferenceFilter(RenderElement& renderer, FilterEffect& previousEffect, ReferenceFilterOperation& filterOperation)
{
    auto* cachedSVGDocumentReference = filterOperation.cachedSVGDocumentReference();
    auto* cachedSVGDocument = cachedSVGDocumentReference ? cachedSVGDocumentReference->document() : nullptr;

    // If we have an SVG document, this is an external reference. Otherwise
    // we look up the referenced node in the current document.
    Document* document;
    if (!cachedSVGDocument)
        document = &renderer.document();
    else {
        document = cachedSVGDocument->document();
        if (!document)
            return nullptr;
    }

    auto* filter = document->getElementById(filterOperation.fragment());
    if (!filter) {
        // Although we did not find the referenced filter, it might exist later in the document.
        // FIXME: This skips anonymous RenderObjects. <https://webkit.org/b/131085>
        if (auto* element = renderer.element())
            document->accessSVGExtensions().addPendingResource(filterOperation.fragment(), element);
        return nullptr;
    }

    RefPtr<FilterEffect> effect;

    auto builder = std::make_unique<SVGFilterBuilder>(&previousEffect);

    for (auto& effectElement : childrenOfType<SVGFilterPrimitiveStandardAttributes>(*filter)) {
        effect = effectElement.build(builder.get(), *this);
        if (!effect)
            continue;

        effectElement.setStandardAttributes(effect.get());
        builder->add(effectElement.result(), effect);
        m_effects.append(*effect);
    }
    return effect;
}

bool FilterEffectRenderer::build(RenderElement& renderer, const FilterOperations& operations, FilterConsumer consumer)
{
    m_hasFilterThatMovesPixels = operations.hasFilterThatMovesPixels();
    m_hasFilterThatShouldBeRestrictedBySecurityOrigin = operations.hasFilterThatShouldBeRestrictedBySecurityOrigin();
    if (m_hasFilterThatMovesPixels)
        m_outsets = operations.outsets();

    m_effects.clear();

    RefPtr<FilterEffect> previousEffect = m_sourceGraphic.ptr();
    for (auto& operation : operations.operations()) {
        RefPtr<FilterEffect> effect;
        auto& filterOperation = *operation;
        switch (filterOperation.type()) {
        case FilterOperation::REFERENCE: {
            auto& referenceOperation = downcast<ReferenceFilterOperation>(filterOperation);
            effect = buildReferenceFilter(renderer, *previousEffect, referenceOperation);
            referenceOperation.setFilterEffect(effect.copyRef());
            break;
        }
        case FilterOperation::GRAYSCALE: {
            auto& colorMatrixOperation = downcast<BasicColorMatrixFilterOperation>(filterOperation);
            Vector<float> inputParameters;
            double oneMinusAmount = clampTo(1 - colorMatrixOperation.amount(), 0.0, 1.0);

            // See https://dvcs.w3.org/hg/FXTF/raw-file/tip/filters/index.html#grayscaleEquivalent
            // for information on parameters.

            inputParameters.append(narrowPrecisionToFloat(0.2126 + 0.7874 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.7152 - 0.7152 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.0722 - 0.0722 * oneMinusAmount));
            endMatrixRow(inputParameters);

            inputParameters.append(narrowPrecisionToFloat(0.2126 - 0.2126 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.7152 + 0.2848 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.0722 - 0.0722 * oneMinusAmount));
            endMatrixRow(inputParameters);

            inputParameters.append(narrowPrecisionToFloat(0.2126 - 0.2126 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.7152 - 0.7152 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.0722 + 0.9278 * oneMinusAmount));
            endMatrixRow(inputParameters);

            lastMatrixRow(inputParameters);

            effect = FEColorMatrix::create(*this, FECOLORMATRIX_TYPE_MATRIX, inputParameters);
            break;
        }
        case FilterOperation::SEPIA: {
            auto& colorMatrixOperation = downcast<BasicColorMatrixFilterOperation>(filterOperation);
            Vector<float> inputParameters;
            double oneMinusAmount = clampTo(1 - colorMatrixOperation.amount(), 0.0, 1.0);

            // See https://dvcs.w3.org/hg/FXTF/raw-file/tip/filters/index.html#sepiaEquivalent
            // for information on parameters.

            inputParameters.append(narrowPrecisionToFloat(0.393 + 0.607 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.769 - 0.769 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.189 - 0.189 * oneMinusAmount));
            endMatrixRow(inputParameters);

            inputParameters.append(narrowPrecisionToFloat(0.349 - 0.349 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.686 + 0.314 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.168 - 0.168 * oneMinusAmount));
            endMatrixRow(inputParameters);

            inputParameters.append(narrowPrecisionToFloat(0.272 - 0.272 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.534 - 0.534 * oneMinusAmount));
            inputParameters.append(narrowPrecisionToFloat(0.131 + 0.869 * oneMinusAmount));
            endMatrixRow(inputParameters);

            lastMatrixRow(inputParameters);

            effect = FEColorMatrix::create(*this, FECOLORMATRIX_TYPE_MATRIX, inputParameters);
            break;
        }
        case FilterOperation::SATURATE: {
            auto& colorMatrixOperation = downcast<BasicColorMatrixFilterOperation>(filterOperation);
            Vector<float> inputParameters;
            inputParameters.append(narrowPrecisionToFloat(colorMatrixOperation.amount()));
            effect = FEColorMatrix::create(*this, FECOLORMATRIX_TYPE_SATURATE, inputParameters);
            break;
        }
        case FilterOperation::HUE_ROTATE: {
            auto& colorMatrixOperation = downcast<BasicColorMatrixFilterOperation>(filterOperation);
            Vector<float> inputParameters;
            inputParameters.append(narrowPrecisionToFloat(colorMatrixOperation.amount()));
            effect = FEColorMatrix::create(*this, FECOLORMATRIX_TYPE_HUEROTATE, inputParameters);
            break;
        }
        case FilterOperation::INVERT: {
            auto& componentTransferOperation = downcast<BasicComponentTransferFilterOperation>(filterOperation);
            ComponentTransferFunction transferFunction;
            transferFunction.type = FECOMPONENTTRANSFER_TYPE_TABLE;
            Vector<float> transferParameters;
            transferParameters.append(narrowPrecisionToFloat(componentTransferOperation.amount()));
            transferParameters.append(narrowPrecisionToFloat(1 - componentTransferOperation.amount()));
            transferFunction.tableValues = transferParameters;

            ComponentTransferFunction nullFunction;
            effect = FEComponentTransfer::create(*this, transferFunction, transferFunction, transferFunction, nullFunction);
            break;
        }
        case FilterOperation::OPACITY: {
            auto& componentTransferOperation = downcast<BasicComponentTransferFilterOperation>(filterOperation);
            ComponentTransferFunction transferFunction;
            transferFunction.type = FECOMPONENTTRANSFER_TYPE_TABLE;
            Vector<float> transferParameters;
            transferParameters.append(0);
            transferParameters.append(narrowPrecisionToFloat(componentTransferOperation.amount()));
            transferFunction.tableValues = transferParameters;

            ComponentTransferFunction nullFunction;
            effect = FEComponentTransfer::create(*this, nullFunction, nullFunction, nullFunction, transferFunction);
            break;
        }
        case FilterOperation::BRIGHTNESS: {
            auto& componentTransferOperation = downcast<BasicComponentTransferFilterOperation>(filterOperation);
            ComponentTransferFunction transferFunction;
            transferFunction.type = FECOMPONENTTRANSFER_TYPE_LINEAR;
            transferFunction.slope = narrowPrecisionToFloat(componentTransferOperation.amount());
            transferFunction.intercept = 0;

            ComponentTransferFunction nullFunction;
            effect = FEComponentTransfer::create(*this, transferFunction, transferFunction, transferFunction, nullFunction);
            break;
        }
        case FilterOperation::CONTRAST: {
            auto& componentTransferOperation = downcast<BasicComponentTransferFilterOperation>(filterOperation);
            ComponentTransferFunction transferFunction;
            transferFunction.type = FECOMPONENTTRANSFER_TYPE_LINEAR;
            float amount = narrowPrecisionToFloat(componentTransferOperation.amount());
            transferFunction.slope = amount;
            transferFunction.intercept = -0.5 * amount + 0.5;
            
            ComponentTransferFunction nullFunction;
            effect = FEComponentTransfer::create(*this, transferFunction, transferFunction, transferFunction, nullFunction);
            break;
        }
        case FilterOperation::BLUR: {
            auto& blurOperation = downcast<BlurFilterOperation>(filterOperation);
            float stdDeviation = floatValueForLength(blurOperation.stdDeviation(), 0);
            effect = FEGaussianBlur::create(*this, stdDeviation, stdDeviation, consumer == FilterProperty ? EDGEMODE_NONE : EDGEMODE_DUPLICATE);
            break;
        }
        case FilterOperation::DROP_SHADOW: {
            auto& dropShadowOperation = downcast<DropShadowFilterOperation>(filterOperation);
            effect = FEDropShadow::create(*this, dropShadowOperation.stdDeviation(), dropShadowOperation.stdDeviation(),
                dropShadowOperation.x(), dropShadowOperation.y(), dropShadowOperation.color(), 1);
            break;
        }
        default:
            break;
        }

        if (effect) {
            // Unlike SVG Filters and CSSFilterImages, filter functions on the filter
            // property applied here should not clip to their primitive subregions.
            effect->setClipsToBounds(consumer == FilterFunction);
            effect->setOperatingColorSpace(ColorSpaceSRGB);
            
            if (filterOperation.type() != FilterOperation::REFERENCE) {
                effect->inputEffects().append(WTFMove(previousEffect));
                m_effects.append(*effect);
            }
            previousEffect = WTFMove(effect);
        }
    }

    // If we didn't make any effects, tell our caller we are not valid.
    if (m_effects.isEmpty())
        return false;

    setMaxEffectRects(m_sourceDrawingRegion);
    return true;
}

bool FilterEffectRenderer::updateBackingStoreRect(const FloatRect& filterRect)
{
    if (filterRect.isEmpty() || ImageBuffer::sizeNeedsClamping(filterRect.size()))
        return false;

    if (filterRect == sourceImageRect())
        return false;

    setSourceImageRect(filterRect);
    return true;
}

void FilterEffectRenderer::allocateBackingStoreIfNeeded(const GraphicsContext& targetContext)
{
    // At this point the effect chain has been built, and the
    // source image sizes set. We just need to attach the graphic
    // buffer if we have not yet done so.

    if (m_graphicsBufferAttached)
        return;

    IntSize logicalSize { m_sourceDrawingRegion.size() };
    if (!sourceImage() || sourceImage()->logicalSize() != logicalSize) {
#if USE(DIRECT2D)
        setSourceImage(ImageBuffer::create(logicalSize, renderingMode(), &targetContext, filterScale()));
#else
        UNUSED_PARAM(targetContext);
        setSourceImage(ImageBuffer::create(logicalSize, renderingMode(), filterScale()));
#endif
    }
    m_graphicsBufferAttached = true;
}

void FilterEffectRenderer::clearIntermediateResults()
{
    m_sourceGraphic->clearResult();
    for (auto& effect : m_effects)
        effect->clearResult();
}

void FilterEffectRenderer::apply()
{
    auto& effect = m_effects.last().get();
    effect.apply();
    effect.transformResultColorSpace(ColorSpaceSRGB);
}

LayoutRect FilterEffectRenderer::computeSourceImageRectForDirtyRect(const LayoutRect& filterBoxRect, const LayoutRect& dirtyRect)
{
    // The result of this function is the area in the "filterBoxRect" that needs to be repainted, so that we fully cover the "dirtyRect".
    auto rectForRepaint = dirtyRect;
    if (hasFilterThatMovesPixels()) {
        // Note that the outsets are reversed here because we are going backwards -> we have the dirty rect and
        // need to find out what is the rectangle that might influence the result inside that dirty rect.
        rectForRepaint.move(-m_outsets.right(), -m_outsets.bottom());
        rectForRepaint.expand(m_outsets.left() + m_outsets.right(), m_outsets.top() + m_outsets.bottom());
    }
    rectForRepaint.intersect(filterBoxRect);
    return rectForRepaint;
}

ImageBuffer* FilterEffectRenderer::output() const
{
    return m_effects.last()->asImageBuffer();
}

void FilterEffectRenderer::setMaxEffectRects(const FloatRect& effectRect)
{
    for (auto& effect : m_effects)
        effect->setMaxEffectRect(effectRect);
}

IntRect FilterEffectRenderer::outputRect() const
{
    auto& lastEffect = m_effects.last().get();
    if (!lastEffect.hasResult())
        return { };
    return lastEffect.requestedRegionOfInputImageData(IntRect { m_filterRegion });
}

bool FilterEffectRendererHelper::prepareFilterEffect(RenderLayer& layer, const LayoutRect& filterBoxRect, const LayoutRect& dirtyRect, const LayoutRect& layerRepaintRect)
{
    ASSERT(m_haveFilterEffect);
    ASSERT(layer.filterRenderer());

    auto& filter = *layer.filterRenderer();
    auto filterSourceRect = filter.computeSourceImageRectForDirtyRect(filterBoxRect, dirtyRect);

    if (filterSourceRect.isEmpty()) {
        // The dirty rect is not in view, just bail out.
        m_haveFilterEffect = false;
        return false;
    }

    bool hasUpdatedBackingStore = filter.updateBackingStoreRect(filterSourceRect);

    m_renderLayer = &layer;
    if (!filter.hasFilterThatMovesPixels())
        m_repaintRect = dirtyRect;
    else {
        if (hasUpdatedBackingStore)
            m_repaintRect = filterSourceRect;
        else {
            m_repaintRect = dirtyRect;
            m_repaintRect.unite(layerRepaintRect);
            m_repaintRect.intersect(filterSourceRect);
        }
    }
    m_paintOffset = filterSourceRect.location();

    return true;
}

GraphicsContext* FilterEffectRendererHelper::filterContext() const
{
    if (!m_haveFilterEffect)
        return nullptr;
    return m_renderLayer->filterRenderer()->inputContext();
}

bool FilterEffectRendererHelper::beginFilterEffect()
{
    ASSERT(m_renderLayer);
    ASSERT(m_renderLayer->filterRenderer());

    auto& filter = *m_renderLayer->filterRenderer();
    filter.allocateBackingStoreIfNeeded(m_targetContext);
    // Paint into the context that represents the SourceGraphic of the filter.
    auto* sourceGraphicsContext = filter.inputContext();
    if (!sourceGraphicsContext || filter.filterRegion().isEmpty() || ImageBuffer::sizeNeedsClamping(filter.filterRegion().size())) {
        // Disable the filters and continue.
        m_haveFilterEffect = false;
        return false;
    }

    // Translate the context so that the contents of the layer is captured in the offscreen memory buffer.
    sourceGraphicsContext->save();
    sourceGraphicsContext->translate(-m_paintOffset);
    sourceGraphicsContext->clearRect(m_repaintRect);
    sourceGraphicsContext->clip(m_repaintRect);

    m_startedFilterEffect = true;
    return true;
}

void FilterEffectRendererHelper::applyFilterEffect(GraphicsContext& destinationContext)
{
    ASSERT(m_haveFilterEffect);
    ASSERT(m_renderLayer);
    ASSERT(m_renderLayer->filterRenderer());
    ASSERT(m_renderLayer->filterRenderer()->inputContext());

    auto& filter = *m_renderLayer->filterRenderer();
    filter.inputContext()->restore();

    filter.apply();

    // Get the filtered output and draw it in place.
    LayoutRect destRect = filter.outputRect();
    destRect.move(m_paintOffset.x(), m_paintOffset.y());

    if (auto* outputBuffer = filter.output())
        destinationContext.drawImageBuffer(*outputBuffer, snapRectToDevicePixels(destRect, m_renderLayer->renderer().document().deviceScaleFactor()));

    filter.clearIntermediateResults();
}

} // namespace WebCore
