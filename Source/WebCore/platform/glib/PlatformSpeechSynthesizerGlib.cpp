/*
 *  Copyright (C) 2023 Igalia S.L.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "config.h"
#include "PlatformSpeechSynthesizer.h"

#include <wtf/Assertions.h>

#if ENABLE(SPEECH_SYNTHESIS) && USE(GLIB)

namespace WebCore {

PlatformSpeechSynthesizer::PlatformSpeechSynthesizer(PlatformSpeechSynthesizerClient* client)
{
    UNUSED_PARAM(client);
    ASSERT_NOT_IMPLEMENTED_YET();
}

PlatformSpeechSynthesizer::~PlatformSpeechSynthesizer()
{
    ASSERT_NOT_IMPLEMENTED_YET();
}

void PlatformSpeechSynthesizer::initializeVoiceList()
{
    ASSERT_NOT_IMPLEMENTED_YET();
}

void PlatformSpeechSynthesizer::speak(RefPtr<PlatformSpeechSynthesisUtterance>&&)
{
    ASSERT_NOT_IMPLEMENTED_YET();
}

void PlatformSpeechSynthesizer::pause()
{
    ASSERT_NOT_IMPLEMENTED_YET();
}

void PlatformSpeechSynthesizer::resume()
{
    ASSERT_NOT_IMPLEMENTED_YET();
}

void PlatformSpeechSynthesizer::cancel()
{
    ASSERT_NOT_IMPLEMENTED_YET();
}

void PlatformSpeechSynthesizer::resetState()
{
    ASSERT_NOT_IMPLEMENTED_YET();
}


} // namespace WebCore

#endif // ENABLE(SPEECH_SYNTHESIS) && USE(GLIB)
