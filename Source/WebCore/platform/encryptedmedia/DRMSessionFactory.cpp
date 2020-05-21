/*
 * If not stated otherwise in this file or this component's license file the
 * following copyright and licenses apply:
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**
* @file DRMSessionFactory.cpp
* @brief Source file for DRMSessionFactory
*/

#include "DRMSessionFactory.h"
#include "playreadydrmsession.h"

/**
 *  @brief		Creates appropriate DRM systems Session objects based
 *  			on the requested systemID, like PlayReady or WideVine
 *
 *  @param[in]	systemid - DRM systems uuid
 *  @return		Pointer to DrmSession.
 */
CDMDrmSession* DRMSessionFactory::GetDrmSession(const char* systemid)
{
	CDMDrmSession* drmSession = NULL;
	if(!strcmp(PLAYREADY_PROTECTION_SYSTEM_ID, systemid))
	{
		drmSession = new PlayReadyDRMSession();
	}
}
