/*
 * If not stated otherwise in this file or this component's license file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
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
* @file DRMSessionManager.cpp
* @brief Source file for DrmSessionManager.
*/

#include "DRMSessionManager.h"
#include "priv_drm.h"
#include <pthread.h>
#include "base64.h"
#include <iostream>

#define COMCAST_LICENCE_REQUEST_HEADER_ACCEPT "Accept: application/vnd.xcal.mds.licenseResponse+json; version=1"
#define COMCAST_LICENCE_REQUEST_HEADER_CONTENT_TYPE "Content-Type: application/vnd.xcal.mds.licenseRequest+json; version=1"
#define LICENCE_RESPONSE_JSON_LICENCE_KEY "license\":\""
#define COMCAST_QA_DRM_LICENCE_SERVER_URL "https://mds-qa.ccp.xcal.tv/license"
#define COMCAST_DRM_LICENCE_SERVER_URL "https://mds.ccp.xcal.tv/license"
#define COMCAST_ROGERS_DRM_LICENCE_SERVER_URL "https://mds-rogers.ccp.xcal.tv/license"
#define COMCAST_DRM_METADATA_TAG_START "<ckm:policy xmlns:ckm=\"urn:ccp:ckm\">"
#define COMCAST_DRM_METADATA_TAG_END "</ckm:policy>"
#define SESSION_TOKEN_URL "http://localhost:50050/authService/getSessionToken"
#define MAX_LICENSE_REQUEST_ATTEMPTS 2

static const char *sessionTypeName[] = {"video", "audio"};

DRMSessionManager* DRMSessionManager::_sessionMgr = NULL;

static pthread_mutex_t sessionMgrMutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t drmSessionMutex = PTHREAD_MUTEX_INITIALIZER;

KeyID::KeyID() : len(0), data(NULL), creationTime(0), isFailedKeyId(false), isPrimaryKeyId(false)
{
}


DrmSessionCacheInfo *drmCacheInfo_g = NULL;

void *CreateDRMSession(void *arg);
DrmSessionCacheInfo* getDrmCacheInformationHandler();
int SpawnDRMLicenseAcquireThread(PrivateInstanceAAMP *aamp, DrmSessionDataInfo* drmData);

/**
 *  @brief Get drm cache info handler
 *
 *  @param None
 *  @return		Create the Cache handler if it is null, 
 *      else return the existing one
 */
DrmSessionCacheInfo* getDrmCacheInformationHandler()
{
	if (NULL == drmCacheInfo_g ){
		pthread_mutex_lock(&drmSessionMutex);
		drmCacheInfo_g = (DrmSessionCacheInfo *)malloc(sizeof(DrmSessionCacheInfo));
		if (NULL != drmCacheInfo_g){
			drmCacheInfo_g->createDRMSessionThreadID = 0;
			drmCacheInfo_g->drmSessionThreadStarted = false;
		}
		pthread_mutex_unlock(&drmSessionMutex);
	}
	return  drmCacheInfo_g;
}


#ifdef USE_SECCLIENT
/**
 *  @brief Get formatted URL of license server
 *
 *  @param[in] url URL of license server
 *  @return		formatted url for secclient license acqusition.
 */
static string getFormattedLicenseServerURL(string url)
{
	size_t startpos = 0;
	size_t endpos, len;
	endpos = len = url.size();

	if (memcmp(url.data(), "https://", 8) == 0)
	{
		startpos += 8;
	}
	else if (memcmp(url.data(), "http://", 7) == 0)
	{
		startpos += 7;
	}

	if (startpos != 0)
	{
		endpos = url.find('/', startpos);
		if (endpos != string::npos)
		{
			len = endpos - startpos;
		}
	}

	return url.substr(startpos, len);
}
#endif

/**
 *  @brief      DRMSessionManager constructor.
 */
DRMSessionManager::DRMSessionManager() : drmSessionContexts(NULL), cachedKeyIDs(NULL), accessToken(NULL),
		accessTokenLen(0), sessionMgrState(SessionMgrState::eSESSIONMGR_ACTIVE), accessTokenMutex(PTHREAD_MUTEX_INITIALIZER),
		cachedKeyMutex(PTHREAD_MUTEX_INITIALIZER)
{
}

/**
 *  @brief      DRMSessionManager Destructor.
 */
DRMSessionManager::~DRMSessionManager()
{
}

/**
 *  @brief		Clean up the memory used by session variables.
 *
 *  @return		void.
 */
void DRMSessionManager::clearSessionData()
{
	logprintf("%s:%d DRMSessionManager:: Clearing session data", __FUNCTION__, __LINE__);
	for(int i = 0 ; i < gpGlobalConfig->dash_MaxDRMSessions; i++)
	{
		if(drmSessionContexts != NULL && drmSessionContexts[i].drmSession != NULL)
		{
			delete drmSessionContexts[i].data;
			drmSessionContexts[i].data = NULL;
			drmSessionContexts[i].dataLength = 0;
			delete drmSessionContexts[i].drmSession;
			drmSessionContexts[i].drmSession = NULL;
		}
		if(cachedKeyIDs != NULL && cachedKeyIDs[i].data != NULL)
		{
			delete cachedKeyIDs[i].data;
			cachedKeyIDs[i].data = NULL;
			cachedKeyIDs[i].len = 0;
		}
	}

	if (drmSessionContexts != NULL)
	{
		delete[] drmSessionContexts;
		drmSessionContexts = NULL;
	}
	if (cachedKeyIDs != NULL)
	{
		delete[] cachedKeyIDs;
		cachedKeyIDs = NULL;
	}
}

/**
 * @brief	To get the singleton session manager instance.
 *
 * @return	session manager.
 */
DRMSessionManager* DRMSessionManager::getInstance()
{
	pthread_mutex_lock(&sessionMgrMutex);
	if(NULL == _sessionMgr)
	{
		_sessionMgr = new DRMSessionManager();
	}
	if(NULL == _sessionMgr->drmSessionContexts)
	{
		_sessionMgr->drmSessionContexts = new DrmSessionContext[gpGlobalConfig->dash_MaxDRMSessions];
	}
	if(NULL == _sessionMgr->cachedKeyIDs)
	{
		_sessionMgr->cachedKeyIDs = new KeyID[gpGlobalConfig->dash_MaxDRMSessions];
	}
	pthread_mutex_unlock(&sessionMgrMutex);
	return _sessionMgr;
}

/**
 * @brief	Set Session manager state
 * @param	state
 * @return	void.
 */
void DRMSessionManager::setSessionMgrState(SessionMgrState state)
{
	pthread_mutex_lock(&cachedKeyMutex);
	sessionMgrState = state;
	pthread_mutex_unlock(&cachedKeyMutex);
}


/**
 * @brief	Clean up the failed keyIds.
 *
 * @return	void.
 */
void DRMSessionManager::clearFailedKeyIds()
{
	pthread_mutex_lock(&cachedKeyMutex);
	for(int i = 0 ; i < gpGlobalConfig->dash_MaxDRMSessions; i++)
	{
		if(cachedKeyIDs[i].data != NULL && cachedKeyIDs[i].isFailedKeyId)
		{
			delete cachedKeyIDs[i].data;
			cachedKeyIDs[i].data = NULL;
			cachedKeyIDs[i].len = 0;
			cachedKeyIDs[i].isFailedKeyId = false;
			cachedKeyIDs[i].creationTime = 0;
		}
		cachedKeyIDs[i].isPrimaryKeyId = false;
	}
	pthread_mutex_unlock(&cachedKeyMutex);
}

/**
 *  @brief		Clean up the memory for accessToken.
 *
 *  @return		void.
 */
void DRMSessionManager::clearAccessToken()
{
	pthread_mutex_lock(&accessTokenMutex);
	if(accessToken)
	{
		free(accessToken);
		accessToken = NULL;
		accessTokenLen = 0;
	}
	pthread_mutex_unlock(&accessTokenMutex);
}

/**
 *  @brief		Curl write callback, used to get the curl o/p
 *  			from DRM license, accessToken curl requests.
 *
 *  @param[in]	ptr - Pointer to received data.
 *  @param[in]	size, nmemb - Size of received data (size * nmemb).
 *  @param[out]	userdata - Pointer to buffer where the received data is copied.
 *  @return		returns the number of bytes processed.
 */
size_t DRMSessionManager::write_callback(char *ptr, size_t size,
		size_t nmemb, void *userdata)
{
	DrmData *data = (DrmData *)userdata;
	size_t numBytesForBlock = size * nmemb;
	if (NULL == data->getData())
	{
		data->setData((unsigned char *) ptr, numBytesForBlock);
	}
	else
	{
		data->addData((unsigned char *) ptr, numBytesForBlock);
	}
	if (gpGlobalConfig->logging.trace)
	{
		logprintf("%s:%d wrote %zu number of blocks", __FUNCTION__, __LINE__, numBytesForBlock);
	}
	return numBytesForBlock;
}

/**
 *  @brief		Extract substring between (excluding) two string delimiters.
 *
 *  @param[in]	parentStr - Parent string from which substring is extracted.
 *  @param[in]	startStr, endStr - String delimiters.
 *  @return		Returns the extracted substring; Empty string if delimiters not found.
 */
string _extractSubstring(string parentStr, string startStr, string endStr)
{
	string ret = "";
	int startPos = parentStr.find(startStr);
	if(string::npos != startPos)
	{
		int offset = strlen(startStr.c_str());
		int endPos = parentStr.find(endStr, startPos + offset + 1);
		if(string::npos != endPos)
		{
			ret = parentStr.substr(startPos + offset, endPos - (startPos + offset));
		}
	}
	return ret;
}

/**
 *  @brief		Get the accessToken from authService.
 *
 *  @param[out]	tokenLen - Gets updated with accessToken length.
 *  @return		Pointer to accessToken.
 *  @note		AccessToken memory is dynamically allocated, deallocation
 *				should be handled at the caller side.
 */
const char * DRMSessionManager::getAccessToken(int &tokenLen, long &error_code)
{
	if(accessToken == NULL)
	{
		DrmData * tokenReply = new DrmData();
		CURLcode res;
		long httpCode = -1;

		CURL *curl = curl_easy_init();;
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
		curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_WHATEVER);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, tokenReply);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_URL, SESSION_TOKEN_URL);

		res = curl_easy_perform(curl);

		if (res == CURLE_OK)
		{
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
			if (httpCode == 200 || httpCode == 206)
			{
				string tokenReplyStr = string(reinterpret_cast<char*>(tokenReply->getData()));
				string tokenStatusCode = _extractSubstring(tokenReplyStr, "status\":", ",\"");
				if(tokenStatusCode.length() == 0)
				{
					//StatusCode could be last element in the json
					tokenStatusCode = _extractSubstring(tokenReplyStr, "status\":", "}");
				}
				if(tokenStatusCode.length() == 1 && tokenStatusCode.c_str()[0] == '0')
				{
					string token = _extractSubstring(tokenReplyStr, "token\":\"", "\"");
					if(token.length() != 0)
					{
						accessToken = (char*)calloc(token.length()+1, sizeof(char));
						accessTokenLen = token.length();
						strncpy(accessToken,token.c_str(),token.length());
						logprintf("%s:%d Received session token from auth service ", __FUNCTION__, __LINE__);
					}
					else
					{
						logprintf("%s:%d Could not get access token from session token reply", __FUNCTION__, __LINE__);
						error_code = (long)eAUTHTOKEN_TOKEN_PARSE_ERROR;
					}
				}
				else
				{
					logprintf("%s:%d Missing or invalid status code in session token reply", __FUNCTION__, __LINE__);
					error_code = (long)eAUTHTOKEN_INVALID_STATUS_CODE;
				}
			}
			else
			{
				logprintf("%s:%d Get Session token call failed with http error %d", __FUNCTION__, __LINE__, httpCode);
				error_code = httpCode;
			}
		}
		else
		{
			logprintf("%s:%d Get Session token call failed with curl error %d", __FUNCTION__, __LINE__, res);
			error_code = res;
		}
		delete tokenReply;
		curl_easy_cleanup(curl);
	}

	tokenLen = accessTokenLen;
	return accessToken;
}

/**
 * @brief Sleep for given milliseconds
 * @param milliseconds Time to sleep
 */
static void mssleep(int milliseconds)
{
	struct timespec req, rem;
	if (milliseconds > 0)
	{
		req.tv_sec = milliseconds / 1000;
		req.tv_nsec = (milliseconds % 1000) * 1000000;
		nanosleep(&req, &rem);
	}
}

/**
 *  @brief		Get DRM license key from DRM server.
 *
 *  @param[in]	keyChallenge - Structure holding license request and it's length.
 *  @param[in]	destinationURL - Destination url to which request is send.
 *  @param[out]	httpCode - Gets updated with http error; default -1.
 *  @param[in]	isComcastStream - Flag to indicate whether Comcast specific headers
 *  			are to be used.
 *  @param[in]	licenseProxy - Proxy to use for license requests.
 *  @param[in]	headers - Custom headers from application for license request.
 *  @param[in]	drmSystem - DRM type.
 *  @return		Structure holding DRM license key and it's length; NULL and 0 if request fails
 *  @note		Memory for license key is dynamically allocated, deallocation
 *				should be handled at the caller side.
 *			customHeader ownership should be taken up by getLicense function
 *
 */
DrmData * DRMSessionManager::getLicense(DrmData * keyChallenge,
		string destinationURL, long *httpCode, bool isComcastStream, char* licenseProxy, struct curl_slist *customHeader, DRMSystems drmSystem)
{

	*httpCode = -1;
	CURL *curl;
	CURLcode res;
	double totalTime = 0;
	struct curl_slist *headers = NULL;
	DrmData * keyInfo = new DrmData();
	const long challegeLength = keyChallenge->getDataLength();
	char* destURL = new char[destinationURL.length() + 1];
	curl = curl_easy_init();
	if (customHeader != NULL)
	{
		headers = customHeader;
	}

	if(isComcastStream)
	{
		headers = curl_slist_append(headers, COMCAST_LICENCE_REQUEST_HEADER_ACCEPT);
		headers = curl_slist_append(headers, COMCAST_LICENCE_REQUEST_HEADER_CONTENT_TYPE);
		headers = curl_slist_append(headers, "Expect:");
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "AAMP/1.0.0");
	//	headers = curl_slist_append(headers, "X-MoneyTrace: trace-id=226c94fc4d-3535-4945-a173-61af53444a3d;parent-id=4557953636469444377;span-id=803972323171353973");
	}
	else if(customHeader == NULL)
	{
		if(drmSystem == eDRM_WideVine)
		{
			AAMPLOG_WARN("No custom header, setting default for Widevine");
			headers = curl_slist_append(headers,"Content-Type: application/octet-stream");
		}
		else if (drmSystem == eDRM_PlayReady)
		{
			AAMPLOG_WARN("No custom header, setting default for Playready");
			headers = curl_slist_append(headers,"Content-Type: text/xml; charset=utf-8");
		}
		else
		{
			AAMPLOG_WARN("!!! Custom header is missing and default is not processed.");
		}
	}

	strcpy((char*) destURL, destinationURL.c_str());

	//headers = curl_slist_append(headers, destURL);

	logprintf("%s:%d Sending license request to server : %s ", __FUNCTION__, __LINE__, destinationURL.c_str());
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
	curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_WHATEVER);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_URL, destURL);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, keyInfo);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, challegeLength);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS,(uint8_t * )keyChallenge->getData());
	if (licenseProxy)
	{
		curl_easy_setopt(curl, CURLOPT_PROXY, licenseProxy);
		/* allow whatever auth the proxy speaks */
		curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
	}
	unsigned int attemptCount = 0;
	while(attemptCount < MAX_LICENSE_REQUEST_ATTEMPTS)
	{
		attemptCount++;
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			logprintf("%s:%d curl_easy_perform() failed: %s", __FUNCTION__, __LINE__, curl_easy_strerror(res));
			logprintf("%s:%d acquireLicense FAILED! license request attempt : %d; response code : curl %d", __FUNCTION__, __LINE__, attemptCount, res);
			*httpCode = res;
			break;
		}
		else
		{
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, httpCode);
			curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &totalTime);
			if (*httpCode != 200 && *httpCode != 206)
			{
				logprintf("%s:%d acquireLicense FAILED! license request attempt : %d; response code : http %d", __FUNCTION__, __LINE__, attemptCount, *httpCode);
				if(*httpCode >= 500 && *httpCode < 600
						&& attemptCount < MAX_LICENSE_REQUEST_ATTEMPTS && gpGlobalConfig->licenseRetryWaitTime > 0)
				{
					delete keyInfo;
					keyInfo = new DrmData();
					curl_easy_setopt(curl, CURLOPT_WRITEDATA, keyInfo);
					logprintf("%s:%d acquireLicense : Sleeping %d milliseconds before next retry.", __FUNCTION__, __LINE__, gpGlobalConfig->licenseRetryWaitTime);
					mssleep(gpGlobalConfig->licenseRetryWaitTime);
				}
				else
				{
					break;
				}
			}
			else
			{
				logprintf("%s:%d DRM Session Manager Received license data from server; Curl total time  = %.1f", __FUNCTION__, __LINE__, totalTime);
				logprintf("%s:%d acquireLicense SUCCESS! license request attempt %d; response code : http %d",__FUNCTION__, __LINE__, attemptCount, *httpCode);
				break;
			}
		}
	}

	delete destURL;
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	return keyInfo;
}

