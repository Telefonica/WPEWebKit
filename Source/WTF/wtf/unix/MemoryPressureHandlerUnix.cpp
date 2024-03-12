/*
 * Copyright (C) 2011, 2012 Apple Inc. All Rights Reserved.
 * Copyright (C) 2014 Raspberry Pi Foundation. All Rights Reserved.
 * Copyright (C) 2018 Igalia S.L.
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
#include <wtf/MemoryPressureHandler.h>

#include <malloc.h>
#include <unistd.h>
#include <wtf/Logging.h>
#include <wtf/MainThread.h>
#include <wtf/MemoryFootprint.h>
#include <wtf/text/WTFString.h>

#if OS(LINUX)
#include <fnmatch.h>
#include <wtf/linux/CurrentProcessMemoryStatus.h>
#elif OS(FREEBSD)
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#endif
#include <wtf/Threading.h>

namespace WTF {

// Disable memory event reception for a minimum of s_minimumHoldOffTime
// seconds after receiving an event. Don't let events fire any sooner than
// s_holdOffMultiplier times the last cleanup processing time. Effectively
// this is 1 / s_holdOffMultiplier percent of the time.
// If after releasing the memory we don't free at least s_minimumBytesFreedToUseMinimumHoldOffTime,
// we wait longer to try again (s_maximumHoldOffTime).
// These value seems reasonable and testing verifies that it throttles frequent
// low memory events, greatly reducing CPU usage.
#if PLATFORM(WPE)
static const Seconds s_minimumHoldOffTime { 1_s };
static const Seconds s_maximumHoldOffTime { 1_s };
#else
static const Seconds s_minimumHoldOffTime { 1_s };
static const Seconds s_maximumHoldOffTime { 1_s };
#endif
static const size_t s_minimumBytesFreedToUseMinimumHoldOffTime = 1 * MB;
static const unsigned s_holdOffMultiplier = 20;

static const Seconds s_memoryUsagePollerInterval { 1_s };
static size_t s_pollMaximumProcessMemoryCriticalLimit = 0;
static size_t s_pollMaximumProcessMemoryNonCriticalLimit = 0;

static const char* s_processStatus = "/proc/self/status";
static const char* s_cmdline = "/proc/self/cmdline";

static inline String nextToken(FILE* file)
{
    if (!file)
        return String();

    static const unsigned bufferSize = 128;
    char buffer[bufferSize] = {0, };
    unsigned index = 0;
    while (index < bufferSize) {
        int ch = fgetc(file);
        if (ch == EOF || (isASCIISpace(ch) && index)) // Break on non-initial ASCII space.
            break;
        if (!isASCIISpace(ch)) {
            buffer[index] = ch;
            index++;
        }
    }

    return String::fromLatin1(buffer);
}

bool readToken(const char* filename, const char* key, size_t fileUnits, size_t &result)
{
    FILE* file = fopen(filename, "r");
    if (!file)
        return false;

    String sKey { String::fromLatin1(key) };
    bool validValue = false;
    String token;
    do {
        token = nextToken(file);
        if (token.isEmpty())
            break;

        if (!key) {
            validValue = sscanf(token.utf8().data(), "%u", &result);
            break;
        }

        if (token == sKey) {
            validValue = sscanf(nextToken(file).utf8().data(), "%u", &result);
            break;
        }
    } while (!token.isEmpty());

    fclose(file);
    return validValue;
}

static String getProcessName()
{
    FILE* file = fopen(s_cmdline, "r");
    if (!file)
        return String();

    String result = nextToken(file);
    fclose(file);

    return result;
}

static bool initializeProcessMemoryLimits(size_t &criticalLimit, size_t &nonCriticalLimit)
{
    static bool initialized = false;
    static bool success = false;

    if (initialized)
        return success;

    initialized = true;

    // Syntax: Case insensitive, process name, wildcard (*), unit multipliers (M=Mb, K=Kb, <empty>=bytes).
    // Example: WPE_POLL_MAX_MEMORY='WPEWebProcess:500M,*Process:150M'
    String processName(getProcessName().convertToLowercaseWithoutLocale());
    String s(String::fromLatin1(getenv("WPE_POLL_MAX_MEMORY")));
    if (!s.isEmpty()) {
        Vector<String> entries = s.split(',');
        for (const String& entry : entries) {
            Vector<String> keyvalue = entry.split(':');
            if (keyvalue.size() != 2)
                continue;
            String key = "*"+keyvalue[0].stripWhiteSpace().convertToLowercaseWithoutLocale();
            String value = keyvalue[1].stripWhiteSpace().convertToLowercaseWithoutLocale();
            size_t units = 1;
            if (value.endsWith('k'))
                units = 1024;
            else if (value.endsWith('m'))
                units = 1024 * 1024;
            if (units != 1)
                value = value.substring(0, value.length()-1);
            bool ok = false;
            size_t size = 0;
            ok = sscanf(value.utf8().data(), "%u", &size);
            if (!ok)
                continue;

            if (!fnmatch(key.utf8().data(), processName.utf8().data(), 0)) {
                criticalLimit = size * units;
                nonCriticalLimit = criticalLimit * 0.95; //0.75;
                success = true;
                return true;
            }
        }
    }

    success = false;
    return false;
}


MemoryPressureHandler::MemoryUsagePoller::MemoryUsagePoller()
{
    m_thread = Thread::create("WTF: MemoryPressureHandler", [this] {
        do {
            bool underMemoryPressure = false;
            bool critical = false;
            size_t value = 0;

            if (s_pollMaximumProcessMemoryCriticalLimit) {
                if (readToken(s_processStatus, "VmRSS:", KB, value)) {
                    if (value > s_pollMaximumProcessMemoryNonCriticalLimit) {
                        underMemoryPressure = true;
                        critical = value > s_pollMaximumProcessMemoryCriticalLimit;
                    }
                }
            }

            if (underMemoryPressure) {
                callOnMainThread([critical] {
                    MemoryPressureHandler::singleton().triggerMemoryPressureEvent(critical);
                });
                return;
            }

            sleep(s_memoryUsagePollerInterval);
        } while (true);
    });
}

MemoryPressureHandler::MemoryUsagePoller::~MemoryUsagePoller()
{
    if (m_thread)
        m_thread->detach();
}

void MemoryPressureHandler::triggerMemoryPressureEvent(bool isCritical)
{
    if (!m_installed)
        return;

    if (ReliefLogger::loggingEnabled())
        LOG(MemoryPressure, "Got memory pressure notification (%s)", isCritical ? "critical" : "non-critical");

    setMemoryPressureStatus(MemoryPressureStatus::SystemCritical);

    ensureOnMainThread([this, isCritical] {
        // When memory usage reaches the critical state, we may not release enough memory in time if we use the
        // async mode, so use synchrounous mode in such case
        respondToMemoryPressure(isCritical ? Critical::Yes : Critical::No, isCritical ? Synchronous::Yes : Synchronous::No);
    });

    if (ReliefLogger::loggingEnabled() && isUnderMemoryPressure())
        LOG(MemoryPressure, "System is no longer under memory pressure.");

    setMemoryPressureStatus(MemoryPressureStatus::Normal);
}

void MemoryPressureHandler::install()
{
    if (m_installed || m_holdOffTimer.isActive())
        return;

    // If the per process limits are not defined, we don't create the memory poller.
    if (initializeProcessMemoryLimits(s_pollMaximumProcessMemoryCriticalLimit, s_pollMaximumProcessMemoryNonCriticalLimit))
        m_memoryUsagePoller = std::make_unique<MemoryUsagePoller>();

    m_installed = true;
}

void MemoryPressureHandler::uninstall()
{
    if (!m_installed)
        return;

    m_holdOffTimer.stop();

    m_memoryUsagePoller = nullptr;

    m_installed = false;
}

void MemoryPressureHandler::holdOffTimerFired()
{
    install();
}

void MemoryPressureHandler::holdOff(Seconds seconds)
{
    m_holdOffTimer.startOneShot(seconds);
}

static size_t processMemoryUsage()
{
#if OS(LINUX)
    ProcessMemoryStatus memoryStatus;
    currentProcessMemoryStatus(memoryStatus);
    return (memoryStatus.resident - memoryStatus.shared);
#elif OS(FREEBSD)
    static size_t pageSize = sysconf(_SC_PAGE_SIZE);
    struct kinfo_proc info;
    size_t infolen = sizeof(info);

    int mib[4];
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    if (sysctl(mib, 4, &info, &infolen, nullptr, 0))
        return 0;

    return static_cast<size_t>(info.ki_rssize - info.ki_tsize) * pageSize;
#else
#error "Missing a platform specific way of determining the memory usage"
#endif
}

void MemoryPressureHandler::respondToMemoryPressure(Critical critical, Synchronous synchronous)
{
    uninstall();

    MonotonicTime startTime = MonotonicTime::now();
    int64_t processMemory = processMemoryUsage();
    releaseMemory(critical, synchronous);
    int64_t bytesFreed = processMemory - processMemoryUsage();
    Seconds holdOffTime = s_maximumHoldOffTime;
    if (bytesFreed > 0 && static_cast<size_t>(bytesFreed) >= s_minimumBytesFreedToUseMinimumHoldOffTime)
        holdOffTime = (MonotonicTime::now() - startTime) * s_holdOffMultiplier;
    holdOff(std::max(holdOffTime, s_minimumHoldOffTime));
}

void MemoryPressureHandler::platformReleaseMemory(Critical)
{
#if HAVE(MALLOC_TRIM)
    malloc_trim(0);
#endif
}

std::optional<MemoryPressureHandler::ReliefLogger::MemoryUsage> MemoryPressureHandler::ReliefLogger::platformMemoryUsage()
{
    return MemoryUsage {processMemoryUsage(), memoryFootprint()};
}

} // namespace WTF
