// Background tracking: the per-user scheduled task and the headless collector.
#pragma once
#include <string>

namespace culprit {

std::string dataDir();  // %LOCALAPPDATA%\Culprit, created on demand

inline const wchar_t* const kCollectorMutex = L"Local\\Culprit.Collector";
inline const wchar_t* const kWriterMutex    = L"Local\\Culprit.Writer";
inline const wchar_t* const kStopEvent      = L"Local\\Culprit.CollectorStop";

bool collectorRunning();
bool spawnCollector();              // detached, no window
bool stopCollector(unsigned waitMs);

struct TrackStatus {
    bool        registered = false;
    bool        running = false;
    std::string taskName;
    std::string command;  // what the task launches
};

TrackStatus trackStatus();
bool trackOn(std::string& message);
bool trackOff(std::string& message);
bool trackRestart(std::string& message);

int collectorMain();  // `culprit collect`

}  // namespace culprit
