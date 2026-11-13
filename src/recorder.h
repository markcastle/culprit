// Turns a stream of samples into per-minute deltas ready to be stored.
// Pure: no clock, no database.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "score.h"

namespace culprit {

struct AppUsage {
    std::string key;         // application group key
    double      cpuSec = 0;  // CPU-seconds consumed during the interval
    double      privBytes = 0;
};

struct SampleTick {
    int64_t unixSec = 0;  // wall clock at the end of the interval
    double  dtSec   = 0;  // interval length
    int     ncpu    = 1;
    double  totalRam = 0;
    double  memLoad  = 0; // 0..1
    std::vector<AppUsage> apps;
};

struct MinuteDelta {
    int64_t      minute = 0;  // unixSec / 60
    WindowTotals sys;
    std::unordered_map<std::string, AppTotals> apps;
};

// An interval longer than this means the machine slept or we were starved;
// it is recorded as a gap rather than smeared across the minute.
inline constexpr double kMaxTickSec = 20.0;

// Rows contributing less than about a quarter of a point are not stored.
inline constexpr double kMinCpuShare = 0.0005;
inline constexpr double kMinMemShare = 0.001;

class Recorder {
public:
    void add(const SampleTick& t);
    // Minutes earlier than `beforeMinute` accumulated so far, insignificant
    // rows dropped. With no argument: everything, including the open minute.
    std::vector<MinuteDelta> take(int64_t beforeMinute = INT64_MAX);
    // Not yet taken (normally just the minute still in progress).
    const std::map<int64_t, MinuteDelta>& pending() const { return pending_; }
    bool empty() const { return pending_.empty(); }

private:
    std::map<int64_t, MinuteDelta> pending_;
};

}  // namespace culprit
