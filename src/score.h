// Impact score: pure, deterministic, no Windows dependencies.
#pragma once
#include <optional>

namespace culprit {

// What the machine could have done during the observed part of a window.
struct WindowTotals {
    double obsSec    = 0;  // seconds actually sampled inside the window
    double cpuCapSec = 0;  // sum of (observed seconds x logical CPUs)
    double ramBs     = 0;  // sum of (observed seconds x installed RAM bytes)
};

// What one application did during the same window.
struct AppTotals {
    double cpuSec = 0;  // CPU-seconds consumed
    double memwBs = 0;  // private bytes x seconds, already pressure-weighted
};

inline constexpr double kMinHistorySec   = 60.0;  // below this, no score at all
inline constexpr double kCpuPoints       = 70.0;
inline constexpr double kCpuSaturation   = 0.15;  // 15% of the whole machine
inline constexpr double kMemPoints       = 30.0;
inline constexpr double kMemSaturation   = 0.12;  // 12% of installed RAM

// Weight applied to memory held while the system is at `memLoad` (0..1 of
// physical RAM in use). 0.5 when the machine has plenty free (<= 50% used),
// rising linearly to 1.0 at >= 90% used.
double pressureFactor(double memLoad);

// 0..100, or nullopt while there is not enough history to say anything.
// Averages over all observed time in the window, so an app that ran for five
// minutes of an observed hour is diluted by the other fifty-five.
std::optional<int> impact(const AppTotals& app, const WindowTotals& win);

}  // namespace culprit
