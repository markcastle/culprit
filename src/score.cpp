#include "score.h"

#include <algorithm>
#include <cmath>

namespace culprit {

double pressureFactor(double memLoad) {
    if (!(memLoad > 0.5)) return 0.5;  // also catches NaN
    if (memLoad >= 0.9) return 1.0;
    return 0.5 + (memLoad - 0.5) / 0.4 * 0.5;
}

std::optional<int> impact(const AppTotals& app, const WindowTotals& win) {
    if (win.obsSec < kMinHistorySec || win.cpuCapSec <= 0 || win.ramBs <= 0) return std::nullopt;

    double cpuShare = std::max(0.0, app.cpuSec) / win.cpuCapSec;
    double memShare = std::max(0.0, app.memwBs) / win.ramBs;

    double pts = kCpuPoints * std::min(1.0, cpuShare / kCpuSaturation) +
                 kMemPoints * std::min(1.0, memShare / kMemSaturation);
    long r = std::lround(pts);
    return (int)std::clamp(r, 0L, 100L);
}

}  // namespace culprit
