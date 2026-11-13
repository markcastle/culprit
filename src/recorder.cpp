#include "recorder.h"

namespace culprit {

void Recorder::add(const SampleTick& t) {
    if (t.dtSec <= 0 || t.dtSec > kMaxTickSec || t.ncpu < 1 || t.totalRam <= 0) return;

    int64_t minute = t.unixSec >= 0 ? t.unixSec / 60 : (t.unixSec - 59) / 60;
    MinuteDelta& m = pending_[minute];
    m.minute = minute;
    m.sys.obsSec += t.dtSec;
    m.sys.cpuCapSec += t.dtSec * t.ncpu;
    m.sys.ramBs += t.dtSec * t.totalRam;

    double w = pressureFactor(t.memLoad);
    for (const AppUsage& a : t.apps) {
        AppTotals& x = m.apps[a.key];
        x.cpuSec += a.cpuSec > 0 ? a.cpuSec : 0;
        x.memwBs += a.privBytes * t.dtSec * w;
    }
}

std::vector<MinuteDelta> Recorder::take(int64_t beforeMinute) {
    std::vector<MinuteDelta> out;
    auto stop = pending_.lower_bound(beforeMinute);
    for (auto pit = pending_.begin(); pit != stop; ++pit) {
        MinuteDelta& m = pit->second;
        for (auto it = m.apps.begin(); it != m.apps.end();) {
            bool keep = it->second.cpuSec >= kMinCpuShare * m.sys.cpuCapSec ||
                        it->second.memwBs >= kMinMemShare * m.sys.ramBs;
            it = keep ? std::next(it) : m.apps.erase(it);
        }
        out.push_back(std::move(m));
    }
    pending_.erase(pending_.begin(), stop);
    return out;
}

}  // namespace culprit
