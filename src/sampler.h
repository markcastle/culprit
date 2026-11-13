// Process table snapshots. One NtQuerySystemInformation call per snapshot:
// no process handles are opened, so it sees every process without admin.
#pragma once
#include "model.h"

namespace culprit {

struct Snapshot {
    std::vector<Proc> procs;
    int64_t  qpc = 0;
    uint64_t sysIdle100ns = 0;
    uint64_t sysTotal100ns = 0;
};

struct SysInfo {
    int      ncpu = 1;
    uint64_t totalRam = 0;
    double   memLoad = 0;  // 0..1
};

bool    takeSnapshot(Snapshot& out);
double  secondsBetween(const Snapshot& a, const Snapshot& b);
SysInfo sysInfo();
int64_t unixNow();

// Executable path of a process we are not allowed to open (for example one
// running as another account). Asks the kernel by pid; no handle needed.
// Returns "" if unknown.
std::string imagePathByPid(uint32_t pid);

// Pure: fill cpuSec / cpuFrac on `cur` from the previous snapshot. A process
// born during the interval is charged all the CPU it has used so far.
void applyDeltas(const std::vector<Proc>& prev, std::vector<Proc>& cur, double dtSec, int ncpu);

}  // namespace culprit
