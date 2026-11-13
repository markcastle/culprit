// Plain data shared by every module. No Windows headers.
#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace culprit {

// One process as seen in one snapshot. (pid, created) is the identity:
// Windows recycles pids, so pid alone is never trusted.
struct Proc {
    uint32_t    pid     = 0;
    uint32_t    ppid    = 0;
    uint64_t    created = 0;   // FILETIME, 100ns since 1601
    uint64_t    cpu100ns = 0;  // lifetime user+kernel
    uint64_t    privBytes = 0; // private commit
    uint32_t    session = 0;
    std::string image;         // "chrome.exe" (UTF-8)
    double      cpuFrac = 0;   // share of whole machine over last interval, 0..1
    double      cpuSec  = 0;   // CPU-seconds consumed over last interval
};

struct ProcId {
    uint32_t pid = 0;
    uint64_t created = 0;
    bool operator==(const ProcId&) const = default;
};

// Processes sharing an executable name, shown as one row. This is an
// *application group*, not a process tree.
struct Group {
    std::string         key;      // lower-case image name
    std::string         display;  // friendly name
    std::vector<size_t> members;  // indexes into Model::procs
    double              cpuFrac = 0;
    uint64_t            privBytes = 0;
    std::optional<int>  impact;
};

struct Model {
    std::vector<Proc>  procs;
    std::vector<Group> groups;
    double   sysCpuFrac  = 0;
    double   memLoad     = 0;   // 0..1
    uint64_t totalRam    = 0;
    int      ncpu        = 1;
    int      windowMin   = 60;  // history window the impact column reflects
    double   historySec  = 0;   // observed seconds available inside that window
    bool     writer      = false;  // this process is recording history
    bool     collectorUp = false;  // background collector process is alive
    bool     storeOk     = true;
    uint64_t seq         = 0;
};

}  // namespace culprit
