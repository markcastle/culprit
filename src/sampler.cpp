#include "sampler.h"

#include <algorithm>
#include <cstddef>
#include <unordered_map>

#include "win.h"

namespace culprit {

namespace {

// ntdll structures. Not in the public SDK in full, but layout-stable since
// Windows 7. Offsets are asserted below so a mistake cannot compile.
using NTSTATUS_T = LONG;
constexpr NTSTATUS_T kInfoLengthMismatch = (NTSTATUS_T)0xC0000004L;
constexpr ULONG kSystemProcessInformation = 5;

struct UStr {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct ProcInfo {
    ULONG         NextEntryOffset;
    ULONG         NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG         HardFaultCount;
    ULONG         NumberOfThreadsHighWatermark;
    ULONGLONG     CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UStr          ImageName;
    LONG          BasePriority;
    HANDLE        UniqueProcessId;
    HANDLE        InheritedFromUniqueProcessId;
    ULONG         HandleCount;
    ULONG         SessionId;
    ULONG_PTR     UniqueProcessKey;
    SIZE_T        PeakVirtualSize;
    SIZE_T        VirtualSize;
    ULONG         PageFaultCount;
    SIZE_T        PeakWorkingSetSize;
    SIZE_T        WorkingSetSize;
    SIZE_T        QuotaPeakPagedPoolUsage;
    SIZE_T        QuotaPagedPoolUsage;
    SIZE_T        QuotaPeakNonPagedPoolUsage;
    SIZE_T        QuotaNonPagedPoolUsage;
    SIZE_T        PagefileUsage;
    SIZE_T        PeakPagefileUsage;
    SIZE_T        PrivatePageCount;
};

#ifdef _WIN64
static_assert(offsetof(ProcInfo, CreateTime) == 32);
static_assert(offsetof(ProcInfo, ImageName) == 56);
static_assert(offsetof(ProcInfo, UniqueProcessId) == 80);
static_assert(offsetof(ProcInfo, InheritedFromUniqueProcessId) == 88);
static_assert(offsetof(ProcInfo, SessionId) == 100);
static_assert(offsetof(ProcInfo, PrivatePageCount) == 200);
#endif

using NtQsiFn = NTSTATUS_T(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

NtQsiFn ntQsi() {
    static NtQsiFn fn = [] {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        return nt ? (NtQsiFn)(void*)GetProcAddress(nt, "NtQuerySystemInformation") : nullptr;
    }();
    return fn;
}

}  // namespace

bool takeSnapshot(Snapshot& out) {
    NtQsiFn q = ntQsi();
    if (!q) return false;

    static thread_local std::vector<BYTE> buf(1u << 19);
    for (;;) {
        ULONG need = 0;
        NTSTATUS_T st = q(kSystemProcessInformation, buf.data(), (ULONG)buf.size(), &need);
        if (st == kInfoLengthMismatch) {
            buf.resize(std::max<size_t>(need, buf.size() * 2) + (1u << 16));
            continue;
        }
        if (st < 0) return false;
        break;
    }

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    out.qpc = now.QuadPart;

    FILETIME idle, kern, user;
    if (GetSystemTimes(&idle, &kern, &user)) {
        out.sysIdle100ns = ftToU64(idle);
        out.sysTotal100ns = ftToU64(kern) + ftToU64(user);  // kernel includes idle
    }

    out.procs.clear();
    const ProcInfo* p = (const ProcInfo*)buf.data();
    for (;;) {
        Proc r;
        r.pid = (uint32_t)(ULONG_PTR)p->UniqueProcessId;
        r.ppid = (uint32_t)(ULONG_PTR)p->InheritedFromUniqueProcessId;
        r.created = (uint64_t)p->CreateTime.QuadPart;
        r.cpu100ns = (uint64_t)p->UserTime.QuadPart + (uint64_t)p->KernelTime.QuadPart;
        r.privBytes = (uint64_t)p->PrivatePageCount;
        r.session = p->SessionId;
        if (p->ImageName.Buffer && p->ImageName.Length)
            r.image = narrow(p->ImageName.Buffer, p->ImageName.Length / (int)sizeof(WCHAR));
        else
            r.image = r.pid == 0 ? "Idle" : "System";
        out.procs.push_back(std::move(r));

        if (p->NextEntryOffset == 0) break;
        p = (const ProcInfo*)((const BYTE*)p + p->NextEntryOffset);
    }
    return true;
}

double secondsBetween(const Snapshot& a, const Snapshot& b) {
    static double freq = [] {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        return (double)f.QuadPart;
    }();
    return (double)(b.qpc - a.qpc) / freq;
}

SysInfo sysInfo() {
    SysInfo s;
    DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    s.ncpu = n ? (int)n : 1;
    MEMORYSTATUSEX m{};
    m.dwLength = sizeof m;
    if (GlobalMemoryStatusEx(&m)) {
        s.totalRam = m.ullTotalPhys;
        s.memLoad = m.ullTotalPhys ? 1.0 - (double)m.ullAvailPhys / (double)m.ullTotalPhys : 0.0;
    }
    return s;
}

std::string imagePathByPid(uint32_t pid) {
    NtQsiFn q = ntQsi();
    if (!q) return {};
    struct {
        HANDLE ProcessId;
        UStr   ImageName;
    } info{};
    std::vector<wchar_t> buf(1024);
    info.ProcessId = (HANDLE)(ULONG_PTR)pid;
    info.ImageName.Buffer = buf.data();
    info.ImageName.MaximumLength = (USHORT)(buf.size() * sizeof(wchar_t));
    constexpr ULONG kSystemProcessIdInformation = 88;
    if (q(kSystemProcessIdInformation, &info, sizeof info, nullptr) < 0 || !info.ImageName.Length) return {};
    std::wstring nt(info.ImageName.Buffer, info.ImageName.Length / sizeof(wchar_t));

    // \Device\HarddiskVolume3\Windows\System32\dwm.exe  ->  C:\Windows\...
    wchar_t drives[512];
    DWORD n = GetLogicalDriveStringsW((DWORD)std::size(drives), drives);
    for (const wchar_t* d = drives; n && *d; d += wcslen(d) + 1) {
        wchar_t letter[3] = {d[0], L':', 0}, device[512];
        if (!QueryDosDeviceW(letter, device, (DWORD)std::size(device))) continue;
        size_t len = wcslen(device);
        if (nt.size() > len && nt[len] == L'\\' && _wcsnicmp(nt.c_str(), device, len) == 0)
            return narrow(std::wstring(letter) + nt.substr(len));
    }
    return {};
}

int64_t unixNow() {
    FILETIME f;
    GetSystemTimeAsFileTime(&f);
    return (int64_t)(ftToU64(f) / 10000000ULL) - 11644473600LL;
}

void applyDeltas(const std::vector<Proc>& prev, std::vector<Proc>& cur, double dtSec, int ncpu) {
    std::unordered_map<uint32_t, const Proc*> byPid;
    byPid.reserve(prev.size());
    for (const Proc& p : prev) byPid[p.pid] = &p;

    double cap = dtSec > 0 ? dtSec * (ncpu < 1 ? 1 : ncpu) : 0;
    for (Proc& c : cur) {
        uint64_t before = 0;
        auto it = byPid.find(c.pid);
        if (it != byPid.end() && it->second->created == c.created) before = it->second->cpu100ns;
        double sec = c.cpu100ns > before ? (double)(c.cpu100ns - before) / 1e7 : 0.0;
        if (c.pid == 0) sec = 0;  // Idle is not load
        if (sec > cap) sec = cap;
        c.cpuSec = sec;
        c.cpuFrac = cap > 0 ? sec / cap : 0;
    }
}

}  // namespace culprit
