#include "kill.h"

#include <cstdlib>
#include <sstream>

#include "inspect.h"
#include "proctree.h"
#include "sampler.h"
#include "win.h"

#include <shellapi.h>

namespace culprit {

int KillReport::count(KillStatus s) const {
    int n = 0;
    for (const KillItem& i : items) n += i.status == s;
    return n;
}

const char* statusText(KillStatus s, bool elevated) {
    switch (s) {
        case KillStatus::Ended:        return "Ended";
        case KillStatus::AlreadyGone:  return "Already exited";
        case KillStatus::AccessDenied: return elevated ? "Protected by Windows" : "Access denied";
        case KillStatus::Blocked:      return "Blocked (critical process)";
        case KillStatus::Changed:      return "Skipped (PID was reused)";
        default:                       return "Failed";
    }
}

std::string blockReason(const Proc& p) {
    if (isCriticalName(p.pid, p.image)) return p.image + " is a critical Windows process";
    if (p.pid == GetCurrentProcessId()) return "this is Culprit itself";

    Handle h = openVerified(p.pid, p.created, 0);
    if (h) {
        BOOL critical = FALSE;
        if (IsProcessCritical(h, &critical) && critical) return p.image + " is marked critical by Windows";
        wchar_t buf[32768];
        DWORD n = (DWORD)std::size(buf);
        if (QueryFullProcessImageNameW(h, 0, buf, &n) &&
            CompareStringOrdinal(buf, (int)n, widen(selfPath()).c_str(), -1, TRUE) == CSTR_EQUAL)
            return "this is part of Culprit (use 'culprit track off' to stop the collector)";
    }
    return {};
}

std::vector<size_t> planKill(const std::vector<Proc>& procs, size_t root, bool tree) {
    std::vector<size_t> plan{root};
    if (tree) {
        auto d = descendants(procs, root);
        plan.insert(plan.end(), d.begin(), d.end());
    }
    return plan;
}

KillReport killProcess(ProcId target, bool tree) {
    KillReport rep;
    rep.elevated = isElevated();

    // Fresh snapshot: identity and descendants are decided now, not from
    // whatever the screen was showing a moment ago.
    Snapshot snap;
    if (!takeSnapshot(snap)) {
        rep.refusal = "Could not read the process table.";
        return rep;
    }
    int root = findProc(snap.procs, target);
    if (root < 0) {
        rep.refusal = "That process has already exited.";
        return rep;
    }
    std::string why = blockReason(snap.procs[(size_t)root]);
    if (!why.empty()) {
        rep.refusal = "Refused: " + why + ".";
        return rep;
    }

    std::vector<size_t> plan = planKill(snap.procs, (size_t)root, tree);

    // Pin every target with a verified handle before ending any of them, so
    // nothing in the plan can be swapped for a recycled pid mid-operation.
    std::vector<Handle> handles(plan.size());
    for (size_t i = 0; i < plan.size(); i++) {
        const Proc& p = snap.procs[plan[i]];
        KillItem item;
        item.pid = p.pid;
        item.created = p.created;
        item.image = p.image;

        if (i > 0 && !blockReason(p).empty()) {
            item.status = KillStatus::Blocked;
        } else {
            handles[i] = openVerified(p.pid, p.created, PROCESS_TERMINATE | SYNCHRONIZE);
            if (!handles[i]) {
                item.error = GetLastError();
                if (item.error == ERROR_ACCESS_DENIED) {
                    item.status = KillStatus::AccessDenied;
                } else {
                    // Distinguish "gone" from "pid now belongs to someone else".
                    Handle probe(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid));
                    item.status = probe ? KillStatus::Changed : KillStatus::AlreadyGone;
                }
            }
        }
        rep.items.push_back(std::move(item));
    }

    for (size_t i = 0; i < plan.size(); i++) {
        if (!handles[i]) continue;
        KillItem& item = rep.items[i];
        if (TerminateProcess(handles[i], 1)) {
            item.status = KillStatus::Ended;
            continue;
        }
        item.error = GetLastError();
        if (WaitForSingleObject(handles[i], 0) == WAIT_OBJECT_0)
            item.status = KillStatus::AlreadyGone;  // died with its parent
        else
            item.status = item.error == ERROR_ACCESS_DENIED ? KillStatus::AccessDenied : KillStatus::Failed;
    }
    return rep;
}

KillReport killMany(const std::vector<ProcId>& targets) {
    KillReport all;
    all.elevated = isElevated();
    Snapshot snap;
    takeSnapshot(snap);
    for (ProcId id : targets) {
        int idx = findProc(snap.procs, id);
        KillItem item;
        item.pid = id.pid;
        item.created = id.created;
        if (idx < 0) {
            item.status = KillStatus::AlreadyGone;
            all.items.push_back(item);
            continue;
        }
        item.image = snap.procs[(size_t)idx].image;
        KillReport one = killProcess(id, false);
        if (!one.items.empty())
            item = one.items.front();
        else
            item.status = one.refusal.rfind("Refused", 0) == 0 ? KillStatus::Blocked : KillStatus::AlreadyGone;
        all.items.push_back(item);
    }
    return all;
}

std::vector<ProcId> deniedTargets(const KillReport& r) {
    std::vector<ProcId> out;
    for (const KillItem& i : r.items)
        if (i.status == KillStatus::AccessDenied) out.push_back({i.pid, i.created});
    return out;
}

// ---------------------------------------------------------------------------
// Elevation: a temporary elevated instance does one operation and reports
// back over a private pipe. The main instance never becomes elevated.
// ---------------------------------------------------------------------------

namespace {

std::string serialise(const KillReport& r) {
    std::ostringstream o;
    if (!r.refusal.empty()) o << "R\t" << r.refusal << "\n";
    for (const KillItem& i : r.items)
        o << "I\t" << i.pid << "\t" << i.created << "\t" << (int)i.status << "\t" << i.error << "\t" << i.image
          << "\n";
    return o.str();
}

bool parse(const std::string& text, KillReport& r) {
    std::istringstream in(text);
    std::string line;
    bool any = false;
    while (std::getline(in, line)) {
        if (line.rfind("R\t", 0) == 0) {
            r.refusal = line.substr(2);
            any = true;
        } else if (line.rfind("I\t", 0) == 0) {
            std::istringstream f(line.substr(2));
            std::string pid, created, status, error, image;
            if (!std::getline(f, pid, '\t') || !std::getline(f, created, '\t') || !std::getline(f, status, '\t') ||
                !std::getline(f, error, '\t'))
                continue;
            std::getline(f, image);
            KillItem item;
            item.pid = (uint32_t)strtoul(pid.c_str(), nullptr, 10);
            item.created = strtoull(created.c_str(), nullptr, 10);
            int s = atoi(status.c_str());
            item.status = s >= 0 && s <= (int)KillStatus::Failed ? (KillStatus)s : KillStatus::Failed;
            item.error = (uint32_t)strtoul(error.c_str(), nullptr, 10);
            item.image = image;
            r.items.push_back(std::move(item));
            any = true;
        }
    }
    return any;
}

void enableDebugPrivilege() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &raw)) return;
    Handle tok(raw);
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr);
}

}  // namespace

bool killElevated(const std::vector<ProcId>& targets, KillReport& out, std::string& error) {
    wchar_t pipeName[128];
    LARGE_INTEGER salt;
    QueryPerformanceCounter(&salt);
    swprintf(pipeName, std::size(pipeName), L"\\\\.\\pipe\\culprit-%lu-%llx", GetCurrentProcessId(),
             (unsigned long long)salt.QuadPart);

    Handle pipe(CreateNamedPipeW(pipeName, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 0,
                                 16384, 0, nullptr));
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!pipe || !event) {
        error = "Could not prepare elevation.";
        return false;
    }
    OVERLAPPED ov{};
    ov.hEvent = event;
    bool connected = false;
    if (ConnectNamedPipe(pipe, &ov) || GetLastError() == ERROR_PIPE_CONNECTED)
        connected = true;
    else if (GetLastError() != ERROR_IO_PENDING) {
        error = "Could not prepare elevation.";
        return false;
    }

    std::wstring args = L"--elevated-kill \"" + std::wstring(pipeName) + L"\"";
    for (ProcId t : targets) args += L" " + std::to_wstring(t.pid) + L":" + std::to_wstring(t.created);
    std::wstring exe = widen(selfPath());

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof sei;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpVerb = L"runas";
    sei.lpFile = exe.c_str();
    sei.lpParameters = args.c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei) || !sei.hProcess) {
        CancelIo(pipe);
        error = GetLastError() == ERROR_CANCELLED ? "Elevation was declined. Nothing was ended."
                                                  : "Could not start the elevated instance.";
        return false;
    }
    Handle child(sei.hProcess);

    if (!connected) {
        HANDLE waits[2] = {event, child};
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, 60000);
        if (w != WAIT_OBJECT_0 && WaitForSingleObject(event, 500) != WAIT_OBJECT_0) {
            CancelIo(pipe);
            error = "The elevated instance did not report back.";
            return false;
        }
    }

    std::string text;
    for (;;) {
        char buf[4096];
        DWORD got = 0;
        ResetEvent(event);
        if (!ReadFile(pipe, buf, sizeof buf, &got, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING) break;
            if (!GetOverlappedResult(pipe, &ov, &got, TRUE)) break;
        }
        if (!got) break;
        text.append(buf, got);
        if (text.size() > (1u << 20)) break;
    }
    WaitForSingleObject(child, 5000);

    out = {};
    out.elevated = true;
    if (!parse(text, out)) {
        error = "The elevated instance did not report back.";
        return false;
    }
    return true;
}

int elevatedKillMain(int argc, wchar_t** argv) {
    // culprit --elevated-kill <pipe> <pid>:<created> [<pid>:<created> ...]
    if (argc < 4) return 2;
    std::vector<ProcId> targets;
    for (int i = 3; i < argc; i++) {
        wchar_t* end = nullptr;
        ProcId t;
        t.pid = (uint32_t)wcstoul(argv[i], &end, 10);
        if (!end || *end != L':') return 2;
        t.created = wcstoull(end + 1, nullptr, 10);
        targets.push_back(t);
    }

    Handle pipe(CreateFileW(argv[2], GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!pipe) return 3;

    KillReport rep;
    if (!isElevated()) {
        rep.refusal = "Elevation did not take effect.";
    } else {
        enableDebugPrivilege();
        rep = killMany(targets);
    }
    std::string text = serialise(rep);
    DWORD wrote = 0;
    WriteFile(pipe, text.data(), (DWORD)text.size(), &wrote, nullptr);
    FlushFileBuffers(pipe);
    return 0;
}

}  // namespace culprit
