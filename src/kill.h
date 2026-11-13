// Process termination with the safeguards the spec demands.
#pragma once
#include "model.h"

namespace culprit {

enum class KillStatus {
    Ended,
    AlreadyGone,   // exited on its own before we got to it
    AccessDenied,  // Windows refused; elevation may help
    Blocked,       // critical to Windows, or part of Culprit: never attempted
    Changed,       // pid now belongs to a different process: never attempted
    Failed,
};

struct KillItem {
    uint32_t    pid = 0;
    uint64_t    created = 0;
    std::string image;
    KillStatus  status = KillStatus::Failed;
    uint32_t    error = 0;
};

struct KillReport {
    std::string           refusal;  // set when nothing was attempted at all
    std::vector<KillItem> items;
    bool                  elevated = false;  // produced by an elevated instance

    int  count(KillStatus s) const;
    bool anyDenied() const { return count(KillStatus::AccessDenied) > 0; }
};

// Why this process must never be terminated, or "" if it may be.
std::string blockReason(const Proc& p);

// The processes an operation would touch right now (root first), from an
// existing snapshot. Used to show the user a count before they confirm.
std::vector<size_t> planKill(const std::vector<Proc>& procs, size_t root, bool tree);

// Takes a fresh snapshot, re-verifies identity and descendants, then acts.
KillReport killProcess(ProcId target, bool tree);

// End exactly these processes (no tree expansion), each re-verified.
KillReport killMany(const std::vector<ProcId>& targets);

// The processes in a report that Windows refused to end.
std::vector<ProcId> deniedTargets(const KillReport& r);

// Relaunch this exe elevated through UAC for one operation on exactly these
// processes and collect its report. Returns false (with `error`) if
// elevation was declined or failed.
bool killElevated(const std::vector<ProcId>& targets, KillReport& out, std::string& error);

// Entry point of that temporary elevated instance.
int elevatedKillMain(int argc, wchar_t** argv);

const char* statusText(KillStatus s, bool elevated);

}  // namespace culprit
