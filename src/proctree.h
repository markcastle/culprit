// Pure process-relationship logic: grouping, trees, kill safeguards.
#pragma once
#include "model.h"

namespace culprit {

std::string lowerAscii(std::string s);
std::string groupKey(const std::string& image);
std::string stripExe(const std::string& image);

// A parent link is only real if the parent was created no later than the
// child; otherwise the ppid has been recycled by an unrelated process.
// Returns the index of the true parent in `procs`, or -1.
int parentIndex(const std::vector<Proc>& procs, size_t child);

// Indexes of every true descendant of `root` (root itself excluded),
// breadth-first so parents always precede their children.
std::vector<size_t> descendants(const std::vector<Proc>& procs, size_t root);

// Index of the process with this identity, or -1 if it is gone / recycled.
int findProc(const std::vector<Proc>& procs, ProcId id);

// Members of a group whose parent is not in the same group.
std::vector<size_t> groupRoots(const std::vector<Proc>& procs, const std::vector<size_t>& members);

// The process that best represents a group: its only root, or, when the
// group has several unrelated roots, the one holding the most memory.
int mainProcess(const std::vector<Proc>& procs, const std::vector<size_t>& members);

// Processes Windows cannot survive losing. Name-based; the Win32 layer adds
// the kernel's own "critical process" flag on top of this.
bool isCriticalName(uint32_t pid, const std::string& image);

// Build groups (members only; no display names or scores) from a snapshot.
// Pid 0 (Idle) is excluded.
std::vector<Group> buildGroups(const std::vector<Proc>& procs);

}  // namespace culprit
