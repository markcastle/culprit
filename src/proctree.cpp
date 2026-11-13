#include "proctree.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace culprit {

std::string lowerAscii(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

std::string groupKey(const std::string& image) { return lowerAscii(image); }

std::string stripExe(const std::string& image) {
    if (image.size() > 4 && lowerAscii(image.substr(image.size() - 4)) == ".exe")
        return image.substr(0, image.size() - 4);
    return image;
}

int parentIndex(const std::vector<Proc>& procs, size_t child) {
    const Proc& c = procs[child];
    if (c.pid == 0 || c.ppid == c.pid) return -1;
    for (size_t i = 0; i < procs.size(); i++) {
        if (i == child || procs[i].pid != c.ppid) continue;
        return procs[i].created <= c.created ? (int)i : -1;
    }
    return -1;
}

std::vector<size_t> descendants(const std::vector<Proc>& procs, size_t root) {
    // children-by-parent, validated once
    std::unordered_multimap<size_t, size_t> kids;
    for (size_t i = 0; i < procs.size(); i++) {
        int p = parentIndex(procs, i);
        if (p >= 0) kids.emplace((size_t)p, i);
    }
    std::vector<size_t> out;
    std::unordered_set<size_t> seen{root};
    std::vector<size_t> frontier{root};
    while (!frontier.empty()) {
        std::vector<size_t> next;
        for (size_t p : frontier) {
            auto [a, b] = kids.equal_range(p);
            std::vector<size_t> level;
            for (auto it = a; it != b; ++it)
                if (seen.insert(it->second).second) level.push_back(it->second);
            std::sort(level.begin(), level.end());
            out.insert(out.end(), level.begin(), level.end());
            next.insert(next.end(), level.begin(), level.end());
        }
        frontier = std::move(next);
    }
    return out;
}

int findProc(const std::vector<Proc>& procs, ProcId id) {
    for (size_t i = 0; i < procs.size(); i++)
        if (procs[i].pid == id.pid && procs[i].created == id.created) return (int)i;
    return -1;
}

std::vector<size_t> groupRoots(const std::vector<Proc>& procs, const std::vector<size_t>& members) {
    std::unordered_set<size_t> in(members.begin(), members.end());
    std::vector<size_t> roots;
    for (size_t m : members) {
        int p = parentIndex(procs, m);
        if (p < 0 || !in.count((size_t)p)) roots.push_back(m);
    }
    return roots;
}

int mainProcess(const std::vector<Proc>& procs, const std::vector<size_t>& members) {
    auto roots = groupRoots(procs, members);
    if (roots.empty()) return members.empty() ? -1 : (int)members.front();
    size_t best = roots.front();
    for (size_t r : roots) {
        const Proc &a = procs[r], &b = procs[best];
        if (a.privBytes > b.privBytes || (a.privBytes == b.privBytes && a.pid < b.pid)) best = r;
    }
    return (int)best;
}

bool isCriticalName(uint32_t pid, const std::string& image) {
    if (pid == 0 || pid == 4) return true;
    static const char* const names[] = {
        "system",       "registry",    "secure system", "memory compression",
        "smss.exe",     "csrss.exe",   "wininit.exe",   "winlogon.exe",
        "services.exe", "lsass.exe",   "lsaiso.exe",    "ntoskrnl.exe",
    };
    std::string k = lowerAscii(image);
    for (const char* n : names)
        if (k == n) return true;
    return false;
}

std::vector<Group> buildGroups(const std::vector<Proc>& procs) {
    std::vector<Group> groups;
    std::unordered_map<std::string, size_t> index;
    for (size_t i = 0; i < procs.size(); i++) {
        const Proc& p = procs[i];
        if (p.pid == 0) continue;
        std::string key = groupKey(p.image);
        auto [it, fresh] = index.emplace(key, groups.size());
        if (fresh) {
            Group g;
            g.key = key;
            g.display = stripExe(p.image);
            groups.push_back(std::move(g));
        }
        Group& g = groups[it->second];
        g.members.push_back(i);
        g.cpuFrac += p.cpuFrac;
        g.privBytes += p.privBytes;
    }
    return groups;
}

}  // namespace culprit
