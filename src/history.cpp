#include "history.h"

#include <cstdio>
#include <cstdlib>

#include "win.h"

namespace culprit {

// ------------------------------------------------------------- History ----

uint32_t History::intern(const std::string& name) {
    auto [it, fresh] = ids_.emplace(name, (uint32_t)names_.size());
    if (fresh) names_.push_back(name);
    return it->second;
}

void History::merge(const MinuteDelta& d) {
    Minute& m = minutes_[d.minute];
    m.sys.obsSec += d.sys.obsSec;
    m.sys.cpuCapSec += d.sys.cpuCapSec;
    m.sys.ramBs += d.sys.ramBs;
    for (const auto& [name, t] : d.apps) {
        uint32_t id = intern(name);
        Row* row = nullptr;
        for (Row& r : m.rows)
            if (r.app == id) { row = &r; break; }
        if (!row) {
            m.rows.push_back({id, {}});
            row = &m.rows.back();
        }
        row->t.cpuSec += t.cpuSec;
        row->t.memwBs += t.memwBs;
    }
}

void History::query(int64_t fromMinute, int64_t toMinute, HistoryWindow& out) const {
    out = {};
    std::vector<AppTotals> sums(names_.size());
    for (auto it = minutes_.lower_bound(fromMinute); it != minutes_.end() && it->first <= toMinute; ++it) {
        const Minute& m = it->second;
        out.sys.obsSec += m.sys.obsSec;
        out.sys.cpuCapSec += m.sys.cpuCapSec;
        out.sys.ramBs += m.sys.ramBs;
        for (const Row& r : m.rows) {
            sums[r.app].cpuSec += r.t.cpuSec;
            sums[r.app].memwBs += r.t.memwBs;
        }
    }
    for (size_t i = 0; i < sums.size(); i++)
        if (sums[i].cpuSec > 0 || sums[i].memwBs > 0) out.apps.emplace(names_[i], sums[i]);
}

void History::prune(int64_t beforeMinute) { minutes_.erase(minutes_.begin(), minutes_.lower_bound(beforeMinute)); }

// -------------------------------------------------------------- format ----

std::string formatJournal(const MinuteDelta& d) {
    char b[256];
    snprintf(b, sizeof b, "S\t%lld\t%.9g\t%.9g\t%.9g\n", (long long)d.minute, d.sys.obsSec, d.sys.cpuCapSec,
             d.sys.ramBs);
    std::string out = b;
    for (const auto& [name, t] : d.apps) {
        if (name.find_first_of("\t\r\n") != std::string::npos) continue;
        snprintf(b, sizeof b, "A\t%lld\t%.9g\t%.9g\t", (long long)d.minute, t.cpuSec, t.memwBs);
        out += b;
        out += name;
        out += '\n';
    }
    return out;
}

size_t parseJournal(const std::string& text, std::vector<MinuteDelta>& out) {
    size_t pos = 0;
    for (;;) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) break;
        std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() < 3 || line[1] != '\t') continue;

        const char* p = line.c_str() + 2;
        char* end = nullptr;
        long long minute = strtoll(p, &end, 10);
        if (end == p || *end != '\t') continue;
        double v[3] = {0, 0, 0};
        int want = line[0] == 'S' ? 3 : line[0] == 'A' ? 2 : 0;
        bool ok = want > 0;
        for (int i = 0; ok && i < want; i++) {
            p = end + 1;
            v[i] = strtod(p, &end);
            ok = end != p && (*end == '\t' || *end == '\0') && v[i] >= 0;
        }
        if (!ok) continue;  // a damaged line costs one record, not the file

        if (out.empty() || out.back().minute != minute) {
            out.emplace_back();
            out.back().minute = minute;
        }
        MinuteDelta& d = out.back();
        if (line[0] == 'S') {
            d.sys.obsSec += v[0];
            d.sys.cpuCapSec += v[1];
            d.sys.ramBs += v[2];
        } else if (*end == '\t' && end[1] != '\0') {
            AppTotals& t = d.apps[end + 1];
            t.cpuSec += v[0];
            t.memwBs += v[1];
        }
    }
    return pos;
}

// ------------------------------------------------------------- Journal ----

namespace {

int64_t dayOf(int64_t minute) { return minute >= 0 ? minute / 1440 : (minute - 1439) / 1440; }

// Reads from `offset` to the end of the file. Missing file is not an error.
bool readFrom(const std::string& path, uint64_t offset, std::string& out) {
    out.clear();
    Handle f(CreateFileW(widen(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!f) return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
    LARGE_INTEGER size, at;
    if (!GetFileSizeEx(f, &size) || (uint64_t)size.QuadPart <= offset) return true;
    at.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(f, at, nullptr, FILE_BEGIN)) return false;
    uint64_t left = (uint64_t)size.QuadPart - offset;
    if (left > (64u << 20)) left = 64u << 20;
    out.resize((size_t)left);
    size_t done = 0;
    while (done < out.size()) {
        DWORD got = 0;
        if (!ReadFile(f, out.data() + done, (DWORD)(out.size() - done), &got, nullptr) || !got) break;
        done += got;
    }
    out.resize(done);
    return true;
}

}  // namespace

std::string Journal::fileFor(int64_t day) const {
    return dir_ + "\\history-" + std::to_string((long long)day) + ".tsv";
}

bool Journal::tail(int64_t nowMinute, History& into) {
    int64_t today = dayOf(nowMinute);
    if (!started_) {
        started_ = true;
        day_ = dayOf(nowMinute - kMemoryMinutes);
        offset_ = 0;
    }
    bool ok = true;
    for (;;) {
        std::string text;
        std::vector<MinuteDelta> deltas;
        if (readFrom(fileFor(day_), offset_, text)) {
            offset_ += parseJournal(text, deltas);
            for (const MinuteDelta& d : deltas) into.merge(d);
        } else {
            ok = false;
        }
        if (day_ >= today) break;
        day_++;
        offset_ = 0;
    }
    return ok;
}

bool Journal::append(const std::vector<MinuteDelta>& deltas, int64_t nowMinute, History* seen) {
    if (deltas.empty()) return true;
    // Catch up on anything a previous writer left, so our own lines are the
    // only thing between offset_ and the end of the file afterwards.
    History scratch;
    tail(nowMinute, seen ? *seen : scratch);

    bool ok = true;
    for (const MinuteDelta& d : deltas) {
        std::string text = formatJournal(d);
        int64_t day = dayOf(d.minute);
        Handle f(CreateFileW(widen(fileFor(day)).c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        DWORD wrote = 0;
        if (!f || !WriteFile(f, text.data(), (DWORD)text.size(), &wrote, nullptr) || wrote != text.size()) {
            ok = false;
            continue;
        }
        if (day == day_) offset_ += wrote;
    }
    return ok;
}

void Journal::removeOlderThan(int64_t nowMinute) {
    int64_t keepFrom = dayOf(nowMinute) - kRetainDays;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(widen(dir_ + "\\history-*.tsv").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        std::string name = narrow(fd.cFileName);
        long long day = atoll(name.c_str() + 8);  // after "history-"
        if (day > 0 && day < keepFrom) DeleteFileW(widen(dir_ + "\\" + name).c_str());
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

}  // namespace culprit
