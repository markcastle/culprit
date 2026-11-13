// History: per-minute totals held in memory, plus a plain-text journal on
// disk so history survives restarts and can be shared between the background
// collector and the live view. No database.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "recorder.h"

namespace culprit {

struct HistoryWindow {
    WindowTotals sys;
    std::unordered_map<std::string, AppTotals> apps;
};

inline constexpr int64_t kMemoryMinutes = 24 * 60;  // what is kept in memory
inline constexpr int64_t kRetainDays    = 7;        // what is kept on disk

// Pure, in-memory. About 1 MB for a full 24 hours on a busy machine.
class History {
public:
    void merge(const MinuteDelta& d);  // additive
    void query(int64_t fromMinute, int64_t toMinute, HistoryWindow& out) const;
    void prune(int64_t beforeMinute);
    size_t minutes() const { return minutes_.size(); }

private:
    struct Row {
        uint32_t  app;
        AppTotals t;
    };
    struct Minute {
        WindowTotals     sys;
        std::vector<Row> rows;
    };
    uint32_t intern(const std::string& name);

    std::map<int64_t, Minute> minutes_;
    std::unordered_map<std::string, uint32_t> ids_;
    std::vector<std::string> names_;
};

// Journal text format, one record per line, one file per UTC day:
//   S <minute> <obsSec> <cpuCapSec> <ramByteSec>
//   A <minute> <cpuSec> <memWeightedByteSec> <app key>
std::string formatJournal(const MinuteDelta& d);
// Parses complete lines only; returns how many bytes were consumed.
size_t parseJournal(const std::string& text, std::vector<MinuteDelta>& out);

// Append-only files in a directory. One writer at a time (enforced by the
// caller); any number of readers following along with tail().
class Journal {
public:
    explicit Journal(std::string dir) : dir_(std::move(dir)) {}

    // Read everything not yet seen, up to and including `nowMinute`'s day,
    // into `into`. The first call loads the last 24 hours.
    bool tail(int64_t nowMinute, History& into);
    // Write deltas; they are *not* echoed back by a later tail() here.
    bool append(const std::vector<MinuteDelta>& deltas, int64_t nowMinute, History* seen);
    void removeOlderThan(int64_t nowMinute);

    std::string fileFor(int64_t day) const;

private:
    std::string dir_;
    bool    started_ = false;
    int64_t day_ = 0;      // file currently being followed
    uint64_t offset_ = 0;  // bytes of it already consumed
};

}  // namespace culprit
