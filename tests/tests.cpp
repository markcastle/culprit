// Unit tests. Tiny home-grown harness: no dependency to fetch.
#include <cmath>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "format.h"
#include "proctree.h"
#include "recorder.h"
#include "sampler.h"
#include "score.h"
#include "history.h"
#include "win.h"

using namespace culprit;

static int g_failed = 0, g_checks = 0;
static const char* g_test = "";

#define CHECK(cond)                                                              \
    do {                                                                         \
        g_checks++;                                                              \
        if (!(cond)) {                                                           \
            g_failed++;                                                          \
            printf("FAIL %s  %s:%d  %s\n", g_test, __FILE__, __LINE__, #cond);   \
        }                                                                        \
    } while (0)

#define CHECK_EQ(a, b)                                                           \
    do {                                                                         \
        g_checks++;                                                              \
        auto va = (a);                                                           \
        auto vb = (b);                                                           \
        if (!(va == vb)) {                                                       \
            g_failed++;                                                          \
            printf("FAIL %s  %s:%d  %s == %s\n", g_test, __FILE__, __LINE__, #a, #b); \
        }                                                                        \
    } while (0)

struct Test {
    const char* name;
    std::function<void()> fn;
};
static std::vector<Test>& tests() {
    static std::vector<Test> t;
    return t;
}
struct Reg {
    Reg(const char* n, std::function<void()> f) { tests().push_back({n, std::move(f)}); }
};
#define TEST(name)                         \
    static void name();                    \
    static Reg reg_##name(#name, name);    \
    static void name()

static const double GB = 1024.0 * 1024.0 * 1024.0;

// One hour observed on an 8-CPU, 16 GB machine.
static WindowTotals hourWindow() {
    WindowTotals w;
    w.obsSec = 3600;
    w.cpuCapSec = 3600 * 8;
    w.ramBs = 3600 * 16 * GB;
    return w;
}

// ---------------------------------------------------------------- score ----

TEST(impact_needs_history) {
    WindowTotals w = hourWindow();
    w.obsSec = 59;
    CHECK(!impact({100, 0}, w).has_value());
    w.obsSec = 60;
    CHECK(impact({100, 0}, w).has_value());
    CHECK(!impact({1, 1}, WindowTotals{}).has_value());
}

TEST(impact_cpu_saturates_at_15_percent) {
    WindowTotals w = hourWindow();
    CHECK_EQ(*impact({0.15 * w.cpuCapSec, 0}, w), 70);
    CHECK_EQ(*impact({0.50 * w.cpuCapSec, 0}, w), 70);
    CHECK_EQ(*impact({0.075 * w.cpuCapSec, 0}, w), 35);
    CHECK_EQ(*impact({0, 0}, w), 0);
}

TEST(impact_memory_saturates_at_12_percent) {
    WindowTotals w = hourWindow();
    CHECK_EQ(*impact({0, 0.12 * w.ramBs}, w), 30);
    CHECK_EQ(*impact({0, 0.90 * w.ramBs}, w), 30);
    CHECK_EQ(*impact({0, 0.06 * w.ramBs}, w), 15);
}

TEST(impact_combines_and_clamps) {
    WindowTotals w = hourWindow();
    CHECK_EQ(*impact({w.cpuCapSec, w.ramBs}, w), 100);
    CHECK_EQ(*impact({0.075 * w.cpuCapSec, 0.06 * w.ramBs}, w), 50);
    CHECK_EQ(*impact({-5, -5}, w), 0);
}

TEST(impact_is_deterministic) {
    WindowTotals w = hourWindow();
    AppTotals a{1234.5, 0.031 * w.ramBs};
    int first = *impact(a, w);
    for (int i = 0; i < 100; i++) CHECK_EQ(*impact(a, w), first);
}

TEST(sustained_load_outranks_brief_spike) {
    WindowTotals w = hourWindow();
    // 5% of the machine for the whole hour vs 100% of it for one minute.
    AppTotals sustained{0.05 * w.cpuCapSec, 0};
    AppTotals spike{60.0 * 8, 0};
    CHECK(*impact(sustained, w) > *impact(spike, w));
}

TEST(time_not_running_dilutes_the_score) {
    WindowTotals w = hourWindow();
    // 15% of the machine, but only for 30 of the 60 observed minutes.
    AppTotals half{0.15 * 8 * 1800, 0};
    CHECK_EQ(*impact(half, w), 35);
}

TEST(pressure_factor_curve) {
    CHECK_EQ(pressureFactor(0.0), 0.5);
    CHECK_EQ(pressureFactor(0.5), 0.5);
    CHECK_EQ(pressureFactor(0.9), 1.0);
    CHECK_EQ(pressureFactor(1.0), 1.0);
    CHECK(std::fabs(pressureFactor(0.7) - 0.75) < 1e-9);
    CHECK(pressureFactor(0.8) > pressureFactor(0.6));
}

// ------------------------------------------------------------- recorder ----

static SampleTick tick(int64_t t, double dt, double cpuSec, double bytes, double load = 0.9) {
    SampleTick s;
    s.unixSec = t;
    s.dtSec = dt;
    s.ncpu = 8;
    s.totalRam = 16 * GB;
    s.memLoad = load;
    s.apps.push_back({"app.exe", cpuSec, bytes});
    return s;
}

TEST(recorder_accumulates_into_minutes) {
    Recorder r;
    for (int i = 0; i < 12; i++) r.add(tick(6000 + i * 5, 5, 1.0, 2 * GB));  // minute 100
    r.add(tick(6060, 5, 1.0, 2 * GB));                                       // minute 101
    auto out = r.take();
    CHECK_EQ(out.size(), (size_t)2);
    CHECK_EQ(out[0].minute, (int64_t)100);
    CHECK(std::fabs(out[0].sys.obsSec - 60) < 1e-9);
    CHECK(std::fabs(out[0].sys.cpuCapSec - 480) < 1e-9);
    CHECK(std::fabs(out[0].apps["app.exe"].cpuSec - 12) < 1e-9);
    CHECK(std::fabs(out[0].apps["app.exe"].memwBs - 2 * GB * 60) < 1);
    CHECK_EQ(out[1].minute, (int64_t)101);
    CHECK(r.empty());
    CHECK(r.take().empty());
}

TEST(recorder_weights_memory_by_pressure) {
    Recorder relaxed, pressed;
    relaxed.add(tick(6000, 5, 0, 4 * GB, 0.3));
    pressed.add(tick(6000, 5, 0, 4 * GB, 0.95));
    double a = relaxed.take()[0].apps["app.exe"].memwBs;
    double b = pressed.take()[0].apps["app.exe"].memwBs;
    CHECK(std::fabs(b - 2 * a) < 1);
}

TEST(recorder_treats_long_gaps_as_unobserved) {
    Recorder r;
    r.add(tick(6000, 3600, 500, 2 * GB));  // machine slept for an hour
    r.add(tick(6005, 0, 1, 2 * GB));
    r.add(tick(6010, -1, 1, 2 * GB));
    CHECK(r.empty());
}

TEST(recorder_drops_insignificant_rows) {
    Recorder r;
    SampleTick t = tick(6000, 5, 1.0, 2 * GB);
    t.apps.push_back({"idle.exe", 0.0, 1024.0 * 1024.0});   // 1 MB, no CPU
    t.apps.push_back({"busy.exe", 0.5, 1024.0 * 1024.0});   // tiny RAM, real CPU
    r.add(t);
    auto out = r.take();
    CHECK_EQ(out[0].apps.count("idle.exe"), (size_t)0);
    CHECK_EQ(out[0].apps.count("busy.exe"), (size_t)1);
    CHECK_EQ(out[0].apps.count("app.exe"), (size_t)1);
}

// ------------------------------------------------------------- proctree ----

static Proc proc(uint32_t pid, uint32_t ppid, uint64_t created, const char* image, uint64_t priv = 0) {
    Proc p;
    p.pid = pid;
    p.ppid = ppid;
    p.created = created;
    p.image = image;
    p.privBytes = priv;
    return p;
}

// explorer(10) -> chrome(20) -> chrome(21), chrome(22) -> helper(23)
// explorer(10) -> notepad(30)
// svchost(40), svchost(41) under services(5)
// stale(50) claims parent pid 20 but was created *before* 20: recycled pid.
static std::vector<Proc> sampleProcs() {
    return {
        proc(0, 0, 0, "Idle"),
        proc(4, 0, 1, "System"),
        proc(5, 4, 2, "services.exe"),
        proc(10, 99, 100, "explorer.exe"),
        proc(20, 10, 200, "chrome.exe", 500),
        proc(21, 20, 210, "chrome.exe", 100),
        proc(22, 20, 220, "Chrome.EXE", 300),
        proc(23, 22, 230, "helper.exe"),
        proc(30, 10, 240, "notepad.exe"),
        proc(40, 5, 50, "svchost.exe", 10),
        proc(41, 5, 60, "svchost.exe", 90),
        proc(50, 20, 150, "stale.exe"),
    };
}

static int indexOfPid(const std::vector<Proc>& v, uint32_t pid) {
    for (size_t i = 0; i < v.size(); i++)
        if (v[i].pid == pid) return (int)i;
    return -1;
}

TEST(parent_link_rejects_recycled_pids) {
    auto v = sampleProcs();
    CHECK_EQ(parentIndex(v, (size_t)indexOfPid(v, 21)), indexOfPid(v, 20));
    CHECK_EQ(parentIndex(v, (size_t)indexOfPid(v, 50)), -1);  // older than its "parent"
    CHECK_EQ(parentIndex(v, (size_t)indexOfPid(v, 10)), -1);  // parent gone
    CHECK_EQ(parentIndex(v, 0), -1);
}

TEST(descendants_follow_real_tree_only) {
    auto v = sampleProcs();
    auto d = descendants(v, (size_t)indexOfPid(v, 20));
    std::vector<uint32_t> pids;
    for (size_t i : d) pids.push_back(v[i].pid);
    CHECK_EQ(pids, (std::vector<uint32_t>{21, 22, 23}));  // not stale.exe, not notepad
    CHECK(descendants(v, (size_t)indexOfPid(v, 30)).empty());
}

TEST(tree_is_not_same_name) {
    auto v = sampleProcs();
    // Ending the tree of one svchost must not touch the other svchost.
    CHECK(descendants(v, (size_t)indexOfPid(v, 40)).empty());
    auto d = descendants(v, (size_t)indexOfPid(v, 22));
    CHECK_EQ(d.size(), (size_t)1);
    CHECK_EQ(v[d[0]].pid, (uint32_t)23);
}

TEST(descendants_survive_cycles) {
    std::vector<Proc> v = {proc(1, 2, 10, "a.exe"), proc(2, 1, 10, "b.exe")};
    CHECK(descendants(v, 0).size() <= 1);
}

TEST(find_proc_requires_matching_creation_time) {
    auto v = sampleProcs();
    CHECK_EQ(findProc(v, {20, 200}), indexOfPid(v, 20));
    CHECK_EQ(findProc(v, {20, 201}), -1);
    CHECK_EQ(findProc(v, {999, 200}), -1);
}

TEST(groups_by_image_case_insensitively) {
    auto v = sampleProcs();
    auto groups = buildGroups(v);
    const Group* chrome = nullptr;
    for (const Group& g : groups) {
        CHECK(g.key != "idle");
        if (g.key == "chrome.exe") chrome = &g;
    }
    CHECK(chrome != nullptr);
    if (chrome) {
        CHECK_EQ(chrome->members.size(), (size_t)3);
        CHECK_EQ(chrome->privBytes, (uint64_t)900);
        CHECK_EQ(chrome->display, std::string("chrome"));
    }
}

TEST(main_process_is_root_or_largest_root) {
    auto v = sampleProcs();
    for (const Group& g : buildGroups(v)) {
        if (g.key == "chrome.exe") {
            CHECK_EQ(groupRoots(v, g.members).size(), (size_t)1);
            CHECK_EQ(v[(size_t)mainProcess(v, g.members)].pid, (uint32_t)20);
        }
        if (g.key == "svchost.exe") {
            CHECK_EQ(groupRoots(v, g.members).size(), (size_t)2);
            CHECK_EQ(v[(size_t)mainProcess(v, g.members)].pid, (uint32_t)41);
        }
    }
}

TEST(critical_names) {
    CHECK(isCriticalName(0, "Idle"));
    CHECK(isCriticalName(4, "anything"));
    CHECK(isCriticalName(600, "CSRSS.EXE"));
    CHECK(isCriticalName(700, "lsass.exe"));
    CHECK(isCriticalName(800, "wininit.exe"));
    CHECK(!isCriticalName(900, "chrome.exe"));
    CHECK(!isCriticalName(901, "notepad.exe"));
}

TEST(deltas_charge_cpu_and_handle_pid_reuse) {
    std::vector<Proc> prev = {proc(1, 0, 10, "a.exe"), proc(2, 0, 20, "b.exe")};
    prev[0].cpu100ns = 10'000'000;   // 1s
    prev[1].cpu100ns = 500'000'000;  // 50s
    std::vector<Proc> cur = {proc(1, 0, 10, "a.exe"), proc(2, 0, 99, "c.exe"), proc(0, 0, 0, "Idle")};
    cur[0].cpu100ns = 30'000'000;    // +2s
    cur[1].cpu100ns = 5'000'000;     // new process on a recycled pid: 0.5s total
    cur[2].cpu100ns = 900'000'000;
    applyDeltas(prev, cur, 1.0, 4);
    CHECK(std::fabs(cur[0].cpuSec - 2.0) < 1e-9);
    CHECK(std::fabs(cur[0].cpuFrac - 0.5) < 1e-9);
    CHECK(std::fabs(cur[1].cpuSec - 0.5) < 1e-9);
    CHECK_EQ(cur[2].cpuSec, 0.0);
}

// --------------------------------------------------------------- format ----

TEST(formats) {
    CHECK_EQ(fmtBytes(754ull * 1024 * 1024), std::string("754 MB"));
    CHECK_EQ(fmtBytes((uint64_t)(7.2 * GB)), std::string("7.2 GB"));
    CHECK_EQ(fmtBytes(512 * 1024), std::string("512 KB"));
    CHECK_EQ(fmtPercent(0.091), std::string("9.1%"));
    CHECK_EQ(fmtDuration(45), std::string("45s"));
    CHECK_EQ(fmtDuration(12 * 60), std::string("12m"));
    CHECK_EQ(fmtDuration(3 * 3600 + 5 * 60), std::string("3h 05m"));
}

TEST(clipping_counts_code_points) {
    CHECK_EQ(cells("na\xC3\xAFve"), (size_t)5);
    CHECK_EQ(clip("abcdef", 4), std::string("abc\xE2\x80\xA6"));
    CHECK_EQ(clip("abc", 4), std::string("abc"));
    CHECK_EQ(cells(padRight("\xC3\xA9", 4)), (size_t)4);
    CHECK_EQ(padLeft("7", 3), std::string("  7"));
    std::string p = clipPath("C:\\Users\\Someone\\AppData\\Local\\Programs\\Claude\\Claude.exe", 30);
    CHECK(cells(p) <= 30);
    CHECK(p.find("\\Claude.exe") != std::string::npos);
    CHECK(p.find("...") != std::string::npos);
}

// -------------------------------------------------------------- history ----

static std::vector<MinuteDelta> minutesOf(int64_t from, int64_t to) {
    Recorder r;
    for (int64_t m = from; m < to; m++)
        for (int i = 0; i < 12; i++) r.add(tick(m * 60 + i * 5, 5, 1.0, 2 * GB));
    return r.take();
}

TEST(history_windows_and_scores) {
    History h;
    for (const MinuteDelta& d : minutesOf(100, 110)) h.merge(d);
    HistoryWindow w;
    h.query(100, 109, w);
    CHECK(std::fabs(w.sys.obsSec - 600) < 1e-6);
    CHECK(std::fabs(w.apps["app.exe"].cpuSec - 120) < 1e-6);
    h.query(105, 109, w);
    CHECK(std::fabs(w.sys.obsSec - 300) < 1e-6);
    CHECK(std::fabs(w.apps["app.exe"].cpuSec - 60) < 1e-6);
    // 1 cpu-sec per 5s on 8 CPUs = 2.5% of the machine, plus saturated memory
    CHECK_EQ(*impact(w.apps["app.exe"], w.sys), (int)std::lround(70 * 0.025 / 0.15 + 30));

    h.prune(105);
    h.query(0, 1000, w);
    CHECK(std::fabs(w.sys.obsSec - 300) < 1e-6);
    CHECK_EQ(h.minutes(), (size_t)5);
}

TEST(history_merge_is_additive) {
    History h;
    auto one = minutesOf(100, 101);
    h.merge(one[0]);
    h.merge(one[0]);
    HistoryWindow w;
    h.query(100, 100, w);
    CHECK(std::fabs(w.sys.obsSec - 120) < 1e-6);
    CHECK(std::fabs(w.apps["app.exe"].cpuSec - 24) < 1e-6);
}

TEST(journal_text_round_trips) {
    auto in = minutesOf(100, 103);
    in[1].apps["name with spaces.exe"] = {3.25, 1e12};
    std::string text;
    for (const MinuteDelta& d : in) text += formatJournal(d);

    std::vector<MinuteDelta> out;
    CHECK_EQ(parseJournal(text, out), text.size());
    CHECK_EQ(out.size(), (size_t)3);
    CHECK_EQ(out[1].minute, (int64_t)101);
    CHECK(std::fabs(out[1].sys.cpuCapSec - 480) < 1e-6);
    CHECK(std::fabs(out[1].apps["name with spaces.exe"].cpuSec - 3.25) < 1e-9);
    CHECK(std::fabs(out[1].apps["app.exe"].memwBs - in[1].apps["app.exe"].memwBs) < 1e3);
}

TEST(journal_ignores_partial_and_damaged_lines) {
    std::string good = "S\t100\t60\t480\t1e12\nA\t100\t5\t1e9\tapp.exe\n";
    std::vector<MinuteDelta> out;
    // a writer is mid-line: only complete lines are consumed
    CHECK_EQ(parseJournal(good + "A\t100\t7\t1e", out), good.size());
    CHECK_EQ(out.size(), (size_t)1);
    CHECK(std::fabs(out[0].apps["app.exe"].cpuSec - 5) < 1e-9);

    out.clear();
    std::string messy = "garbage\nA\tnope\t1\t2\tx.exe\nA\t100\t-4\t1\tneg.exe\n\n" + good;
    CHECK_EQ(parseJournal(messy, out), messy.size());
    CHECK_EQ(out.size(), (size_t)1);
    CHECK_EQ(out[0].apps.size(), (size_t)1);
}

static std::string tempDir() {
    wchar_t dir[MAX_PATH], file[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"clp", 0, file);
    DeleteFileW(file);
    CreateDirectoryW(file, nullptr);
    return narrow(file);
}

static void removeDir(const std::string& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(widen(dir + "\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do DeleteFileW(widen(dir + "\\" + narrow(fd.cFileName)).c_str());
        while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(widen(dir).c_str());
}

static bool exists(const std::string& path) {
    return GetFileAttributesW(widen(path).c_str()) != INVALID_FILE_ATTRIBUTES;
}

TEST(journal_shares_history_between_writer_and_reader) {
    std::string dir = tempDir();
    const int64_t day = 20000, base = day * 1440 + 600;  // mid-day
    {
        Journal writer(dir), reader(dir);
        History writerSeen, readerSeen;
        HistoryWindow w;

        CHECK(reader.tail(base, readerSeen));  // nothing there yet: fine
        CHECK(writer.append(minutesOf(base, base + 3), base + 3, &writerSeen));

        CHECK(reader.tail(base + 3, readerSeen));
        readerSeen.query(base, base + 10, w);
        CHECK(std::fabs(w.sys.obsSec - 180) < 1e-6);
        CHECK(std::fabs(w.apps["app.exe"].cpuSec - 36) < 1e-6);

        // tailing again must not double count
        CHECK(reader.tail(base + 3, readerSeen));
        readerSeen.query(base, base + 10, w);
        CHECK(std::fabs(w.sys.obsSec - 180) < 1e-6);

        // the writer never reads back its own lines
        CHECK(writer.append(minutesOf(base + 3, base + 4), base + 4, &writerSeen));
        writerSeen.query(base, base + 10, w);
        CHECK_EQ(w.sys.obsSec, 0.0);

        // a fresh process later the same day loads everything
        Journal late(dir);
        History lateSeen;
        CHECK(late.tail(base + 5, lateSeen));
        lateSeen.query(base, base + 10, w);
        CHECK(std::fabs(w.sys.obsSec - 240) < 1e-6);
    }
    removeDir(dir);
}

TEST(journal_spans_midnight_and_expires_old_files) {
    std::string dir = tempDir();
    const int64_t day = 20000, midnight = day * 1440;
    {
        Journal writer(dir);
        CHECK(writer.append(minutesOf(midnight - 2, midnight + 2), midnight + 2, nullptr));
        CHECK(exists(writer.fileFor(day - 1)));
        CHECK(exists(writer.fileFor(day)));

        Journal reader(dir);
        History seen;
        HistoryWindow w;
        CHECK(reader.tail(midnight + 2, seen));
        seen.query(midnight - 10, midnight + 10, w);
        CHECK(std::fabs(w.sys.obsSec - 240) < 1e-6);

        writer.removeOlderThan(midnight + kRetainDays * 1440);
        CHECK(!exists(writer.fileFor(day - 1)));
        CHECK(exists(writer.fileFor(day)));
    }
    removeDir(dir);
}

TEST(recorder_take_leaves_the_open_minute) {
    Recorder r;
    r.add(tick(6000, 5, 1.0, 2 * GB));  // minute 100
    r.add(tick(6060, 5, 1.0, 2 * GB));  // minute 101, still open
    auto done = r.take(101);
    CHECK_EQ(done.size(), (size_t)1);
    CHECK_EQ(done[0].minute, (int64_t)100);
    CHECK_EQ(r.pending().size(), (size_t)1);
    CHECK_EQ(r.take().size(), (size_t)1);
}

// -------------------------------------------------------------- sampler ----

TEST(snapshot_sees_this_process) {
    Snapshot s;
    CHECK(takeSnapshot(s));
    CHECK(s.procs.size() > 5);
    bool found = false;
    for (const Proc& p : s.procs) {
        if (p.pid != GetCurrentProcessId()) continue;
        found = true;
        CHECK(lowerAscii(p.image).find("culprit_tests") != std::string::npos);
        CHECK(p.privBytes > 0);
        FILETIME c, e, k, u;
        GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u);
        CHECK_EQ(p.created, ftToU64(c));  // identity check used before any kill
    }
    CHECK(found);
}

int main() {
    for (const Test& t : tests()) {
        g_test = t.name;
        t.fn();
    }
    printf("%zu tests, %d checks, %d failed\n", tests().size(), g_checks, g_failed);
    return g_failed ? 1 : 0;
}
