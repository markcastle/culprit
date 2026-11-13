#include "engine.h"

#include <unordered_map>

#include "history.h"
#include "inspect.h"
#include "proctree.h"
#include "recorder.h"
#include "sampler.h"
#include "track.h"
#include "win.h"

namespace culprit {

namespace {
constexpr double kTailEverySec = 5.0;
constexpr int    kNamesPerTick = 40;
}  // namespace

Engine::Engine() {
    stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    wake_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    changed_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

Engine::~Engine() {
    stop();
    CloseHandle(stop_);
    CloseHandle(wake_);
    CloseHandle(changed_);
}

bool Engine::start(const Options& opt) {
    if (thread_.joinable()) return false;
    opt_ = opt;
    ResetEvent(stop_);
    thread_ = std::thread([this] { run(); });
    return true;
}

void Engine::stop() {
    if (!thread_.joinable()) return;
    SetEvent(stop_);
    thread_.join();
}

std::shared_ptr<const Model> Engine::model() const {
    std::lock_guard lock(mu_);
    return model_;
}

void Engine::setWindowMin(int minutes) {
    windowMin_ = minutes;
    SetEvent(wake_);
}

void Engine::run() {
    std::string dir = dataDir();
    bool storeOk = !dir.empty();
    Journal journal(dir);
    History history;  // interactive only; the collector just appends

    // Whoever holds this mutex records history. The collector waits for it;
    // an interactive instance takes it only if nobody else has.
    Handle writerMutex(CreateMutexW(nullptr, FALSE, kWriterMutex));
    bool writer = false;

    Recorder recorder;
    std::unordered_map<std::string, std::string> names;  // group key -> friendly name
    double   sinceTail = 0;
    int64_t  lastHousekeeping = 0;
    uint64_t seq = 0;
    double   sysCpu = 0;

    if (storeOk && !opt_.headless) journal.tail(unixNow() / 60, history);

    Snapshot prev, cur;
    bool havePrev = takeSnapshot(prev);

    auto flush = [&](int64_t beforeMinute, int64_t nowMin) {
        auto done = recorder.take(beforeMinute);
        if (done.empty()) return;
        if (storeOk) journal.append(done, nowMin, opt_.headless ? nullptr : &history);
        if (!opt_.headless)
            for (const MinuteDelta& d : done) history.merge(d);
    };

    auto publish = [&](const Snapshot& snap, const SysInfo& si) {
        int windowMin = windowMin_;
        int64_t nowMin = unixNow() / 60;
        int64_t from = nowMin - windowMin + 1;
        HistoryWindow win;
        history.query(from, nowMin, win);
        for (const auto& [minute, d] : recorder.pending()) {  // the minute in progress
            if (minute < from) continue;
            win.sys.obsSec += d.sys.obsSec;
            win.sys.cpuCapSec += d.sys.cpuCapSec;
            win.sys.ramBs += d.sys.ramBs;
            for (const auto& [key, t] : d.apps) {
                AppTotals& a = win.apps[key];
                a.cpuSec += t.cpuSec;
                a.memwBs += t.memwBs;
            }
        }

        auto m = std::make_shared<Model>();
        m->procs = snap.procs;
        m->groups = buildGroups(m->procs);
        int budget = kNamesPerTick;
        for (Group& g : m->groups) {
            auto it = names.find(g.key);
            if (it == names.end() && budget > 0) {
                budget--;
                const Proc& p = m->procs[g.members.front()];
                it = names.emplace(g.key, friendlyName({p.pid, p.created})).first;
            }
            if (it != names.end() && !it->second.empty()) g.display = it->second;

            auto h = win.apps.find(g.key);
            g.impact = impact(h == win.apps.end() ? AppTotals{} : h->second, win.sys);
        }
        m->ncpu = si.ncpu;
        m->totalRam = si.totalRam;
        m->memLoad = si.memLoad;
        m->sysCpuFrac = sysCpu;
        m->windowMin = windowMin;
        m->historySec = win.sys.obsSec;
        m->writer = writer;
        m->collectorUp = collectorRunning();
        m->storeOk = storeOk;
        m->seq = ++seq;
        {
            std::lock_guard lock(mu_);
            model_ = std::move(m);
        }
        SetEvent(changed_);
    };

    if (!opt_.headless && havePrev) publish(prev, sysInfo());

    HANDLE waits[2] = {stop_, wake_};
    for (;;) {
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, opt_.intervalMs);
        if (w == WAIT_OBJECT_0) break;
        if (w == WAIT_OBJECT_0 + 1) {
            // History window changed: refresh the scores without resampling.
            if (!opt_.headless && havePrev) publish(prev, sysInfo());
            continue;
        }

        if (!takeSnapshot(cur)) continue;
        SysInfo si = sysInfo();
        double dt = havePrev ? secondsBetween(prev, cur) : 0;
        if (havePrev) applyDeltas(prev.procs, cur.procs, dt, si.ncpu);
        if (havePrev && cur.sysTotal100ns > prev.sysTotal100ns) {
            double total = (double)(cur.sysTotal100ns - prev.sysTotal100ns);
            double idle = (double)(cur.sysIdle100ns - prev.sysIdle100ns);
            sysCpu = 1.0 - idle / total;
        }
        int64_t now = unixNow(), nowMin = now / 60;

        if (!writer && writerMutex) {
            DWORD got = WaitForSingleObject(writerMutex, 0);
            writer = got == WAIT_OBJECT_0 || got == WAIT_ABANDONED;
        }

        if (writer && havePrev) {
            SampleTick tick;
            tick.unixSec = now;
            tick.dtSec = dt;
            tick.ncpu = si.ncpu;
            tick.totalRam = (double)si.totalRam;
            tick.memLoad = si.memLoad;
            for (const Group& g : buildGroups(cur.procs)) {
                AppUsage u;
                u.key = g.key;
                u.privBytes = (double)g.privBytes;
                for (size_t i : g.members) u.cpuSec += cur.procs[i].cpuSec;
                tick.apps.push_back(std::move(u));
            }
            recorder.add(tick);
            flush(nowMin, nowMin);  // completed minutes go to disk, once each
        } else if (!writer && !opt_.headless && storeOk) {
            // Someone else (the collector) is recording: follow its journal.
            sinceTail += dt;
            if (sinceTail >= kTailEverySec) {
                journal.tail(nowMin, history);
                sinceTail = 0;
            }
        }

        if (nowMin - lastHousekeeping >= 60) {
            history.prune(nowMin - kMemoryMinutes);
            if (writer && storeOk) journal.removeOlderThan(nowMin);
            lastHousekeeping = nowMin;
        }

        if (!opt_.headless) publish(cur, si);
        std::swap(prev, cur);
        havePrev = true;
    }

    if (writer) {
        flush(INT64_MAX, unixNow() / 60);  // including the minute in progress
        ReleaseMutex(writerMutex);
    }
}

}  // namespace culprit
