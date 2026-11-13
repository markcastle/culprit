// The sampling loop. Runs on its own thread so the UI never waits on the
// process table or the database. Used by both the interactive UI (1s) and
// the headless collector (5s).
#pragma once
#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

#include "model.h"

namespace culprit {

class Engine {
public:
    struct Options {
        bool     headless = false;  // collector: record only, publish nothing
        unsigned intervalMs = 1000;
    };

    Engine();
    ~Engine();

    bool start(const Options& opt);
    void stop();

    std::shared_ptr<const Model> model() const;
    void* changedEvent() const { return changed_; }  // HANDLE, auto-reset
    void  setWindowMin(int minutes);

private:
    void run();

    Options opt_;
    std::thread thread_;
    void* stop_ = nullptr;
    void* wake_ = nullptr;
    void* changed_ = nullptr;
    std::atomic<int> windowMin_{60};
    mutable std::mutex mu_;
    std::shared_ptr<const Model> model_;
};

}  // namespace culprit
