#include "ui.h"

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "engine.h"
#include "format.h"
#include "inspect.h"
#include "kill.h"
#include "proctree.h"
#include "sampler.h"
#include "score.h"
#include "history.h"
#include "track.h"
#include "win.h"

namespace culprit {

namespace {

// --- styling ----------------------------------------------------------------
const char* const RST   = "\x1b[0m";
const char* const DIM   = "\x1b[38;5;245m";
const char* const BOLD  = "\x1b[1m";
const char* const SEL   = "\x1b[48;5;238m\x1b[97m";
const char* const AMBER = "\x1b[38;5;214m";
const char* const RED   = "\x1b[38;5;203m";
const char* const GREEN = "\x1b[38;5;78m";

const char* const DASH  = "\xE2\x80\x94";  // —
const char* const DOT   = "\xE2\x80\xA2";  // • (in every console font, unlike ●)
const char* const MID   = "\xC2\xB7";      // ·

std::string rule(size_t n) {
    std::string s;
    for (size_t i = 0; i < n; i++) s += "\xE2\x94\x80";
    return s;
}

std::string dim(const std::string& s) { return std::string(DIM) + s + RST; }

const char* impactColor(const std::optional<int>& v) {
    if (!v) return DIM;
    if (*v >= 75) return RED;
    if (*v >= 40) return AMBER;
    return "";
}

std::string impactText(const std::optional<int>& v) { return v ? std::to_string(*v) : std::string(DASH); }

enum class SortBy { Impact, Cpu, Ram };
enum class View { List, Detail, Tree, KillMenu, KillConfirm, Result };

std::vector<const Group*> sortedGroups(const Model& m, SortBy by) {
    std::vector<const Group*> v;
    v.reserve(m.groups.size());
    for (const Group& g : m.groups) v.push_back(&g);
    std::sort(v.begin(), v.end(), [by](const Group* a, const Group* b) {
        int ia = a->impact.value_or(-1), ib = b->impact.value_or(-1);
        if (by == SortBy::Impact && ia != ib) return ia > ib;
        if (by == SortBy::Ram && a->privBytes != b->privBytes) return a->privBytes > b->privBytes;
        if (a->cpuFrac != b->cpuFrac) return a->cpuFrac > b->cpuFrac;
        if (a->privBytes != b->privBytes) return a->privBytes > b->privBytes;
        return a->key < b->key;
    });
    return v;
}

std::string groupLabel(const Group& g, size_t width) {
    std::string suffix = g.members.size() > 1 ? " (" + std::to_string(g.members.size()) + ")" : "";
    size_t room = width > cells(suffix) ? width - cells(suffix) : 0;
    return clip(g.display, room) + suffix;
}

struct TreeLine {
    int         proc = -1;  // index into Model::procs, or -1 for a heading
    std::string label;
};

// The real parent/child trees that contain this application's processes.
std::vector<TreeLine> buildTree(const Model& m, const Group& g) {
    const auto& procs = m.procs;
    std::unordered_map<int, std::vector<size_t>> kids;
    std::vector<int> parent(procs.size(), -1);
    for (size_t i = 0; i < procs.size(); i++) {
        parent[i] = parentIndex(procs, i);
        if (parent[i] >= 0) kids[parent[i]].push_back(i);
    }

    std::vector<size_t> roots = groupRoots(procs, g.members);
    std::sort(roots.begin(), roots.end(), [&](size_t a, size_t b) {
        if (parent[a] != parent[b]) return parent[a] < parent[b];
        if (procs[a].privBytes != procs[b].privBytes) return procs[a].privBytes > procs[b].privBytes;
        return procs[a].pid < procs[b].pid;
    });

    std::vector<TreeLine> out;
    std::unordered_set<size_t> seen;
    bool first = true;
    int lastParent = -2;

    struct Walker {
        const std::vector<Proc>& procs;
        std::unordered_map<int, std::vector<size_t>>& kids;
        std::unordered_set<size_t>& seen;
        std::vector<TreeLine>& out;
        void walk(size_t node, const std::string& prefix, bool last, int depth) {
            if (!seen.insert(node).second) return;
            std::string branch = depth ? (last ? "\xE2\x94\x94\xE2\x94\x80 " : "\xE2\x94\x9C\xE2\x94\x80 ") : "";
            out.push_back({(int)node, prefix + branch + procs[node].image});
            std::string next = prefix + (depth ? (last ? "   " : "\xE2\x94\x82  ") : "");
            auto it = kids.find((int)node);
            if (it == kids.end()) return;
            for (size_t i = 0; i < it->second.size(); i++)
                walk(it->second[i], next, i + 1 == it->second.size(), depth + 1);
        }
    } walker{procs, kids, seen, out};

    for (size_t r : roots) {
        if (seen.count(r)) continue;
        if (first || parent[r] != lastParent) {
            std::string head = parent[r] >= 0
                                   ? "started by " + procs[(size_t)parent[r]].image + " (" +
                                         std::to_string(procs[(size_t)parent[r]].pid) + ")"
                                   : "parent no longer running";
            out.push_back({-1, head});
            first = false;
            lastParent = parent[r];
        }
        walker.walk(r, "", true, 0);
    }
    return out;
}

// --- console ----------------------------------------------------------------

struct Console {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  inMode = 0, outMode = 0;
    bool   active = false;

    bool begin() {
        if (!GetConsoleMode(in, &inMode) || !GetConsoleMode(out, &outMode)) return false;
        if (!SetConsoleMode(out, outMode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
            return false;
        SetConsoleMode(in, ENABLE_WINDOW_INPUT | ENABLE_EXTENDED_FLAGS);
        active = true;
        write("\x1b[?1049h\x1b[?25l");
        return true;
    }
    void end() {
        if (!active) return;
        active = false;
        write("\x1b[0m\x1b[?25h\x1b[?1049l");
        SetConsoleMode(in, inMode);
        SetConsoleMode(out, outMode);
    }
    void write(const std::string& utf8) {
        std::wstring w = widen(utf8);
        const wchar_t* p = w.data();
        size_t left = w.size();
        while (left) {
            DWORD n = 0, chunk = (DWORD)std::min<size_t>(left, 16000);
            if (!WriteConsoleW(out, p, chunk, &n, nullptr) || !n) break;
            p += n;
            left -= n;
        }
    }
    void size(int& cols, int& rows) {
        CONSOLE_SCREEN_BUFFER_INFO i{};
        if (GetConsoleScreenBufferInfo(out, &i)) {
            cols = i.srWindow.Right - i.srWindow.Left + 1;
            rows = i.srWindow.Bottom - i.srWindow.Top + 1;
        } else {
            cols = 80;
            rows = 25;
        }
    }
};

Console* g_console = nullptr;

BOOL WINAPI onCtrl(DWORD) {
    if (g_console) g_console->end();
    return FALSE;
}

struct DetailJob {
    std::mutex mu;
    bool       done = false;
    Details    d;
};

// --- the application --------------------------------------------------------

struct App {
    Console console;
    Engine  engine;
    std::shared_ptr<const Model> model;
    HANDLE  uiWake = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    View   view = View::List;
    SortBy sort = SortBy::Impact;
    int    windowMin = 60;
    bool   quit = false;

    std::string selKey;
    int         selIndex = 0;
    int         scroll = 0;

    ProcId detailId;
    std::shared_ptr<DetailJob> job;

    std::vector<TreeLine> tree;
    ProcId treeSel;
    int    treeScroll = 0;
    View   treeReturn = View::List;

    Proc        target;
    std::string targetGroup;
    std::string blocked;
    bool        killTree = false;
    size_t      killCount = 0;
    size_t      treeCount = 0;
    size_t      groupRootCount = 0;
    View        killReturn = View::List;
    KillReport  report;
    std::string resultNote;
    bool        offerElevate = false;

    int cols = 80, rows = 25;
    size_t W = 79;

    // ---- lookups -----------------------------------------------------------
    const Group* selectedGroup() const {
        if (!model) return nullptr;
        for (const Group& g : model->groups)
            if (g.key == selKey) return &g;
        return nullptr;
    }

    void syncSelection(const std::vector<const Group*>& list) {
        if (list.empty()) { selIndex = 0; selKey.clear(); return; }
        int found = -1;
        for (size_t i = 0; i < list.size(); i++)
            if (list[i]->key == selKey) { found = (int)i; break; }
        if (found < 0) found = std::clamp(selIndex, 0, (int)list.size() - 1);
        selIndex = found;
        selKey = list[(size_t)found]->key;
    }

    void moveSelection(int delta) {
        if (!model) return;
        auto list = sortedGroups(*model, sort);
        if (list.empty()) return;
        syncSelection(list);
        selIndex = std::clamp(selIndex + delta, 0, (int)list.size() - 1);
        selKey = list[(size_t)selIndex]->key;
    }

    // ---- frame -------------------------------------------------------------
    std::vector<std::string> lines;
    void add(const std::string& s = "") { lines.push_back(s); }

    void present() {
        std::string out = "\x1b[H";
        size_t n = std::min(lines.size(), (size_t)std::max(rows, 1));
        for (size_t i = 0; i < n; i++) {
            out += lines[i];
            out += "\x1b[0m\x1b[K";
            if (i + 1 < n) out += "\r\n";
        }
        out += "\x1b[J";
        console.write(out);
    }

    void footer(const std::string& text) {
        // pin to the bottom row
        while ((int)lines.size() < rows - 1) add();
        if ((int)lines.size() > rows - 1) lines.resize((size_t)std::max(rows - 1, 0));
        add(dim(clip(" " + text, W)));
    }

    void title(const std::string& name, const std::string& right = "", const char* rightColor = "") {
        size_t width = std::min<size_t>(W, 68);
        add();
        std::string left = clip(" " + name, width);
        std::string line = std::string(BOLD) + left + RST;
        if (!right.empty() && cells(left) + cells(right) + 2 <= width)
            line += std::string(width - cells(left) - cells(right), ' ') + rightColor + right + RST;
        add(line);
    }

    // ---- views -------------------------------------------------------------
    void renderList() {
        size_t nameW = std::clamp<size_t>(W > 28 ? W - 28 : 10, 10, 40);
        size_t tableW = 1 + nameW + 26;

        std::string status;
        if (!model) status = "starting";
        else if (!model->storeOk) status = "history unavailable";
        else if (model->collectorUp) status = "tracking on";
        else status = "tracking off";
        std::string hist = model && model->historySec >= kMinHistorySec
                               ? fmtDuration(model->historySec) + " recorded"
                               : "collecting history";
        add();
        {
            std::string left = " CULPRIT", right = std::string(DOT) + " LIVE";
            std::string line = std::string(BOLD) + left + RST;
            if (tableW <= W && tableW > cells(left) + cells(right))
                line += std::string(tableW - cells(left) - cells(right), ' ') + GREEN + right + RST;
            add(line);
        }
        add(dim(clip(" Impact over the last " + std::string(windowMin == 60 ? "hour" : "24 hours") + "  " + MID +
                     "  " + hist + "  " + MID + "  " + status, W)));
        add();

        auto mark = [&](SortBy s, const char* name) {
            return std::string(name) + (sort == s ? "\xE2\x86\x93" : "");
        };
        add(dim(clip(" " + padRight("PROCESS", nameW) + padLeft(mark(SortBy::Cpu, "CPU"), 8) +
                     padLeft(mark(SortBy::Ram, "RAM"), 10) + padLeft(mark(SortBy::Impact, "IMPACT"), 8), W)));
        add(dim(clip(" " + rule(tableW - 1), W)));

        std::vector<const Group*> list;
        if (model) list = sortedGroups(*model, sort);
        syncSelection(list);

        int visible = std::max(1, rows - (int)lines.size() - 2);
        if (selIndex < scroll) scroll = selIndex;
        if (selIndex >= scroll + visible) scroll = selIndex - visible + 1;
        scroll = std::clamp(scroll, 0, std::max(0, (int)list.size() - visible));

        for (int i = scroll; i < (int)list.size() && i < scroll + visible; i++) {
            const Group& g = *list[(size_t)i];
            bool sel = i == selIndex;
            std::string text = " " + padRight(groupLabel(g, nameW), nameW) + padLeft(fmtPercent(g.cpuFrac), 8) +
                               padLeft(fmtBytes(g.privBytes), 10);
            std::string imp = padLeft(impactText(g.impact), 8);
            if (cells(text) + cells(imp) > W) { text = clip(text, W); imp.clear(); }
            add(std::string(sel ? SEL : "") + text + impactColor(g.impact) + imp + (sel ? " " : "") + RST);
        }
        footer("\xE2\x86\x91\xE2\x86\x93 Select   D Details   K Kill   T Tree   H 1h/24h   S Sort   Q Quit");
    }

    void field(const std::string& name, const std::string& value, const char* color = "") {
        size_t room = W > 15 ? W - 15 : 1;
        add(dim(" " + padRight(name, 13)) + " " + color + clip(value, room) + RST);
    }

    void startDetail(const Proc& p) {
        detailId = {p.pid, p.created};
        job = std::make_shared<DetailJob>();
        auto j = job;
        auto procs = model->procs;
        HANDLE wake = uiWake;
        std::thread([j, p, procs, wake] {
            Details d = inspect(p, procs);
            {
                std::lock_guard lock(j->mu);
                j->d = std::move(d);
                j->done = true;
            }
            SetEvent(wake);
        }).detach();
    }

    void renderDetail() {
        const Group* g = selectedGroup();
        if (!g) {
            title("No longer running");
            add();
            add(" This application has exited.");
            footer("Esc Back");
            return;
        }
        int mainIdx = mainProcess(model->procs, g->members);
        const Proc& p = model->procs[(size_t)mainIdx];
        if (!job || !(detailId == ProcId{p.pid, p.created})) startDetail(p);

        Details d;
        bool ready = false;
        {
            std::lock_guard lock(job->mu);
            ready = job->done;
            if (ready) d = job->d;
        }
        std::string wait = "\xE2\x80\xA6";

        title(g->display);
        add(dim(" " + rule(std::min<size_t>(W - 1, 60))));
        field("Impact", impactText(g->impact) + (g->impact ? std::string(windowMin == 60 ? "  (1h)" : "  (24h)") : ""),
              impactColor(g->impact));
        field("CPU", fmtPercent(g->cpuFrac));
        field("Memory", fmtBytes(g->privBytes));
        add();
        field("Publisher", ready ? d.publisher : wait);
        field("Signature", ready ? d.signature : wait);
        field("Location", ready ? clipPath(d.path, W > 15 ? W - 15 : 1) : wait);
        field("Running as", ready ? d.user + (d.elevatedKnown && d.elevated ? "  (elevated)" : "") : wait);
        field("Started", fmtFileTime(p.created));
        field("PID", std::to_string(p.pid) + "  " + p.image);
        field("Parent", ready ? d.parent : wait);
        size_t roots = groupRoots(model->procs, g->members).size();
        std::string count = std::to_string(g->members.size());
        if (roots > 1) count += "  (" + std::to_string(roots) + " separate trees; details are for the largest)";
        field("Processes", count);
        if (ready) {
            if (d.children) field("Descendants", std::to_string(d.children));
            for (size_t i = 0; i < d.services.size() && i < 6; i++) field(i ? "" : "Service", d.services[i]);
            if (d.services.size() > 6) field("", "+" + std::to_string(d.services.size() - 6) + " more");
        }
        footer("T Process tree   K Kill   Esc Back");
    }

    void renderTree() {
        const Group* g = selectedGroup();
        if (!g) {
            title("No longer running");
            add();
            add(" This application has exited.");
            footer("Esc Back");
            return;
        }
        tree = buildTree(*model, *g);
        int sel = -1, firstProc = -1;
        for (size_t i = 0; i < tree.size(); i++) {
            if (tree[i].proc < 0) continue;
            if (firstProc < 0) firstProc = (int)i;
            const Proc& p = model->procs[(size_t)tree[i].proc];
            if (p.pid == treeSel.pid && p.created == treeSel.created) sel = (int)i;
        }
        if (sel < 0) sel = firstProc;
        if (sel >= 0) {
            const Proc& p = model->procs[(size_t)tree[(size_t)sel].proc];
            treeSel = {p.pid, p.created};
        }

        size_t nameW = std::clamp<size_t>(W > 28 ? W - 28 : 10, 10, 50);
        title(g->display + " " + MID + " process tree");
        add(dim(clip(" " + padRight("PROCESS", nameW) + padLeft("PID", 8) + padLeft("CPU", 8) + padLeft("RAM", 10), W)));
        add(dim(clip(" " + rule(nameW + 26), W)));

        int visible = std::max(1, rows - (int)lines.size() - 2);
        if (sel >= 0 && sel < treeScroll + 1) treeScroll = std::max(0, sel - 1);
        if (sel >= treeScroll + visible) treeScroll = sel - visible + 1;
        treeScroll = std::clamp(treeScroll, 0, std::max(0, (int)tree.size() - visible));

        for (int i = treeScroll; i < (int)tree.size() && i < treeScroll + visible; i++) {
            const TreeLine& t = tree[(size_t)i];
            if (t.proc < 0) {
                add(dim(clip(" " + t.label, W)));
                continue;
            }
            const Proc& p = model->procs[(size_t)t.proc];
            bool mine = groupKey(p.image) == g->key;
            std::string text = clip(" " + padRight(t.label, nameW) + padLeft(std::to_string(p.pid), 8) +
                                    padLeft(fmtPercent(p.cpuFrac), 8) + padLeft(fmtBytes(p.privBytes), 10) + " ", W);
            add(std::string(i == sel ? SEL : (mine ? "" : DIM)) + text + RST);
        }
        footer("\xE2\x86\x91\xE2\x86\x93 Select   K Kill   Esc Back");
    }

    void openKill(const Proc& p, const Group* g, View from) {
        target = p;
        targetGroup = g ? g->display + " " + MID + " " + std::to_string(g->members.size()) +
                              (g->members.size() == 1 ? " process" : " processes")
                        : p.image;
        groupRootCount = g ? groupRoots(model->procs, g->members).size() : 1;
        blocked = blockReason(p);
        int idx = findProc(model->procs, {p.pid, p.created});
        treeCount = idx >= 0 ? planKill(model->procs, (size_t)idx, true).size() : 1;
        killReturn = from;
        view = View::KillMenu;
    }

    std::string targetName() const { return target.image + " (PID " + std::to_string(target.pid) + ")"; }

    void renderKillMenu() {
        title(targetGroup);
        add();
        add(clip(" Target: " + targetName(), W));
        add();
        if (!blocked.empty()) {
            add(std::string(AMBER) + clip(" Cannot end this: " + blocked + ".", W) + RST);
            footer("Esc Back");
            return;
        }
        add(" [1] End selected process");
        add(clip(" [2] End process tree" +
                     std::string(treeCount > 1 ? "  (" + std::to_string(treeCount) + " processes)" : "  (no child processes)"), W));
        add(" [Esc] Cancel");
        if (groupRootCount > 1 && killReturn != View::Tree) {
            add();
            add(dim(clip(" This application has " + std::to_string(groupRootCount) +
                         " separate process trees. Press T to choose a specific one.", W)));
        }
        footer("1 End process   2 End tree   Esc Cancel");
    }

    void renderKillConfirm() {
        title(targetGroup);
        add();
        if (killTree && killCount > 1)
            add(clip(" End " + targetName() + " and its " + std::to_string(killCount - 1) +
                     (killCount == 2 ? " descendant process?" : " descendant processes?"), W));
        else
            add(clip(" End " + targetName() + "?", W));
        add();
        add(std::string(AMBER) + clip(" " + std::to_string(killCount) +
                                      (killCount == 1 ? " process" : " processes") +
                                      " will be terminated. Unsaved work will be lost.", W) + RST);
        add();
        add(" [Y] End    [N] Cancel");
        footer("Y Confirm   N Cancel");
    }

    void renderResult() {
        title(targetGroup);
        add();
        if (!report.refusal.empty()) {
            add(clip(" " + report.refusal, W));
        } else {
            int ended = report.count(KillStatus::Ended) + report.count(KillStatus::AlreadyGone);
            bool all = ended == (int)report.items.size();
            add(std::string(all ? GREEN : AMBER) +
                clip(" Ended " + std::to_string(ended) + " of " + std::to_string(report.items.size()) +
                     (report.items.size() == 1 ? " process." : " processes."), W) + RST);
            add();
            int room = std::max(1, rows - (int)lines.size() - 6);
            // failures first: they are what the user needs to see
            std::vector<const KillItem*> order;
            for (const KillItem& i : report.items)
                if (i.status != KillStatus::Ended && i.status != KillStatus::AlreadyGone) order.push_back(&i);
            for (const KillItem& i : report.items)
                if (i.status == KillStatus::Ended || i.status == KillStatus::AlreadyGone) order.push_back(&i);
            for (int i = 0; i < (int)order.size() && i < room; i++) {
                const KillItem& k = *order[(size_t)i];
                bool ok = k.status == KillStatus::Ended || k.status == KillStatus::AlreadyGone;
                add(clip(" " + padLeft(std::to_string(k.pid), 7) + "  " + padRight(k.image, 28) + " ", W) +
                    (ok ? "" : AMBER) + statusText(k.status, report.elevated) + RST);
            }
            if ((int)order.size() > room) add(dim(" +" + std::to_string(order.size() - (size_t)room) + " more"));
        }
        if (!resultNote.empty()) {
            add();
            add(clip(" " + resultNote, W));
        }
        if (offerElevate) {
            add();
            add(" Administrator permission required. Elevate? [Y/N]");
            footer("Y Elevate   N Back");
        } else {
            footer("Press any key");
        }
    }

    void render() {
        console.size(cols, rows);
        W = (size_t)std::max(cols - 1, 20);
        lines.clear();
        switch (view) {
            case View::List:        renderList(); break;
            case View::Detail:      renderDetail(); break;
            case View::Tree:        renderTree(); break;
            case View::KillMenu:    renderKillMenu(); break;
            case View::KillConfirm: renderKillConfirm(); break;
            case View::Result:      renderResult(); break;
        }
        present();
    }

    // ---- actions -----------------------------------------------------------
    void doKill() {
        report = killProcess({target.pid, target.created}, killTree);
        resultNote.clear();
        offerElevate = report.anyDenied() && !report.elevated;
        if (report.anyDenied() && report.elevated)
            resultNote = "Windows protects these processes; Culprit will not try to bypass that.";
        view = View::Result;
    }

    void doElevate() {
        offerElevate = false;
        resultNote = "Waiting for the Windows permission prompt\xE2\x80\xA6";
        render();
        KillReport elevated;
        std::string error;
        if (killElevated(deniedTargets(report), elevated, error)) {
            // keep what already succeeded, replace the denied rows
            KillReport merged;
            merged.elevated = true;
            for (const KillItem& i : report.items)
                if (i.status != KillStatus::AccessDenied) merged.items.push_back(i);
            for (const KillItem& i : elevated.items) merged.items.push_back(i);
            merged.refusal = elevated.items.empty() ? elevated.refusal : "";
            report = merged;
            resultNote = report.anyDenied()
                             ? "Windows protects these processes; Culprit will not try to bypass that."
                             : "";
        } else {
            resultNote = error;
        }
    }

    void toTree(View from) {
        treeReturn = from;
        treeSel = {};
        treeScroll = 0;
        view = View::Tree;
    }

    void killFromGroup(View from) {
        const Group* g = selectedGroup();
        if (!g || !model) return;
        int idx = mainProcess(model->procs, g->members);
        if (idx >= 0) openKill(model->procs[(size_t)idx], g, from);
    }

    void key(WORD vk, wchar_t ch, DWORD ctrl) {
        wchar_t c = (wchar_t)towlower(ch);
        bool esc = vk == VK_ESCAPE;
        if (ch == 3 || (c == L'c' && (ctrl & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)))) { quit = true; return; }

        switch (view) {
            case View::List: {
                int page = std::max(1, rows - 9);
                if (vk == VK_UP) moveSelection(-1);
                else if (vk == VK_DOWN) moveSelection(1);
                else if (vk == VK_PRIOR) moveSelection(-page);
                else if (vk == VK_NEXT) moveSelection(page);
                else if (vk == VK_HOME) moveSelection(-100000);
                else if (vk == VK_END) moveSelection(100000);
                else if (vk == VK_RETURN || c == L'd') { if (selectedGroup()) { job.reset(); view = View::Detail; } }
                else if (c == L'k' || vk == VK_DELETE) killFromGroup(View::List);
                else if (c == L't') { if (selectedGroup()) toTree(View::List); }
                else if (c == L'h') { windowMin = windowMin == 60 ? 1440 : 60; engine.setWindowMin(windowMin); }
                else if (c == L's') sort = sort == SortBy::Impact ? SortBy::Cpu : sort == SortBy::Cpu ? SortBy::Ram : SortBy::Impact;
                else if (c == L'q' || esc) quit = true;
                break;
            }
            case View::Detail:
                if (esc || vk == VK_BACK || vk == VK_LEFT) view = View::List;
                else if (c == L't') toTree(View::Detail);
                else if (c == L'k') killFromGroup(View::Detail);
                else if (c == L'q') quit = true;
                break;
            case View::Tree: {
                if (esc || vk == VK_BACK || vk == VK_LEFT) { view = treeReturn; break; }
                if (c == L'q') { quit = true; break; }
                std::vector<int> rowsSel;
                int cur = -1;
                for (size_t i = 0; i < tree.size(); i++) {
                    if (tree[i].proc < 0 || !model || (size_t)tree[i].proc >= model->procs.size()) continue;
                    const Proc& p = model->procs[(size_t)tree[i].proc];
                    if (p.pid == treeSel.pid && p.created == treeSel.created) cur = (int)rowsSel.size();
                    rowsSel.push_back((int)i);
                }
                if (rowsSel.empty() || cur < 0) break;
                int next = cur;
                if (vk == VK_UP) next = cur - 1;
                else if (vk == VK_DOWN) next = cur + 1;
                else if (vk == VK_PRIOR) next = cur - 10;
                else if (vk == VK_NEXT) next = cur + 10;
                else if (vk == VK_HOME) next = 0;
                else if (vk == VK_END) next = (int)rowsSel.size() - 1;
                next = std::clamp(next, 0, (int)rowsSel.size() - 1);
                const Proc& p = model->procs[(size_t)tree[(size_t)rowsSel[(size_t)next]].proc];
                treeSel = {p.pid, p.created};
                if (c == L'k' || vk == VK_DELETE) openKill(p, selectedGroup(), View::Tree);
                break;
            }
            case View::KillMenu:
                if (esc || c == L'n' || c == L'q') view = killReturn;
                else if (c == L't' && killReturn != View::Tree) toTree(killReturn);
                else if (blocked.empty() && (c == L'1' || c == L'2')) {
                    killTree = c == L'2';
                    killCount = killTree ? treeCount : 1;
                    view = View::KillConfirm;
                }
                break;
            case View::KillConfirm:
                if (c == L'y') doKill();
                else if (esc || c == L'n' || c == L'q') view = View::KillMenu;
                break;
            case View::Result:
                if (offerElevate) {
                    if (c == L'y') doElevate();
                    else if (c == L'n' || esc) offerElevate = false, view = View::List;
                } else {
                    view = View::List;
                }
                break;
        }
    }

    int run() {
        if (!console.begin()) {
            fprintf(stderr, "culprit: this terminal does not support the interactive display.\n"
                            "Try Windows Terminal, or run 'culprit list' for plain output.\n");
            return 1;
        }
        g_console = &console;
        SetConsoleCtrlHandler(onCtrl, TRUE);

        engine.start({});
        HANDLE waits[3] = {console.in, (HANDLE)engine.changedEvent(), uiWake};
        render();
        while (!quit) {
            DWORD w = WaitForMultipleObjects(3, waits, FALSE, 2000);
            if (w == WAIT_OBJECT_0) {
                DWORD pending = 0;
                while (!quit && GetNumberOfConsoleInputEvents(console.in, &pending) && pending) {
                    INPUT_RECORD rec[32];
                    DWORD got = 0;
                    if (!ReadConsoleInputW(console.in, rec, 32, &got)) { quit = true; break; }
                    for (DWORD i = 0; i < got && !quit; i++)
                        if (rec[i].EventType == KEY_EVENT && rec[i].Event.KeyEvent.bKeyDown)
                            key(rec[i].Event.KeyEvent.wVirtualKeyCode, rec[i].Event.KeyEvent.uChar.UnicodeChar,
                                rec[i].Event.KeyEvent.dwControlKeyState);
                }
            } else if (w == WAIT_FAILED) {
                break;
            }
            if (auto m = engine.model()) model = m;
            if (!quit) render();
        }
        console.end();
        g_console = nullptr;
        engine.stop();
        return 0;
    }
};

// --- plain-text commands ------------------------------------------------------

void setUtf8Output() { SetConsoleOutputCP(CP_UTF8); }

bool sampleTwice(Snapshot& cur, SysInfo& si, unsigned ms) {
    Snapshot prev;
    if (!takeSnapshot(prev)) return false;
    Sleep(ms);
    if (!takeSnapshot(cur)) return false;
    si = sysInfo();
    applyDeltas(prev.procs, cur.procs, secondsBetween(prev, cur), si.ncpu);
    return true;
}

void printDetails(const Proc& p, const std::vector<Proc>& all) {
    Details d = inspect(p, all);
    auto row = [](const char* k, const std::string& v) { printf(" %-13s %s\n", k, v.c_str()); };
    printf("\n %s\n", d.description.empty() ? p.image.c_str() : d.description.c_str());
    row("PID", std::to_string(p.pid) + "  " + p.image);
    row("CPU", fmtPercent(p.cpuFrac));
    row("Memory", fmtBytes(p.privBytes));
    row("Publisher", d.publisher);
    row("Signature", d.signature);
    row("Location", d.path);
    row("Running as", d.user + (d.elevatedKnown && d.elevated ? "  (elevated)" : ""));
    row("Started", d.started);
    row("Parent", d.parent);
    row("Descendants", std::to_string(d.children));
    for (size_t i = 0; i < d.services.size(); i++) row(i ? "" : "Service", d.services[i]);
}

void printReport(const KillReport& r) {
    if (!r.refusal.empty()) printf("%s\n", r.refusal.c_str());
    for (const KillItem& i : r.items)
        printf(" %7u  %-28s %s\n", i.pid, i.image.c_str(), statusText(i.status, r.elevated));
}

bool askYes(const char* prompt) {
    printf("%s ", prompt);
    fflush(stdout);
    std::string line;
    if (!std::getline(std::cin, line)) return false;
    size_t i = 0;
    if (line.rfind("\xEF\xBB\xBF", 0) == 0) i = 3;  // PowerShell pipes a BOM first
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) i++;
    return i < line.size() && (line[i] == 'y' || line[i] == 'Y');
}

}  // namespace

int runInteractive() {
    App app;
    return app.run();
}

int runOnce() {
    setUtf8Output();
    Snapshot cur;
    SysInfo si;
    if (!sampleTwice(cur, si, 1000)) {
        fprintf(stderr, "culprit: could not read the process table\n");
        return 1;
    }
    Model m;
    m.procs = cur.procs;
    m.groups = buildGroups(m.procs);

    HistoryWindow hist;
    std::string dir = dataDir();
    int64_t nowMin = unixNow() / 60;
    if (!dir.empty()) {
        History all;
        Journal(dir).tail(nowMin, all);
        all.query(nowMin - 59, nowMin, hist);
    }
    for (Group& g : m.groups) {
        auto h = hist.apps.find(g.key);
        g.impact = impact(h == hist.apps.end() ? AppTotals{} : h->second, hist.sys);
    }

    auto list = sortedGroups(m, SortBy::Impact);
    printf("%-40s %8s %10s %8s\n", "PROCESS", "CPU", "RAM", "IMPACT");
    for (size_t i = 0; i < list.size() && i < 25; i++) {
        Group g = *list[i];
        const Proc& p = m.procs[g.members.front()];
        std::string nice = friendlyName({p.pid, p.created});
        if (!nice.empty()) g.display = nice;
        printf("%s %8s %10s %8s\n", padRight(groupLabel(g, 40), 40).c_str(), fmtPercent(g.cpuFrac).c_str(),
               fmtBytes(g.privBytes).c_str(), g.impact ? std::to_string(*g.impact).c_str() : "-");
    }
    if (hist.sys.obsSec >= kMinHistorySec)
        printf("\nImpact over the last hour (%s recorded).\n", fmtDuration(hist.sys.obsSec).c_str());
    else
        printf("\nNo impact scores yet: not enough history. Run 'culprit track on' to record in the background.\n");
    return 0;
}

int runWho(const std::string& what) {
    setUtf8Output();
    Snapshot cur;
    SysInfo si;
    if (!sampleTwice(cur, si, 300)) return 1;

    char* end = nullptr;
    unsigned long pid = strtoul(what.c_str(), &end, 10);
    bool isPid = end && *end == '\0' && !what.empty();
    std::string want = lowerAscii(what);

    int shown = 0;
    if (isPid) {
        for (const Proc& p : cur.procs)
            if (p.pid == pid) { printDetails(p, cur.procs); shown++; }
    } else {
        for (const Group& g : buildGroups(cur.procs)) {
            if (g.key != want && g.key != want + ".exe") continue;
            int idx = mainProcess(cur.procs, g.members);
            if (idx < 0) continue;
            printDetails(cur.procs[(size_t)idx], cur.procs);
            printf(" %-13s %zu\n", "Processes", g.members.size());
            shown++;
        }
    }
    if (!shown) {
        fprintf(stderr, "culprit: no running process matches '%s'\n", what.c_str());
        return 1;
    }
    return 0;
}

int runKill(const std::string& pidText, bool tree) {
    setUtf8Output();
    char* end = nullptr;
    unsigned long pid = strtoul(pidText.c_str(), &end, 10);
    if (pidText.empty() || !end || *end != '\0') {
        fprintf(stderr, "usage: culprit kill <pid> [--tree]\n");
        return 2;
    }
    Snapshot snap;
    if (!takeSnapshot(snap)) return 1;
    int idx = -1;
    for (size_t i = 0; i < snap.procs.size(); i++)
        if (snap.procs[i].pid == pid) idx = (int)i;
    if (idx < 0) {
        fprintf(stderr, "culprit: no process with PID %lu\n", pid);
        return 1;
    }
    const Proc& p = snap.procs[(size_t)idx];
    std::string why = blockReason(p);
    if (!why.empty()) {
        fprintf(stderr, "culprit: refused: %s\n", why.c_str());
        return 1;
    }
    auto plan = planKill(snap.procs, (size_t)idx, tree);
    printf("About to end %zu process%s:\n", plan.size(), plan.size() == 1 ? "" : "es");
    for (size_t i : plan) printf(" %7u  %s\n", snap.procs[i].pid, snap.procs[i].image.c_str());
    if (!askYes("Continue? [y/N]")) {
        printf("Cancelled. Nothing was ended.\n");
        return 1;
    }

    KillReport r = killProcess({p.pid, p.created}, tree);
    printReport(r);
    if (r.anyDenied() && !r.elevated && askYes("Administrator permission required. Elevate? [y/N]")) {
        KillReport e;
        std::string error;
        if (killElevated(deniedTargets(r), e, error)) {
            printReport(e);
            r = e;
        } else {
            printf("%s\n", error.c_str());
        }
    }
    bool ok = r.refusal.empty() && r.count(KillStatus::Ended) + r.count(KillStatus::AlreadyGone) == (int)r.items.size();
    return ok ? 0 : 1;
}

}  // namespace culprit
