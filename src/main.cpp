// culprit - find out what's slowing your PC down.
#include <cstdio>
#include <string>
#include <vector>

#include "inspect.h"
#include "kill.h"
#include "track.h"
#include "ui.h"
#include "win.h"

using namespace culprit;

static void usage() {
    printf(
        "culprit %s - find out what's slowing your PC down\n\n"
        "  culprit                 live view: who is using the machine, and for how long\n"
        "  culprit list            the same as a plain one-off table (also used when piped)\n"
        "  culprit who <pid|name>  who owns a process: publisher, signature, account, parent\n"
        "  culprit kill <pid> [--tree]   end a process (asks first)\n\n"
        "  culprit track on        record history in the background, starting at sign-in\n"
        "  culprit track off       stop recording and remove the sign-in task\n"
        "  culprit track status\n\n"
        "In the live view:  Up/Down select   D (or Enter) details   T process tree   K kill\n"
        "                   H 1h/24h impact   S sort   Q quit\n\n"
        "History lives in %%LOCALAPPDATA%%\\Culprit. Nothing leaves this machine.\n",
        CULPRIT_VERSION);
}

static int track(const std::string& sub) {
    SetConsoleOutputCP(CP_UTF8);
    std::string msg;
    if (sub == "on") {
        bool ok = trackOn(msg);
        printf("%s\n", msg.c_str());
        return ok ? 0 : 1;
    }
    if (sub == "off") {
        bool ok = trackOff(msg);
        printf("%s\n", msg.c_str());
        return ok ? 0 : 1;
    }
    if (sub == "restart") {
        bool ok = trackRestart(msg);
        printf("%s\n", msg.c_str());
        return ok ? 0 : 1;
    }
    if (sub == "status" || sub.empty()) {
        TrackStatus st = trackStatus();
        printf("Sign-in task:  %s\n", st.registered ? "registered" : "not registered");
        printf("Collector:     %s\n", st.running ? "running" : "not running");
        if (st.registered) printf("Launches:      conhost.exe %s\n", st.command.c_str());
        printf("History:       %s\n", dataDir().c_str());
        if (!st.registered) printf("\nRun 'culprit track on' to record history in the background.\n");
        return 0;
    }
    fprintf(stderr, "usage: culprit track on|off|status\n");
    return 2;
}

int wmain(int argc, wchar_t** argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++) args.push_back(narrow(argv[i]));
    std::string cmd = args.empty() ? "" : args[0];

    if (cmd == "--elevated-kill") return elevatedKillMain(argc, argv);
    if (cmd == "collect") return collectorMain();
    if (cmd == "-v" || cmd == "--version" || cmd == "version") {
        printf("culprit %s\n", CULPRIT_VERSION);
        return 0;
    }
    if (cmd == "-h" || cmd == "--help" || cmd == "help" || cmd == "/?") {
        usage();
        return 0;
    }
    if (cmd == "track") return track(args.size() > 1 ? args[1] : "");
    if (cmd == "list") return runOnce();
    if (cmd == "who") {
        if (args.size() < 2) {
            fprintf(stderr, "usage: culprit who <pid|name>\n");
            return 2;
        }
        return runWho(args[1]);
    }
    if (cmd == "kill") {
        std::string pid;
        bool tree = false;
        for (size_t i = 1; i < args.size(); i++) {
            if (args[i] == "--tree" || args[i] == "-t") tree = true;
            else pid = args[i];
        }
        return runKill(pid, tree);
    }
    if (!cmd.empty()) {
        fprintf(stderr, "culprit: unknown command '%s'\n\n", cmd.c_str());
        usage();
        return 2;
    }

    // No arguments: interactive when attached to a real console, plain otherwise.
    DWORD mode = 0;
    bool tty = GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) &&
               GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
    return tty ? runInteractive() : runOnce();
}
