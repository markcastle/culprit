// Terminal front ends.
#pragma once
#include <string>

namespace culprit {

int runInteractive();                       // the live keyboard UI
int runOnce();                              // plain one-shot table (piped output)
int runWho(const std::string& what);        // details for a pid or app name
int runKill(const std::string& pid, bool tree);  // confirm, then end a process

}  // namespace culprit
