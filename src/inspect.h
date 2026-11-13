// On-demand process details. Nothing here runs on the per-second hot path.
#pragma once
#include "model.h"

namespace culprit {

inline const char* const kUnavailable = "Unavailable";
inline const char* const kRestricted  = "Restricted";

struct Details {
    ProcId      id;
    std::string image;
    std::string path;         // full executable path
    std::string description;  // version-resource FileDescription
    std::string publisher;    // signer, or version-resource company marked unverified
    std::string signature;    // "Valid", "Not signed", ...
    std::string user;         // DOMAIN\user
    std::string started;      // local time
    std::string parent;       // "explorer.exe (1234)"
    std::vector<std::string> services;  // Windows services hosted by this pid
    size_t      children = 0;
    bool        elevated = false;
    bool        elevatedKnown = false;
};

// Full executable path, or "" when the process is gone or off limits.
std::string imagePath(ProcId id);
// Friendly application name from the executable's version resource, or "".
std::string friendlyName(ProcId id);
// Everything the detail view shows. May take a few hundred milliseconds
// (signature check), so call it off the UI thread.
Details inspect(const Proc& p, const std::vector<Proc>& all);

bool        isElevated();
std::string selfPath();
std::string fmtFileTime(uint64_t ft);

}  // namespace culprit
