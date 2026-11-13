#include "format.h"

#include <cmath>
#include <cstdio>

namespace culprit {

std::string fmtBytes(uint64_t bytes) {
    char b[32];
    double mb = (double)bytes / (1024.0 * 1024.0);
    if (mb < 1.0)
        snprintf(b, sizeof b, "%.0f KB", (double)bytes / 1024.0);
    else if (mb < 999.5)
        snprintf(b, sizeof b, "%.0f MB", mb);
    else
        snprintf(b, sizeof b, "%.1f GB", mb / 1024.0);
    return b;
}

std::string fmtPercent(double frac) {
    char b[32];
    double p = frac * 100.0;
    if (p < 0) p = 0;
    snprintf(b, sizeof b, "%.1f%%", p);
    return b;
}

std::string fmtDuration(double seconds) {
    char b[32];
    long long s = seconds < 0 ? 0 : (long long)std::llround(seconds);
    if (s < 60)
        snprintf(b, sizeof b, "%llds", s);
    else if (s < 3600)
        snprintf(b, sizeof b, "%lldm", s / 60);
    else if (s < 86400)
        snprintf(b, sizeof b, "%lldh %02lldm", s / 3600, (s % 3600) / 60);
    else
        snprintf(b, sizeof b, "%lldd %lldh", s / 86400, (s % 86400) / 3600);
    return b;
}

static bool isLead(unsigned char c) { return (c & 0xC0) != 0x80; }

size_t cells(const std::string& s) {
    size_t n = 0;
    for (unsigned char c : s) n += isLead(c);
    return n;
}

// Byte offset of the start of code point number `cp`.
static size_t offsetOf(const std::string& s, size_t cp) {
    size_t n = 0;
    for (size_t i = 0; i < s.size(); i++) {
        if (isLead((unsigned char)s[i])) {
            if (n == cp) return i;
            n++;
        }
    }
    return s.size();
}

std::string clip(const std::string& s, size_t width) {
    if (cells(s) <= width) return s;
    if (width == 0) return "";
    return s.substr(0, offsetOf(s, width - 1)) + "\xE2\x80\xA6";
}

std::string padRight(const std::string& s, size_t width) {
    std::string c = clip(s, width);
    c.append(width - cells(c), ' ');
    return c;
}

std::string padLeft(const std::string& s, size_t width) {
    std::string c = clip(s, width);
    return std::string(width - cells(c), ' ') + c;
}

std::string clipPath(const std::string& path, size_t width) {
    size_t n = cells(path);
    if (n <= width) return path;
    size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos) return clip(path, width);
    std::string tail = path.substr(slash);  // "\Claude.exe"
    size_t tailCells = cells(tail);
    if (tailCells + 4 > width) return clip(path, width);
    size_t headCells = width - tailCells - 3;
    // keep whole leading directories where possible
    std::string head = path.substr(0, offsetOf(path, headCells));
    size_t cut = head.find_last_of("\\/");
    if (cut != std::string::npos && cut >= 2) head = head.substr(0, cut + 1);
    return head + "..." + tail;
}

}  // namespace culprit
