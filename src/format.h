// Pure text helpers for the terminal UI.
#pragma once
#include <cstdint>
#include <string>

namespace culprit {

std::string fmtBytes(uint64_t bytes);      // "754 MB", "7.2 GB"
std::string fmtPercent(double frac);       // 0.091 -> "9.1%"
std::string fmtDuration(double seconds);   // "45s", "12m", "3h 05m", "2d 4h"

// Display width in terminal cells, treating each code point as one cell.
size_t cells(const std::string& utf8);
// Clip to `width` cells, ending in an ellipsis when something was cut.
std::string clip(const std::string& utf8, size_t width);
std::string padRight(const std::string& utf8, size_t width);
std::string padLeft(const std::string& utf8, size_t width);

// Shorten a path from the middle: C:\Users\...\Claude.exe
std::string clipPath(const std::string& path, size_t width);

}  // namespace culprit
