// Small Win32 conveniences shared by the Windows-facing modules.
#pragma once
#include <windows.h>

#include <cstdint>
#include <string>

namespace culprit {

inline std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

inline std::string narrow(const wchar_t* w, int len = -1) {
    if (!w || len == 0) return {};
    if (len < 0) len = (int)wcslen(w);
    int n = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, s.data(), n, nullptr, nullptr);
    return s;
}

inline std::string narrow(const std::wstring& w) { return narrow(w.data(), (int)w.size()); }

struct Handle {
    HANDLE h = nullptr;
    Handle() = default;
    explicit Handle(HANDLE x) : h(x == INVALID_HANDLE_VALUE ? nullptr : x) {}
    Handle(Handle&& o) noexcept : h(o.h) { o.h = nullptr; }
    Handle& operator=(Handle&& o) noexcept {
        if (this != &o) { reset(); h = o.h; o.h = nullptr; }
        return *this;
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { reset(); }
    void reset() { if (h) CloseHandle(h); h = nullptr; }
    explicit operator bool() const { return h != nullptr; }
    operator HANDLE() const { return h; }
};

inline uint64_t ftToU64(FILETIME f) { return ((uint64_t)f.dwHighDateTime << 32) | f.dwLowDateTime; }

// Open a process and confirm it is still the one we sampled: a recycled pid
// will have a different creation time. Returns an empty handle on mismatch,
// with GetLastError() == ERROR_INVALID_PARAMETER.
inline Handle openVerified(uint32_t pid, uint64_t created, DWORD access) {
    Handle h(OpenProcess(access | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!h) return h;
    FILETIME c, e, k, u;
    if (!GetProcessTimes(h, &c, &e, &k, &u) || ftToU64(c) != created) {
        h.reset();
        SetLastError(ERROR_INVALID_PARAMETER);
    }
    return h;
}

}  // namespace culprit
