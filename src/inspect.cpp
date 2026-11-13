#include "inspect.h"

#include "proctree.h"
#include "sampler.h"
#include "win.h"

#include <mscat.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <winsvc.h>

namespace culprit {

namespace {

std::wstring imagePathW(ProcId id, DWORD* err = nullptr) {
    Handle h = openVerified(id.pid, id.created, 0);
    if (!h) {
        DWORD why = GetLastError();
        if (err) *err = why;
        // Processes owned by other accounts (dwm, services) cannot be opened
        // without admin, but the kernel will still say what they are.
        return why == ERROR_ACCESS_DENIED ? widen(imagePathByPid(id.pid)) : std::wstring();
    }
    wchar_t buf[32768];
    DWORD n = (DWORD)std::size(buf);
    if (!QueryFullProcessImageNameW(h, 0, buf, &n)) {
        if (err) *err = GetLastError();
        return {};
    }
    return std::wstring(buf, n);
}

// One string from the version resource, first translation found.
std::string versionString(const std::wstring& path, const wchar_t* field) {
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, path.c_str(), &dummy);
    if (!size) return {};
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, path.c_str(), 0, size, data.data())) return {};

    struct LangCp { WORD lang, cp; };
    LangCp* tr = nullptr;
    UINT trLen = 0;
    std::vector<LangCp> tries;
    if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", (void**)&tr, &trLen))
        for (UINT i = 0; i < trLen / sizeof(LangCp); i++) tries.push_back(tr[i]);
    tries.push_back({0x0409, 1200});
    tries.push_back({0x0409, 1252});
    tries.push_back({0x0000, 1200});

    for (LangCp t : tries) {
        wchar_t key[96];
        swprintf(key, std::size(key), L"\\StringFileInfo\\%04x%04x\\%s", t.lang, t.cp, field);
        wchar_t* val = nullptr;
        UINT len = 0;
        if (VerQueryValueW(data.data(), key, (void**)&val, &len) && val && len > 1) {
            std::string s = narrow(val);
            while (!s.empty() && s.back() == ' ') s.pop_back();
            if (!s.empty()) return s;
        }
    }
    return {};
}

struct SigInfo {
    std::string status;
    std::string signer;
    bool valid = false;
};

std::string signerName(HANDLE state) {
    CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(state);
    if (!pd) return {};
    CRYPT_PROVIDER_SGNR* sg = WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0);
    if (!sg) return {};
    CRYPT_PROVIDER_CERT* pc = WTHelperGetProvCertFromChain(sg, 0);
    if (!pc || !pc->pCert) return {};
    wchar_t name[256];
    DWORD n = CertGetNameStringW(pc->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, (DWORD)std::size(name));
    return n > 1 ? narrow(name) : std::string();
}

// Runs one WinVerifyTrust pass. No UI, no revocation lookups, no network.
LONG verifyOnce(WINTRUST_DATA& wd, std::string& signer) {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    LONG st = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    if (wd.hWVTStateData) signer = signerName(wd.hWVTStateData);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    return st;
}

std::string describeTrust(LONG st) {
    switch ((DWORD)st) {
        case (DWORD)TRUST_E_NOSIGNATURE:       return "Not signed";
        case (DWORD)TRUST_E_BAD_DIGEST:        return "Invalid (file modified after signing)";
        case (DWORD)CERT_E_EXPIRED:            return "Invalid (certificate expired)";
        case (DWORD)CERT_E_UNTRUSTEDROOT:      return "Untrusted (unknown root certificate)";
        case (DWORD)CERT_E_CHAINING:           return "Untrusted (incomplete certificate chain)";
        case (DWORD)TRUST_E_EXPLICIT_DISTRUST: return "Distrusted";
        case (DWORD)TRUST_E_SUBJECT_NOT_TRUSTED: return "Untrusted";
        case (DWORD)CERT_E_REVOKED:            return "Invalid (certificate revoked)";
        default: {
            char b[48];
            snprintf(b, sizeof b, "Invalid (0x%08lX)", (unsigned long)st);
            return b;
        }
    }
}

// Most Windows binaries carry no embedded signature; they are covered by a
// signed catalog instead.
bool verifyCatalog(const std::wstring& path, SigInfo& out) {
    HCATADMIN admin = nullptr;
    if (!CryptCATAdminAcquireContext2(&admin, nullptr, L"SHA256", nullptr, 0)) return false;
    bool found = false;
    Handle f(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, 0, nullptr));
    if (f) {
        DWORD hashLen = 0;
        CryptCATAdminCalcHashFromFileHandle2(admin, f, &hashLen, nullptr, 0);
        std::vector<BYTE> hash(hashLen);
        if (hashLen && CryptCATAdminCalcHashFromFileHandle2(admin, f, &hashLen, hash.data(), 0)) {
            HCATINFO ci = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), hashLen, 0, nullptr);
            if (ci) {
                CATALOG_INFO info{};
                info.cbStruct = sizeof info;
                if (CryptCATCatalogInfoFromContext(ci, &info, 0)) {
                    std::wstring tag;
                    for (BYTE b : hash) {
                        wchar_t hx[3];
                        swprintf(hx, 3, L"%02X", b);
                        tag += hx;
                    }
                    WINTRUST_CATALOG_INFO wci{};
                    wci.cbStruct = sizeof wci;
                    wci.pcwszCatalogFilePath = info.wszCatalogFile;
                    wci.pcwszMemberFilePath = path.c_str();
                    wci.pcwszMemberTag = tag.c_str();
                    wci.pbCalculatedFileHash = hash.data();
                    wci.cbCalculatedFileHash = hashLen;
                    wci.hCatAdmin = admin;
                    WINTRUST_DATA wd{};
                    wd.cbStruct = sizeof wd;
                    wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                    wd.pCatalog = &wci;
                    LONG st = verifyOnce(wd, out.signer);
                    found = true;
                    out.valid = st == ERROR_SUCCESS;
                    out.status = out.valid ? "Valid (Windows catalog)" : describeTrust(st);
                }
                CryptCATAdminReleaseCatalogContext(admin, ci, 0);
            }
        }
    }
    CryptCATAdminReleaseContext(admin, 0);
    return found;
}

SigInfo verifySignature(const std::wstring& path) {
    SigInfo out;
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = path.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof wd;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    LONG st = verifyOnce(wd, out.signer);
    if (st == ERROR_SUCCESS) {
        out.valid = true;
        out.status = "Valid";
        return out;
    }
    if ((DWORD)st == (DWORD)TRUST_E_NOSIGNATURE && verifyCatalog(path, out)) return out;
    out.status = describeTrust(st);
    return out;
}

std::string accountOf(ProcId id, bool& elevated, bool& elevatedKnown) {
    Handle h = openVerified(id.pid, id.created, 0);
    if (!h) return GetLastError() == ERROR_ACCESS_DENIED ? kRestricted : kUnavailable;
    HANDLE rawTok = nullptr;
    if (!OpenProcessToken(h, TOKEN_QUERY, &rawTok))
        return GetLastError() == ERROR_ACCESS_DENIED ? kRestricted : kUnavailable;
    Handle tok(rawTok);

    TOKEN_ELEVATION el{};
    DWORD got = 0;
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &got)) {
        elevated = el.TokenIsElevated != 0;
        elevatedKnown = true;
    }

    BYTE buf[256];
    if (!GetTokenInformation(tok, TokenUser, buf, sizeof buf, &got)) return kUnavailable;
    PSID sid = ((TOKEN_USER*)buf)->User.Sid;
    wchar_t name[256], domain[256];
    DWORD nName = (DWORD)std::size(name), nDomain = (DWORD)std::size(domain);
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, sid, name, &nName, domain, &nDomain, &use)) return kUnavailable;
    std::string out = narrow(domain);
    if (!out.empty()) out += "\\";
    return out + narrow(name);
}

std::vector<std::string> servicesOf(uint32_t pid) {
    std::vector<std::string> out;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return out;
    std::vector<BYTE> buf(256 * 1024);
    DWORD need = 0, count = 0, resume = 0;
    for (;;) {
        BOOL ok = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, buf.data(),
                                        (DWORD)buf.size(), &need, &count, &resume, nullptr);
        if (!ok && GetLastError() != ERROR_MORE_DATA) break;
        auto* e = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
        for (DWORD i = 0; i < count; i++)
            if (e[i].ServiceStatusProcess.dwProcessId == pid)
                out.push_back(narrow(e[i].lpDisplayName) + " (" + narrow(e[i].lpServiceName) + ")");
        if (ok) break;
    }
    CloseServiceHandle(scm);
    return out;
}

}  // namespace

std::string imagePath(ProcId id) { return narrow(imagePathW(id)); }

std::string friendlyName(ProcId id) {
    std::wstring path = imagePathW(id);
    if (path.empty()) return {};
    return versionString(path, L"FileDescription");
}

std::string fmtFileTime(uint64_t ft) {
    if (!ft) return kUnavailable;
    FILETIME f{(DWORD)ft, (DWORD)(ft >> 32)};
    SYSTEMTIME utc, loc;
    if (!FileTimeToSystemTime(&f, &utc) || !SystemTimeToTzSpecificLocalTime(nullptr, &utc, &loc)) return kUnavailable;
    char b[48];
    snprintf(b, sizeof b, "%04d-%02d-%02d %02d:%02d:%02d", loc.wYear, loc.wMonth, loc.wDay, loc.wHour, loc.wMinute,
             loc.wSecond);
    return b;
}

Details inspect(const Proc& p, const std::vector<Proc>& all) {
    Details d;
    d.id = {p.pid, p.created};
    d.image = p.image;
    d.started = fmtFileTime(p.created);

    DWORD err = 0;
    std::wstring path = imagePathW(d.id, &err);
    if (path.empty()) {
        const char* why = err == ERROR_ACCESS_DENIED ? kRestricted : kUnavailable;
        d.path = d.publisher = d.signature = why;
    } else {
        d.path = narrow(path);
        d.description = versionString(path, L"FileDescription");
        SigInfo sig = verifySignature(path);
        d.signature = sig.status;
        if (sig.valid && !sig.signer.empty()) {
            d.publisher = sig.signer;
        } else {
            std::string company = versionString(path, L"CompanyName");
            d.publisher = company.empty() ? kUnavailable : company + " (unverified)";
        }
    }

    d.user = accountOf(d.id, d.elevated, d.elevatedKnown);

    int self = findProc(all, d.id);
    if (self >= 0) {
        int par = parentIndex(all, (size_t)self);
        if (par >= 0)
            d.parent = all[(size_t)par].image + " (" + std::to_string(all[(size_t)par].pid) + ")";
        else
            d.parent = p.ppid ? "Exited (was PID " + std::to_string(p.ppid) + ")" : "None";
        d.children = descendants(all, (size_t)self).size();
    } else {
        d.parent = kUnavailable;
    }

    d.services = servicesOf(p.pid);
    return d;
}

bool isElevated() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
    Handle tok(raw);
    TOKEN_ELEVATION el{};
    DWORD got = 0;
    return GetTokenInformation(tok, TokenElevation, &el, sizeof el, &got) && el.TokenIsElevated;
}

std::string selfPath() {
    wchar_t buf[32768];
    DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)std::size(buf));
    return narrow(buf, (int)n);
}

}  // namespace culprit
