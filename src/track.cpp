#include "track.h"

#include <shlobj.h>
#include <taskschd.h>

#include "engine.h"
#include "inspect.h"
#include "win.h"

namespace culprit {

std::string dataDir() {
    std::wstring dir;
    wchar_t over[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"CULPRIT_DATA_DIR", over, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        dir = over;
    } else {
        PWSTR base = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &base)) && base) {
            dir = std::wstring(base) + L"\\Culprit";
        }
        CoTaskMemFree(base);
    }
    if (dir.empty()) return {};
    CreateDirectoryW(dir.c_str(), nullptr);
    return narrow(dir);
}

bool collectorRunning() {
    Handle m(OpenMutexW(SYNCHRONIZE, FALSE, kCollectorMutex));
    return (bool)m;
}

bool spawnCollector() {
    std::wstring exe = widen(selfPath());
    std::wstring cmd = L"\"" + exe + L"\" collect";
    STARTUPINFOW si{};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    DWORD flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    // Prefer to outlive the terminal's job object; fall back if not allowed.
    BOOL ok = CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, flags | CREATE_BREAKAWAY_FROM_JOB,
                             nullptr, nullptr, &si, &pi);
    if (!ok) ok = CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, flags, nullptr, nullptr, &si, &pi);
    if (!ok) return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

bool stopCollector(unsigned waitMs) {
    Handle ev(OpenEventW(EVENT_MODIFY_STATE, FALSE, kStopEvent));
    if (ev) SetEvent(ev);
    for (unsigned waited = 0; collectorRunning(); waited += 50) {
        if (waited >= waitMs) return false;
        Sleep(50);
    }
    return true;
}

int collectorMain() {
    Handle mtx(CreateMutexW(nullptr, FALSE, kCollectorMutex));
    if (!mtx || GetLastError() == ERROR_ALREADY_EXISTS) return 0;  // one per user session
    Handle stop(CreateEventW(nullptr, TRUE, FALSE, kStopEvent));
    if (!stop) return 1;

    Engine engine;
    Engine::Options opt;
    opt.headless = true;
    opt.intervalMs = 5000;
    if (!engine.start(opt)) return 1;
    WaitForSingleObject(stop, INFINITE);
    engine.stop();
    return 0;
}

// ---------------------------------------------------------------------------
// Scheduled task (per user, logon trigger, standard privilege)
// ---------------------------------------------------------------------------

namespace {

struct Bstr {
    BSTR b;
    explicit Bstr(const std::wstring& s) : b(SysAllocStringLen(s.data(), (UINT)s.size())) {}
    ~Bstr() { SysFreeString(b); }
    operator BSTR() const { return b; }
};

template <class T>
struct Com {
    T* p = nullptr;
    ~Com() { if (p) p->Release(); }
    T** operator&() { return &p; }
    T* operator->() const { return p; }
    explicit operator bool() const { return p != nullptr; }
};

std::wstring xmlEscape(const std::wstring& s) {
    std::wstring o;
    for (wchar_t c : s) {
        switch (c) {
            case L'&': o += L"&amp;"; break;
            case L'<': o += L"&lt;"; break;
            case L'>': o += L"&gt;"; break;
            case L'"': o += L"&quot;"; break;
            default:   o += c;
        }
    }
    return o;
}

bool currentUser(std::wstring& qualified, std::wstring& plain) {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
    Handle tok(raw);
    BYTE buf[256];
    DWORD got = 0;
    if (!GetTokenInformation(tok, TokenUser, buf, sizeof buf, &got)) return false;
    wchar_t name[256], domain[256];
    DWORD nName = (DWORD)std::size(name), nDomain = (DWORD)std::size(domain);
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, ((TOKEN_USER*)buf)->User.Sid, name, &nName, domain, &nDomain, &use)) return false;
    plain = name;
    qualified = std::wstring(domain) + L"\\" + name;
    return true;
}

std::wstring taskNameFor(const std::wstring& plainUser) {
    std::wstring safe;
    for (wchar_t c : plainUser) safe += (wcschr(L"\\/:*?\"<>|", c) ? L'_' : c);
    return L"Culprit Collector (" + safe + L")";
}

struct Scheduler {
    bool comInit = false;
    Com<ITaskService> svc;
    Com<ITaskFolder> root;
    HRESULT hr = S_OK;

    Scheduler() {
        hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        comInit = SUCCEEDED(hr);
        if (!comInit && hr != RPC_E_CHANGED_MODE) return;
        hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc);
        if (FAILED(hr)) return;
        VARIANT e;
        VariantInit(&e);
        hr = svc->Connect(e, e, e, e);
        if (FAILED(hr)) return;
        hr = svc->GetFolder(Bstr(L"\\"), &root);
    }
    ~Scheduler() {
        if (root.p) { root.p->Release(); root.p = nullptr; }
        if (svc.p) { svc.p->Release(); svc.p = nullptr; }
        if (comInit) CoUninitialize();
    }
    bool ok() const { return SUCCEEDED(hr) && root; }
};

std::string hrText(HRESULT hr) {
    char b[32];
    snprintf(b, sizeof b, "0x%08lX", (unsigned long)hr);
    return b;
}

std::wstring between(const std::wstring& s, const wchar_t* a, const wchar_t* b) {
    size_t i = s.find(a);
    if (i == std::wstring::npos) return {};
    i += wcslen(a);
    size_t j = s.find(b, i);
    return j == std::wstring::npos ? std::wstring() : s.substr(i, j - i);
}

}  // namespace

TrackStatus trackStatus() {
    TrackStatus st;
    st.running = collectorRunning();
    std::wstring qualified, plain;
    if (!currentUser(qualified, plain)) return st;
    std::wstring name = taskNameFor(plain);
    st.taskName = narrow(name);

    Scheduler s;
    if (!s.ok()) return st;
    Com<IRegisteredTask> task;
    if (SUCCEEDED(s.root->GetTask(Bstr(name), &task)) && task) {
        st.registered = true;
        BSTR xml = nullptr;
        if (SUCCEEDED(task->get_Xml(&xml)) && xml) {
            std::wstring x(xml, SysStringLen(xml));
            st.command = narrow(between(x, L"<Arguments>", L"</Arguments>"));
        }
        SysFreeString(xml);
    }
    return st;
}

bool trackOn(std::string& message) {
    std::wstring qualified, plain;
    if (!currentUser(qualified, plain)) {
        message = "Could not determine the current Windows user.";
        return false;
    }
    std::wstring exe = widen(selfPath());
    std::wstring user = xmlEscape(qualified);

    // conhost --headless runs a console program with no visible window.
    std::wstring xml =
        L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
        L" <RegistrationInfo><Description>Culprit: records which applications use CPU and memory, "
        L"so history is available when you open it. Remove with 'culprit track off'.</Description></RegistrationInfo>\n"
        L" <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>" + user + L"</UserId></LogonTrigger></Triggers>\n"
        L" <Principals><Principal id=\"Author\"><UserId>" + user + L"</UserId>"
        L"<LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\n"
        L" <Settings>"
        L"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        L"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        L"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        L"<AllowHardTerminate>true</AllowHardTerminate>"
        L"<StartWhenAvailable>true</StartWhenAvailable>"
        L"<IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>"
        L"<Enabled>true</Enabled><Hidden>false</Hidden>"
        L"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>4</Priority>"
        L"</Settings>\n"
        L" <Actions Context=\"Author\"><Exec><Command>conhost.exe</Command>"
        L"<Arguments>--headless \"" + xmlEscape(exe) + L"\" collect</Arguments></Exec></Actions>\n"
        L"</Task>\n";

    Scheduler s;
    if (!s.ok()) {
        message = "Could not reach the Windows Task Scheduler (" + hrText(s.hr) + ").";
        return false;
    }
    VARIANT e;
    VariantInit(&e);
    Com<IRegisteredTask> task;
    HRESULT hr = s.root->RegisterTask(Bstr(taskNameFor(plain)), Bstr(xml), TASK_CREATE_OR_UPDATE, e, e,
                                      TASK_LOGON_INTERACTIVE_TOKEN, e, &task);
    if (FAILED(hr)) {
        message = "Could not register the scheduled task (" + hrText(hr) + ").";
        return false;
    }

    if (!collectorRunning() && !spawnCollector()) {
        message = "Tracking will start at your next sign-in, but the collector could not be started now.";
        return false;
    }
    message = "Tracking is on. History is recorded in the background and starts automatically at sign-in.";
    return true;
}

bool trackOff(std::string& message) {
    std::wstring qualified, plain;
    bool removed = true;
    if (currentUser(qualified, plain)) {
        Scheduler s;
        if (s.ok()) {
            HRESULT hr = s.root->DeleteTask(Bstr(taskNameFor(plain)), 0);
            removed = SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
            if (!removed) message = "Could not remove the scheduled task (" + hrText(hr) + "). ";
        }
    }
    bool stopped = stopCollector(8000);
    if (!stopped) message += "The collector did not stop in time. ";
    if (removed && stopped) message = "Tracking is off. Existing history is kept in " + dataDir() + ".";
    return removed && stopped;
}

bool trackRestart(std::string& message) {
    TrackStatus st = trackStatus();
    if (!st.registered && !st.running) {
        message = "Tracking is off; nothing to restart.";
        return true;
    }
    if (!stopCollector(8000)) {
        message = "The collector did not stop in time.";
        return false;
    }
    if (!spawnCollector()) {
        message = "Could not start the collector.";
        return false;
    }
    message = "Collector restarted.";
    return true;
}

}  // namespace culprit
