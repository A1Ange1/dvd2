
#include <windows.h>
#include <tlhelp32.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <psapi.h>
#include <commctrl.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <algorithm>
#include <string>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

#define APP_NAME "DLL Injector - By Real"
#define APP_CLASS "DLLInjectorClass"
#define APP_VERSION "v2.0"
#define CONFIG_REG_KEY "Software\\DLLInjectorPro"
#define CONFIG_FILE_NAME "dllinjector_config.txt"
#define LOG_FILE_NAME "dllinjector.log"

#define IDC_INJECT        101
#define IDC_BROWSE        102
#define IDC_PROC_LIST     103
#define IDC_REFRESH       104
#define IDC_DLL_PATH      105
#define IDC_PID_ENTRY     106
#define IDC_SEARCH        107
#define IDC_ON_TOP        108
#define IDC_DRYRUN        109
#define IDC_SETTINGS      110
#define IDC_METHOD        111
#define IDC_RECENT_DLLS   112
#define IDC_FAV_PROC      113

#define IDR_MENU          200
#define IDM_ABOUT         201
#define IDM_EXIT          202
#define IDM_SETTINGS      203
#define IDM_TRAY_RESTORE  204
#define IDM_TRAY_INJECT   205
#define IDM_TRAY_EXIT     206

#define TIMER_PROC_REFRESH 300

HINSTANCE hInst;
HWND hwndMain, hwndDllPath, hwndProcList, hwndPidEntry, hwndSearch, hwndOnTop;
HWND hwndSettingsDlg, hwndMethod, hwndDryRun, hwndRecentDlls, hwndFavProc;
HMENU hTrayMenu;
NOTIFYICONDATA nid = { sizeof(nid) };
bool alwaysOnTop = false;
bool dryRunMode = false;
bool autoAttachLast = true;
bool showTrayIcon = true;
bool useRegistry = true;
bool loggingEnabled = true;
DWORD refreshInterval = 3000; // ms
std::string lastDllPath, lastProcName;
DWORD lastPid = 0;
std::set<std::string> recentDlls;
std::set<DWORD> favoritePids;
std::map<DWORD, std::string> pidToName;
std::string logFile = LOG_FILE_NAME;
std::string configFile = CONFIG_FILE_NAME;
std::vector<std::pair<std::string, DWORD>> processList;
std::string processSearch;
UINT_PTR refreshTimer = 0;

// Injection methods
enum InjectMethod { METHOD_CLASSIC = 0, METHOD_MANUALMAP = 1, METHOD_REFLECTIVE = 2 };
InjectMethod currentMethod = METHOD_CLASSIC;
const char* methodNames[] = { "Classic (LoadLibrary)", "Manual Mapping (POC)", "Reflective (POC)" };

// Forward declarations
void ParseCLI(int argc, char* argv[]);

void LoadConfig();
void SaveConfig();
void LogAction(const std::string& msg);
void ShowSettingsDialog(HWND hwndParent);
void ShowAbout(HWND hwnd);
void UpdateTrayIcon(bool add);
void ShowTrayBalloon(const std::string& title, const std::string& msg, DWORD infoFlags = NIIF_INFO);
void RefreshProcessList(HWND hwnd, const std::string& filter = "");
bool InjectDLL(DWORD pid, const std::string& dllPath, std::string& errOut, InjectMethod method, bool dryRun);
void ManualMapStub(DWORD pid, const std::string& dllPath, std::string& logMsg, bool dryRun);
void ReflectiveInjectStub(DWORD pid, const std::string& dllPath, std::string& logMsg, bool dryRun);
void AddRecentDll(const std::string& path);
void AddFavoritePid(DWORD pid);
void RemoveFavoritePid(DWORD pid);
void AutoAttachLast();
void UpdateFavoritesList();
void UpdateRecentDllsList();
void SetControlText(HWND hwnd, int id, const std::string& text);
std::string GetControlText(HWND hwnd, int id);
void ShowProcessTooltip(HWND hwnd, int itemIndex, POINT pt);
std::string GetProcessDetails(DWORD pid);
INT_PTR CALLBACK SettingsDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);

//
// --- Settings and Config Management ---
//
struct AppConfig {
    bool useRegistry = true;
    bool loggingEnabled = true;
    bool autoAttachLast = true;
    bool showTrayIcon = true;
    DWORD refreshInterval = 3000;
    bool dryRunMode = false;
    InjectMethod injectMethod = METHOD_CLASSIC;
    std::set<std::string> recentDlls;
    std::set<DWORD> favoritePids;
    std::string lastDllPath;
    std::string lastProcName;
    DWORD lastPid = 0;
};

AppConfig config;

void SaveConfig() {
    if (config.useRegistry) {
        HKEY hKey;
        if (RegCreateKeyA(HKEY_CURRENT_USER, CONFIG_REG_KEY, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "LoggingEnabled", 0, REG_DWORD, (BYTE*)&config.loggingEnabled, sizeof(DWORD));
            RegSetValueExA(hKey, "AutoAttachLast", 0, REG_DWORD, (BYTE*)&config.autoAttachLast, sizeof(DWORD));
            RegSetValueExA(hKey, "ShowTrayIcon", 0, REG_DWORD, (BYTE*)&config.showTrayIcon, sizeof(DWORD));
            RegSetValueExA(hKey, "RefreshInterval", 0, REG_DWORD, (BYTE*)&config.refreshInterval, sizeof(DWORD));
            RegSetValueExA(hKey, "DryRunMode", 0, REG_DWORD, (BYTE*)&config.dryRunMode, sizeof(DWORD));
            RegSetValueExA(hKey, "InjectMethod", 0, REG_DWORD, (BYTE*)&config.injectMethod, sizeof(DWORD));
            RegSetValueExA(hKey, "LastDllPath", 0, REG_SZ, (BYTE*)config.lastDllPath.c_str(), config.lastDllPath.size() + 1);
            RegSetValueExA(hKey, "LastProcName", 0, REG_SZ, (BYTE*)config.lastProcName.c_str(), config.lastProcName.size() + 1);
            RegSetValueExA(hKey, "LastPid", 0, REG_DWORD, (BYTE*)&config.lastPid, sizeof(DWORD));
            // Save recent DLLs and favorites as comma-separated strings
            std::ostringstream oss1;
            for (const auto& s : config.recentDlls) { oss1 << s << ";"; }
            std::string r1 = oss1.str();
            RegSetValueExA(hKey, "RecentDlls", 0, REG_SZ, (BYTE*)r1.c_str(), r1.size() + 1);
            std::ostringstream oss2;
            for (auto p : config.favoritePids) { oss2 << p << ";"; }
            std::string r2 = oss2.str();
            RegSetValueExA(hKey, "FavoritePids", 0, REG_SZ, (BYTE*)r2.c_str(), r2.size() + 1);
            RegCloseKey(hKey);
        }
    }
    else {
        std::ofstream f(configFile);
        f << "LoggingEnabled=" << config.loggingEnabled << "\n";
        f << "AutoAttachLast=" << config.autoAttachLast << "\n";
        f << "ShowTrayIcon=" << config.showTrayIcon << "\n";
        f << "RefreshInterval=" << config.refreshInterval << "\n";
        f << "DryRunMode=" << config.dryRunMode << "\n";
        f << "InjectMethod=" << (int)config.injectMethod << "\n";
        f << "LastDllPath=" << config.lastDllPath << "\n";
        f << "LastProcName=" << config.lastProcName << "\n";
        f << "LastPid=" << config.lastPid << "\n";
        f << "RecentDlls=";
        for (const auto& s : config.recentDlls) f << s << ";";
        f << "\nFavoritePids=";
        for (auto p : config.favoritePids) f << p << ";";
        f << "\n";
        f.close();
    }
}

void LoadConfig() {
    config = AppConfig(); // Defaults
    if (PathFileExistsA(configFile.c_str())) config.useRegistry = false;
    if (config.useRegistry) {
        HKEY hKey;
        if (RegOpenKeyA(HKEY_CURRENT_USER, CONFIG_REG_KEY, &hKey) == ERROR_SUCCESS) {
            DWORD dword = 0, sz;
            char buff[2048];
            sz = sizeof(dword);
            if (RegQueryValueExA(hKey, "LoggingEnabled", 0, NULL, (BYTE*)&dword, &sz) == ERROR_SUCCESS)
                config.loggingEnabled = !!dword;
            sz = sizeof(dword);
            if (RegQueryValueExA(hKey, "AutoAttachLast", 0, NULL, (BYTE*)&dword, &sz) == ERROR_SUCCESS)
                config.autoAttachLast = !!dword;
            sz = sizeof(dword);
            if (RegQueryValueExA(hKey, "ShowTrayIcon", 0, NULL, (BYTE*)&dword, &sz) == ERROR_SUCCESS)
                config.showTrayIcon = !!dword;
            sz = sizeof(dword);
            if (RegQueryValueExA(hKey, "RefreshInterval", 0, NULL, (BYTE*)&dword, &sz) == ERROR_SUCCESS)
                config.refreshInterval = dword;
            sz = sizeof(dword);
            if (RegQueryValueExA(hKey, "DryRunMode", 0, NULL, (BYTE*)&dword, &sz) == ERROR_SUCCESS)
                config.dryRunMode = !!dword;
            sz = sizeof(dword);
            if (RegQueryValueExA(hKey, "InjectMethod", 0, NULL, (BYTE*)&dword, &sz) == ERROR_SUCCESS)
                config.injectMethod = (InjectMethod)dword;
            sz = sizeof(buff);
            if (RegQueryValueExA(hKey, "LastDllPath", 0, NULL, (BYTE*)buff, &sz) == ERROR_SUCCESS)
                config.lastDllPath = buff;
            sz = sizeof(buff);
            if (RegQueryValueExA(hKey, "LastProcName", 0, NULL, (BYTE*)buff, &sz) == ERROR_SUCCESS)
                config.lastProcName = buff;
            sz = sizeof(dword);
            if (RegQueryValueExA(hKey, "LastPid", 0, NULL, (BYTE*)&dword, &sz) == ERROR_SUCCESS)
                config.lastPid = dword;
            sz = sizeof(buff);
            if (RegQueryValueExA(hKey, "RecentDlls", 0, NULL, (BYTE*)buff, &sz) == ERROR_SUCCESS) {
                std::string s = buff, tok;
                std::istringstream iss(s);
                while (std::getline(iss, tok, ';')) if (!tok.empty()) config.recentDlls.insert(tok);
            }
            sz = sizeof(buff);
            if (RegQueryValueExA(hKey, "FavoritePids", 0, NULL, (BYTE*)buff, &sz) == ERROR_SUCCESS) {
                std::string s = buff, tok;
                std::istringstream iss(s);
                while (std::getline(iss, tok, ';')) if (!tok.empty()) config.favoritePids.insert(atoi(tok.c_str()));
            }
            RegCloseKey(hKey);
        }
    }
    else {
        std::ifstream f(configFile);
        std::string line;
        while (std::getline(f, line)) {
            size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string key = line.substr(0, eq), val = line.substr(eq + 1);
            if (key == "LoggingEnabled") config.loggingEnabled = !!atoi(val.c_str());
            if (key == "AutoAttachLast") config.autoAttachLast = !!atoi(val.c_str());
            if (key == "ShowTrayIcon") config.showTrayIcon = !!atoi(val.c_str());
            if (key == "RefreshInterval") config.refreshInterval = atoi(val.c_str());
            if (key == "DryRunMode") config.dryRunMode = !!atoi(val.c_str());
            if (key == "InjectMethod") config.injectMethod = (InjectMethod)atoi(val.c_str());
            if (key == "LastDllPath") config.lastDllPath = val;
            if (key == "LastProcName") config.lastProcName = val;
            if (key == "LastPid") config.lastPid = atoi(val.c_str());
            if (key == "RecentDlls") {
                std::istringstream iss(val);
                std::string tok;
                while (std::getline(iss, tok, ';')) if (!tok.empty()) config.recentDlls.insert(tok);
            }
            if (key == "FavoritePids") {
                std::istringstream iss(val);
                std::string tok;
                while (std::getline(iss, tok, ';')) if (!tok.empty()) config.favoritePids.insert(atoi(tok.c_str()));
            }
        }
    }
    // Copy from config struct to globals
    alwaysOnTop = config.showTrayIcon;
    dryRunMode = config.dryRunMode;
    autoAttachLast = config.autoAttachLast;
    refreshInterval = config.refreshInterval;
    lastDllPath = config.lastDllPath;
    lastProcName = config.lastProcName;
    lastPid = config.lastPid;
    recentDlls = config.recentDlls;
    favoritePids = config.favoritePids;
    currentMethod = config.injectMethod;
    loggingEnabled = config.loggingEnabled;
    useRegistry = config.useRegistry;
}

void LogAction(const std::string& msg) {
    if (!loggingEnabled) return;
    std::ofstream log(logFile, std::ios_base::app);
    std::time_t t = std::time(nullptr);
    char tm[64];
    std::strftime(tm, sizeof(tm), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    log << "[" << tm << "] " << msg << std::endl;
}
// ... (continuation from previous part)

//
// --- Utility Functions ---
//

// Set text for a control
void SetControlText(HWND hwnd, int id, const std::string& text) {
    SetWindowText(GetDlgItem(hwnd, id), text.c_str());
}

// Get text from a control
std::string GetControlText(HWND hwnd, int id) {
    char buf[512] = {};
    GetWindowText(GetDlgItem(hwnd, id), buf, sizeof(buf));
    return buf;
}

// Add a DLL to recent list (and update UI/config)
void AddRecentDll(const std::string& path) {
    if (path.empty()) return;
    recentDlls.insert(path);
    config.recentDlls = recentDlls;
    SaveConfig();
    // Optionally update recent DLLs UI list
}

// Add/remove PID to/from favorites
void AddFavoritePid(DWORD pid) {
    if (pid) favoritePids.insert(pid);
    config.favoritePids = favoritePids;
    SaveConfig();
}
void RemoveFavoritePid(DWORD pid) {
    favoritePids.erase(pid);
    config.favoritePids = favoritePids;
    SaveConfig();
}

// Update favorites UI (stub, actual code will fill listbox or similar)
void UpdateFavoritesList() {
    // For demo: just log for now
    for (DWORD pid : favoritePids) {
        LogAction("Favorite PID: " + std::to_string(pid));
    }
}

// Update recent DLLs UI (stub)
void UpdateRecentDllsList() {
    // For demo: just log for now
    for (const auto& dll : recentDlls) {
        LogAction("Recent DLL: " + dll);
    }
}

// Tooltips for process list
std::string GetProcessDetails(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return "(Unable to open process)";
    char exeFile[MAX_PATH] = {}, cmdline[1024] = {};
    HMODULE hMod;
    DWORD cbNeeded;
    if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleFileNameExA(hProc, hMod, exeFile, MAX_PATH);
    }
    // Parent PID, session, bitness
    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG rlen = 0;
    typedef LONG(WINAPI* PNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    PNtQueryInformationProcess NtQueryInformationProcess = (PNtQueryInformationProcess)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    DWORD parentPid = 0, session = 0;
    if (NtQueryInformationProcess) {
        if (NtQueryInformationProcess(hProc, 0, &pbi, sizeof(pbi), &rlen) == 0)
            parentPid = (DWORD)(ULONG_PTR)pbi.InheritedFromUniqueProcessId;
    }
    ProcessIdToSessionId(pid, &session);
    BOOL isWow64 = FALSE;
    IsWow64Process(hProc, &isWow64);
    bool isX64 = !!(sizeof(void*) == 8) || !isWow64;
    sprintf(cmdline, "Path: %s\nPID: %lu\nParent PID: %lu\nSession: %lu\nBitness: %s",
        exeFile, pid, parentPid, session, isX64 ? "64-bit" : "32-bit");
    CloseHandle(hProc);
    return cmdline;
}

// Show tooltip at point for process list
void ShowProcessTooltip(HWND hwnd, int itemIndex, POINT pt) {
    if (itemIndex < 0 || itemIndex >= (int)processList.size()) return;
    DWORD pid = processList[itemIndex].second;
    std::string details = GetProcessDetails(pid);
    // For demo, use MessageBox; for real, use a tooltip window.
    MessageBox(hwnd, details.c_str(), "Process Details", MB_OK | MB_ICONINFORMATION);
}

//
// --- Injection Methods ---
//

// Classic injection
bool InjectDLL(DWORD pid, const std::string& dllPath, std::string& errOut, InjectMethod method, bool dryRun) {
    // For demo, only Classic (LoadLibrary) is implemented fully. Others call stub functions.
    if (method == METHOD_CLASSIC) {
        if (dryRun) {
            errOut = "Dry Run: Would call LoadLibraryA in target process.";
            LogAction("[Dry Run] Classic injection for PID " + std::to_string(pid) + " DLL: " + dllPath);
            return true;
        }
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProc) {
            errOut = "OpenProcess failed: " + std::to_string(GetLastError());
            return false;
        }
        void* allocMem = VirtualAllocEx(hProc, nullptr, dllPath.length() + 1, MEM_COMMIT, PAGE_READWRITE);
        if (!allocMem) {
            errOut = "VirtualAllocEx failed: " + std::to_string(GetLastError());
            CloseHandle(hProc);
            return false;
        }
        if (!WriteProcessMemory(hProc, allocMem, dllPath.c_str(), dllPath.length() + 1, nullptr)) {
            errOut = "WriteProcessMemory failed: " + std::to_string(GetLastError());
            VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }
        HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
            (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"),
            allocMem, 0, nullptr);
        if (!hThread) {
            errOut = "CreateRemoteThread failed: " + std::to_string(GetLastError());
            VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }
        WaitForSingleObject(hThread, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProc);
        if (exitCode == 0)
            errOut = "LoadLibraryA failed (exit code 0). Check DLL path and architecture.";
        LogAction("Classic injection for PID " + std::to_string(pid) + " DLL: " + dllPath);
        return exitCode != 0;
    }
    else if (method == METHOD_MANUALMAP) {
        ManualMapStub(pid, dllPath, errOut, dryRun);
        return errOut.empty();
    }
    else if (method == METHOD_REFLECTIVE) {
        ReflectiveInjectStub(pid, dllPath, errOut, dryRun);
        return errOut.empty();
    }
    errOut = "Unknown method.";
    return false;
}
// Manual mapping stub (real implementation is nontrivial)
void ManualMapStub(DWORD pid, const std::string& dllPath, std::string& logMsg, bool dryRun) {
    if (dryRun) {
        logMsg = "Dry Run: Would perform manual mapping of DLL in process.";
        LogAction("[Dry Run] Manual mapping for PID " + std::to_string(pid) + " DLL: " + dllPath);
        return;
    }
    // For brevity, not implemented here. See references for full code.
    logMsg = "Manual mapping not implemented in this demo. (Would inject " + dllPath + ")";
    LogAction("[ManualMapStub] Not implemented. PID " + std::to_string(pid) + " DLL: " + dllPath);
}

void UpdateRecentDllsCombo(HWND hwndRecentCombo) {
    SendMessage(hwndRecentCombo, CB_RESETCONTENT, 0, 0);
    for (const auto& path : recentDlls)
        SendMessage(hwndRecentCombo, CB_ADDSTRING, 0, (LPARAM)path.c_str());
}

// Reflective injection stub (real implementation is nontrivial)
void ReflectiveInjectStub(DWORD pid, const std::string& dllPath, std::string& logMsg, bool dryRun) {
    if (dryRun) {
        logMsg = "Dry Run: Would perform reflective DLL injection.";
        LogAction("[Dry Run] Reflective injection for PID " + std::to_string(pid) + " DLL: " + dllPath);
        return;
    }
    // For brevity, not implemented here. See references for full code.
    logMsg = "Reflective injection not implemented in this demo. (Would inject " + dllPath + ")";
    LogAction("[ReflectiveInjectStub] Not implemented. PID " + std::to_string(pid) + " DLL: " + dllPath);
}
// ... (continuation from previous part)

//
// --- Main Window and Message Loop ---
//

// Forward declaration of window procedure
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpCmdLine, int nCmdShow) {
    hInst = hInstance;

    // Use CommandLineToArgvW for proper argument parsing (handles spaces, quotes, etc.)
    int argc = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::string> argv(argc);
    for (int i = 0; i < argc; ++i) {
        char buf[1024];
        WideCharToMultiByte(CP_ACP, 0, argvW[i], -1, buf, sizeof(buf), NULL, NULL);
        argv[i] = buf;
    }
    LocalFree(argvW);

    // Only run CLI mode if arguments are passed
    if (argc > 1) {
        std::vector<char*> argv_raw;
        for (auto& s : argv) argv_raw.push_back((char*)s.c_str());
        ParseCLI(argc, argv_raw.data());
        return 0; // Exit after handling CLI
    }

    LoadConfig();

    // Register window class
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = APP_CLASS;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);

    // Create main window
    hwndMain = CreateWindow(APP_CLASS, APP_NAME " " APP_VERSION,
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, hInstance, NULL);
    if (!hwndMain) return 0;

    // Show window
    ShowWindow(hwndMain, nCmdShow);
    UpdateWindow(hwndMain);

    // Message loop
    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (hwndSettingsDlg == 0 || !IsDialogMessage(hwndSettingsDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return 0;
}

void ShowAbout(HWND hwnd) {
    MessageBox(hwnd,
        APP_NAME " " APP_VERSION "\n"
        "Features:\n"
        "- Recent DLLs\n"
        "- Favorite Processes\n"
        "- Process Tooltips\n"
        "- Multiple Injection Methods\n"
        "- Manual Mapping & Reflective (POC)\n"
        "- System Tray\n"
        "- Choice of Registry or Local Config\n"
        "- Logging, CLI mode\n"
        "- Dry Run, Auto-attach\n"
        "- Settings Dialog\n",
        "About", MB_OK | MB_ICONINFORMATION);
}

// Menu bar construction (with Settings)
HMENU CreateMainMenu() {
    HMENU hMenu = CreateMenu();
    HMENU hFile = CreatePopupMenu();
    AppendMenu(hFile, MF_STRING, IDM_SETTINGS, "Settings...");
    AppendMenu(hFile, MF_SEPARATOR, 0, NULL);
    AppendMenu(hFile, MF_STRING, IDM_ABOUT, "About");
    AppendMenu(hFile, MF_STRING, IDM_EXIT, "Exit");
    AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hFile, "Menu");
    return hMenu;
}

// Process list refresh
void RefreshProcessList(HWND hwnd, const std::string& filter) {
    SendMessage(hwnd, LB_RESETCONTENT, 0, 0);
    processList.clear();
    // Snapshot
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            std::string name = pe.szExeFile;
            if (filter.empty() || StrStrIA(name.c_str(), filter.c_str())) {
                processList.emplace_back(name, pe.th32ProcessID);
                std::string entry = name + " - PID: " + std::to_string(pe.th32ProcessID);
                // Mark favorite
                if (favoritePids.count(pe.th32ProcessID))
                    entry = "[★] " + entry;
                SendMessage(hwnd, LB_ADDSTRING, 0, (LPARAM)entry.c_str());
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// Tray icon
void UpdateTrayIcon(bool add) {
    nid.hWnd = hwndMain;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    nid.uCallbackMessage = WM_USER + 1;
    nid.hIcon = (HICON)LoadIcon(NULL, IDI_APPLICATION);
    strcpy_s(nid.szTip, sizeof(nid.szTip), APP_NAME);
    if (add)
        Shell_NotifyIcon(NIM_ADD, &nid);
    else
        Shell_NotifyIcon(NIM_DELETE, &nid);
}

// Tray balloon
void ShowTrayBalloon(const std::string& title, const std::string& msg, DWORD infoFlags) {
    nid.uFlags = NIF_INFO;
    strcpy_s(nid.szInfo, sizeof(nid.szInfo), msg.c_str());
    strcpy_s(nid.szInfoTitle, sizeof(nid.szInfoTitle), title.c_str());
    nid.dwInfoFlags = infoFlags;
    Shell_NotifyIcon(NIM_MODIFY, &nid);
}

// Main window procedure
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hwndInject, hwndBrowse, hwndRefresh, hwndSettings, hwndMethodCombo, hwndDryRunChk;
    static HWND hwndRecentCombo, hwndFavList;
    static UINT_PTR timerId = 0;

    switch (msg) {
    case WM_CREATE: {
        SetMenu(hwnd, CreateMainMenu());
        // Example for 800x600, adjust as you like!
        CreateWindow("STATIC", "DLL Path:", WS_VISIBLE | WS_CHILD, 20, 20, 100, 25, hwnd, nullptr, hInst, nullptr);
        hwndDllPath = CreateWindow("EDIT", lastDllPath.c_str(), WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 130, 20, 500, 25, hwnd, (HMENU)IDC_DLL_PATH, hInst, nullptr);
        hwndBrowse = CreateWindow("BUTTON", "Browse", WS_VISIBLE | WS_CHILD, 650, 20, 100, 25, hwnd, (HMENU)IDC_BROWSE, hInst, nullptr);

        CreateWindow("STATIC", "PID:", WS_VISIBLE | WS_CHILD, 20, 60, 40, 25, hwnd, nullptr, hInst, nullptr);
        hwndPidEntry = CreateWindow("EDIT", std::to_string(lastPid).c_str(), WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER, 70, 60, 80, 25, hwnd, (HMENU)IDC_PID_ENTRY, hInst, nullptr);

        CreateWindow("STATIC", "Process Search:", WS_VISIBLE | WS_CHILD, 170, 60, 120, 25, hwnd, nullptr, hInst, nullptr);
        hwndSearch = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 300, 60, 200, 25, hwnd, (HMENU)IDC_SEARCH, hInst, nullptr);

        hwndRefresh = CreateWindow("BUTTON", "Refresh", WS_VISIBLE | WS_CHILD, 520, 60, 100, 25, hwnd, (HMENU)IDC_REFRESH, hInst, nullptr);

        hwndOnTop = CreateWindow("BUTTON", "Always on Top", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 650, 60, 130, 25, hwnd, (HMENU)IDC_ON_TOP, hInst, nullptr);

        CreateWindow("STATIC", "Method:", WS_VISIBLE | WS_CHILD, 20, 100, 60, 25, hwnd, nullptr, hInst, nullptr);
        hwndMethodCombo = CreateWindow("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, 90, 100, 220, 200, hwnd, (HMENU)IDC_METHOD, hInst, nullptr);
        for (int i = 0; i < 3; ++i)
            SendMessage(hwndMethodCombo, CB_ADDSTRING, 0, (LPARAM)methodNames[i]);
        SendMessage(hwndMethodCombo, CB_SETCURSEL, (WPARAM)currentMethod, 0);

        hwndDryRunChk = CreateWindow("BUTTON", "Dry Run (simulate only)", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 330, 100, 200, 25, hwnd, (HMENU)IDC_DRYRUN, hInst, nullptr);

        CreateWindow("STATIC", "Recent DLLs:", WS_VISIBLE | WS_CHILD, 20, 140, 100, 25, hwnd, nullptr, hInst, nullptr);
        hwndRecentCombo = CreateWindow("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWN, 130, 140, 500, 100, hwnd, (HMENU)IDC_RECENT_DLLS, hInst, nullptr);

        CreateWindow("STATIC", "Favorites:", WS_VISIBLE | WS_CHILD, 20, 180, 80, 25, hwnd, nullptr, hInst, nullptr);
        hwndFavList = CreateWindow("LISTBOX", "", WS_VISIBLE | WS_CHILD | WS_BORDER | LBS_NOTIFY | WS_VSCROLL, 110, 180, 200, 60, hwnd, (HMENU)IDC_FAV_PROC, hInst, nullptr);

        CreateWindow("STATIC", "Process List:", WS_VISIBLE | WS_CHILD, 20, 260, 120, 25, hwnd, nullptr, hInst, nullptr);
        hwndProcList = CreateWindow("LISTBOX", "", WS_VISIBLE | WS_CHILD | WS_BORDER | LBS_NOTIFY | WS_VSCROLL,
            20, 290, 760, 230, hwnd, (HMENU)IDC_PROC_LIST, hInst, nullptr);

        hwndInject = CreateWindow("BUTTON", "Inject", WS_VISIBLE | WS_CHILD, 660, 540, 120, 40, hwnd, (HMENU)IDC_INJECT, hInst, nullptr);
        hwndSettings = CreateWindow("BUTTON", "Settings...", WS_VISIBLE | WS_CHILD, 520, 540, 120, 40, hwnd, (HMENU)IDC_SETTINGS, hInst, nullptr);

        // Tray icon
        if (showTrayIcon) UpdateTrayIcon(true);

        // Initial process list
        RefreshProcessList(hwndProcList, "");

        // Timer: auto-refresh
        timerId = SetTimer(hwnd, TIMER_PROC_REFRESH, refreshInterval, NULL);

        return 0;
    }
    case WM_TIMER:
        if (wParam == TIMER_PROC_REFRESH) {
            char buf[128] = {};
            GetWindowText(hwndSearch, buf, sizeof(buf));
            RefreshProcessList(hwndProcList, buf);
        }
        break;
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        switch (id) {
        case IDM_ABOUT:
            ShowAbout(hwnd);
            break;
        case IDM_EXIT:
            PostQuitMessage(0);
            break;
        case IDM_SETTINGS:
        case IDC_SETTINGS:
            ShowSettingsDialog(hwnd);
            break;
        case IDC_BROWSE: {
            char fileName[MAX_PATH] = "";
            OPENFILENAME ofn = { sizeof(ofn) };
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = "DLL Files\0*.dll\0";
            ofn.lpstrFile = fileName;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileName(&ofn)) {
                SetWindowText(hwndDllPath, fileName);
                AddRecentDll(fileName);
                UpdateRecentDllsCombo(hwndRecentCombo);
                config.lastDllPath = fileName;
                SaveConfig();

            }
            break;
        }
        case IDC_REFRESH: {
            char buf[128];
            GetWindowText(hwndSearch, buf, sizeof(buf));
            RefreshProcessList(hwndProcList, buf);
            break;
        }
        case IDC_ON_TOP:
            alwaysOnTop = (SendMessage(hwndOnTop, BM_GETCHECK, 0, 0) == BST_CHECKED);
            SetWindowPos(hwnd, alwaysOnTop ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE);
            break;
        case IDC_SEARCH:
            if (HIWORD(wParam) == EN_CHANGE) {
                char buf[128];
                GetWindowText(hwndSearch, buf, sizeof(buf));
                RefreshProcessList(hwndProcList, buf);
            }
            break;
        case IDC_PROC_LIST:
            if (HIWORD(wParam) == LBN_DBLCLK) {
                LRESULT idx = SendMessage(hwndProcList, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    DWORD pid = processList[idx].second;
                    char pidStr[32];
                    sprintf(pidStr, "%u", pid);
                    SetWindowText(hwndPidEntry, pidStr);
                }
            }
            if (HIWORD(wParam) == LBN_SELCHANGE) {
                // Tooltip on hover - for simplicity, show MessageBox on select
                LRESULT idx = SendMessage(hwndProcList, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    POINT pt;
                    GetCursorPos(&pt);
                    ShowProcessTooltip(hwnd, (int)idx, pt);
                }
            }
            break;
        case IDC_RECENT_DLLS:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                int sel = (int)SendMessage(hwndRecentCombo, CB_GETCURSEL, 0, 0);
                char buf[MAX_PATH] = {};
                SendMessage(hwndRecentCombo, CB_GETLBTEXT, sel, (LPARAM)buf);
                SetWindowText(hwndDllPath, buf);
            }
            break;
        case IDC_METHOD:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                int sel = (int)SendMessage(hwndMethodCombo, CB_GETCURSEL, 0, 0);
                currentMethod = (InjectMethod)sel;
            }
            break;
        case IDC_DRYRUN:
            dryRunMode = (SendMessage(hwndDryRunChk, BM_GETCHECK, 0, 0) == BST_CHECKED);
            break;
        case IDC_FAV_PROC:
            if (HIWORD(wParam) == LBN_DBLCLK) {
                int sel = (int)SendMessage(hwndFavList, LB_GETCURSEL, 0, 0);
                if (sel != LB_ERR) {
                    char buf[64] = {};
                    SendMessage(hwndFavList, LB_GETTEXT, sel, (LPARAM)buf);
                    DWORD pid = atoi(strstr(buf, "PID: ") + 5);
                    char pidStr[32];
                    sprintf(pidStr, "%u", pid);
                    SetWindowText(hwndPidEntry, pidStr);
                }
            }
            break;
        case IDC_INJECT: {
            DWORD pid = atoi(GetControlText(hwnd, IDC_PID_ENTRY).c_str());
            char dllBuf[MAX_PATH] = {};
            GetWindowText(hwndDllPath, dllBuf, sizeof(dllBuf));
            std::string dllPath = dllBuf;
            if (pid && !dllPath.empty()) {
                std::string errMsg;
                bool ok = InjectDLL(pid, dllPath, errMsg, currentMethod, dryRunMode);
                if (ok) {
                    std::string msg = "DLL Injected Successfully!\n\n";
                    if (dryRunMode) msg += "(Dry Run)";
                    MessageBox(hwnd, msg.c_str(), "Success", MB_OK | MB_ICONINFORMATION);
                }
                else {
                    MessageBox(hwnd, (std::string("DLL Injection Failed!\n\n") + errMsg).c_str(),
                        "Injection Error", MB_OK | MB_ICONERROR);
                }
                AddRecentDll(dllPath);
                UpdateRecentDllsCombo(hwndRecentCombo); // <-- Add this line!
                config.lastDllPath = dllPath;
                config.lastPid = pid;
                SaveConfig();
            }
            else {
                MessageBox(hwnd, "Select a process (or enter PID) and DLL path first!", "Warning", MB_OK | MB_ICONWARNING);
            }
            break;
        }
        }
        break;
    }
    case WM_CLOSE:
        if (showTrayIcon) {
            ShowWindow(hwnd, SW_HIDE);
            ShowTrayBalloon("DLL Injector", "Minimized to tray", NIIF_INFO);
            return 0;
        }
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        if (timerId) KillTimer(hwnd, TIMER_PROC_REFRESH);
        UpdateTrayIcon(false);
        PostQuitMessage(0);
        break;
    default:
        // Tray icon messages
        if (msg == WM_USER + 1) {
            if (lParam == WM_LBUTTONDBLCLK) {
                ShowWindow(hwnd, SW_RESTORE);
                SetForegroundWindow(hwnd);
            }
            if (lParam == WM_RBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenu(hMenu, MF_STRING, IDM_TRAY_RESTORE, "Restore");
                AppendMenu(hMenu, MF_STRING, IDM_TRAY_EXIT, "Exit");
                SetForegroundWindow(hwnd);
                int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
                if (cmd == IDM_TRAY_RESTORE)
                    ShowWindow(hwnd, SW_RESTORE);
                if (cmd == IDM_TRAY_EXIT)
                    PostQuitMessage(0);
                DestroyMenu(hMenu);
            }
        }
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}
// ... (continuation from previous part)

//
// --- Settings Dialog ---
//

INT_PTR CALLBACK SettingsDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hRadioRegistry, hRadioFile, hLogChk, hAutoAttachChk, hTrayChk, hDryRunChk, hIntervalEdit, hMethodCombo;
    switch (msg) {
    case WM_INITDIALOG: {
        hRadioRegistry = GetDlgItem(hwndDlg, 1001);
        hRadioFile = GetDlgItem(hwndDlg, 1002);
        hLogChk = GetDlgItem(hwndDlg, 1003);
        hAutoAttachChk = GetDlgItem(hwndDlg, 1004);
        hTrayChk = GetDlgItem(hwndDlg, 1005);
        hDryRunChk = GetDlgItem(hwndDlg, 1006);
        hIntervalEdit = GetDlgItem(hwndDlg, 1007);
        hMethodCombo = GetDlgItem(hwndDlg, 1008);

        SendMessage(hRadioRegistry, BM_SETCHECK, config.useRegistry ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessage(hRadioFile, BM_SETCHECK, !config.useRegistry ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessage(hLogChk, BM_SETCHECK, config.loggingEnabled ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessage(hAutoAttachChk, BM_SETCHECK, config.autoAttachLast ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessage(hTrayChk, BM_SETCHECK, config.showTrayIcon ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessage(hDryRunChk, BM_SETCHECK, config.dryRunMode ? BST_CHECKED : BST_UNCHECKED, 0);
        char buf[32]; sprintf(buf, "%lu", config.refreshInterval);
        SetWindowText(hIntervalEdit, buf);
        for (int i = 0; i < 3; ++i)
            SendMessage(hMethodCombo, CB_ADDSTRING, 0, (LPARAM)methodNames[i]);
        SendMessage(hMethodCombo, CB_SETCURSEL, (WPARAM)config.injectMethod, 0);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            config.useRegistry = (SendMessage(hRadioRegistry, BM_GETCHECK, 0, 0) == BST_CHECKED);
            config.loggingEnabled = (SendMessage(hLogChk, BM_GETCHECK, 0, 0) == BST_CHECKED);
            config.autoAttachLast = (SendMessage(hAutoAttachChk, BM_GETCHECK, 0, 0) == BST_CHECKED);
            config.showTrayIcon = (SendMessage(hTrayChk, BM_GETCHECK, 0, 0) == BST_CHECKED);
            config.dryRunMode = (SendMessage(hDryRunChk, BM_GETCHECK, 0, 0) == BST_CHECKED);
            char buf[32];
            GetWindowText(hIntervalEdit, buf, sizeof(buf));
            config.refreshInterval = std::max(500, atoi(buf));
            int method = (int)SendMessage(hMethodCombo, CB_GETCURSEL, 0, 0);
            config.injectMethod = (InjectMethod)method;
            SaveConfig();
            EndDialog(hwndDlg, IDOK);
            break;
        }
        case IDCANCEL:
            EndDialog(hwndDlg, IDCANCEL);
            break;
        }
        break;
    }
    return FALSE;
}

void ShowSettingsDialog(HWND hwndParent) {
    DialogBoxParam(
        hInst, MAKEINTRESOURCE(5000), hwndParent, SettingsDlgProc, 0);
}

// --- CLI Mode

// Example usage: DLLInjector.exe /pid 1234 /dll "C:\path\to\test.dll" /method 0 /dryrun
void ParseCLI(int argc, char* argv[]) {
    DWORD pid = 0;
    std::string dllPath;
    InjectMethod method = config.injectMethod;
    bool dryRun = config.dryRunMode;
    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "/pid") == 0 && i + 1 < argc) pid = atoi(argv[++i]);
        else if (_stricmp(argv[i], "/dll") == 0 && i + 1 < argc) dllPath = argv[++i];
        else if (_stricmp(argv[i], "/method") == 0 && i + 1 < argc) method = (InjectMethod)atoi(argv[++i]);
        else if (_stricmp(argv[i], "/dryrun") == 0) dryRun = true;
    }
    if (pid && !dllPath.empty()) {
        std::string errMsg;
        bool ok = InjectDLL(pid, dllPath, errMsg, method, dryRun);
        printf("%s\n", ok ? "Injection SUCCESS" : ("Injection FAILED: " + errMsg).c_str());
        exit(ok ? 0 : 1);
    }
}