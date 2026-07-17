// ============================================================================
// MonitorService.cpp
// Bai tap 3.2 (mo rong) - Windows Service tu tao (CreateService) chay nen,
// ghi log hieu nang CPU / RAM / DISK moi 1 phut, tu dong restart khi bi kill,
// xoay vong log khi vuot 1MB hoac qua 5 ngay.
// ============================================================================

#include <windows.h>
#include <pdh.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>

#pragma comment(lib, "Pdh.lib")

#define SERVICE_NAME_STR   L"SysMonService"
#define LOG_DIR            L"C:\\ProgramData\\SysMonService"
#define LOG_FILE           L"C:\\ProgramData\\SysMonService\\perf.log"
#define MAX_LOG_SIZE_BYTES (1 * 1024 * 1024)   // 1 MB
#define MAX_LOG_AGE_DAYS   5.0
#define INTERVAL_MS        60000               // 1 phut

// ---------------------------------------------------------------------------
// Bien toan cuc phuc vu SCM (Service Control Manager)
// ---------------------------------------------------------------------------
SERVICE_STATUS        g_ServiceStatus = {};
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
HANDLE                g_StopEvent = nullptr;
HANDLE                g_WorkerThread = nullptr;

// ============================================================================
// PHAN 1: GHI LOG KEM XOAY VONG (LOG ROTATION)
// ============================================================================

void EnsureLogDir() {
    CreateDirectoryW(LOG_DIR, nullptr); // bo qua loi neu thu muc da ton tai
}

// Kiem tra dieu kien xoay log: > 1MB HOAC file da ton tai qua 5 ngay.
// Neu dieu kien dung: doi ten log hien tai thanh perf.log.old (ghi de ban cu),
// lan ghi log tiep theo se tao file perf.log moi hoan toan (=> "xoa log cu").
void RotateLogIfNeeded() {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(LOG_FILE, GetFileExInfoStandard, &fad)) {
        return; // file chua ton tai, chua can xoay
    }

    ULARGE_INTEGER size;
    size.LowPart = fad.nFileSizeLow;
    size.HighPart = fad.nFileSizeHigh;

    FILETIME nowFt;
    SYSTEMTIME nowSt;
    GetSystemTime(&nowSt);
    SystemTimeToFileTime(&nowSt, &nowFt);

    ULARGE_INTEGER creation, current;
    creation.LowPart = fad.ftCreationTime.dwLowDateTime;
    creation.HighPart = fad.ftCreationTime.dwHighDateTime;
    current.LowPart = nowFt.dwLowDateTime;
    current.HighPart = nowFt.dwHighDateTime;

    // FILETIME tinh theo don vi 100-nano-giay
    double diffDays = static_cast<double>(current.QuadPart - creation.QuadPart)
        / (10000000.0 * 60 * 60 * 24);

    bool sizeExceeded = size.QuadPart > MAX_LOG_SIZE_BYTES;
    bool ageExceeded = diffDays > MAX_LOG_AGE_DAYS;

    if (sizeExceeded || ageExceeded) {
        std::wstring oldPath = std::wstring(LOG_FILE) + L".old";
        DeleteFileW(oldPath.c_str());     // xoa ban backup cu neu co
        MoveFileW(LOG_FILE, oldPath.c_str()); // "xoa" log hien tai (chuyen thanh backup)
        // Lan WriteLog tiep theo se tu tao lai perf.log rong => log moi
    }
}

void WriteLog(const std::string& line) {
    EnsureLogDir();
    RotateLogIfNeeded();

    std::ofstream ofs(LOG_FILE, std::ios::app);
    if (ofs.is_open()) {
        ofs << line << std::endl;
    }
}

std::string CurrentTimestamp() {
    time_t t = time(nullptr);
    struct tm tmBuf;
    localtime_s(&tmBuf, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmBuf);
    return std::string(buf);
}

// ============================================================================
// PHAN 2: THU THAP CHI SO HIEU NANG (CPU / RAM / DISK)
// ============================================================================

struct PerfCounters {
    PDH_HQUERY   hQuery = nullptr;
    PDH_HCOUNTER hCpu = nullptr;
    PDH_HCOUNTER hDisk = nullptr;
};

bool InitPerfCounters(PerfCounters& pc) {
    if (PdhOpenQueryW(nullptr, 0, &pc.hQuery) != ERROR_SUCCESS) return false;
    PdhAddEnglishCounterW(pc.hQuery, L"\\Processor(_Total)\\% Processor Time", 0, &pc.hCpu);
    PdhAddEnglishCounterW(pc.hQuery, L"\\PhysicalDisk(_Total)\\% Disk Time", 0, &pc.hDisk);
    // Lay mau dau tien de PDH co gia tri tham chieu cho lan tinh % tiep theo
    PdhCollectQueryData(pc.hQuery);
    return true;
}

void ClosePerfCounters(PerfCounters& pc) {
    if (pc.hQuery) PdhCloseQuery(pc.hQuery);
}

std::string CollectAndFormat(PerfCounters& pc) {
    // --- CPU & Disk I/O qua PDH ---
    PdhCollectQueryData(pc.hQuery);

    PDH_FMT_COUNTERVALUE cpuVal{}, diskVal{};
    double cpuPercent = 0.0, diskIoPercent = 0.0;

    if (PdhGetFormattedCounterValue(pc.hCpu, PDH_FMT_DOUBLE, nullptr, &cpuVal) == ERROR_SUCCESS)
        cpuPercent = cpuVal.doubleValue;
    if (PdhGetFormattedCounterValue(pc.hDisk, PDH_FMT_DOUBLE, nullptr, &diskVal) == ERROR_SUCCESS)
        diskIoPercent = diskVal.doubleValue;

    // --- RAM qua GlobalMemoryStatusEx ---
    MEMORYSTATUSEX memInfo{};
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);
    DWORDLONG totalMB = memInfo.ullTotalPhys / (1024 * 1024);
    DWORDLONG usedMB = (memInfo.ullTotalPhys - memInfo.ullAvailPhys) / (1024 * 1024);
    double ramPercent = memInfo.dwMemoryLoad;

    // --- Dung luong dia C: qua GetDiskFreeSpaceEx ---
    ULARGE_INTEGER freeBytes{}, totalBytes{};
    double diskFreePercent = 0.0;
    ULONGLONG diskTotalMB = 0, diskFreeMB = 0;
    if (GetDiskFreeSpaceExW(L"C:\\", &freeBytes, &totalBytes, nullptr) && totalBytes.QuadPart > 0) {
        diskTotalMB = totalBytes.QuadPart / (1024 * 1024);
        diskFreeMB = freeBytes.QuadPart / (1024 * 1024);
        diskFreePercent = static_cast<double>(freeBytes.QuadPart) * 100.0
            / static_cast<double>(totalBytes.QuadPart);
    }

    std::ostringstream oss;
    oss << "[" << CurrentTimestamp() << "] "
        << "CPU: " << std::fixed << std::setprecision(1) << cpuPercent << "% | "
        << "RAM: " << ramPercent << "% (" << usedMB << "MB/" << totalMB << "MB) | "
        << "Disk C: free " << std::setprecision(1) << diskFreePercent << "% ("
        << diskFreeMB << "MB/" << diskTotalMB << "MB) | "
        << "DiskIO: " << diskIoPercent << "%";

    return oss.str();
}

// ============================================================================
// PHAN 3: LUONG NEN (WORKER THREAD) - GHI LOG MOI 1 PHUT
// ============================================================================

DWORD WINAPI WorkerThread(LPVOID) {
    PerfCounters pc;
    InitPerfCounters(pc);
    Sleep(1000); // cho PDH co mau tham chieu dau tien hop le

    WriteLog("[" + CurrentTimestamp() + "] SysMonService da khoi dong, ghi log hieu nang moi "
        + std::to_string(INTERVAL_MS / 1000) + " giay.");

    while (true) {
        // Cho toi da INTERVAL_MS, thoat som neu co tin hieu dung tu SCM
        DWORD waitResult = WaitForSingleObject(g_StopEvent, INTERVAL_MS);
        if (waitResult == WAIT_OBJECT_0) {
            break; // nhan tin hieu STOP
        }
        std::string line = CollectAndFormat(pc);
        WriteLog(line);
    }

    WriteLog("[" + CurrentTimestamp() + "] SysMonService dang dung.");
    ClosePerfCounters(pc);
    return 0;
}

// ============================================================================
// PHAN 4: SCM CALLBACKS (ServiceMain + Ctrl Handler)
// ============================================================================

void UpdateServiceStatus(DWORD state, DWORD exitCode = 0, DWORD waitHint = 0) {
    g_ServiceStatus.dwCurrentState = state;
    g_ServiceStatus.dwWin32ExitCode = exitCode;
    g_ServiceStatus.dwWaitHint = waitHint;
    g_ServiceStatus.dwControlsAccepted =
        (state == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

DWORD WINAPI ServiceCtrlHandler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        UpdateServiceStatus(SERVICE_STOP_PENDING, 0, 3000);
        SetEvent(g_StopEvent);
        return NO_ERROR;
    default:
        return NO_ERROR;
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_StatusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME_STR, ServiceCtrlHandler, nullptr);
    if (!g_StatusHandle) return;

    g_ServiceStatus = {};
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    UpdateServiceStatus(SERVICE_START_PENDING, 0, 3000);

    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_StopEvent) {
        UpdateServiceStatus(SERVICE_STOPPED, GetLastError());
        return;
    }

    g_WorkerThread = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);

    UpdateServiceStatus(SERVICE_RUNNING);

    WaitForSingleObject(g_WorkerThread, INFINITE);

    CloseHandle(g_StopEvent);
    CloseHandle(g_WorkerThread);

    UpdateServiceStatus(SERVICE_STOPPED);
}

// ============================================================================
// PHAN 5: CAI DAT / GO BO SERVICE + CAU HINH AUTO-RESTART KHI BI KILL
// ============================================================================

bool InstallService() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        wprintf(L"Khong the mo SCM. Hay chay voi quyen Administrator.\n");
        return false;
    }

    SC_HANDLE hService = CreateServiceW(
        hSCM,
        SERVICE_NAME_STR,          // ten dinh danh (key) cua service
        SERVICE_NAME_STR,          // ten hien thi
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, // service chay trong tien trinh rieng
        SERVICE_AUTO_START,        // tu dong khoi dong cung Windows
        SERVICE_ERROR_NORMAL,
        path,                      // duong dan file .exe hien tai
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hService) {
        wprintf(L"CreateService that bai. Ma loi: %lu\n", GetLastError());
        CloseServiceHandle(hSCM);
        return false;
    }

    // --- Cau hinh tu dong restart khi service bi kill / crash bat thuong ---
    SERVICE_FAILURE_ACTIONS_FLAG faf = { TRUE };
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &faf);

    SC_ACTION actions[3];
    actions[0] = { SC_ACTION_RESTART, 5000 };  // loi lan 1: doi 5 giay roi restart
    actions[1] = { SC_ACTION_RESTART, 10000 };  // loi lan 2: doi 10 giay
    actions[2] = { SC_ACTION_RESTART, 30000 };  // loi tu lan 3: doi 30 giay

    SERVICE_FAILURE_ACTIONSW fa = {};
    fa.dwResetPeriod = 86400; // sau 1 ngay khong loi, reset bo dem so lan loi
    fa.lpRebootMsg = nullptr;
    fa.lpCommand = nullptr;
    fa.cActions = 3;
    fa.lpsaActions = actions;

    if (!ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &fa)) {
        wprintf(L"Canh bao: khong cau hinh duoc auto-restart. Ma loi: %lu\n", GetLastError());
    }

    wprintf(L"Da cai dat service '%s' thanh cong.\n", SERVICE_NAME_STR);
    wprintf(L"  - Tu dong khoi dong cung Windows (SERVICE_AUTO_START)\n");
    wprintf(L"  - Tu dong restart neu bi kill/crash (5s -> 10s -> 30s)\n");
    wprintf(L"Khoi dong ngay: sc start %ls\n", SERVICE_NAME_STR);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

bool UninstallService() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { wprintf(L"Khong the mo SCM.\n"); return false; }

    SC_HANDLE hService = OpenServiceW(hSCM, SERVICE_NAME_STR, SERVICE_STOP | DELETE);
    if (!hService) {
        wprintf(L"Khong tim thay service.\n");
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);
    Sleep(1000);

    if (DeleteService(hService)) {
        wprintf(L"Da go bo service '%s'.\n", SERVICE_NAME_STR);
    }
    else {
        wprintf(L"Go bo that bai. Ma loi: %lu\n", GetLastError());
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

// ============================================================================
// ENTRY POINT
// ============================================================================
int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        std::wstring arg = argv[1];
        if (arg == L"--install") { return InstallService() ? 0 : 1; }
        if (arg == L"--uninstall") { return UninstallService() ? 0 : 1; }
        wprintf(L"Tham so khong hop le. Dung: --install | --uninstall\n");
        return 1;
    }

    // Khong co tham so => chuong trinh dang duoc SCM khoi chay o che do service
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(SERVICE_NAME_STR), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        wprintf(L"Loi: chuong trinh nay phai duoc Service Control Manager khoi chay.\n");
        wprintf(L"Dung tham so --install de cai dat thanh Windows Service.\n");
        return GetLastError();
    }
    return 0;
}

// sc start SysMonService
// sc stop SysMonService
// sc query SysMonService
// powershell: Get-Content "C:\ProgramData\SysMonService\perf.log" -Wait