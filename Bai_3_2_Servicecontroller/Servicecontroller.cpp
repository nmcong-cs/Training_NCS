// ============================================================================
// ServiceController.cpp
// Bai tap 3.2 - Cong cu liet ke / start / stop Windows Services
// Su dung: OpenSCManager, EnumServicesStatusEx, OpenService, StartService,
//          ControlService, QueryServiceStatusEx
//
// Build (Visual Studio Developer Command Prompt):
//   cl /EHsc ServiceController.cpp advapi32.lib
//
// Build (MinGW-w64):
//   g++ -o ServiceController.exe ServiceController.cpp -ladvapi32
//
// Su dung:
//   ServiceController.exe list
//   ServiceController.exe status <TenService>
//   ServiceController.exe start  <TenService>
//   ServiceController.exe stop   <TenService>
//
// Luu y: can chay Command Prompt / PowerShell voi quyen Administrator
//        de start/stop service.
// ============================================================================

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// In thong bao loi kem noi dung loi cua Windows
void PrintError(const char* msg) {
    DWORD err = GetLastError();
    LPSTR buf = nullptr;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buf, 0, nullptr);
    std::cerr << "[LOI] " << msg << " (ma loi " << err << "): "
        << (buf ? buf : "khong xac dinh") << std::endl;
    if (buf) LocalFree(buf);
}

const char* StateToStr(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED:          return "STOPPED";
    case SERVICE_START_PENDING:    return "START_PENDING";
    case SERVICE_STOP_PENDING:     return "STOP_PENDING";
    case SERVICE_RUNNING:          return "RUNNING";
    case SERVICE_CONTINUE_PENDING: return "CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING:    return "PAUSE_PENDING";
    case SERVICE_PAUSED:           return "PAUSED";
    default:                       return "UNKNOWN";
    }
}

// ---------------------------------------------------------------------------
// Liet ke toan bo Windows Services (kieu SERVICE_WIN32) bang EnumServicesStatusEx
// ---------------------------------------------------------------------------
bool ListServices() {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) { PrintError("Khong the mo Service Control Manager"); return false; }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;

    // Lan goi dau: chi de lay kich thuoc buffer can thiet
    EnumServicesStatusExA(
        hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

    if (bytesNeeded == 0) {
        PrintError("EnumServicesStatusEx that bai (khong lay duoc kich thuoc buffer)");
        CloseServiceHandle(hSCM);
        return false;
    }

    std::vector<BYTE> buffer(bytesNeeded);
    if (!EnumServicesStatusExA(
        hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned,
        &resumeHandle, nullptr)) {
        PrintError("EnumServicesStatusEx that bai (lan goi thu 2)");
        CloseServiceHandle(hSCM);
        return false;
    }

    auto services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buffer.data());

    printf("%-4s %-32s %-16s %-8s %s\n", "STT", "TEN SERVICE (KEY)", "TRANG THAI", "PID", "TEN HIEN THI");
    printf("--------------------------------------------------------------------------------------------\n");
    for (DWORD i = 0; i < servicesReturned; i++) {
        printf("%-4lu %-32s %-16s %-8lu %s\n",
            i + 1,
            services[i].lpServiceName,
            StateToStr(services[i].ServiceStatusProcess.dwCurrentState),
            services[i].ServiceStatusProcess.dwProcessId,
            services[i].lpDisplayName);
    }
    printf("--------------------------------------------------------------------------------------------\n");
    printf("Tong so service: %lu\n", servicesReturned);

    CloseServiceHandle(hSCM);
    return true;
}

// ---------------------------------------------------------------------------
bool ShowStatus(const char* name) {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintError("Khong the mo SCM"); return false; }

    SC_HANDLE hService = OpenServiceA(hSCM, name, SERVICE_QUERY_STATUS);
    if (!hService) {
        PrintError("Khong tim thay service");
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
        PrintError("QueryServiceStatusEx that bai");
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }

    printf("Service    : %s\n", name);
    printf("Trang thai : %s\n", StateToStr(status.dwCurrentState));
    printf("PID        : %lu\n", status.dwProcessId);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

// ---------------------------------------------------------------------------
bool StartServiceByName(const char* name) {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintError("Khong the mo SCM"); return false; }

    SC_HANDLE hService = OpenServiceA(hSCM, name, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        PrintError("Khong tim thay service (co the can chay voi quyen Administrator)");
        CloseServiceHandle(hSCM);
        return false;
    }

    if (!StartServiceA(hService, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("Service '%s' da dang chay.\n", name);
        }
        else {
            PrintError("Khong the khoi dong service");
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
    }
    else {
        printf("Da gui yeu cau khoi dong service '%s'. Dang cho...\n", name);
        SERVICE_STATUS_PROCESS status;
        DWORD bytesNeeded;
        for (int i = 0; i < 20; i++) {
            if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) break;
            if (status.dwCurrentState == SERVICE_RUNNING) {
                printf("Service '%s' da RUNNING (PID %lu).\n", name, status.dwProcessId);
                break;
            }
            Sleep(250);
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

// ---------------------------------------------------------------------------
bool StopServiceByName(const char* name) {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintError("Khong the mo SCM"); return false; }

    SC_HANDLE hService = OpenServiceA(hSCM, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        PrintError("Khong tim thay service (co the can chay voi quyen Administrator)");
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS_PROCESS status;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, reinterpret_cast<LPSERVICE_STATUS>(&status))) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            printf("Service '%s' da dung san.\n", name);
        }
        else {
            PrintError("Khong the dung service");
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
    }
    else {
        printf("Da gui yeu cau dung service '%s'. Dang cho...\n", name);
        DWORD bytesNeeded;
        for (int i = 0; i < 20; i++) {
            if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) break;
            if (status.dwCurrentState == SERVICE_STOPPED) {
                printf("Service '%s' da STOPPED.\n", name);
                break;
            }
            Sleep(250);
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

// ---------------------------------------------------------------------------
void PrintUsage() {
    printf("Su dung:\n");
    printf("  ServiceController.exe list\n");
    printf("  ServiceController.exe status <TenService>\n");
    printf("  ServiceController.exe start  <TenService>\n");
    printf("  ServiceController.exe stop   <TenService>\n");
    printf("\nLuu y: chay Command Prompt/PowerShell voi quyen Administrator\n");
    printf("de start/stop service.\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) { PrintUsage(); return 1; }

    std::string cmd = argv[1];
    if (cmd == "list") {
        return ListServices() ? 0 : 1;
    }
    else if (cmd == "status" && argc >= 3) {
        return ShowStatus(argv[2]) ? 0 : 1;
    }
    else if (cmd == "start" && argc >= 3) {
        return StartServiceByName(argv[2]) ? 0 : 1;
    }
    else if (cmd == "stop" && argc >= 3) {
        return StopServiceByName(argv[2]) ? 0 : 1;
    }
    else {
        PrintUsage();
        return 1;
    }
}