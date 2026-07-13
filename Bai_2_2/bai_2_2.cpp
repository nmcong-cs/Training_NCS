// =====================================================================
// Bai tap 2.2 - Thread Monitor
// Windows x64, Visual Studio, khong dung thu vien ben thu ba.
//
// Chuc nang:
//   1. Liet ke toan bo process dang chay (CreateToolhelp32Snapshot +
//      Process32First/Next).
//   2. Nguoi dung nhap PID can theo doi.
//   3. Liet ke thread cua PID do bang Thread32First/Thread32Next
//      (loc theo th32OwnerProcessID).
//   4. Do CPU usage cua tung thread bang OpenThread + GetThreadTimes,
//      do 2 lan cach nhau ~1 giay.
//   5. Lay trang thai that cua thread bang
//      NtQuerySystemInformation(SystemProcessInformation).
//   6. In bang: TID | State | CPU Usage (%).
//
// Ghi chu: NtQuerySystemInformation CHI dung de lay trang thai thread,
// KHONG dung de thay the Thread32First/Thread32Next.
// =====================================================================

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <iomanip>

// ---------------------------------------------------------------------
// Dinh nghia thu cong cac cau truc/khai bao khong cong khai (undocumented)
// can cho NtQuerySystemInformation(SystemProcessInformation).
// Dat ten rieng (MY_...) de khong dung do trung ten voi winternl.h.
// ---------------------------------------------------------------------

// NTSTATUS: winternl.h thuong da co typedef nay; typedef lai voi cung
// kieu underlying (LONG) la hop le trong C++ nen khong gay loi.
typedef LONG NTSTATUS;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

// KTHREAD_STATE (undocumented) - gia tri ThreadState tra ve tu
// SYSTEM_THREAD_INFORMATION. Thu tu chuan cua Windows:
// 0 Initialized, 1 Ready, 2 Running, 3 Standby, 4 Terminated,
// 5 Waiting, 6 Transition, 7 DeferredReady, ...

typedef struct _MY_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;      // ClientId.UniqueThread = TID that su
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;   // trang thai thread (KTHREAD_STATE)
    ULONG         WaitReason;
} MY_SYSTEM_THREAD_INFORMATION;

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG          NextEntryOffset;   // offset (byte) toi entry tiep theo, 0 = het danh sach
    ULONG          NumberOfThreads;
    LARGE_INTEGER  Reserved1[3];
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         ProcessId;
    HANDLE         InheritedFromProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      PageDirectoryBase;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount;
    LARGE_INTEGER  WriteOperationCount;
    LARGE_INTEGER  OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount;
    LARGE_INTEGER  WriteTransferCount;
    LARGE_INTEGER  OtherTransferCount;
    MY_SYSTEM_THREAD_INFORMATION Threads[1]; // mang thread, so phan tu = NumberOfThreads
} MY_SYSTEM_PROCESS_INFORMATION;

static const ULONG MY_SystemProcessInformation = 5; // SYSTEM_INFORMATION_CLASS = 5

typedef NTSTATUS(WINAPI* PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// =====================================================================
// Ham phu: chuyen ma trang thai thread (ULONG) -> chuoi mo ta
// =====================================================================
static std::string ThreadStateToString(ULONG state)
{
    switch (state)
    {
    case 0: return "Initialized";
    case 1: return "Ready";
    case 2: return "Running";
    case 3: return "Standby";
    case 4: return "Terminated";
    case 5: return "Waiting";
    case 6: return "Transition";
    default: return "Unknown";
    }
}

// =====================================================================
// Buoc 1: Liet ke toan bo process dang chay
//   API: CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) + Process32FirstW/NextW
// =====================================================================
static void ListProcesses()
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"[Loi] CreateToolhelp32Snapshot(SNAPPROCESS) that bai. GetLastError="
            << GetLastError() << L"\n";
        return;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(hSnap, &pe))
    {
        std::wcerr << L"[Loi] Process32First that bai. GetLastError=" << GetLastError() << L"\n";
        CloseHandle(hSnap);
        return;
    }

    std::wcout << L"===== DANH SACH PROCESS DANG CHAY =====\n";
    std::wcout << std::left << std::setw(10) << L"PID" << L"Ten Process\n";
    std::wcout << L"----------------------------------------\n";

    do
    {
        std::wcout << std::left << std::setw(10) << pe.th32ProcessID << pe.szExeFile << L"\n";
    } while (Process32NextW(hSnap, &pe));

    CloseHandle(hSnap); // luon dong handle sau khi dung xong
    std::wcout << L"========================================\n\n";
}

// =====================================================================
// Buoc 2: Liet ke thread cua 1 PID cu the
//   API: CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) + Thread32First/Next
// =====================================================================
static std::vector<DWORD> ListProcessThreads(DWORD pid)
{
    std::vector<DWORD> tids;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"[Loi] CreateToolhelp32Snapshot(SNAPTHREAD) that bai. GetLastError="
            << GetLastError() << L"\n";
        return tids;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (!Thread32First(hSnap, &te))
    {
        std::wcerr << L"[Loi] Thread32First that bai. GetLastError=" << GetLastError() << L"\n";
        CloseHandle(hSnap);
        return tids;
    }

    do
    {
        // Snapshot chua thread cua TAT CA process -> phai loc theo owner PID
        if (te.th32OwnerProcessID == pid)
        {
            tids.push_back(te.th32ThreadID);
        }
    } while (Thread32Next(hSnap, &te));

    CloseHandle(hSnap);
    return tids;
}

// =====================================================================
// Buoc 3: Do CPU usage tung thread
// =====================================================================

// Mau thoi gian CPU (kernel+user) cua 1 thread tai 1 thoi diem
struct ThreadTimeSample
{
    bool     valid = false;
    ULONGLONG kernel100ns = 0;
    ULONGLONG user100ns = 0;
};

static ULONGLONG FileTimeToU64(const FILETIME& ft)
{
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

// Mo thread (THREAD_QUERY_INFORMATION) va lay KernelTime/UserTime hien tai.
// Neu OpenThread that bai (vi du thread da ket thuc) -> tra ve mau invalid.
static ThreadTimeSample SampleThreadTime(DWORD tid)
{
    ThreadTimeSample s;

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (hThread == NULL)
    {
        // Thread co the da ket thuc giua luc liet ke va luc do,
        // hoac khong du quyen truy cap -> bo qua, khong coi la loi fatal.
        return s;
    }

    FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
    if (GetThreadTimes(hThread, &ftCreate, &ftExit, &ftKernel, &ftUser))
    {
        s.valid = true;
        s.kernel100ns = FileTimeToU64(ftKernel);
        s.user100ns = FileTimeToU64(ftUser);
    }
    else
    {
        std::wcerr << L"[Canh bao] GetThreadTimes that bai cho TID=" << tid
            << L", GetLastError=" << GetLastError() << L"\n";
    }

    CloseHandle(hThread); // dong handle ngay sau khi dung xong
    return s;
}

// Ket qua CPU usage cua 1 thread
struct ThreadCpuResult
{
    bool   valid = false;
    double cpuPercent = 0.0;
};

// Do CPU usage cho danh sach TID:
//   - Lay mau lan 1
//   - Sleep(intervalMs) - dong thoi do thoi gian thuc te bang QueryPerformanceCounter
//   - Lay mau lan 2
//   - Tinh: CPU% = (delta_CPU_time / delta_wall_time) * 100
// Chi tinh cho thread co du lieu HOP LE o CA HAI lan do.
static std::map<DWORD, ThreadCpuResult> MeasureCpuUsage(const std::vector<DWORD>& tids, DWORD intervalMs)
{
    std::map<DWORD, ThreadCpuResult> results;
    std::map<DWORD, ThreadTimeSample> firstSamples;

    // ----- Lan do thu 1 -----
    for (DWORD tid : tids)
    {
        firstSamples[tid] = SampleThreadTime(tid);
    }

    // Do khoang thoi gian thuc te troi qua bang QueryPerformanceCounter
    // (chinh xac hon la gia dinh dung 1000ms, vi Sleep() co sai so).
    LARGE_INTEGER freq{}, t1{}, t2{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);

    Sleep(intervalMs);

    QueryPerformanceCounter(&t2);
    double elapsedSeconds = double(t2.QuadPart - t1.QuadPart) / double(freq.QuadPart);
    ULONGLONG elapsed100ns = (ULONGLONG)(elapsedSeconds * 10000000.0); // giay -> don vi 100ns

    // ----- Lan do thu 2 -----
    for (DWORD tid : tids)
    {
        ThreadTimeSample s1 = firstSamples[tid];
        ThreadTimeSample s2 = SampleThreadTime(tid); // neu thread da ket thuc, s2.valid = false

        ThreadCpuResult r;
        if (s1.valid && s2.valid && elapsed100ns > 0)
        {
            ULONGLONG total1 = s1.kernel100ns + s1.user100ns;
            ULONGLONG total2 = s2.kernel100ns + s2.user100ns;

            if (total2 >= total1) // de phong truong hop bat thuong
            {
                ULONGLONG deltaCpu = total2 - total1;
                // CPU% tinh theo 1 loi (giong cach Task Manager/Process Explorer
                // hien thi %CPU cua tung thread) -> khong chia cho so loi CPU.
                r.cpuPercent = (double(deltaCpu) / double(elapsed100ns)) * 100.0;
                r.valid = true;
            }
        }
        results[tid] = r; // neu khong valid -> se hien thi N/A o buoc in ket qua
    }

    return results;
}

// =====================================================================
// Buoc 4: Lay trang thai that cua tung thread bang
//   NtQuerySystemInformation(SystemProcessInformation)
// (CHI dung de lay State, khong dung de thay the Thread32First/Next)
// =====================================================================
static std::map<DWORD, std::string> GetThreadStatesForProcess(DWORD pid)
{
    std::map<DWORD, std::string> result;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL)
    {
        std::wcerr << L"[Canh bao] Khong tim thay ntdll.dll, khong the lay trang thai thread.\n";
        return result;
    }

    auto pNtQuerySystemInformation =
        (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL)
    {
        std::wcerr << L"[Canh bao] Khong tim thay NtQuerySystemInformation.\n";
        return result;
    }

    // Kich thuoc du lieu tra ve khong co dinh -> can thu voi buffer tang dan
    ULONG bufSize = 1 << 20; // bat dau voi 1MB
    std::vector<BYTE> buffer;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;

    for (int attempt = 0; attempt < 6; ++attempt)
    {
        buffer.assign(bufSize, 0);
        ULONG returnLen = 0;

        status = pNtQuerySystemInformation(MY_SystemProcessInformation, buffer.data(), bufSize, &returnLen);

        if (status == STATUS_SUCCESS)
            break;

        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            // Buffer chua du -> tang kich thuoc va thu lai
            bufSize = (returnLen > bufSize) ? (returnLen + 4096) : (bufSize * 2);
            continue;
        }

        // Loi khac -> dung lai
        std::wcerr << L"[Canh bao] NtQuerySystemInformation loi, NTSTATUS=0x"
            << std::hex << status << std::dec << L"\n";
        return result;
    }

    if (status != STATUS_SUCCESS)
    {
        std::wcerr << L"[Canh bao] NtQuerySystemInformation khong lay duoc du lieu sau nhieu lan thu.\n";
        return result;
    }

    // Duyet danh sach process (lien ket qua NextEntryOffset) de tim dung PID
    BYTE* p = buffer.data();
    for (;;)
    {
        MY_SYSTEM_PROCESS_INFORMATION* info = reinterpret_cast<MY_SYSTEM_PROCESS_INFORMATION*>(p);
        DWORD curPid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info->ProcessId));

        if (curPid == pid)
        {
            // Tim thay dung process -> lay trang thai cua tung thread ben trong
            for (ULONG i = 0; i < info->NumberOfThreads; ++i)
            {
                const MY_SYSTEM_THREAD_INFORMATION& t = info->Threads[i];
                DWORD tid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(t.ClientId.UniqueThread));
                result[tid] = ThreadStateToString(t.ThreadState);
            }
            break;
        }

        if (info->NextEntryOffset == 0)
            break; // het danh sach, khong tim thay PID (co the process vua thoat)

        p += info->NextEntryOffset;
    }

    return result;
}

// =====================================================================
// MAIN
// =====================================================================
int main()
{
    // ----- Buoc 1: liet ke toan bo process -----
    ListProcesses();

    // ----- Buoc 2: nhap PID can theo doi -----
    DWORD pid = 0;
    std::wcout << L"Nhap PID can theo doi: ";
    if (!(std::wcin >> pid))
    {
        std::wcerr << L"[Loi] PID nhap vao khong hop le.\n";
        return 1;
    }

    // Kiem tra PID co ton tai khong bang cach thu mo process
    HANDLE hCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hCheck == NULL)
    {
        std::wcerr << L"[Loi] PID " << pid << L" khong ton tai hoac khong the mo (GetLastError="
            << GetLastError() << L")\n";
        return 1;
    }
    CloseHandle(hCheck);

    // ----- Buoc 3: liet ke thread cua PID -----
    std::vector<DWORD> tids = ListProcessThreads(pid);
    if (tids.empty())
    {
        std::wcout << L"Khong tim thay thread nao thuoc PID " << pid << L".\n";
        return 0;
    }

    std::wcout << L"\nTim thay " << tids.size() << L" thread thuoc PID " << pid
        << L". Dang do CPU usage (~1 giay)...\n";

    // ----- Buoc 4: do CPU usage -----
    std::map<DWORD, ThreadCpuResult> cpuResults = MeasureCpuUsage(tids, 1000);

    // ----- Buoc 5: lay trang thai that cua thread -----
    std::map<DWORD, std::string> stateMap = GetThreadStatesForProcess(pid);

    // ----- Buoc 6: in bang ket qua -----
    std::wcout << L"\n===== KET QUA THREAD MONITOR (PID=" << pid << L") =====\n";
    std::wcout << std::left
        << std::setw(10) << L"TID"
        << std::setw(15) << L"State"
        << L"CPU Usage (%)\n";
    std::wcout << L"----------------------------------------------\n";

    for (DWORD tid : tids)
    {
        std::wstring stateStr = L"Unknown";
        auto stateIt = stateMap.find(tid);
        if (stateIt != stateMap.end())
        {
            const std::string& s = stateIt->second; // chuoi ASCII, convert truc tiep
            stateStr.assign(s.begin(), s.end());
        }

        std::wcout << std::left << std::setw(10) << tid << std::setw(15) << stateStr;

        auto cpuIt = cpuResults.find(tid);
        if (cpuIt != cpuResults.end() && cpuIt->second.valid)
        {
            std::wcout << std::fixed << std::setprecision(2) << cpuIt->second.cpuPercent << L"\n";
        }
        else
        {
            std::wcout << L"N/A (thread da ket thuc hoac khong the do)\n";
        }
    }

    std::wcout << L"================================================\n";
    return 0;
}