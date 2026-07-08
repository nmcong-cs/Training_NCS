#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>

#pragma comment(lib, "Psapi.lib")

#define MAX_PATH_LEN 1024
#define MAX_KEYWORD_LEN 260

void ToLowerString(wchar_t* s) {
    for (int i = 0; s[i] != L'\0'; i++) {
        s[i] = (wchar_t)towlower(s[i]);
    }
}

int ContainsIgnoreCase(const wchar_t* text, const wchar_t* keyword) {
    if (keyword == NULL || keyword[0] == L'\0') {
        return 1;
    }

    wchar_t textCopy[MAX_KEYWORD_LEN];
    wchar_t keywordCopy[MAX_KEYWORD_LEN];

    wcsncpy_s(textCopy, MAX_KEYWORD_LEN, text, _TRUNCATE);
    wcsncpy_s(keywordCopy, MAX_KEYWORD_LEN, keyword, _TRUNCATE);

    ToLowerString(textCopy);
    ToLowerString(keywordCopy);

    return wcsstr(textCopy, keywordCopy) != NULL;
}

void GetProcessPathAndMemory(DWORD pid, wchar_t* path, DWORD pathSize, SIZE_T* memoryBytes) {
    wcscpy_s(path, pathSize, L"Unknown");
    *memoryBytes = 0;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (hProcess == NULL) {
        return;
    }

    DWORD size = pathSize;

    if (!QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        wcscpy_s(path, pathSize, L"Unknown");
    }

    PROCESS_MEMORY_COUNTERS pmc;

    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        *memoryBytes = pmc.WorkingSetSize;
    }

    CloseHandle(hProcess);
}

void PrintProcessInfo(PROCESSENTRY32W* pe) {
    wchar_t path[MAX_PATH_LEN];
    SIZE_T memoryBytes = 0;

    GetProcessPathAndMemory(
        pe->th32ProcessID,
        path,
        MAX_PATH_LEN,
        &memoryBytes
    );

    double memoryMB = memoryBytes / 1024.0 / 1024.0;

    wprintf(
        L"%-8lu | %-30ls | %-10.2f MB | %ls\n",
        pe->th32ProcessID,
        pe->szExeFile,
        memoryMB,
        path
    );
}

void ListProcesses(const wchar_t* filterName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0
    );

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe)) {
        wprintf(L"Process32First failed. Error: %lu\n", GetLastError());
        CloseHandle(hSnapshot);
        return;
    }

    wprintf(L"\n%-8ls | %-30ls | %-13ls | %ls\n",
        L"PID",
        L"Process Name",
        L"RAM",
        L"Path"
    );

    wprintf(L"---------------------------------------------------------------------------------------------\n");

    do {
        if (ContainsIgnoreCase(pe.szExeFile, filterName)) {
            PrintProcessInfo(&pe);
        }

    } while (Process32NextW(hSnapshot, &pe));

    CloseHandle(hSnapshot);
}

void KillProcessByPID(DWORD pid) {
    if (pid == 0 || pid == 4) {
        wprintf(L"Do not kill System Idle Process or System process.\n");
        return;
    }

    if (pid == GetCurrentProcessId()) {
        wprintf(L"Do not kill this program itself.\n");
        return;
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_TERMINATE,
        FALSE,
        pid
    );

    if (hProcess == NULL) {
        wprintf(L"Cannot open process PID %lu. Error: %lu\n", pid, GetLastError());
        return;
    }

    if (TerminateProcess(hProcess, 1)) {
        wprintf(L"Killed process PID %lu successfully.\n", pid);
    }
    else {
        wprintf(L"TerminateProcess failed. Error: %lu\n", GetLastError());
    }

    CloseHandle(hProcess);
}

void ShowMenu() {
    wprintf(L"\n========== Process Explorer Mini ==========\n");
    wprintf(L"1. List all processes\n");
    wprintf(L"2. Filter processes by name\n");
    wprintf(L"3. Kill process by PID\n");
    wprintf(L"0. Exit\n");
    wprintf(L"Choose: ");
}

int wmain() {
    int choice;

    while (1) {
        ShowMenu();

        if (wscanf_s(L"%d", &choice) != 1) {
            wprintf(L"Invalid input.\n");
            return 1;
        }

        if (choice == 1) {
            ListProcesses(L"");
        }
        else if (choice == 2) {
            wchar_t keyword[MAX_KEYWORD_LEN];

            wprintf(L"Enter process name keyword: ");
            wscanf_s(L"%259ls", keyword, (unsigned)_countof(keyword));

            ListProcesses(keyword);
        }
        else if (choice == 3) {
            DWORD pid;
            wchar_t confirm;

            wprintf(L"Enter PID to kill: ");
            wscanf_s(L"%lu", &pid);

            wprintf(L"Are you sure you want to kill PID %lu? (y/n): ", pid);
            wscanf_s(L" %lc", &confirm, 1);

            if (confirm == L'y' || confirm == L'Y') {
                KillProcessByPID(pid);
            }
            else {
                wprintf(L"Canceled.\n");
            }
        }
        else if (choice == 0) {
            wprintf(L"Exit program.\n");
            break;
        }
        else {
            wprintf(L"Invalid choice.\n");
        }
    }

    return 0;
}