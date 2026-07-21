// ============================================================================
// PEScanner.cpp
// Bai tap 4.2 - Duyet thu muc, tim file PE (Portable Executable)
//
// Minh hoa su dung:
//   - FindFirstFile / FindNextFile  : duyet file/thu muc
//   - CreateThread                  : quet nen, khong treo giao dien
//   - CreateEvent                   : co (flag) bao hieu STOP cho luong quet
//   - CreateMutex                   : dam bao chi 1 instance chuong trinh chay
//
// Bien dich (MinGW):
//   g++ -O2 -municode -mwindows PEScanner.cpp -o PEScanner.exe -lcomctl32 -lshell32 -lole32 -luuid
//
// Bien dich (MSVC - Developer Command Prompt):
//   cl /EHsc /D_UNICODE /DUNICODE PEScanner.cpp user32.lib gdi32.lib comctl32.lib shell32.lib ole32.lib
// ============================================================================

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <cstdio>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// ---------------------------------------------------------------------------
// Constants / IDs
// ---------------------------------------------------------------------------
#define IDC_EDIT_PATH     1001
#define IDC_BTN_BROWSE    1002
#define IDC_BTN_SCAN      1003
#define IDC_BTN_STOP      1004
#define IDC_BTN_CLEAR     1005
#define IDC_LISTVIEW      1006
#define IDC_STATIC_STATUS 1007
#define IDC_STATIC_LABEL  1008

#define WM_APP_FOUND_PE   (WM_APP + 1)   // bao co 1 file PE moi tim duoc
#define WM_APP_SCAN_DONE  (WM_APP + 2)   // bao luong quet da ket thuc
#define WM_APP_STATUS     (WM_APP + 3)   // cap nhat dong trang thai

#define MAX_DEPTH         10             // do sau toi da cua thu muc con

// Ten mutex duy nhat cho ca he thong -> dam bao chi chay 1 instance
static const wchar_t* MUTEX_NAME = L"Global\\PEScanner_SingleInstance_Mutex_9F3A21E7";

// ---------------------------------------------------------------------------
// Global handles / state
// ---------------------------------------------------------------------------
HWND      g_hMainWnd = NULL;
HWND      g_hEditPath = NULL;
HWND      g_hListView = NULL;
HWND      g_hBtnScan = NULL;
HWND      g_hBtnStop = NULL;
HWND      g_hBtnClear = NULL;
HWND      g_hBtnBrowse = NULL;
HWND      g_hStatus = NULL;

HANDLE    g_hThread = NULL;   // luong quet (CreateThread)
HANDLE    g_hStopEvent = NULL;   // co bao dung (CreateEvent, manual-reset)
HANDLE    g_hMutex = NULL;   // mutex chong chay 2 instance (CreateMutex)

volatile LONG g_bScanning = 0;   // co dang quet hay khong
volatile LONG g_lTotalFiles = 0;   // tong so file da duyet qua
volatile LONG g_lTotalPEFound = 0;   // tong so file PE tim duoc

// g_bScanning phai LUON duoc doc/ghi qua ho ham Interlocked* (khong bao gio
// doc/ghi truc tiep bang "=" hay "if (g_bScanning)") de tranh canh bao
// C28112 va tranh loi tiem an do trinh bien dich toi uu hoa truy cap bien.
inline LONG IsScanning()
{
    return InterlockedCompareExchange(&g_bScanning, 0, 0);
}
inline void SetScanningFlag(LONG value)
{
    InterlockedExchange(&g_bScanning, value);
}

// ---------------------------------------------------------------------------
// Cau truc du lieu tra ve tu luong quet cho luong giao dien
// ---------------------------------------------------------------------------
struct PEFoundInfo {
    std::wstring path;
    unsigned long long size = 0;
    std::wstring type;   // "EXE", "DLL", "SYS/DRV", "PE"
};

struct StatusMsg {
    std::wstring text;
};

// ---------------------------------------------------------------------------
// Kiem tra 1 file co phai la file PE hay khong bang cach doc header
// (khong dua vao phan mo rong cua ten file)
//   - Doc IMAGE_DOS_HEADER, kiem tra e_magic == 'MZ'
//   - Nhay den e_lfanew, doc chu ky PE\0\0 (IMAGE_NT_SIGNATURE)
//   - Doc them IMAGE_FILE_HEADER de phan loai EXE/DLL/SYS
// ---------------------------------------------------------------------------
bool IsPEFile(const std::wstring& filePath, std::wstring& outType)
{
    HANDLE hFile = CreateFileW(
        filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    bool result = false;
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead = 0;

    if (ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) &&
        bytesRead == sizeof(dosHeader) &&
        dosHeader.e_magic == IMAGE_DOS_SIGNATURE)
    {
        LARGE_INTEGER li;
        li.QuadPart = dosHeader.e_lfanew;
        if (SetFilePointerEx(hFile, li, NULL, FILE_BEGIN))
        {
            DWORD peSignature = 0;
            if (ReadFile(hFile, &peSignature, sizeof(peSignature), &bytesRead, NULL) &&
                bytesRead == sizeof(peSignature) &&
                peSignature == IMAGE_NT_SIGNATURE)
            {
                result = true;
                outType = L"PE";

                IMAGE_FILE_HEADER fh;
                if (ReadFile(hFile, &fh, sizeof(fh), &bytesRead, NULL) &&
                    bytesRead == sizeof(fh))
                {
                    if (fh.Characteristics & IMAGE_FILE_DLL)
                        outType = L"DLL";
                    else if (fh.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
                        outType = L"EXE";

                    // .sys/.drv thuong la DLL image nhung Subsystem = NATIVE
                    // (khong bat buoc, chi de minh hoa phan loai them)
                }
            }
        }
    }

    CloseHandle(hFile);
    return result;
}

// ---------------------------------------------------------------------------
// Chuyen doi kich thuoc sang chuoi de hien thi (KB/MB)
// ---------------------------------------------------------------------------
std::wstring FormatSize(unsigned long long size)
{
    wchar_t buf[64];
    if (size >= 1024ULL * 1024 * 1024)
        swprintf(buf, 64, L"%.2f GB", size / (1024.0 * 1024 * 1024));
    else if (size >= 1024ULL * 1024)
        swprintf(buf, 64, L"%.2f MB", size / (1024.0 * 1024));
    else if (size >= 1024ULL)
        swprintf(buf, 64, L"%.2f KB", size / 1024.0);
    else
        swprintf(buf, 64, L"%llu B", size);
    return buf;
}

// ---------------------------------------------------------------------------
// Duyet de quy thu muc bang FindFirstFile/FindNextFile
// depth: do sau hien tai (thu muc goc = 0), toi da MAX_DEPTH
// Kiem tra g_hStopEvent thuong xuyen de co the dung ngay lap tuc
// ---------------------------------------------------------------------------
void ScanDirectory(const std::wstring& dirPath, int depth)
{
    if (depth > MAX_DEPTH)
        return;

    if (WaitForSingleObject(g_hStopEvent, 0) == WAIT_OBJECT_0)
        return; // nguoi dung da bam Stop

    std::wstring base = dirPath;
    if (!base.empty() && base.back() != L'\\')
        base += L'\\';

    std::wstring pattern = base + L"*";

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return; // khong mo duoc thu muc (vd: khong co quyen truy cap)

    // Cap nhat trang thai dang quet thu muc nao
    {
        StatusMsg* sm = new StatusMsg();
        sm->text = L"Dang quet: " + base;
        PostMessage(g_hMainWnd, WM_APP_STATUS, 0, (LPARAM)sm);
    }

    std::vector<std::wstring> subDirs;

    do
    {
        if (WaitForSingleObject(g_hStopEvent, 0) == WAIT_OBJECT_0)
            break;

        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..")
            continue;

        std::wstring fullPath = base + name;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            // Bo qua reparse point (symbolic link / junction) de tranh vong lap vo han
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                continue;
            subDirs.push_back(fullPath);
        }
        else
        {
            InterlockedIncrement(&g_lTotalFiles);

            std::wstring type;
            if (IsPEFile(fullPath, type))
            {
                InterlockedIncrement(&g_lTotalPEFound);

                LARGE_INTEGER sz;
                sz.LowPart = fd.nFileSizeLow;
                sz.HighPart = fd.nFileSizeHigh;

                PEFoundInfo* info = new PEFoundInfo();
                info->path = fullPath;
                info->size = (unsigned long long)sz.QuadPart;
                info->type = type;

                PostMessage(g_hMainWnd, WM_APP_FOUND_PE, 0, (LPARAM)info);
            }
        }

    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);

    // De quy vao cac thu muc con (sau khi da liet ke xong file cua thu muc hien tai)
    for (size_t i = 0; i < subDirs.size(); ++i)
    {
        if (WaitForSingleObject(g_hStopEvent, 0) == WAIT_OBJECT_0)
            break;
        ScanDirectory(subDirs[i], depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Ham chay tren luong rieng (CreateThread) de khong lam treo giao dien
// ---------------------------------------------------------------------------
DWORD WINAPI ScanThreadProc(LPVOID lpParam)
{
    wchar_t* rawPath = (wchar_t*)lpParam;
    std::wstring rootPath(rawPath);
    delete[] rawPath;

    g_lTotalFiles = 0;
    g_lTotalPEFound = 0;

    ScanDirectory(rootPath, 0);

    PostMessage(g_hMainWnd, WM_APP_SCAN_DONE, 0, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Bat dau quet: tao Event de bao dung, tao Thread de chay ScanThreadProc
// ---------------------------------------------------------------------------
void StartScan(HWND hwnd)
{
    if (InterlockedCompareExchange(&g_bScanning, 1, 0) != 0)
        return; // dang quet roi thi bo qua

    wchar_t pathBuf[MAX_PATH * 4];
    GetWindowTextW(g_hEditPath, pathBuf, MAX_PATH * 4);

    if (wcslen(pathBuf) == 0)
    {
        MessageBoxW(hwnd, L"Vui long nhap hoac chon duong dan thu muc can quet.",
            L"Thieu duong dan", MB_ICONWARNING | MB_OK);
        SetScanningFlag(0);
        return;
    }

    DWORD attrs = GetFileAttributesW(pathBuf);
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY))
    {
        MessageBoxW(hwnd, L"Duong dan khong ton tai hoac khong phai la thu muc.",
            L"Duong dan khong hop le", MB_ICONERROR | MB_OK);
        SetScanningFlag(0);
        return;
    }

    // Xoa ket qua cu, reset event stop (manual reset -> ve trang thai chua bao)
    ListView_DeleteAllItems(g_hListView);
    ResetEvent(g_hStopEvent);

    EnableWindow(g_hBtnScan, FALSE);
    EnableWindow(g_hBtnBrowse, FALSE);
    EnableWindow(g_hEditPath, FALSE);
    EnableWindow(g_hBtnStop, TRUE);
    SetWindowTextW(g_hStatus, L"Bat dau quet...");

    size_t pathLen = wcslen(pathBuf) + 1;
    wchar_t* pathCopy = new wchar_t[pathLen];
    wcscpy_s(pathCopy, pathLen, pathBuf);

    g_hThread = CreateThread(NULL, 0, ScanThreadProc, pathCopy, 0, NULL);
    if (g_hThread == NULL)
    {
        MessageBoxW(hwnd, L"Khong the tao luong quet (CreateThread that bai).",
            L"Loi", MB_ICONERROR | MB_OK);
        delete[] pathCopy;
        SetScanningFlag(0);
        EnableWindow(g_hBtnScan, TRUE);
        EnableWindow(g_hBtnBrowse, TRUE);
        EnableWindow(g_hEditPath, TRUE);
        EnableWindow(g_hBtnStop, FALSE);
    }
}

// ---------------------------------------------------------------------------
// Yeu cau dung quet: chi can bao hieu Event, luong se tu ket thuc
// ---------------------------------------------------------------------------
void StopScan()
{
    if (IsScanning())
    {
        SetEvent(g_hStopEvent);         // bao cho luong quet biet phai dung
        SetWindowTextW(g_hStatus, L"Dang dung...");
        EnableWindow(g_hBtnStop, FALSE);
    }
}

// ---------------------------------------------------------------------------
// Hien hop thoai chon thu muc (Browse)
// ---------------------------------------------------------------------------
void BrowseForFolder(HWND hwnd)
{
    BROWSEINFOW bi = { 0 };
    bi.hwndOwner = hwnd;
    bi.lpszTitle = L"Chon thu muc can quet";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl != NULL)
    {
        wchar_t path[MAX_PATH];
        if (SHGetPathFromIDListW(pidl, path))
        {
            SetWindowTextW(g_hEditPath, path);
        }
        CoTaskMemFree(pidl);
    }
}

// ---------------------------------------------------------------------------
// Them 1 dong ket qua vao ListView (chi goi tren luong giao dien)
// ---------------------------------------------------------------------------
void AddResultRow(PEFoundInfo* info)
{
    LVITEMW lvi = { 0 };
    lvi.mask = LVIF_TEXT;
    lvi.iItem = ListView_GetItemCount(g_hListView);
    lvi.iSubItem = 0;
    lvi.pszText = (LPWSTR)info->path.c_str();
    int idx = (int)SendMessageW(g_hListView, LVM_INSERTITEMW, 0, (LPARAM)&lvi);

    std::wstring sizeStr = FormatSize(info->size);
    ListView_SetItemText(g_hListView, idx, 1, (LPWSTR)sizeStr.c_str());
    ListView_SetItemText(g_hListView, idx, 2, (LPWSTR)info->type.c_str());
}

// ---------------------------------------------------------------------------
// Tao cac control tren cua so chinh (khong dung .rc, tao truc tiep bang code)
// ---------------------------------------------------------------------------
void CreateControls(HWND hwnd)
{
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    g_hStatus = CreateWindowW(L"STATIC", L"Chua quet",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 400, 760, 20, hwnd, (HMENU)IDC_STATIC_STATUS, NULL, NULL);

    CreateWindowW(L"STATIC", L"Thu muc:",
        WS_CHILD | WS_VISIBLE,
        10, 15, 60, 20, hwnd, (HMENU)IDC_STATIC_LABEL, NULL, NULL);

    g_hEditPath = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"C:\\",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        75, 12, 500, 24, hwnd, (HMENU)IDC_EDIT_PATH, NULL, NULL);

    g_hBtnBrowse = CreateWindowW(L"BUTTON", L"Browse...",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        585, 11, 90, 26, hwnd, (HMENU)IDC_BTN_BROWSE, NULL, NULL);

    g_hBtnScan = CreateWindowW(L"BUTTON", L"Scan",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 50, 100, 30, hwnd, (HMENU)IDC_BTN_SCAN, NULL, NULL);

    g_hBtnStop = CreateWindowW(L"BUTTON", L"Stop",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        120, 50, 100, 30, hwnd, (HMENU)IDC_BTN_STOP, NULL, NULL);

    g_hBtnClear = CreateWindowW(L"BUTTON", L"Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        230, 50, 100, 30, hwnd, (HMENU)IDC_BTN_CLEAR, NULL, NULL);

    g_hListView = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SHOWSELALWAYS,
        10, 90, 760, 300, hwnd, (HMENU)IDC_LISTVIEW, NULL, NULL);

    ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    LVCOLUMNW col = { 0 };
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    col.pszText = (LPWSTR)L"Duong dan file PE";
    col.cx = 520; col.iSubItem = 0;
    ListView_InsertColumn(g_hListView, 0, &col);

    col.pszText = (LPWSTR)L"Kich thuoc";
    col.cx = 100; col.iSubItem = 1;
    ListView_InsertColumn(g_hListView, 1, &col);

    col.pszText = (LPWSTR)L"Loai";
    col.cx = 100; col.iSubItem = 2;
    ListView_InsertColumn(g_hListView, 2, &col);

    // Ap font cho tat ca control cho dep
    HWND ctrls[] = { g_hEditPath, g_hBtnBrowse, g_hBtnScan, g_hBtnStop, g_hBtnClear, g_hListView, g_hStatus };
    for (HWND h : ctrls)
        SendMessageW(h, WM_SETFONT, (WPARAM)hFont, TRUE);
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
        g_hMainWnd = hwnd;
        CreateControls(hwnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BTN_BROWSE:
            BrowseForFolder(hwnd);
            return 0;

        case IDC_BTN_SCAN:
            StartScan(hwnd);
            return 0;

        case IDC_BTN_STOP:
            StopScan();
            return 0;

        case IDC_BTN_CLEAR:
            ListView_DeleteAllItems(g_hListView);
            SetWindowTextW(g_hStatus, L"Da xoa ket qua.");
            return 0;
        }
        return 0;

        // Luong quet gui ve 1 file PE moi tim duoc -> them vao ListView
    case WM_APP_FOUND_PE:
    {
        PEFoundInfo* info = (PEFoundInfo*)lParam;
        AddResultRow(info);
        delete info;
        return 0;
    }

    // Cap nhat dong trang thai (thu muc dang quet)
    case WM_APP_STATUS:
    {
        StatusMsg* sm = (StatusMsg*)lParam;
        SetWindowTextW(g_hStatus, sm->text.c_str());
        delete sm;
        return 0;
    }

    // Luong quet da ket thuc (xong het hoac bi Stop)
    case WM_APP_SCAN_DONE:
    {
        if (g_hThread) { CloseHandle(g_hThread); g_hThread = NULL; }
        SetScanningFlag(0);

        EnableWindow(g_hBtnScan, TRUE);
        EnableWindow(g_hBtnBrowse, TRUE);
        EnableWindow(g_hEditPath, TRUE);
        EnableWindow(g_hBtnStop, FALSE);

        wchar_t buf[256];
        swprintf(buf, 256, L"Hoan tat. Da duyet %ld file, tim thay %ld file PE.",
            g_lTotalFiles, g_lTotalPEFound);
        SetWindowTextW(g_hStatus, buf);
        return 0;
    }

    case WM_SIZE:
    {
        // Co ban khong bat buoc resize dong, giu layout co dinh cho don gian
        return 0;
    }

    case WM_CLOSE:
        if (IsScanning())
        {
            if (MessageBoxW(hwnd, L"Dang quet, ban co muon dung va thoat khong?",
                L"Xac nhan", MB_ICONQUESTION | MB_YESNO) != IDYES)
                return 0;

            SetEvent(g_hStopEvent);
            if (g_hThread)
                WaitForSingleObject(g_hThread, 5000); // doi luong ket thuc gon gang
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// WinMain: kiem tra single-instance bang CreateMutex, khoi tao va chay ung dung
// ---------------------------------------------------------------------------
int WINAPI wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // ---- Chi cho phep 1 instance duy nhat cua chuong trinh chay ----
    g_hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
    if (g_hMutex == NULL)
    {
        MessageBoxW(NULL, L"Khong the khoi tao mutex.", L"Loi", MB_ICONERROR);
        return 1;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        MessageBoxW(NULL,
            L"Chuong trinh PE Scanner dang chay roi!\n"
            L"Vui long dong ban dang chay truoc khi mo lai.",
            L"Chuong trinh da chay", MB_ICONWARNING | MB_OK);
        CloseHandle(g_hMutex);
        return 0;
    }

    // ---- Tao Event dung o che do manual-reset, ban dau chua bao ----
    g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_hStopEvent == NULL)
    {
        MessageBoxW(NULL, L"Khong the tao Event.", L"Loi", MB_ICONERROR);
        ReleaseMutex(g_hMutex);
        CloseHandle(g_hMutex);
        return 1;
    }

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    const wchar_t* CLASS_NAME = L"PEScannerWindowClass";
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(
        0, CLASS_NAME, L"PE Scanner - Bai tap 4.2",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 460,
        NULL, NULL, hInstance, NULL);

    if (!hwnd)
    {
        MessageBoxW(NULL, L"Khong the tao cua so chinh.", L"Loi", MB_ICONERROR);
        CloseHandle(g_hStopEvent);
        ReleaseMutex(g_hMutex);
        CloseHandle(g_hMutex);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // ---- Don dep tai nguyen ----
    if (g_hThread)
    {
        SetEvent(g_hStopEvent);
        WaitForSingleObject(g_hThread, 5000);
        CloseHandle(g_hThread);
    }
    CloseHandle(g_hStopEvent);
    ReleaseMutex(g_hMutex);
    CloseHandle(g_hMutex);

    return (int)msg.wParam;
}