/*
* 
 * ============================================================================
 *  RegistryEditorCLI.c
 *  Bai tap 3.1 - Registry Editor CLI
 *
 *  Chuc nang:
 *      - Them (Add)   Registry Value kieu REG_SZ
 *      - Sua  (Edit)  Registry Value kieu REG_SZ
 *      - Xoa  (Delete) Registry Value
 *
 *  API su dung:
 *      RegOpenKeyExW, RegSetValueExW, RegDeleteValueW, RegCloseKey
 *
 *  Bien dich (Visual Studio x64 - Developer Command Prompt):
 *      cl /W4 /utf-8 RegistryEditorCLI.c Advapi32.lib
 * 
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <locale.h>   /* Can cho macro LC_ALL dung trong _wsetlocale */

#pragma comment(lib, "Advapi32.lib")

  /* ----------------------------------------------------------------------
   *  Ham phu tro: chuyen chuoi Hive nguoi dung nhap (vd "HKCU", "HKLM")
   *  thanh gia tri HKEY tuong ung.
   *  Tra ve TRUE neu hop le, FALSE neu khong nhan dien duoc.
   * ---------------------------------------------------------------------- */
static BOOL ResolveHive(const wchar_t* hiveText, HKEY* outHive)
{
    if (_wcsicmp(hiveText, L"HKCU") == 0 || _wcsicmp(hiveText, L"HKEY_CURRENT_USER") == 0)
    {
        *outHive = HKEY_CURRENT_USER;
        return TRUE;
    }
    if (_wcsicmp(hiveText, L"HKLM") == 0 || _wcsicmp(hiveText, L"HKEY_LOCAL_MACHINE") == 0)
    {
        *outHive = HKEY_LOCAL_MACHINE;
        return TRUE;
    }
    if (_wcsicmp(hiveText, L"HKCR") == 0 || _wcsicmp(hiveText, L"HKEY_CLASSES_ROOT") == 0)
    {
        *outHive = HKEY_CLASSES_ROOT;
        return TRUE;
    }
    if (_wcsicmp(hiveText, L"HKU") == 0 || _wcsicmp(hiveText, L"HKEY_USERS") == 0)
    {
        *outHive = HKEY_USERS;
        return TRUE;
    }
    if (_wcsicmp(hiveText, L"HKCC") == 0 || _wcsicmp(hiveText, L"HKEY_CURRENT_CONFIG") == 0)
    {
        *outHive = HKEY_CURRENT_CONFIG;
        return TRUE;
    }
    return FALSE;
}

/* ----------------------------------------------------------------------
 *  Ham phu tro: in thong bao loi kem ma loi he thong (GetLastError)
 *  duoi dang chuoi mo ta (FormatMessage) de de doc.
 * ---------------------------------------------------------------------- */
static void PrintWinError(const wchar_t* context, LONG errorCode)
{
    wchar_t* msgBuffer = NULL;
    DWORD charsWritten;

    charsWritten = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        (DWORD)errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&msgBuffer,
        0,
        NULL);

    /* Kiem tra CA gia tri tra ve (so ky tu ghi duoc) LAN con tro khac NULL.
     * FormatMessageW co the tra ve 0 (that bai) ma khong dam bao msgBuffer
     * duoc gan gia tri hop le -> phai kiem tra ca hai de tranh
     * dereference con tro khong xac dinh (canh bao /analyze C6011). */
    if (charsWritten > 0 && msgBuffer != NULL)
    {
        /* FormatMessage thuong tra ve chuoi co \r\n o cuoi, ta khong can xu ly them */
        wprintf(L"[LOI] %ls -> Ma loi: %ld - %ls", context, errorCode, msgBuffer);
        LocalFree(msgBuffer);
    }
    else
    {
        if (msgBuffer != NULL)
        {
            LocalFree(msgBuffer);
        }
        wprintf(L"[LOI] %ls -> Ma loi: %ld (khong lay duoc mo ta chi tiet)\n", context, errorCode);
    }
}

/* ----------------------------------------------------------------------
 *  AddRegistryValue
 *  Luong:
 *      1. RegOpenKeyExW mo subkey voi quyen KEY_SET_VALUE.
 *      2. Neu mo thanh cong -> RegSetValueExW de tao/ghi value moi (REG_SZ).
 *      3. In ket qua thanh cong hoac loi.
 *      4. RegCloseKey de dong handle.
 *
 *  Luu y: RegSetValueEx tren mot key da mo se TU DONG TAO value neu
 *  value do chua ton tai -> khong can goi rieng ham "Create value".
 *  Chi dung RegCreateKeyEx khi can tao MOI ban than subkey (khong yeu
 *  cau trong bai nay nen khong su dung).
 * ---------------------------------------------------------------------- */
static void AddRegistryValue(HKEY hive, const wchar_t* subKey,
    const wchar_t* valueName, const wchar_t* valueData)
{
    HKEY hKey = NULL;
    LONG result;

    /* Buoc 1: Mo Registry Key voi quyen ghi gia tri (KEY_SET_VALUE) */
    result = RegOpenKeyExW(
        hive,               /* HKEY goc: HKCU, HKLM, ... */
        subKey,             /* Duong dan subkey */
        0,                  /* Tuy chon mac dinh */
        KEY_SET_VALUE,      /* Quyen truy cap: cho phep RegSetValueEx */
        &hKey);             /* Handle ket qua */

    if (result != ERROR_SUCCESS)
    {
        PrintWinError(L"Khong mo duoc Registry Key (Add)", result);
        return;
    }

    /* Buoc 2: Ghi/Tao value moi dang REG_SZ */
    /* cbData phai tinh ca ky tu NULL ket thuc chuoi, don vi la byte */
    DWORD dataSize = (DWORD)((wcslen(valueData) + 1) * sizeof(wchar_t));

    result = RegSetValueExW(
        hKey,                       /* Handle key da mo */
        valueName,                  /* Ten value */
        0,                          /* Reserved, phai la 0 */
        REG_SZ,                     /* Kieu du lieu: chuoi ket thuc bang NULL */
        (const BYTE*)valueData,     /* Du lieu (ep kieu ve BYTE*) */
        dataSize);                  /* Kich thuoc du lieu (byte) */

    /* Buoc 3: In ket qua */
    if (result == ERROR_SUCCESS)
    {
        wprintf(L"[OK] Da them Value \"%ls\" = \"%ls\" thanh cong.\n", valueName, valueData);
    }
    else
    {
        PrintWinError(L"Them Value that bai", result);
    }

    /* Buoc 4: Dong handle */
    RegCloseKey(hKey);
}

/* ----------------------------------------------------------------------
 *  EditRegistryValue
 *  Ve ban chat ky thuat, RegSetValueExW dung chung cho ca "them moi"
 *  va "cap nhat" (neu value da ton tai thi du lieu se bi ghi de).
 *  Tach thanh ham rieng theo dung yeu cau de:
 *      - Kiem tra value co ton tai truoc khi sua (RegQueryValueExW)
 *        nham tranh vo tinh tao moi khi nguoi dung chon "Edit"
 *        nham voi mot value chua ton tai.
 *      - Lam ro y nghia nghiep vu (Add vs Edit) trong menu.
 * ---------------------------------------------------------------------- */
static void EditRegistryValue(HKEY hive, const wchar_t* subKey,
    const wchar_t* valueName, const wchar_t* newData)
{
    HKEY hKey = NULL;
    LONG result;

    /* Buoc 1: Mo key voi quyen QUERY (kiem tra ton tai) + SET_VALUE (ghi) */
    result = RegOpenKeyExW(
        hive,
        subKey,
        0,
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        &hKey);

    if (result != ERROR_SUCCESS)
    {
        PrintWinError(L"Khong mo duoc Registry Key (Edit)", result);
        return;
    }

    /* Kiem tra value da ton tai hay chua truoc khi cho phep "sua" */
    result = RegQueryValueExW(hKey, valueName, NULL, NULL, NULL, NULL);
    if (result != ERROR_SUCCESS)
    {
        wprintf(L"[LOI] Value \"%ls\" khong ton tai. Vui long dung chuc nang Add truoc.\n", valueName);
        RegCloseKey(hKey);
        return;
    }

    /* Buoc 2: Cap nhat du lieu bang RegSetValueExW */
    DWORD dataSize = (DWORD)((wcslen(newData) + 1) * sizeof(wchar_t));

    result = RegSetValueExW(
        hKey,
        valueName,
        0,
        REG_SZ,
        (const BYTE*)newData,
        dataSize);

    /* Buoc 3: In ket qua */
    if (result == ERROR_SUCCESS)
    {
        wprintf(L"[OK] Da cap nhat Value \"%ls\" thanh \"%ls\" thanh cong.\n", valueName, newData);
    }
    else
    {
        PrintWinError(L"Cap nhat Value that bai", result);
    }

    /* Buoc 4: Dong handle */
    RegCloseKey(hKey);
}

/* ----------------------------------------------------------------------
 *  DeleteRegistryValue
 *  Luong:
 *      1. RegOpenKeyExW mo subkey voi quyen KEY_SET_VALUE (du de xoa value).
 *      2. RegDeleteValueW xoa value theo ten.
 *      3. In ket qua.
 *      4. RegCloseKey.
 * ---------------------------------------------------------------------- */
static void DeleteRegistryValue(HKEY hive, const wchar_t* subKey, const wchar_t* valueName)
{
    HKEY hKey = NULL;
    LONG result;

    /* Buoc 1: Mo Registry Key */
    result = RegOpenKeyExW(
        hive,
        subKey,
        0,
        KEY_SET_VALUE,      /* KEY_SET_VALUE bao gom quyen xoa value */
        &hKey);

    if (result != ERROR_SUCCESS)
    {
        PrintWinError(L"Khong mo duoc Registry Key (Delete)", result);
        return;
    }

    /* Buoc 2: Xoa value theo ten */
    result = RegDeleteValueW(hKey, valueName);

    /* Buoc 3: In ket qua */
    if (result == ERROR_SUCCESS)
    {
        wprintf(L"[OK] Da xoa Value \"%ls\" thanh cong.\n", valueName);
    }
    else
    {
        PrintWinError(L"Xoa Value that bai", result);
    }

    /* Buoc 4: Dong handle */
    RegCloseKey(hKey);
}

/* ----------------------------------------------------------------------
 *  Ham phu tro nhap chuoi tu ban phim an toan (gioi han buffer,
 *  loai bo ky tu newline con sot lai).
 * ---------------------------------------------------------------------- */
static void ReadLineW(const wchar_t* prompt, wchar_t* buffer, size_t bufferCount)
{
    wprintf(L"%ls", prompt);
    if (fgetws(buffer, (int)bufferCount, stdin) != NULL)
    {
        size_t len = wcslen(buffer);
        /* Xoa ky tu xuong dong (\n) neu co */
        if (len > 0 && buffer[len - 1] == L'\n')
        {
            buffer[len - 1] = L'\0';
        }
    }
    else
    {
        buffer[0] = L'\0';
    }
}

/* ----------------------------------------------------------------------
 *  Ham thu thap thong tin chung: Hive, SubKey, Value Name
 *  (dung chung cho ca 3 chuc nang Add/Edit/Delete).
 *  Tra ve FALSE neu Hive nhap khong hop le.
 * ---------------------------------------------------------------------- */
static BOOL CollectCommonInput(HKEY* outHive, wchar_t* subKey, size_t subKeySize,
    wchar_t* valueName, size_t valueNameSize)
{
    wchar_t hiveText[64];

    ReadLineW(L"Nhap Hive (HKCU, HKLM, HKCR, HKU, HKCC): ", hiveText, ARRAYSIZE(hiveText));

    if (!ResolveHive(hiveText, outHive))
    {
        wprintf(L"[LOI] Hive khong hop le: \"%ls\"\n", hiveText);
        return FALSE;
    }

    ReadLineW(L"Nhap SubKey (vd: Software\\\\MyApp): ", subKey, subKeySize);
    ReadLineW(L"Nhap Value Name: ", valueName, valueNameSize);

    return TRUE;
}

/* ----------------------------------------------------------------------
 *  3 ham "handler" duoi day duoc tach rieng khoi wmain().
 *  Ly do: neu khai bao cac buffer subKey/valueName/valueData truc tiep
 *  trong tung nhanh "case" cua switch trong wmain, trinh bien dich co
 *  the cong don kich thuoc stack cua CA 3 nhanh vao chung 1 stack frame
 *  cua wmain (vi cung 1 ham) -> sinh canh bao C6262 (stack usage lon).
 *  Tach thanh ham rieng giup moi handler co stack frame doc lap, chi
 *  ton tai trong luc no dang chay, giam tong kich thuoc stack toi da.
 * ---------------------------------------------------------------------- */
static void HandleAddOperation(void)
{
    HKEY hive;
    wchar_t subKey[512];
    wchar_t valueName[256];
    wchar_t valueData[1024];

    if (CollectCommonInput(&hive, subKey, ARRAYSIZE(subKey), valueName, ARRAYSIZE(valueName)))
    {
        ReadLineW(L"Nhap Value Data: ", valueData, ARRAYSIZE(valueData));
        AddRegistryValue(hive, subKey, valueName, valueData);
    }
}

static void HandleEditOperation(void)
{
    HKEY hive;
    wchar_t subKey[512];
    wchar_t valueName[256];
    wchar_t valueData[1024];

    if (CollectCommonInput(&hive, subKey, ARRAYSIZE(subKey), valueName, ARRAYSIZE(valueName)))
    {
        ReadLineW(L"Nhap Value Data moi: ", valueData, ARRAYSIZE(valueData));
        EditRegistryValue(hive, subKey, valueName, valueData);
    }
}

static void HandleDeleteOperation(void)
{
    HKEY hive;
    wchar_t subKey[512];
    wchar_t valueName[256];

    if (CollectCommonInput(&hive, subKey, ARRAYSIZE(subKey), valueName, ARRAYSIZE(valueName)))
    {
        DeleteRegistryValue(hive, subKey, valueName);
    }
}

/* ----------------------------------------------------------------------
 *  ShowMenu
 *  Hien thi menu chinh va dieu huong den chuc nang tuong ung.
 * ---------------------------------------------------------------------- */
static void ShowMenu(void)
{
    wprintf(L"\n=========================\n");
    wprintf(L"   Registry Editor CLI\n");
    wprintf(L"=========================\n");
    wprintf(L"1. Add Value\n");
    wprintf(L"2. Edit Value\n");
    wprintf(L"3. Delete Value\n");
    wprintf(L"0. Exit\n");
    wprintf(L"=========================\n");
    wprintf(L"Lua chon: ");
}

/* ----------------------------------------------------------------------
 *  wmain: diem vao chuong trinh (Unicode entry point)
 * ---------------------------------------------------------------------- */
int wmain(void)
{
    wchar_t choiceLine[16];
    int choice;
    BOOL running = TRUE;

    /* Dat locale de wprintf/fgetws xu ly Unicode tot hon tren console */
    _wsetlocale(LC_ALL, L"");

    while (running)
    {
        ShowMenu();
        ReadLineW(L"", choiceLine, ARRAYSIZE(choiceLine));
        choice = _wtoi(choiceLine);

        switch (choice)
        {
        case 1: /* Add Value */
            HandleAddOperation();
            break;

        case 2: /* Edit Value */
            HandleEditOperation();
            break;

        case 3: /* Delete Value */
            HandleDeleteOperation();
            break;

        case 0: /* Exit */
            wprintf(L"Thoat chuong trinh.\n");
            running = FALSE;
            break;

        default:
            wprintf(L"[LOI] Lua chon khong hop le, vui long thu lai.\n");
            break;
        }
    }

    return 0;
}