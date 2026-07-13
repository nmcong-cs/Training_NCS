/*
 * regtool.c - Registry Editor CLI
 * ---------------------------------------------------------
 * Bai tap 3.1: Cong cu them / sua / xoa key (value) trong Windows Registry
 * Su dung Windows API: RegOpenKeyEx, RegSetValueEx, RegDeleteValue
 *
 * Bien dich (Windows, MinGW):
 *      gcc regtool.c -o regtool.exe -ladvapi32
 * Bien dich (Windows, MSVC - Developer Command Prompt):
 *      cl regtool.c advapi32.lib
 *
 * Cach dung:
 *   regtool.exe add    <HIVE> <SubKey> <ValueName> <Type> <Data>
 *   regtool.exe edit   <HIVE> <SubKey> <ValueName> <Type> <Data>
 *   regtool.exe delete <HIVE> <SubKey> <ValueName>
 *   regtool.exe list   <HIVE> <SubKey>
 *
 *   HIVE  : HKCU | HKLM | HKCR | HKU | HKCC
 *   Type  : REG_SZ | REG_DWORD | REG_EXPAND_SZ | REG_BINARY
 *
 * Vi du:
 *   regtool.exe add HKCU "Software\MyApp" Version REG_SZ "1.0.0"
 *   regtool.exe edit HKCU "Software\MyApp" Version REG_SZ "1.1.0"
 *   regtool.exe delete HKCU "Software\MyApp" Version
 *   regtool.exe list HKCU "Software\MyApp"
 * ---------------------------------------------------------
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

 /* ---------- Ham tien ich: chuyen chuoi HIVE -> HKEY ---------- */
static BOOL ParseHive(const char* s, HKEY* outHive)
{
    if (_stricmp(s, "HKCU") == 0 || _stricmp(s, "HKEY_CURRENT_USER") == 0) {
        *outHive = HKEY_CURRENT_USER;
    }
    else if (_stricmp(s, "HKLM") == 0 || _stricmp(s, "HKEY_LOCAL_MACHINE") == 0) {
        *outHive = HKEY_LOCAL_MACHINE;
    }
    else if (_stricmp(s, "HKCR") == 0 || _stricmp(s, "HKEY_CLASSES_ROOT") == 0) {
        *outHive = HKEY_CLASSES_ROOT;
    }
    else if (_stricmp(s, "HKU") == 0 || _stricmp(s, "HKEY_USERS") == 0) {
        *outHive = HKEY_USERS;
    }
    else if (_stricmp(s, "HKCC") == 0 || _stricmp(s, "HKEY_CURRENT_CONFIG") == 0) {
        *outHive = HKEY_CURRENT_CONFIG;
    }
    else {
        return FALSE;
    }
    return TRUE;
}

/* ---------- Ham tien ich: chuoi kieu du lieu -> REG_* ---------- */
static BOOL ParseType(const char* s, DWORD* outType)
{
    if (_stricmp(s, "REG_SZ") == 0) { *outType = REG_SZ; return TRUE; }
    if (_stricmp(s, "REG_EXPAND_SZ") == 0) { *outType = REG_EXPAND_SZ; return TRUE; }
    if (_stricmp(s, "REG_DWORD") == 0) { *outType = REG_DWORD; return TRUE; }
    if (_stricmp(s, "REG_BINARY") == 0) { *outType = REG_BINARY; return TRUE; }
    return FALSE;
}

static void PrintErr(const char* action, LONG code)
{
    char* msg = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, (DWORD)code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msg, 0, NULL);
    fprintf(stderr, "[LOI] %s that bai (ma loi %ld): %s\n",
        action, code, msg ? msg : "Khong ro nguyen nhan");
    if (msg) LocalFree(msg);
}

/* ---------- ADD / EDIT: RegOpenKeyEx (tao neu chua co) + RegSetValueEx ---------- */
static int CmdSetValue(const char* action, HKEY hive, const char* subKey,
    const char* valueName, const char* typeStr, const char* data)
{
    DWORD type;
    if (!ParseType(typeStr, &type)) {
        fprintf(stderr, "[LOI] Kieu du lieu khong hop le: %s\n", typeStr);
        fprintf(stderr, "      Ho tro: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_BINARY\n");
        return 1;
    }

    HKEY hKey;
    DWORD disposition;
    /* RegCreateKeyEx: mo key, neu chua ton tai thi tao moi (bao ham RegOpenKeyEx) */
    LONG rc = RegCreateKeyExA(
        hive, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &hKey, &disposition);

    if (rc != ERROR_SUCCESS) {
        PrintErr("Mo/tao key", rc);
        return 1;
    }

    BYTE* pData = NULL;
    DWORD cbData = 0;
    DWORD dwordVal = 0;

    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        pData = (BYTE*)data;
        cbData = (DWORD)(strlen(data) + 1); /* bao gom ky tu null */
        break;
    case REG_DWORD:
        dwordVal = (DWORD)strtoul(data, NULL, 0); /* ho tro ca so thap phan/hex (0x..) */
        pData = (BYTE*)&dwordVal;
        cbData = sizeof(DWORD);
        break;
    case REG_BINARY: {
        /* Du lieu nhap dang chuoi hex, vd: "DEADBEEF" */
        size_t len = strlen(data);
        if (len % 2 != 0) {
            fprintf(stderr, "[LOI] Chuoi hex cho REG_BINARY phai co so ky tu chan\n");
            RegCloseKey(hKey);
            return 1;
        }
        cbData = (DWORD)(len / 2);
        pData = (BYTE*)malloc(cbData);
        for (DWORD i = 0; i < cbData; i++) {
            char byteStr[3] = { data[i * 2], data[i * 2 + 1], 0 };
            pData[i] = (BYTE)strtoul(byteStr, NULL, 16);
        }
        break;
    }
    }

    rc = RegSetValueExA(hKey, valueName, 0, type, pData, cbData);

    if (type == REG_BINARY && pData) free(pData);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS) {
        PrintErr(action, rc);
        return 1;
    }

    printf("[OK] Da %s gia tri \"%s\" = %s (%s) trong key \"%s\"\n",
        (_stricmp(action, "them") == 0) ? "them" : "sua", valueName, data, typeStr, subKey);
    return 0;
}

/* ---------- DELETE: RegOpenKeyEx + RegDeleteValue ---------- */
static int CmdDeleteValue(HKEY hive, const char* subKey, const char* valueName)
{
    HKEY hKey;
    LONG rc = RegOpenKeyExA(hive, subKey, 0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        PrintErr("Mo key", rc);
        return 1;
    }

    rc = RegDeleteValueA(hKey, valueName);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS) {
        PrintErr("Xoa gia tri", rc);
        return 1;
    }

    printf("[OK] Da xoa gia tri \"%s\" trong key \"%s\"\n", valueName, subKey);
    return 0;
}

/* ---------- LIST (tien ich them): liet ke cac gia tri trong 1 key ---------- */
static int CmdListValues(HKEY hive, const char* subKey)
{
    HKEY hKey;
    LONG rc = RegOpenKeyExA(hive, subKey, 0, KEY_QUERY_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        PrintErr("Mo key", rc);
        return 1;
    }

    printf("Danh sach gia tri trong \"%s\":\n", subKey);
    char name[16384];
    BYTE data[16384];
    DWORD index = 0;

    for (;;) {
        DWORD nameLen = sizeof(name);
        DWORD dataLen = sizeof(data);
        DWORD type;
        rc = RegEnumValueA(hKey, index, name, &nameLen, NULL, &type, data, &dataLen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) { PrintErr("Doc gia tri", rc); break; }

        const char* typeName = "UNKNOWN";
        char valueBuf[512] = "";
        switch (type) {
        case REG_SZ:
        case REG_EXPAND_SZ:
            typeName = (type == REG_SZ) ? "REG_SZ" : "REG_EXPAND_SZ";
            snprintf(valueBuf, sizeof(valueBuf), "%s", (char*)data);
            break;
        case REG_DWORD:
            typeName = "REG_DWORD";
            snprintf(valueBuf, sizeof(valueBuf), "%lu", *(DWORD*)data);
            break;
        case REG_BINARY:
            typeName = "REG_BINARY";
            snprintf(valueBuf, sizeof(valueBuf), "(%lu bytes)", dataLen);
            break;
        }
        printf("  %-20s %-14s %s\n", name[0] ? name : "(Default)", typeName, valueBuf);
        index++;
    }

    RegCloseKey(hKey);
    return 0;
}

static void PrintUsage(const char* prog)
{
    printf("Registry Editor CLI - Bai tap 3.1\n\n");
    printf("Cach dung:\n");
    printf("  %s add    <HIVE> <SubKey> <ValueName> <Type> <Data>\n", prog);
    printf("  %s edit   <HIVE> <SubKey> <ValueName> <Type> <Data>\n", prog);
    printf("  %s delete <HIVE> <SubKey> <ValueName>\n", prog);
    printf("  %s list   <HIVE> <SubKey>\n\n", prog);
    printf("HIVE  : HKCU | HKLM | HKCR | HKU | HKCC\n");
    printf("Type  : REG_SZ | REG_EXPAND_SZ | REG_DWORD | REG_BINARY\n\n");
    printf("Vi du:\n");
    printf("  %s add HKCU \"Software\\MyApp\" Version REG_SZ \"1.0.0\"\n", prog);
    printf("  %s edit HKCU \"Software\\MyApp\" Version REG_SZ \"1.1.0\"\n", prog);
    printf("  %s delete HKCU \"Software\\MyApp\" Version\n", prog);
    printf("  %s list HKCU \"Software\\MyApp\"\n", prog);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    const char* cmd = argv[1];

    if (_stricmp(cmd, "add") == 0 || _stricmp(cmd, "edit") == 0) {
        if (argc != 7) {
            fprintf(stderr, "[LOI] Thieu tham so.\n");
            PrintUsage(argv[0]);
            return 1;
        }
        HKEY hive;
        if (!ParseHive(argv[2], &hive)) {
            fprintf(stderr, "[LOI] HIVE khong hop le: %s\n", argv[2]);
            return 1;
        }
        const char* action = (_stricmp(cmd, "add") == 0) ? "them" : "sua";
        return CmdSetValue(action, hive, argv[3], argv[4], argv[5], argv[6]);
    }
    else if (_stricmp(cmd, "delete") == 0) {
        if (argc != 5) {
            fprintf(stderr, "[LOI] Thieu tham so.\n");
            PrintUsage(argv[0]);
            return 1;
        }
        HKEY hive;
        if (!ParseHive(argv[2], &hive)) {
            fprintf(stderr, "[LOI] HIVE khong hop le: %s\n", argv[2]);
            return 1;
        }
        return CmdDeleteValue(hive, argv[3], argv[4]);
    }
    else if (_stricmp(cmd, "list") == 0) {
        if (argc != 4) {
            fprintf(stderr, "[LOI] Thieu tham so.\n");
            PrintUsage(argv[0]);
            return 1;
        }
        HKEY hive;
        if (!ParseHive(argv[2], &hive)) {
            fprintf(stderr, "[LOI] HIVE khong hop le: %s\n", argv[2]);
            return 1;
        }
        return CmdListValues(hive, argv[3]);
    }
    else {
        fprintf(stderr, "[LOI] Lenh khong hop le: %s\n", cmd);
        PrintUsage(argv[0]);
        return 1;
    }
}