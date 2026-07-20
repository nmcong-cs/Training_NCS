/*
    ===========================================================
    BAI TAP 4.1 - PE FILE PARSER (HARDENED VERSION)
    ===========================================================
    Phien ban da duoc sieu am (bounds-check) toan bo:
      - Kiem tra kich thuoc file truoc moi lan doc.
      - RvaToOffset() tra ve bool, khong dung 0 lam ma loi.
      - Khong ep kieu con tro khi chua kiem tra offset+size hop le.
      - Unicode hoa toan bo (wmain / CreateFileW / wstring).
      - Giai phong HANDLE / MapViewOfFile bang RAII tren moi nhanh loi.

    Bien dich (Visual Studio 2022, x64, v143):
      - Tao project Console App (C++), Character Set = Unicode.
      - cl /std:c++17 /EHsc pe_parser.cpp
      hoac dung Developer Command Prompt.

    Chay:
      pe_parser.exe "C:\Windows\System32\notepad.exe"
    ===========================================================
*/

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cstddef>

using namespace std;

// =============================================================
//  GIOI HAN AN TOAN (chong DoS tu file bi loi / co chu dich)
// =============================================================
static const int    MAX_RESOURCE_DEPTH = 8;      // resource tree that ra chi can 3 cap
static const WORD    MAX_REASONABLE_SECTIONS = 96;     // Windows loader cung gioi han tuong tu
static const uint64_t MAX_EXPORT_ENTRIES = 200000;
static const uint64_t MAX_IMPORT_DESCRIPTORS = 20000;
static const uint64_t MAX_THUNKS_PER_DLL = 200000;
static const size_t   MAX_NAME_LEN = 512;   // gioi han doc ten ham/DLL
static const size_t   MAX_RES_NAME_LEN = 260;   // gioi han doc ten resource (UTF-16)

// =============================================================
//  TRANG THAI TOAN CUC CUA FILE DA MAP (chi hop le sau khi validate)
// =============================================================
static BYTE* g_base = nullptr;
static uint64_t g_fileSize = 0;
static PIMAGE_SECTION_HEADER g_sections = nullptr;
static WORD     g_numSections = 0;
static bool     g_is64 = false;
static DWORD    g_sizeOfHeaders = 0;

// =============================================================
//  RAII: dam bao HANDLE / mapping luon duoc giai phong
// =============================================================
class FileMapping
{
public:
    ~FileMapping() { Close(); }

    bool Open(const wstring& path, wstring& outError)
    {
        m_hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (m_hFile == INVALID_HANDLE_VALUE)
        {
            outError = L"Khong mo duoc file (GetLastError=" + to_wstring(GetLastError()) + L")";
            return false;
        }

        LARGE_INTEGER li{};
        if (!GetFileSizeEx(m_hFile, &li))
        {
            outError = L"GetFileSizeEx that bai (GetLastError=" + to_wstring(GetLastError()) + L")";
            return false;
        }
        if (li.QuadPart <= 0)
        {
            outError = L"File rong hoac kich thuoc khong hop le";
            return false;
        }
        m_size = (uint64_t)li.QuadPart;

        // Khong the map file 0 byte, va cung tu choi map neu qua lon mot cach bat thuong
        // (chi la gioi han an toan, PE that hiem khi vuot vai GB).
        if (m_size > (uint64_t)8ull * 1024 * 1024 * 1024)
        {
            outError = L"File qua lon, tu choi xu ly de dam bao an toan";
            return false;
        }

        m_hMap = CreateFileMappingW(m_hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!m_hMap)
        {
            outError = L"CreateFileMapping that bai (GetLastError=" + to_wstring(GetLastError()) + L")";
            return false;
        }

        m_data = (BYTE*)MapViewOfFile(m_hMap, FILE_MAP_READ, 0, 0, 0);
        if (!m_data)
        {
            outError = L"MapViewOfFile that bai (GetLastError=" + to_wstring(GetLastError()) + L")";
            return false;
        }

        return true;
    }

    void Close()
    {
        if (m_data) { UnmapViewOfFile(m_data); m_data = nullptr; }
        if (m_hMap) { CloseHandle(m_hMap); m_hMap = nullptr; }
        if (m_hFile && m_hFile != INVALID_HANDLE_VALUE) { CloseHandle(m_hFile); m_hFile = INVALID_HANDLE_VALUE; }
    }

    BYTE* Data() const { return m_data; }
    uint64_t Size() const { return m_size; }

private:
    HANDLE   m_hFile = INVALID_HANDLE_VALUE;
    HANDLE   m_hMap = nullptr;
    BYTE* m_data = nullptr;
    uint64_t m_size = 0;
};

// =============================================================
//  HAM AN TOAN CO BAN
// =============================================================

// Kiem tra [offset, offset+size) nam hoan toan trong file, khong overflow.
bool IsRangeValid(uint64_t offset, uint64_t size)
{
    if (offset > g_fileSize) return false;
    if (size > (UINT64_MAX - offset)) return false;   // chong overflow phep cong
    return (offset + size) <= g_fileSize;
}

// Lay con tro toi struct T tai offset, chi tra ve true neu vung nho hop le.
template <typename T>
bool GetStructPtr(uint64_t offset, T*& outPtr)
{
    outPtr = nullptr;
    if (!IsRangeValid(offset, sizeof(T))) return false;
    outPtr = reinterpret_cast<T*>(g_base + offset);
    return true;
}

// Doc chuoi ANSI (khong dung strncpy / khong printf %s truc tiep tren du lieu file):
// duyet tung byte trong pham vi [offset, offset+maxLen) VA trong file, dam bao
// tim thay byte '\0' truoc khi coi chuoi la hop le.
bool ReadAnsiStringSafe(uint64_t offset, size_t maxLen, string& out)
{
    out.clear();
    if (offset >= g_fileSize) return false;

    uint64_t limit = offset + maxLen;
    if (limit > g_fileSize) limit = g_fileSize;

    for (uint64_t i = offset; i < limit; i++)
    {
        char c = (char)g_base[i];
        if (c == '\0') return true; // tim thay terminator hop le trong file
        out += c;
    }
    return false; // khong tim thay '\0' trong pham vi cho phep -> khong an toan de in
}

// Doc chuoi UTF-16 co do dai tuong minh (dung cho ten resource): tra ve so ky tu
// da doc duoc, dam bao khong doc vuot file.
bool ReadUnicodeStringSafe(uint64_t offset, WORD lengthInChars, wstring& out)
{
    out.clear();
    size_t clampedLen = min<size_t>(lengthInChars, MAX_RES_NAME_LEN);
    uint64_t byteSize = (uint64_t)clampedLen * sizeof(wchar_t);
    if (!IsRangeValid(offset, byteSize)) return false;

    const wchar_t* p = reinterpret_cast<const wchar_t*>(g_base + offset);
    out.assign(p, clampedLen);
    return true;
}

wstring Widen(const string& s)
{
    // Ten trong Export/Import table luon la ASCII theo dac ta PE -> widen truc tiep an toan.
    return wstring(s.begin(), s.end());
}

// RVA -> file offset. Tra ve bool thay vi dung 0 de bao loi.
// - Ho tro RVA nam trong SizeOfHeaders (vung header duoc anh xa 1:1 vao file).
// - Tranh overflow bang so hoc uint64_t.
// - Khong tra offset nam ngoai file.
// - Chi chap nhan phan du lieu thuc su ton tai trong raw data cua section.
bool RvaToOffset(DWORD rva, DWORD size, DWORD& outOffset)
{
    outOffset = 0;

    // Vung header (truoc section dau tien) duoc anh xa 1:1 giua RVA va file offset.
    if (rva < g_sizeOfHeaders)
    {
        uint64_t end = (uint64_t)rva + size;
        if (end > g_sizeOfHeaders) return false; // vuot khoi vung header hop le
        if (!IsRangeValid(rva, size)) return false;
        outOffset = rva;
        return true;
    }

    for (WORD i = 0; i < g_numSections; i++)
    {
        DWORD va = g_sections[i].VirtualAddress;
        DWORD virtualSize = g_sections[i].Misc.VirtualSize
            ? g_sections[i].Misc.VirtualSize
            : g_sections[i].SizeOfRawData;

        uint64_t sectionEnd = (uint64_t)va + virtualSize;
        if (rva < va || (uint64_t)rva >= sectionEnd) continue;

        uint64_t deltaInSection = (uint64_t)rva - va;
        uint64_t reqEnd = deltaInSection + (uint64_t)size;

        // Chi anh xa phan thuc su ton tai trong raw data tren dia; phan con lai
        // (vung duoc zero-fill luc load, vd .bss) khong co byte thuc trong file.
        if (reqEnd > g_sections[i].SizeOfRawData) return false;

        uint64_t fileOffset = (uint64_t)g_sections[i].PointerToRawData + deltaInSection;
        if (!IsRangeValid(fileOffset, size)) return false;

        outOffset = (DWORD)fileOffset;
        return true;
    }

    return false; // RVA khong thuoc header va khong thuoc section nao
}

// =============================================================
//  TIEN ICH HIEN THI
// =============================================================
void PrintTitle(const wstring& title)
{
    wcout << L"\n==================================================\n";
    wcout << L"   " << title << L"\n";
    wcout << L"==================================================\n";
}

void PrintSub(const wstring& title)
{
    wcout << L"\n--- " << title << L" ---\n";
}

wstring MachineToString(WORD machine)
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:  return L"IMAGE_FILE_MACHINE_I386 (x86)";
    case IMAGE_FILE_MACHINE_AMD64: return L"IMAGE_FILE_MACHINE_AMD64 (x64)";
    case IMAGE_FILE_MACHINE_ARM:   return L"IMAGE_FILE_MACHINE_ARM";
    case IMAGE_FILE_MACHINE_ARM64: return L"IMAGE_FILE_MACHINE_ARM64";
    case IMAGE_FILE_MACHINE_IA64:  return L"IMAGE_FILE_MACHINE_IA64";
    default:                       return L"Unknown (0x" + to_wstring(machine) + L")";
    }
}

wstring SubsystemToString(WORD s)
{
    switch (s)
    {
    case IMAGE_SUBSYSTEM_NATIVE:                 return L"Native";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:             return L"Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:             return L"Windows Console (CUI)";
    case IMAGE_SUBSYSTEM_OS2_CUI:                 return L"OS/2 Console";
    case IMAGE_SUBSYSTEM_POSIX_CUI:               return L"POSIX Console";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:         return L"EFI Application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return L"EFI Boot Service Driver";
    default:                                      return L"Unknown/Other";
    }
}

wstring TimeStampToString(DWORD ts)
{
    time_t t = (time_t)ts;
    wchar_t buf[64] = {};
    struct tm tmInfo {};
    if (gmtime_s(&tmInfo, &t) != 0) return L"(khong xac dinh)";
    wcsftime(buf, 64, L"%Y-%m-%d %H:%M:%S UTC", &tmInfo);
    return wstring(buf);
}

const wchar_t* g_dataDirNames[16] = {
    L"Export Table", L"Import Table", L"Resource Table", L"Exception Table",
    L"Certificate Table", L"Base Relocation Table", L"Debug", L"Architecture",
    L"Global Ptr", L"TLS Table", L"Load Config Table", L"Bound Import",
    L"Import Address Table (IAT)", L"Delay Import Descriptor",
    L"CLR Runtime Header (COM)", L"Reserved"
};

// =============================================================
//  1. DOS HEADER
// =============================================================
// Tra ve true neu doc va validate thanh cong; ghi ket qua vao outDos.
bool PrintDosHeader(PIMAGE_DOS_HEADER& outDos)
{
    PrintTitle(L"DOS HEADER");

    if (!IsRangeValid(0, sizeof(IMAGE_DOS_HEADER)))
    {
        wcout << L"!!! File qua nho, khong du chua IMAGE_DOS_HEADER.\n";
        return false;
    }
    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(g_base);

    wcout << left;
    wcout << setw(20) << L"e_magic:" << L"0x" << hex << dos->e_magic << dec
        << (dos->e_magic == IMAGE_DOS_SIGNATURE ? L"  (Hop le - 'MZ')" : L"  !!! KHONG PHAI FILE PE") << L"\n";
    wcout << setw(20) << L"e_lfanew:" << L"0x" << hex << dos->e_lfanew << dec << L"  (offset toi NT Headers)\n";

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    // e_lfanew la LONG (co dau) -> phai duong va nam trong file.
    if (dos->e_lfanew < 0)
    {
        wcout << L"!!! e_lfanew am, du lieu bi loi.\n";
        return false;
    }
    // Can it nhat 4 byte Signature + sizeof(IMAGE_FILE_HEADER) ngay sau do.
    uint64_t ntMinRequired = (uint64_t)sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!IsRangeValid((uint64_t)dos->e_lfanew, ntMinRequired))
    {
        wcout << L"!!! e_lfanew tro ra ngoai file hoac NT Header vuot qua kich thuoc file.\n";
        return false;
    }

    outDos = dos;
    return true;
}

// =============================================================
//  2/3/4. NT HEADERS / FILE HEADER / OPTIONAL HEADER
// =============================================================
void PrintFileHeader(PIMAGE_FILE_HEADER fh)
{
    PrintSub(L"FILE HEADER (IMAGE_FILE_HEADER)");
    wcout << left;
    wcout << setw(28) << L"Machine:" << MachineToString(fh->Machine) << L"\n";
    wcout << setw(28) << L"NumberOfSections:" << fh->NumberOfSections << L"\n";
    wcout << setw(28) << L"TimeDateStamp:" << fh->TimeDateStamp
        << L"  (" << TimeStampToString(fh->TimeDateStamp) << L")\n";
    wcout << setw(28) << L"PointerToSymbolTable:" << L"0x" << hex << fh->PointerToSymbolTable << dec << L"\n";
    wcout << setw(28) << L"NumberOfSymbols:" << fh->NumberOfSymbols << L"\n";
    wcout << setw(28) << L"SizeOfOptionalHeader:" << fh->SizeOfOptionalHeader << L" bytes\n";
    wcout << setw(28) << L"Characteristics:" << L"0x" << hex << fh->Characteristics << dec << L"\n";

    struct { WORD flag; const wchar_t* name; } flags[] = {
        { IMAGE_FILE_RELOCS_STRIPPED,     L"RELOCS_STRIPPED" },
        { IMAGE_FILE_EXECUTABLE_IMAGE,    L"EXECUTABLE_IMAGE" },
        { IMAGE_FILE_LINE_NUMS_STRIPPED,  L"LINE_NUMS_STRIPPED" },
        { IMAGE_FILE_LOCAL_SYMS_STRIPPED, L"LOCAL_SYMS_STRIPPED" },
        { IMAGE_FILE_LARGE_ADDRESS_AWARE, L"LARGE_ADDRESS_AWARE" },
        { IMAGE_FILE_32BIT_MACHINE,       L"32BIT_MACHINE" },
        { IMAGE_FILE_DEBUG_STRIPPED,      L"DEBUG_STRIPPED" },
        { IMAGE_FILE_DLL,                 L"DLL" },
        { IMAGE_FILE_SYSTEM,              L"SYSTEM_FILE" },
    };
    wcout << L"  -> Flags: ";
    bool any = false;
    for (auto& f : flags)
        if (fh->Characteristics & f.flag) { wcout << f.name << L" "; any = true; }
    if (!any) wcout << L"(none)";
    wcout << L"\n";
}

void PrintDataDirectories(PIMAGE_DATA_DIRECTORY dirs, DWORD count)
{
    PrintSub(L"DATA DIRECTORIES");
    wcout << left << setw(30) << L"Name" << setw(14) << L"RVA" << setw(12) << L"Size" << L"Trang thai\n";
    for (DWORD i = 0; i < count; i++)
    {
        DWORD dummyOffset;
        bool ok = (dirs[i].VirtualAddress == 0) ||
            RvaToOffset(dirs[i].VirtualAddress, dirs[i].Size, dummyOffset);

        wcout << left << setw(30) << g_dataDirNames[i]
            << L"0x" << hex << setw(12) << dirs[i].VirtualAddress
            << dec << setw(12) << dirs[i].Size
            << (dirs[i].VirtualAddress == 0 ? L"(trong)" : (ok ? L"OK" : L"!!! KHONG HOP LE"))
            << L"\n";
    }
}

// Doc va validate Optional Header (PE32 hoac PE32+), tra ve con tro 16 Data Directory
// (thuc te chi duoc dung toi dataDirCount phan tu dau). Tra ve false neu Magic khong
// thuoc {0x10B, 0x20B} hoac vung nho khong hop le.
bool PrintOptionalHeader(uint64_t optHeaderOffset, DWORD sizeOfOptionalHeader,
    PIMAGE_DATA_DIRECTORY& outDirs, DWORD& outDirCount,
    DWORD& outSizeOfHeaders)
{
    PrintSub(L"OPTIONAL HEADER (IMAGE_OPTIONAL_HEADER)");

    if (!IsRangeValid(optHeaderOffset, sizeof(WORD)))
    {
        wcout << L"!!! Khong the doc Magic cua Optional Header (vuot file).\n";
        return false;
    }
    WORD magic = *reinterpret_cast<WORD*>(g_base + optHeaderOffset);

    // Yeu cau 4: chi chap nhan 0x10B (PE32) hoac 0x20B (PE32+)
    if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        wcout << L"!!! Magic Optional Header khong hop le: 0x" << hex << magic << dec
            << L" (chi chap nhan 0x10B hoac 0x20B). Dung phan tich.\n";
        return false;
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        g_is64 = false;
        PIMAGE_OPTIONAL_HEADER32 oh;
        if (!GetStructPtr(optHeaderOffset, oh))
        {
            wcout << L"!!! Optional Header (32-bit) vuot ra ngoai file.\n";
            return false;
        }
        // SizeOfOptionalHeader do FileHeader khai bao phai du lon de chua struct nay
        if (sizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
        {
            wcout << L"!!! SizeOfOptionalHeader (" << sizeOfOptionalHeader
                << L") nho hon IMAGE_OPTIONAL_HEADER32 (" << sizeof(IMAGE_OPTIONAL_HEADER32) << L").\n";
            return false;
        }

        wcout << left;
        wcout << setw(28) << L"Magic:" << L"0x" << hex << oh->Magic << dec << L" (PE32 - 32bit)\n";
        wcout << setw(28) << L"Linker Version:" << (int)oh->MajorLinkerVersion << L"." << (int)oh->MinorLinkerVersion << L"\n";
        wcout << setw(28) << L"AddressOfEntryPoint:" << L"0x" << hex << oh->AddressOfEntryPoint << dec << L"\n";
        wcout << setw(28) << L"ImageBase:" << L"0x" << hex << oh->ImageBase << dec << L"\n";
        wcout << setw(28) << L"SectionAlignment:" << L"0x" << hex << oh->SectionAlignment << dec << L"\n";
        wcout << setw(28) << L"FileAlignment:" << L"0x" << hex << oh->FileAlignment << dec << L"\n";
        wcout << setw(28) << L"SizeOfImage:" << oh->SizeOfImage << L"\n";
        wcout << setw(28) << L"SizeOfHeaders:" << oh->SizeOfHeaders << L"\n";
        wcout << setw(28) << L"Subsystem:" << SubsystemToString(oh->Subsystem) << L"\n";
        wcout << setw(28) << L"DllCharacteristics:" << L"0x" << hex << oh->DllCharacteristics << dec << L"\n";
        wcout << setw(28) << L"NumberOfRvaAndSizes:" << oh->NumberOfRvaAndSizes << L"\n";

        // Chi duyet toi da NumberOfRvaAndSizes, khong vuot 16
        outDirCount = min<DWORD>(oh->NumberOfRvaAndSizes, 16);
        outSizeOfHeaders = oh->SizeOfHeaders;

        // Xac dinh vi tri thuc te cua mang DataDirectory bang offsetof, khong dung sizeof co dinh.
        uint64_t dataDirOffset = optHeaderOffset + offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        if (!IsRangeValid(dataDirOffset, (uint64_t)outDirCount * sizeof(IMAGE_DATA_DIRECTORY)))
        {
            wcout << L"!!! Mang Data Directory vuot ra ngoai file, cat bot so luong.\n";
            // Giam dan cho toi khi hop le hoac ve 0
            while (outDirCount > 0 &&
                !IsRangeValid(dataDirOffset, (uint64_t)outDirCount * sizeof(IMAGE_DATA_DIRECTORY)))
                outDirCount--;
        }
        outDirs = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(g_base + dataDirOffset);
        return true;
    }
    else // PE32+ (64-bit)
    {
        g_is64 = true;
        PIMAGE_OPTIONAL_HEADER64 oh;
        if (!GetStructPtr(optHeaderOffset, oh))
        {
            wcout << L"!!! Optional Header (64-bit) vuot ra ngoai file.\n";
            return false;
        }
        if (sizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
        {
            wcout << L"!!! SizeOfOptionalHeader (" << sizeOfOptionalHeader
                << L") nho hon IMAGE_OPTIONAL_HEADER64 (" << sizeof(IMAGE_OPTIONAL_HEADER64) << L").\n";
            return false;
        }

        wcout << left;
        wcout << setw(28) << L"Magic:" << L"0x" << hex << oh->Magic << dec << L" (PE32+ - 64bit)\n";
        wcout << setw(28) << L"Linker Version:" << (int)oh->MajorLinkerVersion << L"." << (int)oh->MinorLinkerVersion << L"\n";
        wcout << setw(28) << L"AddressOfEntryPoint:" << L"0x" << hex << oh->AddressOfEntryPoint << dec << L"\n";
        wcout << setw(28) << L"ImageBase:" << L"0x" << hex << oh->ImageBase << dec << L"\n";
        wcout << setw(28) << L"SectionAlignment:" << L"0x" << hex << oh->SectionAlignment << dec << L"\n";
        wcout << setw(28) << L"FileAlignment:" << L"0x" << hex << oh->FileAlignment << dec << L"\n";
        wcout << setw(28) << L"SizeOfImage:" << oh->SizeOfImage << L"\n";
        wcout << setw(28) << L"SizeOfHeaders:" << oh->SizeOfHeaders << L"\n";
        wcout << setw(28) << L"Subsystem:" << SubsystemToString(oh->Subsystem) << L"\n";
        wcout << setw(28) << L"DllCharacteristics:" << L"0x" << hex << oh->DllCharacteristics << dec << L"\n";
        wcout << setw(28) << L"NumberOfRvaAndSizes:" << oh->NumberOfRvaAndSizes << L"\n";

        outDirCount = min<DWORD>(oh->NumberOfRvaAndSizes, 16);
        outSizeOfHeaders = oh->SizeOfHeaders;

        uint64_t dataDirOffset = optHeaderOffset + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        if (!IsRangeValid(dataDirOffset, (uint64_t)outDirCount * sizeof(IMAGE_DATA_DIRECTORY)))
        {
            wcout << L"!!! Mang Data Directory vuot ra ngoai file, cat bot so luong.\n";
            while (outDirCount > 0 &&
                !IsRangeValid(dataDirOffset, (uint64_t)outDirCount * sizeof(IMAGE_DATA_DIRECTORY)))
                outDirCount--;
        }
        outDirs = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(g_base + dataDirOffset);
        return true;
    }
}

// =============================================================
//  5. SECTION HEADERS
// =============================================================
// Validate va thiet lap g_sections/g_numSections. Tra ve false neu bang section
// khong the doc an toan (khi do RvaToOffset se khong hoat dong dung).
bool SetupAndPrintSectionHeaders(uint64_t sectionTableOffset, WORD numSectionsDeclared)
{
    PrintTitle(L"SECTION HEADERS");

    WORD numSections = numSectionsDeclared;
    if (numSections == 0)
    {
        wcout << L"(File khong co section nao)\n";
        g_sections = nullptr;
        g_numSections = 0;
        return true;
    }
    if (numSections > MAX_REASONABLE_SECTIONS)
    {
        wcout << L"!!! NumberOfSections (" << numSections << L") vuot gioi han hop ly, "
            << L"chi xu ly " << MAX_REASONABLE_SECTIONS << L" section dau.\n";
        numSections = MAX_REASONABLE_SECTIONS;
    }

    uint64_t tableSize = (uint64_t)numSections * sizeof(IMAGE_SECTION_HEADER);
    if (!IsRangeValid(sectionTableOffset, tableSize))
    {
        wcout << L"!!! Bang Section Header vuot ra ngoai file. Khong the tiep tuc.\n";
        return false;
    }

    g_sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(g_base + sectionTableOffset);
    g_numSections = numSections;

    wcout << left << setw(10) << L"Name" << setw(12) << L"VirtSize" << setw(12) << L"VirtAddr"
        << setw(12) << L"RawSize" << setw(12) << L"RawPtr" << L"Characteristics\n";

    for (WORD i = 0; i < g_numSections; i++)
    {
        // Section Name khong dam bao null-terminated neu du 8 ky tu -> gioi han cung 8.
        char rawName[9] = { 0 };
        memcpy(rawName, g_sections[i].Name, 8);
        rawName[8] = '\0';
        wstring wname = Widen(string(rawName));

        wcout << left << setw(10) << wname
            << L"0x" << hex << setw(10) << g_sections[i].Misc.VirtualSize
            << L"0x" << setw(10) << g_sections[i].VirtualAddress
            << dec << setw(12) << g_sections[i].SizeOfRawData
            << L"0x" << hex << setw(10) << g_sections[i].PointerToRawData
            << dec;

        DWORD c = g_sections[i].Characteristics;
        wstring flags;
        if (c & IMAGE_SCN_MEM_READ)    flags += L"R";
        if (c & IMAGE_SCN_MEM_WRITE)   flags += L"W";
        if (c & IMAGE_SCN_MEM_EXECUTE) flags += L"X";
        if (c & IMAGE_SCN_CNT_CODE)    flags += L" CODE";

        // Canh bao neu raw data cua section vuot file (du lieu bi loi)
        if (!IsRangeValid(g_sections[i].PointerToRawData, g_sections[i].SizeOfRawData))
            flags += L" [!!! RAW DATA VUOT FILE]";

        wcout << flags << L"\n";
    }
    return true;
}

// =============================================================
//  6. EXPORT DIRECTORY (ho tro ordinal-only va forwarded export)
// =============================================================
void PrintExportDirectory(PIMAGE_DATA_DIRECTORY dirs, DWORD dirCount)
{
    PrintTitle(L"EXPORT DIRECTORY");

    if (dirCount <= IMAGE_DIRECTORY_ENTRY_EXPORT || dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        wcout << L"(File khong co Export Table)\n";
        return;
    }

    DWORD exportRva = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    DWORD offset;
    if (!RvaToOffset(exportRva, sizeof(IMAGE_EXPORT_DIRECTORY), offset))
    {
        wcout << L"!!! Export Directory khong hop le hoac vuot file.\n";
        return;
    }

    PIMAGE_EXPORT_DIRECTORY exp;
    if (!GetStructPtr(offset, exp))
    {
        wcout << L"!!! Khong the doc IMAGE_EXPORT_DIRECTORY.\n";
        return;
    }

    string moduleName;
    DWORD nameOff;
    if (RvaToOffset(exp->Name, 1, nameOff))
        ReadAnsiStringSafe(nameOff, MAX_NAME_LEN, moduleName);

    wcout << L"Name (module):        " << Widen(moduleName) << L"\n";
    wcout << L"Base:                 " << exp->Base << L"\n";
    wcout << L"NumberOfFunctions:    " << exp->NumberOfFunctions << L"\n";
    wcout << L"NumberOfNames:        " << exp->NumberOfNames << L"\n";

    if (exp->NumberOfFunctions > MAX_EXPORT_ENTRIES || exp->NumberOfNames > MAX_EXPORT_ENTRIES)
    {
        wcout << L"!!! So luong export qua lon bat thuong, dung de tranh DoS.\n";
        return;
    }

    // Validate toan bo 3 bang truoc khi doc bat ky phan tu nao.
    DWORD funcsOff, namesOff, ordOff;
    bool haveFuncs = exp->NumberOfFunctions > 0 &&
        RvaToOffset(exp->AddressOfFunctions, exp->NumberOfFunctions * (DWORD)sizeof(DWORD), funcsOff);
    bool haveNames = exp->NumberOfNames > 0 &&
        RvaToOffset(exp->AddressOfNames, exp->NumberOfNames * (DWORD)sizeof(DWORD), namesOff) &&
        RvaToOffset(exp->AddressOfNameOrdinals, exp->NumberOfNames * (DWORD)sizeof(WORD), ordOff);

    if (!haveFuncs)
    {
        wcout << L"!!! Bang AddressOfFunctions khong hop le/vuot file.\n";
        return;
    }

    DWORD* funcs = reinterpret_cast<DWORD*>(g_base + funcsOff);
    DWORD* names = haveNames ? reinterpret_cast<DWORD*>(g_base + namesOff) : nullptr;
    WORD* ords = haveNames ? reinterpret_cast<WORD*>(g_base + ordOff) : nullptr;

    vector<bool> hasName(exp->NumberOfFunctions, false);

    if (haveNames)
    {
        wcout << L"\n  Export theo TEN:\n";
        wcout << L"  # | Ordinal | RVA        | Ten ham / Forward\n";
        wcout << L"  --|---------|------------|----------------------------\n";
        for (DWORD i = 0; i < exp->NumberOfNames; i++)
        {
            DWORD fnNameOff;
            string funcName;
            if (RvaToOffset(names[i], 1, fnNameOff))
                ReadAnsiStringSafe(fnNameOff, MAX_NAME_LEN, funcName);

            WORD ordinal = ords[i];
            // Yeu cau 7: kiem tra ordinal index truoc khi truy cap mang funcs
            if (ordinal >= exp->NumberOfFunctions)
            {
                wcout << L"  " << setw(3) << left << i << L"!!! Ordinal " << ordinal
                    << L" vuot ngoai NumberOfFunctions, bo qua.\n";
                continue;
            }
            hasName[ordinal] = true;
            DWORD funcRva = funcs[ordinal];

            wcout << L"  " << setw(3) << left << i
                << setw(9) << (ordinal + exp->Base)
                << L"0x" << hex << setw(10) << funcRva << dec;

            // Forwarded export: RVA nam trong chinh Export Directory -> la chuoi "DLL.Func"
            if (funcRva >= exportRva && funcRva < exportRva + exportSize)
            {
                DWORD fwdOff;
                string fwd;
                if (RvaToOffset(funcRva, 1, fwdOff) && ReadAnsiStringSafe(fwdOff, MAX_NAME_LEN, fwd))
                    wcout << L"[FORWARD -> " << Widen(fwd) << L"]\n";
                else
                    wcout << L"[FORWARD - khong doc duoc chuoi]\n";
            }
            else
            {
                wcout << Widen(funcName) << L"\n";
            }
        }
    }

    // Yeu cau 7: hien thi ca export chi co ordinal (khong co ten)
    wcout << L"\n  Export CHI CO ORDINAL (khong co ten):\n";
    bool anyOrdinalOnly = false;
    for (DWORD i = 0; i < exp->NumberOfFunctions; i++)
    {
        if (funcs[i] == 0) continue;               // slot rong
        if (haveNames && hasName[i]) continue;      // da hien thi o tren
        anyOrdinalOnly = true;
        wcout << L"  Ordinal=" << (i + exp->Base) << L"  RVA=0x" << hex << funcs[i] << dec << L"\n";
    }
    if (!anyOrdinalOnly) wcout << L"  (khong co)\n";
}

// =============================================================
//  7. IMPORT DIRECTORY
// =============================================================
void PrintImportDirectory(PIMAGE_DATA_DIRECTORY dirs, DWORD dirCount)
{
    PrintTitle(L"IMPORT DIRECTORY");

    if (dirCount <= IMAGE_DIRECTORY_ENTRY_IMPORT || dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
    {
        wcout << L"(File khong co Import Table)\n";
        return;
    }

    DWORD startOffset;
    if (!RvaToOffset(dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR), startOffset))
    {
        wcout << L"!!! Import Directory khong hop le hoac vuot file.\n";
        return;
    }

    uint64_t descOffset = startOffset;
    uint64_t count = 0;

    while (count < MAX_IMPORT_DESCRIPTORS)
    {
        PIMAGE_IMPORT_DESCRIPTOR imp;
        if (!GetStructPtr(descOffset, imp))
        {
            wcout << L"!!! Import Descriptor vuot file truoc khi gap phan tu ket thuc (toan 0).\n";
            break;
        }

        // Dieu kien ket thuc: toan bo cac truong bang 0
        if (imp->OriginalFirstThunk == 0 && imp->TimeDateStamp == 0 &&
            imp->ForwarderChain == 0 && imp->Name == 0 && imp->FirstThunk == 0)
            break;

        wstring dllName = L"(khong doc duoc ten DLL)";
        DWORD dllNameOff;
        string dllNameA;
        if (imp->Name != 0 && RvaToOffset(imp->Name, 1, dllNameOff) &&
            ReadAnsiStringSafe(dllNameOff, MAX_NAME_LEN, dllNameA))
            dllName = Widen(dllNameA);

        wcout << L"\nDLL: " << dllName << L"\n";
        wcout << L"  OriginalFirstThunk: 0x" << hex << imp->OriginalFirstThunk << dec << L"\n";
        wcout << L"  FirstThunk:         0x" << hex << imp->FirstThunk << dec << L"\n";
        wcout << L"  Cac ham import:\n";

        DWORD thunkRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        if (thunkRva != 0)
        {
            uint64_t thunkCount = 0;
            uint64_t curRva64 = thunkRva;

            while (thunkCount < MAX_THUNKS_PER_DLL)
            {
                DWORD thunkFileOff;
                size_t entrySize = g_is64 ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);

                if (curRva64 > 0xFFFFFFFFull ||
                    !RvaToOffset((DWORD)curRva64, (DWORD)entrySize, thunkFileOff))
                {
                    wcout << L"    !!! Thunk vuot file, dung tai day.\n";
                    break;
                }

                bool isZero = false;
                bool isOrdinal = false;
                WORD ordinalVal = 0;
                uint64_t addressOfData = 0;

                if (!g_is64)
                {
                    PIMAGE_THUNK_DATA32 thunk;
                    if (!GetStructPtr(thunkFileOff, thunk)) break;
                    if (thunk->u1.AddressOfData == 0) { isZero = true; }
                    else if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                    {
                        isOrdinal = true;
                        ordinalVal = (WORD)(thunk->u1.Ordinal & 0xFFFF);
                    }
                    else addressOfData = thunk->u1.AddressOfData;
                }
                else
                {
                    PIMAGE_THUNK_DATA64 thunk;
                    if (!GetStructPtr(thunkFileOff, thunk)) break;
                    if (thunk->u1.AddressOfData == 0) { isZero = true; }
                    else if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    {
                        isOrdinal = true;
                        ordinalVal = (WORD)(thunk->u1.Ordinal & 0xFFFF);
                    }
                    else addressOfData = thunk->u1.AddressOfData;
                }

                if (isZero) break; // ket thuc mang thunk

                if (isOrdinal)
                {
                    wcout << L"    - Ordinal: " << ordinalVal << L"\n";
                }
                else if (addressOfData <= 0xFFFFFFFFull)
                {
                    DWORD ibnOff;
                    if (RvaToOffset((DWORD)addressOfData, sizeof(WORD), ibnOff))
                    {
                        // Hint (WORD) + Name (chuoi ANSI ngay sau)
                        string funcName;
                        WORD hint = 0;
                        if (IsRangeValid(ibnOff, sizeof(WORD)))
                            hint = *reinterpret_cast<WORD*>(g_base + ibnOff);

                        if (ReadAnsiStringSafe(ibnOff + sizeof(WORD), MAX_NAME_LEN, funcName))
                            wcout << L"    - " << Widen(funcName) << L"  (Hint " << hint << L")\n";
                        else
                            wcout << L"    - (ten ham khong doc duoc an toan)\n";
                    }
                    else
                    {
                        wcout << L"    - !!! IMAGE_IMPORT_BY_NAME vuot file.\n";
                    }
                }

                curRva64 += entrySize;
                thunkCount++;
            }
        }

        descOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        count++;
    }
}

// =============================================================
//  8. RESOURCE DIRECTORY
// =============================================================
void WalkResourceDir(uint64_t dirOffset, uint64_t resBaseOffset, int level, int depth)
{
    if (depth > MAX_RESOURCE_DEPTH)
    {
        wcout << wstring(level * 4, L' ') << L"!!! Vuot gioi han do sau, dung de tranh vong lap.\n";
        return;
    }

    PIMAGE_RESOURCE_DIRECTORY dir;
    if (!GetStructPtr(dirOffset, dir))
    {
        wcout << L"!!! IMAGE_RESOURCE_DIRECTORY vuot file.\n";
        return;
    }

    WORD total = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    uint64_t entriesOffset = dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);

    if (!IsRangeValid(entriesOffset, (uint64_t)total * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)))
    {
        wcout << L"!!! Mang Resource Directory Entry vuot file.\n";
        return;
    }
    PIMAGE_RESOURCE_DIRECTORY_ENTRY entries =
        reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(g_base + entriesOffset);

    for (WORD i = 0; i < total; i++)
    {
        PIMAGE_RESOURCE_DIRECTORY_ENTRY e = &entries[i];
        wstring indent(level * 4, L' ');
        wstring idStr;

        if (e->NameIsString)
        {
            uint64_t strOffset = resBaseOffset + e->NameOffset;
            PIMAGE_RESOURCE_DIR_STRING_U str;
            if (GetStructPtr(strOffset, str))
            {
                wstring name;
                uint64_t charsOffset = strOffset + offsetof(IMAGE_RESOURCE_DIR_STRING_U, NameString);
                if (ReadUnicodeStringSafe(charsOffset, str->Length, name))
                    idStr = name;
                else
                    idStr = L"(ten khong doc duoc an toan)";
            }
            else
            {
                idStr = L"!!! (ten vuot file)";
            }
        }
        else
        {
            idStr = L"ID=" + to_wstring(e->Id);
            if (level == 0)
            {
                // Luu y: cac macro RT_CURSOR, RT_ICON... la MAKEINTRESOURCE (con tro),
                // KHONG the dung lam nhan case -> dung gia tri so nguyen tuong ung.
                switch (e->Id)
                {
                case 1:  idStr += L" (RT_CURSOR)";      break;
                case 2:  idStr += L" (RT_BITMAP)";      break;
                case 3:  idStr += L" (RT_ICON)";        break;
                case 4:  idStr += L" (RT_MENU)";        break;
                case 5:  idStr += L" (RT_DIALOG)";      break;
                case 6:  idStr += L" (RT_STRING)";      break;
                case 9:  idStr += L" (RT_ACCELERATOR)"; break;
                case 10: idStr += L" (RT_RCDATA)";      break;
                case 12: idStr += L" (RT_GROUP_CURSOR)"; break;
                case 14: idStr += L" (RT_GROUP_ICON)";  break;
                case 16: idStr += L" (RT_VERSION)";     break;
                case 24: idStr += L" (RT_MANIFEST)";    break;
                default: break;
                }
            }
        }

        if (e->DataIsDirectory)
        {
            wcout << indent << L"[Dir] " << idStr << L"\n";
            uint64_t subOffset = resBaseOffset + e->OffsetToDirectory;
            WalkResourceDir(subOffset, resBaseOffset, level + 1, depth + 1);
        }
        else
        {
            uint64_t dataEntryOffset = resBaseOffset + e->OffsetToData;
            PIMAGE_RESOURCE_DATA_ENTRY data;
            if (!GetStructPtr(dataEntryOffset, data))
            {
                wcout << indent << L"[Data] " << idStr << L"  !!! Data Entry vuot file.\n";
                continue;
            }
            wcout << indent << L"[Data] " << idStr
                << L"  RVA=0x" << hex << data->OffsetToData << dec
                << L"  Size=" << data->Size << L" bytes"
                << L"  CodePage=" << data->CodePage << L"\n";
        }
    }
}

void PrintResourceDirectory(PIMAGE_DATA_DIRECTORY dirs, DWORD dirCount)
{
    PrintTitle(L"RESOURCE DIRECTORY");

    if (dirCount <= IMAGE_DIRECTORY_ENTRY_RESOURCE || dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress == 0)
    {
        wcout << L"(File khong co Resource Table)\n";
        return;
    }

    DWORD resOffset;
    if (!RvaToOffset(dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, sizeof(IMAGE_RESOURCE_DIRECTORY), resOffset))
    {
        wcout << L"!!! Resource Directory khong hop le hoac vuot file.\n";
        return;
    }

    PIMAGE_RESOURCE_DIRECTORY root;
    if (!GetStructPtr(resOffset, root))
    {
        wcout << L"!!! Khong the doc IMAGE_RESOURCE_DIRECTORY goc.\n";
        return;
    }

    wcout << L"NamedEntries: " << root->NumberOfNamedEntries << L"\n";
    wcout << L"IdEntries:    " << root->NumberOfIdEntries << L"\n\n";
    wcout << L"Cay tai nguyen (Type -> Name/ID -> Language -> Data Entry):\n";

    WalkResourceDir(resOffset, resOffset, 0, 0);
}

// =============================================================
//  9. RELOCATION DIRECTORY
// =============================================================
void PrintRelocationDirectory(PIMAGE_DATA_DIRECTORY dirs, DWORD dirCount)
{
    PrintTitle(L"RELOCATION DIRECTORY (.reloc)");

    if (dirCount <= IMAGE_DIRECTORY_ENTRY_BASERELOC || dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
    {
        wcout << L"(File khong co Relocation Table)\n";
        return;
    }

    DWORD rva = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD size = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    DWORD startOffset;
    if (!RvaToOffset(rva, size, startOffset))
    {
        wcout << L"!!! Relocation Directory khong hop le hoac vuot file.\n";
        return;
    }

    uint64_t curOffset = startOffset;
    uint64_t dirEnd = (uint64_t)startOffset + size;
    int blockIdx = 0;

    while (curOffset < dirEnd)
    {
        PIMAGE_BASE_RELOCATION block;
        if (!GetStructPtr(curOffset, block))
        {
            wcout << L"!!! Block relocation vuot file.\n";
            break;
        }

        // SizeOfBlock phai >= header (8 byte) va khong duoc lam block vuot qua
        // pham vi cua ca Base Relocation Directory.
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            curOffset + block->SizeOfBlock > dirEnd)
        {
            wcout << L"!!! SizeOfBlock khong hop le (block #" << blockIdx << L"), dung.\n";
            break;
        }

        DWORD numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        uint64_t entriesOffset = curOffset + sizeof(IMAGE_BASE_RELOCATION);

        if (!IsRangeValid(entriesOffset, (uint64_t)numEntries * sizeof(WORD)))
        {
            wcout << L"!!! Mang entry cua block #" << blockIdx << L" vuot file.\n";
            break;
        }

        wcout << L"Block #" << blockIdx++ << L":  PageRVA=0x" << hex << block->VirtualAddress
            << dec << L"  SizeOfBlock=" << block->SizeOfBlock
            << L"  SoLuongEntry=" << numEntries << L"\n";

        WORD* entries = reinterpret_cast<WORD*>(g_base + entriesOffset);
        for (DWORD i = 0; i < numEntries; i++)
        {
            WORD type = entries[i] >> 12;
            WORD offsetInPage = entries[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue; // padding, bo qua

            uint64_t targetRva = (uint64_t)block->VirtualAddress + offsetInPage;
            wcout << L"    +0x" << hex << offsetInPage
                << L"  TargetRVA=0x" << targetRva << dec
                << L"  Type=" << type
                << (type == IMAGE_REL_BASED_HIGHLOW ? L" (HIGHLOW)" :
                    type == IMAGE_REL_BASED_DIR64 ? L" (DIR64)" : L"") << L"\n";
        }

        curOffset += block->SizeOfBlock;
    }
}

// =============================================================
//  MAIN
// =============================================================
int wmain(int argc, wchar_t* argv[])
{
    wstring path;
    if (argc >= 2)
        path = argv[1];
    else
    {
        wcout << L"Nhap duong dan file PE (.exe/.dll): ";
        getline(wcin, path);
    }

    FileMapping mapping;
    wstring err;
    if (!mapping.Open(path, err))
    {
        wcerr << L"Loi: " << err << L"\n";
        return 1;
    }

    g_base = mapping.Data();
    g_fileSize = mapping.Size();

    wcout << L"File: " << path << L"  (" << g_fileSize << L" bytes)\n";

    // ---- 1. DOS Header ----
    PIMAGE_DOS_HEADER dos = nullptr;
    if (!PrintDosHeader(dos))
        return 1; // FileMapping se tu dong don dep khi ra khoi scope

    // ---- 2. NT Headers: Signature ----
    uint64_t ntSigOffset = (uint64_t)dos->e_lfanew;
    PrintTitle(L"NT HEADERS");

    if (!IsRangeValid(ntSigOffset, sizeof(DWORD)))
    {
        wcerr << L"!!! Khong the doc NT Signature.\n";
        return 1;
    }
    DWORD ntSignature = *reinterpret_cast<DWORD*>(g_base + ntSigOffset);
    wcout << L"Signature: 0x" << hex << ntSignature << dec
        << (ntSignature == IMAGE_NT_SIGNATURE ? L"  (Hop le - 'PE\\0\\0')" : L"  !!! KHONG HOP LE") << L"\n";

    if (ntSignature != IMAGE_NT_SIGNATURE)
    {
        wcerr << L"NT Header khong hop le, dung chuong trinh.\n";
        return 1;
    }

    // ---- 3. File Header ----
    uint64_t fileHeaderOffset = ntSigOffset + sizeof(DWORD);
    PIMAGE_FILE_HEADER fh;
    if (!GetStructPtr(fileHeaderOffset, fh))
    {
        wcerr << L"!!! IMAGE_FILE_HEADER vuot file.\n";
        return 1;
    }
    PrintFileHeader(fh);

    // ---- 4. Optional Header (+ Data Directories) ----
    uint64_t optHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    if (!IsRangeValid(optHeaderOffset, fh->SizeOfOptionalHeader))
    {
        wcerr << L"!!! SizeOfOptionalHeader lam Optional Header vuot file.\n";
        return 1;
    }

    PIMAGE_DATA_DIRECTORY dataDirs = nullptr;
    DWORD dirCount = 0;
    DWORD sizeOfHeaders = 0;
    if (!PrintOptionalHeader(optHeaderOffset, fh->SizeOfOptionalHeader, dataDirs, dirCount, sizeOfHeaders))
    {
        wcerr << L"Dung phan tich do Optional Header khong hop le.\n";
        return 1;
    }
    g_sizeOfHeaders = sizeOfHeaders;

    PrintDataDirectories(dataDirs, dirCount);

    // ---- 5. Section Headers (bat buoc truoc khi dung RvaToOffset) ----
    uint64_t sectionTableOffset = optHeaderOffset + fh->SizeOfOptionalHeader;
    if (!SetupAndPrintSectionHeaders(sectionTableOffset, fh->NumberOfSections))
    {
        wcerr << L"Dung phan tich do Section Table khong hop le.\n";
        return 1;
    }

    // ---- 6-9. Cac directory con lai (loi o day khong lam dung toan bo chuong trinh) ----
    PrintExportDirectory(dataDirs, dirCount);
    PrintImportDirectory(dataDirs, dirCount);
    PrintResourceDirectory(dataDirs, dirCount);
    PrintRelocationDirectory(dataDirs, dirCount);

    wcout << L"\n================== KET THUC ==================\n";

    // FileMapping::~FileMapping() se tu dong UnmapViewOfFile / CloseHandle o day
    // du ham return o bat ky nhanh nao ben tren.
    return 0;
}