/*
 * parent.c
 * ------------------------------------------------------------
 * 
 * Chương trình CHA (parent process).
 * Nhiệm vụ:
 *   1. Tạo process con bằng CreateProcessW.
 *   2. Truyền tham số (command line) từ cha xuống con.
 *   3. Redirect STDOUT của con về một pipe để cha đọc lại
 *      (STDOUT redirection).
 *   4. Đo thời gian chạy của process con (bắt đầu -> kết thúc).
 *   5. Lấy exit code của con bằng GetExitCodeProcess.
 *   6. Ghi log (thời gian bắt đầu/kết thúc, thời lượng chạy,
 *      command line, exit code) ra console và ra file log.txt.
 *
 * ------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

 /* Ghi 1 dòng log ra cả console và file log.txt (append) */
static void WriteLog(const char* msg)
{
    SYSTEMTIME st;
    FILE* f = NULL;

    GetLocalTime(&st);

    printf("[%02d:%02d:%02d.%03d] %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);

    fopen_s(&f, "log.txt", "a"); //append - chua co thi tao, co roi thi ghi them

    if (f)
    {
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] %s\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);

        fclose(f);
    }
}

int wmain(int argc, wchar_t* argv[])
{
    STARTUPINFOW        si; // cau hinh cach process con khoi dong
    PROCESS_INFORMATION pi; // ghi thong tin process con
    SECURITY_ATTRIBUTES saAttr;
	HANDLE hReadPipe = NULL, hWritePipe = NULL; // process cha read, process con write
    wchar_t cmdLine[1024]; // cmd line truyen cho con
    wchar_t childExe[512] = L"Bai_2_3_Child.exe"; // ten chuong trinh con
    char logBuf[512];
    char outputBuf[4096];
    DWORD bytesRead;
    BOOL ok;

    /* --------------------------------------------------------
     * 1. Xây dựng command line truyền cho con.
     *    argv[1] (nếu có) = tên/đường dẫn file exe con
     *    argv[2..] = các tham số truyền cho con
     * -------------------------------------------------------- */
    if (argc > 1)
    {
        wcsncpy_s(
            childExe,
            _countof(childExe),
            argv[1],
            _TRUNCATE
        );
    }

    /* CreateProcessW yêu cầu command line dạng buffer có thể ghi
       (không được truyền literal string const trực tiếp) */
	// xay dung command line : "Bai_2_3_Child.exe arg[1] arg[2] ..."
    wcscpy_s(
        cmdLine,
        _countof(cmdLine),
        childExe
    );

    {
        int i;

        for (i = 2; i < argc; i++)
        {
            wcscat_s(
                cmdLine,
                _countof(cmdLine),
                L" "
            );

            wcscat_s(
                cmdLine,
                _countof(cmdLine),
                argv[i]
            );
        }
    }

    /* Nếu người dùng không truyền gì, dùng ví dụ mặc định */
    if (argc <= 1)
    {
        wcscpy_s(
            cmdLine,
            _countof(cmdLine),
            L"Bai_2_3_Child.exe 7"
        );
    }

    wprintf(L"[PARENT] Command line se truyen cho con: \"%ls\"\n", cmdLine);

    /* --------------------------------------------------------
     * 2. Tạo pipe để redirect STDOUT của con về cha.
     *    - hWritePipe: đầu ghi -> gán cho con (STDOUT của con)
     *    - hReadPipe : đầu đọc -> cha dùng để đọc dữ liệu
     * -------------------------------------------------------- */
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;   /* handle phải kế thừa được cho con */
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0))
    {
        fprintf(stderr, "CreatePipe that bai, err=%lu\n", GetLastError());
        return 1;
    }

    /* Đảm bảo đầu ĐỌC không bị con kế thừa (chỉ đầu ghi mới đưa cho con) */
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    /* --------------------------------------------------------
     * 3. Chuẩn bị STARTUPINFO: gán STDOUT (và STDERR) của con
     *    trỏ tới đầu ghi của pipe.
     * -------------------------------------------------------- */
	ZeroMemory(&si, sizeof(si)); // xoa du lieu trong struct STARTUPINFO
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    /*
	3 dong duoi day noi voi Windows rang process con phai su dung cac handle de redirect STDOUT/STDERR/STDIN
    */
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    ZeroMemory(&pi, sizeof(pi));

    /* --------------------------------------------------------
     * 4. Ghi log thời điểm bắt đầu + đo thời gian bằng
     *    QueryPerformanceCounter (độ chính xác cao).
     * -------------------------------------------------------- */
    LARGE_INTEGER freq, tStart, tEnd;
    QueryPerformanceFrequency(&freq);

    snprintf(
        logBuf,
        sizeof(logBuf),
        "Bat dau tao process con. CmdLine da chuan bi."
    );

    WriteLog(logBuf);

    QueryPerformanceCounter(&tStart);

    /* --------------------------------------------------------
     * 5. CreateProcessW - tạo process con, truyền command line
     * -------------------------------------------------------- */
    ok = CreateProcessW(
        NULL,        /* lpApplicationName: NULL -> lấy từ cmdLine */
        cmdLine,     /* lpCommandLine: buffer có thể ghi, chứa exe + tham số */
        NULL,        /* process security attributes */
        NULL,        /* thread security attributes */
        TRUE,        /* bInheritHandles: TRUE để con kế thừa pipe handle */
        0,           /* dwCreationFlags */
        NULL,        /* lpEnvironment: NULL -> kế thừa môi trường cha */
        NULL,        /* lpCurrentDirectory: NULL -> giữ nguyên thư mục hiện tại */
        &si,         /* STARTUPINFO */
        &pi          /* PROCESS_INFORMATION (output) */
    );

    /* Cha không cần đầu ghi nữa sau khi đã CreateProcess xong,
       nếu không đóng lại thì ReadFile bên dưới sẽ không bao giờ
       nhận được EOF (vì handle ghi vẫn còn mở phía cha). */
    CloseHandle(hWritePipe);
    hWritePipe = NULL;

    if (!ok)
    {
        DWORD err = GetLastError();

        snprintf(
            logBuf,
            sizeof(logBuf),
            "CreateProcessW THAT BAI. GetLastError=%lu",
            err
        );

        WriteLog(logBuf);
        CloseHandle(hReadPipe);

        return 1;
    }

    snprintf(
        logBuf,
        sizeof(logBuf),
        "Tao process con THANH CONG. PID con = %lu",
        (unsigned long)pi.dwProcessId
    );

    WriteLog(logBuf);

    /* --------------------------------------------------------
     * 6. Đọc dữ liệu STDOUT của con qua pipe (blocking read)
     *    cho đến khi con đóng handle ghi (kết thúc hoặc thoát).
     * -------------------------------------------------------- */
    printf("---- OUTPUT CUA CON (redirect qua pipe) ----\n");

    for (;;)
    {
        ok = ReadFile(
            hReadPipe,
            outputBuf,
            sizeof(outputBuf) - 1,
            &bytesRead,
            NULL
        );

        if (!ok || bytesRead == 0)
            break; /* pipe đã đóng -> con đã kết thúc ghi stdout */

        outputBuf[bytesRead] = '\0';
        fputs(outputBuf, stdout);
    }

    printf("---- HET OUTPUT CUA CON ----\n");

    /* --------------------------------------------------------
     * 7. Chờ con thoát hẳn (đề phòng), lấy exit code.
     * -------------------------------------------------------- */
    WaitForSingleObject(pi.hProcess, INFINITE);
    QueryPerformanceCounter(&tEnd);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    double elapsedMs =
        (double)(tEnd.QuadPart - tStart.QuadPart) * 1000.0
        / (double)freq.QuadPart;

    snprintf(
        logBuf,
        sizeof(logBuf),
        "Process con (PID=%lu) da ket thuc. Exit code = %lu. "
        "Thoi gian chay = %.2f ms",
        (unsigned long)pi.dwProcessId,
        (unsigned long)exitCode,
        elapsedMs
    );

    WriteLog(logBuf);

    /* --------------------------------------------------------
     * 8. Dọn dẹp handle
     * -------------------------------------------------------- */
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}