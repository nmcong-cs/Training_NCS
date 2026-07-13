/*
 * child.c
 * ------------------------------------------------------------
 * Chương trình CON (child process).
 * Nhiệm vụ:
 *   1. Nhận tham số dòng lệnh do process CHA truyền vào.
 *   2. In các tham số đó ra STDOUT (sẽ bị process cha redirect
 *      để đọc lại thông qua pipe).
 *   3. Giả lập "làm việc" bằng cách Sleep vài giây.
 *   4. Trả về một exit code tuỳ theo tham số (để cha đọc được
 *      qua GetExitCodeProcess).
 *
 * Biên dịch (MinGW):
 *   gcc -o child.exe child.c
 * Biên dịch (MSVC - Developer Command Prompt):
 *   cl child.c
 * ------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(int argc, char* argv[])
{
    int i;
    int sleepMs = 1500;   /* thời gian giả lập xử lý */
    int exitCode = 0;

    printf("[CHILD] PID = %lu\n", (unsigned long)GetCurrentProcessId());
    printf("[CHILD] So luong tham so nhan duoc: %d\n", argc - 1);

    for (i = 1; i < argc; i++)
    {
        printf("[CHILD] argv[%d] = %s\n", i, argv[i]);
    }
    fflush(stdout); /* đảm bảo dữ liệu được đẩy qua pipe ngay */

    /* Nếu tham số đầu tiên là 1 số -> dùng làm exit code,
       và cũng dùng làm thời gian sleep (ms) cho sinh động */
    if (argc > 1)
    {
        int val = atoi(argv[1]);
        if (val > 0)
        {
            exitCode = val % 256;   /* exit code Windows chỉ 0-255 khi qua cmd, nhưng DWORD thực ra rộng hơn */
            sleepMs = 500;
        }
    }

    printf("[CHILD] Dang xu ly (sleep %d ms)...\n", sleepMs);
    fflush(stdout);
    Sleep(sleepMs);

    printf("[CHILD] Hoan tat. Se thoat voi exit code = %d\n", exitCode);
    fflush(stdout);

    return exitCode;
}
