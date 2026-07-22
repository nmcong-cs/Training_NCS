#include<Windows.h>
#include<iostream>

using namespace std;

int main() {
	HANDLE hProcess;
	HANDLE hThread;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD dwProcessId = 0;
	DWORD dwThreadId = 0;
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	bool bCreateProcess;
	bCreateProcess = CreateProcess(
		L"D:\\Work\\NCS\\CheckAns\\check.exe",
		NULL,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi
	);
	if (bCreateProcess == FALSE) {
		cout << "CreateProcess Failed and Error No - " << GetLastError() << endl;
	}
	
	cout << "CreateProcess Success" << endl;
	cout << "Process ID: " << pi.dwProcessId << endl;
	cout << "Thread ID: " << pi.dwThreadId << endl;
		
	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

/*
	startupinfo: dau vao CreateProcess
	process_information: dau ra CreateProcess

	Khởi tạo STARTUPINFO (si)
		↓
	Khởi tạo PROCESS_INFORMATION (pi)
		↓
	CreateProcess()
		↓
	Process được tạo
		↓
	WaitForSingleObject(pi.hProcess, INFINITE)
		↓
	(Đợi process kết thúc)
		↓
	CloseHandle(pi.hThread)
	CloseHandle(pi.hProcess)
*/