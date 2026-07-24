#include<Windows.h>
#include<iostream>

using namespace std;

HANDLE hMutex;
int gcount = 0;

DWORD WINAPI ThreadFunEven(LPVOID lpParam) {
	while (gcount < 10) {
		WaitForSingleObject(hMutex, INFINITE);
		if (gcount % 2 == 0) {
			cout << "Even Thread: " << gcount << endl;
			gcount++;
		}
		ReleaseMutex(hMutex);
	}
	return 0;
}

DWORD WINAPI ThreadFunOdd(LPVOID lpParam) {
	while (gcount < 10) {
		WaitForSingleObject(hMutex, INFINITE);
		if (gcount % 2 == 1) {
			cout << "Odd Thread: " << gcount << endl;
			gcount++;
		}
		ReleaseMutex(hMutex);
	}
	return 0;
}

int main() {
	HANDLE hThread1, hThread2;

	hMutex = CreateMutex(
		NULL,
		FALSE,
		NULL
	);

	hThread1 = CreateThread(
		NULL,
		0,
		ThreadFunEven,
		NULL,
		0,
		NULL
	);

	hThread2 = CreateThread(
		NULL,
		0,
		ThreadFunOdd,
		NULL,
		0,
		NULL
	);

	HANDLE handles[2] = { hThread1, hThread2 };
    WaitForMultipleObjects(2, handles, TRUE, INFINITE);

	CloseHandle(hThread1);
	CloseHandle(hThread2);
	CloseHandle(hMutex);

	return 0;
}