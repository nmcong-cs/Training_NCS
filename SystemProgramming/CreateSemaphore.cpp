#include<Windows.h>
#include<iostream>

using namespace std;

int main() {
	HANDLE hSemaphore;
	hSemaphore = CreateSemaphore(
		NULL,
		1, // initial count
		1, // maximum count
		L"MySemaphore" // name of the semaphore
	);
	if (hSemaphore == NULL) {
		cout << "CreateSemaphore failed with error: " << GetLastError() << endl;
	}
	else {
		cout << "CreateSemaphore succeeded." << endl;
	}

	HANDLE hSem = OpenSemaphore(
		SEMAPHORE_ALL_ACCESS,
		FALSE,
		L"MySemaphore1"
	);

	if (hSem == NULL) {
		cout << "OpenSemaphore failed with error: " << GetLastError() << endl;
	}
	else {
		cout << "OpenSemaphore succeeded." << endl;
	}

	CloseHandle(hSemaphore);
}