#include<Windows.h>
#include<iostream>

using namespace std;

int main() {
	HANDLE hFile;
	hFile = CreateFile
	(
		L"D:\\Work\\NCS\\CheckAns\\newFile4.txt", 
		GENERIC_READ | GENERIC_WRITE, 
		0, 
		NULL, 
		CREATE_NEW, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL 
	);
	bool bRFile;
	bRFile = ReadFile
	(
		hFile, 
		"Hello World", 
		11, 
		NULL, 
		NULL
	);
}