#include<Windows.h>
#include<iostream>

using namespace std;

int main() {
	bool bFile;
	bFile = CopyFile(L"D:\\Work\\NCS\\CheckAns\\oldFile.txt", L"D:\\Work\\NCS\\CheckAns\\newFile.txt", FALSE);
	if (bFile == FALSE) {
		cout << "CopyFile Failed and Error No - " << GetLastError() << endl;
	}
	else {
		cout << "CopyFile Success" << endl;
	}
	return 0;
}

//