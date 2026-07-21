#include<Windows.h>
#include<iostream>

using namespace std;

int main() {
	bool bMFile;
	bMFile = MoveFile(L"D:\\Work\\NCS\\CheckAns\\newFile.txt", L"D:\\Work\\NCS\\CheckAns\\newFile1.txt");
	if (bMFile == FALSE) {
		cout << "MoveFile Failed and Error No - " << GetLastError() << endl;
	}
	else {
		cout << "MoveFile Success" << endl;
	}
	return 0;
}

// chuyen noi dung file tu vi tri nay sang vi tri khac, hoac doi ten file