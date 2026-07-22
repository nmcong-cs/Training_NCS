#include<Windows.h>
#include<iostream>

using namespace std;

int main() {
	bool symLink = CreateSymbolicLink(
		L"D:\\Work\\NCS\\CheckAns\\khe.txt",
		L"D:\\Work\\NCS\\CheckAns\\ThuHuong.txt",
		SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
	);
	if (symLink == FALSE) {
		cout << "CreateSymbolicLink Failed and Error No - " << GetLastError() << endl;
	}
	else {
		cout << "CreateSymbolicLink Success" << endl;
	}
}