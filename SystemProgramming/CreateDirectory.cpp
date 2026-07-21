#include<Windows.h>
#include<iostream>
using namespace std;
int main() {
	bool diR1;
	diR1 = CreateDirectory(L"D:\\ThuHuong\\ThuHuongcuoiManhCong", NULL);
	if (diR1 == FALSE) {
		cout << "CreateDirectory Failed and Error No - " << GetLastError() << endl;
	}
	else {
		cout << "CreateDirectory Success" << endl;
	}

	bool diR;
	diR = RemoveDirectory(L"D:\\ThuHuong\\ThuHuongcuoiManhCong");
	if (diR == FALSE) {
		cout << "RemoveDirectory Failed and Error No - " << GetLastError() << endl;
	}
	else {
		cout << "RemoveDirectory Success" << endl;
	}
}

// duoc su dung de tao thu muc va xoa thu muc trong Windows