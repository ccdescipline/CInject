// TestExE.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "Windows.h"
#include <Psapi.h>
#include <TlHelp32.h>

#define CRLF "\r\n"

void Function(ULONG64 a,ULONG64 b,ULONG64 c) {
    printf_s("%d %d %d \r\n",a,b,c);
    printf_s("%d \r\n",GetCurrentThreadId());
}

int DisplayAllThread()
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do {
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID)) {
					if (GetCurrentProcessId() == te.th32OwnerProcessID) {
						printf("Process %d Thread %d\n",
							te.th32OwnerProcessID, te.th32ThreadID);
					}
					
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
	return 0;
}

void TestWindow() {
	std::cout << "Function : " << Function << std::endl;

	DisplayAllThread();
	MSG msg = { 0 };
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}

DWORD GetProcessIdByName(const wchar_t* pName)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (h == INVALID_HANDLE_VALUE)
		return 0;
	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	for (BOOL ret = Process32First(h, &pe); ret; ret = Process32Next(h, &pe))
	{
		if (wcscmp(pe.szExeFile, pName) == 0)
		{
			CloseHandle(h);
			return pe.th32ProcessID;
		}
	}
	CloseHandle(h);
	return 0;
}

void findNotepadWindow() {
	//获取pid 和窗口句柄
	DWORD pid = GetProcessIdByName(L"mspaint.exe");//Calculator.exe  notepad.exe
	HWND windowHWND = FindWindow(L"MSPaintApp", NULL);
	printf("pid : %d windowHWND : %d" CRLF, pid, windowHWND);

	//获取gui线程，打开
	DWORD guiThread = GetWindowThreadProcessId(windowHWND, &pid);
	printf("GUI thread: guiThread : %d", guiThread);
}

int main()
{
	findNotepadWindow();
    
	system("pause");
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
