#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <iostream>


int main(int argc,char* argv[])
{
	HANDLE hParentRead, hParentWrite, hChildRead, hChildWrite; //创建4个句柄

	STARTUPINFO si = { 0 };							//启动信息结构体
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };                 //进程信息结构体

	DWORD dwWritedBytes = 0;
	DWORD dwReadedBytes = 0;

	DWORD dwBytesRead = 0;
	DWORD dwTotalBytesAvail = 0;
	DWORD dwBytesLeftThisMessage = 0;

	SECURITY_ATTRIBUTES sa = { 0 };				   //安全属性描述符		
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;                      //设置句柄可继承

	//创建管道1. 父进程读 -> 子进程写入
	BOOL bRet = CreatePipe(&hParentRead,
		&hChildWrite,
		&sa,
		0);
	std::cout << bRet << std::endl;

	//创建管道2.  子进程读->父进程写.
	bRet = CreatePipe(&hChildRead,
		&hParentWrite,
		&sa,
		0);
	std::cout << bRet << std::endl;

	//这里将子进程写重定向到 stdout中. 子进程读取重定向到stdinput中
	si.hStdInput = hChildRead;
	si.hStdOutput = hChildWrite;
	si.dwFlags = STARTF_USESTDHANDLES;   //设置窗口隐藏启动
	wchar_t lpwstrTmp[15] = L"cmd.exe";
	bRet = CreateProcess(NULL,
		lpwstrTmp,                      //创建cmd进程.默认寻找cmd进程.
		NULL,
		NULL,
		TRUE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi);
	if (!bRet) {
		std::cout << GetLastError() << std::endl;
	}
	char* cmdStr = argv[1];
	char szBuffer[100];
	sprintf(szBuffer, "@echo on\n%s\nexit\n", cmdStr);
	WriteFile(hParentWrite, szBuffer, sizeof(szBuffer), &dwWritedBytes, NULL);//使用writeFile操作管道,给cmd发送数据命令.
	// 等待命令执行结束
	WaitForSingleObject(pi.hThread, INFINITE);
	WaitForSingleObject(pi.hProcess, INFINITE);
	ZeroMemory(szBuffer, 15);
	ReadFile(hParentRead, szBuffer, 10, &dwReadedBytes, NULL);
	std::cout << "dwReadedBytes: " << dwReadedBytes << std::endl;
	std::cout << szBuffer;
	while (dwReadedBytes >= 10) {
		ZeroMemory(szBuffer, 15);
		ReadFile(hParentRead, szBuffer, 10, &dwReadedBytes, NULL);
		std::cout << szBuffer;
	}
	return 0;
}