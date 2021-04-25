// TokenUtil.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <tchar.h>
#include "TokenUtil.h"
#define TOKENLIST_NODE_COUNT 1000


DWORD TryEnableAssignPrimaryPriv(HANDLE token)
{
	HANDLE hToken = token;
	DWORD dwError = 0;
	TOKEN_PRIVILEGES privileges;

	if (hToken == NULL && !OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken))
	{
		dwError = GetLastError();
		goto exit;
	}

	if (!LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &privileges.Privileges[0].Luid))
	{
		dwError = GetLastError();
		goto exit;
	}

	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges.PrivilegeCount = 1;

	if (AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, NULL, NULL) == 0)
	{
		dwError = GetLastError();
		goto exit;
	}

exit:
	if (token == NULL && hToken)
		CloseHandle(hToken);

	return dwError;
}



DWORD TryEnableDebugPriv(HANDLE token)
{
	HANDLE hToken = token;
	DWORD dwError = 0;
	TOKEN_PRIVILEGES privileges;

	if (hToken == NULL && !OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken))
	{
		dwError = GetLastError();
		goto exit;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
	{
		dwError = GetLastError();
		goto exit;
	}

	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges.PrivilegeCount = 1;

	//if (AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, NULL, NULL) == 0)
	if (AdjustTokenPrivileges(hToken, FALSE, &privileges, sizeof(privileges), NULL, NULL) == 0)
	{
		dwError = GetLastError();
		goto exit;
	}

exit:
	if (token == NULL && hToken)
		CloseHandle(hToken);

	return dwError == ERROR_SUCCESS;
}

BOOL ExecuteWithToken(HANDLE hToken,_TCHAR* tCommandArg) {
	TokenList* pTokenList = (TokenList*)malloc(sizeof(TokenList));
	ZeroMemory(pTokenList, sizeof(TokenList));
	pTokenList->pTokenListNode = (PTokenListNode)calloc(1000, sizeof(TokenListNode));
	pTokenList->dwLength = 0;
	TokenInforUtil::GetTokens(pTokenList);
	TokenInforUtil::PrintTokens(*pTokenList);
	return TRUE;
	HANDLE hParentRead, hParentWrite, hChildRead, hChildWrite; //创建4个句柄
	HANDLE hNewToken;

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
	//std::cout << bRet << std::endl;

	//创建管道2.  子进程读->父进程写.
	bRet = CreatePipe(&hChildRead,
		&hParentWrite,
		&sa,
		0);
	//std::cout << bRet << std::endl;

	//这里将子进程写重定向到 stdout中. 子进程读取重定向到stdinput中
	si.hStdInput = hChildRead;
	si.hStdOutput = hChildWrite;
	si.dwFlags = STARTF_USESTDHANDLES;   //设置窗口隐藏启动
	wchar_t lpwstrTmp[15] = L"cmd.exe";
	if(NULL == hToken){
		bRet = CreateProcessW(NULL,
			lpwstrTmp,                      //创建cmd进程.默认寻找cmd进程.
			NULL,
			NULL,
			TRUE,
			CREATE_NO_WINDOW,
			NULL,
			NULL,
			&si,
			&pi);
	}
	else {
		// Create primary token
		if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
		{
			HANDLE hTmpToken;
			OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hTmpToken);

			// Duplicate to make primary token 
			if (!DuplicateTokenEx(hTmpToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
			{
				printf("[-] Failed to duplicate token to primary token: %d\n", GetLastError());
				return FALSE;
			}
			CloseHandle(hTmpToken);
		}
		bRet = CreateProcessWithTokenW(hNewToken,
			0, // logon flags
			0, // application name
			lpwstrTmp, // command-line
			0, // creation flags
			NULL, // environment - inherit from parent
			NULL, // current directory
			&si,
			&pi);
	}
	if (!bRet) {
		std::cout << GetLastError() << std::endl;
	}
	char szBuffer[100];
	sprintf(szBuffer, "@echo on\n%S\nexit\n", tCommandArg);
	//printf("%s\n", szBuffer);
	WriteFile(hParentWrite, szBuffer, sizeof(szBuffer), &dwWritedBytes, NULL);//使用writeFile操作管道,给cmd发送数据命令.
	// 等待命令执行结束
	//WaitForSingleObject(pi.hThread, INFINITE);
	// [-]210419BUG: 有些命令一直处于等待状态，如："hostname && whoami",好像是因为空格的问题
	WaitForSingleObject(pi.hThread, 5000);
	WaitForSingleObject(pi.hProcess, 5000);
	ZeroMemory(szBuffer, 15);
	ReadFile(hParentRead, szBuffer, 10, &dwReadedBytes, NULL);
	std::cout << szBuffer;
	while (dwReadedBytes >= 10) {
		ZeroMemory(szBuffer, 15);
		ReadFile(hParentRead, szBuffer, 10, &dwReadedBytes, NULL);
		std::cout << szBuffer;
	}
	return 0;
}



BOOL HandleArgument(_TCHAR* tModule,int argc,_TCHAR* argv[]) {
	//_TCHAR* tTmpChr = {};
	_TCHAR** tArgv;
	tArgv = (_TCHAR**)calloc(argc - 1,sizeof(_TCHAR*));
	for (int i = 1; i < argc; i++) {
		tArgv[i - 1] = argv[i];
	}
	// OPTION
	char opt;
	//TCHAR* optStr = NULL;
	// 判断传进来的是哪一个module
	if (!_tcscmp(tModule, L"ListToken")) {
		// 从命令行获取参数
		TCHAR tmpstrx[10] = _T("cmd");
		while ((opt = getopt(argc-1, tArgv, "p:t:lcvpu:e:")) != -1) {
			switch (opt) {
			case 'u':
				printf("%c -> %S\n", opt, optarg);
				break;
			case 'p': //列出指定pid或所有进程中的令牌
				printf("%c -> %S\n", opt, optarg);
				break;
			case 't': //列出指定tid或所有线程中的模拟令牌
				printf("%c -> %S\n", opt, optarg);
				break;
			case 'l': //列出当前系统中的系统会话
				printf("%c -> %S\n", opt, optarg);
				break;
			case 'c': //列出当前进程的令牌信息
				printf("%c -> %S\n", opt, optarg);
				break;
			default: //输出帮助文档
				Helper::print_usage();
				exit(1);
			}
		}
	}
	else if (!_tcscmp(tModule, L"ListLogonSession")) {

	}
	else if (!_tcscmp(tModule, L"Execute")) {
		// 从命令行获取参数
		TCHAR tmpstrx[10] = _T("cmd");
		while ((opt = getopt(argc - 1, tArgv, "u:e:")) != -1) {
			switch (opt) {
			case 'u': //用户名
				printf("%c -> %S\n", opt, optarg);
				tUserName = (TCHAR*)malloc(sizeof(optarg));
				_tcscpy(tUserName, optarg);
				break;
			case 'e': //列出当前进程的令牌信息
				printf("%c -> %S\n", opt, optarg);
				tCommand = (TCHAR*)malloc(sizeof(optarg));
				_tcscpy(tCommand, optarg);
				break;
			default: //输出帮助文档
				Helper::print_usage();
				exit(1);
			}
		}
		// 执行命令
		//printf("x%S\n", tCommand);
		ExecuteWithToken(NULL,tCommand);
	}
	else {
		Helper::print_usage();
	}
}
int _tmain(int argc, _TCHAR* argv[])
{
	DWORD tmpRes = TryEnableDebugPriv(NULL);
	printf("enableDebug: %d\n", tmpRes);
	TryEnableAssignPrimaryPriv(NULL);
	if (argc < 2) {
		Helper::print_usage();
		return FALSE;
	}
	for (int i = 0; i < sizeof(ModuleList) / sizeof(TCHAR*); i++) {
		if (!_tcscmp(argv[1], ModuleList[i])) {
			printf("ChooseModule:%ws\n", argv[1]);
			tModule = (TCHAR*)malloc(sizeof(ModuleList[i]));
			_tcscpy(tModule, ModuleList[i]);
		}
	}
	HandleArgument(tModule, argc, argv);
	//printf("%ws\n", tModule);
	return FALSE;
	

}