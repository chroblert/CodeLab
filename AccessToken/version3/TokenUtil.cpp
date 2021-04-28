﻿// TokenUtil.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
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


/*ListTokens*/
BOOL ListTokens(_TCHAR* tUserName,BOOL bVerbose) {
	TokenList* pTokenList = (TokenList*)malloc(sizeof(TokenList));
	ZeroMemory(pTokenList, sizeof(TokenList));
	pTokenList->pTokenListNode = (PTokenListNode)calloc(Token_List_Node_Count, sizeof(TokenListNode));
	pTokenList->dwLength = 0;
	TokenInforUtil::GetTokens(pTokenList);
	TokenList tokenList = *pTokenList;
	for (DWORD i = 0; i < tokenList.dwLength; i++) {
		if (tUserName != NULL && tokenList.pTokenListNode[i].tUserName != nullptr && _tcscmp(tokenList.pTokenListNode[i].tUserName, tUserName) != 0) {
			continue;
		}
		printf("PID: %d\n", tokenList.pTokenListNode[i].dwPID);
		printf("HandleOffset: 0x%x\n", tokenList.pTokenListNode[i].dwHandleOffset);
		printf("LogonID: %08x-%08x\n", tokenList.pTokenListNode[i].luLogonID.HighPart, tokenList.pTokenListNode[i].luLogonID.LowPart);
		printf("IL: %d\n", tokenList.pTokenListNode[i].dwIL);
		printf("CanBeImpersonated: %d\n", tokenList.pTokenListNode[i].bCanBeImpersonate);
		if (tokenList.pTokenListNode[i].tProcName != nullptr) {
			printf("ProcessName: %S\n", tokenList.pTokenListNode[i].tProcName);
		}
		else {
			printf("ProcessName: None\n");
		}
		if (tokenList.pTokenListNode[i].tUserName != nullptr) {
			printf("TokenUser: %S\n", tokenList.pTokenListNode[i].tUserName);
		}
		else {
			printf("TokenUser: None\n");
		}
		printf("\n");
	}
	return TRUE;
}







BOOL HandleArgument(_TCHAR* tModuleArg,int argc,_TCHAR* argv[]) {
	//_TCHAR* tTmpChr = {};
	_TCHAR** tArgv;
	tArgv = (_TCHAR**)calloc(argc - 1,sizeof(_TCHAR*));
	if (!tArgv) {
		return FALSE;
	}
	for (int i = 1; i < argc; i++) {
		tArgv[i - 1] = argv[i];
	}
	// OPTION
	char opt;
	//TCHAR* optStr = NULL;
	// 判断传进来的是哪一个module
	if (!_tcscmp(tModuleArg, L"ListTokens")) {
		// 从命令行获取参数
		while ((opt = getopt(argc-1, tArgv, "p:t:lcvpu:e:")) != -1) {
			switch (opt) {
			case 'u':
				printf("%c -> %S\n", opt, optarg);
				tUserName = (TCHAR*)malloc(sizeof(optarg));
				_tcscpy(tUserName, optarg);
				break;
			case 'p': //列出指定pid或所有进程中的令牌
				printf("%c -> %S\n", opt, optarg);
				break;
			case 't': //列出指定tid或所有线程中的模拟令牌
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
		// ListTokens
		ListTokens(tUserName, TRUE);
	}
	else if (!_tcscmp(tModuleArg, L"ListLogonSession")) {

	}
	else if (!_tcscmp(tModuleArg, L"Execute")) {
		bConsoleMode = FALSE;
		// 从命令行获取参数
		while ((opt = getopt(argc - 1, tArgv, "u:e:c")) != -1) {
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
			case 'c':
				printf("%c -> 1\n", opt);
				bConsoleMode = TRUE;
				break;
			default: //输出帮助文档
				Helper::print_usage();
				exit(1);
			}
		}
		// 执行命令
		Execute::ExecuteWithUsername(tUserName,tCommand, bConsoleMode);
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
			break;
		}
	}
	if (tModule != NULL) {
		HandleArgument(tModule, argc, argv);
		// 这里如果不注释掉会报错:CRT detected that the application wrote memory after end of heap buffer
		// 难道是因为会无法释放全局变量
		//free(tModule);
		//tModule = NULL;
	}
	else {
		Helper::print_usage();
	}
	return FALSE;
	

}