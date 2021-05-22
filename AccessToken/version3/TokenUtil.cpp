// TokenUtil.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <tchar.h>
#include "TokenUtil.h"
//#define TOKENLIST_NODE_COUNT 1000

/*ListTokens*/
BOOL ListTokens(_TCHAR* tUserName,BOOL bVerbose,DWORD dwPid,TCHAR* tProcName) {
	// 声明并开辟空间
	TokenList* pTokenList = (TokenList*)calloc(1,sizeof(TokenList));
	pTokenList->pTokenListNode = (PTokenListNode)calloc(Token_List_Node_Count, sizeof(TokenListNode));
	// token的数量初始为0
	pTokenList->dwLength = 0;
	TokenInforUtil::GetTokens(pTokenList);
	TokenList tokenList = *pTokenList;
	for (DWORD i = 0; i < tokenList.dwLength; i++) {
		// 若传入了用户名，则判断是否为该令牌的用户名；若不是则跳过，继续循环
		if (tUserName != NULL && tokenList.pTokenListNode[i].tUserName != nullptr && _tcscmp(tokenList.pTokenListNode[i].tUserName, tUserName) != 0) {
			continue;
		}
		// 若传入了进程名字符串，则判断是该令牌的进程名是否包含该字符串；若不包含则跳过，继续循环
		if (tProcName != NULL && tokenList.pTokenListNode[i].tProcName != nullptr && _tcsstr(tokenList.pTokenListNode[i].tProcName, tProcName) == NULL) {
			continue;
		}
		// 若传入了进程ID，则判断是否为该令牌的进程ID；若不是则跳过，继续循环
		if (dwPid != -1 && tokenList.pTokenListNode[i].dwPID != dwPid) {
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
	// 释放令牌List
	if (pTokenList) {
		TokenInforUtil::ReleaseTokenList(pTokenList);
		free(pTokenList);
		pTokenList = NULL;
	}
	return TRUE;
}


BOOL HandleArgument(_TCHAR* tModuleArg,DWORD argc,_TCHAR* argv[]) {
	//_TCHAR* tTmpChr = {};
	_TCHAR** tArgv;
	tArgv = (_TCHAR**)calloc(argc - 1,sizeof(_TCHAR*));
	if (!tArgv) {
		return FALSE;
	}
	for (DWORD i = 1; i < argc; i++) {
		tArgv[i - 1] = argv[i];
	}
	// OPTION
	char opt;
	DWORD dwPid = -1;  // -p 进程id
	TCHAR* tUserName = NULL; // -u 用户名
	TCHAR* tProcName = NULL; // -P 进程名
	TCHAR* tCommand = NULL; // -e 命令
	//TCHAR* optStr = NULL;
	// 判断传进来的是哪一个module
	if (!_tcscmp(tModuleArg, L"ListTokens")) {
		// 从命令行获取参数
		while ((opt = getopt(argc-1, tArgv, "p:P:t:lcvpu:e:")) != -1) {
			switch (opt) {
			case 'u':
				printf("\t%c -> %S\n", opt, optarg);
				tUserName = (TCHAR*)calloc(_tcslen(optarg)+1, sizeof(TCHAR));
				_tcscpy(tUserName, optarg);
				break;
			case 'p': //列出指定pid或所有进程中的令牌
				printf("\t%c -> %S\n", opt, optarg);
				dwPid = _ttoi(optarg);
				break;
			case 'P':
				printf("\t%c -> %S\n", opt, optarg);
				tProcName = (TCHAR*)calloc(_tcslen(optarg)+1, sizeof(TCHAR));
				_tcscpy(tProcName, optarg);
				break;
			case 't': //列出指定tid或所有线程中的模拟令牌
				printf("\t%c -> %S\n", opt, optarg);
				break;
			case 'c': //列出当前进程的令牌信息
				printf("\t%c -> %S\n", opt, optarg);
				break;
			default: //输出帮助文档
				Helper::print_usage();
				goto EXIT;
			}
		}
		// ListTokens
		ListTokens(tUserName, TRUE,dwPid,tProcName);
	}
	else if (!_tcscmp(tModuleArg, L"ListLogonSession")) {

	}
	else if (!_tcscmp(tModuleArg, L"Execute")) {
		if (argc <= 2) {
			Helper::print_usage();
			goto EXIT;
		}

		bConsoleMode = FALSE;
		// 从命令行获取参数
		while ((opt = getopt(argc - 1, tArgv, "u:e:c")) != -1) {
			switch (opt) {
			case 'u': //用户名
				printf("\t%c -> %S\n", opt, optarg);
				tUserName = (TCHAR*)calloc(_tcslen(optarg)+1,sizeof(TCHAR));
				_tcscpy(tUserName, optarg);
				break;
			case 'e': //列出当前进程的令牌信息
				printf("\t%c -> %S\n", opt, optarg);
				tCommand = (TCHAR*)calloc(_tcslen(optarg)+1,sizeof(TCHAR));
				_tcscpy(tCommand, optarg);
				break;
			case 'c':
				printf("\t%c -> 1\n", opt);
				bConsoleMode = TRUE;
				break;
			default: //输出帮助文档
				Helper::print_usage();
				goto EXIT;
			}
		}
		// 执行命令
		Execute::ExecuteWithUsername(tUserName,tCommand, bConsoleMode);
	}
	else {
		Helper::print_usage();
	}
EXIT:
	//释放创建的TCHAR指针
	if (tUserName != NULL)
	{
		free(tUserName);
		tUserName = NULL;
	}
	if (tProcName != NULL) {
		free(tProcName);
		tProcName = NULL;
	}
	if (tCommand != NULL) {
		free(tCommand);
		tCommand = NULL;
	}
	if (tArgv != NULL) {
		free(tArgv);
		tArgv = NULL;
	}

}
int _tmain(DWORD argc, _TCHAR* argv[])
{
	DWORD dwError = 0;
	if (!TokenInforUtil::TrySwitchTokenPriv(NULL,SE_DEBUG_NAME, TRUE,&dwError)) {
		printf("TryEnableDebugPriv,Error: %d\n", dwError);
	}
	if (!TokenInforUtil::TrySwitchTokenPriv(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE, &dwError)) {
		printf("TryEnableAssignPrimaryPriv,Error: %d\n", dwError);
	}
	if (!TokenInforUtil::TrySwitchTokenPriv(NULL, SE_INCREASE_QUOTA_NAME, TRUE, &dwError)) {
		printf("TryEnableIncreaseQuotaPriv,Error: %d\n", dwError);
	}
	if (argc < 2) {
		Helper::print_usage();
		return FALSE;
	}
	TCHAR* tModule = NULL; // 模块
	for (DWORD i = 0; i < sizeof(ModuleList) / sizeof(TCHAR*); i++) {
		if (!_tcscmp(argv[1], ModuleList[i])) {
			printf("ChooseModule:%ws\n", argv[1]);
			tModule = (TCHAR*)calloc(_tcslen(ModuleList[i])+1,sizeof(TCHAR));
			_tcscpy(tModule, ModuleList[i]);
			break;
		}
	}
	if (tModule != NULL) {
		HandleArgument(tModule, argc, argv);
	}
	else {
		Helper::print_usage();
	}
	// 释放TCHAR指针
	if (tModule != NULL) {
		free(tModule);
		tModule = NULL;
	}
	return FALSE;
	

}