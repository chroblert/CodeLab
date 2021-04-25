#include "TokenInforUtil.h"
#define DOMAIN_CHAR_COUNT 100
#define USERNAME_CHAR_COUNT 50

BOOL TokenInforUtil::GetDomainUsernameFromToken(HANDLE hToken, char* full_name_to_return) {
	LPVOID TokenUserInfo[BUF_SIZE];
	char username[USERNAME_CHAR_COUNT], domainname[DOMAIN_CHAR_COUNT];
	DWORD user_length = sizeof(username), domain_length = sizeof(domainname), sid_type = 0, dwRet;
	if (!GetTokenInformation(hToken, TokenUser, TokenUserInfo, BUF_SIZE, &dwRet))
		return FALSE;
	//执行完这一步报错，why？how？
	LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);

	// Make full name in DOMAIN\USERNAME format
	sprintf(full_name_to_return, "%s\\%s", domainname, username);
	return TRUE;
}


/*从token中获取域名\用户名*/
BOOL TokenInforUtil::GetDomainUsernameFromToken(HANDLE hToken, TCHAR* full_name_to_return) {
	TCHAR username[BUF_SIZE], domainname[BUF_SIZE];
	DWORD dwUsername = sizeof(username);
	DWORD dwDomain =sizeof(domainname);
	DWORD dwRet = 0;
	SID_NAME_USE snu;
	GetTokenInformation(hToken, TokenUser, NULL, dwRet, &dwRet);
	if (!dwRet) {
		printf("\tGetTokenInformation（）失败,ERROR: %d\n", GetLastError());
		return FALSE;
	}
	PTOKEN_USER pTokenUser = (PTOKEN_USER)GlobalAlloc(GPTR, dwRet);
	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwRet, &dwRet))
		return FALSE;
	PTOKEN_USER ptu = (PTOKEN_USER)GlobalAlloc(GPTR, dwRet);
	//这里会报错，为什么啊？
	if (!LookupAccountSid(NULL, pTokenUser->User.Sid, username, &dwUsername, domainname, &dwDomain, &snu)) {
		DWORD dwError = GetLastError();
		return FALSE;
	}
	else {
		TCHAR* tmpFullname = (TCHAR*)calloc(DOMAIN_CHAR_COUNT+1+ USERNAME_CHAR_COUNT+1,sizeof(TCHAR));
		if (!tmpFullname) {
			printf("\tmalloc失败,ERROR: %d\n", GetLastError());
			return FALSE;
		}
		_tcscat(tmpFullname, domainname);
		_tcscat(tmpFullname, L"\\");
		_tcscat(tmpFullname, username);
		_tcscpy(full_name_to_return, tmpFullname);
		free(tmpFullname);
		tmpFullname = NULL;
		return TRUE;
	}

}


/*判断该token是否可以被模拟*/
BOOL TokenInforUtil::CanBeImpersonate(HANDLE hToken, BOOL* bRet) {
	HANDLE temp_token;
	//LPVOID TokenImpersonationInfo[10];
	// 获取令牌模拟等级信息，若获取到，则判断模拟等级是不是大于等于模拟
	DWORD dwTokenIL;
	if (GetTokenILFromToken(hToken, &dwTokenIL)) {
		if (dwTokenIL >= SecurityImpersonation)
			*bRet = TRUE;
		else
			*bRet = FALSE;
		return TRUE;
	}
	// 若未获取到令牌等级信息，则尝试是否能够使用该令牌创建一个具有模拟等级的模拟令牌。根据创建的结果判断能够模拟该令牌
	*bRet = DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &temp_token);
	if(*bRet && temp_token != NULL)
		CloseHandle(temp_token);
	return TRUE;
}


/*从token中获取模拟等级*/
BOOL TokenInforUtil::GetTokenILFromToken(HANDLE hToken, DWORD* dwIL) {
	//LPVOID TokenImpersonationInfo[BUF_SIZE];
	PSECURITY_IMPERSONATION_LEVEL pTokenIL = NULL;
	DWORD dwRet = 0;
	// 获取令牌模拟等级信息，若获取到，则判断模拟等级是不是大于等于模拟
	GetTokenInformation(hToken, TokenImpersonationLevel, pTokenIL, NULL, &dwRet);
	pTokenIL = (PSECURITY_IMPERSONATION_LEVEL)malloc(dwRet);
	if (!pTokenIL) {
		printf("\tmalloc失败，ERROR: %d\n", GetLastError());
		return FALSE;
	}
	if (GetTokenInformation(hToken, TokenImpersonationLevel, pTokenIL, dwRet, &dwRet)) {
		*dwIL = *pTokenIL;
		//printf("\t获取令牌中的模拟等级成功，%d\n", *dwIL);
	}
	else {
		//printf("\t获取令牌中的模拟等级失败，ERROR: %d\n", GetLastError());
		*dwIL = -1;
		return FALSE;
	}
	return TRUE;
}


/*从token中获取令牌类型*/
BOOL TokenInforUtil::GetTokenTypeFromToken(HANDLE hToken,DWORD* dwTokenType) {
	DWORD* pTokenTypeInfo;
	DWORD dwRet = 0;
	DWORD error;
	GetTokenInformation(hToken, TokenType, NULL, NULL, &dwRet);
	if (0 == dwRet) {
		error = GetLastError();
		printf(" \tTokenType\t: Error: %d\n\n", error);
		*dwTokenType = -1;
		return FALSE;
	}

	pTokenTypeInfo = (DWORD*)malloc(dwRet);
	if (!pTokenTypeInfo) {
		printf("\tmalloc失败，ERROR: %d\n", GetLastError());
		return FALSE;
	}
	if (GetTokenInformation(hToken, TokenType, pTokenTypeInfo, dwRet, &dwRet)) {
		error = GetLastError();
		switch ((DWORD)*pTokenTypeInfo) {
		case 1:
			printf(" \tTokenType\t: Primary Token\n");
			break;
		case 2:
			printf(" \tTokenType\t: Impersonation Token\n");
			break;
		default:
			printf(" \tTokenType\t: Error: %d\n", error);
			*dwTokenType = -1;
			return FALSE;
		}
		*dwTokenType = *pTokenTypeInfo;
		return TRUE;
	}
	else {
		error = GetLastError();
		printf(" \t获取token中的令牌类型失败， Error: %d\n", error);
		*dwTokenType = -1;
		return FALSE;

	}
}


/*根据用户名获取令牌*/
BOOL TokenInforUtil::GetTokenByUsername(TCHAR* tUsernameArg, HANDLE* hOutToken) {
	return TRUE;
}


/*打印令牌信息*/
BOOL TokenInforUtil::PrintTokens(TokenList tokenList) {
	for (int i = 0; i < tokenList.dwLength; i++) {
		printf("PID: %d\n", tokenList.pTokenListNode[i].dwPID);
		printf("HandleOffset: 0x%x\n", tokenList.pTokenListNode[i].dwHandleOffset);
		printf("LogonID: %08x-%08x\n", tokenList.pTokenListNode[i].luLogonID.HighPart,tokenList.pTokenListNode[i].luLogonID.LowPart);
		printf("IL: %d\n", tokenList.pTokenListNode[i].dwIL);
		printf("CanBeImpersonated: %d\n", tokenList.pTokenListNode[i].bCanBeImpersonate);
		printf("ProcessName: %S\n", tokenList.pTokenListNode[i].tProcName);
		printf("TokenUser: %S\n", tokenList.pTokenListNode[i].tUserName);
		printf("\n");
	}
	return TRUE;
}


/*
初始化TokenListNode
*/
#define USERNAME_CHAR_COUNT 50
#define PROCNAME_CHAR_COUNT 260
BOOL TokenInforUtil::InitTokenListNode(TokenListNode* pTokenListNode) {
	// Step1. 以0填充
	ZeroMemory(pTokenListNode, sizeof(TokenListNode));
	// Step2. 为TCHAR*指针创建内存块
	pTokenListNode->tUserName = (TCHAR*)calloc(USERNAME_CHAR_COUNT+1, sizeof(TCHAR));
	pTokenListNode->tProcName = (TCHAR*)calloc(PROCNAME_CHAR_COUNT+1, sizeof(TCHAR));
	// Step3. 为其他成员赋值
	pTokenListNode->hToken = NULL;
	pTokenListNode->dwPID = -1;
	pTokenListNode->dwTID = -1;
	pTokenListNode->dwIL = -1;
	pTokenListNode->dwTokenType = -1;
	pTokenListNode->luLogonID = { 0,0 };
	pTokenListNode->bCanBeImpersonate = FALSE;
	return TRUE;
}


/*获取系统中的所有令牌*/
BOOL TokenInforUtil::GetTokens(PTokenList pTokenList) {
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION_EX pshi = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(sizeof(SYSTEM_HANDLE_INFORMATION_EX));
	if (!pshi) {
		printf("\tmalloc失败，ERROR: %d\n", GetLastError());
		return FALSE;
	}
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtQuerySystemInformation");
	TCHAR* tmpStr;
	DWORD dwRet = 0;
	PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
	HANDLE hObject = NULL;
	HANDLE hProc = NULL;


	if (pshi) {
		status = NtQuerySystemInformation(SystemHandleInformation, pshi, sizeof(SYSTEM_HANDLE_INFORMATION_EX), NULL);
		printf("pshi->NumberOfHandles: %lu\n", pshi->NumberOfHandles);
		for (ULONG r = 0; r < pshi->NumberOfHandles; r++)
		{
			// Token类型的值是5
			if (pshi->Information[r].ObjectTypeNumber == 5)
			{
				// Info1. 句柄所在的进程ID
				(pTokenList->pTokenListNode + pTokenList->dwLength)->dwPID = pshi->Information[r].ProcessId;
				// Info2. 句柄在进程句柄表中的offset
				(pTokenList->pTokenListNode + pTokenList->dwLength)->dwHandleOffset = pshi->Information[r].Handle;
				// 打开进程句柄
				hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)pshi->Information[r].ProcessId);
				if (hProc == NULL) {
					hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pshi->Information[r].ProcessId);
					if (hProc == NULL) {
						// 下个句柄
						continue;
					}
				}
				// 获取PID对应的进程名
				TCHAR* tProcName = (TCHAR*)calloc(MAX_PATH,sizeof(TCHAR));
				if (!tProcName) {
					printf("\tcalloc失败，ERROR: %d\n", GetLastError());
					return FALSE;
				}
				else {
					if (ProcessInforUtil::GetProcessNameFromPid((DWORD)pshi->Information[r].ProcessId, tProcName)) {
						// Info3. 进程所在文件名
						// 这里经常出错，ansi编码+1，宽字节编码*2+2
						(pTokenList->pTokenListNode + pTokenList->dwLength)->tProcName = (TCHAR*)calloc(_tcslen(tProcName)+1,sizeof(TCHAR));
						_tcscpy((pTokenList->pTokenListNode + pTokenList->dwLength)->tProcName, tProcName);
					}
					free(tProcName);
				}
				// 复制token句柄到当前进程的句柄表中
				if (DuplicateHandle(hProc, (HANDLE)(pshi->Information[r].Handle), GetCurrentProcess(), &hObject, MAXIMUM_ALLOWED, FALSE, 0x02) != FALSE)
				{
					// Info4. token句柄
					(pTokenList->pTokenListNode + pTokenList->dwLength)->hToken = hObject;
					// 从token中获取登录会话ID
					dwRet = 0;
					PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
					GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet);
					if (dwRet == 0) {
						printf("\tdwreterror,ERROR: %d\n", GetLastError());
					}
					else {
						pTokenGroupsAndPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)calloc(dwRet, 1);
						if (GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet)) {
							// Info5. 令牌所关联的登录会话
							(pTokenList->pTokenListNode + pTokenList->dwLength)->luLogonID = pTokenGroupsAndPrivileges->AuthenticationId;
						}
					}
					// 从token中获取用户名
					tmpStr = (TCHAR*)calloc(DOMAIN_CHAR_COUNT + 1 + USERNAME_CHAR_COUNT+1,sizeof(TCHAR));
					if (!tmpStr) {
						printf("\tcalloc失败,ERROR: %d\n", GetLastError());
						return FALSE;
					}
					else {
						GetDomainUsernameFromToken(hObject, tmpStr);
						(pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName = (TCHAR*)calloc(_tcslen(tmpStr) + 1, sizeof(TCHAR));
						_tcscpy((pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName,tmpStr);
						free(tmpStr);
						tmpStr = NULL;
					}
					// 获取令牌模拟等级
					DWORD dwIL;
					if (TokenInforUtil::GetTokenILFromToken(hObject,&dwIL)) {
						(pTokenList->pTokenListNode + pTokenList->dwLength)->dwIL = dwIL;
					}
					else {
						(pTokenList->pTokenListNode + pTokenList->dwLength)->dwIL = -1;
					}
					// 令牌是否可以被模拟
					CanBeImpersonate(hObject, &((pTokenList->pTokenListNode + pTokenList->dwLength)->bCanBeImpersonate));
				}
			loopCon:
				if (hObject != NULL) {
					CloseHandle(hObject);
				}
				if (hProc != NULL) {
					CloseHandle(hProc);
				}
				pTokenList->dwLength++;
			}
		}
		free(pshi);
	}else {
		return FALSE;
	}
	return TRUE;
}