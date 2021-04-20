#include "TokenInforUtil.h"

BOOL TokenInforUtil::GetDomainUsernameFromToken(HANDLE token, TCHAR** full_name_to_return) {
	LPVOID TokenUserInfo[BUF_SIZE];
	char username[BUF_SIZE], domainname[BUF_SIZE];
	DWORD user_length = sizeof(username), domain_length = sizeof(domainname), sid_type = 0, dwRet;

	if (!GetTokenInformation(token, TokenUser, TokenUserInfo, BUF_SIZE, &dwRet))
		return FALSE;
	LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);

	// Make full name in DOMAIN\USERNAME format
	char* tmpFullname=(char*)malloc(255);
	sprintf(tmpFullname, "%s\\%s", domainname, username);
	USES_CONVERSION;
	*full_name_to_return = (TCHAR*)malloc(sizeof(A2T(tmpFullname)));
	_tcscpy(*full_name_to_return, A2T(tmpFullname));
	free(tmpFullname);
	return TRUE;
}


BOOL TokenInforUtil::CanBeImpersonate(HANDLE hToken, BOOL* bRet) {
	HANDLE temp_token;
	LPVOID TokenImpersonationInfo[10];
	// ��ȡ����ģ��ȼ���Ϣ������ȡ�������ж�ģ��ȼ��ǲ��Ǵ��ڵ���ģ��
	DWORD dwTokenIL;
	if (GetTokenILFromToken(hToken, &dwTokenIL)) {
		if (dwTokenIL >= SecurityImpersonation)
			*bRet = TRUE;
		else
			*bRet = FALSE;
		return TRUE;
	}
	// ��δ��ȡ�����Ƶȼ���Ϣ�������Ƿ��ܹ�ʹ�ø����ƴ���һ������ģ��ȼ���ģ�����ơ����ݴ����Ľ���ж��ܹ�ģ�������
	*bRet = DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &temp_token);
	if(temp_token != NULL)
		CloseHandle(temp_token);
	return TRUE;
}

BOOL TokenInforUtil::GetTokenILFromToken(HANDLE hToken, DWORD* dwIL) {
	//LPVOID TokenImpersonationInfo[BUF_SIZE];
	PSECURITY_IMPERSONATION_LEVEL pTokenIL = NULL;
	DWORD dwRet = 0;
	// ��ȡ����ģ��ȼ���Ϣ������ȡ�������ж�ģ��ȼ��ǲ��Ǵ��ڵ���ģ��
	GetTokenInformation(hToken, TokenImpersonationLevel, pTokenIL, NULL, &dwRet);
	pTokenIL = (PSECURITY_IMPERSONATION_LEVEL)malloc(dwRet);
	if (GetTokenInformation(hToken, TokenImpersonationLevel, pTokenIL, dwRet, &dwRet)) {
		*dwIL = *pTokenIL;
		//printf("\t��ȡ�����е�ģ��ȼ��ɹ���%d\n", *dwIL);
	}
	else {
		//printf("\t��ȡ�����е�ģ��ȼ�ʧ�ܣ�ERROR: %d\n", GetLastError());
		*dwIL = -1;
		return FALSE;
	}
	return TRUE;
}

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
		printf(" \t��ȡtoken�е���������ʧ�ܣ� Error: %d\n", error);
		*dwTokenType = -1;
		return FALSE;

	}
}

BOOL TokenInforUtil::GetTokenByUsername(TCHAR* tUsernameArg, HANDLE* hOutToken) {
	return TRUE;
}

BOOL TokenInforUtil::PrintTokens(TokenList tokenList) {
	for (int i = 0; i < tokenList.dwLength; i++) {
		printf("%d\n", tokenList.ppTokenListNode[i]->dwPID);
	}
	return TRUE;
}

BOOL TokenInforUtil::GetTokens(PTokenList pTokenList) {
	PTokenListNode pTokenListNode = NULL;
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION_EX pshi = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(sizeof(SYSTEM_HANDLE_INFORMATION_EX));
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtQuerySystemInformation");
	TCHAR* tmpStr;
	DWORD dwRet = 0;
	PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
	HANDLE hObject = NULL;
	HANDLE hProc = NULL;


	if (pshi) {
		status = NtQuerySystemInformation(SystemHandleInformation, pshi, sizeof(SYSTEM_HANDLE_INFORMATION_EX), NULL);
		for (ULONG r = 0; r < pshi->NumberOfHandles; r++)
		{
			// Token���͵�ֵ��5
			if (pshi->Information[r].ObjectTypeNumber == 5)
			{
				pTokenListNode = (TokenListNode*)malloc(sizeof(TokenListNode));
				ZeroMemory(pTokenListNode, sizeof(TokenListNode));
				pTokenListNode->dwPID = pshi->Information[r].ProcessId;
				//pTokenListNode->hToken = pshi->Information[r].Handle;

				// ���������ڵĽ���ID
				printf("ProcessId: %d\n", pshi->Information[r].ProcessId);
				// ����������
				printf("\tHandleType\t: Token\n");
				printf("\tHandleOffset\t: 0x%x\n", pshi->Information[r].Handle);
				// �����Ӧ���ں˶���
				printf("\t�ں˶���\t\t: 0x%p\n", pshi->Information[r].Object);
				// �򿪽��̾��
				hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)pshi->Information[r].ProcessId);
				if (hProc == NULL) {
					hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pshi->Information[r].ProcessId);
					if (hProc == NULL) {
						printf("\t��ȡ���̾��ʧ�ܣ�Error: %d\n", GetLastError());
						// �¸����
						continue;
					}
				}
				// ��ȡpid��Ӧ�Ľ�����
				TCHAR* tProcName ;
				tProcName = (TCHAR*)malloc(MAX_PATH);
				if (ProcessInforUtil::GetProcessNameFromPid((DWORD)pshi->Information[r].ProcessId, tProcName)) {
					printf("\tProcessName\t: %S\n", tProcName);
					pTokenListNode->tProcName = (TCHAR*)malloc(sizeof(tProcName));
					_tcscpy(pTokenListNode->tProcName, tProcName);
				}
				else {
					printf("\tProcessName\t: Error%d\n", GetLastError());
				}
				free(tProcName);
				
				// ����token�������ǰ���̵ľ������
				if (DuplicateHandle(hProc, (HANDLE)(pshi->Information[r].Handle), GetCurrentProcess(), &hObject, MAXIMUM_ALLOWED, FALSE, 0x02) != FALSE)
				{
					pTokenListNode->hToken = (HANDLE)malloc(sizeof(hObject));
					pTokenListNode->hToken = hObject;
					// ��token�л�ȡ��¼�ỰID
					dwRet = 0;
					PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
					GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet);
					if (dwRet == 0) {
						printf("\tdwreterror,ERROR: %d\n", GetLastError());
						//getchar();
					}
					else {
						pTokenGroupsAndPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)calloc(dwRet, 1);
						if (!GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet)) {
							printf("\t��ȡ������Ϣʧ�ܣ�ERROR: %d\n", GetLastError());
						}
						else {
							printf("\tLogonId\t\t: %08x-%08x\n", pTokenGroupsAndPrivileges->AuthenticationId.HighPart, pTokenGroupsAndPrivileges->AuthenticationId.LowPart);
							//pTokenListNode->luLogonID = (LUID*)malloc(sizeof(LUID));
							pTokenListNode->luLogonID = pTokenGroupsAndPrivileges->AuthenticationId;
						}
					}
					// ��token�л�ȡ�û���
					TokenInforUtil::GetDomainUsernameFromToken(hObject, &tmpStr);
					printf(" \tTokenUser\t: %S\n", tmpStr);
					pTokenListNode->tUserName = (TCHAR*)malloc(sizeof(tmpStr));
					_tcscpy(pTokenListNode->tUserName,tmpStr);
					// ��ȡ����ģ��ȼ�
					DWORD dwIL;
					if (TokenInforUtil::GetTokenILFromToken(hObject,&dwIL)) {
						pTokenListNode->dwIL = dwIL;
					}
					else {
						pTokenListNode->dwIL = -1;
					}
					CanBeImpersonate(hObject,&(pTokenListNode->bCanBeImpersonate));
					// ��token�л�ȡ��������
					//GetTokenTypeFromToken(hObject);
				}
				//else {
				//	printf("\t����Token���ʧ��,ERROR: %d\n", GetLastError());
				//	goto loopCon;
				//}
			loopCon:
				printf("\n");
				if (hObject != NULL) {
					CloseHandle(hObject);
				}
				if (hProc != 0x0) {
					CloseHandle(hProc);
					printf("Error: %d\n", GetLastError());
					//FindClose(hProc);
				}
				else {
					printf("============%x\n", hProc);
				}
				pTokenList->ppTokenListNode[pTokenList->dwLength] = pTokenListNode;
				pTokenList->dwLength++;
			}
		}
		free(pshi);
	}
	return TRUE;
}