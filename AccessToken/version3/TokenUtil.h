#pragma once
#include "getopt.h"
#include "Helper.h"
#include <tchar.h>
#include <Windows.h>
#include "TokenInforUtil.h"
#define Token_List_Node_Count 1000
extern TCHAR* tUserName = NULL;
extern TCHAR* tCommand = NULL;
extern TCHAR* tModule = NULL;
extern DWORD dwPID;
extern DWORD dwTID;
extern BOOL bVerbose = FALSE;
extern BOOL bPrivileges = FALSE;
extern BOOL bCurInfo = FALSE;
extern BOOL bDisLogonSession = FALSE;

// ����module: Token,LogonSession,Execute
const TCHAR* ModuleList[] = { L"ListToken",L"Execute",L"ListLogonSession" };

