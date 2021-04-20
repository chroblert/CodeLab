#pragma once
#include <tchar.h>
#include <Windows.h>
#include <Psapi.h>
#include <iostream>

class ProcessInforUtil
{
public:
	static BOOL GetProcessNameFromPid(DWORD pid, TCHAR* tProcName);
};

