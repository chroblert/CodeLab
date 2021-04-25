#include "ProcessInforUtil.h"
#define PROCNAME_CHAR_COUNT 260

BOOL ProcessInforUtil::GetProcessNameFromPid(DWORD pid, TCHAR* tProcName) {
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (hProc == NULL) {
		hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (hProc == NULL) {
			std::cout << "\t获取进程句柄失败,ERROR: " << GetLastError() << std::endl;
			return FALSE;
		}
	}
	TCHAR* Buffer = (TCHAR*)calloc(1,PROCNAME_CHAR_COUNT);
	if (!Buffer) {
		printf("\tmalloc失败，ERROR: %d\n", GetLastError());
		return FALSE;
	}
	//ZeroMemory(Buffer, MAX_PATH);
	if (!GetModuleFileNameEx(hProc, NULL, Buffer, PROCNAME_CHAR_COUNT))
	{
		// You better call GetLastError() here
		std::cout << "\t" << "ProcessName   : error" << GetLastError() << std::endl;
		free(Buffer);
		return FALSE;
	}
	else
	{
		_tcscpy(tProcName, Buffer);
		free(Buffer);
		Buffer = NULL;
		return TRUE;
	}
}