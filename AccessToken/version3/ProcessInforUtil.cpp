#include "ProcessInforUtil.h"


BOOL ProcessInforUtil::GetProcessNameFromPid(DWORD pid, TCHAR* tProcName) {
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (hProc == NULL) {
		hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (hProc == NULL) {
			std::cout << "\t获取进程句柄失败,ERROR: " << GetLastError() << std::endl;
			return FALSE;
		}
	}
	//TCHAR Buffer[MAX_PATH] = {};
	TCHAR* Buffer = (TCHAR*)malloc(MAX_PATH);
	ZeroMemory(Buffer, MAX_PATH);
	if (GetModuleFileNameEx(hProc, NULL, Buffer, MAX_PATH))
	{
		//*tProcName = (TCHAR*)malloc(sizeof(Buffer));
		//tProcName = (TCHAR*)realloc(tProcName, sizeof(Buffer));
		//if (*tProcName == NULL) {
		//	printf("xxxxxxxxxxError\n");
		//	exit(-1);
		//}
		_tcscpy(tProcName, Buffer);
		free(Buffer);
		return TRUE;
	}
	else
	{
		// You better call GetLastError() here
		std::cout << "\t" << "ProcessName   : error" << GetLastError() << std::endl;
		free(Buffer);
		return FALSE;
	}
}