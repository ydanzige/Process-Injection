// ProcessInjector.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <comdef.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <Winternl.h>
#include <atlconv.h>

int main()
{
    return 0;
}

BOOL FindThreadEntry(THREADENTRY32  &te32,DWORD processId)
{
	HANDLE hSnap = NULL;
	te32.dwSize = sizeof(te32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(hSnap, &te32);
	printf("\nFinding a thread to hijack.\n");
	BOOL threadFound = false;
	while (Thread32Next(hSnap, &te32))
	{
		if (te32.th32OwnerProcessID == processId)
		{
			printf("\nTarget thread found. Thread ID: %d\n", te32.th32ThreadID);
			threadFound = true;
			break;
		}
	}
	
	CloseHandle(hSnap);
	return threadFound;
}
DWORD GetProcID(std::string ProcName)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	do {
		//translate wchar to char
		_bstr_t b(pe32.szExeFile);
		char * processName = b;
		if (strcmp(processName, ProcName.c_str()) == 0)
		{
			DWORD ProcId = pe32.th32ProcessID;
			CloseHandle(hProcessSnap);
			return ProcId;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return 0;
}

void DbgPrint(const char *msg)
{

#ifdef DEBUG
	DWORD eMsgLen, errNum = GetLastError();
	LPTSTR lpvSysMsg;

	if (msg)
		printf("%s: ", msg);
	eMsgLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL, errNum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpvSysMsg, 0, NULL);
	if (eMsgLen > 0)
		_ftprintf(stderr, _T("%d %s\n"), errNum, lpvSysMsg);
	else
		_ftprintf(stderr, _T("Error %d\n"), errNum);
	if (lpvSysMsg != NULL)
		LocalFree(lpvSysMsg);
#endif
}
//const wchar_t *GetWC( char *c)
//{
//	const size_t cSize = strlen(c) + 1;
//	wchar_t* wc = new wchar_t[cSize];
//	mbstowcs(wc, c, cSize);
//
//	return wc;
//}
wchar_t *convertCharArrayToLPCWSTR(const char* charArray)
{
	wchar_t* wString = new wchar_t[4096];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
	return wString;
}

