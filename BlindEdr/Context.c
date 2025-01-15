#include "Common.h"
#include "Structs.h"

#include <tlhelp32.h>
#include <stdio.h>

BOOL NyxInitializeContext(void) {
	HANDLE	hDevice = NULL;
	DWORD	dwMajor = 0;
	DWORD	dwMinor = 0;
	DWORD	dwBuild = 0;

	HINSTANCE hinst = LoadLibraryA("ntdll.dll");

	if (hinst == NULL) {
		// LOG
		return FALSE;
	}

	hDevice = CreateFileW(
		DRIVER_NAME,
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hDevice == INVALID_HANDLE_VALUE) {
		// LOG
		return FALSE;
	}

	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuild);
	dwBuild &= 0xffff;

	// Do not support Windows 8
	if (dwMajor == 6 && dwMinor == 2) {
		PRINT("Not Support\r\n");
		return FALSE;
	}

	g_Context.hDevice = hDevice;
	g_Context.PatchTable = (PMemoryPatch)NULL;
	g_Context.Systeminfo.dwMajor = dwMajor;
	g_Context.Systeminfo.dwBuild = dwBuild;
	g_Context.Systeminfo.dwMinorVersion = dwMinor;

	return TRUE;
}

PBasic_INFO GetContext(void) {
	return &g_Context;
}

PMemoryPatch GetPatchTable(void) {
	return g_Context.PatchTable;
}

DWORD GetNtVersion(void) {
	return g_Context.Systeminfo.dwMajor;
}

DWORD GetNtBuild(void) {
	return g_Context.Systeminfo.dwBuild;
}

DWORD GetNtMinorVersion(void) {
	return g_Context.Systeminfo.dwMinorVersion;
}

HANDLE GetContextHandle(void) {
	return g_Context.hDevice;
}

VOID CleanupContext(void)
{
	PMemoryPatch current = g_Context.PatchTable;
	while (current != NULL) {
		PMemoryPatch next = current->pNext;

		if (current->pData) {
			free(current->pData);
		}
		free(current);
		current = next;
	}
	g_Context.PatchTable = NULL;

	if (g_Context.hDevice != NULL && g_Context.hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(g_Context.hDevice);
		g_Context.hDevice = NULL;
	}

	g_Context.Systeminfo.dwBuild = 0;
	g_Context.Systeminfo.dwMajor = 0;
	g_Context.Systeminfo.dwMinorVersion = 0;
}