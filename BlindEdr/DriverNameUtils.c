#include "Common.h"
#include "Structs.h"

#include <stdio.h>

#define UINT64_MAX 0xffffffffffffffffui64

static PUINT64 addressArray = NULL;
static UINT64 ArraySize = 0;
static UINT64 ArraySizeByte = 0;

CHAR* ReadDriverName(INT64 FLT_FILTERAddr) {
	// Early parameter validation
	if (!FLT_FILTERAddr) {
		return NULL;
	}

	INT Offset = 0;
	INT64 FilterNameAddr = 0;
	USHORT FilterNameLen = 0;
	TCHAR* FilterName = NULL;
	CHAR* FilterNameA = NULL;
	DWORD dwMajor = GetNtVersion();
	DWORD build = GetNtBuild();

	// Determine offset based on Windows version
	switch (dwMajor) {
		case 10:
			Offset = (build == 26100) ? 0x40 : 0x38;
			break;
		case 6:
			Offset = 0x28;
			break;
		default:
			PRINT("[ReadDriverName] Unsupported Windows version.\n");
			return NULL;  // Replace exit() with return for better error handling
	}

	// Read filter name length
	DriverMemoryOperation((VOID*)(FLT_FILTERAddr + Offset + 2), &FilterNameLen, 2, MEMORY_WRITE);
	if (FilterNameLen == 0) {
		return NULL;
	}

	// Read filter name address
	DriverMemoryOperation((VOID*)(FLT_FILTERAddr + Offset + 8), &FilterNameAddr, 8, MEMORY_WRITE);
	if (!FilterNameAddr) {
		return NULL;
	}

	// Allocate buffer for filter name with bounds checking
	if (FilterNameLen > MAX_PATH) {  // Add reasonable size limit
		return NULL;
	}
	
	FilterName = (TCHAR*)calloc(FilterNameLen + 1, sizeof(TCHAR));  // More precise allocation
	if (!FilterName) {
		return NULL;
	}

	// Read filter name
	DriverMemoryOperation((VOID*)FilterNameAddr, FilterName, FilterNameLen, MEMORY_WRITE);

	// Convert to ANSI string
	FilterNameA = (CHAR*)calloc(FilterNameLen + 5, sizeof(CHAR));  // +5 for ".sys\0"
	if (!FilterNameA) {
		free(FilterName);
		return NULL;
	}

	size_t convertedChars = 0;
	errno_t err = wcstombs_s(&convertedChars, 
							 FilterNameA, 
							 FilterNameLen + 1, 
							 FilterName, 
							 FilterNameLen);

	if (err != 0) {  
		free(FilterName);
		free(FilterNameA);
		return NULL;
	}

	free(FilterName);  // Free temporary wide string buffer
	lstrcatA(FilterNameA, ".sys");
	return FilterNameA;
}

CHAR* GetDriverName(UINT64 DriverCallBackFuncAddr)
{
	CHAR* DriverName = NULL;
	DWORD bytesNeeded = 0;
	DWORD i = 0;
	INT j = 0;
	INT64 tmp = 0;
	PUINT64 ArrayMatch = NULL;
	UINT64 MatchAddr = 0;

	// Init driver address array if needed
	if (!addressArray) {
		if (EnumDeviceDrivers(NULL, 0, &bytesNeeded)) {
			ArraySize = bytesNeeded / 8;
			ArraySizeByte = bytesNeeded;
			addressArray = (INT64*)malloc(ArraySizeByte);
			if (addressArray == NULL) return NULL;
			EnumDeviceDrivers((LPVOID*)addressArray, ArraySizeByte, &bytesNeeded);
		}
	}

	if (addressArray) {
		// Use stack memory instead of heap to avoid memory leaks
		UINT64 stackArrayMatch[1024];  // Assuming driver count won't exceed 1024
		
		// Optimize search logic - find closest address in a single pass
		UINT64 closestAddr = 0;
		UINT64 minDiff = UINT64_MAX;
		
		for (i = 0; i < ArraySize - 1; i++) {
			if (DriverCallBackFuncAddr > addressArray[i]) {
				UINT64 diff = DriverCallBackFuncAddr - addressArray[i];
				if (diff < minDiff) {
					minDiff = diff;
					closestAddr = addressArray[i];
				}
			}
		}

		// If a matching address was found
		if (closestAddr != 0) {
			CHAR* DriverName = (CHAR*)calloc(1024, 1);
			if (DriverName && GetDeviceDriverBaseNameA((LPVOID)closestAddr, DriverName, 1024) > 0) {
				return DriverName;
			}
			free(DriverName);
		}
	}
	return NULL;
}
