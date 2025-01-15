#pragma once

#include "Common.h"
#include "Structs.h"

// Object type definitions for process and thread
typedef enum _PS_OBJECT_TYPE {
	PsProcessType = 1,    // Process object type
	PsThreadType = 2     // Thread object type
} PS_OBJECT_TYPE;


INT64 GetPspNotifyRoutineArrayH(UINT32 KernelCallbackRegFuncHash);

INT64 GetPsProcessAndProcessTypeAddr(PS_OBJECT_TYPE objectType);


VOID PrintAndClearCallBack(INT64 PspNotifyRoutineAddress, CHAR* CallBackRegFunc);
VOID PrintAndClearCallBack(INT64 PspNotifyRoutineAddress, UINT32 CallBackRegFuncHash);


VOID RemoveObRegisterCallbacks(INT64 PsProcessTypeAddr, PS_OBJECT_TYPE objectType);

VOID RemoveInstanceCallback(INT64 FLT_FILTERAddr);

VOID ClearThreeCallBack();
VOID ClearMiniFilterCallBack(INT64 FltEnumerateFiltersAddr);


VOID ClearCmRegistercallback();
VOID ClearObRegisterCallbacks();
