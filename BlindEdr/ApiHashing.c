#include <Windows.h>

#include "Common.h"
#include "Structs.h"


#include "ApiHashing.h"
#include "FunctionPointers.h"


#define FIRST_HASH  0xcbf29ce484222325
#define SECOND_HASH 0x100000001b3
#define THIRD_HASH  0xff51afd7ed558ccd
#define HASH_OFFSET 33


UINT32 CityHash(LPCSTR cString)
{
    int length = strlen(cString);
    UINT64 hash = FIRST_HASH;

    for (size_t i = 0; i < length; ++i) {
        hash ^= (UINT64)cString[i];
        hash *= SECOND_HASH;
    }

    hash ^= hash >> HASH_OFFSET;
    hash *= THIRD_HASH;
    hash ^= hash >> HASH_OFFSET;

    return hash;
}

FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash)
{
	PBYTE	pBase = (PBYTE)hModule;
	PIMAGE_NT_HEADERS pImgNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY pImgExpdir = NULL;
	PDWORD	pdwFunctionNameArray = NULL;
	PDWORD	pdwFunctionAddressArray = NULL;
	PWORD	pwFunctionOrdinalArray = NULL;
	DWORD	dwImgExportDirSize = 0x00;

	// Check for invalid module or hash
	if (!hModule || !uApiHash)
	{
		PRINT("GetProcessAddressH Failed!!");
		return NULL;
	}

	// Get the NT headers of the module
	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	// Get the export directory and related arrays
	pImgExpdir = (PIMAGE_EXPORT_DIRECTORY)(pBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	dwImgExportDirSize = pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	pdwFunctionNameArray = (PDWORD)(pBase + pImgExpdir->AddressOfNames);
	pdwFunctionAddressArray = (PDWORD)(pBase + pImgExpdir->AddressOfFunctions);
	pwFunctionOrdinalArray = (PWORD)(pBase + pImgExpdir->AddressOfNameOrdinals);

	// Iterate over all exported functions
	for (DWORD i = 0; i < pImgExpdir->NumberOfFunctions; i++) {

		CHAR* pFunctionName = (CHAR*)(pBase + pdwFunctionNameArray[i]);
		PVOID	pFunctionAddress = (PVOID)(pBase + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]]);

		// Check if the hash matches
		if (CHASH(pFunctionName) == uApiHash) {

			// Handle forwarded functions
			if ((((ULONG_PTR)pFunctionAddress) >= ((ULONG_PTR)pImgExpdir)) &&
				(((ULONG_PTR)pFunctionAddress) < ((ULONG_PTR)pImgExpdir) + dwImgExportDirSize)
				) {

				CHAR	cForwarderName[MAX_PATH] = { 0 };
				DWORD	dwDotOffset = 0x00;
				PCHAR	pcFunctionMod = NULL;
				PCHAR	pcFunctionName = NULL;

				// Copy the forwarder name
				Memcpy(cForwarderName, pFunctionAddress, strlen((PCHAR)pFunctionAddress));

				// Find the dot in the forwarder name
				for (int i = 0; i < strlen((PCHAR)cForwarderName); i++) {

					if (((PCHAR)cForwarderName)[i] == '.') {
						dwDotOffset = i;
						cForwarderName[i] = NULL;
						break;
					}
				}

				pcFunctionMod = cForwarderName;
				pcFunctionName = cForwarderName + dwDotOffset + 1;

				// Load the library and get the function address
				fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(GetModuleHandleH(kernel32dll_CH, FALSE), LoadLibraryA_CH);
				if (pLoadLibraryA)
					return GetProcAddressH(pLoadLibraryA(pcFunctionMod), CHASH(pcFunctionName));
			}
			return (FARPROC)pFunctionAddress;
		}

	}

	return NULL;
}

HMODULE GetModuleHandleH(IN UINT32 uModuleHash, IN BOOL isKernel) {
    if (isKernel) {
        // For kernel modules, use NtQuerySystemInformation
        PRTL_PROCESS_MODULES ModuleInfo = NULL;
        NTSTATUS status = 0;
        HMODULE result = NULL;

        // Allocate buffer for module info
        ModuleInfo = (PRTL_PROCESS_MODULES)calloc(1024 * 1024, 1);
        if (ModuleInfo == NULL) {
            return NULL;
        }

        // Query system modules
        status = NtQuerySystemInformation(
            SystemModuleInformation,
            ModuleInfo,
            1024 * 1024,
            NULL
        );

        if (!NT_SUCCESS(status)) {
            free(ModuleInfo);
            return NULL;
        }

        // Iterate through kernel modules
        for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++) {
            CHAR* moduleName = (CHAR*)(ModuleInfo->Modules[i].FullPathName + 
                                     ModuleInfo->Modules[i].OffsetToFileName);
            
            // Convert to lowercase and check hash
            CHAR lowerName[MAX_PATH] = {0};
            strncpy_s(lowerName, MAX_PATH, moduleName, _TRUNCATE);
            _strlwr_s(lowerName, MAX_PATH);

            if (CHASH(lowerName) == uModuleHash) {
                result = (HMODULE)ModuleInfo->Modules[i].ImageBase;
                break;
            }
        }

        free(ModuleInfo);
        return result;
    } 
    else {
        // Original user-mode module lookup code
        PPEB pPeb = (PPEB)__readgsqword(0x60);
        PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);
        PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

        // Return the handle of the local .exe image if no hash is provided
        if (!uModuleHash) {
            return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
        }

        if (uModuleHash == advapi32dll_CH) {
            HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
            if (hAdvapi32) {
                PRINT("Successfully loaded advapi32.dll at 0x%p\n", hAdvapi32);
                return hAdvapi32;
            }
        }

        // Iterate over the loaded modules
        while (pDte) {
            if (pDte->FullDllName.Buffer && pDte->FullDllName.Length < MAX_PATH) {
                CHAR cLDllName[MAX_PATH] = { 0 };
                SIZE_T x = 0;

                // Convert the DLL name to lowercase
                while (pDte->FullDllName.Buffer[x] && x < MAX_PATH - 1) {
                    WCHAR wC = pDte->FullDllName.Buffer[x];
                    cLDllName[x] = (wC >= L'A' && wC <= L'Z') ?
                        (CHAR)(wC - L'A' + L'a') : (CHAR)wC;
                    x++;
                }

                if (CHASH(cLDllName) == uModuleHash) {
                    return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
                }
            }

            pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
        }

        // If not found, try to load it
        PRINT("Module with hash 0x%08x not found\n", uModuleHash);
        return NULL;
    }
}