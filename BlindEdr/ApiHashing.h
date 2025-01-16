#pragma once

// Common Function City hash
#define LoadLibraryExA_CH						 0xE4B4B3BE
#define LoadLibraryA_CH                          0x64DD6C03

// DLL name City hash
#define kernel32dll_CH                           0xD009B80C
#define advapi32dll_CH                           0xEF149922


// Essential Function
#define OpenProcessToken_CH                      0x7C37481F
#define LookupPrivilegeValueA_CH                 0x893E9289
#define AdjustTokenPrivileges_CH                 0x3D660B5D
#define FLTMGRSYS_CH							 0x44B3C584
#define NTOSKRNLEXE_CH                           0x4D75420E
#define FltEnumerateFilters_CH                   0x97B9D79D
#define NtDuplicateObject_CH                     0x99D79FFF
#define NtOpenThreadTokenEx_CH                   0xD5966046
#define CmUnRegisterCallback_CH                  0x5DB9C22C
#define PsSetCreateProcessNotifyRoutine_CH       0x7676A5F2
#define PsSetCreateThreadNotifyRoutine_CH        0xF12F24DA
#define PsSetLoadImageNotifyRoutine_CH           0x6783E0E8

// ApiHashing
UINT32 CityHash(LPCSTR cString);
#define CHASH(STR)	( CityHash( (LPCSTR)STR ) )

