#pragma once

#include <Windows.h>


typedef HMODULE(WINAPI* fnLoadLibraryExA)(
    IN LPCSTR lpLibFileName,
    IN HANDLE hFile,
    IN DWORD dwFlags
    );

typedef HMODULE(WINAPI* fnLoadLibraryA)(IN LPCSTR lpLibFileName);

typedef BOOL(WINAPI* fnOpenProcessToken)(
    HANDLE ProcessHandle,    // Handle to the process
    DWORD DesiredAccess,    // Desired access to the token
    PHANDLE TokenHandle     // Pointer to receive token handle
    );

typedef BOOL(WINAPI* fnLookupPrivilegeValueA)(
    LPCSTR lpSystemName,    // Name of system (NULL for local)
    LPCSTR lpName,         // Name of privilege
    PLUID lpLuid           // Receives LUID of privilege
    );

typedef BOOL(WINAPI* fnAdjustTokenPrivileges)(
    HANDLE TokenHandle,           // Handle to token
    BOOL DisableAllPrivileges,    // TRUE to disable all privileges
    PTOKEN_PRIVILEGES NewState,   // Array of privileges
    DWORD BufferLength,          // Size of buffer
    PTOKEN_PRIVILEGES PreviousState, // Previous state (NULL if not needed)
    PDWORD ReturnLength          // Required buffer size
    );