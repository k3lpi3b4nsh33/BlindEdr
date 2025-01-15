#pragma once

#include <Windows.h>


typedef HMODULE(WINAPI* fnLoadLibraryExA)(
    IN LPCSTR lpLibFileName,
    IN HANDLE hFile,
    IN DWORD dwFlags
    );

typedef HMODULE(WINAPI* fnLoadLibraryA)(IN LPCSTR lpLibFileName);

typedef PTP_TIMER(WINAPI* fnCreateThreadpoolTimer)(IN PTP_TIMER_CALLBACK pfnti, IN OUT OPTIONAL PVOID pv, IN OPTIONAL PTP_CALLBACK_ENVIRON pcbe);

typedef void (WINAPI* fnSetThreadpoolTimer)(IN OUT PTP_TIMER pti, IN OPTIONAL PFILETIME pftDueTime, IN DWORD msPeriod, IN DWORD msWindowLength);

typedef DWORD(WINAPI* fnWaitForSingleObject)(IN HANDLE hHandle, IN DWORD dwMilliseconds);

typedef PVOID(WINAPI* fnAddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);

typedef ULONG(WINAPI* fnRemoveVectoredExceptionHandler)(PVOID Handle);
