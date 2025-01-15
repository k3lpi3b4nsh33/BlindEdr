#pragma once

#include <Windows.h>

// Compile-time constants for randomization
#define SEED_PRIME_1    0x1337CAFE
#define SEED_PRIME_2    0xAE860167
#define SEED_PRIME_3    0xB16B00B5

// Generate compile-time seed using time
#define TIME_SEED       (__TIME__[7] - '0' + \
                        (__TIME__[6] - '0') * 10 + \
                        (__TIME__[4] - '0') * 60 + \
                        (__TIME__[3] - '0') * 600 + \
                        (__TIME__[1] - '0') * 3600 + \
                        (__TIME__[0] - '0') * 36000)

// Compile-time hash calculation
#define COMPILE_TIME_HASH(x)  ((x) * SEED_PRIME_1 ^ \
                              ((x) << 13) * SEED_PRIME_2 ^ \
                              ((x) >> 7) * SEED_PRIME_3)

// Helper function for memory operations
__forceinline PVOID AllocateRandomBuffer(PVOID* ppAddress) {
    SIZE_T size = (TIME_SEED & 0xFFF) + 0x100;
    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!pAddress) return NULL;

    *(DWORD*)pAddress = COMPILE_TIME_HASH(TIME_SEED);
    *ppAddress = pAddress;
    return pAddress;
}

// Main camouflage function
__declspec(noinline) VOID IatCamouflage(VOID) {
    PVOID pAddress = NULL;
    volatile int* pValue = (int*)AllocateRandomBuffer(&pAddress);
    if (!pValue) return;

    // Use RDTSC for unpredictable execution path
    if (__rdtsc() % COMPILE_TIME_HASH(TIME_SEED) == *pValue) {
        volatile UINT64 result = 0;
        
        // Mix Windows API calls
        result += GetTickCount64();
        result += GetCurrentProcessId();
        result ^= GetLastError();
        result += IsDebuggerPresent();
        
        // System information calls
        SYSTEM_INFO sysInfo = {0};
        GetSystemInfo(&sysInfo);
        result ^= sysInfo.dwPageSize;
        
        // Time-based operations
        FILETIME ft = {0};
        GetSystemTimeAsFileTime(&ft);
        result += ft.dwLowDateTime;
        
        // Additional entropy
        result *= GetCurrentThreadId();
        result ^= __rdtsc();
        
        *(volatile UINT64*)pAddress = result;
    }

    HeapFree(GetProcessHeap(), 0, pAddress);
}