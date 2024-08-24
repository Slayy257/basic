#include "hack.hpp"
#include "sigscanner.hpp"
#include <thread>
#include <chrono>

HMODULE g_hMod = 0;

void panic(const char* reason) {
    MessageBoxA(0, reason, "PANIC!!", 0);
    FreeLibraryAndExitThread(g_hMod, 0);
}

using t_fnPrintf = int(*)(const char *const _Format, ...);
using t_fnGetUserInput = __int64 __fastcall(const char *prompt, char *buffer, int bufferSizeLimit);

t_fnGetUserInput* ofnGetUserInput = nullptr;

bool hook(void *func, void* detour) {
    LPVOID func_addr = reinterpret_cast<LPVOID>(func);

    DWORD lpflOldProtect;
    VirtualProtect(func_addr, sizeof(func_addr), PAGE_EXECUTE_READWRITE, &lpflOldProtect);


    // do hook detour process
    const BYTE jmpOPCODE = 0xE9;

    LPVOID allocAddr = VirtualAlloc(nullptr, sizeof(detour), MEM_COMMIT | MEM_RESERVE, lpflOldProtect);

    if (!allocAddr) {
        VirtualProtect(func_addr, sizeof(func_addr), lpflOldProtect, &lpflOldProtect);
        panic("Can't alloc for detour");
    }

    // do detour at alloc addr;
    // make func addr jmp to our allocAddr func with shellcode 0xE9

    VirtualProtect(func_addr, sizeof(func_addr), lpflOldProtect, &lpflOldProtect);
};

__int64 __fastcall fnGetUserInputDetour(const char *prompt, char *buffer, int bufferSizeLimit) {
    
    MessageBoxA(0, buffer, "Change Buffer?", 0);
    snprintf(buffer, sizeof(buffer), "GETFUCKED");

    return ofnGetUserInput(prompt, buffer, bufferSizeLimit);
}

void hack(HMODULE hmod)
{
    g_hMod = hmod;
    HANDLE baseModule = GetModuleHandleA("ccmd.exe");

    //t_fnPrintf printf = reinterpret_cast<t_fnPrintf>(GetProcAddress(GetModuleHandleA("msvcrt.dll"), "printf"));
    t_fnGetUserInput* fnGetUserInput = reinterpret_cast<t_fnGetUserInput*>((PatternScan(baseModule, "55 48 89 E5 48 83 EC 20") - 1));

    if (hook(reinterpret_cast<void*>(fnGetUserInput), reinterpret_cast<void*>(fnGetUserInputDetour)))
        MessageBoxA(0, "DETOUR WORKED", "DETOUR WORKED", 0);

    while(true) {
        if (!GetAsyncKeyState(VK_END) & 1)
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    FreeLibraryAndExitThread(g_hMod, 0);
}