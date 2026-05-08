//
// Created by voltas on 5/8/2026.
//
#include "Hook.h"
#include <Windows.h>
#include <cstring>

namespace hooks::user {

struct IATHook : Hook {
    uintptr_t* iat_entry;
    uintptr_t original;
    uintptr_t detour;
    bool enabled;

    IATHook(const char* dll, const char* func, uintptr_t det) : original(0), detour(det), enabled(false) {
        type = Type::IAT;
        mode = Mode::User;

        uintptr_t target = (uintptr_t)GetProcAddress(GetModuleHandleA(dll), func);
        if (!target) return;

        auto* dos = (PIMAGE_DOS_HEADER)GetModuleHandleA(nullptr);
        auto* nt = (PIMAGE_NT_HEADERS)((uint8_t*)dos + dos->e_lfanew);
        DWORD iat_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        auto* desc = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)dos + iat_rva);

        while (desc->Name) {
            const char* name = (const char*)((uint8_t*)dos + desc->Name);
            if (!_stricmp(name, dll)) {
                auto* thunk = (PIMAGE_THUNK_DATA)((uint8_t*)dos + desc->FirstThunk);
                while (thunk->u1.Function) {
                    if (thunk->u1.Function == target) {
                        iat_entry = (uintptr_t*)&thunk->u1.Function;
                        original = target;
                        this->target = target;
                        return;
                    }
                    thunk++;
                }
            }
            desc++;
        }
    }

    bool enable() override {
        if (enabled || !iat_entry) return false;
        DWORD old;
        VirtualProtect(iat_entry, sizeof(uintptr_t), PAGE_READWRITE, &old);
        *iat_entry = detour;
        VirtualProtect(iat_entry, sizeof(uintptr_t), old, &old);
        enabled = true;
        return true;
    }

    bool disable() override {
        if (!enabled || !iat_entry) return false;
        DWORD old;
        VirtualProtect(iat_entry, sizeof(uintptr_t), PAGE_READWRITE, &old);
        *iat_entry = original;
        VirtualProtect(iat_entry, sizeof(uintptr_t), old, &old);
        enabled = false;
        return true;
    }
};

Hook* iat(const char* dll, const char* function, uintptr_t detour) {
    return new IATHook(dll, function, detour);
}

} // namespace hooks::user