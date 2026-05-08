//
// Created by voltas on 5/8/2026.
//
#pragma once
#include <cstdint>
#include <vector>

namespace hooks {

    enum class Mode { User, Kernel };
    enum class Type { Detour, IAT, EAT, VTable, SSDT, IRP };

    struct Hook {
        uintptr_t target;      // original function
        uintptr_t detour;      // our function
        uintptr_t trampoline;  // callable original (for detours)
        Type      type;
        Mode      mode;
        bool      enabled;

        virtual bool enable() = 0;
        virtual bool disable() = 0;
    };

    // length disassembler
    namespace disasm {
        size_t instruction_length(uintptr_t addr, size_t min_bytes);
    }

    // user mode hooks
    namespace user {
        Hook* detour(uintptr_t target, uintptr_t detour);
        Hook* iat(const char* dll, const char* function, uintptr_t detour);
        Hook* eat(const char* dll, const char* function, uintptr_t detour);
        Hook* vtable(uintptr_t* vtable, size_t index, uintptr_t detour);
    }

    // kernel mode hooks
    namespace kernel {
        Hook* detour(uintptr_t target, uintptr_t detour);
        Hook* ssdt(uint32_t index, uintptr_t detour);
        Hook* irp(uintptr_t driver_object, uint8_t major_function, uintptr_t detour);
        Hook* callback(const wchar_t* name, uintptr_t detour);
    }

} // namespace hooks
