//
// Created by voltas on 5/8/2026.
//
// Not tested
#include "hook.hpp"

#ifdef _KERNEL_MODE
#include <ntddk.h>

namespace hooks::kernel {

struct KernelDetour : Hook {
    uintptr_t target;
    uintptr_t detour;
    uintptr_t trampoline;
    bool enabled;
    uint8_t original_bytes[14];
    size_t stolen;

    KernelDetour(uintptr_t t, uintptr_t d) : target(t), detour(d), trampoline(0), enabled(false) {
        type = Type::Detour;
        mode = Mode::Kernel;
    }

    bool enable() override {
        if (enabled) return true;

        stolen = disasm::instruction_length(target, 14);
        if (stolen < 14) return false;

        // save original
        memcpy(original_bytes, (void*)target, stolen);

        // allocate trampoline
        trampoline = (uintptr_t)ExAllocatePool2(POOL_FLAG_NON_PAGED, stolen + 14, 'Hdet');
        if (!trampoline) return false;

        // copy original + jmp back
        memcpy((void*)trampoline, original_bytes, stolen);
        uint8_t* jmp = (uint8_t*)(trampoline + stolen);
        jmp[0] = 0xFF; jmp[1] = 0x25; jmp[2] = jmp[3] = jmp[4] = jmp[5] = 0;
        *(uint64_t*)(jmp + 6) = target + stolen;

        // write detour
        KIRQL irql = KeRaiseIrqlToDpcLevel();
        uint8_t* dst = (uint8_t*)target;

        // disable write protection (cr0 wp bit)
        uint64_t cr0 = __readcr0();
        __writecr0(cr0 & ~0x10000);

        dst[0] = 0xFF; dst[1] = 0x25; dst[2] = dst[3] = dst[4] = dst[5] = 0;
        *(uint64_t*)(dst + 6) = detour;
        for (size_t i = 14; i < stolen; i++) dst[i] = 0x90;

        __writecr0(cr0);
        KeLowerIrql(irql);

        enabled = true;
        return true;
    }

    bool disable() override {
        if (!enabled) return true;

        KIRQL irql = KeRaiseIrqlToDpcLevel();
        uint64_t cr0 = __readcr0();
        __writecr0(cr0 & ~0x10000);

        memcpy((void*)target, original_bytes, stolen);

        __writecr0(cr0);
        KeLowerIrql(irql);

        if (trampoline) {
            ExFreePool((void*)trampoline);
            trampoline = 0;
        }

        enabled = false;
        return true;
    }
};

Hook* detour(uintptr_t target, uintptr_t detour) {
    return new KernelDetour(target, detour);
}

} // namespace hooks::kernel
#endif