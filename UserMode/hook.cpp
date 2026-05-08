//
// Created by voltas on 5/8/2026.
//
#include "Hook.h"
#include "../Dissasembler/Disasm.h"
#include <Windows.h>
#include <cstring>

namespace hooks::user {

struct DetourHook : Hook {
    std::vector<uint8_t> original_bytes;
    uintptr_t target;
    uintptr_t detour;
    uintptr_t trampoline;
    bool enabled;
    HANDLE remote_process; // nullptr = local, otherwise remote

    DetourHook(uintptr_t t, uintptr_t d, HANDLE proc = nullptr)
        : target(t), detour(d), trampoline(0), enabled(false), remote_process(proc) {
        type = Type::Detour;
        mode = Mode::User;
    }

    // read/write memory, local or remote
    bool read_mem(uintptr_t addr, void* buf, size_t len) {
        if (remote_process) {
            SIZE_T r;
            return ReadProcessMemory(remote_process, (void*)addr, buf, len, &r) && r == len;
        }
        memcpy(buf, (void*)addr, len);
        return true;
    }

    bool write_mem(uintptr_t addr, const void* buf, size_t len) {
        if (remote_process) {
            SIZE_T w;
            return WriteProcessMemory(remote_process, (void*)addr, buf, len, &w) && w == len;
        }
        memcpy((void*)addr, buf, len);
        return true;
    }

    bool protect_mem(uintptr_t addr, size_t len, DWORD prot, DWORD* old) {
        if (remote_process) {
            return VirtualProtectEx(remote_process, (void*)addr, len, prot, old);
        }
        return VirtualProtect((void*)addr, len, prot, old);
    }

    uintptr_t alloc_mem(size_t size) {
        if (remote_process) {
            return (uintptr_t)VirtualAllocEx(remote_process, nullptr, size,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
        return (uintptr_t)VirtualAlloc(nullptr, size,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    void free_mem(uintptr_t addr) {
        if (remote_process) {
            VirtualFreeEx(remote_process, (void*)addr, 0, MEM_RELEASE);
        } else {
            VirtualFree((void*)addr, 0, MEM_RELEASE);
        }
    }

    bool enable() override {
        if (enabled) return true;

        const size_t stub_size = 14;
        size_t needed = disasm::instruction_length(target, stub_size, remote_process);
        if (needed < stub_size) return false;

        // save original bytes
        original_bytes.resize(needed);
        if (!read_mem(target, original_bytes.data(), needed)) return false;

        // allocate trampoline
        trampoline = alloc_mem(needed + stub_size);
        if (!trampoline) return false;

        // write original instructions to trampoline
        write_mem(trampoline, original_bytes.data(), needed);

        // write jmp back to target + needed
        uint8_t tramp_jmp[14];
        tramp_jmp[0] = 0xFF; tramp_jmp[1] = 0x25;
        tramp_jmp[2] = tramp_jmp[3] = tramp_jmp[4] = tramp_jmp[5] = 0x00;
        *(uint64_t*)(tramp_jmp + 6) = target + needed;
        write_mem(trampoline + needed, tramp_jmp, 14);

        // write detour jump to target
        DWORD old;
        if (!protect_mem(target, needed, PAGE_EXECUTE_READWRITE, &old)) return false;

        uint8_t detour_bytes[14];
        detour_bytes[0] = 0xFF; detour_bytes[1] = 0x25;
        detour_bytes[2] = detour_bytes[3] = detour_bytes[4] = detour_bytes[5] = 0x00;
        *(uint64_t*)(detour_bytes + 6) = detour;
        write_mem(target, detour_bytes, stub_size);

        // nop remaining
        std::vector<uint8_t> nops(needed - stub_size, 0x90);
        if (!nops.empty()) write_mem(target + stub_size, nops.data(), nops.size());

        protect_mem(target, needed, old, &old);
        enabled = true;
        return true;
    }

    bool disable() override {
        if (!enabled) return true;

        DWORD old;
        protect_mem(target, original_bytes.size(), PAGE_EXECUTE_READWRITE, &old);
        write_mem(target, original_bytes.data(), original_bytes.size());
        protect_mem(target, original_bytes.size(), old, &old);

        if (trampoline) {
            free_mem(trampoline);
            trampoline = 0;
        }

        enabled = false;
        return true;
    }
};

Hook* detour(uintptr_t target, uintptr_t detour) {
    return new DetourHook(target, detour);
}

Hook* detour(HANDLE process, uintptr_t target, uintptr_t detour) {
    return new DetourHook(target, detour, process);
}

} // namespace hooks::user