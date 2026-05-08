//
// Created by voltas on 5/8/2026.
//
#include "../UserMode/Hook.h"
#include <cstdint>
#include <Windows.h>
namespace hooks::disasm {

    size_t instruction_length(uintptr_t addr, size_t min_bytes, HANDLE process) {
        uint8_t local_buf[32];
        uint8_t* code;

        if (process) {
            SIZE_T r;
            ReadProcessMemory(process, (void*)addr, local_buf, sizeof(local_buf), &r);
            code = local_buf;
        } else {
            code = (uint8_t*)addr;
        }
    size_t offset = 0;

    while (offset < min_bytes) {
        uint8_t op = code[offset];

        // prefixes
        if (op >= 0x40 && op <= 0x4F) { offset++; continue; } // REX
        if (op == 0x66) { offset++; continue; } // operand size
        if (op == 0x67) { offset++; continue; } // address size
        if (op == 0xF0) { offset++; continue; } // lock
        if (op == 0xF2 || op == 0xF3) { offset++; continue; } // rep

        // 2-byte opcodes
        if (op == 0x0F) {
            uint8_t op2 = code[offset + 1];
            if (op2 == 0x1F) { offset += 3; break; } // nop
            if (op2 == 0x84 || op2 == 0x85) { offset += 6; break; } // jcc near
            offset += 2;
            // modrm
            if (offset < min_bytes) {
                uint8_t modrm = code[offset];
                uint8_t mod = modrm >> 6;
                uint8_t rm = modrm & 7;
                if (mod == 0 && rm == 5) offset += 4; // rip-relative
                else if (mod == 1) offset += 1; // disp8
                else if (mod == 2) offset += 4; // disp32
                if (rm == 4) offset++; // sib (skip computing sib + displacement)
                offset++;
            }
            continue;
        }

        // single-byte opcodes
        if (op >= 0x70 && op <= 0x7F) { offset += 2; break; } // jcc short
        if (op == 0xE8 || op == 0xE9) { offset += 5; break; } // call/jmp rel32
        if (op == 0xFF) {
            uint8_t modrm = code[offset + 1];
            if ((modrm >> 3 & 7) == 4 || (modrm >> 3 & 7) == 5) { offset += 7; break; } // jmp/call [rip+]
            offset += 3; break;
        }
        if (op == 0xC3) { offset += 1; break; } // ret
        if (op == 0xCC) { offset += 1; break; } // int3
        if (op == 0x90) { offset += 1; break; } // nop
        if (op == 0xB8 || op == 0x48) { // mov rax, imm64 or REX.W prefix
            offset++;
            continue;
        }

        // default: skip modrm
        offset++;
        if (offset >= min_bytes) break;
        uint8_t modrm = code[offset];
        uint8_t mod = modrm >> 6;
        uint8_t rm = modrm & 7;
        if (mod == 0 && rm == 5) offset += 4;
        else if (mod == 1) offset += 1;
        else if (mod == 2) offset += 4;
        offset++;
    }

    return offset;
}

} // namespace hooks::disasm