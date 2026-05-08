//
// Created by voltas on 5/9/2026.
//
#include <iostream>
#include <Windows.h>
#include "../UserMode/Hook.h"
#include "../UserMode/Iat.h"

typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t OriginalMessageBoxA = nullptr;

int WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    if (OriginalMessageBoxA) {
        return OriginalMessageBoxA(hWnd, "hooked", "hooked title", uType);
    }
    return 0;
}

int main() {
    HMODULE user32 = GetModuleHandleA("user32.dll");
    OriginalMessageBoxA = (MessageBoxA_t)GetProcAddress(user32, "MessageBoxA");

    if (!OriginalMessageBoxA) {
        printf("Failed to get original\n");
        return 1;
    }

    printf("original at: 0x%p\n", OriginalMessageBoxA);

    auto hook = hooks::user::iat("user32.dll", "MessageBoxA", (uintptr_t)&MyMessageBoxA);
    if (!hook || !hook->enable()) {
        printf("Hook failed\n");
        return 1;
    }
    printf("hook installed\n");

    MessageBoxA(NULL, "Hello", "Test", MB_OK); // <-- If hooked, it will show "hooked, hooked title" / Если хукнем, будет показывать "hooked, hooked title"
    MessageBoxA(NULL, "Hi", "Test", MB_OK);

    hook->disable();
    MessageBoxA(NULL, "Not hooked", "Test", MB_OK); // <-- Will show the original message / Покажет оригинальное сообщение
    return 0;
}