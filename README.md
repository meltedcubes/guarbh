# guardbh

A unified hooking library for Windows with support for local and remote processes. Provides detour, IAT, EAT, and VTable hooks through a single interface.

## Hook types

| Type | Scope | Works across processes |
|------|-------|----------------------|
| Detour | Inline patch at function start | Yes |
| IAT | Import table redirect | No (local only) |
| EAT | Export table redirect | Not implemented yet |
| VTable | Virtual table swap | Not implemented yet) |

## Features

- Same API for local and remote hooks
- Trampoline generation for calling the original function
- Automatic instruction length calculation
- Hook manager for batch enable/disable
- Rollback on failure

## Usage

```cpp
  auto hook = hooks::user::iat("user32.dll", "MessageBoxA", (uintptr_t)&MyMessageBoxA);
    if (!hook || !hook->enable()) {
        printf("Hook failed\n");
        return 1;
    }
    printf("hook installed\n");
  MessageBoxA(NULL, "Hello", "Test", MB_OK);
