# guardbh

A unified hooking library for Windows with support for local and remote processes. Provides detour, IAT, EAT, and VTable hooks through a single interface.

## Hook types

| Type | Scope | Works across processes |
|------|-------|----------------------|
| Detour | Inline patch at function start | Yes |
| IAT | Import table redirect | No (local only) |
| EAT | Export table redirect | No (local only) |
| VTable | Virtual table swap | No (local only) |

## Features

- Same API for local and remote hooks
- Trampoline generation for calling the original function
- Automatic instruction length calculation
- Hook manager for batch enable/disable
- Rollback on failure

## Usage

```cpp
hooks::Manager mgr;

// Local IAT hook
mgr.add_iat("user32.dll", "MessageBoxA", (uintptr_t)&MyMessageBoxA);

// Remote detour
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
mgr.add_detour(hProc, target_addr, (uintptr_t)&MyFunction);

// Enable all
mgr.enable_all();
