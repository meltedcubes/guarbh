cmake_minimum_required(VERSION 4.0)
project(guarbh)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
add_executable(HookExeAW main.cpp
        Hooks/UserMode/Hook.h
        Hooks/UserMode/hook.cpp
        Hooks/KernelMode/KernelModeHook.h
        Hooks/Dissasembler/DisAsm.h
        Hooks/UserMode/Iat.h
        Hooks/UserMode/Eat.h
        Hooks/UserMode/Vtable.h
        Hooks/HookManager.h
        Hooks/Main/entry.cpp)
