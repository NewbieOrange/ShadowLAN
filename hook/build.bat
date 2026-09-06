@echo off
REM Build on Windows with MinGW (or MSVC cl). Needs no deps.
REM Match the DLL to the GAME bitness, not the OS.
gcc -shared -O2 -Wall -o lan_hook64.dll lan_hook.c -lws2_32
gcc -O2 -Wall -o injector.exe injector.c
REM 32-bit games: rebuild the DLL with a 32-bit toolchain, e.g.
REM i686-w64-mingw32-gcc -shared -O2 -Wall -o lan_hook32.dll lan_hook.c -lws2_32
echo built lan_hook64.dll + injector.exe
