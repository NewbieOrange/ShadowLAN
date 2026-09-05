@echo off
REM Build on Windows with MinGW (or MSVC cl). Needs no deps.
gcc -shared -O2 -Wall -o lan_hook64.dll lan_hook.c -lws2_32
gcc -O2 -Wall -o injector.exe injector.c
echo built lan_hook64.dll + injector.exe
