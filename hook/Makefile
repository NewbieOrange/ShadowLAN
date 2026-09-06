CC64=x86_64-w64-mingw32-gcc
CC32=i686-w64-mingw32-gcc
CFLAGS=-O2 -Wall

all: lan_hook64.dll lan_hook32.dll injector.exe lan_hook.so

lan_hook64.dll: lan_hook.c lan_hook.def
	$(CC64) -shared $(CFLAGS) -o $@ lan_hook.c lan_hook.def -lws2_32 -ldbghelp -lpsapi

lan_hook32.dll: lan_hook.c lan_hook.def
	$(CC32) -shared $(CFLAGS) -o $@ lan_hook.c lan_hook.def -lws2_32 -ldbghelp -lpsapi

injector.exe: injector.c
	$(CC64) $(CFLAGS) -o $@ $< -lpsapi

lan_hook.so: lan_hook.c
	gcc -shared -fPIC -DLINUX_BUILD -O2 -Wall -o $@ $< -ldl -lpthread

test: lan_hook.so
	python3 test_direct.py
	python3 test_virtual_p2p.py
	python3 test_childprop.py

clean:
	rm -f lan_hook64.dll lan_hook32.dll injector.exe lan_hook.so
