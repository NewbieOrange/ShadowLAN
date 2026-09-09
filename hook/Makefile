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

test_late.exe: test_late.c
	$(CC64) $(CFLAGS) -o $@ $< -lws2_32 -liphlpapi

test_lateplug.dll: test_lateplug.c
	$(CC64) -shared $(CFLAGS) -o $@ $< -lws2_32

lan_hook.so: lan_hook.c
	gcc -shared -fPIC -DLINUX_BUILD -O2 -Wall -o $@ $< -ldl -lpthread

test: lan_hook.so
	python3 test_direct.py
	python3 test_virtual_p2p.py
	python3 test_childprop.py
	python3 test_treeid.py
	python3 test_perdest.py
	python3 test_noloop.py
	python3 test_udptcp.py
	python3 test_fatal.py
	python3 test_icmp.py
	python3 test_lanonly.py

test-all: test test_late.exe test_lateplug.dll
	SHADOWLAN_WINEPREFIX=~/.wine python3 test_late.py

clean:
	rm -f lan_hook64.dll lan_hook32.dll injector.exe lan_hook.so \
		test_late.exe test_lateplug.dll
