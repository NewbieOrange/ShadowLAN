J ?= auto
CC64=x86_64-w64-mingw32-gcc
CC32=i686-w64-mingw32-gcc
CFLAGS=-O2 -Wall
INC=$(wildcard *.inc)

all: lan_hook64.dll lan_hook32.dll injector.exe lan_hook.so

lan_hook64.dll: lan_hook.c $(INC) lan_hook.def
	$(CC64) -shared $(CFLAGS) -o $@ lan_hook.c lan_hook.def -lws2_32 -ldbghelp -lpsapi

lan_hook32.dll: lan_hook.c $(INC) lan_hook.def
	$(CC32) -shared $(CFLAGS) -o $@ lan_hook.c lan_hook.def -lws2_32 -ldbghelp -lpsapi

injector.exe: injector.c
	$(CC64) $(CFLAGS) -o $@ $< -lpsapi

test_late.exe: test_late.c
	$(CC64) $(CFLAGS) -o $@ $< -lws2_32 -liphlpapi

test_lateplug.dll: test_lateplug.c
	$(CC64) -shared $(CFLAGS) -o $@ $< -lws2_32

lan_hook.so: lan_hook.c $(INC)
	gcc -shared -fPIC -DLINUX_BUILD -O2 -Wall -o $@ $< -ldl -lpthread

# Parallel suite: tests self-allocate real ports (testutil) so any
# subset runs concurrently. J=n overrides the auto (= CPU count).
test: lan_hook.so
	python3 ../runtests.py -j $(J)

test-all: lan_hook.so test_late.exe test_lateplug.dll
	SHADOWLAN_WINEPREFIX=~/.wine python3 ../runtests.py -j $(J) --wine

clean:
	rm -f lan_hook64.dll lan_hook32.dll injector.exe lan_hook.so \
		test_late.exe test_lateplug.dll
