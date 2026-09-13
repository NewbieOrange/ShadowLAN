J ?= auto
# Compile parallelism: default to nproc. An explicit -j / parent jobserver wins.
NPROC ?= $(shell nproc 2>/dev/null || echo 1)
ifeq ($(filter -j%,$(MAKEFLAGS))$(findstring jobserver,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(NPROC)
endif
CC64=x86_64-w64-mingw32-gcc
CC32=i686-w64-mingw32-gcc
CFLAGS=-O2 -Wall
HDRS=hk_plat.h hk_api.h hk_version.h hk_core.h hk_mod.h \
	hk_ports.h hk_sess.h hk_stream.h hk_udp.h hk_route.h hk_linux.h hk_win.h
MOD_COMMON=hk_util hk_alias hk_ledger hk_core hk_ports hk_sess hk_stream hk_udp hk_route
MOD_LNX=$(MOD_COMMON) hk_linux
MOD_WIN=$(MOD_COMMON) hk_winsock hk_wicmp hk_winnic hk_wininst

all: lan_hook64.dll lan_hook32.dll injector.exe lan_hook.so

# Header change rebuilds every object; a .c touch rebuilds only that object.
%.lnx.o: %.c $(HDRS)
	gcc -fPIC -DLINUX_BUILD $(CFLAGS) -c -o $@ $<
%.w64.o: %.c $(HDRS)
	$(CC64) $(CFLAGS) -c -o $@ $<
%.w32.o: %.c $(HDRS)
	$(CC32) $(CFLAGS) -c -o $@ $<

lan_hook64.dll: lan_hook.w64.o $(addsuffix .w64.o,$(MOD_WIN)) lan_hook.def
	$(CC64) -shared $(CFLAGS) -o $@ $^ -lws2_32 -ldbghelp -lpsapi

lan_hook32.dll: lan_hook.w32.o $(addsuffix .w32.o,$(MOD_WIN)) lan_hook.def
	$(CC32) -shared $(CFLAGS) -o $@ $^ -lws2_32 -ldbghelp -lpsapi

injector.exe: injector.c
	$(CC64) $(CFLAGS) -o $@ $< -lpsapi

test_late.exe: test_late.c
	$(CC64) $(CFLAGS) -o $@ $< -lws2_32 -liphlpapi

test_lateplug.dll: test_lateplug.c
	$(CC64) -shared $(CFLAGS) -o $@ $< -lws2_32

lan_hook.so: lan_hook.lnx.o $(addsuffix .lnx.o,$(MOD_LNX))
	gcc -shared -o $@ $^ -ldl -lpthread

# Parallel suite: tests self-allocate real ports (testutil) so any
# subset runs concurrently. J=n overrides the auto (= CPU count).
test: lan_hook.so
	python3 ../runtests.py -j $(J)

test-all: lan_hook.so lan_hook64.dll injector.exe test_late.exe test_lateplug.dll
	SHADOWLAN_WINEPREFIX=~/.wine python3 ../runtests.py -j $(J) --wine

format:
	clang-format -i $(wildcard *.c *.h)

clean:
	rm -f lan_hook64.dll lan_hook32.dll injector.exe lan_hook.so \
		test_late.exe test_lateplug.dll *.o
