/* Universal LAN->relay hook. Windows DLL + Linux LD_PRELOAD test build.
 *
 * Direct-tunnel mode (needs LAN_HOOK_SERVER): game traffic to LAN IPs is
 * tunneled to the ShadowLAN relay - TCP streams multiplexed over one TCP
 * link, game UDP over UDP, discovery over either. Without LAN_HOOK_SERVER
 * the hook is a pure passthrough. Hosting games stamp a host claim via
 * listen() (a link-ordering hint, never an election: implicit dials ask
 * every machine, only the listener answers); all peers get virtual LAN
 * IPs for P2P mesh play.
 *
 * No TUN/TAP, no driver, no admin. Per-process: only the injected game
 * is affected.
 *
 * Windows: IAT patch (no asm blobs) + GetProcAddress/LoadLibrary guards.
 * Build (Linux, mingw installed):
 *   x86_64-w64-mingw32-gcc -shared -O2 -Wall -o lan_hook64.dll lan_hook.c lan_hook.def -lws2_32 -ldbghelp
 *   i686-w64-mingw32-gcc -shared -O2 -Wall -o lan_hook32.dll lan_hook.c lan_hook.def -lws2_32 -ldbghelp
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o injector.exe injector.c -lpsapi
 * Linux self-test:
 *   gcc -shared -fPIC -DLINUX_BUILD -O2 -o lan_hook.so lan_hook.c -ldl -lpthread
 */
#ifdef LINUX_BUILD
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <ctype.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif


/* Implementation split by concern. Single translation unit BY DESIGN:
 * these fragments share the static state graph (tables, locks, identity)
 * and are order-dependent - do not compile or reorder them standalone.
 * Platform guards are balanced per fragment. */
#include "hk_policy.inc"
#include "hk_ports.inc"
#include "hk_sess.inc"
#include "hk_stream.inc"
#include "hk_udp.inc"
#include "hk_route.inc"
#include "hk_linux.inc"
#include "hk_winsock.inc"
#include "hk_wicmp.inc"
#include "hk_winnic.inc"
#include "hk_wininst.inc"
