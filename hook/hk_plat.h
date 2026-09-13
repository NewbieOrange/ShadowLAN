#ifndef HK_PLAT_H
#define HK_PLAT_H
/* Platform includes shared by lan_hook.c and its internal modules.
 * LINUX_BUILD selects the LD_PRELOAD test build; default is Windows. */
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
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <sys/select.h>
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif
#endif
