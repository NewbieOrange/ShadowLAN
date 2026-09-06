/* Late-loaded plugin: mimics a game engine pulling networking plugin DLLs
 * in via LoadLibrary long after the hook installed. Exports run(void*),
 * which binds a query port and answers broadcast queries with a broadcast
 * "lobby response" on answer_port. If the hook never patches this module,
 * queries are dropped and no answer is ever emitted. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>

static volatile int g_stop = 0;

__declspec(dllexport) void run(int query_port, int answer_port) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { printf("plug socket fail %d\n", WSAGetLastError()); fflush(stdout); return; }
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons((unsigned short)query_port);
    if (bind(s, (struct sockaddr *)&a, sizeof(a))) {
        printf("plug bind fail %d\n", WSAGetLastError()); fflush(stdout);
        closesocket(s); return;
    }
    unsigned long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = INADDR_BROADCAST;
    to.sin_port = htons((unsigned short)answer_port);
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&on, sizeof(on));
    for (int i = 0; i < 3600 && !g_stop; i++) {   /* serve ~90s */
        char buf[256];
        struct sockaddr_in from;
        int fl = sizeof(from);
        int n = recvfrom(s, buf, sizeof(buf) - 32, 0, (struct sockaddr *)&from, &fl);
        if (n > 0) {
            int m = sprintf(buf, "PLUGINLOBBY answer %d", i);
            sendto(s, buf, m, 0, (struct sockaddr *)&to, sizeof(to));
        } else {
            Sleep(25);
        }
    }
    closesocket(s);
}

__declspec(dllexport) void stopper(void) { g_stop = 1; }

BOOL APIENTRY DllMain(HMODULE h, DWORD why, LPVOID r) {
    (void)r;
    if (why == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
