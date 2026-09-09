/* Harness for late-loaded module patching.
 *   test_late.exe host   : sleeps, LoadLibraryW(test_lateplug.dll), run()
 *   test_late.exe client : broadcasts queries on 45711, listens 45712
 * Client must print GOT-BCAST + GOT-UCAST and LATE_OK when the plugin
 * (loaded long after hook install) received the query through the tunnel
 * and answered both ways. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>

typedef void (*run_fn)(int, int);

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: test_late.exe host|client|clash [qport aport] [xport]\n"); return 2; }
    int qport = argc > 2 ? atoi(argv[2]) : 45711;
    int aport = argc > 3 ? atoi(argv[3]) : 45712;
    int xport = argc > 4 ? atoi(argv[4]) : 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd);
    if (!strcmp(argv[1], "clash")) {
        /* shared-port emulation: s1 owns qport plainly; s2's bind to the
         * same port must EADDRINUSE on the real stack, get aliased by
         * the hook, and still receive broadcasts addressed to qport */
        SOCKET s1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        SOCKET s2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        struct sockaddr_in p;
        memset(&p, 0, sizeof(p));
        p.sin_family = AF_INET;
        p.sin_addr.s_addr = INADDR_ANY;
        p.sin_port = htons((unsigned short)qport);
        if (bind(s1, (struct sockaddr *)&p, sizeof(p))) { printf("clash s1 fail %d\n", WSAGetLastError()); return 1; }
        int on = 1;
        setsockopt(s2, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
        if (bind(s2, (struct sockaddr *)&p, sizeof(p))) { printf("clash s2 fail %d\n", WSAGetLastError()); return 1; }
        struct sockaddr_in chk;
        int cl = sizeof(chk);
        getsockname(s2, (struct sockaddr *)&chk, &cl); /* must read as qport via alias */
        printf("clash armed aliasport=%d\n", (int)ntohs(chk.sin_port));
        int tmo = 30000;
        setsockopt(s2, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmo, sizeof(tmo));
        char buf[256];
        struct sockaddr_in from;
        int fl = sizeof(from);
        int n = recvfrom(s2, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fl);
        if (n > 0) {
            buf[n] = 0;
            printf("CLASH_OK %s from %s\n", buf, inet_ntoa(from.sin_addr));
            return 0;
        }
        printf("CLASH_NONE err=%d\n", WSAGetLastError());
        return 1;
    }
    if (!strcmp(argv[1], "ifprobe")) {
        /* Adapter-view check for the interface shim. Always: the vnode
         * must appear as a local unicast address. With LAN_HOOK_LAN_ONLY=1
         * additionally: the pseudo-adapter must be the ONLY interface, with
         * the ShadowLAN if-index and a /24 on-link prefix (a machine whose
         * only network is the tunnel). */
        int iso = 0;
        char ev[8];
        if (GetEnvironmentVariableA("LAN_HOOK_LAN_ONLY", ev, sizeof(ev)) > 0
            && ev[0] && ev[0] != '0') iso = 1;
        int found = 0, count = 0, idx_ok = 0, prefix_ok = 0;
        ULONG len = 0;
        GetAdaptersAddresses(AF_INET, 0, 0, 0, &len);
        IP_ADAPTER_ADDRESSES *ad = len ? (IP_ADAPTER_ADDRESSES *)malloc(len + 1024) : 0;
        if (ad && GetAdaptersAddresses(AF_INET, 0, 0, ad, &len) == 0) {
            IP_ADAPTER_ADDRESSES *p;
            for (p = ad; p; p = p->Next) {
                PIP_ADAPTER_UNICAST_ADDRESS u;
                count++;
                for (u = p->FirstUnicastAddress; u; u = u->Next) {
                    char *s2;
                    if (!u->Address.lpSockaddr ||
                        u->Address.lpSockaddr->sa_family != AF_INET) continue;
                    s2 = inet_ntoa(((struct sockaddr_in *)u->Address.lpSockaddr)->sin_addr);
                    if (s2 && !strncmp(s2, "10.200.", 7)) {
                        found = 1;
                        prefix_ok = (u->OnLinkPrefixLength == 24);
                        idx_ok = (p->IfIndex == 0x7F000001u);
                        printf("ifprobe iface idx=%lu addr=%s prefix=%u\n",
                               (unsigned long)p->IfIndex, s2,
                               (unsigned)u->OnLinkPrefixLength);
                    }
                }
            }
        }
        free(ad);
        {
        int found2 = 0, count2 = 0;
        ULONG l2 = 0;
        GetAdaptersInfo(NULL, &l2);
        if (l2) {
            IP_ADAPTER_INFO *i2 = (IP_ADAPTER_INFO *)malloc(l2 + 1024);
            if (i2 && GetAdaptersInfo(i2, &l2) == 0) {
                IP_ADAPTER_INFO *q;
                for (q = i2; q; q = q->Next) {
                    count2++;
                    if (!strncmp(q->IpAddressList.IpAddress.String, "10.200.", 7)) {
                        found2 = 1;
                        printf("ifprobe2 desc=%s addr=%s mask=%s\n",
                               q->Description, q->IpAddressList.IpAddress.String,
                               q->IpAddressList.IpMask.String);
                    }
                }
            }
            free(i2);
        }
        printf("ifprobe count=%d found=%d count2=%d found2=%d idx=%d prefix=%d\n",
               count, found, count2, found2, idx_ok, prefix_ok);
        fflush(stdout);
        if (!found || !found2) { printf("IF_MISS\n"); return 1; }
        if (iso) {
            if (count == 1 && count2 == 1 && idx_ok && prefix_ok) {
                printf("IF_ISO_OK\n"); return 0;
            }
            printf("IF_ISO_BAD count=%d count2=%d idx=%d prefix=%d\n",
                   count, count2, idx_ok, prefix_ok);
            return 1;
        }
        printf("IF_OK\n");
        return 0;
        }
    }
    if (!strcmp(argv[1], "host")) {
        Sleep(4000); /* well past LanHookInit: this load is "late" */
        char dir[MAX_PATH]; GetModuleFileNameA(NULL, dir, sizeof(dir));
        char *bs = strrchr(dir, '\\'); if (bs) bs[1] = 0;
        strcat(dir, "test_lateplug.dll");
        HMODULE h = LoadLibraryA(dir);
        if (!h) { printf("load failed %lu\n", GetLastError()); return 1; }
        run_fn r = (run_fn)(void *)GetProcAddress(h, "run");
        if (!r) { printf("no run export\n"); return 1; }
        /* shim check: our virtual address must appear as a local one */
        {
            ULONG len = 0;
            IP_ADAPTER_ADDRESSES *ad = 0;
            int found = 0;
            GetAdaptersAddresses(AF_INET, 0, 0, 0, &len);
            if (len) {
                ad = (IP_ADAPTER_ADDRESSES *)malloc(len + 512);
                if (ad && GetAdaptersAddresses(AF_INET, 0, 0, ad, &len) == 0) {
                    IP_ADAPTER_ADDRESSES *p;
                    for (p = ad; p && !found; p = p->Next)
                        for (PIP_ADAPTER_UNICAST_ADDRESS u = p->FirstUnicastAddress;
                             u; u = u->Next) {
                            char *s;
                            if (!u->Address.lpSockaddr ||
                                u->Address.lpSockaddr->sa_family != AF_INET) continue;
                            s = inet_ntoa(((struct sockaddr_in *)u->Address.lpSockaddr)->sin_addr);
                            if (s && !strncmp(s, "10.200.", 7)) { found = 1; printf("iface %s\n", s); }
                        }
                }
            }
            printf(found ? "IFOK\n" : "IFMISS\n");
            free(ad);
        }
        fflush(stdout);
        printf("plugin loaded late, serving\n"); fflush(stdout);
        r(qport, aport); /* blocks ~10s answering queries */
        return 0;
    }
    /* client */
    SOCKET q = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET a = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int on = 1;
    setsockopt(a, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    struct sockaddr_in ab;
    memset(&ab, 0, sizeof(ab));
    ab.sin_family = AF_INET;
    ab.sin_addr.s_addr = INADDR_ANY;
    ab.sin_port = htons((unsigned short)aport);
    if (bind(a, (struct sockaddr *)&ab, sizeof(ab))) { printf("bind fail %d\n", WSAGetLastError()); return 1; }
    unsigned long nb = 1;
    ioctlsocket(a, FIONBIO, &nb);
    struct sockaddr_in qb;
    memset(&qb, 0, sizeof(qb));
    qb.sin_family = AF_INET;
    qb.sin_addr.s_addr = INADDR_ANY;
    qb.sin_port = htons((unsigned short)qport); /* like a real lobby tool */
    setsockopt(q, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    if (bind(q, (struct sockaddr *)&qb, sizeof(qb))) { printf("qbind fail %d\n", WSAGetLastError()); return 1; }
    ioctlsocket(q, FIONBIO, &nb);
    setsockopt(q, SOL_SOCKET, SO_BROADCAST, (char *)&on, sizeof(on));
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = INADDR_BROADCAST;
    dst.sin_port = htons((unsigned short)qport);
    int got = 0, got_b = 0, got_u = 0;
    for (int i = 0; i < 300 && !got; i++) {
        sendto(q, "PLUGINQUERY", 11, 0, (struct sockaddr *)&dst, sizeof(dst));
        if (xport) {
            struct sockaddr_in xd = dst;
            xd.sin_port = htons((unsigned short)xport);
            sendto(q, "PLUGINCLASH", 12, 0, (struct sockaddr *)&xd, sizeof(xd));
        }
        for (int k = 0; k < 6 && !got; k++) {
            char buf[256];
            struct sockaddr_in from;
            int fl = sizeof(from);
            int n = recvfrom(a, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fl);
            if (n > 0) {
                buf[n] = 0;
                printf("GOT-BCAST %s from %s\n", buf, inet_ntoa(from.sin_addr));
                got_b = 1;
            }
            fl = sizeof(from);
            n = recvfrom(q, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fl);
            if (n > 0) {
                buf[n] = 0;
                printf("GOT-UCAST %s from %s\n", buf, inet_ntoa(from.sin_addr));
                got_u = 1;
            }
            got = got_b && got_u;
            Sleep(50);
        }
        Sleep(200);
    }
    printf(got ? "LATE_OK\n" : "LATE_NONE\n");
    return got ? 0 : 1;
}
