#include "hk_mod.h"

/* hk_ports.c - listen table, wake pair, NODE/ASSIGN */
int g_lports[DT_MAXLISTEN];

void dt_record_listen(int port) {
    int i, free_i = -1;
    if (port <= 0) return;
    DLOCK();
    for (i = 0; i < DT_MAXLISTEN; i++) {
        if (g_lports[i] == port) {
            DUNLOCK();
            return;
        }
        if (free_i < 0 && g_lports[i] == 0) free_i = i;
    }
    if (free_i >= 0) g_lports[free_i] = port;
    DUNLOCK();
}
int dt_owns_listen(int port) {
    int i, own = 0;
    DLOCK();
    for (i = 0; i < DT_MAXLISTEN; i++)
        if (g_lports[i] == port) {
            own = 1;
            break;
        }
    DUNLOCK();
    return own;
}
int dt_bound_port(long long gsock) {
    struct sockaddr_in a;
#ifdef LINUX_BUILD
    socklen_t l = sizeof(a);
    if (getsockname((int)gsock, (struct sockaddr *)&a, &l) != 0) return -1;
#else
    int il = sizeof(a);
    if (getsockname((SOCKET)gsock, (struct sockaddr *)&a, &il) != 0) return -1;
#endif
    if (a.sin_family != AF_INET) return -1;
    return ntohs(a.sin_port);
}
int dt_sock_type(long long gsock) {
    int t = 0;
#ifdef LINUX_BUILD
    socklen_t l = sizeof(t);
    if (getsockopt((int)gsock, SOL_SOCKET, SO_TYPE, &t, &l) != 0) return -1;
#else
    int il = sizeof(t);
    if (getsockopt((SOCKET)gsock, SOL_SOCKET, SO_TYPE, (char *)&t, &il) != 0) return -1;
#endif
    return t;
}
int dt_rcvtimeo_ms(long long gsock) {
#ifdef LINUX_BUILD
    struct timeval tv;
    socklen_t l = sizeof(tv);
    if (getsockopt((int)gsock, SOL_SOCKET, SO_RCVTIMEO, &tv, &l) != 0) return -1;
    long ms = tv.tv_sec * 1000L + tv.tv_usec / 1000L;
    if (tv.tv_sec == 0 && tv.tv_usec == 0) return -1; /* unset = infinite */
    return (int)ms;
#else
    DWORD ms = 0;
    int l = sizeof(ms);
    if (getsockopt((SOCKET)gsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, &l) != 0) return -1;
    if (ms == 0) return -1;
    return (int)ms;
#endif
}
#ifdef LINUX_BUILD
int dt_is_nonblock(long long gsock) {
    int f = fcntl((int)gsock, F_GETFL, 0);
    return (f >= 0 && (f & O_NONBLOCK) != 0);
}
#else
struct dt_nbtrack g_nbt[DT_MAXUDP + DT_MAXSTREAM];
int dt_is_nonblock(long long gsock) {
    int nb = 0;
    DLOCK();
    for (int i = 0; i < (int)(sizeof(g_nbt) / sizeof(g_nbt[0])); i++)
        if (g_nbt[i].sock == gsock) {
            nb = g_nbt[i].nb;
            break;
        }
    DUNLOCK();
    return nb;
}
void dt_set_nonblock(long long gsock, int nb) {
    DLOCK();
    int freei = -1;
    for (int i = 0; i < (int)(sizeof(g_nbt) / sizeof(g_nbt[0])); i++) {
        if (g_nbt[i].sock == gsock) {
            g_nbt[i].nb = nb;
            DUNLOCK();
            return;
        }
        if (!g_nbt[i].sock && freei < 0) freei = i;
    }
    if (freei >= 0) {
        g_nbt[freei].sock = gsock;
        g_nbt[freei].nb = nb;
    }
    DUNLOCK();
}
#endif

/* Event-driven wake channels. Kernel readiness already drives select by
 * itself; these cover the WAITER-SIDE events: a cross-thread enqueue must
 * not wait for the sleeper's poll slice. A connected datagram pair whose
 * read end joins the sleeper's select set. Plain calls are safe here:
 * internal fds are never in the app-facing tables, so the hooks on the
 * other side of these calls pass through. Creation failure degrades to
 * slice polling (bounded, just slower). */
DTSOCK g_wake_r = DTSOCK_BAD, g_wake_w = DTSOCK_BAD;
/* MUST use real symbols: these run under DLOCK and inside app threads;
 * the hooked send/recv would re-enter the same lock (non-recursive). */
void dt_wake_write(DTSOCK w) {
    if (w == DTSOCK_BAD) return;
#ifdef LINUX_BUILD
    dt_reals();
    {
        static const char b = 1;
        ssize_t r = r_send(w, &b, 1, MSG_NOSIGNAL);
        (void)r;
    }
#else
    {
        static int(WSAAPI * fp)(SOCKET, const char *, int, int) = 0;
        if (!fp)
            fp = (int(WSAAPI *)(SOCKET, const char *, int, int))GetProcAddress(
                GetModuleHandleA("ws2_32.dll"), "send");
        if (fp) {
            static const char b = 1;
            int r = fp(w, &b, 1, 0);
            (void)r;
        }
    }
#endif
}
void dt_wake_drain(DTSOCK rd) {
    char sb[256];
#ifdef LINUX_BUILD
    dt_reals();
    while (r_recv(rd, sb, sizeof sb, MSG_DONTWAIT) > 0);
#else
    {
        static int(WSAAPI * fp)(SOCKET, char *, int, int) = 0;
        if (!fp)
            fp = (int(WSAAPI *)(SOCKET, char *, int, int))GetProcAddress(
                GetModuleHandleA("ws2_32.dll"), "recv");
        if (fp)
            while (fp(rd, sb, sizeof sb, 0) > 0);
    }
#endif
}
void dt_wake_pair(DTSOCK *rp, DTSOCK *wp) {
    *rp = *wp = DTSOCK_BAD;
#ifdef LINUX_BUILD
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, sv) == 0) {
            *rp = (DTSOCK)sv[0];
            *wp = (DTSOCK)sv[1];
        }
    }
#else
    {
        struct sockaddr_in a;
        int al = (int)sizeof(a);
        DTSOCK x = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        DTSOCK y = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (x != INVALID_SOCKET && y != INVALID_SOCKET) {
            memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (bind(x, (struct sockaddr *)&a, al) == 0 &&
                getsockname(x, (struct sockaddr *)&a, &al) == 0) {
                struct sockaddr_in me = a;
                memset(&a, 0, sizeof(a));
                a.sin_family = AF_INET;
                if (bind(y, (struct sockaddr *)&a, al) == 0 &&
                    getsockname(y, (struct sockaddr *)&a, &al) == 0) {
                    struct sockaddr_in o = a;
                    if (connect(x, (struct sockaddr *)&o, al) == 0 &&
                        connect(y, (struct sockaddr *)&me, al) == 0) {
                        u_long nb = 1;
                        ioctlsocket(x, FIONBIO, &nb);
                        ioctlsocket(y, FIONBIO, &nb);
                        *rp = y;
                        *wp = x; /* enqueue on wp, wake reader rp */
                        return;
                    }
                }
            }
        }
        if (x != INVALID_SOCKET) closesocket(x);
        if (y != INVALID_SOCKET) closesocket(y);
    }
#endif
}
void dt_tcp_queue(unsigned char type, const unsigned char *p, size_t n) {
    struct dt_frame *f = (struct dt_frame *)malloc(sizeof(*f));
    if (!f) return;
    f->type = type;
    f->n = n;
    f->next = NULL;
    f->p = n ? (unsigned char *)malloc(n) : NULL;
    if (n && !f->p) {
        free(f);
        return;
    }
    if (n) memcpy(f->p, p, n);
    DLOCK();
    if (g_sqt) g_sqt->next = f;
    else g_sqh = f;
    g_sqt = f;
    DUNLOCK();
    dt_wake_write(g_wake_w); /* send now, not at the next poll slice */
}
/* NODE token prefix: !H token_len + token. */
size_t dt_token_prefix(unsigned char *out) {
    out[0] = (unsigned char)((g_token_len >> 8) & 255);
    out[1] = (unsigned char)(g_token_len & 255);
    if (g_token_len) memcpy(out + 2, g_token, (size_t)g_token_len);
    return (size_t)(2 + g_token_len);
}
/* Called when the local game starts serving: stamp the host claim. */
void dt_send_node(void); /* defined below (payload builders) */
void dt_send_udp_node(void);
void dt_claim(void) {
    if (!g_direct || g_claimed) return;
    g_claimed = 1;
    dlog("hosting claim: game serves locally");
    dt_send_node();     /* re-register with NODE_F_HOST (queued) */
    dt_send_udp_node(); /* best-effort UDP claim now too */
}
int dt_tun_udp_port(void) {
#ifdef LINUX_BUILD
    struct sockaddr_in a;
    socklen_t l = sizeof(a);
    if (g_udptun < 0) return 0;
    if (getsockname(g_udptun, (struct sockaddr *)&a, &l) != 0) return 0;
#else
    struct sockaddr_in a;
    int l = sizeof(a);
    if (g_udptun == INVALID_SOCKET) return 0;
    if (getsockname(g_udptun, (struct sockaddr *)&a, &l) != 0) return 0;
#endif
    return ntohs(a.sin_port);
}
void dt_send_node(void) {
    unsigned char p[3 + 256 + 8];
    size_t h;
    p[0] = DT_PVER;
    h = 1 + dt_token_prefix(p + 1);
    p[h] = (unsigned char)((g_node >> 24) & 255);
    p[h + 1] = (unsigned char)((g_node >> 16) & 255);
    p[h + 2] = (unsigned char)((g_node >> 8) & 255);
    p[h + 3] = (unsigned char)(g_node & 255);
    {
        int pt = dt_tun_udp_port();
        p[h + 4] = (unsigned char)((pt >> 8) & 255);
        p[h + 5] = (unsigned char)(pt & 255);
    }
    p[h + 6] = (unsigned char)(g_claimed ? DT_NODE_F_HOST : 0);
    dt_tcp_queue(DT_NODE, p, h + 7);
}
void dt_send_udp_node(void) {
    unsigned char d[4 + 2 + 256 + 8];
    struct sockaddr_in sa;
    d[0] = 'V';
    d[1] = 'N';
    d[2] = DU_VER;
    d[3] = DU_NODE;
    size_t h = dt_token_prefix(d + 4);
    d[4 + h] = (unsigned char)((g_node >> 24) & 255);
    d[5 + h] = (unsigned char)((g_node >> 16) & 255);
    d[6 + h] = (unsigned char)((g_node >> 8) & 255);
    d[7 + h] = (unsigned char)(g_node & 255);
    {
        int pt = dt_tun_udp_port();
        d[8 + h] = (unsigned char)((pt >> 8) & 255);
        d[9 + h] = (unsigned char)(pt & 255);
    }
    d[10 + h] = (unsigned char)(g_claimed ? DT_NODE_F_HOST : 0);
    size_t n = 4 + h + 7;
    if (dt_resolve(&sa) != 0) return;
#ifdef LINUX_BUILD
    dt_reals();
    int u = g_udptun;
    if (u >= 0) r_sendto(u, d, n, 0, (struct sockaddr *)&sa, sizeof(sa));
#else
    DTSOCK u = g_udptun;
    if (u != INVALID_SOCKET)
        sendto(u, (const char *)d, (int)n, 0, (struct sockaddr *)&sa, sizeof(sa));
#endif
}
/* Numeric IP (0x0AC80002 for 10.200.0.2) from network-order bytes. */
unsigned dt_ipnum(const unsigned char *b) {
    return ((unsigned)b[0] << 24) | ((unsigned)b[1] << 16) | ((unsigned)b[2] << 8) | (unsigned)b[3];
}
/* ASSIGN: !I my_virt + !I net + !B bits + !H n + n*(!I node + !I virt),
 * all multi-byte fields big-endian on the wire. */
void dt_apply_assign(const unsigned char *p, size_t n) {
    if (n < DT_ASSIGN_HDR_N) return;
    {
        int bits = p[8];
        int cnt = ((int)p[9] << 8) | p[10];
        if (bits <= 0 || bits > 32 || cnt < 0 || cnt > DT_MAXMEMB) return;
        if (n != (size_t)(DT_ASSIGN_HDR_N + 8 * cnt)) return;
        DLOCK();
        g_myvirt = dt_ipnum(p);
        memcpy(g_vnetb, p + 4, 4);
        g_vbits = bits;
        g_nmembers = 0;
        for (int i = 0; i < cnt && i < DT_MAXMEMB; i++) {
            g_members[g_nmembers].node = dt_ipnum(p + DT_ASSIGN_HDR_N + 8 * i);
            g_members[g_nmembers].virt = dt_ipnum(p + DT_ASSIGN_HDR_N + 4 + 8 * i);
            g_nmembers++;
        }
        DUNLOCK();
    }
    g_have_assign = 1;
    {
        char lb[160];
        snprintf(lb, sizeof(lb), "assign pid=%u node=%u self=%u.%u.%u.%u members=%d",
                 (unsigned)current_pid(), g_node, (g_myvirt >> 24) & 255, (g_myvirt >> 16) & 255,
                 (g_myvirt >> 8) & 255, g_myvirt & 255, g_nmembers);
        dlog(lb);
    }
}
/* Network-order address -> node id (0 = not a known virtual peer). */
unsigned dt_virt_node(unsigned long inaddr) {
    unsigned node = 0;
    unsigned char ab[4];
    memcpy(ab, &inaddr, 4);
    DLOCK();
    if (g_nmembers > 0 && g_vbits > 0 && g_vbits <= 32) {
        int full = g_vbits / 8, rem = g_vbits % 8, ok = 1;
        if (memcmp(g_vnetb, ab, (size_t)full) != 0) ok = 0;
        else if (rem) {
            unsigned m = (0xFFu << (8 - rem)) & 0xFFu;
            if (((unsigned)g_vnetb[full] & m) != ((unsigned)ab[full] & m)) ok = 0;
        }
        if (ok && memcmp(g_vnetb, ab, 4) != 0) {
            unsigned v = dt_ipnum(ab);
            for (int i = 0; i < g_nmembers; i++)
                if (g_members[i].virt == v) {
                    node = g_members[i].node;
                    break;
                }
        }
    }
    DUNLOCK();
    return node;
}
/* node id -> virtual IP (0 = unknown). */
unsigned dt_node_virt(unsigned node) {
    unsigned virt = 0;
    DLOCK();
    for (int i = 0; i < g_nmembers; i++)
        if (g_members[i].node == node) {
            virt = g_members[i].virt;
            break;
        }
    DUNLOCK();
    return virt;
}
