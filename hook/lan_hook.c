/* Universal LAN->relay hook. Windows DLL + Linux LD_PRELOAD test build.
 *
 * Idea: keep ports, rewrite IP. Any RFC1918 / link-local / broadcast /
 * multicast IPv4 destination becomes LAN_HOOK_RELAY (default 127.0.0.1),
 * where wclient.py already listens on the same game ports. Inbound packets
 * from the relay are spoofed back to the original LAN IP so the
 * broadcast-only game believes it talks to LAN.
 *
 * No TUN/TAP, no driver, no admin. Per-process: only the injected game
 * is affected.
 *
 * Windows: IAT patch (no asm blobs) + GetProcAddress/LoadLibrary guards.
 * Build (Linux, mingw installed):
 *   x86_64-w64-mingw32-gcc -shared -O2 -o lan_hook64.dll lan_hook.c -lws2_32
 *   i686-w64-mingw32-gcc   -shared -O2 -o lan_hook32.dll lan_hook.c -lws2_32
 *   x86_64-w64-mingw32-gcc -O2 -o injector.exe injector.c
 * Linux self-test:
 *   gcc -shared -fPIC -DLINUX_BUILD -O2 -o lan_hook.so lan_hook.c -ldl -lpthread
 */
#ifdef LINUX_BUILD
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

/* ---------- shared policy ---------- */
static unsigned long g_relay_ip = 0x0100007f; /* 127.0.0.1 network order */
static int g_only_ports[64];
static int g_nports = 0; /* 0 = all */
static int g_debug = 0;
/* direct-tunnel mode: hook dials server itself (no wclient.py needed) */
static char g_server[256] = {0};
static int g_srvport = 47777;
static int g_direct = 0;

static void policy_init(void) {
    const char *r = getenv("LAN_HOOK_RELAY");
    if (r && r[0]) {
        unsigned long v = inet_addr(r);
        if (v != INADDR_NONE) g_relay_ip = v;
    }
    const char *p = getenv("LAN_HOOK_PORTS");
    if (p && p[0]) {
        char tmp[512]; strncpy(tmp, p, sizeof(tmp) - 1); tmp[sizeof(tmp)-1] = 0;
        for (char *t = strtok(tmp, ",; "); t && g_nports < 64; t = strtok(NULL, ",; "))
            g_only_ports[g_nports++] = atoi(t);
    }
    if (getenv("LAN_HOOK_DEBUG") && getenv("LAN_HOOK_DEBUG")[0] == '1') g_debug = 1;
    const char *s = getenv("LAN_HOOK_SERVER");
    if (s && s[0]) {
        strncpy(g_server, s, sizeof(g_server) - 1);
        const char *pp = getenv("LAN_HOOK_PORT");
        if (pp && pp[0]) { int v = atoi(pp); if (v > 0 && v < 65536) g_srvport = v; }
        g_direct = 1;
    }
}

static int port_allowed(int port) {
    if (g_nports == 0) return 1;
    for (int i = 0; i < g_nports; i++) if (g_only_ports[i] == port) return 1;
    return 0;
}

/* true for 10/8, 172.16/12, 192.168/16, 169.254/16, 224-239 mcast, bcast */
static int ipv4_is_lan(unsigned long net_order) {
    unsigned long h = ntohl(net_order);
    if ((h >> 24) == 0xFF) return 1;                       /* 255.255.255.255 */
    if ((h & 0xFF000000) == 0x0A000000) return 1;           /* 10/8 */
    if ((h & 0xFFF00000) == 0xAC100000) return 1;           /* 172.16/12 */
    if ((h & 0xFFFF0000) == 0xC0A80000) return 1;           /* 192.168/16 */
    if ((h & 0xFFFF0000) == 0xA9FE0000) return 1;           /* 169.254/16 */
    if ((h & 0xF0000000) == 0xE0000000) return 1;           /* 224/4 mcast */
    if ((h & 0xFF) == 0xFF) return 1;                      /* x.x.x.255 directed bcast */
    return 0;
}

static int sockaddr_is_lan_target(const struct sockaddr *sa, int *port_out) {
    if (!sa || sa->sa_family != AF_INET) return 0;
    const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
    int port = ntohs(in->sin_port);
    if (!port_allowed(port)) return 0;
    return ipv4_is_lan(in->sin_addr.s_addr);
}

/* broadcast-ish (discovery) vs unicast LAN: bcast goes over TCP tunnel,
 * unicast game UDP over UDP tunnel */
static int ipv4_is_bcast(unsigned long net_order) {
    unsigned long h = ntohl(net_order);
    if ((h >> 24) == 0xFF) return 1;
    if ((h & 0xF0000000) == 0xE0000000) return 1;
    if ((h & 0xFF) == 0xFF) return 1;
    return 0;
}

/* socket -> original peers. UDP uses FIFO queue (one request can yield
 * many replies, so we pop in order but keep last for extra replies);
 * TCP getpeername peeks last without consuming. */
#define MAPN 256
#define MAPQ 8
struct mapent {
    long long sock; struct sockaddr_in q[MAPQ]; int qn, qhead;
    struct sockaddr_in last; int has_last; int used;
};
static struct mapent g_map[MAPN];
#ifdef LINUX_BUILD
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
#define LOCK() pthread_mutex_lock(&g_mu)
#define UNLOCK() pthread_mutex_unlock(&g_mu)
#else
static CRITICAL_SECTION g_cs; static int g_cs_init = 0;
#define LOCK() EnterCriticalSection(&g_cs)
#define UNLOCK() LeaveCriticalSection(&g_cs)
#endif

static void map_save(long long s, const struct sockaddr_in *orig) {
    LOCK();
    struct mapent *e = 0;
    int freei = -1;
    for (int i = 0; i < MAPN; i++) {
        if (g_map[i].used && g_map[i].sock == s) { e = &g_map[i]; break; }
        if (!g_map[i].used && freei < 0) freei = i;
    }
    if (!e) {
        if (freei < 0) { UNLOCK(); return; }
        e = &g_map[freei]; e->used = 1; e->sock = s; e->qn = 0; e->qhead = 0; e->has_last = 0;
    }
    if (e->qn < MAPQ) {
        e->q[(e->qhead + e->qn) % MAPQ] = *orig; e->qn++;
    } else {
        e->q[e->qhead] = *orig; e->qhead = (e->qhead + 1) % MAPQ;
    }
    e->last = *orig; e->has_last = 1;
    UNLOCK();
}
/* peek last (TCP getpeername: never consume) */
static int map_lookup(long long s, struct sockaddr_in *out) {
    int ok = 0; LOCK();
    for (int i = 0; i < MAPN; i++)
        if (g_map[i].used && g_map[i].sock == s && g_map[i].has_last) { *out = g_map[i].last; ok = 1; break; }
    UNLOCK(); return ok;
}
/* pop oldest, else last (UDP recvfrom: ordered replies + multi-reply bcast) */
static int map_next_udp(long long s, struct sockaddr_in *out) {
    int ok = 0; LOCK();
    for (int i = 0; i < MAPN; i++) {
        if (g_map[i].used && g_map[i].sock == s) {
            if (g_map[i].qn > 0) {
                *out = g_map[i].q[g_map[i].qhead];
                g_map[i].qhead = (g_map[i].qhead + 1) % MAPQ; g_map[i].qn--;
                ok = 1;
            } else if (g_map[i].has_last) { *out = g_map[i].last; ok = 1; }
            break;
        }
    }
    UNLOCK(); return ok;
}
static void map_drop(long long s) {
    LOCK();
    for (int i = 0; i < MAPN; i++)
        if (g_map[i].used && g_map[i].sock == s) g_map[i].used = 0;
    UNLOCK();
}
static int from_relay(const struct sockaddr_in *in) {
    return in && in->sin_addr.s_addr == g_relay_ip;
}

/* rewrite dest copy in place; returns 1 if rewritten (and saves orig) */
/* (inlined at call sites to keep Linux + Windows paths explicit) */

/* ================= DIRECT TUNNEL CORE (hook dials server itself) ============= */
/* Speaks server.py framing so no wclient.py is needed on the game PC.
 * Relay mode (no LAN_HOOK_SERVER) keeps the old 127.0.0.1 rewrite above.
 * Direct mode: TCP broadcast+game-TCP over one TCP link, game-UDP over UDP.
 * Include discovery UDP ports in server --udp too (unicast replies). */
#ifdef LINUX_BUILD
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/time.h>
typedef int DTSOCK;
#define DTSOCK_BAD (-1)
#else
typedef SOCKET DTSOCK;
#define DTSOCK_BAD INVALID_SOCKET
#endif

#define DT_BCAST 0x01
#define DT_OPEN  0x10
#define DT_C2S   0x11
#define DT_S2C   0x12
#define DT_CLOSE 0x13
#define DU_C2S 0x01
#define DU_S2C 0x02
#define DT_MAXSTREAM 128
#define DT_MAXUDP 128
#define DT_MAXSLOT 256
#define DT_MAXQ 64

struct dt_chunk { unsigned char *p; size_t n, off; struct dt_chunk *next; };
struct dt_dgram { unsigned char *p; size_t n; struct sockaddr_in from; struct dt_dgram *next; };
struct dt_stream { int used; long long gsock; unsigned sid; struct sockaddr_in orig;
                   struct dt_chunk *h, *t; size_t total; int dead; };
struct dt_udp { int used; long long gsock; struct dt_dgram *h, *t; int nq; int closed; };
struct dt_slot { int used; long long gsock; int game_port; struct sockaddr_in orig; };
struct dt_frame { unsigned char type; unsigned char *p; size_t n; struct dt_frame *next; };

static struct dt_stream g_st[DT_MAXSTREAM];
static struct dt_udp g_uq[DT_MAXUDP];
static struct dt_slot g_sl[DT_MAXSLOT];
static struct dt_frame *g_sqh = NULL, *g_sqt = NULL;
static unsigned g_sid = 0;
static volatile int g_tun_run = 0, g_tun_started = 0, g_tcp_up = 0;
static DTSOCK g_tcp = DTSOCK_BAD, g_udptun = DTSOCK_BAD;
static unsigned long g_fakeip = 0; /* 192.168.7.1 net order, set at start */
#ifdef LINUX_BUILD
static pthread_mutex_t g_dmu = PTHREAD_MUTEX_INITIALIZER;
#define DLOCK() pthread_mutex_lock(&g_dmu)
#define DUNLOCK() pthread_mutex_unlock(&g_dmu)
#else
static CRITICAL_SECTION g_dcs; static int g_dcs_init = 0;
#define DLOCK() EnterCriticalSection(&g_dcs)
#define DUNLOCK() LeaveCriticalSection(&g_dcs)
#endif

static void dt_msleep(int ms) {
#ifdef LINUX_BUILD
    usleep((useconds_t)ms * 1000);
#else
    Sleep(ms);
#endif
}
static void dlog(const char *m) {
    if (!g_debug) return;
#ifdef LINUX_BUILD
    fprintf(stderr, "[lan_hook] %s\n", m);
#else
    OutputDebugStringA("lan_hook: ");
    OutputDebugStringA(m);
    OutputDebugStringA("\n");
#endif
}
static void dt_put32(unsigned char *b, unsigned v) {
    b[0] = (v >> 24) & 255; b[1] = (v >> 16) & 255; b[2] = (v >> 8) & 255; b[3] = v & 255;
}
static unsigned dt_get32(const unsigned char *b) {
    return ((unsigned)b[0] << 24) | ((unsigned)b[1] << 16) | ((unsigned)b[2] << 8) | b[3];
}
static void dt_put16(unsigned char *b, unsigned v) { b[0] = (v >> 8) & 255; b[1] = v & 255; }
static unsigned dt_get16(const unsigned char *b) { return ((unsigned)b[0] << 8) | b[1]; }

/* live socket introspection (no extra hooks needed except Win nonblock) */
static int dt_bound_port(long long gsock) {
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
static int dt_sock_type(long long gsock) {
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
static int dt_rcvtimeo_ms(long long gsock) {
#ifdef LINUX_BUILD
    struct timeval tv; socklen_t l = sizeof(tv);
    if (getsockopt((int)gsock, SOL_SOCKET, SO_RCVTIMEO, &tv, &l) != 0) return -1;
    long ms = tv.tv_sec * 1000L + tv.tv_usec / 1000L;
    if (tv.tv_sec == 0 && tv.tv_usec == 0) return -1; /* unset = infinite */
    return (int)ms;
#else
    DWORD ms = 0; int l = sizeof(ms);
    if (getsockopt((SOCKET)gsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&ms, &l) != 0) return -1;
    if (ms == 0) return -1;
    return (int)ms;
#endif
}
#ifdef LINUX_BUILD
static int dt_is_nonblock(long long gsock) {
    int f = fcntl((int)gsock, F_GETFL, 0);
    return (f >= 0 && (f & O_NONBLOCK) != 0);
}
#else
static struct { long long sock; int nb; } g_nbt[DT_MAXUDP + DT_MAXSTREAM];
static int dt_is_nonblock(long long gsock) {
    int nb = 0; DLOCK();
    for (int i = 0; i < (int)(sizeof(g_nbt) / sizeof(g_nbt[0])); i++)
        if (g_nbt[i].sock == gsock) { nb = g_nbt[i].nb; break; }
    DUNLOCK(); return nb;
}
static void dt_set_nonblock(long long gsock, int nb) {
    DLOCK();
    int freei = -1;
    for (int i = 0; i < (int)(sizeof(g_nbt) / sizeof(g_nbt[0])); i++) {
        if (g_nbt[i].sock == gsock) { g_nbt[i].nb = nb; DUNLOCK(); return; }
        if (!g_nbt[i].sock && freei < 0) freei = i;
    }
    if (freei >= 0) { g_nbt[freei].sock = gsock; g_nbt[freei].nb = nb; }
    DUNLOCK();
}
#endif

static void dt_tcp_queue(unsigned char type, const unsigned char *p, size_t n) {
    struct dt_frame *f = (struct dt_frame *)malloc(sizeof(*f));
    if (!f) return;
    f->type = type; f->n = n; f->next = NULL;
    f->p = n ? (unsigned char *)malloc(n) : NULL;
    if (n && !f->p) { free(f); return; }
    if (n) memcpy(f->p, p, n);
    DLOCK();
    if (g_sqt) g_sqt->next = f; else g_sqh = f;
    g_sqt = f;
    DUNLOCK();
}
static struct dt_stream *dt_stream_by_sock(long long s) {
    for (int i = 0; i < DT_MAXSTREAM; i++)
        if (g_st[i].used && g_st[i].gsock == s) return &g_st[i];
    return NULL;
}
static struct dt_stream *dt_stream_by_sid(unsigned sid) {
    for (int i = 0; i < DT_MAXSTREAM; i++)
        if (g_st[i].used && g_st[i].sid == sid) return &g_st[i];
    return NULL;
}
static struct dt_udp *dt_udp_entry(long long s, int create) {
    for (int i = 0; i < DT_MAXUDP; i++)
        if (g_uq[i].used && g_uq[i].gsock == s) return &g_uq[i];
    if (!create) return NULL;
    for (int i = 0; i < DT_MAXUDP; i++)
        if (!g_uq[i].used) {
            g_uq[i].used = 1; g_uq[i].gsock = s;
            g_uq[i].h = g_uq[i].t = NULL; g_uq[i].nq = 0; g_uq[i].closed = 0;
            return &g_uq[i];
        }
    return NULL;
}
static void dt_udp_push(long long gsock, const unsigned char *p, size_t n,
                        const struct sockaddr_in *from) {
    DLOCK();
    struct dt_udp *e = dt_udp_entry(gsock, 1);
    if (e && !e->closed) {
        if (e->nq >= DT_MAXQ) { /* drop oldest */
            struct dt_dgram *o = e->h; e->h = o->next; if (!e->h) e->t = NULL;
            free(o->p); free(o); e->nq--;
        }
        struct dt_dgram *d = (struct dt_dgram *)malloc(sizeof(*d));
        if (d) {
            d->p = (unsigned char *)malloc(n ? n : 1);
            if (d->p) { if (n) memcpy(d->p, p, n); d->n = n; d->from = *from; d->next = NULL;
                if (e->t) e->t->next = d; else e->h = d; e->t = d; e->nq++;
#ifdef LINUX_BUILD
                { char lb[128]; snprintf(lb, sizeof(lb), "udp push gsock=%lld nq=%d n=%zu", gsock, e->nq, n); dlog(lb); }
#else
                dlog("udp push ok");
#endif
            } else free(d);
        }
    }
    DUNLOCK();
}
/* nonblocking pop; 1 = got data, 0 = empty, -1 = closed */
static int dt_udp_pop(long long gsock, unsigned char *buf, size_t blen,
                      struct sockaddr_in *from, size_t *outn) {
    int r = 0; DLOCK();
    struct dt_udp *e = dt_udp_entry(gsock, 0);
    if (e && e->closed && !e->h) r = -1;
    else if (e && e->h) {
        struct dt_dgram *d = e->h; e->h = d->next; if (!e->h) e->t = NULL; e->nq--;
        size_t n = d->n < blen ? d->n : blen;
        memcpy(buf, d->p, n); *from = d->from; *outn = n;
        free(d->p); free(d); r = 1;
    }
    DUNLOCK(); return r;
}
static struct dt_slot *dt_slot_get(long long gsock, int game_port,
                                   const struct sockaddr_in *orig) {
    for (int i = 0; i < DT_MAXSLOT; i++)
        if (g_sl[i].used && g_sl[i].gsock == gsock && g_sl[i].game_port == game_port)
            return &g_sl[i];
    for (int i = 0; i < DT_MAXSLOT; i++)
        if (!g_sl[i].used) {
            g_sl[i].used = 1; g_sl[i].gsock = gsock;
            g_sl[i].game_port = game_port; g_sl[i].orig = *orig;
            return &g_sl[i];
        }
    return NULL;
}

/* resolve server each connect (cheap, handles DNS change) */
static int dt_resolve(struct sockaddr_in *out) {
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((unsigned short)g_srvport);
    unsigned long v = inet_addr(g_server);
    if (v != INADDR_NONE) { out->sin_addr.s_addr = v; return 0; }
#ifdef LINUX_BUILD
    struct hostent *h = gethostbyname(g_server);
    if (!h || !h->h_addr_list[0]) return -1;
    memcpy(&out->sin_addr, h->h_addr_list[0], sizeof(out->sin_addr));
    return 0;
#else
    struct addrinfo hints, *res = NULL;
    char portbuf[16]; snprintf(portbuf, sizeof(portbuf), "%d", g_srvport);
    memset(&hints, 0, sizeof(hints)); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (GetAddrInfoA(g_server, portbuf, &hints, &res) != 0 || !res) return -1;
    memcpy(out, res->ai_addr, sizeof(*out));
    FreeAddrInfoA(res);
    return 0;
#endif
}

#ifdef LINUX_BUILD
/* real libc symbols for tunnel use (avoid recursing into our hooks) */
static int (*r_connect)(int, const struct sockaddr *, socklen_t) = 0;
static ssize_t (*r_send)(int, const void *, size_t, int) = 0;
static ssize_t (*r_recv)(int, void *, size_t, int) = 0;
static ssize_t (*r_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = 0;
static int (*r_close)(int) = 0;
static void dt_reals(void) {
    if (!r_connect) r_connect = dlsym(RTLD_NEXT, "connect");
    if (!r_send) r_send = dlsym(RTLD_NEXT, "send");
    if (!r_recv) r_recv = dlsym(RTLD_NEXT, "recv");
    if (!r_sendto) r_sendto = dlsym(RTLD_NEXT, "sendto");
    if (!r_close) r_close = dlsym(RTLD_NEXT, "close");
}
static int dt_send_all(int s, const unsigned char *b, size_t n) {
    dt_reals();
    while (n) { ssize_t k = r_send(s, b, n, 0); if (k <= 0) return -1; b += k; n -= (size_t)k; }
    return 0;
}
static int dt_recv_all(int s, unsigned char *b, size_t n) {
    dt_reals();
    while (n) { ssize_t k = r_recv(s, b, n, 0); if (k <= 0) return -1; b += k; n -= (size_t)k; }
    return 0;
}
#else
static int dt_send_all(SOCKET s, const unsigned char *b, size_t n) {
    while (n) { int k = send(s, (const char *)b, (int)n, 0); if (k <= 0) return -1; b += k; n -= (size_t)k; }
    return 0;
}
static int dt_recv_all(SOCKET s, unsigned char *b, size_t n) {
    while (n) { int k = recv(s, (char *)b, (int)n, 0); if (k <= 0) return -1; b += k; n -= (size_t)k; }
    return 0;
}
#endif

static void dt_dispatch_bcast(int port, const unsigned char *raw, size_t n) {
    struct sockaddr_in fake; memset(&fake, 0, sizeof(fake));
    fake.sin_family = AF_INET; fake.sin_port = htons((unsigned short)port);
    fake.sin_addr.s_addr = g_fakeip;
    DLOCK();
    for (int i = 0; i < DT_MAXUDP; i++) {
        if (!g_uq[i].used || g_uq[i].closed) continue;
        long long gs = g_uq[i].gsock;
        DUNLOCK();
        int bp = dt_bound_port(gs);
        DLOCK();
        /* re-find (table may shift); keep simple: match by gsock again */
        struct dt_udp *e = NULL;
        for (int j = 0; j < DT_MAXUDP; j++)
            if (g_uq[j].used && g_uq[j].gsock == gs) { e = &g_uq[j]; break; }
        if (e && bp == port) {
            if (e->nq < DT_MAXQ) {
                struct dt_dgram *d = (struct dt_dgram *)malloc(sizeof(*d));
                if (d) {
                    d->p = (unsigned char *)malloc(n ? n : 1);
                    if (d->p) { if (n) memcpy(d->p, raw, n); d->n = n; d->from = fake; d->next = NULL;
                        if (e->t) e->t->next = d; else e->h = d; e->t = d; e->nq++;
                    } else free(d);
                }
            }
        }
    }
    DUNLOCK();
}
static void dt_dispatch_s2c(unsigned sid, const unsigned char *raw, size_t n) {
    DLOCK();
    struct dt_stream *st = dt_stream_by_sid(sid);
    if (st && !st->dead) {
        struct dt_chunk *c = (struct dt_chunk *)malloc(sizeof(*c));
        if (c) {
            c->p = (unsigned char *)malloc(n ? n : 1);
            if (c->p) { if (n) memcpy(c->p, raw, n); c->n = n; c->off = 0; c->next = NULL;
                if (st->t) st->t->next = c; else st->h = c; st->t = c; st->total += n;
            } else free(c);
        }
    }
    DUNLOCK();
}
static void dt_dispatch_close(unsigned sid) {
    DLOCK();
    struct dt_stream *st = dt_stream_by_sid(sid);
    if (st) st->dead = 1;
    DUNLOCK();
}

/* TCP tunnel thread: one link carrying BCAST + all TCP streams */
#ifdef LINUX_BUILD
static void *dt_tcp_thread(void *u) {
#else
static DWORD WINAPI dt_tcp_thread(LPVOID u) {
#endif
    (void)u;
    unsigned char hdr[4], *pl = NULL;
    for (;;) {
        if (!g_tun_run) break;
#ifdef LINUX_BUILD
        dt_reals();
        int s = socket(AF_INET, SOCK_STREAM, 0);
#else
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#endif
#ifdef LINUX_BUILD
        if (s < 0) { dt_msleep(1000); continue; }
#else
        if (s == INVALID_SOCKET) { dt_msleep(1000); continue; }
#endif
        struct sockaddr_in sa;
        if (dt_resolve(&sa) != 0) {
#ifdef LINUX_BUILD
            r_close(s);
#else
            closesocket(s);
#endif
            dt_msleep(1000); continue;
        }
#ifdef LINUX_BUILD
        if (r_connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) { r_close(s); dt_msleep(1000); continue; }
#else
        if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) { closesocket(s); dt_msleep(1000); continue; }
#endif
#ifdef LINUX_BUILD
        g_tcp = s;
#else
        g_tcp = s;
#endif
        g_tcp_up = 1;
        dlog("tunnel TCP up");
        /* Re-announce live TCP streams: the server drops per-connection
         * streams on disconnect. Requeue OPENs at the FRONT (ahead of any
         * still-queued DATA) and drop stale queued OPENs to avoid dups. */
        DLOCK();
        {
            struct dt_frame *kept_h = NULL, *kept_t = NULL;
            struct dt_frame *f = g_sqh;
            while (f) {
                struct dt_frame *nx = f->next;
                if (f->type != DT_OPEN) {
                    f->next = NULL;
                    if (kept_t) kept_t->next = f; else kept_h = f;
                    kept_t = f;
                } else { free(f->p); free(f); }
                f = nx;
            }
            g_sqh = NULL; g_sqt = NULL;
            for (int i = 0; i < DT_MAXSTREAM; i++) {
                if (g_st[i].used && !g_st[i].dead && g_st[i].sid) {
                    unsigned char ob[6];
                    dt_put32(ob, g_st[i].sid);
                    dt_put16(ob + 4, (unsigned)ntohs(g_st[i].orig.sin_port));
                    struct dt_frame *nf = (struct dt_frame *)malloc(sizeof(*nf));
                    if (nf) {
                        nf->p = (unsigned char *)malloc(6);
                        if (nf->p) {
                            memcpy(nf->p, ob, 6); nf->type = DT_OPEN; nf->n = 6; nf->next = NULL;
                            if (g_sqt) g_sqt->next = nf; else g_sqh = nf;
                            g_sqt = nf;
                        } else free(nf);
                    }
                }
            }
            if (kept_h) {
                if (g_sqt) g_sqt->next = kept_h; else g_sqh = kept_h;
                g_sqt = kept_t;
            }
        }
        DUNLOCK();
        for (;;) {
            if (!g_tun_run) break;
            /* flush send queue */
            for (;;) {
                DLOCK();
                struct dt_frame *f = g_sqh;
                if (f) { g_sqh = f->next; if (!g_sqh) g_sqt = NULL; }
                DUNLOCK();
                if (!f) break;
                unsigned char fr[4]; dt_put32(fr, (unsigned)(1 + f->n));
                int bad = 0;
                if (dt_send_all(s, fr, 4)) bad = 1;
                else if (dt_send_all(s, &f->type, 1)) bad = 1;
                else if (f->n && dt_send_all(s, f->p, f->n)) bad = 1;
                free(f->p); free(f);
                if (bad) goto redial;
            }
            /* recv with 100ms poll */
            {
                fd_set rf; FD_ZERO(&rf);
#ifdef LINUX_BUILD
                FD_SET(s, &rf);
                struct timeval tv = {0, 100000};
                int r = select(s + 1, &rf, NULL, NULL, &tv);
#else
                FD_SET(s, &rf);
                struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 100000;
                int r = select(0, &rf, NULL, NULL, &tv);
#endif
                if (!g_tun_run) break;
                if (r < 0) goto redial;
                if (r == 0) continue;
            }
            if (dt_recv_all(s, hdr, 4)) goto redial;
            unsigned ml = dt_get32(hdr);
            if (ml < 1 || ml > 8 * 1024 * 1024) goto redial;
            if (pl) { free(pl); pl = NULL; }
            pl = (unsigned char *)malloc(ml);
            if (!pl) goto redial;
            if (dt_recv_all(s, pl, ml)) goto redial;
            unsigned char t = pl[0];
            if (t == DT_BCAST && ml >= 3) {
                dt_dispatch_bcast((int)dt_get16(pl + 1), pl + 3, ml - 3);
            } else if (t == DT_S2C && ml >= 5) {
                dt_dispatch_s2c(dt_get32(pl + 1), pl + 5, ml - 5);
            } else if (t == DT_CLOSE && ml >= 5) {
                dt_dispatch_close(dt_get32(pl + 1));
            }
        }
redial:
        g_tcp_up = 0;
        dlog("tunnel TCP redial");
#ifdef LINUX_BUILD
        r_close(s);
#else
        closesocket(s);
#endif
#ifdef LINUX_BUILD
        g_tcp = -1;
#else
        g_tcp = INVALID_SOCKET;
#endif
        if (pl) { free(pl); pl = NULL; }
        dt_msleep(1000);
    }
    if (pl) free(pl);
#ifdef LINUX_BUILD
    return NULL;
#else
    return 0;
#endif
}

/* UDP tunnel thread: game-UDP datagrams stay UDP */
#ifdef LINUX_BUILD
static void *dt_udp_thread(void *u) {
#else
static DWORD WINAPI dt_udp_thread(LPVOID u) {
#endif
    (void)u;
#ifdef LINUX_BUILD
    dt_reals();
    int s = g_udptun;
    if (s < 0) {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) return NULL;
        g_udptun = s;
    }
    for (;;) {
        if (!g_tun_run) break;
        fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
        struct timeval tv = {0, 200000};
        int r = select(s + 1, &rf, NULL, NULL, &tv);
        if (!g_tun_run) break;
        if (r <= 0) continue;
        unsigned char buf[65535];
        ssize_t n = r_recv(s, buf, sizeof(buf), 0);
        if (n <= 0) continue;
        if (n < 10 || buf[0] != 'V' || buf[1] != 'N' || buf[2] != 1 || buf[3] != DU_S2C) continue;
        dlog("udp tun: S2C in");
        int gp = dt_get16(buf + 4), il = dt_get16(buf + 6);
        if (8 + il + 2 > n) continue;
        int mp = dt_get16(buf + 8 + il);
        const unsigned char *raw = buf + 10 + il; size_t rl = (size_t)(n - 10 - il);
        int slot = mp - 50000;
        struct sockaddr_in orig; long long gs = -1; int ok = 0;
        DLOCK();
        if (slot >= 0 && slot < DT_MAXSLOT && g_sl[slot].used && g_sl[slot].game_port == gp) {
            orig = g_sl[slot].orig; gs = g_sl[slot].gsock; ok = 1;
        }
        DUNLOCK();
        if (ok) dt_udp_push(gs, raw, rl, &orig);
        else dlog("udp tun: slot miss");
    }
    return NULL;
#else
    SOCKET s = g_udptun;
    if (s == INVALID_SOCKET) {
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) return 0;
        g_udptun = s;
    }
    for (;;) {
        if (!g_tun_run) break;
        fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
        struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 200000;
        int r = select(0, &rf, NULL, NULL, &tv);
        if (!g_tun_run) break;
        if (r <= 0) continue;
        unsigned char buf[65535];
        int n = recv(s, (char *)buf, (int)sizeof(buf), 0);
        if (n <= 0) continue;
        if (n < 10 || buf[0] != 'V' || buf[1] != 'N' || buf[2] != 1 || buf[3] != DU_S2C) continue;
        int gp = dt_get16(buf + 4), il = dt_get16(buf + 6);
        if (8 + il + 2 > n) continue;
        int mp = dt_get16(buf + 8 + il);
        const unsigned char *raw = buf + 10 + il; size_t rl = (size_t)(n - 10 - il);
        int slot = mp - 50000;
        struct sockaddr_in orig; long long gs = -1; int ok = 0;
        DLOCK();
        if (slot >= 0 && slot < DT_MAXSLOT && g_sl[slot].used && g_sl[slot].game_port == gp) {
            orig = g_sl[slot].orig; gs = g_sl[slot].gsock; ok = 1;
        }
        DUNLOCK();
        if (ok) dt_udp_push(gs, raw, rl, &orig);
        else dlog("udp tun: slot miss");
    }
    return 0;
#endif
}

static void dt_start(void) {
    if (g_tun_started || !g_direct) return;
    g_tun_started = 1; g_tun_run = 1;
    g_fakeip = inet_addr("192.168.7.1");
    /* Create the UDP tunnel socket synchronously: game threads may send
     * within microseconds of the first intercepted call, before a
     * background thread would get scheduled. */
#ifdef LINUX_BUILD
    {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            struct sockaddr_in b; memset(&b, 0, sizeof(b));
            b.sin_family = AF_INET; b.sin_addr.s_addr = htonl(INADDR_ANY); b.sin_port = 0;
            if (bind(s, (struct sockaddr *)&b, sizeof(b)) != 0) { close(s); }
            else g_udptun = s;
        }
    }
#else
    {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s != INVALID_SOCKET) {
            struct sockaddr_in b; memset(&b, 0, sizeof(b));
            b.sin_family = AF_INET; b.sin_addr.s_addr = htonl(INADDR_ANY); b.sin_port = 0;
            if (bind(s, (struct sockaddr *)&b, sizeof(b)) != 0) { closesocket(s); }
            else g_udptun = s;
        }
    }
#endif
#ifdef LINUX_BUILD
    {
        pthread_t t; pthread_attr_t a; pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        pthread_create(&t, &a, dt_tcp_thread, NULL);
        pthread_create(&t, &a, dt_udp_thread, NULL);
        pthread_attr_destroy(&a);
    }
#else
    if (!g_dcs_init) { InitializeCriticalSection(&g_dcs); g_dcs_init = 1; }
    {
        HANDLE t = CreateThread(NULL, 0, dt_tcp_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
        t = CreateThread(NULL, 0, dt_udp_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
#endif
}

/* --- hook call-ins: 1 = consumed (tunnel), 0 = passthrough to real --- */
static unsigned dt_next_sid(void) {
#ifdef LINUX_BUILD
    return (unsigned)__sync_add_and_fetch(&g_sid, 1);
#else
    return (unsigned)InterlockedIncrement((volatile LONG *)&g_sid);
#endif
}
/* UDP sendto: bcast->TCP BCAST, unicast LAN->UDP GAME. -1 game-port means skip */
static int dt_on_sendto(long long gsock, const unsigned char *buf, size_t len,
                        const struct sockaddr_in *dst) {
    int port = 0;
    if (!sockaddr_is_lan_target((const struct sockaddr *)dst, &port)) return 0;
    int game_port = ntohs(dst->sin_port);
    if (ipv4_is_bcast(dst->sin_addr.s_addr)) {
        unsigned char *p = (unsigned char *)malloc(2 + len);
        if (!p) return 1;
        dt_put16(p, (unsigned)game_port);
        if (len) memcpy(p + 2, buf, len);
        dt_tcp_queue(DT_BCAST, p, 2 + len);
        free(p);
        DLOCK(); dt_udp_entry(gsock, 1); DUNLOCK();
        return 1;
    }
    DLOCK();
    struct dt_slot *sl = dt_slot_get(gsock, game_port, dst);
    int slot = sl ? (int)(sl - g_sl) : -1;
    DUNLOCK();
    if (slot < 0) { dlog("udp game: slot table full"); return 1; } /* table full: drop, pretend sent */
    /* build U_GAME_C2S: VN 01 01 | H game | H iplen | ip | H mark | raw */
    const char *mip = "127.0.0.1"; int ml = 9, mark = 50000 + slot;
    size_t n = 4 + 2 + 2 + (size_t)ml + 2 + len;
    unsigned char *d = (unsigned char *)malloc(n);
    if (!d) return 1;
    d[0] = 'V'; d[1] = 'N'; d[2] = 1; d[3] = DU_C2S;
    dt_put16(d + 4, (unsigned)game_port); dt_put16(d + 6, (unsigned)ml);
    memcpy(d + 8, mip, (size_t)ml); dt_put16(d + 8 + ml, (unsigned)mark);
    if (len) memcpy(d + 10 + ml, buf, len);
    {
        struct sockaddr_in sa;
        if (dt_resolve(&sa) == 0) {
#ifdef LINUX_BUILD
            dt_reals();
            int u = g_udptun;
            if (u >= 0) {
                ssize_t k = r_sendto(u, d, n, 0, (struct sockaddr *)&sa, sizeof(sa));
                if (k < 0) dlog("udp game: tunnel send failed");
            } else dlog("udp game: no tunnel sock yet");
#else
            DTSOCK u = g_udptun;
            if (u != INVALID_SOCKET) sendto(u, (const char *)d, (int)n, 0, (struct sockaddr *)&sa, sizeof(sa));
#endif
        } else dlog("udp game: resolve failed");
    }
    free(d);
    DLOCK(); dt_udp_entry(gsock, 1); DUNLOCK();
    return 1;
}
static int dt_on_connect(long long gsock, const struct sockaddr_in *dst) {
    int port = 0;
    if (!sockaddr_is_lan_target((const struct sockaddr *)dst, &port)) return 0;
    if (dt_sock_type(gsock) != SOCK_STREAM) return 0;
    unsigned sid = dt_next_sid();
    if (!sid) sid = dt_next_sid();
    DLOCK();
    struct dt_stream *st = NULL;
    for (int i = 0; i < DT_MAXSTREAM; i++)
        if (!g_st[i].used) { st = &g_st[i]; break; }
    if (st) {
        st->used = 1; st->gsock = gsock; st->sid = sid; st->orig = *dst;
        st->h = st->t = NULL; st->total = 0; st->dead = 0;
    }
    DUNLOCK();
    if (!st) return 1; /* table full: fake success, data dropped */
    unsigned char ob[6]; dt_put32(ob, sid); dt_put16(ob + 4, (unsigned)ntohs(dst->sin_port));
    dt_tcp_queue(DT_OPEN, ob, 6);
    return 1;
}
static int dt_stream_send(long long gsock, const unsigned char *buf, size_t len) {
    DLOCK();
    struct dt_stream *st = dt_stream_by_sock(gsock);
    int dead = st ? st->dead : 1; unsigned sid = st ? st->sid : 0;
    int ok = (st && !dead);
    DUNLOCK();
    if (!st) return 0;
    if (dead) return -1;
    unsigned char *p = (unsigned char *)malloc(4 + len);
    if (!p) return (int)len;
    dt_put32(p, sid);
    if (len) memcpy(p + 4, buf, len);
    dt_tcp_queue(DT_C2S, p, 4 + len);
    free(p);
    (void)ok; return (int)len;
}
/* pop stream bytes; 1 got (>0), 0 empty, -1 dead */
static int dt_stream_pop(long long gsock, unsigned char *buf, size_t blen, size_t *outn) {
    int r = 0; DLOCK();
    struct dt_stream *st = dt_stream_by_sock(gsock);
    if (st && st->h) {
        size_t n = st->h->n - st->h->off;
        if (n > blen) n = blen;
        memcpy(buf, st->h->p + st->h->off, n);
        st->h->off += n; st->total -= n; *outn = n; r = 1;
        if (st->h->off >= st->h->n) {
            struct dt_chunk *o = st->h; st->h = o->next; if (!st->h) st->t = NULL;
            free(o->p); free(o);
        }
    } else if (st && st->dead) r = -1;
    DUNLOCK(); return r;
}
static int dt_getpeer(long long gsock, struct sockaddr_in *out) {
    int ok = 0; DLOCK();
    struct dt_stream *st = dt_stream_by_sock(gsock);
    if (st) { *out = st->orig; ok = 1; }
    DUNLOCK(); return ok;
}
/* peek for poll/select hooks: tunnel data pending? (no consume) */
static int dt_udp_has(long long gsock) {
    int r = 0; DLOCK();
    struct dt_udp *e = dt_udp_entry(gsock, 0);
    r = (e && !e->closed && e->h) ? 1 : 0;
    DUNLOCK(); return r;
}
static int dt_stream_has(long long gsock) {
    int r = 0; DLOCK();
    struct dt_stream *st = dt_stream_by_sock(gsock);
    if (st) r = (st->h || st->dead) ? 1 : 0; /* dead reads EOF = readable */
    DUNLOCK(); return r;
}
static int dt_fd_readable(long long gsock) {
    return dt_udp_has(gsock) || dt_stream_has(gsock);
}
static void dt_on_close(long long gsock) {
    DLOCK();
    struct dt_stream *st = dt_stream_by_sock(gsock);
    unsigned sid = 0;
    if (st) { sid = st->sid; st->used = 0;
        struct dt_chunk *c = st->h; while (c) { struct dt_chunk *n = c->next; free(c->p); free(c); c = n; } }
    struct dt_udp *e = dt_udp_entry(gsock, 0);
    if (e) { e->closed = 1; e->used = 0;
        struct dt_dgram *d = e->h; while (d) { struct dt_dgram *n = d->next; free(d->p); free(d); d = n; } e->h = e->t = NULL; }
    for (int i = 0; i < DT_MAXSLOT; i++)
        if (g_sl[i].used && g_sl[i].gsock == gsock) g_sl[i].used = 0;
    DUNLOCK();
    if (sid) { unsigned char b[4]; dt_put32(b, sid); dt_tcp_queue(DT_CLOSE, b, 4); }
    map_drop(gsock);
#ifndef LINUX_BUILD
    DLOCK();
    for (int i = 0; i < (int)(sizeof(g_nbt) / sizeof(g_nbt[0])); i++)
        if (g_nbt[i].sock == gsock) g_nbt[i].sock = 0;
    DUNLOCK();
#endif
}

/* Blocking pop for hooked TCP stream bytes.
 * Returns 1 got data (*outn>0), 0 timeout/empty-nonblock, -1 dead/closed. */
static int dt_tcp_wait(long long gsock, unsigned char *buf, size_t blen,
                       size_t *outn, int timeout_ms, int nonblock) {
    long long t0 = 0;
#ifdef LINUX_BUILD
    struct timeval tv0; gettimeofday(&tv0, NULL);
    t0 = (long long)tv0.tv_sec * 1000 + tv0.tv_usec / 1000;
#else
    t0 = (long long)GetTickCount();
#endif
    for (;;) {
        int r = dt_stream_pop(gsock, buf, blen, outn);
        if (r != 0) return r;
        if (nonblock) return 0;
        long long now;
#ifdef LINUX_BUILD
        struct timeval tv; gettimeofday(&tv, NULL);
        now = (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#else
        now = (long long)GetTickCount();
#endif
        if (timeout_ms >= 0 && now - t0 >= timeout_ms) return 0;
        /* stop early if socket was closed under us */
        {
            int alive = 0; DLOCK();
            struct dt_stream *st = dt_stream_by_sock(gsock);
            alive = (st != NULL);
            DUNLOCK();
            if (!alive) return -1;
        }
        dt_msleep(10);
    }
}

#ifdef LINUX_BUILD
/* ================= Linux LD_PRELOAD test build ================= */
static void ensure_init(void) {
    static int done = 0;
    if (!done) { done = 1; policy_init(); if (g_direct) dt_start(); }
}
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest, socklen_t addrlen) {
    static ssize_t (*real_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t) = 0;
    ensure_init();
    if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");
    if (g_direct && dest && dest->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        if (dt_on_sendto((long long)sockfd, (const unsigned char *)buf, len,
                         (const struct sockaddr_in *)dest))
            return (ssize_t)len;
    }
    struct sockaddr_in cp; const struct sockaddr *dp = dest;
    if (dest && dest->sa_family == AF_INET && addrlen >= sizeof(cp)) {
        memcpy(&cp, dest, sizeof(cp));
        int port = 0;
        if (sockaddr_is_lan_target(dest, &port)) {
            struct sockaddr_in o = cp; cp.sin_addr.s_addr = g_relay_ip; map_save(sockfd, &o); dp = (struct sockaddr*)&cp;
        }
    }
    return real_sendto(sockfd, buf, len, flags, dp, addrlen);
}
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src, socklen_t *addrlen) {
    static ssize_t (*real_recvfrom)(int, void*, size_t, int, struct sockaddr*, socklen_t*) = 0;
    ensure_init();
    if (!real_recvfrom) real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    if (g_direct) {
        int st = dt_sock_type((long long)sockfd);
        { char lb[128]; snprintf(lb, sizeof(lb), "recvfrom fd=%d type=%d", sockfd, st); dlog(lb); }
        if (st == SOCK_DGRAM) {
        DLOCK(); dt_udp_entry((long long)sockfd, 1); DUNLOCK();
        int nb = dt_is_nonblock((long long)sockfd) || (flags & MSG_DONTWAIT);
        int tmo = dt_rcvtimeo_ms((long long)sockfd);
        long long t0 = 0; struct timeval tv0; gettimeofday(&tv0, NULL);
        t0 = (long long)tv0.tv_sec * 1000 + tv0.tv_usec / 1000;
        int iters = 0;
        for (;;) {
            struct sockaddr_in from; size_t on = 0;
            int pr = dt_udp_pop((long long)sockfd, (unsigned char *)buf, len, &from, &on);
            if (pr == 1) {
                if (src && addrlen && *addrlen >= sizeof(from)) { memcpy(src, &from, sizeof(from)); *addrlen = sizeof(from); }
                return (ssize_t)on;
            }
            if (pr == -1) { errno = EBADF; return -1; }
            if (++iters == 20) { char lb[128]; snprintf(lb, sizeof(lb), "recvfrom direct wait fd=%d tmo=%d nb=%d", sockfd, tmo, nb); dlog(lb); iters = 0; }
            fd_set rf; FD_ZERO(&rf); FD_SET(sockfd, &rf);
            struct timeval tv = {0, 50000};
            int rr = select(sockfd + 1, &rf, NULL, NULL, nb ? &(struct timeval){0, 0} : &tv);
            if (rr > 0) {
                struct sockaddr_in rfrom; socklen_t rfl = sizeof(rfrom);
                struct sockaddr *sp = src ? src : (struct sockaddr *)&rfrom;
                socklen_t *lp = src ? addrlen : &rfl;
                return real_recvfrom(sockfd, buf, len, flags, sp, lp);
            }
            if (nb) { errno = EAGAIN; return -1; }
            struct timeval tvn; gettimeofday(&tvn, NULL);
            long long now = (long long)tvn.tv_sec * 1000 + tvn.tv_usec / 1000;
            if (tmo >= 0 && now - t0 >= tmo) { errno = EAGAIN; return -1; }
        }
        }
    }
    struct sockaddr_in from; socklen_t fl = sizeof(from);
    struct sockaddr *sp = src ? src : (struct sockaddr*)&from;
    socklen_t *lp = src ? addrlen : &fl;
    ssize_t n = real_recvfrom(sockfd, buf, len, flags, sp, lp);
    if (n >= 0 && sp->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in*)sp;
        if (from_relay(in)) {
            struct sockaddr_in o; if (map_next_udp(sockfd, &o)) *in = o;
        }
    }
    return n;
}
ssize_t send(int s, const void *buf, size_t len, int flags) {
    static ssize_t (*real_send)(int, const void *, size_t, int) = 0;
    ensure_init();
    if (!real_send) real_send = dlsym(RTLD_NEXT, "send");
    if (g_direct) {
        int r = dt_stream_send((long long)s, (const unsigned char *)buf, len);
        if (r > 0) return (ssize_t)r;
        if (r < 0) { errno = ECONNRESET; return -1; }
    }
    return real_send(s, buf, len, flags);
}
ssize_t recv(int s, void *buf, size_t len, int flags) {
    static ssize_t (*real_recv)(int, void *, size_t, int) = 0;
    ensure_init();
    if (!real_recv) real_recv = dlsym(RTLD_NEXT, "recv");
    if (g_direct) {
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock((long long)s);
        DUNLOCK();
        if (st) {
            int nb = dt_is_nonblock((long long)s) || (flags & MSG_DONTWAIT);
            int tmo = dt_rcvtimeo_ms((long long)s);
            size_t on = 0;
            int r = dt_tcp_wait((long long)s, (unsigned char *)buf, len, &on, tmo, nb);
            if (r == 1) return (ssize_t)on;
            if (r == -1) return 0; /* EOF */
            errno = EAGAIN; return -1;
        }
    }
    return real_recv(s, buf, len, flags);
}
int my_connect_hook(int s, const struct sockaddr *a, socklen_t l) {
    static int (*real_connect)(int, const struct sockaddr*, socklen_t) = 0;
    ensure_init();
    if (!real_connect) real_connect = dlsym(RTLD_NEXT, "connect");
    if (g_direct && a && a->sa_family == AF_INET && l >= sizeof(struct sockaddr_in)) {
        if (dt_on_connect((long long)s, (const struct sockaddr_in *)a)) return 0;
    }
    struct sockaddr_in cp; const struct sockaddr *ap = a;
    if (a && a->sa_family == AF_INET && l >= sizeof(cp)) {
        memcpy(&cp, a, sizeof(cp));
        int port = 0;
        if (sockaddr_is_lan_target(a, &port)) {
            struct sockaddr_in o = cp; cp.sin_addr.s_addr = g_relay_ip; map_save(s, &o); ap = (struct sockaddr*)&cp;
        }
    }
    return real_connect(s, ap, l);
}
int connect(int s, const struct sockaddr *a, socklen_t l) { return my_connect_hook(s, a, l); }
int getpeername(int s, struct sockaddr *a, socklen_t *l) {
    static int (*real_gp)(int, struct sockaddr*, socklen_t*) = 0;
    ensure_init();
    if (!real_gp) real_gp = dlsym(RTLD_NEXT, "getpeername");
    if (g_direct && a && l && *l >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in o;
        if (dt_getpeer((long long)s, &o)) { memcpy(a, &o, sizeof(o)); *l = sizeof(o); return 0; }
    }
    int r = real_gp(s, a, l);
    if (r == 0 && a && a->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in*)a;
        if (from_relay(in)) { struct sockaddr_in o; if (map_lookup(s, &o)) *in = o; }
    }
    return r;
}
int close(int fd) {
    static int (*real_close)(int) = 0;
    if (!real_close) real_close = dlsym(RTLD_NEXT, "close");
    if (g_direct) dt_on_close((long long)fd);
    map_drop(fd);
    return real_close(fd);
}
/* poll/select must report tunnel-queued data as readable, or apps with
 * timeouts (incl. every CPython socket with settimeout) sleep in poll
 * and never call recvfrom. Slices bound tunnel latency to ~25ms. */
#include <poll.h>
#include <signal.h>
#include <sys/select.h>
static int dt_select_scan(int nfds, fd_set *r, fd_set *w, fd_set *x);
static int dt_poll_scan(struct pollfd *fds, nfds_t nfds) {
    int n = 0;
    for (nfds_t i = 0; i < nfds; i++) {
        if (fds[i].fd >= 0 && (fds[i].events & POLLIN)) {
            if (dt_fd_readable((long long)fds[i].fd)) { fds[i].revents |= POLLIN; n++; }
        }
    }
    return n;
}
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    static int (*real_poll)(struct pollfd *, nfds_t, int) = 0;
    ensure_init();
    if (!real_poll) real_poll = dlsym(RTLD_NEXT, "poll");
    if (!g_direct) return real_poll(fds, nfds, timeout);
    for (nfds_t i = 0; i < nfds; i++) fds[i].revents = 0;
    if (dt_poll_scan(fds, nfds)) {
        int n = 0;
        for (nfds_t i = 0; i < nfds; i++) if (fds[i].revents) n++;
        return n;
    }
    int waited = 0;
    for (;;) {
        int slice = 25;
        if (timeout >= 0) {
            if (waited >= timeout) return 0;
            if (timeout - waited < slice) slice = timeout - waited;
        }
        int r = real_poll(fds, nfds, slice);
        if (r < 0) return r; /* EINTR etc: preserve */
        if (r > 0) {
            dt_poll_scan(fds, nfds);
            int n = 0;
            for (nfds_t i = 0; i < nfds; i++) if (fds[i].revents) n++;
            return n ? n : r;
        }
        if (dt_poll_scan(fds, nfds)) {
            int n = 0;
            for (nfds_t i = 0; i < nfds; i++) if (fds[i].revents) n++;
            return n;
        }
        waited += slice;
        if (timeout >= 0 && waited >= timeout) return 0;
    }
}
int pselect(int nfds, fd_set *r, fd_set *w, fd_set *x,
            const struct timespec *tmo, const sigset_t *mask) {
    static int (*real_pselect)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *) = 0;
    ensure_init();
    if (!real_pselect) real_pselect = dlsym(RTLD_NEXT, "pselect");
    if (!g_direct) return real_pselect(nfds, r, w, x, tmo, mask);
    long budget = tmo ? (long)(tmo->tv_sec * 1000 + tmo->tv_nsec / 1000000) : -1;
    fd_set r0, w0, x0;
    if (r) r0 = *r; if (w) w0 = *w; if (x) x0 = *x;
    {
        struct timespec z = {0, 0};
        fd_set rr;
        if (r) rr = r0;
        else FD_ZERO(&rr);
        int qr = real_pselect(nfds, r ? &rr : NULL, NULL, NULL, &z, NULL);
        int tun = r ? dt_select_scan(nfds, &r0, NULL, NULL) : 0;
        if (qr > 0 || tun > 0) {
            if (r) {
                FD_ZERO(r);
                if (qr > 0) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, &rr)) FD_SET(fd, r);
                for (int fd = 0; fd < nfds; fd++)
                    if (FD_ISSET(fd, &r0) && dt_fd_readable((long long)fd)) FD_SET(fd, r);
            }
            if (w) FD_ZERO(w);
            if (x) FD_ZERO(x);
            int n = 0;
            if (r) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, r)) n++;
            return n;
        }
    }
    long waited = 0;
    for (;;) {
        long slice = 25;
        if (budget >= 0) {
            if (waited >= budget) {
                if (r) FD_ZERO(r); if (w) FD_ZERO(w); if (x) FD_ZERO(x);
                return 0;
            }
            if (budget - waited < slice) slice = budget - waited;
        }
        fd_set rr, ww, xx;
        if (r) rr = r0; else FD_ZERO(&rr);
        if (w) ww = w0; else FD_ZERO(&ww);
        if (x) xx = x0; else FD_ZERO(&xx);
        struct timespec tv;
        tv.tv_sec = slice / 1000; tv.tv_nsec = (slice % 1000) * 1000000;
        int rr_ = real_pselect(nfds, r ? &rr : NULL, w ? &ww : NULL, x ? &xx : NULL, &tv, mask);
        if (rr_ < 0) return rr_;
        if (rr_ > 0) {
            if (r) *r = rr; if (w) *w = ww; if (x) *x = xx;
            if (r) for (int fd = 0; fd < nfds; fd++)
                if (FD_ISSET(fd, &r0) && dt_fd_readable((long long)fd)) FD_SET(fd, r);
            int n = 0;
            if (r) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, r)) n++;
            if (w) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, w)) n++;
            if (x) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, x)) n++;
            return n ? n : rr_;
        }
        if (r && dt_select_scan(nfds, &r0, NULL, NULL)) {
            FD_ZERO(r); if (w) FD_ZERO(w); if (x) FD_ZERO(x);
            for (int fd = 0; fd < nfds; fd++)
                if (FD_ISSET(fd, &r0) && dt_fd_readable((long long)fd)) FD_SET(fd, r);
            int n = 0;
            for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, r)) n++;
            return n;
        }
        waited += slice;
        if (budget >= 0 && waited >= budget) {
            if (r) FD_ZERO(r); if (w) FD_ZERO(w); if (x) FD_ZERO(x);
            return 0;
        }
    }
}
int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo,
          const sigset_t *mask) {
    static int (*real_ppoll)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *) = 0;
    ensure_init();
    if (!real_ppoll) real_ppoll = dlsym(RTLD_NEXT, "ppoll");
    if (!g_direct) return real_ppoll(fds, nfds, tmo, mask);
    long budget = tmo ? (long)(tmo->tv_sec * 1000 + tmo->tv_nsec / 1000000) : -1;
    for (nfds_t i = 0; i < nfds; i++) fds[i].revents = 0;
    if (dt_poll_scan(fds, nfds)) {
        int n = 0;
        for (nfds_t i = 0; i < nfds; i++) if (fds[i].revents) n++;
        return n;
    }
    long waited = 0;
    for (;;) {
        struct timespec cur = {0, 25000000};
        if (budget >= 0) {
            if (waited >= budget) return 0;
            long rem = budget - waited;
            if (rem < 25) { cur.tv_sec = 0; cur.tv_nsec = rem * 1000000; }
        }
        int r = real_ppoll(fds, nfds, &cur, mask);
        if (r < 0) return r;
        if (r > 0) {
            dt_poll_scan(fds, nfds);
            int n = 0;
            for (nfds_t i = 0; i < nfds; i++) if (fds[i].revents) n++;
            return n ? n : r;
        }
        if (dt_poll_scan(fds, nfds)) {
            int n = 0;
            for (nfds_t i = 0; i < nfds; i++) if (fds[i].revents) n++;
            return n;
        }
        waited += 25;
        if (budget >= 0 && waited >= budget) return 0;
    }
}
static int dt_select_scan(int nfds, fd_set *r, fd_set *w, fd_set *x) {
    int n = 0;
    if (r) {
        for (int fd = 0; fd < nfds; fd++) {
            if (FD_ISSET(fd, r) && dt_fd_readable((long long)fd)) n++;
            /* NB: keep FD_ISSET as-is; readable mark = bit already set.
             * We only count here; real select result merged by caller. */
        }
    }
    (void)w; (void)x;
    return n;
}
int select(int nfds, fd_set *r, fd_set *w, fd_set *x, struct timeval *tmo) {
    static int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *) = 0;
    ensure_init();
    if (!real_select) real_select = dlsym(RTLD_NEXT, "select");
    if (!g_direct) return real_select(nfds, r, w, x, tmo);
    long budget = tmo ? (long)(tmo->tv_sec * 1000 + tmo->tv_usec / 1000) : -1;
    fd_set r0, w0, x0;
    if (r) r0 = *r; if (w) w0 = *w; if (x) x0 = *x;
    /* fast path: tunnel data already pending? */
    {
        struct timeval z = {0, 0};
        fd_set rr; FD_ZERO(&rr); if (r) rr = r0;
        int qr = real_select(nfds, r ? &rr : NULL, NULL, NULL, &z);
        int tun = r ? dt_select_scan(nfds, &r0, NULL, NULL) : 0;
        if (qr > 0 || tun > 0) {
            if (r) {
                FD_ZERO(r);
                if (qr > 0) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, &rr)) FD_SET(fd, r);
                for (int fd = 0; fd < nfds; fd++)
                    if (FD_ISSET(fd, &r0) && dt_fd_readable((long long)fd)) FD_SET(fd, r);
            }
            if (w) FD_ZERO(w);
            if (x) FD_ZERO(x);
            int n = 0;
            if (r) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, r)) n++;
            return n;
        }
    }
    long waited = 0;
    for (;;) {
        long slice = 25;
        if (budget >= 0) {
            if (waited >= budget) {
                if (r) FD_ZERO(r); if (w) FD_ZERO(w); if (x) FD_ZERO(x);
                return 0;
            }
            if (budget - waited < slice) slice = budget - waited;
        }
        fd_set rr, ww, xx;
        FD_ZERO(&rr); FD_ZERO(&ww); FD_ZERO(&xx);
        if (r) rr = r0; if (w) ww = w0; if (x) xx = x0;
        struct timeval tv;
        tv.tv_sec = slice / 1000; tv.tv_usec = (slice % 1000) * 1000;
        int rr_ = real_select(nfds, r ? &rr : NULL, w ? &ww : NULL, x ? &xx : NULL, &tv);
        if (rr_ < 0) return rr_;
        if (rr_ > 0) {
            if (r) *r = rr; if (w) *w = ww; if (x) *x = xx;
            if (r) for (int fd = 0; fd < nfds; fd++)
                if (FD_ISSET(fd, &r0) && dt_fd_readable((long long)fd)) FD_SET(fd, r);
            int n = 0;
            if (r) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, r)) n++;
            if (w) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, w)) n++;
            if (x) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, x)) n++;
            return n ? n : rr_;
        }
        if (r && dt_select_scan(nfds, &r0, NULL, NULL)) {
            FD_ZERO(r); if (w) FD_ZERO(w); if (x) FD_ZERO(x);
            for (int fd = 0; fd < nfds; fd++)
                if (FD_ISSET(fd, &r0) && dt_fd_readable((long long)fd)) FD_SET(fd, r);
            int n = 0;
            for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, r)) n++;
            return n;
        }
        waited += slice;
        if (budget >= 0 && waited >= budget) {
            if (r) FD_ZERO(r); if (w) FD_ZERO(w); if (x) FD_ZERO(x);
            return 0;
        }
    }
}
#else
/* ================= Windows DLL ================= */
typedef int (WSAAPI *PFN_sendto)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI *PFN_recvfrom)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WSAAPI *PFN_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *PFN_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *PFN_connect)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *PFN_WSAConnect)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int (WSAAPI *PFN_getpeername)(SOCKET, struct sockaddr*, int*);
typedef int (WSAAPI *PFN_closesocket)(SOCKET);
typedef int (WSAAPI *PFN_send)(SOCKET, const char*, int, int);
typedef int (WSAAPI *PFN_recv)(SOCKET, char*, int, int);
typedef int (WSAAPI *PFN_WSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *PFN_WSARecv)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *PFN_ioctlsocket)(SOCKET, long, u_long*);
typedef FARPROC (WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);

static PFN_sendto p_sendto = 0; static PFN_recvfrom p_recvfrom = 0;
static PFN_WSASendTo p_WSASendTo = 0; static PFN_WSARecvFrom p_WSARecvFrom = 0;
static PFN_connect p_connect = 0; static PFN_WSAConnect p_WSAConnect = 0;
static PFN_getpeername p_getpeername = 0; static PFN_closesocket p_closesocket = 0;
static PFN_send p_send = 0; static PFN_recv p_recv = 0;
static PFN_WSASend p_WSASend = 0; static PFN_WSARecv p_WSARecv = 0;
static PFN_ioctlsocket p_ioctlsocket = 0;
static HMODULE g_hself = 0;
static PFN_GetProcAddress p_GetProcAddress = 0;
static HMODULE hWS2 = 0, hKernel = 0;

static void dbg(const char *m) {
    if (!g_debug) return;
    OutputDebugStringA(m);
}

/* Direct-tunnel UDP recv multiplex: tunnel queue first, then real socket.
 * Returns like recvfrom (n bytes, SOCKET_ERROR + WSA code on empty). */
static int dt_win_udp_recv(SOCKET s, char *buf, int len, int flags,
                           struct sockaddr *from, int *fromlen) {
    DLOCK(); dt_udp_entry((long long)s, 1); DUNLOCK();
    int nb = dt_is_nonblock((long long)s);
    int tmo = dt_rcvtimeo_ms((long long)s);
    DWORD t0 = GetTickCount();
    for (;;) {
        struct sockaddr_in tfrom; size_t on = 0;
        int pr = dt_udp_pop((long long)s, (unsigned char *)buf, (size_t)len, &tfrom, &on);
        if (pr == 1) {
            if (from && fromlen && *fromlen >= (int)sizeof(tfrom)) {
                memcpy(from, &tfrom, sizeof(tfrom)); *fromlen = sizeof(tfrom);
            }
            return (int)on;
        }
        if (pr == -1) { WSASetLastError(WSAEBADF); return SOCKET_ERROR; }
        fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
        struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 50000;
        struct timeval ztv; ztv.tv_sec = 0; ztv.tv_usec = 0;
        int rr = select(0, &rf, NULL, NULL, nb ? &ztv : &tv);
        if (rr > 0) {
            int n = p_recvfrom(s, buf, len, flags, from, fromlen);
            if (n != SOCKET_ERROR && from && from->sa_family == AF_INET) {
                struct sockaddr_in *in = (struct sockaddr_in *)from;
                if (!g_direct && from_relay(in)) {
                    struct sockaddr_in o;
                    if (map_next_udp((long long)s, &o)) *in = o;
                }
            }
            return n;
        }
        if (nb) { WSASetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
        if (tmo >= 0 && (int)(GetTickCount() - t0) >= tmo) {
            WSASetLastError(WSAETIMEDOUT); return SOCKET_ERROR;
        }
    }
}

int WSAAPI hk_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
    if (g_direct && to && to->sa_family == AF_INET && tolen >= (int)sizeof(struct sockaddr_in)) {
        if (dt_on_sendto((long long)s, (const unsigned char *)buf, (size_t)(len < 0 ? 0 : len),
                         (const struct sockaddr_in *)to))
            return len;
    }
    struct sockaddr_in cp; const struct sockaddr *tp = to;
    if (to && to->sa_family == AF_INET && tolen >= (int)sizeof(cp)) {
        int port = 0;
        if (sockaddr_is_lan_target(to, &port)) {
            memcpy(&cp, to, sizeof(cp));
            struct sockaddr_in o = cp; cp.sin_addr.s_addr = g_relay_ip;
            map_save((long long)s, &o); tp = (struct sockaddr*)&cp;
            dbg("lan_hook: sendto redirected\n");
        }
    }
    return p_sendto(s, buf, len, flags, tp, tolen);
}
int WSAAPI hk_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) {
    if (g_direct && dt_sock_type((long long)s) == SOCK_DGRAM)
        return dt_win_udp_recv(s, buf, len, flags, from, fromlen);
    int n = p_recvfrom(s, buf, len, flags, from, fromlen);
    if (n != SOCKET_ERROR && from && from->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in*)from;
        if (from_relay(in)) { struct sockaddr_in o; if (map_next_udp((long long)s, &o)) *in = o; }
    }
    return n;
}
int WSAAPI hk_WSASendTo(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD sent, DWORD flags,
                        const struct sockaddr *to, int tolen,
                        LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (g_direct && !ov && !cr && to && to->sa_family == AF_INET && tolen >= (int)sizeof(struct sockaddr_in)) {
        /* gather bufs (usually 1) */
        size_t total = 0;
        for (DWORD i = 0; i < nb; i++) total += b[i].len;
        unsigned char *tmp = (unsigned char *)malloc(total ? total : 1);
        if (tmp) {
            size_t off = 0;
            for (DWORD i = 0; i < nb; i++) { memcpy(tmp + off, b[i].buf, b[i].len); off += b[i].len; }
            int consumed = dt_on_sendto((long long)s, tmp, total, (const struct sockaddr_in *)to);
            free(tmp);
            if (consumed) { if (sent) *sent = (DWORD)total; return 0; }
        }
    }
    struct sockaddr_in cp; const struct sockaddr *tp = to;
    if (to && to->sa_family == AF_INET && tolen >= (int)sizeof(cp)) {
        int port = 0;
        if (sockaddr_is_lan_target(to, &port)) {
            memcpy(&cp, to, sizeof(cp));
            struct sockaddr_in o = cp; cp.sin_addr.s_addr = g_relay_ip;
            map_save((long long)s, &o); tp = (struct sockaddr*)&cp;
        }
    }
    return p_WSASendTo(s, b, nb, sent, flags, tp, tolen, ov, cr);
}
int WSAAPI hk_WSARecvFrom(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD recvd, LPDWORD flags,
                          struct sockaddr *from, LPINT fromlen,
                          LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (ov) return p_WSARecvFrom(s, b, nb, recvd, flags, from, fromlen, ov, cr);
    if (g_direct && dt_sock_type((long long)s) == SOCK_DGRAM && nb == 1) {
        int fl = fromlen ? *fromlen : 0;
        int dwflags = flags ? (int)*flags : 0;
        int n = dt_win_udp_recv(s, b[0].buf, (int)b[0].len, dwflags, from, &fl);
        if (n == SOCKET_ERROR) return SOCKET_ERROR;
        if (recvd) *recvd = (DWORD)n;
        if (fromlen) *fromlen = fl;
        if (flags) *flags = 0;
        return 0;
    }
    int n = p_WSARecvFrom(s, b, nb, recvd, flags, from, fromlen, NULL, NULL);
    if (n == 0 && from && from->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in*)from;
        if (from_relay(in)) { struct sockaddr_in o; if (map_next_udp((long long)s, &o)) *in = o; }
    }
    return n;
}
int WSAAPI hk_connect(SOCKET s, const struct sockaddr *a, int l) {
    if (g_direct && a && a->sa_family == AF_INET && l >= (int)sizeof(struct sockaddr_in)) {
        if (dt_on_connect((long long)s, (const struct sockaddr_in *)a)) {
            dbg("lan_hook: connect tunneled\n");
            return 0;
        }
    }
    struct sockaddr_in cp; const struct sockaddr *ap = a;
    if (a && a->sa_family == AF_INET && l >= (int)sizeof(cp)) {
        int port = 0;
        if (sockaddr_is_lan_target(a, &port)) {
            memcpy(&cp, a, sizeof(cp));
            struct sockaddr_in o = cp; cp.sin_addr.s_addr = g_relay_ip;
            map_save((long long)s, &o); ap = (struct sockaddr*)&cp;
            dbg("lan_hook: connect redirected\n");
        }
    }
    return p_connect(s, ap, l);
}
int WSAAPI hk_WSAConnect(SOCKET s, const struct sockaddr *a, int l, LPWSABUF b1, LPWSABUF b2, LPQOS q1, LPQOS q2) {
    if (g_direct && a && a->sa_family == AF_INET && l >= (int)sizeof(struct sockaddr_in)) {
        if (dt_on_connect((long long)s, (const struct sockaddr_in *)a)) return 0;
    }
    struct sockaddr_in cp; const struct sockaddr *ap = a;
    if (a && a->sa_family == AF_INET && l >= (int)sizeof(cp)) {
        int port = 0;
        if (sockaddr_is_lan_target(a, &port)) {
            memcpy(&cp, a, sizeof(cp));
            struct sockaddr_in o = cp; cp.sin_addr.s_addr = g_relay_ip;
            map_save((long long)s, &o); ap = (struct sockaddr*)&cp;
        }
    }
    return p_WSAConnect(s, ap, l, b1, b2, q1, q2);
}
int WSAAPI hk_getpeername(SOCKET s, struct sockaddr *a, int *l) {
    if (g_direct && a && l && *l >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in o;
        if (dt_getpeer((long long)s, &o)) { memcpy(a, &o, sizeof(o)); *l = sizeof(o); return 0; }
    }
    int r = p_getpeername(s, a, l);
    if (r == 0 && a && a->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in*)a;
        if (from_relay(in)) { struct sockaddr_in o; if (map_lookup((long long)s, &o)) *in = o; }
    }
    return r;
}
int WSAAPI hk_closesocket(SOCKET s) {
    if (g_direct) dt_on_close((long long)s);
    map_drop((long long)s);
    return p_closesocket(s);
}

/* Connected-socket byte path for direct-tunnel TCP streams. */
int WSAAPI hk_send(SOCKET s, const char *buf, int len, int flags) {
    (void)flags;
    if (g_direct) {
        int r = dt_stream_send((long long)s, (const unsigned char *)buf, (size_t)(len < 0 ? 0 : len));
        if (r > 0) return r;
        if (r < 0) { WSASetLastError(WSAECONNRESET); return SOCKET_ERROR; }
    }
    return p_send(s, buf, len, flags);
}
int WSAAPI hk_recv(SOCKET s, char *buf, int len, int flags) {
    (void)flags;
    if (g_direct) {
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock((long long)s);
        DUNLOCK();
        if (st) {
            int nb = dt_is_nonblock((long long)s);
            int tmo = dt_rcvtimeo_ms((long long)s);
            size_t on = 0;
            int r = dt_tcp_wait((long long)s, (unsigned char *)buf, (size_t)(len < 0 ? 0 : len), &on, tmo, nb);
            if (r == 1) return (int)on;
            if (r == -1) return 0;
            WSASetLastError(nb ? WSAEWOULDBLOCK : WSAETIMEDOUT);
            return SOCKET_ERROR;
        }
    }
    return p_recv(s, buf, len, flags);
}
int WSAAPI hk_WSASend(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD sent, DWORD flags,
                      LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (g_direct && !ov && !cr) {
        size_t total = 0;
        for (DWORD i = 0; i < nb; i++) total += b[i].len;
        unsigned char *tmp = (unsigned char *)malloc(total ? total : 1);
        if (tmp) {
            size_t off = 0;
            for (DWORD i = 0; i < nb; i++) { memcpy(tmp + off, b[i].buf, b[i].len); off += b[i].len; }
            int r = dt_stream_send((long long)s, tmp, total);
            free(tmp);
            if (r > 0) { if (sent) *sent = (DWORD)r; return 0; }
            if (r < 0) { WSASetLastError(WSAECONNRESET); return SOCKET_ERROR; }
        }
    }
    return p_WSASend(s, b, nb, sent, flags, ov, cr);
}
int WSAAPI hk_WSARecv(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD recvd, LPDWORD flags,
                      LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (g_direct && !ov && !cr && nb == 1) {
        int nbk = dt_is_nonblock((long long)s);
        int tmo = dt_rcvtimeo_ms((long long)s);
        size_t on = 0;
        int have = 0;
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock((long long)s);
        have = (st != NULL);
        DUNLOCK();
        if (have) {
            int r = dt_tcp_wait((long long)s, (unsigned char *)b[0].buf, (size_t)b[0].len, &on, tmo, nbk);
            if (r == 1) { if (recvd) *recvd = (DWORD)on; if (flags) *flags = 0; return 0; }
            if (r == -1) { if (recvd) *recvd = 0; return 0; }
            WSASetLastError(nbk ? WSAEWOULDBLOCK : WSAETIMEDOUT);
            return SOCKET_ERROR;
        }
    }
    return p_WSARecv(s, b, nb, recvd, flags, ov, cr);
}
int WSAAPI hk_ioctlsocket(SOCKET s, long cmd, u_long *argp) {
    int r = p_ioctlsocket(s, cmd, argp);
    if (r == 0 && cmd == (long)FIONBIO && argp) dt_set_nonblock((long long)s, *argp ? 1 : 0);
    return r;
}
/* select/WSAPoll must report tunnel data readable (same reason as Linux). */
int WSAAPI hk_select(int nfds, fd_set *r, fd_set *w, fd_set *x, const struct timeval *tmo) {
    typedef int (WSAAPI *PFN_select)(int, fd_set *, fd_set *, fd_set *, const struct timeval *);
    static PFN_select p_sel = 0;
    if (!p_sel) p_sel = (PFN_select)GetProcAddress(hWS2 ? hWS2 : GetModuleHandleA("ws2_32.dll"), "select");
    if (!g_direct) return p_sel(nfds, r, w, x, tmo);
    long budget = tmo ? (long)(tmo->tv_sec * 1000 + tmo->tv_usec / 1000) : -1;
    fd_set r0, w0, x0;
    FD_ZERO(&r0); FD_ZERO(&w0); FD_ZERO(&x0);
    if (r) r0 = *r; if (w) w0 = *w; if (x) x0 = *x;
    {
        fd_set rq = r0, wq = w0, xq = x0;
        struct timeval z = {0, 0};
        int qr = ((r || w || x)) ? p_sel(nfds, r ? &rq : NULL, w ? &wq : NULL, x ? &xq : NULL, &z) : 0;
        if (qr < 0) return qr;
        int n = 0;
        if (r) {
            FD_ZERO(r);
            for (u_int i = 0; i < rq.fd_count; i++) FD_SET(rq.fd_array[i], r);
            for (u_int i = 0; i < r0.fd_count; i++)
                if (dt_fd_readable((long long)r0.fd_array[i])) FD_SET(r0.fd_array[i], r);
            for (u_int i = 0; i < r->fd_count; i++) n++;
        }
        if (w) { *w = wq; for (u_int i = 0; i < w->fd_count; i++) n++; }
        if (x) { *x = xq; for (u_int i = 0; i < x->fd_count; i++) n++; }
        if (n) return n;
    }
    long waited = 0;
    for (;;) {
        long slice = 25;
        if (budget >= 0) {
            if (waited >= budget) {
                if (r) FD_ZERO(r); if (w) FD_ZERO(w); if (x) FD_ZERO(x);
                return 0;
            }
            if (budget - waited < slice) slice = budget - waited;
        }
        fd_set rq = r0, wq = w0, xq = x0;
        struct timeval tv;
        tv.tv_sec = slice / 1000; tv.tv_usec = (slice % 1000) * 1000;
        int rr_ = p_sel(nfds, r ? &rq : NULL, w ? &wq : NULL, x ? &xq : NULL, &tv);
        if (rr_ < 0) return rr_;
        {
            int n = 0;
            if (r) {
                FD_ZERO(r);
                if (rr_ > 0) for (u_int i = 0; i < rq.fd_count; i++) FD_SET(rq.fd_array[i], r);
                for (u_int i = 0; i < r0.fd_count; i++)
                    if (dt_fd_readable((long long)r0.fd_array[i])) FD_SET(r0.fd_array[i], r);
                for (u_int i = 0; i < r->fd_count; i++) n++;
            }
            if (w && rr_ > 0) { *w = wq; for (u_int i = 0; i < w->fd_count; i++) n++; }
            else if (w) FD_ZERO(w);
            if (x && rr_ > 0) { *x = xq; for (u_int i = 0; i < x->fd_count; i++) n++; }
            else if (x) FD_ZERO(x);
            if (n) return n;
        }
        waited += slice;
        if (budget >= 0 && waited >= budget) {
            if (r) FD_ZERO(r); if (w) FD_ZERO(w); if (x) FD_ZERO(x);
            return 0;
        }
    }
}
int WSAAPI hk_WSAPoll(LPWSAPOLLFD fds, ULONG nfds, INT timeout) {
    typedef int (WSAAPI *PFN_WSAPoll)(LPWSAPOLLFD, ULONG, INT);
    static PFN_WSAPoll p_p = 0;
    if (!p_p) p_p = (PFN_WSAPoll)GetProcAddress(hWS2 ? hWS2 : GetModuleHandleA("ws2_32.dll"), "WSAPoll");
    if (!g_direct) return p_p(fds, nfds, timeout);
    for (ULONG i = 0; i < nfds; i++) fds[i].revents = 0;
    {
        int n = 0;
        for (ULONG i = 0; i < nfds; i++)
            if ((fds[i].events & POLLRDNORM) && dt_fd_readable((long long)fds[i].fd)) {
                fds[i].revents |= POLLRDNORM; n++;
            }
        if (n) return n;
    }
    int waited = 0;
    for (;;) {
        int slice = 25;
        if (timeout >= 0) {
            if (waited >= timeout) return 0;
            if (timeout - waited < slice) slice = timeout - waited;
        }
        int r = p_p(fds, nfds, slice);
        if (r < 0) return r;
        int n = 0;
        for (ULONG i = 0; i < nfds; i++)
            if ((fds[i].events & POLLRDNORM) && dt_fd_readable((long long)fds[i].fd)) {
                if (!(fds[i].revents & POLLRDNORM)) fds[i].revents |= POLLRDNORM;
            }
        for (ULONG i = 0; i < nfds; i++) if (fds[i].revents) n++;
        if (n) return n;
        if (r < 0) return r;
        waited += slice;
        if (timeout >= 0 && waited >= timeout) return 0;
    }
}

/* If game resolves exports dynamically, hand out our hooks. */
FARPROC WINAPI hk_GetProcAddress(HMODULE m, LPCSTR n) {
    if (n && ((ULONG_PTR)n >> 16)) {
        char mod[MAX_PATH] = {0};
        GetModuleFileNameA(m, mod, sizeof(mod)-1);
        int isws2 = 0;
        for (char *p = mod; *p; p++) if ((p[0]=='w'||p[0]=='W')&&(p[1]=='s'||p[1]=='S')) { isws2 = 1; break; }
        if (isws2 || m == hWS2) {
            if (!strcmp(n,"sendto")) return (FARPROC)hk_sendto;
            if (!strcmp(n,"recvfrom")) return (FARPROC)hk_recvfrom;
            if (!strcmp(n,"WSASendTo")) return (FARPROC)hk_WSASendTo;
            if (!strcmp(n,"WSARecvFrom")) return (FARPROC)hk_WSARecvFrom;
            if (!strcmp(n,"connect")) return (FARPROC)hk_connect;
            if (!strcmp(n,"WSAConnect")) return (FARPROC)hk_WSAConnect;
            if (!strcmp(n,"getpeername")) return (FARPROC)hk_getpeername;
            if (!strcmp(n,"closesocket")) return (FARPROC)hk_closesocket;
            if (!strcmp(n,"send")) return (FARPROC)hk_send;
            if (!strcmp(n,"recv")) return (FARPROC)hk_recv;
            if (!strcmp(n,"WSASend")) return (FARPROC)hk_WSASend;
            if (!strcmp(n,"WSARecv")) return (FARPROC)hk_WSARecv;
            if (!strcmp(n,"ioctlsocket")) return (FARPROC)hk_ioctlsocket;
            if (!strcmp(n,"select")) return (FARPROC)hk_select;
            if (!strcmp(n,"WSAPoll")) return (FARPROC)hk_WSAPoll;
        }
    }
    return p_GetProcAddress(m, n);
}

static void patch_iat(HMODULE mod) {
    if (!mod) return;
    {
        BYTE *base = (BYTE*)mod;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;
        IMAGE_DATA_DIRECTORY *impdir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!impdir->VirtualAddress) return;
        IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + impdir->VirtualAddress);
        for (; desc->Name; desc++) {
            char *dll = (char*)(base + desc->Name);
            int isws2 = (_stricmp(dll, "ws2_32.dll") == 0);
            int isk32 = (_stricmp(dll, "kernel32.dll") == 0);
            if (!isws2 && !isk32) continue;
            IMAGE_THUNK_DATA *orig = desc->OriginalFirstThunk ?
                (IMAGE_THUNK_DATA*)(base + desc->OriginalFirstThunk) : 0;
            IMAGE_THUNK_DATA *iat = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
            for (; iat->u1.Function; iat++, orig ? orig++ : 0) {
                if (IMAGE_SNAP_BY_ORDINAL(iat->u1.Ordinal)) continue;
                IMAGE_IMPORT_BY_NAME *nm = 0;
                if (orig) nm = (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
                else nm = (IMAGE_IMPORT_BY_NAME*)(base + iat->u1.AddressOfData);
                if (!nm) continue;
                char *fn = (char*)nm->Name;
                FARPROC rep = 0;
                if (isws2) {
                    if (!strcmp(fn,"sendto")) rep = (FARPROC)hk_sendto;
                    else if (!strcmp(fn,"recvfrom")) rep = (FARPROC)hk_recvfrom;
                    else if (!strcmp(fn,"WSASendTo")) rep = (FARPROC)hk_WSASendTo;
                    else if (!strcmp(fn,"WSARecvFrom")) rep = (FARPROC)hk_WSARecvFrom;
                    else if (!strcmp(fn,"connect")) rep = (FARPROC)hk_connect;
                    else if (!strcmp(fn,"WSAConnect")) rep = (FARPROC)hk_WSAConnect;
                    else if (!strcmp(fn,"getpeername")) rep = (FARPROC)hk_getpeername;
                    else if (!strcmp(fn,"closesocket")) rep = (FARPROC)hk_closesocket;
                    else if (!strcmp(fn,"send")) rep = (FARPROC)hk_send;
                    else if (!strcmp(fn,"recv")) rep = (FARPROC)hk_recv;
                    else if (!strcmp(fn,"WSASend")) rep = (FARPROC)hk_WSASend;
                    else if (!strcmp(fn,"WSARecv")) rep = (FARPROC)hk_WSARecv;
                    else if (!strcmp(fn,"ioctlsocket")) rep = (FARPROC)hk_ioctlsocket;
                    else if (!strcmp(fn,"select")) rep = (FARPROC)hk_select;
                    else if (!strcmp(fn,"WSAPoll")) rep = (FARPROC)hk_WSAPoll;
                } else if (isk32 && !strcmp(fn,"GetProcAddress")) {
                    rep = (FARPROC)hk_GetProcAddress;
                }
                if (rep) {
                    DWORD old = 0;
                    if (VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) {
                        iat->u1.Function = (ULONG_PTR)rep;
                        VirtualProtect(&iat->u1.Function, sizeof(void*), old, &old);
                    }
                }
            }
        }
    }
}

static void patch_all(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) { patch_iat(GetModuleHandleA(NULL)); return; }
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    /* skip our own module: tunnel threads must call the real Winsock */
    if (Module32First(snap, &me)) do {
        if (me.hModule != g_hself) patch_iat(me.hModule);
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
}

/* LoadLibrary hooks: patch newcomers too. */
static PFN_LoadLibraryA p_LoadLibraryA = 0; static PFN_LoadLibraryW p_LoadLibraryW = 0;
static PFN_LoadLibraryExA p_LoadLibraryExA = 0; static PFN_LoadLibraryExW p_LoadLibraryExW = 0;
HMODULE WINAPI hk_LoadLibraryA(LPCSTR n) { HMODULE h = p_LoadLibraryA(n); if (h && h != g_hself) patch_iat(h); return h; }
HMODULE WINAPI hk_LoadLibraryW(LPCWSTR n) { HMODULE h = p_LoadLibraryW(n); if (h && h != g_hself) patch_iat(h); return h; }
HMODULE WINAPI hk_LoadLibraryExA(LPCSTR n, HANDLE f, DWORD fl) { HMODULE h = p_LoadLibraryExA(n,f,fl); if (h && h != g_hself) patch_iat(h); return h; }
HMODULE WINAPI hk_LoadLibraryExW(LPCWSTR n, HANDLE f, DWORD fl) { HMODULE h = p_LoadLibraryExW(n,f,fl); if (h && h != g_hself) patch_iat(h); return h; }

static void patch_loader_iat(void) {
    /* patch kernel32 LoadLibrary imports in exe so future DLLs get hooked */
    HMODULE exe = GetModuleHandleA(NULL);
    BYTE *base = (BYTE*)exe;
    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR*)(base +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; desc->Name; desc++) {
            char *dll = (char*)(base + desc->Name);
            if (_stricmp(dll, "kernel32.dll")) continue;
            IMAGE_THUNK_DATA *iat = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
            IMAGE_THUNK_DATA *orig = desc->OriginalFirstThunk ? (IMAGE_THUNK_DATA*)(base + desc->OriginalFirstThunk) : 0;
            for (; iat->u1.Function; iat++, orig ? orig++ : 0) {
                IMAGE_IMPORT_BY_NAME *nm = (IMAGE_IMPORT_BY_NAME*)(base +
                    (orig ? orig->u1.AddressOfData : iat->u1.AddressOfData));
                if (!nm || IMAGE_SNAP_BY_ORDINAL(iat->u1.Ordinal)) continue;
                FARPROC rep = 0;
                if (!strcmp((char*)nm->Name, "LoadLibraryA")) rep = (FARPROC)hk_LoadLibraryA;
                else if (!strcmp((char*)nm->Name, "LoadLibraryW")) rep = (FARPROC)hk_LoadLibraryW;
                else if (!strcmp((char*)nm->Name, "LoadLibraryExA")) rep = (FARPROC)hk_LoadLibraryExA;
                else if (!strcmp((char*)nm->Name, "LoadLibraryExW")) rep = (FARPROC)hk_LoadLibraryExW;
                if (rep) {
                    DWORD old = 0;
                    if (VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) {
                        iat->u1.Function = (ULONG_PTR)rep;
                        VirtualProtect(&iat->u1.Function, sizeof(void*), old, &old);
                    }
                }
            }
        }
    }
}

static DWORD WINAPI installer(LPVOID unused) {
    (void)unused;
    Sleep(50);
    hWS2 = GetModuleHandleA("ws2_32.dll");
    if (!hWS2) hWS2 = LoadLibraryA("ws2_32.dll");
    hKernel = GetModuleHandleA("kernel32.dll");
    p_sendto = (PFN_sendto)GetProcAddress(hWS2, "sendto");
    p_recvfrom = (PFN_recvfrom)GetProcAddress(hWS2, "recvfrom");
    p_WSASendTo = (PFN_WSASendTo)GetProcAddress(hWS2, "WSASendTo");
    p_WSARecvFrom = (PFN_WSARecvFrom)GetProcAddress(hWS2, "WSARecvFrom");
    p_connect = (PFN_connect)GetProcAddress(hWS2, "connect");
    p_WSAConnect = (PFN_WSAConnect)GetProcAddress(hWS2, "WSAConnect");
    p_getpeername = (PFN_getpeername)GetProcAddress(hWS2, "getpeername");
    p_closesocket = (PFN_closesocket)GetProcAddress(hWS2, "closesocket");
    p_send = (PFN_send)GetProcAddress(hWS2, "send");
    p_recv = (PFN_recv)GetProcAddress(hWS2, "recv");
    p_WSASend = (PFN_WSASend)GetProcAddress(hWS2, "WSASend");
    p_WSARecv = (PFN_WSARecv)GetProcAddress(hWS2, "WSARecv");
    p_ioctlsocket = (PFN_ioctlsocket)GetProcAddress(hWS2, "ioctlsocket");
    p_GetProcAddress = (PFN_GetProcAddress)GetProcAddress(hKernel, "GetProcAddress");
    p_LoadLibraryA = (PFN_LoadLibraryA)GetProcAddress(hKernel, "LoadLibraryA");
    p_LoadLibraryW = (PFN_LoadLibraryW)GetProcAddress(hKernel, "LoadLibraryW");
    p_LoadLibraryExA = (PFN_LoadLibraryExA)GetProcAddress(hKernel, "LoadLibraryExA");
    p_LoadLibraryExW = (PFN_LoadLibraryExW)GetProcAddress(hKernel, "LoadLibraryExW");
    policy_init();
    {
        WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd);
    }
    if (g_direct) dt_start();
    patch_all();
    patch_loader_iat();
    /* late GetProcAddress IAT swap for already-loaded modules */
    patch_all();
    dbg("lan_hook: installed\n");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hself = h;
        DisableThreadLibraryCalls(h);
        if (!g_cs_init) { InitializeCriticalSection(&g_cs); g_cs_init = 1; }
        if (!g_dcs_init) { InitializeCriticalSection(&g_dcs); g_dcs_init = 1; }
        HANDLE t = CreateThread(NULL, 0, installer, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
#endif
