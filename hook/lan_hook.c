/* Universal LAN->relay hook. Windows DLL + Linux LD_PRELOAD test build.
 *
 * Direct-tunnel mode (needs LAN_HOOK_SERVER): game traffic to LAN IPs is
 * tunneled to the ShadowLAN relay - TCP streams multiplexed over one TCP
 * link, game UDP over UDP, discovery over either. Without LAN_HOOK_SERVER
 * the hook is a pure passthrough. Hosting games auto-claim designated-host
 * via listen(); all peers get virtual LAN IPs for P2P mesh play.
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
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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

/* ---------- shared policy ---------- */
static int g_only_ports[64];
static int g_nports = 0; /* 0 = all */
#define SHADOWLAN_VERSION "1.1.0"
static long long dt_now_ms(void);
static void dt_stamp(char *out, size_t n);
static void dt_fatal(int code, const char *msg);
static int g_debug = 0;
/* direct-tunnel mode: hook dials server itself (no wclient.py needed) */
static char g_server[256] = {0};
static int g_srvport = 47777;
static int g_direct = 0;
static int g_udp_tcp = 0;   /* UDP-over-TCP mode (policy_init, used everywhere) */
static int g_lan_only = 0;  /* LAN_HOOK_LAN_ONLY: ShadowLAN is the only network */
/* hosting claim: set when the local game serves (listen() hook) */
static volatile int g_claimed = 0;
static unsigned char g_token[256];
static int g_token_len = 0;

static void policy_init(void) {
    const char *p = getenv("LAN_HOOK_PORTS");
    if (p && p[0]) {
        char tmp[512]; strncpy(tmp, p, sizeof(tmp) - 1); tmp[sizeof(tmp)-1] = 0;
        for (char *t = strtok(tmp, ",; "); t && g_nports < 64; t = strtok(NULL, ",; "))
            g_only_ports[g_nports++] = atoi(t);
    }
    if (getenv("LAN_HOOK_DEBUG") && getenv("LAN_HOOK_DEBUG")[0] == '1') g_debug = 1;
    const char *tk = getenv("LAN_HOOK_TOKEN");
    if (tk && tk[0]) {
        size_t tl = strlen(tk);
        if (tl > sizeof(g_token)) tl = sizeof(g_token);
        memcpy(g_token, tk, tl);
        g_token_len = (int)tl;
    }
    const char *s = getenv("LAN_HOOK_SERVER");
    if (s && s[0]) {
        strncpy(g_server, s, sizeof(g_server) - 1);
        const char *pp = getenv("LAN_HOOK_PORT");
        if (pp && pp[0]) { int v = atoi(pp); if (v > 0 && v < 65536) g_srvport = v; }
        g_direct = 1;
    }
    {
        /* UDP-over-TCP (unfriendly NAT): game datagrams ride the TCP
         * link; UDP keepalives still go out so the relay keeps a fresh
         * return mapping. LAN_HOOK_UDP_OVER_TCP=1 (or injector --udp-over-tcp). */
        const char *ut = getenv("LAN_HOOK_UDP_OVER_TCP");
        g_udp_tcp = (ut && ut[0] && ut[0] != '0') ? 1 : 0;
    }
    {
        /* LAN_HOOK_LAN_ONLY=1: emulate a machine whose only network is the
         * ShadowLAN subnet (no WAN, no other LANs): wire destinations fail
         * with ENETUNREACH and non-loopback wire frames are not delivered.
         * The loopback interface stays fully functional (bridges, tools). */
        const char *lo = getenv("LAN_HOOK_LAN_ONLY");
        g_lan_only = (lo && lo[0] && lo[0] != '0') ? 1 : 0;
    }
}

#ifndef LINUX_BUILD
static void flog(const char *m);         /* defined below in Windows section */
#endif
/* One-line startup census of every option (set or default): makes
 * "which build/flags actually ran?" answerable from the log alone. */
static void dt_log_options(void) {
    char lb[1024];
    const char *e;
    long lease = 3000, ito = 30000;
    if ((e = getenv("LAN_HOOK_LEASE_WAIT")) && e[0]) {
        long long v = atoll(e);
        lease = (v == 0) ? 0 : (v < 0 ? -1 : (v > 600000 ? 600000 : v));
    }
    if ((e = getenv("LAN_HOOK_INIT_TIMEOUT")) && e[0]) {
        long long v = atoll(e);
        ito = (v < 0) ? -1 : (v > 600000 ? 600000 : v);
    }
    snprintf(lb, sizeof(lb),
             "options v%s pid=%u server=%s port=%d token=%s ports=%s debug=%d "
             "node=%s lease_wait=%ld init_timeout=%ld udp_over_tcp=%d "
             "modules=%s children=%s nochild=%s lan_only=%d logfile=%s",
             SHADOWLAN_VERSION,
#ifdef LINUX_BUILD
             (unsigned)getpid(),
#else
             (unsigned)GetCurrentProcessId(),
#endif
             g_server[0] ? g_server : "(unset)", g_srvport,
             g_token_len ? "set" : "(unset)",
             getenv("LAN_HOOK_PORTS") ? getenv("LAN_HOOK_PORTS") : "(all)",
             g_debug,
             getenv("LAN_HOOK_NODE") ? getenv("LAN_HOOK_NODE") : "(gen)",
             lease, ito, g_udp_tcp,
             getenv("LAN_HOOK_MODULES") ? getenv("LAN_HOOK_MODULES") : "(all)",
             getenv("LAN_HOOK_CHILDREN") ? getenv("LAN_HOOK_CHILDREN") : "(all)",
             getenv("LAN_HOOK_NOCHILD") ? getenv("LAN_HOOK_NOCHILD") : "0",
             g_lan_only,
             getenv("LAN_HOOK_LOGFILE") ? getenv("LAN_HOOK_LOGFILE") : "(debugview)");
    lb[sizeof(lb) - 1] = 0;
    /* Unconditional (not gated on debug): the point is answering
     * "which flags actually ran?" from any log. */
#ifdef LINUX_BUILD
    { char ts[32]; dt_stamp(ts, sizeof(ts)); fprintf(stderr, "[%s lan_hook] %s\n", ts, lb); }
#else
    OutputDebugStringA("lan_hook: ");
    OutputDebugStringA(lb);
    OutputDebugStringA("\n");
    flog(lb);
#endif
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

/* ================= DIRECT TUNNEL CORE (hook dials server itself) ============= */
/* Speaks server.py framing so no wclient.py is needed on the game PC.
 * Tunnel mode (LAN_HOOK_SERVER set): broadcast+game-TCP over one TCP link,
 * game-UDP over UDP. Include discovery UDP ports in the relay --udp list
 * too (unicast discovery replies). Without LAN_HOOK_SERVER: passthrough. */
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

/* Control-connection frames (one per hook instance): membership, host
 * claim, discovery beacons, UDP-over-TCP. Game TCP streams are NOT
 * multiplexed here: every fake game TCP connection is its own real TCP
 * connection to the relay (see "per-stream TCP" section below), so a
 * stalled stream can never head-of-line-block beacons or other streams.
 * One contiguous op block; keep in sync with common.py. */
#define DT_NODE  0x01     /* !H tlen + token + !I node + !H uport + !B flags */
#define DT_ASSIGN 0x02
#define DT_BCAST 0x03
#define DT_BCAST_FROM 0x04
#define DT_UDP_MODE 0x05  /* declare UDP-over-TCP mode (empty) */
#define DT_UDP_TUN 0x06   /* one UDP-tunnel datagram (UDP-over-TCP mode) */
#define DT_NODE_F_HOST 0x01  /* T_NODE flags bit: claim designated-host */
/* wire protocol version: one leading byte on the TCP registration frames
 * (DT_NODE). The relay gates there, which transitively gates
 * every stream routed by the resulting node id. Keep == common.PVER. */
#define DT_PVER 2
/* per-stream ops. Opener dials the relay on a NEW tcp conn, sends
 * DT_STOPEN; the relay asks the destination (DT_STREQ on EVERY control
 * link of the dest node -- process-tree identity means sibling processes
 * race to serve); a destination dials the relay on its OWN new tcp conn,
 * sends DT_STJOIN, and the relay answers the CLAIM on that conn right
 * away (DT_STOK = you serve it / DT_STFAIL(BUSY) = a sibling won, stand
 * down before bridging); the winner bridges to its local game and sends
 * DT_STJOINED; the relay confirms DT_STOK to the opener and pipes raw
 * bytes both ways. */
#define DT_STOPEN 0x07    /* opener->relay: !I node + !I dest_node + !I sid + !H gport */
#define DT_STREQ  0x08    /* relay->dest (control): !I sid + !H gport */
#define DT_STJOIN 0x09    /* dest->relay: !I node + !I sid */
#define DT_STJOINED 0x0A  /* dest->relay: !I sid (local bridge up) */
#define DT_STOK   0x0B    /* relay->opener (confirmed) / relay->dest (claim): !I sid */
#define DT_STFAIL 0x0C    /* relay->opener/dest, dest->relay: !I sid + !B reason */
#define STF_NO_ROUTE 1
#define STF_JOIN_TIMEOUT 2
#define STF_HOST_FAILED 3
#define STF_BAD_ID 4
#define STF_BUSY 5
#define DT_ST_TIMEOUT_MS 10000   /* handshake budget, both sides + relay */
/* stream states (opener side) */
#define ST_CONNECTING 1
#define ST_OPEN 2
#define ST_DEAD 3
/* UDP tunnel datagram ops: 'V' 'N' DU_VER op payload... (keep in sync
 * with common.py U_* table) */
#define DU_VER 2
#define DU_C2S 0x01
#define DU_S2C 0x02
#define DU_PDAT 0x03
#define DU_NODE 0x04      /* !H tlen + token + !I node + !H uport + !B flags */
#define DU_ICMP_REQ 0x05  /* VN 02 05 | !I src + !I dest + !H id + !H seq + data (0 = relay) */
#define DU_ICMP_REP 0x06  /* same layout, reply */
/* virtual-IP membership (assigned by relay per token room) */
static volatile unsigned g_node = 0;
static unsigned g_myvirt = 0;      /* numeric, e.g. 0x0AC80002 */
static unsigned char g_vnetb[4];   /* subnet bytes, network order */
static int g_vbits = 24;
#define DT_MAXMEMB 256
static struct { unsigned node, virt; } g_members[DT_MAXMEMB]; /* virt numeric */
static int g_nmembers = 0;
static unsigned dt_rand_state = 0;
static unsigned dt_rand(void) {
    unsigned x = dt_rand_state;
    if (!x) x = 0x9e3779b9u;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    dt_rand_state = x;
    return x ? x : 1;
}
/* hosting claim: set when the local game serves (listen() hook).
 * The claimer becomes the relay's designated host, so any peer —
 * hook or wclient --host — can host with client-only software. */
#define DT_MAXSTREAM 128
#define DT_MAXUDP 128
#define DT_MAXSLOT 256
#define DT_MAXQ 64

struct dt_chunk { unsigned char *p; size_t n, off; struct dt_chunk *next; };
struct dt_dgram { unsigned char *p; size_t n; struct sockaddr_in from; struct dt_dgram *next; };
struct dt_stream { int used; long long gsock; unsigned sid; struct sockaddr_in orig;
                   struct dt_chunk *h, *t; size_t total; int dead;
                   /* one real TCP conn to the relay per stream */
                   int state;          /* ST_CONNECTING/ST_OPEN/ST_DEAD */
                   unsigned fail;      /* STF_* when dead via handshake */
                   int in_paused;      /* in-queue full: stop reading relay */
                   int connect_signaled; /* FD_CONNECT reported once */
                   DTSOCK fd;          /* per-stream TCP (DTSOCK_BAD = none) */
                   struct dt_chunk *oh, *ot; size_t ototal;  /* app out-queue */
                   /* field diagnostics: app-facing byte counters + log throttle */
                   unsigned an_rx, an_tx; size_t ab_rx, ab_tx; long long a_log; };
struct dt_udp { int used; long long gsock; struct dt_dgram *h, *t; int nq; int closed; int vport; };
struct dt_slot { int used; long long gsock; int game_port; struct sockaddr_in orig; };
struct dt_frame { unsigned char type; unsigned char *p; size_t n; struct dt_frame *next; };

static struct dt_stream g_st[DT_MAXSTREAM];
static struct dt_udp g_uq[DT_MAXUDP];
static struct dt_slot g_sl[DT_MAXSLOT];
static struct dt_frame *g_sqh = NULL, *g_sqt = NULL;
static volatile int g_tun_run = 0, g_tun_started = 0, g_tcp_up = 0;
static volatile int g_have_assign = 0;   /* first ASSIGN (our vnode) seen */
/* Fatal startup errors: without a relay link AND an address lease the
 * tunnel is unusable, so running on would only produce a broken game.
 * Report visibly and terminate the process with a distinct exit code.
 * LAN_HOOK_INIT_TIMEOUT (ms, default 30000, 0 = never fail) bounds how
 * long init waits for the first lease; LAN_HOOK_LEASE_WAIT=0 skips the
 * wait (and the watchdog) entirely for unassigned starts. */
#define SL_FATAL_NORELAY 200  /* relay unreachable (resolve/connect) */
#define SL_FATAL_NOLEASE 201  /* link up but no virtual-IP lease */
static volatile int g_init_done = 0;      /* LanHookInit/ensure_init finished */
static volatile int g_tcp_ever_up = 0;    /* any TCP link since process start */
static long long g_init_t0 = 0;
static long long g_fatal_after_ms = 30000;
static void dt_fatal(int code, const char *msg);
#ifndef LINUX_BUILD
static void flog(const char *m);         /* defined below; lease logs use it */
DWORD WINAPI hk_IcmpSendEcho(HANDLE, IPAddr, LPVOID, WORD,
                             PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
DWORD WINAPI hk_IcmpSendEcho2(HANDLE, HANDLE, FARPROC, PVOID, IPAddr, LPVOID,
                              WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
#endif
static DTSOCK g_tcp = DTSOCK_BAD, g_udptun = DTSOCK_BAD;
static int g_tun_conn = 0;
static void dt_tun_setup(DTSOCK s);
static unsigned long g_fakeip = 0; /* 192.168.7.1 net order, set at start */
/* Relay-assigned per-LINK slot base (ASSIGN tail byte, 1..59; 0 = legacy).
 * Client marks are 50000 + g_link_id*DT_MAXSLOT + slot: unique across
 * sibling links of one node, so relay return-path bindings for the two
 * processes can never collide (the cross-machine "UDP triple collision"
 * failure). Presented ports stay hook-allocated and stable - the relay
 * rewrites nothing. */
static int g_link_id = 1;
/* Mark = the source port peers see for our client socket:
 * link_id*DT_MAXSLOT + slot, link_id relay-assigned 1..255 in ASSIGN
 * (mandatory tail; initial value overwritten before the app runs -
 * the lease barrier gates it). This spans the FULL u16 space, so
 * games keep every port usable themselves; a mark landing in some
 * game's service band stays harmless because replies to a mark are
 * demuxed by exact hosted-session triple (dt_on_sendto), never by
 * port range. */
static int dt_mark(int slot) {
    return g_link_id * DT_MAXSLOT + slot;
}
static int dt_unmark(int mp) {
    int base = g_link_id * DT_MAXSLOT;
    return (mp >= base && mp < base + DT_MAXSLOT) ? mp - base : -1;
}
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
static unsigned current_pid(void) {
#ifdef LINUX_BUILD
    return (unsigned)getpid();
#else
    return GetCurrentProcessId();
#endif
}
/* forward decls: stream helpers defined in the per-stream section below */
static struct dt_stream *dt_stream_by_sid(unsigned sid);
/* wall-clock stamp for file logs: "MM-DD HH:MM:SS.mmm" */
static void dt_stamp(char *out, size_t n) {
#ifdef LINUX_BUILD
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);
    snprintf(out, n, "%02d-%02d %02d:%02d:%02d.%03d",
             tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
             (int)(tv.tv_usec / 1000));
#else
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(out, n, "%02d-%02d %02d:%02d:%02d.%03d",
             (int)st.wMonth, (int)st.wDay, (int)st.wHour,
             (int)st.wMinute, (int)st.wSecond, (int)st.wMilliseconds);
#endif
    out[n - 1] = 0;
}
static void dlog(const char *m) {
    if (!g_debug) return;
#ifdef LINUX_BUILD
    { char ts[32]; dt_stamp(ts, sizeof(ts)); fprintf(stderr, "[%s lan_hook] %s\n", ts, m); }
#else
    OutputDebugStringA("lan_hook: ");
    OutputDebugStringA(m);
    OutputDebugStringA("\n");
    {
        static FILE *lf = NULL;
        static int tried = 0;
        if (!tried) {
            tried = 1;
            const char *p = getenv("LAN_HOOK_LOGFILE");
            if (p && p[0]) lf = fopen(p, "a");
        }
        if (lf) {
            char ts[32];
            dt_stamp(ts, sizeof(ts));
            fputs(ts, lf); fputs(" lan_hook: ", lf);
            fputs(m, lf); fputc('\n', lf); fflush(lf);
        }
    }
#endif
}
/* Fatal startup failure: the tunnel cannot work, so running on would
 * only produce a broken game. Log unconditionally, tell the user, and
 * terminate the process with a distinct exit code (200/201). Never
 * returns. Safe to call from any thread, including the init thread. */
static void dt_fatal(int code, const char *msg) {
    /* Fatal is init-only by construction: every call site checks
     * !g_init_done, and this re-checks so no future path can ever kill
     * a running game mid-play (post-init drops just redial silently). */
    if (g_init_done) {
        dlog("dt_fatal after init: ignored (never kill gameplay)");
        return;
    }
    char full[512];
    snprintf(full, sizeof(full), "ShadowLAN fatal (%d): %s [relay %s:%d]",
             code, msg,
             g_server[0] ? g_server : "(unset)", g_srvport);
    full[sizeof(full) - 1] = 0;
    dlog(full);
#ifdef LINUX_BUILD
    fprintf(stderr, "%s\n", full);
    fflush(stderr);
    _exit(code);
#else
    {
        static FILE *lf = NULL;
        const char *p = getenv("LAN_HOOK_LOGFILE");
        if (p && p[0]) lf = fopen(p, "a");
        if (lf) {
            char ts[32];
            dt_stamp(ts, sizeof(ts));
            fputs(ts, lf); fputs(" lan_hook: ", lf);
            fputs(full, lf); fputc('\n', lf); fflush(lf); fclose(lf);
        }
    }
    OutputDebugStringA("lan_hook: ");
    OutputDebugStringA(full);
    OutputDebugStringA("\n");
    MessageBoxA(NULL, full, "ShadowLAN",
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND);
    TerminateProcess(GetCurrentProcess(), (UINT)code);
    ExitProcess((UINT)code); /* unreachable, paranoia if Terminate fails */
#endif
}
static int dt_fatal_code(void) {
    /* 200 = never reached the relay, 201 = link up but no address lease */
    return g_tcp_ever_up ? SL_FATAL_NOLEASE : SL_FATAL_NORELAY;
}
/* Init watchdog: still unleashed (no lease) past the fatal timeout means
 * the tunnel can never work (dead relay, wrong port, token rejected so
 * no ASSIGN). Fail loudly instead of running a broken game. Post-init
 * redials keep retrying silently: mid-game drops recover on their own. */
static void dt_init_watchdog(void) {
    if (!g_init_done && !g_have_assign && g_fatal_after_ms > 0 &&
        g_tun_run && dt_now_ms() - g_init_t0 > g_fatal_after_ms) {
        int code = dt_fatal_code();
        dt_fatal(code, code == SL_FATAL_NORELAY
                 ? "cannot reach relay (check server/port, relay running, firewall)"
                 : "relay connected but no virtual-IP lease (check token, relay log)");
    }
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
static void dt_sig_locked(long long gsock);
static void dt_icmp_in(unsigned is_rep, unsigned src, unsigned dest,
                       unsigned id, unsigned seq,
                       const unsigned char *data, size_t dlen);
static void dt_udp_ingress(const unsigned char *buf, size_t n);
#ifndef LINUX_BUILD
static int dt_icmp_pend_complete(unsigned id, unsigned seq,
                                 const unsigned char *data, size_t dlen,
                                 unsigned from_virt);
#endif
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
/* Forward declarations: these helpers live further down the file. */
static int dt_resolve(struct sockaddr_in *out);
#ifdef LINUX_BUILD
static void dt_reals(void);
static ssize_t (*r_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static int (*r_close)(int);
static int (*r_connect)(int, const struct sockaddr *, socklen_t);
#endif
/* HELLO payload: !H token_len + token (matches common.encode_hello). */
static size_t dt_hello_payload(unsigned char *out) {
    out[0] = (unsigned char)((g_token_len >> 8) & 255);
    out[1] = (unsigned char)(g_token_len & 255);
    if (g_token_len) memcpy(out + 2, g_token, (size_t)g_token_len);
    return (size_t)(2 + g_token_len);
}
/* Called when the local game starts serving: claim designated-host. */
static void dt_send_node(void);      /* defined below (payload builders) */
static void dt_send_udp_node(void);
static void dt_claim(void) {
    if (!g_direct || g_claimed) return;
    g_claimed = 1;
    dlog("hosting claim: game serves locally");
    dt_send_node();      /* re-register with NODE_F_HOST (queued) */
    dt_send_udp_node();  /* best-effort UDP claim now too */
}
static int dt_tun_udp_port(void) {
#ifdef LINUX_BUILD
    struct sockaddr_in a; socklen_t l = sizeof(a);
    if (g_udptun < 0) return 0;
    if (getsockname(g_udptun, (struct sockaddr *)&a, &l) != 0) return 0;
#else
    struct sockaddr_in a; int l = sizeof(a);
    if (g_udptun == INVALID_SOCKET) return 0;
    if (getsockname(g_udptun, (struct sockaddr *)&a, &l) != 0) return 0;
#endif
    return ntohs(a.sin_port);
}
static void dt_send_node(void) {
    unsigned char p[3 + 256 + 8];
    size_t h;
    p[0] = DT_PVER;
    h = 1 + dt_hello_payload(p + 1);
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
static void dt_send_udp_node(void) {
    unsigned char d[4 + 2 + 256 + 8];
    struct sockaddr_in sa;
    d[0] = 'V'; d[1] = 'N'; d[2] = DU_VER; d[3] = DU_NODE;
    size_t h = dt_hello_payload(d + 4);
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
    if (u != INVALID_SOCKET) sendto(u, (const char *)d, (int)n, 0, (struct sockaddr *)&sa, sizeof(sa));
#endif
}
/* Numeric IP (0x0AC80002 for 10.200.0.2) from network-order bytes. */
static unsigned dt_ipnum(const unsigned char *b) {
    return ((unsigned)b[0] << 24) | ((unsigned)b[1] << 16) |
           ((unsigned)b[2] << 8) | (unsigned)b[3];
}
/* ASSIGN: !I my_virt + !I net + !B bits + !H n + n*(!I node + !I virt),
 * all multi-byte fields big-endian on the wire. */
static void dt_apply_assign(const unsigned char *p, size_t n) {
    if (n < 11) return;
    {
        int bits = p[8];
        int cnt = ((int)p[9] << 8) | p[10];
        int lid;
        if (bits <= 0 || bits > 32 || cnt < 0 || cnt > DT_MAXMEMB) return;
        if (n != (size_t)(12 + 8 * cnt)) return;   /* link_id tail is
                                                     * mandatory */
        DLOCK();
        g_myvirt = dt_ipnum(p);
        memcpy(g_vnetb, p + 4, 4);
        g_vbits = bits;
        g_nmembers = 0;
        for (int i = 0; i < cnt && i < DT_MAXMEMB; i++) {
            g_members[g_nmembers].node = dt_ipnum(p + 11 + 8 * i);
            g_members[g_nmembers].virt = dt_ipnum(p + 15 + 8 * i);
            g_nmembers++;
        }
        lid = p[11 + 8 * cnt];
        g_link_id = (lid >= 1 && lid <= 255) ? lid : 1;
        DUNLOCK();
    }
    g_have_assign = 1;
    { char lb[160];
      snprintf(lb, sizeof(lb),
               "assign pid=%u node=%u self=%u.%u.%u.%u members=%d link=%d",
               (unsigned)current_pid(), g_node,
               (g_myvirt >> 24) & 255, (g_myvirt >> 16) & 255,
               (g_myvirt >> 8) & 255, g_myvirt & 255, g_nmembers,
               g_link_id);
      dlog(lb); }
}
/* Network-order address -> node id (0 = not a known virtual peer). */
static unsigned dt_virt_node(unsigned long inaddr) {
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
                if (g_members[i].virt == v) { node = g_members[i].node; break; }
        }
    }
    DUNLOCK();
    return node;
}
/* node id -> virtual IP (0 = unknown). */
static unsigned dt_node_virt(unsigned node) {
    unsigned virt = 0;
    DLOCK();
    for (int i = 0; i < g_nmembers; i++)
        if (g_members[i].node == node) { virt = g_members[i].virt; break; }
    DUNLOCK();
    return virt;
}
/* ---- hosted (inbound) sessions: relay routes remote players to us ---- */
#define DT_MAXHOST 64
#define DT_MAXUSESS 64
struct dt_hosted {
    int used; unsigned sid;
    DTSOCK real;          /* local loopback bridge to the game */
    DTSOCK fd;            /* per-stream TCP to the relay */
    int live;             /* bridge up (STJOINED sent) */
    long long last;       /* last activity (pending sweep) */
    int dead;
};
static struct dt_hosted g_hs[DT_MAXHOST];
struct dt_usess {
    int used; int game_port; struct sockaddr_in cli;
#ifdef LINUX_BUILD
    int real;
#else
    SOCKET real;
#endif
    long long last;
};
static struct dt_usess g_us[DT_MAXUSESS];
static long long dt_now_ms(void) {
#ifdef LINUX_BUILD
    struct timeval tv; gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#else
    return (long long)GetTickCount();
#endif
}
static struct dt_hosted *dt_hs_by_sid(unsigned sid) {
    for (int i = 0; i < DT_MAXHOST; i++)
        if (g_hs[i].used && g_hs[i].sid == sid) return &g_hs[i];
    return NULL;
}
static void dt_hs_close(unsigned sid) {
    struct dt_hosted hcp; int have = 0;
    DLOCK();
    struct dt_hosted *h = dt_hs_by_sid(sid);
    if (h) { hcp = *h; have = 1; h->used = 0; h->real = DTSOCK_BAD; h->fd = DTSOCK_BAD; }
    DUNLOCK();
    if (!have) return;
    if (hcp.real != DTSOCK_BAD) {
#ifdef LINUX_BUILD
        dt_reals();
        if (hcp.real >= 0) r_close(hcp.real);
#else
        if (hcp.real != INVALID_SOCKET) closesocket(hcp.real);
#endif
    }
    if (hcp.fd != DTSOCK_BAD) {
#ifdef LINUX_BUILD
        dt_reals();
        if (hcp.fd >= 0) r_close(hcp.fd);
#else
        if (hcp.fd != INVALID_SOCKET) closesocket(hcp.fd);
#endif
    }
}
/* Local loopback bridge to our own game server (joinee side). */
static int dt_host_bridge(unsigned sid, int port) {
    struct sockaddr_in lo; memset(&lo, 0, sizeof(lo));
    lo.sin_family = AF_INET; lo.sin_port = htons((unsigned short)port);
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    DTSOCK s;
#ifdef LINUX_BUILD
    dt_reals();
    s = (DTSOCK)socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    if (r_connect(s, (struct sockaddr *)&lo, sizeof(lo)) != 0) { r_close(s); return -1; }
#else
    s = (DTSOCK)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;
    if (connect(s, (struct sockaddr *)&lo, sizeof(lo)) != 0) { closesocket(s); return -1; }
#endif
    DLOCK();
    struct dt_hosted *h = dt_hs_by_sid(sid);
    if (h) { h->real = s; h->live = 1; h->last = dt_now_ms(); }
    DUNLOCK();
    return 0;
}
static struct dt_usess *dt_usess_find(int game_port, const unsigned char *raw,
                                      size_t rl, const struct sockaddr_in *cli,
                                      int create) {
    (void)raw; (void)rl;
    long long now = dt_now_ms();
    for (int i = 0; i < DT_MAXUSESS; i++)
        if (g_us[i].used && g_us[i].game_port == game_port &&
            g_us[i].cli.sin_addr.s_addr == cli->sin_addr.s_addr &&
            g_us[i].cli.sin_port == cli->sin_port)
            return &g_us[i];
    if (!create) return NULL;
    for (int i = 0; i < DT_MAXUSESS; i++)
        if (!g_us[i].used || now - g_us[i].last > 45000) {
            if (g_us[i].used) {
#ifdef LINUX_BUILD
                dt_reals(); r_close(g_us[i].real);
#else
                closesocket(g_us[i].real);
#endif
            }
            g_us[i].used = 1; g_us[i].game_port = game_port;
            g_us[i].cli = *cli; g_us[i].last = now;
#ifdef LINUX_BUILD
            dt_reals();
            g_us[i].real = socket(AF_INET, SOCK_DGRAM, 0);
            if (g_us[i].real < 0) { g_us[i].used = 0; continue; }
#else
            g_us[i].real = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (g_us[i].real == INVALID_SOCKET) { g_us[i].used = 0; continue; }
#endif
            return &g_us[i];
        }
    return NULL;
}
/* Inbound game datagram for OUR hosted game -> real loopback socket.
 * Caller: UDP tunnel thread. Locking: takes DLOCK internally. */
static int dt_hosted_udp_in(int game_port, const unsigned char *ipb, int iplen,
                            int cport, const unsigned char *raw, size_t rl) {
    char ipstr[64];
    if (iplen <= 0 || iplen >= (int)sizeof(ipstr) || rl > 65000) return 0;
    memcpy(ipstr, ipb, (size_t)iplen); ipstr[iplen] = 0;
    struct sockaddr_in cli; memset(&cli, 0, sizeof(cli));
    cli.sin_family = AF_INET; cli.sin_port = htons((unsigned short)cport);
    cli.sin_addr.s_addr = inet_addr(ipstr);
    if (cli.sin_addr.s_addr == INADDR_NONE) return 0;
    struct sockaddr_in lo; memset(&lo, 0, sizeof(lo));
    lo.sin_family = AF_INET; lo.sin_port = htons((unsigned short)game_port);
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef LINUX_BUILD
    dt_reals();
    DLOCK();
    struct dt_usess *u = dt_usess_find(game_port, raw, rl, &cli, 1);
    int rs = u ? u->real : -1;
    if (u) u->last = dt_now_ms();
    DUNLOCK();
    if (!u || rs < 0) return 0;
    r_sendto(rs, raw, rl, 0, (struct sockaddr *)&lo, sizeof(lo));
    return 1;
#else
    DLOCK();
    struct dt_usess *u = dt_usess_find(game_port, raw, rl, &cli, 1);
    SOCKET rs = u ? u->real : INVALID_SOCKET;
    if (u) u->last = dt_now_ms();
    DUNLOCK();
    if (!u || rs == INVALID_SOCKET) return 0;
    sendto(rs, (const char *)raw, (int)rl, 0, (struct sockaddr *)&lo, sizeof(lo));
    return 1;
#endif
}
/* Addressed datagram with no hosted session on this side: the first packet
 * of a unicast exchange (e.g. a lobby answer that unicast-replies to a
 * broadcast query - the querier only ever broadcast, so no session triple
 * exists). Deliver to every datagram socket that appears to listen on the
 * game port (bound, or aliased via shared-port emulation), the way a real
 * NIC would. from = sender's address on that same port. */
static void dt_direct_udp_in(int game_port, const unsigned char *ipb, int iplen,
                             const unsigned char *raw, size_t rl) {
    char ipstr[64];
    if (iplen <= 0 || iplen >= (int)sizeof(ipstr) || rl > 65000) return;
    memcpy(ipstr, ipb, (size_t)iplen); ipstr[iplen] = 0;
    struct sockaddr_in from; memset(&from, 0, sizeof(from));
    from.sin_family = AF_INET;
    from.sin_addr.s_addr = inet_addr(ipstr);
    from.sin_port = htons((unsigned short)game_port);
    if (from.sin_addr.s_addr == INADDR_NONE) return;
    int matched = 0, shown = 0;
    char lb[256]; int hp = 0;
    hp = snprintf(lb, sizeof(lb), "udp direct pid=%u gport=%d:", (unsigned)current_pid(), game_port);
    DLOCK();
    for (int i = 0; i < DT_MAXUDP; i++) {
        if (!g_uq[i].used || g_uq[i].closed) continue;
        long long gs = g_uq[i].gsock;
        int aliased = g_uq[i].vport;
        DUNLOCK();
        int bp = aliased ? aliased : dt_bound_port(gs);
        int dg = dt_sock_type(gs) == SOCK_DGRAM;
        DLOCK();
        struct dt_udp *e = &g_uq[i];
        if (!e->used || e->closed) continue;
        if (shown < 6 && hp < (int)sizeof(lb) - 32) {
            hp += snprintf(lb + hp, sizeof(lb) - hp, " s%lld=%d%s",
                           gs, bp, dg ? "" : "!dgram");
            shown++;
        }
        if (!dg || bp != game_port) continue;
        if (e->nq >= DT_MAXQ) continue;
        matched = 1;
        struct dt_dgram *d = (struct dt_dgram *)malloc(sizeof(*d));
        if (!d) continue;
        d->p = (unsigned char *)malloc(rl ? rl : 1);
        if (!d->p) { free(d); continue; }
        if (rl) memcpy(d->p, raw, rl);
        d->n = rl; d->from = from; d->next = NULL;
        if (e->t) e->t->next = d; else e->h = d;
        e->t = d; e->nq++;
        dt_sig_locked(gs);
        if (g_debug) {
            char lb[320]; int hp = 0;
            size_t hn = rl < 130 ? rl : 130;
            hp = snprintf(lb, sizeof(lb), "udp direct pid=%u sock=%lld n=%d hex=",
                          (unsigned)current_pid(), gs, (int)rl);
            for (size_t qi = 0; qi < hn && hp < (int)sizeof(lb) - 3; qi++)
                hp += snprintf(lb + hp, sizeof(lb) - hp, "%02x", raw[qi]);
            dlog(lb);
        }
    }
    DUNLOCK();
    if (g_debug && !matched) {
        if (hp < (int)sizeof(lb) - 12)
            snprintf(lb + hp, sizeof(lb) - hp, " NOMATCH");
        dlog(lb);
    }
}
#ifndef LINUX_BUILD
/* Passive wire observation (indirect/no-relay mode + debug): log real
 * send/recv frames so a working unhooked session can be compared
 * byte-for-byte against a tunneled one. Never alters behavior. */
static void dt_obsv(const char *dir, long long s, const struct sockaddr *a,
                    const unsigned char *p, int n) {
    char lb[256]; int hp;
    if (!g_debug || n <= 0 || !a || a->sa_family != AF_INET) return;
    {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)a;
        unsigned long av = 0; memcpy(&av, &sa->sin_addr.s_addr, 4);
        hp = snprintf(lb, sizeof(lb), "obsv %s sock=%lld ip=%lu.%lu.%lu.%lu:%d n=%d hex=",
                      dir, s, (av & 255), ((av >> 8) & 255), ((av >> 16) & 255),
                      ((av >> 24) & 255), (int)ntohs(sa->sin_port), n);
    }
    for (int qi = 0; qi < n && qi < 80 && hp < (int)sizeof(lb) - 3; qi++)
        hp += snprintf(lb + hp, sizeof(lb) - hp, "%02x", p[qi]);
    dlog(lb);
}
#endif
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
            g_uq[i].vport = 0;
            return &g_uq[i];
        }
    return NULL;
}
/* socket state for wait hooks (platform-independent). */
static void dt_sock_state_locked(long long gsock, int *data, int *dead,
                                 int *writable, int *connect) {
    int i;
    *data = 0; *dead = 0; *writable = 0; *connect = 0;
    for (i = 0; i < DT_MAXUDP; i++)
        if (g_uq[i].used && !g_uq[i].closed && g_uq[i].gsock == gsock) {
            if (g_uq[i].h) *data = 1;
            *writable = 1; /* datagram send never blocks */
        }
    for (i = 0; i < DT_MAXSTREAM; i++)
        if (g_st[i].used && g_st[i].gsock == gsock) {
            if (g_st[i].h) *data = 1;
            if (g_st[i].dead || g_st[i].state == ST_DEAD) *dead = 1;
            if (g_st[i].state == ST_OPEN && !g_st[i].dead) {
                *writable = 1;
                if (!g_st[i].connect_signaled) *connect = 1;
            }
        }
}
static void dt_sock_state_full(long long gsock, int *data, int *dead,
                               int *writable, int *connect) {
    DLOCK(); dt_sock_state_locked(gsock, data, dead, writable, connect); DUNLOCK();
}
#ifndef LINUX_BUILD
#define DT_MAXEV 128
static struct { int used; long long sock; WSAEVENT ev; long mask; } g_evmap[DT_MAXEV];
/* DLOCK must be held (every queue-insert path holds it). */
static void dt_sig_locked(long long gsock) {
    int i;
    for (i = 0; i < DT_MAXEV; i++)
        if (g_evmap[i].used && g_evmap[i].sock == gsock)
            (void)WSASetEvent(g_evmap[i].ev);
}
static void dt_ev_unhook_sock(long long sock) {
    int i;
    DLOCK();
    for (i = 0; i < DT_MAXEV; i++)
        if (g_evmap[i].used && g_evmap[i].sock == sock) g_evmap[i].used = 0;
    DUNLOCK();
}
static void dt_ev_unhook_ev(WSAEVENT ev) {
    int i;
    DLOCK();
    for (i = 0; i < DT_MAXEV; i++)
        if (g_evmap[i].used && g_evmap[i].ev == ev) g_evmap[i].used = 0;
    DUNLOCK();
}
#else
static void dt_sig_locked(long long gsock) { (void)gsock; }
#endif
static void dt_udp_push(long long gsock, const unsigned char *p, size_t n,
                        const struct sockaddr_in *from) {
    DLOCK();
    struct dt_udp *e = dt_udp_entry(gsock, 1);
    if (e && !e->closed) {
        if (e->nq >= DT_MAXQ) {
            /* full: drop THIS datagram, like a real udp rx buffer
             * (kernel drops new arrivals, never reorders/drops old) */
            DUNLOCK();
            { char lb[96];
              snprintf(lb, sizeof(lb), "udp q full gsock=%lld nq=%d: drop new", gsock, e->nq);
              dlog(lb); }
            return;
        }
        struct dt_dgram *d = (struct dt_dgram *)malloc(sizeof(*d));
        if (d) {
            d->p = (unsigned char *)malloc(n ? n : 1);
            if (d->p) { if (n) memcpy(d->p, p, n); d->n = n; d->from = *from; d->next = NULL;
                if (e->t) e->t->next = d; else e->h = d; e->t = d; e->nq++;
                dt_sig_locked(gsock);
#ifdef LINUX_BUILD
                { char lb[128]; snprintf(lb, sizeof(lb), "udp push gsock=%lld nq=%d n=%zu", gsock, e->nq, n); dlog(lb); }
#else
                { char lb[128]; snprintf(lb, sizeof(lb), "udp push gsock=%lld nq=%d n=%d", gsock, e->nq, (int)n); dlog(lb); }
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
    /* Per-dest slots: same socket to different game servers gets different
     * marks, so S2C replies demux by mark and relay triples
     * (virt-IP, mark) stay unique per destination. Same socket + port +
     * dest reuses its slot. */
    for (int i = 0; i < DT_MAXSLOT; i++)
        if (g_sl[i].used && g_sl[i].gsock == gsock && g_sl[i].game_port == game_port &&
            g_sl[i].orig.sin_addr.s_addr == orig->sin_addr.s_addr &&
            g_sl[i].orig.sin_port == orig->sin_port)
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

static void dt_dispatch_bcast_from(unsigned node, int port, int sport,
                                     const unsigned char *raw, size_t n) {
    struct sockaddr_in fake; memset(&fake, 0, sizeof(fake));
    fake.sin_family = AF_INET;
    /* App-facing source port: the sender's real socket port when known
     * (a LAN browser cross-checks it against the port embedded in the
     * announcement payload); fall back to the destination port. */
    fake.sin_port = htons((unsigned short)(sport > 0 ? sport : port));
    {
        unsigned virt = node ? dt_node_virt(node) : 0;
        fake.sin_addr.s_addr = virt ? htonl(virt) : g_fakeip;
    }
    DLOCK();
    for (int i = 0; i < DT_MAXUDP; i++) {
        if (!g_uq[i].used || g_uq[i].closed) continue;
        long long gs = g_uq[i].gsock;
        DUNLOCK();
        int bp = dt_bound_port(gs);
        { char lb[160]; snprintf(lb, sizeof(lb), "fanout pid=%u port=%d sock=%lld bound=%d",
                                 (unsigned)current_pid(), port, gs, bp); dlog(lb); }
        DLOCK();
        /* re-find (table may shift); keep simple: match by gsock again */
        struct dt_udp *e = NULL;
        for (int j = 0; j < DT_MAXUDP; j++)
            if (g_uq[j].used && g_uq[j].gsock == gs) { e = &g_uq[j]; break; }
        if (e && e->vport) bp = e->vport;   /* shared-port member */
        if (e && bp == port) {
            if (e->nq < DT_MAXQ) {
                struct dt_dgram *d = (struct dt_dgram *)malloc(sizeof(*d));
                if (d) {
                    d->p = (unsigned char *)malloc(n ? n : 1);
                    if (d->p) { if (n) memcpy(d->p, raw, n); d->n = n; d->from = fake; d->next = NULL;
                        if (e->t) e->t->next = d; else e->h = d; e->t = d; e->nq++;
                        dt_sig_locked(gs);
                    } else free(d);
                }
            }
        }
    }
    DUNLOCK();
}
static void dt_dispatch_bcast(int port, int sport, const unsigned char *raw, size_t n) {
    dt_dispatch_bcast_from(0, port, sport, raw, n);
}

/* ---- per-stream TCP ------------------------------------------------
 * Every fake game TCP connection is one REAL tcp connection to the
 * relay, opened by THIS process (NAT-safe: both ends dial out). The
 * relay pipes raw bytes between the two per-stream connections, so a
 * stalled stream can never head-of-line-block beacons or other streams
 * on the control link, and connect() only "completes" after the relay
 * confirms the destination bridged its local game (real connect
 * semantics, kernel-style blocking backpressure both directions).
 *
 * opener:  app connect(vnet) -> dt_on_connect -> stream thread:
 *          dial relay, DT_STOPEN, wait DT_STOK/DT_STFAIL (10s), pipe.
 * joinee:  control link DT_STREQ -> dt_on_streq -> join thread:
 *          dial relay, DT_STJOIN, local bridge connect, DT_STJOINED,
 *          pipe per-stream-tcp <-> local bridge.
 * Frame layout on per-stream TCPs (handshake only, then raw bytes):
 *          [u32 len][u8 type][payload]  (same framing as the control
 *          connection; the relay swaps to raw after DT_STOK/DT_STJOINED).
 * -------------------------------------------------------------------- */
#define DT_ST_MAXIN  (1024 * 1024)    /* app-read backpressure cap */
#define DT_ST_MAXOUT (4 * 1024 * 1024)

static DTSOCK dt_st_dial_relay(void) {
    struct sockaddr_in sa;
    if (dt_resolve(&sa) != 0) return DTSOCK_BAD;
    DTSOCK s;
#ifdef LINUX_BUILD
    dt_reals();
    s = (DTSOCK)socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return DTSOCK_BAD;
    int fl = fcntl((int)s, F_GETFL, 0);
    fcntl((int)s, F_SETFL, fl | O_NONBLOCK);
    int r = r_connect(s, (struct sockaddr *)&sa, sizeof(sa));
    if (r != 0 && errno != EINPROGRESS) { r_close(s); return DTSOCK_BAD; }
    if (r == 0) return s;
    fd_set wf; FD_ZERO(&wf); FD_SET((int)s, &wf);
    struct timeval tv = { DT_ST_TIMEOUT_MS / 1000,
                          (DT_ST_TIMEOUT_MS % 1000) * 1000 };
    if (select((int)s + 1, NULL, &wf, NULL, &tv) <= 0) { r_close(s); return DTSOCK_BAD; }
    int err = 0; socklen_t el = sizeof(err);
    getsockopt((int)s, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err) { r_close(s); return DTSOCK_BAD; }
    return s;
#else
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return DTSOCK_BAD;
    u_long on = 1;
    ioctlsocket(s, FIONBIO, &on); /* stays nonblocking (select-driven) */
    int r = connect(s, (struct sockaddr *)&sa, sizeof(sa));
    if (r != 0 && WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(s); return DTSOCK_BAD; }
    if (r == 0) return s;
    fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
    struct timeval tv = { DT_ST_TIMEOUT_MS / 1000,
                          (DT_ST_TIMEOUT_MS % 1000) * 1000 };
    if (select(0, NULL, &wf, NULL, &tv) <= 0) { closesocket(s); return DTSOCK_BAD; }
    int err = 0; int el = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &el);
    if (err) { closesocket(s); return DTSOCK_BAD; }
    return s;
#endif
}
/* blocking-ish framed send/recv over the (nonblocking) per-stream fd */
static int dt_st_send_all_tmo(DTSOCK fd, const unsigned char *b, size_t n,
                              long long tmo_ms) {
    long long t0 = dt_now_ms();
    while (n) {
#ifdef LINUX_BUILD
        ssize_t k = r_send(fd, b, n, 0);
        if (k > 0) { b += (size_t)k; n -= (size_t)k; continue; }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            { char lb[80]; snprintf(lb, sizeof(lb), "st send: err=%d", errno); dlog(lb); }
            return -1;
        }
#else
        int k = send(fd, (const char *)b, (int)n, 0);
        if (k > 0) { b += (size_t)k; n -= (size_t)k; continue; }
        if (WSAGetLastError() != WSAEWOULDBLOCK) return -1;
#endif
        fd_set wf; FD_ZERO(&wf);
#ifdef LINUX_BUILD
        FD_SET((int)fd, &wf);
        struct timeval tv = { 0, 50000 };
        int sr = select((int)fd + 1, NULL, &wf, NULL, &tv);
        if (sr < 0) {
            if (errno == EINTR) continue;
            { char lb[80]; snprintf(lb, sizeof(lb), "st send: select err=%d", errno); dlog(lb); }
            return -1;
        }
        /* sr == 0: not writable yet; retry until the budget runs out */
#else
        FD_SET(fd, &wf);
        struct timeval tv = { 0, 50000 };
        int sr = select(0, NULL, &wf, NULL, &tv);
        if (sr < 0) { if (WSAGetLastError() == WSAEINTR) continue; return -1; }
#endif
        if (dt_now_ms() - t0 > tmo_ms) return -1;
    }
    return 0;
}
static int dt_st_send_frame(DTSOCK fd, unsigned char type,
                            const unsigned char *p, size_t n) {
    unsigned char hdr[5];
    dt_put32(hdr, (unsigned)(1 + n));
    hdr[4] = type;
    if (dt_st_send_all_tmo(fd, hdr, 5, DT_ST_TIMEOUT_MS)) return -1;
    if (n && dt_st_send_all_tmo(fd, p, n, DT_ST_TIMEOUT_MS)) return -1;
    return 0;
}
static int dt_st_recv_frame(DTSOCK fd, unsigned char *type, unsigned char *p,
                            size_t pcap, size_t *pn, long long tmo_ms) {
    unsigned char hdr[4];
    long long t0 = dt_now_ms();
    size_t got = 0;
    while (got < 4) {
#ifdef LINUX_BUILD
        ssize_t k = r_recv(fd, hdr + got, 4 - got, 0);
        if (k > 0) { got += (size_t)k; continue; }
        { int e = errno;
          if (e != EAGAIN && e != EWOULDBLOCK) {
              char lb[96];
              snprintf(lb, sizeof(lb), "st recv hdr: err=%d (n=%ld)", e, (long)got);
              dlog(lb);
              return -1; } }
#else
        int k = recv(fd, (char *)hdr + got, (int)(4 - got), 0);
        if (k > 0) { got += (size_t)k; continue; }
        { int e = WSAGetLastError();
          if (e != WSAEWOULDBLOCK) {
              char lb[96];
              snprintf(lb, sizeof(lb), "st recv hdr: err=%d (n=%ld)", e, (long)got);
              dlog(lb);
              return -1; } }
#endif
        fd_set rf; FD_ZERO(&rf);
#ifdef LINUX_BUILD
        FD_SET((int)fd, &rf);
        struct timeval tv = { 0, 50000 };
        int sr = select((int)fd + 1, &rf, NULL, NULL, &tv);
        if (sr < 0) {
            if (errno == EINTR) continue;
            { char lb[80]; snprintf(lb, sizeof(lb), "st recv: select err=%d", errno); dlog(lb); }
            return -1;
        }
        /* sr == 0: no data yet; retry until the budget runs out */
#else
        FD_SET(fd, &rf);
        struct timeval tv = { 0, 50000 };
        int sr = select(0, &rf, NULL, NULL, &tv);
        if (sr < 0) { if (WSAGetLastError() == WSAEINTR) continue; return -1; }
#endif
        if (dt_now_ms() - t0 > tmo_ms) return -1;
    }
    unsigned ml = dt_get32(hdr);
    if (ml < 1 || ml > 65536) return -1;
    if (ml > pcap + 1) return -1;   /* body = type byte + payload */
    got = 0;
    t0 = dt_now_ms();
    while (got < ml) {
#ifdef LINUX_BUILD
        ssize_t k = r_recv(fd, p + got, (size_t)(ml - got), 0);
        if (k > 0) { got += (size_t)k; continue; }
        if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
#else
        int k = recv(fd, (char *)p + got, (int)(ml - got), 0);
        if (k > 0) { got += (size_t)k; continue; }
        if (WSAGetLastError() != WSAEWOULDBLOCK) return -1;
#endif
        fd_set rf; FD_ZERO(&rf);
#ifdef LINUX_BUILD
        FD_SET((int)fd, &rf);
        struct timeval tv = { 0, 50000 };
        int sr = select((int)fd + 1, &rf, NULL, NULL, &tv);
        if (sr < 0) { if (errno == EINTR) continue; return -1; }
        /* sr == 0: not readable yet; retry until budget runs out */
#else
        FD_SET(fd, &rf);
        struct timeval tv = { 0, 50000 };
        int sr = select(0, &rf, NULL, NULL, &tv);
        if (sr < 0) { if (WSAGetLastError() == WSAEINTR) continue; return -1; }
#endif
        if (dt_now_ms() - t0 > tmo_ms) return -1;
    }
    *type = p[0];
    if (ml > 1) memmove(p, p + 1, (size_t)(ml - 1));
    *pn = (size_t)(ml - 1);
    return 0;
}
static void dt_st_close_fd(DTSOCK fd) {
    if (fd == DTSOCK_BAD) return;
#ifdef LINUX_BUILD
    dt_reals();
    if (fd >= 0) r_close(fd);
#else
    if (fd != INVALID_SOCKET) closesocket(fd);
#endif
}
/* fail an opener stream locally (no relay involved) */
static void dt_st_fail_local(struct dt_stream *st, unsigned reason) {
    DLOCK();
    if (st->used && st->state != ST_DEAD) {
        st->state = ST_DEAD;
        st->fail = reason;
        dt_sig_locked(st->gsock);
        { char lb[160];
          snprintf(lb, sizeof(lb), "stream fail pid=%u gsock=%lld sid=%u reason=%u (local)",
                   (unsigned)current_pid(), st->gsock, st->sid, (unsigned)reason);
          dlog(lb); }
    }
    DUNLOCK();
}
#ifdef LINUX_BUILD
static void *dt_stream_thread(void *u);
static void *dt_join_thread(void *u);
static void dt_st_spawn(void *(*fn)(void *), void *arg) {
    pthread_t t; pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &a, fn, arg);
    pthread_attr_destroy(&a);
}
#else
static DWORD WINAPI dt_stream_thread(LPVOID u);
static DWORD WINAPI dt_join_thread(LPVOID u);
static void dt_st_spawn(LPTHREAD_START_ROUTINE fn, void *arg) {
    HANDLE h = CreateThread(NULL, 0, fn, arg, 0, NULL);
    if (h) CloseHandle(h);
}
#endif
/* Opener side: handshake + raw pipe for one fake game connection. */
#ifdef LINUX_BUILD
static void *dt_stream_thread(void *u)
#else
static DWORD WINAPI dt_stream_thread(LPVOID u)
#endif
{
    unsigned sid = (unsigned)(uintptr_t)u;
    long long gsock = 0;
    struct sockaddr_in orig; unsigned origport = 0;
    DLOCK();
    struct dt_stream *st = dt_stream_by_sid(sid);
    if (st) { gsock = st->gsock; orig = st->orig; origport = ntohs(st->orig.sin_port); }
    DUNLOCK();
    if (!st || !gsock) return 0;
    DTSOCK fd = dt_st_dial_relay();
    if (fd == DTSOCK_BAD) {
        dt_st_fail_local(st, STF_JOIN_TIMEOUT);
        return 0;
    }
    {
        int st_aborted = 0;
        DLOCK();
        st_aborted = !st->used || st->dead;
        DUNLOCK();
        if (st_aborted) {
            dt_st_close_fd(fd);
            return 0;
        }
        unsigned dest = dt_virt_node(orig.sin_addr.s_addr); /* 0 = implicit host */
        unsigned char p[14];
        dt_put32(p, g_node); dt_put32(p + 4, dest);
        dt_put32(p + 8, sid); dt_put16(p + 12, origport);
        { char lb[200];
          snprintf(lb, sizeof(lb), "stream open pid=%u gsock=%lld sid=%u dest=%u port=%u",
                   (unsigned)current_pid(), gsock, sid, dest, origport);
          dlog(lb); }
        if (dt_st_send_frame(fd, DT_STOPEN, p, 14) != 0) {
            dt_st_close_fd(fd);
            dt_st_fail_local(st, STF_JOIN_TIMEOUT);
            return 0;
        }
        DLOCK();
        if (st->used && st->sid == sid) st->fd = fd;
        DUNLOCK();
        unsigned char type = 0, rp[16]; size_t rn = 0;
        int r = dt_st_recv_frame(fd, &type, rp, sizeof(rp), &rn, DT_ST_TIMEOUT_MS);
        DLOCK();
        int gone = !st->used || st->sid != sid || st->dead;
        if (!gone) {
            if (r == 0 && type == DT_STOK && rn >= 4 && dt_get32(rp) == sid) {
                st->state = ST_OPEN;
                dt_sig_locked(gsock);
            } else if (r == 0 && type == DT_STFAIL && rn >= 5 && dt_get32(rp) == sid) {
                st->state = ST_DEAD; st->fail = rp[4];
                dt_sig_locked(gsock);
            } else {
                st->state = ST_DEAD; st->fail = STF_JOIN_TIMEOUT;
                dt_sig_locked(gsock);
            }
        }
        int open = (!gone && st->state == ST_OPEN);
        int fail = st->fail;
        DUNLOCK();
        if (open) {
            char lb[128];
            snprintf(lb, sizeof(lb), "stream ok pid=%u gsock=%lld sid=%u",
                     (unsigned)current_pid(), gsock, sid);
            dlog(lb);
        } else if (!gone) {
            char lb[160];
            snprintf(lb, sizeof(lb), "stream fail pid=%u gsock=%lld sid=%u reason=%u",
                     (unsigned)current_pid(), gsock, sid, (unsigned)fail);
            dlog(lb);
            dt_st_close_fd(fd);
            return 0;
        } else {
            dt_st_close_fd(fd);
            return 0;
        }
    }
    /* raw pipe: app out-queue -> relay; relay -> app in-queue.
     * Blocking semantics like the kernel: full relay buffer blocks the
     * thread here (backpressure), full app queue pauses reads. */
    unsigned char buf[65536];
    size_t in0 = 0, out0 = 0;
    for (;;) {
        if (!g_tun_run) break;
        DLOCK();
        int mine = st->used && st->sid == sid;
        int has_out = mine && st->ototal > 0;
        int pause = !mine || st->in_paused;
        int dead = !mine || st->dead;
        DUNLOCK();
        if (dead) break;
        fd_set rf, wf;
        FD_ZERO(&rf); FD_ZERO(&wf);
        if (!pause)
#ifdef LINUX_BUILD
            FD_SET((int)fd, &rf)
#else
            FD_SET(fd, &rf)
#endif
            ;
        if (has_out)
#ifdef LINUX_BUILD
            FD_SET((int)fd, &wf)
#else
            FD_SET(fd, &wf)
#endif
            ;
        struct timeval tv = { 0, 25000 };
#ifdef LINUX_BUILD
        int sr = select((int)fd + 1, pause ? NULL : &rf, has_out ? &wf : NULL, NULL, &tv);
#else
        int sr = select(0, pause ? NULL : &rf, has_out ? &wf : NULL, NULL, &tv);
#endif
        if (!g_tun_run) break;
        if (sr < 0) break;
        int can_rd = (!pause &&
#ifdef LINUX_BUILD
                      FD_ISSET((int)fd, &rf)
#else
                      FD_ISSET(fd, &rf)
#endif
                     );
        int can_wr = (has_out &&
#ifdef LINUX_BUILD
                      FD_ISSET((int)fd, &wf)
#else
                      FD_ISSET(fd, &wf)
#endif
                     );
        if (can_wr) {
            for (;;) {
                unsigned char *sp = NULL; size_t sn = 0;
                DLOCK();
                if (st->used && st->sid == sid && st->oh) {
                    sp = st->oh->p + st->oh->off; sn = st->oh->n - st->oh->off;
                }
                DUNLOCK();
                if (!sp || !sn) break;
#ifdef LINUX_BUILD
                ssize_t k = r_send(fd, sp, sn, 0);
#else
                int k = send(fd, (const char *)sp, (int)sn, 0);
#endif
                if (k <= 0) {
#ifdef LINUX_BUILD
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
#else
                    if (WSAGetLastError() == WSAEWOULDBLOCK) break;
#endif
                    { char lb[80]; snprintf(lb, sizeof(lb), "stream pipe: send err=%d",
#ifdef LINUX_BUILD
                                             errno
#else
                                             WSAGetLastError()
#endif
                                         ); dlog(lb); }
                    break;
                }
                out0 += (size_t)k;
                DLOCK();
                if (st->used && st->sid == sid && st->oh) {
                    st->oh->off += (size_t)k;
                    st->ototal -= (size_t)k;
                    if (st->oh->off >= st->oh->n) {
                        struct dt_chunk *o = st->oh;
                        st->oh = o->next;
                        if (!st->oh) st->ot = NULL;
                        free(o->p); free(o);
                    }
                }
                DUNLOCK();
            }
        }
        if (can_rd) {
#ifdef LINUX_BUILD
            ssize_t n = r_recv(fd, buf, sizeof(buf), 0);
#else
            int n = recv(fd, (char *)buf, (int)sizeof(buf), 0);
#endif
            if (n < 0) {
#ifdef LINUX_BUILD
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
#else
                if (WSAGetLastError() == WSAEWOULDBLOCK) continue;
#endif
                { char lb[96];
                  snprintf(lb, sizeof(lb), "stream pipe: recv err=%d",
#ifdef LINUX_BUILD
                           errno
#else
                           WSAGetLastError()
#endif
                      ); dlog(lb); }
                DLOCK();
                if (st->used && st->sid == sid) {
                    st->state = ST_DEAD; st->fail = 0;
                    dt_sig_locked(gsock);
                }
                DUNLOCK();
                break;
            }
            if (n == 0) {
                DLOCK();
                if (st->used && st->sid == sid) {
                    st->state = ST_DEAD; st->fail = 0; /* peer closed / reset */
                    dt_sig_locked(gsock);
                }
                DUNLOCK();
                { char lb[190];
                  snprintf(lb, sizeof(lb),
                           "stream eof pid=%u gsock=%lld sid=%u in=%llu out=%llu",
                           (unsigned)current_pid(), gsock, sid,
                           (unsigned long long)in0, (unsigned long long)out0);
                  dlog(lb); }
                break;
            }
            in0 += (size_t)n;
            DLOCK();
            if (st->used && st->sid == sid) {
                if (st->total + (size_t)n > DT_ST_MAXIN) {
                    st->in_paused = 1; /* kernel window would close; resume on drain */
                } else {
                    struct dt_chunk *c = (struct dt_chunk *)malloc(sizeof(*c));
                    if (c) {
                        c->p = (unsigned char *)malloc((size_t)n);
                        if (c->p) {
                            memcpy(c->p, buf, (size_t)n);
                            c->n = (size_t)n; c->off = 0; c->next = NULL;
                            if (st->t) st->t->next = c; else st->h = c;
                            st->t = c; st->total += (size_t)n;
                            dt_sig_locked(gsock);
                        } else { st->in_paused = 1; }
                        if (!c->p) free(c);
                    } else st->in_paused = 1;
                }
            }
            DUNLOCK();
        }
    }
    DLOCK();
    if (st->used && st->sid == sid) {
        int app_closed = st->dead;
        st->state = ST_DEAD;
        if (app_closed) {
            st->used = 0;
            st->fd = DTSOCK_BAD;
            struct dt_chunk *c = st->h;
            while (c) { struct dt_chunk *nx = c->next; free(c->p); free(c); c = nx; }
            c = st->oh;
            while (c) { struct dt_chunk *nx = c->next; free(c->p); free(c); c = nx; }
            st->h = st->t = st->oh = st->ot = NULL;
            st->total = st->ototal = 0;
            dt_sig_locked(gsock);
        }
    }
    DUNLOCK();
    dt_st_close_fd(fd);
    return 0;
}
/* Joinee side: serve one inbound stream (DT_STREQ from the control link). */
static void dt_on_streq(unsigned sid, int gport) {
    DLOCK();
    struct dt_hosted *h = NULL;
    for (int i = 0; i < DT_MAXHOST; i++)
        if (!g_hs[i].used) {
            h = &g_hs[i];
            h->used = 1; h->sid = sid; h->real = DTSOCK_BAD; h->fd = DTSOCK_BAD;
            h->live = 0; h->dead = 0; h->last = dt_now_ms();
            break;
        }
    DUNLOCK();
    if (!h) { dlog("hosted req: session table full"); return; }
    { char lb[160];
      snprintf(lb, sizeof(lb), "hosted req pid=%u sid=%u port=%d",
               (unsigned)current_pid(), sid, gport);
      dlog(lb); }
    struct { unsigned sid; int gport; } *a = (typeof(a))malloc(sizeof(*a));
    if (!a) { dt_hs_close(sid); return; }
    a->sid = sid; a->gport = gport;
    dt_st_spawn(dt_join_thread, a);
}
#ifdef LINUX_BUILD
static void *dt_join_thread(void *u)
#else
static DWORD WINAPI dt_join_thread(LPVOID u)
#endif
{
    struct { unsigned sid; int gport; } *a = u;
    unsigned sid = a->sid; int gport = a->gport;
    free(a);
    DTSOCK fd = dt_st_dial_relay();
    if (fd == DTSOCK_BAD) {
        char lb[128];
        snprintf(lb, sizeof(lb), "hosted join fail pid=%u sid=%u relay dial",
                 (unsigned)current_pid(), sid);
        dlog(lb);
        dt_hs_close(sid);
        return 0;
    }
    {
        unsigned char p[8];
        dt_put32(p, g_node); dt_put32(p + 4, sid);
        if (dt_st_send_frame(fd, DT_STJOIN, p, 8) != 0) {
            dt_st_close_fd(fd);
            dt_hs_close(sid);
            return 0;
        }
        /* claim verdict: the relay answers STJOIN on this connection
         * immediately (STOK = this link serves the stream; anything else
         * = a sibling process of the same identity already won). Read it
         * BEFORE bridging so losers never open the game port. */
        {
            unsigned char type = 0, rp[16]; size_t rn = 0;
            if (dt_st_recv_frame(fd, &type, rp, sizeof(rp), &rn,
                                 DT_ST_TIMEOUT_MS) != 0 ||
                type != DT_STOK || rn < 4 || dt_get32(rp) != sid) {
                char lb[160];
                snprintf(lb, sizeof(lb),
                         "hosted join stood down pid=%u sid=%u (dup/busy)",
                         (unsigned)current_pid(), sid);
                dlog(lb);
                dt_st_close_fd(fd);
                dt_hs_close(sid);
                return 0;
            }
        }
        /* local game bridge; retry briefly (the game may still be
         * binding its port right now) */
        int ok = 0;
        for (int i = 0; i < 4 && !ok; i++) {
            if (dt_host_bridge(sid, gport) == 0) ok = 1;
            else dt_msleep(250);
        }
        if (!ok) {
            unsigned char q[5];
            dt_put32(q, sid); q[4] = STF_HOST_FAILED;
            dt_st_send_frame(fd, DT_STFAIL, q, 5);
            char lb[160];
            snprintf(lb, sizeof(lb), "hosted open fail pid=%u sid=%u port=%d",
                     (unsigned)current_pid(), sid, gport);
            dlog(lb);
            dt_st_close_fd(fd);
            dt_hs_close(sid);
            return 0;
        }
        unsigned char q[4];
        dt_put32(q, sid);
        if (dt_st_send_frame(fd, DT_STJOINED, q, 4) != 0) {
            dt_st_close_fd(fd);
            dt_hs_close(sid);
            return 0;
        }
        DLOCK();
        struct dt_hosted *h = dt_hs_by_sid(sid);
        if (h) h->fd = fd;
        DUNLOCK();
        char lb[160];
        snprintf(lb, sizeof(lb), "hosted stream up pid=%u sid=%u port=%d",
                 (unsigned)current_pid(), sid, gport);
        dlog(lb);
    }
    /* raw pipe: relay <-> local game bridge (both directions, blocking
     * sends so a slow local game backpressures the relay like a kernel
     * would, and vice versa). */
    unsigned char buf[65536];
    size_t in0 = 0, out0 = 0;
    DTSOCK real = DTSOCK_BAD;
    DLOCK();
    struct dt_hosted *h0 = dt_hs_by_sid(sid);
    if (h0) real = h0->real;
    DUNLOCK();
    if (real == DTSOCK_BAD) { dt_st_close_fd(fd); dt_hs_close(sid); return 0; }
    for (;;) {
        if (!g_tun_run) break;
        DLOCK();
        struct dt_hosted *h = dt_hs_by_sid(sid);
        int dead = h ? h->dead : 1;
        DUNLOCK();
        if (dead) break;
        fd_set rf;
        FD_ZERO(&rf);
#ifdef LINUX_BUILD
        FD_SET((int)fd, &rf);
        FD_SET((int)real, &rf);
        int mx = (int)fd > (int)real ? (int)fd : (int)real;
        struct timeval tv = { 0, 25000 };
        int sr = select(mx + 1, &rf, NULL, NULL, &tv);
        if (sr <= 0) continue;
        if (FD_ISSET((int)fd, &rf)) {
            ssize_t n = r_recv(fd, buf, sizeof(buf), 0);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                { char lb[96]; snprintf(lb, sizeof(lb), "hosted pipe: relay recv err=%d", errno); dlog(lb); }
                break;
            }
            if (n == 0) {
                char lb[64]; snprintf(lb, sizeof(lb), "hosted pipe: relay EOF"); dlog(lb);
                break;
            }
            in0 += (size_t)n;
            const unsigned char *p = buf;
            while ((size_t)n > 0) {
                ssize_t k = r_send(real, p, (size_t)n, 0);
                if (k <= 0) { if (errno == EINTR) continue; break; }
                p += (size_t)k; n -= (size_t)k;
            }
        }
        if (FD_ISSET((int)real, &rf)) {
            ssize_t n = r_recv(real, buf, sizeof(buf), 0);
            if (n <= 0) break;
            out0 += (size_t)n;
            const unsigned char *p = buf;
            while ((size_t)n > 0) {
                ssize_t k = r_send(fd, p, (size_t)n, 0);
                if (k <= 0) { if (errno == EINTR) continue; break; }
                p += (size_t)k; n -= (size_t)k;
            }
        }
#else
        FD_SET(fd, &rf);
        FD_SET(real, &rf);
        struct timeval tv = { 0, 25000 };
        int sr = select(0, &rf, NULL, NULL, &tv);
        if (sr <= 0) continue;
        if (FD_ISSET(fd, &rf)) {
            int n = recv(fd, (char *)buf, (int)sizeof(buf), 0);
            if (n <= 0) break;
            in0 += (size_t)n;
            const char *p = (const char *)buf;
            while (n > 0) {
                int k = send(real, p, n, 0);
                if (k <= 0) break;
                p += k; n -= k;
            }
        }
        if (FD_ISSET(real, &rf)) {
            int n = recv(real, (char *)buf, (int)sizeof(buf), 0);
            if (n <= 0) break;
            out0 += (size_t)n;
            const char *p = (const char *)buf;
            while (n > 0) {
                int k = send(fd, p, n, 0);
                if (k <= 0) break;
                p += k; n -= k;
            }
        }
#endif
    }
    { char lb[190];
      snprintf(lb, sizeof(lb), "hosted eof pid=%u sid=%u in=%llu out=%llu",
               (unsigned)current_pid(), sid,
               (unsigned long long)in0, (unsigned long long)out0);
      dlog(lb); }
    dt_hs_close(sid);
    return 0;
}

/* TCP tunnel thread: control link (membership, beacons, UDP-over-TCP,
 * stream requests). Game TCP stream DATA never transits this link. */
#ifdef LINUX_BUILD
static void *dt_tcp_thread(void *u) {
#else
static DWORD WINAPI dt_tcp_thread(LPVOID u) {
#endif
    (void)u;
    unsigned char hdr[4], *pl = NULL;
    for (;;) {
        if (!g_tun_run) break;
        dt_init_watchdog();
#ifdef LINUX_BUILD
        dt_reals();
        int s = socket(AF_INET, SOCK_STREAM, 0);
#else
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#endif
#ifdef LINUX_BUILD
        if (s < 0) { dt_msleep(g_init_done ? 1000 : 250); continue; }
#else
        if (s == INVALID_SOCKET) { dt_msleep(g_init_done ? 1000 : 250); continue; }
#endif
        struct sockaddr_in sa;
        if (dt_resolve(&sa) != 0) {
#ifdef LINUX_BUILD
            r_close(s);
#else
            closesocket(s);
#endif
            dt_msleep(g_init_done ? 1000 : 250); continue;
        }
#ifdef LINUX_BUILD
        if (r_connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) { r_close(s); dt_msleep(g_init_done ? 1000 : 250); continue; }
#else
        if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) { closesocket(s); dt_msleep(g_init_done ? 1000 : 250); continue; }
#endif
#ifdef LINUX_BUILD
        g_tcp = s;
#else
        g_tcp = s;
#endif
        g_tcp_up = 1;
        g_tcp_ever_up = 1;
        { char lb[96];
          snprintf(lb, sizeof(lb), "tunnel TCP up pid=%u", (unsigned)current_pid());
          dlog(lb); }
        dt_send_node(); /* (re)register membership + UDP endpoint (+host flag) */
        if (g_udp_tcp) {
            unsigned char z = 0;
            dt_tcp_queue(DT_UDP_MODE, &z, 0); /* declare UDP-over-TCP mode */
        }
        /* game TCP streams run on their own relay connections and
         * survive control redials; nothing to re-announce here. */
        for (;;) {
            if (!g_tun_run) break;
            dt_init_watchdog();
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
            if (t == DT_BCAST && ml >= 5) {
                dt_dispatch_bcast((int)dt_get16(pl + 1), (int)dt_get16(pl + 3),
                                  pl + 5, ml - 5);
            } else if (t == DT_BCAST_FROM && ml >= 9) {
                unsigned node = dt_get32(pl + 1);
                int bport = (int)dt_get16(pl + 5);
                int sport = (int)dt_get16(pl + 7);
                {
                    char lb[360]; int hp = 0;
                    size_t hn = ml - 9 < 110 ? ml - 9 : 110;
                    hp = snprintf(lb, sizeof(lb), "rx FROM node=%u port=%d sp=%d n=%u pid=%u hex=",
                                  node, bport, sport, ml - 9, (unsigned)current_pid());
                    for (size_t qi = 0; qi < hn && hp < (int)sizeof(lb) - 3; qi++)
                        hp += snprintf(lb + hp, sizeof(lb) - hp, "%02x", pl[9 + qi]);
                    dlog(lb);
                }
                dt_dispatch_bcast_from(node, bport, sport, pl + 9, ml - 9);
            } else if (t == DT_ASSIGN && ml >= 2) {
                dt_apply_assign(pl + 1, ml - 1);
            } else if (t == DT_STREQ && ml >= 7) {
                /* another player is joining OUR game. Serve it on a
                 * dedicated per-stream relay connection (join thread);
                 * stream data never transits this control link. */
                unsigned sid = dt_get32(pl + 1);
                int gport = (int)dt_get16(pl + 5);
                dt_on_streq(sid, gport);
            } else if (t == DT_UDP_TUN && ml >= 2) {
                /* UDP-over-TCP mode: one decapsulated UDP-tunnel
                 * datagram; same ingress path as the UDP socket */
                dt_udp_ingress(pl + 1, ml - 1);
            }
        }
redial:
        g_tcp_up = 0;
        { char lb[96];
          snprintf(lb, sizeof(lb), "tunnel TCP redial pid=%u", (unsigned)current_pid());
          dlog(lb); }
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

/* Hosted UDP poller: forwards loopback usess datagrams to the relay.
 * (Hosted TCP streams are served per-connection by join threads.) */
#ifdef LINUX_BUILD
static void *dt_hosted_thread(void *u) {
#else
static DWORD WINAPI dt_hosted_thread(LPVOID u) {
#endif
    (void)u;
#ifdef LINUX_BUILD
    dt_reals();
#endif
    unsigned char buf[65536];
    for (;;) {
        if (!g_tun_run) break;
        /* sweep hosted sessions stuck in PENDING (relay redial lost the
         * STREQ; the join thread will free its own on handshake failure) */
        {
            long long now = dt_now_ms();
            DLOCK();
            for (int i = 0; i < DT_MAXHOST; i++)
                if (g_hs[i].used && !g_hs[i].live && now - g_hs[i].last > 30000)
                    g_hs[i].used = 0;
            DUNLOCK();
        }
        /* snapshot live usess (hosted UDP) fds */
        struct { long long fd; unsigned sid; int gport;
                 struct sockaddr_in cli; int slot; } fds[DT_MAXUSESS];
        int nfds = 0;
        long long now = dt_now_ms();
        DLOCK();
        for (int i = 0; i < DT_MAXUSESS && nfds < (int)(sizeof(fds) / sizeof(fds[0])); i++) {
            if (g_us[i].used) {
#ifdef LINUX_BUILD
                if (g_us[i].real < 0) { g_us[i].used = 0; continue; }
#else
                if (g_us[i].real == INVALID_SOCKET) { g_us[i].used = 0; continue; }
#endif
                if (now - g_us[i].last > 45000) {
                    /* expire idle session */
#ifdef LINUX_BUILD
                    int rs = g_us[i].real;
#else
                    DTSOCK rs = g_us[i].real;
#endif
                    g_us[i].used = 0;
                    DUNLOCK();
#ifdef LINUX_BUILD
                    r_close(rs);
#else
                    closesocket(rs);
#endif
                    DLOCK();
                    continue;
                }
                fds[nfds].fd = (long long)g_us[i].real;
                fds[nfds].sid = 0;
                fds[nfds].gport = g_us[i].game_port;
                fds[nfds].cli = g_us[i].cli; fds[nfds].slot = i; nfds++;
            }
        }
        DUNLOCK();
        if (!nfds) { dt_msleep(100); continue; }
        fd_set rf; FD_ZERO(&rf);
#ifdef LINUX_BUILD
        int maxfd = -1;
        for (int i = 0; i < nfds; i++) {
            FD_SET((int)fds[i].fd, &rf);
            if ((int)fds[i].fd > maxfd) maxfd = (int)fds[i].fd;
        }
        struct timeval tv = {0, 100000};
        int r = select(maxfd + 1, &rf, NULL, NULL, &tv);
#else
        for (int i = 0; i < nfds; i++) FD_SET((SOCKET)fds[i].fd, &rf);
        struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 100000;
        int r = select(0, &rf, NULL, NULL, &tv);
#endif
        if (!g_tun_run) break;
        if (r <= 0) continue;
        for (int i = 0; i < nfds; i++) {
#ifdef LINUX_BUILD
            if (!FD_ISSET((int)fds[i].fd, &rf)) continue;
#else
            if (!FD_ISSET((SOCKET)fds[i].fd, &rf)) continue;
#endif
            {
                /* hosted UDP: game -> tunnel (only our game talks here).
                 * Hosted TCP data flows on per-stream relay connections
                 * and is served by the join threads, not here. */
#ifdef LINUX_BUILD
                ssize_t n = r_recv((int)fds[i].fd, buf, sizeof(buf), 0);
#else
                int n = recv((SOCKET)fds[i].fd, (char *)buf, (int)sizeof(buf), 0);
#endif
                if (n <= 0) continue;
                const char *mip = NULL; int ml = 0;
                /* rebuild caller triple from snapshot */
                char ipb[64]; int iplen;
                {
                    unsigned long a = ntohl(fds[i].cli.sin_addr.s_addr);
                    iplen = snprintf(ipb, sizeof(ipb), "%lu.%lu.%lu.%lu",
                                     (a >> 24) & 255, (a >> 16) & 255,
                                     (a >> 8) & 255, a & 255);
                    mip = ipb; ml = iplen;
                }
                size_t pktn = 4 + 2 + 2 + (size_t)ml + 2 + (size_t)n;
                unsigned char *d = (unsigned char *)malloc(pktn);
                if (!d) continue;
                d[0] = 'V'; d[1] = 'N'; d[2] = DU_VER; d[3] = DU_S2C;
                dt_put16(d + 4, (unsigned)fds[i].gport);
                dt_put16(d + 6, (unsigned)ml);
                memcpy(d + 8, mip, (size_t)ml);
                dt_put16(d + 8 + ml, (unsigned)ntohs(fds[i].cli.sin_port));
                memcpy(d + 10 + ml, buf, (size_t)n);
                {
                    struct sockaddr_in sa;
                    if (dt_resolve(&sa) == 0) {
#ifdef LINUX_BUILD
                        r_sendto(g_udptun, d, pktn, 0, (struct sockaddr *)&sa, sizeof(sa));
#else
                        if (g_udptun != INVALID_SOCKET)
                            sendto(g_udptun, (const char *)d, (int)pktn, 0,
                                   (struct sockaddr *)&sa, sizeof(sa));
#endif
                    }
                }
                free(d);
                DLOCK();
                for (int j = 0; j < DT_MAXUSESS; j++)
                    if (g_us[j].used && j == fds[i].slot) { g_us[j].last = dt_now_ms(); break; }
                DUNLOCK();
            }
        }
    }
#ifdef LINUX_BUILD
    return NULL;
#else
    return 0;
#endif
}

/* One UDP-tunnel datagram (UDP socket or decapsulated T_UDP_TUN):
 * addressed game/ICMP traffic for our sockets. Shared by the UDP
 * thread and the TCP thread (UDP-over-TCP mode). */
static void dt_udp_ingress(const unsigned char *buf, size_t n) {
    if (n < 10 || buf[0] != 'V' || buf[1] != 'N' || buf[2] != DU_VER) return;
    { char lb[80]; snprintf(lb, sizeof(lb), "udp tun in op=0x%02x n=%d pid=%u", buf[3], (int)n, (unsigned)current_pid()); dlog(lb); }
    if (buf[3] == DU_C2S) {
        /* inbound: another player targets OUR hosted game */
        int gp2 = dt_get16(buf + 4), il2 = dt_get16(buf + 6);
        if (8 + il2 + 2 > (int)n) return;
        {
            int cport2 = dt_get16(buf + 8 + il2);
            if (!dt_hosted_udp_in(gp2, buf + 8, il2, cport2,
                                  buf + 10 + il2, n - 10 - (size_t)il2))
                dt_direct_udp_in(gp2, buf + 8, il2,
                                 buf + 10 + il2, n - 10 - (size_t)il2);
        }
        return;
    }
    if (buf[3] == DU_ICMP_REQ || buf[3] == DU_ICMP_REP) {
        /* ping request/reply: addressed, never looped back by relay */
        if (n >= 16) {
            unsigned src = dt_get32(buf + 4), dest = dt_get32(buf + 8);
            unsigned iid = dt_get16(buf + 12), seq = dt_get16(buf + 14);
            dt_icmp_in(buf[3] == DU_ICMP_REP, src, dest, iid, seq,
                       buf + 16, n - 16);
        }
        return;
    }
    if (buf[3] != DU_S2C) return;
    dlog("udp tun: S2C in");
    {
        int gp = dt_get16(buf + 4), il = dt_get16(buf + 6);
        int mp, slot;
        const unsigned char *raw;
        size_t rl;
        struct sockaddr_in orig; long long gs = -1; int ok = 0;
        if (8 + il + 2 > (int)n) return;
        mp = dt_get16(buf + 8 + il);
        raw = buf + 10 + il; rl = n - 10 - (size_t)il;
        slot = dt_unmark(mp);
        DLOCK();
        if (slot >= 0 && slot < DT_MAXSLOT && g_sl[slot].used && g_sl[slot].game_port == gp) {
            orig = g_sl[slot].orig; gs = g_sl[slot].gsock; ok = 1;
        }
        DUNLOCK();
        if (ok) dt_udp_push(gs, raw, rl, &orig);
        else dlog("udp tun: slot miss");
    }
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
        g_tun_conn = 0;
        dt_tun_setup(s);
        dt_send_node();      /* punch the reply pinhole right away */
        dt_send_udp_node();
    }
    for (;;) {
        if (!g_tun_run) break;
        {
            static long long last_nd = 0;
            long long nown = dt_now_ms();
            if (nown - last_nd > 12000) {
                last_nd = nown;
                dt_send_node();      /* TCP: membership + UDP endpoint */
                dt_send_udp_node();  /* UDP: refresh NAT mapping */
            }
        }
        fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
        struct timeval tv = {0, 200000};
        int r = select(s + 1, &rf, NULL, NULL, &tv);
        if (!g_tun_run) break;
        if (r <= 0) continue;
        unsigned char buf[65535];
        ssize_t n = r_recv(s, buf, sizeof(buf), 0);
        if (n <= 0) continue;
        dt_udp_ingress(buf, (size_t)(n > 0 ? n : 0));
    }
    return NULL;
#else
    SOCKET s = g_udptun;
    if (s == INVALID_SOCKET) {
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) return 0;
        g_udptun = s;
        g_tun_conn = 0;
        dt_tun_setup(s);
        dt_send_node();      /* punch the reply pinhole right away */
        dt_send_udp_node();
    }
    for (;;) {
        if (!g_tun_run) break;
        {
            static long long last_nd = 0;
            long long nown = dt_now_ms();
            if (nown - last_nd > 12000) {
                last_nd = nown;
                dt_send_node();      /* TCP: membership + UDP endpoint */
                dt_send_udp_node();  /* UDP: refresh NAT mapping */
            }
        }
        fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
        struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 200000;
        int r = select(0, &rf, NULL, NULL, &tv);
        if (!g_tun_run) break;
        if (r <= 0) continue;
        unsigned char buf[65535];
        int n = recv(s, (char *)buf, (int)sizeof(buf), 0);
        if (n <= 0) continue;
        dt_udp_ingress(buf, (size_t)(n > 0 ? n : 0));
    }
    return 0;
#endif
}

static void dt_start(void) {
    if (g_tun_started || !g_direct) return;
    g_tun_started = 1; g_tun_run = 1;
    g_init_t0 = dt_now_ms(); /* watchdog baseline: threads start below */
    g_fakeip = inet_addr("192.168.7.1");
    if (!g_node) {
        /* One identity per process TREE: a child (GBE self-restart chain,
         * injected sub-process, plain fork/exec) inherits LAN_HOOK_NODE
         * from the parent environment and adopts the same node_id -> the
         * relay sees the whole tree as ONE host (one vnode, many links).
         * Roots generate once, then publish into their OWN environment so
         * every later CreateProcess/exec child inherits it. Can also be
         * set manually (LAN_HOOK_NODE=709102507) to merge separate
         * launches into one identity. */
        const char *ne = getenv("LAN_HOOK_NODE");
        unsigned long ev = (ne && ne[0]) ? strtoul(ne, NULL, 0) : 0;
        if (ev) {
            g_node = (unsigned)ev;
        } else {
            /* stable-ish random node id (loopback tests fork rarely collide) */
#ifdef LINUX_BUILD
            dt_rand_state = (unsigned)dt_now_ms() ^ ((unsigned)getpid() << 16);
#else
            dt_rand_state = (unsigned)GetTickCount() ^ (GetCurrentProcessId() << 16);
#endif
            g_node = dt_rand() | 1;
        }
        {
            char nb[24];
            snprintf(nb, sizeof nb, "%u", g_node);
#ifdef LINUX_BUILD
            setenv("LAN_HOOK_NODE", nb, 1);
#else
            SetEnvironmentVariableA("LAN_HOOK_NODE", nb);
#endif
        }
        { char lb[96];
          snprintf(lb, sizeof(lb), "identity pid=%u node=%u%s",
                   (unsigned)current_pid(), g_node, ev ? " (inherited)" : "");
          dlog(lb); }
    }
    dt_send_udp_node(); /* refresh even if the socket below already exists */
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
            else {
                g_udptun = s;
                g_tun_conn = 0;
                dt_tun_setup(s);
                dt_send_node();      /* punch the reply pinhole now */
                dt_send_udp_node();
            }
        }
    }
#else
    {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s != INVALID_SOCKET) {
            struct sockaddr_in b; memset(&b, 0, sizeof(b));
            b.sin_family = AF_INET; b.sin_addr.s_addr = htonl(INADDR_ANY); b.sin_port = 0;
            if (bind(s, (struct sockaddr *)&b, sizeof(b)) != 0) { closesocket(s); }
            else {
                g_udptun = s;
                g_tun_conn = 0;
                dt_tun_setup(s);
                dt_send_node();      /* punch the reply pinhole now */
                dt_send_udp_node();
            }
        }
    }
#endif
#ifdef LINUX_BUILD
    {
        pthread_t t; pthread_attr_t a; pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        pthread_create(&t, &a, dt_tcp_thread, NULL);
        pthread_create(&t, &a, dt_udp_thread, NULL);
        pthread_create(&t, &a, dt_hosted_thread, NULL);
        pthread_attr_destroy(&a);
    }
#else
    if (!g_dcs_init) { InitializeCriticalSection(&g_dcs); g_dcs_init = 1; }
    {
        HANDLE t = CreateThread(NULL, 0, dt_tcp_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
        t = CreateThread(NULL, 0, dt_udp_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
        t = CreateThread(NULL, 0, dt_hosted_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
#endif
    /* Lease barrier: LAN titles enumerate their interfaces once, early,
     * and trust peers only from subnets they see as local; the adapter
     * shim can only answer if our virtual address already exists when
     * that enumeration runs. A VPN service gets this ordering from the
     * kernel (its interface predates the game); we get it by not
     * finishing initialization until the relay's ASSIGN (our vnode) is
     * in hand. The injector holds the game suspended through init, so
     * the title simply starts a few hundred ms later.
     *
     * A missing lease is fatal (see dt_fatal): without it the tunnel
     * cannot work. LAN_HOOK_LEASE_WAIT=0 skips the wait AND the
     * watchdog for unassigned starts. */
    {
        /* Default 3000ms: fail fast on a dead relay instead of hanging
         * the game startup. N>=0 caps the wait here; LAN_HOOK_LEASE_WAIT
         * overrides (0 skips, larger values wait longer). */
        long long budget = 3000;
        long long t0, last_warn = 0;
        int no_wait = 0;
        const char *wb = getenv("LAN_HOOK_LEASE_WAIT");
        if (wb && wb[0]) {
            long long v = atoll(wb);
            if (v == 0) no_wait = 1;
            else if (v < 0) budget = -1; /* infinite: watchdog decides */
            else if (v <= 600000) budget = v;
        }
        {
            const char *fb = getenv("LAN_HOOK_INIT_TIMEOUT");
            g_fatal_after_ms = 30000;
            if (fb && fb[0]) {
                long long v = atoll(fb);
                if (v >= 0 && v <= 600000) g_fatal_after_ms = v;
            }
            if (no_wait) g_fatal_after_ms = 0;
        }
        g_init_t0 = dt_now_ms();
        t0 = g_init_t0;
        while (!g_have_assign && g_tun_run && !no_wait) {
            long long e = dt_now_ms() - t0;
            if (budget >= 0 && e >= budget) break;
            if (e - last_warn >= 5000) {
                last_warn = e;
#ifndef LINUX_BUILD
                flog("LanHookInit: waiting for relay lease...");
#else
                dlog("waiting for relay lease...");
#endif
            }
#ifdef LINUX_BUILD
            usleep(20000);
#else
            Sleep(20);
#endif
        }
        if (!g_have_assign && g_tun_run && !no_wait) {
            /* Barrier cap hit (or watchdog already past due): the game
             * would start broken. Fail loudly instead. */
            int code = dt_fatal_code();
            dt_fatal(code, code == SL_FATAL_NORELAY
                     ? "cannot reach relay (check server/port, relay running, firewall)"
                     : "relay connected but no virtual-IP lease (check token, relay log)");
        }
        dlog("lease acquired before install");
    }
}

/* --- hook call-ins: 1 = consumed (tunnel), 0 = passthrough to real --- */
static unsigned dt_next_sid(void) {
    /* room-wide unique stream id (the relay keys streams by it): random,
     * not a per-process counter (two nodes would otherwise collide) */
    unsigned v;
    do { v = dt_rand(); } while (!v);
    return v;
}
/* Outbound UDP source identity: our virtual IP (unique per node) when
 * assigned, else loopback. Unique triples keep relay per-dest flows and
 * host session tables from merging two players that share home-LAN
 * numbering (or two hook sockets that share slot 0 -> 127.0.0.1:50000).
 * Player-side demux uses the mark/slot, so the IP choice is safe. */
static int dt_src_ip(char *out, size_t n) {
    unsigned v;
    DLOCK(); v = g_myvirt; DUNLOCK();
    if (!v || n < 16) return 0;
    snprintf(out, n, "%u.%u.%u.%u",
             (v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255);
    return 1;
}
/* Raw tunnel-UDP transmit to the relay. */
/* Prepare the UDP tunnel socket: connect() pins the exact 4-tuple to
 * the relay (so the reply pinhole stays unambiguous) on an ephemeral
 * port; outbound keepalives keep the NAT mapping fresh. */
static void dt_tun_setup(DTSOCK s) {
    struct sockaddr_in sa;
    if (dt_resolve(&sa) == 0 &&
        connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        g_tun_conn = 1;
        dlog("udp tun: connected to relay");
    }
}
static void dt_udp_tun_send(const unsigned char *d, size_t n) {
    struct sockaddr_in sa;
    if (g_udp_tcp) {
        /* UDP-over-TCP: game datagrams ride the TCP link (same bytes,
         * decapsulated by the relay). Keeps working where inbound UDP
         * is filtered; costs head-of-line blocking, hence opt-in. */
        unsigned char *p = (unsigned char *)malloc(n ? n : 1);
        if (!p) return;
        if (n) memcpy(p, d, n);
        dt_tcp_queue(DT_UDP_TUN, p, n);
        free(p);
        dlog("udp game: via TCP link");
        return;
    }
    if (dt_resolve(&sa) != 0) { dlog("udp game: resolve failed"); return; }
#ifdef LINUX_BUILD
    dt_reals();
    int u = g_udptun;
    if (u >= 0) {
        ssize_t k = g_tun_conn ? r_send(u, d, n, 0)
                               : r_sendto(u, d, n, 0, (struct sockaddr *)&sa, sizeof(sa));
        if (k < 0) dlog("udp game: tunnel send failed");
    } else dlog("udp game: no tunnel sock yet");
#else
    DTSOCK u = g_udptun;
    if (u != INVALID_SOCKET) {
        int k = g_tun_conn ? send(u, (const char *)d, (int)n, 0)
                           : sendto(u, (const char *)d, (int)n, 0, (struct sockaddr *)&sa, sizeof(sa));
        if (k < 0 && g_debug) {
            char lb[96];
            snprintf(lb, sizeof(lb), "udp tun send fail %d n=%d",
                     WSAGetLastError(), (int)n);
            dlog(lb);
        }
    } else dlog("udp game: no tunnel sock yet");
#endif
}
/* Outbound sendto routing. Returns 1 when consumed: virtual peer IP ->
 * addressed P2P datagram; broadcast -> TCP BCAST frame; other LAN ->
 * UDP GAME datagram. Returns 0 (passthrough) otherwise. */
/* Same-host shortcut: traffic addressed to this machine (loopback or any
 * of its own interface addresses) must NOT enter the tunnel. On a real
 * LAN such packets already loop locally, and several games' discovery
 * relies on that self-loop (peer-list announcements sent to the local
 * LAN IP, overlay IPC on 127.0.0.1). Interface list cached ~30s. */
static unsigned long g_lips[16];
static int g_nlips = -1;
static long long g_lips_next = 0;
/* (Re)build the cached list of this machine's interface addresses. */
static void lips_refresh(void) {
    long long now = dt_now_ms();
    char host[256];
    struct addrinfo hints, *res = 0, *rp;
    DLOCK();
    if (g_nlips >= 0 && now < g_lips_next) { DUNLOCK(); return; }
    DUNLOCK();
    if (gethostname(host, sizeof(host)) != 0) host[0] = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    if (host[0] && getaddrinfo(host, 0, &hints, &res) == 0) {
        DLOCK();
        g_nlips = 0;
        for (rp = res; rp && g_nlips < (int)(sizeof(g_lips) / sizeof(g_lips[0]));
             rp = rp->ai_next)
            if (rp->ai_family == AF_INET && rp->ai_addrlen >= sizeof(struct sockaddr_in))
                g_lips[g_nlips++] = ((struct sockaddr_in *)rp->ai_addr)->sin_addr.s_addr;
        g_lips_next = dt_now_ms() + 30000;
        DUNLOCK();
        freeaddrinfo(res);
    }
}
/* strict loopback (inbound isolation predicate: tunnel data never rides
 * the real stack; only the hook's own 127.0.0.1 bridge traffic may) */
static int ipv4_is_loopback(unsigned long net_order) {
    return (ntohl(net_order) >> 24) == 127;
}
/* LAN_ONLY drops can be a steady stream (LAN beacons); log 1s bursts. */
static void dt_log_wire_drop(unsigned long net_order) {
    static long last = 0;
    unsigned long h = ntohl(net_order), now;
#ifdef LINUX_BUILD
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    now = (unsigned long)(ts.tv_sec);
#else
    now = GetTickCount() / 1000;
#endif
    if (g_debug && (long)(now - last) > 0) {
        char lb[112];
        last = (long)now;
        snprintf(lb, sizeof(lb), "lan-only: drop wire src=%lu.%lu.%lu.%lu",
                 (h >> 24) & 255, (h >> 16) & 255, (h >> 8) & 255, h & 255);
        dlog(lb);
    }
}
static int ipv4_is_local(unsigned long net_order) {
    unsigned long h = ntohl(net_order);
    int i, hit = 0;
    if ((h >> 24) == 127) return 1;
    lips_refresh();
    DLOCK();
    for (i = 0; i < g_nlips; i++) if (g_lips[i] == net_order) { hit = 1; break; }
    DUNLOCK();
    return hit;
}
/* Primary interface address as dotted string (the source a NIC would put
 * on locally delivered traffic). 0 on failure. */
static int dt_machine_ip(char *out, int n) {
    unsigned long a = 0;
    int ok = 0;
    lips_refresh();
    DLOCK();
    if (g_nlips > 0) { a = g_lips[0]; ok = 1; }
    DUNLOCK();
    if (!ok) return 0;
    snprintf(out, n, "%lu.%lu.%lu.%lu", a & 255, (a >> 8) & 255,
             (a >> 16) & 255, (a >> 24) & 255);
    return 1;
}
/* ---- ICMP (ping) over the UDP tunnel --------------------------------
 * Raw/ICMP sockets and (Windows) IcmpSendEcho are tunneled like game
 * UDP: echo requests become addressed REQ frames, replies come back as
 * REP frames and are re-materialized as echo replies for the app.
 * Same loopback rules as everything else: self-pings are answered
 * locally, the relay never echoes to source (it drops), broadcast
 * pings fan out per-member. Non-echo ICMP and real-LAN destinations
 * stay on the real stack untouched. ---- */
static int dt_is_icmp_sock(long long gsock) {
    int t = dt_sock_type(gsock);
    if (t == SOCK_RAW) {
#ifdef LINUX_BUILD
        int p = 0; socklen_t l = sizeof(p);
        if (getsockopt((int)gsock, SOL_SOCKET, SO_PROTOCOL, &p, &l) == 0)
            return p == IPPROTO_ICMP;
#endif
        return 1; /* raw: the payload parse decides (ICMPv4 echo only) */
    }
#ifdef LINUX_BUILD
    if (t == SOCK_DGRAM) { /* unprivileged "ping" sockets */
        int p = 0; socklen_t l = sizeof(p);
        if (getsockopt((int)gsock, SOL_SOCKET, SO_PROTOCOL, &p, &l) == 0)
            return p == IPPROTO_ICMP;
    }
#endif
    return 0;
}
/* UDP-like for queue purposes: normal datagram sockets + ICMP sockets
 * (both consume tunnel queues via the same recv paths). */
static int dt_is_udp_like(long long gsock) {
    if (dt_sock_type(gsock) == SOCK_DGRAM) return 1;
    return dt_is_icmp_sock(gsock);
}
/* our own relay's virtual address (.1 of the assigned subnet), 0 if none */
static unsigned dt_relay_virt(void) {
    unsigned v = 0;
    DLOCK();
    if (g_nmembers > 0) v = dt_ipnum(g_vnetb) | 1;
    DUNLOCK();
    return v;
}
/* in our virtual subnet at all (any host address)? */
static int dt_in_vnet(unsigned long inaddr) {
    unsigned char ab[4];
    int full, rem, ok = 1;
    memcpy(ab, &inaddr, 4);
    DLOCK();
    if (g_nmembers <= 0 || g_vbits <= 0 || g_vbits > 32) ok = 0;
    else {
        full = g_vbits / 8; rem = g_vbits % 8;
        if (memcmp(g_vnetb, ab, (size_t)full) != 0) ok = 0;
        else if (rem) {
            unsigned m = (0xFFu << (8 - rem)) & 0xFFu;
            if (((unsigned)g_vnetb[full] & m) != ((unsigned)ab[full] & m)) ok = 0;
        }
    }
    DUNLOCK();
    return ok;
}
/* all host bits set = subnet broadcast (.255 on a /24) */
static int dt_is_vnet_bcast(unsigned long inaddr) {
    unsigned char ab[4];
    int i, full, rem;
    if (!dt_in_vnet(inaddr)) return 0;
    memcpy(ab, &inaddr, 4);
    full = g_vbits / 8; rem = g_vbits % 8;
    for (i = full + (rem ? 1 : 0); i < 4; i++)
        if (ab[i] != 0xFF) return 0;
    if (rem) {
        unsigned m = 0xFFu >> rem;
        if ((ab[full] & m) != m) return 0;
    }
    return 1;
}
/* ICMPv4 echo request? fills id/seq/payload view. */
static int dt_icmp_parse_req(const unsigned char *buf, size_t len,
                             unsigned *id, unsigned *seq,
                             const unsigned char **data, size_t *dlen) {
    if (len < 8 || buf[0] != 8 || buf[1] != 0) return 0;
    *id = ((unsigned)buf[4] << 8) | buf[5];
    *seq = ((unsigned)buf[6] << 8) | buf[7];
    *data = buf + 8; *dlen = len - 8;
    return 1;
}
static unsigned short dt_icmp_cksum(const unsigned char *b, size_t n) {
    unsigned sum = 0;
    while (n > 1) { sum += ((unsigned)b[0] << 8) | b[1]; b += 2; n -= 2; }
    if (n) sum += (unsigned)b[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short)~sum;
}
/* echo reply bytes into out (needs 8+dlen); returns total length */
static size_t dt_icmp_build_rep(unsigned char *out, unsigned id, unsigned seq,
                                const unsigned char *data, size_t dlen) {
    unsigned c;
    out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 0;
    out[4] = (id >> 8) & 255; out[5] = id & 255;
    out[6] = (seq >> 8) & 255; out[7] = seq & 255;
    if (dlen) memcpy(out + 8, data, dlen);
    c = dt_icmp_cksum(out, 8 + dlen);
    out[2] = (c >> 8) & 255; out[3] = c & 255;
    return 8 + dlen;
}
/* outstanding echo ids per raw socket, for reply matching (id is
 * app-chosen and shared across its seq series; entries expire). */
#define DT_MAXICMP 128
struct dt_icmp_out { int used; long long gsock; unsigned id; long long last; };
static struct dt_icmp_out g_io[DT_MAXICMP];
static void dt_icmp_note(long long gsock, unsigned id) {
    int i, freei = -1, oldi = -1;
    long long now = dt_now_ms(), oldest = now;
    DLOCK();
    for (i = 0; i < DT_MAXICMP; i++) {
        if (g_io[i].used && g_io[i].gsock == gsock && g_io[i].id == id) {
            g_io[i].last = now; DUNLOCK(); return;
        }
        if (!g_io[i].used && freei < 0) freei = i;
        if (g_io[i].used && g_io[i].last < oldest) { oldest = g_io[i].last; oldi = i; }
    }
    i = (freei >= 0) ? freei : oldi;
    if (i >= 0) { g_io[i].used = 1; g_io[i].gsock = gsock; g_io[i].id = id; g_io[i].last = now; }
    DUNLOCK();
}
static int dt_icmp_match(long long gsock, unsigned id) {
    int i, hit = 0;
    long long now = dt_now_ms();
    DLOCK();
    for (i = 0; i < DT_MAXICMP; i++)
        if (g_io[i].used && g_io[i].gsock == gsock && g_io[i].id == id &&
            now - g_io[i].last < 30000) { hit = 1; break; }
    DUNLOCK();
    return hit;
}
/* queue an echo reply (from a virtual address, numeric octet0-MSB) to
 * every local ICMP socket waiting on this id */
static void dt_icmp_deliver(unsigned from_virt, unsigned id, unsigned seq,
                            const unsigned char *data, size_t dlen) {
    unsigned char rep[1500];
    size_t rn;
    long long gs[DT_MAXICMP];
    int i, n = 0;
    struct sockaddr_in from;
    if (8 + dlen > sizeof(rep)) return;
    rn = dt_icmp_build_rep(rep, id, seq, data, dlen);
    memset(&from, 0, sizeof(from));
    from.sin_family = AF_INET;
    from.sin_addr.s_addr = htonl(from_virt);
    from.sin_port = 0;
    DLOCK();
    for (i = 0; i < DT_MAXUDP && n < DT_MAXICMP; i++)
        if (g_uq[i].used && !g_uq[i].closed) gs[n++] = g_uq[i].gsock;
    DUNLOCK();
    for (i = 0; i < n; i++) {
        if (!dt_is_icmp_sock(gs[i])) continue;
        if (!dt_icmp_match(gs[i], id)) continue;
        dt_udp_push(gs[i], rep, rn, &from);
    }
}
/* reply to our own socket immediately (self-ping / broadcast self-part):
 * what a NIC delivers when we are our own destination */
static void dt_icmp_self(long long gsock, unsigned id, unsigned seq,
                         const unsigned char *data, size_t dlen) {
    unsigned char rep[1500];
    size_t rn;
    struct sockaddr_in from;
    unsigned myv;
    if (8 + dlen > sizeof(rep)) return;
    DLOCK(); myv = g_myvirt; DUNLOCK();
    if (!myv) return;
    rn = dt_icmp_build_rep(rep, id, seq, data, dlen);
    memset(&from, 0, sizeof(from));
    from.sin_family = AF_INET;
    from.sin_addr.s_addr = htonl(myv);
    from.sin_port = 0;
    dt_udp_push(gsock, rep, rn, &from);
}
/* send one REQ frame toward dest_node (0 = the relay itself) */
static void dt_icmp_send_req(unsigned dest, unsigned id, unsigned seq,
                             const unsigned char *data, size_t dlen) {
    size_t n = 4 + 4 + 4 + 2 + 2 + dlen;
    unsigned char *d = (unsigned char *)malloc(n ? n : 1);
    if (!d) return;
    d[0] = 'V'; d[1] = 'N'; d[2] = DU_VER; d[3] = DU_ICMP_REQ;
    dt_put32(d + 4, g_node);
    dt_put32(d + 8, dest);
    dt_put16(d + 12, id); dt_put16(d + 14, seq);
    if (dlen) memcpy(d + 16, data, dlen);
    dt_udp_tun_send(d, n);
    free(d);
}
/* Outbound ICMP sendto routing. Returns 1 when consumed. */
static int dt_on_icmp_send(long long gsock, const unsigned char *buf, size_t len,
                           const struct sockaddr_in *dst) {
    unsigned id, seq, vnode, relay1;
    const unsigned char *data;
    size_t dlen;
    if (ipv4_is_local(dst->sin_addr.s_addr)) return 0;   /* same-host: real */
    if (!dt_icmp_parse_req(buf, len, &id, &seq, &data, &dlen)) return 0;
    if (g_debug) {
        unsigned long a = 0; char lb[128];
        memcpy(&a, &dst->sin_addr.s_addr, 4);
        snprintf(lb, sizeof(lb), "icmp send id=%u seq=%u n=%d to %lu.%lu.%lu.%lu",
                 id, seq, (int)dlen,
                 a & 255, (a >> 8) & 255, (a >> 16) & 255, (a >> 24) & 255);
        dlog(lb);
    }
    if (ntohl(dst->sin_addr.s_addr) == g_myvirt) {
        dt_icmp_self(gsock, id, seq, data, dlen);   /* self-ping: local */
        DLOCK(); dt_udp_entry(gsock, 1); DUNLOCK();
        return 1;
    }
    relay1 = dt_relay_virt();
    if (relay1 && ntohl(dst->sin_addr.s_addr) == relay1) {
        dt_icmp_note(gsock, id);
        dt_icmp_send_req(0, id, seq, data, dlen);    /* ping the relay */
        DLOCK(); dt_udp_entry(gsock, 1); DUNLOCK();
        return 1;
    }
    vnode = dt_virt_node(dst->sin_addr.s_addr);
    if (vnode) {
        dt_icmp_note(gsock, id);
        dt_icmp_send_req(vnode, id, seq, data, dlen);
        DLOCK(); dt_udp_entry(gsock, 1); DUNLOCK();
        return 1;
    }
    if (dt_is_vnet_bcast(dst->sin_addr.s_addr)) {
        /* broadcast ping: one addressed request per member (the relay
         * fans out nothing for ICMP; we address explicitly), plus our
         * own reply for the self part, like a NIC broadcast ping */
        int i, nm = 0;
        unsigned nodes[DT_MAXMEMB];
        DLOCK();
        for (i = 0; i < g_nmembers && nm < DT_MAXMEMB; i++)
            nodes[nm++] = g_members[i].node;
        DUNLOCK();
        dt_icmp_note(gsock, id);
        for (i = 0; i < nm; i++) {
            unsigned virt = dt_node_virt(nodes[i]);
            if (!virt || virt == g_myvirt) continue;
            dt_icmp_send_req(nodes[i], id, seq, data, dlen);
        }
        dt_icmp_self(gsock, id, seq, data, dlen);
        DLOCK(); dt_udp_entry(gsock, 1); DUNLOCK();
        return 1;
    }
    return 0;   /* real-LAN destination: real wire */
}
/* Inbound REQ/REP from the UDP tunnel. */
static void dt_icmp_in(unsigned is_rep, unsigned src, unsigned dest,
                       unsigned id, unsigned seq,
                       const unsigned char *data, size_t dlen) {
    unsigned from_virt;
    if (!is_rep) {
        /* echo request addressed to us (the relay never forwards
         * self/other): answer back through the tunnel with our node as
         * source. The request itself is never shown locally, mirroring
         * IcmpSendEcho semantics for raw sockets too. */
        size_t n;
        unsigned char *d;
        if (g_node == 0 || dest != g_node) return;
        n = 4 + 4 + 4 + 2 + 2 + dlen;
        d = (unsigned char *)malloc(n ? n : 1);
        if (!d) return;
        d[0] = 'V'; d[1] = 'N'; d[2] = DU_VER; d[3] = DU_ICMP_REP;
        dt_put32(d + 4, g_node);
        dt_put32(d + 8, src);
        dt_put16(d + 12, id); dt_put16(d + 14, seq);
        if (dlen) memcpy(d + 16, data, dlen);
        dt_udp_tun_send(d, n);
        free(d);
        return;
    }
    from_virt = (src == 0) ? dt_relay_virt() : dt_node_virt(src);
    if (!from_virt) return;
#ifndef LINUX_BUILD
    /* IcmpSendEcho waiters first (they own no socket) */
    if (dt_icmp_pend_complete(id, seq, data, dlen, from_virt)) return;
#endif
    dt_icmp_deliver(from_virt, id, seq, data, dlen);
}
/* LAN_ONLY verdict for an outbound v4 destination: loopback, mesh vnodes
 * and (broadcast/lan) targets the tunnel itself serves are allowed;
 * everything that would reach the physical NIC is a "no route" error. */
static int dt_reject_wire4(const struct sockaddr_in *dst) {
    int dummy = 0;
    if (!g_lan_only) return 0;
    if (ipv4_is_local(dst->sin_addr.s_addr)) return 0;
    if (dt_virt_node(dst->sin_addr.s_addr)) return 0;
    if (sockaddr_is_lan_target((const struct sockaddr *)dst, &dummy)) return 0;
    return 1;
}
static int dt_on_sendto(long long gsock, const unsigned char *buf, size_t len,
                        const struct sockaddr_in *dst) {
    if (dt_is_icmp_sock(gsock))
        return dt_on_icmp_send(gsock, buf, len, dst);
    unsigned vnode = dt_virt_node(dst->sin_addr.s_addr);
    int game_port = ntohs(dst->sin_port);
    if (ipv4_is_local(dst->sin_addr.s_addr)) {
        if (g_debug) {
            unsigned long a = 0; char lb[112];
            memcpy(&a, &dst->sin_addr.s_addr, 4);
            snprintf(lb, sizeof(lb), "sendto local pass %lu.%lu.%lu.%lu:%d n=%d",
                     a & 255, (a >> 8) & 255, (a >> 16) & 255, (a >> 24) & 255,
                     game_port, (int)len);
            dlog(lb);
        }
        return 0;   /* same-host loop stays on the real stack */
    }
    {
        char lb[224];
        unsigned long a = 0; memcpy(&a, &dst->sin_addr.s_addr, 4);
        {
            int rp = 0, vp = -1;
            struct sockaddr_in sn;
#ifdef LINUX_BUILD
            socklen_t sl = sizeof(sn);
            if (getsockname((int)gsock, (struct sockaddr *)&sn, &sl) == 0) rp = ntohs(sn.sin_port);
#else
            int sl = sizeof(sn);
            if (getsockname((SOCKET)gsock, (struct sockaddr *)&sn, &sl) == 0) rp = ntohs(sn.sin_port);
#endif
            DLOCK();
            { struct dt_udp *e = dt_udp_entry(gsock, 0); if (e) vp = e->vport; }
            DUNLOCK();
#ifdef LINUX_BUILD
            snprintf(lb, sizeof(lb), "on_sendto pid=%d fd=%lld port=%d addr=%lu.%lu.%lu.%lu vnode=%u realp=%d vport=%d",
                     (int)getpid(), gsock, game_port, (a & 255), ((a >> 8) & 255), ((a >> 16) & 255),
                     ((a >> 24) & 255), vnode, rp, vp);
#else
            snprintf(lb, sizeof(lb), "on_sendto pid=%u fd=%lld port=%d addr=%lu.%lu.%lu.%lu vnode=%u realp=%d vport=%d",
                     (unsigned)GetCurrentProcessId(), gsock, game_port, (a & 255), ((a >> 8) & 255), ((a >> 16) & 255),
                     ((a >> 24) & 255), vnode, rp, vp);
#endif
        }
        dlog(lb);
    }
    if (vnode && !ipv4_is_bcast(dst->sin_addr.s_addr)) {
        if (ntohl(dst->sin_addr.s_addr) == g_myvirt) {
            /* our own virtual address: loop to our own listeners, exactly
             * like a NIC's self-echo of locally addressed traffic */
            char myip[32];
            if (dt_src_ip(myip, sizeof(myip)))
                dt_direct_udp_in(game_port, (const unsigned char *)myip,
                                 (int)strlen(myip), buf, len);
            return 1;
        }
        {   /* reply-to-mark demux: an app unicasting back to the source
             * (vnode, port) that recvfrom presented hits this path when
             * that port is one of OUR hosted sessions' marks. Marks now
             * live anywhere in the u16 space, so decide by the exact
             * session tuple - never by a port band - and emit a proper
             * S2C instead of a bogus C2S whose game_port would be a
             * mark number with no listener on the far side. */
            int sg = -1; struct sockaddr_in sc;
            memset(&sc, 0, sizeof(sc));
            DLOCK();
            for (int i = 0; i < DT_MAXUSESS; i++)
                if (g_us[i].used &&
                    g_us[i].cli.sin_addr.s_addr == dst->sin_addr.s_addr &&
                    g_us[i].cli.sin_port == dst->sin_port) {
                    sg = g_us[i].game_port; sc = g_us[i].cli; break;
                }
            DUNLOCK();
            if (sg >= 0) {
                char cip[32]; unsigned long sa = ntohl(sc.sin_addr.s_addr);
                int ml = snprintf(cip, sizeof(cip), "%lu.%lu.%lu.%lu",
                                  (sa >> 24) & 255, (sa >> 16) & 255,
                                  (sa >> 8) & 255, sa & 255);
                size_t sn = 4 + 2 + 2 + (size_t)ml + 2 + len;
                unsigned char *sd = (unsigned char *)malloc(sn);
                if (!sd) return 1;
                sd[0] = 'V'; sd[1] = 'N'; sd[2] = DU_VER; sd[3] = DU_S2C;
                dt_put16(sd + 4, (unsigned)sg);
                dt_put16(sd + 6, (unsigned)ml);
                memcpy(sd + 8, cip, (size_t)ml);
                dt_put16(sd + 8 + ml, (unsigned)ntohs(sc.sin_port));
                if (len) memcpy(sd + 10 + ml, buf, len);
                dt_udp_tun_send(sd, sn);
                free(sd);
                return 1;
            }
        }
        /* addressed P2P datagram: same slot scheme, dest-prefixed frame */
        DLOCK();
        struct dt_slot *sl = dt_slot_get(gsock, game_port, dst);
        int slot = sl ? (int)(sl - g_sl) : -1;
        DUNLOCK();
        if (slot < 0) return 1;
        char srcip[32]; const char *mip = "127.0.0.1"; int ml = 9;
        if (dt_src_ip(srcip, sizeof(srcip))) { mip = srcip; ml = (int)strlen(srcip); }
        int mark = dt_mark(slot);
        size_t n = 4 + 4 + 2 + 2 + (size_t)ml + 2 + len;
        unsigned char *d = (unsigned char *)malloc(n);
        if (!d) return 1;
        d[0] = 'V'; d[1] = 'N'; d[2] = DU_VER; d[3] = DU_PDAT;
        dt_put32(d + 4, vnode);
        dt_put16(d + 8, (unsigned)game_port); dt_put16(d + 10, (unsigned)ml);
        memcpy(d + 12, mip, (size_t)ml); dt_put16(d + 12 + ml, (unsigned)mark);
        if (len) memcpy(d + 14 + ml, buf, len);
        dt_udp_tun_send(d, n);
        free(d);
        DLOCK(); dt_udp_entry(gsock, 1); DUNLOCK();
        return 1;
    }
    int port = 0;
    if (!sockaddr_is_lan_target((const struct sockaddr *)dst, &port))
        return dt_reject_wire4(dst) ? -1 : 0;
    if (ipv4_is_bcast(dst->sin_addr.s_addr)) {
        unsigned char *p = (unsigned char *)malloc(4 + len);
        if (!p) return 1;
        {
            int sport = 0;
            struct sockaddr_in sn;
#ifdef LINUX_BUILD
            socklen_t sl = sizeof(sn);
            if (getsockname((int)gsock, (struct sockaddr *)&sn, &sl) == 0)
#else
            int sl = sizeof(sn);
            if (getsockname((SOCKET)gsock, (struct sockaddr *)&sn, &sl) == 0)
#endif
                sport = ntohs(sn.sin_port);
            {   /* shared-port alias: the app (and every baseline peer)
                 * knows this socket by its logical port, not the
                 * ephemeral one the real stack handed us */
                int vp = -1;
                DLOCK();
                { struct dt_udp *e = dt_udp_entry(gsock, 0); if (e) vp = e->vport; }
                DUNLOCK();
                if (vp > 0) sport = vp;
            }
            dt_put16(p, (unsigned)game_port);
            dt_put16(p + 2, (unsigned)sport);
        }
        if (len) memcpy(p + 4, buf, len);
        dt_tcp_queue(DT_BCAST, p, 4 + len);
        free(p);
        DLOCK(); dt_udp_entry(gsock, 1); DUNLOCK();
        /* NIC-style local echo: many LAN discovery schemes seed their
         * peer table from the echo of their own broadcast, which the
         * real stack always delivers to local sockets. Replicate -
         * sourced with OUR VIRTUAL address (the identity a peer's packet
         * carries on the wire). Never the physical NIC ip: apps adopt
         * announce sources into own_ip/peer state (GBE does), so leaking
         * it breaks exactly the isolation LAN_ONLY promises and pollutes
         * PONG peer lists across machines. Pre-lease (no vnode yet) the
         * machine ip stays the honest answer unless we're isolated. */
        {
            char mip[64];
            if (dt_src_ip(mip, (int)sizeof(mip)))
                dt_direct_udp_in(game_port, (const unsigned char *)mip,
                                 (int)strlen(mip), buf, len);
            else if (!g_lan_only &&
                     dt_machine_ip(mip, (int)sizeof(mip)))
                dt_direct_udp_in(game_port, (const unsigned char *)mip,
                                 (int)strlen(mip), buf, len);
        }
        return 1;
    }
    DLOCK();
    struct dt_slot *sl = dt_slot_get(gsock, game_port, dst);
    int slot = sl ? (int)(sl - g_sl) : -1;
    DUNLOCK();
    if (slot < 0) { dlog("udp game: slot table full"); return 1; } /* table full: drop, pretend sent */
    /* build U_GAME_C2S: VN 02 01 | H game | H iplen | ip | H mark | raw */
    char srcip2[32]; const char *mip = "127.0.0.1"; int ml = 9;
    if (dt_src_ip(srcip2, sizeof(srcip2))) { mip = srcip2; ml = (int)strlen(srcip2); }
    int mark = dt_mark(slot);
    size_t n = 4 + 2 + 2 + (size_t)ml + 2 + len;
    unsigned char *d = (unsigned char *)malloc(n);
    if (!d) return 1;
    d[0] = 'V'; d[1] = 'N'; d[2] = DU_VER; d[3] = DU_C2S;
    dt_put16(d + 4, (unsigned)game_port); dt_put16(d + 6, (unsigned)ml);
    memcpy(d + 8, mip, (size_t)ml); dt_put16(d + 8 + ml, (unsigned)mark);
    if (len) memcpy(d + 10 + ml, buf, len);
    dt_udp_tun_send(d, n);
    free(d);
    DLOCK(); dt_udp_entry(gsock, 1); DUNLOCK();
    return 1;
}
static struct dt_stream *dt_stream_alloc(long long gsock,
                                         const struct sockaddr_in *dst,
                                         unsigned *sid_out) {
    unsigned sid = dt_next_sid();
    if (!sid) sid = dt_next_sid();
    DLOCK();
    struct dt_stream *st = NULL;
    for (int i = 0; i < DT_MAXSTREAM; i++)
        if (!g_st[i].used) { st = &g_st[i]; break; }
    if (st) {
        st->used = 1; st->gsock = gsock; st->sid = sid; st->orig = *dst;
        st->h = st->t = NULL; st->total = 0; st->dead = 0;
        st->state = ST_CONNECTING; st->fail = 0;
        st->in_paused = 0; st->connect_signaled = 0;
        st->fd = DTSOCK_BAD;
        st->oh = st->ot = NULL; st->ototal = 0;
        st->an_rx = st->an_tx = 0; st->ab_rx = st->ab_tx = 0; st->a_log = 0;
    }
    DUNLOCK();
    if (st) *sid_out = sid;
    return st;
}
/* Outbound connect routing. Virtual peer IP -> addressed stream (dest
 * node); other LAN target -> implicit stream (relay routes to the
 * designated host / newest beaconer). Each becomes its own real TCP
 * connection to the relay. Returns 1 when consumed, 2 when the
 * socket already has a live stream (WSAEALREADY), else 0 (real stack). */
static int dt_on_connect(long long gsock, const struct sockaddr_in *dst) {
    if (ipv4_is_local(dst->sin_addr.s_addr)) return 0;   /* same-host: real stack */
    if (dt_sock_type(gsock) != SOCK_STREAM) return 0;
    if (dt_reject_wire4(dst)) return 3;  /* LAN_ONLY: no route to host */
    DLOCK();
    struct dt_stream *ex = dt_stream_by_sock(gsock);
    DUNLOCK();
    if (ex) return 2;
    unsigned vnode = dt_virt_node(dst->sin_addr.s_addr);
    int is_vnode = vnode != 0;
    if (!is_vnode) {
        int port = 0;
        if (!sockaddr_is_lan_target((const struct sockaddr *)dst, &port))
            return dt_reject_wire4(dst) ? -1 : 0;
    }
    unsigned sid = 0;
    if (!dt_stream_alloc(gsock, dst, &sid)) return 1; /* table full */
    dt_st_spawn(dt_stream_thread, (void *)(uintptr_t)sid);
    return 1;
}
/* App -> stream out-queue. Returns: len queued; 0 not our stream;
 * -1 stream dead (ECONNRESET); -2 our stream, out-queue full
 * (caller: nonblocking app -> EWOULDBLOCK, blocking app -> wait+retry). */
static int dt_stream_send(long long gsock, const unsigned char *buf, size_t len) {
    unsigned lsid = 0; size_t ln = 0, tot = 0; int dolog = 0;
    DLOCK();
    struct dt_stream *st = dt_stream_by_sock(gsock);
    if (!st) { DUNLOCK(); return 0; }
    if (st->dead || st->state == ST_DEAD) { DUNLOCK(); return -1; }
    if (st->ototal + len > DT_ST_MAXOUT) { DUNLOCK(); return -2; }
    if (len) {
        struct dt_chunk *c = (struct dt_chunk *)malloc(sizeof(*c));
        if (!c) { DUNLOCK(); return -2; }
        c->p = (unsigned char *)malloc(len);
        if (!c->p) { free(c); DUNLOCK(); return -2; }
        memcpy(c->p, buf, len);
        c->n = len; c->off = 0; c->next = NULL;
        if (st->ot) st->ot->next = c; else st->oh = c;
        st->ot = c; st->ototal += len;
        st->ab_tx += len; st->an_tx++;
        tot = st->ab_tx; lsid = st->sid; ln = len;
        long long now = dt_now_ms();
        if (st->an_tx <= 3 || now - st->a_log > 1000) { st->a_log = now; dolog = 1; }
    }
    DUNLOCK();
    if (dolog) {
        char lb[160];
        snprintf(lb, sizeof(lb), "app tx pid=%u gsock=%lld sid=%u n=%zu tot=%zu",
                 (unsigned)current_pid(), gsock, lsid, ln, tot);
        dlog(lb);
    }
    return (int)len;
}
/* App -> stream out-queue with kernel-like backpressure: a nonblocking
 * app gets EWOULDBLOCK when the queue is full; a blocking app simply
 * blocks until there is room (or the stream dies). Shared by the Linux
 * send() and Windows send()/WSASend() hooks. Returns: len queued,
 * 0 not our stream, -1 dead (ECONNRESET set), -2 full (EWOULDBLOCK set
 * for nonblocking apps; blocking apps never see -2). */
static void dt_stream_send_err(int r) {
#ifdef LINUX_BUILD
    if (r == -1) errno = ECONNRESET;
    else if (r == -2) errno = EAGAIN;
#else
    if (r == -1) WSASetLastError(WSAECONNRESET);
    else if (r == -2) WSASetLastError(WSAEWOULDBLOCK);
#endif
}
static int dt_stream_send_wait(long long s, const unsigned char *buf, size_t len) {
    int nonblock = dt_is_nonblock(s);
    for (;;) {
        int r = dt_stream_send(s, buf, len);
        if (r >= 0) return r;
        if (r == -1) { dt_stream_send_err(-1); return -1; }
        if (r == -2) {
            if (nonblock) { dt_stream_send_err(-2); return -2; }
            dt_msleep(5);
            continue;
        }
    }
}
/* pop stream bytes; 1 got (>0), 0 empty, -1 dead */
static int dt_stream_pop(long long gsock, unsigned char *buf, size_t blen, size_t *outn) {
    int r = 0; size_t ln = 0; unsigned lsid = 0; int dolog = 0; size_t tot = 0;
    DLOCK();
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
        if (st->in_paused && st->total < DT_ST_MAXIN / 2) st->in_paused = 0;
        ln = n; lsid = st->sid; st->ab_rx += n; st->an_rx++; tot = st->ab_rx;
        long long now = dt_now_ms();
        if (st->an_rx <= 3 || now - st->a_log > 1000) { st->a_log = now; dolog = 1; }
    } else if (st && (st->dead || st->state == ST_DEAD)) r = -1;
    DUNLOCK();
    if (dolog) {
        char lb[160];
        snprintf(lb, sizeof(lb), "app rx pid=%u gsock=%lld sid=%u n=%zu tot=%zu",
                 (unsigned)current_pid(), gsock, lsid, ln, tot);
        dlog(lb);
    }
    return r;
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
    if (st) r = (st->h || st->dead || st->state == ST_DEAD) ? 1 : 0; /* dead = readable EOF */
    DUNLOCK(); return r;
}
/* one-shot connect-completed (FD_CONNECT): mark reported (Windows
 * WSAEnum path). inline: referenced only there, no unused warning elsewhere. */
static inline void dt_stream_mark_connect(long long gsock) {
    DLOCK();
    struct dt_stream *st = dt_stream_by_sock(gsock);
    if (st) st->connect_signaled = 1;
    DUNLOCK();
}
/* Timeout sockets park in poll()/select() BEFORE ever calling recvfrom,
 * so the wait hooks must register DGRAM interest too — otherwise fan-out
 * finds no entry and tunnel broadcasts are dropped. */
static void dt_udp_ensure(long long gsock) {
    if (!dt_is_udp_like(gsock)) return;
    DLOCK(); dt_udp_entry(gsock, 1); DUNLOCK();
}
static int dt_fd_readable(long long gsock) {
    dt_udp_ensure(gsock);
    return dt_udp_has(gsock) || dt_stream_has(gsock);
}
/* Timeout sockets park in poll()/select() BEFORE ever calling recvfrom,
 * so the wait hooks must register DGRAM interest too — otherwise fan-out
 * finds no entry and tunnel broadcasts are dropped. */
static void dt_on_close(long long gsock) {
    DLOCK();
    struct dt_stream *st = dt_stream_by_sock(gsock);
    int stream_freed = 0;
    if (st) {
        st->dead = 1;          /* stream thread finishes + frees the slot */
        if (st->state != ST_CONNECTING) {
            /* thread already exited (or never started): free now */
            st->used = 0; st->fd = DTSOCK_BAD;
            struct dt_chunk *c = st->h;
            while (c) { struct dt_chunk *n = c->next; free(c->p); free(c); c = n; }
            c = st->oh;
            while (c) { struct dt_chunk *n = c->next; free(c->p); free(c); c = n; }
            st->h = st->t = st->oh = st->ot = NULL;
            st->total = st->ototal = 0;
            stream_freed = 1;
        }
    }
    struct dt_udp *e = dt_udp_entry(gsock, 0);
    if (e) { e->closed = 1; e->used = 0;
        struct dt_dgram *d = e->h; while (d) { struct dt_dgram *n = d->next; free(d->p); free(d); d = n; } e->h = e->t = NULL; }
    for (int i = 0; i < DT_MAXSLOT; i++)
        if (g_sl[i].used && g_sl[i].gsock == gsock) g_sl[i].used = 0;
    dt_sig_locked(gsock); /* wake event waiters with CLOSE (noop on Linux) */
#ifndef LINUX_BUILD
    for (int i = 0; i < DT_MAXEV; i++)
        if (g_evmap[i].used && g_evmap[i].sock == gsock) g_evmap[i].used = 0;
#endif
    DUNLOCK();
    if (!stream_freed && st && st->state == ST_CONNECTING) {
        /* wake the (starting) stream thread so it aborts the handshake */
        dt_st_fail_local(st, STF_HOST_FAILED);
    }
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
    if (!done) { done = 1;
        dlog("ShadowLAN hook v" SHADOWLAN_VERSION " init");
        policy_init(); dt_log_options(); if (g_direct) dt_start(); g_init_done = 1; }
}
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest, socklen_t addrlen) {
    static ssize_t (*real_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t) = 0;
    ensure_init();
    if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");
    if (g_direct && dest && dest->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        {
            int cr = dt_on_sendto((long long)sockfd, (const unsigned char *)buf, len,
                                  (const struct sockaddr_in *)dest);
            if (cr == -1) { errno = ENETUNREACH; return -1; }
            if (cr) return (ssize_t)len;
        }
    }
    return real_sendto(sockfd, buf, len, flags, dest, addrlen);
}
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src, socklen_t *addrlen) {
    static ssize_t (*real_recvfrom)(int, void*, size_t, int, struct sockaddr*, socklen_t*) = 0;
    ensure_init();
    if (!real_recvfrom) real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    if (g_direct) {
        int st = dt_sock_type((long long)sockfd);
        { char lb[128]; snprintf(lb, sizeof(lb), "recvfrom fd=%d type=%d", sockfd, st); dlog(lb); }
        if (st == SOCK_DGRAM || dt_is_icmp_sock((long long)sockfd)) {
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
                ssize_t rn = real_recvfrom(sockfd, buf, len, flags, sp, lp);
                if (g_lan_only && rn > 0 && lp &&
                    *lp >= sizeof(struct sockaddr_in) &&
                    !ipv4_is_loopback(((struct sockaddr_in *)sp)->sin_addr.s_addr)) {
                    dt_log_wire_drop(((struct sockaddr_in *)sp)->sin_addr.s_addr);
                    if (nb) { errno = EAGAIN; return -1; }
                    continue;  /* LAN_ONLY: no wire world beyond the tunnel */
                }
                return rn;
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
    return real_recvfrom(sockfd, buf, len, flags, sp, lp);
}
ssize_t send(int s, const void *buf, size_t len, int flags) {
    static ssize_t (*real_send)(int, const void *, size_t, int) = 0;
    ensure_init();
    if (!real_send) real_send = dlsym(RTLD_NEXT, "send");
    if (g_direct) {
        int r = dt_stream_send_wait((long long)s, (const unsigned char *)buf, len);
        if (r > 0) return (ssize_t)r;
        if (r == -1) { errno = ECONNRESET; return -1; }
        if (r == -2) { errno = EAGAIN; return -1; }
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
        int r = dt_on_connect((long long)s, (const struct sockaddr_in *)a);
        if (r == 3) { errno = ENETUNREACH; return -1; }
        if (r == 1) {
            int nonblock = dt_is_nonblock((long long)s);
            if (nonblock) { errno = EINPROGRESS; return -1; }
            long long t0 = dt_now_ms();
            for (;;) {
                DLOCK();
                struct dt_stream *st = dt_stream_by_sock((long long)s);
                int state = st ? st->state : 0;
                unsigned fail = st ? st->fail : 0;
                DUNLOCK();
                if (state == ST_OPEN) return 0;
                if (state == ST_DEAD) {
                    errno = (fail == STF_JOIN_TIMEOUT) ? ETIMEDOUT : ECONNREFUSED;
                    return -1;
                }
                if (dt_now_ms() - t0 > (long long)DT_ST_TIMEOUT_MS + 500) {
                    errno = ETIMEDOUT;
                    return -1;
                }
                dt_msleep(10);
            }
        }
        if (r == 2) { errno = EALREADY; return -1; }
    }
    return real_connect(s, a, l);
}
int connect(int s, const struct sockaddr *a, socklen_t l) { return my_connect_hook(s, a, l); }
int listen(int s, int backlog) {
    static int (*real_listen)(int, int) = 0;
    ensure_init();
    if (!real_listen) real_listen = dlsym(RTLD_NEXT, "listen");
    int r = real_listen(s, backlog);
    /* game serves a TCP port -> claim designated-host on the relay */
    if (r == 0 && g_direct && dt_sock_type((long long)s) == SOCK_STREAM) {
        struct sockaddr_in a; socklen_t l = sizeof(a);
        if (getsockname(s, (struct sockaddr *)&a, &l) == 0 && a.sin_family == AF_INET)
            dt_claim();
    }
    return r;
}
int getpeername(int s, struct sockaddr *a, socklen_t *l) {
    static int (*real_gp)(int, struct sockaddr*, socklen_t*) = 0;
    ensure_init();
    if (!real_gp) real_gp = dlsym(RTLD_NEXT, "getpeername");
    if (g_direct && a && l && *l >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in o;
        if (dt_getpeer((long long)s, &o)) { memcpy(a, &o, sizeof(o)); *l = sizeof(o); return 0; }
    }
    return real_gp(s, a, l);
}
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    static int (*real_accept)(int, struct sockaddr*, socklen_t*) = 0;
    ensure_init();
    if (!real_accept) real_accept = dlsym(RTLD_NEXT, "accept");
    int fd = real_accept(sockfd, addr, addrlen);
    /* LAN_ONLY: drop wire LAN peers; loopback (bridge) passes. */
    if (g_direct && g_lan_only && fd >= 0 && addr && addrlen &&
        *addrlen >= sizeof(struct sockaddr_in) &&
        !ipv4_is_loopback(((struct sockaddr_in *)addr)->sin_addr.s_addr)) {
        close(fd); errno = EAGAIN; return -1;
    }
    return fd;
}
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    static int (*real_accept4)(int, struct sockaddr*, socklen_t*, int) = 0;
    ensure_init();
    if (!real_accept4) real_accept4 = dlsym(RTLD_NEXT, "accept4");
    int fd = real_accept4(sockfd, addr, addrlen, flags);
    if (g_direct && g_lan_only && fd >= 0 && addr && addrlen &&
        *addrlen >= sizeof(struct sockaddr_in) &&
        !ipv4_is_loopback(((struct sockaddr_in *)addr)->sin_addr.s_addr)) {
        close(fd); errno = EAGAIN; return -1;
    }
    return fd;
}
int close(int fd) {
    static int (*real_close)(int) = 0;
    if (!real_close) real_close = dlsym(RTLD_NEXT, "close");
    if (g_direct) dt_on_close((long long)fd);
    return real_close(fd);
}
int ioctl(int fd, unsigned long request, ...) {
    static int (*real_ioctl)(int, unsigned long, ...) = 0;
    va_list ap;
    ensure_init();
    if (!real_ioctl) real_ioctl = dlsym(RTLD_NEXT, "ioctl");
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (g_direct && request == FIONREAD && arg) {
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock((long long)fd);
        int v = 0;
        if (st) v = (int)st->total;
        DUNLOCK();
        if (st) { *(int *)arg = v; return 0; }
    }
    return real_ioctl(fd, request, arg);
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
        if (fds[i].fd < 0) continue;
        if ((fds[i].events & POLLIN) && dt_fd_readable((long long)fds[i].fd))
            fds[i].revents |= POLLIN;
        if (fds[i].events & (POLLOUT | POLLWRNORM)) {
            int data, dead, wr, cn;
            dt_sock_state_full((long long)fds[i].fd, &data, &dead, &wr, &cn);
            if (wr || cn) fds[i].revents |= POLLOUT;
        }
        if (fds[i].revents) n++;
    }
    return n;
}
/* tunneled writable set: streams that are open (or just connected) and
 * udp sockets; like a real select would report for those */
static int dt_wscan(int nfds, fd_set *w0, fd_set *wout) {
    int n = 0;
    if (!w0 || !wout) return 0;
    for (int fd = 0; fd < nfds; fd++) {
        if (!FD_ISSET(fd, w0)) continue;
        int data, dead, wr, cn;
        dt_sock_state_full((long long)fd, &data, &dead, &wr, &cn);
        if (wr || cn) FD_SET(fd, wout);
    }
    for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, wout)) n++;
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
            if (w) { FD_ZERO(w); dt_wscan(nfds, &w0, w); }
            if (x) FD_ZERO(x);
            int n = 0;
            if (r) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, r)) n++;
            if (w) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, w)) n++;
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
            if (r) *r = rr; if (w) { *w = ww; dt_wscan(nfds, &w0, w); } if (x) *x = xx;
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
            if (!FD_ISSET(fd, r)) continue;
            if (dt_fd_readable((long long)fd)) n++;
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
            if (w) { FD_ZERO(w); dt_wscan(nfds, &w0, w); }
            if (x) FD_ZERO(x);
            int n = 0;
            if (r) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, r)) n++;
            if (w) for (int fd = 0; fd < nfds; fd++) if (FD_ISSET(fd, w)) n++;
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
            if (r) *r = rr; if (w) { *w = ww; dt_wscan(nfds, &w0, w); } if (x) *x = xx;
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
typedef SOCKET (WSAAPI *PFN_accept)(SOCKET, struct sockaddr*, int*);
typedef int (WSAAPI *PFN_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *PFN_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *PFN_connect)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *PFN_bind)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *PFN_WSAConnect)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int (WSAAPI *PFN_getpeername)(SOCKET, struct sockaddr*, int*);
typedef int (WSAAPI *PFN_getsockname)(SOCKET, struct sockaddr*, int*);
typedef int (WSAAPI *PFN_closesocket)(SOCKET);
typedef int (WSAAPI *PFN_listen)(SOCKET, int);
typedef int (WSAAPI *PFN_send)(SOCKET, const char*, int, int);
typedef int (WSAAPI *PFN_recv)(SOCKET, char*, int, int);
typedef int (WSAAPI *PFN_WSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *PFN_WSARecv)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *PFN_ioctlsocket)(SOCKET, long, u_long*);
typedef int (WSAAPI *PFN_WSAEventSelect)(SOCKET, WSAEVENT, long);
typedef int (WSAAPI *PFN_WSAEnumNetworkEvents)(SOCKET, WSAEVENT, LPWSANETWORKEVENTS);
typedef DWORD (WSAAPI *PFN_WSAWaitForMultipleEvents)(DWORD, const WSAEVENT*, BOOL, DWORD, BOOL);
typedef WSAEVENT (WSAAPI *PFN_WSACreateEvent)(void);
typedef BOOL (WSAAPI *PFN_WSACloseEvent)(WSAEVENT);
typedef FARPROC (WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);

static PFN_sendto p_sendto = 0; static PFN_recvfrom p_recvfrom = 0;
static PFN_accept p_accept = 0;
static PFN_WSASendTo p_WSASendTo = 0; static PFN_WSARecvFrom p_WSARecvFrom = 0;
static PFN_connect p_connect = 0; static PFN_WSAConnect p_WSAConnect = 0;
static PFN_bind p_bind = 0;
static PFN_getpeername p_getpeername = 0; static PFN_closesocket p_closesocket = 0;
static PFN_getsockname p_getsockname = 0;
static PFN_listen p_listen = 0;
static PFN_send p_send = 0; static PFN_recv p_recv = 0;
static PFN_WSASend p_WSASend = 0; static PFN_WSARecv p_WSARecv = 0;
static PFN_ioctlsocket p_ioctlsocket = 0;
static PFN_WSAEventSelect p_WSAEventSelect = 0;
static PFN_WSAEnumNetworkEvents p_WSAEnumNetworkEvents = 0;
static PFN_WSAWaitForMultipleEvents p_WSAWaitForMultipleEvents = 0;
static PFN_WSACreateEvent p_WSACreateEvent = 0;
static PFN_WSACloseEvent p_WSACloseEvent = 0;
static HMODULE g_hself = 0;
static PFN_GetProcAddress p_GetProcAddress = 0;
static HMODULE hWS2 = 0, hKernel = 0;
BOOL WINAPI hk_CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                              LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                              LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
BOOL WINAPI hk_CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                              LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                              LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static void dbg(const char *m) {
    if (!g_debug) return;
    OutputDebugStringA(m);
    /* Optional log file (LAN_HOOK_LOGFILE=path): the only way to see
     * progress when DebugView is unavailable. Opened lazily, appended. */
    {
        static FILE *lf = NULL;
        static int tried = 0;
        if (!tried) {
            tried = 1;
            const char *p = getenv("LAN_HOOK_LOGFILE");
            if (p && p[0]) lf = fopen(p, "a");
        }
        if (lf) {
            char ts[32];
            dt_stamp(ts, sizeof(ts));
            fputs(ts, lf); fputc(' ', lf);
            fputs(m, lf); fflush(lf);
        }
    }
}

/* Crash guard for PE walking (packed/protected game binaries, odd modules).
 * mingw has no __try/__except, so: a vectored handler longjmps out of an
 * access violation back to the guarded region, which skips that module.
 * Only ever armed on the init thread while patching. */
static jmp_buf g_seh_jb;
static volatile LONG g_seh_armed = 0;
/* Whole-init guard + minidump (see LanHookInit). Inner patch guard wins. */
static jmp_buf g_init_jb;
static volatile LONG g_init_armed = 0;
static EXCEPTION_POINTERS *g_init_ep = NULL;
static LONG WINAPI seh_filter(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        if (g_seh_armed) {
            g_seh_armed = 0;
            longjmp(g_seh_jb, 1);
        }
        if (g_init_armed) {
            g_init_ep = ep;
            g_init_armed = 0;
            longjmp(g_init_jb, 1);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
/* Eager file log: opened FIRST in LanHookInit (before anything that can
 * fault) and written unconditionally, so even a crash leaves breadcrumbs.
 * Unset or empty LAN_HOOK_LOGFILE means no file logging at all. */
static FILE *g_logf = NULL;
static void flog_open(void) {
    char path[MAX_PATH];
    DWORD n;
    if (g_logf) return;
    /* Unset or empty: file logging stays off entirely. */
    n = GetEnvironmentVariableA("LAN_HOOK_LOGFILE", path, sizeof(path));
    if (n == 0 || n >= sizeof(path)) return;
    g_logf = fopen(path, "a");
}
static void flog(const char *m) {
    if (!g_logf) flog_open();
    if (g_logf) {
        char ts[32];
        dt_stamp(ts, sizeof(ts));
        fputs(ts, g_logf); fputc(' ', g_logf);
        fputs(m, g_logf); fputc('\n', g_logf); fflush(g_logf);
    }
}
static void write_minidump(void) {
    HMODULE hd = GetModuleHandleA("dbghelp.dll");
    if (!hd) hd = LoadLibraryA("dbghelp.dll");
    if (!hd || !g_init_ep) return;
    {
        typedef BOOL (WINAPI *PFN_Dump)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
            PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION,
            PMINIDUMP_CALLBACK_INFORMATION);
        PFN_Dump fn = (PFN_Dump)GetProcAddress(hd, "MiniDumpWriteDump");
        char full[MAX_PATH + 32], dir[MAX_PATH];
        char *s;
        HANDLE f;
        MINIDUMP_EXCEPTION_INFORMATION ex;
        if (!fn) return;
        /* Game binary's directory only: dumps stay with the game. If it
         * is not writable there is no dump (by design). */
        if (!GetModuleFileNameA(NULL, dir, sizeof(dir))) return;
        s = strrchr(dir, '\\');
        if (!s) return;
        *s = 0;
        snprintf(full, sizeof(full), "%s\\lan_hook_%lu.dmp",
                 dir, (unsigned long)GetCurrentProcessId());
        full[sizeof(full) - 1] = 0;
        f = CreateFileA(full, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE) return;
        ex.ThreadId = GetCurrentThreadId();
        ex.ExceptionPointers = g_init_ep;
        ex.ClientPointers = FALSE;
        fn(GetCurrentProcess(), GetCurrentProcessId(), f, MiniDumpNormal,
           &ex, NULL, NULL);
        CloseHandle(f);
        {
            char lb[MAX_PATH + 48];
            snprintf(lb, sizeof(lb), "minidump written: %s", full);
            lb[sizeof(lb) - 1] = 0;
            flog(lb);
        }
    }
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
            if (g_debug) {
                unsigned long av = 0; memcpy(&av, &tfrom.sin_addr.s_addr, 4);
                char lb[128];
                snprintf(lb, sizeof(lb), "grecv pid=%u sock=%lld n=%d src=%lu.%lu.%lu.%lu:%d",
                         (unsigned)current_pid(), (long long)s, (int)on,
                         (av & 255), ((av >> 8) & 255),
                         ((av >> 16) & 255), ((av >> 24) & 255),
                         (int)ntohs(tfrom.sin_port));
                dlog(lb);
            }
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
            if (g_debug) {
                char lb[96];
                snprintf(lb, sizeof(lb), "grecv REAL-WIRE pid=%u sock=%lld n=%d err=%d",
                         (unsigned)current_pid(), (long long)s, n,
                         n == SOCKET_ERROR ? WSAGetLastError() : 0);
                dlog(lb);
            }
            if (g_lan_only && n > 0 && from && fromlen &&
                *fromlen >= (int)sizeof(struct sockaddr_in) &&
                !ipv4_is_loopback(((struct sockaddr_in *)from)->sin_addr.s_addr)) {
                dt_log_wire_drop(((struct sockaddr_in *)from)->sin_addr.s_addr);
                if (nb) { WSASetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
                continue;   /* LAN_ONLY: no wire world beyond the tunnel */
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
        {
            int cr = dt_on_sendto((long long)s, (const unsigned char *)buf, (size_t)(len < 0 ? 0 : len),
                                  (const struct sockaddr_in *)to);
            if (cr == -1) { WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR; }
            if (cr) return len;
        }
    }
    {
        int r = p_sendto(s, buf, len, flags, to, tolen);
        if (!g_direct && r > 0) dt_obsv("SEND", (long long)s, to, (const unsigned char *)buf, r);
        return r;
    }
}
SOCKET WSAAPI hk_accept(SOCKET s, struct sockaddr *addr, int *addrlen) {
    SOCKET r = p_accept ? p_accept(s, addr, addrlen) : INVALID_SOCKET;
    /* LAN_ONLY: an isolated NIC has no inbound LAN peers; only loopback
     * (bridge/proxy traffic) may reach a listening game socket. */
    if (g_direct && g_lan_only && r != INVALID_SOCKET && addr && addrlen &&
        *addrlen >= (int)sizeof(struct sockaddr_in) &&
        !ipv4_is_loopback(((struct sockaddr_in *)addr)->sin_addr.s_addr)) {
        unsigned long a = 0;
        char lb[112];
        memcpy(&a, &((struct sockaddr_in *)addr)->sin_addr.s_addr, 4);
        snprintf(lb, sizeof(lb), "lan-only: drop wire accept from %lu.%lu.%lu.%lu",
                 a & 255, (a >> 8) & 255, (a >> 16) & 255, (a >> 24) & 255);
        dlog(lb);
        closesocket(r);
        WSASetLastError(WSAEWOULDBLOCK);
        return INVALID_SOCKET;
    }
    return r;
}
int WSAAPI hk_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) {
    if (g_direct && dt_is_udp_like((long long)s))
        return dt_win_udp_recv(s, buf, len, flags, from, fromlen);
    {
        int r = p_recvfrom(s, buf, len, flags, from, fromlen);
        if (!g_direct && r > 0) dt_obsv("RECV", (long long)s, from, (const unsigned char *)buf, r);
        return r;
    }
}
int WSAAPI hk_WSASendTo(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD sent, DWORD flags,
                        const struct sockaddr *to, int tolen,
                        LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (g_direct && ov && !cr && to && to->sa_family == AF_INET && tolen >= (int)sizeof(struct sockaddr_in)) {
        /* overlapped send to game destinations: run it through the
         * tunnel synchronously (we copy, so no lifetime issues),
         * else true async below */
        size_t total = 0;
        DWORD i;
        for (i = 0; i < nb; i++) total += b[i].len;
        {
            unsigned char *tmp = (unsigned char *)malloc(total ? total : 1);
            if (tmp) {
                size_t off = 0;
                for (i = 0; i < nb; i++) { memcpy(tmp + off, b[i].buf, b[i].len); off += b[i].len; }
                int consumed = dt_on_sendto((long long)s, tmp, total, (const struct sockaddr_in *)to);
                free(tmp);
                if (consumed == -1) {
                    WSASetLastError(WSAENETUNREACH);
                    if (ov->hEvent) WSASetEvent(ov->hEvent);
                    return SOCKET_ERROR;
                }
                if (consumed) {
                    if (sent) *sent = (DWORD)total;
                    if (ov->hEvent) WSASetEvent(ov->hEvent);
                    return 0;
                }
            }
        }
    }
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
            if (consumed == -1) { WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR; }
            if (consumed) { if (sent) *sent = (DWORD)total; return 0; }
        }
    }
    return p_WSASendTo(s, b, nb, sent, flags, to, tolen, ov, cr);
}
int WSAAPI hk_WSARecvFrom(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD recvd, LPDWORD flags,
                          struct sockaddr *from, LPINT fromlen,
                          LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (ov && g_direct && !cr && dt_is_udp_like((long long)s)) {
        /* overlapped poll: complete synchronously from our queue when
         * data waits, else hand to the real provider for true async */
        size_t total = 0;
        DWORD i;
        for (i = 0; i < nb; i++) total += b[i].len;
        if (total > 0 && total <= 65536) {
            unsigned char *tmp = (unsigned char *)malloc(total);
            if (tmp) {
                struct sockaddr_in tfrom; size_t on = 0;
                int pr;
                { DLOCK(); dt_udp_entry((long long)s, 1); DUNLOCK(); }
                pr = dt_udp_pop((long long)s, tmp, total, &tfrom, &on);
                if (pr == 1) {
                    size_t off = 0; DWORD k;
                    for (k = 0; k < nb && off < on; k++) {
                        size_t n = b[k].len;
                        if (n > on - off) n = on - off;
                        memcpy(b[k].buf, tmp + off, n);
                        off += n;
                    }
                    free(tmp);
                    if (recvd) *recvd = (DWORD)on;
                    if (flags) *flags = 0;
                    if (from && fromlen && *fromlen >= (int)sizeof(tfrom)) {
                        memcpy(from, &tfrom, sizeof(tfrom));
                        *fromlen = sizeof(tfrom);
                    }
                    if (ov->hEvent) WSASetEvent(ov->hEvent);
                    return 0;
                }
                free(tmp);
                if (pr == -1) { WSASetLastError(WSAEBADF); return SOCKET_ERROR; }
            }
        }
        return p_WSARecvFrom(s, b, nb, recvd, flags, from, fromlen, ov, cr);
    }
    if (ov) return p_WSARecvFrom(s, b, nb, recvd, flags, from, fromlen, ov, cr);
    if (g_direct && dt_is_udp_like((long long)s) && nb == 1) {
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
    return n;
}
/* Real connect semantics for tunneled streams: the stream thread runs
 * the handshake (relay dial + STOPEN/STOK) and only then reports the
 * socket open. Nonblocking apps get WSAEWOULDBLOCK + later FD_CONNECT /
 * writable; blocking apps wait here until confirmed (or failed). */
static int dt_stfail_wsae(unsigned reason) {
    switch (reason) {
    case STF_JOIN_TIMEOUT: return WSAETIMEDOUT;
    case STF_NO_ROUTE:
    case STF_HOST_FAILED:
    case STF_BAD_ID:
    case STF_BUSY:         return WSAECONNREFUSED;
    default:               return WSAETIMEDOUT;
    }
}
static int dt_connect_wait(long long gsock, int nonblock) {
    if (nonblock) { WSASetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
    long long t0 = dt_now_ms();
    for (;;) {
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock(gsock);
        int state = st ? st->state : 0;
        unsigned fail = st ? st->fail : 0;
        DUNLOCK();
        if (state == ST_OPEN) return 0;
        if (state == ST_DEAD) { WSASetLastError(dt_stfail_wsae(fail)); return SOCKET_ERROR; }
        if (dt_now_ms() - t0 > DT_ST_TIMEOUT_MS + 500) {
            WSASetLastError(WSAETIMEDOUT);
            return SOCKET_ERROR;
        }
        dt_msleep(10);
    }
}
int WSAAPI hk_connect(SOCKET s, const struct sockaddr *a, int l) {
    if (g_direct && a && a->sa_family == AF_INET && l >= (int)sizeof(struct sockaddr_in)) {
        int r = dt_on_connect((long long)s, (const struct sockaddr_in *)a);
        if (r == 3) { WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR; }
        if (r == 1) return dt_connect_wait((long long)s, dt_is_nonblock((long long)s));
        if (r == 2) { WSASetLastError(WSAEALREADY); return SOCKET_ERROR; }
    }
    return p_connect(s, a, l);
}
/* A bound socket can receive without ever calling a tracked function
 * first (pure blocking reader): register it here or fanout can never
 * find it and its arrivals are silently dropped. */
int WSAAPI hk_bind(SOCKET s, const struct sockaddr *a, int l) {
    int r;
    unsigned myv = 0;
    if (g_direct && a && a->sa_family == AF_INET) {
        DLOCK(); myv = g_myvirt; DUNLOCK();
        if (myv && ((const struct sockaddr_in *)a)->sin_addr.s_addr == htonl(myv)) {
            /* binding to our advertised virtual interface: give the real
             * stack a wildcard bind; the shim made the app believe in it */
            struct sockaddr_in mod = *(const struct sockaddr_in *)a;
            mod.sin_addr.s_addr = htonl(INADDR_ANY);
            dlog("bind vnode->ANY");
            r = p_bind ? p_bind(s, (struct sockaddr *)&mod, l) : SOCKET_ERROR;
            if (r == 0) { DLOCK(); dt_udp_entry((long long)s, 1); DUNLOCK(); }
            return r;
        }
    }
    r = p_bind ? p_bind(s, a, l) : SOCKET_ERROR;
    /* Shared discovery ports: several game processes bind one UDP port
     * (SO_REUSEADDR). If the real stack refuses it - another socket on
     * this machine owns the port - bind ephemerally instead but register
     * the socket as a member of the requested port, so tunnel fanout and
     * getsockname still present it as bound there. Without this, the
     * second binder goes deaf: inbound traffic for the shared port no
     * longer matches its (fallback) bound port. */
    if (r != 0 && g_direct && a && a->sa_family == AF_INET &&
        ((const struct sockaddr_in *)a)->sin_port != 0 &&
        (WSAGetLastError() == WSAEADDRINUSE || WSAGetLastError() == WSAEACCES) &&
        dt_sock_type((long long)s) == SOCK_DGRAM) {
        struct sockaddr_in sa = *(const struct sockaddr_in *)a;
        int want = ntohs(sa.sin_port);
        sa.sin_port = 0;
        if (p_bind && p_bind(s, (struct sockaddr *)&sa, l) == 0) {
            DLOCK();
            struct dt_udp *e = dt_udp_entry((long long)s, 1);
            if (e) e->vport = want;
            DUNLOCK();
            r = 0;
            if (g_debug) {
                char lb[128];
                snprintf(lb, sizeof(lb), "bind alias pid=%u sock=%lld vport=%d",
                         (unsigned)GetCurrentProcessId(), (long long)s, want);
                dlog(lb);
            }
        }
    }
    if (g_debug && g_direct && a && a->sa_family == AF_INET) {
        const struct sockaddr_in *ba = (const struct sockaddr_in *)a;
        unsigned long addr = 0; memcpy(&addr, &ba->sin_addr.s_addr, 4);
        char lb[192];
        snprintf(lb, sizeof(lb), "bind pid=%u sock=%lld %lu.%lu.%lu.%lu:%d r=%d err=%d",
                 (unsigned)GetCurrentProcessId(), (long long)s,
                 (addr & 255), ((addr >> 8) & 255), ((addr >> 16) & 255),
                 ((addr >> 24) & 255), (int)ntohs(ba->sin_port),
                 r, r ? WSAGetLastError() : 0);
        dlog(lb);
    }
    if (r == 0 && g_direct && a && a->sa_family == AF_INET) {
        DLOCK(); dt_udp_entry((long long)s, 1); DUNLOCK();
    }
    return r;
}
int WSAAPI hk_getsockname(SOCKET s, struct sockaddr *a, int *l) {
    int r = p_getsockname ? p_getsockname(s, a, l) : SOCKET_ERROR;
    if (r == 0 && g_direct && a && a->sa_family == AF_INET) {
        int vp = 0;
        DLOCK();
        struct dt_udp *e = dt_udp_entry((long long)s, 0);
        if (e) vp = e->vport;
        DUNLOCK();
        if (vp) ((struct sockaddr_in *)a)->sin_port = htons((unsigned short)vp);
    }
    return r;
}
int WSAAPI hk_WSAConnect(SOCKET s, const struct sockaddr *a, int l, LPWSABUF b1, LPWSABUF b2, LPQOS q1, LPQOS q2) {
    (void)b1; (void)b2; (void)q1; (void)q2;
    if (g_direct && a && a->sa_family == AF_INET && l >= (int)sizeof(struct sockaddr_in)) {
        int r = dt_on_connect((long long)s, (const struct sockaddr_in *)a);
        if (r == 3) { WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR; }
        if (r == 1) return dt_connect_wait((long long)s, dt_is_nonblock((long long)s));
        if (r == 2) { WSASetLastError(WSAEALREADY); return SOCKET_ERROR; }
    }
    return p_WSAConnect ? p_WSAConnect(s, a, l, b1, b2, q1, q2) : SOCKET_ERROR;
}
int WSAAPI hk_getpeername(SOCKET s, struct sockaddr *a, int *l) {
    if (g_direct && a && l && *l >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in o;
        if (dt_getpeer((long long)s, &o)) { memcpy(a, &o, sizeof(o)); *l = sizeof(o); return 0; }
    }
    return p_getpeername(s, a, l);
}
int WSAAPI hk_closesocket(SOCKET s) {
    if (g_direct) dt_on_close((long long)s);
    else dt_ev_unhook_sock((long long)s);
    return p_closesocket(s);
}
int WSAAPI hk_listen(SOCKET s, int backlog) {
    int r = p_listen(s, backlog);
    /* game serves a TCP port -> claim designated-host on the relay */
    if (r == 0 && g_direct && dt_sock_type((long long)s) == SOCK_STREAM) {
        struct sockaddr_in a; int l = sizeof(a);
        if (getsockname(s, (struct sockaddr *)&a, &l) == 0 && a.sin_family == AF_INET)
            dt_claim();
    }
    return r;
}

/* Connected-socket byte path for direct-tunnel TCP streams. */
int WSAAPI hk_send(SOCKET s, const char *buf, int len, int flags) {
    (void)flags;
    if (g_direct) {
        int r = dt_stream_send_wait((long long)s, (const unsigned char *)buf, (size_t)(len < 0 ? 0 : len));
        if (r > 0) return r;
        if (r == 0) { /* fall through to real socket */ }
        else return SOCKET_ERROR;
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
    if (g_direct && ov && !cr) {
        /* overlapped TCP send into our stream: synchronous, then
         * signal like a completed operation, else true async below */
        size_t total = 0;
        DWORD i;
        for (i = 0; i < nb; i++) total += b[i].len;
        {
            unsigned char *tmp = (unsigned char *)malloc(total ? total : 1);
            if (tmp) {
                size_t off = 0;
                for (i = 0; i < nb; i++) { memcpy(tmp + off, b[i].buf, b[i].len); off += b[i].len; }
                int r = dt_stream_send_wait((long long)s, tmp, total);
                free(tmp);
                if (r > 0) {
                    if (sent) *sent = (DWORD)r;
                    if (ov->hEvent) WSASetEvent(ov->hEvent);
                    return 0;
                }
                if (r == 0) { /* not our stream: fall through */ }
                else {
                    WSASetLastError(WSAECONNRESET);
                    if (r == -2) WSASetLastError(WSAEWOULDBLOCK);
                    if (ov->hEvent) WSASetEvent(ov->hEvent);
                    return SOCKET_ERROR;
                }
            }
        }
        return p_WSASend(s, b, nb, sent, flags, ov, cr);
    }
    if (g_direct && !ov && !cr) {
        size_t total = 0;
        for (DWORD i = 0; i < nb; i++) total += b[i].len;
        unsigned char *tmp = (unsigned char *)malloc(total ? total : 1);
        if (tmp) {
            size_t off = 0;
            for (DWORD i = 0; i < nb; i++) { memcpy(tmp + off, b[i].buf, b[i].len); off += b[i].len; }
            int r = dt_stream_send_wait((long long)s, tmp, total);
            free(tmp);
            if (r > 0) { if (sent) *sent = (DWORD)r; return 0; }
            if (r == 0) { /* not our stream: fall through */ }
            else {
                WSASetLastError(r == -2 ? WSAEWOULDBLOCK : WSAECONNRESET);
                return SOCKET_ERROR;
            }
        }
    }
    return p_WSASend(s, b, nb, sent, flags, ov, cr);
}
int WSAAPI hk_WSARecv(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD recvd, LPDWORD flags,
                      LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (g_direct && ov && !cr) {
        /* overlapped poll: single non-blocking pop from our stream,
         * else true async below */
        size_t total = 0;
        DWORD i;
        for (i = 0; i < nb; i++) total += b[i].len;
        if (total > 0 && total <= 65536) {
            unsigned char *tmp = (unsigned char *)malloc(total);
            if (tmp) {
                size_t on = 0;
                int r = dt_tcp_wait((long long)s, tmp, total, &on, 0, 1);
                if (r == 1) {
                    size_t off = 0; DWORD k;
                    for (k = 0; k < nb && off < on; k++) {
                        size_t n = b[k].len;
                        if (n > on - off) n = on - off;
                        memcpy(b[k].buf, tmp + off, n);
                        off += n;
                    }
                    free(tmp);
                    if (recvd) *recvd = (DWORD)on;
                    if (flags) *flags = 0;
                    if (ov->hEvent) WSASetEvent(ov->hEvent);
                    return 0;
                }
                free(tmp);
                if (r == -1) {
                    if (recvd) *recvd = 0;
                    if (ov->hEvent) WSASetEvent(ov->hEvent);
                    return 0;
                }
            }
        }
        return p_WSARecv(s, b, nb, recvd, flags, ov, cr);
    }
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
    /* FIONREAD on a tunneled stream: report the hook in-queue (the real
     * socket never sees the bytes). Readers driven by FIONREAD (e.g.
     * GBE's recv_tcp) never read otherwise and the peer can never
     * "connect" from their side. */
    if (cmd == (long)FIONREAD && argp && g_direct) {
        int dolog = 0; unsigned qn = 0;
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock((long long)s);
        if (st) {
            qn = (unsigned)st->total; *argp = (u_long)qn;
            /* key field signal: bytes waiting but app has read NONE yet */
            if (qn && st->an_rx == 0 && !st->a_log) { st->a_log = 1; dolog = 1; }
            DUNLOCK();
            if (dolog) {
                char lb[128];
                snprintf(lb, sizeof(lb), "fion: queued=%u unread pid=%u sock=%lld sid=%u",
                         qn, (unsigned)current_pid(), (long long)s, st->sid);
                dlog(lb);
            }
            return 0;
        }
        DUNLOCK();
    }
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
        if (w) {
            *w = wq;
            for (u_int i = 0; i < w0.fd_count; i++) {
                int data, dead, wr, cn;
                dt_sock_state_full((long long)w0.fd_array[i], &data, &dead, &wr, &cn);
                if (wr || cn) FD_SET(w0.fd_array[i], w);
            }
            for (u_int i = 0; i < w->fd_count; i++) n++;
        }
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
            if (w) {
                FD_ZERO(w);
                if (rr_ > 0) for (u_int i = 0; i < wq.fd_count; i++) FD_SET(wq.fd_array[i], w);
                for (u_int i = 0; i < w0.fd_count; i++) {
                    int data, dead, wr, cn;
                    dt_sock_state_full((long long)w0.fd_array[i], &data, &dead, &wr, &cn);
                    if (wr || cn) FD_SET(w0.fd_array[i], w);
                }
                for (u_int i = 0; i < w->fd_count; i++) n++;
            }
            if (x) {
                if (rr_ > 0) { *x = xq; for (u_int i = 0; i < x->fd_count; i++) n++; }
                else FD_ZERO(x);
            }
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
        for (ULONG i = 0; i < nfds; i++) {
            if ((fds[i].events & POLLRDNORM) && dt_fd_readable((long long)fds[i].fd))
                fds[i].revents |= POLLRDNORM;
            if (fds[i].events & (POLLOUT | POLLWRNORM)) {
                int data, dead, wr, cn;
                dt_sock_state_full((long long)fds[i].fd, &data, &dead, &wr, &cn);
                if (wr || cn) fds[i].revents |= POLLOUT;
            }
            if (fds[i].revents) n++;
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
        for (ULONG i = 0; i < nfds; i++) {
            if ((fds[i].events & POLLRDNORM) && dt_fd_readable((long long)fds[i].fd))
                if (!(fds[i].revents & POLLRDNORM)) fds[i].revents |= POLLRDNORM;
            if (fds[i].events & (POLLOUT | POLLWRNORM)) {
                int data, dead, wr, cn;
                dt_sock_state_full((long long)fds[i].fd, &data, &dead, &wr, &cn);
                if ((wr || cn) && !(fds[i].revents & POLLOUT)) fds[i].revents |= POLLOUT;
            }
            if (fds[i].revents) n++;
        }
        if (n) return n;
        if (r < 0) return r;
        waited += slice;
        if (timeout >= 0 && waited >= timeout) return 0;
    }
}

/* Event-driven waiting (WSAEventSelect family): inbound tunnel data sits
 * in hook queues, so also drive the app's event objects or event waiters
 * sleep through arrivals. */
int WSAAPI hk_WSAEventSelect(SOCKET s, WSAEVENT hEvent, long lNetworkEvents) {
    int r = p_WSAEventSelect ? p_WSAEventSelect(s, hEvent, lNetworkEvents) : SOCKET_ERROR;
    if (g_direct) { DLOCK(); dt_udp_entry((long long)s, 1); DUNLOCK(); }
    if (g_debug) {
        char lb[128];
        snprintf(lb, sizeof(lb), "evsel pid=%u sock=%lld ev=%p mask=0x%lx",
                 (unsigned)GetCurrentProcessId(), (long long)s, (void *)hEvent,
                 (unsigned long)lNetworkEvents);
        dlog(lb);
    }
    dt_ev_unhook_sock((long long)s);
    if (r == 0 && hEvent && lNetworkEvents) {
        int i, done = 0;
        DLOCK();
        for (i = 0; i < DT_MAXEV; i++) if (!g_evmap[i].used) {
            g_evmap[i].used = 1; g_evmap[i].sock = (long long)s;
            g_evmap[i].ev = hEvent; g_evmap[i].mask = lNetworkEvents; done = 1; break;
        }
        DUNLOCK();
        if (done) {
            int data = 0, dead = 0, wr = 0, cn = 0;
            dt_sock_state_full((long long)s, &data, &dead, &wr, &cn);
            if ((data && (lNetworkEvents & FD_READ)) ||
                (dead && (lNetworkEvents & FD_CLOSE)) ||
                (wr && (lNetworkEvents & FD_WRITE)) ||
                (cn && (lNetworkEvents & FD_CONNECT)))
                WSASetEvent(hEvent); /* already waiting */
        }
    }
    return r;
}
int WSAAPI hk_WSAEnumNetworkEvents(SOCKET s, WSAEVENT hEventObject,
                                   LPWSANETWORKEVENTS lpNetworkEvents) {
    int r = p_WSAEnumNetworkEvents ?
        p_WSAEnumNetworkEvents(s, hEventObject, lpNetworkEvents) : SOCKET_ERROR;
    if (g_direct && r == 0 && lpNetworkEvents) {
        int data = 0, dead = 0, wr = 0, cn = 0;
        dt_sock_state_full((long long)s, &data, &dead, &wr, &cn);
        long vm = 0;
        if (data) { lpNetworkEvents->lNetworkEvents |= FD_READ; vm |= FD_READ; }
        if (dead) { lpNetworkEvents->lNetworkEvents |= FD_CLOSE; vm |= FD_CLOSE; }
        if (wr)   { lpNetworkEvents->lNetworkEvents |= FD_WRITE; vm |= FD_WRITE; }
        if (cn)   {
            lpNetworkEvents->lNetworkEvents |= FD_CONNECT; vm |= FD_CONNECT;
            dt_stream_mark_connect((long long)s); /* one-shot, like the real one */
        }
        /* real Enum reset the event: re-arm so later waits still fire */
        if (vm && hEventObject) WSASetEvent(hEventObject);
    }
    return r;
}
/* mask-gated virtual-event hit for one mapped socket; DLOCK must be held */
static int dt_ev_hit_locked(long long sock, long mask) {
    int data = 0, dead = 0, wr = 0, cn = 0;
    dt_sock_state_locked(sock, &data, &dead, &wr, &cn);
    if (cn && (mask & FD_CONNECT)) {
        for (int i = 0; i < DT_MAXSTREAM; i++)
            if (g_st[i].used && g_st[i].gsock == sock && !g_st[i].connect_signaled)
                g_st[i].connect_signaled = 1;
    }
    return (data && (mask & FD_READ)) || (dead && (mask & FD_CLOSE)) ||
           (wr && (mask & FD_WRITE)) || (cn && (mask & FD_CONNECT));
}
DWORD WSAAPI hk_WSAWaitForMultipleEvents(DWORD cEvents, const WSAEVENT *lphEvents,
                                         BOOL fWaitAll, DWORD dwTimeout,
                                         BOOL fAlertable) {
    if (g_direct && !fWaitAll && lphEvents && p_WSAWaitForMultipleEvents) {
        long long budget = (dwTimeout == WSA_INFINITE) ? -1 : (long long)dwTimeout;
        long long t0 = dt_now_ms(), waited = 0;
        for (;;) {
            DWORD i;
            DLOCK();
            for (i = 0; i < cEvents; i++) {
                int j, hit = 0;
                for (j = 0; j < DT_MAXEV; j++) {
                    if (!g_evmap[j].used || g_evmap[j].ev != lphEvents[i]) continue;
                    if (dt_ev_hit_locked(g_evmap[j].sock, g_evmap[j].mask)) {
                        hit = 1;
                        break;
                    }
                }
                if (hit) { DUNLOCK(); return WSA_WAIT_EVENT_0 + i; }
            }
            DUNLOCK();
            if (budget >= 0 && waited >= budget) return WSA_WAIT_TIMEOUT;
            {
                DWORD slice = 25;
                DWORD r;
                if (budget >= 0 && waited + 25 > budget) slice = (DWORD)(budget - waited);
                r = p_WSAWaitForMultipleEvents(cEvents, lphEvents, FALSE, slice, fAlertable);
                if (r != WSA_WAIT_TIMEOUT) return r;
                waited = dt_now_ms() - t0;
            }
        }
    }
    if (p_WSAWaitForMultipleEvents)
        return p_WSAWaitForMultipleEvents(cEvents, lphEvents, fWaitAll, dwTimeout, fAlertable);
    WSASetLastError(WSAENETDOWN);
    return WSA_WAIT_FAILED;
}
WSAEVENT WSAAPI hk_WSACreateEvent(void) {
    return p_WSACreateEvent ? p_WSACreateEvent() : WSA_INVALID_EVENT;
}
BOOL WSAAPI hk_WSACloseEvent(WSAEVENT hEvent) {
    dt_ev_unhook_ev(hEvent);
    return p_WSACloseEvent ? p_WSACloseEvent(hEvent) : FALSE;
}

/* Ordinal imports: MinGW import libs bind ws2_32 (and kernel32) by
 * ordinal, so name-based IAT patching is blind to them (some modules
 * import all of their socket I/O this way, hiding their traffic
 * entirely). Resolve ordinals through the exporting module's export
 * table. The small cache avoids re-walking; concurrent duplicate
 * inserts are benign (same bytes). */
#define ORD_MAXMAP 128
static struct { HMODULE mod; DWORD ord; char name[40]; } g_ordmap[ORD_MAXMAP];
static int g_ordmap_n = 0;

static const char *export_name_for_ordinal(HMODULE mod, DWORD ord) {
    BYTE *base;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *expdir;
    IMAGE_EXPORT_DIRECTORY *exp;
    DWORD *names;
    WORD *nameords;
    DWORD j;
    int i;
    if (!mod || !ord) return 0;
    for (i = 0; i < g_ordmap_n; i++)
        if (g_ordmap[i].mod == mod && g_ordmap[i].ord == ord)
            return g_ordmap[i].name;
    base = (BYTE*)mod;
    dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 1024 * 1024) return 0;
    nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    expdir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expdir->VirtualAddress || !expdir->Size) return 0;
    exp = (IMAGE_EXPORT_DIRECTORY*)(base + expdir->VirtualAddress);
    if (!exp->AddressOfNames || !exp->AddressOfNameOrdinals) return 0;
    names = (DWORD*)(base + exp->AddressOfNames);
    nameords = (WORD*)(base + exp->AddressOfNameOrdinals);
    for (j = 0; j < exp->NumberOfNames; j++) {
        if ((DWORD)(nameords[j] + exp->Base) == ord) {
            const char *nm = (const char*)(base + names[j]);
            size_t k;
            for (k = 0; nm[k] && k < 39; k++) {
                if (nm[k] < 32 || nm[k] > 126) return 0; /* sanity */
            }
            if (g_ordmap_n < ORD_MAXMAP) {
                g_ordmap[g_ordmap_n].mod = mod;
                g_ordmap[g_ordmap_n].ord = ord;
                strncpy(g_ordmap[g_ordmap_n].name, nm, 39);
                g_ordmap[g_ordmap_n].name[39] = 0;
                g_ordmap_n++;
                return g_ordmap[g_ordmap_n - 1].name;
            }
            return nm; /* cache full: direct pointer, module stays loaded */
        }
    }
    return 0;
}

/* If game resolves exports dynamically, hand out our hooks. */
/* LoadLibrary hooks (defined below): patch newcomers too. */
HMODULE WINAPI hk_LoadLibraryA(LPCSTR);
HMODULE WINAPI hk_LoadLibraryW(LPCWSTR);
HMODULE WINAPI hk_LoadLibraryExA(LPCSTR, HANDLE, DWORD);
HMODULE WINAPI hk_LoadLibraryExW(LPCWSTR, HANDLE, DWORD);

FARPROC WINAPI hk_GetProcAddress(HMODULE m, LPCSTR n) {
    if (n && !((ULONG_PTR)n >> 16)) {
        /* by ordinal: map through the target's exports, then match by
         * name below like any other lookup */
        const char *onm = export_name_for_ordinal(m, (DWORD)(ULONG_PTR)n);
        if (!onm) return p_GetProcAddress(m, n);
        n = onm;
    }
    if (n && ((ULONG_PTR)n >> 16)) {
        char mod[MAX_PATH] = {0};
        GetModuleFileNameA(m, mod, sizeof(mod)-1);
        int isws2 = 0;
        for (char *p = mod; *p; p++) if ((p[0]=='w'||p[0]=='W')&&(p[1]=='s'||p[1]=='S')) { isws2 = 1; break; }
        if (isws2 || m == hWS2) {
            if (!strcmp(n,"sendto")) return (FARPROC)hk_sendto;
            if (!strcmp(n,"recvfrom")) return (FARPROC)hk_recvfrom;
            if (!strcmp(n,"accept")) return (FARPROC)hk_accept;
            if (!strcmp(n,"WSASendTo")) return (FARPROC)hk_WSASendTo;
            if (!strcmp(n,"WSARecvFrom")) return (FARPROC)hk_WSARecvFrom;
            if (!strcmp(n,"connect")) return (FARPROC)hk_connect;
            if (!strcmp(n,"bind")) return (FARPROC)hk_bind;
            if (!strcmp(n,"WSAConnect")) return (FARPROC)hk_WSAConnect;
            if (!strcmp(n,"getpeername")) return (FARPROC)hk_getpeername;
            if (!strcmp(n,"getsockname")) return (FARPROC)hk_getsockname;
            if (!strcmp(n,"closesocket")) return (FARPROC)hk_closesocket;
            if (!strcmp(n,"listen")) return (FARPROC)hk_listen;
            if (!strcmp(n,"send")) return (FARPROC)hk_send;
            if (!strcmp(n,"recv")) return (FARPROC)hk_recv;
            if (!strcmp(n,"WSASend")) return (FARPROC)hk_WSASend;
            if (!strcmp(n,"WSARecv")) return (FARPROC)hk_WSARecv;
            if (!strcmp(n,"ioctlsocket")) return (FARPROC)hk_ioctlsocket;
            if (!strcmp(n,"select")) return (FARPROC)hk_select;
            if (!strcmp(n,"WSAPoll")) return (FARPROC)hk_WSAPoll;
            if (!strcmp(n,"WSAEventSelect")) return (FARPROC)hk_WSAEventSelect;
            if (!strcmp(n,"WSAEnumNetworkEvents")) return (FARPROC)hk_WSAEnumNetworkEvents;
            if (!strcmp(n,"WSAWaitForMultipleEvents")) return (FARPROC)hk_WSAWaitForMultipleEvents;
            if (!strcmp(n,"WSACreateEvent")) return (FARPROC)hk_WSACreateEvent;
            if (!strcmp(n,"WSACloseEvent")) return (FARPROC)hk_WSACloseEvent;
        }
        {
            char imod[MAX_PATH] = {0};
            GetModuleFileNameA(m, imod, sizeof(imod)-1);
            {
                char *bs = strrchr(imod, '\\');
                const char *base = bs ? bs + 1 : imod;
                if (!_stricmp(base, "iphlpapi.dll")) {
                    if (!strcmp(n,"IcmpSendEcho")) return (FARPROC)hk_IcmpSendEcho;
                    if (!strcmp(n,"IcmpSendEcho2")) return (FARPROC)hk_IcmpSendEcho2;
                }
            }
        }
        if (m == hKernel) {
            if (!strcmp(n,"CreateProcessA")) return (FARPROC)hk_CreateProcessA;
            if (!strcmp(n,"CreateProcessW")) return (FARPROC)hk_CreateProcessW;
            if (!strcmp(n,"LoadLibraryA")) return (FARPROC)hk_LoadLibraryA;
            if (!strcmp(n,"LoadLibraryW")) return (FARPROC)hk_LoadLibraryW;
            if (!strcmp(n,"LoadLibraryExA")) return (FARPROC)hk_LoadLibraryExA;
            if (!strcmp(n,"LoadLibraryExW")) return (FARPROC)hk_LoadLibraryExW;
        }
    }
    return p_GetProcAddress(m, n);
}

/* ---- ICMP echo API (Windows IcmpSendEcho family) -----------------------
 * Synchronous ping APIs own no socket, so echo requests are tracked in
 * a pending table keyed by synthetic (id, seq) and completed by
 * inbound REPs (see dt_icmp_in). Unicast returns on the first reply;
 * subnet-broadcast collects until timeout/buffer-full, like the real
 * stack. IcmpSendEcho2's event is signaled; its APC routine is NOT
 * queued (documented limitation: wait on the event instead). ---- */
typedef DWORD (WINAPI *PFN_IcmpSendEcho)(HANDLE, IPAddr, LPVOID, WORD,
    PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_IcmpSendEcho2)(HANDLE, HANDLE, FARPROC, PVOID,
    IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
static PFN_IcmpSendEcho p_IcmpSendEcho = 0;
static PFN_IcmpSendEcho2 p_IcmpSendEcho2 = 0;
#define DT_MAXPEND 32
#define DT_MAXREPS 8
struct dt_icmp_pend { int used; unsigned id, seq; HANDLE ev;
                      unsigned from[DT_MAXREPS]; int nrep;
                      unsigned char data[1400]; size_t dlen;
                      long long t0, last; };
static struct dt_icmp_pend g_pend[DT_MAXPEND];
static unsigned dt_icmp_synth_id(void) {
    static volatile LONG ctr = 0;
    long c = InterlockedIncrement(&ctr);
    return (unsigned)(0xC000 | ((GetCurrentThreadId() ^ (c * 0x9E37)) & 0x3FFF));
}
/* allocate a waiter slot; -1 when full (caller fails the API call) */
static int dt_icmp_pend_alloc(unsigned id, unsigned seq, HANDLE ev) {
    int i, idx = -1;
    long long now = dt_now_ms(), oldest = now;
    int oldi = -1;
    DLOCK();
    for (i = 0; i < DT_MAXPEND; i++) {
        if (!g_pend[i].used && idx < 0) idx = i;
        if (g_pend[i].used && g_pend[i].last < oldest) { oldest = g_pend[i].last; oldi = i; }
    }
    if (idx < 0 && oldi >= 0 && now - oldest > 60000) {
        if (g_pend[oldi].ev) CloseHandle(g_pend[oldi].ev);
        memset(&g_pend[oldi], 0, sizeof(g_pend[oldi]));
        idx = oldi;
    }
    if (idx >= 0) {
        memset(&g_pend[idx], 0, sizeof(g_pend[idx]));
        g_pend[idx].used = 1; g_pend[idx].id = id; g_pend[idx].seq = seq;
        g_pend[idx].ev = ev; g_pend[idx].t0 = now; g_pend[idx].last = now;
    }
    DUNLOCK();
    return idx;
}
static void dt_icmp_pend_free(int idx) {
    if (idx < 0 || idx >= DT_MAXPEND) return;
    DLOCK();
    if (g_pend[idx].used) {
        if (g_pend[idx].ev) CloseHandle(g_pend[idx].ev);
        memset(&g_pend[idx], 0, sizeof(g_pend[idx]));
    }
    DUNLOCK();
}
/* inbound REP completion: record responder, wake waiter. Returns hits. */
static int dt_icmp_pend_complete(unsigned id, unsigned seq,
                                 const unsigned char *data, size_t dlen,
                                 unsigned from_virt) {
    int i, hit = 0;
    HANDLE evs[DT_MAXPEND];
    int nev = 0;
    DLOCK();
    for (i = 0; i < DT_MAXPEND; i++) {
        int k, dup = 0;
        if (!g_pend[i].used || g_pend[i].id != id || g_pend[i].seq != seq) continue;
        for (k = 0; k < g_pend[i].nrep; k++)
            if (g_pend[i].from[k] == from_virt) { dup = 1; break; }
        if (!dup && g_pend[i].nrep < DT_MAXREPS) {
            size_t cn = dlen < sizeof(g_pend[i].data) ? dlen : sizeof(g_pend[i].data);
            if (g_pend[i].nrep == 0 && cn) memcpy(g_pend[i].data, data, cn);
            if (g_pend[i].nrep == 0) g_pend[i].dlen = cn;
            g_pend[i].from[g_pend[i].nrep++] = from_virt;
            g_pend[i].last = dt_now_ms();
        }
        if (nev < DT_MAXPEND && g_pend[i].ev) evs[nev++] = g_pend[i].ev;
        hit = 1;
    }
    DUNLOCK();
    for (i = 0; i < nev; i++) SetEvent(evs[i]);
    return hit;
}
/* lay out nrep ICMP_ECHO_REPLY structs + data into the caller's buffer */
static DWORD dt_icmp_emit(int idx, PVOID repbuf, DWORD repsize, long long rtt_ms) {
    BYTE *p = (BYTE *)repbuf;
    DWORD left = repsize;
    int i, n = 0, nrep = 0;
    size_t dlen = 0;
    unsigned char data[1400];
    unsigned from[DT_MAXREPS];
    DLOCK();
    if (idx >= 0 && idx < DT_MAXPEND && g_pend[idx].used) {
        nrep = g_pend[idx].nrep;
        dlen = g_pend[idx].dlen;
        if (dlen) memcpy(data, g_pend[idx].data, dlen);
        for (i = 0; i < nrep && i < DT_MAXREPS; i++) from[i] = g_pend[idx].from[i];
    }
    DUNLOCK();
    for (i = 0; i < nrep; i++) {
        PICMP_ECHO_REPLY r;
        if (left < sizeof(ICMP_ECHO_REPLY) + (DWORD)dlen) break;
        r = (PICMP_ECHO_REPLY)p;
        r->Address = from[i];
        r->Status = 0;
        r->RoundTripTime = (ULONG)(rtt_ms < 1 ? 1 : (rtt_ms > 0x7FFFFFFF ? 0x7FFFFFFF : rtt_ms));
        r->DataSize = (USHORT)dlen;
        r->Reserved = 0;
        r->Data = p + sizeof(ICMP_ECHO_REPLY);
        if (dlen) memcpy(r->Data, data, dlen);
        r->Options.Ttl = 64;
        r->Options.Tos = 0;
        r->Options.Flags = 0;
        r->Options.OptionsSize = 0;
        r->Options.OptionsData = NULL;
        p += sizeof(ICMP_ECHO_REPLY) + dlen;
        left -= (DWORD)(sizeof(ICMP_ECHO_REPLY) + dlen);
        n++;
    }
    return (DWORD)n;
}
/* shared IcmpSendEcho(2) body */
static DWORD dt_icmp_echo(HANDLE h, IPAddr dst, const void *req, WORD reqsize,
                          PVOID repbuf, DWORD repsize, DWORD timeout) {
    unsigned long da = (unsigned long)dst; /* IPAddr is network order */
    unsigned relay1 = 0, node = 0;
    unsigned id, seq;
    int idx = -1, is_bcast = 0, is_self = 0;
    HANDLE ev = NULL, wev = NULL;
    long long t0;
    DWORD n = 0;
    static volatile LONG seqctr = 0;
    if (!g_direct || !p_IcmpSendEcho)
        goto passthrough;
    if (ipv4_is_local(da)) goto passthrough;
    if (ntohl(da) == g_myvirt) is_self = 1;
    else if (dt_is_vnet_bcast(da)) is_bcast = 1;
    else {
        relay1 = dt_relay_virt();
        if (relay1 && ntohl(da) == relay1) node = 0;
        else {
            node = dt_virt_node(da);
            if (!node) goto passthrough; /* real-LAN destination */
        }
    }
    if (repsize < sizeof(ICMP_ECHO_REPLY)) { SetLastError(IP_BUF_TOO_SMALL); return 0; }
    id = dt_icmp_synth_id();
    seq = (unsigned)(InterlockedIncrement(&seqctr) & 0xFFFF);
    ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!ev) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    t0 = dt_now_ms();
    if (is_self && !is_bcast) {
        /* pinging ourselves: answer inline, no tunnel, no wait */
        unsigned char rep[1500];
        size_t rn, rl = reqsize;
        unsigned myv;
        DLOCK(); myv = g_myvirt; DUNLOCK();
        if (rl > sizeof(rep) - 8) rl = sizeof(rep) - 8;
        rn = dt_icmp_build_rep(rep, id, seq, (const unsigned char *)req, rl);
        idx = dt_icmp_pend_alloc(id, seq, NULL);
        if (idx >= 0) {
            dt_icmp_pend_complete(id, seq, rep + 8, rn - 8, myv);
            n = dt_icmp_emit(idx, repbuf, repsize, 0);
            dt_icmp_pend_free(idx);
        } else {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }
        CloseHandle(ev);
        return n;
    }
    idx = dt_icmp_pend_alloc(id, seq, ev);
    if (idx < 0) { CloseHandle(ev); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    wev = ev; ev = NULL; /* owned by the slot now */
    if (is_bcast) {
        int i, nm = 0;
        unsigned nodes[DT_MAXMEMB];
        unsigned myv;
        DLOCK();
        myv = g_myvirt;
        for (i = 0; i < g_nmembers && nm < DT_MAXMEMB; i++)
            nodes[nm++] = g_members[i].node;
        DUNLOCK();
        for (i = 0; i < nm; i++) {
            unsigned virt = dt_node_virt(nodes[i]);
            if (!virt || virt == myv) continue;
            dt_icmp_send_req(nodes[i], id, seq, (const unsigned char *)req, reqsize);
        }
        /* self part of a broadcast ping answers immediately */
        if (myv) dt_icmp_pend_complete(id, seq, (const unsigned char *)req, reqsize, myv);
        /* collect until the timeout (or buffer full), like the stack */
        {
            long long deadline = t0 + (timeout ? timeout : 4000);
            for (;;) {
                long long left = deadline - dt_now_ms();
                DWORD w;
                int fits;
                if (left <= 0) break;
                w = WaitForSingleObject(wev, left > 250 ? 250 : (DWORD)left);
                (void)w;
                DLOCK();
                fits = ((size_t)(g_pend[idx].nrep + 1) *
                        (sizeof(ICMP_ECHO_REPLY) + reqsize) <= repsize);
                DUNLOCK();
                if (!fits) break;
            }
        }
        n = dt_icmp_emit(idx, repbuf, repsize, dt_now_ms() - t0);
        dt_icmp_pend_free(idx);
        if (n == 0) SetLastError(IP_REQ_TIMED_OUT);
        return n;
    }
    dt_icmp_send_req(node, id, seq, (const unsigned char *)req, reqsize);
    {
        DWORD w = WaitForSingleObject(wev, timeout ? timeout : 4000);
        if (w == WAIT_OBJECT_0) {
            n = dt_icmp_emit(idx, repbuf, repsize, dt_now_ms() - t0);
            dt_icmp_pend_free(idx);
            if (n == 0) SetLastError(IP_REQ_TIMED_OUT);
            return n;
        }
        dt_icmp_pend_free(idx);
        SetLastError(IP_REQ_TIMED_OUT);
        return 0;
    }
passthrough:
    if (p_IcmpSendEcho)
        return p_IcmpSendEcho(h, dst, (LPVOID)req, reqsize, NULL,
                              repbuf, repsize, timeout);
    SetLastError(ERROR_INVALID_FUNCTION);
    return 0;
}
DWORD WINAPI hk_IcmpSendEcho(HANDLE h, IPAddr dst, LPVOID req, WORD reqsize,
                             PIP_OPTION_INFORMATION opts, LPVOID repbuf,
                             DWORD repsize, DWORD timeout) {
    (void)opts;
    return dt_icmp_echo(h, dst, req, reqsize, repbuf, repsize, timeout);
}
DWORD WINAPI hk_IcmpSendEcho2(HANDLE h, HANDLE hev, FARPROC apc, PVOID ctx,
                              IPAddr dst, LPVOID req, WORD reqsize,
                              PIP_OPTION_INFORMATION opts, LPVOID repbuf,
                              DWORD repsize, DWORD timeout) {
    DWORD n;
    (void)apc; (void)ctx; (void)opts;
    /* APC routines are not queued (documented): the event is the
     * completion signal; callers waiting on it work unchanged. */
    n = dt_icmp_echo(h, dst, req, reqsize, repbuf, repsize, timeout);
    if (hev) SetEvent(hev);
    return n;
}
/* ---- interface-identity shim --------------------------------------
 * A virtual-NIC product would expose the tunnel address as a real local
 * interface; without a driver we fake that view per-process: the vnode
 * appears as a STANDALONE pseudo-adapter ("ShadowLAN Virtual Interface",
 * up, /24) appended to the adapter lists returned by the IP Helper
 * APIs. Consumers that enumerate "my IPs", compute per-interface
 * broadcast ranges, or sanity-check peers against local subnets (via
 * FirstUnicastAddress or the adapter walk) then see 10.200.0.x exactly
 * like a real LAN interface; binds to it are rewritten to INADDR_ANY.
 * Pure data surgery on caller-owned buffers; failures degrade to the
 * unshimmed answer. ---- */
#define DT_SL_IFINDEX 0x7F000001u  /* pseudo-adapter if-index (high, stable) */
typedef ULONG (WINAPI *PFN_GetAdaptersAddresses)(ULONG, ULONG, PVOID,
                                                 PIP_ADAPTER_ADDRESSES, PULONG);
typedef ULONG (WINAPI *PFN_GetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
static PFN_GetAdaptersAddresses p_GetAdaptersAddresses = 0;
static PFN_GetAdaptersInfo p_GetAdaptersInfo = 0;
static int g_gaa_logged = 0;

static int dt_vnode_str(char *out, int n) { return dt_src_ip(out, (size_t)n); }

/* Build one pseudo-adapter node at base+off (caller buffer). Strings live
 * in the DLL's .rdata (loaded for the whole process lifetime), so only the
 * adapter struct + its unicast node/sockaddr occupy the buffer. */
#define DT_SL_NAME_A "ShadowLAN Virtual Interface"
#define DT_SL_NAME_W L"ShadowLAN Virtual Interface"
static size_t dt_gaa_sizes(size_t *anode, size_t *unode) {
    *anode = (sizeof(IP_ADAPTER_ADDRESSES) + 15u) & ~(size_t)15;
    *unode = (sizeof(IP_ADAPTER_UNICAST_ADDRESS) + sizeof(SOCKADDR_IN)
              + 15u) & ~(size_t)15;
    return *anode + *unode;
}
static void dt_gaa_fill(BYTE *base, size_t off, size_t anode, size_t unode,
                        const char *ip) {
    IP_ADAPTER_ADDRESSES *na = (IP_ADAPTER_ADDRESSES *)(base + off);
    memset(na, 0, anode);
    na->Length = sizeof(IP_ADAPTER_ADDRESSES);
    na->IfIndex = DT_SL_IFINDEX;
    na->IfType = IF_TYPE_ETHERNET_CSMACD;
    na->OperStatus = IfOperStatusUp;
    na->Mtu = 1500;
    na->TransmitLinkSpeed = 1000000000ull;
    na->ReceiveLinkSpeed = 1000000000ull;
    /* locally-administered MAC, ASCII "SH" (ShadowLAN) in bytes 2-3 */
    na->PhysicalAddress[0] = 0x02; na->PhysicalAddress[1] = 0x00;
    na->PhysicalAddress[2] = 0x53; na->PhysicalAddress[3] = 0x48;
    na->PhysicalAddress[4] = 0x00; na->PhysicalAddress[5] = 0x01;
    na->PhysicalAddressLength = 6;
    na->AdapterName = (PCHAR)DT_SL_NAME_A;
    na->Description = (PWCHAR)DT_SL_NAME_W;
    na->FriendlyName = (PWCHAR)DT_SL_NAME_W;
    {
        static const wchar_t empty[] = L"";
        na->DnsSuffix = (PWCHAR)empty;
    }
    IP_ADAPTER_UNICAST_ADDRESS *nu =
        (IP_ADAPTER_UNICAST_ADDRESS *)(base + off + anode);
    memset(nu, 0, unode);
    nu->Length = sizeof(IP_ADAPTER_UNICAST_ADDRESS);
    nu->Next = NULL;
    nu->Address.lpSockaddr =
        (PSOCKADDR)(base + off + anode + sizeof(IP_ADAPTER_UNICAST_ADDRESS));
    nu->Address.iSockaddrLength = sizeof(SOCKADDR_IN);
    nu->PrefixOrigin = IpPrefixOriginManual;
    nu->SuffixOrigin = IpSuffixOriginManual;
    nu->DadState = IpDadStatePreferred;
    nu->ValidLifetime = 0xFFFFFFFFu;
    nu->PreferredLifetime = 0xFFFFFFFFu;
    nu->LeaseLifetime = 0xFFFFFFFFu;
    nu->OnLinkPrefixLength = 24;
    SOCKADDR_IN *sa = (SOCKADDR_IN *)nu->Address.lpSockaddr;
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = inet_addr(ip);
    na->FirstUnicastAddress = nu;
}

ULONG WINAPI hk_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved,
                                     PIP_ADAPTER_ADDRESSES AdapterAddresses,
                                     PULONG SizePointer) {
    ULONG r, used, room, at;
    size_t anode, unode;
    char ip[48];
    if (!p_GetAdaptersAddresses) return ERROR_FUNCTION_FAILED;
    if (g_debug && !g_gaa_logged) { g_gaa_logged = 1;
        dlog("GAA shim active"); }
    if (!g_direct || !dt_vnode_str(ip, sizeof(ip)))
        return p_GetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);
    if (Family != AF_INET && Family != AF_UNSPEC)
        return p_GetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);
    room = SizePointer ? *SizePointer : 0;
    dt_gaa_sizes(&anode, &unode);
    if (g_lan_only) {
        /* Isolated: the pseudo-interface is the ONLY interface this process
         * has. Synthesize a complete one-adapter answer; never touch the
         * real adapter list (that would leak the physical LAN's IPs). */
        ULONG need = (ULONG)(anode + unode);
        if (Family == AF_INET6) {
            if (SizePointer) *SizePointer = 0;
            return ERROR_NO_DATA;
        }
        if (!AdapterAddresses || !SizePointer || room < need) {
            if (SizePointer) *SizePointer = need;
            return ERROR_BUFFER_OVERFLOW;
        }
        dt_gaa_fill((BYTE *)AdapterAddresses, 0, anode, unode, ip);
        AdapterAddresses->Next = NULL;
        *SizePointer = need;
        return NO_ERROR;
    }
    r = p_GetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);
    if (r == ERROR_BUFFER_OVERFLOW) {
        ULONG need = SizePointer ? *SizePointer : 0;
        if (need < 0xFFFFFFFFu - 2560 && SizePointer) *SizePointer = need + 2560;
        return r;
    }
    if (r != NO_ERROR || !AdapterAddresses || !SizePointer) return r;
    used = *SizePointer;
    {   /* some implementations report the whole buffer as "used"; trust a
         * fresh size probe (NULL buffer) when it says BUFFER_OVERFLOW */
        ULONG probe = 0;
        if (p_GetAdaptersAddresses(Family, Flags, Reserved, NULL, &probe)
                == ERROR_BUFFER_OVERFLOW && probe && probe < used)
            used = probe;
    }
    at = (used + 15u) & ~15u;
    if (at + anode + unode <= room) {
        dt_gaa_fill((BYTE *)AdapterAddresses, at, anode, unode, ip);
        ((IP_ADAPTER_ADDRESSES *)((BYTE *)AdapterAddresses + at))->Next = NULL;
        {   /* append after the real adapters */
            IP_ADAPTER_ADDRESSES *a = AdapterAddresses;
            while (a && a->Next) a = a->Next;
            if (a) a->Next = (IP_ADAPTER_ADDRESSES *)((BYTE *)AdapterAddresses + at);
        }
        *SizePointer = (ULONG)(at + anode + unode);
    }
    return r;
}

/* Windows-SDK layout of the legacy IP_ADAPTER_INFO (iprtrmib.h). Some
 * compiler SDKs ship a different or truncated definition (older mingw has
 * no DnsServerList), so the surgery below walks its own byte-exact layout
 * and treats the caller buffer opaquely. Lease times are time_t: 8 bytes
 * on x64; on x86 we slightly over-reserve, which is harmless. */
typedef struct dt_ms_ipa_str {
    struct dt_ms_ipa_str *Next;
    char IpAddress[16];
    char IpMask[16];
    DWORD Context;
} dt_ms_ipa_str;
typedef struct dt_ms_ip_adapter_info {
    struct dt_ms_ip_adapter_info *Next;
    DWORD ComboIndex;
    char AdapterName[256 + 4];
    char Description[128 + 4];
    UINT AddressLength;
    unsigned char Address[8];
    DWORD Index;
    UINT Type;
    UINT DhcpEnabled;
    dt_ms_ipa_str *CurrentIpAddress;
    dt_ms_ipa_str IpAddressList;
    dt_ms_ipa_str GatewayList;
    dt_ms_ipa_str DnsServerList;
    dt_ms_ipa_str DhcpServer;
    UINT HaveWins;
    dt_ms_ipa_str PrimaryWinsServer;
    dt_ms_ipa_str SecondaryWinsServer;
    long long LeaseObtained;
    long long LeaseExpires;
} dt_ms_ip_adapter_info;

static size_t dt_gai_node(void) {
    return (sizeof(dt_ms_ip_adapter_info) + 15u) & ~(size_t)15;
}
static void dt_gai_fill(BYTE *base, size_t off, const char *ip) {
    dt_ms_ip_adapter_info *na = (dt_ms_ip_adapter_info *)(base + off);
    memset(na, 0, sizeof(*na));
    strncpy(na->AdapterName, DT_SL_NAME_A, sizeof(na->AdapterName) - 1);
    strncpy(na->Description, DT_SL_NAME_A, sizeof(na->Description) - 1);
    na->AddressLength = 6;
    na->Address[0] = 0x02; na->Address[1] = 0x00; na->Address[2] = 0x53;
    na->Address[3] = 0x48; na->Address[4] = 0x00; na->Address[5] = 0x01;
    na->Index = DT_SL_IFINDEX;
    na->Type = 6;            /* MIB_IF_TYPE_ETHERNET */
    na->DhcpEnabled = 0;
    na->CurrentIpAddress = &na->IpAddressList;
    strncpy(na->IpAddressList.IpAddress, ip,
            sizeof(na->IpAddressList.IpAddress) - 1);
    strncpy(na->IpAddressList.IpMask, "255.255.255.0",
            sizeof(na->IpAddressList.IpMask) - 1);
    na->IpAddressList.Next = NULL;
    na->Next = NULL;
}

ULONG WINAPI hk_GetAdaptersInfo(PIP_ADAPTER_INFO InfoBuffer, PULONG SizePointer) {
    ULONG r, used, at, room;
    char ip[48];
    size_t ino;
    if (!p_GetAdaptersInfo) return ERROR_FUNCTION_FAILED;
    if (!g_direct || !dt_vnode_str(ip, sizeof(ip)))
        return p_GetAdaptersInfo(InfoBuffer, SizePointer);
    room = SizePointer ? *SizePointer : 0;
    ino = dt_gai_node();
    if (g_lan_only) {   /* isolated: one-adapter answer, real list hidden */
        if (!InfoBuffer || !SizePointer || room < (ULONG)ino) {
            if (SizePointer) *SizePointer = (ULONG)ino;
            return ERROR_BUFFER_OVERFLOW;
        }
        dt_gai_fill((BYTE *)InfoBuffer, 0, ip);
        *SizePointer = (ULONG)ino;
        return NO_ERROR;
    }
    r = p_GetAdaptersInfo(InfoBuffer, SizePointer);
    if (r == ERROR_BUFFER_OVERFLOW) {
        ULONG need = SizePointer ? *SizePointer : 0;
        if (need < 0xFFFFFFFFu - 2048 && SizePointer) *SizePointer = need + 2048;
        return r;
    }
    if (r != NO_ERROR || !InfoBuffer || !SizePointer) return r;
    used = *SizePointer;
    {   /* same whole-buffer-as-used quirk as GetAdaptersAddresses: clamp
         * to a fresh size probe when it reports the true packed size */
        ULONG probe = 0;
        if (p_GetAdaptersInfo(NULL, &probe) == ERROR_BUFFER_OVERFLOW
                && probe && probe < used)
            used = probe;
    }
    at = (used + 15u) & ~15u;
    if (at + ino <= room) {
        dt_gai_fill((BYTE *)InfoBuffer, at, ip);
        {   /* append after the real adapters (Next is offset 0 in both
             * SDK spellings, so the walk is safe) */
            dt_ms_ip_adapter_info *a = (dt_ms_ip_adapter_info *)InfoBuffer;
            while (a && a->Next) a = a->Next;
            if (a) a->Next = (dt_ms_ip_adapter_info *)((BYTE *)InfoBuffer + at);
        }
        *SizePointer = (ULONG)(at + ino);
    }
    return r;
}

/* Optional module allowlist (LAN_HOOK_MODULES=a.dll,b.dll): only patch
 * modules whose file name contains one of these (case-insensitive).
 * Escape hatch when a specific DLL (overlay, anti-tamper, ...) misbehaves.
 * Empty = patch everything. */
static int module_allowed(const char *path) {
    const char *list = getenv("LAN_HOOK_MODULES");
    if (!list || !list[0]) return 1;
    const char *base = strrchr(path, '\\');
    base = base ? base + 1 : path;
    const char *slash = strrchr(base, '/');
    base = slash ? slash + 1 : base;
    char tmp[1024];
    strncpy(tmp, list, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    for (char *t = strtok(tmp, ",;"); t; t = strtok(NULL, ",;")) {
        while (*t == ' ') t++;
        if (!*t) continue;
        const char *a = base, *b = t;
        /* case-insensitive substring */
        for (; *a; a++) {
            const char *x = a; const char *y = b;
            while (*y && tolower((unsigned char)*x) == tolower((unsigned char)*y)) { x++; y++; }
            if (!*y) return 1;
        }
    }
    return 0;
}

static void patch_iat_inner(HMODULE mod) {
    if (!mod) return;
    int patched = 0;
    char modname[MAX_PATH] = {0};
    if (g_debug) {
        GetModuleFileNameA(mod, modname, sizeof(modname) - 1);
        char *bs = strrchr(modname, '\\');
        memmove(modname, bs ? bs + 1 : modname,
                strlen(bs ? bs + 1 : modname) + 1);
    }
    {
        BYTE *base = (BYTE*)mod;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        if (dos->e_lfanew <= 0 || dos->e_lfanew > 1024 * 1024) return;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;
        IMAGE_DATA_DIRECTORY *impdir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!impdir->VirtualAddress) return;
        IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + impdir->VirtualAddress);
        for (; desc->Name; desc++) {
            char *dll = (char*)(base + desc->Name);
            int isws2 = (_stricmp(dll, "ws2_32.dll") == 0);
            int isk32 = (_stricmp(dll, "kernel32.dll") == 0);
            int isiph = (_stricmp(dll, "iphlpapi.dll") == 0);
            if (!isws2 && !isk32 && !isiph) continue;
            IMAGE_THUNK_DATA *orig = desc->OriginalFirstThunk ?
                (IMAGE_THUNK_DATA*)(base + desc->OriginalFirstThunk) : 0;
            IMAGE_THUNK_DATA *iat = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
            HMODULE hExp = GetModuleHandleA(dll);
            for (; iat->u1.Function; iat++, orig ? orig++ : 0) {
                char *fn = 0;
                char ordname[40];
                /* Ordinal-ness must come from the import lookup table:
                 * the loader overwrites the IAT with resolved addresses,
                 * so testing the IAT slot itself misses every ordinal
                 * import (this hid MinGW-linked socket I/O entirely). */
                IMAGE_THUNK_DATA *lu = orig ? orig : iat;
                if (IMAGE_SNAP_BY_ORDINAL(lu->u1.Ordinal)) {
                    const char *rn = export_name_for_ordinal(
                        hExp, IMAGE_ORDINAL(lu->u1.Ordinal));
                    if (!rn) continue;
                    strncpy(ordname, rn, sizeof(ordname) - 1);
                    ordname[sizeof(ordname) - 1] = 0;
                    fn = ordname;
                } else {
                    IMAGE_IMPORT_BY_NAME *nm = (IMAGE_IMPORT_BY_NAME*)(base + lu->u1.AddressOfData);
                    if (!nm) continue;
                    fn = (char*)nm->Name;
                }
                FARPROC rep = 0;
                if (isws2) {
                    if (!strcmp(fn,"sendto")) rep = (FARPROC)hk_sendto;
                    else if (!strcmp(fn,"recvfrom")) rep = (FARPROC)hk_recvfrom;
                    else if (!strcmp(fn,"accept")) rep = (FARPROC)hk_accept;
                    else if (!strcmp(fn,"WSASendTo")) rep = (FARPROC)hk_WSASendTo;
                    else if (!strcmp(fn,"WSARecvFrom")) rep = (FARPROC)hk_WSARecvFrom;
                    else if (!strcmp(fn,"connect")) rep = (FARPROC)hk_connect;
                    else if (!strcmp(fn,"bind")) rep = (FARPROC)hk_bind;
                    else if (!strcmp(fn,"WSAConnect")) rep = (FARPROC)hk_WSAConnect;
                    else if (!strcmp(fn,"getpeername")) rep = (FARPROC)hk_getpeername;
                    else if (!strcmp(fn,"getsockname")) rep = (FARPROC)hk_getsockname;
                    else if (!strcmp(fn,"closesocket")) rep = (FARPROC)hk_closesocket;
                    else if (!strcmp(fn,"listen")) rep = (FARPROC)hk_listen;
                    else if (!strcmp(fn,"send")) rep = (FARPROC)hk_send;
                    else if (!strcmp(fn,"recv")) rep = (FARPROC)hk_recv;
                    else if (!strcmp(fn,"WSASend")) rep = (FARPROC)hk_WSASend;
                    else if (!strcmp(fn,"WSARecv")) rep = (FARPROC)hk_WSARecv;
                    else if (!strcmp(fn,"ioctlsocket")) rep = (FARPROC)hk_ioctlsocket;
                    else if (!strcmp(fn,"select")) rep = (FARPROC)hk_select;
                    else if (!strcmp(fn,"WSAPoll")) rep = (FARPROC)hk_WSAPoll;
                    else if (!strcmp(fn,"WSAEventSelect")) rep = (FARPROC)hk_WSAEventSelect;
                    else if (!strcmp(fn,"WSAEnumNetworkEvents")) rep = (FARPROC)hk_WSAEnumNetworkEvents;
                    else if (!strcmp(fn,"WSAWaitForMultipleEvents")) rep = (FARPROC)hk_WSAWaitForMultipleEvents;
                    else if (!strcmp(fn,"WSACreateEvent")) rep = (FARPROC)hk_WSACreateEvent;
                    else if (!strcmp(fn,"WSACloseEvent")) rep = (FARPROC)hk_WSACloseEvent;
                } else if (isiph && !strcmp(fn,"GetAdaptersAddresses")) {
                    rep = (FARPROC)hk_GetAdaptersAddresses;
                } else if (isiph && !strcmp(fn,"IcmpSendEcho")) {
                    rep = (FARPROC)hk_IcmpSendEcho;
                } else if (isiph && !strcmp(fn,"IcmpSendEcho2")) {
                    rep = (FARPROC)hk_IcmpSendEcho2;
                } else if (isiph && !strcmp(fn,"GetAdaptersInfo")) {
                    rep = (FARPROC)hk_GetAdaptersInfo;
                } else if (isk32 && !strcmp(fn,"GetProcAddress")) {
                    rep = (FARPROC)hk_GetProcAddress;
                } else if (isk32 && !strcmp(fn,"LoadLibraryA")) {
                    rep = (FARPROC)hk_LoadLibraryA;
                } else if (isk32 && !strcmp(fn,"LoadLibraryW")) {
                    rep = (FARPROC)hk_LoadLibraryW;
                } else if (isk32 && !strcmp(fn,"LoadLibraryExA")) {
                    rep = (FARPROC)hk_LoadLibraryExA;
                } else if (isk32 && !strcmp(fn,"LoadLibraryExW")) {
                    rep = (FARPROC)hk_LoadLibraryExW;
                } else if (isk32 && !strcmp(fn,"CreateProcessA")) {
                    rep = (FARPROC)hk_CreateProcessA;
                } else if (isk32 && !strcmp(fn,"CreateProcessW")) {
                    rep = (FARPROC)hk_CreateProcessW;
                }
                if (rep) {
                    DWORD old = 0;
                    if (VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) {
                        iat->u1.Function = (ULONG_PTR)rep;
                        VirtualProtect(&iat->u1.Function, sizeof(void*), old, &old);
                        if (g_debug && patched < 256) {
                            char lb[160];
                            snprintf(lb, sizeof(lb), "patch iat %s!%s", modname, fn);
                            dlog(lb); patched++;
                        }
                    }
                }
            }
        }
    }
}

/* Guarded entry points: a bad module is skipped, never fatal. */
/* Patching is re-entrant across threads (init, LoadLibrary hooks on app
 * threads, the late-module sweep): serialize it. The shared SEH jump
 * buffer is only sound under this lock. */
static CRITICAL_SECTION g_pcs;
static int g_pcs_init = 0;
#define DT_MAXSEEN 1024
static HMODULE g_seen[DT_MAXSEEN];
static int g_nseen = 0;

static void patch_iat(HMODULE mod) {
    if (!mod) return;
    if (!g_pcs_init) return;
    EnterCriticalSection(&g_pcs);
    if (mod != g_hself) {
        char path[MAX_PATH] = {0};
        if (GetModuleFileNameA(mod, path, sizeof(path) - 1) &&
            !module_allowed(path)) {
            dbg("lan_hook: module not in allowlist, skipped\n");
            LeaveCriticalSection(&g_pcs);
            return;
        }
    }
    if (setjmp(g_seh_jb) != 0) {
        dbg("lan_hook: skipped unreadable module\n");
        LeaveCriticalSection(&g_pcs);
        return;
    }
    g_seh_armed = 1;
    patch_iat_inner(mod);
    g_seh_armed = 0;
    {   /* remember: the sweep only revisits modules it has never seen */
        int i, have = 0;
        for (i = 0; i < g_nseen; i++) if (g_seen[i] == mod) { have = 1; break; }
        if (!have && g_nseen < DT_MAXSEEN) g_seen[g_nseen++] = mod;
    }
    LeaveCriticalSection(&g_pcs);
}

static void patch_all(int force) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) { patch_iat(GetModuleHandleA(NULL)); return; }
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    int n = 0;
    /* skip our own module: tunnel threads must call the real Winsock */
    if (Module32First(snap, &me)) do {
        if (me.hModule == g_hself || me.hModule == NULL) continue;
        if (!force) {
            int i, have = 0;
            EnterCriticalSection(&g_pcs);
            for (i = 0; i < g_nseen; i++) if (g_seen[i] == me.hModule) { have = 1; break; }
            LeaveCriticalSection(&g_pcs);
            if (have) continue;
        }
        patch_iat(me.hModule);
        n++;
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    if (force || n > 0) {
        char lb[96];
        snprintf(lb, sizeof(lb), force ? "lan_hook: patched %d modules\n"
                                       : "lan_hook: late-patched %d new modules\n", n);
        dbg(lb);
    }
}

/* Game engines routinely grab networking plugin DLLs long after our
 * install pass. LoadLibrary hooks catch the common case, but a direct
 * ntdll loader call bypasses every user-mode import hook, so keep a
 * slow differential sweep as a safety net: cheap module-list diff,
 * patch anything new once. */
static DWORD WINAPI dt_sweep_thread(LPVOID u) {
    (void)u;
    for (;;) {
        Sleep(2000);
        patch_all(0);
    }
    return 0;
}

/* LoadLibrary hooks: patch newcomers too. */
static PFN_LoadLibraryA p_LoadLibraryA = 0; static PFN_LoadLibraryW p_LoadLibraryW = 0;
static PFN_LoadLibraryExA p_LoadLibraryExA = 0; static PFN_LoadLibraryExW p_LoadLibraryExW = 0;
HMODULE WINAPI hk_LoadLibraryA(LPCSTR n) { HMODULE h = p_LoadLibraryA(n); if (h && h != g_hself) patch_iat(h); return h; }
HMODULE WINAPI hk_LoadLibraryW(LPCWSTR n) { HMODULE h = p_LoadLibraryW(n); if (h && h != g_hself) patch_iat(h); return h; }
HMODULE WINAPI hk_LoadLibraryExA(LPCSTR n, HANDLE f, DWORD fl) { HMODULE h = p_LoadLibraryExA(n,f,fl); if (h && h != g_hself) patch_iat(h); return h; }
HMODULE WINAPI hk_LoadLibraryExW(LPCWSTR n, HANDLE f, DWORD fl) { HMODULE h = p_LoadLibraryExW(n,f,fl); if (h && h != g_hself) patch_iat(h); return h; }

/* Sub-process hooking: a launcher tool that
 * spawns the real game gets the hook carried into each child automatically.
 * Same bitness only (Windows cannot cross-inject); failures fall back to
 * launching unhooked rather than breaking the game. Filter with
 * LAN_HOOK_CHILDREN=a.exe,b.exe (substring list, empty = all children);
 * LAN_HOOK_NOCHILD=1 disables child injection entirely. */
typedef BOOL (WINAPI *PFN_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR,
    LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION);
static PFN_CreateProcessA p_CreateProcessA = 0;
static PFN_CreateProcessW p_CreateProcessW = 0;

static int child_wanted(const char *image) {
    const char *e = getenv("LAN_HOOK_NOCHILD");
    if (e && e[0] == '1') return 0;
    e = getenv("LAN_HOOK_CHILDREN");
    if (!e || !e[0]) return 1;
    if (!image || !image[0]) return 1;
    {
        char tmp[1024];
        strncpy(tmp, e, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = 0;
        for (char *t = strtok(tmp, ",;"); t; t = strtok(NULL, ",;")) {
            while (*t == ' ') t++;
            if (!*t) continue;
            const char *a = image;
            for (; *a; a++) {
                const char *x = a; const char *y = t;
                while (*y && tolower((unsigned char)*x) == tolower((unsigned char)*y)) { x++; y++; }
                if (!*y) return 1;
            }
        }
    }
    return 0;
}

/* image path of the child for the name filter (app name, else argv[0]). */
static void child_image(const char *app, const char *cmd, char *out, size_t n) {
    const char *src;
    int quoted = 0;
    if (!n) return;
    if (app && app[0]) {
        strncpy(out, app, n - 1);
        out[n - 1] = 0;
        return;
    }
    if (!cmd) { out[0] = 0; return; }
    src = cmd;
    while (*src == ' ') src++;
    if (*src == '"') { quoted = 1; src++; }
    {
        size_t i = 0;
        for (; *src && i + 1 < n; src++) {
            if (quoted ? (*src == '"') : (*src == ' ')) break;
            out[i++] = *src;
        }
        out[i] = 0;
    }
}

static void inject_child(PROCESS_INFORMATION *pi) {
    char dllpath[MAX_PATH] = {0};
    LPVOID mem;
    size_t n;
    HMODULE k;
    LPTHREAD_START_ROUTINE fn;
    HANDLE th;
    DWORD code = 0;
    if (!GetModuleFileNameA(g_hself, dllpath, sizeof(dllpath) - 1)) return;
    n = strlen(dllpath) + 1;
    mem = VirtualAllocEx(pi->hProcess, NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return;
    if (!WriteProcessMemory(pi->hProcess, mem, dllpath, n, NULL)) {
        VirtualFreeEx(pi->hProcess, mem, 0, MEM_RELEASE);
        return;
    }
    k = GetModuleHandleA("kernel32.dll");
    fn = (LPTHREAD_START_ROUTINE)GetProcAddress(k, "LoadLibraryA");
    th = CreateRemoteThread(pi->hProcess, NULL, 0, fn, mem, 0, NULL);
    if (!th) { VirtualFreeEx(pi->hProcess, mem, 0, MEM_RELEASE); return; }
    if (WaitForSingleObject(th, 30000) != WAIT_OBJECT_0) {
        dbg("lan_hook: child LoadLibrary timed out, continuing unhooked\n");
        CloseHandle(th);
        VirtualFreeEx(pi->hProcess, mem, 0, MEM_RELEASE);
        return;
    }
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    VirtualFreeEx(pi->hProcess, mem, 0, MEM_RELEASE);
    if (!code) {
        dbg("lan_hook: child LoadLibrary failed (bitness?), continuing unhooked\n");
        return;
    }
    {
        /* remote base via enumeration (exit codes truncate 64-bit bases) */
        FARPROC localInit = GetProcAddress(g_hself, "LanHookInit");
        if (localInit) {
            HMODULE mods[512];
            DWORD need = 0;
            if (EnumProcessModules(pi->hProcess, mods, sizeof(mods), &need)) {
                DWORD cnt = need / sizeof(HMODULE);
                DWORD i;
                if (cnt > 512) cnt = 512;
                for (i = 0; i < cnt; i++) {
                    char path[MAX_PATH] = {0};
                    if (GetModuleFileNameExA(pi->hProcess, mods[i], path, sizeof(path) - 1) &&
                        _stricmp(path, dllpath) == 0) {
                        uintptr_t rva = (uintptr_t)localInit - (uintptr_t)g_hself;
                        LPTHREAD_START_ROUTINE rInit =
                            (LPTHREAD_START_ROUTINE)((uintptr_t)mods[i] + rva);
                        HANDLE th2 = CreateRemoteThread(pi->hProcess, NULL, 0, rInit, NULL, 0, NULL);
                        if (th2) {
                            DWORD st = 1;
                            if (WaitForSingleObject(th2, 30000) == WAIT_OBJECT_0)
                                GetExitCodeThread(th2, &st);
                            CloseHandle(th2);
                            if (st != 0) dbg("lan_hook: child init non-zero\n");
                        }
                        break;
                    }
                }
            }
        }
    }
    dbg("lan_hook: child injected\n");
}

/* Tree identity, explicit-env case: with lpEnvironment==NULL the child
 * inherits our stamped process env already. When the caller supplies an
 * explicit block (CREATE_NEW_ENVIRONMENT), append LAN_HOOK_NODE to it so
 * the child still joins the parent's node. Returns a malloc'd replacement
 * block (caller frees) or the original when untouched. */
static LPVOID dt_env_with_node(LPVOID env, DWORD flags) {
    char num[24];
    if (!env || !g_node) return env;
    snprintf(num, sizeof num, "%u", g_node);
    if (flags & CREATE_UNICODE_ENVIRONMENT) {
        static const WCHAR nm[] = L"LAN_HOOK_NODE=";
        const WCHAR *p = (const WCHAR *)env;
        size_t n = 0;
        int found = 0;
        while (p[n]) {
            if (!_wcsnicmp(p + n, nm, 14)) found = 1;
            n += wcslen(p + n) + 1;
        }
        if (found) return env;
        {
            WCHAR *blk = (WCHAR *)malloc((n + 48) * sizeof(WCHAR));
            if (!blk) return env;
            memcpy(blk, p, n * sizeof(WCHAR));
            {
                WCHAR *q = blk + n;
                memcpy(q, nm, sizeof(nm) - sizeof(WCHAR));
                q += 14;
                MultiByteToWideChar(CP_UTF8, 0, num, -1, q, 16);
                q += wcslen(q);
                q[0] = 0;   /* string terminator + block terminator */
                q[1] = 0;
            }
            return blk;
        }
    } else {
        const char *p = (const char *)env;
        size_t n = 0;
        int found = 0;
        while (p[n]) {
            if (!_strnicmp(p + n, "LAN_HOOK_NODE=", 14)) found = 1;
            n += strlen(p + n) + 1;
        }
        if (found) return env;
        {
            char *blk = (char *)malloc(n + 48);
            if (!blk) return env;
            memcpy(blk, p, n);
            {
                int w = snprintf(blk + n, 32, "LAN_HOOK_NODE=%s", num);
                blk[n + (size_t)w + 1] = 0;   /* double-null terminate */
            }
            return blk;
        }
    }
}

BOOL WINAPI hk_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa,
                              LPSECURITY_ATTRIBUTES ta, BOOL inh, DWORD flags,
                              LPVOID env, LPCSTR dir, LPSTARTUPINFOA si,
                              LPPROCESS_INFORMATION pi) {
    char image[MAX_PATH] = {0};
    BOOL wantSuspend;
    BOOL ok;
    if (!p_CreateProcessA) return FALSE;
    child_image(app, cmd, image, sizeof(image));
    if (!child_wanted(image)) {
        dbg("lan_hook: child not in filter, launching unhooked\n");
        return p_CreateProcessA(app, cmd, pa, ta, inh, flags, env, dir, si, pi);
    }
    wantSuspend = (flags & CREATE_SUSPENDED) != 0;
    {
        LPVOID cenv = dt_env_with_node(env, flags);
        ok = p_CreateProcessA(app, cmd, pa, ta, inh, flags | CREATE_SUSPENDED,
                              cenv, dir, si, pi);
        if (cenv != env) free(cenv);
    }
    if (!ok) return FALSE;
    inject_child(pi);
    if (!wantSuspend) ResumeThread(pi->hThread);
    return TRUE;
}

BOOL WINAPI hk_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                              LPSECURITY_ATTRIBUTES ta, BOOL inh, DWORD flags,
                              LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si,
                              LPPROCESS_INFORMATION pi) {
    char image[MAX_PATH] = {0};
    char appA[MAX_PATH] = {0}, cmdA[8192] = {0};
    BOOL wantSuspend;
    BOOL ok;
    if (!p_CreateProcessW) return FALSE;
    if (app) WideCharToMultiByte(CP_UTF8, 0, app, -1, appA, sizeof(appA) - 1, NULL, NULL);
    if (cmd) WideCharToMultiByte(CP_UTF8, 0, cmd, -1, cmdA, sizeof(cmdA) - 1, NULL, NULL);
    child_image(app ? appA : NULL, cmd ? cmdA : NULL, image, sizeof(image));
    if (!child_wanted(image)) {
        dbg("lan_hook: child not in filter, launching unhooked\n");
        return p_CreateProcessW(app, cmd, pa, ta, inh, flags, env, dir, si, pi);
    }
    wantSuspend = (flags & CREATE_SUSPENDED) != 0;
    {
        LPVOID cenv = dt_env_with_node(env, flags);
        ok = p_CreateProcessW(app, cmd, pa, ta, inh, flags | CREATE_SUSPENDED,
                              cenv, dir, si, pi);
        if (cenv != env) free(cenv);
    }
    if (!ok) return FALSE;
    inject_child(pi);
    if (!wantSuspend) ResumeThread(pi->hThread);
    return TRUE;
}

static void patch_loader_iat_inner(void) {
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
            HMODULE hExp = GetModuleHandleA("kernel32.dll");
            for (; iat->u1.Function; iat++, orig ? orig++ : 0) {
                char *fn = 0;
                char ordname[40];
                IMAGE_THUNK_DATA *lu = orig ? orig : iat;
                if (IMAGE_SNAP_BY_ORDINAL(lu->u1.Ordinal)) {
                    const char *rn = export_name_for_ordinal(
                        hExp, IMAGE_ORDINAL(lu->u1.Ordinal));
                    if (!rn) continue;
                    strncpy(ordname, rn, sizeof(ordname) - 1);
                    ordname[sizeof(ordname) - 1] = 0;
                    fn = ordname;
                } else {
                    IMAGE_IMPORT_BY_NAME *nm = (IMAGE_IMPORT_BY_NAME*)(base + lu->u1.AddressOfData);
                    if (!nm) continue;
                    fn = (char*)nm->Name;
                }
                FARPROC rep = 0;
                if (!strcmp(fn, "LoadLibraryA")) rep = (FARPROC)hk_LoadLibraryA;
                else if (!strcmp(fn, "LoadLibraryW")) rep = (FARPROC)hk_LoadLibraryW;
                else if (!strcmp(fn, "LoadLibraryExA")) rep = (FARPROC)hk_LoadLibraryExA;
                else if (!strcmp(fn, "LoadLibraryExW")) rep = (FARPROC)hk_LoadLibraryExW;
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

static void patch_loader_iat(void) {
    if (setjmp(g_seh_jb) != 0) {
        dbg("lan_hook: skipped unreadable exe imports\n");
        return;
    }
    g_seh_armed = 1;
    patch_loader_iat_inner();
    g_seh_armed = 0;
}

/* Two-stage init: DllMain does nothing but record our handle (running
 * under the loader lock is no place for threads or patching). The
 * injector calls LanHookInit on a normal remote thread after
 * LoadLibrary succeeds. Returns 0 on success. */
__declspec(dllexport) DWORD WINAPI LanHookInit(LPVOID unused) {
    static volatile LONG done = 0;
    if (InterlockedCompareExchange(&done, 1, 0) != 0)
        return 0; /* already initialized */
    (void)unused;
    flog_open();
    flog("LanHookInit: enter");
    AddVectoredExceptionHandler(1, seh_filter);
    if (setjmp(g_init_jb) != 0) {
        /* guarded fault anywhere below: leave a dump, keep game alive */
        flog("LanHookInit: guarded fault during init");
        write_minidump();
        return 2;
    }
    g_init_armed = 1;
    if (!g_dcs_init) { InitializeCriticalSection(&g_dcs); g_dcs_init = 1; }
    flog("LanHookInit: resolving imports");
    hWS2 = GetModuleHandleA("ws2_32.dll");
    if (!hWS2) hWS2 = LoadLibraryA("ws2_32.dll");
    hKernel = GetModuleHandleA("kernel32.dll");
    dbg("lan_hook: resolving imports\n");
    p_sendto = (PFN_sendto)GetProcAddress(hWS2, "sendto");
    p_recvfrom = (PFN_recvfrom)GetProcAddress(hWS2, "recvfrom");
    p_accept = (PFN_accept)GetProcAddress(hWS2, "accept");
    p_WSASendTo = (PFN_WSASendTo)GetProcAddress(hWS2, "WSASendTo");
    p_WSARecvFrom = (PFN_WSARecvFrom)GetProcAddress(hWS2, "WSARecvFrom");
    p_connect = (PFN_connect)GetProcAddress(hWS2, "connect");
    p_bind = (PFN_bind)GetProcAddress(hWS2, "bind");
    p_WSAConnect = (PFN_WSAConnect)GetProcAddress(hWS2, "WSAConnect");
    p_getpeername = (PFN_getpeername)GetProcAddress(hWS2, "getpeername");
    p_getsockname = (PFN_getsockname)GetProcAddress(hWS2, "getsockname");
    {
        HMODULE hIPH = LoadLibraryA("iphlpapi.dll");
        if (hIPH) {
            p_GetAdaptersAddresses = (PFN_GetAdaptersAddresses)GetProcAddress(hIPH, "GetAdaptersAddresses");
            p_GetAdaptersInfo = (PFN_GetAdaptersInfo)GetProcAddress(hIPH, "GetAdaptersInfo");
            p_IcmpSendEcho = (PFN_IcmpSendEcho)GetProcAddress(hIPH, "IcmpSendEcho");
            p_IcmpSendEcho2 = (PFN_IcmpSendEcho2)GetProcAddress(hIPH, "IcmpSendEcho2");
            dbg("lan_hook: iphlpapi pointers resolved\n");
        }
    }
    p_closesocket = (PFN_closesocket)GetProcAddress(hWS2, "closesocket");
    p_listen = (PFN_listen)GetProcAddress(hWS2, "listen");
    p_send = (PFN_send)GetProcAddress(hWS2, "send");
    p_recv = (PFN_recv)GetProcAddress(hWS2, "recv");
    p_WSASend = (PFN_WSASend)GetProcAddress(hWS2, "WSASend");
    p_WSARecv = (PFN_WSARecv)GetProcAddress(hWS2, "WSARecv");
    p_ioctlsocket = (PFN_ioctlsocket)GetProcAddress(hWS2, "ioctlsocket");
    p_WSAEventSelect = (PFN_WSAEventSelect)GetProcAddress(hWS2, "WSAEventSelect");
    p_WSAEnumNetworkEvents = (PFN_WSAEnumNetworkEvents)GetProcAddress(hWS2, "WSAEnumNetworkEvents");
    p_WSAWaitForMultipleEvents = (PFN_WSAWaitForMultipleEvents)GetProcAddress(hWS2, "WSAWaitForMultipleEvents");
    p_WSACreateEvent = (PFN_WSACreateEvent)GetProcAddress(hWS2, "WSACreateEvent");
    p_WSACloseEvent = (PFN_WSACloseEvent)GetProcAddress(hWS2, "WSACloseEvent");
    p_GetProcAddress = (PFN_GetProcAddress)GetProcAddress(hKernel, "GetProcAddress");
    p_CreateProcessA = (PFN_CreateProcessA)GetProcAddress(hKernel, "CreateProcessA");
    p_CreateProcessW = (PFN_CreateProcessW)GetProcAddress(hKernel, "CreateProcessW");
    p_LoadLibraryA = (PFN_LoadLibraryA)GetProcAddress(hKernel, "LoadLibraryA");
    p_LoadLibraryW = (PFN_LoadLibraryW)GetProcAddress(hKernel, "LoadLibraryW");
    p_LoadLibraryExA = (PFN_LoadLibraryExA)GetProcAddress(hKernel, "LoadLibraryExA");
    p_LoadLibraryExW = (PFN_LoadLibraryExW)GetProcAddress(hKernel, "LoadLibraryExW");
    policy_init();
    dbg("lan_hook: policy ready\n");
    flog("LanHookInit: policy ready");
    dt_log_options();
    {
        WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd);
    }
    if (g_direct) { dbg("lan_hook: starting tunnel\n"); flog("LanHookInit: starting tunnel"); dt_start(); }
    dbg("lan_hook: patching modules\n");
    flog("LanHookInit: patching modules");
    InitializeCriticalSection(&g_pcs);
    g_pcs_init = 1;
    patch_all(1);
    patch_loader_iat();
    /* late GetProcAddress IAT swap for already-loaded modules */
    patch_all(1);
    {
        HANDLE t = CreateThread(NULL, 0, dt_sweep_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    dbg("lan_hook: installed\n");
    flog("LanHookInit: ShadowLAN hook v" SHADOWLAN_VERSION);
    flog("LanHookInit: build " __DATE__ " " __TIME__);
    flog("LanHookInit: installed");
    g_init_armed = 0;
    g_init_done = 1;
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hself = h;
        DisableThreadLibraryCalls(h);
    }
    return TRUE;
}
#endif
