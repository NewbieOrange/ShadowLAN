/* hk_policy.inc - policy, logging, wire ops, platform helpers (shared)
 * Part of lan_hook.c; see the note there before editing. */
/* ---------- shared policy ---------- */
static int g_only_ports[64];
static int g_nports = 0; /* 0 = all */
static void dt_fatal(int code, const char *msg);
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
#define DT_NODE_F_HOST 0x01  /* T_NODE flags bit: host claim (ordering stamp) */
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
#define DT_STFAIL 0x0C
#define DT_STSHUT 0x0D   /* half-close: my write side is done */    /* relay->opener/dest, dest->relay: !I sid + !B reason */
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
/* UDP tunnel datagram framing version 3 (the only version on the wire):
 * source port = the sender socket's BOUND VPORT (what a real NIC puts
 * on the wire; apps legitimately fold recvfrom sources and dial them
 * back - the legacy mark-in-source-port broke exactly that, field SNS
 * black-screen). Return-routing mark travels as its own fixed u16
 * field. Co-ships with the relay and all hooks (like PVER 2). */
#define DU_VER 3
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
/* hosting claim: set when the local game serves (listen() hook). The
 * relay keeps it per LINK as an ordering stamp (freshest claim first) so
 * bridge migration is deterministic; it never gates or excludes anyone —
 * any peer, hook or wclient --host, can host. */
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
                   int fd_live;        /* thread published its relay fd */
                   struct dt_chunk *oh, *ot; size_t ototal;  /* app out-queue */
                   /* field diagnostics: app-facing byte counters + log throttle */
                   unsigned an_rx, an_tx; size_t ab_rx, ab_tx; long long a_log;
                   /* exit drain handshake: while flushing the pump leaves the
                    * out-queue to the exiting thread (sending = in-flight) */
                   int flushing; int sending;
                   int thread_done;  /* pump loop exited (owns teardown) */
    int shut_done;    /* DT_STSHUT queued once after WR flush */
    DTSOCK wake_r, wake_w;  /* pump self-wake (enqueue from app threads) */
    int ever_open;    /* reached ST_OPEN at least once: post-open
                     * deaths are NOT connect errors (SO_ERROR) */
                   int peer_fin;     /* relay delivered FIN: read side closed,
                                      * writes stay alive (kernel half-close) */
                   int wr_shut;      /* app called shutdown(SHUT_WR) */
                   int rd_shut;      /* app called shutdown(SHUT_RD) */ };
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

/* forward decls: stream helpers defined in the per-stream section below */
static struct dt_stream *dt_stream_by_sid(unsigned sid);
/* wall-clock stamp for file logs: "MM-DD HH:MM:SS.mmm" */
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
/* TCP ports this process actually listens on. A DT_STREQ must only be
 * served by the process that owns the game's listener: any sibling that
 * bridges blindly gets its loopback connection ACCEPTED by the owner's
 * socket - across processes, so the accepted-socket vnode rewrite (g_hs
 * lives in the bridging process) is invisible and the game sees the
 * joiner as 127.0.0.1 again (observed in the field: host read the JOIN,
 * answered 271KB, still never opened the session). Non-owners now stay
 * silent; the owner serves; nobody owns -> opener gets the normal
 * handshake timeout (nothing listens, faithful). */
#define DT_MAXLISTEN 32
static int g_lports[DT_MAXLISTEN];
