/* hk_core.c - wire tables, DLOCK, policy, fatal, put/get. */
#include "hk_core.h"

int g_only_ports[64];
int g_nports = 0;
char g_server[256] = {0};
int g_srvport = 47777;
int g_direct = 0;
int g_udp_tcp = 0;
int g_lan_only = 0;
volatile int g_claimed = 0;
unsigned char g_token[256];
int g_token_len = 0;
volatile unsigned g_node = 0;
unsigned g_myvirt = 0;
unsigned char g_vnetb[4];
int g_vbits = 24;
struct dt_member g_members[DT_MAXMEMB];
int g_nmembers = 0;
struct dt_stream g_st[DT_MAXSTREAM];
struct dt_udp g_uq[DT_MAXUDP];
struct dt_slot g_sl[DT_MAXSLOT];
struct dt_frame *g_sqh = NULL, *g_sqt = NULL;
volatile int g_tun_run = 0, g_tun_started = 0, g_tcp_up = 0;
volatile int g_have_assign = 0;
volatile int g_init_done = 0;
volatile int g_tcp_ever_up = 0;
long long g_init_t0 = 0;
long long g_fatal_after_ms = 30000;
DTSOCK g_tcp = DTSOCK_BAD, g_udptun = DTSOCK_BAD;
int g_tun_conn = 0;
unsigned long g_fakeip = 0;

#ifdef LINUX_BUILD
pthread_mutex_t g_dmu = PTHREAD_MUTEX_INITIALIZER;
#else
CRITICAL_SECTION g_dcs;
int g_dcs_init = 0;
#endif

void policy_init(void) {
    const char *p = getenv("LAN_HOOK_PORTS");
    if (p && p[0]) {
        char tmp[512];
        strncpy(tmp, p, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = 0;
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
        if (pp && pp[0]) {
            int v = atoi(pp);
            if (v > 0 && v < 65536) g_srvport = v;
        }
        g_direct = 1;
    }
    {
        const char *ut = getenv("LAN_HOOK_UDP_OVER_TCP");
        g_udp_tcp = (ut && ut[0] && ut[0] != '0') ? 1 : 0;
    }
    {
        const char *lo = getenv("LAN_HOOK_LAN_ONLY");
        g_lan_only = (lo && lo[0] && lo[0] != '0') ? 1 : 0;
    }
}

void dt_log_options(void) {
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
             g_server[0] ? g_server : "(unset)", g_srvport, g_token_len ? "set" : "(unset)",
             getenv("LAN_HOOK_PORTS") ? getenv("LAN_HOOK_PORTS") : "(all)", g_debug,
             getenv("LAN_HOOK_NODE") ? getenv("LAN_HOOK_NODE") : "(gen)", lease, ito, g_udp_tcp,
             getenv("LAN_HOOK_MODULES") ? getenv("LAN_HOOK_MODULES") : "(all)",
             getenv("LAN_HOOK_CHILDREN") ? getenv("LAN_HOOK_CHILDREN") : "(all)",
             getenv("LAN_HOOK_NOCHILD") ? getenv("LAN_HOOK_NOCHILD") : "0", g_lan_only,
             getenv("LAN_HOOK_LOGFILE") ? getenv("LAN_HOOK_LOGFILE") : "(debugview)");
    lb[sizeof(lb) - 1] = 0;
#ifdef LINUX_BUILD
    {
        char ts[32];
        dt_stamp(ts, sizeof(ts));
        fprintf(stderr, "[%s lan_hook] %s\n", ts, lb);
    }
#else
    OutputDebugStringA("lan_hook: ");
    OutputDebugStringA(lb);
    OutputDebugStringA("\n");
    flog(lb);
#endif
}

int port_allowed(int port) {
    if (g_nports == 0) return 1;
    for (int i = 0; i < g_nports; i++)
        if (g_only_ports[i] == port) return 1;
    return 0;
}

int ipv4_is_lan(unsigned long net_order) {
    unsigned long h = ntohl(net_order);
    if ((h >> 24) == 0xFF) return 1;
    if ((h & 0xFF000000) == 0x0A000000) return 1;
    if ((h & 0xFFF00000) == 0xAC100000) return 1;
    if ((h & 0xFFFF0000) == 0xC0A80000) return 1;
    if ((h & 0xFFFF0000) == 0xA9FE0000) return 1;
    if ((h & 0xF0000000) == 0xE0000000) return 1;
    if ((h & 0xFF) == 0xFF) return 1;
    return 0;
}

int sockaddr_is_lan_target(const struct sockaddr *sa, int *port_out) {
    if (!sa || sa->sa_family != AF_INET) return 0;
    const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
    int port = ntohs(in->sin_port);
    if (port_out) *port_out = port;
    if (!port_allowed(port)) return 0;
    return ipv4_is_lan(in->sin_addr.s_addr);
}

int ipv4_is_bcast(unsigned long net_order) {
    unsigned long h = ntohl(net_order);
    if ((h >> 24) == 0xFF) return 1;
    if ((h & 0xF0000000) == 0xE0000000) return 1;
    if ((h & 0xFF) == 0xFF) return 1;
    return 0;
}

void dt_fatal(int code, const char *msg) {
    if (g_init_done) {
        dlog("dt_fatal after init: ignored (never kill gameplay)");
        return;
    }
    char full[512];
    snprintf(full, sizeof(full), "ShadowLAN fatal (%d): %s [relay %s:%d]", code, msg,
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
            fputs(ts, lf);
            fputs(" lan_hook: ", lf);
            fputs(full, lf);
            fputc('\n', lf);
            fflush(lf);
            fclose(lf);
        }
    }
    OutputDebugStringA("lan_hook: ");
    OutputDebugStringA(full);
    OutputDebugStringA("\n");
    MessageBoxA(NULL, full, "ShadowLAN", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND);
    TerminateProcess(GetCurrentProcess(), (UINT)code);
    ExitProcess((UINT)code);
#endif
}

int dt_fatal_code(void) {
    return g_tcp_ever_up ? SL_FATAL_NOLEASE : SL_FATAL_NORELAY;
}

void dt_init_watchdog(void) {
    if (!g_init_done && !g_have_assign && g_fatal_after_ms > 0 && g_tun_run &&
        dt_now_ms() - g_init_t0 > g_fatal_after_ms) {
        int code = dt_fatal_code();
        dt_fatal(code, code == SL_FATAL_NORELAY
                           ? "cannot reach relay (check server/port, relay running, firewall)"
                           : "relay connected but no virtual-IP lease (check token, relay log)");
    }
}

void dt_put32(unsigned char *b, unsigned v) {
    b[0] = (v >> 24) & 255;
    b[1] = (v >> 16) & 255;
    b[2] = (v >> 8) & 255;
    b[3] = v & 255;
}
unsigned dt_get32(const unsigned char *b) {
    return ((unsigned)b[0] << 24) | ((unsigned)b[1] << 16) | ((unsigned)b[2] << 8) | b[3];
}
void dt_put16(unsigned char *b, unsigned v) {
    b[0] = (v >> 8) & 255;
    b[1] = v & 255;
}
unsigned dt_get16(const unsigned char *b) {
    return ((unsigned)b[0] << 8) | b[1];
}
