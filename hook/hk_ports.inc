/* hk_ports.inc - vport alias table + node-scoped port ledger (shared)
 * Part of lan_hook.c; see the note there before editing. */
/* -1 when the socket binds its port for real */
static int dt_alias_vport(long long sock) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock && g_ta[i].vport > 0) return g_ta[i].vport;
    return -1;
}
/* real local port serving this virtual port in THIS process (0: none) */
static int dt_alias_real(int vport) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].vport == vport && g_ta[i].real > 0) return g_ta[i].real;
    return 0;
}
static void dt_alias_bindv(long long sock) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock) { g_ta[i].bindv = 1; return; }
}
static int dt_alias_is_bindv(long long sock) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock) return g_ta[i].bindv;
    return 0;
}
static void dt_alias_drop(long long sock) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock) { g_ta[i].sock = 0; g_ta[i].vport = g_ta[i].real = 0; }
}
/* ---- node-scoped shared port ledger ----
 * A NODE (process tree) is ONE emulated machine: its processes share a
 * real kernel, which already arbitrates REAL ports - but the aliasing
 * above lets two same-node processes each claim the same VIRTUAL port,
 * something no real machine allows. The ledger records each node's
 * vport claims in shared memory so same-node binds collide exactly
 * like the kernel would collide them, while other nodes on this OS
 * (separate emulated machines) stay invisible to each other.
 * Windows: Local\ pagefile-backed CreateFileMapping (kernel holds it
 * until the last process closes it); Linux: shm_open + flock. Any
 * failure degrades silently to the previous per-process behavior. */
#define SLP_MAGIC 0x534c5032u
#define SLP_MAX 192
typedef struct { unsigned int pid; unsigned int node;
                 unsigned long long start;
                 int vport; int real;
                 unsigned char proto; unsigned char reuse;
                 unsigned char used; unsigned char pad; } slp_ent;
typedef struct { unsigned int magic; unsigned int gen; slp_ent e[SLP_MAX]; } slp_t;

#ifdef LINUX_BUILD
static int g_slp_fd = -1;
static slp_t *g_slp = 0;
static int slp_attach(void) {
    /* ONE machine-wide registry object; entries carry the node id.
     * (A per-node name would leave a /dev/shm stub per random node id
     * forever - the object is kernel-refcounted, the NAME is not.) */
    if (g_slp) return 1;
    if (!g_node) return 0;
    int fd = shm_open("/slp-ports", O_CREAT | O_RDWR, 0600);
    if (fd < 0) return 0;
    if (ftruncate(fd, (off_t)sizeof(slp_t)) != 0) { close(fd); return 0; }
    void *p = mmap(0, sizeof(slp_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { close(fd); return 0; }
    g_slp_fd = fd; g_slp = (slp_t *)p;
    if (g_slp->magic != SLP_MAGIC) {
        g_slp->magic = SLP_MAGIC; g_slp->gen = 0;
        memset(g_slp->e, 0, sizeof g_slp->e);
    }
    return 1;
}
#define SLP_LOCK()   do { if (g_slp_fd >= 0) flock(g_slp_fd, LOCK_EX); } while (0)
#define SLP_UNLOCK() do { if (g_slp_fd >= 0) flock(g_slp_fd, LOCK_UN); } while (0)
#else
static HANDLE g_slp_mx = 0;
static HANDLE g_slp_sec = 0;
static slp_t *g_slp = 0;
static int slp_attach(void) {
    char nm[96], mx[96];
    if (g_slp) return 1;
    if (!g_node) return 0;
    snprintf(nm, sizeof nm, "Local\\ShadowLAN-ports-%08x", (unsigned)g_node);
    snprintf(mx, sizeof mx, "Local\\ShadowLAN-portlk-%08x", (unsigned)g_node);
    HANDLE m = CreateMutexA(NULL, FALSE, mx);
    if (!m) return 0;
    HANDLE h = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                  0, sizeof(slp_t), nm);
    if (!h) { CloseHandle(m); return 0; }
    void *p = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, sizeof(slp_t));
    if (!p) { CloseHandle(m); return 0; }
    /* keep the section handle: some environments (observed under Wine)
     * drop the shared pages when the last CREATE handle closes even if
     * views remain - never gamble on that here */
    g_slp_mx = m; g_slp_sec = h; g_slp = (slp_t *)p;
    /* OWNED init, never GetLastError(ERROR_ALREADY_EXISTS): some
     * environments (observed under Wine) do not preserve that flag to
     * this point, and a false "fresh" would WIPE a live registry. */
    WaitForSingleObject(g_slp_mx, INFINITE);
    if (g_slp->magic != SLP_MAGIC) {
        g_slp->magic = 0; g_slp->gen = 0;
        memset(g_slp->e, 0, sizeof g_slp->e);
        InterlockedExchange((LONG *)&g_slp->magic, (LONG)SLP_MAGIC);
    }
    ReleaseMutex(g_slp_mx);
    return 1;
}
#define SLP_LOCK()   do { if (g_slp_mx) WaitForSingleObject(g_slp_mx, INFINITE); } while (0)
#define SLP_UNLOCK() do { if (g_slp_mx) ReleaseMutex(g_slp_mx); } while (0)
#endif

/* pid alone cannot prove identity (reuse): stamp the holder's process
 * start time beside it. */
#ifdef LINUX_BUILD
static unsigned long long slp_starttime(unsigned pid) {
    char path[64], buf[2048];
    FILE *f;
    char *p, *tok;
    unsigned long long v = 0;
    int idx = 0;
    snprintf(path, sizeof path, "/proc/%u/stat", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(buf, sizeof buf, f)) { fclose(f); return 0; }
    fclose(f);
    p = strrchr(buf, ')');
    if (!p) return 0;
    p++;
    /* field 22 overall; after the ')' we are at field 3 -> +20 tokens */
    tok = strtok(p, " ");
    while (tok && ++idx < 20) tok = strtok(NULL, " ");
    if (tok) v = strtoull(tok, 0, 10);
    return v;
}
static int slp_alive(unsigned pid, unsigned long long start) {
    unsigned long long now;
    if (!pid) return 0;
    if (kill(pid, 0) != 0 && errno != EPERM) return 0;
    if (!start) return 1;
    now = slp_starttime(pid);
    return now != 0 && now == start;
}
static unsigned long long slp_self_start(void) {
    return slp_starttime((unsigned)current_pid());
}
#else
/* process start time straight from the PEB (field stable across all
 * supported Windows; the 32-bit build reads the TEB's static PEB
 * pointer).  OpenProcess+GetProcessTimes is NOT an option here: it
 * faults inside kernelbase under some builds (field AV at startup,
 * reproduced under Wine) and we may run on arbitrary app threads. */
static unsigned long long slp_self_start(void) {
    unsigned long long v = 0;
#ifdef _WIN64
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    if (peb) v = *(unsigned long long *)(peb + 0x0a8);   /* Peb->CreateTime */
#else
    unsigned char *peb = 0;
    __asm__ __volatile__ ("movl %%fs:0x30, %0" : "=r"(peb));
    if (peb) v = *(unsigned long long *)(peb + 0x0a4);   /* 32-bit offset */
#endif
    return v;
}
/* NEVER GetProcessTimes here (field AV at app startup, reproducible
 * under Wine). Liveness by exit code; access-denied means alive; the
 * start stamp is kept only for self-audits. */
static int slp_alive(unsigned pid, unsigned long long start) {
    HANDLE h; DWORD code = 0; int alive;
    (void)start;
    if (!pid) return 0;
    if (pid == (unsigned)GetCurrentProcessId()) return 1;
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return GetLastError() != ERROR_INVALID_PARAMETER;
    alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}
#endif
/* claim vport for THIS process. 0/1 = ok (1 = shared), -1 = conflict,
 * -2 = no ledger available. Dead holders' claims are taken over. */
static int slp_claim(int vport, int proto, int reuse, int real) {
    int rc;
    if (!slp_attach()) return -2;      /* no ledger: caller decides */
    SLP_LOCK();
    rc = -2;
    {
        int i, found = -1;
        for (i = 0; i < SLP_MAX; i++) {
            slp_ent *x = &g_slp->e[i];
            if (x->used && x->node == (unsigned)g_node &&
                x->vport == vport && x->proto == (unsigned char)proto) {
                found = i; break;
            }
        }
        if (found >= 0) {
            slp_ent *x = &g_slp->e[found];
#ifndef LINUX_BUILD
            if (g_debug) { char lb[160];
                snprintf(lb, sizeof lb, "slp dbg found=%d holder=%u start=%llx self=%llx alive=%d",
                         found, x->pid, x->start, slp_self_start(), slp_alive(x->pid, x->start));
                dlog(lb); }
#endif
            if (!slp_alive(x->pid, x->start)) { /* stale claim: take over */
                x->pid = (unsigned)current_pid(); x->real = real;
                x->start = slp_self_start();
                x->reuse = (unsigned char)reuse; rc = 0;
            } else if (proto == SOCK_DGRAM && x->reuse && reuse) {
                rc = 1;      /* kernel-faithful: datagram sharing needs
                              * SO_REUSEADDR on BOTH sockets */
            }
            else rc = -1;                       /* kernel would collide */
        } else {
            /* allocation with a janitor pass: a dead holder's slot is
             * free space too. Without this sweep the machine-wide
             * registry fills with stale claims over many runs (-2 ->
             * fail-open -> same-node duplicates alias through: the
             * table-full bug found on a day of heavy test runs). */
            int slot = -1, reap = -1, i2;
            for (i2 = 0; i2 < SLP_MAX; i2++) {
                slp_ent *x = &g_slp->e[i2];
                if (!x->used) { slot = i2; break; }
                if (reap < 0 && !slp_alive(x->pid, x->start)) reap = i2;
            }
            if (slot < 0) slot = reap;
            if (slot >= 0) {
                slp_ent *x = &g_slp->e[slot];
                x->used = 1; x->pid = (unsigned)current_pid();
                x->node = (unsigned)g_node;
                x->start = slp_self_start();
                x->vport = vport; x->real = real;
                x->proto = (unsigned char)proto; x->reuse = (unsigned char)reuse;
                g_slp->gen++;
                rc = 0;
            }
        }
    }
    SLP_UNLOCK();
    return rc;
}
static void slp_release(int vport, int proto) {
    if (!g_slp) return;
    SLP_LOCK();
    {
        int i;
        for (i = 0; i < SLP_MAX; i++) {
            slp_ent *x = &g_slp->e[i];
            if (x->used && x->node == (unsigned)g_node &&
                x->vport == vport && x->proto == (unsigned char)proto
                && x->pid == (unsigned)current_pid()) {
                x->used = 0; g_slp->gen++;
            }
        }
    }
    SLP_UNLOCK();
}
/* any-proto claim check for bind(0) port selection */
static int slp_used(void) {
    int n = 0;
    if (!g_slp) return 0;
    SLP_LOCK();
    { int i; for (i = 0; i < SLP_MAX; i++) if (g_slp->e[i].used) n++; }
    SLP_UNLOCK();
    return n;
}
static int slp_taken(int vport) {
    int t = 0;
    if (!g_slp) return 0;
    SLP_LOCK();
    {
        int i;
        for (i = 0; i < SLP_MAX; i++)
            if (g_slp->e[i].used && g_slp->e[i].node == (unsigned)g_node &&
                g_slp->e[i].vport == vport) { t = 1; break; }
    }
    SLP_UNLOCK();
    return t;
}
/* release whatever this socket claimed (called from close) */
static void slp_release_sock(long long sock) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock && g_ta[i].vport > 0)
            slp_release(g_ta[i].vport, g_ta[i].proto);
}
static void dt_record_listen(int port) {
    int i, free_i = -1;
    if (port <= 0) return;
    DLOCK();
    for (i = 0; i < DT_MAXLISTEN; i++) {
        if (g_lports[i] == port) { DUNLOCK(); return; }
        if (free_i < 0 && g_lports[i] == 0) free_i = i;
    }
    if (free_i >= 0) g_lports[free_i] = port;
    DUNLOCK();
}
static int dt_owns_listen(int port) {
    int i, own = 0;
    DLOCK();
    for (i = 0; i < DT_MAXLISTEN; i++)
        if (g_lports[i] == port) { own = 1; break; }
    DUNLOCK();
    return own;
}
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

/* Forward declarations: these helpers live further down the file. */
static int dt_resolve(struct sockaddr_in *out);
#ifdef LINUX_BUILD
static void dt_reals(void);
static ssize_t (*r_send)(int, const void *, size_t, int);
static ssize_t (*r_recv)(int, void *, size_t, int);
static ssize_t (*r_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static int (*r_close)(int);
static int (*r_bind)(int, const struct sockaddr *, socklen_t);
static int (*r_connect)(int, const struct sockaddr *, socklen_t);
#endif

/* Event-driven wake channels. Kernel readiness already drives select by
 * itself; these cover the WAITER-SIDE events: a cross-thread enqueue must
 * not wait for the sleeper's poll slice. A connected datagram pair whose
 * read end joins the sleeper's select set. Plain calls are safe here:
 * internal fds are never in the app-facing tables, so the hooks on the
 * other side of these calls pass through. Creation failure degrades to
 * slice polling (bounded, just slower). */
static DTSOCK g_wake_r = DTSOCK_BAD, g_wake_w = DTSOCK_BAD;
/* MUST use real symbols: these run under DLOCK and inside app threads;
 * the hooked send/recv would re-enter the same lock (non-recursive). */
static void dt_wake_write(DTSOCK w) {
    if (w == DTSOCK_BAD) return;
#ifdef LINUX_BUILD
    dt_reals();
    { static const char b = 1; ssize_t r = r_send(w, &b, 1, MSG_NOSIGNAL); (void)r; }
#else
    { static int (WSAAPI *fp)(SOCKET, const char *, int, int) = 0;
      if (!fp) fp = (int (WSAAPI *)(SOCKET, const char *, int, int))
          GetProcAddress(GetModuleHandleA("ws2_32.dll"), "send");
      if (fp) { static const char b = 1; int r = fp(w, &b, 1, 0); (void)r; } }
#endif
}
static void dt_wake_drain(DTSOCK rd) {
    char sb[256];
#ifdef LINUX_BUILD
    dt_reals();
    while (r_recv(rd, sb, sizeof sb, MSG_DONTWAIT) > 0) ;
#else
    { static int (WSAAPI *fp)(SOCKET, char *, int, int) = 0;
      if (!fp) fp = (int (WSAAPI *)(SOCKET, char *, int, int))
          GetProcAddress(GetModuleHandleA("ws2_32.dll"), "recv");
      if (fp) while (fp(rd, sb, sizeof sb, 0) > 0) ; }
#endif
}
static void dt_wake_pair(DTSOCK *rp, DTSOCK *wp) {
    *rp = *wp = DTSOCK_BAD;
#ifdef LINUX_BUILD
    { int sv[2];
      if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, sv) == 0) {
          *rp = (DTSOCK)sv[0]; *wp = (DTSOCK)sv[1]; } }
#else
    { struct sockaddr_in a; int al = (int)sizeof(a);
      DTSOCK x = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      DTSOCK y = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if (x != INVALID_SOCKET && y != INVALID_SOCKET) {
          memset(&a, 0, sizeof(a)); a.sin_family = AF_INET;
          a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
          if (bind(x, (struct sockaddr *)&a, al) == 0 &&
              getsockname(x, (struct sockaddr *)&a, &al) == 0) {
              struct sockaddr_in me = a;
              memset(&a, 0, sizeof(a)); a.sin_family = AF_INET;
              if (bind(y, (struct sockaddr *)&a, al) == 0 &&
                  getsockname(y, (struct sockaddr *)&a, &al) == 0) {
                  struct sockaddr_in o = a;
                  if (connect(x, (struct sockaddr *)&o, al) == 0 &&
                      connect(y, (struct sockaddr *)&me, al) == 0) {
                      u_long nb = 1;
                      ioctlsocket(x, FIONBIO, &nb);
                      ioctlsocket(y, FIONBIO, &nb);
                      *rp = y; *wp = x;   /* enqueue on wp, wake reader rp */
                      return; } } } }
      if (x != INVALID_SOCKET) closesocket(x);
      if (y != INVALID_SOCKET) closesocket(y);
    }
#endif
}
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
    dt_wake_write(g_wake_w);   /* send now, not at the next poll slice */
}
/* HELLO payload: !H token_len + token (matches common.encode_hello). */
static size_t dt_hello_payload(unsigned char *out) {
    out[0] = (unsigned char)((g_token_len >> 8) & 255);
    out[1] = (unsigned char)(g_token_len & 255);
    if (g_token_len) memcpy(out + 2, g_token, (size_t)g_token_len);
    return (size_t)(2 + g_token_len);
}
/* Called when the local game starts serving: stamp the host claim. */
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
static void dt_rand_seed(void);
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
