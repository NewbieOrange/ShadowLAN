/* hk_sess.inc - hosted sessions + accept-door identity (shared)
 * Part of lan_hook.c; see the note there before editing. */
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
    unsigned ovirt;       /* opener's virtual IP (from DT_STREQ) */
    int lport;            /* bridge socket's local ephemeral port: the
                             peer port the game's accept() will see */
    int accsp;            /* accepted socket's real src port (fd-reuse
                             guard for the getpeername door) */
};
static struct dt_hosted g_hs[DT_MAXHOST];
struct dt_usess {
    int used; int game_port; struct sockaddr_in cli; int lport;
    unsigned ovirt;              /* sender vnode seen on the wire: the
                                  * accept door presents it to the local
                                  * game as the peer of the bridged
                                  * socket (UDP bootstrap apps cross-check
                                  * it against the announce source) */
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
static struct dt_udp *dt_udp_entry(long long s, int create);
/* EADDRINUSE fallback for bind(): rebind ephemerally, remember the
 * virtual port. DGRAM additionally registers the dt_udp vport so UDP
 * fan-out matches; STREAM relies on the alias table + listen record.
 * Caller holds no lock; DLOCK taken internally. Returns 0 on success. */
static int dt_bind_alias(long long s, const struct sockaddr_in *want,
                         int is_dgram,
                         int (*binder)(int, const struct sockaddr *, socklen_t)) {
    struct sockaddr_in sa = *want;
    int wp = ntohs(sa.sin_port);
    int r;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
#ifdef LINUX_BUILD
    r = binder((int)s, (struct sockaddr *)&sa, sizeof(sa));
#else
    r = binder((int)(SOCKET)s, (struct sockaddr *)&sa, sizeof(sa));
#endif
    if (r != 0) return -1;
    {
        struct sockaddr_in got;
#ifdef LINUX_BUILD
        socklen_t gl = sizeof(got);
#else
        int gl = (int)sizeof(got);
#endif
        int rp = 0;
#ifdef LINUX_BUILD
        {
            static int (*rgs)(int, struct sockaddr *, socklen_t *) = 0;
            if (!rgs) rgs = (int (*)(int, struct sockaddr *, socklen_t *))
                dlsym(RTLD_NEXT, "getsockname");
            if (rgs && rgs((int)s, (struct sockaddr *)&got, &gl) == 0) rp = ntohs(got.sin_port);
        }
#else
        if (getsockname((SOCKET)s, (struct sockaddr *)&got, &gl) == 0) rp = ntohs(got.sin_port);
#endif
        DLOCK();
        dt_alias_add(s, wp, rp, is_dgram ? SOCK_DGRAM : SOCK_STREAM);
        if (is_dgram) {
            struct dt_udp *e = dt_udp_entry(s, 1);
            if (e) e->vport = wp;
        }
        DUNLOCK();
        if (g_debug) { char lb[128];
            snprintf(lb, sizeof(lb), "bind alias sock=%lld vport=%d real=%d %s",
                     s, wp, rp, is_dgram ? "dgram" : "stream");
            dlog(lb); }
    }
    return 0;
}
/* Local loopback bridge to our own game server (joinee side). */
static int dt_host_bridge(unsigned sid, int port) {
    { int al = dt_alias_real(port); if (al) port = al; }
    struct sockaddr_in lo; memset(&lo, 0, sizeof(lo));
    lo.sin_family = AF_INET; lo.sin_port = htons((unsigned short)port);
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    DTSOCK s;
#ifdef LINUX_BUILD
    dt_reals();
    s = (DTSOCK)socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    if (r_connect(s, (struct sockaddr *)&lo, sizeof(lo)) != 0) { r_close(s); return -1; }
    { int fl = fcntl((int)s, F_GETFL, 0); fcntl((int)s, F_SETFL, fl | O_NONBLOCK); }
#else
    s = (DTSOCK)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;
    if (connect(s, (struct sockaddr *)&lo, sizeof(lo)) != 0) { closesocket(s); return -1; }
    { u_long nb = 1; ioctlsocket(s, FIONBIO, &nb); }
#endif
    struct sockaddr_in bn;
#ifdef LINUX_BUILD
    socklen_t bl = sizeof(bn);
#else
    int bl = sizeof(bn);
#endif
    memset(&bn, 0, sizeof(bn));
    int lp = 0;
#ifdef LINUX_BUILD
    if (getsockname((int)s, (struct sockaddr *)&bn, &bl) == 0)
#else
    if (getsockname(s, (struct sockaddr *)&bn, &bl) == 0)
#endif
        lp = ntohs(bn.sin_port);
    DLOCK();
    struct dt_hosted *h = dt_hs_by_sid(sid);
    if (h) { h->real = s; h->live = 1; h->last = dt_now_ms(); h->lport = lp; }
    DUNLOCK();
    { char lb[96];
      snprintf(lb, sizeof(lb), "hosted bridge: fd=%d lport=%d ovirt=%u",
               (int)(int)s, lp, h ? h->ovirt : 0);
      dlog(lb); }
    return 0;
}
/* ---- accepted-socket peer spoofing -------------------------------------
 * On a real LAN the game's accept() reports the connector's announced
 * address; locally the connector is our loopback bridge, so an app that
 * cross-checks getpeername against the lobby's vnode would reject the
 * session (observed: full 271KB handshake accepted by the bridge yet the game
 * stalled at menu). Map accepted sockets whose real peer is the bridge
 * endpoint to the opener's vnode captured at DT_STREQ time. */
#ifdef LINUX_BUILD
typedef socklen_t socklen_int_t;
#else
typedef int socklen_int_t;
#endif
#define DT_MAXACC 64
struct dt_accfd { int used; long long gsock; unsigned vnode;
                  int lport; int bport; };
static struct dt_accfd g_acc[DT_MAXACC];
/* fd is the ACCEPTED socket. The bridge/real peer lives elsewhere on the
 * row (accepted fds are NOT the bridge fds), so we match by ports:
 * peer->sin_port = bridge ephemeral src; the listen port comes in via
 * *lp_hint (set by post-accept from getsockname) and identifies the
 * hosted row. We store BOTH ports: sp for the fd-reuse check in
 * getpeername, gport for bookkeeping. */
static void dt_acc_learn_fd(long long fd, const struct sockaddr_in *peer,
                            int listen_port) {
    int sp = (int)ntohs(peer->sin_port);   /* bridge's ephemeral src port */

    DLOCK();
    int hitp = -1, hitf = -1;   /* exact-port / first-live */
    for (int i = 0; i < DT_MAXHOST; i++) {
        if (!g_hs[i].used || !g_hs[i].live || !g_hs[i].ovirt) continue;
        if (hitf < 0) hitf = i;
        if (listen_port && (int)g_hs[i].lport == listen_port) { hitp = i; break; }
        if (sp && (int)g_hs[i].accsp == sp) { hitp = i; break; }
    }

    int pick = hitp >= 0 ? hitp : (listen_port ? -1 : hitf);
    if (pick >= 0) {
        g_hs[pick].accsp = sp;
        for (int j = 0; j < DT_MAXACC; j++)
            if (!g_acc[j].used || g_acc[j].gsock == fd) {
                g_acc[j].used = 1; g_acc[j].gsock = fd;
                g_acc[j].vnode = g_hs[pick].ovirt;
                g_acc[j].lport = (int)g_hs[pick].lport;  /* listen port:
                    the port the app must see as LOCAL (getpeername door
                    compares the TRUE peer's bridge port separately) */
                g_acc[j].bport = sp;
                break;
            }
        DUNLOCK();
        return;
    }
    /* no TCP stream carried this opener: the peer may be bootstrapping
     * us over UDP (session-bridging libs announce, then connect). The
     * hosted UDP session saw the sender's vnode on the wire - present
     * it as the accepted socket's peer. */
    for (int i = 0; i < DT_MAXUSESS; i++)
        if (g_us[i].used && g_us[i].ovirt && g_us[i].lport == sp) {
            for (int j = 0; j < DT_MAXACC; j++)
                if (!g_acc[j].used || g_acc[j].gsock == fd) {
                    g_acc[j].used = 1; g_acc[j].gsock = fd;
                    g_acc[j].vnode = g_us[i].ovirt;
                    g_acc[j].lport = g_us[i].game_port;
                    g_acc[j].bport = sp;
                    break;
                }
            break;
        }
    DUNLOCK();
}
/* hit returns 1 and fills *out (vnet view) + *rlport (expected real peer
 * port, for the caller's fd-reuse verification against the TRUE peer). */
static int dt_acc_get(long long fd, struct sockaddr_in *out, int *rlport) {
    int hit = 0, lp = 0, bp = 0; unsigned v = 0;
    DLOCK();
    for (int j = 0; j < DT_MAXACC; j++)
        if (g_acc[j].used && g_acc[j].gsock == fd) {
            hit = 1; lp = g_acc[j].lport; v = g_acc[j].vnode;
            bp = g_acc[j].bport; break;
        }
    DUNLOCK();

    if (!hit) return 0;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_addr.s_addr = htonl(v);
    out->sin_port = htons((unsigned short)lp);
    if (rlport) *rlport = bp;   /* TRUE bridge port: fd-reuse guard */
    return 1;
}
static void dt_acc_forget(long long fd) {
    DLOCK();
    for (int j = 0; j < DT_MAXACC; j++)
        if (g_acc[j].used && g_acc[j].gsock == fd) { g_acc[j].used = 0; break; }
    DUNLOCK();
}
/* shared post-accept handling: real peer == our bridge -> learn, then
 * present the opener's vnode to the app (fd/addr are the accept out
 * params as returned by the OS) */
static void dt_acc_post_accept(long long fd, struct sockaddr *addr,
                               socklen_int_t *addrlen,
                               const struct sockaddr_in *real_peer) {
    if (real_peer->sin_family != AF_INET ||
        real_peer->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        return;
    }
    dt_acc_learn_fd(fd, real_peer, 0);
    { struct sockaddr_in o; int lp = 0;
      char lb[128];
      int hit = dt_acc_get(fd, &o, &lp);
      snprintf(lb, sizeof(lb), "acc-hook: fd=%lld loopback:%d learn=%d",
               fd, (int)ntohs(real_peer->sin_port), hit);
      dlog(lb);
      if (hit && addr && addrlen && *addrlen >= (socklen_int_t)sizeof(struct sockaddr_in)) {
          memcpy(addr, &o, sizeof(o)); *addrlen = (socklen_int_t)sizeof(o);
      }
    }
}
static struct dt_usess *dt_usess_find(int game_port, const unsigned *ovirt,
                                      const struct sockaddr_in *cli,
                                      int create) {
    long long now = dt_now_ms();
    for (int i = 0; i < DT_MAXUSESS; i++)
        if (g_us[i].used && g_us[i].game_port == game_port &&
            g_us[i].cli.sin_addr.s_addr == cli->sin_addr.s_addr &&
            g_us[i].cli.sin_port == cli->sin_port) {
            if (ovirt && !g_us[i].ovirt) g_us[i].ovirt = *ovirt;
            return &g_us[i];
        }
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
            g_us[i].cli = *cli; g_us[i].last = now; g_us[i].lport = 0;
            g_us[i].ovirt = ovirt ? *ovirt : 0;
            g_us[i].ovirt = 0;
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
    { int al = dt_alias_real(game_port); if (al) game_port = al; }
    struct sockaddr_in lo; memset(&lo, 0, sizeof(lo));
    lo.sin_family = AF_INET; lo.sin_port = htons((unsigned short)game_port);
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    unsigned ovhost = ntohl(cli.sin_addr.s_addr);  /* host-order vnode */
#ifdef LINUX_BUILD
    dt_reals();
    DLOCK();
    struct dt_usess *u = dt_usess_find(game_port, &ovhost, &cli, 1);
    int rs = u ? u->real : -1;
    if (u) { u->last = dt_now_ms();
             if (iplen >= 4) memcpy(&u->ovirt, ipb, 4); }  /* host-order vnode */
    DUNLOCK();
    if (!u || rs < 0) return 0;
    if (r_sendto(rs, raw, rl, 0, (struct sockaddr *)&lo, sizeof(lo)) > 0) {
        struct sockaddr_in sn; socklen_t sl = sizeof(sn);
        int lp = 0;
        if (getsockname(rs, (struct sockaddr *)&sn, &sl) == 0) lp = ntohs(sn.sin_port);
        DLOCK();
        if (lp && u->lport == 0) u->lport = lp;   /* injection source port */
        if (u && iplen >= 4) { unsigned ov; memcpy(&ov, ipb, 4);
                               u->ovirt = ntohl(ov); } /* accept door peer */
        DUNLOCK();
    }
    return 1;
#else
    DLOCK();
    struct dt_usess *u = dt_usess_find(game_port, &ovhost, &cli, 1);
    SOCKET rs = u ? u->real : INVALID_SOCKET;
    if (u) u->last = dt_now_ms();
    DUNLOCK();
    if (!u || rs == INVALID_SOCKET) return 0;
    if (sendto(rs, (const char *)raw, (int)rl, 0, (struct sockaddr *)&lo,
               sizeof(lo)) > 0) {
        struct sockaddr_in sn; int sl = (int)sizeof(sn);
        int lp = 0;
        if (getsockname(rs, (struct sockaddr *)&sn, &sl) == 0) lp = ntohs(sn.sin_port);
        DLOCK();
        if (lp && u->lport == 0) u->lport = lp;   /* injection source port */
        if (u && iplen >= 4) { unsigned ov; memcpy(&ov, ipb, 4);
                               u->ovirt = ntohl(ov); } /* accept door peer */
        DUNLOCK();
    }
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
    if (!s) return NULL;   /* gsock 0 = slot owned by a finished pump */
    for (int i = 0; i < DT_MAXSTREAM; i++)
        if (g_st[i].used && g_st[i].gsock == s) return &g_st[i];
    return NULL;
}
static struct dt_stream *dt_stream_by_sock_peeked(struct sockaddr_in dst) {
    for (int i = 0; i < DT_MAXSTREAM; i++)
        if (g_st[i].used && g_st[i].gsock &&
            g_st[i].orig.sin_addr.s_addr == dst.sin_addr.s_addr &&
            g_st[i].orig.sin_port == dst.sin_port)
            return &g_st[i];
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
            if (g_st[i].dead || g_st[i].state == ST_DEAD) {
                *dead = 1;
                /* a socket that received RST/error is readable AND
                 * writable in the kernel: the verdict must be reapable
                 * through select/poll by apps that never call recv */
                *data = 1; *writable = 1;
            }
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
/* queued bytes; caller holds DLOCK (Windows readers only) */
__attribute__((unused))
static size_t dt_inq_count_locked(struct dt_stream *st) {
    return st ? st->total : 0;
}
__attribute__((unused))   /* Windows wait hooks only */
static int dt_stream_by_sock_peek(long long gsock) {
    DLOCK();
    int has = dt_stream_by_sock(gsock) != NULL;
    DUNLOCK();
    return has;
}
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
static int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *) = 0;
static int (*real_getsockopt)(int, int, int, void *, socklen_t *) = 0;
static ssize_t (*r_send)(int, const void *, size_t, int) = 0;
static ssize_t (*r_recv)(int, void *, size_t, int) = 0;
static ssize_t (*r_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = 0;
static int (*r_close)(int) = 0;
static void dt_reals(void) {
    if (!r_connect) r_connect = dlsym(RTLD_NEXT, "connect");
    if (!real_select) real_select = dlsym(RTLD_NEXT, "select");
    if (!real_getsockopt) real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    if (!r_send) r_send = dlsym(RTLD_NEXT, "send");
    if (!r_recv) r_recv = dlsym(RTLD_NEXT, "recv");
    if (!r_sendto) r_sendto = dlsym(RTLD_NEXT, "sendto");
    if (!r_close) r_close = dlsym(RTLD_NEXT, "close");
    if (!r_bind) r_bind = dlsym(RTLD_NEXT, "bind");
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

