/* hk_route.inc - connect routing / dial (shared)
 * Part of lan_hook.c; see the note there before editing. */

/* Connecting-side presentation for a NIC-style hairpin (own-vnode
 * dial completed through loopback). getpeername must keep speaking
 * the vnode:vport the app dialed, not 127.0.0.1:alias-real. */
#define DT_MAXHP 32
static struct { long long sock; struct sockaddr_in dest; } g_hp[DT_MAXHP];
static void dt_hairpin_remember(long long sock, const struct sockaddr_in *dest) {
    int i;
    DLOCK();
    for (i = 0; i < DT_MAXHP; i++)
        if (!g_hp[i].sock || g_hp[i].sock == sock) {
            g_hp[i].sock = sock; g_hp[i].dest = *dest; break;
        }
    DUNLOCK();
}
static void dt_hairpin_forget_locked(long long sock) {
    int i;
    for (i = 0; i < DT_MAXHP; i++)
        if (g_hp[i].sock == sock) { g_hp[i].sock = 0; break; }
}

static int dt_on_connect(long long gsock, const struct sockaddr_in *dst) {
#ifdef SL_CONNECT_TRACE
    { char lb[128]; unsigned long a = ntohl(dst->sin_addr.s_addr);
      snprintf(lb, sizeof(lb), "on_connect gsock=%lld -> %lu.%lu.%lu.%lu:%d type=%d",
               gsock, (a >> 24) & 255, (a >> 16) & 255, (a >> 8) & 255, a & 255,
               (int)ntohs(dst->sin_port), dt_sock_type(gsock));
      dlog(lb); }
#endif
    if (ipv4_is_local(dst->sin_addr.s_addr)) return 0;   /* same-host: real stack */
    if (dt_sock_type(gsock) != SOCK_STREAM) return 0;
    if (dt_reject_wire4(dst)) return 3;  /* LAN_ONLY: no route to host */
    DLOCK();
    struct dt_stream *ex = dt_stream_by_sock(gsock);
    DUNLOCK();
    if (ex) return 2;
    unsigned vnode = dt_virt_node(dst->sin_addr.s_addr);
    if (vnode && dt_is_dial_local(vnode)) {
        /* dial of our OWN machine (own vnode, or a sibling process'
         * vnode in the same tree): on a LAN this never leaves the host -
         * complete it through the kernel loopback so the local listen
         * backlog serves it like a NIC hairpin. Going through the relay
         * instead turns it into a ghost self-connection the app then
         * heartbeats/timeouts against forever.
         *
         * The dest PORT must be THIS process's real listen port. When
         * another of our nodes owns the kernel vport (same-box two
         * vnodes), we are aliased underneath: connect(127.0.0.1:vport)
         * would hit the OTHER node's listener, which a real LAN / a
         * Tailscale interface can never do (each machine has its own
         * listen port). Field: the joiner's self-dial landed on the
         * host, the session library replaced the tunneled peer socket,
         * and JoinLobby died pending. dt_host_bridge already rewrites
         * this way. */
        struct sockaddr_in lo = *dst;
        int rr, vp = (int)ntohs(dst->sin_port);
        int real = dt_alias_real(vp, SOCK_STREAM);
        lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (real > 0) lo.sin_port = htons((unsigned short)real);
#ifdef LINUX_BUILD
        dt_reals();
        rr = r_connect((int)gsock, (struct sockaddr *)&lo, sizeof(lo));
        if (rr != 0 && errno != EINPROGRESS && errno != EALREADY
                && errno != EISCONN && errno != EWOULDBLOCK) return -1;
#else
        rr = connect((SOCKET)gsock, (struct sockaddr *)&lo, sizeof(lo));
        if (rr != 0 && WSAGetLastError() != WSAEWOULDBLOCK
                && WSAGetLastError() != WSAEALREADY
                && WSAGetLastError() != WSAEISCONN) return -1;
#endif
        dt_hairpin_remember(gsock, dst);
        { char lb[160];
          snprintf(lb, sizeof(lb),
                   "hairpin pid=%u sock=%lld -> 127.0.0.1:%d (vport=%d)",
                   (unsigned)current_pid(), gsock, real > 0 ? real : vp, vp);
          dlog(lb); }
        return 4;
    }
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
 * (caller: nonblocking app -> EWOULDBLOCK, blocking app -> wait+retry);
 * -3 write side shut down by the app (EPIPE). */
static int dt_stream_send(long long gsock, const unsigned char *buf, size_t len) {
    unsigned lsid = 0; size_t ln = 0, tot = 0; int dolog = 0;
    DLOCK();
    struct dt_stream *st = dt_stream_by_sock(gsock);
    if (!st) { DUNLOCK(); return 0; }
    if (st->wr_shut) { DUNLOCK(); return -3; }   /* EPIPE: we shut it down */
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
        if (ln >= 4096 || st->an_tx <= 3 || now - st->a_log > 1000) {
            st->a_log = now; dolog = 1; }
    }
    { DTSOCK ww = st->wake_w; DUNLOCK(); dt_wake_write(ww); }
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
    else if (r == -3) errno = EPIPE;
#else
    if (r == -1) WSASetLastError(WSAECONNRESET);
    else if (r == -2) WSASetLastError(WSAEWOULDBLOCK);
    else if (r == -3) WSASetLastError(WSAESHUTDOWN);
#endif
}
static int dt_stream_send_wait(long long s, const unsigned char *buf, size_t len) {
    int nonblock = dt_is_nonblock(s);
    for (;;) {
        int r = dt_stream_send(s, buf, len);
        if (r >= 0) return r;
        if (r == -3) { dt_stream_send_err(-3); return -3; }
        if (r == -1) {
#ifdef LINUX_BUILD
            /* kernel: send to a stream the peer reset => SIGPIPE + EPIPE
             * (default-ignored here only if the app blocked it already) */
            raise(SIGPIPE);
            errno = EPIPE; return -1;
#else
            dt_stream_send_err(-1); return -1;
#endif
        }
        if (r == -2) {
            if (nonblock) { dt_stream_send_err(-2); return -2; }
            dt_msleep(5);
            continue;
        }
    }
}
/* pop stream bytes; 1 got (>0), 0 empty, -1 dead.
 * Gather across in-queue chunks up to blen: a kernel TCP recv() of N
 * when N bytes are already queued returns N, not the first skb. FIONREAD
 * reports st->total; apps that ioctl then recv(exactly that) (the
 * reference lobby stack does, and never shrinks a short read) treat a
 * first-chunk-only pop as a torn length prefix and never parse again. */
static int dt_stream_pop(long long gsock, unsigned char *buf, size_t blen, size_t *outn) {
    int r = 0; size_t ln = 0; unsigned lsid = 0; int dolog = 0; size_t tot = 0;
    DLOCK();
    struct dt_stream *st = dt_stream_by_sock(gsock);
    if (st && st->h) {
        size_t got = 0;
        while (st->h && got < blen) {
            size_t n = st->h->n - st->h->off;
            if (n > blen - got) n = blen - got;
            memcpy(buf + got, st->h->p + st->h->off, n);
            st->h->off += n; st->total -= n; got += n;
            if (st->h->off >= st->h->n) {
                struct dt_chunk *o = st->h; st->h = o->next; if (!st->h) st->t = NULL;
                free(o->p); free(o);
            }
        }
        *outn = got; r = 1;
        if (st->in_paused && st->total < DT_ST_MAXIN / 2) {
            st->in_paused = 0;
            dt_wake_write(st->wake_w);   /* window reopened: read again now */
        }
        ln = got; lsid = st->sid; st->ab_rx += got; st->an_rx++; tot = st->ab_rx;
        long long now = dt_now_ms();
        if (ln >= 4096 || st->an_rx <= 3 || now - st->a_log > 1000) {
            st->a_log = now; dolog = 1; }
    } else if (st && (st->dead || st->state == ST_DEAD || st->peer_fin
                     || st->rd_shut)) r = -1;
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
    else {
        int i;
        for (i = 0; i < DT_MAXHP; i++)
            if (g_hp[i].sock == gsock) { *out = g_hp[i].dest; ok = 1; break; }
    }
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
    if (st) {
        /* Kernel: close() flushes queued sends then FINs; reads die now.
         * The pump owns the slot until its thread retires: hand it the
         * close (dead=1) and let it drain, FIN, and free. Only the
         * pre-thread window may free here. */
        st->dead = 1;
        if (st->fd_live) dt_wake_write(st->wake_w);  /* run flush now */
        if (st->state != ST_CONNECTING && st->fd_live) {
            /* pump owns the wire: release the app identity so a recycled
             * fd can bind a fresh stream; it flushes + frees by sid */
            st->gsock = 0;
        }
        if (st->state == ST_CONNECTING && !st->fd_live) {
            st->used = 0; st->fd = DTSOCK_BAD;
            struct dt_chunk *c = st->h;
            while (c) { struct dt_chunk *n = c->next; free(c->p); free(c); c = n; }
            c = st->oh;
            while (c) { struct dt_chunk *n = c->next; free(c->p); free(c); c = n; }
            st->h = st->t = st->oh = st->ot = NULL;
            st->total = st->ototal = 0;
        }
    }
    struct dt_udp *e = dt_udp_entry(gsock, 0);
    if (e) { e->closed = 1; e->used = 0;
        struct dt_dgram *d = e->h; while (d) { struct dt_dgram *n = d->next; free(d->p); free(d); d = n; } e->h = e->t = NULL; }
    for (int i = 0; i < DT_MAXSLOT; i++)
        if (g_sl[i].used && g_sl[i].gsock == gsock) g_sl[i].used = 0;
    dt_hairpin_forget_locked(gsock);
    dt_alias_release_all(gsock);
    dt_alias_drop(gsock);
    dt_sig_locked(gsock); /* wake event waiters with CLOSE (noop on Linux) */
#ifndef LINUX_BUILD
    for (int i = 0; i < DT_MAXEV; i++)
        if (g_evmap[i].used && g_evmap[i].sock == gsock) g_evmap[i].used = 0;
#endif
    DUNLOCK();
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

