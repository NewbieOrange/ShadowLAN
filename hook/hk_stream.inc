/* hk_stream.inc - per-stream TCP, control link, hook call-ins (shared)
 * Part of lan_hook.c; see the note there before editing. */
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
#define DT_RSTMARK 255u                /* st->fail: peer sent RST */
#define DT_ST_MAXIN  (1024 * 1024)    /* app-read backpressure cap */
#define DT_ST_MAXOUT (4 * 1024 * 1024)

/* Give the relay tunnels generous TCP capacity: large send/receive
 * buffers requested BEFORE connect so window scaling rides the SYN
 * negotiation, and Nagle off so small handshake frames stay prompt.
 * The app still sees plain TCP semantics end to end; this only raises
 * throughput on long-fat or high-hop paths. */
static void dt_sock_tune(DTSOCK s) {
    int v = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&v, sizeof(v));
    v = 4 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&v, sizeof(v));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&v, sizeof(v));
}
static DTSOCK dt_st_dial_relay(void) {
    struct sockaddr_in sa;
    if (dt_resolve(&sa) != 0) return DTSOCK_BAD;
    DTSOCK s;
#ifdef LINUX_BUILD
    dt_reals();
    s = (DTSOCK)socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return DTSOCK_BAD;
    dt_sock_tune(s);
    int fl = fcntl((int)s, F_GETFL, 0);
    fcntl((int)s, F_SETFL, fl | O_NONBLOCK);
    int r = r_connect(s, (struct sockaddr *)&sa, sizeof(sa));
    if (r != 0 && errno != EINPROGRESS) { r_close(s); return DTSOCK_BAD; }
    if (r == 0) return s;
    fd_set wf; FD_ZERO(&wf); FD_SET((int)s, &wf);
    /* kernel-style completion wait: writable, exception (RST -> the
     * caller's getsockopt still reports ECONNREFUSED), or budget. The
     * select HOOKS must not answer for this transport fd: poll the
     * socket directly. */
    long long t0 = dt_now_ms();
    int err = -1;
    for (;;) {
        fd_set wf, xf;
        FD_ZERO(&wf); FD_ZERO(&xf);
        FD_SET((int)s, &wf); FD_SET((int)s, &xf);
        struct timeval tv = { 0, 20000 };
        int sr = real_select ? real_select((int)s + 1, NULL, &wf, &xf, &tv) : -1;
        if (sr > 0 && (FD_ISSET((int)s, &wf) || FD_ISSET((int)s, &xf))) {
            socklen_t el = sizeof(err);
            real_getsockopt((int)s, SOL_SOCKET, SO_ERROR, &err, &el);
            break;
        }
        if (!g_tun_run) { err = ECANCELED; break; }
        if (dt_now_ms() - t0 > DT_ST_TIMEOUT_MS) { err = ETIMEDOUT; break; }
    }
    if (err) { r_close(s); return DTSOCK_BAD; }
    return s;
#else
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return DTSOCK_BAD;
    dt_sock_tune(s);
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
        if (k == 0 && got == 0) { errno = EPIPE; return -1; }
        { int e = errno;
          if (e != EAGAIN && e != EWOULDBLOCK) {
              char lb[96];
              snprintf(lb, sizeof(lb), "st recv hdr: err=%d (n=%ld)", e, (long)got);
              dlog(lb);
              return -1; } }
#else
        int k = recv(fd, (char *)hdr + got, (int)(4 - got), 0);
        if (k > 0) { got += (size_t)k; continue; }
        if (k == 0 && got == 0) { WSASetLastError(WSA_E_CANCELLED); return -1; }
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
        if (dt_now_ms() - t0 > tmo_ms) {
#ifdef LINUX_BUILD
            errno = EAGAIN;
#else
            WSASetLastError(WSAEWOULDBLOCK);
#endif
            return -1;
        }
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
/* Kernel close semantics: bytes the app queued for send are flushed on
 * process exit (the OS drains a socket before tearing it down). Our
 * stream out-queue lives in the target process, so an exit would drop
 * whatever the app wrote last - e.g. its goodbye frames - and the peer
 * would see a silence-timeout instead of a clean close. Drain, with a
 * bounded budget, then close so the peer receives EOF exactly like a
 * real socket shutdown. Called from the exit hooks below; all pump
 * threads are stopped first so the queues have a single owner. */
static void dt_flush_streams(void) {
    int i;
    long long t0 = dt_now_ms();
    dlog("exit drain");
    /* 1) control-queue frames (beacon/leave/UDP-over-TCP goodbyes):
     * only the control thread may write the control conn - wait for it
     * to flush what the app already handed us. */
    for (;;) {
        int pend;
        DLOCK(); pend = g_sqh != NULL; DUNLOCK();
        if (!pend || dt_now_ms() - t0 > 300) break;
        dt_msleep(15);
    }
    /* 2) per-stream out-queues. Takeover is cooperative: flushing stops
     * the pump from starting new sends, sending marks an in-flight one,
     * so every byte on the wire keeps its order - drain-then-close,
     * exactly what the kernel does with a socket buffer. */
    for (i = 0; i < DT_MAXSTREAM; i++) {
        struct dt_stream *st = &g_st[i];
        int claimable = 0;
        for (;;) {   /* a stream mid-handshake may still complete inside
                      * the budget: its queued bytes deserve the wire */
            DLOCK();
            claimable = st->used && st->fd_live && st->oh &&
                        (st->state == ST_OPEN ||
                         (st->state == ST_CONNECTING
                          && dt_now_ms() - t0 < 600));
            if (st->used && st->oh && st->state == ST_DEAD) { DUNLOCK(); break; }
            if (claimable) st->flushing = 1;
            DUNLOCK();
            if (claimable || dt_now_ms() - t0 > 900) break;
            dt_msleep(15);
        }
        if (!claimable) continue;
        for (;;) {
            const unsigned char *p = NULL; size_t n = 0; size_t off0 = 0;
            DTSOCK fd;
            DLOCK();
            while (st->sending && dt_now_ms() - t0 < 900) { DUNLOCK(); dt_msleep(10); DLOCK(); }
            fd = st->fd;
            if (st->used && !st->sending && st->oh) {
                p = st->oh->p + st->oh->off; n = st->oh->n - st->oh->off;
                off0 = st->oh->off;
                if (n) st->sending = 1;
            }
            DUNLOCK();
            if (!p || !n) break;
            int ok = dt_st_send_all_tmo(fd, p, n, 150) == 0;
            DLOCK();
            st->sending = 0;
            if (st->used && ok && n) {
                struct dt_chunk *c = st->oh;
                if (c) {
                    c->off = c->n;   /* sent whole (or gave up mid: keep
                                      * ordering by dropping the rest -
                                      * the socket is dying anyway) */
                    st->oh = c->next;
                    if (!st->oh) st->ot = NULL;
                    st->ototal -= (c->n - off0);
                }
            }
            DUNLOCK();
            if (!ok || dt_now_ms() - t0 > 900) break;
        }
        DLOCK();
        if (st->used) st->flushing = 0;
        DUNLOCK();
    }
    /* fds stay open: process teardown FINs them after the bytes above */
}

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
    {   /* wake channel: app enqueues and closes poke this pump's select */
        DTSOCK wr, ww;
        dt_wake_pair(&wr, &ww);
        DLOCK();
        if (st->used && st->sid == sid) { st->wake_r = wr; st->wake_w = ww; }
        else {
#ifdef LINUX_BUILD
            if (wr != DTSOCK_BAD) { close((int)wr); close((int)ww); }
#else
            if (wr != INVALID_SOCKET) { closesocket(wr); closesocket(ww); }
#endif
        }
        DUNLOCK();
    }
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
        if (st->used && st->sid == sid) { st->fd = fd; st->fd_live = 1; }
        DUNLOCK();
        unsigned char type = 0, rp[16]; size_t rn = 0;
        /* Verdict wait mirrors the kernel: the app MAY close() us while
         * the handshake runs (the bridge abandons pending dials after ~3 s).
         * dt_on_close detaches the app identity but keeps the slot; we
         * keep waiting, record the verdict, and hand it to whatever
         * stream the app opened for the SAME destination (the bridge retries
         * with a fresh socket immediately - a real stack answers that
         * retry from the listener's state, not from scratch). */
        int r, sys_e = 0;
        for (;;) {                           /* pending -1 (EAGAIN): the
                                              * handshake budget spans
                                              * claim+bridge; retry */
            r = dt_st_recv_frame(fd, &type, rp, sizeof(rp), &rn,
                                 DT_ST_TIMEOUT_MS);
            sys_e = errno;
            if (r == -1 && (sys_e == EAGAIN || sys_e == EWOULDBLOCK))
                continue;
            { char lb[96]; snprintf(lb, sizeof(lb),
                "st verdict r=%d errno=%d t=%lld", r, sys_e,
                (long long)(dt_now_ms())); dlog(lb); }
            break;                           /* 0 verdict | -1 death */
        }
        if (r == -1) {                       /* transport died pre-verdict
                                              * (EOF or budget exhausted):
                                              * kernel says ECONNREFUSED */
            DLOCK();
            if (st->used && st->sid == sid) {
                st->state = ST_DEAD; st->fail = STF_NO_ROUTE;
                if (st->gsock) dt_sig_locked(st->gsock);
            }
            DUNLOCK();
            dt_st_close_fd(fd);
            return 0;
        }
        DLOCK();
        int detached = st->used && st->sid == sid && st->gsock == 0;
        int gone = !st->used || st->sid != sid;
        if (detached) {
            /* the app closed this dial (the bridge abandons pending connects);
             * hand a refusal to a retry for the SAME destination - a
             * real stack answers the retry from listener state, and the
             * only honest verdict for a stream nobody completed is the
             * one the app's select() would reap - then free the slot. */
            unsigned vfail = STF_NO_ROUTE;
            if (r == 0 && type == DT_STOK && rn >= 4 && dt_get32(rp) == sid)
                vfail = 0;                  /* we DID connect: orphaned */
            else if (r == 0 && type == DT_STFAIL && rn >= 5 &&
                     dt_get32(rp) == sid)
                vfail = rp[4];
            if (vfail) {
                struct dt_stream *cur = dt_stream_by_sock_peeked(st->orig);
                if (cur && cur->state == ST_CONNECTING) {
                    cur->state = ST_DEAD; cur->fail = vfail;
                    dt_sig_locked(cur->gsock);
                }
            }
            st->used = 0; st->state = ST_DEAD; st->fd = DTSOCK_BAD;
            struct dt_chunk *c = st->h;
            while (c) { struct dt_chunk *nx = c->next; free(c->p); free(c); c = nx; }
            c = st->oh;
            while (c) { struct dt_chunk *nx = c->next; free(c->p); free(c); c = nx; }
            st->h = st->t = st->oh = st->ot = NULL;
            st->total = st->ototal = 0;
            DUNLOCK();
            dt_st_close_fd(fd);
            return 0;
        }
        if (!gone) {
            if (r == 0 && type == DT_STOK && rn >= 4 && dt_get32(rp) == sid) {
                st->state = ST_OPEN; st->ever_open = 1;
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
        int has_out = mine && st->ototal > 0 && !st->flushing;
        int pause = !mine || st->in_paused;
        int finr = mine && st->peer_fin;
        DTSOCK wake_r = mine ? st->wake_r : DTSOCK_BAD;
        int dead = !mine || st->dead;
        int shut_now = 0;
        if (st->used && st->sid == sid && st->wr_shut && !st->shut_done
                && st->ototal == 0) { st->shut_done = 1; shut_now = 1; }
        DUNLOCK();
        if (shut_now) {           /* FIN toward the peer once flushed */
            unsigned char sb[4]; dt_put32(sb, sid);
            dt_tcp_queue(DT_STSHUT, sb, 4);
        }
        if (dead) {
            /* close(): pending reads are discarded by the kernel but
             * queued sends are flushed and FIN'd - do the same before
             * retiring (bounded), then let the tail free the slot. */
            for (;;) {
                const unsigned char *p = NULL; size_t n = 0; DTSOCK fd2;
                DLOCK();
                if (st->used && st->sid == sid && st->oh && st->fd_live) {
                    p = st->oh->p + st->oh->off;
                    n = st->oh->n - st->oh->off;
                    fd2 = st->fd;
                }
                DUNLOCK();
                if (!p || !n) break;
                if (dt_st_send_all_tmo(fd2, p, n, 150)) break;
                DLOCK();
                if (st->used && st->sid == sid && st->oh) {
                    struct dt_chunk *c = st->oh;
                    st->oh = c->next;
                    if (!st->oh) st->ot = NULL;
                    st->ototal -= (c->n - c->off);
                }
                DUNLOCK();
            }
            break;
        }
        fd_set rf, wf;
        FD_ZERO(&rf); FD_ZERO(&wf);
        if (!pause && !finr)
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
        int sr;
#ifdef LINUX_BUILD
        { int mx = (int)fd;
          if (wake_r != DTSOCK_BAD) { FD_SET((int)wake_r, &rf);
                if ((int)wake_r > mx) mx = (int)wake_r; }
          struct timeval tv = {0, 100000};
          sr = select(mx + 1, &rf, has_out ? &wf : NULL, NULL, &tv); }
#else
        if (wake_r != DTSOCK_BAD) FD_SET(wake_r, &rf);
        struct timeval tv = { 0, 100000 };
        sr = select(0, &rf, has_out ? &wf : NULL, NULL, &tv);
#endif
        if (!g_tun_run) break;
        if (sr < 0) break;
#ifdef LINUX_BUILD
        if (wake_r != DTSOCK_BAD && FD_ISSET((int)wake_r, &rf))
#else
        if (wake_r != DTSOCK_BAD && FD_ISSET(wake_r, &rf))
#endif
            dt_wake_drain(wake_r);
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
                if (st->used && st->sid == sid && st->oh && !st->flushing) {
                    sp = st->oh->p + st->oh->off; sn = st->oh->n - st->oh->off;
                    if (sn) st->sending = 1;
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
                st->sending = 0;
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
                    st->state = ST_DEAD;
                    st->fail = DT_RSTMARK;   /* hard error: resets surface */
                    dt_sig_locked(gsock);
                }
                DUNLOCK();
                break;
            }
            if (n == 0) {
                /* peer FIN (half-close): our reads EOF after the queue
                 * drains, but writes stay alive until the app closes -
                 * do NOT kill the whole stream here */
                DLOCK();
                if (st->used && st->sid == sid) {
                    st->peer_fin = 1;
                    /* edge wake, not level: EOF must not busy-poll the
                     * merged select (a still-open socket would spin);
                     * recv/poll read the flag when they look at state */
                    if (st->h == NULL) dt_sig_locked(gsock);
                }
                DUNLOCK();
                { char lb[96]; snprintf(lb, sizeof(lb),
                    "stream fin pid=%u sid=%u", (unsigned)current_pid(), sid);
                  dlog(lb); }
                continue;
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
    st->thread_done = 1;
    if (st->used && st->sid == sid) {
        int app_closed = st->dead || st->wr_shut;
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
static void dt_on_streq(unsigned sid, int gport, unsigned ovirt) {
    if (!dt_owns_listen(gport)) {
        /* this process has no listener on the game port: leave the
         * stream to the sibling that does (or to timeout if none) */
        char lb[128];
        snprintf(lb, sizeof(lb), "hosted req no-listener pid=%u sid=%u port=%d",
                 (unsigned)current_pid(), sid, gport);
        dlog(lb);
        return;
    }
    DLOCK();
    struct dt_hosted *h = NULL;
    for (int i = 0; i < DT_MAXHOST; i++)
        if (!g_hs[i].used) {
            h = &g_hs[i];
            h->used = 1; h->sid = sid; h->real = DTSOCK_BAD; h->fd = DTSOCK_BAD;
            h->live = 0; h->dead = 0; h->last = dt_now_ms();
            h->ovirt = ovirt; h->lport = 0;
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
    /* raw pipe, two INDEPENDENT directions: each side gets its own hold
     * slot and its own writable watch; a stalled reader on one side
     * closes only that direction's window (we stop reading that fd) and
     * never touches the other - the same full-duplex semantics a kernel
     * gives. Both sockets are nonblocking: the pump must never park in
     * a syscall, or the idle direction would block with it. */
    unsigned char obuf[65536], ibuf[65536];
    size_t op_n = 0, op_o = 0;   /* game -> relay hold (read from real) */
    size_t ip_n = 0, ip_o = 0;   /* relay -> game hold (read from fd)   */
    int fin_real = 0, fin_fd = 0, shut_sent = 0, eof_sent = 0;
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
        if (fin_fd && fin_real) break;     /* both directions finished */
        if (!shut_sent && fin_real && op_n == op_o) {
            shut_sent = 1;                 /* game FIN'd: tell the relay */
            unsigned char sb[4]; dt_put32(sb, sid);
            dt_tcp_queue(DT_STSHUT, sb, 4);
        }
        if (fin_fd && !eof_sent && ip_n == ip_o) {
            eof_sent = 1;                  /* peer FIN'd: FIN the app's
                                            * socket once data is drained */
#ifdef LINUX_BUILD
            shutdown(real, SHUT_WR);
#else
            shutdown(real, SD_SEND);
#endif
        }
        fd_set rf, wf;
        FD_ZERO(&rf); FD_ZERO(&wf);
#ifdef LINUX_BUILD
        int opend = op_n > op_o, ipend = ip_n > ip_o;
        if (!ipend && !fin_fd) FD_SET((int)fd, &rf);   /* hold slot full: close the
                                             * window upstream, kernel-style */
        if (!opend && !fin_real) FD_SET((int)real, &rf);  /* gate: drain
            before more game reads; fin_real = game already half-closed */
        if (opend) FD_SET((int)fd, &wf);      /* gate: keep reading relay meanwhile */
        if (ipend) FD_SET((int)real, &wf);
        struct timeval tv = { 0, 25000 };
        int mx = (int)fd > (int)real ? (int)fd : (int)real;
        int sr = select(mx + 1, &rf, (opend || ipend) ? &wf : NULL, NULL, &tv);
        if (sr <= 0) continue;
        if (opend && FD_ISSET((int)fd, &wf)) {
            errno = 0;
            ssize_t k = r_send(fd, obuf + op_o, op_n - op_o, 0);
            if (k > 0) { op_o += (size_t)k; if (op_o >= op_n) op_n = op_o = 0; }
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
        }
        if (ipend && FD_ISSET((int)real, &wf)) {
            errno = 0;
            ssize_t k = r_send(real, ibuf + ip_o, ip_n - ip_o, 0);
            if (k > 0) { ip_o += (size_t)k; if (ip_o >= ip_n) ip_n = ip_o = 0; }
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
        }
        if (!opend && FD_ISSET((int)real, &rf)) {
            errno = 0;
            ssize_t n = r_recv(real, (char *)obuf, (int)sizeof(obuf), 0);
            if (n == 0) {   /* game shut down writes: half-close ours */
                fin_real = 1;
                continue;
            }
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                char lb[96];
                snprintf(lb, sizeof(lb), "hosted pipe: game n=%zd err=%d", n, errno);
                dlog(lb); break;
            }
            out0 += (size_t)n;
            { char lb[112];
              snprintf(lb, sizeof(lb), "hs out sid=%u n=%zd tot=%llu",
                       sid, n, (unsigned long long)out0); dlog(lb); }
            op_n = (size_t)n; op_o = 0;
        }
        if (!ipend && FD_ISSET((int)fd, &rf)) {
            errno = 0;
            ssize_t n = r_recv(fd, (char *)ibuf, (int)sizeof(ibuf), 0);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                char lb[96];
                snprintf(lb, sizeof(lb), "hosted pipe: relay recv err=%d", errno);
                dlog(lb); break;
            }
            if (n == 0) { fin_fd = 1; continue; }
            in0 += (size_t)n;
            { char lb[112];
              snprintf(lb, sizeof(lb), "hs in sid=%u n=%zd tot=%llu",
                       sid, n, (unsigned long long)in0); dlog(lb); }
            ip_n = (size_t)n; ip_o = 0;
        }
#else
        int opend = op_n > op_o, ipend = ip_n > ip_o;
        if (!ipend && !fin_fd) FD_SET(fd, &rf);
        if (!opend && !fin_real) FD_SET(real, &rf);
        if (opend) FD_SET(fd, &wf);
        if (ipend) FD_SET(real, &wf);
        struct timeval tv = { 0, 25000 };
        int sr = select(0, &rf, (opend || ipend) ? &wf : NULL, NULL, &tv);
        if (sr <= 0) continue;
        if (opend && FD_ISSET(fd, &wf)) {
            int k = send(fd, (const char *)obuf + op_o, (int)(op_n - op_o), 0);
            if (k > 0) { op_o += (size_t)k; if (op_o >= op_n) op_n = op_o = 0; }
            else if (WSAGetLastError() != WSAEWOULDBLOCK) break;
        }
        if (ipend && FD_ISSET(real, &wf)) {
            int k = send(real, (const char *)ibuf + ip_o, (int)(ip_n - ip_o), 0);
            if (k > 0) { ip_o += (size_t)k; if (ip_o >= ip_n) ip_n = ip_o = 0; }
            else if (WSAGetLastError() != WSAEWOULDBLOCK) break;
        }
        if (!opend && FD_ISSET(real, &rf)) {
            int n = recv(real, (char *)obuf, (int)sizeof(obuf), 0);
            if (n == 0) { fin_real = 1; continue; }
            if (n < 0) {
                char lb[96];
                snprintf(lb, sizeof(lb), "hosted pipe: game n=%d err=%d",
                         n, WSAGetLastError());
                dlog(lb); break;
            }
            out0 += (size_t)n;
            { char lb[112];
              snprintf(lb, sizeof(lb), "hs out sid=%u n=%d tot=%llu",
                       sid, n, (unsigned long long)out0); dlog(lb); }
            op_n = (size_t)n; op_o = 0;
        }
        if (!ipend && FD_ISSET(fd, &rf)) {
            int n = recv(fd, (char *)ibuf, (int)sizeof(ibuf), 0);
            if (n < 0) {
                if (WSAGetLastError() == WSAEWOULDBLOCK) continue;
                break;
            }
            if (n == 0) { fin_fd = 1; continue; }
            in0 += (size_t)n;
            { char lb[112];
              snprintf(lb, sizeof(lb), "hs in sid=%u n=%d tot=%llu",
                       sid, n, (unsigned long long)in0); dlog(lb); }
            ip_n = (size_t)n; ip_o = 0;
        }
#endif
    }
    /* final drain: kernel semantics - data already read from one side
     * must reach the other before either direction dies */
    {
        long long t0 = dt_now_ms();
        while ((ip_n > ip_o || op_n > op_o) && dt_now_ms() - t0 < 500) {
            if (ip_n > ip_o) {
#ifdef LINUX_BUILD
                ssize_t k = r_send(real, ibuf + ip_o, ip_n - ip_o, 0);
                if (k > 0) ip_o += (size_t)k;
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) ip_n = ip_o = 0;
#else
                int k = send(real, (const char *)ibuf + ip_o, (int)(ip_n - ip_o), 0);
                if (k > 0) ip_o += (size_t)k;
                else if (WSAGetLastError() != WSAEWOULDBLOCK) ip_n = ip_o = 0;
#endif
            }
            if (op_n > op_o) {
#ifdef LINUX_BUILD
                ssize_t k = r_send(fd, obuf + op_o, op_n - op_o, 0);
                if (k > 0) op_o += (size_t)k;
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) op_n = op_o = 0;
#else
                int k = send(fd, (const char *)obuf + op_o, (int)(op_n - op_o), 0);
                if (k > 0) op_o += (size_t)k;
                else if (WSAGetLastError() != WSAEWOULDBLOCK) op_n = op_o = 0;
#endif
            }
            dt_msleep(2);
        }
    }
    { char lb[190]; int hx_d;
      DLOCK();
      struct dt_hosted *hx = dt_hs_by_sid(sid);
      hx_d = hx ? hx->dead : -1;
      DUNLOCK();
      snprintf(lb, sizeof(lb), "hosted eof pid=%u sid=%u in=%llu out=%llu dead=%d tun=%d",
               (unsigned)current_pid(), sid,
               (unsigned long long)in0, (unsigned long long)out0,
               hx_d, (int)g_tun_run);
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
        dt_sock_tune(s);
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
                int r;
                /* event wait: inbound frames OR local enqueues; the
                 * slice is a backstop for timers only */
#ifdef LINUX_BUILD
                { int mx = (int)s;
                  FD_SET((int)s, &rf);
                  if (g_wake_r != DTSOCK_BAD) { FD_SET((int)g_wake_r, &rf);
                        if ((int)g_wake_r > mx) mx = (int)g_wake_r; }
                  struct timeval tv = {0, 100000};
                  r = select(mx + 1, &rf, NULL, NULL, &tv); }
#else
                FD_SET(s, &rf);
                if (g_wake_r != DTSOCK_BAD) FD_SET(g_wake_r, &rf);
                struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 100000;
                r = select(0, &rf, NULL, NULL, &tv);
#endif
                if (!g_tun_run) break;
                if (r < 0) goto redial;
                if (r == 0) continue;
                {
                    int ctl =
#ifdef LINUX_BUILD
                        FD_ISSET((int)s, &rf);
#else
                        FD_ISSET(s, &rf);
#endif
#ifdef LINUX_BUILD
                    if (g_wake_r != DTSOCK_BAD && FD_ISSET((int)g_wake_r, &rf))
#else
                    if (g_wake_r != DTSOCK_BAD && FD_ISSET(g_wake_r, &rf))
#endif
                        dt_wake_drain(g_wake_r);
                    /* wake-only wakeup: no frame pending, do NOT feed the
                     * frame reader with an empty socket (EAGAIN = redial) */
                    if (!ctl) continue;
                }
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
                unsigned ovirt = (ml >= 11) ? dt_get32(pl + 7) : 0;
                dt_on_streq(sid, gport, ovirt);
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

#ifdef LINUX_BUILD
static void dt_atexit_flush(void) { dt_flush_streams(); }
/* intercept even hard exits: the kernel flushes socket buffers on
 * process teardown for the real stack, so both exit doors must drain */
static void dt_exit_guard(void) {
    static int done = 0;
    if (done) return;
    done = 1;
    dt_atexit_flush();
}
void exit(int code) {
    static void (*real)(int) = 0;
    if (!real) real = (void (*)(int))dlsym(RTLD_NEXT, "exit");
    dt_exit_guard();
    if (real) real(code);
    _Exit(code);
}
void _exit(int code) {
    static void (*real)(int) = 0;
    if (!real) real = (void (*)(int))dlsym(RTLD_NEXT, "_exit");
    dt_exit_guard();
    if (real) real(code);
    for (;;) ;
}
#endif
static void dt_start(void) {
    if (g_tun_started || !g_direct) return;
    g_tun_started = 1; g_tun_run = 1;
    dt_wake_pair(&g_wake_r, &g_wake_w);
#ifdef LINUX_BUILD
    atexit(dt_atexit_flush);  /* kernel-like exit drain of queued sends */
#endif
    g_init_t0 = dt_now_ms(); /* watchdog baseline: threads start below */
    g_fakeip = inet_addr("192.168.7.1");
    if (!g_node) {
        /* One identity per process TREE: a child (launcher self-restart chain,
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
            slp_set_node(g_node);
        } else {
            /* stable-ish random node id (loopback tests fork rarely collide) */
#ifdef LINUX_BUILD
            dt_rand_seed();
            dt_rand_mix((unsigned)dt_now_ms());
#else
            dt_rand_seed();
            dt_rand_mix((unsigned)GetTickCount());
#endif
            g_node = dt_rand() | 1;
            slp_set_node(g_node);
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
    dt_reals();
    {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            struct sockaddr_in b; memset(&b, 0, sizeof(b));
            b.sin_family = AF_INET; b.sin_addr.s_addr = htonl(INADDR_ANY); b.sin_port = 0;
            if (r_bind(s, (struct sockaddr *)&b, sizeof(b)) != 0) { close(s); }
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
