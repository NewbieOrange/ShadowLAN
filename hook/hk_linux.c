#include "hk_mod.h"

/* hk_linux.c - LD_PRELOAD exports + dt_reals */
/* real libc symbols for tunnel use (avoid recursing into our hooks) */
int (*r_connect)(int, const struct sockaddr *, socklen_t) = 0;
int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *) = 0;
int (*real_getsockopt)(int, int, int, void *, socklen_t *) = 0;
ssize_t (*r_send)(int, const void *, size_t, int) = 0;
ssize_t (*r_recv)(int, void *, size_t, int) = 0;
ssize_t (*r_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = 0;
int (*r_close)(int) = 0;
int (*r_bind)(int, const struct sockaddr *, socklen_t) = 0;
int (*r_poll)(struct pollfd *, nfds_t, int) = 0;
ssize_t (*r_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *) = 0;
void dt_reals(void) {
    if (!r_poll) r_poll = dlsym(RTLD_NEXT, "poll");
    if (!r_recvfrom) r_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    if (!r_connect) r_connect = dlsym(RTLD_NEXT, "connect");
    if (!real_select) real_select = dlsym(RTLD_NEXT, "select");
    if (!real_getsockopt) real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    if (!r_send) r_send = dlsym(RTLD_NEXT, "send");
    if (!r_recv) r_recv = dlsym(RTLD_NEXT, "recv");
    if (!r_sendto) r_sendto = dlsym(RTLD_NEXT, "sendto");
    if (!r_close) r_close = dlsym(RTLD_NEXT, "close");
    if (!r_bind) r_bind = dlsym(RTLD_NEXT, "bind");
}

/* ================= Linux LD_PRELOAD test build ================= */
static void ensure_init(void) {
    static int done = 0;
    if (!done) {
        done = 1;
        dlog("ShadowLAN hook v" SHADOWLAN_VERSION " init");
        policy_init();
        dt_log_options();
        if (g_direct) dt_start();
        g_init_done = 1;
    }
}
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest,
               socklen_t addrlen) {
    static ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *,
                                  socklen_t) = 0;
    ensure_init();
    if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");
    if (g_direct && dest && dest->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        {
            int cr = dt_on_sendto((long long)sockfd, (const unsigned char *)buf, len,
                                  (const struct sockaddr_in *)dest);
            if (cr == -1) {
                errno = ENETUNREACH;
                return -1;
            }
            if (cr) return (ssize_t)len;
        }
    }
    return real_sendto(sockfd, buf, len, flags, dest, addrlen);
}
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src,
                 socklen_t *addrlen) {
    static ssize_t (*real_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *) = 0;
    ensure_init();
    if (!real_recvfrom) real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    if (g_direct) {
        int st = dt_sock_type((long long)sockfd);
        {
            char lb[128];
            snprintf(lb, sizeof(lb), "recvfrom fd=%d type=%d", sockfd, st);
            dlog(lb);
        }
        if (st == SOCK_DGRAM || dt_is_icmp_sock((long long)sockfd)) {
            DLOCK();
            dt_udp_entry((long long)sockfd, 1);
            DUNLOCK();
            int nb = dt_is_nonblock((long long)sockfd) || (flags & MSG_DONTWAIT);
            int tmo = dt_rcvtimeo_ms((long long)sockfd);
            long long t0 = 0;
            struct timeval tv0;
            gettimeofday(&tv0, NULL);
            t0 = (long long)tv0.tv_sec * 1000 + tv0.tv_usec / 1000;
            int slot = -1;
            for (;;) {
                struct sockaddr_in from;
                size_t on = 0;
                int pr = dt_udp_pop((long long)sockfd, (unsigned char *)buf, len, &from, &on);
                if (pr == 1) {
                    dt_wait_done(slot);
                    if (src && addrlen && *addrlen >= sizeof(from)) {
                        memcpy(src, &from, sizeof(from));
                        *addrlen = sizeof(from);
                    }
                    return (ssize_t)on;
                }
                if (pr == -1) {
                    dt_wait_done(slot);
                    errno = EBADF;
                    return -1;
                }
                /* a real wire datagram (LAN, loopback bridge)? never
                 * block in the kernel here: tunnel arrivals land in the
                 * hook queue, not on this fd */
                struct sockaddr_in rfrom;
                socklen_t rfl = sizeof(rfrom);
                struct sockaddr *sp = src ? src : (struct sockaddr *)&rfrom;
                socklen_t *lp = src ? addrlen : &rfl;
                dt_reals();
                ssize_t rn = r_recvfrom(sockfd, buf, len, flags | MSG_DONTWAIT, sp, lp);
                if (rn >= 0) {
                    if (g_lan_only && rn > 0 && lp && *lp >= sizeof(struct sockaddr_in) &&
                        !ipv4_is_loopback(((struct sockaddr_in *)sp)->sin_addr.s_addr)) {
                        dt_log_wire_drop(((struct sockaddr_in *)sp)->sin_addr.s_addr);
                        continue; /* LAN_ONLY: no wire world beyond the tunnel */
                    }
                    dt_wait_done(slot);
                    if (rn > 0 && g_direct) dt_hosted_unsource(sp, (socklen_int_t *)lp);
                    return rn;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    int e = errno;
                    dt_wait_done(slot);
                    errno = e;
                    return -1;
                }
                if (nb) {
                    dt_wait_done(slot);
                    errno = EAGAIN;
                    return -1;
                }
                if (slot < 0) { /* arm, then look again before sleeping */
                    slot = dt_wait_arm((long long[]){sockfd}, 1);
                    continue;
                }
                long long now = dt_now_ms();
                if (tmo >= 0 && now - t0 >= tmo) {
                    dt_wait_done(slot);
                    errno = EAGAIN;
                    return -1;
                }
                {
                    long w = DT_WAIT_BACKSTOP_MS;
                    if (tmo >= 0 && tmo - (now - t0) < w) w = (long)(tmo - (now - t0));
                    struct pollfd pw[2] = {{sockfd, POLLIN, 0}, {(int)dt_wait_fd(slot), POLLIN, 0}};
                    r_poll(pw, slot >= 0 ? 2 : 1, (int)w);
                }
                dt_wait_rearm(slot);
            }
        }
    }
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    struct sockaddr *sp = src ? src : (struct sockaddr *)&from;
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
        if (r == -1) {
            errno = ECONNRESET;
            return -1;
        }
        if (r == -2) {
            errno = EAGAIN;
            return -1;
        }
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
            if (r == -1) {
                int rst = 0;
                DLOCK();
                struct dt_stream *s3 = dt_stream_by_sock((long long)s);
                if (s3 && s3->fail == DT_RSTMARK) rst = 1;
                DUNLOCK();
                if (rst) {
                    errno = ECONNRESET;
                    return -1;
                }
                return 0; /* clean EOF */
            }
            errno = EAGAIN;
            return -1;
        }
    }
    return real_recv(s, buf, len, flags);
}
static int my_connect_hook(int s, const struct sockaddr *a, socklen_t l) {
    static int (*real_connect)(int, const struct sockaddr *, socklen_t) = 0;
    ensure_init();
    if (!real_connect) real_connect = dlsym(RTLD_NEXT, "connect");
    if (g_direct && a && a->sa_family == AF_INET && l >= sizeof(struct sockaddr_in)) {
        int r = dt_on_connect((long long)s, (const struct sockaddr_in *)a);
        if (r == 3) {
            errno = ENETUNREACH;
            return -1;
        }
        if (r == 4) return 0; /* machine-internal: looped back already */
        if (r == 1) {
            int nonblock = dt_is_nonblock((long long)s);
            if (nonblock) {
                errno = EINPROGRESS;
                return -1;
            }
            long long t0 = dt_now_ms();
            int slot = dt_wait_arm((long long[]){s}, 1); /* before the first look */
            for (;;) {
                DLOCK();
                struct dt_stream *st = dt_stream_by_sock((long long)s);
                int state = st ? st->state : 0;
                unsigned fail = st ? st->fail : 0;
                DUNLOCK();
                if (state == ST_OPEN) {
                    dt_wait_done(slot);
                    return 0;
                }
                if (state == ST_DEAD) {
                    dt_wait_done(slot);
                    errno = (fail == STF_JOIN_TIMEOUT) ? ETIMEDOUT : ECONNREFUSED;
                    return -1;
                }
                if (dt_now_ms() - t0 > (long long)DT_ST_TIMEOUT_MS + 500) {
                    dt_wait_done(slot);
                    errno = ETIMEDOUT;
                    return -1;
                }
                dt_wait_sleep(slot, DT_WAIT_BACKSTOP_MS);
                dt_wait_rearm(slot);
            }
        }
        if (r == 2) {
            errno = EALREADY;
            return -1;
        }
    }
    return real_connect(s, a, l);
}
int bind(int s, const struct sockaddr *a, socklen_t l) {
    static int (*real_bind)(int, const struct sockaddr *, socklen_t) = 0;
    static int (*real_gsn)(int, struct sockaddr *, socklen_t *) = 0;
    ensure_init();
    if (!real_bind)
        real_bind = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "bind");
    if (!real_gsn)
        real_gsn = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "getsockname");
    if (g_direct && a && a->sa_family == AF_INET && l >= (socklen_t)sizeof(struct sockaddr_in)) {
        struct sockaddr_in in = *(const struct sockaddr_in *)a;
        unsigned myv = 0;
        DLOCK();
        myv = g_myvirt;
        DUNLOCK();
        int bindv = (myv && in.sin_addr.s_addr == htonl(myv));
        int proto = dt_sock_type((long long)s);
        if (proto < 0) proto = SOCK_STREAM;
        int reuse = 0;
        {
            int ra = 0;
            socklen_t rl = sizeof(ra);
            if (getsockopt(s, SOL_SOCKET, SO_REUSEADDR, &ra, &rl) == 0) reuse = ra;
        }
        if (bindv) in.sin_addr.s_addr = htonl(INADDR_ANY);
        int want = ntohs(in.sin_port);
        int r;
        if (want != 0) {
            /* vnet (node-scoped) space first: a sibling process of THIS
             * machine may not take a port another of its processes
             * serves - kernel rule, enforced across the aliasing */
            int rv = slp_claim(want, proto, reuse, want);
            if (rv == -1) {
                errno = EADDRINUSE;
                return -1;
            }
            r = real_bind(s, (struct sockaddr *)&in, l);
            if (r != 0 && errno == EADDRINUSE) {
                /* the REAL port belongs to another NODE here: two LAN
                 * machines on one OS - alias beneath, vport stays ours */
                if (dt_bind_alias((long long)s, &in, proto == SOCK_DGRAM, real_bind) == 0) {
                    if (bindv) dt_alias_bindv((long long)s);
                    if (proto == SOCK_DGRAM) {
                        DLOCK();
                        dt_udp_entry((long long)s, 1);
                        DUNLOCK();
                    }
                    return 0;
                }
                slp_release(want, proto);
                errno = EADDRINUSE;
                return -1;
            }
            if (r == 0) {
                DLOCK();
                dt_alias_add((long long)s, want, want, proto);
                if (bindv && proto == SOCK_DGRAM) dt_udp_entry((long long)s, 1);
                DUNLOCK();
                if (bindv) dt_alias_bindv((long long)s);
            } else {
                slp_release(want, proto);
            }
            return r;
        }
        /* bind(0): with the NIC gone the virtual port is the machine's
         * port - pick one free in the node ledger (and, for LAN_ONLY=0,
         * acceptable to the real stack too). */
        if (g_lan_only || slp_used() > 0) {
            int i, base = 49152 + (int)(current_pid() % 4096);
            for (i = 0; i < 4096; i++) {
                int p0 = 49152 + ((base - 49152 + i) % 16383);
                if (slp_taken(p0)) continue;
                if (slp_claim(p0, proto, 1, 0) == -1) continue;
                struct sockaddr_in trya = in;
                trya.sin_port = htons((unsigned short)p0);
                r = real_bind(s, (struct sockaddr *)&trya, l);
                if (r == 0) {
                    DLOCK();
                    dt_alias_add((long long)s, p0, p0, proto);
                    if (proto == SOCK_DGRAM) {
                        struct dt_udp *e = dt_udp_entry((long long)s, 1);
                        if (e) e->vport = p0;
                    }
                    DUNLOCK();
                    if (bindv) dt_alias_bindv((long long)s);
                    return 0;
                }
                slp_release(p0, proto);
                if (errno != EADDRINUSE) break;
            }
        }
        in.sin_port = 0; /* allocator exhausted: plain OS pick */
        r = real_bind(s, (struct sockaddr *)&in, l);
        if (r == 0) {
            struct sockaddr_in got;
            socklen_t gl = sizeof(got);
            if (real_gsn(s, (struct sockaddr *)&got, &gl) == 0) {
                int p0 = ntohs(got.sin_port);
                slp_claim(p0, proto, reuse, p0);
                DLOCK();
                dt_alias_add((long long)s, p0, p0, proto);
                if (bindv && proto == SOCK_DGRAM) dt_udp_entry((long long)s, 1);
                DUNLOCK();
                if (bindv) dt_alias_bindv((long long)s);
            }
        }
        return r;
    }
    return real_bind(s, a, l);
}
int connect(int s, const struct sockaddr *a, socklen_t l) {
    return my_connect_hook(s, a, l);
}
/* present the machine's own view: aliased/virtual ports and the vnode
 * the app bound (a bound socket never leaks the ephemeral real number
 * or the wildcard identity it was shimmed to). */
int getsockname(int s, struct sockaddr *a, socklen_t *l) {
    static int (*real_gsn)(int, struct sockaddr *, socklen_t *) = 0;
    ensure_init();
    if (!real_gsn)
        real_gsn = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "getsockname");
    int r = real_gsn(s, a, l);
    if (r == 0 && g_direct && a && l && *l >= (socklen_t)sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sa = (struct sockaddr_in *)a;
        if (sa->sin_family == AF_INET) {
            {
                int bp3 = 0;
                struct sockaddr_in o3;
                if (dt_acc_get((long long)s, &o3, &bp3)) {
                    dt_acc_self_view((long long)s, sa); /* accepted: vnode + vport */
                    return r;
                }
            }
            int vp = dt_alias_vport((long long)s);
            if (vp > 0) {
                sa->sin_port = htons((unsigned short)vp);
                if (dt_alias_is_bindv((long long)s)) {
                    DLOCK();
                    unsigned myv = g_myvirt;
                    DUNLOCK();
                    if (myv && sa->sin_addr.s_addr == htonl(INADDR_ANY))
                        sa->sin_addr.s_addr = htonl(myv);
                }
            }
        }
    }
    return r;
}
int listen(int s, int backlog) {
    static int (*real_listen)(int, int) = 0;
    ensure_init();
    if (!real_listen) real_listen = dlsym(RTLD_NEXT, "listen");
    int r = real_listen(s, backlog);
    /* game serves a TCP port -> stamp the host claim on the relay */
    if (r == 0 && g_direct && dt_sock_type((long long)s) == SOCK_STREAM) {
        struct sockaddr_in a;
        socklen_t l = sizeof(a);
        if (getsockname(s, (struct sockaddr *)&a, &l) == 0 && a.sin_family == AF_INET) {
            int av = dt_alias_vport((long long)s); /* requested port wins */
            dt_record_listen(av > 0 ? av : ntohs(a.sin_port));
            dt_claim();
        }
    }
    return r;
}
static int (*real_getpeername_sym(void))(int, struct sockaddr *, socklen_t *);
/* kernel half-close for tunnel streams: SHUT_RD discards unread bytes,
 * SHUT_WR flushes queued sends then FINs the peer (the pump emits
 * DT_STSHUT once the out-queue drains); the other direction keeps
 * working until the peer or the app closes it. */
int shutdown(int s, int how) {
    static int (*real)(int, int) = 0;
    if (!real) real = (int (*)(int, int))dlsym(RTLD_NEXT, "shutdown");
    if (g_direct) {
        int hit = 0, sig = 0;
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock((long long)s);
        if (st) {
            hit = 1;
            if (how == SHUT_RD || how == SHUT_RDWR) {
                st->rd_shut = 1;
                struct dt_chunk *c = st->h;
                while (c) {
                    struct dt_chunk *n = c->next;
                    free(c->p);
                    free(c);
                    c = n;
                }
                st->h = st->t = NULL;
                st->total = 0;
                st->in_paused = 0;
                sig = 1;
            }
            if (how == SHUT_WR || how == SHUT_RDWR) st->wr_shut = 1;
            if (sig) dt_sig_locked((long long)s);
        }
        DUNLOCK();
        if (hit) return 0;
    }
    return real(s, how);
}
/* SO_ERROR on a tunnel stream mirrors connect() state: pending
 * EINPROGRESS, refused/timeout per the verdict, 0 once open - the
 * nonblocking connect idiom (select writable + getsockopt) must not
 * see the real socket's meaningless zero. */
int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen) {
    static int (*real)(int, int, int, void *, socklen_t *) = 0;
    if (!real) real = (int (*)(int, int, int, void *, socklen_t *))dlsym(RTLD_NEXT, "getsockopt");
    if (g_direct && level == SOL_SOCKET && optname == SO_ERROR && optval && optlen &&
        *optlen >= (socklen_t)sizeof(int)) {
        int err = -1;
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock((long long)s);
        if (st) {
            if (st->state == ST_CONNECTING)
                err = 0; /* kernel: SO_ERROR
                * only carries the COMPLETION error; a connect still in
                * flight reports zero (EINPROGRESS comes from connect) */
            else if (st->state == ST_DEAD && !st->ever_open)
                err = (st->fail == DT_RSTMARK)         ? ECONNRESET
                      : (st->fail == STF_JOIN_TIMEOUT) ? ETIMEDOUT
                                                       : ECONNREFUSED;
            else
                err = 0; /* open, or died
                                                          * after opening */
        }
        DUNLOCK();
        if (err >= 0) {
            memcpy(optval, &err, sizeof(err));
            *optlen = sizeof(err);
            return 0;
        }
    }
    return real(s, level, optname, optval, optlen);
}
int getpeername(int s, struct sockaddr *a, socklen_t *l) {
    static int (*real_gp)(int, struct sockaddr *, socklen_t *) = 0;
    ensure_init();
    if (!real_gp) real_gp = real_getpeername_sym();
    if (g_direct && a && l && *l >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in o;
        if (dt_getpeer((long long)s, &o)) {
            memcpy(a, &o, sizeof(o));
            *l = sizeof(o);
            return 0;
        }
        int bp = 0;
        if (dt_acc_get((long long)s, &o, &bp)) {
            struct sockaddr_in rp;
            socklen_t rl = sizeof(rp);
            int gpr = real_gp(s, (struct sockaddr *)&rp, &rl);
            if (gpr != 0) {
                memcpy(a, &o, sizeof(o));
                *l = sizeof(o);
                return 0;
            }
            if (rp.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
                if ((int)ntohs(rp.sin_port) == bp) {
                    memcpy(a, &o, sizeof(o));
                    *l = sizeof(o);
                    return 0;
                }
                dt_acc_forget((long long)s); /* fd recycled */
            }
        }
    }
    return real_gp(s, a, l);
}
/* the TRUE libc getpeername: dlsym(RTLD_NEXT) is unreliable here - our
 * exported getpeername may sit first in the lookup scope depending on
 * link order, so resolve via ELF introspection with a fallback. */
static int (*real_getpeername_sym(void))(int, struct sockaddr *, socklen_t *) {
    static int (*fp)(int, struct sockaddr *, socklen_t *);
    if (fp) return fp;
    fp = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "getpeername");
    if (!fp) {
        void *h = dlopen("libc.so.6", RTLD_NOLOAD | RTLD_LAZY);
        if (h) fp = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(h, "getpeername");
    }
    return fp;
}
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    static int (*real_accept)(int, struct sockaddr *, socklen_t *) = 0;
    ensure_init();
    if (!real_accept) real_accept = dlsym(RTLD_NEXT, "accept");
    int fd = real_accept(sockfd, addr, addrlen);
    /* LAN_ONLY first (on the REAL peer): drop wire LAN peers; loopback
     * (bridge) passes. Must precede the vnode rewrite below, which
     * would otherwise make our own bridge look like a wire peer. */
    if (g_direct && g_lan_only && fd >= 0 && addr && addrlen &&
        *addrlen >= sizeof(struct sockaddr_in) &&
        !ipv4_is_loopback(((struct sockaddr_in *)addr)->sin_addr.s_addr)) {
        unsigned long a = 0;
        char lb[112];
        memcpy(&a, &((struct sockaddr_in *)addr)->sin_addr.s_addr, 4);
        snprintf(lb, sizeof(lb), "lan-only: drop wire accept from %lu.%lu.%lu.%lu", a & 255,
                 (a >> 8) & 255, (a >> 16) & 255, (a >> 24) & 255);
        dlog(lb);
        close(fd);
        errno = EAGAIN;
        return -1;
    }
    if (g_direct && fd >= 0) {
        struct sockaddr_in rp;
        socklen_t rl = sizeof(rp);
        static int (*rgp)(int, struct sockaddr *, socklen_t *) = 0;
        if (!rgp) rgp = dlsym(RTLD_NEXT, "getpeername");
        /* ALWAYS take the REAL peer first (the out-param may hold it, but
         * getpeername is the single source of truth), then learn/spoof:
         * post_accept must not be fed the out-param as 'real' or the
         * second read of it (when already rewritten) misses loopback. */
        if (rgp && rgp(fd, (struct sockaddr *)&rp, &rl) == 0)
            dt_acc_post_accept(fd, addr, (socklen_int_t *)addrlen, &rp);
    }
    return fd;
}
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int) = 0;
    ensure_init();
    if (!real_accept4) real_accept4 = dlsym(RTLD_NEXT, "accept4");
    int fd = real_accept4(sockfd, addr, addrlen, flags);
    /* LAN_ONLY first (real peer), THEN the vnode rewrite - see accept() */
    if (g_direct && g_lan_only && fd >= 0 && addr && addrlen &&
        *addrlen >= sizeof(struct sockaddr_in) &&
        !ipv4_is_loopback(((struct sockaddr_in *)addr)->sin_addr.s_addr)) {
        unsigned long a = 0;
        char lb[112];
        memcpy(&a, &((struct sockaddr_in *)addr)->sin_addr.s_addr, 4);
        snprintf(lb, sizeof(lb), "lan-only: drop wire accept4 from %lu.%lu.%lu.%lu", a & 255,
                 (a >> 8) & 255, (a >> 16) & 255, (a >> 24) & 255);
        dlog(lb);
        close(fd);
        errno = EAGAIN;
        return -1;
    }
    if (g_direct && fd >= 0) {
        struct sockaddr_in rp;
        socklen_t rl = sizeof(rp);
        static int (*rgp)(int, struct sockaddr *, socklen_t *) = 0;
        if (!rgp) rgp = real_getpeername_sym();
        if (rgp && rgp(fd, (struct sockaddr *)&rp, &rl) == 0)
            dt_acc_post_accept(fd, addr, (socklen_int_t *)addrlen, &rp);
    }
    return fd;
}
int close(int fd) {
    dt_acc_forget((long long)fd);
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
        if (st) {
            *(int *)arg = v;
            return 0;
        }
    }
    return real_ioctl(fd, request, arg);
}
/* poll/select must report tunnel-queued data as readable, or apps with
 * timeouts (incl. every CPython socket with settimeout) sleep in poll
 * and never call recvfrom. Waits are event-driven: the real wait gets
 * a wake fd that every hook state change pokes (dt_sig_locked), so a
 * queued datagram/stream byte wakes the app at once. A tunneled
 * stream's own fd never joins the real wait: it is a never-connected
 * socket the kernel reports as hung up, which made every poll return
 * at once (a busy-spinning app thread). */
#include <poll.h>
#include <signal.h>
#include <sys/select.h>
/* kernel: a socket still in connect() never reports writable; the
 * merged scan adds the connect edge back exactly once at verdict */
static int dt_fd_connecting(long long fd) {
    int r = 0;
    DLOCK();
    struct dt_stream *st = dt_stream_by_sock(fd);
    if (st && st->state == ST_CONNECTING) r = 1;
    DUNLOCK();
    return r;
}
static int dt_poll_scan(struct pollfd *fds, nfds_t nfds) {
    int n = 0;
    for (nfds_t i = 0; i < nfds; i++) {
        if (fds[i].fd < 0) continue;
        if ((fds[i].events & POLLIN) && dt_fd_readable((long long)fds[i].fd))
            fds[i].revents |= POLLIN;
        if (fds[i].revents & (POLLOUT | POLLWRNORM) && dt_fd_connecting(fds[i].fd))
            fds[i].revents &= ~(POLLOUT | POLLWRNORM); /* not yet connected */
        if (fds[i].events & (POLLOUT | POLLWRNORM)) {
            int data, dead, wr, cn;
            dt_sock_state_full((long long)fds[i].fd, &data, &dead, &wr, &cn);
            if (wr || cn) fds[i].revents |= POLLOUT;
        }
        if (fds[i].revents) n++;
    }
    return n;
}
/* 2 = tunneled stream (hook-owned readiness only), 1 = tunnel-fed
 * datagram socket (real fd + hook queue), 0 = not ours */
static int dt_fd_kind(int fd) {
    if (fd < 0) return 0;
    if (dt_stream_by_sock_peek((long long)fd)) return 2;
    if (dt_is_udp_like((long long)fd)) {
        dt_udp_ensure((long long)fd); /* fan-out needs the entry */
        return 1;
    }
    return 0;
}
/* Shared poll/ppoll/select/pselect core. tmo_ms < 0 = infinite. */
static int dt_poll_core(struct pollfd *fds, nfds_t nfds, long tmo_ms, const sigset_t *mask) {
    static int (*real_ppoll)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *) =
        0;
    if (!real_ppoll) real_ppoll = dlsym(RTLD_NEXT, "ppoll");
    long long ks[8];
    int nk = 0, any = 0, streams = 0;
    for (nfds_t i = 0; i < nfds; i++) {
        int k = dt_fd_kind(fds[i].fd);
        if (!k) continue;
        if (k == 2) streams++;
        if (nk < 8) ks[nk++] = fds[i].fd;
        else any = 1;
    }
    if (!nk) { /* nothing of ours in the set: the plain kernel wait */
        struct timespec ts = {tmo_ms / 1000, (tmo_ms % 1000) * 1000000};
        return real_ppoll(fds, nfds, tmo_ms < 0 ? NULL : &ts, mask);
    }
    struct pollfd sb[33], *pf = nfds < 32 ? sb : (struct pollfd *)malloc((nfds + 1) * sizeof(*pf));
    if (!pf) {
        errno = ENOMEM;
        return -1;
    }
    int slot = dt_wait_arm(ks, any ? -1 : nk); /* before the first scan */
    long long t0 = dt_now_ms();
    int n, err = 0, polled = 0;
    for (;;) {
        for (nfds_t i = 0; i < nfds; i++) fds[i].revents = 0;
        n = dt_poll_scan(fds, nfds);
        if (n) break;
        long w = DT_WAIT_BACKSTOP_MS;
        if (tmo_ms >= 0) {
            long left = tmo_ms - (long)(dt_now_ms() - t0);
            if (left <= 0) {
                if (polled) break;
                left = 0; /* zero timeout still samples the real fds once */
            }
            if (left < w) w = left;
        }
        polled = 1;
        for (nfds_t i = 0; i < nfds; i++) {
            pf[i] = fds[i];
            if (streams && dt_stream_by_sock_peek((long long)fds[i].fd)) pf[i].fd = -1;
        }
        nfds_t m = nfds;
        if (slot >= 0) {
            pf[m].fd = (int)dt_wait_fd(slot);
            pf[m].events = POLLIN;
            pf[m].revents = 0;
            m++;
        }
        struct timespec ts = {w / 1000, (w % 1000) * 1000000};
        int r = real_ppoll(pf, m, &ts, mask);
        if (r < 0) {
            err = errno;
            n = -1;
            break;
        }
        for (nfds_t i = 0; i < nfds; i++) fds[i].revents = pf[i].fd < 0 ? 0 : pf[i].revents;
        n = dt_poll_scan(fds, nfds);
        if (n) break;
        dt_wait_rearm(slot);
    }
    dt_wait_done(slot);
    if (pf != sb) free(pf);
    if (n < 0) errno = err;
    return n < 0 ? -1 : n;
}
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    static int (*real_poll)(struct pollfd *, nfds_t, int) = 0;
    ensure_init();
    if (!real_poll) real_poll = dlsym(RTLD_NEXT, "poll");
    if (!g_direct) return real_poll(fds, nfds, timeout);
    return dt_poll_core(fds, nfds, timeout < 0 ? -1 : timeout, NULL);
}
int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo, const sigset_t *mask) {
    static int (*real_ppoll)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *) =
        0;
    ensure_init();
    if (!real_ppoll) real_ppoll = dlsym(RTLD_NEXT, "ppoll");
    if (!g_direct) return real_ppoll(fds, nfds, tmo, mask);
    long ms = tmo ? (long)(tmo->tv_sec * 1000 + (tmo->tv_nsec + 999999) / 1000000) : -1;
    return dt_poll_core(fds, nfds, ms, mask);
}
/* select on top of the poll core, with the kernel's own readiness
 * masks (fs/select.c POLLIN_SET / POLLOUT_SET / POLLEX_SET). */
static int dt_select_core(int nfds, fd_set *r, fd_set *w, fd_set *x, long ms,
                          const sigset_t *mask) {
    if (nfds < 0 || nfds > FD_SETSIZE) {
        errno = EINVAL;
        return -1;
    }
    int cnt = 0;
    for (int fd = 0; fd < nfds; fd++)
        if ((r && FD_ISSET(fd, r)) || (w && FD_ISSET(fd, w)) || (x && FD_ISSET(fd, x))) cnt++;
    struct pollfd sb[64], *pf = cnt <= 64 ? sb : (struct pollfd *)malloc(cnt * sizeof(*pf));
    if (!pf) {
        errno = ENOMEM;
        return -1;
    }
    int k = 0;
    for (int fd = 0; fd < nfds; fd++) {
        short ev = 0;
        if (r && FD_ISSET(fd, r)) ev |= POLLIN;
        if (w && FD_ISSET(fd, w)) ev |= POLLOUT;
        if (x && FD_ISSET(fd, x)) ev |= POLLPRI;
        if (!ev) continue;
        pf[k].fd = fd;
        pf[k].events = ev;
        pf[k].revents = 0;
        k++;
    }
    int rc = dt_poll_core(pf, (nfds_t)k, ms, mask);
    if (rc >= 0) {
        for (int i = 0; i < k; i++)
            if (pf[i].revents & POLLNVAL) {
                errno = EBADF;
                rc = -1;
                break;
            }
    }
    if (rc >= 0) {
        if (r) FD_ZERO(r);
        if (w) FD_ZERO(w);
        if (x) FD_ZERO(x);
        rc = 0;
        for (int i = 0; i < k; i++) {
            short re = pf[i].revents, ev = pf[i].events;
            if ((ev & POLLIN) && (re & (POLLIN | POLLRDNORM | POLLRDBAND | POLLHUP | POLLERR))) {
                FD_SET(pf[i].fd, r);
                rc++;
            }
            if ((ev & POLLOUT) && (re & (POLLOUT | POLLWRNORM | POLLWRBAND | POLLERR))) {
                FD_SET(pf[i].fd, w);
                rc++;
            }
            if ((ev & POLLPRI) && (re & POLLPRI)) {
                FD_SET(pf[i].fd, x);
                rc++;
            }
        }
    }
    if (pf != sb) free(pf);
    return rc;
}
int pselect(int nfds, fd_set *r, fd_set *w, fd_set *x, const struct timespec *tmo,
            const sigset_t *mask) {
    static int (*real_pselect)(int, fd_set *, fd_set *, fd_set *, const struct timespec *,
                               const sigset_t *) = 0;
    ensure_init();
    if (!real_pselect) real_pselect = dlsym(RTLD_NEXT, "pselect");
    if (!g_direct) return real_pselect(nfds, r, w, x, tmo, mask);
    long ms = tmo ? (long)(tmo->tv_sec * 1000 + (tmo->tv_nsec + 999999) / 1000000) : -1;
    return dt_select_core(nfds, r, w, x, ms, mask);
}
int select(int nfds, fd_set *r, fd_set *w, fd_set *x, struct timeval *tmo) {
    static int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *) = 0;
    ensure_init();
    if (!real_select) real_select = dlsym(RTLD_NEXT, "select");
    if (!g_direct) return real_select(nfds, r, w, x, tmo);
    long ms = tmo ? (long)(tmo->tv_sec * 1000 + (tmo->tv_usec + 999) / 1000) : -1;
    return dt_select_core(nfds, r, w, x, ms, NULL);
}
