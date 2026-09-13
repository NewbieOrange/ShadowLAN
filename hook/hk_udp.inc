/* hk_udp.inc - UDP tunnel engine + ICMP over tunnel (shared)
 * Part of lan_hook.c; see the note there before editing. */
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
/* The hosted bridge injects from an anonymous 127.0.0.1 socket; the app
 * must NEVER see that - its peer state (the bridge's udp_ip_port) keys on the
 * recvfrom source, and a loopback source there makes the game unicast
 * its lobby JOIN back to itself (silently looping, host never sees it).
 * Map the injection socket's source port back to the session's real
 * peer (virtual ip + presented mark port), like the direct path does. */
static void dt_hosted_unsource(struct sockaddr *sa, socklen_int_t *len) {
    if (!sa || !len || *len < (socklen_int_t)sizeof(struct sockaddr_in)) return;
    struct sockaddr_in *in = (struct sockaddr_in *)sa;
    if (in->sin_family != AF_INET ||
        in->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) return;
    int port = ntohs(in->sin_port), hit = 0;
    struct sockaddr_in cli;
    memset(&cli, 0, sizeof(cli));
    DLOCK();
    for (int i = 0; i < DT_MAXUSESS; i++)
        if (g_us[i].used && g_us[i].lport == port) {
            cli = g_us[i].cli; hit = 1; break;
        }
    DUNLOCK();
    if (hit) { in->sin_addr = cli.sin_addr; in->sin_port = cli.sin_port; }
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
         * announce sources into own_ip/peer state (the reference app does), so leaking
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
        st->flushing = 0; st->sending = 0;
        st->thread_done = 0; st->peer_fin = 0; st->wr_shut = 0; st->rd_shut = 0;
        st->shut_done = 0; st->ever_open = 0;
        st->wake_r = st->wake_w = DTSOCK_BAD;
        st->fd = DTSOCK_BAD;
        st->oh = st->ot = NULL; st->ototal = 0;
        st->an_rx = st->an_tx = 0; st->ab_rx = st->ab_tx = 0; st->a_log = 0;
    }
    DUNLOCK();
    if (st) *sid_out = sid;
    return st;
}
/* Outbound connect routing. Virtual peer IP -> addressed stream (dest
 * node); other LAN target -> implicit stream (relay fan-outs ARP-style
 * to every live link of every member; the listener claims). Each
 * becomes its own real TCP
 * connection to the relay. Returns 1 when consumed, 2 when the
 * socket already has a live stream (WSAEALREADY), else 0 (real stack). */
static int dt_is_dial_local(unsigned vnode) {
    /* true when the resolved dest NODE is this machine: the dial target
     * is our own lease, or a sibling process' vnode inside our own
     * process tree (one node, many links). Either way a LAN stack would
     * never put this on the wire - complete it through loopback instead
     * (vnode arrives here as the NODE id from dt_virt_node, so compare
     * against g_node, NOT the virtual-IP number). */
    int same = 0;
    DLOCK();
    same = (vnode != 0 && vnode == g_node);
    DUNLOCK();
    return same;
}
