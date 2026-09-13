/* hk_wicmp.inc - ICMP echo API (IcmpSendEcho family) (Windows only)
 * Part of lan_hook.c; see the note there before editing. */
#ifndef LINUX_BUILD
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

#endif
