#include "hk_mod.h"

/* hk_winsock.c - Windows socket IAT hooks */
/* ================= Windows DLL ================= */
PFN_sendto p_sendto = 0;
PFN_recvfrom p_recvfrom = 0;
PFN_accept p_accept = 0;
PFN_WSASendTo p_WSASendTo = 0;
PFN_WSARecvFrom p_WSARecvFrom = 0;
PFN_connect p_connect = 0;
PFN_WSAConnect p_WSAConnect = 0;
PFN_bind p_bind = 0;
PFN_getpeername p_getpeername = 0;
PFN_closesocket p_closesocket = 0;
PFN_getsockname p_getsockname = 0;
PFN_listen p_listen = 0;
PFN_send p_send = 0;
PFN_recv p_recv = 0;
PFN_WSASend p_WSASend = 0;
PFN_WSARecv p_WSARecv = 0;
PFN_ioctlsocket p_ioctlsocket = 0;
PFN_WSAEventSelect p_WSAEventSelect = 0;
PFN_WSAEnumNetworkEvents p_WSAEnumNetworkEvents = 0;
PFN_WSAWaitForMultipleEvents p_WSAWaitForMultipleEvents = 0;
PFN_WSACreateEvent p_WSACreateEvent = 0;
PFN_WSACloseEvent p_WSACloseEvent = 0;
HMODULE g_hself = 0;
PFN_GetProcAddress p_GetProcAddress = 0;
HMODULE hWS2 = 0, hKernel = 0;
PFN_ExitProcess p_ExitProcess = 0;
BOOL(WINAPI *p_TerminateProcess)(HANDLE, UINT) = 0;
void WINAPI hk_ExitProcess(UINT code) {
    dt_flush_streams();
    if (!p_ExitProcess)
        p_ExitProcess =
            (PFN_ExitProcess)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess");
    if (p_ExitProcess) p_ExitProcess(code);
}
BOOL WINAPI hk_TerminateProcess(HANDLE h, UINT code) {
    if (!p_TerminateProcess)
        p_TerminateProcess = (BOOL(WINAPI *)(HANDLE, UINT))GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "TerminateProcess");
    if (h == GetCurrentProcess()) dt_flush_streams(); /* self-close: drain */
    return p_TerminateProcess ? p_TerminateProcess(h, code) : FALSE;
}
BOOL WINAPI hk_CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
                              DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
BOOL WINAPI hk_CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
                              DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

void dbg(const char *m) {
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
            fputs(ts, lf);
            fputc(' ', lf);
            fputs(m, lf);
            fflush(lf);
        }
    }
}

/* Crash guard for PE walking (packed/protected game binaries, odd modules).
 * mingw has no __try/__except, so: a vectored handler longjmps out of an
 * access violation back to the guarded region, which skips that module.
 * Only ever armed on the init thread while patching. */
jmp_buf g_seh_jb;
volatile LONG g_seh_armed = 0;
/* Whole-init guard + minidump (see LanHookInit). Inner patch guard wins. */
jmp_buf g_init_jb;
volatile LONG g_init_armed = 0;
EXCEPTION_POINTERS *g_init_ep = NULL;
LONG WINAPI seh_filter(EXCEPTION_POINTERS *ep) {
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
void flog_open(void) {
    char path[MAX_PATH];
    DWORD n;
    if (g_logf) return;
    /* Unset or empty: file logging stays off entirely. */
    n = GetEnvironmentVariableA("LAN_HOOK_LOGFILE", path, sizeof(path));
    if (n == 0 || n >= sizeof(path)) return;
    g_logf = fopen(path, "a");
}
void flog(const char *m) {
    if (!g_logf) flog_open();
    if (g_logf) {
        char ts[32];
        dt_stamp(ts, sizeof(ts));
        fputs(ts, g_logf);
        fputc(' ', g_logf);
        fputs(m, g_logf);
        fputc('\n', g_logf);
        fflush(g_logf);
    }
}
void write_minidump(void) {
    HMODULE hd = GetModuleHandleA("dbghelp.dll");
    if (!hd) hd = LoadLibraryA("dbghelp.dll");
    if (!hd || !g_init_ep) return;
    {
        typedef BOOL(WINAPI * PFN_Dump)(
            HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION,
            PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
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
        snprintf(full, sizeof(full), "%s\\lan_hook_%lu.dmp", dir,
                 (unsigned long)GetCurrentProcessId());
        full[sizeof(full) - 1] = 0;
        f = CreateFileA(full, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE) return;
        ex.ThreadId = GetCurrentThreadId();
        ex.ExceptionPointers = g_init_ep;
        ex.ClientPointers = FALSE;
        fn(GetCurrentProcess(), GetCurrentProcessId(), f, MiniDumpNormal, &ex, NULL, NULL);
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
static int dt_win_udp_recv(SOCKET s, char *buf, int len, int flags, struct sockaddr *from,
                           int *fromlen) {
    DLOCK();
    dt_udp_entry((long long)s, 1);
    DUNLOCK();
    int nb = dt_is_nonblock((long long)s);
    int tmo = dt_rcvtimeo_ms((long long)s);
    DWORD t0 = GetTickCount();
    for (;;) {
        struct sockaddr_in tfrom;
        size_t on = 0;
        int pr = dt_udp_pop((long long)s, (unsigned char *)buf, (size_t)len, &tfrom, &on);
        if (pr == 1) {
            if (g_debug) {
                unsigned long av = 0;
                memcpy(&av, &tfrom.sin_addr.s_addr, 4);
                char lb[128];
                snprintf(lb, sizeof(lb), "grecv pid=%u sock=%lld n=%d src=%lu.%lu.%lu.%lu:%d",
                         (unsigned)current_pid(), (long long)s, (int)on, (av & 255),
                         ((av >> 8) & 255), ((av >> 16) & 255), ((av >> 24) & 255),
                         (int)ntohs(tfrom.sin_port));
                dlog(lb);
            }
            if (from && fromlen && *fromlen >= (int)sizeof(tfrom)) {
                memcpy(from, &tfrom, sizeof(tfrom));
                *fromlen = sizeof(tfrom);
            }
            return (int)on;
        }
        if (pr == -1) {
            WSASetLastError(WSAEBADF);
            return SOCKET_ERROR;
        }
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(s, &rf);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 50000;
        struct timeval ztv;
        ztv.tv_sec = 0;
        ztv.tv_usec = 0;
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
                if (nb) {
                    WSASetLastError(WSAEWOULDBLOCK);
                    return SOCKET_ERROR;
                }
                continue; /* LAN_ONLY: no wire world beyond the tunnel */
            }
            if (n > 0 && g_direct) dt_hosted_unsource(from, (socklen_int_t *)fromlen);
            return n;
        }
        if (nb) {
            WSASetLastError(WSAEWOULDBLOCK);
            return SOCKET_ERROR;
        }
        if (tmo >= 0 && (int)(GetTickCount() - t0) >= tmo) {
            WSASetLastError(WSAETIMEDOUT);
            return SOCKET_ERROR;
        }
    }
}

int WSAAPI hk_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to,
                     int tolen) {
    if (g_direct && to && to->sa_family == AF_INET && tolen >= (int)sizeof(struct sockaddr_in)) {
        {
            int cr = dt_on_sendto((long long)s, (const unsigned char *)buf,
                                  (size_t)(len < 0 ? 0 : len), (const struct sockaddr_in *)to);
            if (cr == -1) {
                WSASetLastError(WSAENETUNREACH);
                return SOCKET_ERROR;
            }
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
        snprintf(lb, sizeof(lb), "lan-only: drop wire accept from %lu.%lu.%lu.%lu", a & 255,
                 (a >> 8) & 255, (a >> 16) & 255, (a >> 24) & 255);
        dlog(lb);
        closesocket(r);
        WSASetLastError(WSAEWOULDBLOCK);
        return INVALID_SOCKET;
    }
    if (g_direct && r != INVALID_SOCKET) {
        if (addr && addrlen && *addrlen >= (int)sizeof(struct sockaddr_in))
            dt_acc_post_accept((long long)r, addr, (socklen_int_t *)addrlen,
                               (struct sockaddr_in *)addr);
        else {
            struct sockaddr_in rp;
            int rl = (int)sizeof(rp);
            if (p_getpeername && p_getpeername(r, (struct sockaddr *)&rp, &rl) == 0)
                dt_acc_post_accept((long long)r, NULL, NULL, &rp);
        }
    }
    return r;
}
/* Tunneled-stream receive for every door (recv/recvfrom/WSARecv/
 * WSARecvFrom): serve from the hook queue, present peer-vnode sources,
 * and drain-before-error on peer death exactly like the kernel: queued
 * bytes first, then WSAECONNRESET (hard kill / refusal) or 0 (FIN).
 * Never fall through to the real fd: that IS the relay transport. */
static int dt_win_stream_recv(SOCKET s, char *buf, int len, int flags) {
    (void)flags; /* Windows has no MSG_DONTWAIT */
    int nb = dt_is_nonblock((long long)s);
    int tmo = dt_rcvtimeo_ms((long long)s);
    size_t on = 0;
    int r = dt_tcp_wait((long long)s, (unsigned char *)buf, (size_t)(len < 0 ? 0 : len), &on,
                        nb ? 0 : tmo, nb);
    if (r == 1) return (int)on;
    if (r == -1) {
        /* kernel drains the receive buffer before reporting a reset */
        size_t q = 0;
        int dead = 0;
        DLOCK();
        struct dt_stream *s2 = dt_stream_by_sock((long long)s);
        if (s2) {
            q = dt_inq_count_locked(s2);
            dead = s2->dead;
        }
        DUNLOCK();
        if (q) {
            int r2 = dt_tcp_wait((long long)s, (unsigned char *)buf, (size_t)(len < 0 ? 0 : len),
                                 &on, 0, 1);
            if (r2 == 1) return (int)on;
        }
        {
            int rst = 0;
            DLOCK();
            struct dt_stream *s4 = dt_stream_by_sock((long long)s);
            if (s4 && s4->fail == DT_RSTMARK) rst = 1;
            DUNLOCK();
            if (rst) {
                WSASetLastError(WSAECONNRESET);
                return SOCKET_ERROR;
            }
        }
        if (dead) {
            WSASetLastError(WSAECONNRESET);
            return SOCKET_ERROR;
        }
        return 0;
    }
    WSASetLastError(nb ? WSAEWOULDBLOCK : WSAETIMEDOUT);
    return SOCKET_ERROR;
}

int WSAAPI hk_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from,
                       int *fromlen) {
    if (g_direct && dt_is_udp_like((long long)s))
        return dt_win_udp_recv(s, buf, len, flags, from, fromlen);
    if (g_direct && dt_stream_by_sock_peek((long long)s)) {
        int n = dt_win_stream_recv(s, buf, len, flags);
        if (n > 0 && from && fromlen) {
            struct sockaddr_in o;
            if (dt_getpeer((long long)s, &o) && *fromlen >= (int)sizeof(o)) {
                memcpy(from, &o, sizeof(o));
                *fromlen = sizeof(o);
            }
        }
        return n;
    }
    {
        int r = p_recvfrom(s, buf, len, flags, from, fromlen);
        if (!g_direct && r > 0) dt_obsv("RECV", (long long)s, from, (const unsigned char *)buf, r);
        return r;
    }
}
int WSAAPI hk_WSASendTo(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD sent, DWORD flags,
                        const struct sockaddr *to, int tolen, LPWSAOVERLAPPED ov,
                        LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (g_direct && ov && !cr && to && to->sa_family == AF_INET &&
        tolen >= (int)sizeof(struct sockaddr_in)) {
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
                for (i = 0; i < nb; i++) {
                    memcpy(tmp + off, b[i].buf, b[i].len);
                    off += b[i].len;
                }
                int consumed =
                    dt_on_sendto((long long)s, tmp, total, (const struct sockaddr_in *)to);
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
    if (g_direct && !ov && !cr && to && to->sa_family == AF_INET &&
        tolen >= (int)sizeof(struct sockaddr_in)) {
        /* gather bufs (usually 1) */
        size_t total = 0;
        for (DWORD i = 0; i < nb; i++) total += b[i].len;
        unsigned char *tmp = (unsigned char *)malloc(total ? total : 1);
        if (tmp) {
            size_t off = 0;
            for (DWORD i = 0; i < nb; i++) {
                memcpy(tmp + off, b[i].buf, b[i].len);
                off += b[i].len;
            }
            int consumed = dt_on_sendto((long long)s, tmp, total, (const struct sockaddr_in *)to);
            free(tmp);
            if (consumed == -1) {
                WSASetLastError(WSAENETUNREACH);
                return SOCKET_ERROR;
            }
            if (consumed) {
                if (sent) *sent = (DWORD)total;
                return 0;
            }
        }
    }
    return p_WSASendTo(s, b, nb, sent, flags, to, tolen, ov, cr);
}
int WSAAPI hk_WSARecvFrom(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD recvd, LPDWORD flags,
                          struct sockaddr *from, LPINT fromlen, LPWSAOVERLAPPED ov,
                          LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (ov && g_direct && !cr && dt_is_udp_like((long long)s)) {
        /* overlapped poll: complete synchronously from our queue when
         * data waits, else hand to the real provider for true async */
        size_t total = 0;
        DWORD i;
        for (i = 0; i < nb; i++) total += b[i].len;
        if (total > 0 && total <= 65536) {
            unsigned char *tmp = (unsigned char *)malloc(total);
            if (tmp) {
                struct sockaddr_in tfrom;
                size_t on = 0;
                int pr;
                {
                    DLOCK();
                    dt_udp_entry((long long)s, 1);
                    DUNLOCK();
                }
                pr = dt_udp_pop((long long)s, tmp, total, &tfrom, &on);
                if (pr == 1) {
                    size_t off = 0;
                    DWORD k;
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
                if (pr == -1) {
                    WSASetLastError(WSAEBADF);
                    return SOCKET_ERROR;
                }
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
    case STF_JOIN_TIMEOUT:
        return WSAETIMEDOUT;
    case STF_NO_ROUTE:
    case STF_HOST_FAILED:
    case STF_BAD_ID:
    case STF_BUSY:
        return WSAECONNREFUSED;
    default:
        return WSAETIMEDOUT;
    }
}
static int dt_connect_wait(long long gsock, int nonblock) {
    if (nonblock) {
        WSASetLastError(WSAEWOULDBLOCK);
        return SOCKET_ERROR;
    }
    long long t0 = dt_now_ms();
    for (;;) {
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock(gsock);
        int state = st ? st->state : 0;
        unsigned fail = st ? st->fail : 0;
        DUNLOCK();
        if (state == ST_OPEN) return 0;
        if (state == ST_DEAD) {
            WSASetLastError(dt_stfail_wsae(fail));
            return SOCKET_ERROR;
        }
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
        if (r == 3) {
            WSASetLastError(WSAENETUNREACH);
            return SOCKET_ERROR;
        }
        if (r == 4) return 0; /* machine-internal: looped back already */
        if (r == 1) return dt_connect_wait((long long)s, dt_is_nonblock((long long)s));
        if (r == 2) {
            WSASetLastError(WSAEALREADY);
            return SOCKET_ERROR;
        }
    }
    return p_connect(s, a, l);
}
/* A bound socket can receive without ever calling a tracked function
 * first (pure blocking reader): register it here or fanout can never
 * find it and its arrivals are silently dropped. */
int WSAAPI hk_bind(SOCKET s, const struct sockaddr *a, int l) {
    int r;
    unsigned myv = 0;
    if (g_direct && a && a->sa_family == AF_INET && l >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in in = *(const struct sockaddr_in *)a;
        int proto = dt_sock_type((long long)s);
        int reuse = 0;
        {
            int ra = 0;
            int rl = (int)sizeof(ra);
            if (getsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&ra, &rl) == 0) reuse = ra;
        }
        DLOCK();
        myv = g_myvirt;
        DUNLOCK();
        int bindv = (myv && in.sin_addr.s_addr == htonl(myv));
        if (bindv) in.sin_addr.s_addr = htonl(INADDR_ANY);
        int want = ntohs(in.sin_port);
        if (want != 0) {
            int rv = slp_claim(want, proto, reuse, want);
            if (rv == -1) {
                WSASetLastError(WSAEADDRINUSE);
                r = SOCKET_ERROR;
                goto bindexit;
            }
            r = p_bind ? p_bind(s, (struct sockaddr *)&in, l) : SOCKET_ERROR;
            if (r != 0 && (WSAGetLastError() == WSAEADDRINUSE || WSAGetLastError() == WSAEACCES)) {
                if (dt_bind_alias((long long)s, &in, proto == SOCK_DGRAM,
                                  (int (*)(int, const struct sockaddr *, socklen_t))p_bind) == 0) {
                    if (bindv) dt_alias_bindv((long long)s);
                    if (proto == SOCK_DGRAM) {
                        DLOCK();
                        dt_udp_entry((long long)s, 1);
                        DUNLOCK();
                    }
                    r = 0;
                    goto bindexit;
                }
                slp_release(want, proto);
            } else if (r == 0) {
                DLOCK();
                dt_alias_add((long long)s, want, want, proto);
                if (bindv && proto == SOCK_DGRAM) dt_udp_entry((long long)s, 1);
                DUNLOCK();
                if (bindv) dt_alias_bindv((long long)s);
            } else {
                slp_release(want, proto);
            }
            goto bindexit;
        }
        if (g_lan_only || slp_used() > 0) {
            int i, base = 49152 + (int)(current_pid() % 4096);
            for (i = 0; i < 4096; i++) {
                int p0 = 49152 + ((base - 49152 + i) % 16383);
                if (slp_taken(p0)) continue;
                if (slp_claim(p0, proto, 1, 0) == -1) continue;
                struct sockaddr_in trya = in;
                trya.sin_port = htons((unsigned short)p0);
                r = p_bind ? p_bind(s, (struct sockaddr *)&trya, l) : SOCKET_ERROR;
                if (r == 0) {
                    DLOCK();
                    dt_alias_add((long long)s, p0, p0, proto);
                    if (proto == SOCK_DGRAM) {
                        struct dt_udp *e = dt_udp_entry((long long)s, 1);
                        if (e) e->vport = p0;
                    }
                    DUNLOCK();
                    if (bindv) dt_alias_bindv((long long)s);
                    r = 0;
                    goto bindexit;
                }
                slp_release(p0, proto);
                if (WSAGetLastError() != WSAEADDRINUSE) break;
            }
        }
        in.sin_port = 0;
        r = p_bind ? p_bind(s, (struct sockaddr *)&in, l) : SOCKET_ERROR;
        if (r == 0) {
            struct sockaddr_in got;
            int gl = (int)sizeof(got);
            if (getsockname(s, (struct sockaddr *)&got, &gl) == 0) {
                int p0 = ntohs(got.sin_port);
                slp_claim(p0, proto, reuse, p0);
                DLOCK();
                dt_alias_add((long long)s, p0, p0, proto);
                if (bindv && proto == SOCK_DGRAM) dt_udp_entry((long long)s, 1);
                DUNLOCK();
                if (bindv) dt_alias_bindv((long long)s);
            }
        }
        goto bindexit;
    }
    r = p_bind ? p_bind(s, a, l) : SOCKET_ERROR;
bindexit: {
    int berr = (r != 0) ? WSAGetLastError() : 0; /* snapshot: the
              * logging calls below may overwrite last-error */
    if (g_debug && g_direct && a && a->sa_family == AF_INET) {
        const struct sockaddr_in *ba = (const struct sockaddr_in *)a;
        unsigned long addr = 0;
        memcpy(&addr, &ba->sin_addr.s_addr, 4);
        char lb[192];
        snprintf(lb, sizeof(lb), "bind pid=%u sock=%lld %lu.%lu.%lu.%lu:%d r=%d err=%d",
                 (unsigned)GetCurrentProcessId(), (long long)s, (addr & 255), ((addr >> 8) & 255),
                 ((addr >> 16) & 255), ((addr >> 24) & 255), (int)ntohs(ba->sin_port), r, berr);
        dlog(lb);
    }
    if (r != 0) WSASetLastError(berr);
    if (r == 0 && g_direct && a && a->sa_family == AF_INET) {
        DLOCK();
        dt_udp_entry((long long)s, 1);
        DUNLOCK();
    }
    return r;
}
}
static void dt_gp_spoof(SOCKET fd, struct sockaddr_in *sa, int l, int want_self);
/* kernel: a socket still in connect() never reports writable */
static int dt_fd_connecting(long long fd) {
    int r = 0;
    DLOCK();
    struct dt_stream *st = dt_stream_by_sock(fd);
    if (st && st->state == ST_CONNECTING) r = 1;
    DUNLOCK();
    return r;
}
static int(WSAAPI *p_shutdown)(SOCKET, int) = 0;
int WSAAPI hk_shutdown(SOCKET s, int how) {
    if (!p_shutdown)
        p_shutdown = (int(WSAAPI *)(SOCKET, int))GetProcAddress(
            hWS2 ? hWS2 : GetModuleHandleA("ws2_32.dll"), "shutdown");
    if (g_direct) {
        int hit = 0, sig = 0;
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock((long long)s);
        if (st) {
            hit = 1;
            if (how == SD_RECEIVE || how == SD_BOTH) {
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
            if (how == SD_SEND || how == SD_BOTH) st->wr_shut = 1;
            if (sig) dt_sig_locked((long long)s);
        }
        DUNLOCK();
        if (hit) return 0;
    }
    return p_shutdown ? p_shutdown(s, how) : SOCKET_ERROR;
}
static int(WSAAPI *p_getsockopt)(SOCKET, int, int, char *, int *) = 0;
int WSAAPI hk_getsockopt(SOCKET s, int level, int optname, char *optval, int *optlen) {
    if (!p_getsockopt)
        p_getsockopt = (int(WSAAPI *)(SOCKET, int, int, char *, int *))GetProcAddress(
            hWS2 ? hWS2 : GetModuleHandleA("ws2_32.dll"), "getsockopt");
    if (g_direct && level == SOL_SOCKET && optname == SO_ERROR && optval && optlen &&
        *optlen >= (int)sizeof(int)) {
        int err = -1;
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock((long long)s);
        if (st) {
            if (st->state == ST_CONNECTING) err = 0; /* see Linux note */
            else if (st->state == ST_DEAD && !st->ever_open)
                err = (st->fail == DT_RSTMARK) ? WSAECONNRESET : dt_stfail_wsae(st->fail);
            else err = 0;
        }
        DUNLOCK();
        if (err >= 0) {
            memcpy(optval, &err, sizeof(err));
            *optlen = sizeof(err);
            return 0;
        }
    }
    return p_getsockopt ? p_getsockopt(s, level, optname, optval, optlen) : SOCKET_ERROR;
}
int WSAAPI hk_getsockname(SOCKET s, struct sockaddr *a, int *l) {
    int r = p_getsockname ? p_getsockname(s, a, l) : SOCKET_ERROR;
    if (r == 0 && g_direct && a && a->sa_family == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)a;
        int vp = 0;
        DLOCK();
        struct dt_udp *e = dt_udp_entry((long long)s, 0);
        if (e) vp = e->vport;
        DUNLOCK();
        if (vp <= 0) vp = dt_alias_vport((long long)s);
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
        dt_gp_spoof(s, sa, l ? *l : 0, 1);
    }
    return r;
}
int WSAAPI hk_WSAConnect(SOCKET s, const struct sockaddr *a, int l, LPWSABUF b1, LPWSABUF b2,
                         LPQOS q1, LPQOS q2) {
    (void)b1;
    (void)b2;
    (void)q1;
    (void)q2;
    if (g_direct && a && a->sa_family == AF_INET && l >= (int)sizeof(struct sockaddr_in)) {
        int r = dt_on_connect((long long)s, (const struct sockaddr_in *)a);
        if (r == 3) {
            WSASetLastError(WSAENETUNREACH);
            return SOCKET_ERROR;
        }
        if (r == 4) return 0; /* machine-internal: looped back already */
        if (r == 1) return dt_connect_wait((long long)s, dt_is_nonblock((long long)s));
        if (r == 2) {
            WSASetLastError(WSAEALREADY);
            return SOCKET_ERROR;
        }
    }
    return p_WSAConnect ? p_WSAConnect(s, a, l, b1, b2, q1, q2) : SOCKET_ERROR;
}
/* shared spoof door for getpeername (want=0) and getsockname (want=1).
 * For accepted (bridged) sockets only: presents the vnode view the
 * kernel would give on a real LAN - peer = opener's vnode, local = own
 * vnode; the listen port stays real either way. */
static void dt_gp_spoof(SOCKET fd, struct sockaddr_in *sa, int l, int want_self) {
    if (l < (int)sizeof(struct sockaddr_in) || !g_direct) return;
    struct sockaddr_in o;
    int lp = 0;
    if (!dt_acc_get((long long)fd, &o, &lp)) return;
    struct sockaddr_in rp;
    int rl = (int)sizeof(rp);
    if (!p_getpeername || p_getpeername(fd, (struct sockaddr *)&rp, &rl) != 0 ||
        rp.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
        return; /* not our bridge: hands off */
    if (want_self) {
        dt_acc_self_view((long long)fd, sa); /* own vnode + listen VPORT
            (the listener may be aliased on a machine hosting two of our
            nodes; the raw local port would contradict the announce) */
    } else {
        *sa = o; /* opener's vnode + port */
    }
}
int WSAAPI hk_getpeername(SOCKET s, struct sockaddr *a, int *l) {
    if (g_direct && a && l && *l >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in o;
        if (dt_getpeer((long long)s, &o)) {
            memcpy(a, &o, sizeof(o));
            *l = sizeof(o);
            return 0;
        }
        int lp = 0;
        if (dt_acc_get((long long)s, &o, &lp)) {
            struct sockaddr_in rp;
            int rl = (int)sizeof(rp);
            if (p_getpeername(s, (struct sockaddr *)&rp, &rl) == 0 &&
                rp.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && ntohs(rp.sin_port) == lp) {
                memcpy(a, &o, sizeof(o));
                *l = sizeof(o);
                return 0;
            }
            dt_acc_forget((long long)s); /* fd-reused */
        }
    }
    return p_getpeername(s, a, l);
}
int WSAAPI hk_closesocket(SOCKET s) {
    dt_acc_forget((long long)s);
    if (g_direct) dt_on_close((long long)s);
    else dt_ev_unhook_sock((long long)s);
    return p_closesocket(s);
}
int WSAAPI hk_listen(SOCKET s, int backlog) {
    int r = p_listen(s, backlog);
    /* game serves a TCP port -> stamp the host claim on the relay */
    if (r == 0 && g_direct && dt_sock_type((long long)s) == SOCK_STREAM) {
        struct sockaddr_in a;
        int l = sizeof(a);
        if (getsockname(s, (struct sockaddr *)&a, &l) == 0 && a.sin_family == AF_INET) {
            int av = dt_alias_vport((long long)s);
            dt_record_listen(av > 0 ? av : ntohs(a.sin_port));
            dt_claim();
        }
    }
    return r;
}

/* Connected-socket byte path for direct-tunnel TCP streams. */
int WSAAPI hk_send(SOCKET s, const char *buf, int len, int flags) {
    (void)flags;
    if (g_direct) {
        int r = dt_stream_send_wait((long long)s, (const unsigned char *)buf,
                                    (size_t)(len < 0 ? 0 : len));
        if (r > 0) return r;
        if (r == 0) { /* fall through to real socket */
        } else return SOCKET_ERROR;
    }
    return p_send(s, buf, len, flags);
}
int WSAAPI hk_recv(SOCKET s, char *buf, int len, int flags) {
    if (g_direct && !dt_is_udp_like((long long)s)) {
        if (dt_stream_by_sock_peek((long long)s)) return dt_win_stream_recv(s, buf, len, flags);
    }
    return p_recv(s, buf, len, flags);
}
int WSAAPI hk_WSASend(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD sent, DWORD flags, LPWSAOVERLAPPED ov,
                      LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
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
                for (i = 0; i < nb; i++) {
                    memcpy(tmp + off, b[i].buf, b[i].len);
                    off += b[i].len;
                }
                int r = dt_stream_send_wait((long long)s, tmp, total);
                free(tmp);
                if (r > 0) {
                    if (sent) *sent = (DWORD)r;
                    if (ov->hEvent) WSASetEvent(ov->hEvent);
                    return 0;
                }
                if (r == 0) { /* not our stream: fall through */
                } else {
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
            for (DWORD i = 0; i < nb; i++) {
                memcpy(tmp + off, b[i].buf, b[i].len);
                off += b[i].len;
            }
            int r = dt_stream_send_wait((long long)s, tmp, total);
            free(tmp);
            if (r > 0) {
                if (sent) *sent = (DWORD)r;
                return 0;
            }
            if (r == 0) { /* not our stream: fall through */
            } else {
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
                    size_t off = 0;
                    DWORD k;
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
            int r = dt_tcp_wait((long long)s, (unsigned char *)b[0].buf, (size_t)b[0].len, &on, tmo,
                                nbk);
            if (r == 1) {
                if (recvd) *recvd = (DWORD)on;
                if (flags) *flags = 0;
                return 0;
            }
            if (r == -1) {
                if (recvd) *recvd = 0;
                return 0;
            }
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
     * the classic polling reader) never read otherwise and the peer can never
     * "connect" from their side. */
    if (cmd == (long)FIONREAD && argp && g_direct) {
        int dolog = 0;
        unsigned qn = 0;
        DLOCK();
        struct dt_stream *st = dt_stream_by_sock((long long)s);
        if (st) {
            qn = (unsigned)st->total;
            *argp = (u_long)qn;
            /* key field signal: bytes waiting but app has read NONE yet */
            if (qn && st->an_rx == 0 && !st->a_log) {
                st->a_log = 1;
                dolog = 1;
            }
            DUNLOCK();
            if (dolog) {
                char lb[128];
                snprintf(lb, sizeof(lb), "fion: queued=%u unread pid=%u sock=%lld sid=%u", qn,
                         (unsigned)current_pid(), (long long)s, st->sid);
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
    typedef int(WSAAPI * PFN_select)(int, fd_set *, fd_set *, fd_set *, const struct timeval *);
    static PFN_select p_sel = 0;
    if (!p_sel)
        p_sel = (PFN_select)GetProcAddress(hWS2 ? hWS2 : GetModuleHandleA("ws2_32.dll"), "select");
    if (!g_direct) return p_sel(nfds, r, w, x, tmo);
    long budget = tmo ? (long)(tmo->tv_sec * 1000 + tmo->tv_usec / 1000) : -1;
    fd_set r0, w0, x0;
    FD_ZERO(&r0);
    FD_ZERO(&w0);
    FD_ZERO(&x0);
    if (r) r0 = *r;
    if (w) w0 = *w;
    if (x) x0 = *x;
    {
        fd_set rq = r0, wq = w0, xq = x0;
        struct timeval z = {0, 0};
        int qr =
            ((r || w || x)) ? p_sel(nfds, r ? &rq : NULL, w ? &wq : NULL, x ? &xq : NULL, &z) : 0;
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
            for (u_int i = 0; i < w0.fd_count; i++)
                if (FD_ISSET(w0.fd_array[i], w) && dt_fd_connecting((long long)w0.fd_array[i]))
                    FD_CLR(w0.fd_array[i], w);
            for (u_int i = 0; i < w0.fd_count; i++) {
                int data, dead, wr, cn;
                dt_sock_state_full((long long)w0.fd_array[i], &data, &dead, &wr, &cn);
                if (wr || cn) FD_SET(w0.fd_array[i], w);
            }
            for (u_int i = 0; i < w->fd_count; i++) n++;
        }
        if (x) {
            *x = xq;
            for (u_int i = 0; i < x->fd_count; i++) n++;
        }
        if (n) return n;
    }
    long waited = 0;
    for (;;) {
        long slice = 25;
        if (budget >= 0) {
            if (waited >= budget) {
                if (r) FD_ZERO(r);
                if (w) FD_ZERO(w);
                if (x) FD_ZERO(x);
                return 0;
            }
            if (budget - waited < slice) slice = budget - waited;
        }
        fd_set rq = r0, wq = w0, xq = x0;
        struct timeval tv;
        tv.tv_sec = slice / 1000;
        tv.tv_usec = (slice % 1000) * 1000;
        int rr_ = p_sel(nfds, r ? &rq : NULL, w ? &wq : NULL, x ? &xq : NULL, &tv);
        if (rr_ < 0) return rr_;
        {
            int n = 0;
            if (r) {
                FD_ZERO(r);
                if (rr_ > 0)
                    for (u_int i = 0; i < rq.fd_count; i++) FD_SET(rq.fd_array[i], r);
                for (u_int i = 0; i < r0.fd_count; i++)
                    if (dt_fd_readable((long long)r0.fd_array[i])) FD_SET(r0.fd_array[i], r);
                for (u_int i = 0; i < r->fd_count; i++) n++;
            }
            if (w) {
                FD_ZERO(w);
                if (rr_ > 0)
                    for (u_int i = 0; i < wq.fd_count; i++) FD_SET(wq.fd_array[i], w);
                for (u_int i = 0; i < w0.fd_count; i++) {
                    int data, dead, wr, cn;
                    dt_sock_state_full((long long)w0.fd_array[i], &data, &dead, &wr, &cn);
                    if (wr || cn) FD_SET(w0.fd_array[i], w);
                }
                for (u_int i = 0; i < w->fd_count; i++) n++;
            }
            if (x) {
                if (rr_ > 0) {
                    *x = xq;
                    for (u_int i = 0; i < x->fd_count; i++) n++;
                } else FD_ZERO(x);
            }
            if (n) return n;
        }
        waited += slice;
        if (budget >= 0 && waited >= budget) {
            if (r) FD_ZERO(r);
            if (w) FD_ZERO(w);
            if (x) FD_ZERO(x);
            return 0;
        }
    }
}
int WSAAPI hk_WSAPoll(LPWSAPOLLFD fds, ULONG nfds, INT timeout) {
    typedef int(WSAAPI * PFN_WSAPoll)(LPWSAPOLLFD, ULONG, INT);
    static PFN_WSAPoll p_p = 0;
    if (!p_p)
        p_p = (PFN_WSAPoll)GetProcAddress(hWS2 ? hWS2 : GetModuleHandleA("ws2_32.dll"), "WSAPoll");
    if (!g_direct) return p_p(fds, nfds, timeout);
    for (ULONG i = 0; i < nfds; i++) fds[i].revents = 0;
    {
        int n = 0;
        for (ULONG i = 0; i < nfds; i++) {
            if ((fds[i].events & POLLRDNORM) && dt_fd_readable((long long)fds[i].fd))
                fds[i].revents |= POLLRDNORM;
            if (fds[i].revents & (POLLOUT | POLLWRNORM) && dt_fd_connecting((long long)fds[i].fd))
                fds[i].revents &= ~(POLLOUT | POLLWRNORM);
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
    if (g_direct) {
        DLOCK();
        dt_udp_entry((long long)s, 1);
        DUNLOCK();
    }
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
        for (i = 0; i < DT_MAXEV; i++)
            if (!g_evmap[i].used) {
                g_evmap[i].used = 1;
                g_evmap[i].sock = (long long)s;
                g_evmap[i].ev = hEvent;
                g_evmap[i].mask = lNetworkEvents;
                done = 1;
                break;
            }
        DUNLOCK();
        if (done) {
            int data = 0, dead = 0, wr = 0, cn = 0;
            dt_sock_state_full((long long)s, &data, &dead, &wr, &cn);
            if ((data && (lNetworkEvents & FD_READ)) || (dead && (lNetworkEvents & FD_CLOSE)) ||
                (wr && (lNetworkEvents & FD_WRITE)) || (cn && (lNetworkEvents & FD_CONNECT)))
                WSASetEvent(hEvent); /* already waiting */
        }
    }
    return r;
}
int WSAAPI hk_WSAEnumNetworkEvents(SOCKET s, WSAEVENT hEventObject,
                                   LPWSANETWORKEVENTS lpNetworkEvents) {
    int r = p_WSAEnumNetworkEvents ? p_WSAEnumNetworkEvents(s, hEventObject, lpNetworkEvents)
                                   : SOCKET_ERROR;
    if (g_direct && r == 0 && lpNetworkEvents) {
        int data = 0, dead = 0, wr = 0, cn = 0;
        dt_sock_state_full((long long)s, &data, &dead, &wr, &cn);
        long vm = 0;
        if (data) {
            lpNetworkEvents->lNetworkEvents |= FD_READ;
            vm |= FD_READ;
        }
        if (dead) {
            lpNetworkEvents->lNetworkEvents |= FD_CLOSE;
            vm |= FD_CLOSE;
        }
        if (wr) {
            lpNetworkEvents->lNetworkEvents |= FD_WRITE;
            vm |= FD_WRITE;
        }
        if (cn) {
            lpNetworkEvents->lNetworkEvents |= FD_CONNECT;
            vm |= FD_CONNECT;
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
    return (data && (mask & FD_READ)) || (dead && (mask & FD_CLOSE)) || (wr && (mask & FD_WRITE)) ||
           (cn && (mask & FD_CONNECT));
}
DWORD WSAAPI hk_WSAWaitForMultipleEvents(DWORD cEvents, const WSAEVENT *lphEvents, BOOL fWaitAll,
                                         DWORD dwTimeout, BOOL fAlertable) {
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
                if (hit) {
                    DUNLOCK();
                    return WSA_WAIT_EVENT_0 + i;
                }
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
static struct {
    HMODULE mod;
    DWORD ord;
    char name[40];
} g_ordmap[ORD_MAXMAP];
static int g_ordmap_n = 0;

const char *export_name_for_ordinal(HMODULE mod, DWORD ord) {
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
        if (g_ordmap[i].mod == mod && g_ordmap[i].ord == ord) return g_ordmap[i].name;
    base = (BYTE *)mod;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 1024 * 1024) return 0;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    expdir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expdir->VirtualAddress || !expdir->Size) return 0;
    exp = (IMAGE_EXPORT_DIRECTORY *)(base + expdir->VirtualAddress);
    if (!exp->AddressOfNames || !exp->AddressOfNameOrdinals) return 0;
    names = (DWORD *)(base + exp->AddressOfNames);
    nameords = (WORD *)(base + exp->AddressOfNameOrdinals);
    for (j = 0; j < exp->NumberOfNames; j++) {
        if ((DWORD)(nameords[j] + exp->Base) == ord) {
            const char *nm = (const char *)(base + names[j]);
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
        GetModuleFileNameA(m, mod, sizeof(mod) - 1);
        int isws2 = 0;
        for (char *p = mod; *p; p++)
            if ((p[0] == 'w' || p[0] == 'W') && (p[1] == 's' || p[1] == 'S')) {
                isws2 = 1;
                break;
            }
        if (isws2 || m == hWS2) {
            if (!strcmp(n, "sendto")) return (FARPROC)hk_sendto;
            if (!strcmp(n, "recvfrom")) return (FARPROC)hk_recvfrom;
            if (!strcmp(n, "accept")) return (FARPROC)hk_accept;
            if (!strcmp(n, "WSASendTo")) return (FARPROC)hk_WSASendTo;
            if (!strcmp(n, "WSARecvFrom")) return (FARPROC)hk_WSARecvFrom;
            if (!strcmp(n, "connect")) return (FARPROC)hk_connect;
            if (!strcmp(n, "bind")) return (FARPROC)hk_bind;
            if (!strcmp(n, "WSAConnect")) return (FARPROC)hk_WSAConnect;
            if (!strcmp(n, "shutdown")) return (FARPROC)hk_shutdown;
            if (!strcmp(n, "getsockopt")) return (FARPROC)hk_getsockopt;
            if (!strcmp(n, "getpeername")) return (FARPROC)hk_getpeername;
            if (!strcmp(n, "getsockname")) return (FARPROC)hk_getsockname;
            if (!strcmp(n, "closesocket")) return (FARPROC)hk_closesocket;
            if (!strcmp(n, "listen")) return (FARPROC)hk_listen;
            if (!strcmp(n, "send")) return (FARPROC)hk_send;
            if (!strcmp(n, "recv")) return (FARPROC)hk_recv;
            if (!strcmp(n, "WSASend")) return (FARPROC)hk_WSASend;
            if (!strcmp(n, "WSARecv")) return (FARPROC)hk_WSARecv;
            if (!strcmp(n, "ioctlsocket")) return (FARPROC)hk_ioctlsocket;
            if (!strcmp(n, "select")) return (FARPROC)hk_select;
            if (!strcmp(n, "WSAPoll")) return (FARPROC)hk_WSAPoll;
            if (!strcmp(n, "WSAEventSelect")) return (FARPROC)hk_WSAEventSelect;
            if (!strcmp(n, "WSAEnumNetworkEvents")) return (FARPROC)hk_WSAEnumNetworkEvents;
            if (!strcmp(n, "WSAWaitForMultipleEvents")) return (FARPROC)hk_WSAWaitForMultipleEvents;
            if (!strcmp(n, "WSACreateEvent")) return (FARPROC)hk_WSACreateEvent;
            if (!strcmp(n, "WSACloseEvent")) return (FARPROC)hk_WSACloseEvent;
        }
        {
            char imod[MAX_PATH] = {0};
            GetModuleFileNameA(m, imod, sizeof(imod) - 1);
            {
                char *bs = strrchr(imod, '\\');
                const char *base = bs ? bs + 1 : imod;
                if (!_stricmp(base, "iphlpapi.dll")) {
                    if (!strcmp(n, "IcmpSendEcho")) return (FARPROC)hk_IcmpSendEcho;
                    if (!strcmp(n, "IcmpSendEcho2")) return (FARPROC)hk_IcmpSendEcho2;
                }
            }
        }
        if (m == hKernel) {
            if (!strcmp(n, "ExitProcess")) return (FARPROC)hk_ExitProcess;
            if (!strcmp(n, "TerminateProcess")) return (FARPROC)hk_TerminateProcess;
            if (!strcmp(n, "CreateProcessA")) return (FARPROC)hk_CreateProcessA;
            if (!strcmp(n, "CreateProcessW")) return (FARPROC)hk_CreateProcessW;
            if (!strcmp(n, "LoadLibraryA")) return (FARPROC)hk_LoadLibraryA;
            if (!strcmp(n, "LoadLibraryW")) return (FARPROC)hk_LoadLibraryW;
            if (!strcmp(n, "LoadLibraryExA")) return (FARPROC)hk_LoadLibraryExA;
            if (!strcmp(n, "LoadLibraryExW")) return (FARPROC)hk_LoadLibraryExW;
        }
    }
    return p_GetProcAddress(m, n);
}
