/* hk_ledger.c - machine-wide, node-filtered port claim registry
 * (Local\ pagefile mapping / shm_open+flock). Independent TU: the node
 * id is PUSHED via slp_set_node so no core globals are reached into;
 * dlog/current_pid come from hk_util. */
#include "hk_plat.h"
#include "hk_api.h"

static unsigned g_slp_node = 0;
void slp_set_node(unsigned node) {
    g_slp_node = node;
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
typedef struct {
    unsigned int pid;
    unsigned int node;
    unsigned long long start;
    int vport;
    int real;
    unsigned char proto;
    unsigned char reuse;
    unsigned char used;
    unsigned char pad;
} slp_ent;
typedef struct {
    unsigned int magic;
    unsigned int gen;
    slp_ent e[SLP_MAX];
} slp_t;

#ifdef LINUX_BUILD
static int g_slp_fd = -1;
static slp_t *g_slp = 0;
static int slp_attach(void) {
    /* ONE machine-wide registry object; entries carry the node id.
     * (A per-node name would leave a /dev/shm stub per random node id
     * forever - the object is kernel-refcounted, the NAME is not.) */
    if (g_slp) return 1;
    if (!g_slp_node) return 0;
    int fd = shm_open("/slp-ports", O_CREAT | O_RDWR, 0600);
    if (fd < 0) return 0;
    if (ftruncate(fd, (off_t)sizeof(slp_t)) != 0) {
        close(fd);
        return 0;
    }
    void *p = mmap(0, sizeof(slp_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        close(fd);
        return 0;
    }
    g_slp_fd = fd;
    g_slp = (slp_t *)p;
    if (g_slp->magic != SLP_MAGIC) {
        g_slp->magic = SLP_MAGIC;
        g_slp->gen = 0;
        memset(g_slp->e, 0, sizeof g_slp->e);
    }
    return 1;
}
#define SLP_LOCK()                                                                                 \
    do {                                                                                           \
        if (g_slp_fd >= 0) flock(g_slp_fd, LOCK_EX);                                               \
    } while (0)
#define SLP_UNLOCK()                                                                               \
    do {                                                                                           \
        if (g_slp_fd >= 0) flock(g_slp_fd, LOCK_UN);                                               \
    } while (0)
#else
static HANDLE g_slp_mx = 0;
static HANDLE g_slp_sec = 0;
static slp_t *g_slp = 0;
static int slp_attach(void) {
    char nm[96], mx[96];
    if (g_slp) return 1;
    if (!g_slp_node) return 0;
    snprintf(nm, sizeof nm, "Local\\ShadowLAN-ports-%08x", g_slp_node);
    snprintf(mx, sizeof mx, "Local\\ShadowLAN-portlk-%08x", g_slp_node);
    HANDLE m = CreateMutexA(NULL, FALSE, mx);
    if (!m) return 0;
    HANDLE h = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(slp_t), nm);
    if (!h) {
        CloseHandle(m);
        return 0;
    }
    void *p = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, sizeof(slp_t));
    if (!p) {
        CloseHandle(m);
        return 0;
    }
    /* keep the section handle: some environments (observed under Wine)
     * drop the shared pages when the last CREATE handle closes even if
     * views remain - never gamble on that here */
    g_slp_mx = m;
    g_slp_sec = h;
    g_slp = (slp_t *)p;
    /* OWNED init, never GetLastError(ERROR_ALREADY_EXISTS): some
     * environments (observed under Wine) do not preserve that flag to
     * this point, and a false "fresh" would WIPE a live registry. */
    WaitForSingleObject(g_slp_mx, INFINITE);
    if (g_slp->magic != SLP_MAGIC) {
        g_slp->magic = 0;
        g_slp->gen = 0;
        memset(g_slp->e, 0, sizeof g_slp->e);
        InterlockedExchange((LONG *)&g_slp->magic, (LONG)SLP_MAGIC);
    }
    ReleaseMutex(g_slp_mx);
    return 1;
}
#define SLP_LOCK()                                                                                 \
    do {                                                                                           \
        if (g_slp_mx) WaitForSingleObject(g_slp_mx, INFINITE);                                     \
    } while (0)
#define SLP_UNLOCK()                                                                               \
    do {                                                                                           \
        if (g_slp_mx) ReleaseMutex(g_slp_mx);                                                      \
    } while (0)
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
    if (!fgets(buf, sizeof buf, f)) {
        fclose(f);
        return 0;
    }
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
    if (peb) v = *(unsigned long long *)(peb + 0x0a8); /* Peb->CreateTime */
#else
    unsigned char *peb = 0;
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb));
    if (peb) v = *(unsigned long long *)(peb + 0x0a4); /* 32-bit offset */
#endif
    return v;
}
/* NEVER GetProcessTimes here (field AV at app startup, reproducible
 * under Wine). Liveness by exit code; access-denied means alive; the
 * start stamp is kept only for self-audits. */
static int slp_alive(unsigned pid, unsigned long long start) {
    HANDLE h;
    DWORD code = 0;
    int alive;
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
int slp_claim(int vport, int proto, int reuse, int real) {
    int rc;
    if (!slp_attach()) return -2; /* no ledger: caller decides */
    SLP_LOCK();
    rc = -2;
    {
        int i, found = -1;
        for (i = 0; i < SLP_MAX; i++) {
            slp_ent *x = &g_slp->e[i];
            if (x->used && x->node == g_slp_node && x->vport == vport &&
                x->proto == (unsigned char)proto) {
                found = i;
                break;
            }
        }
        if (found >= 0) {
            slp_ent *x = &g_slp->e[found];
#ifndef LINUX_BUILD
            if (g_debug) {
                char lb[160];
                snprintf(lb, sizeof lb, "slp dbg found=%d holder=%u start=%llx self=%llx alive=%d",
                         found, x->pid, x->start, slp_self_start(), slp_alive(x->pid, x->start));
                dlog(lb);
            }
#endif
            if (!slp_alive(x->pid, x->start)) { /* stale claim: take over */
                x->pid = (unsigned)current_pid();
                x->real = real;
                x->start = slp_self_start();
                x->reuse = (unsigned char)reuse;
                rc = 0;
            } else if (proto == SOCK_DGRAM && x->reuse && reuse) {
                rc = 1;     /* kernel-faithful: datagram sharing needs
                              * SO_REUSEADDR on BOTH sockets */
            } else rc = -1; /* kernel would collide */
        } else {
            /* allocation with a janitor pass: a dead holder's slot is
             * free space too. Without this sweep the machine-wide
             * registry fills with stale claims over many runs (-2 ->
             * fail-open -> same-node duplicates alias through: the
             * table-full bug found on a day of heavy test runs). */
            int slot = -1, reap = -1, i2;
            for (i2 = 0; i2 < SLP_MAX; i2++) {
                slp_ent *x = &g_slp->e[i2];
                if (!x->used) {
                    slot = i2;
                    break;
                }
                if (reap < 0 && !slp_alive(x->pid, x->start)) reap = i2;
            }
            if (slot < 0) slot = reap;
            if (slot >= 0) {
                slp_ent *x = &g_slp->e[slot];
                x->used = 1;
                x->pid = (unsigned)current_pid();
                x->node = g_slp_node;
                x->start = slp_self_start();
                x->vport = vport;
                x->real = real;
                x->proto = (unsigned char)proto;
                x->reuse = (unsigned char)reuse;
                g_slp->gen++;
                rc = 0;
            }
        }
    }
    SLP_UNLOCK();
    if (g_debug) {
        char lb[128];
        snprintf(lb, sizeof lb, "slp claim node=%u pid=%u vport=%d proto=%d reuse=%d rv=%d",
                 g_slp_node, current_pid(), vport, proto, reuse, rc);
        dlog(lb);
    }
    return rc;
}
void slp_release(int vport, int proto) {
    if (!g_slp) return;
    SLP_LOCK();
    {
        int i;
        for (i = 0; i < SLP_MAX; i++) {
            slp_ent *x = &g_slp->e[i];
            if (x->used && x->node == g_slp_node && x->vport == vport &&
                x->proto == (unsigned char)proto && x->pid == (unsigned)current_pid()) {
                x->used = 0;
                g_slp->gen++;
            }
        }
    }
    SLP_UNLOCK();
}
/* any-proto claim check for bind(0) port selection */
int slp_used(void) {
    int n = 0;
    if (!g_slp) return 0;
    SLP_LOCK();
    {
        int i;
        for (i = 0; i < SLP_MAX; i++)
            if (g_slp->e[i].used) n++;
    }
    SLP_UNLOCK();
    return n;
}
int slp_taken(int vport) {
    int t = 0;
    if (!g_slp) return 0;
    SLP_LOCK();
    {
        int i;
        for (i = 0; i < SLP_MAX; i++)
            if (g_slp->e[i].used && g_slp->e[i].node == g_slp_node && g_slp->e[i].vport == vport) {
                t = 1;
                break;
            }
    }
    SLP_UNLOCK();
    return t;
}
