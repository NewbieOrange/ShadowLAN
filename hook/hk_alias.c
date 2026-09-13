/* hk_alias.c - per-process virtual<->real port presentation table.
 * Independent TU; interface in hk_api.h. */
#include "hk_plat.h"
#include "hk_api.h"

/* Per-process virtual<->real port table: one row per hooked bind
 * (identity rows included), so listeners, fan-out, getsockname and the
 * loopback bridges all keep speaking the app's virtual port. Same-node
 * bind conflicts are arbitrated by the NODE ledger BEFORE the real
 * stack (kernel-collide); only a conflict owned by a DIFFERENT node on
 * this OS reaches here as an alias: the bind is re-issued ephemerally
 * under the kept vport. Kernel fidelity, not a trick: two real LAN
 * hosts never see each other's EADDRINUSE. */
#define DT_TA_MAX 64     /* per-process vport<->real presentation table */
static struct { long long sock; int vport; int real;
                  unsigned char proto; unsigned char bindv; } g_ta[DT_TA_MAX];
void dt_alias_add(long long sock, int vport, int real, int proto) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock) {
            g_ta[i].vport = vport; g_ta[i].real = real;
            g_ta[i].proto = (unsigned char)proto; return;
        }
    for (i = 0; i < DT_TA_MAX; i++)
        if (!g_ta[i].sock) {
            g_ta[i].sock = sock; g_ta[i].vport = vport; g_ta[i].real = real;
            g_ta[i].proto = (unsigned char)proto; return;
        }
}
/* -1 when the socket binds its port for real */
int dt_alias_vport(long long sock) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock && g_ta[i].vport > 0) return g_ta[i].vport;
    return -1;
}
/* real local port serving this virtual port in THIS process (0: none) */
int dt_alias_real(int vport, int proto) {
    int i;
    /* proto-filtered: a game that aliased UDP and TCP on the SAME vport
     * (two machines on one OS) must never have its TCP bridge dial the
     * UDP row's ephemeral (field join failure, single-box runs). */
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].vport == vport && g_ta[i].real > 0 &&
            (proto <= 0 || (int)g_ta[i].proto == proto))
            return g_ta[i].real;
    return 0;
}
void dt_alias_bindv(long long sock) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock) { g_ta[i].bindv = 1; return; }
}
int dt_alias_is_bindv(long long sock) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock) return g_ta[i].bindv;
    return 0;
}
void dt_alias_drop(long long sock) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock) { g_ta[i].sock = 0; g_ta[i].vport = g_ta[i].real = 0; }
}

/* close(): hand every vport this socket presented back to the ledger */
void dt_alias_release_all(long long sock) {
    int i;
    for (i = 0; i < DT_TA_MAX; i++)
        if (g_ta[i].sock == sock && g_ta[i].vport > 0)
            slp_release(g_ta[i].vport, g_ta[i].proto);
}
