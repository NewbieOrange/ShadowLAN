#ifndef HK_API_H
#define HK_API_H
/* Cross-TU surface of the lan_hook internal modules (hk_util.c,
 * hk_alias.c, hk_ledger.c). Everything else stays file-local. The
 * extra dynamic symbols the .so exports are all dt_/slp_-prefixed,
 * so they can never shadow what an app imports. */

/* --- hk_util.c: time, log, identity, rng --- */
extern int g_debug;                    /* LAN_HOOK_DEBUG; set by policy_init */
long long dt_now_ms(void);
unsigned current_pid(void);
void dt_msleep(int ms);
void dt_stamp(char *out, size_t n);
void dlog(const char *m);
void dt_rand_seed(void);
unsigned dt_rand(void);
void dt_rand_mix(unsigned v);

/* --- hk_alias.c: per-process vport<->real presentation table --- */
void dt_alias_add(long long sock, int vport, int real, int proto);
int  dt_alias_vport(long long sock);
int  dt_alias_real(int vport, int proto);  /* proto<=0: any */
void dt_alias_bindv(long long sock);
int  dt_alias_is_bindv(long long sock);
void dt_alias_drop(long long sock);
void dt_alias_release_all(long long sock);   /* also releases ledger claims */

/* --- hk_ledger.c: node-scoped shared port registry --- */
void slp_set_node(unsigned node);            /* push identity after minting */
int  slp_claim(int vport, int proto, int reuse, int real); /* -2 no ledger */
void slp_release(int vport, int proto);
int  slp_taken(int vport);
int  slp_used(void);
#endif
