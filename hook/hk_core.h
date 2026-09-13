#ifndef HK_CORE_H
#define HK_CORE_H
/* Shared wire ops, tables, and policy. Every hook TU includes this.
 * Definitions live in hk_core.c. Keep DT_/DU_ ops in lockstep with common.py. */
#include "hk_plat.h"
#include "hk_api.h"
#include "hk_version.h"

#ifdef LINUX_BUILD
typedef int DTSOCK;
#define DTSOCK_BAD (-1)
typedef socklen_t socklen_int_t;
#define HK_INT __attribute__((visibility("hidden")))
#else
typedef SOCKET DTSOCK;
#define DTSOCK_BAD INVALID_SOCKET
typedef int socklen_int_t;
#define HK_INT
#endif

/* Control-connection frames (one per hook instance). Game TCP streams
 * are NOT multiplexed here: every fake game TCP connection is its own
 * real TCP connection to the relay. */
#define DT_NODE 0x01   /* !H tlen + token + !I node + !H uport + !B flags */
#define DT_ASSIGN 0x02 /* !I my_virt + !I net + !B bits + !H n + n*(!I node + !I virt) */
#define DT_BCAST 0x03
#define DT_BCAST_FROM 0x04
#define DT_UDP_MODE 0x05
#define DT_UDP_TUN 0x06
#define DT_NODE_F_HOST 0x01
#define DT_PVER 3
#define DT_STOPEN 0x07 /* !I node + !I dest_node + !I sid + !H gport */
#define DT_STREQ 0x08  /* !I sid + !H gport + !I opener_virt */
#define DT_STJOIN 0x09
#define DT_STJOINED 0x0A
#define DT_STOK 0x0B
#define DT_STFAIL 0x0C
#define DT_STSHUT 0x0D
#define STF_NO_ROUTE 1
#define STF_JOIN_TIMEOUT 2
#define STF_HOST_FAILED 3
#define STF_BAD_ID 4
#define STF_BUSY 5
#define DT_ST_TIMEOUT_MS 10000
#define ST_CONNECTING 1
#define ST_OPEN 2
#define ST_DEAD 3
#define DU_VER 3
#define DU_C2S 0x01
#define DU_S2C 0x02
#define DU_PDAT 0x03
#define DU_NODE 0x04
#define DU_ICMP_REQ 0x05
#define DU_ICMP_REP 0x06

#define DT_MAXMEMB 256
#define DT_MAXSTREAM 128
#define DT_MAXUDP 128
#define DT_MAXSLOT 256
#define DT_MAXQ 64
#define DT_MAXLISTEN 32
#define DT_MAXHOST 64
#define DT_MAXUSESS 64
#define DT_MAXACC 64
#define DT_MAXEV 128
#define DT_MAXHP 32
#define DT_MAXICMP 128
#define DT_RSTMARK 255u
#define DT_ST_MAXIN (1024 * 1024)
#define DT_ST_MAXOUT (4 * 1024 * 1024)
#define SL_FATAL_NORELAY 200
#define SL_FATAL_NOLEASE 201

struct dt_chunk {
    unsigned char *p;
    size_t n, off;
    struct dt_chunk *next;
};
struct dt_dgram {
    unsigned char *p;
    size_t n;
    struct sockaddr_in from;
    struct dt_dgram *next;
};
struct dt_stream {
    int used;
    long long gsock;
    unsigned sid;
    struct sockaddr_in orig;
    struct dt_chunk *h, *t;
    size_t total;
    int dead;
    int state;
    unsigned fail;
    int in_paused;
    int connect_signaled;
    DTSOCK fd;
    int fd_live;
    struct dt_chunk *oh, *ot;
    size_t ototal;
    unsigned an_rx, an_tx;
    size_t ab_rx, ab_tx;
    long long a_log;
    int flushing;
    int sending;
    int thread_done;
    int shut_done;
    DTSOCK wake_r, wake_w;
    int ever_open;
    int peer_fin;
    int wr_shut;
    int rd_shut;
};
struct dt_udp {
    int used;
    long long gsock;
    struct dt_dgram *h, *t;
    int nq;
    int closed;
    int vport;
};
struct dt_slot {
    int used;
    long long gsock;
    int game_port;
    struct sockaddr_in orig;
};
struct dt_frame {
    unsigned char type;
    unsigned char *p;
    size_t n;
    struct dt_frame *next;
};

struct dt_hosted {
    int used;
    unsigned sid;
    DTSOCK real;
    DTSOCK fd;
    int live;
    long long last;
    int dead;
    unsigned ovirt;
    int gport;
    int lport;
    int accsp;
};
struct dt_usess {
    int used;
    int game_port;
    struct sockaddr_in cli;
    int lport;
    unsigned ovirt;
#ifdef LINUX_BUILD
    int real;
#else
    SOCKET real;
#endif
    long long last;
};
struct dt_accfd {
    int used;
    long long gsock;
    unsigned vnode;
    int lport;
    int bport;
};
#ifndef LINUX_BUILD
struct dt_evmap {
    int used;
    long long sock;
    WSAEVENT ev;
    long mask;
};
#endif
struct dt_nbtrack {
    long long sock;
    int nb;
};

#ifdef LINUX_BUILD
HK_INT extern pthread_mutex_t g_dmu;
#define DLOCK() pthread_mutex_lock(&g_dmu)
#define DUNLOCK() pthread_mutex_unlock(&g_dmu)
#else
extern CRITICAL_SECTION g_dcs;
extern int g_dcs_init;
#define DLOCK() EnterCriticalSection(&g_dcs)
#define DUNLOCK() LeaveCriticalSection(&g_dcs)
#endif

HK_INT extern int g_only_ports[64];
HK_INT extern int g_nports;
HK_INT extern char g_server[256];
HK_INT extern int g_srvport;
HK_INT extern int g_direct;
HK_INT extern int g_udp_tcp;
HK_INT extern int g_lan_only;
HK_INT extern volatile int g_claimed;
HK_INT extern unsigned char g_token[256];
HK_INT extern int g_token_len;
HK_INT extern volatile unsigned g_node;
HK_INT extern unsigned g_myvirt;
HK_INT extern unsigned char g_vnetb[4];
HK_INT extern int g_vbits;
struct dt_member {
    unsigned node, virt;
};
HK_INT extern struct dt_member g_members[DT_MAXMEMB];
HK_INT extern int g_nmembers;
HK_INT extern struct dt_stream g_st[DT_MAXSTREAM];
HK_INT extern struct dt_udp g_uq[DT_MAXUDP];
HK_INT extern struct dt_slot g_sl[DT_MAXSLOT];
HK_INT extern struct dt_frame *g_sqh, *g_sqt;
HK_INT extern volatile int g_tun_run, g_tun_started, g_tcp_up;
HK_INT extern volatile int g_have_assign;
HK_INT extern volatile int g_init_done;
HK_INT extern volatile int g_tcp_ever_up;
HK_INT extern long long g_init_t0;
HK_INT extern long long g_fatal_after_ms;
HK_INT extern DTSOCK g_tcp, g_udptun;
HK_INT extern int g_tun_conn;
HK_INT extern unsigned long g_fakeip;

HK_INT void policy_init(void);
HK_INT void dt_log_options(void);
HK_INT int port_allowed(int port);
HK_INT int ipv4_is_lan(unsigned long net_order);
HK_INT int sockaddr_is_lan_target(const struct sockaddr *sa, int *port_out);
HK_INT int ipv4_is_bcast(unsigned long net_order);
HK_INT void dt_fatal(int code, const char *msg);
HK_INT int dt_fatal_code(void);
HK_INT void dt_init_watchdog(void);
HK_INT void dt_put32(unsigned char *b, unsigned v);
HK_INT unsigned dt_get32(const unsigned char *b);
HK_INT void dt_put16(unsigned char *b, unsigned v);
HK_INT unsigned dt_get16(const unsigned char *b);

#ifndef LINUX_BUILD
HK_INT void flog(const char *m);
#endif
#endif
