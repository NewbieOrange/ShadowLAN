#ifndef HK_PORTS_H
#define HK_PORTS_H
#include "hk_core.h"

HK_INT extern int g_lports[DT_MAXLISTEN];
HK_INT extern DTSOCK g_wake_r, g_wake_w;
#ifndef LINUX_BUILD
HK_INT extern struct dt_nbtrack g_nbt[DT_MAXUDP + DT_MAXSTREAM];
#endif

HK_INT void dt_record_listen(int port);
HK_INT int dt_owns_listen(int port);
HK_INT int dt_bound_port(long long gsock);
HK_INT int dt_sock_type(long long gsock);
HK_INT int dt_rcvtimeo_ms(long long gsock);
HK_INT int dt_is_nonblock(long long gsock);
#ifndef LINUX_BUILD
HK_INT void dt_set_nonblock(long long gsock, int nb);
#endif
HK_INT void dt_wake_write(DTSOCK w);
HK_INT void dt_wake_drain(DTSOCK rd);
HK_INT void dt_wake_pair(DTSOCK *rp, DTSOCK *wp);
HK_INT void dt_tcp_queue(unsigned char type, const unsigned char *p, size_t n);
HK_INT size_t dt_token_prefix(unsigned char *out);
HK_INT void dt_claim(void);
HK_INT int dt_tun_udp_port(void);
HK_INT void dt_send_node(void);
HK_INT void dt_send_udp_node(void);
HK_INT unsigned dt_ipnum(const unsigned char *b);
HK_INT void dt_apply_assign(const unsigned char *p, size_t n);
HK_INT unsigned dt_virt_node(unsigned long inaddr);
HK_INT unsigned dt_node_virt(unsigned node);
#endif
