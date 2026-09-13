#ifndef HK_STREAM_H
#define HK_STREAM_H
#include "hk_core.h"

HK_INT void dt_flush_streams(void);
HK_INT void dt_on_streq(unsigned sid, int gport, unsigned ovirt);
HK_INT void dt_start(void);
HK_INT void dt_udp_ingress(const unsigned char *buf, size_t n);
HK_INT unsigned dt_next_sid(void);
HK_INT int dt_src_ip(char *out, size_t n);
HK_INT void dt_tun_setup(DTSOCK s);
HK_INT void dt_udp_tun_send(const unsigned char *d, size_t n);
HK_INT void dt_log_wire_drop(unsigned long net_order);
HK_INT int ipv4_is_loopback(unsigned long net_order);
HK_INT int ipv4_is_local(unsigned long net_order);
HK_INT int dt_machine_ip(char *out, int n);

#ifdef LINUX_BUILD
HK_INT void dt_st_spawn(void *(*fn)(void *), void *arg);
HK_INT void *dt_stream_thread(void *u);
HK_INT void *dt_join_thread(void *u);
#else
HK_INT void dt_st_spawn(LPTHREAD_START_ROUTINE fn, void *arg);
HK_INT DWORD WINAPI dt_stream_thread(LPVOID u);
HK_INT DWORD WINAPI dt_join_thread(LPVOID u);
#endif
#endif
