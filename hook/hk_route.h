#ifndef HK_ROUTE_H
#define HK_ROUTE_H
#include "hk_core.h"

HK_INT int dt_on_connect(long long gsock, const struct sockaddr_in *dst);
HK_INT int dt_stream_send(long long gsock, const unsigned char *buf, size_t len);
HK_INT void dt_stream_send_err(int r);
HK_INT int dt_stream_send_wait(long long s, const unsigned char *buf, size_t len);
HK_INT int dt_stream_pop(long long gsock, unsigned char *buf, size_t blen, size_t *outn);
HK_INT int dt_getpeer(long long gsock, struct sockaddr_in *out);
HK_INT int dt_udp_has(long long gsock);
HK_INT int dt_stream_has(long long gsock);
HK_INT void dt_udp_ensure(long long gsock);
HK_INT void dt_stream_mark_connect(long long gsock);
HK_INT int dt_fd_readable(long long gsock);
HK_INT void dt_on_close(long long gsock);
HK_INT int dt_tcp_wait(long long gsock, unsigned char *buf, size_t blen, size_t *outn,
                       int timeout_ms, int nonblock);
#endif
