#ifndef HK_UDP_H
#define HK_UDP_H
#include "hk_core.h"

HK_INT int dt_is_icmp_sock(long long gsock);
HK_INT int dt_is_udp_like(long long gsock);
HK_INT unsigned dt_relay_virt(void);
HK_INT int dt_in_vnet(unsigned long inaddr);
HK_INT int dt_is_vnet_bcast(unsigned long inaddr);
HK_INT size_t dt_icmp_build_rep(unsigned char *out, unsigned id, unsigned seq,
                                const unsigned char *data, size_t dlen);
HK_INT void dt_icmp_send_req(unsigned dest, unsigned id, unsigned seq, const unsigned char *data,
                             size_t dlen);
HK_INT void dt_icmp_in(unsigned is_rep, unsigned src, unsigned dest, unsigned id, unsigned seq,
                       const unsigned char *data, size_t dlen);
HK_INT void dt_hosted_unsource(struct sockaddr *sa, socklen_int_t *len);
HK_INT int dt_reject_wire4(const struct sockaddr_in *dst);
HK_INT int dt_sport_presentation(long long gsock);
HK_INT int dt_on_sendto(long long gsock, const unsigned char *buf, size_t len,
                        const struct sockaddr_in *dst);
HK_INT struct dt_stream *dt_stream_alloc(long long gsock, const struct sockaddr_in *dst,
                                         unsigned *sid_out);
HK_INT int dt_is_dial_local(unsigned vnode);
#endif
