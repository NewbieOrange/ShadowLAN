#ifndef HK_SESS_H
#define HK_SESS_H
#include "hk_core.h"

HK_INT extern struct dt_hosted g_hs[DT_MAXHOST];
HK_INT extern struct dt_usess g_us[DT_MAXUSESS];
HK_INT extern struct dt_accfd g_acc[DT_MAXACC];
#ifndef LINUX_BUILD
extern struct dt_evmap g_evmap[DT_MAXEV];
#endif

HK_INT struct dt_hosted *dt_hs_by_sid(unsigned sid);
HK_INT void dt_hs_close(unsigned sid);
HK_INT int dt_bind_alias(long long s, const struct sockaddr_in *want, int is_dgram,
                         int (*binder)(int, const struct sockaddr *, socklen_t));
HK_INT int dt_host_bridge(unsigned sid, int port);
HK_INT void dt_acc_learn_fd(long long fd, const struct sockaddr_in *peer, int listen_port);
HK_INT int dt_acc_get(long long fd, struct sockaddr_in *out, int *rlport);
HK_INT void dt_acc_self_view(long long fd, struct sockaddr_in *sa);
HK_INT void dt_acc_forget(long long fd);
HK_INT void dt_acc_post_accept(long long fd, struct sockaddr *addr, socklen_int_t *addrlen,
                               const struct sockaddr_in *real_peer);
HK_INT struct dt_usess *dt_usess_find(int game_port, const unsigned *ovirt,
                                      const struct sockaddr_in *cli, int create);
HK_INT int dt_hosted_udp_in(int game_port, const unsigned char *ipb, int iplen, int cport,
                            const unsigned char *raw, size_t rl);
HK_INT void dt_direct_udp_in(int game_port, const unsigned char *ipb, int iplen,
                             const unsigned char *raw, size_t rl);
#ifndef LINUX_BUILD
HK_INT void dt_obsv(const char *dir, long long s, const struct sockaddr *a, const unsigned char *p,
                    int n);
#endif
HK_INT struct dt_stream *dt_stream_by_sock(long long s);
HK_INT struct dt_stream *dt_stream_by_sock_peeked(struct sockaddr_in dst);
HK_INT struct dt_stream *dt_stream_by_sid(unsigned sid);
HK_INT struct dt_udp *dt_udp_entry(long long s, int create);
HK_INT void dt_sock_state_locked(long long gsock, int *data, int *dead, int *writable,
                                 int *connect);
HK_INT void dt_sock_state_full(long long gsock, int *data, int *dead, int *writable, int *connect);
HK_INT void dt_sig_locked(long long gsock);
#ifndef LINUX_BUILD
HK_INT void dt_ev_unhook_sock(long long sock);
HK_INT void dt_ev_unhook_ev(WSAEVENT ev);
#endif
HK_INT void dt_udp_push(long long gsock, const unsigned char *p, size_t n,
                        const struct sockaddr_in *from);
HK_INT size_t dt_inq_count_locked(struct dt_stream *st);
HK_INT int dt_stream_by_sock_peek(long long gsock);
HK_INT int dt_udp_pop(long long gsock, unsigned char *buf, size_t blen, struct sockaddr_in *from,
                      size_t *outn);
HK_INT struct dt_slot *dt_slot_get(long long gsock, int game_port, const struct sockaddr_in *orig);
HK_INT int dt_resolve(struct sockaddr_in *out);
HK_INT int dt_send_all(DTSOCK s, const unsigned char *b, size_t n);
HK_INT int dt_recv_all(DTSOCK s, unsigned char *b, size_t n);
HK_INT void dt_dispatch_bcast_from(unsigned node, int port, int sport, const unsigned char *raw,
                                   size_t n);
HK_INT void dt_dispatch_bcast(int port, int sport, const unsigned char *raw, size_t n);
#endif
