#ifndef HK_LINUX_H
#define HK_LINUX_H
#include "hk_core.h"

#ifdef LINUX_BUILD
HK_INT extern int (*r_connect)(int, const struct sockaddr *, socklen_t);
HK_INT extern int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
HK_INT extern int (*real_getsockopt)(int, int, int, void *, socklen_t *);
HK_INT extern ssize_t (*r_send)(int, const void *, size_t, int);
HK_INT extern ssize_t (*r_recv)(int, void *, size_t, int);
HK_INT extern ssize_t (*r_sendto)(int, const void *, size_t, int, const struct sockaddr *,
                                  socklen_t);
HK_INT extern int (*r_close)(int);
HK_INT extern int (*r_bind)(int, const struct sockaddr *, socklen_t);

HK_INT void dt_reals(void);
#endif
#endif
