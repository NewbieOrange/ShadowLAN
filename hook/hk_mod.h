#ifndef HK_MOD_H
#define HK_MOD_H
/* Every converted hook TU includes this so prototypes stay in one place. */
#include "hk_core.h"
#include "hk_ports.h"
#include "hk_sess.h"
#include "hk_stream.h"
#include "hk_udp.h"
#include "hk_route.h"
#ifdef LINUX_BUILD
#include "hk_linux.h"
#else
#include "hk_win.h"
#endif
#endif
