/* Universal LAN->relay hook. Windows DLL + Linux LD_PRELOAD test build.
 *
 * Direct-tunnel mode (needs LAN_HOOK_SERVER): game traffic to LAN IPs is
 * tunneled to the ShadowLAN relay. Without LAN_HOOK_SERVER the hook is a
 * pure passthrough. Hosting games stamp a host claim via listen() (a
 * link-ordering hint, never an election).
 *
 * No TUN/TAP, no driver, no admin. Per-process: only the injected game
 * is affected.
 *
 * Layout: each hk_*.c is its own translation unit. Shared types and
 * tables live in hk_core.h / hk_core.c. Platform interceptors are
 * hk_linux.c (LD_PRELOAD) or the four hk_win*.c files (IAT). This root
 * holds only the version stamp (pair: common.py VERSION).
 */

#include "hk_version.h"

/* Version stamp #1 of 2. rc stamps stay UNCOMMITTED. */
const char shadowlan_version[] = SHADOWLAN_VERSION;
