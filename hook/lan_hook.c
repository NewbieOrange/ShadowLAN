/* Universal LAN->relay hook. Windows DLL + Linux LD_PRELOAD test build.
 *
 * Direct-tunnel mode (needs LAN_HOOK_SERVER): game traffic to LAN IPs is
 * tunneled to the ShadowLAN relay - TCP streams multiplexed over one TCP
 * link, game UDP over UDP, discovery over either. Without LAN_HOOK_SERVER
 * the hook is a pure passthrough. Hosting games stamp a host claim via
 * listen() (a link-ordering hint, never an election: implicit dials ask
 * every machine, only the listener answers); all peers get virtual LAN
 * IPs for P2P mesh play.
 *
 * No TUN/TAP, no driver, no admin. Per-process: only the injected game
 * is affected.
 *
 * Windows: IAT patch (no asm blobs) + GetProcAddress/LoadLibrary guards.
 *
 * Layout: hk_util.c / hk_alias.c / hk_ledger.c are independent modules
 * sharing ONLY the hk_api.h interface. Everything else - this root plus
 * the hk_*.inc fragments - forms ONE translation unit (the core shares
 * the static state graph; fragment order is load-bearing, see the note
 * at the include list). Build from the hook directory: `make` (cross-
 * builds both DLLs from Linux with mingw) or build.bat on Windows.
 */

#include "hk_plat.h"
#include "hk_api.h"

/* Version stamp #1 of 2 (pair: common.py VERSION); both move together in
 * a dedicated bump commit. rc stamps stay UNCOMMITTED. */
#define SHADOWLAN_VERSION "2.0.0"

/* Implementation split: hk_util/hk_alias/hk_ledger are independent TUs
 * (interface: hk_api.h). The remaining .inc fragments form ONE
 * translation unit with this root - they share the static state graph
 * and are order-dependent; do not reorder or compile standalone. */
#include "hk_policy.inc"
#include "hk_ports.inc"
#include "hk_sess.inc"
#include "hk_stream.inc"
#include "hk_udp.inc"
#include "hk_route.inc"
#include "hk_linux.inc"
#include "hk_winsock.inc"
#include "hk_wicmp.inc"
#include "hk_winnic.inc"
#include "hk_wininst.inc"
