# lan_hook — universal game hook (Windows + Linux)

No TUN/TAP, no driver. Per-process socket-layer rewrite; only the injected
game is affected. Needs `LAN_HOOK_SERVER` (a ShadowLAN relay), otherwise it
is a pure passthrough. One source builds both the Windows DLL and the Linux
`LD_PRELOAD` `.so` (same behavior; tested on Linux, shipped for Windows).

## Modes (automatic)

- **Player:** LAN/broadcast destinations tunnel to the relay; beacons come
  back attributed per sender, so browsers list distinct servers.
- **Host:** when the game calls `listen()`, the hook claims designated-host
  on the relay and bridges inbound players to the game over loopback.
  No flags needed — hosting in-game is enough.
- **P2P mesh:** the relay assigns every node a virtual LAN IP
  (`--subnet`, default `10.200.0.0/24`). The hook routes `sendto`/`connect`
  to virtual IPs to the owning node and spoofs `recvfrom`/`getpeername`
  sources with the sender's virtual IP, so each peer looks like its own
  machine on the same LAN.

## TCP streams

Every fake game TCP connection is ONE real TCP connection to the relay
opened by the process itself (both peers dial out, so NATs never block a
stream; no driver, no inbound ports). The control connection carries only
membership, beacons and UDP-over-TCP datagrams, so a stalled stream can
never head-of-line-block discovery or other streams.

- `connect()` to a vnet/LAN address only returns success after the relay
  confirms the destination actually bridged the stream to its local game
  (STOPEN → STREQ → STJOIN → claim → STJOINED → STOK, 10s budget). With
  a shared process-tree identity the STREQ goes to every sibling and the
  relay answers each JOIN with a claim (`OK`/`BUSY`) before anything
  touches the local game port. Nonblocking
  sockets get `WSAEWOULDBLOCK` + a later `FD_CONNECT`/writable, like a
  real in-flight connect; a refused/unreachable target fails the connect
  with `WSAECONNREFUSED`/`WSAETIMEDOUT`.
- After the handshake, bytes pipe raw on the per-stream TCP with kernel
  backpressure both ways (full relay buffer blocks the sender; the local
  game not reading backpressures the relay). UDP hook queues drop the NEW
  datagram when full, like a real UDP rx buffer.
- The process's vnet IP is also exposed as a standalone pseudo-adapter
  ("ShadowLAN Virtual Interface", up, /24) in `GetAdaptersAddresses`/
  `GetAdaptersInfo`, so apps that compute per-interface broadcast ranges
  or sanity-check peers against local subnets see the vnet exactly like a
  real LAN interface. With `LAN_HOOK_LAN_ONLY=1` these APIs return the
  pseudo-adapter *alone* (physical NICs hidden).

## Covered calls

`sendto`, `WSASendTo`, `recvfrom`, `WSARecvFrom` (sync), `connect`,
`WSAConnect`, `send`, `recv`, `WSASend`, `WSARecv` (sync), `listen`,
`getpeername`, `closesocket`, `ioctlsocket` (nonblock tracking), `select`,
`WSAPoll` (+ Linux `poll`/`ppoll`/`pselect`), `GetProcAddress` guard,
`LoadLibrary` re-patch: every patched module's `LoadLibrary*` imports are
swapped too, plus a slow differential module sweep as a safety net, so
plugin DLLs loaded long after install (game engines do this) are hooked.
Shared UDP discovery ports are emulated: if a bind fails because another
local socket owns the port, the hook binds ephemerally and aliases the
socket to the requested port, matching `SO_REUSEADDR` broadcast semantics.
Addressed datagrams with no prior session (a unicast reply to a broadcast
query, a first join packet) are delivered to every socket listening on
that game port, as a real NIC would. Method: IAT patch, no asm blobs.
ICMP ping rides the UDP tunnel as addressed echo request/reply frames:
raw/ICMP sockets on both OSes plus `IcmpSendEcho`/`IcmpSendEcho2` on
Windows (its event is signaled; the APC routine is not queued). The relay
answers at `.1` of the subnet and routes peer pings by node; self-pings
and subnet-broadcast pings are answered locally, and the relay never
echoes a packet back to its sender — loopback is always client-side,
exactly like a NIC.
Unfriendly NAT? `LAN_HOOK_UDP_OVER_TCP=1` (injector `--udp-over-tcp`) sends game
datagrams over the existing TCP link instead of inbound UDP (UDP
keepalives still go out so the relay keeps a fresh return mapping).
Opt-in per peer; mixed rooms interoperate; costs head-of-line blocking of
those datagrams (TCP streams are unaffected — they ride their own
connections), so leave it off when plain UDP works.

`poll`/`select` hooks are load-bearing: runtimes (incl. every socket with
a timeout) wait in `poll` and never call `recvfrom` until the fd reads
ready, so tunnel-queued data must report readable. Slices bound the extra
latency to ~25ms.

## Use

Match DLL to **game** bitness:

```bat
injector.exe --server RELAY_IP --port 47777 --token SECRET -- lan_hook64.dll game.exe
REM 32-bit game on 64-bit Windows:
injector.exe --server RELAY_IP --port 47777 --token SECRET -- lan_hook32.dll game.exe
```

Linux (no launcher needed):

```sh
LD_PRELOAD=./lan_hook.so LAN_HOOK_SERVER=RELAY_IP LAN_HOOK_PORT=47777 LAN_HOOK_TOKEN=SECRET ./game
```

Env (or injector flags): `LAN_HOOK_SERVER`, `LAN_HOOK_PORT` (default
`47777`), `LAN_HOOK_TOKEN`, `LAN_HOOK_PORTS` (`4444,27015` to limit hooked
ports), `LAN_HOOK_DEBUG=1`, `LAN_HOOK_LOGFILE=C:\hook.log` (appended log),
`LAN_HOOK_MODULES=game.exe,unityplayer.dll` (patch only these),
`LAN_HOOK_CHILDREN=lobby.exe,game.exe` (inject only these children, empty =
all), `LAN_HOOK_NOCHILD=1` (never inject children),
`LAN_HOOK_LAN_ONLY=1` (**ShadowLAN only**: the process behaves like a
machine whose only network is the tunnel — connects/sendto to any public
address fail instantly with `WSAENETUNREACH`/`ENETUNREACH` (no route),
inbound wire datagrams and LAN TCP peers are not delivered (loopback
stays fully functional for the local bridge), and the IP-Helper adapter
APIs report the ShadowLAN pseudo-interface as the ONLY interface — no
physical NIC, no real-LAN IPs or beacons visible. Discovery and mesh
traffic ride the tunnel exactly as before. Great for clean repros; not
needed for normal play.),
`LAN_HOOK_NODE=709102507` (force a node id — the hook sets this in its own
environment automatically, so children inherit one identity per process
tree; set it manually to merge separate launches into one virtual host),
`LAN_HOOK_LEASE_WAIT=3000` (game startup
waits up to N ms until the relay grants our address lease — installing means
playing *on* ShadowLAN; `0` skips the wait, `-1` waits indefinitely.
A missing lease is fatal: messagebox (Windows) or stderr (Linux) and the
game exits with code 200 (relay unreachable) or 201 (no lease).
`LAN_HOOK_INIT_TIMEOUT=30000` bounds the watchdog the same way (`0` disables).

## Sub-processes

Injection follows `CreateProcessA/W`: a hooked launcher that spawns the
real game (launcher tools, plugin loaders, …) gets each child suspended,
injected, initialized and resumed automatically — env included, so the
room config carries over. Same-bitness only; failures launch unhooked
rather than breaking the game. (On Linux this is free: `LD_PRELOAD` is
inherited — covered by a local parent-spawns-sender inheritance test.)

## Process-tree identity (one vnode per tree)

The whole tree shares **one virtual IP**: the first hooked process picks
a node id, publishes it into its own environment (`LAN_HOOK_NODE`), and
every descendant inherits it — the relay then keeps one node with one
vnode and a list of live links, fanning beacons, memberships and stream
requests to all of them. There is deliberately no "who is last"
bookkeeping: the identity's lifetime is the environment copy the kernel
already manages per process tree (Windows `CreateProcess` copies it; on
Linux `execve` inherits it), just like a kernel-created file mapping
dies with its last handle. Consequences you can rely on:

- a launcher self-restart chain (e.g. GBE's `RestartAppIfNecessary`)
  keeps the same vnode across the restart;
- tool + game on one PC are one "machine" to peers (distinct apps are
  still distinct GBE/steamid connections — exactly like real LAN);
- a process started with a fresh environment (double-clicked, different
  service) is a different machine — unrelated instances stay separate.

`LAN_HOOK_NODE=709102507` forces an id (merge separate launches into one
host if you ever need to). Inbound streams to a shared node are claimed
first-come: every sibling gets the request, the one whose local game
actually listens bridges it, the others stand down (relay answers the
JOIN claim `OK`/`BUSY` before anyone touches the local port).

## Troubleshooting

**Game crashes or hangs at startup.** Capture a log first (no quotes around
the path — `set` keeps them as part of the value):

```bat
set LAN_HOOK_LOGFILE=C:\hook.log
injector.exe --server RELAY_IP --port 47777 --token SECRET --debug -- lan_hook64.dll game.exe
```

The tail shows how far init got (`enter` → `resolving imports` →
`policy ready` → `starting tunnel` → `patching modules` →
`patched N modules` → `installed`). The file opens first thing in init;
unset or empty means no file logging at all. A guarded fault still drops
`lan_hook_<pid>.dmp` next to the game binary with the exact crash address.
Common causes:

- Wrong bitness: 32-bit game needs `lan_hook32.dll` (check Task Manager →
  Details → Platform column).
- Host machine must not drop inbound UDP: the relay forwards addressed
  game datagrams back to each player's ephemeral tunnel port. If one-way
  traffic appears (broadcasts arrive, unicast answers do not), allow the
  game and tool executables through the firewall for UDP, e.g.
  `netsh advfirewall firewall add rule dir=in action=allow protocol=UDP
  program="C:\path\to\game.exe" name="ShadowLAN"`.
- A specific DLL misbehaving: restrict patching with
  `set LAN_HOOK_MODULES=game.exe,unityplayer.dll` (substring list).
- Anti-tamper: some titles fault when imports change; the hook skips
  unreadable modules automatically — the log names them.

**`server=(unset)` in the injector line.** Upgrade `injector.exe`
(pre-`--token` builds neither parse nor display it). Values shown come
from the live environment; the game inherits them regardless.

**Nothing happens after inject.** The game may not use LAN sockets at all
(many "co-op" titles are online-only). Confirm with a Wireshark loopback
capture: no UDP broadcasts / LAN connects = nothing to tunnel.

## Limits

- IPv4 only. IPv6 passes through.
- Async overlapped `WSARecvFrom`/`WSASend`/`WSARecv` pass through unspoofed
  (most LAN discovery/gameplay uses blocking calls).
- `ConnectEx` / `WSAConnectByList` / event-based (`WSAEventSelect`)
  waiting not hooked.
- One game per relay port; `--token` is the room key.
