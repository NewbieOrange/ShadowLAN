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
all), `LAN_HOOK_NOCHILD=1` (never inject children).

## Sub-processes

Injection follows `CreateProcessA/W`: a hooked launcher that spawns the
real game (launcher tools, plugin loaders, …) gets each child suspended,
injected, initialized and resumed automatically — env included, so the
room config carries over. Same-bitness only; failures launch unhooked
rather than breaking the game. (On Linux this is free: `LD_PRELOAD` is
inherited — covered by a local parent-spawns-sender inheritance test.)

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
