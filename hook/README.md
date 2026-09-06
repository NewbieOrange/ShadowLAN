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
`LoadLibrary` re-patch. Method: IAT patch, no asm blobs.

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
ports), `LAN_HOOK_DEBUG=1`.

## Limits

- IPv4 only. IPv6 passes through.
- Async overlapped `WSARecvFrom`/`WSASend`/`WSARecv` pass through unspoofed
  (most LAN discovery/gameplay uses blocking calls).
- `ConnectEx` / `WSAConnectByList` / event-based (`WSAEventSelect`)
  waiting not hooked.
- One game per relay port; `--token` is the room key.
