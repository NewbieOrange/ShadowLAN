# Universal DLL hook: route all LAN traffic to relay

No TUN/TAP, no driver. Per-process Winsock rewrite, only the injected game.

## Two modes

**Relay mode** (no `LAN_HOOK_SERVER`): rewrites LAN/broadcast destinations
to `LAN_HOOK_RELAY` (`127.0.0.1`), where `wclient.py` listens. Needs
`wclient.py` running next to the game.

**Direct mode** (`LAN_HOOK_SERVER` set): the hook itself speaks the
`server.py` protocol over one public TCP+UDP port. **No `wclient.py`
needed** - just inject and play:
```bat
injector.exe --server HOST_PUBLIC_IP --port 47777 -- lan_hook64.dll game.exe
```
Broadcast discovery arrives as `192.168.7.1` (fake LAN server, so the game
connects back through the hook). TCP game streams and UDP game datagrams
stay on their optimal transports. Include discovery UDP ports in the
server's `--udp` list too, so unicast discovery replies get proxied.

## What it hooks

Keeps ports, rewrites IP: any `10/8`, `172.16/12`, `192.168/16`,
`169.254/16`, multicast, `*.255` / `255.255.255.255` destination goes to
the tunnel. Replies are spoofed back to the original LAN IP (`recvfrom` /
`WSARecvFrom` / `getpeername`, FIFO per socket).

Covered: `sendto`, `WSASendTo`, `recvfrom`, `WSARecvFrom` (sync),
`connect`, `WSAConnect`, `send`, `recv`, `WSASend`, `WSARecv` (sync),
`getpeername`, `closesocket`, `ioctlsocket` (nonblock tracking),
`select`, `WSAPoll` (+ Linux `poll`/`ppoll`/`pselect`), `GetProcAddress`
guard, `LoadLibrary` re-patch. Method: IAT patch, no asm blobs.

`poll`/`select` hooks are load-bearing: runtimes (incl. every socket with
a timeout) wait in `poll` and never call `recvfrom` until the fd reads
ready, so tunnel-queued data must report readable. Slices bound the extra
latency to ~25ms.

## Windows use (client PC)

Direct mode, one step (match DLL to **game** bitness):
```bat
injector.exe --server HOST_PUBLIC_IP --port 47777 -- lan_hook64.dll game.exe
REM 32-bit game on 64-bit Windows:
injector.exe --server HOST_PUBLIC_IP --port 47777 -- lan_hook32.dll game.exe
```
Relay mode (needs `wclient.py` first):
```bat
python wclient.py --server HOST_PUBLIC_IP --port 47777 --disc 4444 --tcp 27015 --udp 7777
injector.exe lan_hook64.dll game.exe
```
`injector.exe` options (set hook env for the child, game args go last):
```
[--server HOST] [--port PORT] [--relay IP] [--ports LIST] [-e KEY=VAL]... [--debug] [--]
<hook.dll> <game.exe> [game args...]
```
Also directly: `set LAN_HOOK_SERVER=...`, `LAN_HOOK_PORT` (default
`47777`), `LAN_HOOK_RELAY` (default `127.0.0.1`), `LAN_HOOK_PORTS`
(`4444,27015` to limit hooked ports), `LAN_HOOK_DEBUG=1`.

## Limits

- IPv4 only. IPv6 passes through.
- Async overlapped `WSARecvFrom`/`WSASend`/`WSARecv` pass through unspoofed
  (most LAN discovery/gameplay uses blocking calls).
- `ConnectEx` / `WSAConnectByList` / event-based (`WSAEventSelect`)
  waiting not hooked; `select`/`poll` + blocking sockets are covered.
- One server per process. No encryption; trusted peers only.
