# ShadowLAN

Play broadcast-only Windows LAN co-op games online. The host exposes **one port** (TCP+UDP); the client connects to `IP:port`; the game sees a fake LAN.

- No TUN/TAP, no virtual NIC, no WinDivert/WFP driver, no admin
- Per-game: only the injected game is affected, rest of the PC is untouched
- Python relay (stdlib only) + universal Windows DLL hook (`lan_hook64/32.dll`)
- Discovery broadcast, game TCP and game UDP all tunneled; UDP stays UDP

## How it works

1. Host's `server.py` snoops local discovery broadcasts via `SO_REUSEADDR` socket shadowing and forwards them over the public TCP link.
2. Client re-broadcasts them to `255.255.255.255`, so the game believes a LAN server is present.
3. The game connects to the relay; game TCP is multiplexed over public TCP `IP:P`, game UDP over public UDP `IP:P`.
4. Host forwards everything to `127.0.0.1:G` where the real game listens.
5. Games with exclusive binds or hardcoded LAN IPs use the DLL hook instead: it rewrites LAN destinations into the tunnel in-process and spoofs replies back, including `poll`/`select` wakeups so timeout-based discovery works.

## Quickstart

Pick one free port, e.g. `47777`. Forward **TCP+UDP 47777** to the host PC (or allow it in the firewall if the public IP is on the host).

Find the game's ports once with Wireshark (`udp.dstport`, `tcp.dstport`) or `netstat -ano`: discovery UDP `D`, game TCP `T`, game UDP `U`.

Host (next to the game server, Linux or Windows):

```bat
python server.py --port 47777 --disc 4444 --tcp 27015 --udp 7777
```

Client, easiest path — direct hook, no relay process (match DLL to **game** bitness):

```bat
injector.exe --server HOST_PUBLIC_IP --port 47777 -- lan_hook64.dll game.exe
```

Alternative client path — relay process (needs the game to use reusable UDP binds):

```bat
python wclient.py --server HOST_PUBLIC_IP --port 47777 --disc 4444 --tcp 27015 --udp 7777
```

Then host starts the LAN game, client opens the LAN browser, joins. Include discovery UDP ports in `--udp` too if that title uses unicast discovery replies.

## Injector options

```bat
injector.exe [--server HOST] [--port PORT] [--relay IP] [--ports LIST] [-e KEY=VAL]... [--debug] [--] <hook.dll> <game.exe> [game args...]
```

`--server` selects direct-tunnel mode; without it the hook rewrites to `LAN_HOOK_RELAY` (`127.0.0.1`) for `wclient.py`. Also honored as env: `LAN_HOOK_SERVER`, `LAN_HOOK_PORT` (default `47777`), `LAN_HOOK_RELAY`, `LAN_HOOK_PORTS` (`4444,27015` to limit hooked ports), `LAN_HOOK_DEBUG=1`.

## Layout

- `server.py` — host relay: public TCP+UDP on one port, broadcast snoop, TCP/UDP proxy to `127.0.0.1`
- `wclient.py` — Windows relay client (stdlib only)
- `common.py` — shared framing
- `hook/lan_hook.c` — universal DLL (`lan_hook64.dll`/`lan_hook32.dll`, plus Linux `lan_hook.so` test build)
- `hook/injector.c` — launcher (`injector.exe`)
- `game.example.json` — config template

## Build the hook

Linux cross-build (also builds the test `.so`):

```sh
make -C hook all
```

On Windows with MinGW: `hook/build.bat`.

## Tests

```sh
python3 test_e2e.py        # relay path: discovery + TCP + UDP (ALL PASS)
python3 hook/test_hook.py  # hook rewrite + spoof (HOOK_ALL_PASS)
python3 hook/test_direct.py # hook straight to server.py, no relay (DIRECT_ALL_PASS)
```

## Limits

- IPv4 only; IPv6 passes through untouched
- 1 host + 1 client focused; discovery fans out, UDP sessions keyed per endpoint
- No encryption — trusted peers only (or wrap in WireGuard)
- Async overlapped Winsock and `ConnectEx`/`WSAEventSelect` waiting are not hooked; blocking sockets and `select`/`poll` are
- Games embedding a private IP inside the discovery payload (instead of dialing the broadcast source) need a per-title payload rewrite
