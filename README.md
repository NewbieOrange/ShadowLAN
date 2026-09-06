# ShadowLAN

Play broadcast-only LAN co-op games online, on Windows **and** Linux. One dedicated relay on a VPS hands every player a virtual LAN IP — any player can host, the rest just join. No TUN/TAP, no virtual NIC, no driver, no admin.

- Relay + client are plain Python 3.10+ (stdlib only), identical on both OSes
- Per-game network hook: Windows DLL (`lan_hook64/32.dll`) or Linux `LD_PRELOAD` (`lan_hook.so`)
- One public port on the relay (TCP+UDP); players need no port forwarding
- Discovery broadcast, game TCP and game UDP all tunneled; UDP stays UDP
- P2P mesh: each node appears at its own virtual IP (default `10.200.0.0/24`)

## How it works

1. Each node registers with the relay (`NODE` + token room) and gets a stable virtual IP.
2. Discovery broadcasts fan out with sender identity; games see distinct servers at distinct IPs.
3. Joins go to explicit destinations: addressed TCP opens and UDP datagrams route by node; legacy traffic falls back to designated-host → beaconer → learned-replier routing.
4. The hosting node bridges tunnel traffic to its local game at `127.0.0.1` — via `wclient --host`, or the hook, which auto-claims when the game calls `listen()`.

## Quickstart

Relay (any Linux/Windows box with a public IP, forward TCP+UDP `47777`):

```sh
python server.py --port 47777 --token SECRET --subnet 10.200.0.0/24
```

Hosting player (the PC running the game server):

Windows:
```bat
injector.exe --server RELAY_IP --port 47777 --token SECRET -- lan_hook64.dll game.exe
```

Linux, or Windows without the hook:
```sh
python wclient.py --server RELAY_IP --port 47777 --disc 4444 --host --token SECRET
```

Linux hook instead of `wclient` (same thing the DLL does, via `LD_PRELOAD`):
```sh
LD_PRELOAD=./lan_hook.so LAN_HOOK_SERVER=RELAY_IP LAN_HOOK_PORT=47777 LAN_HOOK_TOKEN=SECRET ./game
```

Joining players (same binaries, no flags beyond the room):

```bat
injector.exe --server RELAY_IP --port 47777 --token SECRET -- lan_hook64.dll game.exe
```

```sh
python wclient.py --server RELAY_IP --port 47777 --disc 4444 --tcp 27015 --udp 7777 --token SECRET
```

Then the host starts the LAN game, everyone else opens the LAN browser and joins. Find the game's ports once with Wireshark (`udp.dstport`, `tcp.dstport`) or `netstat -ano` / `ss -tunap`: discovery UDP, game TCP/UDP. Include discovery UDP ports in `--udp` too if that title uses unicast discovery replies. One game per relay port; run more relays on more ports for more parties.

## Injector options (Windows)

```bat
injector.exe [--server HOST] [--port PORT] [--token SECRET] [--ports LIST] [-e KEY=VAL]... [--debug] [--]
<hook.dll> <game.exe> [game args...]
```

Without `--server` the hook is a passthrough. Also honored as env (both OSes): `LAN_HOOK_SERVER`, `LAN_HOOK_PORT` (default `47777`), `LAN_HOOK_TOKEN`, `LAN_HOOK_PORTS` (`4444,27015` to limit hooked ports), `LAN_HOOK_DEBUG=1`. Match the DLL to the **game** bitness (`lan_hook32.dll` for 32-bit games).

## Layout

- `server.py` — dedicated relay only: membership, virtual-IP assignment, addressed + fallback routing
- `wclient.py` — symmetric client: player proxy and/or `--host` bridge, node registration
- `common.py` — shared framing
- `hook/lan_hook.c` — universal hook (Windows DLLs + Linux `.so` test/LD_PRELOAD build)
- `hook/injector.c` — Windows launcher (`injector.exe`)
- `game.example.json` — config template

## Build the hook

```sh
make -C hook all        # DLLs + injector.exe (mingw) + lan_hook.so
```

On Windows with MinGW: `hook/build.bat`. Run hook tests with `make -C hook test`.

## Tests

```sh
python3 test_e2e.py               # relay + wclient host + wclient player (ALL PASS)
python3 test_relay_topology.py   # host migration incl. demote-keeps-link (MIGRATE_ALL_PASS)
python3 hook/test_direct.py      # symmetric hook host+join (DIRECT_ALL_PASS)
python3 hook/test_virtual_p2p.py # 3-node virtual-IP mesh (P2P_ALL_PASS)
```

## Limits

- IPv4 only; IPv6 passes through untouched
- One game per relay port; `--token` is the room key (empty = open relay)
- No encryption — trusted peers only (or wrap in WireGuard)
- Async overlapped Winsock and `ConnectEx`/`WSAEventSelect` waiting are not hooked; blocking sockets and `select`/`poll` are
- Full per-peer virtual-IP attribution needs the hook; `wclient` re-emits beacons with its own source
- Games embedding a private IP inside the discovery payload (instead of dialing the broadcast source) need a per-title payload rewrite
