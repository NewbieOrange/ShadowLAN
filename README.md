# ShadowLAN

Play broadcast-only LAN co-op games online, on Windows **and** Linux. One dedicated relay on a VPS hands every player a virtual LAN IP — any player can host, the rest just join. No TUN/TAP, no virtual NIC, no driver, no admin.

- Relay + client are plain Python 3.10+ (stdlib only), identical on both OSes
- Per-game network hook: Windows DLL (`lan_hook64/32.dll`) or Linux `LD_PRELOAD` (`lan_hook.so`)
- One public port on the relay (TCP+UDP); players need no port forwarding
- Discovery broadcast, game TCP and game UDP all tunneled; UDP stays UDP
- P2P mesh: each node appears at its own virtual IP (default `10.200.0.0/24`)
- One virtual IP per process tree: a game with launcher children and
  self-restarts shares a single node/vnode (the identity travels to
  children through the inherited environment); the relay fans traffic to
  all live links of a node, and an inbound stream is claimed by whichever
  sibling actually listens on the game port — no ghost nodes, no restart
  churn, no "who is last" bookkeeping
- Game TCP is per-connection: each fake game `connect()` is its own real TCP
  to the relay (both peers dial out — NAT-safe), piped raw once the host has
  bridged to its local game. A stalled stream can't head-of-line-block
  discovery or other streams, and `connect()` only succeeds after the relay
  confirms the peer accepted (real connect semantics; 10s budget).
- The vnet IP is also presented as a standalone pseudo-adapter
  ("ShadowLAN Virtual Interface") via the GetAdapters* APIs, so apps that
  derive their own IP / per-interface broadcast / peer-subnet sanity checks
  see the vnet like a real LAN interface.
- ICMP ping across the mesh: the relay answers at `10.200.0.1`, peers answer
  at their virtual IPs (raw sockets everywhere, plus `IcmpSendEcho` on Windows)
- UDP-over-TCP option (`--udp-over-tcp` / `LAN_HOOK_UDP_OVER_TCP=1`): game datagrams ride
  the control TCP link when a peer sits behind a NAT/firewall that filters inbound UDP.
  Opt-in per peer (costs head-of-line blocking for those datagrams only); mixed rooms interoperate.
- Fail-fast startup: no relay link or no address lease aborts the game with a
  visible error (exit `200`/`201`) instead of running broken; the relay never
  echoes a packet back to its sender (loopback is always client-side)

## How it works

1. Each node registers with the relay (`NODE` + token room) and gets a stable virtual IP. All processes of one game tree register the same node id (inherited `LAN_HOOK_NODE`), so a tree is exactly one virtual machine.
2. Discovery broadcasts fan out with sender identity; games see distinct servers at distinct IPs.
3. Joins go to explicit destinations: addressed TCP opens and UDP datagrams route by node (per-dest flows, so identical LAN triples to different hosts don't collide); implicit (unaddressed) traffic falls back to designated-host → beaconer → per-sender sticky-replier routing. A new host claim only steers NEW implicit joins — live streams keep flowing to their original targets. Node-targeted traffic reaches every live link of the node; a stream JOIN is claimed by exactly one sibling (`OK`/`BUSY` answer before the local bridge).
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

Then the host starts the LAN game, everyone else opens the LAN browser and joins. Find the game's ports once with Wireshark (`udp.dstport`, `tcp.dstport`) or `netstat -ano` / `ss -tunap`: discovery UDP, game TCP/UDP. Include discovery UDP ports in `--udp` too if that title uses unicast discovery replies. One game per relay port is still the supported setup (run more relays on more ports for more parties); if two hosts do claim the same port, live sessions now survive and only new implicit joins follow the newest claim, while addressed (hook virtual-IP) sessions stay per-dest isolated.

## Injector options (Windows)

```bat
injector.exe [--server HOST] [--port PORT] [--token SECRET] [--ports LIST] [-e KEY=VAL]... [--debug] [--]
<hook.dll> <game.exe> [game args...]
```

Without `--server` the hook is a passthrough. Also honored as env (both OSes): `LAN_HOOK_SERVER`, `LAN_HOOK_PORT` (default `47777`), `LAN_HOOK_TOKEN`, `LAN_HOOK_PORTS` (`4444,27015` to limit hooked ports), `LAN_HOOK_DEBUG=1`. Match the DLL to the **game** bitness (`lan_hook32.dll` for 32-bit games). Game command-line arguments after the exe pass through untouched (quote args containing spaces).
Startup waits up to `LAN_HOOK_LEASE_WAIT` ms (default `3000`) for the relay's address lease; without it the game exits with code `200` (relay unreachable) or `201` (no lease) after a messagebox (Windows) or stderr message (Linux). `LAN_HOOK_INIT_TIMEOUT` (default `30000`, `0` disables) is the backstop watchdog; neither ever fires after startup — mid-game drops just redial silently.

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
python3 test_relay_multilink.py  # one node id, many links: tree identity fanout (MULTILINK_ALL_PASS)
python3 hook/test_direct.py      # symmetric hook host+join (DIRECT_ALL_PASS)
python3 hook/test_virtual_p2p.py # 3-node virtual-IP mesh (P2P_ALL_PASS)
python3 hook/test_childprop.py   # child-process inheritance (CHILDPROP_ALL_PASS)
python3 hook/test_treeid.py      # process tree shares one vnode; stranger roots don't (TREEID_ALL_PASS)
python3 hook/test_perdest.py     # per-dest UDP flows, node GC (PERDEST_ALL_PASS)
SHADOWLAN_WINEPREFIX=~/.wine python3 hook/test_late.py  # late-loaded plugin DLLs (LATE_ALL_PASS; Wine)
python3 hook/test_noloop.py      # relay never echoes to source + ICMP mesh (NOLOOP_ALL_PASS)
python3 hook/test_udptcp.py      # UDP-over-TCP mode incl. mixed rooms (UDPTCP_ALL_PASS)
python3 hook/test_fatal.py       # fatal startup errors kill game with 200/201 (FATAL_ALL_PASS; Linux)
python3 hook/test_icmp.py        # hook-level ping mesh via raw sockets (ICMP_ALL_PASS; Linux root)
```

## Limits

- IPv4 only; IPv6 passes through untouched
- Same-machine peers talk over the real local stack (self-addressed
  traffic is never tunneled); the tunnel carries what would leave the
  NIC. Keep the relay subnet (default 10.200.0.0/24) clear of any real
  local interface, or pick another with --subnet.
- One game per relay port is the supported setup; `--token` is the room key (empty = open relay). Accidental double-claims no longer kill live sessions (new implicit joins follow the newest claim; addressed hook sessions are per-dest isolated).
- Same-dest UDP with byte-identical LAN triples from two sites still last-writer-wins per dest (logged); the hook sends from its virtual IP so hook nodes don't collide, and `wclient` client ports are usually random ephemerals.
- No encryption — trusted peers only (or wrap in WireGuard)
- Async overlapped Winsock and `ConnectEx`/`WSAEventSelect` waiting are not hooked; blocking sockets and `select`/`poll` are
- Full per-peer virtual-IP attribution needs the hook; `wclient` re-emits beacons with its own source
- Games embedding a private IP inside the discovery payload (instead of dialing the broadcast source) need a per-title payload rewrite
