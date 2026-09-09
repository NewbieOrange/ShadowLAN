# AGENTS.md — working notes for ShadowLAN

Everything an agent needs to be productive here, most of it learned the
hard way (field debugging 2026-09). Read this before touching the wire
protocol, the hook, or the test harness.

## What this project is

ShadowLAN makes two machines behind separate NATs behave like one LAN for
arbitrary games, with **no drivers, no TUN, no port forwarding**. Three
pieces, all versioned together in this repo:

- `server.py` — a pure-Python relay (TCP+UDP on ONE port) users deploy
  themselves (current deployment: `v4.router.chengzi.xyz:47777`, token
  set). **We cannot deploy it** — deliver the file + ask the user.
- `hook/lan_hook.c` — one C file, two builds: Windows DLLs (`lan_hook64/32`
  via mingw, injected with `hook/injector.exe`, IAT patching only, no asm)
  and a Linux `LD_PRELOAD` `.so` (used by the test suite; field users are
  on Windows). Rewrites socket calls of the game process tree so the
  relay looks like the local NIC.
- `wclient.py` — driverless Python client (proxy/bridge roles). No syscall
  visibility, so it has explicit `--host` mode; the hook auto-detects the
  same things (`listen()` ⇒ host claim, bound ports ⇒ serve).

Hard constraints from the user:
- Fixes go in hook/relay ONLY. The test app is **Goldberg Emulator (GBE)**
  (`/tmp/opencode/gbe_fork` if present) plus the `lobby_connect` tool —
  never patch them, never parse/rewrite game payloads (protobuf or else).
- The vnet must be indistinguishable from a real LAN to the app
  (addresses, ports, `getpeername`, adapters — see Interface shim).
- Universal > game-specific. No timing hacks: real per-connection TCP
  errors/timeouts do the work; the hook never invents stall timeouts.

## Wire protocol (2.0 generation, `common.py` + `DT_*/DU_*` in lan_hook.c)

Framing on ALL TCP conns: `[u32 len][u8 type][payload]` (`common.HDR`, len
covers type+payload). UDP tunnel datagrams: `'V','N',UVER,op,payload`.
`PVER = UVER = 2`; **Python and C op tables must stay in lockstep** (both
defined once: `common.py` header, `lan_hook.c` ~line 212).

TCP control conn (one per hook process, ephemeral, auto-redial):

    T_NODE=0x01    ver + !H tlen + token + !I node + !H uport + !B flags
                   flags bit0 = NODE_F_HOST (designated-host claim).
                   Registration is the ONLY versioned frame: gating it
                   gates everything routed by the node id (streams too).
    T_ASSIGN=0x02  relay->peer: my_virt, net, bits, members + trailing
                   !B link_id (1..255, MANDATORY, per-LINK; every link of
                   a node gets its own ASSIGN carrying its own link_id;
                   membership is per-NODE, not per-link)
    T_BCAST=0x03 / T_BCAST_FROM=0x04   discovery fanout
    T_UDP_MODE=0x05 / T_UDP_TUN=0x06   per-LINK UDP-over-TCP mode

Per-stream conns (one real TCP conn to the relay PER fake game TCP conn —
both ends dial out; that is the anti-HoL design; never multiplex streams):

    T_STOPEN=0x07 -> relay fans T_STREQ=0x08 to EVERY live link of dest
    node; siblings race to serve. T_STJOIN=0x09 is answered on the
    joiner's own conn with the CLAIM: T_STOK=0x0B (you serve) or
    T_STFAIL=0x0C + STF_BUSY (stand down BEFORE bridging). Winner bridges
    127.0.0.1:game-port (retries ~1s) then sends T_STJOINED=0x0A; relay
    then STOKs the OPENER. After that: raw bytes both ways. 10s budget
    (ST_TIMEOUT_S / DT_ST_TIMEOUT_MS).
    Failure reasons STF_NO_ROUTE/TIMEOUT/HOST_FAILED/BAD_ID/BUSY = 1..5;
    hook maps them to WSAECONNREFUSED/WSAETIMEDOUT (also ECONNRESET on
    post-connect peer death).

UDP tunnel ops: U_GAME_C2S=1, U_GAME_S2C=2, U_GAME_P2P=3 (dest-node
prefixed), U_NODE=4 (carries host flag; refreshes link udp_addr AND
host_udp when flagged), U_ICMP_REQ/REP=5/6 (dest node 0 = relay answers
at .1; `10.200.0.1` is the relay's pseudo-IP, relay pings are local).
Marks: a client socket is presented as (vnode, link_id*256 + slot) -
the FULL u16 port space, nothing reserved away from games. link_id is
relay-allocated per LINK (1..255) and delivered in the ASSIGN tail
(hook var `g_link_id`); slot is the per-process client-socket table
index (DT_MAXSLOT=256). Rationale: slots are per-PROCESS, so sibling
links of one node used to collide in the relay's return-path binding
("UDP triple collision, latest sender wins") and S2C replies
flip-flopped between processes - the cross-machine UDP killer of
2026-09-09. Two invariants make full-range marks safe: (1) the mark is
always HOOK-allocated and stable - the relay rewrites nothing, because
apps unicast-reply to whatever recvfrom presented and the hook
forwards that value as the frame game_port (relay-internal numbers
would become phantom game ports: an attempt that way same-boxed a
regression and never shipped); (2) sendto(vnode, P) is first demuxed
against the HOSTED-SESSION table by exact (peer-virt, P) tuple - a
reply to a mark flows as a proper S2C instead of a C2S whose game_port
is a mark number - so marks landing in some game's service band are
harmless. Wire is otherwise PVER 2, but the mandatory ASSIGN tail
means hook+relay ship TOGETHER (mismatched length = fatal 201 fail-
fast, intended).

Semantics that matter:
- `connect()` completes ONLY after the destination bridged (real connect
  semantics). Nonblocking: EWOULDBLOCK + FD_CONNECT/writable later.
- Backpressure: TCP app-send blocks (or EWOULDBLOCK for nonblocking apps)
  when the 4 MB out-queue is full; in-queue (1 MB) pauses relay reads
  until drained (kernel window). UDP hook queues drop the NEW datagram
  (never reorder/drop-old).
- Relay: per-writer send queues (drain task) — never write a control
  writer outside `r_send`; droppable = beacons/UDP_TUN, ASSIGN/STREQ are
  not. `NODE_TTL=600` keeps a node+virt for reconnects (stale sibling
  instances of dead trees linger as members for up to 10 min — before
  blaming routing, check the relay log for how many NODES each machine
  registered: multiple per machine means leftover game instances
  receiving 0-return streams).

## Process-tree identity

One node per process TREE: the hook generates node_id once, publishes it
into its own environment (`LAN_HOOK_NODE`), descendants inherit it for
free (kernel copies env; `SetEnvironmentVariableA`/`setenv` before any
spawn; Windows `CreateProcess` with an EXPLICIT env block gets the var
appended — `dt_env_with_node`, ANSI + wide paths). Consequences:

- GBE self-restart chains and game+child = ONE vnode, many links. The
  relay fans out per-link; a sibling link dying never kills the node or
  its streams (whole-node-dark does; the peer sees EOF).
- Streams to a shared node are CLAIMED (see protocol) — exactly one
  process bridges the local port.
- No shared memory sections were needed anywhere: identity lifetime ==
  env inheritance == tree lifetime; ports are deduped by the OS kernel
  (bind(0) is machine-unique); vport aliases are per-socket presentation
  state. If real mutable shared state is ever needed (e.g. a port
  ledger), use `Local\` named pagefile-backed CreateFileMapping on
  Windows (kernel refcounts, last handle close destroys — NEVER decide
  "last process" yourself) — user's explicit guidance.
- Tests rely on UNRELATED roots getting DIFFERENT ids
  (`test_treeid.py` proves inherit vs stripped-env both ways).

## LAN_HOOK_LAN_ONLY=1 (isolated mode)

The process sees a machine cabled ONLY to the tunnel:
- Out: TCP connect + UDP/raw sendto to anything not loopback / not vnode
  / not a tunnel-served target (`sockaddr_is_lan_target`: RFC1918 +
  169.254 + 224/4 + bcast, with allowed ports) fail instantly
  ENETUNREACH/WSAENETUNREACH. UDP `connect()` intentionally passes
  (faithful: kernels allow unroutable udp connects; the SEND fails).
- In: wire datagrams with a non-loopback SOURCE are dropped
  (recvfrom/recv/WSARecv* fall-through); `accept/accept4/WSA accept`
  drop wire peers. **Inbound predicate is strict `127/8`** — NOT
  `ipv4_is_local()`, which includes the machine's own NIC IPs and made a
  same-host wire test pass the wrong thing.
- Adapters: GAA/GetAdaptersInfo return the pseudo-adapter ALONE.
- Broadcast/multicast discovery tunnels as usual — isolation changes
  only what would hit the physical wire.
- The own-broadcast NIC-style local echo MUST carry the vnode
  (`dt_src_ip`), never `dt_machine_ip`: apps fold announce sources into
  own-IP/peer state and stamp them into payload `source_ip` (GBE does),
  so a physical IP in that echo contradicts the vnode `getpeername`
  presents and apps silently reject the connection. That leak was the
  real "lobby invisible under LAN_ONLY" root cause (fixed in 2.0.0); it
  also poisoned cross-machine runs without LAN_ONLY. `test_lanonly`
  phase 5 guards it.

## Interface shim (Windows adapter APIs)

Purpose: GBE (and many engines) enumerate adapters for own-IP, per-iface
broadcast ranges, subnet sanity checks. The vnode appears as a
standalone "ShadowLAN Virtual Interface" pseudo-adapter: if-index
`0x7F000001`, `IF_TYPE_ETHERNET_CSMACD`, up, MAC `02:00:53:48:00:01`,
vnode/24 unicast, 1 Gb/s. Appended after real adapters normally; the
ONLY adapter in LAN_ONLY mode.

Pitfalls baked into the implementation (`hk_GetAdaptersAddresses`):
- mingw's `IP_ADAPTER_ADDRESSES` == SDK Vista+ (LH) layout, fine to use.
- `IP_ADAPTER_UNICAST_ADDRESS` = LH variant by default: `OnLinkPrefixLength`
  is a REAL field — set it (older code wrongly set `PrefixOrigin`
  believing an XP-offset myth).
- The runtime `IP_ADAPTER_INFO` from real Windows == SDK `iprtrmib.h`
  (`Next, ComboIndex, AdapterName[260], Description[132], AddressLength,
  Address[8], Index, Type, DhcpEnabled, CurrentIpAddress, IpAddressList,
  GatewayList, DnsServerList, DhcpServer, HaveWins, ...`) — **mingw's
  header is NOT ABI-exact (missing DnsServerList, time_t leases)**; the
  code uses its own `dt_ms_ip_adapter_info` and treats caller buffers
  opaquely. Verify against `/usr/x86_64-w64-mingw32/include/iptypes.h`
  + docs before "fixing" it.
- Some drivers report the WHOLE caller buffer as `*SizePointer=used`
  (observed in Wine): both shims clamp `used` via a NULL-buffer probe
  (`ERROR_BUFFER_OVERFLOW`), else the GetAdaptersInfo append silently
  no-ops.
- Only surgery on the caller's buffers, degrade to unshimmed on any
  doubt. Wine exercises both paths in `test_late.py` phase C
  (`IF_OK` / `IF_ISO_OK`).

## Hook implementation traps (each cost hours; do not rediscover)

- The hook's OWN sockets must bypass its hooks: Linux uses `r_*`
  (dlsym RTLD_NEXT) for socket ops that could hit vnodes; the tunnel UDP
  socket is SOCK_DGRAM so even a hooked `connect` passes the stream-only
  gate — keep `dt_reject_wire4` AFTER the `SOCK_STREAM` check in
  `dt_on_connect` or you reject your own relay link.
- Frame loops: a `select()` timeout is NOT an error and `recv()==-1
  EAGAIN` on nonblocking is NOT EOF — retry within the budget (an early
  version "saw EOF" on the first 50 ms tick). Body reads consume the
  whole `ml` bytes (type + payload), payload len = ml-1.
- `ioctlsocket(FIONREAD)` MUST return the hook in-queue count for
  tunneled streams (GBE `recv_tcp` reads ONLY when FIONREAD>0 — this
  exact bug was the original "lobby invisible" root cause). Linux:
  `ioctl` hook does the same.
- `getpeername`/`recvfrom` sources must present the vnode (orig addr),
  never 127.0.0.1/relay — apps key connections on peer IP.
- Stream slots live in a static array reused across fd numbers: every
  write from a stream/join thread must re-check `st->used && st->sid ==
  sid` (ownership), and ONLY the owning thread frees on peer-EOF;
  `dt_on_close` marks dead (thread frees) or frees directly if the
  thread is gone.
- Windows event model: virtual events (`WSAEventSelect`) need mask-aware
  one-shot reporting (FD_CONNECT once via `connect_signaled`; FD_READ/
  WRITE/CLOSE per state), select/poll hooks must merge hook-queue
  readability AND writable/FD_CONNECT or event-driven apps spin.
- Blocking sends from apps: `dt_stream_send_wait` blocks while out-queue
  full (nonblocking apps get EWOULDBLOCK); never fall through to the
  REAL socket of a tunneled connection.
- Relay-side (Python): an `asyncio.start_server` callback RETURNING
  closes the transport — per-stream handlers `await st["done"]` for the
  stream's lifetime (this exact bug RST every join mid-handshake).
  `Server.wait_closed()` (3.12+) waits for LIVE handlers: `Relay.run()`
  tracks and cancels them in a bounded (3 s) teardown or shutdown hangs.
- Per-writer queue frames include the HDR length (`HDR.pack`) — the
  first "no discovery" regression was a missing prefix in `r_send`.
- sid must be random (room-wide unique), not a per-process counter.
- Pre-init control redials back off 250 ms (fast fatal 200/201); post-
  init stays 1 s to avoid dial storms.
- Shared UDP ports: bind EADDRINUSE -> bind ephemeral + `vport` alias
  (SO_REUSEADDR broadcast semantics emulated; fanout matches vport).

## GBE-specific facts (the app under test — never modify it)

- GBE `dll/network.cpp`: listens on base 47584 + scans 10 ports,
  beacons announce every ~5s per port, HEARTBEAT/USER_TIMEOUT 20s;
  `recv_tcp` is FIONREAD-gated (see trap above); `handle_announce` sets
  `tcp_ip_port` from the recvfrom SOURCE (so spoofed vnode sources work)
  and adopts own-IP from `GetAdaptersAddresses` broadcast info.
- A conn counts as visible/`connected` only after TCP data is READ on
  either socket — beacons alone create the conn but not `connected`.
- KNOWN UPSTREAM BUG: `new_connection()` does `struct Connection
  connection;` — uninitialized; `tcp_socket_outgoing.sock` may be
  garbage so some instances never dial outgoing (per-process lottery).
  Don't chase this as a tunnel bug — check `app tx/app rx` lines first;
  inbound streams + FIONREAD make the peer visible regardless.
- `lobby_connect.exe` tool: inits GBE (appids differ from game — beacon
  payload sizes differ, e.g. n=42 vs n=41 = different appid), prints
  `GetFriendCount` ONCE after 2 s then BLOCKS ON STDIN; invalid input =
  re-list. Field procedure: friend hosts, wait ~10 s, press Enter/x in
  the tool. Tool runs as a self-restart chain (RestartAppIfNecessary) —
  now sharing one vnode via LAN_HOOK_NODE.

## Version & release policy (user's rules — follow exactly)

- Version lives in TWO places only: `common.VERSION` + lan_hook.c
  `SHADOWLAN_VERSION`; they move together in a dedicated
  `chore: bump version to X` commit.
- **rc versions are NEVER committed** — local stamp only; keep those two
  lines dirty in the working tree between releases (current: none —
  2.0.0 is released; the next local build starts 2.0.1-rc1).
  At release: change to the final number, commit the bump, build, ship.
- **Every local build/package you hand to the user must increment the rc
  number** (rc1 -> rc2 -> ...) — never rebuild under a stale stamp, or
  field logs and `dist/` artifacts become indistinguishable. Exception:
  a release build carries the final version with no rc suffix at all.
  Remember the binaries + both packages must be rebuilt after stamping.
- No version numbers in commit-message TITLES (bodies are fine); no git
  tags unless asked.
- Commits split by layer where the history allows (protocol/relay, hook,
  tests, docs). Don't push unless explicitly told; history rewrites of
  pushed commits need `--force-with-lease` (done once, on request).
- `dist/` holds release/rc packages + user-dropped field logs. Packages:
  linux `.tar.gz` (lan_hook.so + py + docs, hook README as
  HOOK_README.md) and windows `.zip` (+ both DLLs + injector). Old rc
  packages are wire-INCOMPATIBLE (ops renumbered) — offer to delete.

## Debugging the test harness itself (meta-lessons)

- A `run_in_executor` lambda that blocks in `recv_udp(3.0)` and whose
  result is discarded STEALS the next datagram that arrives within its
  timeout — this produced a phantom "relay drops P2P" bug hunt (tcpdump
  said delivered, socket said no) that was purely a test leftover. When
  a packet "vanishes": enumerate every reader of the fd (`strace -f -e
  trace=network` shows which thread stole it).
- tcpdump on loopback taps BEFORE checksum validation and UDP socket
  demux: "captured" != "enqueued". Pair it with `nstat` counters and
  per-socket strace before concluding kernel drops.

## Testing discipline & harness knowledge

- Full suite: `make -C hook test` (Linux, ~45 s total) + `test-all` adds
  Wine (`SHADOWLAN_WINEPREFIX=~/.wine`, prefix already prepared; wine is
  slow to start — budget minutes, run in background). Root needed for
  ICMP tests. Verdict markers are `*_ALL_PASS` / `ALL PASS` — grep with
  plain `-E "ALL_PASS|FAIL"` (an anchored `[A-Z0-9]+ALL_PASS` silently
  misses `DIRECT_ALL_PASS`).
- Every test has a hard asyncio watchdog (`_guarded`, 20 s; lanonly 90 s
  + outer `timeout`): a hanging test must fail loudly, never pin CI. All
  tests pass in <=8 s normally — if one hits the guard, find the hang,
  don't raise the limit.
- **Test relays bind 127.0.0.1** (`Relay(port, bind="127.0.0.1")`): the
  user's real LAN device (192.168.1.1, the router) connects to stray
  0.0.0.0:47777 test relays and caused phantom flaky hangs. Also: two
  live relays on the same port (SO_REUSEADDR) silently split traffic.
  Kill leftover `server.py`/test procs before running; beware
  `pkill -f <pattern>` matching your OWN `bash -c` command line (quote a
  char, e.g. `[s]erver.py`, or use exact PIDs).
- When a test "hangs", remember `cmd | tail` buffers until EOF — write
  to a file and inspect, or `-X faulthandler` + SIGQUIT-style dumps.
- New wire behavior needs: a relay-level test (raw frames), a hook-level
  test (LD_PRELOAD child scripts), and for anything Windows-specific an
  ifprobe-ish wine phase. `test_relay_multilink.py`, `test_treeid.py`,
  `test_lanonly.py` are the patterns to copy.
- `dt_hs_close(sid)` has no keep_real arg (always closes both); junk
  legacy paths (T_TCP_*, T_POPEN, ride-port/TUNNEL_PORT, once-per-link
  hello) are deleted — never resurrect them; grep before adding "compat".

## Field debugging playbook (how the last wins were found)

- Ask for: relay.log + BOTH hook logs + which exe/pid is which. Require
  `LAN_HOOK_DEBUG=1` (Windows dlog is debug-gated: without it the tool's
  whole side is invisible); hook logs land in `LAN_HOOK_LOGFILE`.
- Correlate with the now-present identity lines: `identity pid=.. node=..
  (inherited)`, `assign pid=.. node=.. self=10.200.0.x members=N`,
  `tunnel TCP up pid=`, `stream open/ok/fail/eof pid= gsock= sid=`,
  `hosted req/stream up/eof`, `app rx/tx ... tot=` (did the GAME read
  the bytes?!), `fion: queued=N unread` (bytes waiting, app never
  reads = app-layer problem, not tunnel). Relay side: `stream
  open/join/ok/claim-BUSY/pipe closed Xb/Yb`, `proto mismatch NODE ver`.
- Version skew is now LOUD: relay logs `proto mismatch ... ver X != 2`
  and drops the link; hook fatal 201 "no lease" if it can't register.
  Wire changes ship to relay + ALL machines together, always.
- Timing skew between machines is real (~11 s observed): correlate by
  event order/relay, never by wall clock across machines.
- User's remote-test topology: own Windows PC (lobby_connect tool +
  game, LAN 192.168.1.x, second unhooked game PC at .160 = noise source
  — use LAN_ONLY=1) vs friend in China (game via GBE, symmetric NAT,
  `LAN_HOOK_UDP_OVER_TCP=1`). Friend must run a single game instance.

## Open ideas / known gaps

- DNS/`gethostname`/`GetIpAddrTable`/`GetIfTable` are NOT isolated yet —
  GBE doesn't use them; add to LAN_ONLY if a game reveals the real NIC
  through another door.
- Blocking-socket `accept` under LAN_ONLY returns EAGAIN for dropped
  wire peers (callers may spin; rare) — could sleep-slice.
- Host-claim ping-pong between two genuine hosts (both games listen) is
  log noise only: explicit addressing rules; last claim wins for
  implicit routing.
- GBE's uninitialized-`Connection` dial lottery: consider a hook-side
  nudge if it ever blocks a sale (e.g. treat a never-read garbage fd's
  FIONREAD/select on the tool side as retry-worthy) — unverified idea.
- dist/ cleanup of v1.2.0-rc*/v1.0.0/v1.1.1 packages: offered to user,
  not yet done.
- `getsockname` is NOT hooked: on a tunneled TCP socket it reports the
  real local endpoint (own NIC ip + ephemeral port). Games almost never
  consult their own side (getpeername IS spoofed and that is what they
  key on), but it is a door LAN_ONLY does not close; hook it (vnode +
  real port) if an app ever shows it.

## Status snapshot (2026-09-09: RELEASED 2.0.0)

2.0.0 (2026-09-09) additionally ships the
relay-assigned per-link UDP slot ranges (see Wire section): ASSIGN grew
a mandatory trailing link_id byte, hooks mark `link_id*256 + slot`
across the full port space. Relay tests (multilink incl. link-id assertions, topology) + Wine + compiles
verified; the hook e2e suites were BLOCKED by a SANDBOX KERNEL-UDP
failure (every loopback sendto EPIPE, /proc/net/udp empty after heavy
tcpdump/strace - environmental). RERUN `make -C hook test` on a
healthy box before trusting a field round; if loopback UDP EPIPEs,
that is the sandbox, not the protocol - switch to TCP-only relay tests.

`2.0.0` RELEASED (pushed to origin). History since `a6c5f0b`:
refactor(proto) → LAN_ONLY → wine phase C → docs → AGENTS →
echo-source fix → per-link UDP slot ranges → bump `chore: bump version
to 2.0.0`. Ship set = `dist/shadowlan-v2.0.0-*` rebuilt with the slot
ranges (hooks and relay MUST be deployed together: the ASSIGN tail is
strict for old hooks, fatal 201 fail-fast). Field evidence behind the
fix chain: same-box LAN_ONLY lobby worked (all grecv sources vnodes,
zero wire drops, zero self-dials); cross-machine relay.log showed the
sibling-mark collision that motivated the slot ranges. Known noise
only: host-claim ping-pong (both trees listen) and shutdown-race
`fatal 200`. Hook e2e suite was last run BEFORE the slot-range change
(sandbox kernel UDP died afterwards) — rerun `make -C hook test` on a
healthy box, then a same-box LAN_ONLY smoke with tool+game, then the
friend link.
