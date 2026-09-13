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
- `hook/` — version stamp in `lan_hook.c` / `hk_version.h`; shared
  tables in `hk_core.c`; one TU per `hk_*.c`. Two builds: Windows DLLs
  (`lan_hook64/32` via mingw, injected with `hook/injector.exe`, IAT
  patching only, no asm) and a Linux `LD_PRELOAD` `.so` (used by the
  test suite; field users are on Windows). Rewrites socket calls of the
  game process tree so the relay looks like the local NIC.
- `wclient.py` — driverless Python client (proxy/bridge roles). No syscall
  visibility, so it has explicit `--host` mode; the hook auto-detects the
  same things (`listen()` ⇒ host claim, bound ports ⇒ serve).

Hard constraints from the user:
- Fixes go in hook/relay ONLY. The test stack is a LAN-lobby reference
  pair (a session-bridging library + a lobby viewer tool; sources live
  on the local boxes only, never in this repo) — never patch them,
  never parse/rewrite game payloads (protobuf or else).
- The vnet must be indistinguishable from a real LAN to the app
  (addresses, ports, `getpeername`, adapters — see Interface shim).
- Universal > game-specific. No timing hacks: real per-connection TCP
  errors/timeouts do the work; the hook never invents stall timeouts.
- No replay of discovery traffic: on a real LAN a machine that appears
  late simply waits for the next beacon round, so the relay only
  forwards beacons — it must never cache and re-send them (the
  `bcast_cache`/`BCAST_FRESH` replay added on 2026-09-13 was removed
  for this reason; the field run disproved its necessity anyway).

## Wire protocol (PVER 3 / UVER 3, `common.py` + `DT_*/DU_*` in `hk_core.h`)

Framing on ALL TCP conns: `[u32 len][u8 type][payload]` (`common.HDR`, len
covers type+payload). UDP tunnel datagrams: `'V','N',UVER,op,payload`.
`PVER = 3`, `UVER = 3`; **Python and C op tables must stay in lockstep**
(both defined once: `common.py` header, `DT_*/DU_*` in `hk_core.h`).
Hook + relay ship together: a PVER-2 peer is dropped at registration.

TCP control conn (one per hook process, ephemeral, auto-redial):

    T_NODE=0x01    ver + !H tlen + token + !I node + !H uport + !B flags
                   flags bit0 = NODE_F_HOST (listener claim: an ordering
                   stamp for implicit fan-out ONLY — no election).
                   Registration is the ONLY versioned frame: gating it
                   gates everything routed by the node id (streams too).
    T_ASSIGN=0x02  relay->peer: !I my_virt + !I net + !B bits + !H n
                   + n*(!I node + !I virt). Length `11+8*n`. No tail.
                   Membership is per-NODE, not per-link.
    T_STREQ carries the OPENER's vnode (10 bytes: sid + gport + ovirt);
    the joinee maps the accepted game socket's peer (accept out-param +
    getpeername) from the bridge's 127.0.0.1 to that vnode — games
    cross-check it against the announce source (dt_acc table, keyed by
    bridge ephemeral port, fd-reuse verified).
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
prefixed), U_NODE=4 (carries host flag; refreshes link udp_addr and,
when flagged, the link's `host_claim` ordering stamp), U_ICMP_REQ/REP=5/6 (dest node 0 = relay answers
at .1; `10.200.0.1` is the relay's pseudo-IP, relay pings are local).
Source identity (UVER 3): the `cli_port` field of C2S/S2C/PDAT frames
is the sender socket's BOUND VPORT - exactly what a real NIC stamps.
Unbound sockets get the kernel's implicit-bind replicated at first send
(dt_sport_presentation) and recorded as an identity row. A prior
generation presented an internal slot mark (link_id*256+slot) as the
source port: apps fold recvfrom sources into peer state and DIAL them -
the mark was un-dialable from the app's seat, which poisoned GBE's peer
tables (MEMBERS flip) and deadlocked SteamNetworkingSockets (post-join
black screen, same-box field rounds). No mark exists on the wire: S2C
receivers resolve the flow from (game_port, own port) against their own
outbound flow table. The relay may keep an internal link id for logs;
it is not on the wire.

Semantics that matter:
- `connect()` completes when a dest link CLAIMS the stream (STOK at
  claim; SYN/ACK semantics - the local bridge/accept latency hides in
  transport buffers like a kernel backlog). A bridge failure after
  confirmation tears down via close() = post-connect reset, which real
  TCP can do too. Nonblocking: EWOULDBLOCK + FD_CONNECT/writable later.
- Accept door: the game's accepted socket (peer == our bridge loopback)
  presents the OPENER's vnode via accept out-param AND
  getpeername/getsockname - all three agree, or apps that cross-check
  reject the session (`g_acc` + `real_getpeername_sym()`; dlsym of
  getpeername can bind OUR OWN export depending on link order - use the
  ELF-introspected real symbol).
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

- Launcher self-restart chains and game+child = ONE vnode, many links. The
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
  own-IP/peer state and stamp them into payload `source_ip` (the
  reference app does), so a physical IP in that echo contradicts the vnode `getpeername`
  presents and apps silently reject the connection. That leak was the
  real "lobby invisible under LAN_ONLY" root cause (fixed in 2.0.0); it
  also poisoned cross-machine runs without LAN_ONLY. `test_lanonly`
  phase 5 guards it.

## Interface shim (Windows adapter APIs)

Purpose: the reference test app (and many engines) enumerate adapters
for own-IP, per-iface broadcast ranges, subnet sanity checks. The vnode appears as a
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
  tunneled streams (the reference app's TCP reader polls ONLY when
  FIONREAD>0 — this exact bug was the original "lobby invisible" root
  cause). Linux:
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
- Windows ledger APIs that fault where docs say they cannot: `OpenProcess
  + GetProcessTimes(h,&ct,0,0,0)` AV'd the field game at startup inside
  kernelbase's out-param write (steam_api64 bind -> hk_bind -> slp_claim;
  reproduced exactly under Wine with the real DLL). Self start-stamp =
  read `Peb->CreateTime` (gs:0x60, +0xa8; 32-bit fs:[0x30], +0x0a4);
  foreign liveness = OpenProcess + GetExitCodeProcess ONLY, fail-safes
  split: `ERROR_INVALID_PARAMETER` = dead (take claim over),
  `ACCESS_DENIED` = alive (respect it). Wine stubs Peb->CreateTime (same
  value everywhere) — stamps are self-audit only, never cross-pid.
- `GetLastError() != ERROR_ALREADY_EXISTS` after `CreateFileMappingA` is
  NOT a reliable "fresh" signal (Wine: err=0 while a live holder existed
  — a false fresh WIPES the shared registry between processes). Init is
  content-based: check the magic under the mutex, never the create error.
- Keep the mapping's CREATE handle open for the process lifetime
  (`g_slp_sec`): Wine drops the shared pages of a handle-closed section
  despite live views (Windows docs keep it via views — do not gamble).
  Cross-process `Local\` sections themselves share fine under Wine.
- `WSASetLastError` is thread state that ANY logging side-effect can
  overwrite: `dlog` (file/time APIs) between setting an error and
  returning SOCKET_ERROR handed the app err=2 instead of 10048. hk_bind
  now has ONE exit label that snapshots the error before logging and
  re-sets it after. Same idea applies to `errno` around dlog on Linux.
- UDP port sharing in the ledger is kernel-faithful: `SO_REUSEADDR`
  must be set on BOTH the holder and the newcomer or the bind collides
  (Windows and Linux agree here); TCP never shares. The Wine shared-port
  fixture asserts both halves (reuse+reuse coexists and both receive
  fan-out; a plain bind against holders gets WSAEADDRINUSE).
- Test suites must REAP children they kill (`p.kill(); p.wait()`): an
  unreaped SIGKILL'd holder is still "alive" to the ledger and to the
  kernel, so the very next trial legitimately collides with it — this
  masqueraded as a ledger bug for a whole debugging round.

## Reference test app facts (never modify it)

- Its network layer: listens on base 47584 + scans 10 ports,
  beacons announce every ~5s per port, HEARTBEAT/USER_TIMEOUT 20s;
  `recv_tcp` is FIONREAD-gated (see trap above); `handle_announce` sets
  `tcp_ip_port` from the recvfrom SOURCE (so spoofed vnode sources work)
  and adopts own-IP from `GetAdaptersAddresses` broadcast info.
- A conn counts as visible/`connected` only after TCP data is READ on
  either socket — beacons alone create the conn but not `connected`.
- KNOWN UPSTREAM BUG (viewer tool's library): `new_connection()` does
  `struct Connection connection;` — uninitialized;
  `tcp_socket_outgoing.sock` may be garbage so some instances never dial outgoing (per-process lottery).
  Don't chase this as a tunnel bug — check `app tx/app rx` lines first;
  inbound streams + FIONREAD make the peer visible regardless.
- The viewer tool FORCES its own hard-coded application id
  (sentinel (uint32)-2) into the session id environment variables at
  startup, and that env beats every on-disk config in the shared
  layer. A game SPAWNED BY THE TOOL inherits the sentinel and dies in
  its own init check ("reported AppId != expected"; reported =
  0xFFFFFE = the sentinel truncated to a 24-bit field) BEFORE its
  first socket call - nothing to do with the vnet. The tool's config
  file name may show the correct id - irrelevant, env wins. Fixes:
  launch games directly (game<->game share the real id), or rebuild
  the tool with the game's id (its browsing mode special-cases the
  sentinel client-side).
- The lobby viewer tool: inits the bridge library with its own appid
  (differs from the game's — beacon payload sizes differ, e.g. n=42
  vs n=41), prints the friend count ONCE after 2 s then BLOCKS ON
  STDIN; invalid input = re-list. Field procedure: friend hosts, wait ~10 s, press Enter/x in
  the tool. Tool runs as a self-restart chain (re-exec pattern) — now
  sharing one vnode via LAN_HOOK_NODE.

## Version & release policy (user's rules — follow exactly)

- Version lives in TWO places only: `common.VERSION` +
  `hook/hk_version.h` `SHADOWLAN_VERSION` (included by `lan_hook.c`);
  they move together in a dedicated `chore: bump version to X` commit.
- **rc versions are NEVER committed** — local stamp only; keep those two
  lines dirty in the working tree between releases (current: none —
  2.0.0 is released; the next committed stamp is the 3.0.0 release).
  At release: change to the final number, commit the bump, build, ship.
- **No rc references in git content either**: all change notes between
  releases live in ONE "Status snapshot (UNRELEASED)" section here; at
  release, rename that section (and the stamps) to the final version.
  Commit TITLES never mention rc numbers or which snapshot/version they
  cut ("docs: X notes in UNRELEASED snapshot" -> "docs: X notes");
  bodies may be specific.
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
- `dist/` holds release/rc packages + user-dropped field logs. Build
  them ONLY with `./pack.sh` (stamp both versions, rebuild the three
  hook binaries, then run it): explicit per-package file lists + a
  leakage guard stop the Windows `.zip` ever carrying `lan_hook.so` or
  the linux `.tar.gz` the DLLs. Packages: linux `.tar.gz` (lan_hook.so
  + py + docs, hook README as HOOK_README.md) and windows `.zip` (+
  both DLLs + injector). Old rc packages are wire-INCOMPATIBLE (ops
  renumbered) — offer to delete.

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

- Full suite: `make -C hook test` runs the Linux suites IN PARALLEL via
  `runtests.py` (`-j` auto = CPU count; override `make -C hook test J=4`
  or `SHADOWLAN_TEST_JOBS`). `make -C hook test-all` is the same
  parallel pool PLUS the Wine suite (`runtests.py --wine`; test_late
  overlaps the Linux suites, gets a 900s watchdog). Hard-coded REAL ports and shared /tmp files
  are banned in tests: take them from `testutil.free_port()` /
  `free_ports(n)` / `tmp_path(name)`. Virtual LAN vports (47584-style,
  10.200.x) are per-relay and may stay fixed; wclient proxy binds and
  relay ports are REAL and must be allocated. `test_late.py` (Wine)
  honors `SHADOWLAN_LATE_PORT`, auto-picked otherwise. + `test-all` adds
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
- User's remote-test topology: own Windows PC (viewer tool + game, LAN
  192.168.1.x, second unhooked game PC at .160 = noise source — use
  LAN_ONLY=1) vs friend in China (game via the bridge library,
  symmetric NAT, `LAN_HOOK_UDP_OVER_TCP=1`). Friend must run a single
  game instance.

## Open ideas / known gaps

- DNS/`gethostname`/`GetIpAddrTable`/`GetIfTable` are NOT isolated yet —
  the reference app doesn't use them; add to LAN_ONLY if a game
  reveals the real NIC through another door.
- Blocking-socket `accept` under LAN_ONLY returns EAGAIN for dropped
  wire peers (callers may spin; rare) — could sleep-slice.
- (retired) The designated-host election (`host_writer`/`host_udp`) is
  GONE from the relay: two real games both claim host via `listen()` and
  the election flapped every few seconds. Implicit (port-only) dials now
  fan STREQ to ALL live links (LAN ARP: everyone is asked, only the
  process that actually listens claims; the rest never answer). The
  NODE_F_HOST flag survives ONLY as a per-link ordering stamp
  (`host_claim`) so wclient `--host` bridge migration stays deterministic
  (freshest claimer first) — it never excludes or demotes anything.
- The bridge library's uninitialized-`Connection` dial lottery: consider
  nudge if it ever blocks a sale (e.g. treat a never-read garbage fd's
  FIONREAD/select on the tool side as retry-worthy) — unverified idea.
- dist/ cleanup of v1.2.0-rc*/v1.0.0/v1.1.1 packages: offered to user,
  not yet done.
- `getsockname` IS hooked (both platforms): aliased/virtual ports and
  vnode binds are presented as the app bound them (never the ephemeral
  real number, never 0.0.0.0 where a vnode was requested). Ledger notes:
  every hook-level bind claims the vport in a NODE-scoped shared ledger
  (Local\ CreateFileMapping / shm_open+flock; dead holders' claims are
  taken over) so same-node sibling binds collide like a real kernel
  collides them, while DIFFERENT nodes on one OS alias ephemerally
  beneath and never see each other. `bind(0)` under LAN_ONLY=1 allocates
  from the node's ephemeral space (>=49152) and must not collide with
  claimed vports. test_bindfidelity guards the whole matrix.

## Status snapshot (UNRELEASED)

PVER 3 + hook modules (this cut): control registration is now PVER 3
(old PVER-2 peers fail-fast at NODE). ASSIGN dropped the unused
`link_id` tail (payload length `11+8*n`); `decode_streq` requires the
10-byte opener-virt form; `dt_mark`/`dt_unmark`/`g_link_id` deleted;
NODE token prefix renamed `dt_token_prefix`. UVER stays 3. Hook is
real TUs: `hk_core` (ops, tables, DLOCK, policy) plus one `.c` per
former `.inc` fragment; `lan_hook.c` is the version stamp only.
Makefile `MOD` lists every `hk_*.c` (Linux skips `hk_win*`, Windows
skips `hk_linux.c`). Product stamps stay dirty locally until the
release bump. Hook + relay ship together.

Source-port identity (prior unreleased cut): source port = bound vport,
mark system DELETED (dt_mark/dt_unmark/g_link_id-arithmetic gone; frame
bytes unchanged from the v2 UDP layout - only the meaning + UVER 3).
This was the last same-box
fidelity gap: with it fixed, the co-host yield guard and the any-proto
bridge backstop were RETIRED - same-box double-node runs now behave
exactly like two machines (forward+reverse channels both bridge;
test_aliasbridge R6b asserts FWD round-trip through the alias; local
SNS dual-dial harness /tmp/opencode/gbelob echoes both directions).
Replacement atomicity (dt_on_streq retires the same (peer,gport)
session before claiming) stays: it restores the kernel guarantee that
a new connection implies the old is dead - GBE's REPLACED logic
depends on it at ~0ms RTT. The v2-era 'do NOT correct dt_host_bridge
to SOCK_STREAM' decree is OVERTURNED by the mark fix - that policy
existed only to keep the poisoned forward channel from being used.
Same-box field round still needed after the source-identity cut.

Own-vnode TCP hairpin (this cut): must use THIS process's alias real
port, not the vport number. Same-box JoinLobby timed out because the
joiner's self-dial of 10.200.0.3:47584 was rewritten to
127.0.0.1:47584 - the HOST's real listener. Host accepted it
(acc-hook learn=0), the session library replaced the tunneled peer
socket. Two real machines (or Tailscale) never share a kernel port,
so a NIC hairpin cannot cross vnodes. dt_host_bridge already rewrote
this way; dt_on_connect did not. test_aliasbridge R6e: aliased node
connect(own vnode:V) is accepted by the aliaser, never the owner.
Cross-machine: no alias row => hairpin still uses the vport
(real == vport).

Stream recv gather (this cut): FIONREAD reports the full in-queue
(st->total) but dt_stream_pop returned only the first chunk. Kernel
TCP: recv(N) when N bytes are already queued returns N. The reference
lobby stack does ioctl(FIONREAD) then recv(exactly that) and never
shrinks a short read - a first-chunk pop leaves an oversized buffer
whose length prefix never completes, so a later JOIN sitting behind a
271KB friends dump is never parsed (host app-rx'd the 72B, zero
UNBUFFER / no LOBBY MESSAGE). Same-box field after the hairpin fix
was this. test_fullduplex scenario 4. Accept-door learn also stopped
using "first live hosted row": a self-dial loopback accept stole the
opener vnode (hairpin learn=1). Match is accept-peer == hosted bridge
ephemeral only.

Co-host guard (replaces slot-luck): dt_on_streq now yields the inbound
forward claim WHENEVER its own listener for that vport is aliased
(real != vport = another of our nodes owns the kernel port). Field
traces proved identity spoofing is complete (FOLD/ACC-VIEW byte-equal
pass-vs-fail) - the killer is GBE's reconnect storm (epoch-initialized
timers send an immediate first beat; every stale redial lands as a real
inbound through the bridge and REPLACEd - kills live sockets). Two
machines never enter this state; vnet-same-box with both nodes serving
47584 does, and no spoofing can make the app's state machine survive
it. Yielding the forward channel is exactly what the passing same-box
runs did by luck. test_aliasbridge R6b went nondeterministic->10.0s
deterministic. Cross-machine: predicate never true => provably inert.
Linux same-box harness note: flaky BOTH configs after heavy kernel-UDP
windows - trust Windows field rounds for join semantics.

rc17 = the A/B outcome: bridge dial reverted to any-proto first-match
(field-validated rc11/ab2 behavior, deliberate policy now), self-view
and proto-scoped helpers KEPT. A/B binaries: rc11-abtest and rc16-ab2
both joined same-box; rc15/16 did not -> single call site was the axis.
Deploy rc17 for field: identical semantics to rc11-era joins plus all
crash fixes and the ledger.

rc15 field round (same-box): alias bridge fix verified working end to
end (271KB lobby + heartbeats crossed byte-exact), but the host game's
ACCEPTED sockets still leaked the listener's alias real port via
getsockname -> identity triple disagreed -> app closed the session and
RST the retries. New dt_acc_self_view presents (own vnode, listen
vport) on both platforms (test_aliasbridge R6b guards the triple).
The WAN topology can never hit this (no aliasing); only one-machine
double-node runs do.

Channel policy (settled by A/B after three field rounds): when one OS
hosts two of our nodes, the HOST game must NOT receive the joiner's
forward lobby-query on a bridged accept socket - its session library
then splits per-peer state across the forward channel and its own
outbound session dial (observed rc15/16: full 271KB served on the
forward channel, 6B retransmits, host closes, retries RST, no session).
rc11 'worked' because the proto-blind bridge resolver dialed the datagram
alias row: the forward channel died bounded (reason=3 / connect-then-EOF
in ~1s) and the join completed on the host's own outbound dial. ab2
(rc16 minus the proto-scoped bridge call) reproduced rc11 success; rc17
ships that as POLICY with the reasoning in code (hk_sess dt_host_bridge)
and a field-faithful guard (test_aliasbridge: owner node + aliasing node,
forward must stay dataless+bounded, reverse must echo with the correct
accept-door triple). dt_alias_real keeps its proto parameter - hosted-UDP
inbound and every future consumer use it; ONLY the bridge dials -1.
Cross-machine runs have no alias rows and are untouched either way.

TU refactor (post-split sweep): hk_util.c (clock/log/stamp/sleep/pid/rng),
hk_alias.c (vport<->real table; slp_release_sock became dt_alias_release_all
so the table owner iterates its own rows - alias->ledger is one-way now)
and hk_ledger.c (claim registry; node id PUSHED via slp_set_node, module
reads no core globals; claim verdict dlogs on both platforms) compile as
independent TUs behind hk_api.h; the tangled core stays one TU (root +
fragments, order-dependent, shared statics - documented at the include
list). Interface names all dt_/slp_-prefixed (verified zero libc .dynsym
collisions; LD_PRELOAD-safe). Gotchas logged: GNU make silently REJECTS a
pattern rule whose extra prerequisites (headers) are missing - the error
names the target, not the missing header; and `make clean` + test-all
missing injector.exe in its deps = test_late build() -> LATE_SKIP -> suite
FAIL (deps now closed). Gate 20/20 incl. Wine; core still -Wextra clean.

Post-rc11 sweep (field-confirmed state): dead code gone
(dt_fd_readable_peek, Windows slp_starttime, stream_freed accumulator),
retired-election wording purged from comments/READMEs, g_ta gets
DT_TA_MAX, select/poll misleading-indentation reformatted (now zero
compiler warnings on -Wextra for the Linux build), helper imports
consolidated, runtests prints per-suite wall times. Substantive fix
found by the audit: dt_rand_seed accumulated in 'unsigned long' =
32-bit on EVERY Windows ABI, so the (x>>32) fold was UB/no-op - the
sid/heap seed was weaker than designed on both DLL builds; now a real
64-bit accumulator. CAUTION logged the hard way twice more: pruning
'unused' imports needs WORD-ANCHORED usage counts (line-count grep
swallowed encode_stsid -> _implicit_grant NameError -> perdest spun its
10s-retry loop looking like a hang), and never pipe runtests through
tail (buffers until EOF; write to a file). Full gate 20/20 parallel. Then the registry's own bug: stale
claims accumulate (SIGKILL'd suites never release) and only key-matched
takeover reclaimed them - a day of runs filled all 192 slots and the
fail-open (-2) path silently re-allowed same-node duplicate binds.
slp_claim now does a janitor pass at allocation (dead-owner slot =
free slot; full tables pay one bounded liveness scan per claim).
bindfidelity runs stacked-green against an intentionally full registry;
gate 20/20 again.

Shared-port fidelity final cut: the ledger's UDP rule is now exactly
the kernel's (SO_REUSEADDR on both sides), the Wine clash fixture was
corrected to test the faithful matrix instead of the old alias-around
behavior (a fixture asserting non-kernel semantics was the blocker, not
the hook), and hk_bind's single-exit path both restores the debug
`bind pid=` line the harnesses watch and stops dlog from clobbering
WSAGetLastError (field-visible class of bug: apps saw err 2 for a
refused bind). test-all now runs everything - 19 Linux suites + Wine -
as ONE parallel set: 20/20.

Ledger rc-fixes (field crash cut): rc10 AV'd the game at startup -
GetProcessTimes faulted writing its create-time out-param (reproducible
under Wine); replaced with Peb->CreateTime self-stamp + GetExitCodeProcess
liveness (never GetProcessTimes). Same repro surfaced two registry
integrity bugs: fresh-detection via ERROR_ALREADY_EXISTS is not preserved
(Wine showed fresh=1 while a holder was live - wiping the registry between
processes; init is content-based under the mutex now) and the section
create handle must stay open (Wine drops pages of handle-closed sections
despite live views). Debug-gated slp claim/attach logs ship for field
runs. Verified under Wine with the real DLL: same-node TCP dup -> 10048
with live-holder verdict in log, cross-node dup aliases and presents the
vport, bind(0) lands in the node ephemeral space; Linux 19/19, Wine
test-all gates the release of this cut.

Parallel-haul fixes (this cut, beyond the harness work): (1) ARP
fan-out for implicit streams now excludes the OPENER'S WHOLE NODE and
grants claims on a short preferential window (IMPLICIT_GRACE_S: all
claims collected, freshest host_claim wins, rest get BUSY) - with
pure first-come claims a bridge host could claim its own stream and
host-migration was nondeterministic (perdest/tcp-survive caught it).
(2) wclient fire-and-forget `create_task` calls had no strong refs -
the loop holds only weak references, so live stream pumps could be
GC'd mid-flight (the exact "Task was destroyed but it is pending"
+ peer-EOP pattern perdest hit under parallel load); all spawn sites
now go through WinClient._spawn() (same pattern the relay's
_conn_tasks uses).

Parallel test harness (this cut): `make -C hook test` now runs every
suite concurrently via runtests.py (-j auto = cpu_count; `J=n` or
SHADOWLAN_TEST_JOBS to override; name substrings filter). All 18 suites
self-allocate REAL ports via testutil.free_port()/free_ports()/free_trio()
and pid-unique tmp paths; test_socket_doors is now fully self-contained
(both child scripts embedded instead of the old /tmp/opencode files, with
an explicit client-dead mode instead of a hard-coded port-number sniff).
Hook-internal vports may stay fixed (aliasing covers same-port siblings).

Event-driven internal IO (this cut): every tunnel wait is now an event,
not a poll cadence. Control link + per-stream pumps select on kernel
readiness PLUS self-wake datagram pairs (socketpair on Linux, connected
loopback UDP pair on Windows) so a cross-thread enqueue (app send,
control-frame queue, in-window reopen, close handoff) wakes the sleeper
immediately; poll slices remain only as idle backstops (100ms control,
100ms pumps, 2ms handshake frames). Wake paths MUST call real libc/ws2
symbols (r_send/r_recv, GetProcAddress'd send/recv): the hooked entry
points re-enter the non-recursive DLOCK and deadlock - caught by
test_direct/virtual_p2p/lanonly when the first cut used plain calls.
Wake-only select wakeups must skip the frame reader (EAGAIN there means
redial: the first cut tore the control link down on every app send).
Measured locally: claim round trip open->ok <1ms (was 44ms in field
logs), 271KB relay->app in 77ms pre-fix; suites + fullduplex gate it.

Field join timeline closed (rc7 logs): joiner received the host's full
270,986B lobby reply 77ms after the bridge (per-chunk hs out proves the
pump caught the game's writes instantly; partial recvs rule out pump
lag). The remaining ~16s = the HOST GAME writing the giant message's
final 464B as 113B pieces on its own exact 5.0s rounds - head-of-line
protobuf parse waits for that tail; a JOIN retry after it lands joins
immediately. Trigger counts (LAN 12 vs vnet 1 lobby-dataupdates) also
point at app-side peer bookkeeping, not transport. Nothing pending in
hook/relay for the join path; exit-drain verified live (3x per machine,
clean player-gone cascade).

Kernel close/duplex fidelity (this cut): shutdown() implemented
(SHUT_RD discards, SHUT_WR flushes + FINs the peer via new T_STSHUT
control frame; reverse direction stays alive); close() now flushes the
queued out-queue before retiring the stream; peer FIN half-closes both
pumps instead of killing them; FIN vs RST distinguished (recv: 0 vs
ECONNRESET; Linux send-on-reset raises SIGPIPE); getsockopt(SO_ERROR)
emulates connect completion (0 while pending - the kernel carries only
completion errors - refused/timeout/reset after); select/poll suppress
the vacuous writable of a still-connecting socket and deliver the
connect edge once at verdict; hosted-pump relay-read gate fixed (the
hold slot could be overwritten mid-drain, silently dropping up to a
64KB window). New test_fullduplex covers all of it; exitdrain uses an
isolated subnet. T_STSHUT: relay+hook ship together (old peers just
never half-close - degrades, no corruption).

Hosted-pump integrity (this cut): the joinee pipe used to abandon the
remainder of a game read when the relay connection would block
(nonblocking send + bare break) - a silently corrupted stream strands
the peer's message parser until the sender's NEXT write flushes the
tail, which presents as multi-second-to-minute join/data stalls that
look app-side. Now a hold slot + writable watch + read-gate (no new
game reads while pending), i.e. kernel send-buffer semantics inside the
pump. Pump chunk logs (hs in/out) are unconditional for field timing.

Exit semantics + membership truth (this cut): (1) the kernel flushes a
socket's queued bytes when a process exits — our stream out-queue did
not, so a game's parting frames died with it and peers waited out the
app-level timeout instead of seeing a clean close (field: stale player
after quit). dt_flush_streams() now drains queued stream bytes + the
control-frame queue on exit (cooperative flushing/sending handshake
with the pumps, bounded budget, fds left open so teardown FINs after
the bytes). Hooked doors: Windows ExitProcess/TerminateProcess (self),
Linux exit/_exit + atexit. test_exitdrain proves 200KB queued +
os._exit still lands byte-exact. (2) members() only lists nodes with a
LIVE link — a fully dark node keeps its virtual IP reserved for
reconnect, but is no longer advertised in ASSIGN, so peer member
tables drop a departed machine immediately (was: up to NODE_TTL).

Transport tuning + visibility (this cut): every tunnel TCP dial
(per-stream + control) requests TCP_NODELAY and 4MB SO_SNDBUF/RCVBUF
BEFORE connect (window scaling rides the SYN); relay accepted sockets
get the same. App-tx/app-rx hook logs now stamp every >=4KB write
(throttle only applies below that) and the hosted pump logs `hs in/out
sid= n= tot=` for >=4KB reads — needed because the accepted-side game
writes were previously invisible (bridge sockets bypass the stream
hooks). Verified in-sandbox under the exact field topology (LAN_ONLY=1,
local relay, same-box two-link nodes): a single 135,725B push lands in
38ms with zero gaps - relay-side `pipe closed` counts matched both
apps' totals to the byte. Field trickle of the same payload is
therefore APP-side pacing (lobby pushes ride its 5s beacon rounds;
LAN differs only in per-hop timing), not tunnel stalls. If a field run
still starves a JOIN budget, the new unthrottled logs show exactly
which hop paced.

Unpushed relay + hook layer commits: designated-host election RETIRED (ARP-style implicit fan-out,
claim resolves; NODE_F_HOST = ordering stamp only); UDP-over-TCP links
addressable via ("tcp",writer) identity in node_udp_addrs/udp_targets/
udp_sendto (fixes the field `pdat drop (no-udp-endpoint)` = "lobby
visible, join never starts"); st["busy"] KeyError landmine removed;
hook: dt_rand_seed (sid collisions under inherited LAN_HOOK_NODE),
own-machine dial loopback (dt_is_dial_local must compare against
g_node, NOT the vnode number - comparing wrongly left it dead code and
own-address dials returned as ghost self-connections: field
`TCP SOCKET HEARTBEAT TIMEOUT` storms before any peer activity),
accept-door real symbol + rlport fix, Windows MSG_DONTWAIT misuse
dropped. A beacon cache/replay for late joiners was tried and REMOVED:
a LAN forwards, it never replays (see hard constraints). Linux suite
10/10 + relay suites + doors + e2e green, Wine test-all green.

Findings: transport proven fully transparent in the field - the relay's
`pipe closed ... Xb/Yb` counts match both apps' byte counters exactly
(the apparent "duplicated 135KB blob" was the app's own JOIN re-push
within 1ms, hidden by hook log throttling). Remaining join failure is
at the bridge library's TCP message parsing on the joiner (271KB reply
delivered intact, ~5 messages unbuffered, no lobby object created) -
next diagnostic: a same-game LAN-pair run with full logs to diff the
message sequence. KNOWN: Linux-sandbox game-only pair segfaults (-11)
with ANY hook/relay version incl. none of this round's changes, while
the same build joins fine on a pure LAN pair and Windows field runs
never crash - Linux-only pre-existing artifact, NOT a field blocker;
do not re-chase from the tunnel side.

## Status snapshot (2026-09-13)

2.0.0 RELEASED + post-release field fixes on master (pushed): early-STOK
`39ff861`, relay verdict/fuse + accept-door spoof + dial/select fixes
(`3d30c2d`) with test_socket_doors / test_stfail_semantics /
test_burst_connect; LAN e2e + Wine IF_* suites green. The field game
session flow now blocks INSIDE the bridge library's server-init
assert (reproduced on a pure LAN pair with no tunnel involved) - the
lobby layer is end-to-end healthy.

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
