#!/usr/bin/env python3
"""ShadowLAN dedicated relay. Runs on a VPS with a public IP.

Listens on ONE public port number for both protocols:
  TCP 0.0.0.0:P  -> discovery + game-TCP streams (multiplexed) + membership
  UDP 0.0.0.0:P  -> game-UDP datagrams (low latency, stays UDP)

No TUN/TAP, no virtual NIC, no driver. Any peer can host: the relay
routes addressed (virtual-IP) and implicit (unaddressed) traffic between peers grouped
by --token, and assigns each node a virtual LAN IP (default 10.200.0.0/24).
"""
import argparse
import asyncio
import socket
import struct
import time

from common import (
    VERSION,
    T_BCAST, T_BCAST_FROM, T_TCP_OPEN, T_TCP_DATA_C2S, T_TCP_DATA_S2C,
    T_TCP_CLOSE, T_HELLO, T_NODE, T_ASSIGN, T_POPEN,
    U_GAME_C2S, U_GAME_S2C, U_GAME_P2P, U_HELLO_HOST, U_NODE, UMAGIC, UVER,
    QueueProto,
    decode_udp_game, encode_udp_game, decode_udp_hello,
    decode_hello, decode_node, decode_udp_node, decode_popen, decode_pdat,
    encode_assign, encode_bcast_from,
    ip_to_int, int_to_ip, parse_ports, tcp_read, tcp_send,
)


class Relay:
    """Pure relay for VPS use: no local game, routes peers to each other.

    Any peer can host. Nodes register with T_NODE/U_NODE (token = room)
    and get a virtual LAN IP; addressed frames (POPEN/PDATA/BCAST_FROM)
    carry sender identity so games see distinct peers. Legacy peers
    (no NODE) keep working via designated-host + beaconer fallbacks.
    """

    HOST_UDP_TTL = 45      # forget uplink UDP endpoint after this silence
    BEACON_TTL = 30        # beaconer fallback freshness
    KNOWN_TTL = 120        # known UDP endpoint freshness
    LEARN_TTL = 60         # (src, game_port) -> replier freshness (per-sender sticky)
    FLOW_TTL = 120         # per-dest triple -> player routing freshness
    NODE_GRACE = 5         # token relays: NODE-or-HELLO deadline per conn
    NODE_TTL = 600         # forget disconnected nodes (writer gone) after this

    def __init__(self, port, token="", allowed_tcp=None, allowed_udp=None,
                 disc_ports=None, subnet="10.200.0.0/24"):
        self.port = port
        self.token = token.encode() if isinstance(token, str) else (token or b"")
        self.allowed_tcp = set(allowed_tcp or [])
        self.allowed_udp = set(allowed_udp or [])
        self.disc_ports = set(disc_ports or [])
        try:
            net, bits = subnet.split("/")
            assert int(bits) == 24
            self.subnet_net = ip_to_int(net) & 0xFFFFFF00
        except Exception:
            raise ValueError(f"bad --subnet {subnet!r} (need A.B.C.0/24)")
        self.host_writer = None
        self.players = set()
        self.roles = {}  # id(writer) -> "host" | "player"
        self.send_locks = {}
        self.c2h = {}  # (id(src_writer), sid_s) -> (sid_t, target_writer)
        self.h2c = {}  # sid_t -> (src_writer, sid_s, target_writer)
        self.next_sid = 1
        self.beaconers = {}  # writer -> last BCAST seen (TCP-routable fallback)
        # virtual-IP membership: node_id -> dict(writer, tcp_ip, udp_port,
        # udp_addr, virt, seen_tcp, seen_udp)
        self.nodes = {}
        self.writer_node = {}  # id(writer) -> node_id
        self.next_virt = 2  # .1 reserved
        self.host_udp = None
        self.host_udp_seen = 0.0
        self.known_udp = {}  # addr -> last seen (fan-out candidates)
        # Per-sender sticky: (src_addr, game_port) -> (replier_addr, seen).
        # A global game_port -> replier flaps when two hosts serve the same
        # port; per-sender lets each player stick to its own host.
        self.learned = {}
        # Per-dest flows: (dest_tag, game_port, cli_ip, cli_port) ->
        # [player_addr, seen]. dest_tag is ('n', dest_node) for addressed
        # P2P or ('a', ip, port) for address-scope fan-out. Scoping by dest means
        # identical LAN triples (192.168.x.x, hook 127.0.0.1:5000x) to
        # different hosts no longer collide; same-dest collisions still
        # log and last-writer-wins (fix senders to use unique triples -
        # the hook uses its virtual IP - for full isolation).
        self.udp_flows = {}
        self._public_udp = None
        self._last_noroute = 0.0
        self._pdat_warn = {}
        self._unk_op = {}

    async def r_send(self, writer, mtype, payload):
        lock = self.send_locks.setdefault(id(writer), asyncio.Lock())
        async with lock:
            await tcp_send(writer, mtype, payload)

    def alloc_sid(self):
        for _ in range(0xFFFFFFFF):
            sid = self.next_sid
            self.next_sid = (self.next_sid + 1) & 0xFFFFFFFF or 1
            if sid and sid not in self.h2c:
                return sid
        raise RuntimeError("sid space exhausted")

    def token_ok(self, tok):
        if tok is None:
            return False
        if self.token and tok != self.token:
            return False
        return True

    async def promote_host(self, writer, peer):
        # Non-destructive handover: existing streams keep flowing to their
        # original targets (POPEN addressed streams especially must survive
        # a second host claiming). Only future implicit T_TCP_OPENs go to
        # the new holder. The old holder is demoted, never kicked, so a
        # shared-link claimant stays playable. One game per relay port is
        # still the documented setup; this just stops a claim from killing
        # live sessions.
        old = self.host_writer
        self.host_writer = writer
        self.roles[id(writer)] = "host"
        self.players.discard(writer)
        if old is not None and old is not writer:
            self.players.add(old)
            self.roles[id(old)] = "player"
            print(f"[relay] host demoted to player: "
                  f"{old.get_extra_info('peername')}", flush=True)
        print(f"[relay] host uplink up from {peer}", flush=True)

    def route_tcp(self, port, exclude=None):
        """Where should a TCP OPEN for port go? Designated, else
        most-recent beaconer, else nowhere."""
        now = time.monotonic()
        if self.host_writer is not None and self.host_writer is not exclude \
                and not self.host_writer.is_closing():
            return self.host_writer
        best, best_seen = None, -1.0
        for w, seen in list(self.beaconers.items()):
            if w is exclude or w.is_closing():
                continue
            if now - seen < self.BEACON_TTL and seen > best_seen:
                best, best_seen = w, seen
        return best

    def virt_str(self, v):
        return int_to_ip(v)

    def members(self):
        return [(n, e["virt"]) for n, e in self.nodes.items() if e.get("virt")]

    async def send_assign(self, writer):
        node = self.writer_node.get(id(writer))
        ent = self.nodes.get(node, {}) if node else {}
        try:
            await self.r_send(writer, T_ASSIGN,
                              encode_assign(ent.get("virt", 0), self.subnet_net,
                                            24, self.members()))
        except (ConnectionResetError, BrokenPipeError, RuntimeError):
            pass

    async def broadcast_assign(self, exclude=None):
        for w in list(self.players) + ([self.host_writer] if self.host_writer else []):
            if w is exclude or w.is_closing():
                continue
            if id(w) not in self.writer_node:
                continue  # unregistered peer: no node table
            await self.send_assign(w)

    def prune_nodes(self, now=None):
        """Drop disconnected nodes idle past NODE_TTL. Without this,
        every short-lived peer (helper processes, redial storms) pins
        a virtual IP forever and the /24 fills up until nobody new can
        register ("subnet full")."""
        now = time.monotonic() if now is None else now
        for nid, ent in list(self.nodes.items()):
            w = ent.get("writer")
            if (w is None or w.is_closing()) and \
                    now - ent.get("seen_tcp", 0) > self.NODE_TTL:
                self.nodes.pop(nid, None)
                for o, i in list(self.writer_node.items()):
                    if i == nid:
                        self.writer_node.pop(o, None)

    async def register_node(self, writer, peer, token, node, udp_port):
        """T_NODE/U_NODE endpoint: returns True if accepted."""
        if not self.token_ok(token):
            return False
        now = time.monotonic()
        try:
            tcp_ip = writer.get_extra_info("peername")[0]
        except Exception:
            tcp_ip = ""
        ent = self.nodes.get(node)
        if ent is None:
            self.prune_nodes(now)
            virt = None
            # find free address without mutating yet
            used = {e["virt"] for e in self.nodes.values() if e.get("virt")}
            for i in range(2, 255):
                v = self.subnet_net | i
                if v not in used:
                    virt = v
                    break
            if virt is None:
                # full even after pruning: evict the stalest
                # disconnected entry rather than lock out live peers
                cand, cand_seen = None, None
                for nid, e in self.nodes.items():
                    w = e.get("writer")
                    if w is None or w.is_closing():
                        s = e.get("seen_tcp", 0)
                        if cand is None or s < cand_seen:
                            cand, cand_seen = nid, s
                if cand is None:
                    print("[relay] subnet full, rejecting node "
                          f"{node}", flush=True)
                    return False
                old = self.nodes.pop(cand)
                for o, i in list(self.writer_node.items()):
                    if i == cand:
                        self.writer_node.pop(o, None)
                virt = old.get("virt")
                print(f"[relay] subnet full: evicted stale node {cand} "
                      f"for node {node}", flush=True)
            ent = {"writer": None, "tcp_ip": "", "udp_port": 0,
                   "udp_addr": None, "virt": virt,
                   "seen_tcp": 0.0, "seen_udp": 0.0}
            self.nodes[node] = ent
            print(f"[relay] node {node} -> {self.virt_str(virt)}", flush=True)
        ent["seen_tcp"] = now
        if ent.get("writer") not in (None, writer):
            old = ent["writer"]
            if not old.is_closing():
                old.close()  # stale duplicate connection
        ent["writer"] = writer
        ent["tcp_ip"] = tcp_ip
        if udp_port:
            ent["udp_port"] = udp_port
            ent["udp_addr"] = (tcp_ip, udp_port)
            ent["seen_udp"] = now
            self.known_udp[(tcp_ip, udp_port)] = now
        self.writer_node[id(writer)] = node
        await self.send_assign(writer)
        # tell everyone else about the (possibly new) member
        for w in list(self.players) + ([self.host_writer] if self.host_writer else []):
            if w is not writer and id(w) in self.writer_node and not w.is_closing():
                await self.send_assign(w)
        return True

    async def node_grace(self, writer, peer):
        """Token relays: drop connections that never identify."""
        if not self.token:
            return
        await asyncio.sleep(self.NODE_GRACE)
        if writer.is_closing():
            return
        if id(writer) not in self.writer_node and self.host_writer is not writer:
            print(f"[relay] no NODE/HELLO from {peer}, dropping", flush=True)
            writer.close()

    async def handle_peer(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self.players.add(writer)
        self.roles[id(writer)] = "player"
        self.send_locks.setdefault(id(writer), asyncio.Lock())
        owner = id(writer)
        grace = asyncio.create_task(self.node_grace(writer, peer))
        try:
            while True:
                mtype, payload = await tcp_read(reader)
                if mtype == T_HELLO:
                    tok = decode_hello(payload)
                    if not self.token_ok(tok):
                        print(f"[relay] bad/missing host token from {peer}, dropping", flush=True)
                        return
                    await self.promote_host(writer, peer)
                    continue
                if mtype == T_NODE:
                    dec = decode_node(payload)
                    if not dec:
                        continue
                    tok, node, uport = dec
                    if not node:
                        continue
                    ok = await self.register_node(writer, peer, tok, node, uport)
                    if not ok:
                        return
                    continue
                if mtype == T_POPEN:
                    dec = decode_popen(payload)
                    if not dec:
                        continue
                    sid_c, dest_node, gport = dec
                    if self.allowed_tcp and gport not in self.allowed_tcp:
                        continue
                    tgt = self.nodes.get(dest_node)
                    target = tgt["writer"] if tgt and tgt.get("writer") \
                        and not tgt["writer"].is_closing() and tgt["writer"] is not writer else None
                    if target is None:
                        try:
                            await self.r_send(writer, T_TCP_CLOSE, struct.pack("!I", sid_c))
                        except (ConnectionResetError, BrokenPipeError, RuntimeError):
                            pass
                        continue
                    try:
                        sid_h = self.alloc_sid()
                    except RuntimeError:
                        continue
                    self.c2h[(owner, sid_c)] = (sid_h, target)
                    self.h2c[sid_h] = (writer, sid_c, target)
                    try:
                        await self.r_send(target, T_TCP_OPEN,
                                          struct.pack("!IH", sid_h, gport))
                    except (ConnectionResetError, BrokenPipeError, RuntimeError):
                        pass
                    continue
                role = "host" if self.host_writer is writer else "player"
                if mtype == T_BCAST:
                    if len(payload) < 4:
                        continue
                    (dport, sport) = struct.unpack("!HH", payload[:4])
                    raw = payload[4:]
                    if self.disc_ports and dport not in self.disc_ports:
                        continue
                    # Every beacon fans out as-is; echo loops are cut at
                    # the edge and distinct hosts stay visible.
                    self.beaconers[writer] = time.monotonic()
                    src_node = self.writer_node.get(owner, 0)
                    for w in list(self.players) + ([self.host_writer] if self.host_writer else []):
                        if w is writer or w.is_closing():
                            continue
                        try:
                            if src_node and id(w) in self.writer_node:
                                await self.r_send(w, T_BCAST_FROM,
                                                  encode_bcast_from(src_node, dport, sport, raw))
                            else:
                                await self.r_send(w, T_BCAST, payload)
                        except (ConnectionResetError, BrokenPipeError, RuntimeError):
                            pass
                    continue
                if mtype == T_TCP_OPEN:
                    if len(payload) < 6:
                        continue
                    sid_c, gport = struct.unpack("!IH", payload[:6])
                    if self.allowed_tcp and gport not in self.allowed_tcp:
                        continue
                    target = self.route_tcp(gport, exclude=writer)
                    if target is None:
                        try:
                            await self.r_send(writer, T_TCP_CLOSE, struct.pack("!I", sid_c))
                        except (ConnectionResetError, BrokenPipeError, RuntimeError):
                            pass
                        continue
                    try:
                        sid_h = self.alloc_sid()
                    except RuntimeError:
                        continue
                    self.c2h[(owner, sid_c)] = (sid_h, target)
                    self.h2c[sid_h] = (writer, sid_c, target)
                    try:
                        await self.r_send(target, T_TCP_OPEN,
                                          struct.pack("!IH", sid_h, gport))
                    except (ConnectionResetError, BrokenPipeError, RuntimeError):
                        pass
                elif mtype == T_TCP_DATA_C2S:
                    if len(payload) < 4:
                        continue
                    (sid_c,) = struct.unpack("!I", payload[:4])
                    ent = self.c2h.get((owner, sid_c))
                    if ent is None:
                        continue
                    sid_h, target = ent
                    try:
                        await self.r_send(target, T_TCP_DATA_C2S,
                                          struct.pack("!I", sid_h) + payload[4:])
                    except (ConnectionResetError, BrokenPipeError, RuntimeError):
                        pass
                elif mtype == T_TCP_DATA_S2C:
                    if len(payload) < 4:
                        continue
                    (sid_h,) = struct.unpack("!I", payload[:4])
                    ent = self.h2c.get(sid_h)
                    if not ent:
                        continue
                    cw, sid_c, _tgt = ent
                    try:
                        await self.r_send(cw, T_TCP_DATA_S2C,
                                          struct.pack("!I", sid_c) + payload[4:])
                    except (ConnectionResetError, BrokenPipeError, RuntimeError):
                        pass
                elif mtype == T_TCP_CLOSE:
                    if len(payload) < 4:
                        continue
                    (sid,) = struct.unpack("!I", payload[:4])
                    # sid spaces collide (source and target ids share u32),
                    # so a CLOSE may mean either side: handle both;
                    # duplicate CLOSEs are idempotent.
                    ent = self.c2h.pop((owner, sid), None)
                    if ent is not None:
                        sid_h, target = ent
                        self.h2c.pop(sid_h, None)
                        try:
                            await self.r_send(target, T_TCP_CLOSE,
                                              struct.pack("!I", sid_h))
                        except (ConnectionResetError, BrokenPipeError, RuntimeError):
                            pass
                    for sid_h, (cw, sid_c, tgt) in list(self.h2c.items()):
                        if sid_h == sid and tgt is writer:
                            self.h2c.pop(sid_h, None)
                            self.c2h.pop((id(cw), sid_c), None)
                            try:
                                await self.r_send(cw, T_TCP_CLOSE,
                                                  struct.pack("!I", sid_c))
                            except (ConnectionResetError, BrokenPipeError, RuntimeError):
                                pass
        except (asyncio.IncompleteReadError, ConnectionResetError, ValueError):
            pass
        finally:
            if self.host_writer is writer:
                self.host_writer = None
                print(f"[relay] host uplink {peer} down", flush=True)
            else:
                self.players.discard(writer)
                print(f"[relay] player {peer} gone", flush=True)
            # streams sourced here: tell their targets
            for (o, sid_c), (sid_h, target) in list(self.c2h.items()):
                if o == owner:
                    self.c2h.pop((o, sid_c), None)
                    self.h2c.pop(sid_h, None)
                    try:
                        await self.r_send(target, T_TCP_CLOSE,
                                          struct.pack("!I", sid_h))
                    except Exception:
                        pass
            # streams targeted here: tell their sources
            for sid_h, (cw, sid_c, tgt) in list(self.h2c.items()):
                if tgt is writer:
                    self.h2c.pop(sid_h, None)
                    self.c2h.pop((id(cw), sid_c), None)
                    try:
                        await self.r_send(cw, T_TCP_CLOSE,
                                          struct.pack("!I", sid_c))
                    except Exception:
                        pass
            self.roles.pop(owner, None)
            self.send_locks.pop(owner, None)
            self.beaconers.pop(writer, None)
            node = self.writer_node.pop(owner, None)
            if node is not None:
                ent = self.nodes.get(node)
                if ent is not None and ent.get("writer") is writer:
                    ent["writer"] = None  # keep node+virt for reconnect
                    asyncio.create_task(self.broadcast_assign())
            grace.cancel()
            try:
                writer.close()
            except Exception:
                pass

    def note_noroute(self, what):
        now = time.monotonic()
        if now - self._last_noroute > 10:
            self._last_noroute = now
            print(f"[relay] no route for {what}, dropping", flush=True)

    def note_unknown_udp(self, op):
        now = time.monotonic()
        if now - self._unk_op.get(op, 0.0) > 10:
            self._unk_op[op] = now
            print(f"[relay] unknown UDP opcode 0x{op:02x}, dropping",
                  flush=True)

    def node_by_udp_addr(self, addr):
        """Tunnel addr -> dest node id, freshest match (for S2C lookup)."""
        best, best_seen = None, -1.0
        for nid, ent in self.nodes.items():
            if ent.get("udp_addr") == addr:
                seen = ent.get("seen_udp", 0)
                if seen > best_seen:
                    best, best_seen = nid, seen
        if best is not None:
            return best
        for nid, ent in self.nodes.items():
            if ent.get("udp_port") and ent.get("tcp_ip") and \
                    (ent["tcp_ip"], ent["udp_port"]) == addr:
                return nid
        return None

    def udp_targets(self, gport, src_addr):
        """Who should get a UDP C2S for game_port? This sender's sticky
        replier, else fan-out to all known endpoints except the source."""
        now = time.monotonic()
        ent = self.learned.get((src_addr, gport))
        if ent is not None:
            addr, seen = ent
            if now - seen < self.LEARN_TTL and addr != src_addr:
                return [addr]
            self.learned.pop((src_addr, gport), None)
        out = [a for a, seen in self.known_udp.items()
               if a != src_addr and now - seen < self.KNOWN_TTL]
        if self.host_udp is not None and now - self.host_udp_seen < self.HOST_UDP_TTL \
                and self.host_udp != src_addr and self.host_udp not in out:
            out.append(self.host_udp)
        return out

    async def udp_consume(self, pproto):
        while True:
            data, addr = await pproto.q.get()
            if len(data) < 4 or data[:2] != UMAGIC or data[2] != UVER:
                continue
            mtype = data[3]
            if mtype == U_HELLO_HOST:
                tok = decode_udp_hello(data)
                if not self.token_ok(tok):
                    continue
                if self.host_udp != addr:
                    print(f"[relay] host UDP endpoint {addr}", flush=True)
                self.host_udp = addr
                self.host_udp_seen = time.monotonic()
                self.known_udp[addr] = time.monotonic()
                continue
            if mtype == U_NODE:
                dec = decode_udp_node(data)
                if not dec:
                    continue
                tok, node, _uport = dec
                if not self.token_ok(tok):
                    continue
                ent = self.nodes.get(node)
                if ent is None:
                    continue  # TCP NODE first; UDP alone registers nothing
                ent["udp_addr"] = addr
                ent["seen_udp"] = time.monotonic()
                self.known_udp[addr] = time.monotonic()
                continue
            if mtype == U_GAME_P2P:
                dec = decode_pdat(data)
                if not dec:
                    continue
                dest_node, gport, _cip, _cport, _raw = dec
                if self.allowed_udp and gport not in self.allowed_udp:
                    continue
                tgt = self.nodes.get(dest_node)
                taddr = None
                if tgt:
                    now = time.monotonic()
                    if tgt.get("udp_addr") and now - tgt.get("seen_udp", 0) < self.KNOWN_TTL:
                        taddr = tgt["udp_addr"]
                    elif tgt.get("udp_port") and tgt.get("tcp_ip"):
                        taddr = (tgt["tcp_ip"], tgt["udp_port"])
                if taddr is None or taddr == addr:
                    why = "same-addr" if taddr == addr else (
                        "unknown-node" if tgt is None else "no-udp-endpoint")
                    now = time.monotonic()
                    if now - self._pdat_warn.get(dest_node, 0.0) > 5.0:
                        self._pdat_warn[dest_node] = now
                        print(f"[udp] pdat drop ({why}) dest node "
                              f"{dest_node} gport {gport}", flush=True)
                    continue
                print_k = ("ok", dest_node, gport)
                if now - self._pdat_warn.get(print_k, 0.0) > 5.0:
                    self._pdat_warn[print_k] = now
                    print(f"[udp] pdat {addr} -> node {dest_node} @{taddr} "
                          f"gport {gport} len {len(_raw)}", flush=True)
                self.known_udp[addr] = time.monotonic()
                key = (("n", dest_node), gport, _cip, _cport)
                prev = self.udp_flows.get(key)
                if prev is not None and prev[0] != addr:
                    print(f"[relay] UDP triple collision for dest node "
                          f"{dest_node} on {(gport, _cip, _cport)}, "
                          f"latest sender wins", flush=True)
                self.udp_flows[key] = [addr, time.monotonic()]
                if len(self.udp_flows) > 2048:
                    self.udp_flows.clear()
                # strip the dest prefix: target sees an ordinary C2S
                inner = encode_udp_game(U_GAME_C2S, gport, _cip, _cport, _raw)
                try:
                    self._public_udp.sendto(inner, taddr)
                except OSError as e:
                    print(f"[udp] pdat sendto {taddr} failed: {e}", flush=True)
                except AttributeError:
                    print("[udp] pdat: no public UDP socket yet", flush=True)
                continue
            if mtype == U_GAME_S2C:
                # bridge reply (wclient --host / hook inbound): route by the
                # per-dest triple recorded when the C2S went out; bytes
                # untouched. The S2C sender is the host that got the C2S,
                # so look up (that dest, triple) -> player.
                dec = decode_udp_game(data)
                if not dec:
                    continue
                _m, gport, cip, cport, _raw = dec
                now = time.monotonic()
                ent = self.udp_flows.get((("a", addr[0], addr[1]),
                                          gport, cip, cport))
                if ent is None:
                    nid = self.node_by_udp_addr(addr)
                    if nid is not None:
                        ent = self.udp_flows.get((("n", nid), gport,
                                                  cip, cport))
                if ent is None:
                    # fallback: sender addr changed (NAT rebinding) or old
                    # pre-restart flow - scan same triple across dests,
                    # freshest wins (ambiguity is logged, not silent)
                    best_k, best_e, best_seen = None, None, -1.0
                    for k, e in self.udp_flows.items():
                        if len(k) != 4 or k[1] != gport or k[2] != cip \
                                or k[3] != cport:
                            continue
                        if e[1] > best_seen and now - e[1] < self.FLOW_TTL:
                            best_k, best_e, best_seen = k, e, e[1]
                    if best_e is None:
                        continue
                    if sum(1 for k, e in self.udp_flows.items()
                           if len(k) == 4 and k[1] == gport and k[2] == cip
                           and k[3] == cport
                           and now - e[1] < self.FLOW_TTL) > 1:
                        print(f"[relay] UDP S2C ambiguous on "
                              f"{(gport, cip, cport)}, freshest wins",
                              flush=True)
                    ent = best_e
                paddr, seen = ent
                if now - seen > self.FLOW_TTL:
                    continue
                ent[1] = now
                self.learned[(paddr, gport)] = (addr, now)
                if len(self.learned) > 2048:
                    self.learned.clear()
                try:
                    self._public_udp.sendto(data, paddr)
                except (OSError, AttributeError):
                    pass
                continue
            if mtype != U_GAME_C2S:
                self.note_unknown_udp(mtype)
                continue
            dec = decode_udp_game(data)
            if not dec:
                continue
            _m, gport, _cip, _cport, _raw = dec
            if self.allowed_udp and gport not in self.allowed_udp:
                continue
            self.known_udp[addr] = time.monotonic()
            dests = self.udp_targets(gport, addr)
            if not dests:
                self.note_noroute("UDP")
                continue
            for dst in dests:
                key = (("a", dst[0], dst[1]), gport, _cip, _cport)
                prev = self.udp_flows.get(key)
                if prev is not None and prev[0] != addr:
                    print(f"[relay] UDP triple collision for dest {dst} on "
                          f"{(gport, _cip, _cport)}, latest sender wins",
                          flush=True)
                self.udp_flows[key] = [addr, time.monotonic()]
            if len(self.udp_flows) > 2048:
                self.udp_flows.clear()
            for dst in dests:
                try:
                    self._public_udp.sendto(data, dst)  # bytes untouched
                except (OSError, AttributeError):
                    pass

    async def run(self):
        loop = asyncio.get_running_loop()
        psock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        psock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        psock.bind(("0.0.0.0", self.port))
        psock.setblocking(False)
        pproto = QueueProto()
        self._public_udp, _ = await loop.create_datagram_endpoint(lambda: pproto, sock=psock)
        print(f"[udp] relay 0.0.0.0:{self.port}", flush=True)
        asyncio.create_task(self.udp_consume(pproto))
        srv = await asyncio.start_server(self.handle_peer, "0.0.0.0", self.port)
        print(f"[tcp] relay 0.0.0.0:{self.port}", flush=True)
        print(f"[up] relay v{VERSION} port={self.port} "
              f"token={'set' if self.token else 'open'}", flush=True)
        async with srv:
            await srv.serve_forever()


def main():
    ap = argparse.ArgumentParser(
        description="ShadowLAN dedicated relay (no TUN/TAP). "
                    "Routes any peer's game to any other peer; "
                    "assigns virtual LAN IPs per token room.")
    ap.add_argument("--port", type=int, required=True,
                    help="public port number (TCP+UDP)")
    ap.add_argument("--token", default="",
                    help="room key: peers must present it (empty = open relay)")
    ap.add_argument("--disc", default="",
                    help="pass only these discovery UDP ports, comma (empty=all)")
    ap.add_argument("--tcp", default="", help="allowed game TCP ports, comma (empty=all)")
    ap.add_argument("--udp", default="", help="allowed game UDP ports, comma (empty=all)")
    ap.add_argument("--subnet", default="10.200.0.0/24",
                    help="virtual subnet for peer IPs (/24 only)")
    a = ap.parse_args()
    r = Relay(a.port, a.token, parse_ports(a.tcp), parse_ports(a.udp),
              parse_ports(a.disc), subnet=a.subnet)
    try:
        asyncio.run(r.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
