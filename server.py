#!/usr/bin/env python3
"""ShadowLAN dedicated relay. Runs on a VPS with a public IP.

Listens on ONE public port number for both protocols:
  TCP 0.0.0.0:P  -> control (membership, host claim, discovery beacons,
                    UDP-over-TCP) + one connection per game TCP stream
  UDP 0.0.0.0:P  -> game-UDP datagrams (low latency, stays UDP)

Every fake game TCP connection is its own real TCP
connection to the relay (both peers dial OUT, NAT-safe). The relay pipes
raw bytes between the two per-stream connections, so a stalled stream
never head-of-line-blocks beacons or other streams. connect() only
succeeds for the opener after the destination has confirmed its local
game bridge (T_STJOIN -> T_STJOINED -> T_STOK).

Any peer can host: the relay routes addressed (virtual-IP) and implicit
(unaddressed) streams, and assigns each node a virtual LAN IP
(default 10.200.0.0/24).
"""
import argparse
import asyncio
import socket
import struct
import time

from common import (
    VERSION, HDR,
    T_BCAST, T_BCAST_FROM, T_NODE, T_ASSIGN,
    T_UDP_TUN, T_UDP_MODE,
    T_STOPEN, T_STREQ, T_STJOIN, T_STJOINED, T_STOK, T_STFAIL,
    STF_NO_ROUTE, STF_JOIN_TIMEOUT, STF_BAD_ID, STF_BUSY,
    U_GAME_C2S, U_GAME_S2C, U_GAME_P2P, U_NODE, UMAGIC, UVER,
    U_ICMP_REQ, U_ICMP_REP,
    QueueProto,
    decode_udp_game, encode_udp_game,
    decode_udp_node, decode_pdat,
    PVER, ctl_ver, decode_ctl_node, NODE_F_HOST,
    encode_assign, encode_bcast_from, encode_icmp, decode_icmp,
    encode_stopen, decode_stopen, encode_streq, decode_streq,
    encode_stjoin, decode_stjoin, encode_stsid, decode_stsid,
    encode_stfail, decode_stfail,
    ip_to_int, int_to_ip, parse_ports, tcp_read, tcp_send,
    ST_TIMEOUT_S,
)


class Relay:
    """Pure relay for VPS use: no local game, routes peers to each other.

    Any peer can host. Nodes register with T_NODE/U_NODE (token = room)
    and get a virtual LAN IP. Per-writer send queues keep one slow
    reader from stalling the room's control traffic.
    """

    HOST_UDP_TTL = 45      # forget uplink UDP endpoint after this silence
    BEACON_TTL = 30        # beaconer fallback freshness
    KNOWN_TTL = 120        # known UDP endpoint freshness
    LEARN_TTL = 60         # (src, game_port) -> replier freshness (per-sender sticky)
    FLOW_TTL = 120         # per-dest triple -> player routing freshness
    NODE_GRACE = 5         # token relays: NODE-or-HELLO deadline per conn
    NODE_TTL = 600         # forget disconnected nodes (writer gone) after this
    # per-writer control queue: drop droppable frames (beacons, UDP-over-
    # TCP datagrams) instead of blocking the room on a stalled reader
    WQ_MAXFRAMES = 1024
    WQ_MAXBYTES = 4 * 1024 * 1024
    DROPPABLE = (T_BCAST, T_BCAST_FROM, T_UDP_TUN)

    def __init__(self, port, token="", allowed_tcp=None, allowed_udp=None,
                 disc_ports=None, subnet="10.200.0.0/24", bind="0.0.0.0"):
        self.port = port
        self.bind = bind or "0.0.0.0"
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
        self.beaconers = {}  # writer -> last BCAST seen (TCP-routable fallback)
        # virtual-IP membership: node_id -> dict(virt, seen_tcp, links)
        # where links maps control-writer -> per-link state
        #   dict(tcp_ip, udp_port, udp_addr, seen_udp, udp_tcp).
        # One node may hold SEVERAL links (processes sharing one identity
        # via the hook's shared state); node-targeted traffic fans out to
        # every live link.
        self.nodes = {}
        self.writer_node = {}  # id(writer) -> node_id
        self.host_udp = None
        self.host_udp_seen = 0.0
        self.known_udp = {}  # addr -> last seen (fan-out candidates)
        # Per-sender sticky: (src_addr, game_port) -> (replier_addr, seen).
        # A global game_port -> replier flaps when two hosts serve the same
        # port; per-sender lets each player stick to its own host.
        self.learned = {}
        # Per-dest flows: (dest_tag, game_port, cli_ip, cli_port) ->
        # [player_addr, seen]. dest_tag is ('n', dest_node) for addressed
        # P2P or ('a', ip, port) for address-scope fan-out. Scoping by dest
        # means identical LAN triples to different hosts don't collide.
        self.udp_flows = {}
        # UDP-over-TCP mode: id(writer) -> True once the link declares
        # T_UDP_MODE; nodes carry udp_tcp; tcp_fallback maps a synthetic
        # sender addr ("tcp", id(writer)) back to its writer.
        self.udp_tcp = {}
        self.tcp_fallback = {}
        self._public_udp = None
        self._udp_task = None
        self._conn_tasks = set()   # live per-connection handler tasks
        self._last_noroute = 0.0
        self._pdat_warn = {}
        self._unk_op = {}
        self._wq_drop_note = {}
        # per-writer send queue (control conn): frame bytes in, drained by
        # one task per writer, so handlers never block on a slow peer
        self.wq = {}        # id(writer) -> asyncio.Queue
        self.wq_size = {}   # id(writer) -> [frames, bytes]
        self.wq_task = {}   # id(writer) -> drain task
        # stream table: sid -> dict(opener_node, opener_r/w, dest_node, gport,
        # state open|ready, joiner_r/w, created, task)
        self.streams = {}
        self.node_streams = {}  # node -> set(sid)

    # ---- per-writer send queue ------------------------------------------
    async def r_send(self, writer, mtype, payload, droppable=None):
        """Queue one framed control message for writer. Never drains
        inline: a stalled reader must not hold the handler (HoL)."""
        if droppable is None:
            droppable = mtype in self.DROPPABLE
        key = id(writer)
        q = self.wq.get(key)
        if q is None:
            q = asyncio.Queue(maxsize=self.WQ_MAXFRAMES)
            self.wq[key] = q
            self.wq_size[key] = [0, 0]
            self.wq_task[key] = asyncio.create_task(self._wq_drain(writer, q))
        frame = HDR.pack(1 + len(payload)) + bytes([mtype]) + payload
        cnt, byts = self.wq_size[key]
        if cnt >= self.WQ_MAXFRAMES or byts > self.WQ_MAXBYTES:
            if droppable:
                now = time.monotonic()
                if now - self._wq_drop_note.get(key, 0.0) > 5.0:
                    self._wq_drop_note[key] = now
                    print(f"[relay] control queue full for "
                          f"{writer.get_extra_info('peername')}: dropping "
                          f"op 0x{mtype:02x}", flush=True)
                return
            while cnt >= self.WQ_MAXFRAMES or byts > self.WQ_MAXBYTES:
                await asyncio.sleep(0.01)
                cnt, byts = self.wq_size[key]
        try:
            q.put_nowait(frame)
        except asyncio.QueueFull:
            if droppable:
                return
            await q.put(frame)
        self.wq_size[key] = [cnt + 1, byts + len(frame)]

    async def _wq_drain(self, writer, q):
        key = id(writer)
        try:
            while True:
                frame = await q.get()
                if frame is None:
                    break
                size = self.wq_size.get(key)
                if size:
                    size[0] -= 1
                    size[1] -= len(frame)
                writer.write(frame)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, RuntimeError, OSError):
            pass
        finally:
            self.wq.pop(key, None)
            self.wq_size.pop(key, None)
            self.wq_task.pop(key, None)
            self._wq_drop_note.pop(key, None)

    # ---- membership -------------------------------------------------------
    def token_ok(self, tok):
        if tok is None:
            return False
        if self.token and tok != self.token:
            return False
        return True

    def claim_host(self, writer, peer):
        # Designated-host claim (T_NODE flags bit). Non-destructive
        # handover: existing streams keep flowing to their original
        # targets; only future implicit opens go to the new holder. The
        # old holder is demoted, never kicked. A re-claim from the same
        # node (process-tree sibling link or a keepalive refresh) never
        # demotes anything: it only refreshes the uplink stamp.
        old = self.host_writer
        if old is writer:
            return
        node = self.writer_node.get(id(writer))
        old_node = self.writer_node.get(id(old)) if old is not None else None
        self.host_writer = writer
        self.roles[id(writer)] = "host"
        self.players.discard(writer)
        if old is not None and old_node != node:
            self.players.add(old)
            self.roles[id(old)] = "player"
            print(f"[relay] host demoted to player: "
                  f"{old.get_extra_info('peername')}", flush=True)
            print(f"[relay] host uplink up from {peer}", flush=True)
        elif old is not None:
            print(f"[relay] host uplink refreshed from {peer}", flush=True)
        else:
            print(f"[relay] host uplink up from {peer}", flush=True)

    def live_links(self, nid, exclude_writer=None, exclude_node=None):
        """All live control writers registered for node nid."""
        ent = self.nodes.get(nid)
        if not ent:
            return []
        out = []
        for w in list(ent["links"]):
            if w is exclude_writer or w.is_closing():
                continue
            if exclude_node is not None and nid == exclude_node:
                continue
            out.append(w)
        return out

    def route_tcp(self, port, exclude=None):
        """Where should an implicit (unaddressed) stream for port go?
        Designated host NODE, else most-recent beaconer's node, else None.
        Returns a node id; the opener fans STREQ to every live link of it
        (shared-identity trees: the process that actually listens locally
        joins first, the others answer BUSY and stand down)."""
        now = time.monotonic()
        excl_node = self.writer_node.get(id(exclude)) if exclude is not None else None
        if self.host_writer is not None and self.host_writer is not exclude \
                and not self.host_writer.is_closing():
            nid = self.writer_node.get(id(self.host_writer))
            if nid is not None and nid != excl_node:
                return nid
        best, best_seen = None, -1.0
        for w, seen in list(self.beaconers.items()):
            if w is exclude or w.is_closing():
                continue
            if excl_node is not None and self.writer_node.get(id(w)) == excl_node:
                continue
            if now - seen < self.BEACON_TTL and seen > best_seen:
                best, best_seen = w, seen
        if best is None:
            return None
        return self.writer_node.get(id(best))

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
        register ("subnet full"). A node stays while ANY link lives."""
        now = time.monotonic() if now is None else now
        for nid, ent in list(self.nodes.items()):
            # housekeeping: detach dead links even if seen_tcp is fresh
            for w in list(ent["links"]):
                if w.is_closing():
                    ent["links"].pop(w, None)
                    self.writer_node.pop(id(w), None)
            if ent["links"]:
                continue
            if now - ent.get("seen_tcp", 0) > self.NODE_TTL:
                self.nodes.pop(nid, None)
                for o, i in list(self.writer_node.items()):
                    if i == nid:
                        self.writer_node.pop(o, None)

    async def register_node(self, writer, peer, token, node, udp_port):
        """T_NODE/U_NODE endpoint: returns True if accepted. The SAME
        node id may register from several control links (processes that
        share one identity block); each gets its own per-link state and
        node-targeted traffic fans out to all live links."""
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
                    if e["links"]:
                        continue
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
            ent = {"links": {}, "virt": virt, "seen_tcp": 0.0}
            self.nodes[node] = ent
            print(f"[relay] node {node} -> {self.virt_str(virt)}", flush=True)
        ent["seen_tcp"] = now
        link = ent["links"].get(writer)
        if link is None:
            link = {"tcp_ip": tcp_ip, "udp_port": 0, "udp_addr": None,
                    "seen_udp": 0.0, "udp_tcp": False}
            ent["links"][writer] = link
            n = len(ent["links"])
            if n > 1:
                print(f"[relay] node {node} link joined ({n} links)",
                      flush=True)
        link["tcp_ip"] = tcp_ip
        if udp_port:
            if link["udp_port"] != udp_port or link["udp_addr"] is None:
                link["udp_port"] = udp_port
                link["udp_addr"] = (tcp_ip, udp_port)
                link["seen_udp"] = now
                self.known_udp[link["udp_addr"]] = now
        self.writer_node[id(writer)] = node
        if self.udp_tcp.pop(id(writer), False):
            link["udp_tcp"] = True
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
        if id(writer) not in self.writer_node:
            print(f"[relay] no NODE from {peer}, dropping", flush=True)
            writer.close()

    # ---- per-stream connections ----------------------------------------
    def _stream_pop(self, sid):
        st = self.streams.pop(sid, None)
        if st is None:
            return None
        for nid in (st.get("opener_node"), st.get("dest_node")):
            s = self.node_streams.get(nid)
            if s is not None:
                s.discard(sid)
        if st.get("done") is not None and not st["done"].done():
            st["done"].set_result(None)
        for r, w in ((st.get("opener_r"), st.get("opener_w")),
                     (st.get("joiner_r"), st.get("joiner_w"))):
            if w is not None:
                try:
                    w.close()
                except Exception:
                    pass
        return st

    async def _stream_fail(self, st, sid, reason, why):
        opener_w = st.get("opener_w")
        if opener_w is not None and not opener_w.is_closing():
            try:
                await tcp_send(opener_w, T_STFAIL, encode_stfail(sid, reason))
            except (ConnectionResetError, BrokenPipeError, RuntimeError, OSError):
                pass
        print(f"[stream] {why}: sid {sid} node {st.get('opener_node')} "
              f"-> dest {st.get('dest_node')} port {st.get('gport')} "
              f"reason={reason}", flush=True)
        self._stream_pop(sid)

    async def handle_stream_open(self, reader, writer, payload):
        """Opener's per-stream TCP: T_STOPEN first frame."""
        peer = writer.get_extra_info("peername")
        dec = decode_stopen(payload)
        if not dec:
            writer.close()
            return
        node, dest_node, sid, gport = dec
        if self.allowed_tcp and gport not in self.allowed_tcp:
            await self._stream_fail_standalone(writer, sid, STF_NO_ROUTE,
                                               "port not allowed")
            return
        ent = self.nodes.get(node)
        if ent is None or not self.live_links(node):
            await self._stream_fail_standalone(writer, sid, STF_NO_ROUTE,
                                               f"unknown node {node}")
            return
        linfo = ent["links"].get(writer)
        tcp_ip = linfo["tcp_ip"] if linfo else ""
        if tcp_ip and peer and peer[0] != tcp_ip:
            print(f"[stream] node {node} per-stream conn from {peer[0]} "
                  f"differs from control {tcp_ip} (accepted)",
                  flush=True)
        if sid in self.streams:
            await self._stream_fail_standalone(writer, sid, STF_BUSY,
                                               "stream id in use")
            return
        # resolve destination NODE (its live links all get the STREQ; the
        # process that actually serves the port joins, the rest answer BUSY)
        if dest_node:
            if dest_node not in self.nodes:
                await self._stream_fail_standalone(writer, sid, STF_NO_ROUTE,
                                                   f"dest node {dest_node} "
                                                   "not connected")
                return
        else:
            dest_node = self.route_tcp(gport, exclude=writer)
            if dest_node is None:
                await self._stream_fail_standalone(writer, sid, STF_NO_ROUTE,
                                                   f"no host for port {gport}")
                return
        dest_links = [w for w in self.live_links(dest_node)
                      if w is not writer]
        if not dest_links:
            await self._stream_fail_standalone(writer, sid, STF_NO_ROUTE,
                                               f"dest node {dest_node} "
                                               "has no other link")
            return
            dest_node = self.writer_node.get(id(target), 0)
        st = {"opener_node": node, "opener_r": reader, "opener_w": writer,
              "dest_node": dest_node, "gport": gport, "state": "open",
              "created": time.monotonic(), "joiner_r": None,
              "joiner_w": None, "task": None,
              "done": asyncio.get_running_loop().create_future()}
        self.streams[sid] = st
        self.node_streams.setdefault(node, set()).add(sid)
        if dest_node:
            self.node_streams.setdefault(dest_node, set()).add(sid)
        print(f"[stream] open: sid {sid} node {node} -> node {dest_node} "
              f"port {gport} from {peer} ({len(dest_links)} dest links)",
              flush=True)
        for w in dest_links:
            await self.r_send(w, T_STREQ, encode_streq(sid, gport),
                              droppable=False)
        asyncio.create_task(self._stream_join_timeout(sid))
        # keep this connection's transport alive (asyncio closes it when
        # the accept coroutine returns); the stream outlives the handshake
        await st["done"]

    async def _stream_fail_standalone(self, writer, sid, reason, why):
        if not writer.is_closing():
            try:
                await tcp_send(writer, T_STFAIL, encode_stfail(sid, reason))
            except (ConnectionResetError, BrokenPipeError, RuntimeError, OSError):
                pass
        print(f"[stream] fail: {why} (sid {sid}, reason={reason})", flush=True)
        try:
            writer.close()
        except Exception:
            pass

    async def _stream_join_timeout(self, sid):
        await asyncio.sleep(ST_TIMEOUT_S)
        st = self.streams.get(sid)
        if st is None or st["state"] != "open":
            return
        await self._stream_fail(st, sid, STF_JOIN_TIMEOUT,
                                "dest never joined in time")

    async def handle_stream_join(self, reader, writer, payload):
        """Joinee's per-stream TCP: T_STJOIN first frame, then the joinee
        bridges to its local game and sends T_STJOINED (or T_STFAIL)."""
        peer = writer.get_extra_info("peername")
        dec = decode_stjoin(payload)
        if not dec:
            writer.close()
            return
        node, sid = dec
        st = self.streams.get(sid)
        if st is None:
            print(f"[stream] join: unknown or late sid {sid} from "
                  f"node {node} {peer}", flush=True)
            writer.close()
            return
        if st["state"] != "open":
            # another link of this node (or the sole joiner) already won:
            # refuse THIS joiner, keep the stream alive for the winner
            try:
                await tcp_send(writer, T_STFAIL,
                               encode_stfail(sid, STF_BUSY))
            except (ConnectionResetError, BrokenPipeError, RuntimeError, OSError):
                pass
            print(f"[stream] join: sid {sid} already claimed (state "
                  f"{st['state']}); dup node {node} -> BUSY", flush=True)
            writer.close()
            return
        if node != st["dest_node"]:
            try:
                await tcp_send(writer, T_STFAIL,
                               encode_stfail(sid, STF_BAD_ID))
            except (ConnectionResetError, BrokenPipeError, RuntimeError, OSError):
                pass
            print(f"[stream] join: node {node} not stream {sid} dest "
                  f"{st['dest_node']}, refusing", flush=True)
            writer.close()
            await self._stream_fail(st, sid, STF_BAD_ID, "joinee identity")
            return
        st["joiner_r"], st["joiner_w"] = reader, writer
        st["state"] = "joined"   # claim: further joiners -> BUSY
        # immediate claim verdict on the joiner's own connection: losers
        # stand down before bridging, the winner proceeds knowingly
        try:
            await tcp_send(writer, T_STOK, encode_stsid(sid))
        except (ConnectionResetError, BrokenPipeError, RuntimeError, OSError):
            await self._stream_fail(st, sid, STF_JOIN_TIMEOUT,
                                    "joinee gone at claim")
            return
        print(f"[stream] join: sid {sid} node {node} {peer} "
              f"(dest for opener node {st['opener_node']})", flush=True)
        try:
            mtype, payload2 = await asyncio.wait_for(
                tcp_read(reader), timeout=ST_TIMEOUT_S)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                ConnectionResetError, ValueError):
            await self._stream_fail(st, sid, STF_JOIN_TIMEOUT,
                                    "joinee handshake lost")
            return
        if mtype == T_STJOINED:
            if decode_stsid(payload2) != sid:
                writer.close()
                await self._stream_fail(st, sid, STF_BAD_ID, "joined sid")
                return
            st["state"] = "ready"
            try:
                await tcp_send(st["opener_w"], T_STOK, encode_stsid(sid))
            except (ConnectionResetError, BrokenPipeError, RuntimeError, OSError):
                await self._stream_fail(st, sid, STF_NO_ROUTE,
                                        "opener gone")
                return
            print(f"[stream] ok: sid {sid} node {st['opener_node']} <-> "
                  f"node {node} port {st['gport']}", flush=True)
            st["task"] = asyncio.create_task(self._stream_pipe(sid))
            # keep the joiner transport alive for the stream's lifetime
            await st["done"]
        elif mtype == T_STFAIL:
            f = decode_stfail(payload2)
            reason = f[1] if f and f[0] == sid else STF_HOST_FAILED
            await self._stream_fail(st, sid, reason,
                                    "dest local bridge failed")
        else:
            writer.close()
            await self._stream_fail(st, sid, STF_HOST_FAILED,
                                    "bad joinee frame")

    async def _stream_pipe(self, sid):
        st = self.streams.get(sid)
        if st is None or st["state"] != "ready":
            return
        counts = [0, 0]

        async def pump(r, w, i, name):
            try:
                while True:
                    d = await r.read(65536)
                    if not d:
                        print(f"[stream] pipe {name} EOF sid {sid}", flush=True)
                        return
                    counts[i] += len(d)
                    w.write(d)
                    await w.drain()
            except Exception as e:
                print(f"[stream] pipe {name} ERR sid {sid}: {e!r}",
                      flush=True)
                raise

        t1 = asyncio.create_task(pump(st["opener_r"], st["joiner_w"], 0,
                                      "opener->dest"))
        t2 = asyncio.create_task(pump(st["joiner_r"], st["opener_w"], 1,
                                      "dest->opener"))
        try:
            await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t1, t2):
                t.cancel()
            await asyncio.gather(t1, t2, return_exceptions=True)
            self._stream_pop(sid)
            print(f"[stream] pipe closed: sid {sid} "
                  f"opener->{st['dest_node']} {counts[0]}B, "
                  f"return {counts[1]}B", flush=True)

    # ---- control connection -------------------------------------------------
    async def accept_conn(self, reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            mtype, payload = await asyncio.wait_for(
                tcp_read(reader), timeout=ST_TIMEOUT_S)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                ConnectionResetError, ValueError, OSError):
            try:
                writer.close()
            except Exception:
                pass
            return
        if mtype == T_STOPEN:
            await self.handle_stream_open(reader, writer, payload)
            return
        if mtype == T_STJOIN:
            await self.handle_stream_join(reader, writer, payload)
            return
        await self.handle_peer(reader, writer, first=(mtype, payload),
                               peer=peer)

    async def handle_peer(self, reader, writer, first=None, peer=None):
        if peer is None:
            peer = writer.get_extra_info("peername")
        self.players.add(writer)
        self.roles[id(writer)] = "player"
        owner = id(writer)
        grace = asyncio.create_task(self.node_grace(writer, peer))
        try:
            mtype, payload = first if first else await tcp_read(reader)
            while True:
                if mtype == T_NODE:
                    if ctl_ver(payload) != PVER:
                        print(f"[relay] proto mismatch from {peer}: NODE "
                              f"ver {ctl_ver(payload)} != {PVER}", flush=True)
                        return
                    dec = decode_ctl_node(payload)
                    if not dec:
                        pass
                    else:
                        tok, node, uport, flags = dec
                        if not node:
                            pass
                        else:
                            ok = await self.register_node(writer, peer, tok, node, uport)
                            if not ok:
                                return
                            if flags & NODE_F_HOST:
                                self.claim_host(writer, peer)
                elif mtype == T_UDP_MODE:
                    # UDP-over-TCP mode for this LINK: game datagrams
                    # arrive as T_UDP_TUN and replies go back the same way
                    self.udp_tcp[owner] = True
                    node = self.writer_node.get(owner)
                    if node is not None and node in self.nodes:
                        lent = self.nodes[node]["links"].get(writer)
                        if lent is not None:
                            lent["udp_tcp"] = True
                            print(f"[relay] node {node} link uses "
                                  "UDP-over-TCP", flush=True)
                elif mtype == T_UDP_TUN:
                    # decapsulated UDP-tunnel datagram from a TCP-mode peer
                    node = self.writer_node.get(owner)
                    if node is not None and node in self.nodes:
                        lent = self.nodes[node]["links"].get(writer)
                        addr = lent.get("udp_addr") if lent else None
                        if addr is None:
                            addr = ("tcp", owner)
                            self.tcp_fallback[addr] = writer
                        else:
                            self.tcp_fallback.setdefault(
                                ("tcp", owner), writer)
                        await self.handle_udp_payload(payload, addr)
                elif mtype == T_BCAST:
                    if len(payload) >= 4:
                        (dport, sport) = struct.unpack("!HH", payload[:4])
                        raw = payload[4:]
                        if not (self.disc_ports and dport not in self.disc_ports):
                            # Every beacon fans out as-is; echo loops are cut
                            # at the edge (all links of the source node are
                            # skipped: same-machine peers already heard the
                            # real LAN broadcast) and distinct hosts stay
                            # visible.
                            self.beaconers[writer] = time.monotonic()
                            src_node = self.writer_node.get(owner, 0)
                            for w in list(self.players) + ([self.host_writer] if self.host_writer else []):
                                if w is writer or w.is_closing():
                                    continue
                                wnode = self.writer_node.get(id(w))
                                if src_node and wnode == src_node:
                                    continue
                                if src_node and wnode is not None:
                                    await self.r_send(w, T_BCAST_FROM,
                                                      encode_bcast_from(src_node, dport, sport, raw))
                                else:
                                    await self.r_send(w, T_BCAST, payload)
                else:
                    self.note_unknown_tcp(mtype)
                mtype, payload = await tcp_read(reader)
        except (asyncio.IncompleteReadError, ConnectionResetError, ValueError, OSError):
            pass
        finally:
            node = self.writer_node.get(owner)
            was_host = self.host_writer is writer
            if was_host:
                self.host_writer = None
                print(f"[relay] host uplink {peer} down", flush=True)
            else:
                self.players.discard(writer)
                print(f"[relay] player {peer} gone", flush=True)
            self.roles.pop(owner, None)
            self.beaconers.pop(writer, None)
            self.udp_tcp.pop(owner, None)
            for k, w in list(self.tcp_fallback.items()):
                if w is writer:
                    self.tcp_fallback.pop(k, None)
            self.writer_node.pop(owner, None)
            if node is not None:
                ent = self.nodes.get(node)
                if ent is not None:
                    ent["links"].pop(writer, None)
                    ent["seen_tcp"] = time.monotonic()
                    survivors = self.live_links(node)
                    if was_host and survivors:
                        # identity survives: promote a sibling link so
                        # implicit routing keeps working for this node
                        self.host_writer = survivors[0]
                        self.roles[id(survivors[0])] = "host"
                        self.players.discard(survivors[0])
                        print(f"[relay] host uplink failover within node "
                              f"{node}", flush=True)
                    if not survivors and not was_host:
                        asyncio.create_task(self.broadcast_assign())
                    # only when the whole node goes dark close its
                    # per-stream TCPs; the other end sees EOF and cleans
                    # up on its side. Streams of a node that still has a
                    # live sibling link stay up.
                    if not survivors:
                        for sid in list(self.node_streams.pop(node, ())):
                            st = self.streams.get(sid)
                            if st is not None:
                                print(f"[stream] close (node {node} gone): "
                                      f"sid {sid}", flush=True)
                                self._stream_pop(sid)
            # retire the per-writer queue
            q = self.wq.get(owner)
            if q is not None:
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    pass
            task = self.wq_task.get(owner)
            if task is not None:
                task.cancel()
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

    def note_unknown_tcp(self, mtype):
        now = time.monotonic()
        if now - self._unk_op.get(mtype, 0.0) > 10:
            self._unk_op[mtype] = now
            print(f"[relay] unknown TCP opcode 0x{mtype:02x}, ignoring",
                  flush=True)

    def note_unknown_udp(self, op):
        now = time.monotonic()
        if now - self._unk_op.get(op, 0.0) > 10:
            self._unk_op[op] = now
            print(f"[relay] unknown UDP opcode 0x{op:02x}, dropping",
                  flush=True)

    def link_writer_for_addr(self, nid, addr):
        """(writer, link dict) of node nid whose udp_addr == addr, or None."""
        ent = self.nodes.get(nid)
        if not ent:
            return None
        for lw, l in ent["links"].items():
            if l.get("udp_addr") == addr:
                return lw, l
        return None

    def node_by_udp_addr(self, addr):
        """Tunnel addr -> node id owning that endpoint (any link)."""
        best, best_seen = None, -1.0
        for nid, ent in self.nodes.items():
            for l in ent["links"].values():
                if l.get("udp_addr") == addr:
                    seen = l.get("seen_udp", 0)
                    if seen > best_seen:
                        best, best_seen = nid, seen
        if best is not None:
            return best
        for nid, ent in self.nodes.items():
            for l in ent["links"].values():
                if l.get("udp_port") and l.get("tcp_ip") and \
                        (l["tcp_ip"], l["udp_port"]) == addr:
                    return nid
        return None

    def node_udp_addrs(self, nid):
        """Fresh UDP endpoints for every live link of node nid."""
        ent = self.nodes.get(nid)
        if not ent:
            return []
        now = time.monotonic()
        out = []
        for l in ent["links"].values():
            a = l.get("udp_addr")
            if a and now - l.get("seen_udp", 0) < self.KNOWN_TTL:
                out.append(a)
            elif l.get("udp_port") and l.get("tcp_ip"):
                out.append((l["tcp_ip"], l["udp_port"]))
        return out

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

    def relay_virt(self):
        """The relay's own virtual address (.1): answers ICMP echo."""
        return self.subnet_net | 1

    def icmp_target(self, dest_node):
        """UDP tunnel addresses for an ICMP dest node (one per live link).

        dest_node 0 addresses the relay itself (handled by the caller).
        Never returns the sender: self-addressed frames are dropped and
        looped back client-side, never echoed by the relay."""
        if not dest_node:
            return []
        return self.node_udp_addrs(dest_node)

    async def udp_sendto(self, data, addr):
        """Route one UDP-tunnel datagram toward addr.

        Destinations behind a UDP-over-TCP link get the datagram back
        over their TCP link (T_UDP_TUN); everyone else gets a plain UDP
        sendto. Never echoes: callers already exclude the source."""
        w = self.tcp_fallback.get(addr)
        if w is None:
            nid = self.node_by_udp_addr(addr)
            if nid is not None:
                lr = self.link_writer_for_addr(nid, addr)
                if lr is not None and lr[1].get("udp_tcp"):
                    w = lr[0]
        if w is not None and not w.is_closing():
            try:
                await self.r_send(w, T_UDP_TUN, data)
            except (ConnectionResetError, BrokenPipeError, RuntimeError):
                pass
            return
        try:
            self._public_udp.sendto(data, addr)
        except (OSError, AttributeError, TypeError):
            pass

    async def udp_consume(self, pproto):
        while True:
            data, addr = await pproto.q.get()
            await self.handle_udp_payload(data, addr)

    async def handle_udp_payload(self, data, addr):
        """One UDP-tunnel datagram from addr (UDP socket or decapsulated
        T_UDP_TUN, where addr may be a ("tcp", writer-id) fallback)."""
        if len(data) < 4 or data[:2] != UMAGIC or data[2] != UVER:
            return
        mtype = data[3]
        if mtype == U_NODE:
            dec = decode_udp_node(data)
            if not dec:
                return
            tok, node, _uport, flags = dec
            # host-flagged U_NODE refreshes the host UDP endpoint
            # (the old dedicated UDP hello heartbeat, folded in)
            if flags & NODE_F_HOST and self.token_ok(tok):
                if self.host_udp != addr:
                    print(f"[relay] host UDP endpoint {addr}", flush=True)
                self.host_udp = addr
                self.host_udp_seen = time.monotonic()
            if not self.token_ok(tok):
                return
            ent = self.nodes.get(node)
            if ent is None:
                return  # TCP NODE first; UDP alone registers nothing
            # attach this endpoint to a link: prefer the one that declared
            # the same source port, else the same-ip link with no live
            # endpoint seen yet, else the stalest (NAT rebind).
            best_l = None
            for l in ent["links"].values():
                if l.get("tcp_ip") == addr[0] and l.get("udp_port") == addr[1]:
                    best_l = l
                    break
            if best_l is None:
                for l in ent["links"].values():
                    if l.get("tcp_ip") == addr[0] and l.get("udp_addr") is None:
                        best_l = l
                        break
            if best_l is None:
                for l in ent["links"].values():
                    if l.get("tcp_ip") == addr[0]:
                        if best_l is None or l.get("seen_udp", 0) < best_l.get("seen_udp", 0):
                            best_l = l
            if best_l is None:
                best_l = next(iter(ent["links"].values()), None)
            if best_l is None:
                return
            best_l["udp_addr"] = addr
            best_l["seen_udp"] = time.monotonic()
            self.known_udp[addr] = time.monotonic()
            return
        if mtype == U_GAME_P2P:
            dec = decode_pdat(data)
            if not dec:
                return
            dest_node, gport, _cip, _cport, _raw = dec
            if self.allowed_udp and gport not in self.allowed_udp:
                return
            tgt = self.nodes.get(dest_node)
            now = time.monotonic()
            taddrs = [a for a in self.node_udp_addrs(dest_node) if a != addr]
            if not taddrs:
                why = "same-addr" if tgt and addr in self.node_udp_addrs(dest_node) \
                      else ("unknown-node" if tgt is None else "no-udp-endpoint")
                if now - self._pdat_warn.get(dest_node, 0.0) > 5.0:
                    self._pdat_warn[dest_node] = now
                    print(f"[udp] pdat drop ({why}) dest node "
                          f"{dest_node} gport {gport}", flush=True)
                return
            print_k = ("ok", dest_node, gport)
            if now - self._pdat_warn.get(print_k, 0.0) > 5.0:
                self._pdat_warn[print_k] = now
                print(f"[udp] pdat {addr} -> node {dest_node} @{taddrs} "
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
            for taddr in taddrs:
                await self.udp_sendto(inner, taddr)
            return
        if mtype in (U_ICMP_REQ, U_ICMP_REP):
            dec = decode_icmp(data)
            if not dec:
                return
            _m, src, dest, iid, seq, idata = dec
            # Authoritative source: the sender's registered node when
            # known (frames are trivially spoofable otherwise).
            sender = self.node_by_udp_addr(addr)
            if sender is not None:
                src = sender
            elif not src:
                return  # anonymous: no return path, drop
            if not dest:
                # ping to the relay itself (.1): echo back to sender
                if mtype != U_ICMP_REQ:
                    return
                self.known_udp[addr] = time.monotonic()
                await self.udp_sendto(
                    encode_icmp(U_ICMP_REP, 0, src, iid, seq, idata), addr)
                return
            if dest == src:
                return  # self-ping: client loops back, relay drops
            taddrs = [a for a in self.icmp_target(dest) if a != addr]
            if not taddrs:
                now = time.monotonic()
                if now - self._pdat_warn.get(("icmp", dest), 0.0) > 5.0:
                    self._pdat_warn[("icmp", dest)] = now
                    print(f"[udp] icmp drop dest node {dest}", flush=True)
                return
            self.known_udp[addr] = time.monotonic()
            for taddr in taddrs:
                await self.udp_sendto(
                    encode_icmp(mtype, src, dest, iid, seq, idata), taddr)
            return
        if mtype == U_GAME_S2C:
            # bridge reply (wclient --host / hook inbound): route by the
            # per-dest triple recorded when the C2S went out; bytes
            # untouched. The S2C sender is the host that got the C2S,
            # so look up (that dest, triple) -> player.
            dec = decode_udp_game(data)
            if not dec:
                return
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
                    return
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
                return
            if paddr == addr:
                return  # reply to self: client loops back, relay drops
            ent[1] = now
            self.learned[(paddr, gport)] = (addr, now)
            if len(self.learned) > 2048:
                self.learned.clear()
            await self.udp_sendto(data, paddr)
            return
        if mtype != U_GAME_C2S:
            self.note_unknown_udp(mtype)
            return
        dec = decode_udp_game(data)
        if not dec:
            return
        _m, gport, _cip, _cport, _raw = dec
        if self.allowed_udp and gport not in self.allowed_udp:
            return
        self.known_udp[addr] = time.monotonic()
        dests = self.udp_targets(gport, addr)
        if not dests:
            self.note_noroute("UDP")
            return
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
            await self.udp_sendto(data, dst)  # bytes untouched

    async def _conn(self, reader, writer):
        """Per-connection wrapper: keep the task handle so run()'s
        teardown can cancel live handlers. Python 3.12+ wait_closed()
        waits for every handler, so without this a half-used relay
        (clients still connected) makes task cancellation hang forever."""
        t = asyncio.current_task()
        self._conn_tasks.add(t)
        try:
            await self.accept_conn(reader, writer)
        finally:
            self._conn_tasks.discard(t)

    async def run(self):
        loop = asyncio.get_running_loop()
        psock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        psock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        psock.bind((self.bind, self.port))
        psock.setblocking(False)
        pproto = QueueProto()
        self._public_udp, _ = await loop.create_datagram_endpoint(lambda: pproto, sock=psock)
        print(f"[udp] relay {self.bind}:{self.port}", flush=True)
        self._udp_task = asyncio.create_task(self.udp_consume(pproto))
        srv = await asyncio.start_server(self._conn, self.bind, self.port)
        print(f"[tcp] relay {self.bind}:{self.port}", flush=True)
        print(f"[up] relay v{VERSION} port={self.port} "
              f"token={'set' if self.token else 'open'} "
              f"streams=per-conn", flush=True)
        try:
            await srv.serve_forever()
        finally:
            # bounded teardown: never let one straggler handler (or a
            # wait_closed that a stuck transport pins) hang the process —
            # tests in particular must fail fast, not stall
            async def _down():
                srv.close()
                for t in list(self._conn_tasks):
                    t.cancel()
                if self._conn_tasks:
                    await asyncio.gather(*list(self._conn_tasks),
                                         return_exceptions=True)
                await srv.wait_closed()
            try:
                await asyncio.wait_for(_down(), timeout=3)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                print("[relay] teardown bounded (3s)", flush=True)
            if self._udp_task is not None:
                self._udp_task.cancel()
                await asyncio.gather(self._udp_task, return_exceptions=True)
            if self._public_udp is not None:
                self._public_udp.close()
                self._public_udp = None


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
    ap.add_argument("--bind", default="0.0.0.0",
                    help="listen address (default all; e.g. 127.0.0.1 for tests)")
    a = ap.parse_args()
    r = Relay(a.port, a.token, parse_ports(a.tcp), parse_ports(a.udp),
              parse_ports(a.disc), subnet=a.subnet, bind=a.bind)
    print(f"[cfg] relay v{VERSION} port={a.port} "
          f"token={'set' if a.token else 'open'} subnet={a.subnet} "
          f"disc={a.disc or 'all'} tcp={a.tcp or 'all'} udp={a.udp or 'all'}",
          flush=True)
    try:
        asyncio.run(r.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
