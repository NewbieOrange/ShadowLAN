#!/usr/bin/env python3
"""Process-tree identity on the relay: ONE node id, MANY control links.

The hook now stamps LAN_HOOK_NODE into its environment, so a game tree
(launcher + restart chain + children) registers the same node id from
several processes. The relay must treat that as one virtual host whose
traffic fans out to every live link:

  phase 1  two links register node N1 -> same vnode on both ASSIGNs
  phase 2  beacon from N2 -> delivered to BOTH links of N1 (and to N3);
           nothing echoes back to N2's own node
  phase 3  addressed stream for N1 -> T_STREQ on both links; the first
           T_STJOIN wins, a duplicate joiner gets T_STFAIL(BUSY) while
           the stream keeps flowing for the winner
  phase 4  one link drops -> node stays up, sibling still receives
"""
import asyncio
import os
import struct
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
from server import Relay
from common import (HDR, T_NODE, T_BCAST, T_BCAST_FROM, T_ASSIGN, T_STOPEN,
                    T_STREQ, T_STJOIN, T_STJOINED, T_STOK, T_STFAIL,
                    STF_BUSY, encode_ctl_node, decode_bcast_from, tcp_read)

PUB = 47975
N1, N2, N3 = 0x11111111, 0x22222222, 0x33333333
SID = 0xABCD1234


class Link:
    def __init__(self, name):
        self.name = name
        self.r = self.w = None

    async def open(self):
        self.r, self.w = await asyncio.open_connection("127.0.0.1", PUB)

    async def send(self, mtype, payload):
        self.w.write(HDR.pack(1 + len(payload)) + bytes([mtype]) + payload)
        await self.w.drain()

    async def recv(self, timeout=3.0):
        return await asyncio.wait_for(tcp_read(self.r), timeout)

    async def expect(self, mtype, timeout=3.0):
        while True:
            t, p = await self.recv(timeout)
            if t == mtype:
                return p
            # tolerate interleaved control noise (ASSIGN refreshes etc.)

    async def expect_nothing(self, dur=0.7):
        """No TRAFFIC frames (beacons) may arrive; membership refreshes
        (T_ASSIGN from other registrations) are control noise: skip."""
        while True:
            try:
                t, p = await self.recv(dur)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                return True, None
            if t != T_ASSIGN:
                return False, (t, p)

    async def register(self, node, uport):
        await self.send(T_NODE, encode_ctl_node(b"", node, uport))
        return await self.expect(T_ASSIGN)

    def close(self):
        try:
            self.w.close()
        except Exception:
            pass


def my_virt(assign_payload):
    return struct.unpack("!I", assign_payload[:4])[0]


async def stream_dial():
    r, w = await asyncio.open_connection("127.0.0.1", PUB)
    return r, w


async def stream_frame(w, mtype, payload):
    w.write(HDR.pack(1 + len(payload)) + bytes([mtype]) + payload)
    await w.drain()


async def stream_expect(r, mtype, timeout=3.0):
    hdr = await asyncio.wait_for(r.readexactly(4), timeout)
    (mlen,) = HDR.unpack(hdr)
    body = await asyncio.wait_for(r.readexactly(mlen), timeout)
    assert body[0] == mtype, f"want op {mtype:#x}, got {body.hex()}"
    return body


async def main():
    relay = Relay(PUB, token="", bind="127.0.0.1")
    asyncio.create_task(relay.run())
    await asyncio.sleep(0.3)

    l1, l2 = Link("L1"), Link("L2")          # two processes, one node N1
    l3 = Link("L3")                          # another node (the sender)
    l4 = Link("L4")                          # the opener (N3)
    for l in (l1, l2, l3, l4):
        await l.open()

    # ---- phase 1: same node id from two links -> one vnode ----
    a1 = await l1.register(N1, 6001)
    a2 = await l2.register(N1, 6002)
    v_1, v_2 = my_virt(a1), my_virt(a2)
    assert v_1 == v_2 and v_1 != 0, (v_1, v_2)
    assert len(relay.nodes[N1]["links"]) == 2
    # per-link slot bases: distinct, in range, so sibling marks
    # (50000 + link_id*256 + slot) can never collide in udp_flows
    from common import decode_assign
    lid1, lid2 = decode_assign(a1)[4], decode_assign(a2)[4]
    assert 1 <= lid1 <= 255 and 1 <= lid2 <= 255 and lid1 != lid2, (lid1, lid2)
    await l3.register(N2, 6003)
    a4 = await l4.register(N3, 6004)
    v_4 = my_virt(a4)
    print(f"PASS[1] one vnode 0x{v_1:08x} for both links, "
          f"slot bases {lid1}/{lid2}", flush=True)

    # ---- phase 2: beacon from N2 fans to every link of N1 ----
    await l3.send(T_BCAST, struct.pack("!HH", 47584, 47584) + b"BIGBEACON")
    p1 = await l1.expect(T_BCAST_FROM)
    p2 = await l2.expect(T_BCAST_FROM)
    n, dport, sport, raw = decode_bcast_from(p1)
    assert n == N2 and raw == b"BIGBEACON", p1[:20]
    assert decode_bcast_from(p2)[3] == b"BIGBEACON"
    ok, seen = await l3.expect_nothing()
    assert ok, f"echo back to sender node: {seen}"
    print("PASS[2] beacon fanned to both links, no self-echo", flush=True)

    # ---- phase 3: STREQ to all links; first join wins; dup -> BUSY ----
    or_, ow = await stream_dial()             # opener per-stream TCP
    await stream_frame(ow, T_STOPEN, struct.pack("!IIIH", N3, N1, SID, 47584))
    q1 = await l1.expect(T_STREQ)
    q2 = await l2.expect(T_STREQ)
    (s1, g1), (s2, g2) = struct.unpack("!IH", q1[:6]), struct.unpack("!IH", q2[:6])
    assert s1 == s2 == SID and g1 == g2 == 47584
    # opener's virtual address rides along so the joinee can present it
    # as the accepted socket's peer (getpeername spoofing)
    assert len(q1) == 10 and struct.unpack("!I", q1[6:10])[0] == v_4, q1.hex()
    j1r, j1w = await stream_dial()            # winning joiner (link L1's proc)
    await stream_frame(j1w, T_STJOIN, struct.pack("!II", N1, SID))
    body = await stream_expect(j1r, T_STOK)   # claim verdict: winner
    assert struct.unpack("!I", body[1:5])[0] == SID
    await stream_frame(j1w, T_STJOINED, struct.pack("!I", SID))
    body = await stream_expect(or_, T_STOK)   # opener's confirmed connect
    assert struct.unpack("!I", body[1:5])[0] == SID
    j2r, j2w = await stream_dial()            # duplicate joiner (link L2's proc)
    await stream_frame(j2w, T_STJOIN, struct.pack("!II", N1, SID))
    body = await stream_expect(j2r, T_STFAIL) # refused: already claimed
    assert struct.unpack("!I", body[1:5])[0] == SID and body[5] == STF_BUSY, \
        body.hex()
    # the winner's pipe still works after the dup was refused
    ow.write(b"ping")
    await ow.drain()
    assert await asyncio.wait_for(j1r.readexactly(4), timeout=3) == b"ping"
    j1w.write(b"pong")
    await j1w.drain()
    assert await asyncio.wait_for(or_.readexactly(4), timeout=3) == b"pong"
    print("PASS[3] STREQ to both links, first join wins, dup BUSY", flush=True)

    # ---- phase 4: one link drops, node stays alive for the sibling ----
    l2.close()
    await asyncio.sleep(0.5)
    assert len(relay.nodes[N1]["links"]) == 1
    await l3.send(T_BCAST, struct.pack("!HH", 47584, 47584) + b"SECOND")
    p = await l1.expect(T_BCAST_FROM)
    assert decode_bcast_from(p)[3] == b"SECOND"
    print("PASS[4] sibling link keeps the node alive", flush=True)

    print("MULTILINK_ALL_PASS", flush=True)
    for l in (l1, l3, l4):
        l.close()
    for w in (ow, j1w, j2w):
        try:
            w.close()
        except Exception:
            pass



async def _guarded():
    """Hard watchdog: a stuck future must fail loudly in <=20s, never
    pin the suite (Python 3.12 wait_closed and co. can swallow hangs)."""
    await asyncio.wait_for(main(), timeout=20)


if __name__ == "__main__":
    asyncio.run(_guarded())
