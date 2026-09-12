"""Burst-connect probe (LAN backlog question): node A opens TWO streams to
the host node on DIFFERENT game ports back-to-back while the first one is
still unclaimed (no listener). On a real LAN the second connect is
independent: it completes (into backlog) or fails on its own merits; it
must NOT be held up by the first port's handshake.

Run: python3 test_burst_connect.py   (starts its own relay on 127.0.0.1)
"""
import asyncio
import struct
import sys

sys.path.insert(0, ".")
from server import Relay
from common import (HDR, T_NODE, T_ASSIGN, T_STOPEN, T_STREQ, T_STJOIN,
                    T_STJOINED, T_STOK, T_STFAIL, STF_NO_ROUTE,
                    STF_JOIN_TIMEOUT,
                    encode_ctl_node)

PUB = 47966
NH, ND = 0x11111111, 0x22222222


async def frame(w, mtype, payload):
    w.write(HDR.pack(1 + len(payload)) + bytes([mtype]) + payload)
    await w.drain()


async def expect(r, mtype, timeout=3.0):
    while True:
        hdr = await asyncio.wait_for(r.readexactly(4), timeout)
        (mlen,) = HDR.unpack(hdr)
        body = await asyncio.wait_for(r.readexactly(mlen), timeout)
        if body[0] == mtype:
            return body
        # tolerate membership refresh noise on control conns
        assert body[0] == T_ASSIGN, f"got op {body[0]:#x} want {mtype:#x}"


async def register(name, node):
    r, w = await asyncio.open_connection("127.0.0.1", PUB)
    await frame(w, T_NODE, encode_ctl_node(b"", node, 6000 + node % 100))
    await expect(r, T_ASSIGN)
    return r, w


async def dial():
    r, w = await asyncio.open_connection("127.0.0.1", PUB)
    return r, w


async def main():
    relay = Relay(PUB, token="", bind="127.0.0.1")
    srv = asyncio.create_task(relay.run())
    await asyncio.sleep(0.3)

    rh, wh = await register("H", NH)      # host, never claims
    rd, wd = await register("D", ND)      # opener node

    # stream 1: D -> H:8000, left UNCLAIMED (no listener at H)
    o1r, o1w = await dial()
    await frame(o1w, T_STOPEN, struct.pack("!IIIH", ND, NH, 0xAAAA, 8000))
    await expect(rh, T_STREQ)             # relay fanned 8000; host stays mute

    # stream 2: D -> H:8001 immediately; host IS willing for this one
    o2r, o2w = await dial()
    await frame(o2w, T_STOPEN, struct.pack("!IIIH", ND, NH, 0xBBBB, 8001))
    burst_fanned = True
    sid2 = None
    try:
        b = await expect(rh, T_STREQ, timeout=0.7)
        sid2 = struct.unpack("!I", b[1:5])[0]
    except asyncio.TimeoutError:
        burst_fanned = False
    print(f"[probe] STREQ for port 8001 fanned while 8000 unclaimed: {burst_fanned}")

    joined_fast = False
    if burst_fanned:
        j1r, j1w = await dial()
        await frame(j1w, T_STJOIN, struct.pack("!II", NH, sid2))
        await expect(j1r, T_STOK)
        await frame(j1w, T_STJOINED, struct.pack("!I", sid2))
        try:
            await expect(o2r, T_STOK, timeout=1.5)
            joined_fast = True
        except asyncio.TimeoutError:
            pass
    print(f"[probe] port-8001 opener confirmed while port-8000 handshake "
          f"still pending: {joined_fast}")

    # stream 1 must still die with NO_ROUTE at its own budget, not forever
    failed = False
    try:
        b = await expect(o1r, T_STFAIL, timeout=15)
        failed = b[5] in (STF_NO_ROUTE, STF_JOIN_TIMEOUT)
    except (asyncio.TimeoutError, AssertionError):
        pass
    print(f"[probe] unclaimed port-8000 fails with NO_ROUTE at budget: {failed}")

    ok = burst_fanned and joined_fast and failed
    for x in (wh, wd, o1w, o2w):
        x.close()
    srv.cancel()
    print("BURST_ALL_PASS" if ok else "BURST_FAIL")
    return 0 if ok else 1


sys.exit(asyncio.run(main()))
