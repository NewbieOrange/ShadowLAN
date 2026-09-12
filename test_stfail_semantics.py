"""LAN-faithful stream verdict semantics (relay side).

A kernel answers connect() quickly and HONESTLY:
  - nobody claims the port in time    -> framed STFAIL/NO_ROUTE
                                          (hook: ECONNREFUSED)
  - dest CLAIMS then VANISHES         -> transport EOF/reset (the hook
                                          maps it to ECONNRESET, like a
                                          reset connect - NOT a 10 s
                                          stall; the early-STOK fuse is
                                          capped so the verdict lands
                                          inside the app's budget)
  - burst dials to different ports    -> independent (backlog semantics)
"""
import asyncio
import struct
import sys

sys.path.insert(0, ".")
import server
from server import Relay
from common import (HDR, T_NODE, T_ASSIGN, T_STOPEN, T_STREQ, T_STJOIN,
                    T_STJOINED, T_STOK, T_STFAIL, STF_NO_ROUTE,
                    STF_HOST_FAILED, encode_ctl_node)

PUB = 47958
NH, ND = 0x11111111, 0x22222222


async def frame(w, mtype, payload):
    w.write(HDR.pack(1 + len(payload)) + bytes([mtype]) + payload)
    await w.drain()


async def rd1(r, timeout=6):
    hdr = await asyncio.wait_for(r.readexactly(4), timeout)
    (mlen,) = HDR.unpack(hdr)
    body = await asyncio.wait_for(r.readexactly(mlen), timeout)
    return body[0], body


async def expect(r, mtype, timeout=6):
    while True:
        t, b = await rd1(r, timeout)
        if t == mtype:
            return b
        assert t == T_ASSIGN, f"got op {t:#x} want {mtype:#x}"


async def register(node):
    r, w = await asyncio.open_connection("127.0.0.1", PUB)
    await frame(w, T_NODE, encode_ctl_node(b"", node, 6000 + node % 100))
    await expect(r, T_ASSIGN)
    return r, w


async def dial():
    return await asyncio.open_connection("127.0.0.1", PUB)


def closer(*objs):
    for o in objs:
        try:
            o.close()
        except Exception:
            pass


async def wait_eof(r, timeout=8):
    try:
        while True:
            got = await asyncio.wait_for(r.read(1), timeout)
            if got == b"":
                return True
            return False      # byte(s) piped - not a clean teardown
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return True
    except asyncio.TimeoutError:
        return False


async def main():
    relay = Relay(PUB, token=b"", bind="127.0.0.1")
    srv = asyncio.create_task(relay.run())
    await asyncio.sleep(0.3)
    server.ST_TIMEOUT_S = 2.0          # shrink handshake budget: fast test
    socks = []
    results = {}
    try:
        rh, wh = await register(NH)     # dest node (one link)
        rd, wd = await register(ND)     # opener node
        socks += [wh, wd]

        # -- 1: nobody claims -> framed refusal with NO_ROUTE at budget
        o1r, o1w = await dial()
        socks.append(o1w)
        await frame(o1w, T_STOPEN, struct.pack("!IIIH", ND, NH, 0xAAAA, 8000))
        await expect(rh, T_STREQ)
        b = await expect(o1r, T_STFAIL, timeout=8)
        results["1-no-route-at-budget"] = b[5] == STF_NO_ROUTE
        print(f"[1] never-claimed stream -> framed NO_ROUTE at budget "
              f"(hook: fast ECONNREFUSED): {results['1-no-route-at-budget']}")

        # -- 2: claim, opener confirmed, then the joinee VANISHES.
        # The stream is raw by then: verdict = transport teardown (EOF),
        # and it must land within the handshake budget (capped fuse),
        # not after it.
        o2r, o2w = await dial()
        socks.append(o2w)
        await frame(o2w, T_STOPEN, struct.pack("!IIIH", ND, NH, 0xBBBB, 8001))
        b2 = await expect(rh, T_STREQ)
        sid2 = struct.unpack("!I", b2[1:5])[0]
        j2r, j2w = await dial()
        socks.append(j2w)
        await frame(j2w, T_STJOIN, struct.pack("!II", NH, sid2))
        await expect(j2r, T_STOK)          # claim read
        await expect(o2r, T_STOK)          # confirmed at claim
        j2w.close()                        # joiner vanishes (no STJOINED)
        eof2 = await wait_eof(o2r)
        print(f"[2] claimed-then-vanished -> opener sees EOF/reset "
              f"(hook: ECONNRESET, not a 10 s stall): {eof2}")
        results["2-vanish-eof"] = eof2

        # -- 3: burst independence (8005 claims while 8004 is pending)
        o4r, o4w = await dial()
        socks.append(o4w)
        await frame(o4w, T_STOPEN, struct.pack("!IIIH", ND, NH, 0xDDDD, 8004))
        await expect(rh, T_STREQ)                    # 8004 ignored
        o5r, o5w = await dial()
        socks.append(o5w)
        await frame(o5w, T_STOPEN, struct.pack("!IIIH", ND, NH, 0xEEEE, 8005))
        b5 = await expect(rh, T_STREQ)               # 8005 fans anyway
        sid5 = struct.unpack("!I", b5[1:5])[0]
        j5r, j5w = await dial()
        socks.append(j5w)
        await frame(j5w, T_STJOIN, struct.pack("!II", NH, sid5))
        await expect(j5r, T_STOK)
        await frame(j5w, T_STJOINED, struct.pack("!I", sid5))
        try:
            await expect(o5r, T_STOK, timeout=2.0)
            ok4 = True
        except (asyncio.TimeoutError, AssertionError):
            ok4 = False
        print(f"[3] burst: 8005 confirmed while 8004 pending: {ok4}")
        results["3-burst-independent"] = ok4
    finally:
        server.ST_TIMEOUT_S = 10.0
        closer(*socks)
        srv.cancel()
    all_ok = all(results.values()) and len(results) == 3
    print("STFAIL_ALL_PASS" if all_ok else f"STFAIL_FAIL {results}")
    return 0 if all_ok else 1


sys.exit(asyncio.run(main()))
