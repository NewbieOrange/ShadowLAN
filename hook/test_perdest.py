#!/usr/bin/env python3
"""Per-dest scoping regressions (relay wire level + TCP survival).

  UDP-A (P2P per-dest): two players use the IDENTICAL triple
  (game_port, cli_ip, cli_port) but address DIFFERENT dest nodes.
  Both dests must get their own payload, and each dest's S2C reply
  must return to its own player (old global key routed both replies
  to the last writer).

  UDP-B (per-sender learned): after host1 replies to player1, a new
  player2's C2S must still fan out to host2 (old global learned sent
  it unicast to host1 only); player1 must stay sticky to host1.

  TCP-C (non-destructive handover): an established stream to host A
  must keep echoing from A after host B claims; only NEW streams go
  to B (old code killed all streams on every HELLO).

  DISC-D (per-source beacons): two hosts beaconing the IDENTICAL
  payload must both reach a player as distinct BCAST_FROMs (a global
  payload cache would forward only the first host's).
"""
import asyncio
import os
import socket
import struct
import sys

HOOKDIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HOOKDIR)
sys.path.insert(0, ROOT)
from server import Relay
from wclient import WinClient
from common import (
    T_NODE, T_BCAST, T_BCAST_FROM, U_GAME_C2S, U_GAME_S2C,
    encode_node, encode_pdat, encode_udp_game,
    decode_udp_game, decode_pdat, decode_bcast_from,
    tcp_send, tcp_read,
)

PUB = 47795
G = 55555
G2 = 55556
TRIPLE_IP, TRIPLE_PORT = "192.168.1.10", 5000
N1, N2 = 0x11111111, 0x22222222

R_TCP = 47391
A_LOCAL, B_LOCAL, PROXY = 47591, 47592, 47593


def udp_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.setblocking(False)
    return s


async def recv_one(loop, sock, timeout=5):
    return await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), timeout)


async def register_node(node_id, udp_sock):
    port = udp_sock.getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", PUB)
    await tcp_send(writer, T_NODE, encode_node(b"", node_id, port))
    from common import UMAGIC, UVER, U_NODE, encode_udp_node
    loop = asyncio.get_running_loop()
    await loop.sock_sendto(
        udp_sock, encode_udp_node(b"", node_id, port), ("127.0.0.1", PUB))

    async def drain():
        try:
            while True:
                await tcp_read(reader)
        except Exception:
            pass

    return writer, asyncio.create_task(drain())


async def test_udp_p2p_perdest():
    loop = asyncio.get_running_loop()
    hd1, hd2, p1, p2 = udp_sock(), udp_sock(), udp_sock(), udp_sock()
    w1, d1 = await register_node(N1, hd1)
    w2, d2 = await register_node(N2, hd2)
    await asyncio.sleep(0.7)
    await loop.sock_sendto(
        p1, encode_pdat(N1, G, TRIPLE_IP, TRIPLE_PORT, b"AAA"),
        ("127.0.0.1", PUB))
    await loop.sock_sendto(
        p2, encode_pdat(N2, G, TRIPLE_IP, TRIPLE_PORT, b"BBB"),
        ("127.0.0.1", PUB))
    d_hd1, _ = await recv_one(loop, hd1)
    d_hd2, _ = await recv_one(loop, hd2)
    dec1 = decode_udp_game(d_hd1)
    dec2 = decode_udp_game(d_hd2)
    assert dec1 and dec1[4] == b"AAA", ("hd1 got wrong payload", d_hd1)
    assert dec2 and dec2[4] == b"BBB", ("hd2 got wrong payload", d_hd2)
    print("PASS[p2p-perdest] dests got their own payloads", flush=True)
    await loop.sock_sendto(
        hd1, encode_udp_game(U_GAME_S2C, G, TRIPLE_IP, TRIPLE_PORT, b"R1"),
        ("127.0.0.1", PUB))
    await loop.sock_sendto(
        hd2, encode_udp_game(U_GAME_S2C, G, TRIPLE_IP, TRIPLE_PORT, b"R2"),
        ("127.0.0.1", PUB))
    r_p1, _ = await recv_one(loop, p1)
    r_p2, _ = await recv_one(loop, p2)
    assert decode_udp_game(r_p1)[4] == b"R1", ("p1 misrouted", r_p1)
    assert decode_udp_game(r_p2)[4] == b"R2", ("p2 misrouted", r_p2)
    print("PASS[p2p-perdest] replies returned to their own players", flush=True)
    for w, d, s in ((w1, d1, hd1), (w2, d2, hd2)):
        d.cancel()
        w.close()
    for s in (hd1, hd2, p1, p2):
        s.close()


async def test_udp_persender_learned():
    loop = asyncio.get_running_loop()
    h1, h2, q1, q2 = udp_sock(), udp_sock(), udp_sock(), udp_sock()
    w1, d1 = await register_node(0x33333333, h1)
    w2, d2 = await register_node(0x44444444, h2)
    await asyncio.sleep(0.7)
    await loop.sock_sendto(
        q1, encode_udp_game(U_GAME_C2S, G2, "10.0.0.9", 4000, b"Q1"),
        ("127.0.0.1", PUB))
    got_h1, _ = await recv_one(loop, h1)
    got_h2, _ = await recv_one(loop, h2)
    assert got_h1.endswith(b"Q1") and got_h2.endswith(b"Q1"), "fan-out broken"
    await loop.sock_sendto(
        h1, encode_udp_game(U_GAME_S2C, G2, "10.0.0.9", 4000, b"REP1"),
        ("127.0.0.1", PUB))
    rep, _ = await recv_one(loop, q1)
    assert rep.endswith(b"REP1"), rep
    # new sender, different triple: must still fan out to h2
    await loop.sock_sendto(
        q2, encode_udp_game(U_GAME_C2S, G2, "10.0.0.9", 4001, b"Q2"),
        ("127.0.0.1", PUB))
    q2_h1, _ = await recv_one(loop, h1)
    q2_h2, _ = await recv_one(loop, h2)
    assert q2_h1.endswith(b"Q2") and q2_h2.endswith(b"Q2"), \
        (q2_h1, q2_h2, "player2 did not fan out (global learned stuck?)")
    print("PASS[learned-persender] new player still fans out", flush=True)
    # old sender stays sticky to h1: h2 must NOT see q1's next packet
    h2.setblocking(False)
    await loop.sock_sendto(
        q1, encode_udp_game(U_GAME_C2S, G2, "10.0.0.9", 4000, b"Q1b"),
        ("127.0.0.1", PUB))
    sticky, _ = await recv_one(loop, h1)
    assert sticky.endswith(b"Q1b"), sticky
    try:
        extra, _ = await asyncio.wait_for(
            loop.sock_recvfrom(h2, 65535), timeout=1.0)
        raise AssertionError(f"h2 saw sticky packet: {extra!r}")
    except asyncio.TimeoutError:
        pass
    print("PASS[learned-persender] old player stays sticky", flush=True)
    for w, d in ((w1, d1), (w2, d2)):
        d.cancel()
        w.close()
    for s in (h1, h2, q1, q2):
        s.close()


async def echo_game(tag, port):
    async def on_conn(r, w):
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(tag + b":" + d)
            await w.drain()
        w.close()

    return await asyncio.start_server(on_conn, "127.0.0.1", port)


async def test_disc_distinct_hosts():
    # two hosts, byte-identical beacon payload, one player: player must
    # see BOTH servers as distinct attributed beacons
    loop = asyncio.get_running_loop()
    DISC = 45678
    PAYLOAD = b"SAME-GAME-BEACON"
    hu1, hu2 = udp_sock(), udp_sock()
    w1, d1 = await register_node(0x55555555, hu1)
    w2, d2 = await register_node(0x66666666, hu2)
    pw, pdraw = await register_node(0x77777777, udp_sock())
    await asyncio.sleep(0.5)
    got = asyncio.Queue()

    async def collect(reader):
        try:
            while True:
                mtype, payload = await tcp_read(reader)
                if mtype == T_BCAST_FROM:
                    await got.put(payload)
        except Exception:
            pass

    # need the reader side of the player conn: reopen with our own drain
    d1.cancel()
    d2.cancel()
    pdraw.cancel()
    for w in (w1, w2, pw):
        w.close()
    await asyncio.sleep(0.3)
    r1, w1 = await asyncio.open_connection("127.0.0.1", PUB)
    await tcp_send(w1, T_NODE, encode_node(b"", 0x55555555, hu1.getsockname()[1]))
    r2, w2 = await asyncio.open_connection("127.0.0.1", PUB)
    await tcp_send(w2, T_NODE, encode_node(b"", 0x66666666, hu2.getsockname()[1]))
    rp, wp = await asyncio.open_connection("127.0.0.1", PUB)
    await tcp_send(wp, T_NODE, encode_node(b"", 0x77777777, 0))
    t1 = asyncio.create_task(collect(r1))
    t2 = asyncio.create_task(collect(r2))
    tp = asyncio.create_task(collect(rp))
    await asyncio.sleep(0.5)
    await tcp_send(w1, T_BCAST, struct.pack("!H", DISC) + PAYLOAD)
    await tcp_send(w2, T_BCAST, struct.pack("!H", DISC) + PAYLOAD)
    seen = {}
    try:
        deadline = loop.time() + 8
        while set(seen) != {0x55555555, 0x66666666}:
            left = deadline - loop.time()
            if left <= 0:
                raise asyncio.TimeoutError()
            payload = await asyncio.wait_for(got.get(), timeout=left)
            dec = decode_bcast_from(payload)
            assert dec, payload
            node, dport, raw = dec
            assert dport == DISC and raw == PAYLOAD, (dport, raw)
            seen[node] = seen.get(node, 0) + 1
    except asyncio.TimeoutError:
        print(f"FAIL[disc-per-source]: only saw {sorted(seen)} (want both hosts)",
              flush=True)
        sys.exit(1)
    assert set(seen) == {0x55555555, 0x66666666}, seen
    print("PASS[disc-per-source] identical beacons from both hosts seen",
          flush=True)
    for t in (t1, t2, tp):
        t.cancel()
    for w in (w1, w2, wp):
        w.close()
    hu1.close()
    hu2.close()


async def test_tcp_survives_claim():
    srv_a = await echo_game(b"A", A_LOCAL)
    srv_b = await echo_game(b"B", B_LOCAL)
    host_a = WinClient("127.0.0.1", PUB, [], [], [],
                       tcp_remote={A_LOCAL: R_TCP}, host_mode=True)
    task_a = asyncio.create_task(host_a.run())
    cli = WinClient("127.0.0.1", PUB, [], [PROXY], [],
                    tcp_remote={PROXY: R_TCP})
    task_c = asyncio.create_task(cli.run())
    await asyncio.sleep(1.5)
    ra, wa = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", PROXY), timeout=5)
    wa.write(b"one")
    await wa.drain()
    assert await asyncio.wait_for(ra.read(65536), timeout=5) == b"A:one"
    host_b = WinClient("127.0.0.1", PUB, [], [], [],
                       tcp_remote={B_LOCAL: R_TCP}, host_mode=True)
    task_b = asyncio.create_task(host_b.run())
    await asyncio.sleep(1.5)
    assert not task_a.done(), "demoted A must stay connected"
    wa.write(b"two")
    await wa.drain()
    try:
        got = await asyncio.wait_for(ra.read(65536), timeout=5)
    except asyncio.TimeoutError:
        print("FAIL[tcp-survive]: old stream died on new claim", flush=True)
        sys.exit(1)
    assert got == b"A:two", (got, "old stream misrouted after claim")
    print("PASS[tcp-survive] old stream still served by A", flush=True)
    rb, wb = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", PROXY), timeout=5)
    wb.write(b"new")
    await wb.drain()
    assert await asyncio.wait_for(rb.read(65536), timeout=5) == b"B:new"
    print("PASS[tcp-survive] new stream goes to B", flush=True)
    wa.close()
    wb.close()
    for t in (task_a, task_b, task_c):
        t.cancel()
    await asyncio.gather(task_a, task_b, task_c, return_exceptions=True)
    srv_a.close()
    srv_b.close()


async def test_subnet_eviction(relay):
    # fill the /24 with dead entries, then a live NODE must evict one
    # and register (old code: "subnet full, rejecting node" forever)
    import time
    from common import ip_to_int
    base = ip_to_int("10.200.0.0") & 0xFFFFFF00
    now = time.monotonic()
    for i in range(2, 255):
        nid = 0x70000000 + i
        relay.nodes[nid] = {"writer": None, "tcp_ip": "", "udp_port": 0,
                            "udp_addr": None, "virt": base | i,
                            "seen_tcp": now, "seen_udp": 0.0}
    assert len(relay.nodes) >= 253, len(relay.nodes)
    reader, writer = await asyncio.open_connection("127.0.0.1", PUB)
    await tcp_send(writer, T_NODE, encode_node(b"", 0x7E11C7, 0))
    mtype, payload = await asyncio.wait_for(tcp_read(reader), timeout=5)
    from common import decode_assign
    assert mtype == 0x23, (mtype, "no ASSIGN = registration rejected")
    dec = decode_assign(payload)
    assert dec and dec[0] != 0, ("no virtual IP assigned", payload)
    assert 0x7E11C7 in relay.nodes, "new node missing"
    assert len(relay.nodes) <= 253, len(relay.nodes)
    print("PASS[subnet-evict] full table evicts stale, live node admitted",
          flush=True)
    writer.close()


async def main():
    relay = Relay(PUB)
    relay_task = asyncio.create_task(relay.run())
    await asyncio.sleep(0.3)
    try:
        await test_subnet_eviction(relay)
        await test_udp_p2p_perdest()
        await test_udp_persender_learned()
        await test_disc_distinct_hosts()
        await test_tcp_survives_claim()
    finally:
        relay_task.cancel()
        await asyncio.gather(relay_task, return_exceptions=True)
    print("PERDEST_ALL_PASS", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
