#!/usr/bin/env python3
"""Relay never echoes to source + ICMP mesh (v1.1.0).

  NOLOOP: the relay must never send a data packet back to its source.
  Loopback is the client's job (hook self-echo / local echo). Covers:
  - UDP addressed P2P to self -> dropped, sender hears nothing
  - UDP unaddressed C2S with a single peer -> no route, sender hears nothing
  - UDP S2C addressed back to its own sender -> dropped
  - TCP broadcast -> sender gets no BCAST/BCAST_FROM, peer does

  ICMP: relay is .1 of its subnet and answers echo requests; requests
  route peer-to-peer by dest node; replies route back; self-pings and
  unknown dests are dropped (client loops back to itself).
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
from common import (
    T_NODE, T_BCAST, T_BCAST_FROM, T_ASSIGN,
    U_GAME_C2S, U_GAME_S2C,
    U_ICMP_REQ, U_ICMP_REP,
    encode_ctl_node, encode_pdat, encode_udp_game,
    decode_udp_game, decode_icmp, encode_icmp,
    tcp_send, tcp_read,
)

PUB = 47801
G = 55601
N1, N2 = 0x0A0A0A0A, 0x0B0B0B0B


def udp_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.setblocking(False)
    return s


async def recv_one(loop, sock, timeout=3):
    return await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), timeout)


async def expect_silence(loop, sock, timeout=0.7):
    try:
        data, _ = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 65535), timeout=timeout)
    except asyncio.TimeoutError:
        return
    raise AssertionError(f"relay echoed to source: {data!r}")


async def register_node(node_id, udp_sock):
    port = udp_sock.getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", PUB)
    await tcp_send(writer, T_NODE, encode_ctl_node(b"", node_id, port))
    from common import encode_udp_node
    loop = asyncio.get_running_loop()
    await loop.sock_sendto(
        udp_sock, encode_udp_node(b"", node_id, port), ("127.0.0.1", PUB))
    try:
        while True:
            mtype, _ = await asyncio.wait_for(tcp_read(reader), timeout=3)
            if mtype == T_ASSIGN:
                break
    except (asyncio.TimeoutError, Exception):
        pass
    return writer, reader


async def tcp_collect(reader, out_q):
    try:
        while True:
            mtype, payload = await tcp_read(reader)
            if mtype in (T_BCAST, T_BCAST_FROM):
                await out_q.put((mtype, payload))
    except Exception:
        pass


async def test_noloop_udp():
    loop = asyncio.get_running_loop()
    a, b = udp_sock(), udp_sock()
    wa, _ra = await register_node(N1, a)
    wb, _rb = await register_node(N2, b)
    # P2P to self: dropped, no echo
    await loop.sock_sendto(
        a, encode_pdat(N1, G, "10.9.9.9", 4000, b"SELF"),
        ("127.0.0.1", PUB))
    await expect_silence(loop, a)
    print("PASS[noloop] P2P-to-self dropped", flush=True)
    # P2P to peer still works (control: routing itself is fine)
    await loop.sock_sendto(
        a, encode_pdat(N2, G, "10.9.9.9", 4000, b"HELLO"),
        ("127.0.0.1", PUB))
    d, _ = await recv_one(loop, b)
    dec = decode_udp_game(d)
    assert dec and dec[4] == b"HELLO", d
    print("PASS[noloop] P2P-to-peer delivered", flush=True)
    # S2C back to its own sender: dropped
    await loop.sock_sendto(
        b, encode_udp_game(U_GAME_S2C, G, "10.9.9.9", 4000, b"BACK"),
        ("127.0.0.1", PUB))
    await expect_silence(loop, b)
    print("PASS[noloop] S2C-to-self dropped", flush=True)
    wa.close()
    wb.close()
    a.close()
    b.close()


async def test_noloop_bcast():
    loop = asyncio.get_running_loop()
    a, b = udp_sock(), udp_sock()
    wa, ra = await register_node(0x0C0C0C0C, a)
    wb, rb = await register_node(0x0D0D0D0D, b)
    qa, qb = asyncio.Queue(), asyncio.Queue()
    ta = asyncio.create_task(tcp_collect(ra, qa))
    tb = asyncio.create_task(tcp_collect(rb, qb))
    await asyncio.sleep(0.2)
    await tcp_send(wa, T_BCAST, struct.pack("!HH", 45601, 4001) + b"BC")
    got_b = await asyncio.wait_for(qb.get(), timeout=3)
    assert got_b[0] == T_BCAST_FROM, got_b
    try:
        extra = await asyncio.wait_for(qa.get(), timeout=0.7)
        raise AssertionError(f"sender got own broadcast: {extra!r}")
    except asyncio.TimeoutError:
        pass
    print("PASS[noloop] broadcast skips sender, reaches peer", flush=True)
    ta.cancel()
    tb.cancel()
    wa.close()
    wb.close()
    a.close()
    b.close()


async def test_icmp():
    loop = asyncio.get_running_loop()
    a, b = udp_sock(), udp_sock()
    wa, _ra = await register_node(N1, a)
    wb, _rb = await register_node(N2, b)
    # A pings B: B gets REQ with A's node as source
    await loop.sock_sendto(
        a, encode_icmp(U_ICMP_REQ, N1, N2, 0x1234, 7, b"pingdata"),
        ("127.0.0.1", PUB))
    d, _ = await recv_one(loop, b)
    dec = decode_icmp(d)
    assert dec and dec[0] == U_ICMP_REQ, d
    _, src, dest, iid, seq, idata = dec
    assert (src, dest, iid, seq, idata) == (N1, N2, 0x1234, 7, b"pingdata"), dec
    print("PASS[icmp] request routed with source attribution", flush=True)
    # B replies: A gets REP
    await loop.sock_sendto(
        b, encode_icmp(U_ICMP_REP, N2, N1, 0x1234, 7, b"pingdata"),
        ("127.0.0.1", PUB))
    d, _ = await recv_one(loop, a)
    dec = decode_icmp(d)
    assert dec and dec[0] == U_ICMP_REP and dec[3] == 0x1234
    assert dec[4] == 7 and dec[5] == b"pingdata", dec
    print("PASS[icmp] reply routed back", flush=True)
    # self-ping: dropped, no echo
    await loop.sock_sendto(
        a, encode_icmp(U_ICMP_REQ, N1, N1, 1, 1, b"me"),
        ("127.0.0.1", PUB))
    await expect_silence(loop, a)
    print("PASS[icmp] self-ping dropped", flush=True)
    # unknown dest: dropped
    await loop.sock_sendto(
        a, encode_icmp(U_ICMP_REQ, N1, 0xDEADDEAD, 2, 2, b"void"),
        ("127.0.0.1", PUB))
    await expect_silence(loop, a)
    await expect_silence(loop, b, timeout=0.4)
    print("PASS[icmp] unknown dest dropped", flush=True)
    # relay .1 (dest 0): relay itself answers
    await loop.sock_sendto(
        a, encode_icmp(U_ICMP_REQ, N1, 0, 0x55, 3, b"relay?"),
        ("127.0.0.1", PUB))
    d, _ = await recv_one(loop, a)
    dec = decode_icmp(d)
    assert dec and dec[0] == U_ICMP_REP, d
    assert dec[2] == N1 and dec[3] == 0x55 and dec[5] == b"relay?", dec
    print("PASS[icmp] relay .1 answers", flush=True)
    # spoofed source corrected: unknown sender addr with src=0 dropped
    c = udp_sock()  # never registered
    await loop.sock_sendto(
        c, encode_icmp(U_ICMP_REQ, 0, N2, 9, 9, b"anon"),
        ("127.0.0.1", PUB))
    await expect_silence(loop, b, timeout=0.5)
    print("PASS[icmp] anonymous request dropped", flush=True)
    c.close()
    wa.close()
    wb.close()
    a.close()
    b.close()


async def main():
    relay = Relay(PUB, bind="127.0.0.1")
    assert (relay.relay_virt() & 0xFF) == 1, hex(relay.relay_virt())
    relay_task = asyncio.create_task(relay.run())
    await asyncio.sleep(0.15)
    try:
        await test_noloop_udp()
        await test_noloop_bcast()
        await test_icmp()
    finally:
        relay_task.cancel()
        await asyncio.gather(relay_task, return_exceptions=True)
    print("NOLOOP_ALL_PASS", flush=True)



async def _guarded():
    """Hard watchdog: a stuck future must fail loudly in <=20s, never
    pin the suite (Python 3.12 wait_closed and co. can swallow hangs)."""
    await asyncio.wait_for(main(), timeout=20)


if __name__ == "__main__":
    asyncio.run(_guarded())
