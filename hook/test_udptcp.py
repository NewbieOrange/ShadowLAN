#!/usr/bin/env python3
"""UDP-over-TCP mode (unfriendly NAT): game datagrams ride the TCP link.

A TCP-mode peer declares T_UDP_MODE after NODE; its PDAT/C2S/S2C/ICMP
payloads travel as T_UDP_TUN frames and relay replies come back the same
way — zero inbound UDP needed. UDP-mode peers are unaffected and the two
modes interoperate. The relay still never echoes to source.
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
    T_NODE, T_ASSIGN, T_UDP_TUN, T_UDP_MODE,
    U_GAME_C2S, U_GAME_S2C, U_ICMP_REQ, U_ICMP_REP,
    encode_node, encode_pdat, encode_udp_game,
    decode_udp_game, decode_icmp, encode_icmp,
    tcp_send, tcp_read,
)

PUB = 47821
G = 55701
NA, NB, NC = 0xE1E1E1E1, 0xE2E2E2E2, 0xE3E3E3E3


def udp_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.setblocking(False)
    return s


async def recv_one(loop, sock, timeout=4):
    return await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), timeout)


async def expect_udp_silence(loop, sock, timeout=0.7):
    try:
        data, _ = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 65535), timeout=timeout)
    except asyncio.TimeoutError:
        return
    raise AssertionError(f"UDP arrived despite TCP mode: {data!r}")


async def register_udp(node_id, udp_sock):
    """Plain UDP-mode node (TCP NODE + UDP U_NODE)."""
    port = udp_sock.getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", PUB)
    await tcp_send(writer, T_NODE, encode_node(b"", node_id, port))
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


class TcpModePeer:
    """TCP-mode node simulator: raw TCP link, optional owned UDP socket
    (proves the relay prefers TCP even when a UDP mapping exists)."""

    def __init__(self, node_id, with_udp_sock=True):
        self.node_id = node_id
        self.q = asyncio.Queue()
        self.udp = udp_sock() if with_udp_sock else None
        self.reader = self.writer = None
        self._rd = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(
            "127.0.0.1", PUB)
        uport = self.udp.getsockname()[1] if self.udp else 0
        await tcp_send(self.writer, T_NODE,
                       encode_node(b"", self.node_id, uport))
        await tcp_send(self.writer, T_UDP_MODE, b"")
        # wait for our ASSIGN (registration committed)
        while True:
            mtype, _ = await asyncio.wait_for(tcp_read(self.reader),
                                              timeout=4)
            if mtype == T_ASSIGN:
                break
        self._rd = asyncio.create_task(self._readloop())

    async def _readloop(self):
        try:
            while True:
                mtype, payload = await tcp_read(self.reader)
                await self.q.put((mtype, payload))
        except Exception:
            pass

    async def send_tun(self, udp_datagram: bytes):
        await tcp_send(self.writer, T_UDP_TUN, udp_datagram)

    async def recv_tun(self, timeout=4):
        """Next T_UDP_TUN payload from the relay."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            left = deadline - asyncio.get_running_loop().time()
            if left <= 0:
                raise asyncio.TimeoutError()
            mtype, payload = await asyncio.wait_for(self.q.get(),
                                                    timeout=left)
            if mtype == T_UDP_TUN:
                return payload

    async def drain_tun(self, quiet=0.4):
        """Drop pending T_UDP_TUN frames (test sequencing)."""
        loop = asyncio.get_running_loop()
        while True:
            t0 = loop.time()
            try:
                await asyncio.wait_for(self.q.get(), timeout=quiet)
            except asyncio.TimeoutError:
                return
            if loop.time() - t0 >= quiet - 0.05:
                return

    async def close(self):
        if self._rd:
            self._rd.cancel()
        if self.writer:
            self.writer.close()
        if self.udp:
            self.udp.close()


async def main():
    loop = asyncio.get_running_loop()
    relay = Relay(PUB, bind="127.0.0.1")
    relay_task = asyncio.create_task(relay.run())
    await asyncio.sleep(0.15)
    try:
        a = udp_sock()
        wa, _ra = await register_udp(NA, a)
        b = TcpModePeer(NB, with_udp_sock=True)
        await b.connect()
        assert any(l.get("udp_tcp") for l in relay.nodes[NB]["links"].values()), \
            "relay missed T_UDP_MODE"

        # B -> A addressed: B's PDAT rides TCP, A gets plain UDP C2S,
        # and B's own UDP socket stays silent (TCP preferred).
        await b.send_tun(encode_pdat(NA, G, "10.7.7.7", 4100, b"VIA-TCP"))
        d, _ = await recv_one(loop, a)
        dec = decode_udp_game(d)
        assert dec and dec[0] == U_GAME_C2S and dec[4] == b"VIA-TCP", d
        await expect_udp_silence(loop, b.udp)
        print("PASS[udptcp] TCP-mode PDAT delivered as UDP C2S", flush=True)

        # A -> B addressed: relay wraps the C2S in T_UDP_TUN for B.
        await loop.sock_sendto(
            a, encode_pdat(NB, G, "10.7.7.7", 4100, b"BACK-VIA-TCP"),
            ("127.0.0.1", PUB))
        inner = await b.recv_tun()
        dec = decode_udp_game(inner)
        assert dec and dec[0] == U_GAME_C2S and dec[4] == b"BACK-VIA-TCP", dec
        await expect_udp_silence(loop, b.udp)
        print("PASS[udptcp] UDP PDAT delivered as T_UDP_TUN", flush=True)

        # S2C back along the flow B opened: A replies, B gets T_UDP_TUN.
        await loop.sock_sendto(
            a, encode_udp_game(U_GAME_S2C, G, "10.7.7.7", 4100, b"R1"),
            ("127.0.0.1", PUB))
        inner = await b.recv_tun()
        dec = decode_udp_game(inner)
        assert dec and dec[0] == U_GAME_S2C and dec[4] == b"R1", dec
        print("PASS[udptcp] S2C follows flow back over TCP", flush=True)

        # Fallback path: TCP-mode node with NO udp mapping at all.
        c = TcpModePeer(NC, with_udp_sock=False)
        await c.connect()
        await c.send_tun(encode_pdat(NA, G, "10.8.8.8", 4200, b"NO-UDP"))
        d, _ = await recv_one(loop, a)
        dec = decode_udp_game(d)
        assert dec and dec[4] == b"NO-UDP", d
        await loop.sock_sendto(
            a, encode_udp_game(U_GAME_S2C, G, "10.8.8.8", 4200, b"R2"),
            ("127.0.0.1", PUB))
        inner = await c.recv_tun()
        dec = decode_udp_game(inner)
        assert dec and dec[0] == U_GAME_S2C and dec[4] == b"R2", dec
        print("PASS[udptcp] fallback sender without UDP mapping", flush=True)

        # ICMP over TCP: B pings the relay, then self (dropped, silence).
        await b.drain_tun()
        await b.send_tun(encode_icmp(U_ICMP_REQ, NB, 0, 77, 1, b"q"))
        inner = await b.recv_tun()
        dec = decode_icmp(inner)
        assert dec and dec[0] == U_ICMP_REP and dec[3] == 77, dec
        print("PASS[udptcp] relay .1 answers over TCP", flush=True)
        await b.drain_tun()
        await b.send_tun(encode_icmp(U_ICMP_REQ, NB, NB, 78, 1, b"me"))
        try:
            await b.recv_tun(timeout=1.0)
            raise AssertionError("self-ping echoed over TCP")
        except asyncio.TimeoutError:
            pass
        print("PASS[udptcp] self-ping dropped, no echo", flush=True)

        # Plain UDP peers unaffected in a mixed room.
        await loop.sock_sendto(
            a, encode_pdat(NA, G, "10.9.9.9", 4300, b"SELF-U"),
            ("127.0.0.1", PUB))
        await expect_udp_silence(loop, a, timeout=0.6)
        print("PASS[udptcp] UDP self-drop intact", flush=True)

        wa.close()
        a.close()
        await b.close()
        await c.close()
    finally:
        relay_task.cancel()
        await asyncio.gather(relay_task, return_exceptions=True)
    print("UDPTCP_ALL_PASS", flush=True)



async def _guarded():
    """Hard watchdog: a stuck future must fail loudly in <=20s, never
    pin the suite (Python 3.12 wait_closed and co. can swallow hangs)."""
    await asyncio.wait_for(main(), timeout=20)


if __name__ == "__main__":
    asyncio.run(_guarded())
