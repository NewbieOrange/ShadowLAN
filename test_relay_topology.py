#!/usr/bin/env python3
"""Host migration on an open relay: any player can take over hosting.

  relay:            public TCP+UDP 127.0.0.1:47791 (open, no token)
  fake game A:      TCP echo "A:" on 127.0.0.1:47101, UDP echo on :47102
  fake game B:      TCP echo "B:" on 127.0.0.1:47201, UDP echo on :47202
  wclient A --host: bridges relay port 47300 -> game A (rev-mapped)
  wclient B --host: bridges relay port 47300 -> game B (rev-mapped)
  player wclient C: TCP proxy 47401=>47300, UDP proxy 47402=>47300

Phase 1: only A up -> C's joins echo "A:" (A designated).
Phase 2: B claims -> A demoted but stays connected; C's joins echo "B:".
Phase 3: game A killed -> C's UDP gets exactly one "B:" reply.
"""
import asyncio
import socket
import sys

sys.path.insert(0, "/root/my_vnet")
from server import Relay
from wclient import WinClient

PUB = 47791
RELAY_TCP = 47300
TCP_PROXY = 47401
UDP_PROXY = 47402
A_TCP, A_UDP = 47101, 47102
B_TCP, B_UDP = 47201, 47202


def make_game(tag, tcp_port, udp_port):
    async def on_tcp(r, w):
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(tag + b":" + d)
            await w.drain()
        w.close()
    return on_tcp


async def start_game(tag, tcp_port, udp_port):
    tcp_srv = await asyncio.start_server(make_game(tag, tcp_port, udp_port),
                                         "127.0.0.1", tcp_port)
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.bind(("127.0.0.1", udp_port))
    usock.setblocking(False)
    loop = asyncio.get_running_loop()

    async def udp_loop():
        while True:
            data, addr = await loop.sock_recvfrom(usock, 65535)
            await loop.sock_sendto(usock, tag + b":" + data, addr)

    return tcp_srv, asyncio.create_task(udp_loop())


async def tcp_check(expect, tag):
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", TCP_PROXY), timeout=5)
    except Exception as e:
        print(f"FAIL[{tag}]: proxy connect: {e}", flush=True)
        sys.exit(1)
    w.write(b"ping")
    await w.drain()
    try:
        got = await asyncio.wait_for(r.read(65536), timeout=5)
    except asyncio.TimeoutError:
        print(f"FAIL[{tag}]: no tcp reply", flush=True)
        sys.exit(1)
    assert got == expect + b":ping", (tag, got)
    print(f"PASS[{tag}] tcp -> {got!r}", flush=True)
    w.close()


async def main():
    relay_task = asyncio.create_task(Relay(PUB).run())
    await asyncio.sleep(0.3)

    srv_a, udp_a = await start_game(b"A", A_TCP, A_UDP)
    host_a = WinClient("127.0.0.1", PUB, [], [], [],
                       tcp_remote={A_TCP: RELAY_TCP},
                       udp_remote={A_UDP: RELAY_TCP},
                       host_mode=True)
    task_a = asyncio.create_task(host_a.run())
    await asyncio.sleep(1.0)

    cli = WinClient("127.0.0.1", PUB, [], [TCP_PROXY], [UDP_PROXY],
                    tcp_remote={TCP_PROXY: RELAY_TCP},
                    udp_remote={UDP_PROXY: RELAY_TCP})
    task_c = asyncio.create_task(cli.run())
    await asyncio.sleep(1.5)

    await tcp_check(b"A", "phase1-designated-A")

    srv_b, udp_b = await start_game(b"B", B_TCP, B_UDP)
    host_b = WinClient("127.0.0.1", PUB, [], [], [],
                       tcp_remote={B_TCP: RELAY_TCP},
                       udp_remote={B_UDP: RELAY_TCP},
                       host_mode=True)
    task_b = asyncio.create_task(host_b.run())
    await asyncio.sleep(1.5)

    await tcp_check(b"B", "phase2-migrated-B")
    assert not task_a.done(), "demoted host A must stay connected"
    print("PASS[phase2] demoted A still connected", flush=True)

    # kill game A: only B may answer UDP from here on
    udp_a.cancel()
    srv_a.close()
    await asyncio.sleep(0.3)
    csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    csock.bind(("127.0.0.1", 0))
    csock.setblocking(False)
    csock.sendto(b"ping-udp", ("127.0.0.1", UDP_PROXY))
    loop = asyncio.get_running_loop()
    try:
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(csock, 65535), timeout=5)
    except asyncio.TimeoutError:
        print("FAIL[phase3]: no udp reply", flush=True)
        sys.exit(1)
    assert data == b"B:ping-udp", data
    print(f"PASS[phase3] udp -> {data!r}", flush=True)
    csock.close()

    print("MIGRATE_ALL_PASS", flush=True)
    for t in (relay_task, task_a, task_b, task_c, udp_b):
        t.cancel()
    await asyncio.gather(relay_task, task_a, task_b, task_c, udp_b,
                         return_exceptions=True)
    srv_b.close()


if __name__ == "__main__":
    asyncio.run(main())
