#!/usr/bin/env python3
"""Symmetric end-to-end on loopback (Linux CI; logic is portable to Win).

  fake game server: bcast->127.0.0.1:45000, TCP 127.0.0.1:47001 echo,
                    UDP 127.0.0.1:47002 echo
  relay:            public TCP+UDP 127.0.0.1:47777 (open)
  host wclient:     --host --disc 45000 (bridges local game, no proxy binds)
  player wclient:   dial 127.0.0.1:47777, re-bcast->127.0.0.1:45001,
                    TCP proxy 0.0.0.0:47011=>47001, UDP proxy 0.0.0.0:47012=>47002
  fake game client: listen 45001 for discovery, TCP to 127.0.0.1:47011,
                    UDP to 127.0.0.1:47012
Asserts all three paths work with nobody co-located but the bridges.
Scenario B repeats discovery against a token relay.
"""
import asyncio
import socket
import sys

sys.path.insert(0, "/root/my_vnet")
from server import Relay
from wclient import WinClient

PUB_A = 47777
PUB_B = 47778
DISC = 45000
DISC_CLI = 45001
TCP_REAL = 47001
TCP_PROXY = 47011
UDP_REAL = 47002
UDP_PROXY = 47012


async def fake_game_server():
    async def on_tcp(r, w):
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(b"ECHO:" + d)
            await w.drain()
        w.close()
    tcp_srv = await asyncio.start_server(on_tcp, "127.0.0.1", TCP_REAL)
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.bind(("127.0.0.1", UDP_REAL))
    usock.setblocking(False)
    loop = asyncio.get_running_loop()

    async def udp_loop():
        while True:
            data, addr = await loop.sock_recvfrom(usock, 65535)
            await loop.sock_sendto(usock, b"UECHO:" + data, addr)

    async def bcast_loop():
        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"FAKESERVER:hello", ("127.0.0.1", DISC))
            s.close()
            await asyncio.sleep(0.3)

    return tcp_srv, asyncio.create_task(udp_loop()), asyncio.create_task(bcast_loop())


async def run_stack(pub, token, checks):
    relay = Relay(pub, token=token)
    relay_task = asyncio.create_task(relay.run())
    await asyncio.sleep(0.3)
    host = WinClient("127.0.0.1", pub, [DISC], [], [],
                     rebroadcast_ip="127.0.0.1", host_mode=True, token=token)
    host_task = asyncio.create_task(host.run())
    await asyncio.sleep(0.5)
    cli = WinClient("127.0.0.1", pub, [], [TCP_PROXY], [UDP_PROXY],
                    rebroadcast_ip="127.0.0.1",
                    rebroadcast_to=f"127.0.0.1:{DISC_CLI}",
                    disc_bind="0.0.0.0",
                    tcp_remote={TCP_PROXY: TCP_REAL},
                    udp_remote={UDP_PROXY: UDP_REAL},
                    token=token)
    cli_task = asyncio.create_task(cli.run())
    await asyncio.sleep(1.5)
    try:
        await checks()
    finally:
        for t in (relay_task, host_task, cli_task):
            t.cancel()
        await asyncio.gather(relay_task, host_task, cli_task,
                             return_exceptions=True)
        await asyncio.sleep(0.2)


async def check_discovery(tag):
    rsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rsock.bind(("127.0.0.1", DISC_CLI))
    rsock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(rsock, 65535), timeout=6)
    except asyncio.TimeoutError:
        print(f"FAIL[{tag}]: no discovery through relay", flush=True)
        sys.exit(1)
    assert data == b"FAKESERVER:hello", data
    print(f"PASS[{tag}] discovery: {data!r}", flush=True)
    rsock.close()


async def check_tcp_udp(tag):
    loop = asyncio.get_running_loop()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", TCP_PROXY), timeout=5)
    except Exception as e:
        print(f"FAIL[{tag}]: tcp proxy connect: {e}", flush=True)
        sys.exit(1)
    w.write(b"ping-tcp")
    await w.drain()
    try:
        got = await asyncio.wait_for(r.read(65536), timeout=5)
    except asyncio.TimeoutError:
        print(f"FAIL[{tag}]: no tcp reply through relay", flush=True)
        sys.exit(1)
    assert got == b"ECHO:ping-tcp", got
    print(f"PASS[{tag}] tcp: {got!r}", flush=True)
    w.close()

    csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    csock.bind(("127.0.0.1", 0))
    csock.setblocking(False)
    csock.sendto(b"ping-udp", ("127.0.0.1", UDP_PROXY))
    try:
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(csock, 65535), timeout=5)
    except asyncio.TimeoutError:
        print(f"FAIL[{tag}]: no udp reply through relay", flush=True)
        sys.exit(1)
    assert data == b"UECHO:ping-udp", data
    print(f"PASS[{tag}] udp: {data!r}", flush=True)
    csock.close()


async def main():
    tcp_srv, udp_task, bcast_task = await fake_game_server()

    async def full():
        await check_discovery("open")
        await check_tcp_udp("open")

    await run_stack(PUB_A, "", full)
    await asyncio.sleep(0.5)

    async def tok_only():
        await check_discovery("token")

    await run_stack(PUB_B, "SECRET", tok_only)

    print("ALL PASS", flush=True)
    for t in (udp_task, bcast_task):
        t.cancel()
    tcp_srv.close()


if __name__ == "__main__":
    asyncio.run(main())
