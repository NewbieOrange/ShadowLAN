#!/usr/bin/env python3
"""End-to-end check on loopback (Linux CI; client logic is portable to Win).

Topology (single host, distinct ports to avoid same-box bind clash;
production uses SAME game ports on two PCs, no clash):
  fake game server: bcast->127.0.0.1:45000, TCP 127.0.0.1:47001 echo,
                    UDP 127.0.0.1:47002 echo
  host server.py:   public TCP+UDP 127.0.0.1:47777, snoop 45000
  wclient.py:       dial 127.0.0.1:47777, re-bcast->127.0.0.1:45001,
                    TCP proxy 0.0.0.0:47011=>47001, UDP proxy 0.0.0.0:47012=>47002
  fake game client: listen 45001 for discovery, TCP to 127.0.0.1:47011,
                    UDP to 127.0.0.1:47012
Asserts all three paths work through the tunnel.
"""
import asyncio
import socket
import sys

sys.path.insert(0, "/root/my_vnet")
from server import Host
from wclient import WinClient

PUB = 47777
DISC = 45000
DISC_CLI = 45001
TCP_REAL = 47001
TCP_PROXY = 47011
UDP_REAL = 47002
UDP_PROXY = 47012


async def fake_game_server():
    # TCP echo
    async def on_tcp(r, w):
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(b"ECHO:" + d)
            await w.drain()
        w.close()
    tcp_srv = await asyncio.start_server(on_tcp, "127.0.0.1", TCP_REAL)
    # UDP echo
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.bind(("127.0.0.1", UDP_REAL))
    usock.setblocking(False)
    loop = asyncio.get_running_loop()

    async def udp_loop():
        while True:
            data, addr = await loop.sock_recvfrom(usock, 65535)
            await loop.sock_sendto(usock, b"UECHO:" + data, addr)

    # periodic broadcast
    bsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    async def bcast_loop():
        while True:
            bsock.sendto(b"FAKESERVER:hello", ("127.0.0.1", DISC))
            await asyncio.sleep(0.3)

    return tcp_srv, asyncio.create_task(udp_loop()), asyncio.create_task(bcast_loop())


async def main():
    tcp_srv, udp_task, bcast_task = await fake_game_server()

    host = Host(PUB, [DISC], target="127.0.0.1")
    host_task = asyncio.create_task(host.run())
    await asyncio.sleep(0.5)

    cli = WinClient("127.0.0.1", PUB, [], [TCP_PROXY], [UDP_PROXY],
                    rebroadcast_ip="127.0.0.1",
                    rebroadcast_to=f"127.0.0.1:{DISC_CLI}",
                    disc_bind="0.0.0.0",
                    tcp_remote={TCP_PROXY: TCP_REAL},
                    udp_remote={UDP_PROXY: UDP_REAL})
    cli_task = asyncio.create_task(cli.run())
    await asyncio.sleep(1.5)  # let dial + listeners come up

    # 1) discovery host -> client
    rsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rsock.bind(("127.0.0.1", DISC_CLI))
    rsock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(rsock, 65535), timeout=5)
    except asyncio.TimeoutError:
        print("FAIL: no discovery through tunnel", flush=True)
        sys.exit(1)
    assert data == b"FAKESERVER:hello", data
    print(f"PASS discovery: {data!r}", flush=True)

    # 2) game TCP via proxy
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", TCP_PROXY), timeout=5)
    except Exception as e:
        print(f"FAIL: tcp proxy connect: {e}", flush=True)
        sys.exit(1)
    w.write(b"ping-tcp")
    await w.drain()
    try:
        got = await asyncio.wait_for(r.read(65536), timeout=5)
    except asyncio.TimeoutError:
        print("FAIL: no tcp reply through tunnel", flush=True)
        sys.exit(1)
    assert got == b"ECHO:ping-tcp", got
    print(f"PASS tcp: {got!r}", flush=True)
    w.close()

    # 3) game UDP via proxy
    csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    csock.bind(("127.0.0.1", 0))
    csock.setblocking(False)
    csock.sendto(b"ping-udp", ("127.0.0.1", UDP_PROXY))
    try:
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(csock, 65535), timeout=5)
    except asyncio.TimeoutError:
        print("FAIL: no udp reply through tunnel", flush=True)
        sys.exit(1)
    assert data == b"UECHO:ping-udp", data
    print(f"PASS udp: {data!r}", flush=True)

    print("ALL PASS", flush=True)
    for t in (host_task, cli_task, udp_task, bcast_task):
        t.cancel()
    tcp_srv.close()


if __name__ == "__main__":
    asyncio.run(main())
