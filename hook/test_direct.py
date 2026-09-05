#!/usr/bin/env python3
"""Direct-mode e2e: hook (LD_PRELOAD, LAN_HOOK_SERVER) talks to server.py
with NO wclient.py in the path. Proves TCP + UDP unicast + broadcast."""
import asyncio
import os
import socket
import subprocess
import sys

sys.path.insert(0, "/root/my_vnet")
from server import Host

HOOK = "/root/my_vnet/hook/lan_hook.so"
SENDER = "/root/my_vnet/hook/hook_sender_direct.py"
PUB = 47788
DISC = 45010
TCP_REAL = 47021
UDP_REAL = 47022


async def fake_game():
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

    bsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # NOTE: fresh socket per beacon. Linux SO_REUSEPORT hashes (src+dst)
    # so a fixed source port would pin ALL beacons to one same-box socket
    # and starve the other. Windows SO_REUSEADDR duplicates to all instead.
    async def bcast_loop():
        while True:
            bs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            bs.sendto(b"BEACON:direct", ("127.0.0.1", DISC))
            bs.close()
            await asyncio.sleep(0.3)

    return tcp_srv, asyncio.create_task(udp_loop()), asyncio.create_task(bcast_loop())


async def main():
    tcp_srv, ut, bt = await fake_game()
    host = Host(PUB, [DISC], target="127.0.0.1")
    ht = asyncio.create_task(host.run())
    await asyncio.sleep(0.5)
    env = dict(os.environ, LD_PRELOAD=HOOK, LAN_HOOK_SERVER="127.0.0.1",
               LAN_HOOK_PORT=str(PUB), LAN_HOOK_DEBUG="1")
    env.pop("LAN_HOOK_RELAY", None)
    p = await asyncio.create_subprocess_exec(
        sys.executable, SENDER, str(DISC), str(TCP_REAL), str(UDP_REAL),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=env)
    try:
        out, _ = await asyncio.wait_for(p.communicate(), timeout=40)
    except asyncio.TimeoutError:
        p.kill()
        print("FAIL: sender hung")
        sys.exit(1)
    text = out.decode(errors="replace")
    print(text, flush=True)
    assert p.returncode == 0, f"sender exit {p.returncode}"
    assert "DISC_OK" in text and "TCP_OK" in text and "UDP_OK" in text
    assert "SENDER_DIRECT_OK" in text
    print("DIRECT_ALL_PASS", flush=True)
    for t in (ht, ut, bt):
        t.cancel()
    tcp_srv.close()


if __name__ == "__main__":
    asyncio.run(main())
