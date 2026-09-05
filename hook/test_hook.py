#!/usr/bin/env python3
"""Verify Linux LD_PRELOAD hook (same logic as Windows DLL).
Relay stands in for wclient.py listening on 127.0.0.1."""
import asyncio
import os
import socket
import subprocess
import sys

HOOK = "/root/my_vnet/hook/lan_hook.so"
SENDER = "/root/my_vnet/hook/hook_sender.py"
UDP_PORT = 50101
TCP_PORT = 50102


async def main():
    loop = asyncio.get_running_loop()
    # relay UDP: answers first datagram so sender can check recvfrom spoof
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.bind(("127.0.0.1", UDP_PORT))
    usock.setblocking(False)
    got = []

    async def udp_relay():
        for _ in range(2):  # unicast + broadcast, both rewritten to here
            data, addr = await loop.sock_recvfrom(usock, 65535)
            got.append((data, addr))
            await loop.sock_sendto(usock, b"reply:" + data, addr)

    # relay TCP
    async def on_tcp(r, w):
        data = await r.read(65536)
        assert data == b"hook-tcp", data
        print(f"TCP_GOT {data!r} at relay", flush=True)
        w.close()

    tcp_srv = await asyncio.start_server(on_tcp, "127.0.0.1", TCP_PORT)
    ut = asyncio.create_task(udp_relay())
    await asyncio.sleep(0.2)

    env = dict(os.environ, LD_PRELOAD=HOOK, LAN_HOOK_RELAY="127.0.0.1")
    p = await asyncio.create_subprocess_exec(
        sys.executable, SENDER, str(UDP_PORT), str(TCP_PORT),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=env)
    try:
        out, _ = await asyncio.wait_for(p.communicate(), timeout=15)
    except asyncio.TimeoutError:
        p.kill()
        print("FAIL: sender hung\n", p)
        sys.exit(1)
    text = out.decode(errors="replace")
    print(text, flush=True)
    assert p.returncode == 0, f"sender exit {p.returncode}"
    assert "UDP_SPOOF_OK" in text and "TCP_SPOOF_OK" in text and "SENDER_OK" in text
    assert len(got) == 2, got
    assert all(d in (b"hook-udp-unicast", b"hook-udp-bcast") for d, _ in got), got
    print("HOOK_ALL_PASS", flush=True)
    ut.cancel()
    tcp_srv.close()


if __name__ == "__main__":
    asyncio.run(main())
