#!/usr/bin/env python3
"""Sub-process inheritance: a hooked parent that never touches sockets
spawns a plain child sender; the child inherits LD_PRELOAD + env, so its
traffic is tunneled and source-spoofed like any hooked game. (On Windows
the same is achieved by the CreateProcessA/W hooks; here the OS does it.)"""
import asyncio
import os
import socket
import sys
import tempfile

HOOKDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HOOKDIR))
from server import Relay
from wclient import WinClient

HOOK = os.path.join(HOOKDIR, "lan_hook.so")
PUB = 47820
UDP_REAL = 47921
RELAY_GAME_PORT = 47331

CHILD = r"""
import socket
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(6)
u.sendto(b"child-udp", ("192.168.99.99", %(port)d))
print("child sent", flush=True)
data, addr = u.recvfrom(65535)
print(f"child got {data!r} from {addr}", flush=True)
assert data == b"UECHO:child-udp" and addr[0] == "192.168.99.99", (data, addr)
print("CHILD_OK", flush=True)
""" % {"port": RELAY_GAME_PORT}

PARENT = r"""
import subprocess, sys
print("parent spawning sender (no sockets of its own)", flush=True)
r = subprocess.run([sys.executable, sys.argv[1]], capture_output=True,
                   text=True, timeout=20)
print(r.stdout, flush=True)
print(r.stderr, flush=True)
sys.exit(r.returncode)
"""


async def main():
    relay_task = asyncio.create_task(Relay(PUB, bind="127.0.0.1").run())
    await asyncio.sleep(0.3)
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.bind(("127.0.0.1", UDP_REAL))
    usock.setblocking(False)
    loop = asyncio.get_running_loop()

    async def echo():
        while True:
            data, addr = await loop.sock_recvfrom(usock, 65535)
            await loop.sock_sendto(usock, b"UECHO:" + data, addr)

    echo_task = asyncio.create_task(echo())
    bridge = WinClient("127.0.0.1", PUB, [], [], [],
                       udp_remote={UDP_REAL: RELAY_GAME_PORT}, host_mode=True)
    bridge_task = asyncio.create_task(bridge.run())
    await asyncio.sleep(1.5)

    with tempfile.TemporaryDirectory() as tmp:
        child = os.path.join(tmp, "child_sender.py")
        parent = os.path.join(tmp, "parent_spawner.py")
        open(child, "w").write(CHILD)
        open(parent, "w").write(PARENT)
        env = dict(os.environ, LD_PRELOAD=HOOK, LAN_HOOK_SERVER="127.0.0.1",
                   LAN_HOOK_PORT=str(PUB))
        proc = await asyncio.create_subprocess_exec(
            sys.executable, parent, child,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env=env)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            print("FAIL: hung")
            sys.exit(1)
        text = out.decode(errors="replace")
        print(text, flush=True)
        assert proc.returncode == 0, proc.returncode
        assert "CHILD_OK" in text
    print("CHILDPROP_ALL_PASS", flush=True)
    for t in (relay_task, bridge_task, echo_task):
        t.cancel()
    await asyncio.gather(relay_task, bridge_task, echo_task,
                         return_exceptions=True)



async def _guarded():
    """Hard watchdog: a stuck future must fail loudly in <=20s, never
    pin the suite (Python 3.12 wait_closed and co. can swallow hangs)."""
    await asyncio.wait_for(main(), timeout=20)


if __name__ == "__main__":
    asyncio.run(_guarded())
