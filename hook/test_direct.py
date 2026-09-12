#!/usr/bin/env python3
"""Symmetric hook e2e: hooked proc A hosts in-process (listen+echo+beacons,
auto-claims via listen()), hooked proc B discovers A's VIRTUAL IP and plays
over TCP+UDP. Relay only; no wclient.py anywhere."""
import asyncio
import os
import sys

HOOKDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HOOKDIR))
from server import Relay

HOOK = os.path.join(HOOKDIR, "lan_hook.so")
HOST_SENDER = os.path.join(HOOKDIR, "hook_sender_host.py")
PLAY_SENDER = os.path.join(HOOKDIR, "hook_sender_direct.py")
PUB = 47788
DISC = 45010
TCP_A = 47021
UDP_A = 47022


def hook_env():
    return dict(os.environ, LD_PRELOAD=HOOK, LAN_HOOK_SERVER="127.0.0.1",
               LAN_HOOK_PORT=str(PUB), LAN_HOOK_DEBUG="1")


async def main():
    relay_task = asyncio.create_task(Relay(PUB, bind="127.0.0.1").run())
    await asyncio.sleep(0.3)

    proc_a = await asyncio.create_subprocess_exec(
        sys.executable, HOST_SENDER,
        str(TCP_A), str(UDP_A), str(DISC), "BEACON:A", "30",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        env=hook_env())
    await asyncio.sleep(1.5)  # A claims + beacons flowing

    proc_b = await asyncio.create_subprocess_exec(
        sys.executable, PLAY_SENDER,
        str(DISC), str(TCP_A), str(UDP_A), "BEACON:A",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        env=hook_env())
    try:
        out_b, _ = await asyncio.wait_for(proc_b.communicate(), timeout=40)
    except asyncio.TimeoutError:
        proc_b.kill()
        print("FAIL: player hung")
        sys.exit(1)
    text_b = out_b.decode(errors="replace")
    print(text_b, flush=True)
    assert proc_b.returncode == 0, f"player exit {proc_b.returncode}"
    for marker in ("DISC_OK", "TCP_OK", "UDP_OK", "SENDER_DIRECT_OK"):
        assert marker in text_b, marker
    assert proc_a.returncode is None, "host must still be alive"
    # HOST side: the socket it accepted must present the PLAYER's vnode
    # as peer (bridge connections arrive from 127.0.0.1; spoofing that
    # never happened for accepted sockets — games cross-check the
    # lobby's announced source with getpeername and reject mismatches)
    peer_line = None
    while True:
        try:
            ln = await asyncio.wait_for(proc_a.stdout.readline(), 3)
        except asyncio.TimeoutError:
            break
        if not ln:
            break
        t = ln.decode(errors="replace")
        print(t, end="", flush=True)
        if "HOST accept peer=" in t:
            peer_line = t.strip()
            break
    assert peer_line and "peer=10.200." in peer_line, \
        f"accepted peer not virtualized: {peer_line}"
    print("DIRECT_ALL_PASS", flush=True)
    for p in (proc_a,):
        try:
            p.terminate()
        except ProcessLookupError:
            pass
    relay_task.cancel()
    await asyncio.gather(relay_task, return_exceptions=True)



async def _guarded():
    """Hard watchdog: a stuck future must fail loudly in <=20s, never
    pin the suite (Python 3.12 wait_closed and co. can swallow hangs)."""
    await asyncio.wait_for(main(), timeout=20)


if __name__ == "__main__":
    asyncio.run(_guarded())
