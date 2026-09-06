#!/usr/bin/env python3
"""Symmetric hook e2e: hooked proc A hosts in-process (listen+echo+beacons,
auto-claims via listen()), hooked proc B discovers A's VIRTUAL IP and plays
over TCP+UDP. Relay only; no wclient.py anywhere."""
import asyncio
import os
import sys

sys.path.insert(0, "/root/my_vnet")
from server import Relay

HOOK = "/root/my_vnet/hook/lan_hook.so"
HOST_SENDER = "/root/my_vnet/hook/hook_sender_host.py"
PLAY_SENDER = "/root/my_vnet/hook/hook_sender_direct.py"
PUB = 47788
DISC = 45010
TCP_A = 47021
UDP_A = 47022


def hook_env():
    return dict(os.environ, LD_PRELOAD=HOOK, LAN_HOOK_SERVER="127.0.0.1",
               LAN_HOOK_PORT=str(PUB), LAN_HOOK_DEBUG="1")


async def main():
    relay_task = asyncio.create_task(Relay(PUB).run())
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
    print("DIRECT_ALL_PASS", flush=True)
    for p in (proc_a,):
        try:
            p.terminate()
        except ProcessLookupError:
            pass
    relay_task.cancel()
    await asyncio.gather(relay_task, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
