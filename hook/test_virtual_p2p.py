#!/usr/bin/env python3
"""Virtual-IP P2P mesh: relay assigns 10.200.0.x per node; hooked proc A
hosts (TCP+UDP+beacons, claims via listen), hooked proc C hosts a second
game (claims too, demoting A without kicking it), hooked proc B meshes
with BOTH over explicitly addressed streams. Proves distinct peer IPs,
attributed sources, and host-migration survival."""
import asyncio
import os
import sys

sys.path.insert(0, "/root/my_vnet")
from server import Relay

HOOK = "/root/my_vnet/hook/lan_hook.so"
HOST_SENDER = "/root/my_vnet/hook/hook_sender_host.py"
P2P_SENDER = "/root/my_vnet/hook/hook_sender_p2p.py"
PUB = 47793
DISC = 45031
A_TCP, A_UDP = 47601, 47602
C_TCP, C_UDP = 47604, 47605


def hook_env():
    return dict(os.environ, LD_PRELOAD=HOOK, LAN_HOOK_SERVER="127.0.0.1",
               LAN_HOOK_PORT=str(PUB))


async def main():
    relay_task = asyncio.create_task(Relay(PUB).run())
    await asyncio.sleep(0.3)

    proc_a = await asyncio.create_subprocess_exec(
        sys.executable, HOST_SENDER,
        str(A_TCP), str(A_UDP), str(DISC), "BEACON:A", "60",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        env=hook_env())
    await asyncio.sleep(1.5)  # A claims + beacons flowing
    proc_c = await asyncio.create_subprocess_exec(
        sys.executable, HOST_SENDER,
        str(C_TCP), str(C_UDP), str(DISC), "LOBBY:C", "60",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        env=hook_env())
    await asyncio.sleep(1.5)  # C claims (demotes A, keeps it connected)

    proc_b = await asyncio.create_subprocess_exec(
        sys.executable, P2P_SENDER,
        str(DISC), str(A_TCP), str(A_UDP), str(C_TCP), str(C_UDP),
        "BEACON:A", "LOBBY:C",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        env=hook_env())
    try:
        out_b, _ = await asyncio.wait_for(proc_b.communicate(), timeout=60)
    except asyncio.TimeoutError:
        proc_b.kill()
        print("FAIL: mesh player hung")
        sys.exit(1)
    text_b = out_b.decode(errors="replace")
    print(text_b, flush=True)
    assert proc_b.returncode == 0, f"mesh player exit {proc_b.returncode}"
    for marker in ("VIRTS distinct", "A TCP_OK", "A UDP_OK",
                   "C TCP_OK", "C UDP_OK", "SENDER_P2P_OK"):
        assert marker in text_b, marker
    assert proc_a.returncode is None, "demoted A must stay connected"
    assert proc_c.returncode is None, "C must stay connected"
    print("P2P_ALL_PASS", flush=True)
    for p in (proc_a, proc_c):
        try:
            p.terminate()
        except ProcessLookupError:
            pass
    relay_task.cancel()
    await asyncio.gather(relay_task, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
