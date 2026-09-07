#!/usr/bin/env python3
"""Hook-level ICMP end to end (Linux, root for raw sockets; skips otherwise).

Two hooked processes discover each other's virtual IP via discovery
beacons, then exchange real ICMP echo request/reply datagrams through
the relay: peer ping, self ping, relay-.1 ping and subnet-broadcast
ping. Exercises raw-socket intercept, addressed REQ/REP routing,
loopback rules and reply synthesis in lan_hook.so.
"""
import asyncio
import os
import socket
import struct
import subprocess
import sys
import time

HOOKDIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HOOKDIR)
sys.path.insert(0, ROOT)

PUB = 47812
DISC = 45699

CHILD = r"""
import socket, struct, sys, time

def cksum(b):
    s = 0
    for i in range(0, len(b) & ~1, 2):
        s += (b[i] << 8) + b[i + 1]
    if len(b) & 1:
        s += b[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def echo_req(iid, seq, payload):
    h = struct.pack("!BBHHH", 8, 0, 0, iid, seq) + payload
    c = cksum(h)
    return struct.pack("!BBHHH", 8, 0, c, iid, seq) + payload

def parse_rep(pkt):
    if len(pkt) < 8:
        return None
    t, code, c, iid, seq = struct.unpack("!BBHHH", pkt[:8])
    return t, code, iid, seq, pkt[8:]

tag = sys.argv[1]
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
raw.settimeout(6)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
u.bind(("0.0.0.0", %DISC%))
u.settimeout(0.5)
print("READY", flush=True)
peer = None
t0 = time.time()
while time.time() - t0 < 15 and peer is None:
    if time.time() - t0 > 1:
        try:
            u.sendto(("BEACON-" + tag).encode(), ("255.255.255.255", %DISC%))
        except OSError:
            pass
    try:
        data, addr = u.recvfrom(65535)
    except socket.timeout:
        continue
    if data.startswith(b"BEACON-") and data != ("BEACON-" + tag).encode():
        peer = addr[0]
        print(f"PEER {peer} {data.decode()}", flush=True)
if peer is None:
    print("NOPEER", flush=True)
    sys.exit(1)
for line in sys.stdin:
    line = line.strip()
    if not line.startswith("PING "):
        continue
    _, ip = line.split(None, 1)
    iid = 0x4000 + (abs(hash(tag)) % 1000)
    seq = 1
    try:
        raw.sendto(echo_req(iid, seq, b"shadowlan"), (ip, 0))
    except OSError as e:
        print(f"SENDFAIL {e}", flush=True)
        continue
    got = []
    t1 = time.time()
    while time.time() - t1 < 5 and len(got) < 4:
        try:
            pkt, addr = raw.recvfrom(65535)
        except socket.timeout:
            break
        pr = parse_rep(pkt)
        if pr and pr[0] == 0 and pr[2] == iid and pr[4] == b"shadowlan":
            got.append(addr[0])
    print("REPLIES " + ",".join(sorted(set(got))), flush=True)
""".replace("%DISC%", str(DISC))


async def read_line(stream, timeout=20):
    try:
        line = await asyncio.wait_for(stream.readline(), timeout)
    except asyncio.TimeoutError:
        return ""
    return line.decode().strip()


async def spawn(tag, env):
    p = await asyncio.create_subprocess_exec(
        sys.executable, "-c", CHILD, tag,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, env=env)
    return p


async def main():
    from server import Relay
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_ICMP)
        probe.close()
    except PermissionError:
        print("ICMP_SKIP (no raw socket privilege)")
        return 0
    relay = Relay(PUB)
    relay_task = asyncio.create_task(relay.run())
    await asyncio.sleep(0.2)
    env = dict(os.environ,
               LD_PRELOAD=os.path.join(HOOKDIR, "lan_hook.so"),
               LAN_HOOK_SERVER="127.0.0.1", LAN_HOOK_PORT=str(PUB),
               LAN_HOOK_DEBUG="0", LAN_HOOK_INIT_TIMEOUT="15000")
    try:
        a = await spawn("A", env)
        b = await spawn("B", env)
        for p, want in ((a, "A"), (b, "B")):
            line = await read_line(p.stdout)
            assert line == "READY", (want, line)
        la = await read_line(a.stdout)
        lb = await read_line(b.stdout)
        assert la.startswith("PEER ") and lb.startswith("PEER "), (la, lb)
        va = lb.split()[1]  # B saw A's beacon from VA
        vb = la.split()[1]  # A saw B's beacon from VB
        assert va.startswith("10.200.") and vb.startswith("10.200."), (va, vb)
        print(f"PASS[icmp] peer discovery A={va} B={vb}", flush=True)

        async def ping(p, ip):
            p.stdin.write(f"PING {ip}\n".encode())
            await p.stdin.drain()
            return await read_line(p.stdout, timeout=12)

        # peer ping both directions
        r = await ping(a, vb)
        assert r == f"REPLIES {vb}", r
        r = await ping(b, va)
        assert r == f"REPLIES {va}", r
        print("PASS[icmp] peer ping both ways", flush=True)
        # self ping (loopback served client-side, relay drops)
        r = await ping(a, va)
        assert r == f"REPLIES {va}", r
        print("PASS[icmp] self ping", flush=True)
        # relay .1
        r = await ping(a, "10.200.0.1")
        assert r == "REPLIES 10.200.0.1", r
        print("PASS[icmp] relay .1 answers", flush=True)
        # subnet broadcast: self + peer reply
        r = await ping(b, "10.200.0.255")
        got = set(r.split(" ", 1)[1].split(",")) if r.startswith("REPLIES ") else set()
        assert got == {va, vb}, (r, va, vb)
        print("PASS[icmp] broadcast ping fans out + self", flush=True)
        for p in (a, b):
            p.kill()
    finally:
        relay_task.cancel()
        await asyncio.gather(relay_task, return_exceptions=True)
    print("ICMP_ALL_PASS", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
