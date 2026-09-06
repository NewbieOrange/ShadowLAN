#!/usr/bin/env python3
"""Hooked game-player simulator. Runs UNDER LD_PRELOAD hook with
LAN_HOOK_SERVER set. Discovers the host's VIRTUAL IP from beacons
(source spoofed per-sender by the hook), then plays over TCP+UDP.
Usage: hook_sender_direct.py DISC TCP UDP BEACON
Expects beacon payload BEACON arriving from a virtual (10.200.x) IP.
"""
import socket
import sys
import time

disc_port, tcp_port, udp_port = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
want = sys.argv[4].encode()


def is_virt(ip):
    return ip.startswith("10.200.")


d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
d.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    d.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
except OSError:
    pass
d.bind(("0.0.0.0", disc_port))
d.settimeout(10)
host_virt = None
t0 = time.time()
while time.time() - t0 < 12 and not host_virt:
    try:
        data, addr = d.recvfrom(65535)
    except socket.timeout:
        break
    if data == want and is_virt(addr[0]):
        host_virt = addr[0]
if not host_virt:
    print("DISC_FAIL: no virtual-IP beacon", flush=True)
    sys.exit(1)
print(f"DISC_OK {want!r} from {host_virt}", flush=True)

t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.settimeout(8)
for attempt in range(3):
    try:
        t.connect((host_virt, tcp_port))
        break
    except OSError as e:
        print(f"tcp try {attempt}: {e}", flush=True)
        time.sleep(0.5)
else:
    print("TCP_FAIL", flush=True)
    sys.exit(1)
peer = t.getpeername()
print(f"TCP_PEER {peer}", flush=True)
assert peer[0] == host_virt and peer[1] == tcp_port, peer
t.sendall(b"direct-tcp")
got = b""
while len(got) < len(b"ECHO:direct-tcp"):
    chunk = t.recv(65536)
    if not chunk:
        break
    got += chunk
assert got == b"ECHO:direct-tcp", got
print(f"TCP_OK {got!r}", flush=True)
t.close()

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(8)
u.sendto(b"direct-udp", (host_virt, udp_port))
data, addr = u.recvfrom(65535)
print(f"UDP_GOT {data!r} from {addr}", flush=True)
assert data == b"UECHO:direct-udp", data
assert addr[0] == host_virt, addr
print("UDP_OK", flush=True)
print("SENDER_DIRECT_OK")
