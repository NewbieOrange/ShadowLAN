#!/usr/bin/env python3
"""Helper run UNDER LD_PRELOAD hook in DIRECT mode (LAN_HOOK_SERVER set).
No wclient.py: the hook itself tunnels to server.py."""
import socket
import sys
import time

disc_port, tcp_port, udp_port = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])

# 1) discovery listener: bound to DISC, expects TUNNELED beacon from 192.168.7.1
d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
d.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    d.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
except OSError:
    pass
# NOTE: bind wildcard (like real games). On single-host Linux tests a
# 127.0.0.1-bound socket would steal ALL unicast beacons from the
# 0.0.0.0-bound host sniffer (exact-match wins over REUSEPORT hash);
# Windows duplicates broadcasts to every bound socket instead.
d.bind(("0.0.0.0", disc_port))
d.settimeout(10)
tunneled = None
t0 = time.time()
while time.time() - t0 < 9:
    try:
        data, addr = d.recvfrom(65535)
    except socket.timeout:
        break
    if addr[0] == "192.168.7.1" and data == b"BEACON:direct":
        tunneled = (data, addr)
        break
if not tunneled:
    print("DISC_FAIL: no tunneled beacon (192.168.7.1)")
    sys.exit(1)
print(f"DISC_OK {tunneled[0]!r} from {tunneled[1]}", flush=True)

# 2) TCP to fake LAN IP: must land on server-side game via tunnel
t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.settimeout(8)
t.connect(("192.168.99.99", tcp_port))
peer = t.getpeername()
print(f"TCP_PEER {peer}", flush=True)
assert peer[0] == "192.168.99.99" and peer[1] == tcp_port, peer
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

# 3) UDP unicast to fake LAN IP
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(8)
u.sendto(b"direct-udp", ("192.168.99.99", udp_port))
data, addr = u.recvfrom(65535)
print(f"UDP_GOT {data!r} from {addr}", flush=True)
assert data == b"UECHO:direct-udp", data
assert addr[0] == "192.168.99.99", addr
print("UDP_OK", flush=True)
print("SENDER_DIRECT_OK")
