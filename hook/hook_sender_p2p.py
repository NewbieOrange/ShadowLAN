#!/usr/bin/env python3
"""Hooked P2P mesh player. Runs UNDER LD_PRELOAD hook with LAN_HOOK_SERVER.
Learns TWO hosts' virtual IPs from their beacons, then plays TCP+UDP with
both over explicitly addressed (POPEN/PDATA) streams. One host claiming
after the other demotes it - reconnects must survive that.
Usage: hook_sender_p2p.py DISC A_TCP A_UDP C_TCP C_UDP A_BEACON C_BEACON
"""
import socket
import sys
import time


def is_virt(ip):
    return ip.startswith("10.200.")


(disc, a_tcp, a_udp, c_tcp, c_udp) = (int(sys.argv[1]), int(sys.argv[2]),
                                      int(sys.argv[3]), int(sys.argv[4]),
                                      int(sys.argv[5]))
want_a, want_c = sys.argv[6].encode(), sys.argv[7].encode()

d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
d.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    d.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
except OSError:
    pass
d.bind(("0.0.0.0", disc))
d.settimeout(10)
found = {}
t0 = time.time()
while time.time() - t0 < 12 and len(found) < 2:
    try:
        data, addr = d.recvfrom(65535)
    except socket.timeout:
        break
    if data in (want_a, want_c) and is_virt(addr[0]) and data not in found:
        found[data] = addr[0]
        print(f"DISC {data!r} from {addr[0]}", flush=True)
if want_a not in found or want_c not in found:
    print(f"DISC_FAIL: {found}", flush=True)
    sys.exit(1)
a_virt, c_virt = found[want_a], found[want_c]
assert a_virt != c_virt, (a_virt, c_virt)
print(f"VIRTS distinct: A={a_virt} C={c_virt}", flush=True)


def play_tcp(virt, port, tag):
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.settimeout(8)
    for attempt in range(4):
        try:
            t.connect((virt, port))
            break
        except OSError as e:
            print(f"{tag} tcp try {attempt}: {e}", flush=True)
            time.sleep(0.7)
    else:
        print(f"{tag} TCP_FAIL", flush=True)
        sys.exit(1)
    peer = t.getpeername()
    assert peer == (virt, port), (tag, peer)
    t.sendall(b"mesh-tcp")
    got = b""
    while len(got) < len(b"ECHO:mesh-tcp"):
        chunk = t.recv(65536)
        if not chunk:
            break
        got += chunk
    assert got == b"ECHO:mesh-tcp", (tag, got)
    print(f"{tag} TCP_OK via {virt}", flush=True)
    t.close()


def play_udp(virt, port, tag):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(8)
    u.sendto(b"mesh-udp", (virt, port))
    data, addr = u.recvfrom(65535)
    assert data == b"UECHO:mesh-udp", (tag, data)
    assert addr[0] == virt, (tag, addr)
    print(f"{tag} UDP_OK via {virt}", flush=True)
    u.close()


play_tcp(a_virt, a_tcp, "A")
play_udp(a_virt, a_udp, "A")
play_tcp(c_virt, c_tcp, "C")
play_udp(c_virt, c_udp, "C")
print("SENDER_P2P_OK")
