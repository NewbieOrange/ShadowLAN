#!/usr/bin/env python3
"""Helper run UNDER LD_PRELOAD hook. Sends to LAN IPs; hook must
rewrite to 127.0.0.1 (relay) and spoof getpeername/recvfrom back."""
import socket
import sys

udp_port = int(sys.argv[1])
tcp_port = int(sys.argv[2])

# 1) UDP unicast to fake LAN server -> should land on relay 127.0.0.1:udp_port
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"hook-udp-unicast", ("192.168.99.99", udp_port))
# 2) UDP broadcast -> also to relay
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.sendto(b"hook-udp-bcast", ("255.255.255.255", udp_port))
# recv spoof check: relay replies in order; FIFO must map back in order
s.settimeout(5)
try:
    data1, addr1 = s.recvfrom(65535)
    data2, addr2 = s.recvfrom(65535)
    print(f"UDP_REPLY1 {data1!r} from {addr1}")
    print(f"UDP_REPLY2 {data2!r} from {addr2}")
    assert data1 == b"reply:hook-udp-unicast" and addr1[0] == "192.168.99.99", (data1, addr1)
    assert data2 == b"reply:hook-udp-bcast" and addr2[0] == "255.255.255.255", (data2, addr2)
    print("UDP_SPOOF_OK")
except Exception as e:
    print(f"UDP_REPLY_FAIL {e}")
    sys.exit(1)

# 3) TCP connect to fake LAN -> should land on relay, getpeername spoofed
t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.settimeout(5)
t.connect(("192.168.99.99", tcp_port))
print("TCP_PEER", t.getpeername())
assert t.getpeername()[0] == "192.168.99.99", t.getpeername()
t.sendall(b"hook-tcp")
print("TCP_SPOOF_OK")
t.close()
print("SENDER_OK")
