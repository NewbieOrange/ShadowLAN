#!/usr/bin/env python3
"""Hooked game-host simulator. Runs UNDER LD_PRELOAD hook with
LAN_HOOK_SERVER set. Behaves like a real LAN game server:

- TCP listen + accept/echo  (the listen() call auto-claims designated-host)
- UDP bind + echo
- periodic broadcast beacons (payload given on CLI)

Inbound relay traffic is bridged by the hook itself via loopback dial,
so no wclient.py is involved on this side.
Usage: hook_sender_host.py TCP UDP DISC BEACON RUNTIME_SECS
"""
import socket
import sys
import threading
import time

tcp_port, udp_port, disc_port = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
beacon, runtime = sys.argv[4].encode(), float(sys.argv[5])
deadline = time.time() + runtime

ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ts.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ts.bind(("127.0.0.1", tcp_port))
ts.listen(5)
ts.settimeout(1.0)
print(f"HOST listen tcp {tcp_port}", flush=True)


def echo_conn(c):
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(b"ECHO:" + d)
    except OSError:
        pass
    finally:
        c.close()


def accept_loop():
    while time.time() < deadline:
        try:
            c, _ = ts.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=echo_conn, args=(c,), daemon=True).start()


us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
us.bind(("127.0.0.1", udp_port))
us.settimeout(1.0)


def udp_loop():
    while time.time() < deadline:
        try:
            d, a = us.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            us.sendto(b"UECHO:" + d, a)
        except OSError:
            break


threading.Thread(target=accept_loop, daemon=True).start()
threading.Thread(target=udp_loop, daemon=True).start()
bs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
bs.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# NOTE: real broadcast destination (what actual games use). The hook only
# tunnels LAN/broadcast/virt destinations; 127.0.0.1 would stay local.
while time.time() < deadline:
    try:
        bs.sendto(beacon, ("255.255.255.255", disc_port))
    except OSError:
        break
    time.sleep(0.3)
print("HOST_DONE", flush=True)
