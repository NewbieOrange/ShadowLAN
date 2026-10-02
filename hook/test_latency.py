#!/usr/bin/env python3
"""Wake latency + wait fidelity through relay and LD_PRELOAD hooks.

Tunnel arrivals land in hook queues on pump threads; an app blocked in
recv/recvfrom/poll/select must wake at once - never on a sleep slice -
and a tunneled stream must never make poll() return instantly (its real
fd is a never-connected socket the kernel reports as hung up).

1 tcp/block    blocking recv ping-pong: median < 5 ms (old: 10 ms sleep)
2 tcp/poll     settimeout (poll) ping-pong: median < 5 ms AND the waiting
               client stays off the CPU (old: busy-spin, 60-99% CPU)
3 udp/block    blocking recvfrom (SO_RCVTIMEO) ping-pong completes with
               median < 5 ms (old: blocked forever in the real recvfrom)
4 udp/poll     settimeout (poll) ping-pong: median < 5 ms (old: 25 ms)
5 udp/select   select() then recvfrom: median < 5 ms (old: 25 ms)
6 bigsend      ONE blocking send() of 1 MB (> the hook out-queue) returns
               1 MB and the peer gets every byte (kernel semantics)
7 bindrace     8 threads binding at once all finish (the ledger attach
               race once leaked its flock and hung every later bind)
"""
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testutil import free_port, relay_up  # noqa: E402

HOOK = "/root/my_vnet/hook/lan_hook.so"
_NODE0 = 100000 + (os.getpid() * 31 + sum(map(ord, os.path.basename(__file__)))) % 700000
A_VIP = "10.200.11.2"

PEER_A = r'''
import hashlib, socket, struct, threading, time

def conn(c):
    hdr = c.recv(1)
    if hdr == b"E":                      # echo 64-byte pings
        while True:
            d = b""
            while len(d) < 64:
                x = c.recv(64 - len(d))
                if not x:
                    return
                d += x
            c.sendall(d)
    elif hdr == b"B":                    # bulk: digest of N bytes
        n = struct.unpack("!I", c.recv(4, socket.MSG_WAITALL))[0]
        h = hashlib.sha256(); got = 0
        while got < n:
            x = c.recv(min(65536, n - got))
            if not x:
                break
            h.update(x); got += len(x)
        c.sendall(h.digest())

def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 47584)); s.listen(8)
    while True:
        c, _ = s.accept()
        threading.Thread(target=conn, args=(c,), daemon=True).start()

def udp():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 47585))
    while True:
        d, a = u.recvfrom(2048)
        u.sendto(d, a)

threading.Thread(target=tcp, daemon=True).start()
threading.Thread(target=udp, daemon=True).start()
time.sleep(0.3)
print("A_READY", flush=True)
time.sleep(60)
'''

PEER_B = r'''
import hashlib, os, select, socket, struct, sys, time
A = sys.argv[1]
N = 60

def med(v):
    v = sorted(v); return v[len(v) // 2] * 1e3

def connect(tag):
    for _ in range(50):
        try:
            s = socket.create_connection((A, 47584), timeout=3)
            s.sendall(tag)
            return s
        except OSError:
            time.sleep(0.2)
    print("CONNECT_FAIL", flush=True); sys.exit(1)

def tcp_ping(s, recv):
    out = []
    for i in range(N + 5):
        t = time.perf_counter()
        s.sendall(b"p" * 64)
        got = b""
        while len(got) < 64:
            got += recv(s, 64 - len(got))
        if i >= 5:
            out.append(time.perf_counter() - t)
    return out

s = connect(b"E"); s.settimeout(None)
print("RES tcp_block %.2f" % med(tcp_ping(s, lambda s, n: s.recv(n))), flush=True)

s = connect(b"E"); s.settimeout(5)
c0, w0 = sum(os.times()[:2]), time.time()
r = tcp_ping(s, lambda s, n: s.recv(n))
# idle wait: a poll that returns at once would burn this whole second
s.settimeout(1.0)
try:
    s.recv(1)
except socket.timeout:
    pass
cpu = (sum(os.times()[:2]) - c0) / (time.time() - w0)
print("RES tcp_poll %.2f cpu=%.2f" % (med(r), cpu), flush=True)

def udp_ping(u, recv):
    out = []
    for i in range(N + 5):
        t = time.perf_counter()
        u.sendto(struct.pack("!I", i) + b"u" * 60, (A, 47585))
        while struct.unpack("!I", recv(u)[:4])[0] != i:
            pass
        if i >= 5:
            out.append(time.perf_counter() - t)
    return out

def udp_sock():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 0))
    return u

def sel_recv(u):
    r, _, _ = select.select([u], [], [], 3)
    if not r:
        raise socket.timeout()
    return u.recvfrom(2048)[0]

u = udp_sock()
u.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 3, 0))
try:
    print("RES udp_block %.2f" % med(udp_ping(u, lambda u: u.recvfrom(2048)[0])), flush=True)
except OSError as e:
    print("RES udp_block FAIL %r" % e, flush=True)
u = udp_sock(); u.settimeout(3)
print("RES udp_poll %.2f" % med(udp_ping(u, lambda u: u.recvfrom(2048)[0])), flush=True)
u = udp_sock(); u.setblocking(False)
print("RES udp_select %.2f" % med(udp_ping(u, sel_recv)), flush=True)

blob = os.urandom(1 << 20)
s = connect(b"B" + struct.pack("!I", len(blob))); s.settimeout(None)
n = s.send(blob)                       # ONE blocking call
dig = b""
while len(dig) < 32:
    x = s.recv(32 - len(dig))
    if not x:
        break
    dig += x
print("RES bigsend sent=%d ok=%d" % (n, dig == hashlib.sha256(blob).digest()), flush=True)
'''

BINDRACE = r'''
import socket, threading, time
socks = []; done = []
def b(i):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 47600 + i)); socks.append(u); done.append(i)
ts = [threading.Thread(target=b, args=(i,)) for i in range(8)]
for t in ts: t.start()
for t in ts: t.join(8)
print("RES bindrace %d" % len(done), flush=True)
'''


def env(node, port):
    return dict(os.environ, LD_PRELOAD=HOOK, LAN_HOOK_SERVER="127.0.0.1",
                LAN_HOOK_PORT=str(port), LAN_HOOK_TOKEN="", LAN_HOOK_DEBUG="0",
                LAN_HOOK_LEASE_WAIT="3000", LAN_HOOK_NODE=str(node))


def main():
    port = free_port()
    relay = subprocess.Popen([sys.executable, "/root/my_vnet/server.py", "--port", str(port),
                              "--bind", "127.0.0.1", "--subnet", "10.200.11.0/24"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs = [relay]
    res = {}
    try:
        if not relay_up(port, proc=relay):
            raise RuntimeError("relay down")
        pa = subprocess.Popen([sys.executable, "-c", PEER_A], env=env(_NODE0 + 1, port),
                              stdout=subprocess.PIPE, text=True)
        procs.append(pa)
        assert pa.stdout.readline().startswith("A_READY")
        pb = subprocess.Popen([sys.executable, "-c", PEER_B, A_VIP], env=env(_NODE0 + 2, port),
                              stdout=subprocess.PIPE, text=True)
        pr = subprocess.Popen([sys.executable, "-c", BINDRACE], env=env(_NODE0 + 3, port),
                              stdout=subprocess.PIPE, text=True)
        procs += [pb, pr]
        outs = []
        for p in (pb, pr):
            try:
                outs.append(p.communicate(timeout=60)[0])
            except subprocess.TimeoutExpired:
                p.kill()
                outs.append(p.communicate()[0])
        for line in "".join(outs).splitlines():
            if line.startswith("RES "):
                k, _, v = line[4:].partition(" ")
                res[k] = v
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
            try:
                p.wait(timeout=3)
            except Exception:
                pass

    def ms(k):
        try:
            return float(res.get(k, "inf").split()[0])
        except ValueError:
            return float("inf")

    ok = True

    def check(name, cond, detail):
        nonlocal ok
        print(f"[{name}] {'OK' if cond else 'FAIL'} {detail}", flush=True)
        ok &= bool(cond)

    check("1 tcp/block", ms("tcp_block") < 5, res.get("tcp_block"))
    cpu = float(res.get("tcp_poll", "x cpu=9").split("cpu=")[-1])
    check("2 tcp/poll", ms("tcp_poll") < 5 and cpu < 0.35, res.get("tcp_poll"))
    check("3 udp/block", ms("udp_block") < 5, res.get("udp_block"))
    check("4 udp/poll", ms("udp_poll") < 5, res.get("udp_poll"))
    check("5 udp/select", ms("udp_select") < 5, res.get("udp_select"))
    check("6 bigsend", res.get("bigsend") == "sent=1048576 ok=1", res.get("bigsend"))
    check("7 bindrace", res.get("bindrace") == "8", res.get("bindrace"))
    print("LATENCY_ALL_PASS" if ok else "LATENCY FAIL", flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    t = threading.Timer(60, lambda: os._exit(2))
    t.daemon = True
    t.start()
    main()
