#!/usr/bin/env python3
"""Peer-to-peer latency benchmark through relay + LD_PRELOAD hooks.

Not part of the suite (no ALL_PASS marker); run by hand:

  python3 hook/bench_latency.py                 # idle, loopback relay
  python3 hook/bench_latency.py --shaped        # 3-netns WAN topology
  python3 hook/bench_latency.py --shaped --udp-over-tcp

Idle scenarios (both peers hooked, relay between them):
  tcp/<mode>   64 B ping-pong on one tunneled TCP stream
  udp/<mode>   64 B ping-pong on tunneled UDP (vnode-addressed P2P)
  <mode> = block (plain blocking recv), timeout (settimeout -> poll),
           select (select() then nonblocking recv)

Shaped scenarios (root ns = peer B, netns slR = relay, netns slA = peer A;
every link netem RATE + DELAY one-way + LIMIT packets queue):
  bulk_same   B streams bulk records to A and, on the SAME stream, a ping
              record every 50 ms; A echoes pings on the idle reverse
              direction. Ping RTT = queueing the stream adds in front of
              new data (app-visible bufferbloat).
  bulk_cross  bulk stream as above + UDP pings on the side.
  udp_flood   B floods UDP to a sink on A above link rate while pinging
              (most telling with --udp-over-tcp: datagrams queue in TCP).
"""
import argparse
import os
import statistics
import subprocess
import sys
import threading
import time

HOOKDIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HOOKDIR)
sys.path.insert(0, ROOT)
from testutil import free_port, relay_up  # noqa: E402

HOOK = os.environ.get("BENCH_HOOK", os.path.join(HOOKDIR, "lan_hook.so"))
SERVER = os.environ.get("BENCH_SERVER", os.path.join(ROOT, "server.py"))
SUBNET = "10.200.9.0/24"
A_VIP = "10.200.9.2"

PEER_A = r'''
import select, socket, struct, sys, threading, time
mode = sys.argv[1]
REC = struct.Struct("!BI")

def rx(s, n):
    if mode == "select":
        r, _, _ = select.select([s], [], [], 30)
        if not r:
            return b""
        try:
            return s.recv(n)
        except BlockingIOError:
            return None
    return s.recv(n)

def prep(s):
    if mode == "timeout":
        s.settimeout(30)
    elif mode == "select":
        s.setblocking(False)

def sendall(s, b):
    if mode != "select":
        s.sendall(b); return
    v = memoryview(b)
    while v:
        try:
            v = v[s.send(v):]
        except BlockingIOError:
            select.select([], [s], [], 5)

def tcp_conn(c):
    prep(c)
    buf = bytearray(); bulk = 0; t0 = None
    while True:
        d = rx(c, 262144)
        if d is None:
            continue
        if not d:
            break
        buf += d
        while len(buf) >= 5:
            t, ln = REC.unpack_from(buf)
            if len(buf) < 5 + ln:
                break
            if t == 1:
                sendall(c, bytes(buf[:5 + ln]))
            else:
                if t0 is None:
                    t0 = time.time()
                bulk += ln
            del buf[:5 + ln]
    if bulk:
        print("A_BULK %d %.3f" % (bulk, time.time() - t0), flush=True)
    c.close()

def tcp_srv():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 47584)); s.listen(8)
    while True:
        c, _ = s.accept()
        threading.Thread(target=tcp_conn, args=(c,), daemon=True).start()

def udp_echo():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 47585)); prep(u)
    while True:
        if mode == "select":
            select.select([u], [], [], 30)
            try:
                d, a = u.recvfrom(2048)
            except BlockingIOError:
                continue
        else:
            try:
                d, a = u.recvfrom(2048)
            except socket.timeout:
                continue
        u.sendto(d, a)

def udp_sink():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 47586))
    n = 0
    while True:
        d, a = u.recvfrom(4096)
        n += 1

# staggered: the pre-fix ledger deadlocked on concurrent first binds
for f in (tcp_srv, udp_echo, udp_sink):
    threading.Thread(target=f, daemon=True).start()
    time.sleep(0.15)
print("A_READY", flush=True)
time.sleep(600)
'''

PEER_B = r'''
import os, select, socket, struct, sys, threading, time
mode, scen, n, dur = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
flood_mbit = float(sys.argv[5])
A = sys.argv[6]
REC = struct.Struct("!BI")
PING = struct.Struct("!Qd")

def prep(s):
    if mode == "timeout":
        s.settimeout(10)
    elif mode == "select":
        s.setblocking(False)
    else:
        s.settimeout(None)

CPU0 = sum(os.times()[:2]); WALL0 = time.time()

def rx(s, n):
    if mode == "select":
        r, _, _ = select.select([s], [], [], 10)
        if not r:
            raise socket.timeout()
        try:
            return s.recv(n)
        except BlockingIOError:
            return None
    return s.recv(n)

def sendall(s, b):
    if mode != "select":
        s.sendall(b); return
    v = memoryview(b)
    while v:
        try:
            v = v[s.send(v):]
        except BlockingIOError:
            select.select([], [s], [], 5)

def connect():
    for _ in range(100):
        try:
            return socket.create_connection((A, 47584), timeout=3)
        except OSError:
            time.sleep(0.2)
    print("B_CONNECT_FAIL", flush=True); sys.exit(1)

def report(tag, rtts, lost=0):
    if not rtts:
        print("RES %s none lost=%d" % (tag, lost), flush=True); return
    rtts = sorted(rtts)
    q = lambda p: rtts[min(len(rtts) - 1, int(p * len(rtts)))]
    cpu = (sum(os.times()[:2]) - CPU0) / max(time.time() - WALL0, 1e-3)
    print("RES %s n=%d p50=%.2f p90=%.2f p99=%.2f max=%.2f lost=%d cpuB=%.0f%%" % (
        tag, len(rtts), q(.5) * 1e3, q(.9) * 1e3, q(.99) * 1e3, rtts[-1] * 1e3, lost,
        cpu * 100), flush=True)

def tcp_pingpong():
    s = connect(); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    prep(s); rtts = []
    for i in range(n + 20):
        msg = REC.pack(1, 59) + b"p" * 59
        t = time.perf_counter()
        sendall(s, msg)
        got = b""
        while len(got) < len(msg):
            d = rx(s, 4096)
            if d is None:
                continue
            if not d:
                raise SystemExit("eof")
            got += d
        if i >= 20:
            rtts.append(time.perf_counter() - t)
    report("tcp/" + mode, rtts)

def udp_sock():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 0)); prep(u)
    return u

def udp_recv(u):
    if mode == "select":
        r, _, _ = select.select([u], [], [], 2)
        if not r:
            raise socket.timeout()
        return u.recvfrom(2048)[0]
    return u.recvfrom(2048)[0]

def udp_pingpong():
    u = udp_sock()
    if mode == "block":
        # kernel-level receive timeout keeps the plain blocking recvfrom
        # path (settimeout would switch CPython to poll)
        u.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 1, 0))
    rtts = []; lost = 0
    # warm the flow (first datagram may race the relay's flow learning)
    for _ in range(20):
        u.sendto(PING.pack(0, 0.0), (A, 47585))
        try:
            udp_recv(u); break
        except OSError:
            pass
    for i in range(1, n + 1):
        t = time.perf_counter()
        u.sendto(PING.pack(i, t) + b"u" * 48, (A, 47585))
        try:
            while True:
                d = udp_recv(u)
                seq, _ = PING.unpack_from(d)
                if seq == i:
                    rtts.append(time.perf_counter() - t)
                    break
        except OSError:
            lost += 1
    report("udp/" + mode, rtts, lost)

def bulk_stream(s, stop, pings):
    """single writer: bulk records + a ping record every 50 ms"""
    blob = REC.pack(0, 16384) + b"b" * 16384
    seq = 0; nxt = time.perf_counter()
    while not stop.is_set():
        now = time.perf_counter()
        if pings is not None and now >= nxt:
            seq += 1
            pings[seq] = now
            sendall(s, REC.pack(1, 16) + PING.pack(seq, now))
            nxt = now + 0.05
        sendall(s, blob)

def wait_eof(s):
    """after SHUT_WR: A closes once it consumed everything we queued"""
    s.settimeout(60)
    try:
        while s.recv(65536):
            pass
    except OSError:
        pass

def ping_reader(s, pings, rtts, stop):
    buf = bytearray()
    while True:
        try:
            d = rx(s, 65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if d is None:
            continue
        if not d:
            break
        buf += d
        while len(buf) >= 5 + 16:
            t, ln = REC.unpack_from(buf)
            seq, ts = PING.unpack_from(buf, 5)
            del buf[:5 + ln]
            rtts.append(time.perf_counter() - ts)

def udp_side_pinger(stop, out):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 0)); u.settimeout(3.0)
    rtts = []; lost = 0; i = 0
    while not stop.is_set():
        i += 1
        t = time.perf_counter()
        u.sendto(PING.pack(i, t) + b"u" * 48, (A, 47585))
        while True:
            try:
                d = u.recvfrom(2048)[0]
            except socket.timeout:
                lost += 1; break
            seq, ts = PING.unpack_from(d)
            if seq == i:
                rtts.append(time.perf_counter() - t); break
        time.sleep(0.02)
    out.append((rtts, lost))

def flood(stop):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", 0))
    pkt = b"f" * 1200
    per = 1200 * 8 / (flood_mbit * 1e6)
    t = time.perf_counter()
    while not stop.is_set():
        u.sendto(pkt, (A, 47586))
        t += per
        d = t - time.perf_counter()
        if d > 0:
            time.sleep(d)

if scen == "tcp":
    tcp_pingpong()
elif scen == "udp":
    udp_pingpong()
elif scen == "bulk":
    s = connect()
    stop = threading.Event()
    th = threading.Thread(target=bulk_stream, args=(s, stop, None), daemon=True)
    th.start()
    time.sleep(dur); stop.set(); th.join(30)
    s.shutdown(socket.SHUT_WR)
    wait_eof(s)
    print("RES bulk/throughput", flush=True)
elif scen in ("bulk_same", "bulk_cross"):
    s = connect(); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    prep(s)
    stop = threading.Event(); rtts = []; pings = {}; side = []
    same = scen == "bulk_same"
    th = [threading.Thread(target=bulk_stream, args=(s, stop, pings if same else None), daemon=True)]
    if same:
        th.append(threading.Thread(target=ping_reader, args=(s, pings, rtts, stop), daemon=True))
    else:
        th.append(threading.Thread(target=udp_side_pinger, args=(stop, side), daemon=True))
    for t in th: t.start()
    time.sleep(dur); stop.set()
    th[0].join(30)
    s.shutdown(socket.SHUT_WR)
    if same:
        th[1].join(60)
        sent = len(pings)
        report("bulk_same/tcp-ping", rtts[3:], lost=sent - len(rtts))
    else:
        th[1].join(5)
        wait_eof(s)
        report("bulk_cross/udp-ping", side[0][0][3:] if side else [], side[0][1] if side else -1)
elif scen == "udp_flood":
    stop = threading.Event(); side = []
    th = [threading.Thread(target=flood, args=(stop,), daemon=True),
          threading.Thread(target=udp_side_pinger, args=(stop, side), daemon=True)]
    for t in th: t.start()
    time.sleep(dur); stop.set(); time.sleep(1.5)
    report("udp_flood/udp-ping", side[0][0][3:] if side else [], side[0][1] if side else -1)
'''


def sh(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Topo:
    """root ns (peer B) <-> slR (relay) <-> slA (peer A), netem both ways
    on every link."""

    def __init__(self, rate, delay, limit):
        self.q = "netem delay %s rate %s limit %d" % (delay, rate, limit)

    def up(self):
        self.down()
        cmds = [
            "ip netns add slR", "ip netns add slA",
            "ip link add slb0 type veth peer name slb1",
            "ip link set slb1 netns slR",
            "ip link add sla0 type veth peer name sla1",
            "ip link set sla0 netns slR", "ip link set sla1 netns slA",
            "ip addr add 10.78.1.1/24 dev slb0", "ip link set slb0 up",
            "ip netns exec slR ip addr add 10.78.1.2/24 dev slb1",
            "ip netns exec slR ip addr add 10.78.2.2/24 dev sla0",
            "ip netns exec slR ip link set slb1 up",
            "ip netns exec slR ip link set sla0 up",
            "ip netns exec slR ip link set lo up",
            "ip netns exec slA ip addr add 10.78.2.1/24 dev sla1",
            "ip netns exec slA ip link set sla1 up",
            "ip netns exec slA ip link set lo up",
            "ip netns exec slA ip route add default via 10.78.2.2",
            # --baseline: plain kernel TCP/UDP B<->A over the SAME links
            "ip netns exec slR sysctl -qw net.ipv4.ip_forward=1",
            "ip route add 10.78.2.0/24 via 10.78.1.2",
            "tc qdisc add dev slb0 root " + self.q,
            "ip netns exec slR tc qdisc add dev slb1 root " + self.q,
            "ip netns exec slR tc qdisc add dev sla0 root " + self.q,
            "ip netns exec slA tc qdisc add dev sla1 root " + self.q,
        ]
        for c in cmds:
            sh(c)

    def down(self):
        sh("ip link del slb0", check=False)
        sh("ip netns del slR", check=False)
        sh("ip netns del slA", check=False)


def hook_env(node, server, port, udp_tcp, baseline=False):
    if baseline:
        e = dict(os.environ)
        e.pop("LD_PRELOAD", None)
        return e
    e = dict(os.environ, LD_PRELOAD=HOOK, LAN_HOOK_SERVER=server,
             LAN_HOOK_PORT=str(port), LAN_HOOK_TOKEN="", LAN_HOOK_DEBUG="0",
             LAN_HOOK_LEASE_WAIT="3000", LAN_HOOK_NODE=str(node))
    if udp_tcp:
        e["LAN_HOOK_UDP_OVER_TCP"] = "1"
    return e


def proc_cpu(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            v = f.read().rsplit(")", 1)[1].split()
        return (int(v[11]) + int(v[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return 0.0


def run_case(args, scen, mode, shaped):
    port = free_port()
    if shaped:
        relay_ip, relay_pre, a_pre = "10.78.1.2", ["ip", "netns", "exec", "slR"], \
            ["ip", "netns", "exec", "slA"]
        a_server = "10.78.2.2"
    else:
        relay_ip, relay_pre, a_pre, a_server = "127.0.0.1", [], [], "127.0.0.1"
    bl = args.baseline
    target = ("10.78.2.1" if shaped else "127.0.0.1") if bl else A_VIP
    procs = []
    if not bl:
        relay = subprocess.Popen(relay_pre + [sys.executable, SERVER,
                                              "--port", str(port), "--bind",
                                              "0.0.0.0" if shaped else "127.0.0.1",
                                              "--subnet", SUBNET],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(relay)
    try:
        if not bl and not shaped and not relay_up(port, proc=relay):
            raise RuntimeError("relay down")
        if not bl and shaped:
            import socket
            end = time.time() + 10
            while time.time() < end:
                try:
                    socket.create_connection((relay_ip, port), timeout=0.5).close()
                    break
                except OSError:
                    time.sleep(0.1)
        base = 300000 + (os.getpid() % 1000) * 100 + hash((scen, mode)) % 90
        pa = subprocess.Popen(a_pre + [sys.executable, "-c", PEER_A, mode],
                              env=hook_env(base + 1, a_server, port, args.udp_over_tcp, bl),
                              stdout=subprocess.PIPE, text=True)
        procs.append(pa)
        if not pa.stdout.readline().startswith("A_READY"):
            raise RuntimeError("peer A not ready")
        time.sleep(0.5)
        a_cpu0, a_t0 = proc_cpu(pa.pid), time.time()
        pb = subprocess.Popen([sys.executable, "-c", PEER_B, mode, scen, str(args.n),
                               str(args.dur), str(args.flood_mbit), target],
                              env=hook_env(base + 2, relay_ip, port, args.udp_over_tcp, bl),
                              stdout=subprocess.PIPE, text=True)
        procs.append(pb)
        try:
            out, _ = pb.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            out = "RES %s/%s TIMEOUT" % (scen, mode)
        res = [l for l in out.splitlines() if l.startswith("RES")]
        a_cpu = (proc_cpu(pa.pid) - a_cpu0) / max(time.time() - a_t0, 1e-3)
        res = [l + " cpuA=%.0f%%" % (a_cpu * 100) for l in res]
        pa.terminate()
        try:
            aout, _ = pa.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            aout = ""
        bulk = [l for l in aout.splitlines() if l.startswith("A_BULK")]
        for l in res:
            extra = ""
            if bulk:
                b, t = bulk[0].split()[1:]
                extra = " thr=%.1fMbit" % (int(b) * 8 / max(float(t), 1e-3) / 1e6)
            print(l[4:] + extra, flush=True)
        if not res:
            print("%s/%s: NO RESULT %r" % (scen, mode, out[-300:]), flush=True)
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
            try:
                p.wait(timeout=3)
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shaped", action="store_true")
    ap.add_argument("--udp-over-tcp", action="store_true")
    ap.add_argument("--baseline", action="store_true",
                    help="no hooks/relay: plain kernel sockets over the same path")
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--dur", type=float, default=8.0)
    ap.add_argument("--rate", default="20mbit")
    ap.add_argument("--delay", default="10ms")
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--flood-mbit", type=float, default=30.0)
    ap.add_argument("--only", default="")
    ap.add_argument("--modes", default="block,timeout,select")
    args = ap.parse_args()
    modes = args.modes.split(",")
    topo = None
    try:
        if args.shaped:
            topo = Topo(args.rate, args.delay, args.limit)
            topo.up()
            cases = [("tcp", m) for m in modes] + [("udp", m) for m in modes] + \
                [("bulk", "block"), ("bulk_same", "block"), ("bulk_cross", "block"),
                 ("udp_flood", "block")]
        else:
            cases = [("tcp", m) for m in modes] + [("udp", m) for m in modes] + \
                [("bulk", "block"), ("bulk_same", "block")]
        for scen, mode in cases:
            if args.only and not any(o in scen for o in args.only.split(",")):
                continue
            run_case(args, scen, mode, args.shaped)
    finally:
        if topo:
            topo.down()


if __name__ == "__main__":
    main()
