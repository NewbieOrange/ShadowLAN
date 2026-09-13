#!/usr/bin/env python3
"""Same-box hosted-bridge across aliased ports (field regression).

Topology that broke lobby joins on a single Windows box running BOTH
game nodes: with the REAL port already owned by another node's process,
the host game's binds all alias ephemerally - and it registers the UDP
announce socket BEFORE the TCP listener on the SAME vport. The stream
bridge must reverse-map the vport to the TCP row's real port; reading
the first row by vport dialed the UDP ephemeral (connection refused
until the 10s budget died => relay reason=3, no session, no gbe log).

R6: node A (host) binds dgram V, then stream V + listen + echo (both
    force-aliased by a plain non-node socket holding real V);
    node B (client) opens the tunnel stream to A's vnode:V and must
    get its payload echoed back.
"""
import os, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from testutil import free_port, start_relay

HOOK = os.path.join(HERE, "lan_hook.so")
_NODE0 = 100000 + (os.getpid() * 31 + sum(map(ord, os.path.basename(__file__)))) % 700000

HOST = r'''
import socket, sys, time
port = int(sys.argv[1])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("0.0.0.0", port))            # dgram row lands in the table FIRST
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", port))            # same vport, stream -> own alias row
s.listen(2)
print("HOST-LISTEN", flush=True)
t0 = time.time()
while time.time() - t0 < 25:
    try:
        s.settimeout(5)
        c, _ = s.accept()
        gp = c.getpeername()
        gs = c.getsockname()
        print("HOST-IDENT %s %s %s %s" % (gp[0], gp[1], gs[0], gs[1]), flush=True)
        d = c.recv(64)
        if d:
            c.sendall(b"ECHO:" + d)
        c.close()
    except socket.timeout:
        pass
'''

def env(port, node):
    return dict(os.environ, LD_PRELOAD=HOOK,
                LAN_HOOK_SERVER="127.0.0.1", LAN_HOOK_PORT=str(port),
                LAN_HOOK_TOKEN="", LAN_HOOK_DEBUG="0",
                LAN_HOOK_NODE=str(node), LAN_HOOK_LEASE_WAIT="25")

ok = True
def check(name, cond, extra=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + (("  " + extra) if extra else ""))
    ok = cond and ok

V = free_port()

# real V held by a NON-node process so both hooked binds must alias
blocker = socket.socket()
blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
try:
    blocker.bind(("0.0.0.0", V)); blocker.listen(1)
except OSError as e:
    print("setup: could not occupy", V, e); sys.exit(1)

relay, RELAY = start_relay(lambda p: [sys.executable, os.path.join(ROOT, "server.py"),
                                      "--port", str(p), "--bind", "127.0.0.1",
                                      "--subnet", "10.200.15.0/24"])
time.sleep(0.3)
host = subprocess.Popen([sys.executable, "-c", HOST, str(V)],
                        env=env(RELAY, _NODE0 + 1),
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
check("R6a host up (both vport binds aliased)",
      host.stdout.readline().strip() == "HOST-LISTEN")
CLI = r'''
import socket, sys
socket.setdefaulttimeout(25)
s = socket.create_connection(("10.200.15.2", int(sys.argv[1])))
s.sendall(b"HELLO")
print("GOT", s.recv(64).decode(), flush=True)
'''
cli = subprocess.Popen([sys.executable, "-c", CLI, str(V)], env=env(RELAY, _NODE0 + 2),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
ident = {}
for _ in range(8):
    line = host.stdout.readline()
    if not line: break
    if line.startswith("HOST-IDENT"):
        p = line.split()
        ident = dict(peer=p[1], pport=int(p[2]), self_ip=p[3], self_port=int(p[4]))
        break
cout = ""
try:
    cout = cli.stdout.read().strip()
except Exception:
    pass
cli.wait(timeout=10)
check("R6b accepted socket presents the LAN view (local vport, not alias real)",
      ident.get("self_port") == V and ident.get("self_ip") == "10.200.15.2"
      and ident.get("peer") == "10.200.15.3", str(ident))
check("R6c tunnel stream bridged to the TCP alias row (not the UDP row)",
      "GOT ECHO:HELLO" in cout, cout[-80:])

host.kill(); host.wait()
relay.kill(); relay.wait()
blocker.close()
print("ALIASBRIDGE_ALL_PASS" if ok else "ALIASBRIDGE FAIL")
sys.exit(0 if ok else 1)
