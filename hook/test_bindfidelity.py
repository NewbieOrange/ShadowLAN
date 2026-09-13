#!/usr/bin/env python3
"""bind()/getsockname() emulation fidelity (LAN_ONLY both ways).

Rules under test (emulated machine = one NODE = one process tree):
  R1 LAN_ONLY=0, same node:  a TCP port already served by a sibling
     process must collide (EADDRINUSE) - the alias path may NOT treat
     two processes of ONE machine as two machines.
  R2 LAN_ONLY=0, other node: the same port binds fine (real machines
     never see each other's EADDRINUSE) - aliased underneath,
     getsockname still presents the requested port.
  R3 UDP SO_REUSEADDR sharing: same node -> both binders get the port
     (shared dgram semantics); non-reuse dgram against a holder -> fail.
  R4 vnode bind: getsockname presents (vnode, port), never 0.0.0.0.
  R5 LAN_ONLY=1, bind(0): the port comes from the node's ephemeral
     space (>=49152) and getsockname shows it; two binders, two ports.
"""
import os, re, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testutil import free_port

_NODE0 = 100000 + (os.getpid() * 31 + sum(map(ord, os.path.basename(__file__)))) % 700000
HOOK = "/root/my_vnet/hook/lan_hook.so"

CHILD = r'''
import socket, sys, errno
act, ip, port = sys.argv[1], sys.argv[2], sys.argv[3]
reuse = len(sys.argv) > 4 and sys.argv[4] == "reuse"
kind = socket.SOCK_STREAM if "tcp" in act else socket.SOCK_DGRAM
s = socket.socket(socket.AF_INET, kind)
if reuse:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
p = 0 if port == "0" else int(port)
try:
    s.bind(("0.0.0.0" if ip == "any" else ip, p))
except OSError as e:
    print("ERRNO %d" % e.errno, flush=True)
    sys.exit(0)
if "tcp" in act:
    s.listen(2)
a = s.getsockname()
if act == "udplisten":      # join the shared group to prove coexistence
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                     bytes.fromhex("e00000fb00000000"))
    except OSError:
        pass
print("BOUND %s:%d" % (a[0], a[1]), flush=True)
import time
time.sleep(float(sys.argv[-1]) if sys.argv[-1].isdigit() else 8)
'''

def spawn(relay_port, node, act, ip, port, reuse=False, lan_only=0, timeout=90):
    env = dict(os.environ, LD_PRELOAD=HOOK,
               LAN_HOOK_SERVER="127.0.0.1", LAN_HOOK_PORT=str(relay_port),
               LAN_HOOK_TOKEN="", LAN_HOOK_DEBUG="0", LAN_HOOK_LEASE_WAIT="25",
               LAN_HOOK_NODE=str(node),
               LAN_HOOK_LAN_ONLY=str(lan_only))
    args = [sys.executable, "-c", CHILD, act, ip, port]
    if reuse:
        args.append("reuse")
    args.append("12")
    p = subprocess.Popen(args, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True)
    return p

def readline(p):
    line = p.stdout.readline().strip()
    return line

ok = True

def check(name, cond, extra=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + ("  " + extra if extra else ""))
    ok = cond and ok

# ---- relay 1: LAN_ONLY=0 scenarios (fresh subnet, deterministic .2) ----
R1 = free_port()
relay1 = subprocess.Popen([sys.executable, "/root/my_vnet/server.py",
                           "--port", str(R1), "--bind", "127.0.0.1",
                           "--subnet", "10.200.12.0/24"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.0)
P = str(free_port())          # one node binds it for real; siblings collide

a1 = spawn(R1, _NODE0 + 1, "tcplist", "any", P)   # node X, first listener
l = readline(a1); check("R1a sibling#1 binds", l.startswith("BOUND"), l)
a2 = spawn(R1, _NODE0 + 1, "tcplist", "any", P)   # SAME node -> must collide
l2 = readline(a2); check("R1a same-node TCP dup -> EADDRINUSE",
                         l2 == "ERRNO %d" % 98, l2)
b1 = spawn(R1, _NODE0 + 2, "tcplist", "any", P)   # OTHER node -> alias ok
l3 = readline(b1)
check("R2 other-node dup binds + presents vport",
      l3 == "BOUND 0.0.0.0:%s" % P, l3)
# R3 UDP sharing on node X
c1 = spawn(R1, _NODE0 + 1, "dgram", "any", P, reuse=True)
l4 = readline(c1); check("R3a reuse dgram joins", l4.startswith("BOUND"), l4)
c2 = spawn(R1, _NODE0 + 1, "dgram", "any", P, reuse=False)
l5 = readline(c2); check("R3b non-reuse dgram dup -> EADDRINUSE",
                         l5 == "ERRNO %d" % 98, l5)
# R4 vnode bind presentation: node X is 10.200.12.2
VPORT = str(free_port())
d1 = spawn(R1, _NODE0 + 1, "tcplist", "10.200.12.2", VPORT)
l6 = readline(d1)
check("R4 vnode bind -> getsockname shows vnode",
      l6 == "BOUND 10.200.12.2:%s" % VPORT, l6)
for p_ in (a1, a2, b1, c1, c2, d1):
    p_.kill(); p_.wait(timeout=5)
relay1.kill(); relay1.wait(timeout=5)

# ---- relay 2: LAN_ONLY=1, bind(0) from the node's ephemeral space ----
R2 = free_port()
relay2 = subprocess.Popen([sys.executable, "/root/my_vnet/server.py",
                           "--port", str(R2), "--bind", "127.0.0.1",
                           "--subnet", "10.200.13.0/24"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.0)
e1 = spawn(R2, _NODE0 + 3, "dgram", "any", "0", lan_only=1)
e2 = spawn(R2, _NODE0 + 3, "dgram", "any", "0", lan_only=1)
m1, m2 = readline(e1), readline(e2)
def port_of(l_):
    m = re.search(r":(\d+)$", l_)
    return int(m.group(1)) if m else 0
q1, q2 = port_of(m1), port_of(m2)
check("R5 LAN_ONLY bind(0): ephemeral-space, distinct",
      q1 >= 49152 and q2 >= 49152 and q1 != q2, "%s | %s" % (m1, m2))
for p_ in (e1, e2):
    p_.kill(); p_.wait(timeout=5)
relay2.kill(); relay2.wait(timeout=5)

print("BINDFIDELITY_ALL_PASS" if ok else "BINDFIDELITY FAIL")
sys.exit(0 if ok else 1)
