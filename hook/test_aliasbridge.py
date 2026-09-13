#!/usr/bin/env python3
"""Same-box two-node join channels (field regression, rc11/ab2 policy).

One OS hosting two of our nodes: the first node owns the real vport, the
second aliases BOTH protocols beneath it. The game's session library then
requires: (1) the joiner's forward stream must NOT bridge into the host
game (its state splits across two channels) - it must fail bounded;
(2) the host's own outbound dial must bridge and carry the full session.
Node .15.2 owns real V (no blocker needed); node .15.3 aliases dgram
then stream.

R6a  host node: both binds alias, listener alive, accepted-socket view
     never sees the forward query (bridge must fail)
R6b  forward open from the owner node to the aliased node errors within
     the ~10s claim budget (no hang, no corruption)
R6c  reverse open (aliased node -> owner node vport) bridges and
     echoes through the accept-door identity triple
"""
import os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from testutil import free_port, start_relay

HOOK = os.path.join(HERE, "lan_hook.so")
_NODE0 = 100000 + (os.getpid() * 31 + sum(map(ord, os.path.basename(__file__)))) % 700000

OWNER = r'''
import socket, sys, time
port = int(sys.argv[1])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("0.0.0.0", port))                    # owner: real port, no alias
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", port)); s.listen(2)
print("OWNER-LISTEN", flush=True)
t0 = time.time()
while time.time() - t0 < 40:
    try:
        s.settimeout(3)
        c, _ = s.accept()
    except socket.timeout:
        continue
    except OSError:
        break
    gp, gs = c.getpeername(), c.getsockname()
    print("OWNER-IDENT %s %d %s %d" % (gp[0], gp[1], gs[0], gs[1]), flush=True)
    d = c.recv(64)
    if d: c.sendall(b"ECHO:" + d)
    c.close()
'''

ALIASER = r'''
import socket, sys, time
port = int(sys.argv[1])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("0.0.0.0", port))                    # aliased dgram row lands first
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", port)); s.listen(2)       # aliased stream row
print("ALIAS-LISTEN", flush=True)
time.sleep(35)                                # forward attempts fail here
'''

REVERSE = r'''
import socket, sys
socket.setdefaulttimeout(25)
s = socket.create_connection(("10.200.15.2", int(sys.argv[1])))
s.sendall(b"HELLO")
print("GOT", s.recv(64).decode(errors="replace"), flush=True)
'''

FORWARD = r'''
import socket, sys, time
socket.setdefaulttimeout(20)
t0 = time.time()
try:
    s = socket.create_connection(("10.200.15.3", int(sys.argv[1])))
    s.sendall(b"X")
    r = s.recv(8)          # field-validated shape: open accepted, then
    print("FWD-EOF %.1fs %r" % (time.time() - t0, r), flush=True)  # clean EOF, no data
except OSError as e:
    print("FWD-ERR %.1fs %s" % (time.time() - t0, e), flush=True)
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
relay, RELAY = start_relay(lambda p: [sys.executable, os.path.join(ROOT, "server.py"),
                                      "--port", str(p), "--bind", "127.0.0.1",
                                      "--subnet", "10.200.15.0/24"])
time.sleep(0.3)
owner = subprocess.Popen([sys.executable, "-c", OWNER, str(V)],
                         env=env(RELAY, _NODE0 + 1),
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
check("R6a1 owner node owns real vport",
      owner.stdout.readline().strip() == "OWNER-LISTEN")
alias = subprocess.Popen([sys.executable, "-c", ALIASER, str(V)],
                         env=env(RELAY, _NODE0 + 2),
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
check("R6a2 alias node listener up (both rows aliased)",
      alias.stdout.readline().strip() == "ALIAS-LISTEN")

fwd = subprocess.run([sys.executable, "-c", FORWARD, str(V)],
                     env=env(RELAY, _NODE0 + 1), capture_output=True, text=True, timeout=45)
m = re.search(r"FWD-(EOF|ERR) (\d+\.\d+)", fwd.stdout)
check("R6b forward channel delivers no session data, bounded (no split state, no hang)",
      m is not None and float(m.group(2)) < 15.0,
      fwd.stdout.strip()[:80])

rev = subprocess.Popen([sys.executable, "-c", REVERSE, str(V)],
                       env=env(RELAY, _NODE0 + 2),
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
got = rev.stdout.readline().strip()
check("R6c reverse (host-dialed) channel bridges and echoes",
      got == "GOT ECHO:HELLO", got[:80])
line = owner.stdout.readline().strip()
ident = {}
if line.startswith("OWNER-IDENT"):
    p = line.split()
    ident = dict(peer=p[1], self_ip=p[3], self_port=int(p[4]))
check("R6d accept door presents the identity triple on the working channel",
      ident.get("peer") == "10.200.15.3" and ident.get("self_ip") == "10.200.15.2"
      and ident.get("self_port") == V, str(ident))
time.sleep(0.2)
owner.kill(); owner.wait()
alias.kill(); alias.wait()
rev.kill(); rev.wait()
relay.kill(); relay.wait()
print("ALIASBRIDGE_ALL_PASS" if ok else "ALIASBRIDGE FAIL")
sys.exit(0 if ok else 1)
