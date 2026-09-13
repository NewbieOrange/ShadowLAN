#!/usr/bin/env python3
"""Same-box two-node join channels (LAN / Tailscale fidelity).

One OS hosting two of our nodes: the first node owns the real vport, the
second aliases BOTH protocols beneath it. Two real machines never share
a kernel port, so each vnode's own-address dial must hairpin onto THAT
vnode's listener, not the other node's (field: the joiner's self-dial
landed on the host, the tunneled peer socket was replaced, JoinLobby
timed out).

R6a  both nodes listen (owner owns real V; aliaser aliased)
R6b  forward open (owner -> aliased vport) bridges and echoes
R6c  reverse open (aliased -> owner vport) bridges and echoes
R6d  accept door presents the identity triple on the reverse channel
R6e  aliased node connect(own vnode:V) is accepted by the aliaser,
     never by the owner; accept peer stays loopback (not the opener vnode)
R6f  same self-dial while a hosted (bridged) row is live: still loopback
"""
import os, select, subprocess, sys, time

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
    print("OWNER-GOT %r" % (d,), flush=True)
    if d: c.sendall(b"ECHO:" + d)
    c.close()
'''

ALIASER = r'''
import socket, sys, time, threading
port = int(sys.argv[1])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("0.0.0.0", port))                    # aliased dgram row lands first
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", port)); s.listen(2)       # aliased stream row
print("ALIAS-LISTEN", flush=True)

held = []
def selfdial(tag, delay=0.8):
    time.sleep(delay)
    try:
        c = socket.create_connection(("10.200.15.3", port), timeout=8)
        c.sendall(tag)
        print(tag.decode() + "-GOT", c.recv(64).decode(errors="replace"), flush=True)
        c.close()
    except Exception as e:
        print(tag.decode() + "-ERR", e, flush=True)

threading.Thread(target=selfdial, args=(b"SELF",), daemon=True).start()
t0 = time.time()
while time.time() - t0 < 40:
    try:
        s.settimeout(3)
        c, _ = s.accept()
    except socket.timeout:
        continue
    except OSError:
        break
    gp = c.getpeername()
    d = c.recv(64)
    print("ALIAS-GOT %r peer=%s" % (d, gp[0]), flush=True)
    if d:
        c.sendall(b"ECHO:" + d)
    if d == b"HOLD":
        held.append(c)              # keep the hosted row alive
        threading.Thread(target=selfdial, args=(b"SELF2", 0.05), daemon=True).start()
        continue
    c.close()
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
    s.sendall(b"FWDQUERY")
    r = s.recv(16)
    print("FWD-OK %.1fs %r" % (time.time() - t0, r), flush=True)
except OSError as e:
    print("FWD-ERR %.1fs %s" % (time.time() - t0, e), flush=True)
'''

HOLD = r'''
import socket, sys, time
socket.setdefaulttimeout(15)
s = socket.create_connection(("10.200.15.3", int(sys.argv[1])))
s.sendall(b"HOLD")
print("HOLD-ECHO", s.recv(16).decode(errors="replace"), flush=True)
time.sleep(6)
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

def readline_wait(proc, timeout=8):
    r, _, _ = select.select([proc.stdout], [], [], timeout)
    if not r:
        return ""
    return proc.stdout.readline().strip()

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

# Same process that aliased the listen port dials its own vnode:V
# (GBE does this on every announce). Must not land on the owner.
a1 = readline_wait(alias, 8)
a2 = readline_wait(alias, 8)
self_blob = a1 + " " + a2
owner_steal = readline_wait(owner, 0.3)
check("R6e aliased-node self-dial hairpins onto its own listener (not the owner)",
      "ALIAS-GOT" in self_blob and "SELF" in self_blob
      and "peer=127.0.0.1" in self_blob
      and "OWNER-IDENT" not in owner_steal,
      "alias=%r owner=%r" % (self_blob[:80], owner_steal[:40]))

fwd = subprocess.run([sys.executable, "-c", FORWARD, str(V)],
                     env=env(RELAY, _NODE0 + 1), capture_output=True, text=True, timeout=45)
check("R6b forward channel bridges through the alias to the TCP listener",
      "FWD-OK" in fwd.stdout and "ECHO" in fwd.stdout,
      fwd.stdout.strip()[:80])
a_fwd = readline_wait(alias, 8)
check("R6b aliaser accepted the forward bridge",
      "FWDQUERY" in a_fwd, a_fwd[:80])

hold = subprocess.Popen([sys.executable, "-c", HOLD, str(V)],
                        env=env(RELAY, _NODE0 + 1),
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
h1 = readline_wait(hold, 8)
a_hold = readline_wait(alias, 8)
a_s2a = readline_wait(alias, 8)
a_s2b = readline_wait(alias, 8)
self2_blob = " ".join((a_hold, a_s2a, a_s2b))
self2_peer = next((l for l in (a_hold, a_s2a, a_s2b)
                   if "SELF2" in l and "ALIAS-GOT" in l), "")
check("R6f self-dial while a hosted row is live stays loopback (no opener steal)",
      "HOLD" in self2_blob and "SELF2" in self2_blob
      and "peer=127.0.0.1" in self2_peer,
      "hold=%r alias=%r" % (h1[:40], self2_blob[:100]))

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
hold.kill(); hold.wait()
rev.kill(); rev.wait()
relay.kill(); relay.wait()
print("ALIASBRIDGE_ALL_PASS" if ok else "ALIASBRIDGE FAIL")
sys.exit(0 if ok else 1)
