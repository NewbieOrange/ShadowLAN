#!/usr/bin/env python3
"""Exit-drain test: a hooked client sends 200KB and calls exit(0)
IMMEDIATELY (no sleep). On a real LAN the kernel flushes the socket;
the listener must receive every byte before EOF. Pre-fix, the hook's
userspace out-queue died with the process and the tail was lost."""
import os, subprocess, sys, threading, time
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from testutil import free_port as _free_port, tmp_path as _tmp_path
PUB = _free_port()
_NODE0 = 100000 + (os.getpid() * 31 + sum(map(ord, os.path.basename(__file__)))) % 700000
HOOK = "/root/my_vnet/hook/lan_hook.so"
N = 200000

server_py = r'''
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 47584)); s.listen(2)
print("LISTENING", flush=True)
t0 = time.time(); c = None
while c is None and time.time() - t0 < 20:
    s.settimeout(0.5)
    try: c, a = s.accept()
    except socket.timeout: pass
c.settimeout(15)
total = 0
try:
    while True:
        d = c.recv(65536)
        if not d: break
        total += len(d)
except Exception as e:
    print("ERR", e, flush=True)
print("TOTAL_RX", total, flush=True)
time.sleep(1)
'''

client_py = r'''
import socket, sys, os, time
for a in range(40):
    try:
        s = socket.create_connection(("10.200.0.2", 47584), timeout=2); break
    except OSError: time.sleep(0.4)
blob = b"X" * int(sys.argv[1])
s.sendall(blob)          # goes into the hook out-queue
os._exit(0)              # die RIGHT NOW: only a flushed exit can deliver
'''

relay = subprocess.Popen([sys.executable, "/root/my_vnet/server.py",
                          "--port", str(PUB), "--bind", "127.0.0.1",
                          "--subnet", "10.200.8.0/24"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.7)

def env(node):
    return dict(os.environ, LD_PRELOAD=HOOK,
                LAN_HOOK_SERVER="127.0.0.1", LAN_HOOK_PORT=str(PUB),
                LAN_HOOK_TOKEN="", LAN_HOOK_DEBUG="1",
                LAN_HOOK_LEASE_WAIT="25", LAN_HOOK_NODE=str(node))

results = []
for trial in range(5):
    pa = subprocess.Popen([sys.executable, "-c", server_py], env=env(_NODE0 + 1),
                          stdout=subprocess.PIPE, text=True)
    assert pa.stdout.readline().startswith("LISTENING")
    time.sleep(0.4)
    pb = subprocess.Popen([sys.executable, "-c", client_py, str(N)],
                          env=env(_NODE0 + 2), stdout=subprocess.DEVNULL)
    got = None
    t0 = time.time()
    while time.time() - t0 < 25:
        l = pa.stdout.readline()
        if not l: break
        if l.startswith("TOTAL_RX"):
            got = int(l.split()[1]); break
    pb.wait(timeout=5)
    pa.kill()
    pa.wait()          # REAP: the next trial's ledger takeover needs
                       # the holder gone, not merely signalled
    results.append(got)
    print(f"trial {trial}: server got {got}/{N}", flush=True)
relay.kill()
print("\n", "EXITDRAIN_ALL_PASS" if all(r == N for r in results) else "FAIL")
