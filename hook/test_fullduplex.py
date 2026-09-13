#!/usr/bin/env python3
"""Kernel-fidelity tests for tunnel TCP streams (full-duplex & close).

Scenario 1 stall independence: A sends 256 KB immediately and reads
  NOTHING for 2.5 s; B sends a 64 KB marker and reads to completion.
  B must finish BEFORE A starts reading (the stalled direction did not
  block the other), and A must later get B's marker byte-exact.
Scenario 2 close flush: B sends 200 KB then close()s without waiting;
  A must receive all 200 KB, then EOF - never a truncated stream.
Scenario 3 half-close: A shutdown(SHUT_WR)s after sending; B must read
  A's data, then 0, and A must still receive B's reply afterwards.
"""
import os, subprocess, sys, threading, time
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from testutil import free_port as _free_port, tmp_path as _tmp_path, relay_up as _relay_up
PUB = _free_port()
HOOK = "/root/my_vnet/hook/lan_hook.so"

SHELL_A = r'''
import socket, sys, time, threading
mode = sys.argv[1]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 47584)); s.listen(2)
print("LISTENING", flush=True)
t0 = time.time(); c = None
while c is None and time.time() - t0 < 90:
    s.settimeout(0.5)
    try: c, a = s.accept()
    except socket.timeout: pass
if mode == "stall":
    blob = b"A" * 262144
    off = 0
    while off < len(blob):
        off += c.send(blob[off:])
    print("A_SENT_DONE t=%.2f" % (time.time() - t0), flush=True)
    time.sleep(2.5)
    print("A_READS_START t=%.2f" % (time.time() - t0), flush=True)
    got = b""
    c.settimeout(60)
    while len(got) < 65536:
        d = c.recv(65536)
        if not d: break
        got += d
    print("A_MARKER_OK" if got == b"B" * 65536 else "A_MARKER_BAD %d" % len(got), flush=True)
elif mode == "closeflush":
    c.settimeout(60)
    got = 0
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            got += len(d)
    except socket.timeout:
        pass
    print("A_GOT", got, flush=True)
elif mode == "halfclose":
    c.sendall(b"Z" * 65536)
    c.shutdown(socket.SHUT_WR)
    print("A_SHUT_WR", flush=True)
    c.settimeout(60)
    back = b""
    try:
        while len(back) < 4096:
            d = c.recv(4096)
            if not d: break
            back += d
    except socket.timeout:
        pass
    print("A_BACK_OK" if back == b"R" * 4096 else "A_BACK_BAD %d" % len(back), flush=True)
time.sleep(1)
'''

SHELL_B = r'''
import socket, sys, time, threading
mode = sys.argv[1]
t0 = time.time()
for a in range(120):
    try:
        s = socket.create_connection(("10.200.7.2", 47584), timeout=2); break
    except OSError: time.sleep(0.4)
else:
    print("CONNECT_FAIL", flush=True); sys.exit(1)
if mode == "stall":
    threading.Timer(0.2, lambda: s.sendall(b"B" * 65536)).start()
    total = 0
    s.settimeout(60)
    while total < 262144:
        d = s.recv(65536)
        if not d: break
        total += len(d)
    print("B_RX_DONE t=%.2f total=%d" % (time.time() - t0, total), flush=True)
elif mode == "closeflush":
    s.sendall(b"X" * 200000)
    s.close()                       # kernel must flush, then FIN
    print("B_CLOSED", flush=True)
elif mode == "halfclose":
    s.settimeout(60)
    got = b""
    while len(got) < 65536:
        d = s.recv(65536)
        if not d: break
        got += d
    eof = s.recv(1)                 # must be 0 (FIN), NOT an error
    print("B_SAW_EOF" if eof == b"" else "B_NO_EOF %r" % eof, flush=True)
    s.sendall(b"R" * 4096)          # write side must still work after FIN
'''

def start_relay(port):
    r = subprocess.Popen([sys.executable, "/root/my_vnet/server.py",
                          "--port", str(port), "--bind", "127.0.0.1",
                          "--subnet", "10.200.7.0/24"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _relay_up(port, proc=r):
        try:
            r.kill(); r.wait(timeout=2)
        except Exception:
            pass
        raise RuntimeError("relay did not come up on %d" % port)
    return r

def env(node, port):
    return dict(os.environ, LD_PRELOAD=HOOK,
                LAN_HOOK_SERVER="127.0.0.1", LAN_HOOK_PORT=str(port),
                LAN_HOOK_TOKEN="", LAN_HOOK_DEBUG="0",
                LAN_HOOK_LEASE_WAIT="25", LAN_HOOK_NODE=str(node))

def run(mode, nA, nB):
    port = _free_port()
    relay = start_relay(port)
    pa = subprocess.Popen([sys.executable, "-c", SHELL_A, mode], env=env(nA, port),
                          stdout=subprocess.PIPE, text=True)
    assert pa.stdout.readline().startswith("LISTENING")
    time.sleep(0.4)
    pb = subprocess.Popen([sys.executable, "-c", SHELL_B, mode], env=env(nB, port),
                          stdout=subprocess.PIPE, text=True)
    oa, ob = [], []
    threading.Thread(target=lambda: [oa.append(l.rstrip()) for l in
                                     iter(pa.stdout.readline, '')], daemon=True).start()
    threading.Thread(target=lambda: [ob.append(l.rstrip()) for l in
                                     iter(pb.stdout.readline, '')], daemon=True).start()
    # Both children terminate on their own once the scenario completes
    # (each ends with a bounded sleep); wait for real exit, not a
    # sentinel line - under parallel load the lines just arrive later.
    try:
        pa.wait(timeout=200)
    except subprocess.TimeoutExpired:
        pass
    try:
        pb.wait(timeout=60)
    except subprocess.TimeoutExpired:
        pass
    relay.kill()
    pa.kill(); pb.kill()
    time.sleep(0.3)   # let the reader threads drain final flushed lines
    return oa, ob

ok = True
oa, ob = run("stall", 440101, 440102)
b_rx = next((l for l in ob if l.startswith("B_RX_DONE")), "")
a_read = next((l for l in oa if l.startswith("A_READS_START")), "t=999")
bt = float(b_rx.split("t=")[1].split()[0]) if "t=" in b_rx else 999
at = float(a_read.split("t=")[1]) if "t=" in a_read else 999
s1 = "A_MARKER_OK" in " ".join(oa) and "total=262144" in b_rx and bt < at
print(f"[1 stall-independence] B_done={bt:.2f} < A_reads={at:.2f}: {'OK' if s1 else 'FAIL'} {oa} {ob}")
ok &= s1

oa, ob = run("closeflush", 440103, 440104)
s2 = "A_GOT 200000" in " ".join(oa)
print(f"[2 close-flush] {'OK' if s2 else 'FAIL'} {oa}")
ok &= s2

oa, ob = run("halfclose", 440105, 440106)
s3 = ("A_BACK_OK" in " ".join(oa)) and ("B_SAW_EOF" in " ".join(ob))
print(f"[3 half-close] {'OK' if s3 else 'FAIL'} {oa} {ob}")
ok &= s3

print("FULLDUPLEX_ALL_PASS" if ok else "FULLDUPLEX FAIL")
sys.exit(0 if ok else 1)
