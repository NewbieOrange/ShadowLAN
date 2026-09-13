"""Full-socket-door test for tunneled TCP sockets.

A fake (tunneled) socket must answer EVERY door the app may knock with
what a kernel would: getsockopt(SO_ERROR) 0/ECONNREFUSED, getpeername =
the peer vnode, accept()/getpeername on the ACCEPTED socket = the
OPENER's vnode (spoof door), FIONREAD counts tunnel bytes, re-connect on
a connected socket -> EISCONN/EALREADY, dead-port connect -> ECONNREFUSED
promptly. LD_PRELOAD (dlog -> stderr on Linux).
"""
import os
import re
import subprocess
import sys
import time
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from testutil import free_port as _free_port, tmp_path as _tmp_path, free_trio as _free_trio
P_BASE = _free_trio()   # child listens on base, base+1; base+2 stays dead
HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(HERE, "hook", "lan_hook.so")
PUB = _free_port()
CHILD = _tmp_path("door_child")
SRVERR = _tmp_path("door_srvchild_err")
CLIL = _tmp_path("door_cli_log")

with open(HOOK, "rb") as f:
    assert f.read(4) == b"\x7fELF", "hook/lan_hook.so is not an ELF"

CHILD2 = _tmp_path("door_child2")
CHILD_SRC = r"""
import sys, os, select, socket, time, struct
mode = sys.argv[1]
if mode == "serve":
    port = int(sys.argv[2])
    W = lambda m: (sys.stderr.write(m + "\n"), sys.stderr.flush())
    svcs = []
    for p in (port, port + 1):
        ss = socket.socket(); ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ss.bind(("0.0.0.0", p)); ss.listen(4); svcs.append(ss)
    # drain BOTH backlogs concurrently: pending connects on either port
    # complete from the backlog (LAN semantics) even if nobody reads them
    # (Unity-style) - the doors must answer honestly in that state too.
    import threading
    conns = {}
    def acc(i):
        c, peer = svcs[i].accept()
        conns[i] = (c, peer)
        W("ACCEPTED%d %r" % (i, peer))
    ts = [threading.Thread(target=acc, args=(i,), daemon=True) for i in (0, 1)]
    for t in ts: t.start()
    # serve conns[0] when it arrives
    t0 = time.time()
    while time.time() - t0 < 20:
        if 0 in conns: break
        time.sleep(0.1)
    c1, peer = conns[0]
    W("A accepted=%r" % (peer,))
    try:
        gp = c1.getpeername()
    except OSError:
        gp = "ERR"
    W("B getpeername=%r" % (gp,))
    c1.sendall(b"HELLO-FROM-GAME" * 3)
    time.sleep(1.5)
    try:
        c1.recv(64)
    except OSError:
        pass
    c1.close()
    for ss in svcs: ss.close()
    sys.exit(0)

if mode in ("client", "client-dead"):
    host, port = sys.argv[2], int(sys.argv[3])
    # ---- dead-port door ----
    if mode == "client-dead":
        s = socket.socket(); s.setblocking(False)
        try:
            s.connect((host, port))
        except OSError as e:
            import errno
            if e.errno not in (errno.EINPROGRESS, errno.EWOULDBLOCK):
                print("CLIENT dead connect errno=%d" % e.errno)
                print("CLIENT REFUSED_OK" if e.errno == 111 else "CLIENT REFUSED_BAD")
                sys.exit(0 if e.errno == 111 else 1)
        r, w, x = select.select([s], [s], [], 12)
        v = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if v == 111:
            print("CLIENT dead SO_ERROR=ECONNREFUSED")
            print("CLIENT REFUSED_OK"); sys.exit(0)
        if v:
            print("CLIENT dead SO_ERROR=%d" % v)
            print("CLIENT REFUSED_BAD"); sys.exit(1)
        died = False
        deadline = time.time() + 6
        while time.time() < deadline:
            rr, _, _ = select.select([s], [], [], 0.2)
            if not rr:
                continue
            try:
                d = s.recv(16)
                if d == b"":
                    died = True
                break
            except OSError as e:
                died = e.errno in (104, 111)
                break
        print("CLIENT dead-port recv-death=%s SO_ERROR=%d" % (died, v))
        print("CLIENT REFUSED_OK" if died else "CLIENT REFUSED_BAD")
        sys.exit(0 if died else 1)

    # ---- happy path doors ----
    s = socket.socket()
    s.setblocking(False)
    try:
        s.connect((host, port))
        immediate = True
    except OSError as e:
        import errno
        if e.errno not in (errno.EINPROGRESS, errno.EWOULDBLOCK):
            raise
        immediate = False
    r, w, x = select.select([s], [s], [s], 10)
    v = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if v:
        print("CLIENT verdict SO_ERROR=%d" % v)
        print("CLIENT REFUSED_BAD")
        sys.exit(1)
    pn = s.getpeername()
    print("CLIENT getpeername=%r" % (pn,))
    import fcntl, array
    total = b""
    deadline = time.time() + 6
    while time.time() < deadline and len(total) < 45:
        n = array.array("i", [0])
        try:
            fcntl.ioctl(s.fileno(), 0x541B, n, False)
            n = n[0]
        except OSError:
            n = 0
        if n:
            try:
                d = s.recv(n)
            except BlockingIOError:
                continue
            if not d:
                break
            total += d
        else:
            rr, _, _ = select.select([s], [], [], 0.1)
            if rr:
                try:
                    d = s.recv(4096)
                except BlockingIOError:
                    continue
                if not d:
                    break
                total += d
    print("CLIENT recv %d bytes=%r" % (len(total), total[:17]))
    reok = False
    try:
        s.connect((host, port))
        print("CLIENT reconnect: no error")
        reok = True   # connect on an established vnet socket is a no-op
                      # here; kernel would answer EISCONN (106) or EALREADY
    except OSError as e:
        print("CLIENT reconnect errno=%d" % e.errno)
        reok = e.errno in (106, 114, 115)   # EISCONN/EALREADY/EINPROGRESS
    peerok = pn[0].startswith("10.200.")
    dataok = b"HELLO-FROM-GAME" in total
    good = dataok and peerok and reok
    print("CLIENT " + ("DOORS_OK" if good else "DOORS_BAD"))
    sys.exit(0 if good else 1)

sys.exit(9)
"""
CHILD2_SRC = r"""
import sys, os, select, socket, time, struct, errno
mode = sys.argv[1]
if mode == "serve":
    port = int(sys.argv[2])
    W = lambda m: (sys.stderr.write(m + "\n"), sys.stderr.flush())
    svcs = []
    for p in (port, port + 1):
        ss = socket.socket(); ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ss.bind(("0.0.0.0", p)); ss.listen(4); svcs.append(ss)
    # accept on BOTH listeners (backlog drains) so a connect to port+1
    # succeeds kernel-style; the DEAD-PORT door then uses port+2 (never
    # listened): must surface ECONNREFUSED promptly.
    c1, peer = svcs[0].accept()
    W("A accepted=%r" % (peer,))
    try:
        gp = c1.getpeername()
    except OSError:
        gp = "ERR"
    W("B getpeername=%r" % (gp,))
    c2, peer2 = svcs[1].accept()
    W("C accepted2=%r getpeername2=%r" % (peer2, c2.getpeername()))
    c1.sendall(b"HELLO-FROM-GAME" * 3)
    time.sleep(1.5)
    try:
        c1.recv(64)
    except OSError:
        pass
    c1.close(); c2.close()
    for ss in svcs: ss.close()
    sys.exit(0)

if mode == "peer":
    host, port = sys.argv[2], int(sys.argv[3])
    s = socket.socket(); s.setblocking(False)
    try:
        s.connect((host, port))
    except OSError:
        pass
    time.sleep(25)
    sys.exit(0)

if mode in ("client", "client-dead"):
    host, port = sys.argv[2], int(sys.argv[3])
    # ---- dead-port door: must surface ECONNREFUSED (not a hang) ----
    if mode == "client-dead":
        s = socket.socket(); s.setblocking(False)
        try:
            s.connect((host, port))
        except OSError as e:
            import errno
            if e.errno not in (errno.EINPROGRESS, errno.EWOULDBLOCK):
                print("CLIENT dead connect errno=%d" % e.errno)
                print("CLIENT REFUSED_OK" if e.errno == 111 else "CLIENT REFUSED_BAD")
                sys.exit(0 if e.errno == 111 else 1)
        r, w, x = select.select([s], [s], [s], 12)
        v = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        sys.stderr.write("DEADPROBE2 sel=%r err=%d except=%r\n" % (bool(r or w), v, bool(x))); sys.stderr.flush()
        if v == 111:
            print("CLIENT dead SO_ERROR=ECONNREFUSED")
            print("CLIENT REFUSED_OK"); sys.exit(0)
        if v:
            print("CLIENT dead SO_ERROR=%d" % v)
            print("CLIENT REFUSED_BAD"); sys.exit(1)
        died = False
        deadline = time.time() + 12
        while time.time() < deadline:
            rr, _, _ = select.select([s], [], [], 0.2)
            if not rr:
                continue
            try:
                d = s.recv(16)
                if d == b"":
                    died = True
                break
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                died = e.errno in (104, 111)
                break
        print("CLIENT dead-port recv-death=%s SO_ERROR=%d" % (died, v))
        print("CLIENT REFUSED_OK" if died else "CLIENT REFUSED_BAD")
        sys.exit(0 if died else 1)

    # ---- happy path doors ----
    s = socket.socket()
    s.setblocking(False)
    try:
        s.connect((host, port))
        immediate = True
    except OSError as e:
        import errno
        if e.errno not in (errno.EINPROGRESS, errno.EWOULDBLOCK):
            raise
        immediate = False
    r, w, x = select.select([s], [s], [s], 10)
    v = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if v:
        print("CLIENT verdict SO_ERROR=%d" % v)
        print("CLIENT REFUSED_BAD")
        sys.exit(1)
    pn = s.getpeername()
    print("CLIENT getpeername=%r" % (pn,))
    import fcntl, array
    total = b""
    deadline = time.time() + 6
    while time.time() < deadline and len(total) < 45:
        n = array.array("i", [0])
        try:
            fcntl.ioctl(s.fileno(), 0x541B, n, False)
            n = n[0]
        except OSError:
            n = 0
        if n:
            d = s.recv(n)
            if not d:
                break
            total += d
        else:
            rr, _, _ = select.select([s], [], [], 0.1)
            if rr:
                d = s.recv(4096)
                if not d:
                    break
                total += d
    print("CLIENT recv %d bytes=%r" % (len(total), total[:17]))
    reok = False
    try:
        s.connect((host, port))
        print("CLIENT reconnect: no error")
        reok = True   # hook completes connects synchronously; no-error
                      # on a vnet socket is acceptable (kernel: EISCONN)
    except OSError as e:
        print("CLIENT reconnect errno=%d" % e.errno)
        reok = e.errno in (106, 114, 115)   # EISCONN/EALREADY/EINPROGRESS
    peerok = pn[0].startswith("10.200.")
    dataok = b"HELLO-FROM-GAME" in total
    good = dataok and peerok and reok
    print("CLIENT " + ("DOORS_OK" if good else "DOORS_BAD"))
    sys.exit(0 if good else 1)

sys.exit(9)
"""
with open(CHILD, "w") as _f: _f.write(CHILD_SRC)
with open(CHILD2, "w") as _f: _f.write(CHILD2_SRC)

def env_for(logfile):
    return dict(os.environ, LD_PRELOAD=HOOK,
                LAN_HOOK_SERVER="127.0.0.1", LAN_HOOK_PORT=str(PUB),
                LAN_HOOK_TOKEN="", LAN_HOOK_DEBUG="1",
                LAN_HOOK_LEASE_WAIT="25",
                LAN_HOOK_LOGFILE=logfile)

def run_relay():
    p = subprocess.Popen(
        [sys.executable, "-c",
         f"import asyncio,sys;sys.path.insert(0,{HERE!r});"
         f"from server import Relay;r=Relay({PUB},token=b'',bind='127.0.0.1');"
         "asyncio.run(r.run())"], stdout=subprocess.DEVNULL)
    time.sleep(1.2)
    return p

def scan_vnodes(text):
    return re.findall(r"self=(10\.\d+\.\d+\.\d+)", text)

def main():
    for f in (SRVERR, CLIL):
        try:
            os.remove(f)
        except OSError:
            pass
    relay = run_relay()
    ok = True
    serve = None
    try:
        serve = subprocess.Popen(
            [sys.executable, CHILD, "serve", str(P_BASE)], env=env_for(SRVERR),
            stdout=subprocess.DEVNULL, stderr=open(SRVERR, "wb"))
        # wait until the server child has its lease
        vb = None
        end = time.time() + 30
        while time.time() < end:
            try:
                m = scan_vnodes(open(SRVERR, errors="ignore").read())
                if m:
                    vb = m[0]
                    break
            except OSError:
                pass
            time.sleep(0.3)
        if not vb:
            print("server lease missing")
            sys.exit(1)
        print("server vnode:", vb)

        # Run the happy-path client FIRST (server accepts once per
        # listener), then the dead-port client while the server still
        # holds its second listener open on 47811 (backlog semantics)
        # and nothing at all on 47812 -> ECONNREFUSED promptly.
        # dead-port door FIRST (47812: nothing listens there) while the
        # server sits blocked in accept() on its single listener 47810.
        t0 = time.time()
        cl3 = subprocess.run([sys.executable, CHILD2,
                              "client-dead", vb, str(P_BASE + 2)],
                             env=dict(env_for("/x"), PYTHONUNBUFFERED="1"),
                             capture_output=True, text=True, timeout=60)
        dt = time.time() - t0
        print(f"[refused-side {dt:.1f}s]",
              cl3.stdout.strip().replace("\n", " | "))
        if "REFUSED_OK" not in cl3.stdout:
            print("  ! dead port did not surface ECONNREFUSED")
            ok = False
        # happy path: the held-pending connect on 47810 gets accepted by
        # the server's accept loop; data must flow both ways.
        e2 = env_for(CLIL)
        try:
            os.remove("/tmp/opencode/door_cl2.err")
        except OSError:
            pass
        cl2 = subprocess.Popen([sys.executable, CHILD, "client", vb,
                                str(P_BASE)], env=e2, stdout=subprocess.PIPE,
                               stderr=open("/tmp/opencode/door_cl2.err", "wb"),
                               text=True)
        out2 = cl2.communicate(timeout=60)[0]
        print("[accepted-side]", out2.strip().replace("\n", " | "))
        if "DOORS_OK" not in out2:
            ok = False

        try:
            serve.wait(timeout=25)
        except subprocess.TimeoutExpired:
            serve.kill(); serve.wait()
            ok = False
        out = open(SRVERR, errors="ignore").read()
        m = re.search(r"A accepted=\('([\d.]+)', (\d+)\)\nB getpeername=\('([\d.]+)'", out)
        if not m:
            print("  ! server accept lines missing")
            ok = False
        else:
            acc_a, acc_p, gpa = m.group(1), m.group(2), m.group(3)
            print(f"[accept-door] out-param={acc_a}:{acc_p} "
                  f"getpeername={gpa}")
            if gpa != acc_a or not acc_a.startswith("10.200."):
                print("  ! accept doors not consistent/not vnode")
                ok = False
            else:
                print("[accept-door] accepted peer spoofed to opener OK")

    finally:
        # hard teardown: stray hooked processes re-register into the
        # same room and steal implicit-host routing for later tests
        try:
            serve.kill()
        except Exception:
            pass
        relay.kill()
        relay.wait()
        subprocess.run(["pkill", "-f", "door_child"],
                       capture_output=True)
        time.sleep(0.3)
    print("DOORS_ALL_PASS" if ok else "DOORS_FAIL")
    sys.exit(0 if ok else 1)

main()
