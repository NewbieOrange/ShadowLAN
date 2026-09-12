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

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(HERE, "hook", "lan_hook.so")
PUB = 47962
CHILD = "/tmp/opencode/door_child.py"
SRVERR = "/tmp/opencode/door_srvchild.err"
CLIL = "/tmp/opencode/door_cli.log"

with open(HOOK, "rb") as f:
    assert f.read(4) == b"\x7fELF", "hook/lan_hook.so is not an ELF"


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
            [sys.executable, CHILD, "serve", "47810"], env=env_for(SRVERR),
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
        cl3 = subprocess.run([sys.executable, "/tmp/opencode/door_child2.py",
                              "client", vb, "47812"],
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
                                "47810"], env=e2, stdout=subprocess.PIPE,
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
