#!/usr/bin/env python3
"""Late-loaded module regression (Windows/Wine only; skips elsewhere).

Reproduces the engine pattern where a networking plugin DLL is loaded via
LoadLibrary long after hook install: without the LoadLibrary IAT hooks and
the differential module sweep, the plugin's sockets stay invisible to the
tunnel, inbound queries are dropped, and it never answers. Requires a
ready Wine prefix (env SHADOWLAN_WINEPREFIX); all artifacts land in a
temp dir resolved through the Wine Z: drive.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HOOKDIR = os.path.dirname(os.path.abspath(__file__))

PUB = int(os.environ.get("SHADOWLAN_LATE_PORT", "47825"))
WINEPREFIX = os.environ.get("SHADOWLAN_WINEPREFIX", "")
WINE = shutil.which("wine")


def winpath(p):
    """POSIX path -> Wine Z: path with literal backslashes."""
    return "Z:" + p.replace("/", "\\")


def build():
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        return False
    for src, out, shared in (("test_late.c", "test_late.exe", False),
                             ("test_lateplug.c", "test_lateplug.dll", True)):
        s = os.path.join(HOOKDIR, src)
        d = os.path.join(HOOKDIR, out)
        if os.path.exists(d) and os.path.getmtime(d) > os.path.getmtime(s):
            continue
        cmd = [cc, "-O2", "-Wall"]
        if shared:
            cmd += ["-shared"]
        cmd += ["-o", d, s, "-lws2_32"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            print(r.stderr[:400])
            return False
    for tgt in ("lan_hook64.dll", "injector.exe"):
        if not os.path.exists(os.path.join(HOOKDIR, tgt)):
            return False
    return True


def cleanup():
    subprocess.run("ps -eo pid,args | grep -E '[t]est_late.exe|[i]njector.exe' "
                   "| awk '{print $1}' | xargs -r kill",
                   shell=True, capture_output=True)
    time.sleep(0.5)


def launch(mode, winlog, outpath, ports=None):
    env = dict(os.environ)
    env.update({"WINEDEBUG": "-all", "WINEPREFIX": WINEPREFIX,
                "LAN_HOOK_LOGFILE": winlog, "LAN_HOOK_DEBUG": "1"})
    h = winpath(HOOKDIR)
    portargs = " ".join(str(p) for p in (ports or (PUB + 1, PUB + 2)))
    cmd = (f'timeout 120 {WINE} "{h}\\injector.exe" --server 127.0.0.1 '
           f'--port {PUB} --debug -- "{h}\\lan_hook64.dll" '
           f'"{h}\\test_late.exe" {mode} {portargs} > {outpath} 2>&1')
    return subprocess.Popen(["bash", "-c", cmd], env=env)


def wait_for(path, pattern, timeout):
    """Poll a text file until pattern matches; return matched line or None."""
    end = time.time() + timeout
    rx = re.compile(pattern)
    while time.time() < end:
        try:
            with open(path, errors="replace") as fh:
                for line in fh:
                    if rx.search(line):
                        return line.strip()
        except OSError:
            pass
        time.sleep(0.5)
    return None


def dump_tail(path, n=15):
    if os.path.exists(path):
        print(f"--- {os.path.basename(path)} (tail) ---")
        print("\n".join(open(path, errors="replace").read().splitlines()[-n:]))


def main():
    if not WINE or not WINEPREFIX or not build():
        print("LATE_SKIP")
        return 0
    cleanup()
    tmp = tempfile.mkdtemp(prefix="shadowlan-late-")
    # relay in a real subprocess: an in-process asyncio loop would stall
    # while we block on the wine children and silently starve forwarding
    rlog = open(os.path.join(tmp, "relay.log"), "w")
    relay = subprocess.Popen([sys.executable,
                              os.path.join(os.path.dirname(HOOKDIR), "server.py"),
                              "--port", str(PUB)],
                             stdout=rlog, stderr=subprocess.STDOUT)
    time.sleep(0.8)
    hlog = os.path.join(tmp, "host-hook.log")
    clog = os.path.join(tmp, "cli-hook.log")
    cout = os.path.join(tmp, "cli.out")
    ok = False
    # ---- phase A: shared-port alias (SO_REUSEADDR semantics) ----
    khlog = os.path.join(tmp, "klash-hook.log")
    kout = os.path.join(tmp, "klash.out")
    clash = launch("clash", winpath(khlog), kout, ports=(PUB + 3,))
    aliased = wait_for(khlog, r"bind alias .*vport=%d" % (PUB + 3), 90)
    done = None
    if not aliased:
        print("clash never aliased the busy port")
    else:
        print("clash aliased:", aliased)
        acli = launch("client", os.path.join(tmp, "aclihook.log"),
                      os.path.join(tmp, "acli.out"),
                      ports=(PUB + 4, PUB + 5, PUB + 3))
        done = wait_for(kout, r"CLASH_", 90)
        acli.kill()
        clash.kill()
    okA = done is not None and "CLASH_OK" in open(
        kout, errors="replace").read()
    print("phase A:", "CLASH_OK" if okA else done)
    if not okA:
        dump_tail(kout, 6)
        dump_tail(khlog, 8)
    cleanup()   # wine children outlive their bash wrappers
    # ---- phase B: late-loaded plugin end-to-end ----
    host = launch("host", winpath(hlog), os.path.join(tmp, "host.out"))
    # serialize: cold Wine instances race on shared prefix services, so
    # do not bring the client up until the late plugin really is serving
    served = wait_for(hlog, r"bind pid=\d+ sock=\d+ 0\.0\.0\.0:%d" % (PUB + 1), 90)
    okB = False
    cli = None
    hout = os.path.join(tmp, "host.out")
    if not served:
        print("host never bound the query port")
    else:
        print("host serving:", served)
        ifv = wait_for(hout, r"IF(OK|MISS)", 15)
        print("interface shim:", ifv)
        if ifv and "IFOK" in ifv:
            cli = launch("client", winpath(clog), cout)
            done = wait_for(cout, r"LATE_", 120)
            okB = done is not None and "LATE_OK" in open(
                os.path.join(tmp, "cli.out"), errors="replace").read()
            print("client:", done)
    ok = okA and okB
    if cli:
        cli.kill()
    host.kill()
    if not ok:
        dump_tail(os.path.join(tmp, "host.out"), 6)
        dump_tail(cout, 6)
        dump_tail(hlog)
        dump_tail(clog)
    relay.kill()
    rlog.close()
    cleanup()
    if ok:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print("artifacts: " + tmp)
    print("LATE_ALL_PASS" if ok else "LATE_FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
