"""Test-suite helpers: dynamic port allocation and unique temp paths.

Every test MUST take its network ports from free_port()/free_ports() and
its temp files from tmp_path() instead of hard-coded constants, so the
suite runs in any order, concurrently (runtests.py / make test-all),
and beside a dev box that happens to be running other tests. Virtual
ports inside the emulated LAN (47584-style vports, 10.200.x addresses)
are per-relay and may stay fixed - only REAL bindable ports and shared
file paths need allocation.
"""
import fcntl
import json
import os
import socket
import subprocess
import time

_RES = None  # lazy: /tmp/opencode/shadowlan_ports.json (pid->ports)


def _res_path():
    global _RES
    if _RES is None:
        d = os.environ.get("SHADOWLAN_TEST_TMP", "/tmp/opencode")
        try:
            os.makedirs(d, exist_ok=True)
            _RES = os.path.join(d, "shadowlan_ports.json")
        except OSError:
            _RES = os.path.join("/tmp", "shadowlan_ports.json")
    return _RES


def _alloc_one():
    """Free port cross-process-reserved: concurrent test processes share
    a registry (flocked), so two suites never aim at the same kernel-
    suggested port in the free->bind window. Dead owners are pruned."""
    path = _res_path()
    with open(path, "a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.seek(0)
        try:
            table = json.load(fh)
        except Exception:
            table = {}
        alive = {}
        for pid, ports in table.items():
            try:
                os.kill(int(pid), 0)
                alive[pid] = list(ports)
            except (OSError, ValueError):
                pass
        used = {p for ports in alive.values() for p in ports}
        for _ in range(50):
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", 0))
                p = s.getsockname()[1]
            finally:
                s.close()
            if p not in used:
                alive.setdefault(str(os.getpid()), []).append(p)
                fh.seek(0)
                fh.truncate()
                json.dump(alive, fh)
                return p
        raise RuntimeError("port pool exhausted")


def free_port():
    return _alloc_one()


def free_ports(n):
    socks = []
    ports = []
    try:
        for _ in range(n):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            socks.append(s)
            ports.append(s.getsockname()[1])
        return ports
    finally:
        for s in socks:
            s.close()


def tmp_path(name):
    d = os.environ.get("SHADOWLAN_TEST_TMP", "/tmp/opencode")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        d = "/tmp"
    return os.path.join(d, "%s.%d" % (name, os.getpid()))


def free_trio():
    """Three consecutive free TCP ports (a child that binds base and
    base+1 while base+2 must stay unclaimed). Probed by simultaneous
    bind, then released for the real users."""
    while True:
        p = free_port()
        socks = []
        try:
            for q in (p, p + 1, p + 2):
                s = socket.socket()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", q))
                socks.append(s)
            for s in socks:
                s.close()
            return p
        except OSError:
            for s in socks:
                s.close()


def relay_up(port, timeout=10.0, proc=None):
    """Poll until a relay on 127.0.0.1:port accepts TCP (and, if given,
    the spawn proc is still alive). Replaces fixed sleep(0.7)."""
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def start_relay(argv_builder, attempts=5, timeout=10.0):
    """argv_builder(port) -> argv list for Popen. Allocates a free port,
    spawns, health-checks; re-allocates if the port raced away or the
    process died at bind. Returns (proc, port)."""
    for _ in range(attempts):
        p = free_port()
        proc = subprocess.Popen(argv_builder(p))
        if relay_up(p, timeout=timeout, proc=proc):
            return proc, p
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
    raise RuntimeError("relay would not start (port race?)")
