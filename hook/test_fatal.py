#!/usr/bin/env python3
"""Fatal startup errors (v1.1.0): without a relay link AND an address
lease the tunnel cannot work, so the hook reports visibly and kills
the game with a distinct exit code instead of running broken.

  200 = relay unreachable, 201 = link up but no lease.
  Linux: message on stderr + _exit(code). Windows: messagebox +
  TerminateProcess (same codes; compile-checked, exercised on Linux).

Each case forks a child under LD_PRELOAD that triggers hook init via
one sendto; the parent asserts the child's exit code and stderr.
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile

HOOKDIR = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(HOOKDIR, "lan_hook.so")

CHILD = r"""
import os, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"x", ("192.168.99.99", 47777))
except OSError:
    pass
print("SURVIVED", flush=True)
"""


def run_child(env_extra, timeout=12):
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(CHILD)
        path = f.name
    env = dict(os.environ)
    env["LD_PRELOAD"] = HOOK
    env["LAN_HOOK_DEBUG"] = "1"
    env.update(env_extra)
    try:
        r = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, timeout=timeout, env=env)
    finally:
        os.unlink(path)
    return r


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_norelay():
    """Nothing listening: watchdog must kill the child with 200."""
    port = free_port()
    r = run_child({"LAN_HOOK_SERVER": "127.0.0.1",
                   "LAN_HOOK_PORT": str(port),
                   "LAN_HOOK_LEASE_WAIT": "900",
                   "LAN_HOOK_INIT_TIMEOUT": "900"})
    assert r.returncode == 200, (r.returncode, r.stderr[-500:], r.stdout)
    assert "cannot reach relay" in r.stderr, r.stderr[-500:]
    assert "SURVIVED" not in r.stdout
    print("PASS[fatal] unreachable relay -> exit 200 + stderr", flush=True)


def test_nolease():
    """TCP accepts but never assigns: link up, no lease -> 201."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    srv.setblocking(False)
    import threading
    stop = threading.Event()

    def hold():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except BlockingIOError:
                stop.wait(0.05)
                continue
            except OSError:
                return
            c.setblocking(False)
            try:
                while not stop.is_set():
                    try:
                        if not c.recv(65536):
                            break
                    except BlockingIOError:
                        stop.wait(0.05)
            finally:
                c.close()

    t = threading.Thread(target=hold, daemon=True)
    t.start()
    try:
        r = run_child({"LAN_HOOK_SERVER": "127.0.0.1",
                       "LAN_HOOK_PORT": str(port),
                       "LAN_HOOK_LEASE_WAIT": "900",
                       "LAN_HOOK_INIT_TIMEOUT": "900"})
    finally:
        stop.set()
        srv.close()
    assert r.returncode == 201, (r.returncode, r.stderr[-500:], r.stdout)
    assert "no virtual-IP lease" in r.stderr, r.stderr[-500:]
    assert "SURVIVED" not in r.stdout
    print("PASS[fatal] silent relay -> exit 201 + stderr", flush=True)


def test_healthy_relay():
    """Control: real relay grants a lease, child survives (exit 0)."""
    sys.path.insert(0, os.path.dirname(HOOKDIR))
    import asyncio
    from server import Relay

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(CHILD)
        path = f.name
    env = dict(os.environ)
    env["LD_PRELOAD"] = HOOK
    env["LAN_HOOK_DEBUG"] = "1"
    env["LAN_HOOK_SERVER"] = "127.0.0.1"
    env["LAN_HOOK_PORT"] = "47811"
    env["LAN_HOOK_INIT_TIMEOUT"] = "8000"
    env["LAN_HOOK_LEASE_WAIT"] = "8000"

    async def amain():
        relay = Relay(47811, bind="127.0.0.1")
        task = asyncio.create_task(relay.run())
        await asyncio.sleep(0.2)
        try:
            # async spawn: blocking here would stall the relay loop and
            # the child would never get its lease
            proc = await asyncio.create_subprocess_exec(
                sys.executable, path, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=env)
            try:
                out, err = await asyncio.wait_for(proc.communicate(), 12)
            except asyncio.TimeoutError:
                proc.kill()
                raise AssertionError("healthy child hung")
            return proc.returncode, out.decode(), err.decode()
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    try:
        rc, out, err = asyncio.run(amain())
    finally:
        os.unlink(path)
    assert rc == 0, (rc, err[-800:])
    assert "SURVIVED" in out, (out, err[-500:])
    print("PASS[fatal] healthy relay -> child runs", flush=True)


if __name__ == "__main__":
    if os.name != "posix":
        print("FATAL_SKIP (posix only)")
        sys.exit(0)
    if not os.path.exists(HOOK):
        print("FATAL_SKIP (no lan_hook.so)")
        sys.exit(0)
    test_norelay()
    test_nolease()
    test_healthy_relay()
    print("FATAL_ALL_PASS", flush=True)
