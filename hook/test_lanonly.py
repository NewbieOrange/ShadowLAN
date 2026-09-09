#!/usr/bin/env python3
"""LAN_HOOK_LAN_ONLY=1: the process sees nothing but the ShadowLAN subnet.

  phase 1  mesh still fully works under isolation: the existing
           host/direct senders discover, TCP-connect (relay-confirmed)
           and echo over the tunnel (SENDER_DIRECT_OK)
  phase 2  outbound public unicast = instant "no route": sendto AND
           connect to TEST-NET-1 fail with ENETUNREACH in <0.5s
  phase 3  inbound wire datagrams (non-loopback source) are dropped on
           hooked sockets; the loopback copy is delivered
  phase 4  accept(): wire LAN peer is dropped; loopback peer is served
"""
import asyncio
import os
import socket
import sys
import time

HOOKDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HOOKDIR))
from server import Relay

HOOK = os.path.join(HOOKDIR, "lan_hook.so")
PUB = 47871
HOST_TCP, HOST_UDP, DISC = 47872, 47873, 47874
IN_PORT = 47875
ACC_PORT = 47876
ECHO_PORT = 47877
PUBLIC = "192.0.2.10"          # TEST-NET-1: guaranteed no route / unroutable

PROBE = r"""
import socket, sys, time
mode = sys.argv[1]
if mode == "out":
    pub = sys.argv[2]
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.sendto(b"x", (pub, 55555))
        print("BAD: sendto succeeded"); sys.exit(1)
    except OSError as e:
        assert e.errno == 101, ("sendto errno", e.errno)
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t0 = time.time()
    try:
        t.connect((pub, 80))
        print("BAD: connect succeeded"); sys.exit(1)
    except OSError as e:
        assert e.errno == 101, ("connect errno", e.errno)
        assert time.time() - t0 < 0.5, "connect not instant"
    print("OUT_OK")
elif mode == "in":
    port = int(sys.argv[2])
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    u.bind(("0.0.0.0", port))
    u.settimeout(4)
    got = []
    try:
        while True:
            d, _ = u.recvfrom(1024)
            got.append(d)
            if d == b"LOOP":
                break
    except socket.timeout:
        pass
    print("IN_GOT", got)
    assert b"WIRE" not in got and b"LOOP" in got, got
    print("IN_OK")
elif mode == "echo":
    # The hook loops our own broadcast back (NIC-style local echo). On a
    # truly isolated LAN that echo can ONLY carry our virtual address:
    # apps adopt announce sources into own_ip/peer state, so a physical
    # NIC ip here leaks straight through the isolation.
    port = int(sys.argv[2])
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    u.bind(("", port))
    u.sendto(b"PINGME", ("255.255.255.255", port))
    u.settimeout(4)
    src = None
    while src is None:
        d, a = u.recvfrom(1024)
        if d == b"PINGME":
            src = a[0]
    print("ECHO_SRC", src)
    assert src.startswith("10.200."), src
    print("ECHO_OK")
elif mode == "acc":
    import threading
    port = int(sys.argv[2])
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", port))
    ls.listen(4)
    ls.settimeout(1.0)
    seen = []
    def serve():
        end = time.time() + 6
        while time.time() < end:
            try:
                c, a = ls.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            seen.append(a[0])
            data = c.recv(64)
            c.sendall(b"ACK:" + data)
            c.close()
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    # loopback self-connect must be served normally
    time.sleep(0.4)
    k = socket.create_connection(("127.0.0.1", port), timeout=3)
    k.sendall(b"ping")
    r = k.recv(64)
    k.close()
    assert r == b"ACK:ping", r
    time.sleep(3.0)   # keep the listener alive while the harness probes it
    bad = [ip for ip in seen if not ip.startswith("127.")]
    print("ACC seen:", seen)
    assert not bad, bad
    print("ACC_OK")
"""


def own_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((PUBLIC, 9))
        ip = s.getsockname()[0]
        s.close()
        return None if ip.startswith("127.") else ip
    except OSError:
        return None


async def hooked_py(src, args, env, timeout=20):
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(src)
        path = f.name
    try:
        p = await asyncio.create_subprocess_exec(
            sys.executable, path, *args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env=env)
        out, _ = await asyncio.wait_for(p.communicate(), timeout)
        return p.returncode, out.decode(errors="replace")
    finally:
        os.unlink(path)


async def main():
    relay = Relay(PUB, bind="127.0.0.1")
    relay_task = asyncio.create_task(relay.run())
    await asyncio.sleep(0.3)
    env = dict(os.environ, LD_PRELOAD=HOOK, LAN_HOOK_SERVER="127.0.0.1",
               LAN_HOOK_PORT=str(PUB), LAN_HOOK_DEBUG="1",
               LAN_HOOK_LAN_ONLY="1")

    # phase 1: mesh over the tunnel, isolated client AND isolated host
    host = await asyncio.create_subprocess_exec(
        sys.executable, os.path.join(HOOKDIR, "hook_sender_host.py"),
        str(HOST_TCP), str(HOST_UDP), str(DISC), "BEACON:L", "30",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL, env=env)
    await asyncio.sleep(2.0)
    try:
        p = await asyncio.create_subprocess_exec(
            sys.executable, os.path.join(HOOKDIR, "hook_sender_direct.py"),
            str(DISC), str(HOST_TCP), str(HOST_UDP), "BEACON:L",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT, env=env)
        out, _ = await asyncio.wait_for(p.communicate(), timeout=30)
        text = out.decode(errors="replace")
        assert "SENDER_DIRECT_OK" in text, text[-400:]
    finally:
        host.kill()
    print("PASS[lanonly] mesh works with isolation on", flush=True)

    # phase 2: outbound public = instant ENETUNREACH
    rc, out = await hooked_py(PROBE, ["out", PUBLIC], env)
    assert rc == 0 and "OUT_OK" in out, (rc, out[-400:])
    print("PASS[lanonly] public sendto/connect fail no-route", flush=True)

    ip = own_ip()
    if ip is None:
        print("SKIP[lanonly] wire phases (no non-loopback IPv4)", flush=True)
    else:
        # phase 3: wire inbound dropped, loopback inbound delivered
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(PROBE)
            path = f.name
        try:
            child = await asyncio.create_subprocess_exec(
                sys.executable, path, "in", str(IN_PORT),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, env=env)
            await asyncio.sleep(0.8)          # child is bound now
            h = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            h.sendto(b"WIRE", (ip, IN_PORT))   # via the physical interface
            await asyncio.sleep(0.3)
            h.sendto(b"LOOP", ("127.0.0.1", IN_PORT))
            h.close()
            out, _ = await asyncio.wait_for(child.communicate(), timeout=15)
            text = out.decode(errors="replace")
            assert child.returncode == 0 and "IN_OK" in text, \
                (child.returncode, text[-500:])
        finally:
            os.unlink(path)
        print("PASS[lanonly] wire datagram dropped, loopback delivered",
              flush=True)

        # phase 4: accept filter (wire LAN peer never surfaced)
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(PROBE)
            path = f.name
        try:
            child = await asyncio.create_subprocess_exec(
                sys.executable, path, "acc", str(ACC_PORT),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, env=env)
            await asyncio.sleep(0.8)
            w = socket.create_connection((ip, ACC_PORT), timeout=3)
            w.sendall(b"wire-hi")
            try:
                closed = w.recv(64) == b""   # hook dropped the accepted one
            except ConnectionResetError:
                closed = True                # close-with-pending-data == RST
            w.close()
            out, _ = await asyncio.wait_for(child.communicate(), timeout=20)
            text = out.decode(errors="replace")
            assert closed, "wire accept was NOT dropped"
            assert child.returncode == 0 and "ACC_OK" in text, \
                (child.returncode, text[-500:])
        finally:
            os.unlink(path)
        print("PASS[lanonly] wire TCP peer dropped at accept", flush=True)


    # phase 5: own-broadcast local echo carries the vnode, never the NIC
    rc, out = await hooked_py(PROBE, ["echo", str(ECHO_PORT)], env)
    assert rc == 0 and "ECHO_OK" in out, (rc, out[-400:])
    print("PASS[lanonly] broadcast echo sourced with virtual address", flush=True)

    print("LANONLY_ALL_PASS", flush=True)
    relay_task.cancel()
    await asyncio.gather(relay_task, return_exceptions=True)
    return 0


async def _guarded():
    return await asyncio.wait_for(main(), timeout=90)


if __name__ == "__main__":
    sys.exit(asyncio.run(_guarded()))
