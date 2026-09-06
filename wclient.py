#!/usr/bin/env python3
"""Windows client. Runs next to the game client. No TUN/TAP, no driver.

Connects to ONE specific IP:port on the host:
  TCP server_ip:port -> discovery + game-TCP
  UDP server_ip:port -> game-UDP

What it does per game (ports from CLI):
- Snoops local discovery broadcasts with SO_REUSEADDR (gets a copy
  without disturbing the game), forwards to host over TCP.
- Re-broadcasts host discoveries locally to 255.255.255.255 so the
  broadcast-only game sees a "LAN" server. The game then connects to
  this PC's IP, which is our local proxy.
- Listens on game TCP/UDP ports locally, tunnels to host.

Windows notes:
- Stdlib only, no admin. Allow Python through Windows Firewall once.
- If bind fails with 10013 (game uses exclusive bind), see README
  fallback; most Unity/Unreal/legacy LAN titles use reusable binds.
"""
import argparse
import asyncio
import hashlib
import os
import random
import socket
import struct
import sys
import time

if os.name == "nt":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except AttributeError:
        pass

from common import (
    T_BCAST, T_BCAST_FROM, T_TCP_OPEN, T_TCP_DATA_C2S, T_TCP_DATA_S2C,
    T_TCP_CLOSE, T_HELLO, T_NODE, U_GAME_C2S, U_GAME_S2C, U_NODE,
    Dedup, QueueProto,
    decode_udp_game, encode_udp_game, encode_hello, encode_udp_hello,
    encode_node, encode_udp_node, decode_bcast_from,
    make_reuse_udp, parse_ports, tcp_read, tcp_send,
)


class WinClient:
    def __init__(self, server_ip, port, disc_ports, tcp_ports, udp_ports,
                 rebroadcast_ip="255.255.255.255", rebroadcast_to=None,
                 disc_bind="0.0.0.0", tcp_remote=None, udp_remote=None,
                 host_mode=False, token=""):
        self.server_ip = server_ip
        self.port = port
        self.disc_ports = disc_ports
        self.tcp_ports = tcp_ports
        self.udp_ports = udp_ports
        # test-only remap: local listen port -> remote game port.
        # production: equal (remote defaults to local).
        self.tcp_remote = tcp_remote or {}
        self.udp_remote = udp_remote or {}
        # --host: bridge inbound relay traffic to the LOCAL game instead
        # of proxying a local game client out (skips proxy listeners).
        self.host_mode = host_mode
        self.token = token.encode() if isinstance(token, str) else (token or b"")
        # virtual-IP membership: stable random node id per process
        self.node_id = random.getrandbits(32) or 1
        self.rebroadcast_ip = rebroadcast_ip
        self.rebroadcast_to = rebroadcast_to
        self.disc_bind = disc_bind
        self.dedup = Dedup()
        self.tcp_writer = None
        self.send_lock = asyncio.Lock()
        # stream_id -> StreamWriter to local game (client side)
        self.local_tcp = {}
        self.next_stream = 1
        # hosted streams: relay sid -> StreamWriter to local game server
        self.host_game = {}
        self.host_pending = {}  # sid -> bytearray (OPEN/DATA race)
        # game UDP port -> (transport, proto) local listener
        self.udp_local = {}
        # tunnel UDP transport/proto (ephemeral -> server:port)
        self.udp_tun = None
        self.udp_tun_proto = None
        # hosted UDP: (tunnel_addr, game_port, cli_ip, cli_port) -> socket
        self.udp_host_socks = {}

    async def tcp_send(self, mtype, payload):
        async with self.send_lock:
            await tcp_send(self.tcp_writer, mtype, payload)

    def rebroadcast(self, disc_port, raw):
        dst_ip, dst_port = self.rebroadcast_ip, disc_port
        if self.rebroadcast_to:
            from common import parse_hostport
            dst_ip, dst_port = parse_hostport(self.rebroadcast_to, disc_port)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(raw, (dst_ip, dst_port))
            s.close()
        except OSError as e:
            print(f"[bcast] re-emit {dst_ip}:{dst_port} failed: {e}", flush=True)

    async def bcast_snoop(self, disc_port):
        loop = asyncio.get_running_loop()
        try:
            sock = make_reuse_udp(self.disc_bind, disc_port)
        except OSError as e:
            print(f"[bcast] bind {self.disc_bind}:{disc_port} failed: {e} (win err 10013 = exclusive game bind, see README)", flush=True)
            return
        proto = QueueProto()
        await loop.create_datagram_endpoint(lambda: proto, sock=sock)
        print(f"[bcast] snooping {self.disc_bind}:{disc_port}", flush=True)
        while True:
            raw, _ = await proto.q.get()
            key = hashlib.sha256(b"B" + struct.pack("!H", disc_port) + raw).digest()
            if self.dedup.hit(key):
                continue
            if self.tcp_writer:
                try:
                    await self.tcp_send(T_BCAST, struct.pack("!H", disc_port) + raw)
                except (ConnectionResetError, BrokenPipeError, RuntimeError):
                    pass

    async def tcp_reader_loop(self, reader):
        try:
            while True:
                mtype, payload = await tcp_read(reader)
                if mtype == T_BCAST:
                    if len(payload) < 2:
                        continue
                    (dport,) = struct.unpack("!H", payload[:2])
                    raw = payload[2:]
                    if self.dedup.hit(hashlib.sha256(b"B" + payload).digest()):
                        continue
                    self.rebroadcast(dport, raw)
                elif mtype == T_BCAST_FROM:
                    # attributed beacon from another node; source faking
                    # needs the hook, wclient just re-emits the payload
                    dec = decode_bcast_from(payload)
                    if not dec:
                        continue
                    _node, dport, raw = dec
                    if self.dedup.hit(hashlib.sha256(b"BF" + payload).digest()):
                        continue
                    self.rebroadcast(dport, raw)
                elif mtype == T_TCP_DATA_S2C:
                    sid = struct.unpack("!I", payload[:4])[0]
                    w = self.local_tcp.get(sid)
                    if w and not w.is_closing():
                        w.write(payload[4:])
                        try:
                            await w.drain()
                        except (ConnectionResetError, BrokenPipeError):
                            pass
                elif mtype == T_TCP_CLOSE:
                    sid = struct.unpack("!I", payload[:4])[0]
                    w = self.local_tcp.pop(sid, None)
                    if w and not w.is_closing():
                        w.close()
                    w = self.host_game.pop(sid, None)
                    self.host_pending.pop(sid, None)
                    if w and not w.is_closing():
                        w.close()
                elif mtype == T_TCP_OPEN:
                    # inbound: relay routes another player's stream to our
                    # local game server (--host bridge)
                    if len(payload) < 6:
                        continue
                    sid, gport = struct.unpack("!IH", payload[:6])
                    rev_tcp = {v: k for k, v in self.tcp_remote.items()}
                    asyncio.create_task(
                        self.host_dial(sid, rev_tcp.get(gport, gport)))
                elif mtype == T_TCP_DATA_C2S:
                    # inbound game data for a hosted stream
                    if len(payload) < 4:
                        continue
                    (sid,) = struct.unpack("!I", payload[:4])
                    w = self.host_game.get(sid)
                    if w and not w.is_closing():
                        w.write(payload[4:])
                        try:
                            await w.drain()
                        except (ConnectionResetError, BrokenPipeError):
                            pass
                    else:
                        self.host_pending.setdefault(sid, bytearray()).extend(payload[4:])
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass

    async def host_dial(self, sid, gport):
        """Bridge one inbound relay stream to the local game server."""
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", gport)
        except OSError as e:
            print(f"[tcp] host dial 127.0.0.1:{gport} failed: {e}", flush=True)
            self.host_pending.pop(sid, None)
            try:
                await self.tcp_send(T_TCP_CLOSE, struct.pack("!I", sid))
            except Exception:
                pass
            return
        early = self.host_pending.pop(sid, None)
        if early:
            writer.write(bytes(early))
            try:
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass
        self.host_game[sid] = writer
        print(f"[tcp] hosted stream {sid} -> 127.0.0.1:{gport}", flush=True)
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                await self.tcp_send(T_TCP_DATA_S2C, struct.pack("!I", sid) + chunk)
        except (ConnectionResetError, BrokenPipeError, RuntimeError):
            pass
        finally:
            self.host_game.pop(sid, None)
            self.host_pending.pop(sid, None)
            if not writer.is_closing():
                writer.close()
            try:
                await self.tcp_send(T_TCP_CLOSE, struct.pack("!I", sid))
            except Exception:
                pass

    async def tcp_local_listener(self, gport):
        rport = self.tcp_remote.get(gport, gport)

        async def on_accept(reader, writer):
            sid = self.next_stream
            self.next_stream += 1
            self.local_tcp[sid] = writer
            print(f"[tcp] local game -> stream {sid} (:{gport}=>{rport})", flush=True)
            try:
                await self.tcp_send(T_TCP_OPEN, struct.pack("!IH", sid, rport))
            except Exception:
                self.local_tcp.pop(sid, None)
                writer.close()
                return
            try:
                while True:
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    await self.tcp_send(T_TCP_DATA_C2S, struct.pack("!I", sid) + chunk)
            except (ConnectionResetError, BrokenPipeError, RuntimeError):
                pass
            finally:
                self.local_tcp.pop(sid, None)
                try:
                    await self.tcp_send(T_TCP_CLOSE, struct.pack("!I", sid))
                except Exception:
                    pass
                if not writer.is_closing():
                    writer.close()
        srv = await asyncio.start_server(on_accept, "0.0.0.0", gport)
        print(f"[tcp] proxy listening 0.0.0.0:{gport} (point game at this PC)", flush=True)
        async with srv:
            await srv.serve_forever()

    async def udp_setup(self):
        loop = asyncio.get_running_loop()
        # tunnel socket (ephemeral)
        tsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tsock.bind(("0.0.0.0", 0))
        tsock.setblocking(False)
        self.udp_tun_proto = QueueProto()
        self.udp_tun, _ = await loop.create_datagram_endpoint(
            lambda: self.udp_tun_proto, sock=tsock)
        asyncio.create_task(self.udp_tun_read())
        # local game listeners
        for gport in self.udp_ports:
            try:
                lsock = make_reuse_udp("0.0.0.0", gport)
            except OSError as e:
                print(f"[udp] bind 0.0.0.0:{gport} failed: {e}", flush=True)
                continue
            proto = QueueProto()
            transport, _ = await loop.create_datagram_endpoint(lambda: proto, sock=lsock)
            self.udp_local[gport] = (transport, proto)
            asyncio.create_task(self.udp_local_read(gport, transport, proto))
            print(f"[udp] proxy 0.0.0.0:{gport} -> {self.server_ip}:{self.port}", flush=True)

    async def udp_local_read(self, gport, _transport, proto):
        rport = self.udp_remote.get(gport, gport)
        while True:
            raw, addr = await proto.q.get()
            pkt = encode_udp_game(U_GAME_C2S, rport, addr[0], addr[1], raw)
            try:
                self.udp_tun.sendto(pkt, (self.server_ip, self.port))
            except OSError:
                pass

    async def udp_tun_read(self):
        # tunnel replies carry REMOTE port; map back to local listen port
        rev_udp = {v: k for k, v in self.udp_remote.items()}
        loop = asyncio.get_running_loop()
        while True:
            data, addr = await self.udp_tun_proto.q.get()
            dec = decode_udp_game(data)
            if not dec:
                continue
            mtype, gport, cip, cport, raw = dec
            if mtype == U_GAME_S2C:
                local = rev_udp.get(gport, gport)
                loc = self.udp_local.get(local)
                if not loc:
                    continue
                transport, _proto = loc
                try:
                    transport.sendto(raw, (cip, cport))
                except OSError:
                    pass
            elif mtype == U_GAME_C2S:
                # inbound: another player's datagram for our local game
                await self.udp_host_recv(gport, cip, cport, raw, addr, loop)

    async def udp_host_recv(self, gport, cip, cport, raw, tunnel_addr, loop):
        rev_udp = {v: k for k, v in self.udp_remote.items()}
        local = rev_udp.get(gport, gport)
        key = (tunnel_addr, local, cip, cport)
        s = self.udp_host_socks.get(key)
        if s is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            s.bind(("0.0.0.0", 0))
            self.udp_host_socks[key] = s
            asyncio.create_task(self.udp_host_readloop(key, s, local, loop))
        try:
            await loop.sock_sendto(s, raw, ("127.0.0.1", local))
        except OSError:
            pass

    def _unmap_udp(self, local):
        """Local port -> remote (real) game port for tunnel replies."""
        for lcl, rmt in self.udp_remote.items():
            if lcl == local:
                return rmt
        return local

    async def udp_host_readloop(self, key, s, local, loop):
        _tunnel, _port, cip, cport = key
        remote = self._unmap_udp(local)
        while True:
            try:
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(s, 65535), timeout=30)
            except asyncio.TimeoutError:
                break
            except (asyncio.CancelledError, OSError):
                break
            pkt = encode_udp_game(U_GAME_S2C, remote, cip, cport, data)
            try:
                self.udp_tun.sendto(pkt, (self.server_ip, self.port))
            except (OSError, AttributeError):
                break
        self.udp_host_socks.pop(key, None)
        s.close()

    def send_udp_hello(self):
        if not self.udp_tun:
            return
        try:
            self.udp_tun.sendto(encode_udp_hello(self.token),
                                (self.server_ip, self.port))
        except OSError:
            pass

    def udp_port(self):
        try:
            t = self.udp_tun
            if t is None:
                return 0
            s = t.get_extra_info("socket")
            if s is None:
                return 0
            return s.getsockname()[1]
        except OSError:
            return 0

    def send_udp_node(self):
        if not self.udp_tun:
            return
        try:
            self.udp_tun.sendto(
                encode_udp_node(self.token, self.node_id, self.udp_port()),
                (self.server_ip, self.port))
        except OSError:
            pass

    async def send_tcp_node(self):
        try:
            await self.tcp_send(
                T_NODE, encode_node(self.token, self.node_id, self.udp_port()))
        except (ConnectionResetError, BrokenPipeError, RuntimeError,
                AttributeError):
            pass

    async def hello_loop(self):
        n = 0
        while True:
            self.send_udp_node()
            if self.host_mode:
                self.send_udp_hello()
            if n % 2 == 0:
                await self.send_tcp_node()  # refresh mapping ~60s
            n += 1
            await asyncio.sleep(30)

    async def run(self):
        backoff = 1
        live = set()  # per-connection child tasks (also reaped on teardown)
        try:
            while True:
                cycle_t0 = time.monotonic()
                try:
                    print(f"[peer] dialing {self.server_ip}:{self.port} (TCP) ...", flush=True)
                    reader, writer = await asyncio.open_connection(self.server_ip, self.port)
                except OSError as e:
                    print(f"[peer] dial failed: {e}, retry {backoff}s", flush=True)
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 10)
                    continue
                print("[peer] TCP connected", flush=True)
                backoff = 1
                self.tcp_writer = writer
                self.local_tcp.clear()
                if self.host_mode:
                    try:
                        await self.tcp_send(T_HELLO, encode_hello(self.token))
                    except (ConnectionResetError, BrokenPipeError, RuntimeError):
                        try:
                            writer.close()
                        except Exception:
                            pass
                        self.tcp_writer = None
                        continue
                await self.send_tcp_node()  # register node (+real UDP port later)
                tasks = [asyncio.create_task(self.tcp_reader_loop(reader))]
                for d in self.disc_ports:
                    tasks.append(asyncio.create_task(self.bcast_snoop(d)))
                if not self.host_mode:
                    for g in self.tcp_ports:
                        tasks.append(asyncio.create_task(self.tcp_local_listener(g)))
                tasks.append(asyncio.create_task(self.hello_loop()))
                live.update(tasks)
                if (self.udp_ports or self.host_mode) and self.udp_tun is None:
                    await self.udp_setup()
                    await self.send_tcp_node()  # re-announce with real UDP port
                # wait until TCP drops; listeners die with it
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                live.difference_update(tasks)
            try:
                writer.close()
            except Exception:
                pass
            self.tcp_writer = None
            if self.udp_tun:
                try:
                    self.udp_tun.close()
                except Exception:
                    pass
                self.udp_tun = None
                self.udp_tun_proto = None
                # clear locals too; they will rebind (REUSEADDR ok)
                for tr, _ in self.udp_local.values():
                    try:
                        tr.close()
                    except Exception:
                        pass
                self.udp_local = {}
            print("[peer] disconnected, reconnecting...", flush=True)
            if time.monotonic() - cycle_t0 < 1.0:
                await asyncio.sleep(1.0)  # instant failure (e.g. bind clash): don't hot-loop
        finally:
            # external teardown: close the link (unblocks the reader) and
            # reap children so no listeners/transports leak past us
            if self.tcp_writer is not None:
                try:
                    self.tcp_writer.close()
                except Exception:
                    pass
                self.tcp_writer = None
            for tr, _ in self.udp_local.values():
                try:
                    tr.close()
                except Exception:
                    pass
            self.udp_local = {}
            if self.udp_tun:
                try:
                    self.udp_tun.close()
                except Exception:
                    pass
                self.udp_tun = None
                self.udp_tun_proto = None
            for t in list(live):
                if not t.done():
                    t.cancel()
            if live:
                await asyncio.gather(*live, return_exceptions=True)


def main():
    ap = argparse.ArgumentParser(description="Windows LAN-coop client (no TUN/TAP)")
    ap.add_argument("--server", required=True, help="host public IP (specific IP)")
    ap.add_argument("--port", type=int, required=True, help="host public port (TCP+UDP, same number)")
    ap.add_argument("--disc", default="", help="discovery UDP ports, comma (same as host)")
    ap.add_argument("--tcp", default="", help="game TCP ports, comma")
    ap.add_argument("--udp", default="", help="game UDP ports, comma")
    ap.add_argument("--rebroadcast-ip", default="255.255.255.255")
    ap.add_argument("--host", action="store_true",
                    help="bridge mode: serve inbound relay traffic to the LOCAL game "
                         "(this PC hosts); skips proxy listeners")
    ap.add_argument("--token", default="",
                    help="room key: must match relay --token (empty = open relay)")
    a = ap.parse_args()

    c = WinClient(a.server, a.port, parse_ports(a.disc), parse_ports(a.tcp),
                  parse_ports(a.udp), a.rebroadcast_ip,
                  host_mode=a.host, token=a.token)
    try:
        asyncio.run(c.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
