#!/usr/bin/env python3
"""ShadowLAN symmetric client (Windows + Linux). Runs next to the game. No TUN/TAP, no driver.

Connects to ONE specific IP:port on the relay:
  TCP server_ip:port -> control (membership, beacons) + one conn per stream
  UDP server_ip:port -> game-UDP

Each game TCP stream is its own TCP connection to the
relay (both ends dial out, NAT-safe); the relay pipes raw bytes once the
destination has bridged to its local game (T_STOPEN -> T_STREQ -> T_STJOIN
-> T_STJOINED -> T_STOK). connect() only completes after that handshake.

Player mode (default) per game (ports from CLI):
- Snoops local discovery broadcasts with SO_REUSEADDR (gets a copy
  without disturbing the game), forwards to relay over TCP.
- Re-broadcasts relay discoveries locally to 255.255.255.255 so the
  broadcast-only game sees "LAN" servers. The game then connects to
  this PC's IP, which is our local proxy.
- Listens on game TCP/UDP ports locally, tunnels to relay.

Host mode (--host): bridges inbound relay traffic to the LOCAL game
instead (this PC hosts); skips proxy listeners. Either mode registers
a node id for virtual-IP P2P mesh play.

Notes:
- Stdlib only, no admin. Allow Python through the firewall once.
- If bind fails with 10013 on Windows (game uses exclusive bind), use
  the hook instead; most Unity/Unreal/classic LAN titles use reusable binds.
"""
import argparse
import asyncio
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
    HDR,
    T_BCAST, T_BCAST_FROM, T_NODE, NODE_F_HOST,
    T_STREQ, T_STJOIN, T_STJOINED, T_STOK, T_STFAIL, T_STOPEN,
    STF_HOST_FAILED,
    U_GAME_C2S, U_GAME_S2C, U_NODE,
    U_ICMP_REQ, U_ICMP_REP, UMAGIC, UVER,
    QueueProto,
    decode_udp_game, encode_udp_game,
    encode_ctl_node, encode_udp_node, decode_bcast_from, decode_icmp, encode_icmp,
    encode_stjoin, encode_stsid, encode_stfail, encode_stopen,
    make_reuse_udp, parse_ports, tcp_read, tcp_send, ST_TIMEOUT_S,
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
        self.tcp_writer = None
        self.send_lock = asyncio.Lock()
        # persistent broadcast socket (lazy): one socket for all re-emits,
        # so our own source port is stable and the snoop can ignore it
        # without a cache (see _own_echo)
        self.bcast_sock = None
        self.bcast_port = 0
        self._route_ip = None
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

    def _bcast_socket(self):
        if self.bcast_sock is None:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                except OSError:
                    pass
                s.bind(("0.0.0.0", 0))
                self.bcast_sock = s
                try:
                    self.bcast_port = s.getsockname()[1]
                except OSError:
                    self.bcast_port = 0
            except OSError as e:
                print(f"[bcast] socket failed: {e}", flush=True)
                return None
        return self.bcast_sock

    def _close_bcast(self):
        s, self.bcast_sock = self.bcast_sock, None
        self.bcast_port = 0
        if s is not None:
            try:
                s.close()
            except OSError:
                pass

    def _own_echo(self, addr):
        # Is this snooped packet our own re-emit coming back? Decidable
        # without a cache: our re-emits all leave from one stable source
        # port. The local-IP check keeps a remote game that happens to
        # share the port number from ever looking like us.
        try:
            if not self.bcast_port or addr[1] != self.bcast_port:
                return False
        except (IndexError, TypeError):
            return False
        ip = addr[0]
        if ip == "127.0.0.1":
            return True
        if self._route_ip is None:
            try:
                t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                t.connect((self.server_ip, self.port))
                self._route_ip = t.getsockname()[0]
                t.close()
            except OSError:
                self._route_ip = ""
        return bool(self._route_ip) and ip == self._route_ip

    def rebroadcast(self, disc_port, raw):
        dst_ip, dst_port = self.rebroadcast_ip, disc_port
        if self.rebroadcast_to:
            from common import parse_hostport
            dst_ip, dst_port = parse_hostport(self.rebroadcast_to, disc_port)
        s = self._bcast_socket()
        if s is None:
            return
        try:
            s.sendto(raw, (dst_ip, dst_port))
        except OSError:
            # socket died under us (rare): rebuild once and retry
            self._close_bcast()
            s = self._bcast_socket()
            if s is None:
                return
            try:
                s.sendto(raw, (dst_ip, dst_port))
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
            raw, addr = await proto.q.get()
            if self._own_echo(addr):
                continue
            if self.tcp_writer:
                try:
                    await self.tcp_send(T_BCAST,
                              struct.pack("!HH", disc_port, disc_port) + raw)
                except (ConnectionResetError, BrokenPipeError, RuntimeError):
                    pass

    async def tcp_reader_loop(self, reader):
        try:
            while True:
                mtype, payload = await tcp_read(reader)
                if mtype == T_BCAST:
                    if len(payload) < 4:
                        continue
                    (dport,) = struct.unpack("!H", payload[:2])
                    raw = payload[4:]
                    self.rebroadcast(dport, raw)
                elif mtype == T_BCAST_FROM:
                    # attributed beacon from another node; source faking
                    # needs the hook, wclient just re-emits the payload
                    dec = decode_bcast_from(payload)
                    if not dec:
                        continue
                    _node, dport, _sport, raw = dec
                    self.rebroadcast(dport, raw)
                elif mtype == T_STREQ:
                    # another player is joining a port we serve
                    if len(payload) < 6:
                        continue
                    sid, gport = struct.unpack("!IH", payload[:6])
                    asyncio.create_task(self.stream_join(sid, gport))
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass

    async def pipe_stream(self, ra, wa, rb, wb, tag):
        """Raw bidirectional pipe between two (reader, writer) pairs."""
        async def pump(src, dst):
            try:
                while True:
                    d = await src.read(65536)
                    if not d:
                        break
                    dst.write(d)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, RuntimeError):
                pass
        t1 = asyncio.create_task(pump(ra, wb))
        t2 = asyncio.create_task(pump(rb, wa))
        try:
            await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t1, t2):
                t.cancel()
            await asyncio.gather(t1, t2, return_exceptions=True)
            for w in (wa, wb):
                try:
                    if not w.is_closing():
                        w.close()
                except Exception:
                    pass
            print(f"[stream] {tag} closed", flush=True)

    async def stream_join(self, sid, gport):
        """Joinee side: per-stream TCP to the relay, join, bridge to the
        local game, T_STJOINED, then raw pipe (handshake guarantees the
        bridge exists before the opener's connect() can succeed)."""
        rev_tcp = {v: k for k, v in self.tcp_remote.items()}
        lport = rev_tcp.get(gport, gport)
        try:
            sreader, swriter = await asyncio.wait_for(
                asyncio.open_connection(self.server_ip, self.port),
                timeout=ST_TIMEOUT_S)
        except (OSError, asyncio.TimeoutError) as e:
            print(f"[stream] join {sid}: relay dial failed: {e}", flush=True)
            return
        try:
            swriter.write(HDR.pack(1 + 8) + bytes([T_STJOIN])
                          + encode_stjoin(self.node_id, sid))
            await swriter.drain()
            # claim verdict first: a sibling process sharing this node id
            # may win; stand down BEFORE bridging so the game port is
            # touched by exactly one process.
            _hdr = await asyncio.wait_for(sreader.readexactly(4),
                                          timeout=ST_TIMEOUT_S)
            (mlen,) = HDR.unpack(_hdr)
            _body = await asyncio.wait_for(sreader.readexactly(mlen),
                                           timeout=ST_TIMEOUT_S)
            if _body[0] != T_STOK:
                print(f"[stream] join {sid}: claim refused "
                      f"(op {_body[0]:#x}) - sibling serves it", flush=True)
                swriter.close()
                return
            local = None
            for _ in range(4):
                try:
                    local = await asyncio.open_connection("127.0.0.1", lport)
                    break
                except OSError:
                    await asyncio.sleep(0.25)
            if local is None:
                swriter.write(HDR.pack(1 + 5) + bytes([T_STFAIL])
                              + encode_stfail(sid, STF_HOST_FAILED))
                await swriter.drain()
                print(f"[stream] join {sid}: local dial 127.0.0.1:{lport} failed",
                      flush=True)
                swriter.close()
                return
            lr, lw = local
            swriter.write(HDR.pack(1 + 4) + bytes([T_STJOINED])
                          + encode_stsid(sid))
            await swriter.drain()
            print(f"[stream] hosted {sid} -> 127.0.0.1:{lport}", flush=True)
            await self.pipe_stream(sreader, swriter, lr, lw, f"join {sid}")
        except (asyncio.IncompleteReadError, ConnectionResetError,
                BrokenPipeError, RuntimeError):
            pass
        finally:
            try:
                swriter.close()
            except Exception:
                pass

    async def tcp_local_listener(self, gport):
        rport = self.tcp_remote.get(gport, gport)

        async def on_accept(reader, writer):
            sid = random.getrandbits(32) or 1
            print(f"[stream] local game -> open {sid} (:{gport}=>{rport})", flush=True)
            try:
                sreader, swriter = await asyncio.wait_for(
                    asyncio.open_connection(self.server_ip, self.port),
                    timeout=ST_TIMEOUT_S)
                swriter.write(HDR.pack(1 + 14) + bytes([T_STOPEN])
                              + encode_stopen(self.node_id, 0, sid, rport))
                await swriter.drain()
                # handshake: relay confirms the destination bridged its
                # local game before the connect() may complete
                _hdr = await asyncio.wait_for(sreader.readexactly(4),
                                              timeout=ST_TIMEOUT_S)
                (mlen,) = HDR.unpack(_hdr)
                body = await asyncio.wait_for(sreader.readexactly(mlen),
                                              timeout=ST_TIMEOUT_S)
                if body[0] != T_STOK:
                    print(f"[stream] open {sid}: refused (op {body[0]:#x})",
                          flush=True)
                    swriter.close()
                    writer.close()
                    return
                print(f"[stream] open {sid} -> :{rport}", flush=True)
                await self.pipe_stream(sreader, swriter, reader, writer,
                                       f"open {sid}")
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError,
                    ConnectionResetError, BrokenPipeError, RuntimeError) as e:
                print(f"[stream] open {sid}: failed: {e}", flush=True)
                try:
                    writer.close()
                except Exception:
                    pass
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
            if len(data) >= 4 and data[:2] == UMAGIC and data[2] == UVER \
                    and data[3] in (U_ICMP_REQ, U_ICMP_REP):
                await self.icmp_tun_recv(data, addr)
                continue
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

    async def icmp_tun_recv(self, data, addr):
        """Answer pings to our own node; drop anything else.

        wclient never initiates ICMP (local ping capture needs raw
        privileges the bridge deliberately avoids); it only answers so
        the mesh stays consistent when a hooked peer pings this node."""
        dec = decode_icmp(data)
        if not dec:
            return
        mtype, _src, dest, iid, seq, idata = dec
        if mtype != U_ICMP_REQ or dest != self.node_id:
            return
        try:
            self.udp_tun.sendto(
                encode_icmp(U_ICMP_REP, self.node_id, _src, iid, seq, idata),
                (self.server_ip, self.port))
        except (OSError, AttributeError):
            pass

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
                encode_udp_node(self.token, self.node_id, self.udp_port(),
                                NODE_F_HOST if self.host_mode else 0),
                (self.server_ip, self.port))
        except OSError:
            pass

    async def send_tcp_node(self):
        try:
            await self.tcp_send(
                T_NODE, encode_ctl_node(self.token, self.node_id,
                                        self.udp_port(),
                                        NODE_F_HOST if self.host_mode else 0))
        except (ConnectionResetError, BrokenPipeError, RuntimeError,
                AttributeError):
            pass

    async def hello_loop(self):
        n = 0
        while True:
            self.send_udp_node()
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
                # one frame does it all: identity + endpoint (+ host flag)
                await self.send_tcp_node()
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
            self._close_bcast()
            for t in list(live):
                if not t.done():
                    t.cancel()
            if live:
                await asyncio.gather(*live, return_exceptions=True)


def main():
    ap = argparse.ArgumentParser(description="ShadowLAN symmetric client (no TUN/TAP)")
    ap.add_argument("--server", required=True, help="relay public IP (specific IP)")
    ap.add_argument("--port", type=int, required=True, help="relay public port (TCP+UDP, same number)")
    ap.add_argument("--disc", default="", help="discovery UDP ports to snoop, comma")
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
    print(f"[cfg] wclient server={a.server}:{a.port} "
          f"token={'set' if a.token else 'open'} "
          f"mode={'host' if a.host else 'player'} disc={a.disc or '-'} "
          f"tcp={a.tcp or '-'} udp={a.udp or '-'} "
          f"rebroadcast={a.rebroadcast_ip}", flush=True)
    try:
        asyncio.run(c.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
