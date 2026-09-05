#!/usr/bin/env python3
"""Host side. Runs next to the game server (Linux or Windows).

Listens on ONE public port number for both protocols:
  TCP 0.0.0.0:P  -> discovery broadcast + game-TCP streams (multiplexed)
  UDP 0.0.0.0:P  -> game-UDP datagrams (low latency, stays UDP)

No TUN/TAP, no virtual NIC, no driver.
Discovery is snooped with SO_REUSEADDR socket shadowing (Windows delivers
a broadcast copy to every bound socket), then forwarded over TCP.
Game TCP is proxied to 127.0.0.1:G-TCP, game UDP to 127.0.0.1:G-UDP.

Port-forward TCP+P/UDP+P on the router (or allow in firewall if the
public IP is directly on this machine). Client connects to IP:P.
"""
import argparse
import asyncio
import hashlib
import socket
import struct

from common import (
    T_BCAST, T_TCP_OPEN, T_TCP_DATA_C2S, T_TCP_DATA_S2C, T_TCP_CLOSE,
    U_GAME_C2S, U_GAME_S2C, Dedup, QueueProto,
    decode_udp_game, encode_udp_game, make_reuse_udp,
    parse_ports, tcp_read, tcp_send,
)


class Host:
    def __init__(self, port, disc_ports, target="127.0.0.1",
                 rebroadcast_ip="255.255.255.255", allowed_tcp=None,
                 allowed_udp=None):
        self.port = port
        self.disc_ports = disc_ports
        self.target = target
        self.rebroadcast_ip = rebroadcast_ip
        self.allowed_tcp = set(allowed_tcp or [])
        self.allowed_udp = set(allowed_udp or [])
        self.tcp_clients = set()
        self.dedup = Dedup()
        # (tunnel_addr, game_port, cli_ip, cli_port) -> (transport, proto, task)
        self.udp_sessions = {}
        self._public_udp = None
        self.game_writers = {}
        self.pending_tcp = {}  # (owner, sid) -> bytearray buffered before dial
        self.send_locks = {}  # id(writer) -> asyncio.Lock

    async def hs_send(self, writer, mtype, payload):
        lock = self.send_locks.setdefault(id(writer), asyncio.Lock())
        async with lock:
            await tcp_send(writer, mtype, payload)

    def local_rebroadcast(self, disc_port, raw):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(raw, (self.rebroadcast_ip, disc_port))
            s.close()
        except OSError as e:
            print(f"[bcast] re-emit failed: {e}", flush=True)

    async def bcast_snoop(self, disc_port):
        loop = asyncio.get_running_loop()
        try:
            sock = make_reuse_udp("0.0.0.0", disc_port)
        except OSError as e:
            print(f"[bcast] bind 0.0.0.0:{disc_port} failed: {e}", flush=True)
            return
        proto = QueueProto()
        await loop.create_datagram_endpoint(lambda: proto, sock=sock)
        print(f"[bcast] snooping 0.0.0.0:{disc_port} (REUSEADDR, no driver)", flush=True)
        while True:
            raw, _ = await proto.q.get()
            key = hashlib.sha256(b"B" + struct.pack("!H", disc_port) + raw).digest()
            if self.dedup.hit(key):
                continue
            for w in list(self.tcp_clients):
                try:
                    await self.hs_send(w, T_BCAST, struct.pack("!H", disc_port) + raw)
                except (ConnectionResetError, BrokenPipeError, RuntimeError):
                    pass

    async def handle_tcp_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        print(f"[tcp] client {peer} connected", flush=True)
        self.tcp_clients.add(writer)
        self.send_locks.setdefault(id(writer), asyncio.Lock())
        owner = id(writer)
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
                    self.local_rebroadcast(dport, raw)
                elif mtype == T_TCP_OPEN:
                    sid, gport = struct.unpack("!IH", payload[:6])
                    if self.allowed_tcp and gport not in self.allowed_tcp:
                        try:
                            await self.hs_send(writer, T_TCP_CLOSE, struct.pack("!I", sid))
                        except Exception:
                            pass
                        continue
                    asyncio.create_task(self.dial_game(owner, sid, gport, writer))
                elif mtype == T_TCP_DATA_C2S:
                    sid = struct.unpack("!I", payload[:4])[0]
                    gw = self.game_writers.get((owner, sid))
                    if gw and not gw.is_closing():
                        gw.write(payload[4:])
                        try:
                            await gw.drain()
                        except (ConnectionResetError, BrokenPipeError):
                            pass
                    else:
                        # dial not ready yet: buffer early data (OPEN/DATA race)
                        self.pending_tcp.setdefault((owner, sid), bytearray()).extend(payload[4:])
                elif mtype == T_TCP_CLOSE:
                    sid = struct.unpack("!I", payload[:4])[0]
                    self.pending_tcp.pop((owner, sid), None)
                    gw = self.game_writers.pop((owner, sid), None)
                    if gw and not gw.is_closing():
                        gw.close()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            self.tcp_clients.discard(writer)
            self.send_locks.pop(owner, None)
            for (o, sid), gw in list(self.game_writers.items()):
                if o == owner:
                    if not gw.is_closing():
                        gw.close()
                    self.game_writers.pop((o, sid), None)
            for (o, _sid) in list(self.pending_tcp.keys()):
                if o == owner:
                    self.pending_tcp.pop((o, _sid), None)
            try:
                writer.close()
            except Exception:
                pass
            print(f"[tcp] client {peer} gone", flush=True)

    async def dial_game(self, owner, sid, gport, client_writer):
        try:
            gr, gw = await asyncio.open_connection(self.target, gport)
        except OSError as e:
            print(f"[tcp] dial {self.target}:{gport} failed: {e}", flush=True)
            self.pending_tcp.pop((owner, sid), None)
            try:
                await self.hs_send(client_writer, T_TCP_CLOSE, struct.pack("!I", sid))
            except Exception:
                pass
            return
        # flush early data that arrived before dial completed
        early = self.pending_tcp.pop((owner, sid), None)
        if early:
            gw.write(bytes(early))
            try:
                await gw.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass
        self.game_writers[(owner, sid)] = gw
        print(f"[tcp] stream {sid} -> {self.target}:{gport}", flush=True)
        try:
            while True:
                chunk = await gr.read(65536)
                if not chunk:
                    break
                await self.hs_send(client_writer, T_TCP_DATA_S2C, struct.pack("!I", sid) + chunk)
        except (ConnectionResetError, BrokenPipeError, RuntimeError):
            pass
        finally:
            self.game_writers.pop((owner, sid), None)
            self.pending_tcp.pop((owner, sid), None)
            if not gw.is_closing():
                gw.close()
            try:
                await self.hs_send(client_writer, T_TCP_CLOSE, struct.pack("!I", sid))
            except Exception:
                pass

    async def udp_consume(self, pproto):
        while True:
            data, addr = await pproto.q.get()
            dec = decode_udp_game(data)
            if not dec:
                continue
            mtype, gport, cip, cport, raw = dec
            if mtype != U_GAME_C2S:
                continue
            if self.allowed_udp and gport not in self.allowed_udp:
                continue
            key = (addr, gport, cip, cport)
            sess = self.udp_sessions.get(key)
            if sess is None:
                sess = await self.new_udp_session(key)
                self.udp_sessions[key] = sess
            transport = sess[0]
            try:
                transport.sendto(raw, (self.target, gport))
            except OSError:
                pass

    async def new_udp_session(self, key):
        loop = asyncio.get_running_loop()
        _tunnel, gport, cip, cport = key
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 0))
        s.setblocking(False)
        proto = QueueProto()
        transport, _ = await loop.create_datagram_endpoint(lambda: proto, sock=s)
        task = asyncio.create_task(self.udp_session_read(key, transport, proto))
        return transport, proto, task

    async def udp_session_read(self, key, transport, proto):
        tunnel_addr, gport, cip, cport = key
        try:
            while True:
                try:
                    raw, _ = await asyncio.wait_for(proto.q.get(), timeout=45)
                except asyncio.TimeoutError:
                    break
                pkt = encode_udp_game(U_GAME_S2C, gport, cip, cport, raw)
                try:
                    self._public_udp.sendto(pkt, tunnel_addr)
                except (OSError, AttributeError):
                    break
        except asyncio.CancelledError:
            pass
        finally:
            self.udp_sessions.pop(key, None)
            try:
                transport.close()
            except Exception:
                pass

    async def run(self):
        loop = asyncio.get_running_loop()
        psock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        psock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        psock.bind(("0.0.0.0", self.port))
        psock.setblocking(False)
        pproto = QueueProto()
        self._public_udp, _ = await loop.create_datagram_endpoint(lambda: pproto, sock=psock)
        print(f"[udp] public 0.0.0.0:{self.port}", flush=True)
        asyncio.create_task(self.udp_consume(pproto))
        srv = await asyncio.start_server(self.handle_tcp_client, "0.0.0.0", self.port)
        print(f"[tcp] public 0.0.0.0:{self.port}", flush=True)
        for d in self.disc_ports:
            asyncio.create_task(self.bcast_snoop(d))
        print(f"[up] host port={self.port} disc={self.disc_ports} target={self.target}", flush=True)
        async with srv:
            await srv.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="LAN-coop host (no TUN/TAP)")
    ap.add_argument("--port", type=int, required=True, help="public port number (TCP+UDP)")
    ap.add_argument("--disc", default="", help="discovery UDP ports, comma")
    ap.add_argument("--tcp", default="", help="allowed game TCP ports, comma (empty=all)")
    ap.add_argument("--udp", default="", help="allowed game UDP ports, comma (empty=all)")
    ap.add_argument("--target", default="127.0.0.1")
    ap.add_argument("--rebroadcast-ip", default="255.255.255.255")
    a = ap.parse_args()
    h = Host(a.port, parse_ports(a.disc), a.target, a.rebroadcast_ip,
             parse_ports(a.tcp), parse_ports(a.udp))
    try:
        asyncio.run(h.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
