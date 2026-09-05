"""Shared framing + socket helpers. Stdlib only, Windows + Linux."""
import asyncio
import socket
import struct
import time

# TCP stream framing: [u32 len][u8 type][payload]
HDR = struct.Struct("!I")
T_BCAST = 0x01        # payload: !H disc_port + raw
T_TCP_OPEN = 0x10     # payload: !I stream_id + !H game_port
T_TCP_DATA_C2S = 0x11 # payload: !I stream_id + raw
T_TCP_DATA_S2C = 0x12 # payload: !I stream_id + raw
T_TCP_CLOSE = 0x13    # payload: !I stream_id

# UDP tunnel datagrams: MAGIC + VER + TYPE + payload
UMAGIC = b"VN"
UVER = 0x01
U_GAME_C2S = 0x01
U_GAME_S2C = 0x02
# payload both dirs: !H game_port + !H iplen + ip + !H port + raw


def parse_ports(s):
    if not s:
        return []
    if isinstance(s, (list, tuple)):
        return [int(x) for x in s]
    return [int(p) for p in str(s).split(",") if p.strip()]


def parse_hostport(s, default_port):
    s = s.strip()
    if s.startswith("["):
        h, _, rest = s[1:].partition("]")
        rest = rest.lstrip(":")
        return h, int(rest) if rest else default_port
    if ":" in s:
        h, p = s.rsplit(":", 1)
        try:
            return h or "0.0.0.0", int(p)
        except ValueError:
            pass
    return s, default_port


def make_reuse_udp(bind_ip, port):
    """UDP socket, REUSEADDR (+REUSEPORT where avail), BROADCAST.

    On Windows REUSEADDR lets game + relay co-bind the same discovery/
    game UDP port and both receive broadcast copies. No driver, no admin.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError:
        pass
    s.bind((bind_ip, port))
    s.setblocking(False)
    return s


class Dedup:
    """Drop our own re-broadcast echoes / loops (2s window)."""
    def __init__(self, window=2.0):
        self.window = window
        self.seen = {}

    def hit(self, key: bytes) -> bool:
        now = time.monotonic()
        for k, exp in list(self.seen.items()):
            if exp < now:
                del self.seen[k]
        if key in self.seen:
            return True
        self.seen[key] = now + self.window
        return False


class QueueProto(asyncio.DatagramProtocol):
    def __init__(self):
        self.q = asyncio.Queue()

    def datagram_received(self, data, addr):
        self.q.put_nowait((data, addr))


async def udp_endpoint(loop, sock):
    """Wrap a pre-configured socket in a Datagram transport (Win-safe)."""
    proto = QueueProto()
    transport, _ = await loop.create_datagram_endpoint(lambda: proto, sock=sock)
    return transport, proto


def encode_udp_game(mtype, game_port, cli_ip, cli_port, raw):
    ipb = cli_ip.encode()
    return (UMAGIC + bytes([UVER, mtype])
            + struct.pack("!HH", game_port, len(ipb)) + ipb
            + struct.pack("!H", cli_port) + raw)


def decode_udp_game(data):
    if len(data) < 6 or data[:2] != UMAGIC or data[2] != UVER:
        return None
    mtype = data[3]
    try:
        game_port, iplen = struct.unpack("!HH", data[4:8])
        ip = data[8:8 + iplen].decode()
        cport = struct.unpack("!H", data[8 + iplen:10 + iplen])[0]
        raw = data[10 + iplen:]
    except (struct.error, UnicodeDecodeError, IndexError):
        return None
    return mtype, game_port, ip, cport, raw


async def tcp_send(writer, mtype, payload: bytes):
    body = bytes([mtype]) + payload
    writer.write(HDR.pack(len(body)) + body)
    await writer.drain()


async def tcp_read(reader):
    hdr = await reader.readexactly(HDR.size)
    (mlen,) = HDR.unpack(hdr)
    if mlen < 1 or mlen > 8 * 1024 * 1024:
        raise ValueError(f"bad frame len {mlen}")
    body = await reader.readexactly(mlen)
    return body[0], body[1:]
