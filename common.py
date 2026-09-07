"""Shared framing + socket helpers. Stdlib only, Windows + Linux."""
import asyncio
import socket
import struct

# TCP stream framing: [u32 len][u8 type][payload]
HDR = struct.Struct("!I")
VERSION = "1.1.0"

T_BCAST = 0x01        # payload: !H disc_port + !H src_port + raw (unattributed)
T_BCAST_FROM = 0x02   # relay->peer: !I src_node + !H disc_port + !H src_port + raw
T_TCP_OPEN = 0x10     # payload: !I stream_id + !H game_port (implicit route)
T_TCP_DATA_C2S = 0x11 # payload: !I stream_id + raw
T_TCP_DATA_S2C = 0x12 # payload: !I stream_id + raw
T_TCP_CLOSE = 0x13    # payload: !I stream_id
T_HELLO = 0x20        # payload: !H token_len + token (designated-host claim)
T_NODE = 0x22         # payload: !H tlen + token + !I node_id + !H udp_port
T_ASSIGN = 0x23       # relay->peer: !I my_virt + !I net + !B bits + !H n + n*(!I node + !I virt)
T_POPEN = 0x24        # payload: !I sid + !I dest_node + !H port (P2P open)

# UDP tunnel datagrams: MAGIC + VER + TYPE + payload
UMAGIC = b"VN"
UVER = 0x01
U_GAME_C2S = 0x01
U_GAME_S2C = 0x02
U_GAME_P2P = 0x12  # payload: !I dest_node + std triple+raw
U_ICMP_REQ = 0x20  # payload: !I src_node + !I dest_node + !H id + !H seq + data (0 = relay)
U_ICMP_REP = 0x21  # payload: !I src_node + !I dest_node + !H id + !H seq + data
U_HELLO_HOST = 0x10  # payload: !H token_len + token (host UDP heartbeat)
U_NODE = 0x11        # payload: !H tlen + token + !I node_id + !H udp_port
# game payload both dirs: !H game_port + !H iplen + ip + !H port + raw


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


class QueueProto(asyncio.DatagramProtocol):
    def __init__(self):
        self.q = asyncio.Queue()

    def datagram_received(self, data, addr):
        self.q.put_nowait((data, addr))


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


def encode_hello(token: bytes) -> bytes:
    return struct.pack("!H", len(token)) + token


def decode_hello(payload: bytes):
    """TCP HELLO frame payload -> token bytes, or None if malformed."""
    try:
        if len(payload) < 2:
            return None
        (n,) = struct.unpack("!H", payload[:2])
        if len(payload) != 2 + n:
            return None
        return payload[2:]
    except struct.error:
        return None


def encode_udp_hello(token: bytes) -> bytes:
    return UMAGIC + bytes([UVER, U_HELLO_HOST]) + encode_hello(token)


def decode_udp_hello(data):
    """Full UDP HELLO datagram -> token bytes, or None."""
    if len(data) < 6 or data[:2] != UMAGIC or data[2] != UVER:
        return None
    if data[3] != U_HELLO_HOST:
        return None
    return decode_hello(data[4:])


def encode_node(token: bytes, node: int, udp_port: int) -> bytes:
    return struct.pack("!H", len(token)) + token \
        + struct.pack("!IH", node & 0xFFFFFFFF, udp_port & 0xFFFF)


def decode_node(payload: bytes):
    """T_NODE / U_NODE payload -> (token, node_id, udp_port) or None."""
    try:
        if len(payload) < 2:
            return None
        (n,) = struct.unpack("!H", payload[:2])
        if len(payload) != 2 + n + 6:
            return None
        token = payload[2:2 + n]
        node, uport = struct.unpack("!IH", payload[2 + n:8 + n])
        return token, node, uport
    except struct.error:
        return None


def encode_udp_node(token: bytes, node: int, udp_port: int) -> bytes:
    return UMAGIC + bytes([UVER, U_NODE]) + encode_node(token, node, udp_port)


def decode_udp_node(data):
    if len(data) < 10 or data[:2] != UMAGIC or data[2] != UVER:
        return None
    if data[3] != U_NODE:
        return None
    return decode_node(data[4:])


def encode_assign(my_virt: int, net: int, bits: int, members) -> bytes:
    """members: iterable of (node_id, virt_ip_int)."""
    members = list(members)
    out = [struct.pack("!IIBH", my_virt & 0xFFFFFFFF, net & 0xFFFFFFFF,
                       bits & 0xFF, len(members))]
    for node, virt in members:
        out.append(struct.pack("!II", node & 0xFFFFFFFF, virt & 0xFFFFFFFF))
    return b"".join(out)


def decode_assign(payload: bytes):
    """T_ASSIGN payload -> (my_virt, net, bits, [(node, virt)]) or None."""
    try:
        if len(payload) < 11:
            return None
        my_virt, net, bits, n = struct.unpack("!IIBH", payload[:11])
        if len(payload) != 11 + 8 * n:
            return None
        members = []
        for i in range(n):
            node, virt = struct.unpack("!II", payload[11 + 8 * i:19 + 8 * i])
            members.append((node, virt))
        return my_virt, net, bits, members
    except struct.error:
        return None


def encode_popen(sid: int, dest_node: int, port: int) -> bytes:
    return struct.pack("!IIH", sid & 0xFFFFFFFF, dest_node & 0xFFFFFFFF,
                       port & 0xFFFF)


def decode_popen(payload: bytes):
    try:
        if len(payload) != 10:
            return None
        return struct.unpack("!IIH", payload)
    except struct.error:
        return None


def encode_pdat(dest_node: int, game_port: int, cli_ip: str, cli_port: int,
                raw: bytes) -> bytes:
    ipb = cli_ip.encode()
    return (UMAGIC + bytes([UVER, U_GAME_P2P])
            + struct.pack("!I", dest_node & 0xFFFFFFFF)
            + struct.pack("!HH", game_port, len(ipb)) + ipb
            + struct.pack("!H", cli_port) + raw)


def decode_pdat(data):
    """U_GAME_P2P datagram -> (dest_node, game_port, ip, port, raw)."""
    if len(data) < 10 or data[:2] != UMAGIC or data[2] != UVER:
        return None
    if data[3] != U_GAME_P2P:
        return None
    try:
        (dest,) = struct.unpack("!I", data[4:8])
        game_port, iplen = struct.unpack("!HH", data[8:12])
        ip = data[12:12 + iplen].decode()
        cport = struct.unpack("!H", data[12 + iplen:14 + iplen])[0]
        raw = data[14 + iplen:]
    except (struct.error, UnicodeDecodeError, IndexError):
        return None
    return dest, game_port, ip, cport, raw


def encode_icmp(mtype: int, src_node: int, dest_node: int,
                icmp_id: int, icmp_seq: int, data: bytes) -> bytes:
    return (UMAGIC + bytes([UVER, mtype])
            + struct.pack("!IIHH", src_node & 0xFFFFFFFF,
                          dest_node & 0xFFFFFFFF,
                          icmp_id & 0xFFFF, icmp_seq & 0xFFFF) + data)


def decode_icmp(data):
    """U_ICMP_REQ/REP datagram -> (mtype, src, dest, id, seq, data)."""
    if len(data) < 16 or data[:2] != UMAGIC or data[2] != UVER:
        return None
    if data[3] not in (U_ICMP_REQ, U_ICMP_REP):
        return None
    try:
        src, dest, iid, seq = struct.unpack("!IIHH", data[4:16])
    except struct.error:
        return None
    return data[3], src, dest, iid, seq, data[16:]


def encode_bcast_from(node: int, disc_port: int, src_port: int,
                      raw: bytes) -> bytes:
    return (struct.pack("!IHH", node & 0xFFFFFFFF, disc_port & 0xFFFF,
                        src_port & 0xFFFF) + raw)


def decode_bcast_from(payload: bytes):
    """Attributed beacon frame -> (node, disc_port, src_port, raw)."""
    try:
        if len(payload) < 8:
            return None
        node, dport, sport = struct.unpack("!IHH", payload[:8])
        return node, dport, sport, payload[8:]
    except struct.error:
        return None


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(v: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", v & 0xFFFFFFFF))


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
