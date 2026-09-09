"""Shared framing + socket helpers. Stdlib only, Windows + Linux.

Game TCP streams do not multiplex over the control TCP: each fake game
TCP connection is ONE real TCP connection to the relay, opened by the
hook/client itself (NAT-safe: both ends dial out). The relay pipes raw
bytes between the two per-stream connections. The control TCP carries
only registration (membership + role flags), discovery beacons and
(UDP-over-TCP) game datagrams.
"""
import asyncio
import socket
import struct

# TCP stream framing: [u32 len][u8 type][payload]
HDR = struct.Struct("!I")
VERSION = "1.1.0"

# ---- control-connection ops (one contiguous block) ----------------------
# Registration is a SINGLE frame: identity (node id), reachability (UDP
# endpoint) and role (host claim flag). There is no separate "hello":
# a claim without identity would be unroutable, and claims refresh with
# the keepalives anyway.
T_NODE = 0x01        # payload: !H tlen + token + !I node_id + !H udp_port + !B flags
T_ASSIGN = 0x02      # relay->peer: !I my_virt + !I net + !B bits + !H n + n*(!I node + !I virt) + !B link_id
T_BCAST = 0x03       # payload: !H disc_port + !H src_port + raw (unattributed)
T_BCAST_FROM = 0x04  # relay->peer: !I src_node + !H disc_port + !H src_port + raw
T_UDP_MODE = 0x05    # declare UDP-over-TCP mode for this link (empty payload)
T_UDP_TUN = 0x06     # TCP frame carrying one UDP-tunnel datagram (UDP-over-TCP mode)

# T_NODE/U_NODE flags bits:
NODE_F_HOST = 0x01   # this node hosts a game: claim designated-host

# ---- per-stream TCP ops (first frame(s) of a stream connection) ----------
# opener dials the relay, sends T_STOPEN; the relay asks the destination
# (T_STREQ on its CONTROL connection, to EVERY live link of the dest node
# -- process-tree identity means siblings race to serve); a destination
# process dials the relay and sends T_STJOIN, and the relay answers the
# claim ON THAT connection: T_STOK = first joiner, serve it; T_STFAIL
# (STF_BUSY) = a sibling already claimed, stand down WITHOUT bridging.
# The winner bridges to its local game and sends T_STJOINED; the relay
# then replies T_STOK to the opener and pipes raw bytes both ways.
T_STOPEN = 0x07   # opener->relay (per-stream TCP): !I node + !I dest_node + !I sid + !H gport
T_STREQ = 0x08    # relay->dest (control TCP): !I sid + !H gport
T_STJOIN = 0x09   # dest->relay (per-stream TCP): !I node + !I sid
T_STJOINED = 0x0A # dest->relay (per-stream TCP, local bridge up): !I sid
T_STOK = 0x0B     # relay->opener / relay->joinee (claim): !I sid
T_STFAIL = 0x0C   # relay->opener/joinee or dest->relay: !I sid + !B reason
STF_NO_ROUTE = 1  # destination node unknown / not connected / no host for port
STF_JOIN_TIMEOUT = 2  # destination never joined in time
STF_HOST_FAILED = 3  # destination could not reach its local game
STF_BAD_ID = 4    # joining node is not the stream's destination
STF_BUSY = 5      # stream id already in use

# Wire protocol version. Checked ONCE per node, at registration: the
# relay only assigns a vnode from T_NODE, and every later frame on the
# link plus every per-stream connection is routed by that node id -- so
# gating registration gates the whole session. UDP frames are
# connectionless and self-describing, so they carry UVER in every
# datagram header instead.
PVER = 0x02
UMAGIC = b"VN"
UVER = PVER
U_GAME_C2S = 0x01
U_GAME_S2C = 0x02
U_GAME_P2P = 0x03  # payload: !I dest_node + std triple+raw
U_NODE = 0x04        # payload: !H tlen + token + !I node_id + !H udp_port + !B flags
U_ICMP_REQ = 0x05  # payload: !I src_node + !I dest_node + !H id + !H seq + data (0 = relay)
U_ICMP_REP = 0x06  # same layout, reply
# game payload both dirs: !H game_port + !H iplen + ip + !H port + raw

# stream handshake budget (both sides + relay)
ST_TIMEOUT_S = 10.0


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


def encode_node(token: bytes, node: int, udp_port: int, flags: int = 0) -> bytes:
    return struct.pack("!H", len(token)) + token \
        + struct.pack("!IHB", node & 0xFFFFFFFF, udp_port & 0xFFFF, flags & 0xFF)


def decode_node(payload: bytes):
    """T_NODE / U_NODE payload -> (token, node_id, udp_port, flags) or None."""
    try:
        if len(payload) < 2:
            return None
        (n,) = struct.unpack("!H", payload[:2])
        if len(payload) != 2 + n + 7:
            return None
        token = payload[2:2 + n]
        node, uport, flags = struct.unpack("!IHB", payload[2 + n:9 + n])
        return token, node, uport, flags
    except struct.error:
        return None


# ---- TCP control registration frame: body + 1-byte leading protocol
# version (PVER). UDP carries UVER in the datagram header instead. ----

def ctl_ver(payload: bytes) -> int:
    return payload[0] if payload else 0


def encode_ctl_node(token: bytes, node: int, udp_port: int, flags: int = 0) -> bytes:
    return bytes([PVER]) + encode_node(token, node, udp_port, flags)


def decode_ctl_node(payload: bytes):
    return decode_node(payload[1:]) if ctl_ver(payload) == PVER else None


def encode_udp_node(token: bytes, node: int, udp_port: int, flags: int = 0) -> bytes:
    return UMAGIC + bytes([UVER, U_NODE]) + encode_node(token, node, udp_port, flags)


def decode_udp_node(data):
    if len(data) < 10 or data[:2] != UMAGIC or data[2] != UVER:
        return None
    if data[3] != U_NODE:
        return None
    return decode_node(data[4:])


def encode_assign(my_virt: int, net: int, bits: int, members,
                  link_id: int = 0) -> bytes:
    """members: iterable of (node_id, virt_ip_int). link_id is the
    MANDATORY per-LINK slot base index (1..255): hooks number
    client-socket marks as link_id*256 + slot across the full u16 space,
    so sibling links of one node never collide in the relay's
    return-path binding and games may use any port themselves."""
    members = list(members)
    out = [struct.pack("!IIBH", my_virt & 0xFFFFFFFF, net & 0xFFFFFFFF,
                       bits & 0xFF, len(members))]
    for node, virt in members:
        out.append(struct.pack("!II", node & 0xFFFFFFFF, virt & 0xFFFFFFFF))
    out.append(struct.pack("!B", link_id & 0xFF))
    return b"".join(out)


def decode_assign(payload: bytes):
    """T_ASSIGN payload -> (my_virt, net, bits, [(node, virt)], link_id)
    or None. The trailing link_id byte is mandatory."""
    try:
        if len(payload) < 12:
            return None
        my_virt, net, bits, n = struct.unpack("!IIBH", payload[:11])
        if len(payload) != 12 + 8 * n:
            return None
        link_id = payload[11 + 8 * n]
        members = []
        for i in range(n):
            node, virt = struct.unpack("!II", payload[11 + 8 * i:19 + 8 * i])
            members.append((node, virt))
        return my_virt, net, bits, members, link_id
    except struct.error:
        return None


# ---- per-stream ops -------------------------------------------------------
def encode_stopen(node: int, dest_node: int, sid: int, gport: int) -> bytes:
    return struct.pack("!IIIH", node & 0xFFFFFFFF, dest_node & 0xFFFFFFFF,
                       sid & 0xFFFFFFFF, gport & 0xFFFF)


def decode_stopen(payload: bytes):
    """T_STOPEN -> (node, dest_node, sid, gport) or None."""
    try:
        if len(payload) != 14:
            return None
        return struct.unpack("!IIIH", payload)
    except struct.error:
        return None


def encode_streq(sid: int, gport: int) -> bytes:
    return struct.pack("!IH", sid & 0xFFFFFFFF, gport & 0xFFFF)


def decode_streq(payload: bytes):
    try:
        if len(payload) != 6:
            return None
        return struct.unpack("!IH", payload)
    except struct.error:
        return None


def encode_stjoin(node: int, sid: int) -> bytes:
    return struct.pack("!II", node & 0xFFFFFFFF, sid & 0xFFFFFFFF)


def decode_stjoin(payload: bytes):
    try:
        if len(payload) != 8:
            return None
        return struct.unpack("!II", payload)
    except struct.error:
        return None


def encode_stsid(sid: int) -> bytes:
    """T_STJOINED / T_STOK payload: !I sid."""
    return struct.pack("!I", sid & 0xFFFFFFFF)


def decode_stsid(payload: bytes):
    try:
        if len(payload) != 4:
            return None
        return struct.unpack("!I", payload)[0]
    except struct.error:
        return None


def encode_stfail(sid: int, reason: int) -> bytes:
    return struct.pack("!IB", sid & 0xFFFFFFFF, reason & 0xFF)


def decode_stfail(payload: bytes):
    try:
        if len(payload) != 5:
            return None
        return struct.unpack("!IB", payload)
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
