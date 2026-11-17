"""Decide what a diverted DNS packet becomes, without opening a capture driver.

The Windows sink captures with WinDivert (see :mod:`stadiacast.helpers.dns_windivert`).
The choices that have to be right on every platform live here, so the tests can make them
without a driver: which bind failure may leave the UDP socket, which names get an answer,
and the IPv4/UDP checksums of that answer.

WinDivert's default network layer, the one ``WinDivert(filter)`` opens, delivers packets
addressed to this machine and packets this machine sends.  ``inbound and udp.DstPort == 53``
is the queries aimed at us, which on a Windows Mobile Hotspot includes the clients asking
the gateway.  A query the hotspot only forwards, such as the firmware's fallback straight
to ``8.8.8.8:53``, is not addressed to us.  Those travel the forward layer, and this filter
does not open it.  Replying on that layer is a different injection path, and a wrong
reinjection there drops or mis-NATs the hotspot's traffic.  It is not done here, and it has
not been tried against a controller.
"""

from __future__ import annotations

import errno
import socket
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from stadiacast.errors import SetupError
from stadiacast.helpers.dnswire import RCODE_NXDOMAIN, build_a_response, build_rcode_response, parse_query

#: What the capture opens.  One argument, so the driver's default layer stays the network layer.
WINDIVERT_FILTER = "inbound and udp.DstPort == 53"

WINDIVERT_WINDOWS_ONLY = (
    "--dns-mode windivert is Windows only: it captures inbound UDP port 53 with the WinDivert driver, "
    "which exists only on Windows. Use --dns-mode udp on this system."
)

WINDIVERT_PORT = (
    "--dns-mode windivert captures UDP port 53, the port Windows Mobile Hotspot holds. "
    "--port is the UDP socket and is not used in that mode."
)

#: ``auto`` keeps the UDP sink.  On Windows, and only for port 53, a refusal that means "someone
#: already owns this socket" may switch to the capture.  ``udp`` never switches.  ``windivert``
#: does not bind.
DNS_MODES = ("auto", "udp", "windivert")

# WSAEACCES and WSAEADDRINUSE.  SharedAccess holds the hotspot's UDP 53 exclusively, and Windows
# reports that as one of these two, not as a generic failure.
_WIN_PORT_OWNED = (10013, 10048)


@dataclass(frozen=True)
class DnsDivertAction:
    """What to do with one captured payload.

    ``kind`` is ``reply`` (send ``reply`` back to the client), ``passthrough`` (a DNS query we
    do not answer) or ``ignore`` (not a query we will read).  The last two are put back on the
    wire unchanged: the packet was taken out of the stack, and dropping it would black-hole it.
    """

    kind: str
    reason: str
    reply: bytes | None = None
    qname: str | None = None
    qtype: str | None = None
    ident: int | None = None
    answers: tuple[str, ...] | None = None


def is_windows_port_owned(exc: OSError) -> bool:
    """True when Windows is saying another program already has the socket.

    Mobile Hotspot's SharedAccess service is that program for UDP 53.  A permission error
    (WSAEACCES) and address-already-in-use (WSAEADDRINUSE) are the two shapes that takes.
    Anything else, a bad address or an interface that is down, is a different problem.
    """
    if isinstance(exc, PermissionError):
        return True
    if exc.errno == errno.EADDRINUSE:
        return True
    winerror = getattr(exc, "winerror", None)
    return winerror in _WIN_PORT_OWNED


def select_dns_transport(mode: str, platform: str, port: int, bind_error: BaseException | None = None) -> str:
    """``udp`` or ``windivert`` for this mode, machine and bind attempt.

    ``bind_error`` is raised again when the UDP socket is the right outcome and it failed, so
    the caller reports that failure instead of switching transport.  Only Windows, only port
    53, and only :func:`is_windows_port_owned` may switch, and only in ``auto``.
    """
    if mode not in DNS_MODES:
        raise SetupError(f"unknown --dns-mode {mode!r} (expected auto, udp or windivert)")
    if mode == "windivert":
        if platform != "win32":
            raise SetupError(WINDIVERT_WINDOWS_ONLY)
        if port != 53:
            raise SetupError(WINDIVERT_PORT)
        return "windivert"
    if bind_error is None:
        return "udp"
    if (
        platform == "win32"
        and port == 53
        and mode == "auto"
        and isinstance(bind_error, OSError)
        and is_windows_port_owned(bind_error)
    ):
        return "windivert"
    raise bind_error


def is_ipv6_packet(packet: Any) -> bool:
    """True when ``packet`` is IPv6.  A header object, a boolean, or an IPv6 text address.

    IPv6 queries are put back untouched.  The answers we build are IPv4, and rewriting an
    IPv6 datagram here would be a guess at a header this sink does not own.
    """
    ipv6 = getattr(packet, "ipv6", None)
    if isinstance(ipv6, bool):
        return ipv6
    if ipv6 is not None:
        return True
    src = getattr(packet, "src_addr", None)
    return isinstance(src, str) and ":" in src


def classify_dns_payload(
    payload: bytes,
    *,
    matches: Callable[[str], bool],
    refused: Callable[[str], bool],
    redirect_ip: str,
    log_only: bool,
) -> DnsDivertAction:
    """The reply for a diverted IPv4 UDP payload, or a reason to put the packet back.

    Redirected A and AAAA names, and NXDOMAIN names, use the same builders as the UDP sink.
    Every other query is a passthrough: the hotspot's own resolver still has to answer it,
    which is what keeps ordinary internet working for whoever is on the hotspot.  A payload
    that is not a query is put back too.  Answering it with FORMERR, as the UDP socket does
    for garbage a client chose to send, would answer a packet the stack had not handed us.
    """
    if len(payload) < 12:
        return DnsDivertAction("ignore", "too short")
    if payload[2] & 0x80:  # QR: a response.  Answering one is how two resolvers loop.
        return DnsDivertAction("ignore", "a response")
    try:
        msg = parse_query(payload)
    except Exception:
        return DnsDivertAction("ignore", "unparsable")
    ident = int(msg["id"])
    if not msg["questions"]:
        return DnsDivertAction("ignore", "no question", ident=ident)
    question = msg["questions"][0]
    qname = str(question["name"])
    qtype = str(question["type"])
    base = DnsDivertAction("passthrough", "passthrough", qname=qname, qtype=qtype, ident=ident)
    if log_only:
        return base
    if refused(qname):
        return DnsDivertAction(
            "reply",
            "nxdomain",
            reply=build_rcode_response(payload, RCODE_NXDOMAIN),
            qname=qname,
            qtype=qtype,
            ident=ident,
        )
    qtype_code = int(question["qtype"])
    if matches(qname) and qtype_code in (1, 28):
        ip = redirect_ip if qtype_code == 1 else None
        answers = (redirect_ip,) if ip is not None else ()
        return DnsDivertAction(
            "reply",
            "redirect",
            reply=build_a_response(payload, ip),
            qname=qname,
            qtype=qtype,
            ident=ident,
            answers=answers,
        )
    return base


def apply_dns_reply(packet: Any, reply: bytes, outbound: Any) -> None:
    """Rewrite ``packet`` into the DNS reply and point it back at the client.

    Swapping the endpoints makes the source the address the client asked, which is the
    address it will accept the answer from, and makes the destination port the client's
    own port.  That port is not 53, so the inbound port-53 filter does not capture the
    reply on the way out.  ``outbound`` is the driver's outbound direction value.
    """
    packet.src_addr, packet.dst_addr = packet.dst_addr, packet.src_addr
    packet.src_port, packet.dst_port = packet.dst_port, packet.src_port
    packet.payload = reply
    packet.direction = outbound


def internet_checksum(data: bytes) -> int:
    """The ones-complement checksum of ``data`` (RFC 1071), as a 16-bit integer."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def fill_ipv4_udp_checksums(raw: bytearray) -> None:
    """Write the IPv4 header checksum and the UDP checksum into ``raw``.

    ``raw`` is an IPv4 datagram with no IP options followed by its UDP datagram.  A UDP
    checksum that computes to 0 is stored as 0xFFFF: zero would mean "no checksum" (RFC 768).
    """
    if len(raw) < 28 or raw[0] >> 4 != 4:
        raise ValueError("not an IPv4 UDP datagram")
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or len(raw) < ihl + 8:
        raise ValueError("header truncated")
    raw[10:12] = b"\x00\x00"
    raw[10:12] = struct.pack("!H", internet_checksum(bytes(raw[:ihl])))
    udp_len = struct.unpack_from("!H", raw, ihl + 4)[0]
    if udp_len < 8 or ihl + udp_len > len(raw):
        raise ValueError("udp length past the packet")
    raw[ihl + 6 : ihl + 8] = b"\x00\x00"
    pseudo = bytes(raw[12:20]) + struct.pack("!BBH", 0, 17, udp_len)
    udp_sum = internet_checksum(pseudo + bytes(raw[ihl : ihl + udp_len]))
    raw[ihl + 6 : ihl + 8] = struct.pack("!H", udp_sum or 0xFFFF)


def ipv4_udp_checksums_valid(raw: bytes) -> bool:
    """True when the IPv4 and UDP checksums in ``raw`` are the ones :func:`fill_ipv4_udp_checksums` writes."""
    if len(raw) < 28 or raw[0] >> 4 != 4:
        return False
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or internet_checksum(raw[:ihl]) != 0:
        return False
    udp_len = struct.unpack_from("!H", raw, ihl + 4)[0]
    if udp_len < 8 or ihl + udp_len > len(raw):
        return False
    pseudo = raw[12:20] + struct.pack("!BBH", 0, 17, udp_len)
    return internet_checksum(pseudo + raw[ihl : ihl + udp_len]) == 0


def build_ipv4_udp_packet(src: str, dst: str, src_port: int, dst_port: int, payload: bytes) -> bytearray:
    """One IPv4 UDP datagram with both checksums filled.  TTL 64, identification 1, no options."""
    udp_len = 8 + len(payload)
    total = 20 + udp_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    raw = bytearray(header + udp)
    fill_ipv4_udp_checksums(raw)
    return raw
