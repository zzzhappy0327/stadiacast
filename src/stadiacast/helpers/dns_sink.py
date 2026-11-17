"""Logging DNS server that answers selected names with this host's IP and forwards everything else.

Point the controller at it: the Google names the receiver stands in for resolve to the receiver,
every other name is forwarded to the real upstream resolver and the answer relayed.  The redirect
is for whoever asks, so a device that needs the real Google services keeps its own resolver.

``--dns-mode auto`` (the default) is this UDP server.  On Windows, when UDP port 53 cannot be
bound because some other program already owns it (Mobile Hotspot's SharedAccess service does),
auto captures those queries with WinDivert instead of exiting.  ``--dns-mode udp`` never does
that, and ``--dns-mode windivert`` does not try the socket.  Linux and macOS stay on the socket.

    python -m stadiacast.helpers.dns_sink --upstream 192.168.1.1 --log captures/x/dns.jsonl \\
        --redirect '*.googleapis.com' --redirect googleapis.com

Behaviour:
  * A    query for a redirected name -> ``--redirect-ip`` (TTL 30)
  * AAAA query for a redirected name -> NOERROR, no answer (forces IPv4)
  * a ``--nxdomain`` name            -> NXDOMAIN at once (the client fails in milliseconds)
  * anything else                    -> forwarded to ``--upstream``, answer relayed
  * ``--log-only``                   -> never redirects, just logs and forwards

Every query and the answer it got is one JSONL record.  macOS lets an unprivileged process bind
port 53, so no root is required there.
"""

from __future__ import annotations

import argparse
import fnmatch
import socket
import socketserver
import struct
import sys
import threading
import time
from collections.abc import Sequence
from typing import Any

from stadiacast.errors import SetupError
from stadiacast.helpers.dns_divert import DNS_MODES, WINDIVERT_FILTER, select_dns_transport
from stadiacast.helpers.dnswire import (
    RCODE_FORMERR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    build_a_response,
    build_rcode_response,
    parse_message,
    parse_query,
)
from stadiacast.log import EventLog
from stadiacast.netutil import bind_hint, local_ip_towards

DEFAULT_REDIRECTS = ("*.googleapis.com", "googleapis.com")


class Resolver:
    """Decides and logs the answer to one query (shared by the UDP and TCP handlers)."""

    def __init__(
        self,
        log: EventLog,
        upstream: str,
        redirect_ip: str,
        patterns: Sequence[str],
        *,
        log_only: bool = False,
        controller_ip: str | None = None,
        nxdomain: Sequence[str] | None = None,
        upstream_port: int = 53,
        upstream_timeout: float = 3.0,
    ) -> None:
        self.log = log
        self.upstream = upstream
        self.upstream_port = upstream_port
        self.upstream_timeout = upstream_timeout
        self.redirect_ip = redirect_ip
        self.patterns = [p.lower().rstrip(".") for p in patterns]
        self.log_only = log_only
        self.controller_ip = controller_ip
        self.nxdomain = [p.lower().rstrip(".") for p in (nxdomain or [])]

    def refused(self, name: str) -> bool:
        n = name.lower().rstrip(".")
        return any(fnmatch.fnmatchcase(n, p) for p in self.nxdomain)

    def matches(self, name: str) -> bool:
        n = name.lower().rstrip(".")
        return any(fnmatch.fnmatchcase(n, p) for p in self.patterns)

    def forward(self, query: bytes) -> bytes | None:
        """Relay ``query`` to the upstream resolver; None on timeout or when the upstream is unreachable."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.upstream_timeout)
        try:
            s.sendto(query, (self.upstream, self.upstream_port))
            while True:
                data, _ = s.recvfrom(4096)
                if data[:2] == query[:2]:
                    return data
        except OSError:  # timeout, or ICMP port unreachable surfacing as ConnectionRefusedError
            return None
        finally:
            s.close()

    def handle(self, query: bytes, src: tuple[str, int], proto: str) -> bytes | None:
        """The answer to send, or None for what gets none: a message too short to be DNS, and a
        response (answering those would have two servers send to each other for good)."""
        t0 = time.time()
        rec: dict[str, Any] = {
            "proto": proto,
            "src": f"{src[0]}:{src[1]}",
            "from_controller": src[0] == self.controller_ip,
        }
        if len(query) < 12 or query[2] & 0x80:
            self.log("query_ignored", reason="a response" if len(query) >= 12 else "too short", len=len(query), **rec)
            return None
        try:
            msg = parse_query(query)
        except Exception as e:  # anything that is not a DNS message
            self.log("query_unparsable", error=str(e), raw_hex=query[:512].hex(), **rec)
            return build_rcode_response(query, RCODE_FORMERR)
        q: dict[str, Any] = msg["questions"][0] if msg["questions"] else {"name": "?", "type": "?", "qtype": 0}
        rec.update(id=msg["id"], qname=q["name"], qtype=q["type"])

        def rtt() -> float:
            return round((time.time() - t0) * 1000, 1)

        if self.refused(q["name"]) and not self.log_only:
            # Answer at once so the client's request fails in milliseconds (an unanswered query
            # would block it for the resolver timeout).
            self.log("query", action="nxdomain", rtt_ms=rtt(), **rec)
            return build_rcode_response(query, RCODE_NXDOMAIN)

        if self.matches(q["name"]) and not self.log_only and q["qtype"] in (1, 28):
            answers = [self.redirect_ip] if q["qtype"] == 1 else []
            self.log("query", action="redirect", answers=answers, rtt_ms=rtt(), **rec)
            return build_a_response(query, self.redirect_ip if q["qtype"] == 1 else None)

        resp = self.forward(query)
        if resp is None:
            self.log("query", action="upstream_timeout", upstream=self.upstream, **rec)
            return build_rcode_response(query, RCODE_SERVFAIL)
        try:
            m = parse_message(resp)
            answers = [a.get("data") for a in m["answers"]]
            rcode = m["rcode"]
        except Exception as e:  # relay the answer even if we cannot decode it for the log
            answers, rcode = [f"<parse error {e}>"], None
        self.log("query", action="forward", rcode=rcode, answers=answers, rtt_ms=rtt(), **rec)
        return resp


class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        resp = self.server.resolver.handle(data, self.client_address, "udp")  # type: ignore[attr-defined]
        if resp is not None:
            sock.sendto(resp, self.client_address)


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(10)
        try:
            hdr = self.request.recv(2)
            if len(hdr) < 2:
                return
            (ln,) = struct.unpack("!H", hdr)
            data = b""
            while len(data) < ln:
                chunk = self.request.recv(ln - len(data))
                if not chunk:
                    return
                data += chunk
            resp = self.server.resolver.handle(data, self.client_address, "tcp")  # type: ignore[attr-defined]
            if resp is not None:
                self.request.sendall(struct.pack("!H", len(resp)) + resp)
        except OSError:
            pass


class _UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    max_packet_size = 4096


class _TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument(
        "--dns-mode",
        choices=DNS_MODES,
        default="auto",
        help="auto: bind this port, and on Windows fall back to WinDivert when UDP 53 is already owned "
        "(Mobile Hotspot). udp: the socket only. windivert: capture inbound UDP 53, Windows only",
    )
    ap.add_argument("--upstream", default="192.168.1.1", help="real resolver to forward to")
    ap.add_argument("--upstream-port", type=int, default=53)
    ap.add_argument("--redirect-ip", default=None, help="IP to answer redirected names with (default: this host)")
    ap.add_argument(
        "--redirect",
        action="append",
        default=None,
        help=f"glob of names to redirect (repeatable; default: {', '.join(DEFAULT_REDIRECTS)})",
    )
    ap.add_argument("--log-only", action="store_true", help="forward everything, never redirect")
    ap.add_argument(
        "--nxdomain",
        action="append",
        default=None,
        help="glob of names answered NXDOMAIN at once (repeatable; checked before --redirect)",
    )
    ap.add_argument("--controller-ip", default=None, help="mark queries from this address in the log")
    ap.add_argument("--log", required=True, help="JSONL log file")
    args = ap.parse_args(argv)

    redirect_ip = args.redirect_ip or local_ip_towards(args.upstream)
    if not redirect_ip:
        ap.error(f"no route to {args.upstream}; pass --redirect-ip")
    patterns = args.redirect or list(DEFAULT_REDIRECTS)
    log = EventLog(args.log)
    try:
        resolver = Resolver(
            log,
            args.upstream,
            redirect_ip,
            patterns,
            log_only=args.log_only,
            controller_ip=args.controller_ip,
            nxdomain=args.nxdomain,
            upstream_port=args.upstream_port,
        )
        return _run(args, log, resolver, redirect_ip, patterns)
    finally:
        log.close()


def _run(
    args: argparse.Namespace,
    log: EventLog,
    resolver: Resolver,
    redirect_ip: str,
    patterns: Sequence[str],
) -> int:
    """Bind the UDP sink, or capture with WinDivert when that is what the mode asks for."""
    if args.dns_mode == "windivert":
        return _serve_windivert(args, log, resolver, redirect_ip, patterns)
    try:
        udp = _UdpServer((args.listen, args.port), _UdpHandler)
    except OSError as e:
        # Only the UDP socket decides the fallback.  TCP is tried after it, and a TCP failure
        # once UDP is bound is a different fault: capturing would take queries the socket can answer.
        if _fallback_or_fail(args, log, e) != "windivert":
            return 1
        return _serve_windivert(args, log, resolver, redirect_ip, patterns)
    try:
        tcp = _TcpServer((args.listen, args.port), _TcpHandler)
    except OSError as e:
        udp.server_close()
        hint = bind_hint(args.port, "DNS", e)
        log("bind_failed", listen=f"{args.listen}:{args.port}", error=hint)
        return 1
    return _serve_udp(args, log, resolver, redirect_ip, patterns, udp, tcp)


def _start_fields(args: argparse.Namespace, redirect_ip: str, patterns: Sequence[str], mode: str) -> dict[str, Any]:
    return {
        "listen": f"{args.listen}:{args.port}",
        "upstream": args.upstream,
        "redirect_ip": redirect_ip,
        "redirect_patterns": patterns,
        "log_only": args.log_only,
        "nxdomain": args.nxdomain or [],
        "mode": mode,
    }


def _serve_udp(
    args: argparse.Namespace,
    log: EventLog,
    resolver: Resolver,
    redirect_ip: str,
    patterns: Sequence[str],
    udp: _UdpServer,
    tcp: _TcpServer,
) -> int:
    udp.resolver = tcp.resolver = resolver  # type: ignore[attr-defined]
    log("start", **_start_fields(args, redirect_ip, patterns, "udp"))
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    try:
        udp.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        udp.server_close()
        tcp.shutdown()
        tcp.server_close()
    return 0


def _serve_windivert(
    args: argparse.Namespace, log: EventLog, resolver: Resolver, redirect_ip: str, patterns: Sequence[str]
) -> int:
    """Capture instead of binding.  Imported here so a UDP run never loads the Windows module's driver."""
    from stadiacast.helpers.dns_windivert import serve_windivert

    try:
        # Platform and port, before the driver is opened.  auto reaches this only after the UDP
        # socket was refused; the check is the same one explicit windivert has to pass.
        select_dns_transport("windivert", sys.platform, args.port)
    except SetupError as e:
        log("windivert_unavailable", error=str(e))
        return 1
    log("start", filter=WINDIVERT_FILTER, **_start_fields(args, redirect_ip, patterns, "windivert"))
    return serve_windivert(resolver, log)


def _fallback_or_fail(args: argparse.Namespace, log: EventLog, exc: OSError) -> str | None:
    """``windivert`` when this bind failure is the Windows port-53 case, else log it and return None.

    The original error is reported as ``bind_failed`` for every other failure, on every system.
    It is not replaced with a capture.
    """
    try:
        chosen = select_dns_transport(args.dns_mode, sys.platform, args.port, exc)
    except OSError:
        hint = bind_hint(args.port, "DNS", exc)
        log("bind_failed", listen=f"{args.listen}:{args.port}", error=hint)
        return None
    log(
        "dns_mode_fallback",
        listen=f"{args.listen}:{args.port}",
        error=str(exc),
        note=(
            "UDP 53 is already owned, on Windows normally by Mobile Hotspot (SharedAccess); capturing it with WinDivert"
        ),
    )
    return chosen


if __name__ == "__main__":
    raise SystemExit(main())
