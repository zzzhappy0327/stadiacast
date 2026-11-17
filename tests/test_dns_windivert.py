"""Windows WinDivert DNS: packet decisions, checksums, shutdown and the auto fallback.

Nothing here opens a driver.  The capture is a fake handle, and ``pydivert`` is not imported.
"""

from __future__ import annotations

import asyncio
import builtins
import errno
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from stadiacast.cli import parse_args
from stadiacast.errors import SetupError
from stadiacast.helpers import dns_divert, dns_sink, dns_windivert
from stadiacast.helpers.dns_divert import WINDIVERT_FILTER, select_dns_transport
from stadiacast.helpers.dns_sink import Resolver
from stadiacast.helpers.dns_windivert import (
    WinDivertDnsServer,
    handle_diverted_packet,
    load_pydivert,
    open_windivert_handle,
)
from stadiacast.helpers.dnswire import parse_message
from stadiacast.log import EventLog
from stadiacast.receiver import Receiver
from tests.helpers import make_receiver

OUT = "OUT"


def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"


def query(name: str, qtype: int = 1, ident: int = 0x1234) -> bytes:
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, 1)


def make_resolver(tmp_path: Path, **kwargs: object) -> tuple[Resolver, EventLog]:
    log = EventLog(str(tmp_path / "dns.jsonl"), echo=False)
    resolver = Resolver(
        log,
        "127.0.0.1",
        "192.168.137.1",
        ["*.googleapis.com", "googleapis.com"],
        controller_ip="192.168.137.50",
        upstream_port=1,
        upstream_timeout=0.2,
        **kwargs,  # type: ignore[arg-type]
    )
    return resolver, log


class Packet:
    """Enough of a pydivert packet for the dispatcher: addresses, payload, direction, raw checksums."""

    def __init__(
        self,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        payload: bytes,
        *,
        direction: str = "IN",
        ipv6: bool = False,
    ) -> None:
        self.ipv6 = ipv6
        self.direction = direction
        self._src = src
        self._dst = dst
        self._sport = sport
        self._dport = dport
        self._payload = bytes(payload)
        self.recalculated = 0
        self.raw = bytearray()
        self._sync()

    def _sync(self) -> None:
        if self.ipv6:
            return
        self.raw = dns_divert.build_ipv4_udp_packet(self._src, self._dst, self._sport, self._dport, self._payload)

    @property
    def src_addr(self) -> str:
        return self._src

    @src_addr.setter
    def src_addr(self, value: str) -> None:
        self._src = value
        self._sync()

    @property
    def dst_addr(self) -> str:
        return self._dst

    @dst_addr.setter
    def dst_addr(self, value: str) -> None:
        self._dst = value
        self._sync()

    @property
    def src_port(self) -> int:
        return self._sport

    @src_port.setter
    def src_port(self, value: int) -> None:
        self._sport = value
        self._sync()

    @property
    def dst_port(self) -> int:
        return self._dport

    @dst_port.setter
    def dst_port(self, value: int) -> None:
        self._dport = value
        self._sync()

    @property
    def payload(self) -> bytes:
        return self._payload

    @payload.setter
    def payload(self, value: bytes) -> None:
        self._payload = bytes(value)
        self._sync()

    def recalculate_checksums(self) -> None:
        self.recalculated += 1
        if not self.ipv6:
            dns_divert.fill_ipv4_udp_checksums(self.raw)


class Handle:
    def __init__(self) -> None:
        self.sent: list[tuple[Packet, bool]] = []
        self.closed = False
        self._wake = threading.Event()
        self.receiving = threading.Event()
        self.release = threading.Event()
        self.hold = False
        self._packets: list[Packet] = []

    def recv(self) -> Packet:
        if self._packets:
            return self._packets.pop(0)
        self.receiving.set()
        if self.hold:
            self.release.wait()
        else:
            self._wake.wait()
        raise OSError(errno.EBADF, "handle closed")

    def close(self) -> None:
        self.closed = True
        if not self.hold:
            self._wake.set()

    def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
        if recalculate_checksum:
            packet.recalculate_checksums()
        self.sent.append((packet, recalculate_checksum))
        return len(packet.raw)

    def open(self) -> Handle:
        return self


def client_query(payload: bytes, *, src: str = "192.168.137.50", dst: str = "192.168.137.1") -> Packet:
    return Packet(src, dst, 1234, 53, payload)


def test_checksum_of_a_known_header_and_a_known_udp_datagram():
    """0x7CD6 is the ones-complement sum of this 20-byte header with the checksum field zero."""
    header = bytes.fromhex("4500001400010000401100007f0000017f000001")
    assert dns_divert.internet_checksum(header) == 0x7CD6
    stored = bytearray(header)
    stored[10:12] = struct.pack("!H", 0x7CD6)
    assert dns_divert.internet_checksum(bytes(stored)) == 0

    raw = dns_divert.build_ipv4_udp_packet("192.168.137.1", "192.168.137.50", 1234, 53, b"hi")
    assert struct.unpack_from("!H", raw, 26)[0] == 0xFEE4  # UDP checksum of that datagram
    assert dns_divert.ipv4_udp_checksums_valid(bytes(raw))
    assert dns_divert.internet_checksum(bytes(raw[:20])) == 0


def test_a_redirected_query_is_answered_outbound_with_valid_checksums(tmp_path):
    resolver, log = make_resolver(tmp_path)
    packet = client_query(query("cloudcast-pa.googleapis.com"))
    before = bytes(packet.raw)
    handle = Handle()
    handle_diverted_packet(packet, handle, resolver, outbound=OUT)

    assert len(handle.sent) == 1 and handle.sent[0][1] is True
    assert packet.recalculated == 1
    assert packet.direction == OUT
    assert (packet.src_addr, packet.dst_addr) == ("192.168.137.1", "192.168.137.50")
    assert (packet.src_port, packet.dst_port) == (53, 1234)
    assert packet.raw[12:16] == socket.inet_aton(packet.src_addr)
    assert packet.raw[16:20] == socket.inet_aton(packet.dst_addr)
    assert struct.unpack_from("!HH", packet.raw, 20) == (53, 1234)
    assert bytes(packet.raw) != before
    assert dns_divert.ipv4_udp_checksums_valid(bytes(packet.raw))
    assert dns_divert.internet_checksum(bytes(packet.raw[:20])) == 0

    parsed = parse_message(packet.payload)
    assert parsed["id"] == 0x1234 and parsed["rcode"] == 0
    assert parsed["answers"][0]["data"] == "192.168.137.1"
    record = next(r for r in log.records if r["event"] == "query")
    assert record["action"] == "redirect" and record["from_controller"] is True
    assert record["src"] == "192.168.137.50:1234" and record["dst"] == "192.168.137.1:53"
    assert record["answers"] == ["192.168.137.1"] and record["proto"] == "windivert"


def test_aaaa_for_a_redirected_name_is_an_empty_answer_and_nxdomain_is_answered(tmp_path):
    resolver, log = make_resolver(tmp_path, nxdomain=["play.googleapis.com"])
    aaaa = client_query(query("googleapis.com", 28))
    handle_diverted_packet(aaaa, Handle(), resolver, outbound=OUT)
    parsed = parse_message(aaaa.payload)
    assert parsed["rcode"] == 0 and parsed["answers"] == []
    assert aaaa.direction == OUT and dns_divert.ipv4_udp_checksums_valid(bytes(aaaa.raw))

    denied = client_query(query("play.googleapis.com"))
    handle_diverted_packet(denied, Handle(), resolver, outbound=OUT)
    assert parse_message(denied.payload)["rcode"] == 3
    assert [r["action"] for r in log.records if r["event"] == "query"] == ["redirect", "nxdomain"]


def test_a_query_that_does_not_match_is_sent_on_unchanged(tmp_path):
    resolver, log = make_resolver(tmp_path)
    packet = client_query(query("example.com"))
    before = bytes(packet.raw)
    handle = Handle()
    handle_diverted_packet(packet, handle, resolver, outbound=OUT)

    assert handle.sent == [(packet, False)]
    assert packet.recalculated == 0
    assert bytes(packet.raw) == before
    assert packet.direction == "IN"
    assert (packet.src_addr, packet.dst_addr, packet.src_port, packet.dst_port) == (
        "192.168.137.50",
        "192.168.137.1",
        1234,
        53,
    )
    assert packet.payload == query("example.com")
    record = log.records[-1]
    assert record["event"] == "query" and record["action"] == "passthrough"
    assert record["qname"] == "example.com"


def test_other_types_log_only_and_the_wrong_port_are_not_rewritten(tmp_path):
    resolver, _log = make_resolver(tmp_path, log_only=True)
    matching = client_query(query("cloudcast-pa.googleapis.com"))
    before = bytes(matching.raw)
    handle_diverted_packet(matching, Handle(), resolver, outbound=OUT)
    assert bytes(matching.raw) == before and matching.direction == "IN"

    resolver, _log = make_resolver(tmp_path)
    txt = client_query(query("cloudcast-pa.googleapis.com", 16))
    before = bytes(txt.raw)
    handle_diverted_packet(txt, Handle(), resolver, outbound=OUT)
    assert bytes(txt.raw) == before and txt.payload == query("cloudcast-pa.googleapis.com", 16)

    other = client_query(query("cloudcast-pa.googleapis.com"))
    other.dst_port = 80
    before = bytes(other.raw)
    handle_diverted_packet(other, Handle(), resolver, outbound=OUT)
    assert bytes(other.raw) == before and other.dst_port == 80


@pytest.mark.parametrize(
    "payload",
    [
        b"\x00\x01",
        query("cloudcast-pa.googleapis.com")[:2] + b"\x81\x00" + query("cloudcast-pa.googleapis.com")[4:],
        struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x05nope",
    ],
)
def test_malformed_and_non_query_packets_pass_through(tmp_path, payload):
    resolver, log = make_resolver(tmp_path)
    packet = client_query(payload)
    before = bytes(packet.raw)
    handle_diverted_packet(packet, Handle(), resolver, outbound=OUT)
    assert bytes(packet.raw) == before and packet.direction == "IN" and packet.recalculated == 0
    assert log.records[-1]["event"] == "query_ignored"
    assert log.records[-1]["reason"] in {"too short", "a response", "unparsable"}


def test_ipv6_is_not_rewritten(tmp_path):
    resolver, log = make_resolver(tmp_path)
    packet = Packet("2001:db8::50", "2001:db8::1", 1234, 53, query("cloudcast-pa.googleapis.com"), ipv6=True)
    handle_diverted_packet(packet, Handle(), resolver, outbound=OUT)
    assert packet.direction == "IN"
    assert packet.src_addr == "2001:db8::50" and packet.payload == query("cloudcast-pa.googleapis.com")
    assert log.records[-1]["reason"] == "ipv6"


def test_a_send_error_is_logged_and_does_not_escape(tmp_path):
    resolver, log = make_resolver(tmp_path)

    class Broken(Handle):
        def send(self, packet: Packet, recalculate_checksum: bool = True) -> int:
            del packet, recalculate_checksum
            raise OSError(errno.ENETDOWN, "network is down")

    handle_diverted_packet(client_query(query("cloudcast-pa.googleapis.com")), Broken(), resolver, outbound=OUT)
    assert log.records[-1]["event"] == "windivert_packet_error"
    assert "network is down" in log.records[-1]["error"]


def test_importing_the_dns_modules_does_not_import_pydivert():
    assert "pydivert" not in sys.modules
    assert not hasattr(dns_sink, "pydivert")


def test_pydivert_extra_is_marked_windows_only():
    text = Path(__file__).resolve().parents[1].joinpath("pyproject.toml").read_text(encoding="utf-8")
    assert "windivert = [\"pydivert>=2.1.0; sys_platform == 'win32'\"]" in text


def test_open_uses_the_inbound_port_53_filter_and_names_admin_and_driver_failures(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    seen: dict[str, object] = {}

    class Opened:
        def __init__(self, divert_filter: str, *args: object, **kwargs: object) -> None:
            seen["filter"] = divert_filter
            seen["args"] = args
            seen["kwargs"] = kwargs

        def open(self) -> Opened:
            return self

    handle = open_windivert_handle(module=SimpleNamespace(WinDivert=Opened))
    assert isinstance(handle, Opened)
    assert seen == {"filter": WINDIVERT_FILTER, "args": (), "kwargs": {}}

    class Denied:
        def __init__(self, _filter: str) -> None:
            pass

        def open(self) -> None:
            raise PermissionError(13, "Access is denied")

    with pytest.raises(SetupError, match="Administrator"):
        open_windivert_handle(module=SimpleNamespace(WinDivert=Denied))

    class Missing:
        def __init__(self, _filter: str) -> None:
            pass

        def open(self) -> None:
            raise FileNotFoundError(2, "WinDivert.dll")

    with pytest.raises(SetupError, match="driver files"):
        open_windivert_handle(module=SimpleNamespace(WinDivert=Missing))

    class Unrelated:
        def __init__(self, _filter: str) -> None:
            pass

        def open(self) -> None:
            raise OSError(errno.EINVAL, "invalid argument")

    with pytest.raises(OSError, match="invalid argument") as raised:
        open_windivert_handle(module=SimpleNamespace(WinDivert=Unrelated))
    assert not isinstance(raised.value, SetupError)


def test_a_missing_pydivert_says_which_extra_to_install(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    real = builtins.__import__

    def blocked(name: str, *args: object, **kwargs: object) -> object:
        if name == "pydivert" or name.startswith("pydivert."):
            raise ImportError("no module named pydivert")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    with pytest.raises(SetupError, match=r"stadiacast\[windivert\]"):
        load_pydivert()


def test_windivert_is_refused_off_windows_without_importing_pydivert():
    with pytest.raises(SetupError, match="Windows only"):
        open_windivert_handle()
    assert "pydivert" not in sys.modules


def test_transport_falls_back_only_for_windows_udp_53_being_owned():
    assert select_dns_transport("auto", "linux", 53) == "udp"
    assert select_dns_transport("auto", "win32", 53) == "udp"
    assert select_dns_transport("udp", "win32", 53) == "udp"
    assert select_dns_transport("windivert", "win32", 53) == "windivert"

    owned = OSError(errno.EADDRINUSE, "in use")
    denied = PermissionError(13, "Access is denied")
    assert select_dns_transport("auto", "win32", 53, owned) == "windivert"
    assert select_dns_transport("auto", "win32", 53, denied) == "windivert"
    coded = OSError("address in use")
    coded.errno = None
    coded.winerror = 10048
    assert select_dns_transport("auto", "win32", 53, coded) == "windivert"
    wsaeacces = OSError("access")
    wsaeacces.errno = 0
    wsaeacces.winerror = 10013
    assert select_dns_transport("auto", "win32", 53, wsaeacces) == "windivert"

    unrelated = OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")
    for mode, platform, port, err in (
        ("auto", "win32", 53, unrelated),
        ("auto", "win32", 5353, denied),
        ("udp", "win32", 53, denied),
        ("auto", "linux", 53, denied),
        ("auto", "darwin", 53, owned),
        ("auto", "linux", 53, coded),
    ):
        with pytest.raises(OSError) as raised:
            select_dns_transport(mode, platform, port, err)
        assert raised.value is err

    with pytest.raises(SetupError, match="Windows only"):
        select_dns_transport("windivert", "linux", 53)
    with pytest.raises(SetupError, match="Windows only"):
        select_dns_transport("windivert", "darwin", 53)
    with pytest.raises(SetupError, match="port 53"):
        select_dns_transport("windivert", "win32", 5353)


def _sink(tmp_path: Path, name: str, port: int, mode: str) -> tuple[int, str]:
    log = tmp_path / f"{name}.jsonl"
    code = dns_sink.main(
        [
            "--listen",
            "127.0.0.1",
            "--port",
            str(port),
            "--dns-mode",
            mode,
            "--upstream",
            "127.0.0.1",
            "--redirect-ip",
            "192.168.137.1",
            "--log",
            str(log),
        ]
    )
    return code, log.read_text(encoding="utf-8")


def test_the_sink_falls_back_on_windows_and_reports_every_other_bind_failure(tmp_path, monkeypatch):
    started: list[str] = []

    def fake_serve(_resolver: object, log: EventLog, **_kwargs: object) -> int:
        started.append("yes")
        log("windivert_started", filter=WINDIVERT_FILTER)
        return 0

    monkeypatch.setattr(dns_windivert, "serve_windivert", fake_serve)

    def deny(*_args: object, **_kwargs: object) -> None:
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(dns_sink, "_UdpServer", deny)
    monkeypatch.setattr(sys, "platform", "win32")
    code, text = _sink(tmp_path, "win-53", 53, "auto")
    assert code == 0 and started == ["yes"]
    assert "dns_mode_fallback" in text and "windivert_started" in text and "bind_failed" not in text

    started.clear()
    monkeypatch.setattr(sys, "platform", "linux")
    code, text = _sink(tmp_path, "linux-53", 53, "auto")
    assert code == 1 and started == []
    assert "bind_failed" in text and "dns_mode_fallback" not in text and "needs root" in text

    monkeypatch.setattr(sys, "platform", "darwin")

    def in_use(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.EADDRINUSE, "Address already in use")

    monkeypatch.setattr(dns_sink, "_UdpServer", in_use)
    code, text = _sink(tmp_path, "mac-53", 53, "auto")
    assert code == 1 and started == [] and "dns_mode_fallback" not in text

    monkeypatch.setattr(sys, "platform", "win32")
    code, text = _sink(tmp_path, "win-high", 5353, "auto")
    assert code == 1 and started == [] and "bind_failed" in text and "dns_mode_fallback" not in text

    code, text = _sink(tmp_path, "win-udp", 53, "udp")
    assert code == 1 and started == [] and "dns_mode_fallback" not in text

    def bad_address(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")

    monkeypatch.setattr(dns_sink, "_UdpServer", bad_address)
    code, text = _sink(tmp_path, "win-unrelated", 53, "auto")
    assert code == 1 and started == [] and "dns_mode_fallback" not in text
    assert "Cannot assign requested address" in text


def test_explicit_windivert_on_linux_fails_before_binding(tmp_path, monkeypatch):
    def explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("windivert mode must not bind a socket")

    monkeypatch.setattr(dns_sink, "_UdpServer", explode)
    code, text = _sink(tmp_path, "explicit", 53, "windivert")
    assert code == 1
    assert "Windows only" in text
    assert "windivert_started" not in text


def test_windows_fallback_without_the_extra_names_the_install(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")

    def deny(*_args: object, **_kwargs: object) -> None:
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(dns_sink, "_UdpServer", deny)
    real = builtins.__import__

    def blocked(name: str, *args: object, **kwargs: object) -> object:
        if name == "pydivert" or name.startswith("pydivert."):
            raise ImportError("no module named pydivert")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    code, text = _sink(tmp_path, "no-extra", 53, "auto")
    assert code == 1
    assert "dns_mode_fallback" in text
    assert "windivert_unavailable" in text and "stadiacast[windivert]" in text
    assert "windivert_started" not in text


def _serve_until_stopped(server: WinDivertDnsServer) -> tuple[threading.Thread, dict[str, int]]:
    found: dict[str, int] = {}

    def run() -> None:
        found["code"] = server.serve()

    thread = threading.Thread(target=run)
    thread.start()
    return thread, found


def test_stop_closes_the_handle_unblocks_recv_and_joins(tmp_path):
    _resolver, log = make_resolver(tmp_path)
    handle = Handle()
    server = WinDivertDnsServer(_resolver, log, opener=lambda: handle, direction_outbound=OUT, join_timeout=2)
    thread, found = _serve_until_stopped(server)
    assert handle.receiving.wait(2)
    server.stop()
    thread.join(2)
    assert not thread.is_alive()
    assert handle.closed
    assert server._thread is not None and not server._thread.is_alive()
    assert found["code"] == 0
    assert [r["event"] for r in log.records if r["event"].startswith("windivert_")] == [
        "windivert_started",
        "windivert_stopped",
    ]


def test_stop_does_not_hang_when_close_does_not_wake_recv(tmp_path):
    _resolver, log = make_resolver(tmp_path)
    handle = Handle()
    handle.hold = True
    server = WinDivertDnsServer(_resolver, log, opener=lambda: handle, direction_outbound=OUT, join_timeout=0.2)
    thread, _found = _serve_until_stopped(server)
    try:
        assert handle.receiving.wait(2)
        started = time.monotonic()
        server.stop()
        thread.join(2)
        assert time.monotonic() - started < 1.5
        assert not thread.is_alive()
        assert any(r["event"] == "windivert_join_timeout" for r in log.records)
    finally:
        handle.release.set()


def test_the_signal_handler_closes_the_handle_without_joining(tmp_path):
    _resolver, log = make_resolver(tmp_path)
    handle = Handle()
    server = WinDivertDnsServer(_resolver, log, opener=lambda: handle, direction_outbound=OUT)
    server._handle = handle
    server._install_signals()
    try:
        assert server._signal_handler is not None
        server._signal_handler(signal.SIGINT, None)
        assert handle.closed and server._stop.is_set() and server._user_stop is True
    finally:
        server._restore_signals()


def test_cli_dns_mode_defaults_to_auto_and_windivert_is_windows_only(monkeypatch, capsys):
    assert parse_args([]).dns_mode == "auto"
    assert parse_args(["--preset", "live"]).dns_mode == "auto"
    assert parse_args(["--dns-mode", "udp"]).dns_mode == "udp"
    with pytest.raises(SystemExit) as stopped:
        parse_args(["--dns-upstream", "192.168.1.1", "--dns-mode", "windivert"])
    assert stopped.value.code == 2 and "Windows only" in capsys.readouterr().err

    monkeypatch.setattr(sys, "platform", "win32")
    cfg = parse_args(["--dns-upstream", "192.168.1.1", "--dns-mode", "windivert"])
    assert cfg.dns_mode == "windivert"
    with pytest.raises(SystemExit) as stopped:
        parse_args(["--dns-mode", "windivert"])
    assert stopped.value.code == 2 and "--dns-upstream" in capsys.readouterr().err


def test_the_receiver_passes_dns_mode_and_refuses_windivert_off_windows(tmp_path, monkeypatch):
    from stadiacast import receiver as receiver_module

    seen: dict[str, list[str]] = {}

    def fake(_name: str, args: list[str]) -> list[str]:
        seen["args"] = list(args)
        return [sys.executable, "-c", "import time; time.sleep(30)"]

    monkeypatch.setattr(receiver_module, "helper_command", fake)

    async def run_auto() -> None:
        rx = make_receiver(tmp_path, dns_upstream="192.168.1.1")
        await rx.start()
        try:
            started = next(r for r in rx.log.records if r["event"] == "dns_sink_started")
            assert started["dns_mode"] == "auto"
        finally:
            await rx.stop()

    asyncio.run(run_auto())
    assert seen["args"][seen["args"].index("--dns-mode") + 1] == "auto"

    async def run_windivert() -> None:
        rx: Receiver = make_receiver(tmp_path / "win", dns_upstream="192.168.1.1", dns_mode="windivert")
        try:
            with pytest.raises(SetupError, match="Windows only"):
                await rx.start()
        finally:
            await rx.stop()

    asyncio.run(run_windivert())
