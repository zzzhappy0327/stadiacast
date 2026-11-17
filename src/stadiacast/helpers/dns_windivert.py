"""Answer the hotspot's DNS by capturing inbound UDP port 53, on Windows only.

Windows Mobile Hotspot (the SharedAccess service) already listens on UDP 53, so a socket
cannot.  WinDivert takes the queries addressed to this PC before that listener does.
``pydivert`` is imported in the function that opens the handle and nowhere else: importing
this module on Linux or macOS does not import it, and the dependency is not installed there.

The handle is opened as ``pydivert.WinDivert('inbound and udp.DstPort == 53')``.  That is
the default network layer, not the forward layer, and it is not a sniff: a sniffed copy
would leave SharedAccess free to answer as well.  Packets we do not answer are sent back
inbound, with their checksums left alone.  Packets we answer are sent outbound after the
endpoints are swapped, with checksums recalculated by the driver on send.  Nothing in this
module changes a DNS setting, disables the hotspot, or opens the forward layer.
"""

from __future__ import annotations

import signal
import sys
import threading
from typing import Any

from stadiacast.errors import SetupError
from stadiacast.helpers.dns_divert import (
    WINDIVERT_FILTER,
    WINDIVERT_WINDOWS_ONLY,
    DnsDivertAction,
    apply_dns_reply,
    classify_dns_payload,
    is_ipv6_packet,
)

#: Shown once, when the handle opens.  The forward-layer limitation is WinDivert's model;
#: it has not been confirmed on a machine that is sharing a hotspot.
WINDIVERT_LAYER_NOTE = (
    "captures inbound UDP/53 addressed to this PC, before Mobile Hotspot's DNS proxy. "
    "Forwarded queries such as 8.8.8.8:53 are outside this filter (WinDivert's forward layer) "
    "and were not verified against a controller"
)

_EXTRA = (
    'WinDivert DNS needs the windivert extra, which is Windows-only: pip install "stadiacast[windivert]". '
    "Then start the receiver from an Administrator terminal so the driver can load."
)
_ADMIN = (
    "WinDivert DNS needs an Administrator terminal. Windows Mobile Hotspot (the SharedAccess service) "
    "already holds UDP port 53, and capturing those packets loads the WinDivert driver. Open an elevated "
    "PowerShell and start the receiver again. This does not change the PC's DNS servers and does not turn "
    "the hotspot off ({error})"
)
_DRIVER = (
    "WinDivert's driver files could not be loaded ({error}). Reinstall the Windows extra from an "
    'Administrator terminal: pip install "stadiacast[windivert]".'
)

# ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_MOD_NOT_FOUND.
_MISSING_DRIVER = (2, 3, 126)


def load_pydivert() -> Any:
    """Import ``pydivert`` or say, as a :class:`SetupError`, how to install it."""
    try:
        import pydivert
    except ImportError as e:
        raise SetupError(_EXTRA) from e
    return pydivert


def _access_denied(exc: OSError) -> bool:
    if isinstance(exc, PermissionError):
        return True
    # ERROR_ACCESS_DENIED, and WSAEACCES when it is not already a PermissionError.
    return getattr(exc, "winerror", None) in (5, 10013)


def _driver_missing(exc: OSError) -> bool:
    return isinstance(exc, FileNotFoundError) or getattr(exc, "winerror", None) in _MISSING_DRIVER


def open_windivert_handle(module: Any | None = None) -> Any:
    """Open the port-53 capture.  ``module`` is pydivert, injected by tests.

    An access failure and a missing driver become a :class:`SetupError` that says what to
    do.  Any other error from the driver is raised unchanged.
    """
    if sys.platform != "win32":
        raise SetupError(WINDIVERT_WINDOWS_ONLY)
    pydivert = load_pydivert() if module is None else module
    handle = pydivert.WinDivert(WINDIVERT_FILTER)
    try:
        handle.open()
    except OSError as e:
        if _access_denied(e):
            raise SetupError(_ADMIN.format(error=e)) from e
        if _driver_missing(e):
            raise SetupError(_DRIVER.format(error=e)) from e
        raise
    return handle


def _endpoints(packet: Any) -> tuple[str, str]:
    src = getattr(packet, "src_addr", "?")
    dst = getattr(packet, "dst_addr", "?")
    sport = getattr(packet, "src_port", "?")
    dport = getattr(packet, "dst_port", "?")
    return f"{src}:{sport}", f"{dst}:{dport}"


def _action_for(packet: Any, resolver: Any) -> DnsDivertAction:
    if is_ipv6_packet(packet):
        return DnsDivertAction("ignore", "ipv6")
    if getattr(packet, "dst_port", None) != 53 or getattr(packet, "src_port", None) is None:
        return DnsDivertAction("ignore", "not udp port 53")
    payload = getattr(packet, "payload", None)
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        return DnsDivertAction("ignore", "no payload")
    return classify_dns_payload(
        bytes(payload),
        matches=resolver.matches,
        refused=resolver.refused,
        redirect_ip=resolver.redirect_ip,
        log_only=resolver.log_only,
    )


def _log_action(resolver: Any, action: DnsDivertAction, src: str, dst: str, src_addr: Any) -> None:
    # ``src_addr`` is the address the query came from, read before a reply swaps the endpoints.
    fields: dict[str, Any] = {
        "proto": "windivert",
        "src": src,
        "dst": dst,
        "from_controller": src_addr == resolver.controller_ip,
    }
    if action.qname is not None:
        fields["qname"] = action.qname
        fields["qtype"] = action.qtype
        fields["id"] = action.ident
    if action.kind == "ignore":
        resolver.log("query_ignored", reason=action.reason, **fields)
        return
    if action.answers is not None:
        fields["answers"] = list(action.answers)
    resolver.log("query", action=action.reason, **fields)


def handle_diverted_packet(packet: Any, handle: Any, resolver: Any, *, outbound: Any) -> None:
    """Answer ``packet`` or send it on unchanged.  One packet never ends the capture.

    A failure while sending is logged and the loop continues: dropping the rest of the
    hotspot's DNS because one datagram could not be written would be the larger fault.
    The error itself is not discarded.  An error that is not an ``OSError`` is a bug and
    is raised.
    """
    src_addr = getattr(packet, "src_addr", None)
    src, dst = _endpoints(packet)
    try:
        action = _action_for(packet, resolver)
    except Exception as e:
        resolver.log("windivert_packet_error", error=repr(e), src=src, dst=dst)
        _send(resolver, handle, packet, recalculate=False, src=src, dst=dst)
        return
    if action.kind != "reply" or action.reply is None:
        # Unchanged, including the checksums the stack already computed.  Recalculating
        # would make "passthrough" a rewrite.
        if _send(resolver, handle, packet, recalculate=False, src=src, dst=dst):
            _log_action(resolver, action, src, dst, src_addr)
        return
    apply_dns_reply(packet, action.reply, outbound)
    # pydivert recomputes the IP and UDP checksums, and the checksum-offload flags, on send.
    if _send(resolver, handle, packet, recalculate=True, src=src, dst=dst, qname=action.qname):
        _log_action(resolver, action, src, dst, src_addr)


def _send(
    resolver: Any,
    handle: Any,
    packet: Any,
    *,
    recalculate: bool,
    src: str,
    dst: str,
    qname: str | None = None,
) -> bool:
    """Send one packet.  An ``OSError`` is logged and the capture continues; anything else propagates."""
    try:
        handle.send(packet, recalculate_checksum=recalculate)
    except OSError as e:
        resolver.log("windivert_packet_error", error=str(e), src=src, dst=dst, qname=qname)
        return False
    return True


class WinDivertDnsServer:
    """The capture thread.  ``stop`` closes the handle, which unblocks ``recv``, and joins it."""

    def __init__(
        self,
        resolver: Any,
        log: Any,
        *,
        opener: Any = None,
        direction_outbound: Any = None,
        join_timeout: float = 5.0,
    ) -> None:
        self._resolver = resolver
        self._log = log
        self._opener = opener or open_windivert_handle
        self._outbound = direction_outbound
        self._join_timeout = join_timeout
        self._handle: Any = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._shutdown_done = threading.Event()
        self._lock = threading.Lock()
        self._handle_closed = False
        self._shutdown_started = False
        self._user_stop = False
        self._loop_error: BaseException | None = None
        self._close_error: BaseException | None = None
        self._previous_signals: dict[int, Any] = {}
        self._signal_handler: Any = None

    def _direction(self) -> Any:
        if self._outbound is not None:
            return self._outbound
        return load_pydivert().Direction.OUTBOUND

    def _close_handle(self) -> None:
        """Mark the capture stopped and close the handle.  Closing it is what unblocks ``recv``.

        No logging here: a signal handler calls this, and the log lock may already be held.
        """
        self._stop.set()
        handle = self._handle
        if handle is None or self._handle_closed:
            return
        self._handle_closed = True
        try:
            handle.close()
        except Exception as e:  # a second close, or a driver that has already gone
            self._close_error = e

    def _request_stop(self) -> None:
        """A Ctrl+C or ``stop``: the thread leaving is requested, not a driver failure."""
        self._user_stop = True
        self._close_handle()

    def _install_signals(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return

        def handler(_signum: int, _frame: object) -> None:
            # Close only.  serve() joins the thread when this returns; joining here would
            # run the rest of the shutdown from inside the signal.
            self._request_stop()

        self._signal_handler = handler
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._previous_signals[sig] = signal.signal(sig, handler)
            except (ValueError, OSError):
                continue

    def _restore_signals(self) -> None:
        for sig, previous in list(self._previous_signals.items()):
            try:
                signal.signal(sig, previous)
            except (ValueError, OSError):
                continue
        self._previous_signals.clear()

    def _loop(self) -> None:
        outbound = self._direction()
        handle = self._handle
        try:
            while not self._stop.is_set():
                try:
                    packet = handle.recv()
                except OSError as e:
                    if self._stop.is_set():
                        break
                    self._loop_error = e
                    self._log("windivert_recv_error", error=str(e))
                    break
                handle_diverted_packet(packet, handle, self._resolver, outbound=outbound)
        except Exception as e:
            self._loop_error = e
            self._log("windivert_loop_error", error=repr(e))
            self._stop.set()

    def _shutdown(self) -> None:
        """Close, join the capture thread once, and log how that ended.  A second caller waits for the first."""
        with self._lock:
            if self._shutdown_started:
                waiting = True
            else:
                self._shutdown_started = True
                waiting = False
        if waiting:
            self._shutdown_done.wait(self._join_timeout + 1.0)
            return
        timed_out = False
        try:
            thread = self._thread
            self._close_handle()
            if thread is not None and thread is not threading.current_thread() and thread.is_alive():
                thread.join(self._join_timeout)
                timed_out = thread.is_alive()
            self._restore_signals()
            if self._close_error is not None:
                self._log("windivert_close_error", error=repr(self._close_error))
            if timed_out:
                self._log("windivert_join_timeout", timeout_s=self._join_timeout)
            else:
                self._log("windivert_stopped")
        finally:
            self._shutdown_done.set()

    def serve(self) -> int:
        """Open the handle, answer until :meth:`stop`, and return 0 for a requested stop.

        A missing extra or a refused driver is 1 and a ``windivert_unavailable`` record.
        Any other error from opening the driver propagates.
        """
        if self._stop.is_set():
            return 0
        try:
            self._handle = self._opener()
        except SetupError as e:
            self._log("windivert_unavailable", error=str(e))
            return 1
        if self._stop.is_set():
            self._close_handle()
            return 0
        self._install_signals()
        self._log("windivert_started", filter=WINDIVERT_FILTER, layer="NETWORK", note=WINDIVERT_LAYER_NOTE)
        self._thread = threading.Thread(target=self._loop, name="dns-windivert", daemon=True)
        self._thread.start()
        try:
            while not self._stop.wait(0.25):
                if not self._thread.is_alive():
                    break
        except KeyboardInterrupt:
            self._request_stop()
        finally:
            self._shutdown()
        if self._loop_error is not None and not self._user_stop:
            return 1
        return 0

    def stop(self) -> None:
        """Close the handle, unblock ``recv``, and join the capture thread without waiting past the timeout."""
        self._user_stop = True
        self._shutdown()


def serve_windivert(resolver: Any, log: Any, **kwargs: Any) -> int:
    """Run a :class:`WinDivertDnsServer` until it is stopped.  The keyword arguments are its options."""
    return WinDivertDnsServer(resolver, log, **kwargs).serve()
