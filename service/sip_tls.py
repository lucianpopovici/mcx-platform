"""The only file that opens a SIP socket. TLS or nothing (PLT-SEC-007).

There is no plaintext listener and no code path that creates one: every accepted
connection is checked for a TLS ClientHello *before* the handshake, and anything
else is closed unanswered and counted. That count is what makes VP1-SIG-006
observable rather than merely configured.
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from core.sip import SipError, split_frame

from .config import SipConfig
from .sip_core import SipCore

log = logging.getLogger("mcx.sip.tls")

TLS_HANDSHAKE_RECORD = 0x16
MAX_FRAME = 256 * 1024
HANDSHAKE_TIMEOUT_S = 10
TICK_S = 0.1


def make_context(cfg: SipConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cfg.cert), str(cfg.key))
    if cfg.ca is not None:
        ctx.load_verify_locations(str(cfg.ca))
    # "required": a peer without a certificate cannot connect. "optional": a
    # peer that supports mutual auth is verified, one that cannot still may
    # connect (PLT-SEC-007: "where the peer supports it").
    ctx.verify_mode = (ssl.CERT_REQUIRED if cfg.client_auth == "required"
                       else ssl.CERT_OPTIONAL)
    return ctx


class TlsFlow:
    def __init__(self, sock: ssl.SSLSocket, peer: str, subject: Optional[str]):
        self._sock = sock
        self.peer = peer
        self.peer_subject = subject      # None: peer presented no certificate
        self.closed = False
        self._lock = threading.Lock()

    def send(self, text: str) -> None:
        if self.closed:
            return
        try:
            with self._lock:
                self._sock.sendall(text.encode("utf-8"))
        except OSError:
            self.closed = True

    def close(self) -> None:
        self.closed = True
        try:
            self._sock.close()
        except OSError:
            pass


class TlsListener:
    def __init__(self, core: SipCore, cfg: SipConfig,
                 lock: Optional[threading.RLock] = None) -> None:
        self.core = core
        self.cfg = cfg
        self.lock = lock or threading.RLock()
        self._ctx = make_context(cfg)
        self._stop = threading.Event()
        self._srv: Optional[socket.socket] = None
        self._threads = []
        self._flows = set()
        self.counters: Dict[str, int] = {
            "accepted": 0, "plaintext_refused": 0, "handshake_failed": 0,
            "mutual_auth": 0, "no_client_cert": 0, "oversize_closed": 0}

    @property
    def bound_port(self) -> int:
        assert self._srv is not None
        return self._srv.getsockname()[1]

    def start(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.cfg.host, self.cfg.port))
        srv.listen(128)
        srv.settimeout(0.2)
        self._srv = srv
        for target in (self._accept_loop, self._tick_loop):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for f in list(self._flows):
            f.close()
        if self._srv is not None:
            self._srv.close()
        for t in self._threads:
            t.join(timeout=2)

    # -- loops -----------------------------------------------------------

    def _tick_loop(self) -> None:
        while not self._stop.wait(TICK_S):
            try:
                with self.lock:
                    self.core.tick()
            except Exception:  # noqa: BLE001
                log.exception("tick fault")

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._srv.accept()     # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                return
            t = threading.Thread(target=self._serve, args=(conn, addr), daemon=True)
            t.start()

    def _serve(self, conn: socket.socket, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        conn.settimeout(HANDSHAKE_TIMEOUT_S)
        try:
            first = conn.recv(1, socket.MSG_PEEK)
        except OSError:
            conn.close()
            return
        if not first or first[0] != TLS_HANDSHAKE_RECORD:
            # Not a TLS ClientHello: refuse without answering a single byte.
            self._count("plaintext_refused")
            log.warning("plaintext connection refused from %s", peer)
            conn.close()
            return
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            self._count("handshake_failed")
            log.warning("TLS handshake failed from %s: %s", peer, exc)
            conn.close()
            return
        cert = tls.getpeercert()
        subject = None
        if cert:
            subject = ",".join("=".join(kv) for rdn in cert.get("subject", ())
                               for kv in rdn)
            self._count("mutual_auth")
        else:
            self._count("no_client_cert")
        self._count("accepted")
        tls.settimeout(None)
        flow = TlsFlow(tls, peer, subject)
        self._flows.add(flow)
        log.info("SIP flow up peer=%s client_cert=%s", peer, subject)
        buf = b""
        try:
            while not self._stop.is_set():
                chunk = tls.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while True:
                    try:
                        frame = split_frame(buf)
                    except SipError:
                        buf = b""
                        break
                    if frame is None:
                        break
                    _, total = frame
                    message, buf = buf[:total], buf[total:]
                    with self.lock:
                        self.core.on_bytes(message, flow)
                if len(buf) > MAX_FRAME:
                    self._count("oversize_closed")
                    break
        except (OSError, ssl.SSLError):
            pass
        finally:
            with self.lock:
                self.core.on_flow_closed(flow)
            self._flows.discard(flow)
            flow.close()

    def _count(self, name: str) -> None:
        self.counters[name] += 1
