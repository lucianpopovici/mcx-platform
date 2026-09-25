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

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding

from core.sip import SipError, canonical_uri, split_frame

from .config import SipConfig
from .sip_core import SipCore

log = logging.getLogger("mcx.sip.tls")

TLS_HANDSHAKE_RECORD = 0x16
MAX_FRAME = 256 * 1024
HANDSHAKE_TIMEOUT_S = 10
TICK_S = 0.1


def make_context(cfg: SipConfig,
                 core_ca: Optional[x509.Certificate] = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cfg.cert), str(cfg.key))
    if cfg.ca is not None:
        ctx.load_verify_locations(str(cfg.ca))
    if core_ca is not None:
        # The cores' own anchor (ICD-OP-10), from the network profile: the
        # certificate that was checked and hashed, not the file re-read. A
        # connection verifies against either anchor; which one issued the
        # peer's certificate is decided per connection, by `issued_by`.
        ctx.load_verify_locations(cadata=core_ca.public_bytes(Encoding.DER))
    # "required": a peer without a certificate cannot connect. "optional": a
    # peer that supports mutual auth is verified, one that cannot still may
    # connect (PLT-SEC-007: "where the peer supports it").
    ctx.verify_mode = (ssl.CERT_REQUIRED if cfg.client_auth == "required"
                       else ssl.CERT_OPTIONAL)
    return ctx


def issued_by(der: Optional[bytes], ca: Optional[x509.Certificate]) -> bool:
    """ICD-OP-10: whether the peer's certificate was issued directly by the
    core CA. OpenSSL has already verified the chain to one of the anchors;
    this says which. A certificate from the users' CA carrying a trusted
    core's DNS name is therefore not a core. No certificate, or no core CA,
    is a TypeError here, and so False, like any failure to verify."""
    try:
        x509.load_der_x509_certificate(der).verify_directly_issued_by(ca)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def _san(cert, kind: str) -> tuple:
    """subjectAltName entries of one kind ('URI', 'DNS')."""
    return tuple(v.strip() for k, v in (cert or {}).get("subjectAltName", ())
                 if k == kind)


class TlsFlow:
    def __init__(self, sock: ssl.SSLSocket, peer: str, subject: Optional[str],
                 cert: Optional[dict] = None, core: bool = False):
        self._sock = sock
        self.peer = peer
        self.peer_subject = subject      # None: peer presented no certificate
        # What the verified certificate authenticates (ICD-OP-08): the SIP
        # identities a directly attached client may assert, and the DNS names
        # a trusted SIP core is recognised by. Empty without a certificate.
        self.peer_uris = tuple(canonical_uri(u) for u in _san(cert, "URI")
                               if u.lower().startswith("sip:"))
        self.peer_dns = tuple(d.lower() for d in _san(cert, "DNS"))
        # Issued by the network's core CA (ICD-OP-10): only such a peer can
        # be a trusted core, whatever DNS names it carries.
        self.peer_is_core = core
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
        self.lock = lock or core.lock
        network = core.rt.network
        self._core_ca = network.core_ca
        self._ctx = make_context(cfg, network.core_ca)
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
        with self.lock:
            self.core.close()

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
        flow = TlsFlow(tls, peer, subject, cert or None,
                       core=issued_by(tls.getpeercert(binary_form=True),
                                      self._core_ca))
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
