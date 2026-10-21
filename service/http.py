"""HTTP surface: health, readiness and group documents.

Standard library only. Nothing here reaches into `core/`; it reads a Runtime.

HTTPS or plain HTTP, as the deployment states it (`MCX_HTTP_TLS`, owner
ruling 2026-10-16; service/http_tls.py). Plain HTTP is the recorded deviation
of 2026-09-29 (PLT-VP-R1 RES-OP-05) from HTTP-1 (HTTPS, PLT-SRS 3.1), reported
at startup: group documents name every group's members, so a plain interface
belongs on a network the deployment trusts.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import unquote

from .groups import MEDIA_TYPE, render
from .http_tls import (HANDSHAKE_TIMEOUT_S, IDLE_TIMEOUT_S, MAX_CONNECTIONS,
                       MAX_PER_CLIENT, REQUEST_DEADLINE_S)
from .runtime import Runtime

# PLT-PRF-032: this module implements the HTTP-1 reference point (PLT-SRS §3.1).
REFERENCE_POINT = "HTTP-1"

log = logging.getLogger("mcx.http")

GROUPS_PREFIX = "/docs/groups"


class Handler(BaseHTTPRequestHandler):
    server_version = "mcx-platform"
    # A connection that sends no complete request in this time is closed
    # (StreamRequestHandler.setup applies it): otherwise it holds its thread.
    timeout = IDLE_TIMEOUT_S
    runtime: Runtime  # set on the server class

    def log_message(self, fmt, *args):  # route to structured logging
        log.info("%s %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        self._send(status, json.dumps(obj, sort_keys=True).encode(),
                   "application/json")

    def do_GET(self) -> None:  # noqa: N802
        rt: Runtime = self.server.runtime  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0]
        if path == "/livez":
            return self._json(200, {"live": True})
        if path == "/healthz":
            return self._json(200, rt.health.snapshot())
        if path == "/readyz":
            snap = rt.health.snapshot()
            return self._json(200 if snap["ready"] else 503,
                              {"ready": snap["ready"]})
        if path == GROUPS_PREFIX or path.startswith(GROUPS_PREFIX + "/"):
            if not rt.health.ready:
                return self._json(503, {"error": "not-ready"})
            if path == GROUPS_PREFIX:
                return self._json(200, {"groups": list(rt.groups.ids())})
            group = rt.groups.get(unquote(path[len(GROUPS_PREFIX) + 1:]))
            if group is None:
                return self._json(404, {"error": "unknown-group"})
            return self._send(200, render(group), MEDIA_TYPE)
        return self._json(404, {"error": "not-found"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # socketserver's default listen backlog of 5 leaves connections beyond it
    # waiting on SYN retransmission, unaccepted and so uncounted by the cap.
    request_queue_size = 2 * MAX_CONNECTIONS

    def __init__(self, runtime: Runtime, host: str, port: int) -> None:
        self.runtime = runtime
        # The context build_runtime checked (RES-OP-05), not a second read.
        self._tls = runtime.http_context
        if (runtime.config.http_tls is None) != (self._tls is None):
            raise ValueError("MCX_HTTP_TLS and the runtime's TLS context disagree")
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._per_client: dict = {}
        self._per_client_lock = threading.Lock()
        super().__init__((host, port), Handler)

    def _take(self, host: str) -> bool:
        with self._per_client_lock:
            if self._per_client.get(host, 0) >= MAX_PER_CLIENT:
                return False
            if not self._slots.acquire(blocking=False):
                return False
            self._per_client[host] = self._per_client.get(host, 0) + 1
            return True

    def _give_back(self, host: str) -> None:
        with self._per_client_lock:
            left = self._per_client.get(host, 1) - 1
            if left:
                self._per_client[host] = left
            else:
                self._per_client.pop(host, None)
            self._slots.release()

    def process_request(self, request, client_address) -> None:
        """At most MAX_CONNECTIONS at once, MAX_PER_CLIENT of them from one
        address; one more is closed at once rather than given a thread."""
        host = client_address[0]
        if not self._take(host):
            log.warning("%s: refused, HTTP connection limit reached (%d in all, "
                        "%d per client)", host, MAX_CONNECTIONS, MAX_PER_CLIENT)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._give_back(host)
            raise

    def process_request_thread(self, request, client_address) -> None:
        # The deadline: shut the connection down from outside, which ends any
        # read the handler is blocked in, however slowly the bytes arrive.
        # A duplicate descriptor, so the shutdown never races a TLS object.
        # Set up inside the try: if descriptors or threads run out (as in a
        # flood), the connection is closed and its slot still comes back.
        cut = timer = None
        try:
            cut = socket.socket(fileno=os.dup(request.fileno()))
            timer = threading.Timer(REQUEST_DEADLINE_S, self._cut, (cut,))
            timer.daemon = True
            timer.start()
        except (OSError, RuntimeError) as exc:
            log.warning("%s: HTTP connection closed, no deadline could be set: %s",
                        client_address[0], exc)
            if cut is not None:
                cut.close()
            self.shutdown_request(request)
            self._give_back(client_address[0])
            return
        try:
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            cut.close()
            self._give_back(client_address[0])

    @staticmethod
    def _cut(sock) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def handle_error(self, request, client_address) -> None:
        """One line, not socketserver's traceback: a client that timed out or
        was cut at the deadline is not a fault of the server."""
        exc = sys.exc_info()[1]
        log.info("%s: HTTP connection ended: %s", client_address[0], exc)

    def finish_request(self, request, client_address) -> None:
        """TLS, when on, is negotiated here, in the request's own thread: a
        client that stalls the handshake holds its thread, not the accept
        loop, and is dropped after HANDSHAKE_TIMEOUT_S."""
        if self._tls is None:
            return super().finish_request(request, client_address)
        request.settimeout(HANDSHAKE_TIMEOUT_S)
        try:
            wrapped = self._tls.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            log.info("%s: TLS handshake failed: %s", client_address[0], exc)
            return
        try:
            super().finish_request(wrapped, client_address)
        finally:
            # wrap_socket took the descriptor over; this is its only close.
            wrapped.close()

    @property
    def bound_port(self) -> int:
        return self.server_address[1]
