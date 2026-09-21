"""HTTP surface: health, readiness and group documents.

Standard library only. Nothing here reaches into `core/`; it reads a Runtime.
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import unquote

from .groups import MEDIA_TYPE, render
from .runtime import Runtime

log = logging.getLogger("mcx.http")

GROUPS_PREFIX = "/docs/groups"


class Handler(BaseHTTPRequestHandler):
    server_version = "mcx-platform"
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

    def __init__(self, runtime: Runtime, host: str, port: int) -> None:
        self.runtime = runtime
        super().__init__((host, port), Handler)

    @property
    def bound_port(self) -> int:
        return self.server_address[1]
