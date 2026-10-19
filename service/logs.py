"""Structured, machine-parsable logging (PLT-OAM-005), with the session's
correlation identifier on every line about a session (VP1-OAM-004,
PLT-VP-R1 RES-OP-04).

The service sets the session a piece of work is for with `session_context`
wherever it starts one: a SIP message whose Call-ID belongs to a call, a
call's timers, a media packet, a session's floor timers. Every line logged
inside that scope, by any module, carries `correlation_id`: the same
identifier the audit records carry, so a call's log lines and its audit
trail join on it. The core cannot import the service and names the session
itself, `extra={"correlation_id": ...}`; an explicit id wins over the scope.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from contextlib import contextmanager
from typing import Iterator, Optional

_current: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "mcx_correlation_id", default=None)


@contextmanager
def session_context(correlation_id: Optional[str]) -> Iterator[None]:
    """Log lines inside this scope are about session `correlation_id`
    (none, if it is empty or None)."""
    token = _current.set(correlation_id or None)
    try:
        yield
    finally:
        _current.reset(token)


def current() -> Optional[str]:
    return _current.get()


class CorrelationFilter(logging.Filter):
    """Stamps the scope's session on a record when it is logged, in the
    thread and context that logged it, unless the record names one."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not getattr(record, "correlation_id", None):
            record.correlation_id = _current.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"at_ms": int(record.created * 1000), "level": record.levelname,
               "logger": record.name, "message": record.getMessage()}
        cid = getattr(record, "correlation_id", None)      # CorrelationFilter's
        if cid:
            out["correlation_id"] = cid
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, sort_keys=True)


def configure(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(CorrelationFilter())
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
