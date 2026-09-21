"""Structured, machine-parsable logging (PLT-OAM-005)."""

from __future__ import annotations

import json
import logging
import sys


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"at_ms": int(record.created * 1000), "level": record.levelname,
               "logger": record.name, "message": record.getMessage()}
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, sort_keys=True)


def configure(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
