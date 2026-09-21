"""Durable store for audit records and session records (PLT-GEN-009).

`SessionStore` is the narrow interface; `SqliteStore` is the R1 implementation.
Every write is committed before the call returns, so a record the platform has
acknowledged survives a kill at any later instant (VP1-OAM-005). A failed write
raises: a session must not be reported established when its record was lost.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Protocol

from core.audit import Record

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_id TEXT NOT NULL,
    type           TEXT NOT NULL,
    at_ms          INTEGER NOT NULL,
    profile        TEXT NOT NULL,
    body           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_by_session ON audit (correlation_id);
CREATE TABLE IF NOT EXISTS sessions (
    correlation_id TEXT PRIMARY KEY,
    state          TEXT NOT NULL,
    profile        TEXT NOT NULL,
    established_at_ms INTEGER NOT NULL,
    released_at_ms INTEGER,
    body           TEXT NOT NULL
);
"""


class SessionStore(Protocol):
    def emit(self, record: Record) -> None: ...          # audit Sink
    def save_session(self, correlation_id: str, state: str, profile: str,
                     at_ms: int, body: Mapping[str, Any]) -> None: ...
    def mark_released(self, correlation_id: str, at_ms: int) -> None: ...
    def discard_session(self, correlation_id: str) -> None: ...
    def has_session(self, correlation_id: str) -> bool: ...
    def sessions(self) -> List[Dict[str, Any]]: ...
    def audit_records(self, correlation_id: Optional[str] = None
                      ) -> List[Dict[str, Any]]: ...
    def counts(self) -> Dict[str, int]: ...
    def close(self) -> None: ...


class SqliteStore:
    FILENAME = "mcx.sqlite3"

    def __init__(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / self.FILENAME
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False,
                                   isolation_level=None)   # explicit commits
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(SCHEMA)

    def _write(self, sql: str, args: tuple) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(sql, args)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def emit(self, record: Record) -> None:
        self._write(
            "INSERT INTO audit (correlation_id, type, at_ms, profile, body) "
            "VALUES (?,?,?,?,?)",
            (record.correlation_id, record.type.value, record.at_ms,
             record.profile, record.to_json()))

    def save_session(self, correlation_id, state, profile, at_ms, body) -> None:
        self._write(
            "INSERT OR REPLACE INTO sessions (correlation_id, state, profile, "
            "established_at_ms, released_at_ms, body) VALUES (?,?,?,?,NULL,?)",
            (correlation_id, state, profile, at_ms,
             json.dumps(body, sort_keys=True, default=str)))

    def mark_released(self, correlation_id: str, at_ms: int) -> None:
        self._write("UPDATE sessions SET state='released', released_at_ms=? "
                    "WHERE correlation_id=?", (at_ms, correlation_id))

    def discard_session(self, correlation_id: str) -> None:
        self._write("DELETE FROM sessions WHERE correlation_id=?",
                    (correlation_id,))

    def has_session(self, correlation_id: str) -> bool:
        """Direct inspection of the table (VP1-SIG-005): a row, or not."""
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM sessions WHERE correlation_id=?",
                (correlation_id,)).fetchone()
        return row is not None

    def sessions(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT correlation_id, state, profile, established_at_ms, "
                "released_at_ms, body FROM sessions ORDER BY established_at_ms, "
                "correlation_id").fetchall()
        return [{"correlation_id": r[0], "state": r[1], "profile": r[2],
                 "established_at_ms": r[3], "released_at_ms": r[4],
                 **json.loads(r[5])} for r in rows]

    def audit_records(self, correlation_id: Optional[str] = None):
        sql = "SELECT body FROM audit"
        args: tuple = ()
        if correlation_id is not None:
            sql += " WHERE correlation_id=?"
            args = (correlation_id,)
        with self._lock:
            rows = self._db.execute(sql + " ORDER BY seq", args).fetchall()
        return [json.loads(r[0]) for r in rows]

    def counts(self) -> Dict[str, int]:
        with self._lock:
            a = self._db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
            s = self._db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        return {"audit": a, "sessions": s}

    def close(self) -> None:
        with self._lock:
            self._db.close()
