"""Audit trail.

PLT-OAM-001..005. Every record carries the loaded profile's identity triple and
a correlation identifier stable for the life of a session, so a session can be
reconstructed from the trail alone.

Records are values, not log lines: the sink decides how they are rendered. This
keeps the audit obligation separate from the logging configuration, which is
what makes PLT-OAM-003 ("tamper-evident, retained") implementable later without
touching call paths.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol


class RecordType(Enum):
    HOOK_INVOCATION = "hook-invocation"
    SESSION_ADMITTED = "session-admitted"
    SESSION_REFUSED = "session-refused"
    SESSION_ESTABLISHED = "session-established"
    SESSION_RELEASED = "session-released"
    SESSION_FAILED = "session-failed"
    FLOOR_TRANSITION = "floor-transition"
    # A functional identity activated, deactivated, taken over, restored or
    # dropped at restart (core/functional.py, TS 24.379 clause 9A).
    BINDING_CHANGED = "binding-changed"
    # A functional alias request refused, with its reason code.
    BINDING_REFUSED = "binding-refused"
    # Once per process start, when the configuration has been accepted and
    # before any listener binds: the deployment's stated behaviour settings
    # and which of them depart from the standard (owner ruling 2026-10-16).
    CONFIGURATION_ACCEPTED = "configuration-accepted"
    # MCX_FLOOR_UNRECORDED=allow (RES-OP-14): the floor transitions the store
    # could not take, written when it takes records again, before the next.
    AUDIT_GAP = "audit-gap"


@dataclass(frozen=True)
class Record:
    type: RecordType
    correlation_id: str
    at_ms: int
    profile: str            # name/version/hash — PLT-OAM-001
    detail: Mapping[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        d = asdict(self)
        d["type"] = self.type.value
        return json.dumps(d, sort_keys=True, default=str)


class Sink(Protocol):
    def emit(self, record: Record) -> None: ...


class MemorySink:
    """Collects records. Used by tests and by the trace comparator."""

    def __init__(self) -> None:
        self.records: List[Record] = []

    def emit(self, record: Record) -> None:
        self.records.append(record)

    def of_type(self, record_type: RecordType) -> List[Record]:
        return [r for r in self.records if r.type is record_type]

    def for_session(self, correlation_id: str) -> List[Record]:
        return [r for r in self.records if r.correlation_id == correlation_id]


# RES-OP-14 (MCX_FLOOR_UNRECORDED=allow): the records the store could not
# take are counted into one gap, written as an `audit-gap` record ahead of
# the next record any writer makes once the store takes records again.
AUDIT_GAP_CORRELATION_ID = "audit-gap"
GAP_LOG_INTERVAL_MS = 10_000    # failures logged at most this often
GAP_RETRY_MS = 1_000            # while a gap is pending, the store is tried this often
GAP_SESSIONS_LISTED = 100
GAP_ID_CHARS = 128              # each listed session id, and
GAP_ERROR_CHARS = 256           # the last error, at most this long

log = logging.getLogger("mcx.audit")


class Auditor:
    """Binds a sink to the loaded profile's identity and a clock.

    `emit` writes or raises. `emit_or_count` (the floor's records under
    MCX_FLOOR_UNRECORDED=allow) writes or, if the store cannot take it,
    counts it into the pending gap and returns None; while a gap is pending
    the store is tried at most every GAP_RETRY_MS, so a store that fails
    slowly does not cost a write attempt per packet. Either writes a pending
    gap first, best effort: a gap that cannot be written stays pending and
    never keeps the record behind it from being tried. State is under one
    lock, so the health document may read it from another thread."""

    def __init__(self, sink: Sink, profile_identifier: str,
                 clock: Optional[Callable[[], int]] = None) -> None:
        self._sink = sink
        self._profile = profile_identifier
        self._now = clock or (lambda: 0)
        self._lock = threading.RLock()
        self._gap: Optional[Dict[str, Any]] = None
        self._lost_total = 0
        self._last_log_ms: Optional[int] = None
        self._last_try_ms: Optional[int] = None

    def emit(self, record_type: RecordType, correlation_id: str,
             **detail: Any) -> Record:
        with self._lock:
            # The gap is always tried first, so it precedes this record. With
            # the store down that is two failed attempts, not one: accepted,
            # since only an attempt can tell a store that is down from a gap
            # the store refuses for its own sake (re-review of RES-OP-14).
            self._write_gap()
            return self._write(record_type, correlation_id, detail)

    def _waiting(self, now: int) -> bool:
        # A pending gap means the last attempt failed: a successful write of
        # any record writes the gap ahead of it and clears it.
        return (self._gap is not None and self._last_try_ms is not None
                and now - self._last_try_ms < GAP_RETRY_MS)

    def emit_or_count(self, record_type: RecordType, correlation_id: str,
                      **detail: Any) -> Optional[Record]:
        with self._lock:
            now = self._now()
            if self._waiting(now):
                self._count(record_type, correlation_id, None, now)
                return None
            self._last_try_ms = now
            if not self._write_gap():
                self._count(record_type, correlation_id, None, now)
                return None
            try:
                return self._write(record_type, correlation_id, detail)
            except Exception as exc:                        # noqa: BLE001
                self._count(record_type, correlation_id, exc, now)
                return None

    def try_flush(self, force: bool = False) -> bool:
        """Write a pending gap now (a host's tick; `force` at shutdown, which
        ignores the retry interval). True when no gap is left pending."""
        with self._lock:
            if self._gap is None:
                return True
            now = self._now()
            if not force and self._waiting(now):
                return False
            self._last_try_ms = now
            return self._write_gap()

    def gap_state(self) -> Dict[str, Any]:
        with self._lock:
            gap = self._gap
            return {"unrecorded_floor_records": self._lost_total,
                    "pending_gap": None if gap is None else
                    {k: gap[k] for k in ("unrecorded", "from_ms", "to_ms")}}

    def pending_gap(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return None if self._gap is None else self._gap_record()

    # -- internals, under the lock ----------------------------------------

    def _write(self, record_type: RecordType, correlation_id: str,
               detail: Mapping[str, Any]) -> Record:
        record = Record(type=record_type, correlation_id=correlation_id,
                        at_ms=self._now(), profile=self._profile, detail=dict(detail))
        self._sink.emit(record)
        return record

    def _gap_record(self) -> Dict[str, Any]:
        gap = {k: v for k, v in self._gap.items() if not k.startswith("_")}
        return dict(gap, sessions=tuple(gap["sessions"]),
                    by_type=dict(sorted(gap["by_type"].items())))

    def _write_gap(self) -> bool:
        if self._gap is None:
            return True
        detail = self._gap_record()
        logged = self._gap.get("_logged", False)
        try:
            self._write(RecordType.AUDIT_GAP, AUDIT_GAP_CORRELATION_ID, detail)
        except Exception as exc:                            # noqa: BLE001
            self._gap["error"] = _clip(f"{type(exc).__name__}: {exc}", GAP_ERROR_CHARS)
            return False
        self._gap = None
        # A gap whose failure was logged always logs its end; the limit
        # applies only to a gap that was never logged (re-review, 1).
        if logged or self._may_log(self._now()):
            log.warning("audit store recovered: %d record(s) of the floor were not "
                        "written between %d and %d ms (by type: %s)",
                        detail["unrecorded"], detail["from_ms"], detail["to_ms"],
                        detail["by_type"])
        return True

    def _count(self, record_type: RecordType, correlation_id: str,
               exc: Optional[BaseException], now: int) -> None:
        if self._gap is None:
            self._gap = {"unrecorded": 0, "by_type": {}, "from_ms": now, "to_ms": now,
                         "sessions": [], "sessions_omitted": 0, "error": ""}
        gap = self._gap
        gap["unrecorded"] += 1
        gap["by_type"][record_type.value] = gap["by_type"].get(record_type.value, 0) + 1
        gap["to_ms"] = now
        if exc is not None:
            gap["error"] = _clip(f"{type(exc).__name__}: {exc}", GAP_ERROR_CHARS)
        cid = _clip(correlation_id, GAP_ID_CHARS)
        if cid not in gap["sessions"]:
            if len(gap["sessions"]) < GAP_SESSIONS_LISTED:
                gap["sessions"].append(cid)
            else:
                gap["sessions_omitted"] += 1
        self._lost_total += 1
        if self._may_log(now):
            gap["_logged"] = True
            log.error("audit store failing: the floor runs unrecorded "
                      "(MCX_FLOOR_UNRECORDED=allow); %d record(s) so far in this gap, "
                      "last session %s, last error %s", gap["unrecorded"], cid,
                      gap["error"], extra={"correlation_id": cid})

    def _may_log(self, now: int) -> bool:
        """One limit for both messages, kept across a gap's close and reopen:
        a store that flaps does not log per packet."""
        if self._last_log_ms is not None and now - self._last_log_ms < GAP_LOG_INTERVAL_MS:
            return False
        self._last_log_ms = now
        return True


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "\u2026"
