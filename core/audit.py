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
    BINDING_CHANGED = "binding-changed"


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


class Auditor:
    """Binds a sink to the loaded profile's identity and a clock."""

    def __init__(self, sink: Sink, profile_identifier: str,
                 clock: Optional[Callable[[], int]] = None) -> None:
        self._sink = sink
        self._profile = profile_identifier
        self._now = clock or (lambda: 0)

    def emit(self, record_type: RecordType, correlation_id: str,
             **detail: Any) -> Record:
        record = Record(type=record_type, correlation_id=correlation_id,
                        at_ms=self._now(), profile=self._profile, detail=detail)
        self._sink.emit(record)
        return record
