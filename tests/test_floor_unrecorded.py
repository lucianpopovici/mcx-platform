"""RES-OP-14 (owner ruling 2026-10-16): MCX_FLOOR_UNRECORDED.

How the floor behaves while the audit store is failing:

  deny   a transition that cannot be recorded is undone and not sent; the
         floor stops until the store recovers (PLT-FC-011 kept). The
         behaviour since RES-OP-03.
  allow  it stands and is sent; the transitions lost are counted, logged at
         most every 10 s, shown in the health document, and written as one
         `audit-gap` record before the next record the store takes. A
         departure from PLT-FC-011, reported at startup.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.audit import (AUDIT_GAP_CORRELATION_ID, GAP_ERROR_CHARS,  # noqa: E402
                        GAP_ID_CHARS, GAP_LOG_INTERVAL_MS, GAP_RETRY_MS,
                        GAP_SESSIONS_LISTED, MemorySink, RecordType)
from core.errors import StartupRefused  # noqa: E402
from core.floor import FloorState  # noqa: E402
from core.session import FLOOR_UNRECORDED, SessionState  # noqa: E402
from service.config import Config  # noqa: E402
from service.runtime import build_runtime  # noqa: E402
from tests.test_session import _altered, req  # noqa: E402
from tests.test_settings import _plain_env  # noqa: E402
from tests.test_sip_transport import Clock  # noqa: E402

PROFILES = ROOT / "profiles"


class SinkDown(MemorySink):
    def __init__(self):
        super().__init__()
        self.down = False

    def emit(self, record):
        if self.down:
            raise OSError("audit store unavailable")
        super().emit(record)


class Now:
    def __init__(self):
        self.ms = 1_000

    def __call__(self):
        return self.ms


@pytest.fixture
def mcx():
    return loader.load(PROFILES / "mcx")


def _manager(mcx, sink, choice, clock=None):
    """The manager's own auditor shares the clock, so the gap's times and
    the retry interval are the test's."""
    from core.audit import Auditor
    clock = clock or Now()
    mgr = _altered(mcx, sink, floor_unrecorded=choice, clock=clock)
    mgr._auditor._now = clock
    return mgr


def _request_floor(session, who="sip:u1@mcptt.example", priority=1):
    from core.floor import Event, EventType
    return session.floor.handle(Event(EventType.FLOOR_REQUEST, participant=who,
                                      floor_priority=priority))


# ============================================================ the setting


def test_the_choices_are_pinned():
    assert FLOOR_UNRECORDED == ("deny", "allow")
    assert GAP_LOG_INTERVAL_MS == 10_000 and GAP_SESSIONS_LISTED == 100
    assert GAP_RETRY_MS == 1_000 and GAP_ID_CHARS == 128 and GAP_ERROR_CHARS == 256
    assert AUDIT_GAP_CORRELATION_ID == "audit-gap"


def test_it_is_required_with_no_default(tmp_path):
    env = _plain_env(tmp_path)
    env.pop("MCX_FLOOR_UNRECORDED")
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(env)
    assert "MCX_FLOOR_UNRECORDED is not set" in str(exc.value)
    assert "no default" in str(exc.value)
    with pytest.raises(StartupRefused) as exc:
        Config.from_env({**env, "MCX_FLOOR_UNRECORDED": "maybe"})
    assert "MCX_FLOOR_UNRECORDED='maybe' must be 'deny' or 'allow'" in str(exc.value)


@pytest.mark.parametrize("value", ["deny", "allow"])
def test_the_stated_value_reaches_the_manager_and_the_report(tmp_path, value):
    r = build_runtime(_plain_env(tmp_path, MCX_FLOOR_UNRECORDED=value.upper()), Clock())
    try:
        snap = r.health.snapshot()
        assert snap["settings"]["MCX_FLOOR_UNRECORDED"] == value
        assert snap["audit"] == {"floor_unrecorded": value,
                                 "unrecorded_floor_records": 0, "pending_gap": None}
        reported = [d for d in snap["deviations"] if d["setting"] == "MCX_FLOOR_UNRECORDED"]
        assert bool(reported) is (value == "allow")
        if reported:
            assert reported[0]["ref"] == "RES-OP-14"
            assert reported[0]["departs_from"] == (
                "PLT-SRS PLT-FC-011 (every floor transition recorded); PLT-ICD-001 "
                "ICD-GEN-040/041 (the IF-PRI evaluation of a floor request)")
    finally:
        r.close()


def test_the_manager_refuses_an_unknown_choice(mcx):
    with pytest.raises(ValueError):
        _manager(mcx, MemorySink(), "sometimes")


# ============================================================ deny


def test_deny_undoes_a_transition_it_cannot_record(mcx):
    sink = SinkDown()
    mgr = _manager(mcx, sink, "deny")
    session, _, _ = mgr.establish(req(rid="d1"))
    before = (session.floor.state, session.floor.queue)
    sink.down = True
    with pytest.raises(OSError):
        _request_floor(session)
    assert (session.floor.state, session.floor.queue) == before
    assert mgr.floor_audit_state()["unrecorded_floor_records"] == 0


# ============================================================ allow


def test_allow_keeps_the_transition_and_its_actions(mcx):
    sink = SinkDown()
    mgr = _manager(mcx, sink, "allow")
    session, _, _ = mgr.establish(req(rid="a1"))
    sink.down = True
    actions = _request_floor(session)
    assert actions                                   # sent, not withheld
    assert session.floor.queue == ("sip:u1@mcptt.example",)
    state = mgr.floor_audit_state()
    assert state["unrecorded_floor_records"] == 1
    assert state["pending_gap"] == {"unrecorded": 1, "from_ms": 1_000, "to_ms": 1_000}


def test_the_gap_is_written_before_the_next_record(mcx):
    sink, now = SinkDown(), Now()
    mgr = _manager(mcx, sink, "allow", clock=now)
    session, _, _ = mgr.establish(req(rid="a2"))
    sink.down = True
    _request_floor(session, "sip:u1@mcptt.example")
    now.ms = 4_000
    _request_floor(session, "sip:u2@mcptt.example")
    sink.down = False
    now.ms = 9_000
    _request_floor(session, "sip:u3@mcptt.example")
    tail = [r for r in sink.records if r.type in (RecordType.AUDIT_GAP,
                                                  RecordType.FLOOR_TRANSITION)][-2:]
    assert [r.type for r in tail] == [RecordType.AUDIT_GAP, RecordType.FLOOR_TRANSITION]
    gap = tail[0]
    assert gap.correlation_id == "audit-gap"
    assert gap.detail == {"unrecorded": 2, "by_type": {"floor-transition": 2},
                          "from_ms": 1_000, "to_ms": 4_000, "sessions": ("a2",),
                          "sessions_omitted": 0,
                          "error": "OSError: audit store unavailable"}
    assert tail[1].detail["trigger"]["participant"] == "sip:u3@mcptt.example"
    assert mgr.floor_audit_state()["pending_gap"] is None
    assert mgr.floor_audit_state()["unrecorded_floor_records"] == 2


def test_a_gap_that_cannot_be_written_stays_pending_and_grows(mcx):
    sink = SinkDown()
    mgr = _manager(mcx, sink, "allow")
    session, _, _ = mgr.establish(req(rid="a3"))
    sink.down = True
    for i in range(1, 4):
        _request_floor(session, f"sip:u{i}@mcptt.example")
        mgr._auditor._now.ms += GAP_RETRY_MS              # each one tries the store
    assert mgr.floor_audit_state()["pending_gap"]["unrecorded"] == 3
    assert not sink.of_type(RecordType.AUDIT_GAP)


def test_a_session_ending_writes_a_pending_gap(mcx):
    sink = SinkDown()
    mgr = _manager(mcx, sink, "allow")
    session, _, _ = mgr.establish(req(rid="a4"))
    sink.down = True
    _request_floor(session)
    sink.down = False
    mgr.release("a4")              # the session's end, a plain record, writes it
    assert session.state is SessionState.RELEASED
    types = [r.type for r in sink.records]
    gap_at = types.index(RecordType.AUDIT_GAP)
    assert types.index(RecordType.SESSION_RELEASED) == gap_at + 1
    # the request, and the final transition made within the retry interval
    assert sink.of_type(RecordType.AUDIT_GAP)[0].detail["by_type"] == \
        {"floor-transition": 2}


def test_the_gap_lists_at_most_a_hundred_sessions(mcx):
    sink = SinkDown()
    mgr = _manager(mcx, sink, "allow")
    sessions = [mgr.establish(req(rid=f"s{i}", initiator="sip:u0@mcptt.example"))[0]
                for i in range(GAP_SESSIONS_LISTED + 3)]
    sink.down = True
    for s in sessions:
        _request_floor(s)
    _request_floor(sessions[0], "sip:u2@mcptt.example")      # one listed already
    sink.down = False
    mgr._auditor._now.ms += GAP_RETRY_MS
    _request_floor(sessions[1], "sip:u3@mcptt.example")
    gap = sink.of_type(RecordType.AUDIT_GAP)[0].detail
    assert gap["unrecorded"] == GAP_SESSIONS_LISTED + 4
    assert gap["sessions"] == tuple(f"s{i}" for i in range(GAP_SESSIONS_LISTED))
    assert gap["sessions_omitted"] == 3


def test_the_failure_is_logged_at_most_every_ten_seconds(mcx, caplog):
    sink, now = SinkDown(), Now()
    mgr = _manager(mcx, sink, "allow", clock=now)
    session, _, _ = mgr.establish(req(rid="a5"))
    sink.down = True
    with caplog.at_level(logging.ERROR, logger="mcx.audit"):
        for i in range(50):
            now.ms = 1_000 + i * 100                 # 50 failures in 5 s
            _request_floor(session, f"sip:u{1 + i % 3}@mcptt.example", priority=i)
        now.ms = 11_000
        _request_floor(session, "sip:u1@mcptt.example", priority=99)
    errors = [r.getMessage() for r in caplog.records
              if r.name == "mcx.audit" and r.levelno == logging.ERROR]
    assert len(errors) == 2
    assert errors[0].startswith("audit store failing: the floor runs unrecorded "
                                "(MCX_FLOOR_UNRECORDED=allow); 1 record(s) so far in this gap")


def test_a_final_transition_stands_either_way(mcx):
    for choice in FLOOR_UNRECORDED:
        sink = SinkDown()
        mgr = _manager(mcx, sink, choice)
        session, _, _ = mgr.establish(req(rid=f"f-{choice}"))
        sink.down = True
        mgr.release(f"f-{choice}")
        assert session.floor.state is FloorState.RELEASED


def test_a_flapping_store_logs_at_most_every_ten_seconds(mcx, caplog):
    sink, now = SinkDown(), Now()
    mgr = _manager(mcx, sink, "allow", clock=now)
    session, _, _ = mgr.establish(req(rid="a6"))
    with caplog.at_level(logging.WARNING, logger="mcx.audit"):
        sink.down = True
        _request_floor(session, "sip:u1@mcptt.example")          # logged, t=1000
        sink.down = False
        now.ms = 2_000
        _request_floor(session, "sip:u2@mcptt.example")          # gap written
        sink.down = True
        now.ms = 3_000
        _request_floor(session, "sip:u3@mcptt.example")          # a new gap, within 10 s
        now.ms = 11_500
        _request_floor(session, "sip:u1@mcptt.example", 7)       # 10 s on: logged
    logged = [r.levelno for r in caplog.records if r.name == "mcx.audit"]
    # the failure, its recovery (a logged gap always logs its end), then
    # nothing for 10 s from the first failure; then the next failure
    assert logged == [logging.ERROR, logging.WARNING, logging.ERROR]


def test_a_pending_gap_is_written_before_any_next_record(mcx):
    """Not only the floor's: a new session's hook and admission records
    follow the gap (re-review, finding 1)."""
    sink = SinkDown()
    mgr = _manager(mcx, sink, "allow")
    voice, _, _ = mgr.establish(req(rid="g1"))
    sink.down = True
    _request_floor(voice)
    sink.down = False
    first = len(sink.records)
    mgr.establish(req(rid="g2"))
    assert sink.records[first].type is RecordType.AUDIT_GAP


def test_while_a_gap_is_pending_the_store_is_tried_once_a_second(mcx):
    """A store that fails slowly costs one attempt per GAP_RETRY_MS, not one
    per record under the core lock (re-review, finding 6)."""
    attempts = []

    class Counting(SinkDown):
        def emit(self, record):
            attempts.append(record.type)
            super().emit(record)

    sink, now = Counting(), Now()
    mgr = _manager(mcx, sink, "allow", clock=now)
    session, _, _ = mgr.establish(req(rid="t1"))
    sink.down = True
    attempts.clear()
    for i in range(20):                                # 20 records in 0.95 s
        now.ms = 1_000 + i * 50
        _request_floor(session, f"sip:u{1 + i % 3}@mcptt.example", priority=i)
    assert len(attempts) == 1
    assert mgr.floor_audit_state()["pending_gap"]["unrecorded"] == 20
    now.ms = 2_000
    _request_floor(session, "sip:u1@mcptt.example", priority=50)
    assert len(attempts) == 2                          # the gap, failing again


def test_a_gap_that_cannot_be_written_never_blocks_the_record_behind_it(mcx):
    """A gap the store refuses for its own sake (its size, say) stays
    pending; the session's end record is still written (finding 5)."""
    class RefusesGaps(SinkDown):
        def emit(self, record):
            if record.type is RecordType.AUDIT_GAP:
                raise ValueError("record too large")
            super().emit(record)

    sink = RefusesGaps()
    mgr = _manager(mcx, sink, "allow")
    session, _, _ = mgr.establish(req(rid="b1"))
    sink.down = True
    _request_floor(session)
    sink.down = False
    mgr.release("b1")
    assert sink.of_type(RecordType.SESSION_RELEASED)
    assert mgr.floor_audit_state()["pending_gap"]["unrecorded"] >= 1
    assert mgr._auditor.pending_gap()["error"] == "ValueError: record too large"


def test_long_ids_and_errors_are_clipped(mcx):
    sink, now = SinkDown(), Now()
    mgr = _manager(mcx, sink, "allow", clock=now)
    long_id = "x" * 1000
    session, _, _ = mgr.establish(req(rid=long_id))

    class Huge(OSError):
        def __str__(self):
            return "y" * 5000
    sink.down = True
    sink.emit = lambda record: (_ for _ in ()).throw(Huge())
    _request_floor(session)
    gap = mgr._auditor.pending_gap()
    assert gap["sessions"] == ("x" * (GAP_ID_CHARS - 1) + "\u2026",)
    assert len(gap["error"]) == GAP_ERROR_CHARS and gap["error"].endswith("\u2026")


def test_the_health_read_does_not_race_the_gap_closing(mcx):
    """floor_audit_state reads under the auditor's lock (finding 2)."""
    import threading
    sink, now = SinkDown(), Now()
    mgr = _manager(mcx, sink, "allow", clock=now)
    session, _, _ = mgr.establish(req(rid="h1"))
    errors, stop = [], threading.Event()

    def read():
        while not stop.is_set():
            try:
                mgr.floor_audit_state()
            except Exception as exc:                   # noqa: BLE001
                errors.append(exc)
    t = threading.Thread(target=read)
    t.start()
    try:
        for i in range(300):
            sink.down = i % 2 == 0
            now.ms += GAP_RETRY_MS
            _request_floor(session, f"sip:u{1 + i % 3}@mcptt.example", priority=i)
    finally:
        stop.set()
        t.join()
    assert errors == []


def test_the_final_transition_lost_under_allow_is_counted(mcx):
    sink = SinkDown()
    mgr = _manager(mcx, sink, "allow")
    session, _, _ = mgr.establish(req(rid="fz"))
    sink.down = True
    mgr.release("fz")
    assert session.floor.state is FloorState.RELEASED
    assert mgr._auditor.pending_gap()["by_type"] == {"floor-transition": 1}


def test_a_gap_pending_at_shutdown_is_written_or_logged_in_full(tmp_path, caplog):
    from service.runtime import build_runtime as br
    r = br(_plain_env(tmp_path, MCX_FLOOR_UNRECORDED="allow"), Clock())
    emit = r.store.emit
    r.store.emit = lambda rec: (_ for _ in ()).throw(OSError("down"))
    r.auditor.emit_or_count(RecordType.FLOOR_TRANSITION, "z1")
    r.store.emit = emit
    r.close()                                          # store works: written
    from service.store import SqliteStore
    again = SqliteStore(tmp_path / "data")
    try:
        assert [x["detail"]["unrecorded"] for x in again.audit_records("audit-gap")] == [1]
    finally:
        again.close()
    # and with the store still failing, the whole gap goes to the log
    r2 = br(_plain_env(tmp_path, MCX_FLOOR_UNRECORDED="allow"), Clock())
    r2.store.emit = lambda rec: (_ for _ in ()).throw(OSError("down"))
    r2.auditor.emit_or_count(RecordType.FLOOR_TRANSITION, "z2")
    with caplog.at_level(logging.ERROR, logger="mcx.service"):
        r2.close()
    msg = [m for m in caplog.messages if m.startswith("audit gap not written before shutdown")]
    assert len(msg) == 1 and "'sessions': ('z2',)" in msg[0] and "'unrecorded': 1" in msg[0]


def test_an_establishment_that_cannot_be_recorded_leaves_no_session(mcx):
    """Pre-existing, found by the review: the session stayed in memory,
    counted toward capacity, after its admission record failed (note 7)."""
    for choice in FLOOR_UNRECORDED:
        class FailsAdmission(MemorySink):
            def emit(self, record):
                if record.type is RecordType.SESSION_ADMITTED:
                    raise OSError("down")
                super().emit(record)
        mgr = _manager(mcx, FailsAdmission(), choice)
        with pytest.raises(OSError):
            mgr.establish(req(rid=f"x-{choice}"))
        assert mgr.session(f"x-{choice}") is None and mgr.active == ()

    # admitted written, established not: the trail is closed with a failure
    class FailsEstablished(MemorySink):
        def emit(self, record):
            if record.type is RecordType.SESSION_ESTABLISHED:
                raise OSError("down")
            super().emit(record)
    sink = FailsEstablished()
    mgr = _manager(mcx, sink, "deny")
    with pytest.raises(OSError):
        mgr.establish(req(rid="z1"))
    trail = [r.type for r in sink.for_session("z1") if r.type is not RecordType.HOOK_INVOCATION]
    assert trail == [RecordType.SESSION_ADMITTED, RecordType.SESSION_FAILED]
    assert sink.of_type(RecordType.SESSION_FAILED)[-1].detail["detail"] == \
        "establishment not recorded"


def test_the_sqlite_store_waits_at_most_a_second_on_a_lock():
    from service import store
    assert store.BUSY_TIMEOUT_S == 1.0


def test_a_locked_store_fails_a_write_after_about_a_second(tmp_path):
    import sqlite3
    import time
    from core.audit import Record
    from service.store import SqliteStore
    store = SqliteStore(tmp_path)
    other = sqlite3.connect(str(store.path), isolation_level=None)
    other.execute("BEGIN EXCLUSIVE")
    started = time.monotonic()
    try:
        with pytest.raises(sqlite3.OperationalError):
            store.emit(Record(RecordType.AUDIT_GAP, "x", 0, "p"))
        assert 0.8 < time.monotonic() - started < 3
    finally:
        other.execute("ROLLBACK")
        other.close()
        store.close()



def test_a_recovered_store_is_used_at_once_not_after_the_retry_window(mcx):
    """Once any write has succeeded, the floor's next record is tried at
    once, not counted lost (re-review, note 3)."""
    sink, now = SinkDown(), Now()
    mgr = _manager(mcx, sink, "allow", clock=now)
    session, _, _ = mgr.establish(req(rid="w1"))
    sink.down = True
    _request_floor(session, "sip:u1@mcptt.example")     # gap opens, t=1000
    sink.down = False
    now.ms = 1_200
    mgr._auditor.emit(RecordType.BINDING_CHANGED, "other")   # any writer: gap + record
    assert sink.of_type(RecordType.AUDIT_GAP)
    now.ms = 1_400
    _request_floor(session, "sip:u2@mcptt.example")
    assert mgr.floor_audit_state()["pending_gap"] is None
    assert sink.records[-1].type is RecordType.FLOOR_TRANSITION
