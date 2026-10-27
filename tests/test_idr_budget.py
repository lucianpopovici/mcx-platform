"""IF-IDR against its 50 ms budget (PLT-ICD-001 ICD-OP-01, closed 2026-10-27:
measured with tests/bench_idr.py). Timing on a shared machine is not a pass
criterion here; these catch what would make the budget unreachable at any
speed: work that grows faster than the directory."""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.hooks import LocationContext, MediaKind, SessionRequest  # noqa: E402


def _drivers(n):
    loaded = loader.load(ROOT / "profiles" / "frmcs")
    r = loaded.hooks.identity_resolver
    drivers = [f"sip:d{i}@frmcs.example" for i in range(n)]
    for i, d in enumerate(drivers):
        r.register_user(d)
        r.bind("train-driver", d, LocationContext(attributes={"train_id": f"T{i}"}))
    return r, drivers


def _request():
    return SessionRequest(request_id="r", initiator="sip:x@frmcs.example", target="",
                          call_type="rec-broadcast", media=(MediaKind.VOICE,))


def test_every_driver_by_criteria_is_linear_in_the_holders():
    """ICD-OP-01: a list searched once per holder made 5 000 drivers take
    94 ms; 20 000 would take about 1.5 s. Linear, it is a few ms; the bound
    is wide so a slow machine does not fail it, and a quadratic one does."""
    r, drivers = _drivers(20_000)
    started = time.perf_counter()
    got = r.determine_participants("train-driver", _request())
    assert (time.perf_counter() - started) * 1000 < 500
    # Every holder once, in the order the trains were bound.
    assert got.members == tuple(drivers)


def test_criteria_naming_a_holder_twice_list_it_once_in_first_order():
    r, drivers = _drivers(3)
    got = r.determine_participants(
        "sip:T2.train-driver@frmcs.example, train-driver", _request())
    assert got.members == (drivers[2], drivers[0], drivers[1])


def test_the_benchmark_runs_and_reports_every_case():
    from tests import bench_idr
    results = bench_idr.run(scale=0.01, runs=3)
    assert list(results) == [
        "mcx resolve user (1000 users)",
        "mcx resolve group of 1", "mcx resolve group of 10", "mcx resolve group of 50",
        "mcx resolve group of 200",
        "frmcs identities_of (50 trains held)",
        "frmcs resolve one train's driver (50 held)",
        "frmcs unbind or bind a driver (50 held)",
        "frmcs determine_participants train-driver (50 held)",
        "frmcs resolve rec-area in one section (50 holders)",
        "core step: ad hoc call listing 10 participants",
    ]
    # Every case but the core step is one invocation, held to the budget.
    assert [held for *_, held in results.values()] == [True] * 10 + [False]
    for p50, p99, mx, _ in results.values():
        assert 0 <= p50 <= p99 <= mx
    assert bench_idr.main(["--scale", "0.01", "--runs", "3"]) == 0


def test_the_99th_of_100_runs_is_not_the_largest():
    from tests.bench_idr import _percentile
    runs = [float(i) for i in range(1, 101)]
    assert (_percentile(runs, 50), _percentile(runs, 99), _percentile(runs, 100)) == \
        (50.0, 99.0, 100.0)
    assert _percentile([7.0], 99) == 7.0


def test_a_listed_ad_hoc_call_is_linear_and_keeps_first_order():
    """Review of ICD-OP-01: the core's list of listed participants was
    searched once per entry, quadratic in the list (88 ms for 5 000)."""
    from core.audit import Auditor, MemorySink
    from core.invoke import Invoker
    from core.session import SessionManager
    loaded = loader.load(ROOT / "profiles" / "frmcs")
    r = loaded.hooks.identity_resolver
    users = [f"sip:d{i}@frmcs.example" for i in range(40_001)]
    for u in users:
        r.register_user(u)
    mgr = SessionManager(loaded, Auditor(MemorySink(), "t", clock=time.monotonic_ns),
                         clock=lambda: 0, cells={}, adhoc_list_max=40_003)
    listed = (users[2], users[1], users[2], "sip:nobody@frmcs.example") + tuple(users[3:40_000])
    request = SessionRequest(request_id="r", initiator=users[40_000], target="",
                             call_type="rec-broadcast", media=(MediaKind.VOICE,),
                             participants=listed)
    started = time.perf_counter()
    resolution, refusal = mgr._adhoc_members(Invoker(Auditor(MemorySink(), "t"), "t"),
                                            request)
    elapsed = (time.perf_counter() - started) * 1000
    assert refusal is None
    assert resolution.members[:3] == (users[2], users[1], users[3])
    assert len(resolution.members) == 39_999
    # Linear: about 1 s on a shared 2-CPU machine; the list made it 8 s.
    assert elapsed < 4_000


def test_a_role_and_its_holder_listed_together_are_invited_once():
    """Review of ICD-OP-01: two entries resolving to one user (a train's
    driver by the train, and by the driver's own address) are one member."""
    from core.audit import Auditor, MemorySink
    from core.invoke import Invoker
    from core.session import SessionManager
    loaded = loader.load(ROOT / "profiles" / "frmcs")
    r = loaded.hooks.identity_resolver
    users = [f"sip:d{i}@frmcs.example" for i in range(4)]
    for u in users:
        r.register_user(u)
    r.bind("train-driver", users[2], LocationContext(attributes={"train_id": "T2"}))
    mgr = SessionManager(loaded, Auditor(MemorySink(), "t"), clock=lambda: 0, cells={},
                         adhoc_list_max=10)
    request = SessionRequest(request_id="r", initiator=users[3], target="",
                             call_type="rec-broadcast", media=(MediaKind.VOICE,),
                             participants=("sip:T2.train-driver@frmcs.example", users[1],
                                           users[2]))
    resolution, refusal = mgr._adhoc_members(Invoker(Auditor(MemorySink(), "t"), "t"),
                                            request)
    assert refusal is None
    assert resolution.members == (users[2], users[1])
