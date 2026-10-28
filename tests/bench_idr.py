#!/usr/bin/env python3
"""IF-IDR against its 50 ms budget (PLT-ICD-001 ICD-GEN-010, ICD-OP-01).

    python3 tests/bench_idr.py [--scale 1.0] [--runs 1000]

Times each IF-IDR method as the core times it: through the core's Invoker,
so a figure is the resolver's work plus the core's POST check and the
rendering of its result for the audit (ICD-GEN-041), all inside the budget.

Load profile (PLT-NFR-009: measured, not estimated), at --scale 1.0:

  * mcx: 100 000 registered users; groups of 10, 100, 1 000, 5 000 and
    20 000 members; a user resolved, each group resolved.
  * frmcs: 5 000 trains each with its leading driver activated (keyed
    `train-driver`); a driver's roles (`identities_of`), one train's driver
    (`resolve` of sip:<train>.train-driver@<domain>), a driver changing
    train (`unbind` then `bind`), and every driver by ad hoc criteria
    (`determine_participants`, the railway emergency call); 5 000 holders of
    the location-dependent group identity `rec-area` in one track section,
    resolved.
  * a core step, not one invocation: the ad hoc participants of a call that
    lists 1 000 of them (`_adhoc_members`, one `resolve` per entry). Its
    figure is the step's, each invocation in it being one user's; it is
    reported, not held to the budget.

One call at a time: the SIP core runs SIP, media and timers under one lock
(service/sip_core.py), so hook calls do not overlap in the process, and the
time one takes is time no other call's media is relayed or timer run. The in-tree binding store is in memory (profiles/common/
tables.py); an external one (`group_source`) is not wired in R1, and its
cache and staleness bound are PLT-ICD-001 ICD-OP-16.

Prints p50, p99 and max in milliseconds per case, and exits 1 if any p99 is
over budget. It lives with the tests, not in tools/, because it names the
profiles it loads, and build files may not (VP1-BND-006).
"""

from __future__ import annotations

import argparse
import math
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.audit import Auditor, MemorySink  # noqa: E402
from core.functional import AliasPolicy  # noqa: E402
from core.hooks import LocationContext, MediaKind, SessionRequest  # noqa: E402
from core.invoke import DEFAULT_BUDGETS_MS, Invoker  # noqa: E402
from core.session import SessionManager  # noqa: E402

BUDGET_MS = DEFAULT_BUDGETS_MS["IF-IDR"]


def _percentile(xs: List[float], p: float) -> float:
    """Nearest rank: the smallest value with at least p% of the runs at or
    below it (the 99th of 100 runs is the 99th, not the largest)."""
    xs = sorted(xs)
    return xs[max(0, math.ceil(p / 100 * len(xs)) - 1)]


def _manager(loaded, **kw) -> SessionManager:
    return SessionManager(loaded, Auditor(MemorySink(), "bench", clock=time.monotonic_ns),
                          clock=lambda: 0, cells={}, **kw)


def _request(target: str, initiator: str, call_type: str, **kw) -> SessionRequest:
    return SessionRequest(request_id="bench", initiator=initiator, target=target,
                          call_type=call_type, media=(MediaKind.VOICE,), **kw)


def _invoker() -> Invoker:
    return Invoker(Auditor(MemorySink(), "bench", clock=time.monotonic_ns), "bench")


def _timer(method: str, fn: Callable, *args, post=None) -> Callable[[], float]:
    invoker = _invoker()

    def once() -> float:
        started = time.perf_counter()
        invoker.call("IF-IDR", method, fn, *args, post=post)
        return (time.perf_counter() - started) * 1000
    return once


Case = Tuple[str, Callable[[], float], bool]


def cases(scale: float = 1.0) -> List[Case]:
    """(name, one timed call, held to the budget) for the load profile above,
    scaled."""
    n = lambda x: max(1, int(x * scale))                       # noqa: E731
    out: List[Case] = []

    loaded = loader.load(ROOT / "profiles" / "mcx")
    r = loaded.hooks.identity_resolver
    users = [f"sip:u{i}@mcptt.example" for i in range(n(100_000))]
    for u in users:
        r.register_user(u)
    mgr = _manager(loaded)
    out.append((f"mcx resolve user ({len(users)} users)",
                _timer("resolve", r.resolve, users[-1], _request(users[-1], users[0], "private"),
                       post=mgr._check_resolution), True))
    for size in sorted({min(n(x), len(users)) for x in (10, 100, 1_000, 5_000, 20_000)}):
        gid = f"grp:{size}"
        r.register_group(gid, users[:size])
        out.append((f"mcx resolve group of {size}",
                    _timer("resolve", r.resolve, gid,
                           _request(gid, users[0], "prearranged-group"),
                           post=mgr._check_resolution), True))

    loaded = loader.load(ROOT / "profiles" / "frmcs")
    r = loaded.hooks.identity_resolver
    trains = n(5_000)
    drivers = [f"sip:d{i}@frmcs.example" for i in range(trains + 1)]
    for d in drivers:
        r.register_user(d)
    mgr = _manager(loaded, functional_aliases={
        "train-driver": AliasPolicy(users=frozenset(drivers))})
    for i in range(trains):
        r.bind("train-driver", drivers[i],
               LocationContext(attributes={"train_id": f"T{i}"}))
    target = f"sip:T{trains - 1}.train-driver@frmcs.example"
    out.append((f"frmcs identities_of ({trains} trains held)",
                _timer("identities_of", r.identities_of, drivers[trains - 1]), True))
    out.append((f"frmcs resolve one train's driver ({trains} held)",
                _timer("resolve", r.resolve, target, _request(target, drivers[-1], "private"),
                       post=mgr._check_resolution), True))
    invoker = _invoker()
    moved = drivers[0]

    def change_train() -> float:
        # Unbind then bind, timed as the two invocations they are; the
        # larger is the figure held to the budget.
        times = []
        for method, fn, args in (
                ("unbind", r.unbind, ("train-driver", moved)),
                ("bind", r.bind, ("train-driver", moved,
                                  LocationContext(attributes={"train_id": "T0"})))):
            started = time.perf_counter()
            invoker.call("IF-IDR", method, fn, *args)
            times.append((time.perf_counter() - started) * 1000)
        return max(times)
    out.append((f"frmcs unbind or bind a driver ({trains} held)", change_train, True))
    out.append((f"frmcs determine_participants train-driver ({trains} held)",
                _timer("determine_participants", r.determine_participants, "train-driver",
                       _request("", drivers[-1], "rec-broadcast"),
                       post=mgr._check_participants), True))
    section = LocationContext(attributes={"track_section": "S1"})
    for d in drivers[:trains]:
        r.bind("rec-area", d, section)
    out.append((f"frmcs resolve rec-area in one section ({trains} holders)",
                _timer("resolve", r.resolve, "rec-area",
                       _request("rec-area", drivers[-1], "rec-broadcast", location=section),
                       post=mgr._check_resolution), True))

    listed = min(n(1_000), trains)
    step_mgr = _manager(loaded, adhoc_list_max=listed)
    step_request = _request("", drivers[-1], "rec-broadcast",
                            participants=tuple(drivers[:listed]))

    def adhoc_step() -> float:
        started = time.perf_counter()
        resolution, refusal, _ = step_mgr._adhoc_members(_invoker(), step_request)
        assert refusal is None and len(resolution.members) == listed
        return (time.perf_counter() - started) * 1000
    out.append((f"core step: ad hoc call listing {listed} participants", adhoc_step, False))
    return out


def run(scale: float = 1.0, runs: int = 1000) -> Dict[str, Tuple[float, float, float, bool]]:
    results = {}
    for name, once, held in cases(scale):
        once()                                                  # warm
        times = [once() for _ in range(runs)]
        results[name] = (_percentile(times, 50), _percentile(times, 99), max(times), held)
    return results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--runs", type=int, default=1000)
    args = ap.parse_args(argv)
    results = run(args.scale, args.runs)
    over = 0
    print(f"IF-IDR budget {BUDGET_MS} ms per invocation; one call at a time; "
          f"{args.runs} runs per case")
    for name, (p50, p99, mx, held) in results.items():
        flag = ("OVER" if p99 > BUDGET_MS else "ok") if held else "step"
        over += held and p99 > BUDGET_MS
        print(f"{flag:4s} {name:58s} p50={p50:8.2f} p99={p99:8.2f} max={mx:8.2f} ms")
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
