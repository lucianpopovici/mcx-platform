"""Links between tests and the R1 verification cases (PLT-VP-R1 §10, criteria
1 and 2; tools/vp_results.py).

A test is evidence for a case when
  * its function is named `test_vp1_<suite>_<nnn>...` (the convention the
    suite grew up with), or
  * it is marked `@pytest.mark.vp("VP1-<SUITE>-<nnn>", ...)`, which may name
    several cases.

A marker naming a case the plan does not define is an error at collection:
a link to nothing is not evidence, and a typo would silently leave a case
uncovered.

`--vp-results=PATH` writes every linked test's outcome as JSON, for
tools/vp_results.py.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Set

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs" / "PLT-VP-R1.md"
CASE = re.compile(r"^VP1-[A-Z]+-\d{3}$")
_NAMED = re.compile(r"^test_vp1_([a-z]+)_(\d{3})(?:_|$)")


def plan_cases() -> Set[str]:
    """Every case id §3-§8 of the plan defines (the first column of a table
    row)."""
    return set(re.findall(r"^\| (VP1-[A-Z]+-\d{3}) \|", PLAN.read_text(encoding="utf-8"),
                          re.M))


def cases_of(item) -> List[str]:
    out: List[str] = []
    name = getattr(item, "originalname", None) or item.name.split("[", 1)[0]
    m = _NAMED.match(name)
    if m:
        out.append(f"VP1-{m.group(1).upper()}-{m.group(2)}")
    for mark in item.iter_markers("vp"):
        out.extend(mark.args)
    return list(dict.fromkeys(out))


def pytest_addoption(parser):
    parser.addoption("--vp-results", default=None, metavar="PATH",
                     help="write the outcome of every test linked to a VP1 case")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "vp(*cases): this test is evidence for the named PLT-VP-R1 cases")
    config._vp_outcomes = {}                            # type: ignore[attr-defined]


def pytest_collection_modifyitems(config, items):
    known = plan_cases()
    bad: List[str] = []
    for item in items:
        for mark in item.iter_markers("vp"):
            if not mark.args:
                bad.append(f"{item.nodeid}: @pytest.mark.vp names no case")
            for c in mark.args:
                if not isinstance(c, str) or not CASE.match(c) or c not in known:
                    bad.append(f"{item.nodeid}: {c!r} is not a case of PLT-VP-R1")
        for c in cases_of(item):
            if c not in known:
                bad.append(f"{item.nodeid}: named for {c}, which PLT-VP-R1 does not define")
    if bad:
        raise pytest.UsageError("VP case links:\n  " + "\n  ".join(bad))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    cases = cases_of(item)
    if not cases:
        return
    store: Dict[str, dict] = item.config._vp_outcomes    # type: ignore[attr-defined]
    entry = store.setdefault(item.nodeid, {"cases": cases, "outcome": "passed"})
    # Any phase that did not pass decides; a skip is not a pass.
    if report.failed:
        entry["outcome"] = "failed"
    elif report.skipped and entry["outcome"] == "passed":
        entry["outcome"] = "skipped"


def pytest_sessionfinish(session, exitstatus):
    path = session.config.getoption("--vp-results")
    if not path:
        return
    Path(path).write_text(json.dumps(session.config._vp_outcomes, indent=1,  # type: ignore[attr-defined]
                                     sort_keys=True))
