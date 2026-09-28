"""tools/vp_results.py: the R1 results register judges honestly.

What must hold: passing evidence alone is never PASS; a review goes STALE
when its evidence changes; a failed test fails the case whatever the review
says; the plan is checked against PLT-SRS.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vp_results as v  # noqa: E402

PLAN = """# plan
## 3. TS-LOAD — loading
| Case | Title | Steps | Pass criterion |
|---|---|---|---|
| VP1-LOAD-001 | Loads | Start | Reaches ready |
| VP1-LOAD-002 | Refuses | Start | Exits 2 |
## 7. TS-SIG
### 7.1 TS-SIG — signalling
| Case | Title | Pass criterion |
|---|---|---|
| VP1-SIG-001 | Interop | Two cores |
| VP1-LOAD-001 | Duplicate row | ignored |
## 8. Analyses
| Case | Requirement | Argument required |
|---|---|---|
| VP1-ANL-001 | PLT-PRF-022 | A worked change |
## 9. Traceability matrix
| Requirement | M | Verified by |
|---|---|---|
| PLT-GEN-001 | T | VP1-LOAD-001 |
| PLT-GEN-002 | T | VP1-LOAD-002, VP1-SIG-001 |
| PLT-PRF-022 | A | VP1-ANL-001 |
### 9.1 Cases running ahead of their phase
| Case | Verifies (later phase) |
|---|---|
| VP1-SIG-001 | later |
## 10. Exit criteria
| VP1-LOAD-009 | not a case | here |
"""

SRS = """| PLT-GEN-001 | R1 | text | T |
| PLT-GEN-002 | R1 | text | T |
| PLT-PRF-022 | R1 | text | A |
| PLT-GEN-003 | R2 | later | T |
"""


def test_the_plan_is_read_from_its_tables():
    cases, reqs = v.read_plan(PLAN)
    assert list(cases) == ["VP1-LOAD-001", "VP1-LOAD-002", "VP1-SIG-001", "VP1-ANL-001"]
    assert cases["VP1-LOAD-001"].title == "Loads"                 # first row wins
    assert cases["VP1-LOAD-001"].criterion == "Reaches ready"     # last column
    assert cases["VP1-SIG-001"].criterion == "Two cores"
    assert cases["VP1-SIG-001"].section == "7.1 TS-SIG — signalling"
    assert cases["VP1-SIG-001"].ahead and not cases["VP1-LOAD-001"].ahead
    assert cases["VP1-ANL-001"].analysis and not cases["VP1-LOAD-002"].analysis
    assert [(q.id, q.method, q.cases) for q in reqs] == [
        ("PLT-GEN-001", "T", ("VP1-LOAD-001",)),
        ("PLT-GEN-002", "T", ("VP1-LOAD-002", "VP1-SIG-001")),
        ("PLT-PRF-022", "A", ("VP1-ANL-001",))]


def test_the_plan_is_checked_against_the_srs():
    cases, reqs = v.read_plan(PLAN)
    assert v.plan_defects(cases, reqs, SRS) == []
    srs = SRS + "| PLT-GEN-004 | R1 | new | I |\n"
    srs = srs.replace("| PLT-GEN-002 | R1 | text | T |", "| PLT-GEN-002 | R1 | text | I |")
    plan = PLAN.replace("| PLT-GEN-001 | T | VP1-LOAD-001 |",
                        "| PLT-GEN-001 | T | VP1-LOAD-001, VP1-LOAD-077 |")
    plan = plan.replace("| VP1-SIG-001 | later |\n", "")
    c2, r2 = v.read_plan(plan.replace("| PLT-PRF-022 | A | VP1-ANL-001 |\n", ""))
    got = v.plan_defects(c2, r2, srs)
    assert got == [
        "PLT-GEN-004 is an R1 requirement in PLT-SRS but not in §9",
        "PLT-PRF-022 is an R1 requirement in PLT-SRS but not in §9",
        "§9 traces PLT-GEN-001 to VP1-LOAD-077, which the plan does not define",
        "§9 gives PLT-GEN-002 method T; PLT-SRS says I",
        "VP1-ANL-001 traces to no requirement in §9 and is not in §9.1",
    ]


def test_a_requirement_that_is_not_r1_is_a_defect():
    cases, reqs = v.read_plan(PLAN.replace("PLT-GEN-001 | T", "PLT-GEN-003 | T"))
    assert "§9 lists PLT-GEN-003, which PLT-SRS does not make R1" in \
        v.plan_defects(cases, reqs, SRS)


def ev(id_, outcome="passed", case="VP1-LOAD-001"):
    return v.Evidence(id_, outcome, (case,))


def case(analysis=False):
    return v.Case("VP1-LOAD-001", "t", "c", "s", analysis=analysis)


def review(verdict="pass", evidence=("a",), **kw):
    return {"verdict": verdict, "by": "x", "date": "2026-09-28",
            "evidence": list(evidence), **kw}


def test_no_evidence_is_not_covered():
    assert v.judge(case(), [], None, False).status == "NOT COVERED"


def test_passing_evidence_alone_is_unreviewed_not_pass():
    assert v.judge(case(), [ev("a")], None, False).status == "UNREVIEWED"


@pytest.mark.parametrize("verdict,status", [("pass", "PASS"), ("partial", "PARTIAL"),
                                            ("fail", "FAIL")])
def test_a_current_review_decides(verdict, status):
    r = v.judge(case(), [ev("a"), ev("b")], review(verdict, ("a", "b"), gap="g"), False)
    assert r.status == status


def test_failed_evidence_fails_whatever_the_review_says():
    r = v.judge(case(), [ev("a", "failed")], review("pass"), False)
    assert (r.status, r.detail) == ("FAIL", "failed: a")
    assert v.judge(case(), [ev("a", "failed")], None, False).status == "FAIL"


def test_skipped_evidence_is_not_a_pass():
    assert v.judge(case(), [ev("a", "skipped")], review("pass"), False).status == "FAIL"
    assert v.judge(case(), [ev("a", "skipped")], None, False).status == "FAIL"


def test_changed_evidence_makes_a_review_stale():
    r = v.judge(case(), [ev("a"), ev("c")], review("pass", ("a", "b")), False)
    assert (r.status, r.detail) == ("STALE", "gone: b; new: c")
    assert v.judge(case(), [ev("a")], review("pass", ("a", "b")), False).status == "STALE"
    assert v.judge(case(), [ev("a"), ev("b")], review("pass", ("a",)), False).status == "STALE"


def test_interop_evidence_not_supplied_is_not_run_not_stale():
    rv = review("pass", ("interop:kamailio", "interop:asterisk"))
    assert v.judge(case(), [], rv, interop_run=False).status == "NOT RUN"
    # supplied, but one core missing from the run: the evidence changed
    assert v.judge(case(), [ev("interop:kamailio")], rv, interop_run=True).status == "STALE"
    # a test gone is never excused as "not run"
    assert v.judge(case(), [], review("pass", ("a", "interop:x")), False).status == "STALE"


def test_an_analysis_passes_only_when_signed():
    assert v.judge(case(True), [], None, False).status == "NOT SIGNED"
    assert v.judge(case(True), [], review("pass"), False).status == "NOT SIGNED"
    assert v.judge(case(True), [], review("pass", signed="owner"), False).status == "PASS"
    assert v.judge(case(True), [], review("partial", gap="g"), False).status == "PARTIAL"


def test_a_requirement_takes_its_worst_case():
    cases, reqs = v.read_plan(PLAN)
    res = {c: v.Result(cases[c], s) for c, s in [
        ("VP1-LOAD-001", "PASS"), ("VP1-LOAD-002", "PARTIAL"), ("VP1-SIG-001", "PASS"),
        ("VP1-ANL-001", "NOT SIGNED")]}
    assert [v.requirement_status(q, res) for q in reqs] == ["PASS", "PARTIAL", "NOT SIGNED"]
    res["VP1-SIG-001"] = v.Result(cases["VP1-SIG-001"], "FAIL")
    assert v.requirement_status(reqs[1], res) == "FAIL"


def test_parametrised_items_fold_into_their_function():
    out = v.from_pytest({
        "tests/t.py::test_a[1]": {"cases": ["VP1-LOAD-001"], "outcome": "passed"},
        "tests/t.py::test_a[2]": {"cases": ["VP1-LOAD-001"], "outcome": "failed"},
        "tests/t.py::test_b": {"cases": ["VP1-LOAD-002"], "outcome": "skipped"}})
    assert {(e.id, e.outcome, e.cases) for e in out} == {
        ("tests/t.py::test_a", "failed", ("VP1-LOAD-001",)),
        ("tests/t.py::test_b", "skipped", ("VP1-LOAD-002",))}


def test_a_failed_parameter_is_not_undone_by_a_later_pass():
    out = v.from_pytest({
        "tests/t.py::test_a[1]": {"cases": ["VP1-LOAD-001"], "outcome": "failed"},
        "tests/t.py::test_a[2]": {"cases": ["VP1-LOAD-001"], "outcome": "passed"},
        "tests/t.py::test_a[3]": {"cases": ["VP1-LOAD-001"], "outcome": "skipped"}})
    assert [e.outcome for e in out] == ["failed"]


def test_gate_and_interop_evidence():
    gates = v.from_gates("PASS VP1-BND-001  x\nFAIL VP1-BND-002  y\n       detail\n")
    assert [(e.id, e.outcome) for e in gates] == [("gate:VP1-BND-001", "passed"),
                                                 ("gate:VP1-BND-002", "failed")]
    runs = v.from_interop([{"case": "VP1-SIG-001", "core": "kamailio", "passed": False}])
    assert [(e.id, e.outcome, e.cases) for e in runs] == [
        ("interop:kamailio", "failed", ("VP1-SIG-001",))]


@pytest.mark.parametrize("entry,message", [
    ({"verdict": "ok", "by": "x", "date": "d", "evidence": ["a"]}, "verdict must be"),
    ({"by": "x", "date": "d", "evidence": ["a"]}, "needs verdict, by, date"),
    ({"verdict": "partial", "by": "x", "date": "d", "evidence": ["a"]}, "must name the gap"),
    ({"verdict": "pass", "by": "x", "date": "d"}, "must list the evidence"),
    ({"verdict": "pass", "by": "x", "date": "d", "evidence": ["a"], "extra": 1},
     "needs verdict, by, date"),
])
def test_a_malformed_review_is_refused(tmp_path, entry, message):
    cases, _ = v.read_plan(PLAN)
    p = tmp_path / "r.yaml"
    import yaml
    p.write_text(yaml.safe_dump({"VP1-LOAD-001": entry}))
    with pytest.raises(SystemExit, match=message):
        v.read_reviews(p, cases)


def test_a_review_of_an_unknown_case_or_unsigned_analysis_is_refused(tmp_path):
    cases, _ = v.read_plan(PLAN)
    import yaml
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump({"VP1-LOAD-099": review()}))
    with pytest.raises(SystemExit, match="not a case of PLT-VP-R1"):
        v.read_reviews(p, cases)
    p.write_text(yaml.safe_dump({"VP1-ANL-001": {"verdict": "pass", "by": "x", "date": "d"}}))
    with pytest.raises(SystemExit, match="passes only when signed"):
        v.read_reviews(p, cases)


def test_the_repository_plan_and_reviews_are_consistent():
    """The real plan agrees with PLT-SRS, and every review names a real case."""
    cases, reqs = v.read_plan(v.PLAN.read_text(encoding="utf-8"))
    assert v.plan_defects(cases, reqs, v.SRS.read_text(encoding="utf-8")) == []
    v.read_reviews(v.REVIEWS, cases)
