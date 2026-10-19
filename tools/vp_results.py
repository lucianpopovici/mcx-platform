#!/usr/bin/env python3
"""The R1 results register (PLT-VP-R1 §10, exit criteria 1 to 3).

    python3 tools/vp_results.py [--interop RUN.json ...] [--out docs/PLT-VP-R1-RESULTS.md]

Runs the evidence and writes, for one commit, the result of every case in
§3-§8 and of every requirement in §9:

  * pytest, with tests/conftest.py recording which test is evidence for which
    case (a `test_vp1_<suite>_<nnn>` name or `@pytest.mark.vp(...)`);
  * the boundary gates, tools/check_boundary.py (its PASS/FAIL lines);
  * interoperability runs, tools/interop/run.py --results (VP1-SIG-001), given
    with --interop because they need Kamailio and Asterisk.

Passing evidence is not by itself a result. Whether the evidence shows the
case's pass criterion is a judgement, recorded in docs/PLT-VP-R1-REVIEWS.yaml
with the evidence that was judged. A case is PASS only when that review says
so and its evidence is still the evidence reviewed and still passes. Results:

  PASS          reviewed as meeting the pass criterion; evidence unchanged, passing
  PARTIAL       reviewed: the evidence shows part of the criterion (the gap is named)
  FAIL          evidence failed, or reviewed as failing
  STALE         reviewed, but the evidence has changed since
  UNREVIEWED    evidence exists and passes; nobody has judged it against the criterion
  NOT RUN       reviewed evidence was not run this time (interop not supplied)
  NOT COVERED   no evidence at all
  NOT SIGNED    an analysis (§8) without a signed review

The plan is also checked against itself and PLT-SRS (every R1 requirement
in §9 with the SRS method; every case traced; every traced case defined).

Exit status 1 when any evidence failed or the plan is inconsistent.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs" / "PLT-VP-R1.md"
SRS = ROOT / "docs" / "PLT-SRS.md"
REVIEWS = ROOT / "docs" / "PLT-VP-R1-REVIEWS.yaml"
OUT = ROOT / "docs" / "PLT-VP-R1-RESULTS.md"

VERDICTS = ("pass", "partial", "fail")
ORDER = ("FAIL", "STALE", "NOT RUN", "NOT COVERED", "NOT SIGNED", "UNREVIEWED",
         "PARTIAL", "PASS")                          # worst first
_ROW = re.compile(r"^\| (VP1-[A-Z]+-\d{3}) \|(.*)\|\s*$")
_MENTION = re.compile(r"VP1-[A-Z]+-\d{3}")


# ------------------------------------------------------------------ the plan

@dataclass
class Case:
    id: str
    title: str
    criterion: str
    section: str
    analysis: bool = False
    ahead: bool = False              # §9.1: runs in R1, does not gate R1 exit


@dataclass
class Requirement:
    id: str
    method: str
    cases: Tuple[str, ...]


def _cells(rest: str) -> List[str]:
    return [c.strip() for c in rest.split("|")]


def read_plan(text: str) -> Tuple[Dict[str, Case], List[Requirement]]:
    cases: Dict[str, Case] = {}
    reqs: List[Requirement] = []
    section = ""
    part = "pre"
    ahead: Set[str] = set()
    for line in text.splitlines():
        if line.startswith("## "):
            n = line[3:].split(".", 1)[0]
            part = {"8": "analyses", "9": "matrix", "10": "post"}.get(
                n, "cases" if n in ("3", "4", "5", "6", "7") else "other")
            section = line[3:].strip()
            continue
        if line.startswith("### "):
            section = line[4:].strip()
            if section.startswith("9.1"):
                part = "ahead"
            continue
        if part in ("cases", "analyses"):
            m = _ROW.match(line)
            if m and m.group(1) not in cases:
                cells = _cells(m.group(2))
                cases[m.group(1)] = Case(
                    m.group(1), cells[0] if part == "cases" else f"Analysis for {cells[0]}",
                    cells[-1], section, analysis=(part == "analyses"))
        elif part == "matrix" and line.startswith("| PLT-"):
            c = _cells(line.strip().strip("|"))
            reqs.append(Requirement(c[0], c[1], tuple(_MENTION.findall(c[2]))))
        elif part == "ahead":
            m = _ROW.match(line)
            if m:
                ahead.add(m.group(1))
    for cid in ahead:
        if cid in cases:
            cases[cid].ahead = True
    return cases, reqs


def plan_defects(cases: Dict[str, Case], reqs: List[Requirement], srs: str) -> List[str]:
    r1 = dict(re.findall(r"^\| (PLT-[A-Z]+-\d{3}) \| R1 \|.*\| ([TDAI]) \|\s*$", srs, re.M))
    out = []
    listed = {q.id: q for q in reqs}
    for rid in sorted(set(r1) - set(listed)):
        out.append(f"{rid} is an R1 requirement in PLT-SRS but not in §9")
    for q in reqs:
        if q.id not in r1:
            out.append(f"§9 lists {q.id}, which PLT-SRS does not make R1")
        elif r1[q.id] != q.method:
            out.append(f"§9 gives {q.id} method {q.method}; PLT-SRS says {r1[q.id]}")
        for c in q.cases:
            if c not in cases:
                out.append(f"§9 traces {q.id} to {c}, which the plan does not define")
        if not q.cases:
            out.append(f"§9 traces {q.id} to no case")
    traced = {c for q in reqs for c in q.cases}
    for cid, case in cases.items():
        if cid not in traced and not case.ahead:
            out.append(f"{cid} traces to no requirement in §9 and is not in §9.1")
    return out


# ------------------------------------------------------------------ evidence

@dataclass
class Evidence:
    id: str                  # stable name: test function, gate, interop core
    outcome: str             # passed | failed | skipped
    cases: Tuple[str, ...]


def _worst(a: str, b: str) -> str:
    rank = {"failed": 0, "skipped": 1, "passed": 2}
    return a if rank[a] <= rank[b] else b


def from_pytest(outcomes: Dict[str, dict]) -> List[Evidence]:
    """Parametrised items fold into their test function: it passes only
    when every parameter does."""
    by_fn: Dict[str, Evidence] = {}
    for nodeid, v in outcomes.items():
        fn = nodeid.split("[", 1)[0]
        e = by_fn.get(fn)
        if e is None:
            by_fn[fn] = Evidence(fn, v["outcome"], tuple(v["cases"]))
        else:
            e.outcome = _worst(e.outcome, v["outcome"])
            e.cases = tuple(dict.fromkeys(e.cases + tuple(v["cases"])))
    return list(by_fn.values())


def from_gates(output: str) -> List[Evidence]:
    out = []
    for m in re.finditer(r"^(PASS|FAIL)\s+(VP1-[A-Z]+-\d{3})\b", output, re.M):
        out.append(Evidence(f"gate:{m.group(2)}",
                            "passed" if m.group(1) == "PASS" else "failed",
                            (m.group(2),)))
    return out


def from_interop(runs: Sequence[dict]) -> List[Evidence]:
    return [Evidence(f"interop:{r['core']}", "passed" if r["passed"] else "failed",
                     (r["case"],)) for r in runs]


def run_pytest() -> Tuple[Dict[str, dict], str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "vp.json"
        r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q",
                            "-p", "no:cacheprovider", f"--vp-results={path}"],
                           cwd=ROOT, capture_output=True, text=True)
        summary = (r.stdout.strip().splitlines() or ["(no output)"])[-1]
        if not path.exists():
            raise SystemExit(f"pytest wrote no results ({summary}):\n{r.stdout[-3000:]}")
        return json.loads(path.read_text()), summary


def run_gates() -> str:
    return subprocess.run([sys.executable, "tools/check_boundary.py", "--root", "."],
                          cwd=ROOT, capture_output=True, text=True).stdout


# ------------------------------------------------------------------ reviews

def read_reviews(path: Path, cases: Dict[str, Case]) -> Dict[str, dict]:
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise SystemExit(f"{path}: expected a mapping of case id to review")
    problems = []
    for cid, r in raw.items():
        where = f"{path.name}: {cid}"
        if cid not in cases:
            problems.append(f"{where}: not a case of PLT-VP-R1")
            continue
        if not isinstance(r, dict):
            problems.append(f"{where}: expected a mapping")
            continue
        keys = {"verdict", "by", "date", "evidence", "note", "gap", "signed"}
        if not set(r) <= keys or not {"verdict", "by", "date"} <= set(r):
            problems.append(f"{where}: needs verdict, by, date; may have evidence, "
                            "note, gap, signed")
            continue
        if r["verdict"] not in VERDICTS:
            problems.append(f"{where}: verdict must be one of {', '.join(VERDICTS)}")
        if r["verdict"] == "partial" and not r.get("gap"):
            problems.append(f"{where}: a partial verdict must name the gap")
        if cases[cid].analysis:
            if r["verdict"] == "pass" and not r.get("signed"):
                problems.append(f"{where}: an analysis passes only when signed (§8)")
        elif not isinstance(r.get("evidence"), list) or not r["evidence"]:
            problems.append(f"{where}: must list the evidence reviewed")
    if problems:
        raise SystemExit("reviews:\n  " + "\n  ".join(problems))
    return raw


# ------------------------------------------------------------------ results

@dataclass
class Result:
    case: Case
    status: str
    evidence: List[Evidence] = field(default_factory=list)
    review: Optional[dict] = None
    detail: str = ""


def judge(case: Case, evidence: List[Evidence], review: Optional[dict],
          interop_run: bool) -> Result:
    if case.analysis:
        if review is None:
            return Result(case, "NOT SIGNED", [], None)
        status = {"pass": "PASS", "partial": "PARTIAL", "fail": "FAIL"}[review["verdict"]]
        if status == "PASS" and not review.get("signed"):
            status = "NOT SIGNED"
        return Result(case, status, [], review)
    failed = [e for e in evidence if e.outcome != "passed"]
    if any(e.outcome == "failed" for e in evidence):
        return Result(case, "FAIL", evidence, review,
                      "failed: " + ", ".join(e.id for e in failed if e.outcome == "failed"))
    if review is not None:
        reviewed = set(review.get("evidence") or [])
        now = {e.id for e in evidence}
        missing = reviewed - now
        if missing and not interop_run and all(m.startswith("interop:") for m in missing):
            return Result(case, "NOT RUN", evidence, review,
                          "not run: " + ", ".join(sorted(missing)))
        if reviewed != now:
            gone, new = sorted(reviewed - now), sorted(now - reviewed)
            return Result(case, "STALE", evidence, review,
                          "; ".join(x for x in (
                              ("gone: " + ", ".join(gone)) if gone else "",
                              ("new: " + ", ".join(new)) if new else "") if x))
        if failed:                                   # skipped
            return Result(case, "FAIL", evidence, review,
                          "not passed: " + ", ".join(e.id for e in failed))
        status = {"pass": "PASS", "partial": "PARTIAL", "fail": "FAIL"}[review["verdict"]]
        return Result(case, status, evidence, review, review.get("gap", "") or "")
    if not evidence:
        return Result(case, "NOT COVERED")
    if failed:
        return Result(case, "FAIL", evidence, None,
                      "not passed: " + ", ".join(e.id for e in failed))
    return Result(case, "UNREVIEWED", evidence)


def requirement_status(req: Requirement, results: Dict[str, Result]) -> str:
    states = [results[c].status if c in results else "NOT COVERED" for c in req.cases]
    if not states:
        return "NOT COVERED"
    return min(states, key=ORDER.index)


def mentions_in_tests() -> Dict[str, Set[str]]:
    """Cases a test file mentions without linking: triage hints only."""
    out: Dict[str, Set[str]] = {}
    for f in sorted((ROOT / "tests").glob("*.py")):
        for cid in set(_MENTION.findall(f.read_text(encoding="utf-8"))):
            out.setdefault(cid, set()).add(f.name)
    return out


# ------------------------------------------------------------------ rendering

def _short(e: Evidence) -> str:
    return e.id.replace("tests/", "").replace("::", " ")


def render(cases: Dict[str, Case], reqs: List[Requirement], results: Dict[str, Result],
           meta: Dict[str, str], hints: Dict[str, Set[str]], defects: List[str]) -> str:
    counts = {s: 0 for s in ORDER}
    gating = [r for r in results.values() if not r.case.ahead]
    for r in gating:
        counts[r.status] += 1
    req_states = {q.id: requirement_status(q, results) for q in reqs}
    req_counts = {s: 0 for s in ORDER}
    for s in req_states.values():
        req_counts[s] += 1
    L = ["# R1 results register", "",
         "**Document:** PLT-VP-R1-RESULTS (generated by `tools/vp_results.py`; do not edit)",
         f"**Commit:** {meta['commit']}",
         f"**Run:** {meta['date']}",
         f"**Evidence run:** pytest ({meta['pytest']}); boundary gates ({meta['gates']}); "
         f"interoperability ({meta['interop']})",
         "**Reviews:** `docs/PLT-VP-R1-REVIEWS.yaml`", "",
         "A case is PASS only when a review records that its evidence shows the pass "
         "criterion, and that evidence is unchanged and passing. Passing evidence that "
         "nobody has judged is UNREVIEWED. See `tools/vp_results.py` for every result.",
         "", "## Summary", "",
         f"Cases that gate R1 exit ({len(gating)}; the {len(results) - len(gating)} of "
         "§9.1 are listed but do not gate):", "",
         "| Result | Cases |", "|---|---|"]
    L += [f"| {s} | {counts[s]} |" for s in ORDER if counts[s]]
    L += ["", f"Requirements ({len(reqs)}), each at the worst result of its cases:", "",
          "| Result | Requirements |", "|---|---|"]
    L += [f"| {s} | {req_counts[s]} |" for s in ORDER if req_counts[s]]
    L += ["", "Plan consistency (§9 against PLT-SRS and §3-§8): "
          + ("no defect." if not defects else f"**{len(defects)} defect(s)**:")]
    L += [f"- {d}" for d in defects]
    L += ["", "## Cases", ""]
    section = None
    for cid, case in cases.items():
        if case.section != section:
            section = case.section
            L += ["", f"### {section}", "", "| Case | Title | Result | Evidence | Note |",
                  "|---|---|---|---|---|"]
        r = results[cid]
        ev = "<br>".join(f"{'✗ ' if e.outcome != 'passed' else ''}{_short(e)}"
                         for e in r.evidence) or "—"
        note = r.detail
        if r.status == "NOT COVERED" and cid in hints:
            note = "mentioned, not linked: " + ", ".join(sorted(hints[cid]))
        if r.review and r.review.get("note") and r.status in ("PASS", "PARTIAL"):
            note = "; ".join(x for x in (note, r.review["note"]) if x)
        if r.review:
            by = r.review["by"] + (f", signed {r.review['signed']}" if r.review.get("signed") else "")
            note = "; ".join(x for x in (note, f"reviewed {r.review['date']} by {by}") if x)
        tag = " *(§9.1)*" if case.ahead else ""
        L.append(f"| {cid}{tag} | {case.title} | **{r.status}** | {ev} | {note} |")
    L += ["", "## Requirements (§9)", "", "| Requirement | M | Cases | Result |",
          "|---|---|---|---|"]
    for q in reqs:
        L.append(f"| {q.id} | {q.method} | {', '.join(q.cases) or '—'} | **{req_states[q.id]}** |")
    return "\n".join(L) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--interop", nargs="*", default=[], metavar="RUN.json",
                    help="results of tools/interop/run.py --results")
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--pytest-json", type=Path,
                    help="use this --vp-results file instead of running pytest")
    args = ap.parse_args(argv)

    cases, reqs = read_plan(PLAN.read_text(encoding="utf-8"))
    defects = plan_defects(cases, reqs, SRS.read_text(encoding="utf-8"))
    reviews = read_reviews(REVIEWS, cases)
    if args.pytest_json:
        outcomes, summary = json.loads(args.pytest_json.read_text()), "from file"
    else:
        outcomes, summary = run_pytest()
    gates = run_gates()
    runs = [json.loads(Path(p).read_text()) for p in args.interop]
    evidence = from_pytest(outcomes) + from_gates(gates) + from_interop(runs)

    by_case: Dict[str, List[Evidence]] = {c: [] for c in cases}
    for e in evidence:
        for c in e.cases:
            by_case.setdefault(c, []).append(e)
    unknown = sorted(set(by_case) - set(cases))
    if unknown:
        raise SystemExit(f"evidence for cases the plan does not define: {', '.join(unknown)}")
    results = {cid: judge(cases[cid], sorted(by_case[cid], key=lambda e: e.id),
                          reviews.get(cid), bool(runs))
               for cid in cases}

    head = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", ".",
                            ":(exclude)docs/PLT-VP-R1-RESULTS.md"], cwd=ROOT,
                           capture_output=True, text=True).stdout.strip()
    stale_runs = [r["core"] for r in runs if r.get("commit") and head and
                  not head.startswith(r["commit"][:7])]
    meta = {
        "commit": (head or "unknown") + (" with uncommitted changes" if dirty else ""),
        "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "pytest": summary,
        "gates": f"{len(re.findall(r'^PASS ', gates, re.M))} pass, "
                 f"{len(re.findall(r'^FAIL ', gates, re.M))} fail",
        "interop": ", ".join(f"{r['core']} {'passed' if r['passed'] else 'FAILED'}"
                             + (f" at {r['commit']}" if r["core"] in stale_runs else "")
                             for r in runs) or "not supplied",
    }
    args.out.write_text(render(cases, reqs, results, meta, mentions_in_tests(), defects),
                        encoding="utf-8")
    tally: Dict[str, int] = {}
    for r in results.values():
        tally[r.status] = tally.get(r.status, 0) + 1
    print(f"{args.out.relative_to(ROOT) if args.out.is_absolute() and ROOT in args.out.parents else args.out}: "
          + ", ".join(f"{k} {v}" for k, v in sorted(tally.items(), key=lambda kv: ORDER.index(kv[0]))))
    for d in defects:
        print(f"plan: {d}")
    return 1 if defects or any(e.outcome == "failed" for e in evidence) else 0


if __name__ == "__main__":
    sys.exit(main())
