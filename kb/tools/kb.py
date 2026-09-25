#!/usr/bin/env python3
"""mcx-platform-kb: the agent memory for the mcx-platform repository.

It lives in the repository at kb/ (it also works as a folder beside it). It
never changes anything outside itself. registry/ and STATE.md are GENERATED
and git-ignored; decisions/, handover/, overlay.yaml and tools/ are written by
hand (by people or agents) and committed.

Staleness is judged by a *source fingerprint*: a hash of every tracked file
outside kb/ plus uncommitted changes to them. Committing a handover note
therefore does not make STATE.md stale; changing a doc or a line of code does.

    python3 tools/kb.py build            # regenerate registry/ and STATE.md
    python3 tools/kb.py build --no-run   # skip pytest and the boundary gates
    python3 tools/kb.py check            # exit 1 on drift, conflicts or a stale STATE
    python3 tools/kb.py show SIP-OP-12   # everything the KB knows about one id
    python3 tools/kb.py handover "short-slug"   # start a session note from the template

The repository path comes from --repo, then $MCX_REPO, then config.yaml, then
the folder that contains this KB.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

KB = Path(__file__).resolve().parent.parent
REG = KB / "registry"

# ---------------------------------------------------------------- ids

# "SIP-OP-12", "ADHOC-OP-04", and the SRS's bare "OP-06" (PLT-SRS §19).
OP_RE = re.compile(r"\b(?:[A-Z]{2,6}-)?OP-\d{2}[a-z]?\b")
CA_RE = re.compile(r"\bCA-\d{2}[a-z]?\b")
VP_RE = re.compile(r"\bVP1-[A-Z]+-\d{3}\b")
REQ_RE = re.compile(r"\bPLT-[A-Z]{3}-\d{3}\b")

# Where formal definitions live. Anything else only references an id.
DOCS = ["docs/PLT-SRS.md", "docs/PLT-ICD-001.md", "docs/PLT-VP-R1.md",
        "docs/PLT-ANL-R1.md", "docs/PLT-CONF-AUDIT.md"]
# Scanned for references. Specifications and binaries are not.
SCAN_SUFFIXES = {".md", ".py", ".yaml", ".yml", ".cfg", ".in", ".txt", ".toml"}
SCAN_SKIP = ("docs/3GPP/", "docs/OMA/", "docs/FRMCS/", ".git/")

DATE_RE = re.compile(r"\b(20\d\d-\d\d-\d\d)\b")


def repo_path(arg: str | None) -> Path:
    cand = arg or os.environ.get("MCX_REPO")
    if not cand:
        cfg = KB / "config.yaml"
        if cfg.exists():
            cand = (yaml.safe_load(cfg.read_text()) or {}).get("repo")
    if not cand and (KB.parent / "CLAUDE.md").exists():
        cand = str(KB.parent)
    if not cand:
        sys.exit("no repository: pass --repo, set MCX_REPO, or set repo: in config.yaml")
    p = Path(os.path.expanduser(cand))
    p = (p if p.is_absolute() else KB / p).resolve()
    if not (p / "CLAUDE.md").exists():
        sys.exit(f"{p} does not look like mcx-platform (no CLAUDE.md)")
    return p


def kb_rel(repo: Path) -> str | None:
    """This KB's path inside the repository, or None if it lives outside it."""
    try:
        return KB.relative_to(repo).as_posix()
    except ValueError:
        return None


def outside_kb(repo: Path) -> list[str]:
    """A git pathspec for everything except this KB."""
    rel = kb_rel(repo)
    return ["--", ".", f":(exclude){rel}"] if rel else []


def source_fingerprint(repo: Path) -> str:
    """Hash of tracked files outside kb/ and of uncommitted changes to them."""
    h = hashlib.sha256()
    h.update(git(repo, "ls-files", "-s", *outside_kb(repo)).encode())
    h.update(git(repo, "diff", "HEAD", "--binary", *outside_kb(repo)).encode())
    return h.hexdigest()[:12]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                          text=True, check=False).stdout


# ---------------------------------------------------------------- markdown

def clean(text: str) -> str:
    text = re.sub(r"~~.*?~~", "", text)          # struck-out original question
    text = text.replace("**", "").replace("`", "")
    return re.sub(r"\s+", " ", text).strip()


def first_sentence(text: str, limit: int = 220) -> str:
    text = clean(text)
    m = re.match(r"(.+?[.?!])(\s|$)", text)
    s = m.group(1) if m else text
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"


def cells(line: str) -> list[str] | None:
    line = line.strip()
    if not (line.startswith("|") and line.endswith("|")):
        return None
    return [c.strip() for c in line[1:-1].split("|")]


def section_of(lines: list[str], idx: int) -> str:
    for j in range(idx, -1, -1):
        if lines[j].startswith("#"):
            return lines[j].lstrip("#").strip()
    return ""


def status_of(text: str, last_col: str) -> str:
    t = clean(text)
    if re.search(r"\b(CLOSED|DECIDED)\b|recorded in error", text) or last_col.lower() == "closed":
        return "closed"
    if re.match(r"(20a closed|Split)", t):
        return "partial"
    return "open"


def decision_of(text: str) -> str | None:
    m = re.search(r"\(decided: ([^)]+)\)", text) or re.search(r"DECIDED [\d-]+: ([^.*]+)", text) \
        or re.search(r"decided: ([^.*]+)", text)
    return clean(m.group(1)) if m else None


# ---------------------------------------------------------------- extraction

def extract_open_points(repo: Path) -> tuple[dict, list]:
    listings: dict[str, list[dict]] = defaultdict(list)
    for rel in DOCS:
        lines = (repo / rel).read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            c = cells(line)
            if not c or not OP_RE.fullmatch(c[0].strip("* ")):
                continue
            oid = c[0].strip("* ")
            crossref = rel.endswith("CONF-AUDIT.md")
            if crossref:                       # | id | what | where | status |
                text, last = f"{c[1]}. {c[-1]}", c[-1]
                st = clean(last).lower()
                status = "closed" if st.startswith("closed") else "open"
            else:                              # | id | question/text | needed by |
                text, last = c[1], c[-1]
                status = status_of(text, last)
            listings[oid].append({
                "doc": rel, "line": i + 1, "section": section_of(lines, i), "crossref": crossref,
                "status": status, "text": text, "last": None if crossref else last,
            })
    points, conflicts = {}, []
    for oid, ls in listings.items():
        defs = [l for l in ls if not l["crossref"]] or ls
        xrefs = [l for l in ls if l["crossref"] and l in ls and l not in defs]
        # Two different rows under one id in the same document: keep both, as
        # ID and ID~2, so neither vanishes from the open list.
        by_doc = defaultdict(list)
        for l in defs:
            by_doc[l["doc"]].append(l)
        for doc, rows in by_doc.items():
            if len(rows) > 1:
                conflicts.append({
                    "id": oid, "kind": "defined-twice",
                    "detail": f"{doc} lines {', '.join(str(r['line']) for r in rows)} are different "
                              f"questions under one id: " + " | ".join(
                                  f"[{r['status']}] {summarise(r['text'], 80)}" for r in rows)})
        for n, row in enumerate(defs):
            key = oid if n == 0 else f"{oid}~{n + 1}"
            for x in xrefs:
                if n == 0 and x["status"] != row["status"]:
                    conflicts.append({"id": oid, "kind": "status-disagrees",
                                      "detail": f"{row['doc']}:{row['line']} says {row['status']}, "
                                                f"{x['doc']}:{x['line']} says {x['status']}"})
            dates = DATE_RE.findall(row["text"])
            needed = clean(row["last"] or "")
            points[key] = {
                "id": key,
                "status": row["status"],
                "summary": summarise(row["text"]),
                "decision": decision_of(row["text"]),
                "date": dates[0] if dates and row["status"] != "open" else None,
                "needed_by": None if needed.lower() in ("", "closed") else needed,
                "defined_in": [f"{row['doc']}:{row['line']} ({row['section']})"]
                              + ([f"{x['doc']}:{x['line']} (cross-listing)" for x in xrefs] if n == 0 else []),
            }
            if n:
                points[key]["duplicate_of"] = oid
    return points, conflicts


def summarise(text: str, limit: int = 220) -> str:
    """The question, not the verdict. A struck-out ~~question~~ is the question."""
    struck = re.search(r"~~(.+?)~~", text)
    if struck:
        return first_sentence(struck.group(1), limit)
    body = re.sub(r"^\*\*[^*]+\*\*\s*", "", text.strip())      # leading **CLOSED ...** / **From ...**
    return first_sentence(body or text, limit)


def extract_findings(repo: Path) -> dict:
    rel = "docs/PLT-CONF-AUDIT.md"
    lines = (repo / rel).read_text(encoding="utf-8").splitlines()
    out: dict[str, dict] = {}
    for i, line in enumerate(lines):
        c = cells(line)
        if not c or len(c) < 4 or not CA_RE.fullmatch(c[0].strip("* ")):
            continue
        cid = c[0].strip("* ")
        st = clean(c[-1])
        status = ("partial" if re.match(r"\d+a closed", st) else
                  "closed" if st.lower().startswith("closed") else "open")
        entry = {"id": cid, "subject": clean(c[1]), "reference": clean(c[2]),
                 "status": status, "note": first_sentence(c[-1], 200),
                 "defined_in": f"{rel}:{i + 1}"}
        # The ledger lists some findings twice (summary + detail table); keep the first.
        out.setdefault(cid, entry)
    text = "\n".join(lines)
    # Write-ups: "### 4.1 CA-02 — none of the eleven warning codes was right"
    for i, line in enumerate(lines):
        m = re.match(r"#+ .*?\b(CA-\d{2}[a-z]?)\b\s*(?:\(new\)|closed)?\s*[—-]\s*(.+)", line)
        if not m:
            continue
        cid, title = m.group(1), clean(m.group(2))
        e = out.setdefault(cid, {"id": cid, "subject": title, "reference": None, "status": None,
                                 "note": None, "defined_in": f"{rel}:{i + 1}"})
        e.setdefault("write_ups", []).append(f"{rel}:{i + 1} {title}")
    # Status for findings with no ledger row.
    closed_ranges = re.findall(r"(CA-\d{2}) through (CA-\d{2})[^.]*?are closed", text)
    closed_ranges = [(int(a[3:]), int(b[3:])) for a, b in closed_ranges]
    # Parents first, so a sub-finding (CA-02b) can inherit a closed parent's status.
    for cid, e in sorted(out.items(), key=lambda kv: (len(kv[0]), kv[0])):
        if e["status"]:
            continue
        base, suffix = re.match(r"CA-(\d{2})([a-z]?)", cid).groups()
        parent = out.get(f"CA-{base}")
        if suffix and parent and parent.get("status") == "partial":
            # "20a closed, 20b open"
            m = re.search(rf"\b{int(base)}{suffix} (closed|open)", " ".join(
                l for l in lines if l.startswith(f"| CA-{base} ")))
            e["status"] = m.group(1) if m else "see write-up"
        elif not suffix and any(a <= int(base) <= b for a, b in closed_ranges):
            e["status"] = "closed"
        elif suffix and parent and parent.get("status") == "closed":
            # A sub-finding is a correction made while closing its parent (4.2, 4.3, 4.5, 4.6, 4.13, 4.17).
            e["status"] = "closed"
            e["note"] = f"Corrected as part of {parent['id']}, which is closed. Read the write-up for any open point it spawned."
        else:
            e["status"] = "see write-up"
        e["note"] = e["note"] or "No ledger row; status from the write-up or the ledger's summary sentence."
    for cid in sorted(set(CA_RE.findall(text)) - set(out)):
        base = int(cid[3:5])
        parent = out.get(cid[:5])
        split = parent and parent["status"] == "partial" and re.search(
            rf"\b{base}{cid[5:]} (closed|open)", parent.get("note") or "")
        if split:
            out[cid] = {"id": cid, "subject": f"Part {cid[5:]} of {cid[:5]}: {parent['subject']}",
                        "reference": parent["reference"], "status": split.group(1),
                        "note": f"Split from {cid[:5]}; see its write-up.", "defined_in": parent["defined_in"]}
        elif any(a <= base <= b for a, b in closed_ranges):
            out[cid] = {"id": cid, "subject": None, "reference": None, "status": "closed",
                        "note": "Closed per the ledger summary; no write-up or row of its own.",
                        "defined_in": rel}
    return out


def extract_vp_cases(repo: Path) -> dict:
    rel = "docs/PLT-VP-R1.md"
    lines = (repo / rel).read_text(encoding="utf-8").splitlines()
    cases: dict[str, dict] = {}
    verified_by: dict[str, list[str]] = defaultdict(list)
    for i, line in enumerate(lines):
        c = cells(line)
        if not c:
            continue
        if VP_RE.fullmatch(c[0].strip("* ")):
            cid = c[0].strip("* ")
            cases.setdefault(cid, {"id": cid, "title": clean(c[1]) if len(c) > 1 else "",
                                   "pass_criterion": clean(c[-1]) if len(c) > 2 else "",
                                   "defined_in": f"{rel}:{i + 1}"})
        elif REQ_RE.fullmatch(c[0]) and len(c) >= 3:          # traceability matrix
            for vp in VP_RE.findall(c[2]):
                verified_by[vp].append(c[0])
    for m in re.finditer(r"#+ .*?(VP1-[A-Z]+-\d{3}) — PASSED (20\d\d-\d\d-\d\d)",
                         (repo / rel).read_text(encoding="utf-8")):
        cases.setdefault(m.group(1), {"id": m.group(1)})["passed"] = m.group(2)
    for m in re.finditer(r"\*\*(VP1-[A-Z]+-\d{3}): PASSED, (20\d\d-\d\d-\d\d)",
                         (repo / rel).read_text(encoding="utf-8")):
        cases.setdefault(m.group(1), {"id": m.group(1)})["passed"] = m.group(2)
    for vp, reqs in verified_by.items():
        if vp in cases:
            cases[vp]["requirements"] = sorted(set(reqs))
    return cases


def scan_refs(repo: Path, ids: set[str]) -> dict[str, list[str]]:
    refs: dict[str, set[str]] = defaultdict(set)
    own = kb_rel(repo)
    pattern = re.compile("|".join([OP_RE.pattern, CA_RE.pattern, VP_RE.pattern]))
    for p in repo.rglob("*"):
        rel = p.relative_to(repo).as_posix()
        if not p.is_file() or p.suffix not in SCAN_SUFFIXES or rel.startswith(SCAN_SKIP):
            continue
        if own and (rel == own or rel.startswith(own + "/")):     # the KB is not the repo's evidence
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for m in pattern.findall(text):
            refs[m].add(rel)
    return {k: sorted(v) for k, v in refs.items()}


def scan_commits(repo: Path) -> dict[str, list[str]]:
    # Commits that touch only the KB (handover notes, decisions) are not evidence.
    log = git(repo, "log", "--format=%x1e%h %ad %s%n%b", "--date=short", *outside_kb(repo))
    out: dict[str, list[str]] = defaultdict(list)
    pattern = re.compile("|".join([OP_RE.pattern, CA_RE.pattern, VP_RE.pattern]))
    for entry in log.split("\x1e"):
        if not entry.strip():
            continue
        head = entry.strip().splitlines()[0]
        for i in sorted(set(pattern.findall(entry))):
            out[i].append(head[:120])
    return out


def run_checks(repo: Path) -> dict:
    res: dict = {}
    r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q", "-p", "no:cacheprovider"],
                       cwd=repo, capture_output=True, text=True)
    tail = [l for l in r.stdout.splitlines() if re.search(r"\d+ (passed|failed)", l)]
    res["tests"] = tail[-1].strip() if tail else f"pytest exited {r.returncode}"
    r = subprocess.run([sys.executable, "tools/check_boundary.py", "--root", "."],
                       cwd=repo, capture_output=True, text=True)
    lines = r.stdout.splitlines()
    res["gates_pass"] = sum(l.startswith("PASS") for l in lines)
    res["gates_fail"] = [l for l in lines if l.startswith("FAIL")]
    return res


def claim_drift(repo: Path, results: dict) -> list[dict]:
    """Numeric status claims in agent-facing files that disagree with the run."""
    out = []
    m = re.search(r"(\d+) passed", results.get("tests", ""))
    if not m:
        return out
    actual = int(m.group(1))
    for rel in ["CLAUDE.md", "README.md", *sorted(p.name for p in repo.glob("CLAUDE-*.md"))]:
        p = repo / rel
        if not p.exists():
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            for mm in re.finditer(r"(\d{3,4})\+? tests", line):
                if int(mm.group(1)) != actual:
                    out.append({"file": f"{rel}:{n}", "claims": mm.group(0), "actual": f"{actual} tests"})
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            for mm in re.finditer(r"(\d+)/(\d+)|(\d+) (?:static|boundary) gates", line):
                claimed = mm.group(2) or mm.group(3)
                if claimed and "gate" in line and int(claimed) != results["gates_pass"] + len(results["gates_fail"]):
                    out.append({"file": f"{rel}:{n}", "claims": mm.group(0),
                                "actual": f"{results['gates_pass'] + len(results['gates_fail'])} gates"})
    return out


# ---------------------------------------------------------------- build

def dump(path: Path, data, header: str) -> None:
    path.write_text(f"# GENERATED by tools/kb.py build — do not edit. {header}\n"
                    + yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100),
                    encoding="utf-8")


def load_overlay() -> dict:
    p = KB / "overlay.yaml"
    return (yaml.safe_load(p.read_text()) or {}) if p.exists() else {}


def decision_meta(p: Path) -> dict:
    text = p.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    return yaml.safe_load(text.split("\n---", 1)[0].lstrip("-\n")) or {}


def decisions_index(only_closes: bool = False) -> dict[str, list[str]]:
    idx: dict[str, list[str]] = defaultdict(list)
    for p in sorted((KB / "decisions").glob("[0-9]*.md")):
        meta = decision_meta(p)
        keys = meta.get("closes", []) + ([] if only_closes else meta.get("relates", []))
        for i in keys:
            idx[i].append(p.name)
    return idx


def build(repo: Path, run: bool) -> None:
    REG.mkdir(exist_ok=True)
    head = git(repo, "rev-parse", "--short", "HEAD").strip() or "unknown"
    dirty = bool(git(repo, "status", "--porcelain", "--untracked-files=no", *outside_kb(repo)).strip())
    fp = source_fingerprint(repo)
    ops, conflicts = extract_open_points(repo)
    cas = extract_findings(repo)
    vps = extract_vp_cases(repo)
    refs = scan_refs(repo, set(ops) | set(cas) | set(vps))
    commits = scan_commits(repo)
    overlay = load_overlay()
    dec = decisions_index()

    for oid, o in ops.items():
        o["referenced_in"] = [r for r in refs.get(oid, []) if not r.startswith("docs/PLT-")]
        o["commits"] = commits.get(oid, [])[:6]
        if dec.get(oid):
            o["decision_records"] = dec[oid]
        if oid in overlay:
            o["overlay"] = overlay[oid]
    for cid, c in cas.items():
        c["commits"] = commits.get(cid, [])[:6]
    for vid, v in vps.items():
        v["tests_naming_it"] = [r for r in refs.get(vid, []) if r.startswith(("tests/", "tools/"))]

    # ids used in code, commits or docs that nothing defines
    defined = set(ops) | set(cas) | set(vps)
    orphans = sorted({i for i in (set(refs) | set(commits)) if i not in defined})
    for i in orphans:
        conflicts.append({"id": i, "kind": "referenced-not-defined",
                          "detail": ", ".join((refs.get(i) or [])[:4] + [c[:40] for c in commits.get(i, [])[:2]])})

    results = run_checks(repo) if run else {}
    drift = claim_drift(repo, results) if run else []

    stamp = f"source {fp}, commit {head}{' + uncommitted changes' if dirty else ''}"
    dump(REG / "open-points.yaml", dict(sorted(ops.items())), stamp)
    dump(REG / "findings.yaml", dict(sorted(cas.items())), stamp)
    dump(REG / "vp-cases.yaml", dict(sorted(vps.items())), stamp)
    dump(REG / "conflicts.yaml", {"conflicts": conflicts, "claim_drift": drift}, stamp)
    write_state(repo, head, dirty, fp, ops, cas, vps, conflicts, drift, results, dec)
    print(f"built: {len(ops)} open points, {len(cas)} findings, {len(vps)} VP cases, "
          f"{len(conflicts)} conflicts, {len(drift)} stale claims — {stamp}")


def write_state(repo, head, dirty, fp, ops, cas, vps, conflicts, drift, results, dec) -> None:
    today = dt.date.today()
    st = Counter(o["status"] for o in ops.values())
    cst = Counter(c["status"] for c in cas.values())
    last = git(repo, "log", "-1", "--format=%ad %s", "--date=short", *outside_kb(repo)).strip()
    L = [f"# STATE — mcx-platform",
         "",
         f"<!-- GENERATED by tools/kb.py build. Do not edit; rebuild instead. -->",
         f"Built {dt.datetime.now().strftime('%Y-%m-%d %H:%M')} from source `{fp}` (commit {head}"
         f"{' with uncommitted changes' if dirty else ''}). Last commit outside the KB: {last}",
         ""]
    if results:
        L += ["## Health", "",
              f"- Tests: **{results['tests']}**",
              f"- Boundary gates: **{results['gates_pass']} pass**"
              + (f", {len(results['gates_fail'])} FAIL: " + "; ".join(results['gates_fail']) if results['gates_fail'] else ""),
              ""]
    else:
        L += ["## Health", "", "_Not run (`build --no-run`). Numbers below are from documents only._", ""]
    L += ["## Counts", "",
          f"- Open points: {len(ops)} — {st['open']} open, {st['partial']} partial, {st['closed']} closed",
          f"- Conformance findings (CA): {len(cas)} — " + ", ".join(f"{n} {k}" for k, n in cst.most_common()),
          f"- R1 verification cases: {len(vps)} — {sum(1 for v in vps.values() if v.get('passed'))} with a recorded PASS verdict, "
          f"{sum(1 for v in vps.values() if v.get('tests_naming_it'))} named by at least one test or tool",
          ""]

    L += ["## Open points still open", "",
          "| id | needed by | summary | where |", "|---|---|---|---|"]
    for o in sorted(ops.values(), key=lambda o: (o["status"] != "partial", o["id"])):
        if o["status"] == "closed":
            continue
        where = o["defined_in"][0].split(" (")[0]
        tag = " _(partial)_" if o["status"] == "partial" else ""
        L.append(f"| {o['id']}{tag} | {o['needed_by'] or '—'} | {o['summary'].replace('|', '/')} | {where} |")
    L.append("")

    closes = decisions_index(only_closes=True)
    recent = [o for o in ops.values() if o["status"] == "closed" and o.get("date")
              and (today - dt.date.fromisoformat(o["date"])).days <= 14]
    if recent:
        L += ["## Closed in the last 14 days", ""]
        for o in sorted(recent, key=lambda o: (o["date"], o["id"]), reverse=True):
            d = f" — decided: {o['decision']}" if o.get("decision") else ""
            adr = f" → {', '.join(closes[o['id']])}" if closes.get(o["id"]) else ""
            L.append(f"- {o['date']} **{o['id']}**{d}{adr}")
        L.append("")

    open_ca = [c for c in cas.values() if c["status"] != "closed"]
    if open_ca:
        L += ["## Conformance findings not closed", ""]
        L += [f"- **{c['id']}** ({c['status']}) {c['subject']} — {c['note']}" for c in sorted(open_ca, key=lambda c: c['id'])]
        L.append("")

    if conflicts or drift:
        L += ["## Inconsistencies in the repository", "",
              "The KB reports these; it does not edit the repository's documents. Fix them there, then rebuild.", ""]
        for c in conflicts:
            L.append(f"- `{c['kind']}` **{c['id']}**: {c['detail']}")
        for d in drift:
            L.append(f"- `stale-claim` {d['file']} says “{d['claims']}”, actual {d['actual']}")
        L.append("")

    handovers = sorted((KB / "handover").glob("20*.md"))[-3:]
    if handovers:
        L += ["## Latest handover notes", ""] + [f"- handover/{p.name}" for p in reversed(handovers)] + [""]
    (KB / "STATE.md").write_text("\n".join(L), encoding="utf-8")


# ---------------------------------------------------------------- check

def check(repo: Path) -> int:
    problems = []
    state = KB / "STATE.md"
    fp = source_fingerprint(repo)
    if not state.exists():
        problems.append("STATE.md missing: run build")
    elif f"`{fp}`" not in state.read_text():
        problems.append(f"STATE.md is stale: the repository changed since it was built (source is now {fp}). Run build.")
    ops, conflicts = extract_open_points(repo)
    overlay = load_overlay()
    for oid in overlay:
        if oid not in ops and not CA_RE.fullmatch(oid) and not VP_RE.fullmatch(oid):
            problems.append(f"overlay.yaml annotates {oid}, which no document defines")
    for oid, files in decisions_index(only_closes=True).items():
        if oid in ops and ops[oid]["status"] == "open":
            problems.append(f"{oid} is open in the docs but {files[0]} says it closes it")
        if oid not in ops and not CA_RE.fullmatch(oid):
            problems.append(f"{files[0]} closes {oid}, which no document defines")
    for p in sorted((KB / "decisions").glob("[0-9]*.md")):
        meta = decision_meta(p)
        if not meta:
            problems.append(f"decisions/{p.name}: no front matter")
        elif meta.get("status") not in ("accepted", "superseded", "conflicted", "proposed"):
            problems.append(f"decisions/{p.name}: status must be accepted|superseded|conflicted|proposed")
        elif meta["status"] == "conflicted":
            print(f"WARN decisions/{p.name} is conflicted and waiting for the owner: {meta.get('title')}")
    # Inconsistencies inside the repository are reported, not failed on: the KB cannot fix
    # them, and a check that always fails gets ignored. They are listed in STATE.md too.
    for c in conflicts:
        print(f"REPO {c['kind']} {c['id']}: {c['detail'][:160]}")
    for p in problems:
        print("FAIL", p)
    print(f"{len(problems)} KB problem(s), {len(conflicts)} repository inconsistenc{'y' if len(conflicts) == 1 else 'ies'}")
    return 1 if problems else 0


# ---------------------------------------------------------------- show / handover

def show(ident: str) -> None:
    for f in ["open-points.yaml", "findings.yaml", "vp-cases.yaml"]:
        data = yaml.safe_load((REG / f).read_text()) or {}
        if ident in data:
            print(yaml.safe_dump({ident: data[ident]}, sort_keys=False, allow_unicode=True, width=100))
    for i, files in decisions_index().items():
        if i == ident:
            for fn in files:
                print(f"--- decisions/{fn}\n" + (KB / "decisions" / fn).read_text())
    for p in sorted((KB / "handover").glob("20*.md")):
        if ident in p.read_text():
            print(f"mentioned in handover/{p.name}")


def handover(slug: str) -> None:
    now = dt.datetime.now()
    p = KB / "handover" / f"{now:%Y-%m-%d-%H%M}-{re.sub(r'[^a-z0-9-]+', '-', slug.lower()).strip('-')}.md"
    p.write_text((KB / "handover" / "TEMPLATE.md").read_text().replace("{{date}}", f"{now:%Y-%m-%d %H:%M}"),
                 encoding="utf-8")
    print(p)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build"); b.add_argument("--no-run", action="store_true")
    sub.add_parser("check")
    s = sub.add_parser("show"); s.add_argument("id")
    h = sub.add_parser("handover"); h.add_argument("slug")
    a = ap.parse_args()
    if a.cmd == "build":
        build(repo_path(a.repo), run=not a.no_run)
    elif a.cmd == "check":
        sys.exit(check(repo_path(a.repo)))
    elif a.cmd == "show":
        show(a.id)
    else:
        handover(a.slug)


if __name__ == "__main__":
    main()
