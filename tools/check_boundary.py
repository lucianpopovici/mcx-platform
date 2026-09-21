#!/usr/bin/env python3
"""TS-BND — the profile boundary gate.

One check per verification-plan case. Each returns a list of violations; an
empty list is a pass. `tests/test_boundary.py` runs them as pytest cases so
they produce CI evidence (PLT-VER-002, PLT-VER-004).

    python3 tools/check_boundary.py [--root .] [--case VP1-BND-001]

WHAT THESE PROVE, AND WHAT THEY DO NOT.

PLT-SRS assigns most of these requirements verification method **I**
(inspection). A static gate is a mechanised approximation of an inspection, not
a proof: it catches the textual and structural forms of a violation, not every
semantic one. Checks marked HEURISTIC below are strong enough to block the
common failure and to make a deliberate bypass visible in review, but they do
not replace reading the diff. Where a check is weaker than its requirement, it
says so.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import Callable, Dict, List, Tuple

CORE = "core"
PROFILES = "profiles"
TESTS = "tests"

# --------------------------------------------------------------------------
# VP1-BND-001 — no profile-specific terms in core
# --------------------------------------------------------------------------

# Matching is on word boundaries, not substrings: "ato" must not fire inside
# "initiator", and "rail" must not fire inside "trailing".
FORBIDDEN_TERMS = (
    "frmcs", "railway", "rail", "tetra", "p25", "gsmr", "etcs", "ato",
    "shunting", "train", "driver", "dispatcher", "track section",
    "public safety", "imminent peril",
)

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(line: str) -> set:
    return set(_WORD.findall(line.lower()))


def _iter_python(root: Path, package: str):
    yield from sorted((root / package).rglob("*.py"))


def _parse(path: Path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def check_forbidden_terms(root: Path) -> List[str]:
    """VP1-BND-001 / PLT-GEN-006 / PLT-VER-004."""
    violations: List[str] = []
    multiword = [t for t in FORBIDDEN_TERMS if " " in t]
    single = [t for t in FORBIDDEN_TERMS if " " not in t]
    for path in _iter_python(root, CORE):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            lowered = line.lower()
            present = _tokens(line)
            hits = [t for t in single if t in present]
            hits += [t for t in multiword if t in lowered]
            for term in hits:
                violations.append(
                    f"{path.relative_to(root)}:{lineno}: forbidden term {term!r}: "
                    f"{line.strip()[:90]}")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-002 / 003 / 005 — import and call-site structure
# --------------------------------------------------------------------------


def check_imports(root: Path) -> List[str]:
    """VP1-BND-002 / PLT-GEN-007 — no import edge from core to profiles."""
    violations: List[str] = []
    for path in _iter_python(root, CORE):
        for node in ast.walk(_parse(path)):
            names: List[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name == PROFILES or name.startswith(PROFILES + "."):
                    violations.append(
                        f"{path.relative_to(root)}:{node.lineno}: core imports {name!r}")
    return violations


# The methods each hook interface declares. A call on a hook object outside
# this set means the core is using an undeclared capability.
HOOK_METHODS = {
    "identity_resolver": {"resolve", "bind", "unbind", "identities_of"},
    "priority_policy": {"evaluate", "compare"},
    "session_policy": {"admit", "decide", "floor_policy"},
    "bearer_selector": {"select", "on_path_event"},
    "interworking_gateway": {"route", "map_inbound"},
    "interconnection_gateway": {"route", "rights", "map_inbound_priority",
                                "map_outbound"},
}


def check_hook_call_sites(root: Path) -> List[str]:
    """VP1-BND-003 / PLT-GEN-007 — hook interfaces are the only crossing.

    Finds every `<anything>.<hook_field>.<method>` in core and checks the method
    against that interface's declared set.
    """
    violations: List[str] = []
    for path in _iter_python(root, CORE):
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.Attribute):
                continue
            inner = node.value
            if not isinstance(inner, ast.Attribute):
                continue
            field = inner.attr
            if field not in HOOK_METHODS:
                continue
            if node.attr not in HOOK_METHODS[field]:
                violations.append(
                    f"{path.relative_to(root)}:{node.lineno}: core calls "
                    f"{field}.{node.attr}, which {field} does not declare")
    return violations


def check_profile_callbacks(root: Path) -> List[str]:
    """VP1-BND-005 — profiles reach the core only for the interface types."""
    permitted = {"core.hooks", "core.errors", "core.model", "core"}
    violations: List[str] = []
    for path in _iter_python(root, PROFILES):
        for node in ast.walk(_parse(path)):
            modules: List[str] = []
            if isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            elif isinstance(node, ast.Import):
                modules = [a.name for a in node.names]
            for module in modules:
                if module.startswith("core") and module not in permitted:
                    violations.append(
                        f"{path.relative_to(root)}:{node.lineno}: profile imports "
                        f"core internals {module!r}")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-004 — frozen value objects
# --------------------------------------------------------------------------


def check_frozen_value_objects(root: Path) -> List[str]:
    """VP1-BND-004 / PLT-HOK-001."""
    violations: List[str] = []
    path = root / CORE / "hooks.py"
    for node in _parse(path).body:
        if not isinstance(node, ast.ClassDef):
            continue
        decorators = node.decorator_list
        is_dataclass = any(
            (isinstance(d, ast.Call) and getattr(d.func, "id", "") == "dataclass")
            or getattr(d, "id", "") == "dataclass" for d in decorators)
        if not is_dataclass:
            continue
        frozen = any(
            isinstance(d, ast.Call)
            and any(k.arg == "frozen" and getattr(k.value, "value", False) is True
                    for k in d.keywords)
            for d in decorators)
        if not frozen:
            violations.append(
                f"{path.relative_to(root)}:{node.lineno}: dataclass {node.name!r} "
                "is not frozen")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-006 / 007 / 008 — deployment shape
# --------------------------------------------------------------------------


def check_single_image(root: Path) -> List[str]:
    """VP1-BND-006 / PLT-GEN-001 — one artefact carrying every profile."""
    violations: List[str] = []
    packages = sorted(p.parent.name for p in (root / PROFILES).glob("*/profile.yaml"))
    if len(packages) < 2:
        violations.append(
            f"expected at least two profile packages in the image, found {packages}")
    # A per-profile build variant would mean the image is not profile-agnostic.
    for pattern in ("Dockerfile.*", "*.Dockerfile", "build-*.sh"):
        for candidate in root.glob(pattern):
            if any(name in candidate.name for name in packages):
                violations.append(
                    f"{candidate.relative_to(root)}: per-profile build variant")
    return violations


def check_no_default_profile(root: Path) -> List[str]:
    """VP1-BND-007 / PLT-GEN-004 / PLT-PRF-012 — HEURISTIC.

    Catches a default assigned at a profile- or hook-named parameter. It cannot
    prove no default exists anywhere; VP1-LOAD-002 and VP1-LOAD-022 cover the
    behaviour at runtime, and this guards against a default creeping into a
    signature where no test would notice.
    """
    violations: List[str] = []
    suspicious = re.compile(
        r"""(profile|profile_name|profile_names|hooks?)\s*[:=][^=\n]*=\s*["'][\w./-]+["']""",
        re.IGNORECASE)
    for path in _iter_python(root, CORE):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if suspicious.search(line):
                violations.append(
                    f"{path.relative_to(root)}:{lineno}: possible default profile: "
                    f"{line.strip()[:90]}")
    return violations


RELOAD_MARKERS = ("signal.signal", "SIGHUP", "watchdog", "inotify",
                  "reload(", "watch(", "autoreload")


def check_no_hot_reload(root: Path) -> List[str]:
    """VP1-BND-008 / PLT-PRF-010 — no reload handler, watcher or signal hook."""
    violations: List[str] = []
    for path in _iter_python(root, CORE):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for marker in RELOAD_MARKERS:
                if marker in line:
                    violations.append(
                        f"{path.relative_to(root)}:{lineno}: reload mechanism "
                        f"{marker!r}: {line.strip()[:80]}")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-009 / 015 — the core owns the state machines
# --------------------------------------------------------------------------


def check_state_machine_ownership(root: Path) -> List[str]:
    """VP1-BND-009 / PLT-PRF-030 / PLT-PRF-031.

    The floor transition table must be a module-level constant, so a profile
    cannot supply or alter a transition. Timer VALUES are excepted by
    PLT-PRF-031 and are supplied through Policy.
    """
    violations: List[str] = []
    path = root / CORE / "floor.py"
    source = path.read_text(encoding="utf-8")
    if "_DISPATCH" not in source:
        violations.append(f"{path.relative_to(root)}: no transition table found")
        return violations
    tree = _parse(path)
    assigns = [n for n in tree.body
               if isinstance(n, ast.Assign)
               and any(_target_name(t).endswith("_DISPATCH") for t in n.targets)]
    if not assigns:
        violations.append(
            f"{path.relative_to(root)}: the transition table is not a "
            "module-level constant")
    # A transition table built from a profile object would defeat the point.
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in (
                "call_types", "priority", "bearer", "identity", "admission"):
            violations.append(
                f"{path.relative_to(root)}:{node.lineno}: floor control reads "
                f"profile structure {node.attr!r}")
    return violations


def _target_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


FORBIDDEN_IN_FLOOR = ("sip", "rtp", "rtcp", "socket", "requests", "http")


def check_floor_machine_isolated(root: Path) -> List[str]:
    """VP1-BND-015 / PLT-FC-004 — no dependency on SIP, media or the network."""
    violations: List[str] = []
    path = root / CORE / "floor.py"
    for node in ast.walk(_parse(path)):
        modules: List[str] = []
        if isinstance(node, ast.ImportFrom) and node.module:
            modules = [node.module]
        elif isinstance(node, ast.Import):
            modules = [a.name for a in node.names]
        for module in modules:
            leaf = module.split(".")[-1].lower()
            if leaf in FORBIDDEN_IN_FLOOR:
                violations.append(
                    f"{path.relative_to(root)}:{node.lineno}: floor control "
                    f"imports {module!r}")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-010 — reference-point naming
# --------------------------------------------------------------------------

INTERFACE_IDS = {"IF-IDR", "IF-PRI", "IF-SES", "IF-BER", "IF-IWF", "IF-ICX"}


def check_reference_point_naming(root: Path) -> List[str]:
    """VP1-BND-010 / PLT-PRF-032 — boundaries are named for their interface."""
    violations: List[str] = []
    used = set()
    for path in _iter_python(root, CORE):
        used |= set(re.findall(r'"(IF-[A-Z]{3})"',
                               path.read_text(encoding="utf-8")))
    unknown = used - INTERFACE_IDS
    if unknown:
        violations.append(f"unknown interface identifiers in core: {sorted(unknown)}")
    missing = INTERFACE_IDS - used
    if missing:
        violations.append(
            f"interfaces never named at their call site: {sorted(missing)}")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-011 / 012 / 013 — policy lives in the profile
# --------------------------------------------------------------------------


def check_priority_table_declarative(root: Path) -> List[str]:
    """VP1-BND-011 / PLT-HOK-023 — the table is data, not code."""
    violations: List[str] = []
    import yaml
    for package in sorted((root / PROFILES).glob("*/profile.yaml")):
        data = yaml.safe_load(package.read_text(encoding="utf-8"))
        rules = (data.get("priority") or {}).get("rules")
        if not rules:
            violations.append(
                f"{package.relative_to(root)}: no declarative priority rules")
            continue
        for i, rule in enumerate(rules):
            if "match" not in rule or "decision" not in rule:
                violations.append(
                    f"{package.relative_to(root)}: priority.rules[{i}] is not "
                    "a match/decision pair")
    # The shared implementation must not carry priority constants of its own.
    tables = root / PROFILES / "common" / "tables.py"
    if tables.is_file():
        for node in ast.walk(_parse(tables)):
            if isinstance(node, ast.ClassDef) and node.name == "TablePriorityPolicy":
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, int) \
                            and sub.value not in (0, 1, -1):
                        violations.append(
                            f"{tables.relative_to(root)}:{sub.lineno}: priority "
                            f"policy contains the literal {sub.value}")
    return violations


def check_no_qos_mapping_in_core(root: Path) -> List[str]:
    """VP1-BND-012 / PLT-HOK-043 — no QoS literal outside the interface types."""
    violations: List[str] = []
    for path in _iter_python(root, CORE):
        if path.name == "hooks.py":
            continue            # type definitions only, no values
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.Assign):
                continue
            names = [_target_name(t).lower() for t in node.targets]
            if not any("qos" in n or "arp" in n or "5qi" in n or "qci" in n
                       for n in names):
                continue
            if isinstance(node.value, ast.Constant) and \
                    isinstance(node.value.value, int):
                violations.append(
                    f"{path.relative_to(root)}:{node.lineno}: core assigns a QoS "
                    f"literal to {names}")
    return violations


def check_no_priority_table_in_core(root: Path) -> List[str]:
    """VP1-BND-013 / PLT-HOK-021 — HEURISTIC.

    Comparing a floor priority the profile supplied is required by PLT-FC-005,
    so comparison itself cannot be forbidden. What is forbidden is the core
    DERIVING a priority: a lookup table mapping labels onto levels.

    Two discriminators, both needed. Uniformity: a priority table maps string
    keys onto integer levels and nothing else, where a defaults or accumulator
    dict holds mixed types — flagging those made this check cry wolf on the
    validator's own scaffolding. And context: the giveaway is usually the name
    it is bound to, not the literal, so the assignment target is inspected too.
    """
    violations: List[str] = []
    markers = ("priority", "level", "urgency", "preempt")
    for path in _iter_python(root, CORE):
        if path.name == "hooks.py":
            continue
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(_parse(path)):
            dicts: List[Tuple[ast.Dict, str]] = []
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
                names = " ".join(_target_name(x) for x in node.targets)
                dicts.append((node.value, names))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Dict):
                dicts.append((node.value, _target_name(node.target)))
            for d, context in dicts:
                if len(d.keys) < 2:
                    continue
                keys_are_strings = all(
                    isinstance(k, ast.Constant) and isinstance(k.value, str)
                    for k in d.keys)
                values_all_int = all(
                    isinstance(v, ast.Constant) and isinstance(v.value, int)
                    and not isinstance(v.value, bool)
                    for v in d.values)
                if not (keys_are_strings and values_all_int):
                    continue
                haystack = (context + " " +
                            (ast.get_source_segment(source, d) or "")).lower()
                if any(m in haystack for m in markers):
                    violations.append(
                        f"{path.relative_to(root)}:{d.lineno}: core contains a "
                        "label-to-level mapping, which is a priority table")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-014 — resolver context
# --------------------------------------------------------------------------


def check_resolver_receives_context(root: Path) -> List[str]:
    """VP1-BND-014 / PLT-HOK-011 — the whole request reaches the resolver."""
    violations: List[str] = []
    path = root / CORE / "session.py"
    source = path.read_text(encoding="utf-8")
    if "identity_resolver.resolve" not in source:
        violations.append(f"{path.relative_to(root)}: no resolve call site found")
        return violations
    for node in ast.walk(_parse(path)):
        if not isinstance(node, ast.Call):
            continue
        args = [ast.get_source_segment(source, a) or "" for a in node.args]
        if not any("identity_resolver.resolve" in a for a in args):
            continue
        # The call passes the target and the request itself, which carries
        # initiator, call type, application and location.
        if not any(a.strip() == "request" for a in args):
            violations.append(
                f"{path.relative_to(root)}:{node.lineno}: resolve call does not "
                "pass the full request")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-016 — time discipline
# --------------------------------------------------------------------------

LOCAL_TIME_MARKERS = ("datetime.now()", "localtime", "strftime", "time.time()",
                      "utcnow()")


def check_time_discipline(root: Path) -> List[str]:
    """VP1-BND-016 / PLT-GEN-011 — UTC only, durations in milliseconds."""
    violations: List[str] = []
    for path in _iter_python(root, CORE):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for marker in LOCAL_TIME_MARKERS:
                if marker in line:
                    violations.append(
                        f"{path.relative_to(root)}:{lineno}: local or ambiguous "
                        f"time source {marker!r}")
    # Duration-carrying names must state their unit.
    for path in _iter_python(root, CORE):
        for node in ast.walk(_parse(path)):
            if isinstance(node, ast.arg) and node.arg in (
                    "duration", "timeout", "expires", "budget", "interval"):
                violations.append(
                    f"{path.relative_to(root)}:{node.lineno}: parameter "
                    f"{node.arg!r} does not state its unit")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-020 / 021 — conformance suites
# --------------------------------------------------------------------------

CI_CANDIDATES = (".github/workflows/ci.yml", ".gitlab-ci.yml", "Makefile")


def check_ci_runs_both_suites(root: Path) -> List[str]:
    """VP1-BND-020 / PLT-VER-002 — both suites on every change, unskippable."""
    violations: List[str] = []
    found = [c for c in CI_CANDIDATES if (root / c).is_file()]
    if not found:
        return [f"no CI configuration found (looked for {', '.join(CI_CANDIDATES)})"]
    profiles = sorted(p.parent.name for p in (root / PROFILES).glob("*/profile.yaml"))
    for candidate in found:
        text = (root / candidate).read_text(encoding="utf-8")
        for profile in profiles:
            if profile not in text:
                violations.append(
                    f"{candidate}: no suite run for profile {profile!r}")
        if "check_boundary" not in text:
            violations.append(f"{candidate}: boundary gate is not run")
        # A suite that can be skipped by branch or label is not evidence.
        for escape in ("if: ", "allow_failure", "continue-on-error"):
            if escape in text:
                violations.append(
                    f"{candidate}: contains a conditional or failure escape "
                    f"({escape.strip()})")
    return violations


def check_per_profile_suite(root: Path) -> List[str]:
    """VP1-BND-021 / PLT-VER-001 — one suite per profile, same artefact."""
    violations: List[str] = []
    suite = root / TESTS / "test_conformance.py"
    if not suite.is_file():
        return ["no per-profile conformance suite (tests/test_conformance.py)"]
    source = suite.read_text(encoding="utf-8")
    if "MCX_PROFILE" not in source:
        violations.append(
            f"{suite.relative_to(root)}: suite is not parameterised by profile")
    return violations


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

CHECKS: Tuple[Tuple[str, str, Callable[[Path], List[str]]], ...] = (
    ("VP1-BND-001", "no profile-specific terms in core", check_forbidden_terms),
    ("VP1-BND-002", "core does not import profiles", check_imports),
    ("VP1-BND-003", "hook interfaces are the only crossing", check_hook_call_sites),
    ("VP1-BND-004", "hook value objects are frozen", check_frozen_value_objects),
    ("VP1-BND-005", "profiles do not reach into core internals",
     check_profile_callbacks),
    ("VP1-BND-006", "single image carries every profile", check_single_image),
    ("VP1-BND-007", "no default profile", check_no_default_profile),
    ("VP1-BND-008", "no hot reload mechanism", check_no_hot_reload),
    ("VP1-BND-009", "core owns the protocol state machines",
     check_state_machine_ownership),
    ("VP1-BND-010", "reference-point naming", check_reference_point_naming),
    ("VP1-BND-011", "priority table is declarative",
     check_priority_table_declarative),
    ("VP1-BND-012", "no QoS mapping in core", check_no_qos_mapping_in_core),
    ("VP1-BND-013", "no priority table in core", check_no_priority_table_in_core),
    ("VP1-BND-014", "resolver receives full context",
     check_resolver_receives_context),
    ("VP1-BND-015", "floor machine independently testable",
     check_floor_machine_isolated),
    ("VP1-BND-016", "time discipline", check_time_discipline),
    ("VP1-BND-020", "CI runs both suites per change", check_ci_runs_both_suites),
    ("VP1-BND-021", "per-profile conformance suite exists", check_per_profile_suite),
)

BY_CASE: Dict[str, Callable[[Path], List[str]]] = {c: fn for c, _, fn in CHECKS}


def run(root: Path, only: str = "") -> int:
    failed = 0
    for case, title, fn in CHECKS:
        if only and case != only:
            continue
        violations = fn(root)
        if violations:
            failed += 1
            print(f"FAIL {case}  {title}")
            for v in violations:
                print(f"       {v}")
        else:
            print(f"PASS {case}  {title}")
    if failed:
        print(f"\n{failed} boundary check(s) failed. A boundary violation "
              "invalidates the conformance argument above it.")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", type=Path)
    ap.add_argument("--case", default="", help="run one case, e.g. VP1-BND-001")
    args = ap.parse_args()
    return run(args.root.resolve(), args.case)


if __name__ == "__main__":
    sys.exit(main())
