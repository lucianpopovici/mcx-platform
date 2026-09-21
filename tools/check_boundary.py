#!/usr/bin/env python3
"""VP1-BND-001..005 — the profile boundary gate.

Fails the build if the core has learned anything about a specific profile.
This is the mechanical half of PLT-VER-003: the conformance suites catch
behavioural leaks, this catches textual and structural ones.

    python3 tools/check_boundary.py [--root .]

Exit status 0 clean, 1 on any violation.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

# Terms that name a specific profile or a profile-specific domain concept.
# A profile author introducing a domain vocabulary adds its terms here.
#
# Matching is on word boundaries, not substrings: "ato" must not fire inside
# "initiator", and "rail" must not fire inside "trailing".
FORBIDDEN_TERMS = (
    "frmcs", "railway", "rail", "tetra", "p25", "gsmr", "etcs", "ato",
    "shunting", "train", "driver", "dispatcher", "track section",
    "public safety", "imminent peril", "rec",
)

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(line: str) -> set:
    """Lowercase word tokens, with underscores and hyphens as separators, so
    `initiator_roles` yields {initiator, roles} and never matches 'ato'."""
    return set(_WORD.findall(line.lower()))

CORE = "core"
PROFILES = "profiles"


def _iter_python(root: Path, package: str) -> Iterable[Path]:
    yield from sorted((root / package).rglob("*.py"))


def check_forbidden_terms(root: Path) -> List[str]:
    """VP1-BND-001 — no profile-specific identifier, literal or comment in core."""
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


def check_imports(root: Path) -> List[str]:
    """VP1-BND-002 — no import edge from core to profiles."""
    violations: List[str] = []
    for path in _iter_python(root, CORE):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            violations.append(f"{path.relative_to(root)}: does not parse: {exc}")
            continue
        for node in ast.walk(tree):
            names: List[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name == PROFILES or name.startswith(PROFILES + "."):
                    violations.append(
                        f"{path.relative_to(root)}:{node.lineno}: core imports "
                        f"{name!r}")
    return violations


def check_profile_callbacks(root: Path) -> List[str]:
    """VP1-BND-005 — profiles reach the core only for the hook types.

    A profile importing core machinery (loader, validation) rather than the
    interface types is reaching around the boundary.
    """
    permitted = {"core.hooks", "core.errors", "core.model", "core"}
    violations: List[str] = []
    for path in _iter_python(root, PROFILES):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            violations.append(f"{path.relative_to(root)}: does not parse: {exc}")
            continue
        for node in ast.walk(tree):
            module = None
            if isinstance(node, ast.ImportFrom) and node.module:
                module = node.module
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.startswith("core") and a.name not in permitted:
                        violations.append(
                            f"{path.relative_to(root)}:{node.lineno}: profile "
                            f"imports core internals {a.name!r}")
                continue
            if module and module.startswith("core") and module not in permitted:
                violations.append(
                    f"{path.relative_to(root)}:{node.lineno}: profile imports core "
                    f"internals {module!r}")
    return violations


def check_frozen_value_objects(root: Path) -> List[str]:
    """VP1-BND-004 — every hook value object is a frozen dataclass."""
    violations: List[str] = []
    path = root / CORE / "hooks.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        decorators = [d for d in node.decorator_list]
        is_dataclass = any(
            (isinstance(d, ast.Call) and getattr(d.func, "id", "") == "dataclass")
            or getattr(d, "id", "") == "dataclass"
            for d in decorators)
        if not is_dataclass:
            continue
        frozen = any(
            isinstance(d, ast.Call)
            and any(k.arg == "frozen" and getattr(k.value, "value", False) is True
                    for k in d.keywords)
            for d in decorators)
        if not frozen:
            violations.append(
                f"{path.relative_to(root)}:{node.lineno}: dataclass "
                f"{node.name!r} is not frozen")
    return violations


CHECKS: Tuple[Tuple[str, str, object], ...] = (
    ("VP1-BND-001", "no profile-specific terms in core", check_forbidden_terms),
    ("VP1-BND-002", "core does not import profiles", check_imports),
    ("VP1-BND-004", "hook value objects are frozen", check_frozen_value_objects),
    ("VP1-BND-005", "profiles do not reach into core internals",
     check_profile_callbacks),
)


def run(root: Path) -> int:
    failed = 0
    for case, title, fn in CHECKS:
        violations = fn(root)
        if violations:
            failed += 1
            print(f"FAIL {case}  {title}")
            for v in violations:
                print(f"       {v}")
        else:
            print(f"PASS {case}  {title}")
    if failed:
        print(f"\n{failed} boundary check(s) failed. "
              "A boundary violation invalidates the conformance argument above it.")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", type=Path)
    args = ap.parse_args()
    return run(args.root.resolve())


if __name__ == "__main__":
    sys.exit(main())
