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
from enum import Enum
import io
import re
import sys
import tokenize
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
    # determine_participants: PLT-ICD-001 0.7 section 3.5 (ad hoc criteria).
    "identity_resolver": {"resolve", "bind", "unbind", "identities_of",
                          "determine_participants"},
    "priority_policy": {"evaluate", "compare"},
    # authorise: PLT-ICD-001 0.13 section 5.0 (ICD-OP-09).
    "session_policy": {"authorise", "admit", "decide", "floor_policy"},
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


def _is_dataclass_decorator(d: ast.expr) -> bool:
    """@dataclass, @dataclass(...), @dataclasses.dataclass, @dataclasses.dataclass(...)."""
    target = d.func if isinstance(d, ast.Call) else d
    return (isinstance(target, ast.Name) and target.id == "dataclass") or \
        (isinstance(target, ast.Attribute) and target.attr == "dataclass")


_MUTABLE_TYPES = re.compile(
    r"\b(?:dict|list|set|bytearray|Dict|List|Set|DefaultDict|OrderedDict|Counter|Deque"
    r"|MutableMapping|MutableSequence|MutableSet)\b")


# Every dict method that changes it in place, and __init__, which refills.
_DICT_MUTATORS = {"__setitem__", "__delitem__", "__ior__", "update", "pop", "popitem",
                  "clear", "setdefault"}

# Names a value type's field may be declared with (besides the file's own
# classes and aliases of these): the immutable scalars and the read-only
# generics Value freezes into.
_ALLOWED_TYPE_NAMES = {"str", "int", "float", "bool", "bytes", "complex", "None",
                       "Optional", "Union", "Mapping", "Sequence", "Tuple", "tuple",
                       "FrozenSet", "frozenset", "typing"}


def _annotation_names(expr: ast.expr) -> List[str]:
    """Every name an annotation refers to (`typing.Mapping` gives both)."""
    return [n.id if isinstance(n, ast.Name) else n.attr
            for n in ast.walk(expr) if isinstance(n, (ast.Name, ast.Attribute))]


def _probe_hooks_at_runtime(path: Path) -> List[str]:
    """Load the tree's core/hooks.py and try to change a value (RES-OP-06
    review: names alone can be satisfied by code that does nothing)."""
    import dataclasses as dc
    import importlib.util
    import typing
    rel = path
    name = "_vp1_bnd_004_probe_hooks"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)                     # type: ignore[union-attr]
    except BaseException as exc:                            # noqa: BLE001
        # BaseException: a file ending in sys.exit(0) must not end the whole
        # gate run with success (RES-OP-06 review G3).
        sys.modules.pop(name, None)
        return [f"{rel}: cannot be loaded to probe its values ({exc!r})"]
    try:
        out: List[str] = []
        fd_cls, value_cls = getattr(module, "FrozenDict", None), getattr(module, "Value", None)
        freeze = getattr(module, "freeze", None)
        if fd_cls is None or value_cls is None or freeze is None:
            return [f"{rel}: FrozenDict, Value and freeze must all exist"]
        attempts = {"__setitem__": ("k", 2), "__delitem__": ("k",), "__ior__": ({"k": 2},),
                    "update": ({"k": 2},), "pop": ("k",), "popitem": (), "clear": (),
                    "setdefault": ("n", 3), "__init__": ({"k": 2, "n": 3},)}
        for method, args in attempts.items():
            fd = fd_cls({"k": 1})
            try:
                getattr(fd, method)(*args)
            except Exception:                               # noqa: BLE001
                pass
            if dict(fd) != {"k": 1}:
                out.append(f"{rel}: FrozenDict.{method} changed it")

        def mutable_inside(v) -> bool:
            if isinstance(v, (list, set, bytearray)) or \
                    (isinstance(v, dict) and not isinstance(v, fd_cls)):
                return True
            if isinstance(v, dict):
                return any(mutable_inside(k) or mutable_inside(x) for k, x in v.items())
            if isinstance(v, (tuple, frozenset)):
                return any(mutable_inside(x) for x in v)
            return False

        sample = {"a": [1, {"b": {2}}], "c": bytearray(b"x"), "d": ({"e": []},)}
        try:
            if mutable_inside(freeze(sample)):
                out.append(f"{rel}: freeze() leaves something mutable inside")
        except Exception as exc:                            # noqa: BLE001
            out.append(f"{rel}: freeze() refuses plain nested data ({exc})")

        @dc.dataclass(frozen=True)
        class _Probe(value_cls):
            m: typing.Mapping[str, typing.Any]
            s: typing.Sequence[typing.Any]
            o: typing.Optional[typing.Mapping[str, typing.Any]] = None
        given_m, given_s, given_o = {"x": [1]}, [{"y": 1}], {"z": {"w": 1}}
        try:
            probe = _Probe(given_m, given_s, given_o)
            if mutable_inside(probe.m) or mutable_inside(probe.s) or mutable_inside(probe.o):
                out.append(f"{rel}: Value does not freeze its fields at construction")
        except Exception as exc:                            # noqa: BLE001
            out.append(f"{rel}: a Value cannot be built from plain data ({exc})")
        def subclasses(c):
            for sub in c.__subclasses__():
                yield sub
                yield from subclasses(sub)

        # Every class the file defines, however it was made, and every
        # subclass of its Value (make_dataclass, a class under `if True:`...).
        mine = {c for c in vars(module).values()
                if isinstance(c, type) and c.__module__ == name}
        mine |= {c for c in subclasses(value_cls) if c is not _Probe}
        for cls in sorted(mine, key=lambda c: c.__name__):
            if cls in (value_cls, fd_cls) or issubclass(cls, (Enum, BaseException)) or \
                    getattr(cls, "_is_protocol", False):
                continue
            if not issubclass(cls, value_cls):
                out.append(f"{rel}: {cls.__name__} is not a Value")
                continue
            if not dc.is_dataclass(cls) or not cls.__dataclass_params__.frozen:  # type: ignore[attr-defined]
                out.append(f"{rel}: {cls.__name__} is not a frozen dataclass")
            elif cls.__post_init__ is not value_cls.__post_init__:
                out.append(f"{rel}: {cls.__name__} replaces Value.__post_init__")
            for attr, held in vars(cls).items():
                if not attr.startswith("__") and (
                        isinstance(held, (list, set, bytearray)) or
                        (isinstance(held, dict) and not isinstance(held, fd_cls))):
                    out.append(f"{rel}: {cls.__name__}.{attr} is a mutable "
                               f"{type(held).__name__} shared by every instance")
        return out
    finally:
        sys.modules.pop(name, None)


def check_frozen_value_objects(root: Path) -> List[str]:
    """VP1-BND-004 / PLT-HOK-001: every value type in core/hooks.py is frozen
    and holds nothing mutable.

    A frozen dataclass still lets a dict or list in it be changed in place
    (RES-OP-06). Statically: every class other than a Protocol, an Enum,
    `Value` or `FrozenDict` is a frozen dataclass deriving from `Value`, does
    not define its own `__post_init__`, and declares its fields only with
    immutable types (scalars, Optional/Mapping/Sequence/Tuple/FrozenSet, the
    file's own classes, aliases of these). At runtime, the file is loaded and
    a FrozenDict, freeze() and a probe Value are made to change: names alone
    can be satisfied by code that does nothing (RES-OP-06 review)."""
    violations: List[str] = []
    path = root / CORE / "hooks.py"
    rel = path.relative_to(root)
    tree = _parse(path)
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
    names = {c.name for c in classes}
    aliases: Dict[str, ast.expr] = {
        t.id: n.value for n in tree.body if isinstance(n, ast.Assign)
        for t in n.targets if isinstance(t, ast.Name) and not t.id.startswith("_")}

    def allowed(name: str, seen=()) -> bool:
        if name in _ALLOWED_TYPE_NAMES or name in names:
            return True
        if name in aliases and name not in seen:
            return all(allowed(n, seen + (name,)) for n in _annotation_names(aliases[name]))
        return False

    value = next((c for c in classes if c.name == "Value"), None)
    if value is None or not any(isinstance(n, ast.FunctionDef) and n.name == "__post_init__"
                                for n in value.body):
        violations.append(f"{rel}: no `Value` base with a __post_init__ that freezes "
                          "its fields")
    for node in classes:
        bases = {ast.unparse(b) for b in node.bases}
        if node.name in ("Value", "FrozenDict") or bases & {"Protocol", "Enum"} or \
                any(b.endswith("Enum") or b.startswith("Protocol") for b in bases):
            continue
        where = f"{rel}:{node.lineno}: {node.name!r}"
        decorators = [d for d in node.decorator_list if _is_dataclass_decorator(d)]
        if not decorators:
            violations.append(f"{where} is not a dataclass: a value type must be a "
                              "frozen dataclass deriving from Value")
            continue
        frozen = any(isinstance(d, ast.Call) and any(
            k.arg == "frozen" and isinstance(k.value, ast.Constant) and k.value.value is True
            for k in d.keywords) for d in decorators)
        if not frozen:
            violations.append(f"{where} is not frozen")
        if "Value" not in bases and not (bases & (names - {"Value", "FrozenDict"})):
            violations.append(f"{where} does not derive from Value, so its fields "
                              "are not frozen")
        for stmt in node.body:
            if isinstance(stmt, (ast.Assign, ast.AugAssign)):
                violations.append(f"{rel}:{stmt.lineno}: {node.name} has a class attribute "
                                  "without a declared type: shared by every instance, "
                                  "and not frozen")
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                    stmt.name.startswith("__") and stmt.name != "__post_init__":
                violations.append(f"{rel}:{stmt.lineno}: {node.name} defines {stmt.name}, "
                                  "which can change how a value behaves")
            if isinstance(stmt, ast.FunctionDef) and stmt.name == "__post_init__":
                violations.append(f"{rel}:{stmt.lineno}: {node.name} defines its own "
                                  "__post_init__, which would replace Value's freezing")
            if isinstance(stmt, ast.AnnAssign):
                bad = sorted({n for n in _annotation_names(stmt.annotation) if not allowed(n)})
                if bad or _MUTABLE_TYPES.search(ast.unparse(stmt.annotation)):
                    violations.append(f"{rel}:{stmt.lineno}: {node.name}."
                                      f"{ast.unparse(stmt.target)} is declared "
                                      f"{ast.unparse(stmt.annotation)}, a mutable type or "
                                      f"one not known to be immutable"
                                      + (f" ({', '.join(bad)})" if bad else ""))
    if not violations:
        violations += _probe_hooks_at_runtime(path)
    return violations


# --------------------------------------------------------------------------
# VP1-BND-006 / 007 / 008 — deployment shape
# --------------------------------------------------------------------------


def _load_packager(root: Path):
    import importlib.util
    path = root / "tools" / "package.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_mcx_package", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_per_profile_images(root: Path) -> List[str]:
    """VP1-BND-006 / PLT-GEN-001 — one core, one profile per image.

    Builds every in-tree profile's image with tools/package.py and holds the
    set to three rules:

    1. Each image carries exactly one profile package.
    2. The shared part (core, service, profile framework) hashes the same in
       every image. This is what keeps VP1-BND-001 meaningful once there is
       no single artefact: the core under test is the core in every delivery.
    3. Code that ships in every image does not name a specific profile, and
       nothing in the build varies per profile. What varies is data, the
       profile package, never a build file.

    HEURISTIC for rule 3: it catches a profile package named by import path
    (`profiles.<name>`) or path segment (`/ "<name>"`), not every way code
    could depend on one. Rules 1 and 2 are exact.
    """
    import tempfile
    violations: List[str] = []
    packager = _load_packager(root)
    if packager is None or not hasattr(packager, "stage"):
        return ["tools/package.py is missing: there is no way to build a release image"]
    names = packager.profile_names(root)
    if not names:
        return ["no profile packages to build"]

    with tempfile.TemporaryDirectory(prefix="mcx-bnd006-") as tmp:
        images = {n: packager.stage(n, Path(tmp), root) for n in names}
        violations += packager.verify(images)

    alt = "|".join(map(re.escape, names))
    named = re.compile(rf"\bprofiles\.({alt})\b|[/\\]\s*[\"']({alt})[\"']")
    for rel in packager.shared_files(root):
        if not rel.endswith(".py"):
            continue
        for lineno, line in enumerate((root / rel).read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if named.search(line):
                violations.append(
                    f"{rel}:{lineno}: shared code names a profile package, but every "
                    f"image carries only one: {line.strip()[:90]}")

    for pattern in ("Dockerfile*", "*.Dockerfile", "Containerfile*", "*.Containerfile",
                    "build-*.sh", "tools/*Containerfile*", "tools/*Dockerfile*"):
        for candidate in root.glob(pattern):
            if any(name in candidate.name for name in names):
                violations.append(
                    f"{candidate.relative_to(root)}: per-profile build variant; the profile "
                    "is data given to tools/package.py, not a build file")
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
    """VP1-BND-021 / PLT-VER-001 — one suite per profile, same core (VP1-BND-006)."""
    violations: List[str] = []
    suite = root / TESTS / "test_conformance.py"
    if not suite.is_file():
        return ["no per-profile conformance suite (tests/test_conformance.py)"]
    source = suite.read_text(encoding="utf-8")
    if "MCX_PROFILE" not in source:
        violations.append(
            f"{suite.relative_to(root)}: suite is not parameterised by profile")
    return violations


def _code_lines(path: Path) -> List[Tuple[int, str]]:
    """Source lines with comments and string literals blanked out.

    Written after this gate's first version flagged its own docstring, which
    quotes `release >= 19` as the thing not to write. Stripping only comments
    is not enough: a docstring explaining a rule is not a breach of it. The
    line numbers are preserved so a real violation still points at its line.
    """
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    lines = source.splitlines()
    blanked = list(lines)
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return [(i, l.split("#", 1)[0]) for i, l in enumerate(lines, 1)]
    for tok in tokens:
        if tok.type not in (tokenize.STRING, tokenize.COMMENT):
            continue
        (r1, c1), (r2, c2) = tok.start, tok.end
        for row in range(r1, r2 + 1):
            line = blanked[row - 1]
            start = c1 if row == r1 else 0
            end = c2 if row == r2 else len(line)
            blanked[row - 1] = line[:start] + " " * (end - start) + line[end:]
    return list(enumerate(blanked, 1))


def check_release_knowledge_is_in_one_module(root: Path) -> List[str]:
    """VP1-BND-022 / PLT-REL-008 — release numbers live in core/release.py.

    The same argument as the profile boundary, one axis over. A release
    comparison written inline (`if release >= 19`) is a constant nobody will
    find when Rel-21 lands, and the tables in core/release.py were extracted
    from the specifications while an inline literal was not.

    Digits in comments and docstrings are fine -- citing a release is how the
    code explains itself. What is forbidden is COMPARING to one.
    """
    violations: List[str] = []
    comparison = re.compile(
        r"(?:release|rel)\s*(?:>=|<=|==|!=|>|<)\s*(?:1[3-9]|20)\b"
        r"|(?:1[3-9]|20)\s*(?:>=|<=|==|!=|>|<)\s*(?:release|rel)\b",
        re.IGNORECASE)
    allowed = {Path("core/release.py"), Path("tests/test_release.py")}
    for path in sorted(root.rglob("*.py")):
        rel_path = path.relative_to(root)
        if rel_path in allowed or "__pycache__" in rel_path.parts:
            continue
        if rel_path.parts and rel_path.parts[0] not in (CORE, "service", "tools"):
            continue
        for n, code in _code_lines(path):
            if comparison.search(code):
                violations.append(
                    f"{rel_path}:{n}: release compared to a literal outside "
                    f"core/release.py: {code.strip()[:70]}")
    return violations


def check_release_is_a_deployment_parameter(root: Path) -> List[str]:
    """VP1-BND-023 / PLT-REL-002 — MCX_RELEASE is stated, never defaulted."""
    violations: List[str] = []
    cfg = root / "service" / "config.py"
    if not cfg.is_file():
        return ["service/config.py is missing"]
    source = cfg.read_text(encoding="utf-8")
    if "MCX_RELEASE" not in source:
        violations.append("service/config.py: the release is not read from "
                          "the environment")
    for bad in ('env.get("MCX_RELEASE", ', "env.get('MCX_RELEASE', "):
        if bad in source:
            violations.append(
                "service/config.py: MCX_RELEASE has a fallback value; a "
                "guessed release is silent on the wire")
    suite = root / TESTS / "test_release.py"
    if not suite.is_file():
        violations.append("no per-release conformance suite "
                          "(tests/test_release.py)")
    return violations


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

CHECKS: Tuple[Tuple[str, str, Callable[[Path], List[str]]], ...] = (
    ("VP1-BND-001", "no profile-specific terms in core", check_forbidden_terms),
    ("VP1-BND-002", "core does not import profiles", check_imports),
    ("VP1-BND-003", "hook interfaces are the only crossing", check_hook_call_sites),
    ("VP1-BND-004", "hook value objects are frozen and hold nothing mutable",
     check_frozen_value_objects),
    ("VP1-BND-005", "profiles do not reach into core internals",
     check_profile_callbacks),
    ("VP1-BND-006", "one core, one profile per image", check_per_profile_images),
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
    ("VP1-BND-022", "release knowledge is in one module",
     check_release_knowledge_is_in_one_module),
    ("VP1-BND-023", "release is a stated deployment parameter",
     check_release_is_a_deployment_parameter),
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
