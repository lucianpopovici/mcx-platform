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
import unicodedata
from pathlib import Path
from typing import Callable, Dict, List, Tuple

CORE = "core"
PROFILES = "profiles"
TESTS = "tests"

# --------------------------------------------------------------------------
# VP1-BND-001 — no profile-specific terms in core
# --------------------------------------------------------------------------

# Matching is on word boundaries, not substrings: "ato" must not fire inside
# "initiator", and "rail" must not fire inside "trailing". Since RES-OP-09
# identifiers are split on case and `_` too (`RailwayProfile` is two words),
# a plural matches its term (`trains`), adjacent words are also read joined
# (`GSM-R`, `gsm_r` are `gsmr`), and every file under core/ is read, not only
# Python. The in-tree profile names join the list, read from profiles/; "mcx"
# is exempt, being the platform's own name (MCX_* settings, the mcx.* loggers).
FORBIDDEN_TERMS = (
    "frmcs", "railway", "rail", "tetra", "p25", "gsmr", "etcs", "ato",
    "shunting", "train", "driver", "dispatcher", "track section",
    "public safety",
)
# "imminent peril" left the list with RES-OP-09: it is a TS 24.379 element
# (<imminentperil-ind>) the core must parse and render, not a
# profile's word. Read as identifiers, every hit in core was that element.
PLATFORM_NAMES = frozenset({"mcx"})
# Terms common enough to occur inside an ordinary word ("ato" in "a_to_b",
# "train" in "constraint", "rail" in "guardrail") match only as a whole word;
# the others also match inside one (`railwayprofile`, `FRMCSMODE`), and two-
# word terms match written as one (`tracksection`). Review of RES-OP-09.
WHOLE_WORD_ONLY = frozenset({"ato"})
# "train", "rail" and "driver" match inside a word too (`TRAINID`,
# `railnet`), but not inside these ordinary ones. Accepted false positives,
# to rename if they ever occur: tetrahedron (tetra), p250 (p25),
# EventDispatcher (dispatcher), "device driver", "a utility function".
INSIDE_WORD_EXCEPTIONS = ("trail", "constrain", "strain", "guardrail", "handrail",
                          "training")

_PART = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_COMPOUND = re.compile(r"[A-Za-z0-9_-]+")
_SUBCHUNK = re.compile(r"[A-Za-z0-9]+")


def _normal(text: str) -> str:
    """As Python reads identifiers (NFKC: a fullwidth letter is its ASCII
    one), then without format characters (a soft hyphen) or combining marks
    (an accent), so neither hides a term."""
    text = "".join(c for c in unicodedata.normalize("NFKC", text)
                   if unicodedata.category(c) != "Cf")
    return "".join(c for c in unicodedata.normalize("NFKD", text)
                   if not unicodedata.combining(c))


def _compounds(line: str) -> List[List[str]]:
    """Each run of word characters, `-` and `_`, as its words: split on those
    two, on case and on digits, lower-cased."""
    return [[w.lower() for chunk in _SUBCHUNK.findall(c) for w in _PART.findall(chunk)]
            for c in _COMPOUND.findall(_normal(line))]


def _words(line: str) -> List[str]:
    return [w for c in _compounds(line) for w in c]


def _singular(word: str) -> set:
    forms = {word}
    if word.endswith("ies") and len(word) > 4:
        forms.add(word[:-3] + "y")
    if word.endswith("es") and len(word) > 3:
        forms.add(word[:-2])
    if word.endswith("s") and len(word) > 2:
        forms.add(word[:-1])
    return forms


def _tokens(line: str) -> set:
    """Each word and its singular; and, within one compound only (`GSM-R`,
    `gsm_r`), adjacent words joined. Words are never joined across a space
    or a dot, so "a to" or `a.to_bytes` do not read as one word."""
    out: set = set()
    for words in _compounds(line):
        for w in words:
            out |= _singular(w)
        for x, y in zip(words, words[1:]):
            out |= {f"\x00{j}" for j in _singular(x + y)}       # joined forms, marked
    return out


def _phrases(line: str) -> set:
    """Adjacent word pairs, as 'a b', the second word also singular."""
    words = _words(line)
    return {f"{a} {s}" for a, b in zip(words, words[1:]) for s in _singular(b)}


def _term_hits(line: str, terms: List[str]) -> List[str]:
    tokens, phrases = _tokens(line), _phrases(line)
    plain = {t for t in tokens if not t.startswith("\x00")}
    joined = {t[1:] for t in tokens if t.startswith("\x00")}
    hits = []
    for term in terms:
        squashed = term.replace(" ", "")
        if " " in term and term in phrases:
            hits.append(term)
        elif squashed in plain:
            hits.append(term)
        elif term not in WHOLE_WORD_ONLY and (
                squashed in joined or any(
                    squashed in w and not any(x in w for x in INSIDE_WORD_EXCEPTIONS)
                    for w in plain | joined)):
            hits.append(term)
    return hits


_MIXED = re.compile(r"\w+")


def _mixed_script(line: str) -> List[str]:
    """Words mixing ASCII letters with other letters: a homoglyph hides a
    term from every word match (`rаilway` with a Cyrillic а)."""
    out = []
    for w in _MIXED.findall(line):
        letters = [c for c in w if c.isalpha()]
        if any(c.isascii() for c in letters) and any(not c.isascii() for c in letters):
            out.append(w)
    return out


def _iter_python(root: Path, package: str):
    yield from sorted((root / package).rglob("*.py"))


def _iter_files(root: Path, package: str):
    for path in sorted((root / package).rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            yield path


def _parse(path: Path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _profile_names(root: Path) -> List[str]:
    return sorted(p.parent.name for p in (root / PROFILES).glob("*/profile.yaml"))


_CONTROL = re.compile(r"[\x00-\x08\x0b\x0e-\x1f\x7f]")


CACHE_DIRS = frozenset({"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"})


def _core_files(root: Path):
    """Every file under core/ but the named caches and editor swap files."""
    for path in sorted((root / CORE).rglob("*")):
        parts = path.relative_to(root / CORE).parts
        if not path.is_file() or any(p in CACHE_DIRS for p in parts) or \
                path.name.endswith((".swp", ".swo")):
            continue
        yield path


def check_forbidden_terms(root: Path) -> List[str]:
    """VP1-BND-001 / PLT-GEN-006 / PLT-VER-004."""
    violations: List[str] = []
    terms = list(FORBIDDEN_TERMS) + [n for n in _profile_names(root)
                                     if n not in PLATFORM_NAMES and n not in FORBIDDEN_TERMS]
    for path in _core_files(root):
        rel = path.relative_to(root)
        if not str(path.relative_to(root / CORE)).isascii():
            violations.append(f"{rel}: non-ASCII file name; core file names are ASCII")
        # A module or package name is an identifier too (`import core.railway`).
        for term in _term_hits(" ".join(path.relative_to(root / CORE).with_suffix("").parts),
                               terms):
            violations.append(f"{rel}: forbidden term {term!r} in the file's name")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            violations.append(f"{rel}: not text; core holds code only")
            continue
        if _CONTROL.search(text):
            violations.append(f"{rel}: not text (control characters); core holds code only")
            continue
        if path.suffix == ".py":
            try:
                for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                    if tok.type == tokenize.NAME and not tok.string.isascii():
                        violations.append(f"{rel}:{tok.start[0]}: non-ASCII identifier "
                                          f"{tok.string!r}; core identifiers are ASCII")
            except (tokenize.TokenError, IndentationError, SyntaxError):
                violations.append(f"{rel}: does not tokenise")
        for lineno, line in enumerate(text.splitlines(), 1):
            for word in _mixed_script(line):
                violations.append(f"{rel}:{lineno}: word {word!r} mixes ASCII and other "
                                  "letters")
            for term in _term_hits(line, terms):
                violations.append(
                    f"{rel}:{lineno}: forbidden term {term!r}: {line.strip()[:90]}")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-002 / 003 / 005 — import and call-site structure
# --------------------------------------------------------------------------

# The one dynamic import edge from core: the loader imports the hook classes
# a profile's configuration names (PLT-ICD-001 2.1), in its top-level
# function `_import_symbol`. Anywhere else in core, any reference to a way of
# importing or running code by name is a violation, whatever it is called
# through (review of RES-OP-09: an alias, getattr, exec, importlib.util).
SANCTIONED_DYNAMIC_IMPORT = ("core/loader.py", "_import_symbol")
_DYNAMIC_NAMES = {"import_module", "__import__", "exec", "eval", "compile",
                  "run_module", "run_path", "resolve_name", "spec_from_file_location",
                  "module_from_spec", "find_spec", "exec_module", "__builtins__",
                  "modules", "import_string"}
_DYNAMIC_MODULES = {"importlib", "runpy", "pkgutil", "imp", "zipimport"}
# Standard modules that reach modules or run code by name, or hand out the
# interpreter's import machinery (sys.modules, builtins.__import__). Core
# imports none of them; a profile may not either (review of RES-OP-09).
_NAME_RESOLVERS = {"sys", "builtins", "pydoc", "pickle", "marshal", "code", "codeop",
                   "ctypes", "unittest", "logging.config", "inspect", "gc", "shelve",
                   "copyreg"}
_DYNAMIC_NAMES_EXTRA = {"__loader__", "__spec__", "__self__", "__func__", "__globals__",
                        "__dict__", "__getattribute__", "__subclasses__", "__closure__",
                        "__code__", "__wrapped__", "globals", "locals"}
# What core may import at all: the standard library, the YAML parser the
# loader reads profiles with, and itself. Nothing else can carry a profile in.
CORE_THIRD_PARTY = frozenset({"yaml"})
_PROFILES_STRING = re.compile(r"(?i:(?:^|[/\\.])profiles(?:[/\\.][A-Za-z_]|$))")


def _imported_modules(node, path: Path, root: Path, package: str) -> List[str]:
    """Absolute module names an import statement reaches, relative ones
    resolved against the file's package."""
    if isinstance(node, ast.Import):
        return [a.name for a in node.names]
    if not isinstance(node, ast.ImportFrom):
        return []
    if node.level:
        parts = list(path.relative_to(root).with_suffix("").parts)[:-1]
        if path.name == "__init__.py":
            parts = list(path.relative_to(root).parts)[:-1]
        base = parts[:len(parts) - (node.level - 1)] if node.level - 1 <= len(parts) else []
        prefix = ".".join(base + ([node.module] if node.module else []))
    else:
        prefix = node.module or ""
    if node.module:
        return [prefix] + [f"{prefix}.{a.name}" for a in node.names]
    return [f"{prefix}.{a.name}" if prefix else a.name for a in node.names]


def _string_arg(call: ast.Call):
    if call.args and isinstance(call.args[0], ast.Constant) and \
            isinstance(call.args[0].value, str):
        return call.args[0].value
    return None


def _strings(tree):
    """Every str and bytes constant, f-string parts included."""
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, (str, bytes)):
            v = n.value.decode("latin-1") if isinstance(n.value, bytes) else n.value
            yield n.lineno, v


# The loader's view of a hook (core/loader.py _Declared) reads its own slots
# with object.__getattribute__, which is the one other use of interpreter
# machinery core needs; and the loader alone checks hook classes against
# their Protocols with `inspect`.
SANCTIONED_CLASSES = ("core/loader.py", "_declared")
LOADER_ONLY_IMPORTS = frozenset({"inspect"})


def _sanctioned_lines(tree, rel: str) -> set:
    lines: set = set()
    for node in tree.body:                       # top level only
        if rel == SANCTIONED_DYNAMIC_IMPORT[0] and isinstance(node, ast.FunctionDef) and \
                node.name == SANCTIONED_DYNAMIC_IMPORT[1]:
            lines |= set(range(node.lineno, (node.end_lineno or node.lineno) + 1))
        if rel == SANCTIONED_CLASSES[0] and isinstance(node, (ast.ClassDef, ast.FunctionDef)) \
                and node.name == SANCTIONED_CLASSES[1]:
            lines |= set(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return lines


def _dynamic_references(tree, rel: str, sanctioned: set) -> List[str]:
    out = []
    for n in ast.walk(tree):
        name = n.id if isinstance(n, ast.Name) else \
            n.attr if isinstance(n, ast.Attribute) else None
        if name is None and isinstance(n, ast.alias):
            name = n.name.split(".")[-1]          # what is imported, whatever it is called
        if name is None:
            continue
        if name == "modules" and not (isinstance(n, ast.Attribute) and
                                      isinstance(n.value, ast.Name) and n.value.id == "sys"):
            continue
        if name == "compile" and isinstance(n, ast.Attribute):
            continue                              # re.compile and the like
        if (name in _DYNAMIC_NAMES or name in _DYNAMIC_NAMES_EXTRA) and \
                getattr(n, "lineno", 0) not in sanctioned:
            out.append(f"{rel}:{getattr(n, 'lineno', 0)}: dynamic import or execution "
                       f"({name}); only the loader's configuration-driven import is permitted")
    # The same names written as strings reach the same place through
    # getattr or operator.attrgetter (review of RES-OP-09, round 3).
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and \
                n.value in (_DYNAMIC_NAMES_EXTRA | {"__import__", "__builtins__"}) and \
                n.lineno not in sanctioned:
            out.append(f"{rel}:{n.lineno}: the name {n.value!r} as a string reaches "
                       "interpreter internals")
    return out


def check_imports(root: Path) -> List[str]:
    """VP1-BND-002 / PLT-GEN-007 — no import edge from core to profiles.

    Static imports, absolute or relative; any import of a module outside the
    standard library, `yaml` and core itself; any reference to a dynamic
    import or to running code by name but the loader's one call; and any
    string naming the profiles package as a module or a path."""
    stdlib = set(sys.stdlib_module_names)
    violations: List[str] = []
    for path in _iter_python(root, CORE):
        rel = path.relative_to(root).as_posix()
        try:
            tree = _parse(path)
        except (SyntaxError, UnicodeDecodeError) as exc:
            violations.append(f"{rel}: does not parse ({type(exc).__name__})")
            continue
        sanctioned = _sanctioned_lines(tree, rel)
        for node in ast.walk(tree):
            reached = _imported_modules(node, path, root, CORE)
            for name in reached:
                if name == PROFILES or name.startswith(PROFILES + "."):
                    violations.append(f"{rel}:{node.lineno}: core imports {name!r}")
            if isinstance(node, (ast.Import, ast.ImportFrom)) and reached and \
                    not getattr(node, "level", 0):
                top = reached[0].split(".")[0]
                if any(m == x or m.startswith(x + ".") for m in reached for x in _NAME_RESOLVERS) \
                        and not (rel == SANCTIONED_DYNAMIC_IMPORT[0] and top in LOADER_ONLY_IMPORTS):
                    violations.append(f"{rel}:{node.lineno}: core imports {reached[0]!r}, "
                                      "which reaches modules or runs code by name")
                elif top in _DYNAMIC_MODULES and rel != SANCTIONED_DYNAMIC_IMPORT[0]:
                    violations.append(f"{rel}:{node.lineno}: core imports {reached[0]!r}, "
                                      "a dynamic importer")
                elif top not in stdlib and top not in CORE_THIRD_PARTY and top != CORE:
                    violations.append(f"{rel}:{node.lineno}: core imports {reached[0]!r}, "
                                      "neither the standard library, yaml nor core")
        violations += _dynamic_references(tree, rel, sanctioned)
        for lineno, v in _strings(tree):
            if _PROFILES_STRING.search(v):
                violations.append(f"{rel}:{lineno}: core names the profiles package: "
                                  f"{v[:60]!r}")
    return sorted(set(violations))


# The methods each hook interface declares, read from the Protocols in
# core/hooks.py; the hook fields, from core/validation.py HOOK_FIELDS; and
# the loader's own table checked against both (RES-OP-09: these were hand
# copies, so a seventh hook would have gone unchecked). A call on a hook
# object outside its set means the core is using an undeclared capability.
def _hook_fields(root: Path) -> Dict[str, str]:
    try:
        tree = _parse(root / CORE / "validation.py")
    except (OSError, SyntaxError):
        return {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and any(_target_name(t) == "HOOK_FIELDS"
                                             for t in n.targets):
            fields = ast.literal_eval(n.value)
            return {f: "".join(part.capitalize() for part in f.split("_")) for f in fields}
    return {}


def hook_methods(root: Path) -> Dict[str, set]:
    try:
        tree = _parse(root / CORE / "hooks.py")
    except (OSError, SyntaxError):
        return {}
    protocols = {}
    for c in tree.body:
        if isinstance(c, ast.ClassDef):
            protocols[c.name] = {f.name for f in c.body
                                 if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
                                 and not f.name.startswith("_")}
    return {field: protocols.get(cls, set()) for field, cls in _hook_fields(root).items()}


def _loader_table(root: Path) -> Dict[str, set]:
    try:
        tree = _parse(root / CORE / "loader.py")
    except (OSError, SyntaxError):
        return {}
    for n in tree.body:
        target = n.target if isinstance(n, ast.AnnAssign) else \
            (n.targets[0] if isinstance(n, ast.Assign) else None)
        if target is not None and _target_name(target) == "HOOK_INTERFACES" and \
                isinstance(n.value, ast.Dict):
            return {ast.literal_eval(k): set(ast.literal_eval(v.elts[1]))
                    for k, v in zip(n.value.keys, n.value.values)}
    return {}


def _hook_field(node, fields) -> str:
    """The hook field an expression names (`<x>.session_policy`), or ''."""
    if isinstance(node, ast.Attribute) and node.attr in fields:
        return node.attr
    return ""


# The loaded hook bundle as core holds it (SessionManager._hooks). Not the
# module core.hooks, nor the profile's hook specifications (model.HookPaths).
_BUNDLE_NAMES = {"_hooks"}


def check_hook_call_sites(root: Path) -> List[str]:
    """VP1-BND-003 / PLT-GEN-007 — hook interfaces are the only crossing.

    Every `<x>.<hook_field>.<method>` in core, and every use of an alias bound
    to a hook object -- by assignment, tuple unpacking, alias of an alias, a
    for/with/comprehension target, a default argument, or `self.<x> = ...`
    in any method of the class -- names a method its Protocol declares.
    `getattr`/`vars` on a hook object, an alias of one, or the hook bundle is
    refused outright, and only known shapes of use pass (`_hook_shapes`).
    What no static rule can follow -- a bundle held under another name than
    `_hooks`, an alias passed on or held in a global -- is closed at run time:
    the core holds each hook through core/loader.py's declared-method view,
    which neither by attribute nor through a method's __self__ reaches the
    hook itself (review of RES-OP-09)."""
    methods = hook_methods(root)
    fields = set(methods)
    violations: List[str] = []
    if not fields or not all(methods.values()):
        return ["core/validation.py HOOK_FIELDS or the Protocols in core/hooks.py could "
                "not be read; the gate cannot tell which methods are declared"]
    table = _loader_table(root)
    if table and table != methods:
        violations.append("core/loader.py HOOK_INTERFACES does not list exactly the "
                          "methods the Protocols in core/hooks.py declare")
    for path in _iter_python(root, CORE):
        rel = path.relative_to(root)
        tree = _parse(path)

        def hook_of(expr, aliases):
            if isinstance(expr, ast.Name) and expr.id in aliases:
                return aliases[expr.id]
            if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name) and \
                    expr.value.id == "self" and f"self.{expr.attr}" in aliases:
                return aliases[f"self.{expr.attr}"]
            return _hook_field(expr, fields)

        def bind(target, value, aliases):
            if isinstance(target, (ast.Tuple, ast.List)) and \
                    isinstance(value, (ast.Tuple, ast.List)):
                for t, v in zip(target.elts, value.elts):
                    bind(t, v, aliases)
                return
            field = hook_of(value, aliases)
            if not field:
                return
            if isinstance(target, ast.Name):
                aliases[target.id] = field
            elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) \
                    and target.value.id == "self":
                aliases[f"self.{target.attr}"] = field

        def collect(scope, aliases):
            # Twice, so an alias of an alias bound later in the text is seen.
            for _ in range(2):
                for n in ast.walk(scope):
                    if isinstance(n, ast.Assign):
                        for t in n.targets:
                            bind(t, n.value, aliases)
                    elif isinstance(n, (ast.AnnAssign, ast.NamedExpr)) and n.value:
                        bind(n.target, n.value, aliases)
                    elif isinstance(n, (ast.For, ast.comprehension)):
                        it = n.iter
                        for elt in (it.elts if isinstance(it, (ast.Tuple, ast.List)) else [it]):
                            bind(n.target, elt, aliases)
                    elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                        call = n.context_expr
                        inner = call.args[0] if isinstance(call, ast.Call) and call.args \
                            else call
                        bind(n.optional_vars, inner, aliases)
                    elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                        args = n.args
                        positional = args.posonlyargs + args.args
                        for arg, default in zip(positional[len(positional) - len(args.defaults):],
                                                args.defaults):
                            bind(ast.Name(id=arg.arg), default, aliases)
                        for arg, default in zip(args.kwonlyargs, args.kw_defaults):
                            if default is not None:
                                bind(ast.Name(id=arg.arg), default, aliases)
            return aliases

        # A name is an alias in the function that binds it (nested functions
        # included); `self.<x>` in every method of the class that binds it.
        functions = [n for n in ast.walk(tree)
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))]
        classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        scoped = []
        for c in classes:
            attrs = {k: v for k, v in collect(c, {}).items() if k.startswith("self.")}
            if attrs:
                scoped.append((c, attrs))
        for fn in functions:
            names = {k: v for k, v in collect(fn, {}).items() if not k.startswith("self.")}
            if names:
                scoped.append((fn, names))
        module_names = {}
        for n in tree.body:
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                collect(n, module_names)
        scoped.append((tree, {k: v for k, v in module_names.items() if not k.startswith("self.")}))
        for scope, aliases in scoped:
            for n in ast.walk(scope):
                if isinstance(n, ast.Attribute):
                    field = hook_of(n.value, aliases)
                    if field and n.attr not in methods[field]:
                        violations.append(f"{rel}:{n.lineno}: core calls {field}.{n.attr}, "
                                          f"which {field} does not declare")
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and \
                        n.func.id in ("getattr", "setattr", "hasattr", "vars", "delattr") \
                        and n.args:
                    first = n.args[0]
                    field = hook_of(first, aliases)
                    bundle = (isinstance(first, ast.Name) and first.id in _BUNDLE_NAMES) or \
                        (isinstance(first, ast.Attribute) and first.attr in _BUNDLE_NAMES)
                    if field or bundle:
                        what = field or "the hook bundle"
                        violations.append(f"{rel}:{n.lineno}: {n.func.id} on {what}; "
                                          "call its declared methods")
        violations += _hook_shapes(tree, rel, methods, scoped)
    return sorted(set(violations))


def _hook_shapes(tree, rel, methods, scoped) -> List[str]:
    """Known shapes only (review of RES-OP-09): the bundle `_hooks` appears
    only as `._hooks.<field>` (or as an assignment target); `._hooks.<field>`
    only as `._hooks.<field>.<declared method>` or as the whole right-hand
    side of `name = ...` / `self.x = ...`; an alias only as
    `alias.<declared method>` or the whole right-hand side of another such
    assignment. Anything else -- a conditional, a container, a call taking
    it, a subscript -- is a route the alias tracking cannot follow."""
    parents = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parents[c] = p
    out = []

    def plain_assignment_value(node) -> bool:
        p = parents.get(node)
        return isinstance(p, ast.Assign) and p.value is node and len(p.targets) == 1 and \
            (isinstance(p.targets[0], ast.Name) or
             (isinstance(p.targets[0], ast.Attribute) and
              isinstance(p.targets[0].value, ast.Name) and p.targets[0].value.id == "self"))

    def declared_call(node, field) -> bool:
        p = parents.get(node)
        return isinstance(p, ast.Attribute) and p.value is node and p.attr in methods[field]

    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute) and n.attr in _BUNDLE_NAMES and \
                isinstance(n.ctx, ast.Load):
            p = parents.get(n)
            if not (isinstance(p, ast.Attribute) and p.value is n and p.attr in methods):
                out.append(f"{rel}:{n.lineno}: the hook bundle used other than as "
                           "._hooks.<field>")
        if isinstance(n, ast.Attribute) and n.attr in methods and \
                isinstance(n.value, ast.Attribute) and n.value.attr in _BUNDLE_NAMES:
            if not (declared_call(n, n.attr) or plain_assignment_value(n)):
                out.append(f"{rel}:{n.lineno}: {n.attr} used other than to call a declared "
                           "method or to be named by a plain assignment")
    for scope, aliases in scoped:
        for n in ast.walk(scope):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in aliases:
                field = aliases[n.id]
                if not (declared_call(n, field) or plain_assignment_value(n)):
                    out.append(f"{rel}:{n.lineno}: alias {n.id!r} of {field} used other "
                               "than to call a declared method")
    return out


# VP1-BND-005 as ruled (RES-OP-09, owner ruling 2026-10-17: named symbols
# only). A profile may take, from core, the hook interface types (every public
# name core/hooks.py defines), the reason codes and the two error classes of
# core/errors.py, and the model classes the in-tree tables read -- each by
# `from core.<module> import <Name>`. It may not bind a core module object
# (`from core import model`, `import core.x`), which would let anyone who
# imports the profile module reach the rest of that module through it; nor
# reach core dynamically; nor name a core module in a string; and its
# profile.yaml hook specifications must name its own package or the common
# one (review of RES-OP-09).
PROFILE_MODEL_NAMES = frozenset({"Profile", "CallType", "FunctionalIdentity",
                                 "BearerDecisionSpec"})
PROFILE_ERROR_CLASSES = frozenset({"HookContractViolation", "PlatformError"})


def profile_permitted(root: Path) -> Dict[str, frozenset]:
    hooks = _parse(root / CORE / "hooks.py")
    public = set()
    for n in hooks.body:
        if isinstance(n, (ast.ClassDef, ast.FunctionDef)):
            public.add(n.name)
        elif isinstance(n, (ast.Assign, ast.AnnAssign)):
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                if isinstance(t, ast.Name):
                    public.add(t.id)
    errors = _parse(root / CORE / "errors.py")
    codes = {t.id for n in errors.body if isinstance(n, ast.Assign)
             and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
             for t in n.targets if isinstance(t, ast.Name) and t.id.isupper()}
    return {"core.hooks": frozenset(x for x in public if not x.startswith("_")),
            "core.errors": frozenset(codes | PROFILE_ERROR_CLASSES),
            "core.model": PROFILE_MODEL_NAMES}


def _names_a_core_module(text: str, root: Path) -> bool:
    """`core`, or `core.<m>`/`core/<m>`/`core:<m>...` where <m> is a module
    of core. Attribute keys the core defines (`core.active_sessions`) are
    not modules, and pass."""
    m = re.fullmatch(r"core(?:[./:]([A-Za-z_][A-Za-z0-9_]*)(?:[./:].*)?)?", text)
    if not m:
        return False
    return m.group(1) is None or (root / CORE / f"{m.group(1)}.py").is_file() or \
        (root / CORE / m.group(1)).is_dir()


def check_profile_callbacks(root: Path) -> List[str]:
    """VP1-BND-005 — profiles reach the core only for the interface types."""
    permitted = profile_permitted(root)
    violations: List[str] = []
    for path in sorted((root / PROFILES).rglob("*")):
        rel = path.relative_to(root)
        if "__pycache__" in rel.parts or not path.is_file():
            continue
        if path.suffix in (".so", ".pyd", ".pyc"):
            violations.append(f"{rel}: compiled module in a profile; profiles are "
                              "source, which this gate reads")
    for path in _iter_python(root, PROFILES):
        rel = path.relative_to(root)
        try:
            tree = _parse(path)
        except (SyntaxError, UnicodeDecodeError) as exc:
            violations.append(f"{rel}: does not parse ({type(exc).__name__})")
            continue
        stdlib = set(sys.stdlib_module_names)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)) and not getattr(node, "level", 0):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) \
                    else [node.module or ""]
                for m in mods:
                    top = m.split(".")[0]
                    if top in _DYNAMIC_MODULES or any(m == x or m.startswith(x + ".")
                                                      for x in _NAME_RESOLVERS):
                        violations.append(f"{rel}:{node.lineno}: profile imports {m!r}, "
                                          "which reaches modules or runs code by name")
                    elif top not in stdlib and top not in (CORE, PROFILES):
                        # Another first-party package re-exports core
                        # (service.config holds core.release.Release).
                        violations.append(f"{rel}:{node.lineno}: profile imports {m!r}; a "
                                          "profile imports the standard library, profiles "
                                          "and named core symbols only")
            dunder = node.attr if isinstance(node, ast.Attribute) else \
                node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                else None
            if dunder and re.fullmatch(r"__\w+__", dunder) and \
                    dunder not in ("__init__", "__main__"):
                violations.append(f"{rel}:{node.lineno}: profile uses {dunder}; "
                                  "interpreter internals reach past the named imports")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
                    node.func.id == "vars":
                violations.append(f"{rel}:{node.lineno}: profile uses vars(); name what it uses")
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name == "core" or a.name.startswith("core."):
                        violations.append(f"{rel}:{node.lineno}: profile imports core module "
                                          f"{a.name!r}; import names, not modules")
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module and \
                    (node.module == "core" or node.module.startswith("core.")):
                if node.module == "core" or node.module not in permitted:
                    violations.append(f"{rel}:{node.lineno}: profile imports core internals "
                                      f"{node.module!r} ({', '.join(a.name for a in node.names)})")
                    continue
                for a in node.names:
                    if a.name not in permitted[node.module]:
                        violations.append(f"{rel}:{node.lineno}: profile imports "
                                          f"{node.module}.{a.name}, not an interface name")
        violations += [v.replace("only the loader's configuration-driven import is permitted",
                                 "a profile reaches core by named imports only")
                       for v in _dynamic_references(tree, rel.as_posix(), set())]
        for lineno, v in _strings(tree):
            if _names_a_core_module(v, root):
                violations.append(f"{rel}:{lineno}: profile names a core module: {v[:60]!r}")
    import yaml
    for spec_file in sorted((root / PROFILES).glob("*/profile.yaml")):
        own = spec_file.parent.name
        try:
            doc = yaml.safe_load(spec_file.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue                     # the loader refuses it
        meta = doc.get("profile") if isinstance(doc, dict) else None
        hooks = meta.get("hooks") if isinstance(meta, dict) else None
        for field, spec in (hooks.items() if isinstance(hooks, dict) else ()):
            module = str(spec).partition(":")[0]
            if not module.startswith((f"{PROFILES}.{own}.", f"{PROFILES}.common.")):
                violations.append(f"{spec_file.relative_to(root)}: hook {field} names "
                                  f"{spec!r}, outside profiles.{own} and profiles.common")
    return sorted(set(violations))


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


# --------------------------------------------------------------------------
# Shared by VP1-BND-007, 008, 016, 023: the packages a deployment runs
# --------------------------------------------------------------------------

RUNTIME = (CORE, "service")


def _runtime_trees(root: Path) -> Tuple[List[Tuple[str, ast.AST]], List[str]]:
    """(path, tree) for every Python file the running process loads, and a
    violation for each one that cannot be read: what the gate cannot parse
    it cannot clear."""
    trees, unreadable = [], []
    for package in RUNTIME:
        for path in _iter_python(root, package):
            if any(p in CACHE_DIRS for p in path.parts):
                continue
            rel = path.relative_to(root).as_posix()
            try:
                trees.append((rel, _parse(path)))
            except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
                unreadable.append(f"{rel}: cannot be parsed, so this gate cannot clear it")
    return trees, unreadable


def _parent_map(tree) -> Dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _empty(node) -> bool:
    """No value: absent, None or the empty string."""
    return node is None or (isinstance(node, ast.Constant) and node.value in ("", None))


def _bound_to(tree, value: str) -> set:
    """Names and attributes assigned the string `value` anywhere in `tree`."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and \
                isinstance(node.value, ast.Constant) and node.value.value == value:
            for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                if isinstance(t, ast.Name):
                    names.add(t.id)
                elif isinstance(t, ast.Attribute):
                    names.add(t.attr)
    return names


def _is_key(node, key: str, names: set) -> bool:
    return (isinstance(node, ast.Constant) and node.value == key) or \
        (isinstance(node, ast.Name) and node.id in names) or \
        (isinstance(node, ast.Attribute) and node.attr in names)


_STRING_METHODS = frozenset({"strip", "lstrip", "rstrip", "lower", "upper", "casefold"})


def _outermost(node, parents):
    """`node` with the string methods applied to it: `env.get(K).strip()`."""
    while True:
        p = parents.get(node)
        if isinstance(p, ast.Attribute) and p.attr in _STRING_METHODS and \
                isinstance(parents.get(p), ast.Call) and parents[p].func is p:
            node = parents[p]
        else:
            return node


def _fallback(expr, parents) -> bool:
    """Whether `expr` sits in an `or` or a conditional with a value to fall
    back on."""
    p = parents.get(expr)
    if isinstance(p, ast.BoolOp) and isinstance(p.op, ast.Or):
        return any(not _empty(v) for v in p.values[p.values.index(expr) + 1:])
    if isinstance(p, ast.IfExp):
        return any(not _empty(b) for b in (p.body, p.orelse) if b is not expr)
    return False


def _is_fallback_value(node, parents) -> bool:
    """Whether `node` is what an `or` or a conditional falls back on."""
    p = parents.get(node)
    if isinstance(p, ast.BoolOp) and isinstance(p.op, ast.Or):
        return p.values.index(node) > 0
    return isinstance(p, ast.IfExp) and node is not p.test


def _enclosing_function(node, parents):
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return node
    return None


def setting_fallbacks(tree, key: str) -> List[Tuple[int, str]]:
    """Every place `tree` gives the environment setting `key` a value of its
    own: a read with a default (`env.get(K, "x")`, `os.getenv(K, "x")`), a
    read in an `or` or a conditional with a fallback, a name holding the read
    that is later defaulted the same way or reassigned a literal, and a write
    (`setdefault`, `putenv`, `environ[K] = ...`, `update(K=...)`, a mapping
    literal with K as a key). Refers to the key as a literal or through a
    name bound to it. Not followed: the value passed to another function."""
    names = _bound_to(tree, key)
    parents = _parent_map(tree)
    out: List[Tuple[int, str]] = []
    holders: Dict[ast.AST, set] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            fname = func.attr if isinstance(func, ast.Attribute) else \
                func.id if isinstance(func, ast.Name) else ""
            for kw in node.keywords:
                if kw.arg == key:
                    out.append((node.lineno, f"{key} is given a value"))
            if not node.args or not _is_key(node.args[0], key, names):
                continue
            if fname in ("setdefault", "putenv"):
                out.append((node.lineno, f"{key} is given a value ({fname})"))
                continue
            if fname not in ("get", "getenv", "pop"):
                continue
            default = node.args[1] if len(node.args) > 1 else next(
                (k.value for k in node.keywords if k.arg in ("default", "failobj")), None)
            if not _empty(default):
                out.append((node.lineno, f"{key} is read with a fallback value"))
            expr = _outermost(node, parents)
            if _fallback(expr, parents):
                out.append((node.lineno, f"{key} is read with a fallback value"))
            if isinstance(parents.get(expr), ast.BoolOp):
                expr = _outermost(parents[expr], parents)
            p = parents.get(expr)
            if isinstance(p, ast.Assign):
                held = {t.id for t in p.targets if isinstance(t, ast.Name)}
                if held:
                    holders.setdefault(_enclosing_function(p, parents), set()).update(held)
        elif isinstance(node, ast.Dict):
            for k in node.keys:
                if k is not None and _is_key(k, key, names):
                    out.append((node.lineno, f"{key} is given a value"))
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                if isinstance(t, ast.Subscript) and _is_key(t.slice, key, names):
                    out.append((node.lineno, f"{key} is given a value"))
    # A name holding the read, defaulted later in the same function.
    for scope, held in holders.items():
        body = ast.walk(scope) if scope is not None else ast.walk(tree)
        for node in body:
            if isinstance(node, ast.Name) and node.id in held and \
                    isinstance(node.ctx, ast.Load):
                expr = _outermost(node, parents)
                if _fallback(expr, parents):
                    out.append((node.lineno, f"{key} is given a fallback value "
                                             f"through {node.id!r}"))
            elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(t, ast.Name) and t.id in held for t in targets) and \
                        isinstance(node.value, ast.Constant) and not _empty(node.value):
                    out.append((node.lineno, f"{key} is given a fallback value "
                                             f"through {targets[0].id!r}"))
    return sorted(set(out))


def _reads(tree, key: str) -> bool:
    names = _bound_to(tree, key)
    return any(isinstance(n, ast.Call) and n.args and _is_key(n.args[0], key, names)
               and isinstance(n.func, (ast.Attribute, ast.Name))
               and (n.func.attr if isinstance(n.func, ast.Attribute) else n.func.id)
               in ("get", "getenv")
               or isinstance(n, ast.Subscript) and _is_key(n.slice, key, names)
               and isinstance(n.ctx, ast.Load)
               for n in ast.walk(tree))


# --------------------------------------------------------------------------
# VP1-BND-007 — no default profile
# --------------------------------------------------------------------------

# A parameter or field that carries the profile or its hooks.
PROFILE_CARRIER = re.compile(
    r"(?i)^_?(profiles?|hooks?)(_(names?|ids?|dirs?|specs?|packages?))?$")
# Deployment files a default could be baked into: image builds, compose and
# Kubernetes manifests, env files, units, scripts, and any YAML, JSON or TOML
# outside documentation and tests (CI, .github/, states the profile and
# release of each test run: configuration of a test, not of a deployment).
DEPLOYMENT_FILES = re.compile(
    r"(?i)(^|/)(([^/]*\.)?(containerfile|dockerfile)(\.[^/]*)?|[^/]*\.env(\.[^/]*)?|"
    r"makefile|[^/]*\.(service|conf|sh|ini|toml|cfg|ya?ml|json))$")
_NOT_DEPLOYMENT = frozenset({"docs", TESTS, ".git", ".github", "kb"})


def _setting_patterns(key: str):
    k = re.escape(key)
    inline = re.compile(
        r"(^|[\s\"'{,;]|=)[\"']?" + k + r"[\"']?\s*[=:]\s*[\"']?[^\s\"'#]"
        r"|\b(ENV|ARG)\s+" + k + r"\s+\S"
        r"|[\"']?name[\"']?\s*:\s*[\"']?" + k + r"[\"']?\s*,\s*[\"']?value")
    named = re.compile(r"^\s*-?\s*[\"']?name[\"']?\s*:\s*[\"']?" + k + r"[\"']?\s*,?\s*$")
    value = re.compile(r"^\s*-?\s*[\"']?value(From)?[\"']?\s*:\s*\S")
    return inline, named, value


def deployment_settings(root: Path, key: str, why: str) -> List[str]:
    """Every deployment file outside docs/ and tests/ that sets `key`: as
    KEY=v, "KEY": "v", KEY: v, ENV KEY v, Environment=KEY=v, or a manifest's
    `name: KEY` followed by `value:`. Comment lines are skipped."""
    inline, named, value = _setting_patterns(key)
    out: List[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if not path.is_file() or rel.split("/")[0] in _NOT_DEPLOYMENT or \
                any(p in CACHE_DIRS for p in path.parts) or not DEPLOYMENT_FILES.search(rel):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            out.append(f"{rel}: cannot be read, so this gate cannot clear it")
            continue
        code = [(n, l) for n, l in enumerate(lines, 1)
                if l.strip() and not l.lstrip().startswith(("#", "//"))]
        for i, (n, line) in enumerate(code):
            # A manifest's name and value, on adjacent lines either way round.
            if inline.search(line) or named.search(line) and any(
                    0 <= j < len(code) and value.search(code[j][1]) for j in (i - 1, i + 1)):
                out.append(f"{rel}:{n}: sets {key}; {why}")
    return out


def _no_value(node) -> bool:
    """None, "", an empty literal collection, or `field()` with no default."""
    if _empty(node) or (isinstance(node, (ast.Tuple, ast.List, ast.Set, ast.Dict))
                        and not (node.elts if hasattr(node, "elts") else node.keys)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)) and \
            (node.func.id if isinstance(node.func, ast.Name) else node.func.attr) == "field":
        for kw in node.keywords:
            if kw.arg == "default" and not _no_value(kw.value):
                return False
            if kw.arg == "default_factory" and not (
                    isinstance(kw.value, ast.Name) and kw.value.id in ("tuple", "list", "dict")):
                return False
        return True
    return False


def _defaults(fn) -> List[Tuple[ast.arg, ast.AST]]:
    args = fn.args
    positional = args.posonlyargs + args.args
    pairs = list(zip(positional[len(positional) - len(args.defaults):], args.defaults))
    pairs += [(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None]
    return pairs


def check_no_default_profile(root: Path) -> List[str]:
    """VP1-BND-007 / PLT-GEN-004 / PLT-PRF-012 — no path yields a profile
    without explicit configuration.

    Over every module the process runs (core/ and service/):
      * `MCX_PROFILE` is read in service/config.py, and nowhere is it read
        with a fallback, defaulted later, or given a value
        (`setting_fallbacks`);
      * no parameter or dataclass field carrying a profile or its hooks
        (`profile`, `profile_names`, `hooks`, ...) has a default but None or
        an empty value, annotated or not, positional or keyword-only;
      * no default, field value or fallback anywhere is the name of an
        in-tree profile.
    And no deployment file outside docs/ and tests/ sets `MCX_PROFILE`
    (`deployment_settings`).

    Not followed: a value built at run time (string concatenation) or passed
    through another function, a profile name inside a collection default of
    a parameter not named for a profile. The tests evidencing this case show
    the behaviour at run time, including an image that carries exactly one
    profile (nothing infers it) and the hook refusals (PLT-PRF-012).
    """
    trees, violations = _runtime_trees(root)
    profiles = set(_profile_names(root))
    config_read = False
    for rel, tree in trees:
        for line, what in setting_fallbacks(tree, "MCX_PROFILE"):
            violations.append(f"{rel}:{line}: {what}; the profile is stated or "
                              "the process does not start")
        if rel == "service/config.py":
            config_read = _reads(tree, "MCX_PROFILE")
        parents = _parent_map(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                for arg, default in _defaults(node):
                    if PROFILE_CARRIER.match(arg.arg) and not _no_value(default):
                        violations.append(
                            f"{rel}:{default.lineno}: parameter {arg.arg!r} has a "
                            "default; a profile is never assumed")
            elif isinstance(node, ast.ClassDef):
                for stmt in node.body:
                    target = stmt.target if isinstance(stmt, ast.AnnAssign) else \
                        stmt.targets[0] if isinstance(stmt, ast.Assign) and \
                        len(stmt.targets) == 1 else None
                    if isinstance(target, ast.Name) and PROFILE_CARRIER.match(target.id) \
                            and stmt.value is not None and not _no_value(stmt.value):
                        violations.append(
                            f"{rel}:{stmt.lineno}: field {target.id!r} has a "
                            "default; a profile is never assumed")
            elif isinstance(node, ast.Constant) and node.value in profiles:
                p = parents.get(node)
                defaulted = (
                    isinstance(p, ast.arguments)
                    or (isinstance(p, (ast.AnnAssign, ast.Assign))
                        and isinstance(parents.get(p), ast.ClassDef))
                    or (isinstance(p, ast.keyword) and p.arg in ("default", "failobj"))
                    or (isinstance(p, ast.Call) and len(p.args) > 1 and p.args[1] is node
                        and isinstance(p.func, ast.Attribute)
                        and p.func.attr in ("get", "getenv", "pop", "setdefault"))
                    or _is_fallback_value(node, parents))
                if defaulted:
                    violations.append(
                        f"{rel}:{node.lineno}: defaults to the profile {node.value!r}")
    if not config_read:
        violations.append("service/config.py: MCX_PROFILE is not read; the profile "
                          "must be stated by the deployment")
    violations += deployment_settings(
        root, "MCX_PROFILE", "a built image or unit must not choose the profile")
    return violations


# --------------------------------------------------------------------------
# VP1-BND-008 — no hot reload
# --------------------------------------------------------------------------

# Loader entry points that read a profile package. Only build_runtime calls
# one, once, at start; nothing else in the process refers to them.
LOADER_ENTRY_POINTS = frozenset({"startup", "startup_all", "load", "read_package",
                                 "resolve_hooks", "_load_named", "_import_symbol"})
# What else the process may use of the loader: names that read no profile.
LOADER_PUBLIC = frozenset({"LoadedProfile", "LoadedHooks", "declared_view", "content_hash",
                           "canonicalise", "is_production", "is_test_mode"})
# Attributes that hold the loaded profile: set at construction only (an
# `__init__`), or in the one start-time report of it (`HOLDER_SETTERS`).
PROFILE_HOLDERS = frozenset({"loaded", "_loaded", "profile", "_profile", "hooks", "_hooks"})
HOLDER_SETTERS = frozenset({("service/runtime.py", "set_profile")})
_EXEC = re.compile(r"^(exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?|fork|forkpty)$")
STOP_SIGNALS = frozenset({"SIGTERM", "SIGINT"})
SIGNAL_REGISTRARS = frozenset({"signal", "add_signal_handler", "set_wakeup_fd",
                               "setitimer", "alarm", "siginterrupt", "pthread_kill",
                               "pthread_sigmask", "sigwait", "sigwaitinfo",
                               "sigtimedwait", "raise_signal"})
WATCHER_MODULES = frozenset({"watchdog", "watchfiles", "watchgod", "inotify",
                             "inotify_simple", "pyinotify", "aionotify", "asyncinotify",
                             "butter", "fsevents", "importlib", "imp", "pyfsevents"})
FILE_TIME_ATTRIBUTES = frozenset({"st_mtime", "st_mtime_ns", "st_ctime", "st_ctime_ns",
                                  "st_atime", "st_atime_ns", "getmtime", "getctime",
                                  "getatime", "kqueue", "kevent"})
_SIGNAL_NAME = re.compile(r"^SIG[A-Z0-9]+$")


def _module_aliases(tree, rel: str, dotted: str) -> set:
    """Names `tree` (the module at `rel`) binds to the module `dotted`:
    `import a.b as x`, `from a import b [as x]`, `from . import b` within a,
    and `import b` for a top-level module."""
    package, _, leaf = dotted.rpartition(".")
    here = rel.rsplit("/", 1)[0].replace("/", ".")
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == dotted and (a.asname or "." not in dotted):
                    names.add(a.asname or a.name)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                up = here.split(".")[:len(here.split(".")) - (node.level - 1)]
                base = ".".join(up + ([node.module] if node.module else []))
            if base == package:
                names.update(a.asname or a.name for a in node.names if a.name == leaf)
    return names


def _replaces_profile(call, replace_names: set) -> bool:
    """`dataclasses.replace(<the profile or what holds it>, ...)`, or a
    replace that sets a holder (`replace(rt, loaded=...)`), under any name
    dataclasses' replace is bound to."""
    f = call.func
    if not (isinstance(f, ast.Attribute) and f.attr == "replace" and
            isinstance(f.value, ast.Name) and f.value.id == "dataclasses" or
            isinstance(f, ast.Name) and f.id in replace_names) or not call.args:
        return False
    return any(k.arg in PROFILE_HOLDERS for k in call.keywords) or any(
        (isinstance(n, ast.Name) and n.id in PROFILE_HOLDERS) or
        (isinstance(n, ast.Attribute) and n.attr in PROFILE_HOLDERS)
        for n in ast.walk(call.args[0]))


def _sets_holder_by_name(node) -> bool:
    """`setattr(x, "loaded", v)`, `x.__dict__["loaded"] = v`,
    `vars(x)["profile"] = v`."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
            node.func.id in ("setattr", "delattr") and len(node.args) >= 2:
        return isinstance(node.args[1], ast.Constant) and node.args[1].value in PROFILE_HOLDERS
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)) and \
            isinstance(node.slice, ast.Constant) and node.slice.value in PROFILE_HOLDERS:
        v = node.value
        return isinstance(v, ast.Attribute) and v.attr == "__dict__" or \
            isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "vars"
    return False


def _in_loop_or_nested(node, parents, function) -> bool:
    """Whether `node` runs other than once per call of `function`: inside a
    loop, a nested function, a lambda or a comprehension."""
    p = parents.get(node)
    while p is not None and p is not function:
        if isinstance(p, (ast.For, ast.AsyncFor, ast.While, ast.FunctionDef,
                          ast.AsyncFunctionDef, ast.Lambda, ast.ListComp, ast.SetComp,
                          ast.DictComp, ast.GeneratorExp)):
            return True
        p = parents.get(p)
    return p is None


def _the_stop_handler(call, parents) -> bool:
    """`signal.signal(sig, lambda *_: <event>.set())` inside
    `for sig in (signal.SIGTERM, signal.SIGINT):` -- the process's stop."""
    if len(call.args) != 2 or call.keywords:
        return False
    sig, handler = call.args
    loop = parents.get(parents.get(call))
    if not (isinstance(sig, ast.Name) and isinstance(loop, ast.For)
            and isinstance(loop.target, ast.Name) and loop.target.id == sig.id
            and isinstance(loop.iter, ast.Tuple) and loop.body == [parents[call]]):
        return False
    named = {e.attr for e in loop.iter.elts
             if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name)
             and e.value.id == "signal"}
    if named != STOP_SIGNALS or len(loop.iter.elts) != 2:
        return False
    body = handler.body if isinstance(handler, ast.Lambda) else None
    return isinstance(body, ast.Call) and isinstance(body.func, ast.Attribute) and \
        body.func.attr == "set" and not body.args and not body.keywords and \
        isinstance(body.func.value, ast.Name)


def check_no_hot_reload(root: Path) -> List[str]:
    """VP1-BND-008 / PLT-PRF-010 — the profile is read once, at start.

    Over every module the process runs (core/ and service/):
      * of the loader, the process uses only what reads no profile
        (`LOADER_PUBLIC`) and one call of `loader.startup` in
        service/runtime.py's build_runtime, outside any loop, nested
        function or lambda; module aliases and relative imports are
        followed. build_runtime is imported by service/__main__.py alone,
        under its own name, and main calls it once, the same way; the
        health report of the profile (`set_profile`) is made once, by
        build_runtime; only the loader calls validation.build;
      * the profile is not modified in place: no `object.__setattr__`
        outside core/hooks.py (which freezes value objects), no
        `dataclasses.replace` (under any name) on the profile or what holds
        it or setting a holder, and the attributes that hold it
        (`PROFILE_HOLDERS`) are set only on `self` at construction or in
        that report, never by name (setattr, `__dict__`, vars); no
        os.exec*/spawn*/fork;
      * the one signal handler is the stop: `signal.signal` in
        service/__main__.py for exactly SIGTERM and SIGINT, setting an event.
        Every other signal registration (`add_signal_handler`, `setitimer`,
        `alarm`, ...), every other signal name, and `from signal import`
        are refused;
      * no file watcher or reloader is imported (`WATCHER_MODULES`;
        importlib is the loader's alone), and no file's modification time
        is read (`st_mtime`, `getmtime`, kqueue, ...).

    Not followed: getattr and sys.modules forms, a stat result indexed by
    position, a thread hashing the file, a watcher through ctypes, private
    validation helpers, a signal sent to the process (os.kill), a second
    process started with subprocess, a holder under another name
    (`manager.current = p`), and a Runtime rebuilt from another's
    `__dict__`.
    """
    trees, violations = _runtime_trees(root)
    startup_calls = build_calls = report_calls = 0
    for rel, tree in trees:
        parents = _parent_map(tree)
        functions = {n.name: n for n in ast.walk(tree)
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        loader_names = _module_aliases(tree, rel, "core.loader")
        validation_names = _module_aliases(tree, rel, "core.validation")
        signal_names = _module_aliases(tree, rel, "signal")
        replace_names = {"replace"} | {
            a.asname or a.name for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom) and n.module == "dataclasses"
            for a in n.names if a.name == "replace"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and rel != "core/loader.py":
                base = node.module or ""
                if node.level:
                    here = rel.rsplit("/", 1)[0].split("/")
                    base = ".".join(here[:len(here) - (node.level - 1)] +
                                    ([node.module] if node.module else []))
                for a in node.names:
                    if base == "service.runtime" and a.name == "build_runtime" and (
                            rel != "service/__main__.py" or a.asname):
                        violations.append(f"{rel}:{node.lineno}: imports build_runtime; "
                                          "main imports it, under its name, and calls it "
                                          "once, at start")
                    if base == "core.loader" and a.name not in LOADER_PUBLIC:
                        violations.append(f"{rel}:{node.lineno}: imports the loader's "
                                          f"{a.name!r}; only build_runtime starts it")
                    if base == "core.validation" and a.name == "build":
                        violations.append(f"{rel}:{node.lineno}: imports validation.build; "
                                          "only the loader builds a profile, at start")
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) \
                    else [node.module or ""]
                for m in mods:
                    top = m.split(".")[0]
                    if top in WATCHER_MODULES and rel != "core/loader.py":
                        violations.append(f"{rel}:{node.lineno}: imports {m!r}: a "
                                          "watcher or reloader")
                    if isinstance(node, ast.ImportFrom) and top == "signal":
                        violations.append(f"{rel}:{node.lineno}: imports from signal; "
                                          "use signal.<name> so the gate can see it")
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                if node.attr in FILE_TIME_ATTRIBUTES:
                    violations.append(f"{rel}:{node.lineno}: reads {node.attr!r}: "
                                      "polling a file for change")
                if node.attr == "add_signal_handler" or node.attr in SIGNAL_REGISTRARS \
                        and isinstance(node.value, ast.Name) and node.value.id in signal_names:
                    call = parents.get(node)
                    ok = (rel == "service/__main__.py" and node.attr == "signal"
                          and isinstance(call, ast.Call) and call.func is node
                          and _the_stop_handler(call, parents))
                    if not ok:
                        violations.append(f"{rel}:{node.lineno}: registers a signal "
                                          f"handler ({node.attr}); the only one is the "
                                          "SIGTERM/SIGINT stop")
                if node.attr == "build" and rel != "core/loader.py" and (
                        isinstance(node.value, ast.Name) and node.value.id in validation_names
                        or isinstance(node.value, ast.Attribute)
                        and node.value.attr == "validation"):
                    violations.append(f"{rel}:{node.lineno}: refers to validation.build; "
                                      "only the loader builds a profile, at start")
                if node.attr == "build_runtime":
                    violations.append(f"{rel}:{node.lineno}: refers to build_runtime; "
                                      "main calls it once, at start")
                if node.attr == "set_profile":
                    fn = functions.get("build_runtime")
                    call = parents.get(node)
                    if rel == "service/runtime.py" and fn is not None and \
                            isinstance(call, ast.Call) and call.func is node and \
                            not _in_loop_or_nested(call, parents, fn):
                        report_calls += 1
                    else:
                        violations.append(f"{rel}:{node.lineno}: refers to set_profile; "
                                          "build_runtime reports the profile once, at start")
                if node.attr == "__setattr__" and isinstance(node.value, ast.Name) and \
                        node.value.id == "object" and rel != "core/hooks.py":
                    violations.append(f"{rel}:{node.lineno}: object.__setattr__ changes a "
                                      "frozen value; the profile is not modified at run "
                                      "time")
                if _EXEC.match(node.attr) and _receiver(node) == "os":
                    violations.append(f"{rel}:{node.lineno}: os.{node.attr} restarts or "
                                      "forks the process; a new profile is a new "
                                      "deployment")
                if _SIGNAL_NAME.match(node.attr) and node.attr not in STOP_SIGNALS:
                    violations.append(f"{rel}:{node.lineno}: refers to {node.attr}; the "
                                      "process handles SIGTERM and SIGINT only")
                dotted = isinstance(node.value, ast.Name) and node.value.id in loader_names
                if node.attr not in LOADER_PUBLIC and rel != "core/loader.py" and (
                        dotted or (isinstance(node.value, ast.Attribute)
                                   and node.value.attr == "loader")):
                    fn = functions.get("build_runtime")
                    call = parents.get(node)
                    if rel == "service/runtime.py" and node.attr == "startup" and \
                            fn is not None and isinstance(call, ast.Call) and \
                            call.func is node and not _in_loop_or_nested(call, parents, fn):
                        startup_calls += 1
                    else:
                        violations.append(f"{rel}:{node.lineno}: refers to the loader's "
                                          f"{node.attr!r}; only build_runtime starts it, "
                                          "once")
            elif isinstance(node, ast.Name):
                if _SIGNAL_NAME.match(node.id) and node.id not in STOP_SIGNALS:
                    violations.append(f"{rel}:{node.lineno}: refers to {node.id}; the "
                                      "process handles SIGTERM and SIGINT only")
                if node.id == "build_runtime" and isinstance(node.ctx, ast.Load):
                    fn = functions.get("main")
                    call = parents.get(node)
                    if rel == "service/__main__.py" and fn is not None and \
                            isinstance(call, ast.Call) and call.func is node and \
                            not _in_loop_or_nested(call, parents, fn):
                        build_calls += 1
                    else:
                        violations.append(f"{rel}:{node.lineno}: refers to build_runtime; "
                                          "main calls it once, at start")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and \
                    _SIGNAL_NAME.match(node.value) and node.value not in STOP_SIGNALS:
                violations.append(f"{rel}:{node.lineno}: names {node.value}; the process "
                                  "handles SIGTERM and SIGINT only")
            elif isinstance(node, ast.Call) and _replaces_profile(node, replace_names):
                violations.append(f"{rel}:{node.lineno}: replace() on the loaded profile; "
                                  "the profile is not modified at run time")
            if _sets_holder_by_name(node):
                violations.append(f"{rel}:{node.lineno}: sets a profile holder by name; the "
                                  "profile is held as loaded")
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                fn = _enclosing_function(node, parents)
                named = fn is not None and not isinstance(fn, ast.Lambda)
                for t in targets:
                    for e in (t.elts if isinstance(t, (ast.Tuple, ast.List)) else [t]):
                        # Construction sets its own holders only: `self.loaded`.
                        own = isinstance(e, ast.Attribute) and \
                            isinstance(e.value, ast.Name) and e.value.id == "self"
                        allowed = named and own and (
                            fn.name == "__init__" or (rel, fn.name) in HOLDER_SETTERS)
                        if isinstance(e, ast.Attribute) and e.attr in PROFILE_HOLDERS \
                                and not allowed:
                            violations.append(
                                f"{rel}:{node.lineno}: sets {e.attr!r} after "
                                "construction; the profile is held as loaded")
    if report_calls != 1:
        violations.append(f"service/runtime.py: build_runtime reports the profile "
                          f"{report_calls} times; once, at start")
    if startup_calls != 1:
        violations.append(f"service/runtime.py: build_runtime calls loader.startup "
                          f"{startup_calls} times; once, at start")
    if build_calls != 1:
        violations.append(f"service/__main__.py: main calls build_runtime {build_calls} "
                          "times; once, at start")
    return sorted(violations, key=_by_line)


# --------------------------------------------------------------------------
# VP1-BND-009 / 015 — the core owns the state machines
# --------------------------------------------------------------------------


# VP1-BND-009 as amended (PLT-VP-R1 RES-OP-10 ruling 2): what each protocol
# state machine may read from the profile. The floor machine reads the TS
# 24.380 configuration parameters and timers of its floor policy, and nothing
# else; the SIP session and document modules read the profile attributes
# listed, each for a stated reason, and no module builds a transition from
# them. A new read fails this gate until it is justified here.
FLOOR_POLICY_PARAMETERS = frozenset({
    "timers_ms", "timer",                       # timers (PLT-PRF-031)
    "queueing_enabled", "override_allowed",     # TS 24.380 configuration
    "max_queue_depth", "initial_grant_to_initiator",
    "preemption_at_full_queue",                 # FC-OP-07, 6.3.4.4.7 item 2e
})
STATE_MACHINE_PROFILE_READS: Dict[str, frozenset] = {
    "core/floor.py": frozenset(),
    # The session state machine reads the profile only to check a hook's
    # answer against it or where TS 24.379 orders a check before any hook:
    "core/session.py": frozenset({
        "admission",    # declared reason codes (PLT-ICD-001 5.1 POST-3)
        "identity",     # declared domains (3.2 POST-3; the ad hoc group id)
        "call_type",    # declared model (5.2 POST-1), private vs group (6.3.5.5),
                        # the ad hoc list limit (17.4.2.2 step 6, ICD 5.2),
                        # group_over_limit (6.3.5.5, owner ruling 2026-10-16)
    }),
    # Given the call types, not the profile; reads each one's id and
    # mc_signature (its own docstring; not enforced here).
    "core/sip.py": frozenset(),
    "service/sip_core.py": frozenset({
        "media",        # codec preference (VP-OP-03)
        "call_types",   # no_answer_ms, a timer (SIP-OP-15); signatures (ICD 2.6)
        "identity",     # declared domains, for registration (PLT-IDM-008)
    }),
    "service/sip_txn.py": frozenset(),
    "service/session_timer.py": frozenset(),
    "service/groups.py": frozenset(),   # TS 24.481 documents: network profile data
    "service/http.py": frozenset(),     # serves those documents
    "service/media.py": frozenset(),    # drives the floor machine
}
_PROFILE_NAMES = ("profile", "_profile")


def _named(node, name: str) -> bool:
    return (isinstance(node, ast.Name) and node.id == name) or \
        (isinstance(node, ast.Attribute) and node.attr == name)


def _aliases(tree, is_source) -> set:
    """Names a module binds to something `is_source` recognises (`p =
    runtime.loaded.profile`), so reading through an alias is still seen.
    Function-local or not, by name: a static gate's approximation."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and is_source(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def check_state_machine_ownership(root: Path) -> List[str]:
    """VP1-BND-009 / PLT-PRF-030 / PLT-PRF-031, as amended by RES-OP-10.

    No transition, guard or state is parameterised by profile input, timers
    and TS 24.380 configuration parameters excepted. The floor transition
    table is a module-level constant; the floor machine reads only those
    parameters of its policy; each state-machine module reads only the
    profile attributes STATE_MACHINE_PROFILE_READS allows it.
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
    def policy_like(node) -> bool:
        held = node.id if isinstance(node, ast.Name) else \
            node.attr if isinstance(node, ast.Attribute) else ""
        # A floor policy, whatever the variable holding it is called (the
        # class itself, `Policy`, is the core's own).
        return held.lower().endswith("policy") and held != "Policy"

    policy_aliases = _aliases(tree, policy_like)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in (
                "call_types", "priority", "bearer", "identity", "admission"):
            violations.append(
                f"{path.relative_to(root)}:{node.lineno}: floor control reads "
                f"profile structure {node.attr!r}")
        if isinstance(node, ast.Attribute) and node.attr not in FLOOR_POLICY_PARAMETERS \
                and (policy_like(node.value) or
                     (isinstance(node.value, ast.Name) and node.value.id in policy_aliases)):
            violations.append(
                f"{path.relative_to(root)}:{node.lineno}: the floor machine reads "
                f"{node.attr!r} of its policy, which is not a timer or a TS "
                "24.380 configuration parameter")
        if isinstance(node, ast.Call) and _named(node.func, "getattr") and node.args \
                and (policy_like(node.args[0]) or
                     (isinstance(node.args[0], ast.Name) and node.args[0].id in policy_aliases)):
            violations.append(
                f"{path.relative_to(root)}:{node.lineno}: the floor machine reads its "
                "policy through getattr")
    # The policy carries those parameters and no others.
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Policy":
            fields = {n.target.id for n in node.body
                      if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)}
            if fields != FLOOR_POLICY_PARAMETERS - {"timer"}:
                violations.append(
                    f"{path.relative_to(root)}:{node.lineno}: the floor Policy's fields "
                    f"{sorted(fields)} are not the parameters this gate allows")
    for rel, allowed in STATE_MACHINE_PROFILE_READS.items():
        module = root / rel
        if not module.is_file():
            violations.append(f"{rel}: state-machine module not found")
            continue
        tree = _parse(module)

        def is_profile(node) -> bool:
            return any(_named(node, n) for n in _PROFILE_NAMES)

        aliases = _aliases(tree, is_profile)

        def profile_ref(node) -> bool:
            return is_profile(node) or (isinstance(node, ast.Name) and node.id in aliases)

        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and profile_ref(node.value) \
                    and node.attr not in allowed:
                violations.append(
                    f"{rel}:{node.lineno}: reads profile.{node.attr}, which "
                    "STATE_MACHINE_PROFILE_READS does not allow this module")
            if isinstance(node, ast.Call) and node.args and profile_ref(node.args[0]) \
                    and (_named(node.func, "getattr") or _named(node.func, "vars")):
                violations.append(
                    f"{rel}:{node.lineno}: reads the profile through "
                    f"{node.func.id if isinstance(node.func, ast.Name) else 'a call'}")
    return violations


def _target_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


# VP1-BND-015: what the floor state machine must not reach, directly or
# through anything it imports: SIP, media, the network, the event loop.
FLOOR_FORBIDDEN = ("core.sip", "core.rtcp", "core.codec", "core.mcinfo", "core.session",
                   "core.loader", "service", "socket", "ssl", "asyncio", "selectors",
                   "http", "urllib", "requests", "email", "select", "socketserver",
                   "xmlrpc", "ftplib", "smtplib", "telnetlib", "profiles", "_socket", "_ssl",
                   "multiprocessing", "subprocess", "httpx", "urllib3", "aiohttp",
                   "websocket", "websockets", "zmq", "grpc", "concurrent",
                   "logging.handlers", "logging.config")
# Everything else outside the tree the closure may import: pure language
# and data-structure modules. Anything not here is refused, so a module
# this list never thought of (imaplib, wsgiref) cannot slip in.
FLOOR_ALLOWED = ("__future__", "dataclasses", "enum", "typing", "abc", "collections",
                 "functools", "itertools", "heapq", "bisect", "math", "operator", "types",
                 "copy", "logging")


def _imports_of(tree, module: str, is_package: bool = False) -> List[Tuple[int, str]]:
    """(line, absolute module) for every import in `tree`, the module at
    dotted path `module` (a package's __init__ when `is_package`); relative
    imports resolved."""
    out = []
    package = module if is_package else module.rsplit(".", 1)[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [(node.lineno, a.name) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                parts = parts[:len(parts) - (node.level - 1)]
                base = ".".join(parts + ([node.module] if node.module else []))
            out.append((node.lineno, base))
            out += [(node.lineno, f"{base}.{a.name}") for a in node.names if a.name != "*"]
    return out


def check_floor_machine_isolated(root: Path) -> List[str]:
    """VP1-BND-015 / PLT-FC-004 — no dependency on SIP, media or the network.

    The transitive import closure of core/floor.py within the tree (each
    first-party module it imports, and what those import, relative imports
    resolved, `from pkg import mod` counted as importing pkg.mod) holds
    nothing in `FLOOR_FORBIDDEN` (core.sip, core.rtcp, core.codec, the
    service, profiles, sockets, TLS, the event loop, HTTP and mail), and
    nothing from outside the tree but the pure modules `FLOOR_ALLOWED`
    lists (dataclasses, enum, typing, collections and the like). A
    dynamic import in core is refused by VP1-BND-002. A test imports
    core.floor in a fresh interpreter and shows none of them loaded, and
    the ENV-UNIT tests instantiate the machine with an injected clock.
    """
    violations: List[str] = []
    start = root / CORE / "floor.py"
    if not start.is_file():
        return ["core/floor.py is missing"]
    todo, seen = [("core.floor", start, [])], set()
    while todo:
        module, path, chain = todo.pop()
        if module in seen:
            continue
        seen.add(module)
        try:
            tree = _parse(path)
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
            violations.append(f"{path.relative_to(root)}: cannot be parsed, so this gate "
                              "cannot clear it")
            continue
        for line, name in _imports_of(tree, module, path.name == "__init__.py"):
            via = " -> ".join(chain + [module])
            if any(name == f or name.startswith(f + ".") for f in FLOOR_FORBIDDEN):
                violations.append(f"{path.relative_to(root)}:{line}: floor control reaches "
                                  f"{name!r} ({via})")
                continue
            top = name.split(".")[0]
            first_party = (root / top).is_dir() or (root / f"{top}.py").is_file()
            if not first_party and not any(name == a or name.startswith(a + ".")
                                           for a in FLOOR_ALLOWED):
                violations.append(f"{path.relative_to(root)}:{line}: floor control reaches "
                                  f"{name!r} ({via}), which is not among the modules it may "
                                  "use (FLOOR_ALLOWED)")
                continue
            target = root.joinpath(*name.split("."))
            for candidate in (target.with_suffix(".py"), target / "__init__.py"):
                if candidate.is_file():
                    todo.append((name, candidate, chain + [module]))
                    break
    return sorted(set(violations), key=_by_line)


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


TABLE_INTERPRETER = ("profiles/common/tables.py", "TablePriorityPolicy")
# The interpreter as reviewed: the syntax of TablePriorityPolicy and the
# module functions it calls (`_matches`), docstrings left out. A change to
# either fails VP1-BND-011 until it is reviewed and this is updated
# (`interpreter_fingerprint`).
INTERPRETER_FINGERPRINT = "ddaecef91a4953543ec09b3310817a29b11da80d9bc8b4b89c17e1d0a1dee0b4"
# Literals the table interpreter may compare with or return: the match
# wildcard, no value, and compare's three answers (PLT-ICD-001 §4.2 POST-1).
STRUCTURAL_LITERALS = frozenset({"*", None, 0, 1, -1})


def _bound_class(root: Path, spec: str):
    """(path, class name, class node, module tree) the hook spec
    `pkg.module:Name` binds, followed through `from x import Y [as Name]`
    and `Name = Y` in that module and the modules it imports from within
    the tree; the module's last binding of the name is the one the loader
    gets. None when it cannot be followed (an opaque assignment included)."""
    if ":" not in spec:
        return None
    module, name = spec.split(":", 1)
    seen = set()
    while (module, name) not in seen:
        seen.add((module, name))
        path = root.joinpath(*module.split(".")).with_suffix(".py")
        if not path.is_file():
            return None
        try:
            tree = _parse(path)
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
            return None
        rel = path.relative_to(root).as_posix()
        # The module's last binding of the name is the one the loader gets.
        nxt = None
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == name:
                nxt = ("class", node)
                continue
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    if (a.asname or a.name) == name:
                        base = node.module or ""
                        if node.level:
                            parts = module.split(".")[:-node.level]
                            base = ".".join(parts + ([node.module] if node.module else []))
                        nxt = (base, a.name)
            elif isinstance(node, ast.Assign) and \
                    any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                nxt = (module, node.value.id) if isinstance(node.value, ast.Name) else \
                    ("opaque", None)
        if nxt is None or nxt[0] == "opaque":
            return None
        if nxt[0] == "class":
            return rel, name, nxt[1], tree
        module, name = nxt
    return None


def _without_docstrings(node):
    import copy
    node = copy.deepcopy(node)
    for n in ast.walk(node):
        body = getattr(n, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr) and \
                isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            n.body = body[1:] or [ast.Pass()]
    return node


def _interpreter_parts(tree):
    """The interpreter class and the module functions it calls, transitively."""
    functions = _module_functions(tree)
    cls = next((n for n in tree.body if isinstance(n, ast.ClassDef)
                and n.name == TABLE_INTERPRETER[1]), None)
    if cls is None:
        return []
    parts, todo, done = [cls], [cls], {cls.name}
    while todo:
        for sub in ast.walk(todo.pop()):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and \
                    sub.func.id in functions and sub.func.id not in done:
                done.add(sub.func.id)
                parts.append(functions[sub.func.id])
                todo.append(functions[sub.func.id])
    return parts


def interpreter_fingerprint(root: Path) -> str:
    """sha256 of the interpreter's syntax (TablePriorityPolicy and the module
    functions it calls, transitively), docstrings left out."""
    import hashlib
    try:
        tree = _parse(root / TABLE_INTERPRETER[0])
    except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
        return ""
    parts = _interpreter_parts(tree)
    if not parts:
        return ""
    return hashlib.sha256("\n".join(ast.dump(_without_docstrings(p)) for p in parts)
                          .encode()).hexdigest()


def _chain(node) -> List[str]:
    """The names along an attribute chain: `a.b.c` -> [a, b, c]."""
    out = []
    while isinstance(node, ast.Attribute):
        out.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        out.append(node.id)
    return out[::-1]


def _interpreter_names(root: Path) -> set:
    """The interpreter class and the module functions of tables.py it
    calls, transitively: what a profile could replace to change it."""
    found = _bound_class(root, "profiles.common.tables:TablePriorityPolicy")
    names = {TABLE_INTERPRETER[1]}
    if found is None:
        return names
    functions = _module_functions(found[3])
    todo = [found[2]]
    while todo:
        for sub in ast.walk(todo.pop()):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and \
                    sub.func.id in functions and sub.func.id not in names:
                names.add(sub.func.id)
                todo.append(functions[sub.func.id])
    return names


_OWN_ONLY = "a profile alters only its own instances (self)"


def _names_a_type_in_place(node, parents) -> bool:
    """`node` (a class name) is called, subclassed, read from, tested with
    isinstance/issubclass (also inside a tuple there), or in an annotation."""
    up = parents.get(node)
    if isinstance(up, ast.Tuple):
        node, up = up, parents.get(up)
    if isinstance(up, ast.Call):
        return up.func is node or (_chain(up.func)[-1:] in (["isinstance"], ["issubclass"])
                                   and node in up.args[1:])
    if isinstance(up, ast.Attribute) or isinstance(up, ast.ClassDef) and node in up.bases:
        return True
    while up is not None:
        if isinstance(up, ast.arg) and up.annotation is not None or \
                isinstance(up, ast.AnnAssign) and node is not up.value or \
                isinstance(up, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                up.returns is not None and _contains(up.returns, node):
            return True
        if isinstance(up, (ast.Subscript, ast.Tuple)):   # Dict[str, Tuple[Profile, ...]]
            node, up = up, parents.get(up)
            continue
        return False
    return False


def _contains(tree, node) -> bool:
    return any(n is node for n in ast.walk(tree))


def _own_instance(head: List[str], node, parents) -> bool:
    """`head` is `self` or `cls` as a method's own first parameter: the
    function enclosing `node` is defined in a class body, takes that name
    first, and never rebinds it."""
    if head not in (["self"], ["cls"]):
        return False
    fn = _enclosing_function(node, parents)
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or \
            not isinstance(parents.get(fn), ast.ClassDef) or \
            any(_chain(d)[-1:] == ["staticmethod"] for d in fn.decorator_list):
        return False
    params = fn.args.posonlyargs + fn.args.args
    if not params or params[0].arg != head[0]:
        return False
    return not any(isinstance(n, ast.Name) and n.id == head[0] and
                   isinstance(n.ctx, (ast.Store, ast.Del)) for n in _own_nodes(fn))


def _interpreter_patched(root: Path) -> List[str]:
    """Anywhere under profiles/, the interpreter or a helper it calls
    (`_interpreter_names`) altered, replaced or held:
      * stored or deleted by name or through any attribute chain
        (`TablePriorityPolicy.evaluate = ...`, `_t.TablePriorityPolicy = ...`,
        `_t._matches = ...`), aliases from `import ... as` included;
      * set or deleted by setattr, delattr, or a `__setattr__`/`__delattr__`
        call on it;
      * held anywhere but a call, a base class or a plain module-level
        alias (`Policy = TablePriorityPolicy`, which is followed), so a
        change cannot go through a name the gate does not see;
      * any use of globals(), vars() or `__dict__`, which reach every name;
      * any other attribute store, del, setattr or delattr on anything but
        `self.<attr>` or `cls.<attr>` itself, `self`/`cls` being a
        method's own, never rebound first parameter (not a staticmethod's):
        a profile alters only its own instances, never a core class the
        interpreter calls (`Profile.call_type = ...`); and no core class
        is handed to a call (but isinstance/issubclass), where it could
        arrive as a method's `self` (`_X.go(Profile)`);
    and in tables.py, each of these names bound once, by its definition."""
    out: List[str] = []
    protected = _interpreter_names(root)
    for path in sorted((root / PROFILES).rglob("*.py")):
        if any(p in CACHE_DIRS for p in path.parts):
            continue
        rel = path.relative_to(root).as_posix()
        try:
            tree = _parse(path)
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
            continue
        names = set(protected) | {a.asname for n in ast.walk(tree)
                                  if isinstance(n, (ast.ImportFrom, ast.Import))
                                  for a in n.names if a.asname and a.name in protected}
        # A plain module-level alias (`Policy = TablePriorityPolicy`) is
        # followed: it joins the names, so a change through it is seen.
        aliases = set()
        grew = True
        while grew:
            grew = False
            for node in tree.body:
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and \
                        isinstance(node.targets[0], ast.Name) and \
                        isinstance(node.value, (ast.Name, ast.Attribute)) and \
                        _chain(node.value) and _chain(node.value)[-1] in names and \
                        node.targets[0].id not in names:
                    names.add(node.targets[0].id)
                    aliases |= {id(node.value), id(node.targets[0])}
                    grew = True
        parents = _parent_map(tree)
        # Classes the module imports from the core by name.
        core_classes = {a.asname or a.name for n in ast.walk(tree)
                        if isinstance(n, ast.ImportFrom) and not n.level
                        and (n.module or "").split(".")[0] == CORE
                        for a in n.names
                        if a.name[:1].isupper() and not a.name.isupper()}
        hit = set()

        def report(node, what):
            if (node.lineno, what) not in hit:
                hit.add((node.lineno, what))
                out.append(f"{rel}:{node.lineno}: {what}; the table interpreter is not "
                           "altered by a profile")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Name, ast.Attribute)) and \
                    isinstance(node.ctx, (ast.Store, ast.Del)):
                chain = _chain(node)
                touched = [n for n in chain if n in names]
                if touched and id(node) not in aliases and \
                        not (isinstance(node, ast.Name) and rel == TABLE_INTERPRETER[0]):
                    report(node, f"changes {'.'.join(chain)}")
                elif isinstance(node, ast.Attribute) and (
                        len(chain) != 2 or not _own_instance(chain[:1], node, parents)):
                    # Only `self.<attr>` itself: `self.p.call_type` lands on
                    # whatever `self.p` holds.
                    # Anything else a profile changes from outside is another
                    # module's: a core class the interpreter calls
                    # (`Profile.call_type = ...`), or one held under a name.
                    out.append(f"{rel}:{node.lineno}: changes {'.'.join(chain) or 'an object'} "
                               "from outside it; " + _OWN_ONLY)
            elif isinstance(node, ast.Call):
                f = node.func
                # A core class handed to another function could reach it as
                # its `self` (`_X.go(Profile)`); a profile only uses them.
                fname = f.id if isinstance(f, ast.Name) else \
                    f.attr if isinstance(f, ast.Attribute) else ""
                if fname in ("setattr", "delattr", "__setattr__", "__delattr__"):
                    target = node.args[0] if node.args else None
                    if not (isinstance(target, ast.Name) and
                            _own_instance([target.id], node, parents)) and \
                            not (target is not None and set(_chain(target)) & names) and \
                            not (isinstance(f, ast.Attribute) and set(_chain(f.value)) & names):
                        out.append(f"{rel}:{node.lineno}: {fname} on "
                                   f"{'.'.join(_chain(target)) or 'an object'}; " + _OWN_ONLY)
                    for chain in (_chain(target) if target is not None else [],
                                  _chain(f.value) if isinstance(f, ast.Attribute) else []):
                        if set(chain) & names:
                            report(node, f"{fname} on {'.'.join(chain)}")
                            break
                if isinstance(f, ast.Name) and f.id in ("globals", "vars"):
                    report(node, f"calls {f.id}(), which reaches every name")
            elif isinstance(node, ast.Attribute) and node.attr == "__dict__":
                report(node, "reads __dict__, which reaches every name")
            # A core class is used where it is named: called, subclassed, read
            # from, tested against, or in an annotation. Held or handed to a
            # call, it could arrive as a method's `self` (`_X.go(Profile)`).
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and \
                    node.id in core_classes and not _names_a_type_in_place(node, parents):
                out.append(f"{rel}:{node.lineno}: hands the core class {node.id} on; "
                           + _OWN_ONLY)
            # Otherwise the interpreter is only called or subclassed (refused
            # by the binding rule): held anywhere else, it could be patched
            # through a name this gate does not follow.
            if isinstance(node, (ast.Name, ast.Attribute)) and \
                    isinstance(node.ctx, ast.Load) and id(node) not in aliases and \
                    (node.id if isinstance(node, ast.Name) else node.attr) in names:
                up = parents.get(node)
                if isinstance(up, ast.Attribute) or \
                        isinstance(up, ast.Call) and up.func is node or \
                        isinstance(up, ast.ClassDef) and node in up.bases or \
                        isinstance(up, ast.Call) and node in up.args and \
                        _chain(up.func)[-1:] in (["setattr"], ["delattr"], ["__setattr__"],
                                                 ["__delattr__"]):
                    continue                    # reported above
                report(node, f"holds {'.'.join(_chain(node)) or 'the interpreter'} "
                             "in another name")
        if rel == TABLE_INTERPRETER[0]:
            # Every name the interpreter reads, not only its own: rebinding
            # an import it uses (`HookContractViolation = RuntimeError`) or a
            # constant changes it as surely as editing it.
            referenced = protected | {n.id for part in _interpreter_parts(tree)
                                      for n in ast.walk(part)
                                      if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
            seen = set()
            for node in tree.body:
                bound = [node.name] if isinstance(node, (ast.ClassDef, ast.FunctionDef,
                                                          ast.AsyncFunctionDef)) else \
                    [a.asname or a.name for a in node.names] \
                    if isinstance(node, (ast.Import, ast.ImportFrom)) else []
                for n in bound:
                    if n in referenced and n in seen:
                        out.append(f"{rel}:{node.lineno}: rebinds {n} after its definition; "
                                   "the interpreter is the code as defined")
                    seen.add(n)
                for t in ast.walk(node) if isinstance(node, (ast.Assign, ast.AnnAssign,
                                                              ast.AugAssign, ast.For, ast.With,
                                                              ast.Delete)) else []:
                    if isinstance(t, ast.Name) and isinstance(t.ctx, (ast.Store, ast.Del)) \
                            and t.id in referenced and (t.id in seen or t.id in protected):
                        out.append(f"{rel}:{node.lineno}: rebinds {t.id} after its "
                                   "definition; the interpreter is the code as defined")
                    if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store):
                        seen.add(t.id)
    return sorted(set(out), key=_by_line)


def _module_functions(tree) -> Dict[str, ast.AST]:
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _interpreter_logic(rel: str, cls, tree) -> List[str]:
    """Imperative priority logic in the table interpreter and the module
    functions it calls, transitively: a comparison with, or a return of, a
    literal other than the structural ones, a match statement, an integer
    other than 0 and +-1."""
    out: List[str] = []
    functions = _module_functions(tree)
    todo, done = [cls], set()
    while todo:
        node = todo.pop()
        if id(node) in done:
            continue
        done.add(id(node))
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and \
                    sub.func.id in functions:
                todo.append(functions[sub.func.id])
            literals = []
            if isinstance(sub, ast.Compare):
                literals = [x for x in [sub.left] + sub.comparators
                            if isinstance(x, ast.Constant)]
                literals += [e for x in sub.comparators if isinstance(x, (ast.Tuple, ast.List,
                                                                            ast.Set))
                             for e in x.elts if isinstance(e, ast.Constant)]
            elif isinstance(sub, ast.Return) and isinstance(sub.value, ast.Constant):
                literals = [sub.value]
            elif isinstance(sub, ast.Match):
                out.append(f"{rel}:{sub.lineno}: the priority policy branches with match; "
                           "priority is the profile's table")
            for lit in literals:
                if lit.value not in STRUCTURAL_LITERALS or isinstance(lit.value, bool):
                    out.append(f"{rel}:{lit.lineno}: the priority policy decides on the "
                               f"literal {lit.value!r}; priority is the profile's table")
            if isinstance(sub, ast.Constant) and isinstance(sub.value, int) and \
                    not isinstance(sub.value, bool) and sub.value not in (0, 1, -1):
                out.append(f"{rel}:{sub.lineno}: the priority policy contains the literal "
                           f"{sub.value}")
    return sorted(set(out), key=_by_line)


def check_priority_table_declarative(root: Path) -> List[str]:
    """VP1-BND-011 / PLT-HOK-023 / PLT-PRF-001 — the table is data, not code.

    For every in-tree profile (the MCX profile among them):
      * profile.yaml declares priority as `priority.rules`, each a
        match/decision pair;
      * the class its `profile.hooks.priority_policy` binds, followed
        through imports and assignments, is the generic table interpreter
        (`TABLE_INTERPRETER`) itself, not a subclass or another class: a
        profile cannot add logic to it;
    and the interpreter, with the module functions it calls, compares with
    and returns only structural literals (the `*` wildcard, None, 0, +-1),
    holds no other integer, and has no match statement: it reads the
    table, it does not decide. It is also pinned as reviewed
    (`INTERPRETER_FINGERPRINT`): any change to it, a base class, a helper
    or a constant it reads included, fails until reviewed. Nothing under
    profiles/ changes it or a helper it calls (`_interpreter_patched`: by
    name or attribute chain, setattr and the like, a hidden alias,
    globals(), vars(), __dict__), and tables.py binds each of those names
    once; a binding follows the module's last assignment of the name.

    Not followed: a binding the loader resolves another way than a
    `module:Name` spec; the core accessors the interpreter calls
    (core/model.py), which VP1-BND-013 covers; a change made from outside
    profiles/.
    """
    violations: List[str] = []
    import yaml
    for package in sorted((root / PROFILES).glob("*/profile.yaml")):
        rel = package.relative_to(root).as_posix()
        try:
            data = yaml.safe_load(package.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
            violations.append(f"{rel}: cannot be read, so this gate cannot clear it")
            continue
        rules = ((data.get("priority") or {}).get("rules")) if isinstance(data, dict) else None
        if not rules or not isinstance(rules, list):
            violations.append(f"{rel}: no declarative priority rules")
        else:
            for i, rule in enumerate(rules):
                if not isinstance(rule, dict) or "match" not in rule or "decision" not in rule:
                    violations.append(f"{rel}: priority.rules[{i}] is not a match/decision "
                                      "pair")
        spec = (((data.get("profile") or {}).get("hooks") or {}).get("priority_policy")
                if isinstance(data, dict) else None)
        bound = _bound_class(root, spec) if isinstance(spec, str) else None
        if bound is None:
            violations.append(f"{rel}: profile.hooks.priority_policy ({spec!r}) does not "
                              "resolve to a class in the tree")
            continue
        brel, name, _, _ = bound
        if (brel, name) != TABLE_INTERPRETER:
            violations.append(f"{rel}: priority_policy binds {brel}:{name}, not the table "
                              f"interpreter {TABLE_INTERPRETER[0]}:{TABLE_INTERPRETER[1]}; "
                              "priority logic belongs in the profile's table")
    found = _bound_class(root, "profiles.common.tables:TablePriorityPolicy")
    if found is None:
        violations.append(f"{TABLE_INTERPRETER[0]}: the table interpreter "
                          f"{TABLE_INTERPRETER[1]} is missing")
    else:
        if interpreter_fingerprint(root) != INTERPRETER_FINGERPRINT:
            violations.append(f"{TABLE_INTERPRETER[0]}: the table interpreter has changed "
                              "since it was reviewed; review it and update "
                              "INTERPRETER_FINGERPRINT")
        violations += _interpreter_logic(found[0], found[2], found[3])
    violations += _interpreter_patched(root)
    return violations


# VP1-BND-012 as amended (PLT-VP-R1 RES-OP-10 ruling 1): no priority-to-QoS
# mapping in the core. What a 5QI is and the ARP range are TS 23.501
# definitions, allowed in core/qos.py only, and only these tables.
QOS_DEFINITIONS = frozenset({"STANDARDISED_5QI", "MC_5QI_MEDIA", "ARP_MIN", "ARP_MAX"})
QOS_FUNCTIONS = frozenset({"is_standardised", "media_of"})   # lookups in those tables
MC_5QI = frozenset({65, 66, 67, 69, 70})
# A whole word of an identifier or string: qos_identifier, arp_level, 5QI --
# not "sharp" or "stacklevel".
_QOS_NAME = re.compile(r"(?:^|[^a-z])(?:qos|arp|5qi|qci)(?:[^a-z]|$)", re.I)
# Lines a reviewer has judged not to be QoS values (a 65 ms timer, say), by
# file and exact stripped text, each with its reason. Reviewed like
# STATE_MACHINE_PROFILE_READS: a line is exempt only by being listed here.
QOS_REVIEWED_LINES: Dict[Tuple[str, str], str] = {}
_PRIORITY_NAME = re.compile(r"priority|preempt|scope|level", re.I)


def _names_in(node) -> List[str]:
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.append(sub.id)
        elif isinstance(sub, ast.Attribute):
            out.append(sub.attr)
        elif isinstance(sub, ast.keyword) and sub.arg:
            out.append(sub.arg)
        elif isinstance(sub, ast.arg):
            out.append(sub.arg)
        elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append(sub.name)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                and len(sub.value) < 40:
            out.append(sub.value)
    return out


def _ints_in(node) -> List[int]:
    return [sub.value for sub in ast.walk(node)
            if isinstance(sub, ast.Constant) and type(sub.value) is int
            and sub.value not in (0, 1)]


def check_no_qos_mapping_in_core(root: Path) -> List[str]:
    """VP1-BND-012 / PLT-HOK-043, as amended by RES-OP-10. HEURISTIC.

    core/qos.py holds the TS 23.501 definition tables named in
    QOS_DEFINITIONS, the lookups in QOS_FUNCTIONS and nothing that mentions
    a priority. Elsewhere in the core (hooks.py's types aside), no int
    literal appears in a statement, comparison, keyword or mapping that names
    QoS, ARP, 5QI or QCI, and no mission-critical 5QI value appears outside a
    comparison; a line listed in QOS_REVIEWED_LINES, with its reason, is
    exempt.

    Not caught, as a static gate cannot: a value computed (64 + 1), written
    as a float or a string, passed positionally, or derived from the tables
    themselves; a mapping onto non-mission-critical values under neutral
    names. Review is the check for those.
    """
    violations: List[str] = []
    qos = root / CORE / "qos.py"
    if qos.is_file():
        tree = _parse(qos)
        for node in tree.body:
            targets = []
            if isinstance(node, ast.Assign):
                targets = [t for t in node.targets]
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            for t in targets:
                for sub in ast.walk(t):
                    if isinstance(sub, ast.Name) and sub.id not in QOS_DEFINITIONS:
                        violations.append(
                            f"{qos.relative_to(root)}:{node.lineno}: {sub.id!r} is not "
                            "one of the TS 23.501 definitions core/qos.py may hold")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                 ast.Lambda)) and \
                    getattr(node, "name", "<lambda>") not in QOS_FUNCTIONS:
                violations.append(
                    f"{qos.relative_to(root)}:{node.lineno}: "
                    f"{getattr(node, 'name', 'a lambda')!r} is not one of the lookups "
                    "core/qos.py may define: a function here could map onto QoS")
        for name in _names_in(tree):
            if _PRIORITY_NAME.search(name) and not name.startswith("ARP_"):
                violations.append(
                    f"{qos.relative_to(root)}: mentions {name!r}: core/qos.py defines "
                    "QoS, it does not map priority onto it")
                break
    for path in _iter_python(root, CORE):
        if path.name in ("hooks.py", "qos.py"):
            continue            # the interface types; the named exception
        lines = path.read_text(encoding="utf-8").splitlines()
        rel = path.relative_to(root).as_posix()
        seen = {i + 1 for i, line in enumerate(lines)
                if (rel, line.strip()) in QOS_REVIEWED_LINES}
        tree = _parse(path)
        in_compare = {id(sub) for node in ast.walk(tree) if isinstance(node, ast.Compare)
                      for sub in ast.walk(node)}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Return,
                                 ast.Expr, ast.Assert, ast.Compare, ast.keyword,
                                 ast.Dict)):
                ints = _ints_in(node)
                if ints and any(_QOS_NAME.search(n) for n in _names_in(node)):
                    line = getattr(node, "lineno", getattr(node, "value", node).lineno)
                    if line not in seen:
                        seen.add(line)
                        violations.append(
                            f"{path.relative_to(root)}:{line}: a QoS literal {ints[0]} "
                            "outside core/qos.py")
            if isinstance(node, ast.Constant) and type(node.value) is int \
                    and node.value in MC_5QI and node.lineno not in seen \
                    and id(node) not in in_compare:
                seen.add(node.lineno)
                violations.append(
                    f"{path.relative_to(root)}:{node.lineno}: the mission-critical "
                    f"5QI value {node.value} outside core/qos.py")
    return violations


_PRIORITY_VALUE_WORDS = frozenset({"priority", "prio", "pri", "level", "urgency", "scope",
                                   "label", "capability", "vulnerability"})
# Comparisons written as calls.
_COMPARE_CALLS = frozenset({"lt", "le", "gt", "ge", "eq", "ne", "__lt__", "__le__", "__gt__",
                            "__ge__", "__eq__", "__ne__", "__cmp__"})
# Request fields an ordering might be taken from instead of IF-PRI.
_ORDERING_FIELDS = frozenset({"call_type", "application", "urgency"})
_ORDERING_CALLS = frozenset({"sorted", "sort", "min", "max", "heappush", "heapify",
                             "insort", "insort_left", "insort_right", "nlargest", "nsmallest"})
# Where the core compares or orders priority values, each reviewed: the
# function (Class.method), the priority names it may compare, and why the
# values come from IF-PRI or the comparison only checks a declaration or a
# hook's answer. A comparison anywhere else, or of other names there, fails.
PRIORITY_USES: Dict[Tuple[str, str], Tuple[frozenset, str]] = {
    ("core/floor.py", "FloorControl._enqueue"): (frozenset({"floor_priority"}),
        "queue order by the floor_priority IF-PRI decided (PLT-FC-005), arrival breaking ties"),
    ("core/floor.py", "FloorControl._on_request_taken"): (
        frozenset({"floor_priority", "_holder_priority"}),
        "a request's IF-PRI floor_priority against the holder's (TS 24.380 6.3.4.4.x)"),
    ("core/session.py", "SessionManager.preemption_victims"): (frozenset({"scope"}),
        "IF-PRI decisions' scopes (PLT-ICD-001 4.2 POST-1), then IF-PRI compare"),
    ("core/session.py", "SessionManager._check_bearer"): (
        frozenset({"arp_level", "priority", "preemption_capability"}),
        "IF-BRG's ARP level against the TS 23.501 range, and its pre-emption request "
        "against IF-PRI's decision (contract checks)"),
    ("core/validation.py", "_priority_totality"): (frozenset({"urgency"}),
        "checks at load that the declared table covers every call type"),
    ("core/validation.py", "_bearer_totality"): (frozenset(),
        "checks at load that the declared bearer table covers every call type and medium"),
    ("core/validation.py", "_partner_inbound"): (
        frozenset({"max_level", "to_level", "from_label", "seen_labels"}),
        "checks at load the bounds of a partner's declared level mapping"),
}
# Load-time checks of declared tables: they may hold and compare levels.
_VALIDATING = frozenset(k for k in PRIORITY_USES if k[0] == "core/validation.py")


def _priority_value(name: str) -> bool:
    return any(p.lower() in _PRIORITY_VALUE_WORDS for p in _NAME_PARTS.findall(name or ""))


def _names_of(node) -> List[str]:
    """Names, attributes, and the fields named as text: to attrgetter,
    itemgetter or getattr, or as a subscript (`attributes['urgency']`)."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, (ast.Name, ast.Attribute)):
            out.append(n.id if isinstance(n, ast.Name) else n.attr)
        elif isinstance(n, ast.Call) and isinstance(n.func, (ast.Name, ast.Attribute)):
            fname = n.func.id if isinstance(n.func, ast.Name) else n.func.attr
            if fname in ("attrgetter", "itemgetter"):
                out += [a.value for a in n.args if isinstance(a, ast.Constant)
                        and isinstance(a.value, str)]
            elif fname == "getattr" and len(n.args) >= 2 and \
                    isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str):
                out.append(n.args[1].value)
        elif isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and \
                isinstance(n.slice.value, str):
            out.append(n.slice.value)
    return out


def _qualified(node, parents) -> str:
    """Class.method, or function, enclosing `node`; "" at module level."""
    names = []
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
    return ".".join(reversed(names))


def _number(node):
    """The value of a numeric literal (int or float, signed), or None."""
    sign = 1
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        sign = -1 if isinstance(node.op, ast.USub) else 1
        node = node.operand
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and \
            not isinstance(node.value, bool):
        return sign * node.value
    return None


def _literals(node) -> List:
    """Literal values in `node` that could carry a priority: strings and
    numbers but 0 (not None, booleans), also in collections and
    conditionals; a signed number counted once, with its sign."""
    signed = {id(n.operand) for n in ast.walk(node)
              if isinstance(n, ast.UnaryOp) and isinstance(n.op, (ast.USub, ast.UAdd))}
    out = []
    for n in ast.walk(node):
        if id(n) in signed:
            continue
        v = _number(n)
        if v is not None:
            if v != 0:
                out.append(v)
        elif isinstance(n, ast.Constant) and isinstance(n.value, (str, bytes)):
            out.append(n.value)
    return out


_REQUEST_FIELDS = frozenset({"call_type", "application", "urgency"})
# Reading a field by key is not testing it against the key.
_LOOKUPS = frozenset({"get", "setdefault", "__getitem__", "pop"})
# SessionRequest fields named like much else in the platform (a config's
# `location_reports`, a rule's `media`, a SIP `target`): followed by name
# they would be everything. Their literal comparisons are not judged; a
# bare branch on them still is.
_COMMON_ATTRIBUTES = frozenset({"attributes", "media", "location", "target", "request_id",
                                "initiator", "participants"})


def _functions_of(tree):
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _assigned(fn):
    """(target names, value) for each binding in `fn`, its own nodes only:
    assignments (a tuple target against a tuple value paired position by
    position), and the targets of for, with and comprehensions against
    what they iterate or enter."""
    def names(x):
        return [t.id for t in ast.walk(x) if isinstance(t, ast.Name)]
    for n in _own_nodes(fn):
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign)) and \
                n.value is not None:
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                if isinstance(t, (ast.Tuple, ast.List)) and \
                        isinstance(n.value, (ast.Tuple, ast.List)) and \
                        len(t.elts) == len(n.value.elts):
                    for te, ve in zip(t.elts, n.value.elts):
                        yield names(te), ve
                else:
                    yield names(t), n.value
        elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
            yield names(n.target), n.iter
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if item.optional_vars is not None:
                    yield names(item.optional_vars), item.context_expr


# What may build a label table from literals.
_TABLE_BUILDERS = frozenset({"dict", "zip", "enumerate", "range", "tuple", "list"})
# Functions that test text against a pattern or member.
_MATCH_CALLS = frozenset({"match", "fullmatch", "search", "findall", "finditer", "fnmatch",
                          "fnmatchcase", "contains", "sub", "subn", "split", "countOf",
                          "indexOf"})
# Calls that make text of a value: the value is still the same label.
_TEXT_CALLS = frozenset({"str", "repr", "format"})


def _carries(value, names: set) -> bool:
    """`value` is one of `names`, or made from one without a lookup: an
    attribute, subscript, text made of it (`.lower()`, str(), an f-string),
    a choice among values (`or`, a conditional), a tuple or list of them, a
    sum. Not a value looked up with it (`profile.call_type(r.call_type)`)."""
    if isinstance(value, (ast.Name, ast.Attribute, ast.Subscript)):
        return bool(set(_names_of(value)) & names)
    if isinstance(value, ast.Call):
        f = value.func
        if isinstance(f, ast.Attribute) and f.attr in _STRING_METHODS:
            return _carries(f.value, names)
        if isinstance(f, ast.Name) and f.id in _TEXT_CALLS:
            return any(_carries(a, names) for a in value.args)
        if _chain(f) == ["getattr"]:
            return bool(set(_names_of(value)) & names)
        return False
    if isinstance(value, ast.BoolOp):
        return any(_carries(v, names) for v in value.values)
    if isinstance(value, ast.IfExp):
        return _carries(value.body, names) or _carries(value.orelse, names)
    if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
        return any(_carries(v, names) for v in value.elts)
    if isinstance(value, ast.JoinedStr):
        return any(_carries(v.value, names) for v in value.values
                   if isinstance(v, ast.FormattedValue))
    if isinstance(value, ast.BinOp):
        return _carries(value.left, names) or _carries(value.right, names)
    return False


def _field_locals(fn, fields=_REQUEST_FIELDS) -> set:
    """Names `fn` binds from a request field, directly or through another
    such name (`_carries`): `ct = r.call_type or ''` makes `ct` one."""
    tainted: set = set()
    grew = True
    while grew:
        grew = False
        for names, value in _assigned(fn):
            if _carries(value, fields | tainted):
                for n in names:
                    if n not in tainted:
                        tainted.add(n)
                        grew = True
    return tainted


def _folded(node):
    """The value of an expression made only of literals (numbers and text,
    signed, summed or multiplied, a method called on a literal:
    `'EMERGENCY'.lower()`, `4 + 5`), or None."""
    v = _number(node)
    if v is not None:
        return v
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp):
        a, b = _folded(node.left), _folded(node.right)
        if a is not None and b is not None:
            try:
                return {ast.Add: lambda: a + b, ast.Sub: lambda: a - b,
                        ast.Mult: lambda: a * b}.get(type(node.op), lambda: None)()
            except TypeError:
                return None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
            node.func.attr in _STRING_METHODS and not node.args:
        base = _folded(node.func.value)
        if isinstance(base, str):
            return getattr(base, node.func.attr)()
    return None


def _literal_locals(fn) -> set:
    """Names `fn` binds to a literal number other than 0, also through a
    conditional, a boolean choice or arithmetic on literals:
    `n = 9 if r.adhoc else 1`, `n = 4 + 5`."""
    out = set()
    for names, value in _assigned(fn):
        folded = _folded(value)
        if (folded is not None and not isinstance(folded, str) and folded != 0) or \
                isinstance(value, (ast.IfExp, ast.BoolOp)) and \
                any(not isinstance(v, (str, bytes)) for v in _literals(value)):
            out |= set(names)
    return out


def _constant_collections(tree) -> Dict[str, List]:
    """Module-level names bound to literals: a number or text (folded), or
    a literal tuple, list, set, frozenset(...) or dict: name -> its literal
    members (keys and values)."""
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            v = node.value
            if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and \
                    v.func.id in ("frozenset", "set", "tuple") and v.args:
                v = v.args[0]
            if isinstance(v, ast.Call) and _chain(v.func)[-1:] == ["compile"] and v.args:
                v = v.args[0]                    # re.compile('emerg'): the pattern
            folded = _folded(v)
            lits = [folded] if folded not in (None, 0, "") else \
                _literals(v) if isinstance(v, (ast.Tuple, ast.List, ast.Set, ast.Dict)) else []
            if lits:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        out[t.id] = lits
    return out


def _module_bindings(tree):
    """(name, value) for each plain module-level binding."""
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                if isinstance(t, ast.Name):
                    yield t.id, node.value


def _is_table(v, known: frozenset = frozenset()) -> bool:
    """A literal mapping of text keys onto constants or tuples of them:
    `{'emergency': 9}`, `{'emergency': (9, 'national')}`, `dict(emergency=9)`."""
    def const(x):
        return _folded(x) is not None or isinstance(x, ast.Constant) or \
            isinstance(x, ast.Tuple) and all(const(e) for e in x.elts)
    if isinstance(v, ast.Dict):
        return bool(v.keys) and all(isinstance(k, ast.Constant) and isinstance(k.value, str)
                                    for k in v.keys) and all(const(x) for x in v.values)
    if isinstance(v, ast.Call) and _chain(v.func) == ["dict"] and not v.args and v.keywords:
        return all(k.arg is not None and const(k.value) for k in v.keywords)
    if isinstance(v, ast.DictComp) or isinstance(v, ast.Call) and _chain(v.func) == ["dict"]:
        # Built from literals alone (`dict(zip(('emergency',), (9,)))`,
        # `{k: 9 for k in ('emergency',)}`): no name but the builders and the
        # comprehension's own variables.
        bound = {n.id for g in ast.walk(v) if isinstance(g, ast.comprehension)
                 for n in ast.walk(g.target) if isinstance(n, ast.Name)}
        loads = {n.id for n in ast.walk(v) if isinstance(n, ast.Name)}
        return bool(loads) and loads <= bound | _TABLE_BUILDERS | known and \
            (any(isinstance(c, ast.Constant) and isinstance(c.value, str) for c in ast.walk(v))
             or bool(loads & known))
    return False


def _key_functions(tree) -> Dict[str, ast.AST]:
    return {n.name: n for n in _functions_of(tree)}


def _returned_names(fn) -> set:
    return {x for n in ast.walk(fn) if isinstance(n, (ast.Return, ast.Lambda))
            for x in _names_of(n.value if isinstance(n, ast.Return) else n.body)
            if n is not None and (n.value if isinstance(n, ast.Return) else n.body) is not None}


def _request_attributes(root: Path) -> frozenset:
    """The fields of SessionRequest (core/hooks.py)."""
    try:
        tree = _parse(root / CORE / "hooks.py")
    except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
        return frozenset()
    return frozenset(n.target.id for c in tree.body
                     if isinstance(c, ast.ClassDef) and c.name == "SessionRequest"
                     for n in c.body if isinstance(n, ast.AnnAssign)
                     and isinstance(n.target, ast.Name))


def _priority_decisions_outside_if_pri(rel: str, tree,
                                       request_attributes: frozenset = frozenset()
                                       ) -> List[str]:
    """VP1-BND-013 over one runtime module (see check_no_priority_table_in_core)."""
    out: List[str] = []
    parents = _parent_map(tree)
    # Every field the request carries (VP1-BND-013 round 5): a branch, a
    # comparison or a table keyed on any of them is a priority derived
    # from the request.
    fields_all = _REQUEST_FIELDS | (request_attributes - _COMMON_ATTRIBUTES)
    constants = _constant_collections(tree)
    collections = {n for n, node in _module_bindings(tree)
                   if isinstance(node, (ast.Tuple, ast.List, ast.Set, ast.Call))
                   and n in constants}
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        for n, v in _constant_collections(ast.Module(body=cls.body, type_ignores=[])).items():
            constants[f"{cls.name}.{n}"] = v
    known = frozenset(constants)
    tables = {t.id for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
              and node.value is not None and _is_table(node.value, known)
              for t in (node.targets if isinstance(node, ast.Assign) else [node.target])
              if isinstance(t, ast.Name)}
    # A module dict filled with literals at module level: `_T['emergency'] = 9`.
    tables |= {t.value.id for node in tree.body if isinstance(node, ast.Assign)
               for t in node.targets if isinstance(t, ast.Subscript)
               and isinstance(t.value, ast.Name) and isinstance(t.slice, ast.Constant)
               and isinstance(t.slice.value, str) and _folded(node.value) is not None}
    functions = _key_functions(tree)
    fields_in: Dict[int, set] = {}
    literal_in: Dict[int, set] = {}
    members_in: Dict[int, Dict[str, str]] = {}
    for fn in _functions_of(tree):
        fields_in[id(fn)] = _field_locals(fn, fields_all)
        literal_in[id(fn)] = _literal_locals(fn)
        # Names a loop takes from a literal collection: `for k, v in PAIRS`.
        members_in[id(fn)] = {
            t.id: (n.iter.id if isinstance(n.iter, ast.Name) else "written inline")
            for n in _own_nodes(fn) if isinstance(n, (ast.For, ast.comprehension))
            and (isinstance(n.iter, ast.Name) and n.iter.id in collections or
                 isinstance(n.iter, (ast.Tuple, ast.List, ast.Set)) and _literals(n.iter))
            for t in ast.walk(n.target) if isinstance(t, ast.Name)}

    def _side_literals(x):
        """The literals a compared side or argument stands for: written,
        folded, or a module-level literal constant."""
        if isinstance(x, ast.Name):
            return constants.get(x.id, [])
        if isinstance(x, ast.Attribute) and isinstance(x.value, ast.Name):
            return constants.get(f"{x.value.id}.{x.attr}", [])
        folded = _folded(x)
        if folded is not None:
            return [folded] if folded not in (0, "") else []
        if isinstance(x, (ast.Constant, ast.UnaryOp, ast.Tuple, ast.List, ast.Set, ast.Dict)):
            return _literals(x)
        return []

    def _request_reads(x) -> set:
        """Fields read from what is plainly the request: `request.<f>`,
        `<x>.request.<f>`, or a parameter annotated SessionRequest. The common
        names (`_COMMON_ATTRIBUTES`) are judged here, where the base says
        they are the request's, though not followed by name alone."""
        fn = _enclosing_function(x, parents)
        typed = {a.arg for a in (fn.args.args + fn.args.kwonlyargs)
                 if a.annotation is not None and "SessionRequest" in ast.unparse(a.annotation)} \
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) else set()
        out = set()
        for n in ast.walk(x):
            if isinstance(n, ast.Attribute) and n.attr in request_attributes:
                base = n.value
                if isinstance(base, ast.Name) and (base.id == "request" or base.id in typed) or \
                        isinstance(base, ast.Attribute) and base.attr == "request":
                    out.add(n.attr)
        return out

    def _table_name(x):
        """`x` names a module-level label table, or a table assigned in the
        function, or is one written inline."""
        if isinstance(x, ast.Name) and (x.id in tables or x.id in collections):
            return x.id
        fn = _enclosing_function(x, parents)
        if isinstance(x, ast.Name) and fn is not None and any(
                x.id in names and _is_table(value, known) for names, value in _assigned(fn)):
            return x.id
        if _is_table(x, known) or isinstance(x, (ast.Tuple, ast.List, ast.Set)) and \
                any(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in x.elts):
            return "written inline"
        return ""

    def _asked(node):
        """The request fields a bare test reads (`if r.flag`, `if alert`, `if r.flag
        is True`), or nothing when the test compares with a value or calls:
        those are the rules above."""
        test = node.test
        bare = not any(isinstance(n, ast.Call) for n in ast.walk(test)) and all(
            all(isinstance(c, ast.Constant) and c.value in (True, False, None)
                for c in [n.left] + n.comparators if isinstance(c, ast.Constant)) and
            any(isinstance(c, ast.Constant) for c in [n.left] + n.comparators)
            for n in ast.walk(test) if isinstance(n, ast.Compare))
        if not bare:
            return []
        local_fields, _ = scope(node)
        return sorted({n.attr for n in ast.walk(test)
                       if isinstance(n, ast.Attribute) and n.attr in request_attributes} |
                      {n.id for n in ast.walk(test) if isinstance(n, ast.Name)
                       and n.id in local_fields})

    def _adjusting_number(x):
        """A level number `x` works into a value: `base + 5`, `max(base, 9)`."""
        if not isinstance(x, (ast.BinOp, ast.Call)):
            return None
        for n in ast.walk(x):
            if n is not x and (isinstance(n, ast.Constant) or isinstance(n, ast.Name)):
                v = _chosen_number(n)
                if v is not None:
                    return v
        return None

    def _chosen_number(x):
        """The number `x` is, written, folded or a constant, if it could be a
        level: not 0, not a status code (100-699, SIP and HTTP)."""
        v = _folded(x)
        if v is None and isinstance(x, (ast.Name, ast.Attribute)):
            v = next(iter(_side_literals(x)), None)
        if v is None or isinstance(v, (str, bytes)) or v == 0 or \
                isinstance(v, int) and 100 <= v <= 699:
            return None
        return v

    def scope(node):
        fn = _enclosing_function(node, parents)
        return (fields_in.get(id(fn), set()), literal_in.get(id(fn), set())) \
            if fn is not None else (set(), set())

    def compared(node, sides, where, allowed, validating):
        local_fields, _ = scope(node)
        valued = {n for x in sides for n in _names_of(x) if _priority_value(n)}
        fields = {n for x in sides for n in _names_of(x)
                  if n in fields_all or n in local_fields} | \
            {n for x in sides for n in _request_reads(x)}
        if valued and not valued <= allowed:
            out.append(f"{rel}:{node.lineno}: compares a priority value in "
                       f"{where or 'module'}; priority decisions are IF-PRI's "
                       "(PRIORITY_USES lists the reviewed comparisons)")
        if (valued or fields) and not validating:
            what = "a priority value" if valued else "a request field"
            fn = _enclosing_function(node, parents)
            members = members_in.get(id(fn), {}) if fn is not None else {}
            for x in sides:
                if isinstance(x, ast.Name) and x.id in members:
                    out.append(f"{rel}:{node.lineno}: compares {what} with a member of the "
                               f"literal collection {members[x.id]}; a priority is IF-PRI's, "
                               "not derived from a label or number")
                lits = _side_literals(x)
                for v in lits:
                    out.append(f"{rel}:{node.lineno}: compares {what} with the literal "
                               f"{v!r}; a priority is IF-PRI's, not derived from a "
                               "label or number")

    for node in ast.walk(tree):
        where = _qualified(node, parents)
        use = PRIORITY_USES.get((rel, where))
        validating = (rel, where) in _VALIDATING
        allowed = use[0] if use else frozenset()
        if isinstance(node, ast.Compare):
            compared(node, [node.left] + node.comparators, where, allowed, validating)
        elif isinstance(node, ast.BinOp) and not validating and \
                isinstance(node.op, (ast.BitAnd, ast.BitOr, ast.BitXor, ast.Sub)):
            local_fields, _ = scope(node)
            for a, b in ((node.left, node.right), (node.right, node.left)):
                if _carries(a, fields_all | local_fields) or \
                        isinstance(a, ast.Set) and any(_carries(e, fields_all |
                                                                 local_fields) for e in a.elts):
                    for v in _side_literals(b):
                        out.append(f"{rel}:{node.lineno}: tests a request field against the "
                                   f"literal {v!r} (a set operation); a priority is IF-PRI's, "
                                   "not derived from a label")
        elif isinstance(node, ast.If) and not validating and request_attributes:
            # A number chosen by what the request carries (`if r.adhoc_alert_group:
            # return 9`) is a priority table with one row.
            # A test that compares or calls is judged by the rules above.
            asked = _asked(node)
            if asked:
                for st in node.body + node.orelse:
                    value = st.value if isinstance(st, (ast.Return, ast.Assign, ast.AugAssign)) \
                        else None
                    v = (_chosen_number(value) or _adjusting_number(value)) \
                        if value is not None else None
                    if v is not None:
                        what = "returns" if isinstance(st, ast.Return) else "sets"
                        out.append(f"{rel}:{st.lineno}: {what} {v!r} chosen by the request's "
                                   f"{', '.join(asked)}; a priority is IF-PRI's")
        elif isinstance(node, ast.IfExp) and not validating and request_attributes:
            asked = _asked(node)
            if asked:
                for branch in (node.body, node.orelse):
                    v = _chosen_number(branch) or _adjusting_number(branch)
                    if v is not None:
                        out.append(f"{rel}:{node.lineno}: chooses {v!r} by the request's "
                                   f"{', '.join(asked)}; a priority is IF-PRI's")
                        break
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult) and \
                not validating and request_attributes:
            for a, b in ((node.left, node.right), (node.right, node.left)):
                asked = sorted({n.attr for n in ast.walk(a) if isinstance(n, ast.Attribute)
                                and n.attr in request_attributes})
                if asked and _chosen_number(b) is not None:
                    out.append(f"{rel}:{node.lineno}: scales {_chosen_number(b)!r} by the "
                               f"request's {', '.join(asked)}; a priority is IF-PRI's")
        elif isinstance(node, ast.Match) and not validating:
            local_fields, _ = scope(node)
            subject = set(_names_of(node.subject))
            if subject & (fields_all | local_fields) or \
                    any(_priority_value(n) for n in subject):
                out.append(f"{rel}:{node.lineno}: branches on a request field or priority "
                           "value with match; a priority is IF-PRI's")
        elif isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            local_fields, local_literals = scope(node)
            if name in _COMPARE_CALLS:
                sides = list(node.args) + ([node.func.value]
                                           if isinstance(node.func, ast.Attribute)
                                           and name.startswith("__") else [])
                compared(node, sides, where, allowed, validating)
            if isinstance(node.func, ast.Attribute) and _table_name(node.func.value) \
                    and not validating and \
                    {n for a in node.args for n in _names_of(a)} & (fields_all |
                                                                    local_fields):
                out.append(f"{rel}:{node.lineno}: looks up a request field in the label table "
                           f"{_table_name(node.func.value)}; a priority is IF-PRI's")
            elif isinstance(node.func, ast.Attribute) and not validating and \
                    name not in _COMPARE_CALLS and name not in _LOOKUPS and \
                    (set(_names_of(node.func.value)) & (fields_all | local_fields) or
                     _request_reads(node.func.value)):
                for v in [v for a in node.args for v in _side_literals(a)]:
                    out.append(f"{rel}:{node.lineno}: tests a request field against the "
                               f"literal {v!r} ({name}); a priority is IF-PRI's, not derived "
                               "from a label")
            if name in _MATCH_CALLS and not validating and \
                    isinstance(node.func, ast.Attribute) and \
                    isinstance(node.func.value, ast.Name) and node.func.value.id in constants \
                    and any(_carries(a, fields_all | local_fields) for a in node.args):
                for v in constants[node.func.value.id]:
                    out.append(f"{rel}:{node.lineno}: tests a request field against the "
                               f"literal {v!r} ({name}); a priority is IF-PRI's, not derived "
                               "from a label")
            elif name in _MATCH_CALLS and not validating and \
                    any(_carries(a, fields_all | local_fields) for a in node.args):
                for v in [v for a in node.args for v in _side_literals(a)]:
                    out.append(f"{rel}:{node.lineno}: tests a request field against the "
                               f"literal {v!r} ({name}); a priority is IF-PRI's, not derived "
                               "from a label")
            if name in _ORDERING_CALLS:
                args = list(node.args) + [k.value for k in node.keywords]
                keyed = {n for a in args for n in _names_of(a)
                         if _priority_value(n) or n in (_ORDERING_FIELDS | fields_all)}
                for a in [k.value for k in node.keywords if k.arg == "key"]:
                    target = a.id if isinstance(a, ast.Name) else \
                        a.attr if isinstance(a, ast.Attribute) else None
                    called = [target] + ([c.func.id if isinstance(c.func, ast.Name) else
                                          c.func.attr for c in ast.walk(a)
                                          if isinstance(c, ast.Call) and
                                          isinstance(c.func, (ast.Name, ast.Attribute))]
                                         if isinstance(a, ast.Lambda) else [])
                    for t in called:
                        if t in functions:
                            keyed |= {n for n in _returned_names(functions[t])
                                      if _priority_value(n) or n in (_ORDERING_FIELDS | fields_all)}
                if keyed and not keyed <= allowed:
                    out.append(f"{rel}:{node.lineno}: orders by a priority value or request "
                               f"field in {where or 'module'}; the order is IF-PRI's")
            if name == "PriorityDecision" and not validating:
                for a in list(node.args) + [k.value for k in node.keywords]:
                    v = _number(a)
                    named = [c for c in _side_literals(a) if not isinstance(c, (str, bytes))
                             and c != 0] if isinstance(a, (ast.Name, ast.Attribute)) else []
                    if (v is not None and v != 0) or isinstance(a, ast.IfExp) or named or \
                            isinstance(a, ast.Name) and a.id in local_literals:
                        out.append(f"{rel}:{node.lineno}: builds a PriorityDecision from "
                                   "literals or a condition; a priority is IF-PRI's")
                        break
                if any(k.arg is None for k in node.keywords):
                    out.append(f"{rel}:{node.lineno}: builds a PriorityDecision from an "
                               "unpacked mapping; a priority is IF-PRI's, field by field")
            if name == "replace" and not validating:
                for k in node.keywords:
                    if k.arg is None or _priority_value(k.arg) and (
                            not isinstance(k.value, (ast.Name, ast.Attribute)) or
                            {a.attr for a in ast.walk(k.value) if isinstance(a, ast.Attribute)}
                            & request_attributes):
                        out.append(f"{rel}:{node.lineno}: replaces "
                                   f"{k.arg or 'fields from a mapping'} with a computed value; "
                                   "a priority is IF-PRI's as decided")
        elif isinstance(node, ast.Dict) and not validating and len(node.keys) >= 2 and \
                not (isinstance(parents.get(node), (ast.Assign, ast.AnnAssign)) and
                     parents.get(parents.get(node)) is tree) and \
                all(isinstance(k, ast.Constant) and isinstance(k.value, str) for k in node.keys) \
                and all(_number(v) is not None for v in node.values) and \
                len({_number(v) for v in node.values}) > 1:
            # Counters start alike ({"accepted": 0, ...}); levels differ.
            # Module-level tables are named and reviewed (the marker check
            # below, and the lookups next); one written inline is not.
            out.append(f"{rel}:{node.lineno}: maps labels onto numbers inline; a "
                       "label-to-level mapping is a priority table")
        elif isinstance(node, ast.Subscript) and _table_name(node.value) and \
                not validating and \
                set(_names_of(node.slice)) & (fields_all | scope(node)[0]):
            out.append(f"{rel}:{node.lineno}: looks up a request field in the label table "
                       f"{_table_name(node.value)}; a priority is IF-PRI's")
        if validating:
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            named = [n for t in targets for n in _names_of(t) if _priority_value(n)]
            # An all-capitals name holding text is a reason code or message
            # (LOWER_PRIORITY = "lower-priority"), not a priority value.
            constant = named and all(n.isupper() for n in named)
            value = node.value
            if isinstance(value, ast.Call) and _chain(value.func) == ["getattr"] and \
                    len(value.args) == 3:
                value = value.args[2]            # the default is what it sets
            if named and \
                    isinstance(value, (ast.Constant, ast.UnaryOp, ast.IfExp, ast.BoolOp)):
                for v in _literals(value):
                    if constant and isinstance(v, (str, bytes)):
                        continue
                    out.append(f"{rel}:{node.lineno}: sets a priority value to {v!r}; a "
                               "priority is IF-PRI's")
        elif isinstance(node, ast.keyword) and node.arg and _priority_value(node.arg):
            v = _number(node.value)
            if v is None and isinstance(node.value, (ast.Name, ast.Attribute)):
                v = next((c for c in _side_literals(node.value)
                          if not isinstance(c, (str, bytes)) and c != 0), None)
            if v is not None and v != 0:
                out.append(f"{rel}:{node.value.lineno}: passes {node.arg}={v}; a priority "
                           "is IF-PRI's")
    return out


def check_no_priority_table_in_core(root: Path) -> List[str]:
    """VP1-BND-013 / PLT-HOK-021 — every priority decision is IF-PRI's.

    Comparing a floor priority the profile supplied is required by PLT-FC-005,
    so comparison itself cannot be forbidden. "The core" is the platform
    the profile plugs into: every module the process runs (core/, the
    interface definitions core/hooks.py included, and service/, where the
    floor's priorities are fetched from IF-PRI).
      * A comparison of (also written as operator.lt and the rest, or a
        comparison dunder), or an ordering (sorted, sort, min, max, heapq,
        bisect; attrgetter, itemgetter and a key function of the module
        followed) by, a priority value (a name with priority, prio, pri,
        level, urgency, scope, label, capability or vulnerability in it;
        for orderings also any request field but the common ones) is allowed only in
        the functions `PRIORITY_USES` lists, by Class.method, and only of
        the names listed for each: each use is reviewed, its values coming
        from IF-PRI or it checking a declaration or a hook's answer.
      * Outside the load-time checks of declared tables (`_VALIDATING`):
        a priority value or a request field (call_type, application,
        urgency; also named as getattr text or a subscript, and any local
        bound from one, `ct = r.call_type`) is never compared with a
        literal other than 0 and None, signed and float numbers and the
        members of a module-level literal collection included; never
        tested by a method with a literal argument (`.startswith('emerg')`);
        never the subject of a match; never looked up in a module-level
        label-to-number table. A priority value is never set to a literal
        (a number other than 0; text, unless the name is an all-capitals
        constant), also through a conditional; no keyword passes one a
        number other than 0; no PriorityDecision is built from numeric
        literals, a conditional, a local bound to either, or an unpacked
        mapping; no `replace` gives a priority field a computed value: a
        priority derived by label is a priority table.
      * No dict written inline maps two or more labels onto differing
        numbers; at module level, none does under a priority-like name.

    Literals include module-level text and number constants and values
    folded from literals (`'EMERGENCY'.lower()`, `4 + 5`); a request field
    is followed into locals through `or`, conditionals, str(), f-strings,
    tuples (by position), for and with targets; a label table is any
    literal mapping of text onto constants or tuples of them, dict(k=...)
    too, module-level or inline, or built from literals alone (dict(zip(...)),
    a comprehension); a literal list or tuple is one too (`.index`), and a
    loop over one yields its members as literals (`for k, v in PAIRS`).
    Module and class constants (`NINE`, `K.N`) count as literals in a
    PriorityDecision and a priority keyword; a pattern function (re,
    fnmatch, operator.contains) or a set operation testing a field against
    a literal is refused; and a number returned from a branch on any
    SessionRequest field tested bare (`if r.adhoc_alert_group`, a local
    holding it, `is True`), returned, assigned or chosen in a conditional
    expression, written or a constant, or a number scaled by such a field,
    is a priority table with one row (status codes 100-699 excepted).
    Every SessionRequest field is followed into locals and comparisons but
    the commonly named ones (`_COMMON_ATTRIBUTES`); compiled patterns
    (`re.compile('emerg')`), dicts filled with literals at module level,
    tables zipped from constants and inline literal collections count as
    literals and tables. A key lambda's calls are followed.

    The common field names are judged where the base is plainly the
    request (`request.<f>`, `<x>.request.<f>`, a parameter annotated
    SessionRequest); a branch's arm may not work a level into a value
    (`base + 5`, `max(base, 9)`, `n += 5`); `replace` may not set a
    priority field from a request field; a table assigned in a function
    counts as one.

    Not followed (recorded residue, VP1-BND-013 reviews): a value held
    under a name with none of those words (`rank = 9`) and set from a
    non-literal; a field or decision passed through another function
    (`_lvl(r.call_type)`); a table built at run time from non-literals; a
    flag on an object not plainly the request (`s.emergency`); a level
    that happens to lie in 100-699 (taken as a status code); comparisons
    by hash or other computed identity; a decision made under neutral names
    with no literal (victims chosen by a request flag); a local alias of a
    common request field (`attrs = request.attributes`). Fails safe, for
    review: a literal test of a common field that is not about priority
    (`'audio' in request.media`), a counter bumped under a request flag.
    """
    violations: List[str] = []
    markers = ("priority", "level", "urgency", "preempt")
    attributes = _request_attributes(root)
    paths = [p for package in RUNTIME for p in _iter_python(root, package)]
    for path in paths:
        if any(p in CACHE_DIRS for p in path.parts):
            continue
        rel = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8")
            tree = _parse(path)
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
            violations.append(f"{rel}: cannot be parsed, so this gate cannot clear it")
            continue
        violations += _priority_decisions_outside_if_pri(rel, tree, attributes)
        for node in ast.walk(tree):
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
                        f"{rel}:{d.lineno}: core contains a label-to-level mapping, which "
                        "is a priority table")
    return sorted(set(violations), key=_by_line)


_IN_PLACE_REASON = "values, the request among them, are not altered in place"
# Methods that change a mapping in place.
_MUTATORS = frozenset({"update", "pop", "popitem", "clear", "setdefault", "__setitem__",
                       "__delitem__", "__ior__"})
# VP1-BND-014: the core's own helpers that add to the request before the
# resolver sees it, and nothing else: the location the cell map stands for
# (PLT-ICD-001 2.8) and the initiator's roles (ICD-OP-09).
REQUEST_ENRICHERS = frozenset({"_located", "_with_roles"})
# Where a request is born rather than handed on: the function, and the call
# it is bound from once (IF-IWF map_inbound makes an inbound request).
REQUEST_ORIGINS: Dict[Tuple[str, str], str] = {
    ("core/session.py", "SessionManager.receive_inbound"): "map_inbound"}
# The resolver methods that receive the request.
RESOLVER_REQUEST_METHODS = frozenset({"resolve", "determine_participants"})


def _resolver_method(node) -> bool:
    """`<hooks>.identity_resolver.<method>` for a method that takes the request."""
    return isinstance(node, ast.Attribute) and node.attr in RESOLVER_REQUEST_METHODS and \
        isinstance(node.value, ast.Attribute) and node.value.attr == "identity_resolver"


def _resolve_calls(tree):
    """(call, the request it passes) for every call of a resolver method that
    takes the request: direct (`...identity_resolver.resolve(target,
    request)`) or through the invoker (`invoker.call("IF-IDR", "resolve",
    <method>, target, request, ...)`); the request is the argument after the
    target, or the `request` keyword."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _resolver_method(node.func):
            args = list(node.args)
        else:
            at = next((i for i, a in enumerate(node.args) if _resolver_method(a)), None)
            if at is None:
                continue
            args = list(node.args[at + 1:])
        keyword = next((k.value for k in node.keywords if k.arg == "request"), None)
        yield node, (args[1] if len(args) > 1 else keyword)


def _params(fn) -> List[str]:
    a = fn.args
    return [p.arg for p in a.posonlyargs + a.args + a.kwonlyargs]


def _own_nodes(fn):
    """The nodes of `fn` that are its own: nested functions, lambdas and
    classes left out (their names are their own)."""
    todo = list(ast.iter_child_nodes(fn))
    while todo:
        node = todo.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                                 ast.ClassDef)):
            todo.extend(ast.iter_child_nodes(node))


def _call_name(call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _enrichment(node) -> bool:
    """`request = self.<enricher>(request, ...)`: one of REQUEST_ENRICHERS,
    the core's own method, adding to the request it is given first."""
    v = getattr(node, "value", None)
    return isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(v, ast.Call) and \
        isinstance(v.func, ast.Attribute) and isinstance(v.func.value, ast.Name) and \
        v.func.value.id == "self" and v.func.attr in REQUEST_ENRICHERS and \
        bool(v.args) and isinstance(v.args[0], ast.Name) and v.args[0].id == "request" and \
        _single_request_target(node)


def _born_from(node, origin: str) -> bool:
    """`request = invoker.call(..., "<origin>", ...)`: the request bound from
    the hook operation it is born from."""
    return isinstance(node, (ast.Assign, ast.AnnAssign)) and \
        isinstance(node.value, ast.Call) and _single_request_target(node) and any(
            isinstance(a, ast.Constant) and a.value == origin for a in node.value.args)


def _single_request_target(node) -> bool:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return len(targets) == 1 and isinstance(targets[0], ast.Name) and \
        targets[0].id == "request"


def _rebinds_request(fn, origin: str = "") -> List[ast.AST]:
    """Every place `fn` rebinds or alters its `request` other than through
    the core's adding helpers (`REQUEST_ENRICHERS`) or, in a reviewed origin,
    the one call it is born from: any store to the name (assignment, tuple,
    for, with, comprehension, walrus, del), a store to one of its
    attributes, setattr / object.__setattr__ on it, and vars(request) or
    request.__dict__, which reach its fields. Nested functions and lambdas
    are their own."""
    allowed = {id(n.targets[0] if isinstance(n, ast.Assign) else n.target)
               for n in _own_nodes(fn)
               if _enrichment(n) or (origin and _born_from(n, origin))}
    out = []
    for node in _own_nodes(fn):
        if isinstance(node, ast.Name) and node.id == "request" and \
                isinstance(node.ctx, (ast.Store, ast.Del)) and id(node) not in allowed:
            out.append(node)
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Name) and \
                node.args[0].id == "request" and (
                    isinstance(node.func, ast.Name) and node.func.id in ("setattr", "delattr",
                                                                         "vars")
                    or isinstance(node.func, ast.Attribute) and
                    node.func.attr in ("__setattr__", "__delattr__")):
            out.append(node)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and \
                node.value.id == "request" and (
                    node.attr == "__dict__" or isinstance(node.ctx, (ast.Store, ast.Del))):
            out.append(node)
    return out


def _call_argument(call, fn, name: str):
    """The argument `call` passes for parameter `name` of `fn` (a method:
    the first parameter is bound), or None."""
    params = _params(fn)
    if params and params[0] in ("self", "cls"):
        params = params[1:]
    for k in call.keywords:
        if k.arg == name:
            return k.value
    if name in params and params.index(name) < len(call.args):
        return call.args[params.index(name)]
    return None


def _gets_request(fn) -> bool:
    return fn is not None and not isinstance(fn, ast.Lambda) and "request" in _params(fn)


def check_resolver_receives_context(root: Path) -> List[str]:
    """VP1-BND-014 / PLT-HOK-011 — the whole request reaches the resolver.

    Over every core module, each call of the resolver methods that receive
    the request (`RESOLVER_REQUEST_METHODS`: resolve, determine_participants),
    direct or through the invoker, passes as the request the enclosing
    function's own `request` parameter; that function rebinds or alters
    `request` only through the core's adding helpers (`REQUEST_ENRICHERS`:
    the mapped location, the initiator's roles), never by assignment,
    tuple, for, with, comprehension, setattr or object.__setattr__; and so,
    transitively, does every function of the module that calls it: each
    call passes its caller's own `request`, unrebuilt, or is a reviewed
    origin (`REQUEST_ORIGINS`) binding it once from the call it is born
    from (IF-IWF map_inbound). `vars(request)`, `request.__dict__` and a
    store to one of its attributes count as altering it, and nowhere in
    the core is an object's field table (vars(), __dict__) written to or
    held, so neither an alias nor a helper can alter the request in place
    (object.__setattr__ is VP1-BND-008's). The resolver is
    reached only as `<hooks>.identity_resolver.<method>`, called there or
    handed straight to the invoker; a function that reaches it, and an
    enricher, is referred to only by calling it (not held, not looked up
    with getattr), so every caller is seen. At least one call site exists.
    The trace stays within a module: the service builds the request it
    hands SessionManager, and what reaches the resolver from there is the
    spy tests' to show. A spy-resolver test shows at run time that the
    initiator, call type, application and location arrive as the
    originating request carried them, for a private, a group and an ad hoc
    call by list and by criteria; the enrichers' bodies are left to it.
    """
    violations: List[str] = []
    calls = 0
    for path in _iter_python(root, CORE):
        if any(p in CACHE_DIRS for p in path.parts):
            continue
        rel = path.relative_to(root).as_posix()
        try:
            tree = _parse(path)
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
            violations.append(f"{rel}: cannot be parsed, so this gate cannot clear it")
            continue
        parents = _parent_map(tree)
        for node in ast.walk(tree):
            # The resolver is reached only as `<hooks>.identity_resolver.<method>`,
            # called there or handed straight to the invoker's call.
            held = isinstance(node, ast.Call) and _chain(node.func) == ["getattr"] and \
                len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and \
                node.args[1].value == "identity_resolver"
            if isinstance(node, ast.Attribute) and node.attr == "identity_resolver":
                method = parents.get(node)
                use = parents.get(method)
                held = not (isinstance(method, ast.Attribute) and isinstance(use, ast.Call) and (
                    use.func is method or method in use.args and
                    _chain(use.func)[-1:] == ["call"]))
            if held:
                violations.append(f"{rel}:{node.lineno}: the resolver is held in a name; "
                                  "call it where it is, so its request can be seen")
        # An object's field table, written to or held, alters any value in
        # place, the request among them, whoever holds it under whatever
        # name (`r = request; vars(r).update(...)`, a helper's own argument).
        for node in ast.walk(tree):
            up = parents.get(node)
            if isinstance(node, ast.Name) and node.id == "vars" and \
                    not (isinstance(up, ast.Call) and up.func is node) or \
                    isinstance(node, ast.Call) and _chain(node.func) == ["getattr"] and \
                    len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and \
                    node.args[1].value == "__dict__":
                violations.append(f"{rel}:{node.lineno}: reaches an object's field table "
                                  "through another name; " + _IN_PLACE_REASON)
                continue
            if not (isinstance(node, ast.Call) and _chain(node.func) == ["vars"] or
                    isinstance(node, ast.Attribute) and node.attr == "__dict__"):
                continue
            written = isinstance(up, ast.Attribute) and up.attr in _MUTATORS or \
                isinstance(up, ast.Subscript) and isinstance(up.ctx, (ast.Store, ast.Del)) or \
                isinstance(up, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.Return))
            if written:
                violations.append(f"{rel}:{node.lineno}: writes or holds an object's field "
                                  "table (vars, __dict__); " + _IN_PLACE_REASON)
        reached = []          # functions whose `request` reaches the resolver
        for call, request in _resolve_calls(tree):
            calls += 1
            fn = _enclosing_function(call, parents)
            if not (isinstance(request, ast.Name) and request.id == "request"
                    and _gets_request(fn)):
                violations.append(f"{rel}:{call.lineno}: the resolver is not given the request "
                                  "the function received; it must see the whole request")
                continue
            reached.append(fn)
        done = set()
        while reached:
            fn = reached.pop()
            if id(fn) in done:
                continue
            done.add(id(fn))
            origin = REQUEST_ORIGINS.get((rel, _qualified(fn.body[0], parents)), "")
            for node in _rebinds_request(fn, origin):
                violations.append(f"{rel}:{node.lineno}: the request is rebuilt before the "
                                  "resolver sees it; only the core's adding helpers "
                                  "(REQUEST_ENRICHERS) may change it")
            for call in ast.walk(tree):
                if not isinstance(call, ast.Call):
                    continue
                f = call.func
                callee = f.attr if isinstance(f, ast.Attribute) and \
                    isinstance(f.value, ast.Name) and f.value.id in ("self", "cls") else \
                    f.id if isinstance(f, ast.Name) else None
                if callee != fn.name:
                    continue
                arg = _call_argument(call, fn, "request")
                caller = _enclosing_function(call, parents)
                born = caller is not None and not isinstance(caller, ast.Lambda) and \
                    (rel, _qualified(call, parents)) in REQUEST_ORIGINS
                if not (isinstance(arg, ast.Name) and arg.id == "request"
                        and (_gets_request(caller) or born)):
                    violations.append(f"{rel}:{call.lineno}: {fn.name} reaches the resolver and "
                                      "is not given its caller's request")
                    continue
                reached.append(caller)
        # A function that reaches the resolver, or an enricher, is only
        # called by name: held or looked up, its callers cannot be traced.
        traced = {f.name for f in _functions_of(tree) if id(f) in done} | REQUEST_ENRICHERS
        for node in ast.walk(tree):
            name = node.id if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) \
                else node.attr if isinstance(node, ast.Attribute) else None
            up = parents.get(node)
            if name in traced and not (isinstance(up, ast.Call) and up.func is node):
                violations.append(f"{rel}:{node.lineno}: {name} is referred to other than by "
                                  "a call; its callers must be seen to pass the request")
            if isinstance(node, ast.Call) and _chain(node.func) == ["getattr"] and \
                    len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and \
                    node.args[1].value in traced:
                violations.append(f"{rel}:{node.lineno}: {node.args[1].value} is looked up "
                                  "by name; its callers must be seen to pass the request")
    if calls == 0:
        violations.append("core: no identity_resolver.resolve call site found")
    return sorted(set(violations), key=_by_line)


# --------------------------------------------------------------------------
# VP1-BND-016 — time discipline
# --------------------------------------------------------------------------

# Calls that read or render local time, or make a time with no zone.
LOCAL_TIME_CALLS = frozenset({"localtime", "ctime", "asctime", "strftime", "strptime",
                              "mktime", "tzset", "utcnow", "utcfromtimestamp", "today",
                              "formatTime", "timetuple", "formatdate", "fromisoformat",
                              "fromordinal", "fromisocalendar", "strptime"})
# Rendering a time as text: a time is UTC epoch milliseconds (at_ms), in
# logs and audit records alike.
TIME_AS_TEXT_CALLS = frozenset({"isoformat", "ctime", "strftime", "format_datetime"})
LOCAL_TIME_ATTRIBUTES = frozenset({"timezone", "altzone", "tzname", "daylight"})
# The one place the wall clock is read (service/clock.py, utc_ms).
WALL_CLOCK = "service/clock.py"
# Fields and parameters that carry an RFC or TS wire value counted in
# seconds, so named after it. Nothing else may carry seconds.
WIRE_SECONDS = frozenset({
    ("core/sip.py", "seconds"),             # RFC 4028 Session-Expires, Min-SE
    ("service/session_timer.py", "seconds"),  # RFC 4028 session interval
    ("service/sip_core.py", "seconds"),     # RFC 4028, the refresh in flight
    ("core/rtcp.py", "seconds"),            # TS 24.380 8.2.3.x Floor Indicator duration
})
_SECONDS_NAME = re.compile(r"(?i)^(seconds|secs|sec|.+_(s|sec|secs|seconds))$")
# A name in configuration: a duration states milliseconds; no other unit.
_DURATION_WORD = frozenset({"expires", "expire", "expiry", "timeout", "interval",
                            "duration", "delay", "ttl", "period", "deadline", "lifetime",
                            "grace", "wait", "backoff", "keepalive", "retry", "refresh",
                            "idle", "linger", "lease", "cooldown"})
# A time of day in an audit record: stated in milliseconds too.
_INSTANT_WORD = frozenset({"at", "time", "timestamp", "ts", "when", "since", "until"})
_OTHER_UNITS = frozenset({"s", "sec", "secs", "second", "seconds", "min", "mins",
                          "minute", "minutes", "h", "hr", "hrs", "hour", "hours",
                          "us", "usec", "ns", "d", "day", "days"})
# Where configuration is defined: the environment settings, the profile and
# network schemas, and the dataclasses they are read into.
CONFIG_MODULES = ("service/config.py", "service/network.py", "service/groups.py",
                  "core/validation.py", "core/model.py")
_SETTING = re.compile(r"^MCX_[A-Z0-9_]+$")


# Duration words only as the last word: `ring_timer`, `max_age`, not
# `timer_refresher` or MCX_SESSION_TIMER_MODE.
_TRAILING_DURATION_WORD = frozenset({"timer", "timers", "age", "ages"})


def _config_name_problem(name: str) -> str:
    words = [w for w in name.lower().split("_") if w]
    if not words:
        return ""
    if words[-1] in _OTHER_UNITS:
        return "counts in a unit other than milliseconds"
    if words[-1] in _TRAILING_DURATION_WORD or \
            any(w in _DURATION_WORD for w in words) and words[-1] != "ms":
        return "names a duration without stating milliseconds (_ms)"
    return ""


# PLT-GEN-011 as amended 2026-10-18: a duration in configuration may be
# stated in milliseconds or in seconds; with both, the milliseconds apply and
# a disagreement is reported at startup. A configuration module declares each
# pair in its SECONDS_FORMS mapping, seconds name -> millisecond name.


def _ms_pair(seconds: str, ms: str) -> bool:
    """`ms` is the millisecond form of the seconds name `seconds`:
    no_answer_s/no_answer_ms, timers_s/timers_ms, MCX_X/MCX_X_MS,
    MCX_X_S/MCX_X_MS."""
    if not isinstance(ms, str) or not ms.lower().endswith("_ms"):
        return False
    base = ms[:-3]
    # A setting may name its seconds form without a unit (MCX_SESSION_EXPIRES,
    # the name it had before milliseconds were added); a key states `_s`.
    if base.isupper():
        return seconds in (base, base + "_S")
    return seconds == base + "_s"


def _seconds_forms(trees) -> Dict[str, Tuple[str, str]]:
    """seconds name -> (millisecond name, the module declaring the pair),
    from the SECONDS_FORMS mappings of the configuration modules
    (`CONFIG_MODULES`), each pair well-formed (`_ms_pair`). A mapping
    elsewhere, or a pair not so formed, declares nothing."""
    pairs: Dict[str, Tuple[str, str]] = {}
    for rel, tree in trees:
        if rel not in CONFIG_MODULES:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict) and any(
                    isinstance(t, ast.Name) and t.id == "SECONDS_FORMS" for t in node.targets):
                for k, v in zip(node.value.keys, node.value.values):
                    if isinstance(k, ast.Constant) and isinstance(v, ast.Constant) and \
                            _ms_pair(k.value, v.value):
                        pairs[k.value] = (v.value, rel)
    return pairs


def _paired_fields(cls, declared) -> set:
    """Fields `x_s` of a configuration dataclass that sit beside `x_ms`
    and hold a declared seconds form (`no_answer_s`, `timers_s`;
    `session_expires_s` for MCX_SESSION_EXPIRES): the seconds as stated,
    kept to check against the milliseconds."""
    names = {st.target.id for st in cls.body
             if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name)}
    forms = {d.lower()[len("mcx_"):] if d.startswith("MCX_") else d for d in declared}
    forms |= {f + "_s" for f in forms}
    return {n for n in names if n.endswith("_s") and n[:-2] + "_ms" in names and n in forms}


def _receiver(node) -> str:
    v = node.value
    return v.id if isinstance(v, ast.Name) else v.attr if isinstance(v, ast.Attribute) else ""


def _time_aliases(tree) -> Tuple[set, set]:
    """Names bound to the time module, and to the datetime class (an
    aliased datetime module still reaches the class as `.datetime`)."""
    time_names, datetime_names = {"time"}, {"datetime"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "time":
                    time_names.add(a.asname or a.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "datetime":
            datetime_names.update(a.asname or a.name for a in node.names
                                  if a.name == "datetime")
    # `D = datetime.datetime`, `D = dt`: the class under another name.
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and (
                isinstance(node.value, ast.Attribute) and node.value.attr == "datetime"
                or isinstance(node.value, ast.Name) and node.value.id in datetime_names):
            datetime_names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return time_names, datetime_names


def _utc_names(tree) -> set:
    """Names bound to the UTC zone: `from datetime import UTC`, `UTC =
    datetime.timezone.utc`."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "datetime":
            names.update(a.asname or a.name for a in node.names if a.name == "UTC")
        elif isinstance(node, ast.Assign) and _is_utc(node.value, set()):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def _is_utc(node, utc_names: set) -> bool:
    return isinstance(node, ast.Attribute) and node.attr in ("utc", "UTC") or \
        isinstance(node, ast.Name) and node.id in utc_names


def _zone(call, position: int, keyword: str):
    """The zone given to `call`: its argument at `position` or `keyword`;
    None when not given."""
    if len(call.args) > position:
        return call.args[position]
    return next((k.value for k in call.keywords if k.arg == keyword), None)


def _key_problem(name: str) -> str:
    problem = _config_name_problem(name)
    words = [w for w in name.lower().split("_") if w]
    if not problem and words and words[-1] in _INSTANT_WORD:
        problem = "names a time without stating milliseconds (_ms)"
    return problem


def _audit_keys(call) -> List[Tuple[int, str]]:
    """The detail keys an audit emission writes: its keywords, and the
    string keys of mapping literals among its arguments, at any depth."""
    out = [(call.lineno, k.arg) for k in call.keywords if k.arg]
    for value in list(call.args[2:]) + [k.value for k in call.keywords]:
        for n in ast.walk(value):
            if isinstance(n, ast.Dict):
                out += [(k.lineno, k.value) for k in n.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)]
    return out


def _by_line(v: str):
    path, _, rest = v.partition(":")
    line, _, text = rest.partition(":")
    # The whole message breaks ties, so the order never depends on a set's.
    return (path, int(line) if line.isdigit() else 0, v)


def check_time_discipline(root: Path) -> List[str]:
    """VP1-BND-016 / PLT-GEN-011 — UTC only; durations in milliseconds.

    Over every module the process runs (core/ and service/):
      * no local time is read or rendered: localtime, ctime, asctime,
        strftime, strptime, mktime, utcnow, utcfromtimestamp, today,
        formatTime, formatdate, time.timezone/altzone/tzname, `%(asctime)`
        or `datefmt` in a log format, `localtime=` given; no time rendered
        as text (isoformat, ...): a time is UTC epoch milliseconds;
      * fromisoformat, fromordinal, fromisocalendar refused (zoneless or
        zone-from-text); datetime.now, fromtimestamp, astimezone, combine,
        a datetime constructed and `replace(tzinfo=)` only with the UTC zone (timezone.utc,
        datetime.UTC, a name bound to it): no zone, None, or a fixed offset
        (`timezone(...)`) is refused;
      * the wall clock (time.time) is read in service/clock.py alone, as
        UTC milliseconds;
      * a parameter or field counting seconds is named for the RFC or TS
        wire value it carries (`WIRE_SECONDS`); nothing else does;
      * every environment setting named anywhere (MCX_*), every profile and
        network schema key (in `.keys(allowed=, required=)`, read with
        `.get` or a subscript in the schema modules) and every field of the
        configuration dataclasses (`CONFIG_MODULES`) that is a duration
        ends in `_ms`, and none counts in another unit;
      * every detail key an audit emission writes (`emit`, `emit_or_count`
        keywords and mapping literals) that is a time or a duration ends in
        `_ms`.
    PLT-GEN-011 as amended 2026-10-18: a duration in configuration may be
    stated in seconds as well; a seconds setting or key is exempt in the
    configuration module that declares it beside its millisecond form in
    SECONDS_FORMS (and so handles it), and nowhere else; so is a field
    `x_s` beside `x_ms` of a configuration dataclass holding a declared
    form. Every millisecond setting (MCX_*_MS, in any module) and schema
    key (`*_ms` in `.keys(allowed=)`) must have its seconds form so
    declared. Logs and audit records state milliseconds only.
    Log lines and audit records carry `at_ms` (UTC epoch milliseconds):
    shown at run time by the tests evidencing this case.

    Fails closed on `time.strftime(..., time.gmtime())`, UTC but rendered as
    text all the same.

    Not covered: internal protocol state (`expires_at`, a transaction's
    `interval`, RFC 4028 seconds in `session_expires`), and module
    constants in seconds handed to standard-library calls that count in
    seconds (socket and SQLite timeouts); neither is configuration, a log
    or an audit record. An audit detail built elsewhere and passed whole.
    """
    trees, violations = _runtime_trees(root)
    pairs = _seconds_forms(trees)
    with_seconds = {ms for ms, _ in pairs.values()}

    def add(rel, line, text):
        violations.append(f"{rel}:{line}: {text}")

    for rel, tree in trees:
        # A seconds name is exempt only where its pair is declared, and so
        # handled: read beside its milliseconds, which apply.
        renamed = {k for k, (_, where) in pairs.items() if where == rel}
        time_names, datetime_names = _time_aliases(tree)
        utc = _utc_names(tree)
        config = rel in CONFIG_MODULES
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else \
                    f.id if isinstance(f, ast.Name) else ""
                on_datetime = isinstance(f, ast.Attribute) and _receiver(f) in datetime_names
                zone, what = (None, "")
                if name in LOCAL_TIME_CALLS:
                    add(rel, node.lineno, f"{name}: local or zoneless time")
                elif name in TIME_AS_TEXT_CALLS:
                    add(rel, node.lineno, f"{name}: a time rendered as text; times are "
                                          "UTC epoch milliseconds")
                elif name == "now" and on_datetime:
                    zone, what = _zone(node, 0, "tz"), "datetime.now()"
                elif name == "fromtimestamp":
                    zone, what = _zone(node, 1, "tz"), "fromtimestamp"
                elif name == "astimezone":
                    zone, what = _zone(node, 0, "tz"), "astimezone()"
                elif name in datetime_names and isinstance(f, (ast.Name, ast.Attribute)):
                    zone, what = _zone(node, 7, "tzinfo"), "a datetime"
                elif name == "combine":
                    zone, what = _zone(node, 2, "tzinfo"), "combine()"
                elif name == "replace" and any(k.arg == "tzinfo" for k in node.keywords):
                    zone, what = _zone(node, 99, "tzinfo"), "replace(tzinfo=)"
                elif name == "timezone" and (node.args or node.keywords):
                    add(rel, node.lineno, "a fixed zone: times are UTC")
                if what and zone is None:
                    add(rel, node.lineno, f"{what} without a zone is local or zoneless time")
                elif what and not _is_utc(zone, utc):
                    add(rel, node.lineno, f"{what} with a zone other than UTC")
                for k in node.keywords:
                    if k.arg == "datefmt":
                        add(rel, node.lineno, "datefmt formats local time")
                    if k.arg == "localtime" and not (isinstance(k.value, ast.Constant)
                                                     and k.value.value is False):
                        add(rel, node.lineno, "localtime= renders local time")
                if name in ("emit", "emit_or_count"):
                    for line, key in _audit_keys(node):
                        problem = _key_problem(key)
                        if problem:
                            add(rel, line, f"audit detail {key!r} {problem} (PLT-GEN-011)")
                if config and name == "keys":
                    for k in node.keywords:
                        if k.arg in ("allowed", "required") and \
                                isinstance(k.value, (ast.Tuple, ast.List, ast.Set)):
                            for e in k.value.elts:
                                if isinstance(e, ast.Constant) and isinstance(e.value, str) \
                                        and e.value not in renamed and \
                                        _config_name_problem(e.value):
                                    add(rel, e.lineno, f"schema key {e.value!r} "
                                        f"{_config_name_problem(e.value)} (PLT-GEN-011)")
                                elif isinstance(e, ast.Constant) and \
                                        isinstance(e.value, str) and \
                                        e.value.endswith("_ms") and \
                                        e.value not in with_seconds:
                                    add(rel, e.lineno, f"schema key {e.value!r} has no "
                                        "seconds form in SECONDS_FORMS (PLT-GEN-011)")
                if config and name == "get" and node.args and \
                        isinstance(node.args[0], ast.Constant) and \
                        isinstance(node.args[0].value, str) and \
                        not _SETTING.match(node.args[0].value) and \
                        node.args[0].value not in renamed and \
                        _config_name_problem(node.args[0].value):
                    add(rel, node.lineno, f"schema key {node.args[0].value!r} "
                        f"{_config_name_problem(node.args[0].value)} (PLT-GEN-011)")
            elif isinstance(node, ast.Subscript) and config and \
                    isinstance(node.slice, ast.Constant) and \
                    isinstance(node.slice.value, str) and \
                    not _SETTING.match(node.slice.value) and \
                    node.slice.value not in renamed and \
                    _config_name_problem(node.slice.value):
                add(rel, node.lineno, f"schema key {node.slice.value!r} "
                    f"{_config_name_problem(node.slice.value)} (PLT-GEN-011)")
            elif isinstance(node, ast.Attribute):
                if node.attr in LOCAL_TIME_ATTRIBUTES and _receiver(node) in time_names:
                    add(rel, node.lineno, f"time.{node.attr}: the local zone")
                if node.attr in ("time", "time_ns") and _receiver(node) in time_names and \
                        rel != WALL_CLOCK:
                    add(rel, node.lineno, f"reads the wall clock; it is read in "
                                          f"{WALL_CLOCK} alone (utc_ms)")
            elif isinstance(node, ast.ImportFrom) and node.module == "time" and \
                    rel != WALL_CLOCK:
                add(rel, node.lineno, "imports from time; use time.<name> so the gate "
                                      "can see it")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if "%(asctime)" in node.value or "{asctime}" in node.value:
                    add(rel, node.lineno, "a log format with asctime renders local time")
                if _SETTING.match(node.value) and node.value not in renamed:
                    problem = _config_name_problem(node.value[len("MCX_"):])
                    if problem:
                        add(rel, node.lineno, f"setting {node.value} {problem} "
                                              "(PLT-GEN-011)")
                    elif node.value.endswith("_MS") and node.value not in with_seconds:
                        add(rel, node.lineno, f"setting {node.value} has no seconds "
                                              "form in SECONDS_FORMS (PLT-GEN-011)")
            if isinstance(node, ast.arg) and _SECONDS_NAME.match(node.arg) and \
                    (rel, node.arg) not in WIRE_SECONDS:
                add(rel, node.lineno, f"parameter {node.arg!r} counts seconds; durations "
                                      "are in milliseconds")
            if isinstance(node, ast.ClassDef):
                for stmt in node.body:
                    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                        field_name = stmt.target.id
                        if config and field_name in _paired_fields(node, pairs):
                            continue
                        if _SECONDS_NAME.match(field_name) and \
                                (rel, field_name) not in WIRE_SECONDS:
                            add(rel, stmt.lineno, f"field {field_name!r} counts seconds; "
                                                  "durations are in milliseconds")
                        elif config and _config_name_problem(field_name):
                            add(rel, stmt.lineno, f"configuration field {field_name!r} "
                                f"{_config_name_problem(field_name)} (PLT-GEN-011)")
    return sorted(set(violations), key=_by_line)


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
        if candidate.endswith(".yml"):
            violations += _workflow_escapes(candidate, text)
    return violations


def _workflow_escapes(candidate: str, text: str) -> List[str]:
    """The same ban read from the parsed workflow, so a key spelled any way
    YAML allows (quoted, value on the next line) is still found."""
    import yaml
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"{candidate}: not valid YAML ({exc})"]
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    if not isinstance(jobs, dict):
        return [f"{candidate}: no jobs"]
    found = []
    for name, job in jobs.items():
        blocks = [(f"job {name}", job)]
        if isinstance(job, dict) and isinstance(job.get("steps"), list):
            blocks += [(f"job {name} step {i + 1}", st) for i, st in enumerate(job["steps"])]
        for where, block in blocks:
            if isinstance(block, dict):
                for key in sorted({"if", "continue-on-error"} & set(block)):
                    found.append(f"{candidate}: {where} has {key!r}, a conditional "
                                 "or failure escape")
    return found


# The one way the conformance job may run its suite (RES-OP-08).
CONFORMANCE_RUN = "python3 -m pytest tests/test_conformance.py -q"
CONFORMANCE_ENV = {"MCX_PROFILE": "${{ matrix.profile }}",
                   "MCX_RELEASE": "${{ matrix.release }}"}
CI_ESCAPES = frozenset({"if", "continue-on-error", "services", "container"})
CONFORMANCE_SETUP = [
    {"uses": "actions/checkout@v4"},
    {"uses": "actions/setup-python@v5", "with": {"python-version": "3.11"}},
    {"run": "pip install pyyaml pytest cryptography lxml"},
]
CI_WORKFLOW_ESCAPES = frozenset({"env", "defaults", "concurrency"})
PYTEST_CONFIGS = tuple(f"{d}{n}" for d in ("", "tests/")
                       for n in ("pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini"))
# The section that makes each file a pytest configuration; pytest.ini always is.
PYTEST_SECTIONS = {"pyproject.toml": r"^\s*\[tool\.pytest", "setup.cfg": r"^\s*\[tool:pytest\]",
                   "tox.ini": r"^\s*\[pytest\]"}
CI_TRIGGER_FILTERS = frozenset({"paths", "paths-ignore", "branches", "branches-ignore",
                                "tags", "tags-ignore", "types"})


def check_conformance_matrix(root: Path) -> List[str]:
    """VP1-REL-002 / PLT-REL-007 (RES-OP-08): the CI conformance job runs
    every in-tree profile at every supported release, passes both to the
    suite, and the suite reads both. A matrix that samples releases, or a
    suite that ignores one, leaves combinations nobody ran."""
    import yaml
    violations: List[str] = []
    # The tree's own supported releases, read from core/release.py without
    # running it: the members of `Release`, which SUPPORTED must be all of.
    tree = _parse(root / CORE / "release.py")
    members = [n.value.value for c in tree.body
               if isinstance(c, ast.ClassDef) and c.name == "Release"
               for n in c.body if isinstance(n, ast.Assign)
               and isinstance(n.value, ast.Constant) and type(n.value.value) is int]
    supported_all = any(
        isinstance(n, (ast.Assign, ast.AnnAssign)) and "SUPPORTED" in
        [_target_name(t) for t in (n.targets if isinstance(n, ast.Assign) else [n.target])]
        and ast.unparse(n.value) == "tuple(Release)" for n in tree.body)
    if not members or not supported_all:
        return [f"{CORE}/release.py: SUPPORTED is not every member of Release; "
                "this gate cannot tell which releases CI must run"]
    SUPPORTED = members
    workflow = root / ".github" / "workflows" / "ci.yml"
    if not workflow.is_file():
        return [f"{workflow.relative_to(root)}: not found"]
    try:
        doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"ci.yml: not valid YAML ({exc})"]
    if not isinstance(doc, dict):
        return ["ci.yml: not a workflow"]
    # Every change: no path, branch or tag filter on the triggers. YAML 1.1
    # reads the bare key `on` as True.
    triggers = doc.get("on", doc.get(True))
    if isinstance(triggers, dict):
        for event, spec in triggers.items():
            if event not in ("push", "pull_request"):
                continue
            if spec is not None and not isinstance(spec, dict):
                violations.append(f"ci.yml: on.{event} is not a mapping")
                continue
            for key in sorted(set(spec or {}) & CI_TRIGGER_FILTERS):
                violations.append(f"ci.yml: on.{event} is filtered by {key!r}")
    if not (isinstance(triggers, (list, dict)) and
            {"push", "pull_request"} <= set(triggers)):
        violations.append("ci.yml: does not run on every push and pull request")
    # Settings that reach every job from the top of the workflow: an env or
    # default shell there changes how the suite step runs without touching it.
    for key in sorted(set(doc) & CI_WORKFLOW_ESCAPES):
        violations.append(f"ci.yml: workflow-level {key!r} reaches the conformance job")
    # A pytest configuration file can narrow every combination from outside
    # the workflow.
    violations += _pytest_addopts(root)
    jobs = doc.get("jobs")
    conformance = jobs.get("conformance") if isinstance(jobs, dict) else None
    if not isinstance(conformance, dict):
        return violations + ["ci.yml: no conformance job"]
    strategy = conformance.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict):
        return violations + ["ci.yml conformance matrix is not a literal matrix"]
    if strategy.get("fail-fast") is not False:
        violations.append("ci.yml conformance strategy does not set fail-fast: false; "
                          "one failure would cancel the combinations still running")
    for key in sorted(set(strategy) - {"matrix", "fail-fast"}):
        violations.append(f"ci.yml conformance strategy has {key!r}")
    profiles = sorted(p.parent.name for p in (root / PROFILES).glob("*/profile.yaml"))
    listed = matrix.get("profile")
    if not isinstance(listed, list) or sorted(map(str, listed)) != profiles:
        violations.append(f"ci.yml conformance matrix profiles {listed} "
                          f"are not the in-tree profiles {profiles}")
    releases = matrix.get("release")
    if (not isinstance(releases, list)
            or not all(type(r) is int for r in releases)
            or sorted(releases) != sorted(SUPPORTED)):
        violations.append(f"ci.yml conformance matrix releases {releases} are "
                          f"not the supported releases {sorted(SUPPORTED)}")
    for key in sorted(set(matrix) - {"profile", "release"}):
        violations.append(f"ci.yml conformance matrix excludes or adds combinations ({key})")
    # Nothing on the job or its steps may make a combination conditional or
    # let it fail quietly.
    steps = conformance.get("steps")
    steps = steps if isinstance(steps, list) else []
    for where, block in [("job", conformance)] + [
            (f"step {i + 1}", st) for i, st in enumerate(steps)]:
        if not isinstance(block, dict):
            violations.append(f"ci.yml conformance {where} is not a mapping")
            continue
        for key in sorted(set(block) & CI_ESCAPES):
            violations.append(f"ci.yml conformance {where} has {key!r}")
        if "timeout-minutes" in block and not (
                type(block["timeout-minutes"]) is int and block["timeout-minutes"] > 0):
            violations.append(f"ci.yml conformance {where} has timeout-minutes "
                              f"{block['timeout-minutes']!r}")
    if "env" in conformance or "defaults" in conformance:
        violations.append("ci.yml conformance job sets env or defaults at job level; "
                          "the suite's inputs belong on its step")
    # The steps before the suite are exactly the setup the suite needs: any
    # other step could rewrite its environment, its configuration or pytest.
    if steps[:-1] != CONFORMANCE_SETUP:
        violations.append("ci.yml conformance job's steps before the suite are not "
                          f"exactly {CONFORMANCE_SETUP}")
    # Exactly one step runs the suite, with the matrix's values and nothing
    # that narrows, overrides or swallows the run.
    suite_steps = [st for st in steps if isinstance(st, dict) and (
        "MCX_PROFILE" in (st.get("env") or {}) or "MCX_RELEASE" in (st.get("env") or {})
        or "test_conformance" in str(st.get("run", "")))]
    if len(suite_steps) != 1:
        violations.append(f"ci.yml conformance job has {len(suite_steps)} steps that run "
                          "or configure the suite; exactly one must")
    for st in suite_steps:
        if st.get("env") != CONFORMANCE_ENV:
            violations.append("ci.yml conformance job does not pass the matrix's profile "
                              f"and release to the suite (env {st.get('env')})")
        if str(st.get("run", "")).strip() != CONFORMANCE_RUN:
            violations.append(f"ci.yml conformance step runs {st.get('run')!r}, "
                              f"not {CONFORMANCE_RUN!r}")
        for key in sorted(set(st) - {"name", "env", "run"}):
            violations.append(f"ci.yml conformance step has {key!r}")
    suite = root / TESTS / "test_conformance.py"
    source = suite.read_text(encoding="utf-8") if suite.is_file() else ""
    try:
        reads = {n.args[0].value for n in ast.walk(ast.parse(source))
                 if isinstance(n, ast.Call) and ast.unparse(n.func) == "os.environ.get"
                 and n.args and isinstance(n.args[0], ast.Constant)}
    except SyntaxError:
        reads = set()
    for name in ("MCX_PROFILE", "MCX_RELEASE"):
        if name not in reads:
            violations.append(f"{TESTS}/test_conformance.py does not read {name}")
    return violations


def _pytest_addopts(root: Path) -> List[str]:
    """pytest configuration from outside the workflow (VP1-REL-002): options,
    collection patterns or a collection hook would narrow every combination
    without touching ci.yml. The suite needs none, so any pytest section in a
    config file pytest could read, and any conftest.py above tests/, is
    refused rather than interpreted."""
    found = []
    for name in PYTEST_CONFIGS:
        path = root / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        section = PYTEST_SECTIONS.get(Path(name).name)
        if section is None or re.search(section, text, re.MULTILINE):
            found.append(f"{name}: configures pytest, which every conformance "
                         "combination would run with (addopts, collection patterns)")
    if (root / "conftest.py").is_file():
        found.append("conftest.py: a root conftest can change what every conformance "
                     "combination collects")
    return found


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


RELEASE_MODULE = "core/release.py"
RELEASE_SUITE = "tests/test_release.py"
# The release's own tests: its suite, and the conformance matrix that runs
# every profile at every release (VP1-REL-002), whose per-release
# expectations are literals so they do not merely repeat core/release.py
# (PLT-CONF-AUDIT 4.10).
RELEASE_TESTS = (RELEASE_SUITE, "tests/test_conformance.py")
_NAME_PARTS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_RELEASE_TEXT = re.compile(r"(?i)^\s*(rel(ease)?[-_ ]?|r)?\d+\s*$")
# Building a release from a number outside core/release.py.
_RELEASE_BUILDERS = frozenset({"Release", "parse_release"})
_RELEASE_MEMBER = re.compile(r"^REL_\d+$")
# Every package with Python in it is scanned, and any new top-level one.
_NOT_CODE = frozenset({"docs", "kb", ".git", ".venv"})


def _release_named(name: str) -> bool:
    """`release`, `rel`, `mcx_rel_num`, `cfgRelease`: a word of the name is
    release or rel. Not an all-capitals name: RELEASE is also a floor
    message (TS 24.380 8.2.2) and a SIP state."""
    if not name or name.isupper():
        return False
    return any(p.lower() in ("release", "releases", "rel") for p in _NAME_PARTS.findall(name))


def _release_word(name: str, in_class: bool = False) -> bool:
    """A word of the name is release or rel, capitals included (`MIN_REL`).
    An all-capitals name in a class body (an enum member) counts only with
    REL: RELEASE there is a floor message (TS 24.380 RELEASE_MULTI_TALKER)."""
    words = ("rel",) if in_class and (name or "").isupper() else \
        ("release", "releases", "rel")
    return any(p.lower() in words for p in _NAME_PARTS.findall(name or ""))


def _mentions_release(node) -> bool:
    """An expression whose value is a release: it names one or reads
    MCX_RELEASE, and is not a count (`len(...)`)."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
            node.func.id == "len":
        return False
    for n in ast.walk(node):
        name = n.id if isinstance(n, ast.Name) else n.attr if isinstance(n, ast.Attribute) \
            else n.arg if isinstance(n, ast.keyword) and n.arg else ""
        if _release_named(name) or isinstance(n, ast.Constant) and n.value == "MCX_RELEASE":
            return True
    return False


def _release_constants(tree) -> Tuple[set, set]:
    """Names bound, anywhere in the module, to a number, a numeric string or
    a collection of them (a release held in a constant: `MIN_REL = 19`),
    and names bound to a mapping keyed by them (a release table)."""
    values, tables = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {t.id if isinstance(t, ast.Name) else t.attr for t in targets
                     if isinstance(t, (ast.Name, ast.Attribute))}
            if _release_literal(node.value):
                values |= names
            if isinstance(node.value, ast.Dict) and any(
                    k is not None and _release_literal(k) for k in node.value.keys):
                tables |= names
    return values, tables


def _release_number(node) -> bool:
    """A release-range number (13 to 99), a release string, a collection of
    them, or a table keyed by them."""
    if isinstance(node, ast.Constant):
        v = node.value
        return isinstance(v, int) and not isinstance(v, bool) and 13 <= v <= 99 or \
            isinstance(v, str) and bool(_RELEASE_TEXT.match(v)) and \
            13 <= int(re.sub(r"\D", "", v) or 0) <= 99
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return any(_release_number(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return any(k is not None and _release_number(k) for k in node.keys)
    if isinstance(node, ast.Call):
        return any(_release_number(a) for a in node.args)
    return False


def _named_in(node, names: set) -> bool:
    return isinstance(node, ast.Name) and node.id in names or \
        isinstance(node, ast.Attribute) and node.attr in names


def _release_literal(node) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        node = node.operand
    if isinstance(node, ast.Constant):
        v = node.value
        return (isinstance(v, (int, float)) and not isinstance(v, bool)) or \
            (isinstance(v, (str, bytes)) and bool(_RELEASE_TEXT.match(
                v.decode("latin-1") if isinstance(v, bytes) else v)))
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return any(_release_literal(e) for e in node.elts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
            node.func.id in ("range", "frozenset", "set", "tuple", "list"):
        return any(_release_literal(a) for a in node.args)
    return False


def _python_files(root: Path):
    for path in sorted(root.rglob("*.py")):
        parts = path.relative_to(root).parts
        if parts[0] in _NOT_CODE or any(p in CACHE_DIRS for p in parts):
            continue
        yield path, "/".join(parts)


def check_release_knowledge_is_in_one_module(root: Path) -> List[str]:
    """VP1-BND-022 / PLT-REL-008 — release numbers live in core/release.py.

    A release comparison written inline (`if release >= 19`) is a constant
    nobody will find when the next release lands, and the tables in
    core/release.py were extracted from the specifications while an inline
    literal was not.

    Every Python module in the tree but core/release.py and its own tests
    (`RELEASE_TESTS`) is read as a syntax tree. Refused:
      * a comparison (`<`, `==`, `in`, ...) between an expression naming a
        release (an identifier or attribute with the word release or rel:
        `cfg.release.number`, `int(rel)`, `mcx_rel_num`) and a number, a
        numeric string (`"19"`, `"Rel-19"`), or a collection or range of
        them, whatever the number;
      * a `match` on a release with a numeric case;
      * the same through a name bound to such literals anywhere in the
        module (`MIN_REL = 19; release >= MIN_REL`);
      * a table keyed by release numbers, literal or named, indexed by a
        release (`{17: a}[release]`, `TABLE.get(release)`);
      * a constant or table imported from another module that is one;
      * outside tests/, naming one release (`Release.REL_19`), building one
        from a literal (`Release(19)`, `Release(18 + 1)`, `parse("19")`
        under any name core.release's `parse` is bound to,
        `Release["REL_19"]`), or holding a release-range number (13-99) or
        a table keyed by them in a release-named name (`MIN_REL = 19`).
    A read of MCX_RELEASE is a release; so are "REL_19" and "R19".
    Digits in comments and docstrings are fine: citing a release is how the
    code explains itself. Not recognised: a release held in a name with
    neither word in it or in an all-capitals one (RELEASE is also a floor
    message), reached through getattr or operator functions, compared in
    a match guard, or taken by position from core.release.SUPPORTED. False positives fail closed: a floor-control name with
    the word release (`t_release_ms > 0`), a path named `rel` compared to
    a number, or `rel` meaning relative (`rel_tol = 50`) is refused and must
    be renamed.
    """
    violations: List[str] = []
    modules = []
    for path, rel in _python_files(root):
        if rel == RELEASE_MODULE or rel in RELEASE_TESTS:
            continue
        try:
            modules.append((rel, _parse(path)))
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
            violations.append(f"{rel}: cannot be parsed, so this gate cannot clear it")
    # Release constants and tables of every module, so an import of one is
    # one too (`from .limits import MIN_REL`).
    shared_values, shared_tables = set(), set()
    for rel, tree in modules:
        v, t = _release_constants(tree)
        shared_values |= v
        shared_tables |= t
    for rel, tree in modules:
        values, tables = _release_constants(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    if a.name in shared_values:
                        values.add(a.asname or a.name)
                    if a.name in shared_tables:
                        tables.add(a.asname or a.name)
        release_modules = _module_aliases(tree, rel, "core.release")
        parents = _parent_map(tree)
        builders = set(_RELEASE_BUILDERS)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in ("core.release", "release") \
                    and (node.module == "core.release" or node.level):
                builders.update(a.asname or a.name for a in node.names
                                if a.name in ("Release", "parse"))

        def builder(f):
            return isinstance(f, ast.Name) and f.id in builders or \
                isinstance(f, ast.Attribute) and (
                    f.attr in _RELEASE_BUILDERS or f.attr == "parse" and
                    isinstance(f.value, ast.Name) and f.value.id in release_modules)

        def literal(n):
            # A constant of another module reached as its attribute
            # (`limits.FLOOR`, `Limits.FLOOR`) counts as well.
            return _release_literal(n) or _named_in(n, values) or \
                isinstance(n, ast.Attribute) and n.attr in shared_values

        def table(n):
            return _named_in(n, tables) or \
                isinstance(n, ast.Attribute) and n.attr in shared_tables

        for node in ast.walk(tree):
            hit = ""
            if isinstance(node, ast.Compare):
                sides = [node.left] + node.comparators
                for a, b in zip(sides, sides[1:]):
                    if (_mentions_release(a) and literal(b)) or \
                            (_mentions_release(b) and literal(a)):
                        hit = "release compared to a literal"
            elif isinstance(node, ast.Match) and _mentions_release(node.subject) and any(
                    isinstance(c.pattern, ast.MatchValue) and _release_literal(c.pattern.value)
                    or isinstance(c.pattern, ast.MatchOr) and any(
                        isinstance(p, ast.MatchValue) and _release_literal(p.value)
                        for p in c.pattern.patterns)
                    for c in node.cases):
                hit = "release matched against a literal"
            elif isinstance(node, ast.Subscript) and _mentions_release(node.slice) and (
                    isinstance(node.value, ast.Dict) and
                    any(k is not None and _release_literal(k) for k in node.value.keys)
                    or table(node.value)):
                hit = "a table indexed by release"
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                    node.func.attr == "get" and node.args and \
                    _mentions_release(node.args[0]) and (
                        isinstance(node.func.value, ast.Dict)
                        or table(node.func.value)):
                hit = "a table indexed by release"
            elif not rel.startswith(TESTS + "/") and isinstance(node, ast.Call) and \
                    builder(node.func) and any(
                        isinstance(n, ast.Constant) and _release_literal(n)
                        for a in node.args for n in ast.walk(a)):
                hit = "a release built from a literal"
            elif not rel.startswith(TESTS + "/") and isinstance(node, ast.Subscript) and \
                    builder(node.value) and isinstance(node.slice, ast.Constant) and \
                    isinstance(node.slice.value, str):
                hit = "a release built from a literal"
            elif not rel.startswith(TESTS + "/") and \
                    isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None \
                    and _release_number(node.value) and any(
                        _release_word(t.id if isinstance(t, ast.Name) else t.attr,
                                      isinstance(parents.get(node), ast.ClassDef))
                        for t in (node.targets if isinstance(node, ast.Assign)
                                  else [node.target])
                        if isinstance(t, (ast.Name, ast.Attribute))):
                hit = "a release number held"
            elif not rel.startswith(TESTS + "/") and (
                    isinstance(node, ast.Attribute) and _RELEASE_MEMBER.match(node.attr)
                    or isinstance(node, ast.Name) and _RELEASE_MEMBER.match(node.id)):
                hit = f"names one release ({getattr(node, 'attr', None) or node.id})"
            if hit:
                violations.append(f"{rel}:{node.lineno}: {hit} outside {RELEASE_MODULE}")
    return sorted(set(violations), key=_by_line)


def _skips(decorators) -> bool:
    return any(isinstance(n, ast.Attribute) and n.attr in ("skip", "skipif", "xfail")
               for d in decorators for n in ast.walk(d))


def _suite_problems(tree) -> List[str]:
    """What keeps tests/test_release.py from being the per-release suite."""
    problems = []
    if not any(isinstance(n, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "RELEASES" for t in n.targets)
            and _release_literal(n.value) for n in tree.body):
        problems.append("RELEASES is not written out as literals")
    for n in tree.body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "pytestmark"
                                             for t in n.targets) and _skips([n.value]) or \
                isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and \
                isinstance(n.value.func, ast.Attribute) and n.value.func.attr == "skip":
            problems.append(f"line {n.lineno}: the suite is skipped")
    tests = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and n.name.startswith("test_") and not _skips(n.decorator_list)]
    pinned = any(isinstance(a, ast.Assert) and isinstance(a.test, ast.Compare) and
                 all(isinstance(op, ast.Eq) for op in a.test.ops) and
                 any(_has_name(x, "RELEASES") and not _has_name(x, "SUPPORTED")
                     for x in [a.test.left] + a.test.comparators) and
                 any(_has_name(x, "SUPPORTED") and not _has_name(x, "RELEASES")
                     for x in [a.test.left] + a.test.comparators)
                 for t in tests for a in t.body)
    if not pinned:
        problems.append("RELEASES is not asserted equal to core.release.SUPPORTED in a "
                        "test; a new release would go untested")
    over = [t for t in tests if any(
        isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
        and d.func.attr == "parametrize" and any(_has_name(x, "RELEASES") for x in d.args)
        for d in t.decorator_list)]
    if not over:
        problems.append("no test is parametrised over RELEASES")
    return problems


def check_release_is_a_deployment_parameter(root: Path) -> List[str]:
    """VP1-BND-023 / PLT-REL-002 — MCX_RELEASE is stated, never defaulted.

      * service/config.py reads MCX_RELEASE, and no module the process runs
        reads it with a fallback, defaults it later or gives it a value
        (`setting_fallbacks`, as for MCX_PROFILE); no deployment file outside
        docs/ and tests/ sets it (`deployment_settings`): an image does not
        choose its release;
      * the per-release suite, tests/test_release.py, exists, writes its
        releases as literals (`RELEASES`, PLT-CONF-AUDIT 4.10), asserts them
        equal to core.release.SUPPORTED inside a test, has tests
        parametrised over them, and is not skipped (module-level skip; the
        pin and the parametrised tests not skipped or xfailed), so a release
        added to the platform fails the suite until its expectations are
        written.
    VP1-REL-001's tests and the process-level refusal show it at run time.
    Not followed: a fallback through another function (the run-time test
    covers the configuration path). Not judged: what a test does -- a
    parametrised test whose body is empty, returns early or calls
    pytest.skip, a module-level importorskip, a conftest that drops the
    suite from collection (VP1-REL-002 runs it by path).
    """
    trees, violations = _runtime_trees(root)
    read = False
    for rel, tree in trees:
        for line, what in setting_fallbacks(tree, "MCX_RELEASE"):
            violations.append(f"{rel}:{line}: {what}; a guessed release is silent on "
                              "the wire")
        if rel == "service/config.py":
            read = _reads(tree, "MCX_RELEASE")
    if not read:
        violations.append("service/config.py: the release is not read from the "
                          "environment")
    violations += deployment_settings(
        root, "MCX_RELEASE", "a built image or unit must not choose the release")
    suite = root / RELEASE_SUITE
    if not suite.is_file():
        violations.append(f"no per-release conformance suite ({RELEASE_SUITE})")
        return violations
    try:
        tree = _parse(suite)
    except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
        return violations + [f"{RELEASE_SUITE}: cannot be parsed"]
    return violations + [f"{RELEASE_SUITE}: {p}" for p in _suite_problems(tree)]


def _has_name(node, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name or
               isinstance(n, ast.Attribute) and n.attr == name for n in ast.walk(node))


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
    ("VP1-REL-002", "conformance matrix: every profile at every release",
     check_conformance_matrix),
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
