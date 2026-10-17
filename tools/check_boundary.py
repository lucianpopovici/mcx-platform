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
        "call_types",   # no_answer_s, a timer (SIP-OP-15); signatures (ICD 2.6)
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
