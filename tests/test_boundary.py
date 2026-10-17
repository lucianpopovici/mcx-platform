"""TS-BND — the boundary gates as pytest cases.

PLT-VER-002 requires these to run on every change and produce evidence. The
gate is also a standalone tool (`tools/check_boundary.py`) so it can run in a
pre-commit hook, but the authoritative record is a CI test result.

The last two tests are the ones that matter most: they inject a violation and
assert the gate fails. A gate that has never been seen to fail is not evidence
that the boundary holds — only evidence that the gate is quiet.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

import check_boundary as gate  # noqa: E402


@pytest.mark.parametrize("case,title,fn", gate.CHECKS,
                         ids=[c for c, _, _ in gate.CHECKS])
def test_boundary_case(case, title, fn):
    violations = fn(ROOT)
    assert violations == [], (
        f"{case} ({title}) failed:\n" + "\n".join(f"  {v}" for v in violations))


def test_every_plan_case_has_a_check():
    """The gate must cover exactly the TS-BND cases the plan defines."""
    import re
    plan = (ROOT / "docs" / "PLT-VP-R1.md").read_text(encoding="utf-8")
    planned = set(re.findall(r"VP1-BND-\d{3}", plan))
    implemented = {case for case, _, _ in gate.CHECKS}
    assert planned - implemented == set(), (
        f"plan cases with no check: {sorted(planned - implemented)}")


# --------------------------------------------------------------------------
# The gate must be able to fail
# --------------------------------------------------------------------------


@pytest.mark.vp("VP1-BND-001")
def test_forbidden_term_check_detects_an_injected_violation(tmp_path):
    _stage(tmp_path, core_extra="# a railway-specific note\n")
    violations = gate.check_forbidden_terms(tmp_path)
    assert violations and "railway" in violations[0]


@pytest.mark.vp("VP1-BND-002")
def test_import_check_detects_an_injected_violation(tmp_path):
    _stage(tmp_path, core_extra="from profiles.mcx import hooks\n")
    violations = gate.check_imports(tmp_path)
    assert violations and "profiles.mcx" in violations[0]


@pytest.mark.vp("VP1-BND-003")
def test_hook_call_site_check_detects_an_undeclared_method(tmp_path):
    _tree(tmp_path, {"core/sample.py":
                     "def f(h):\n    return h.priority_policy.recalculate()\n"})
    violations = gate.check_hook_call_sites(tmp_path)
    assert violations and "recalculate" in violations[0]


def test_hot_reload_check_detects_an_injected_watcher(tmp_path):
    _stage(tmp_path, core_extra="import signal\nsignal.signal(1, None)\n")
    violations = gate.check_no_hot_reload(tmp_path)
    assert violations


def test_qos_check_detects_a_literal_in_core(tmp_path):
    _stage(tmp_path, core_extra="qos_identifier = 65\n")
    violations = gate.check_no_qos_mapping_in_core(tmp_path)
    assert violations and "QoS literal" in violations[0]


def test_time_discipline_check_detects_a_local_clock(tmp_path):
    _stage(tmp_path, core_extra="import time\nstamp = time.time()\n")
    violations = gate.check_time_discipline(tmp_path)
    assert violations


def test_frozen_check_detects_a_mutable_value_object(tmp_path):
    _stage(tmp_path)
    hooks = tmp_path / "core" / "hooks.py"
    hooks.write_text(
        "from dataclasses import dataclass\n\n\n"
        "@dataclass\nclass Leaky:\n    x: int = 0\n", encoding="utf-8")
    violations = gate.check_frozen_value_objects(tmp_path)
    assert any("Leaky" in v for v in violations)


REAL_HOOKS = (ROOT / "core" / "hooks.py").read_text(encoding="utf-8")


def _hooks_with(tmp_path, extra="", replace=None):
    _stage(tmp_path)
    text = REAL_HOOKS
    if replace:
        assert replace[0] in text
        text = text.replace(*replace)
    (tmp_path / "core" / "hooks.py").write_text(text + extra, encoding="utf-8")
    return gate.check_frozen_value_objects(tmp_path)


@pytest.mark.vp("VP1-BND-004")
@pytest.mark.parametrize("planted,expect", [
    ("@dataclass\nclass P(Value):\n    x: int = 0\n", "'P' is not frozen"),
    ("@dataclasses.dataclass\nclass P(Value):\n    x: int = 0\n", "'P' is not frozen"),
    ("@dataclasses.dataclass(frozen=False)\nclass P(Value):\n    x: int = 0\n",
     "'P' is not frozen"),
    ("@dataclass(frozen=True)\nclass P:\n    x: int = 0\n", "'P' does not derive from Value"),
    ("class P:\n    x: int = 0\n", "'P' is not a dataclass"),
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: dict = None\n", "P.x is declared dict"),
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: List[str] = ()\n", "P.x is declared List[str]"),
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: Optional[Dict[str, str]] = None\n",
     "a mutable type"),
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: MutableMapping[str, str] = None\n",
     "a mutable type"),
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: Set[str] = ()\n", "a mutable type"),
    # review F2/F3: an alias, a type not known to be immutable, an override
    ("Attrs = Dict[str, str]\n\n\n@dataclass(frozen=True)\nclass P(Value):\n    x: Attrs = None\n",
     "(Attrs)"),
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: Iterable[str] = ()\n", "(Iterable)"),
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: object = None\n", "(object)"),
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: int = 0\n\n"
     "    def __post_init__(self):\n        pass\n", "P defines its own __post_init__"),
    ("@dataclass(frozen=True)\nclass P(FrozenDict):\n    x: int = 0\n",
     "'P' does not derive from Value"),
    # review G2: a shared class attribute, a dunder that changes behaviour,
    # a class hidden under `if`, a dataclass made at runtime
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: int = 0\n    cache = {}\n",
     "P has a class attribute without a declared type"),
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: int = 0\n\n"
     "    def __getattribute__(self, n):\n        return {}\n", "P defines __getattribute__"),
    ("if True:\n    class Q:\n        pass\n", "Q is not a Value"),
    ("P = dataclasses.make_dataclass('P', [('d', dict)], bases=(Value,))\n",
     "P is not a frozen dataclass"),
    ("P = dataclasses.make_dataclass('P', [('d', int)], bases=(Value,), frozen=True,\n"
     "                                namespace={'__post_init__': lambda self: None})\n",
     "P replaces Value.__post_init__"),
    ("@dataclass(frozen=True)\nclass P(Value):\n    x: int = 0\n\n\nP.cache = []\n",
     "P.cache is a mutable list shared by every instance"),
    # review G3: a file that exits must not end the gate run with success
    ("import sys\nsys.exit(0)\n", "cannot be loaded to probe its values"),
])
def test_frozen_check_catches_every_way_a_value_type_can_be_mutable(tmp_path, planted, expect):
    """RES-OP-06: the ways the review found around the old gate, and more."""
    violations = _hooks_with(tmp_path, "\n\n" + planted)
    assert any(expect in v for v in violations), violations


@pytest.mark.vp("VP1-BND-004")
def test_frozen_check_requires_value_to_freeze(tmp_path):
    violations = _hooks_with(tmp_path, replace=("    def __post_init__(self) -> None:",
                                                "    def _unused(self) -> None:"))
    assert any("no `Value` base" in v for v in violations), violations


@pytest.mark.vp("VP1-BND-004")
@pytest.mark.parametrize("change,expect", [
    # a mutator left out of the refusals
    (("    update = pop = popitem = clear = setdefault = _refuse",
      "    pop = popitem = clear = setdefault = _refuse"), "FrozenDict.update changed it"),
    (("    __setitem__ = __delitem__ = __ior__ = _refuse",
      "    __delitem__ = __ior__ = _refuse"), "FrozenDict.__setitem__ changed it"),
    # a def placed after the refusals, shadowing one (names alone pass it)
    (("    @classmethod\n    def fromkeys",
      "    def update(self, *a, **k):\n        dict.update(self, *a, **k)\n\n"
      "    @classmethod\n    def fromkeys"), "FrozenDict.update changed it"),
    # __init__ refilling a live one (RES-OP-06 review F1)
    (("    def __init__(self, *args, **kwargs) -> None:            # filled in __new__\n        pass",
      "    def __init__(self, *args, **kwargs) -> None:\n        dict.__init__(self, *args, **kwargs)"),
     "FrozenDict.__init__ changed it"),
    # Value keeping the name but freezing nothing (review F3)
    (("            object.__setattr__(self, f.name, freeze(value))",
      "            pass"), "Value does not freeze its fields"),
    # freeze() shallow
    (("        return tuple(freeze(v) for v in value)", "        return tuple(value)"),
     "freeze() leaves something mutable inside"),
])
def test_frozen_check_probes_the_values_at_runtime(tmp_path, change, expect):
    violations = _hooks_with(tmp_path, replace=change)
    assert any(expect in v for v in violations), violations


@pytest.mark.vp("VP1-BND-004")
@pytest.mark.parametrize("planted", [
    "@dataclass(frozen=True)\nclass P(Value):\n    x: Mapping[str, str] = field(default_factory=dict)\n",
    "@dataclass(frozen=True)\nclass P(Resolution):\n    y: Sequence[str] = ()\n",
    "@dataclass(frozen=True)\nclass P(Value):\n    y: Optional[Mapping[str, MCServiceId]] = None\n",
    "@dataclass(frozen=True)\nclass P(Value):\n    y: typing.Tuple[int, ...] = ()\n",
    "class P(Protocol):\n    def f(self, x: dict) -> None: ...\n",
    "class P(str, Enum):\n    A = 'a'\n",
])
def test_frozen_check_accepts_what_is_frozen(tmp_path, planted):
    assert _hooks_with(tmp_path, "\n\n" + planted) == []


def test_ci_check_detects_a_missing_profile_suite(tmp_path):
    _stage(tmp_path)
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text("run: pytest\ncheck_boundary\nmcx\n", encoding="utf-8")
    violations = gate.check_ci_runs_both_suites(tmp_path)
    assert any("frmcs" in v for v in violations)


def test_ci_check_detects_a_failure_escape(tmp_path):
    _stage(tmp_path)
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "check_boundary\nmcx\nfrmcs\ncontinue-on-error: true\n", encoding="utf-8")
    violations = gate.check_ci_runs_both_suites(tmp_path)
    assert any("escape" in v for v in violations)


@pytest.mark.parametrize("escape", [
    "    if:\n      false\n", '    "continue-on-error": true\n'])
def test_ci_check_reads_escapes_from_the_parsed_workflow(tmp_path, escape):
    """Review of RES-OP-08: a key YAML allows in another spelling is the
    same escape, whatever the text looks like."""
    _stage(tmp_path)
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text("jobs:\n  t:\n" + escape +
                        "    steps: [{run: check_boundary mcx frmcs}]\n",
                        encoding="utf-8")
    violations = gate.check_ci_runs_both_suites(tmp_path)
    assert any("job t has" in v for v in violations), violations


def _stage(root: Path, core_extra: str = "") -> None:
    """Build a minimal tree the checks can run against."""
    (root / "core").mkdir(parents=True, exist_ok=True)
    (root / "profiles" / "mcx").mkdir(parents=True, exist_ok=True)
    (root / "profiles" / "frmcs").mkdir(parents=True, exist_ok=True)
    (root / "core" / "hooks.py").write_text("", encoding="utf-8")
    (root / "core" / "sample.py").write_text(core_extra, encoding="utf-8")
    for name in ("mcx", "frmcs"):
        (root / "profiles" / name / "profile.yaml").write_text(
            "profile:\n  name: %s\n" % name, encoding="utf-8")


def test_priority_table_check_still_detects_a_real_table(tmp_path):
    """The BND-013 discriminator was sharpened after a false positive on a
    mixed-type defaults dict. Prove it still catches what it is for."""
    _stage(tmp_path, core_extra=(
        "PRIORITY_LEVELS = {\n"
        '    "emergency": 90,\n'
        '    "normal": 20,\n'
        "}\n"))
    violations = gate.check_no_priority_table_in_core(tmp_path)
    assert violations and "priority table" in violations[0]


def test_priority_table_check_ignores_a_mixed_type_defaults_dict(tmp_path):
    """The false positive that prompted the sharpening must stay fixed."""
    _stage(tmp_path, core_extra=(
        "def defaults():\n"
        '    return {"scope": "", "max_level": 0, "may_preempt": False,\n'
        '            "priority_map": ()}\n'))
    assert gate.check_no_priority_table_in_core(tmp_path) == []


# --------------------------------------------------------------------------
# VP1-BND-012 and VP1-BND-009 as amended (PLT-VP-R1 RES-OP-10)
# --------------------------------------------------------------------------


@pytest.mark.vp("VP1-BND-012")
@pytest.mark.parametrize("planted", [
    "qos_default: int = 65\n",                          # an annotated assignment
    "ARP_EMERG, ARP_NORMAL = 1, 9\n",                   # tuple targets
    "table = {'emergency': 65, 'normal': 69}\n",        # a neutral name
    "video, data = 67, 70\n",                          # any MC 5QI, neutral names
    "def f(b):\n    return b.arp_level <= 8\n",         # a comparison
    "def f(make):\n    return make(qos_identifier=69)\n",   # a keyword
    "x = 3\nx += 1\nqci = x * 7\n",                     # arithmetic
], ids=["annotated", "tuple", "neutral-dict", "neutral-mc", "compare", "keyword", "arith"])
def test_the_qos_gate_catches_what_it_used_to_miss(tmp_path, planted):
    """RES-OP-10 review: the gate flagged only `name = <int>` with a QoS name."""
    _stage(tmp_path, core_extra=planted)
    assert gate.check_no_qos_mapping_in_core(tmp_path)


def _qos_module(tmp_path, text):
    _stage(tmp_path)
    (tmp_path / "core" / "qos.py").write_text(text, encoding="utf-8")
    return gate.check_no_qos_mapping_in_core(tmp_path)


@pytest.mark.vp("VP1-BND-012")
def test_core_qos_may_hold_the_ts_23_501_tables_and_nothing_else(tmp_path):
    """The recorded exception: definitions, not a mapping."""
    real = (ROOT / "core" / "qos.py").read_text(encoding="utf-8")
    assert _qos_module(tmp_path, real) == []
    extra = _qos_module(tmp_path, real + "\nEMERGENCY_5QI = 69\n")
    assert extra and "EMERGENCY_5QI" in extra[0]
    mapping = _qos_module(tmp_path, real + "\ndef qos_for(priority):\n    return 65\n")
    assert any("'qos_for' is not one of the lookups" in v for v in mapping)
    assert any("mentions 'priority'" in v for v in mapping)
    # RES-OP-10 review: a mapping that never says "priority".
    by_label = _qos_module(tmp_path, real + "\ndef for_label(label):\n"
                           "    return {'emergency': 65, 'normal': 9}.get(label)\n")
    assert any("'for_label' is not one of the lookups" in v for v in by_label)
    assert _qos_module(tmp_path, real + "\nf = lambda c: 65\n")


@pytest.mark.vp("VP1-BND-012")
@pytest.mark.parametrize("planted", [
    "def letter(c):\n    return 65 <= ord(c) <= 90\n",     # an ASCII range
    "sharp_edge = 9\n",                                  # "arp" inside a word
    "def f(log, x):\n    log.info('x %s', x, stacklevel=2)\n",
], ids=["ascii-compare", "sharp", "stacklevel"])
def test_the_qos_gate_leaves_what_is_not_qos_alone(tmp_path, planted):
    """RES-OP-10 review: false positives the first hardening would raise."""
    _stage(tmp_path, core_extra=planted)
    assert gate.check_no_qos_mapping_in_core(tmp_path) == []


@pytest.mark.vp("VP1-BND-012")
def test_a_line_is_exempt_only_by_being_listed_with_its_reason(tmp_path, monkeypatch):
    """RES-OP-10 re-review: a marker comment anyone could add exempted a line
    unseen. Now an exemption is an entry in the gate, reviewed like any
    other change to it."""
    _stage(tmp_path, core_extra="T_SLOW = 70   # not-qos\n")
    assert gate.check_no_qos_mapping_in_core(tmp_path)          # a comment is nothing
    monkeypatch.setattr(gate, "QOS_REVIEWED_LINES", {
        ("core/sample.py", "T_SLOW = 70   # not-qos"): "a 70 ms timer"})
    assert gate.check_no_qos_mapping_in_core(tmp_path) == []


def _state_machines(tmp_path, rel=None, find=None, replace=None):
    """The real state-machine modules, one of them changed."""
    for name in list(gate.STATE_MACHINE_PROFILE_READS):
        dst = tmp_path / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        text = (ROOT / name).read_text(encoding="utf-8")
        if name == rel:
            assert find in text, find
            text = text.replace(find, replace, 1)
        dst.write_text(text, encoding="utf-8")
    return gate.check_state_machine_ownership(tmp_path)


@pytest.mark.vp("VP1-BND-009")
def test_the_real_state_machines_pass(tmp_path):
    assert _state_machines(tmp_path) == []


@pytest.mark.vp("VP1-BND-009")
@pytest.mark.parametrize("rel,find,replace,expect", [
    # A floor guard on a policy setting that is not a 24.380 parameter.
    ("core/floor.py", "self._policy.override_allowed",
     "self._policy.emergency_override", "'emergency_override' of its policy"),
    # Whatever the variable holding the policy is called.
    ("core/floor.py", "timers_ms=dict(floor_policy.timers_ms),",
     "timers_ms=dict(floor_policy.timers_ms), label=floor_policy.priority_boost,",
     "'priority_boost' of its policy"),
    # The SIP session reading a profile attribute nobody justified.
    ("service/sip_core.py", "runtime.loaded.profile.media.codecs",
     "runtime.loaded.profile.priority.rules", "profile.priority"),
    # Or getting round the list.
    ("service/sip_core.py", "runtime.loaded.profile.media.codecs",
     "getattr(runtime.loaded.profile, 'media').codecs", "through getattr"),
    # A module allowed nothing.
    ("service/sip_txn.py", "from __future__ import annotations",
     "from __future__ import annotations\ndef f(profile):\n    return profile.call_types",
     "profile.call_types"),
    ("core/sip.py", "from __future__ import annotations",
     "from __future__ import annotations\ndef f(lp):\n    return lp.profile.bearer",
     "profile.bearer"),
    # RES-OP-10 review: the session state machine, through self._profile.
    ("core/session.py", "self._profile.admission.reject_reason_codes",
     "self._profile.priority.rules", "profile.priority"),
    # Through an alias.
    ("service/sip_core.py", "self._preference = tuple(",
     "p = runtime.loaded.profile\n        x = p.bearer\n        self._preference = tuple(",
     "profile.bearer"),
    ("service/sip_core.py", "self._preference = tuple(",
     "x = vars(runtime.loaded.profile)\n        self._preference = tuple(",
     "through vars"),
    ("service/media.py", "from __future__ import annotations",
     "from __future__ import annotations\ndef f(rt):\n    return rt.loaded.profile.call_types",
     "profile.call_types"),
    # The floor policy through an alias, getattr, or a new field.
    ("core/floor.py", "        return cls(\n",
     "        pol = floor_policy\n        x = pol.priority_boost\n        return cls(\n",
     "'priority_boost' of its policy"),
    ("core/floor.py", "        return cls(\n",
     "        x = getattr(floor_policy, 'boost')\n        return cls(\n",
     "policy through getattr"),
    ("core/floor.py", "    timers_ms: Mapping[str, int] = field(default_factory=dict)\n",
     "    timers_ms: Mapping[str, int] = field(default_factory=dict)\n    boost: int = 0\n",
     "the floor Policy's fields"),
], ids=["floor-guard", "floor-policy-by-another-name", "sip-core-read", "getattr", "sip-txn",
        "sip-adapter", "session-self-profile", "alias", "vars", "media", "floor-alias",
        "floor-getattr", "floor-new-field"])
def test_the_state_machine_gate_catches_an_unjustified_profile_read(
        tmp_path, rel, find, replace, expect):
    """RES-OP-10 review: the gate covered floor.py only, and a guard driven
    by a policy flag passed."""
    violations = _state_machines(tmp_path, rel, find, replace)
    assert violations and any(expect in v for v in violations), violations


# --------------------------------------------------------------------------
# VP1-REL-002 — the conformance matrix (RES-OP-08)
# --------------------------------------------------------------------------


def _matrix_tree(tmp_path, rel=None, find=None, replace=None):
    files = [".github/workflows/ci.yml", "core/release.py", "tests/test_conformance.py"]
    files += [str(p.relative_to(ROOT)) for p in (ROOT / "profiles").glob("*/profile.yaml")]
    for name in files:
        dst = tmp_path / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        text = (ROOT / name).read_text(encoding="utf-8")
        if name == rel:
            assert find in text, find
            text = text.replace(find, replace, 1)
        dst.write_text(text, encoding="utf-8")
    return gate.check_conformance_matrix(tmp_path)


@pytest.mark.vp("VP1-REL-002")
def test_the_real_matrix_passes(tmp_path):
    assert _matrix_tree(tmp_path) == []


@pytest.mark.vp("VP1-REL-002")
@pytest.mark.parametrize("rel,find,replace,expect", [
    (".github/workflows/ci.yml", "release: [13, 14, 15, 16, 17, 18, 19, 20]",
     "release: [17, 19]", "not the supported releases"),
    (".github/workflows/ci.yml", "profile: [mcx, frmcs, utility]",
     "profile: [mcx, frmcs]", "not the in-tree profiles"),
    (".github/workflows/ci.yml", "release: [13, 14, 15, 16, 17, 18, 19, 20]",
     "release: [13, 14, 15, 16, 17, 18, 19, 20]\n        exclude: [{release: 13}]",
     "excludes or adds"),
    (".github/workflows/ci.yml", "MCX_RELEASE: ${{ matrix.release }}",
     "MCX_RELEASE: 19", "does not pass the matrix"),
    ("tests/test_conformance.py", 'os.environ.get("MCX_RELEASE")',
     'os.environ.get("MCX_REL")', "does not read MCX_RELEASE"),
    ("core/release.py", "    REL_20 = 20\n", "    REL_20 = 20\n    REL_21 = 21\n",
     "not the supported releases"),
    ("core/release.py", "SUPPORTED: Tuple[Release, ...] = tuple(Release)",
     "SUPPORTED: Tuple[Release, ...] = (Release.REL_17, Release.REL_19)",
     "cannot tell which releases"),
    # Review of RES-OP-08: the step's command, the parsed keys and the
    # triggers, not just the matrix.
    (".github/workflows/ci.yml", "run: python3 -m pytest tests/test_conformance.py -q", "run: python3 -m pytest tests/test_conformance.py -q || true", "not 'python3 -m pytest"),
    (".github/workflows/ci.yml", "run: python3 -m pytest tests/test_conformance.py -q", "run: MCX_RELEASE=17 python3 -m pytest tests/test_conformance.py -q",
     "not 'python3 -m pytest"),
    (".github/workflows/ci.yml", "run: python3 -m pytest tests/test_conformance.py -q", "run: python3 -m pytest tests/test_conformance.py -q -k 'not release'", "not 'python3 -m pytest"),
    (".github/workflows/ci.yml", "run: python3 -m pytest tests/test_conformance.py -q", "run: echo skipped", "not 'python3 -m pytest"),
    (".github/workflows/ci.yml", "        run: python3 -m pytest tests/test_conformance.py -q", "        run: python3 -m pytest tests/test_conformance.py -q\n        if:\n          false",
     "step 4 has 'if'"),
    (".github/workflows/ci.yml", "    needs: boundary\n    strategy:",
     '    needs: boundary\n    "continue-on-error": true\n    strategy:',
     "job has 'continue-on-error'"),
    (".github/workflows/ci.yml", "fail-fast: false", "fail-fast: true", "fail-fast: false"),
    (".github/workflows/ci.yml", "on: [push, pull_request]",
     "on:\n  push:\n    paths-ignore: [docs/**]\n  pull_request:",
     "filtered by 'paths-ignore'"),
    (".github/workflows/ci.yml", "release: [13, 14, 15, 16, 17, 18, 19, 20]",
     'release: ["Rel-13", 14, 15, 16, 17, 18, 19, 20]', "not the supported releases"),
    (".github/workflows/ci.yml", "release: [13, 14, 15, 16, 17, 18, 19, 20]",
     "release: ${{ fromJSON(vars.RELEASES) }}", "not the supported releases"),
    (".github/workflows/ci.yml", "      matrix:\n        profile", "      matrix: ${{ fromJSON(vars.M) }}\n      x:\n        profile",
     "not a literal matrix"),
    (".github/workflows/ci.yml", "    needs: boundary\n    strategy:",
     "    needs: boundary\n    env:\n      MCX_RELEASE: 17\n    strategy:", "job level"),
    (".github/workflows/ci.yml", "      - run: pip install pyyaml pytest cryptography lxml\n      # PLT-REL-007",
     "      - run: pip install pyyaml pytest cryptography lxml\n"
     "      - run: python3 -m pytest tests/test_conformance.py -q -k mcx\n      # PLT-REL-007",
     "2 steps that run"),
    ("tests/test_conformance.py", 'os.environ.get("MCX_RELEASE")',
     'os.environ.get("MCX_REL")  # os.environ.get("MCX_RELEASE")', "does not read MCX_RELEASE"),
    (".github/workflows/ci.yml", "        run: python3 -m pytest tests/test_conformance.py -q",
     "        run: python3 -m pytest tests/test_conformance.py -q\n        shell: true {0}",
     "step has 'shell'"),
    # Second review of RES-OP-08: what reaches the suite step from outside it.
    (".github/workflows/ci.yml", "on: [push, pull_request]",
     "on: [push, pull_request]\nenv:\n  PYTEST_ADDOPTS: \"-k 'not release'\"",
     "workflow-level 'env'"),
    (".github/workflows/ci.yml", "on: [push, pull_request]",
     "on: [push, pull_request]\ndefaults: {run: {shell: \"true {0}\"}}",
     "workflow-level 'defaults'"),
    (".github/workflows/ci.yml", "on: [push, pull_request]", "on: {workflow_dispatch: }",
     "every push and pull request"),
    (".github/workflows/ci.yml", "on: [push, pull_request]", "on: {push: }", "every push and pull request"),
    (".github/workflows/ci.yml", "on: [push, pull_request]",
     "on: {push: [paths-ignore], pull_request: }", "on.push is not a mapping"),
    (".github/workflows/ci.yml", "      - run: pip install pyyaml pytest cryptography lxml\n      # PLT-REL-007",
     "      - run: pip install pyyaml pytest cryptography lxml\n"
     "      - run: echo \"PYTEST_ADDOPTS=-k mcx\" >> $GITHUB_ENV\n      # PLT-REL-007",
     "steps before the suite"),
    (".github/workflows/ci.yml", "      - run: pip install pyyaml pytest cryptography lxml\n      # PLT-REL-007",
     "      - run: pip install pyyaml pytest cryptography lxml\n"
     "      - run: printf '[pytest]\\naddopts = -k mcx\\n' > pytest.ini\n      # PLT-REL-007",
     "steps before the suite"),
    (".github/workflows/ci.yml", "      - run: pip install pyyaml pytest cryptography lxml\n      # PLT-REL-007",
     "      - run: pip install pyyaml ./fake-pytest cryptography lxml\n      # PLT-REL-007",
     "steps before the suite"),
    (".github/workflows/ci.yml", "19, 20]\n    steps:\n      - uses: actions/checkout@v4\n",
     "19, 20]\n    steps:\n      - uses: actions/checkout@v4\n        with: {ref: v0.1}\n",
     "steps before the suite"),
    (".github/workflows/ci.yml", "on: [push, pull_request]",
     "on: [push, pull_request]\nconcurrency: {group: ci, cancel-in-progress: true}",
     "workflow-level 'concurrency'"),
], ids=["sampled-releases", "missing-profile", "exclude", "fixed-release",
        "suite-ignores-release", "new-release", "supported-subset",
        "or-true", "inline-override", "deselect", "not-the-suite", "if-next-line",
        "quoted-continue-on-error", "fail-fast", "paths-ignore", "string-release",
        "expression-releases", "expression-matrix", "job-env", "second-step",
        "read-only-in-comment", "step-shell",
        "workflow-env", "workflow-defaults", "dispatch-only", "push-only", "trigger-list",
        "github-env-step", "pytest-ini-step", "fake-pytest", "old-checkout",
        "concurrency"])
def test_the_matrix_gate_fails_when_a_combination_would_go_unrun(
        tmp_path, rel, find, replace, expect):
    """RES-OP-08: CI ran releases 17 and 19 of eight, and the suite ignored
    MCX_RELEASE, so the release axis changed nothing."""
    violations = _matrix_tree(tmp_path, rel, find, replace)
    assert violations and any(expect in v for v in violations), violations


@pytest.mark.vp("VP1-REL-002")
def test_an_unsupported_release_is_an_error_not_a_skip(tmp_path):
    """The suite refuses an MCX_RELEASE it cannot parse at collection, so a
    misconfigured CI job fails instead of passing with nothing run."""
    import os
    import subprocess
    env = dict(os.environ, MCX_RELEASE="12", MCX_PROFILE="mcx")
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        str(ROOT / "tests" / "test_conformance.py")],
                       cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "MCX_RELEASE='12'" in (r.stdout + r.stderr)


@pytest.mark.vp("VP1-REL-002")
def test_a_local_run_of_the_conformance_suite_covers_every_combination(monkeypatch):
    """Unset, each axis is all of its values: a developer's `pytest tests/`
    runs the whole matrix, not one default combination."""
    import importlib
    monkeypatch.delenv("MCX_RELEASE", raising=False)
    monkeypatch.delenv("MCX_PROFILE", raising=False)
    monkeypatch.syspath_prepend(str(ROOT))
    conf = importlib.reload(importlib.import_module("tests.test_conformance"))
    from core.release import SUPPORTED
    assert conf.RELEASES == list(SUPPORTED)
    assert conf.PROFILE_NAMES == sorted(
        p.parent.name for p in (ROOT / "profiles").glob("*/profile.yaml"))


@pytest.mark.vp("VP1-REL-002")
@pytest.mark.parametrize("given", ["13", "20"])
def test_a_ci_job_collects_exactly_its_combination(given):
    """What a CI job collects at MCX_RELEASE=N is the whole suite at Rel-N:
    every test function in the file once, release-parametrised ones at Rel-N
    only. Counted from the file itself, so a filter that drops any test --
    profile or release -- is seen."""
    import ast as _ast
    defined = sorted(n.name for n in _ast.parse(
        (ROOT / "tests" / "test_conformance.py").read_text(encoding="utf-8")).body
        if isinstance(n, _ast.FunctionDef) and n.name.startswith("test_"))
    import os
    import subprocess
    env = dict(os.environ, MCX_RELEASE=given, MCX_PROFILE="frmcs")
    r = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q",
                        "-p", "no:cacheprovider", str(ROOT / "tests" / "test_conformance.py")],
                       cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    ids = [line for line in r.stdout.splitlines() if "::" in line]
    assert sorted(i.split("::")[1].split("[")[0] for i in ids) == defined, ids
    at_release = [i for i in ids if "Rel-" in i]
    assert len(at_release) == 3
    assert all(f"Rel-{given}]" in i and "frmcs" in i for i in at_release), at_release


@pytest.mark.vp("VP1-REL-002")
@pytest.mark.parametrize("name,text", [
    ("pytest.ini", "[pytest]\naddopts = -k mcx\n"),
    ("pytest.ini", "[pytest]\npython_functions = test_profile*\n"),
    ("pyproject.toml", "[tool.pytest.ini_options]\naddopts = \"--deselect x\"\n"),
    ("setup.cfg", "[tool:pytest]\n  addopts=-q -k frmcs\n"),
    ("tox.ini", "[pytest]\naddopts = -m slow\n"),
    ("tests/tox.ini", "[pytest]\naddopts = -k \"not release\"\n"),
    ("tests/setup.cfg", "[tool:pytest]\naddopts = -k \"not release\"\n"),
    ("tests/pytest.ini", "[pytest]\n"),
    ("conftest.py", "def pytest_collection_modifyitems(items):\n    items[:] = items[:1]\n"),
])
def test_a_pytest_config_from_outside_the_workflow_is_refused(tmp_path, name, text):
    """Reviews of RES-OP-08: options, patterns or a collection hook from a
    config file reach every combination without touching ci.yml."""
    assert _matrix_tree(tmp_path) == []
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(text, encoding="utf-8")
    violations = gate.check_conformance_matrix(tmp_path)
    assert any(v.startswith(name + ":") for v in violations), violations


@pytest.mark.vp("VP1-REL-002")
@pytest.mark.parametrize("name,text", [
    ("tox.ini", "[testenv]\ncommands = pytest\n"),
    ("setup.cfg", "[metadata]\nname = x\n"),
    ("pyproject.toml", "[project]\nname = \"x\"\n"),
])
def test_a_config_file_without_a_pytest_section_is_not_refused(tmp_path, name, text):
    assert _matrix_tree(tmp_path) == []
    (tmp_path / name).write_text(text, encoding="utf-8")
    assert gate.check_conformance_matrix(tmp_path) == []


# --------------------------------------------------------------------------
# RES-OP-09 — the variants the TS-BND review got past each gate (batch A:
# VP1-BND-001, 002, 003, 005)
# --------------------------------------------------------------------------


def _tree(tmp_path, files):
    """The real core/hooks.py, core/errors.py and profile.yaml files, plus
    `files` ({relative path: text})."""
    for rel in ("core/hooks.py", "core/errors.py", "core/validation.py", "core/loader.py",
                *[str(p.relative_to(ROOT)) for p in (ROOT / "profiles").glob("*/profile.yaml")]):
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
    for rel, text in files.items():
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(text, encoding="utf-8")
    return tmp_path


@pytest.mark.vp("VP1-BND-001")
@pytest.mark.parametrize("text,term", [
    ("class RailwayProfile:\n    pass\n", "railway"),
    ("TRAINS = 3\n", "train"),
    ("# for dispatchers\n", "dispatcher"),
    ("# GSM-R only\n", "gsmr"),
    ("gsm_r = 1\n", "gsmr"),
    ("track_section = 'a'\n", "track section"),
    ("def trackSection(): pass\n", "track section"),
    ("# P25 interworking\n", "p25"),
    ("MODE = 'utility'\n", "utility"),          # an in-tree profile's name
    ("# frmcs\n", "frmcs"),
], ids=["camel", "plural-upper", "plural", "hyphen", "underscore-join", "snake-phrase",
        "camel-phrase", "p25", "profile-name", "fixed-term"])
def test_bnd_001_catches_the_variants(tmp_path, text, term):
    _tree(tmp_path, {"core/sample.py": text})
    violations = gate.check_forbidden_terms(tmp_path)
    assert any(f"forbidden term {term!r}" in v for v in violations), violations


@pytest.mark.vp("VP1-BND-001")
def test_bnd_001_reads_every_file_under_core(tmp_path):
    _tree(tmp_path, {"core/NOTES.md": "railway notes\n", "core/x.yaml": "k: tetra\n"})
    v = gate.check_forbidden_terms(tmp_path)
    assert any("NOTES.md" in x and "railway" in x for x in v)
    assert any("x.yaml" in x and "tetra" in x for x in v)


@pytest.mark.vp("VP1-BND-001")
@pytest.mark.parametrize("text", [
    "initiator = 1\n", "# trailing text\n", "MCX_RELEASE = 1\n",
    "log = 'mcx.session'\n", "imminent_peril = True\n", "atomic = 1\n",
    "TRAINING = 1\n",
])
def test_bnd_001_leaves_the_platforms_own_words_alone(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert gate.check_forbidden_terms(tmp_path) == []


@pytest.mark.vp("VP1-BND-002")
@pytest.mark.parametrize("text,expect", [
    ("from .. import profiles\n", "core imports 'profiles'"),
    ("from ..profiles import mcx\n", "core imports 'profiles"),
    ("import importlib\nm = importlib.import_module('profiles.mcx.hooks')\n", "dynamic import"),
    ("m = __import__('profiles')\n", "dynamic import"),
    ("from importlib import import_module\nm = import_module(name)\n", "dynamic import"),
    ("P = 'profiles/mcx/hooks.py'\n", "names the profiles package"),
    ("P = 'profiles.mcx'\n", "names the profiles package"),
], ids=["relative", "relative-module", "import_module", "__import__", "bare-import_module",
        "path-string", "module-string"])
def test_bnd_002_catches_the_variants(tmp_path, text, expect):
    _tree(tmp_path, {"core/sample.py": text})
    violations = gate.check_imports(tmp_path)
    assert any(expect in v for v in violations), violations


@pytest.mark.vp("VP1-BND-002")
def test_bnd_002_permits_only_the_loaders_configuration_driven_import(tmp_path):
    loader = ("import importlib\n\ndef _import_symbol(spec):\n"
              "    return importlib.import_module(spec)\n")
    _tree(tmp_path, {"core/loader.py": loader})
    assert gate.check_imports(tmp_path) == []
    # the same call anywhere else, or in a method of that name, is not sanctioned
    _tree(tmp_path, {"core/loader.py": loader.replace("_import_symbol", "elsewhere")})
    assert any("dynamic import" in v for v in gate.check_imports(tmp_path))
    _tree(tmp_path, {"core/loader.py": "import importlib\n\nclass X:\n"
                     "    def _import_symbol(self, n):\n        return importlib.import_module(n)\n"})
    assert any("dynamic import" in v for v in gate.check_imports(tmp_path))
    _tree(tmp_path, {"core/loader.py": loader.replace(
        "importlib.import_module(spec)", "importlib.import_module('profiles.x')")})
    assert any("names the profiles package" in v for v in gate.check_imports(tmp_path))


@pytest.mark.vp("VP1-BND-002")
@pytest.mark.parametrize("text", [
    "from importlib import import_module as im\nm = im(n)\n",
    "import importlib\nim = importlib.import_module\nm = im(n)\n",
    "import importlib\nf = getattr(importlib, 'import_module')\n",
    "exec('import profiles')\n",
    "exec('import ' + 'prof' + 'iles')\n",
    "x = eval(s)\n",
    "import importlib.util\n",
    "import runpy\nrunpy.run_module(n)\n",
    "import pkgutil\npkgutil.resolve_name(spec)\n",
    "import sys\nm = sys.modules[n]\n",
    "f = __builtins__['__import__']\n",
    "import requests\n",
], ids=["alias", "assigned", "getattr", "exec", "exec-concat", "eval", "importlib.util",
        "runpy", "pkgutil", "sys.modules", "builtins", "third-party"])
def test_bnd_002_catches_the_reviews_second_round(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert gate.check_imports(tmp_path), text


@pytest.mark.vp("VP1-BND-002")
@pytest.mark.parametrize("text", [
    "P = f'{root}/profiles/mcx'\n", "P = '/srv/app/profiles/mcx'\n", "P = b'profiles.mcx'\n",
], ids=["f-string", "absolute-path", "bytes"])
def test_bnd_002_finds_profiles_anywhere_in_a_string(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert any("names the profiles package" in v for v in gate.check_imports(tmp_path))


@pytest.mark.vp("VP1-BND-002")
@pytest.mark.parametrize("text", [
    "import re\nx = re.compile('a')\n", "# profiles. are loaded at startup\n",
    "D = 'profiles. are loaded at startup'\n", "import yaml, json, typing\n",
])
def test_bnd_002_leaves_ordinary_code_alone(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert gate.check_imports(tmp_path) == []


@pytest.mark.vp("VP1-BND-003")
@pytest.mark.parametrize("text,expect", [
    ("def f(self):\n    p = self._hooks.session_policy\n    return p.poke()\n",
     "session_policy.poke"),
    ("def f(self):\n    return getattr(self._hooks.session_policy, 'poke')()\n", "getattr"),
    ("def f(self):\n    p = self._hooks.priority_policy\n    return getattr(p, 'x')\n", "getattr"),
    ("def f(h):\n    return h.bearer_selector.reserve()\n", "reserve"),
], ids=["alias", "getattr", "getattr-alias", "undeclared"])
def test_bnd_003_catches_the_variants(tmp_path, text, expect):
    _tree(tmp_path, {"core/sample.py": text})
    violations = gate.check_hook_call_sites(tmp_path)
    assert any(expect in v for v in violations), violations


@pytest.mark.vp("VP1-BND-003")
def test_bnd_003_reads_the_methods_from_the_protocols():
    methods = gate.hook_methods(ROOT)
    assert methods["session_policy"] == {"authorise", "admit", "decide", "floor_policy"}
    assert methods["priority_policy"] == {"evaluate", "compare"}
    assert "determine_participants" in methods["identity_resolver"]


@pytest.mark.vp("VP1-BND-003")
def test_bnd_003_passes_an_alias_used_for_its_declared_methods(tmp_path):
    _tree(tmp_path, {"core/sample.py":
                     "def f(self):\n    p = self._hooks.priority_policy\n"
                     "    return p.evaluate(1), p.compare(1, 2)\n"})
    assert gate.check_hook_call_sites(tmp_path) == []


@pytest.mark.vp("VP1-BND-005")
@pytest.mark.parametrize("text,expect", [
    ("from core import session\n", "core internals 'core'"),
    ("from core import model\n", "core internals 'core'"),          # a module object
    ("import core\n", "core module 'core'"),
    ("import core.hooks as h\n", "core module 'core.hooks'"),
    ("import importlib\nm = importlib.import_module('core.session')\n", "dynamic import"),
    ("import importlib\nm = importlib.import_module('.session', 'core')\n", "dynamic import"),
    ("from importlib import import_module as im\nm = im('core.session')\n", "dynamic import"),
    ("import sys\nm = sys.modules['core'].session\n", "dynamic import"),
    ("exec('from core import session')\n", "dynamic import"),
    ("from core.model import Network\n", "core.model.Network"),
    ("from core.errors import StartupRefused\n", "core.errors.StartupRefused"),
    ("from core.invoke import Invoker\n", "core.invoke"),
    ("S = 'core.loader:startup'\n", "names a core module"),
    ("S = 'core/loader.py'\n", "names a core module"),
], ids=["from-core-module", "from-core-model", "import-core", "import-as", "import_module",
        "import_module-package", "import_module-alias", "sys.modules", "exec", "model-name",
        "error-class", "internal-module", "spec-string", "path-string"])
def test_bnd_005_permits_named_interface_symbols_only(tmp_path, text, expect):
    _tree(tmp_path, {"profiles/mcx/hooks.py": text})
    violations = gate.check_profile_callbacks(tmp_path)
    assert any(expect in v for v in violations), violations


@pytest.mark.vp("VP1-BND-005")
def test_bnd_005_a_profile_module_cannot_launder_a_core_module(tmp_path):
    """The review's blocking finding: `tables.model` was core.model itself.
    A profile now binds no core module, so there is none to re-export."""
    tables = (ROOT / "profiles/common/tables.py").read_text(encoding="utf-8")
    _tree(tmp_path, {"profiles/common/tables.py": tables,
                     "profiles/mcx/hooks.py":
                     "from profiles.common import tables\nx = tables.model.Network\n"})
    assert gate.check_profile_callbacks(tmp_path) == []        # nothing to reach through
    assert "from core import model" not in tables


@pytest.mark.vp("VP1-BND-005")
def test_bnd_005_core_attribute_keys_are_not_modules(tmp_path):
    _tree(tmp_path, {"profiles/mcx/hooks.py": "K = 'core.active_sessions'\n"})
    assert gate.check_profile_callbacks(tmp_path) == []


@pytest.mark.vp("VP1-BND-005")
def test_bnd_005_a_hook_spec_must_name_the_profiles_own_package(tmp_path):
    yaml_text = (ROOT / "profiles/mcx/profile.yaml").read_text(encoding="utf-8")
    import re
    planted = re.sub(r"(\n\s+session_policy:\s*)\S+", r"\1core.session:SessionManager",
                     yaml_text, count=1)
    assert planted != yaml_text
    _tree(tmp_path, {"profiles/mcx/profile.yaml": planted})
    assert any("hook session_policy names 'core.session:SessionManager'" in v
               for v in gate.check_profile_callbacks(tmp_path))


@pytest.mark.vp("VP1-BND-005")
@pytest.mark.parametrize("name", ["profiles/mcx/x.cpython-311-x86_64-linux-gnu.so",
                                  "profiles/mcx/x.pyc"])
def test_bnd_005_refuses_a_compiled_module(tmp_path, name):
    _tree(tmp_path, {name: ""})
    assert any("compiled module" in v for v in gate.check_profile_callbacks(tmp_path))


@pytest.mark.vp("VP1-BND-005")
def test_bnd_005_reports_a_file_it_cannot_parse(tmp_path):
    _tree(tmp_path, {"profiles/mcx/hooks.py": "def (:\n"})
    assert any("does not parse" in v for v in gate.check_profile_callbacks(tmp_path))


@pytest.mark.vp("VP1-BND-005")
def test_bnd_005_permits_what_the_in_tree_tables_use(tmp_path):
    _tree(tmp_path, {"profiles/common/tables.py":
                     (ROOT / "profiles/common/tables.py").read_text(encoding="utf-8")})
    assert gate.check_profile_callbacks(tmp_path) == []
    permitted = gate.profile_permitted(ROOT)
    assert permitted["core.model"] == {"Profile", "CallType", "FunctionalIdentity",
                                       "BearerDecisionSpec"}
    assert {"HookContractViolation", "PlatformError", "UNKNOWN_TARGET"} <= \
        permitted["core.errors"]
    assert {"FloorPolicy", "SessionRequest", "MediaKind"} <= permitted["core.hooks"]



@pytest.mark.vp("VP1-BND-001")
@pytest.mark.parametrize("text,term", [
    ("railwayprofile = 1\n", "railway"), ("RAILWAYPROFILE = 1\n", "railway"),
    ("frmcsmode = 1\n", "frmcs"), ("tracksection = 1\n", "track section"),
    ("publicsafety = 1\n", "public safety"), ("# utilities\n", "utility"),
    ("\uff52ailway = 1\n", "railway"),           # fullwidth r: NFKC reads it as "railway"
], ids=["lower-compound", "upper-compound", "profile-compound", "phrase-joined",
        "phrase-joined-2", "ies-plural", "fullwidth"])
def test_bnd_001_second_round_variants(tmp_path, text, term):
    _tree(tmp_path, {"core/sample.py": text})
    assert any(f"forbidden term {term!r}" in v for v in gate.check_forbidden_terms(tmp_path))


@pytest.mark.vp("VP1-BND-001")
@pytest.mark.parametrize("rel,term", [("core/railway_rules.py", "railway"),
                                      ("core/frmcs/__init__.py", "frmcs")])
def test_bnd_001_reads_file_and_package_names(tmp_path, rel, term):
    _tree(tmp_path, {rel: "x = 1\n"})
    assert any("in the file's name" in v and term in v
               for v in gate.check_forbidden_terms(tmp_path))


@pytest.mark.vp("VP1-BND-001")
@pytest.mark.parametrize("content", [b"\x00\x01", "railway".encode("utf-16-le"), b"\xff\xfe"],
                         ids=["nul", "utf16", "not-utf8"])
def test_bnd_001_refuses_a_file_that_is_not_text(tmp_path, content):
    _tree(tmp_path, {})
    (tmp_path / "core" / "blob.dat").write_bytes(content)
    assert any("blob.dat" in v and "not text" in v for v in gate.check_forbidden_terms(tmp_path))


@pytest.mark.vp("VP1-BND-001")
def test_bnd_001_refuses_a_non_ascii_identifier(tmp_path):
    _tree(tmp_path, {"core/sample.py": "r\u0430ilway = 1\n"})     # Cyrillic a
    assert any("non-ASCII identifier" in v for v in gate.check_forbidden_terms(tmp_path))


@pytest.mark.vp("VP1-BND-001")
@pytest.mark.parametrize("text", [
    "x = a.to_bytes(2, 'big')\n", "# map a to b\n", "def a_to_b(x): pass\n",
    "s = 'From A To B'\n", "# Tr Ains\n", "# et cs\n", "# a constraint\n",
    "# a guardrail\n",
])
def test_bnd_001_does_not_join_words_across_spaces_or_dots(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert gate.check_forbidden_terms(tmp_path) == []


@pytest.mark.vp("VP1-BND-001")
def test_bnd_001_skips_caches_and_dotfiles(tmp_path):
    _tree(tmp_path, {})
    for rel in ("core/.mypy_cache/x.json", "core/.sample.py.swp", "core/__pycache__/a.pyc"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_bytes(b"\x00railway")
    assert gate.check_forbidden_terms(tmp_path) == []


H = "self._hooks.session_policy"


@pytest.mark.vp("VP1-BND-003")
@pytest.mark.parametrize("text,expect", [
    (f"def f(self):\n    p, q = {H}, 1\n    return p.poke()\n", "session_policy.poke"),
    (f"def f(self):\n    (p,) = ({H},)\n    return p.poke()\n", "session_policy.poke"),
    (f"def f(self):\n    p = {H}\n    q = p\n    return q.poke()\n", "session_policy.poke"),
    (f"class C:\n    def __init__(self):\n        self._sp = {H}\n"
     "    def g(self):\n        return self._sp.poke()\n", "session_policy.poke"),
    (f"def f(self):\n    for p in ({H},):\n        p.poke()\n", "session_policy.poke"),
    (f"def f(self):\n    return [p.poke() for p in ({H},)]\n", "session_policy.poke"),
    (f"def f(self):\n    g = lambda p={H}: p.poke()\n", "session_policy.poke"),
    ("def f(self):\n    return getattr(self._hooks, 'session_policy').poke()\n",
     "the hook bundle"),
    ("def f(self):\n    return vars(self._hooks)['session_policy']\n", "the hook bundle"),
], ids=["tuple", "tuple-paren", "alias-of-alias", "self-attribute", "for", "comprehension",
        "lambda-default", "getattr-bundle", "vars-bundle"])
def test_bnd_003_second_round_variants(tmp_path, text, expect):
    _tree(tmp_path, {"core/sample.py": text})
    assert any(expect in v for v in gate.check_hook_call_sites(tmp_path))


@pytest.mark.vp("VP1-BND-003")
def test_bnd_003_an_alias_is_scoped_to_its_function(tmp_path):
    """No false positive: a name bound to a hook in one method and to
    something else in another."""
    _tree(tmp_path, {"core/sample.py":
                     f"class C:\n    def a(self):\n        policy = {H}\n"
                     "        return policy.decide(1)\n"
                     "    def b(self, policy):\n        return policy.max_queue_depth\n"})
    assert gate.check_hook_call_sites(tmp_path) == []


@pytest.mark.vp("VP1-BND-003")
def test_bnd_003_the_loader_table_must_match_the_protocols(tmp_path):
    loader = (ROOT / "core/loader.py").read_text(encoding="utf-8")
    assert '("evaluate", "compare")' in loader
    _tree(tmp_path, {"core/loader.py": loader.replace('("evaluate", "compare")',
                                                      '("evaluate",)')})
    assert any("HOOK_INTERFACES" in v for v in gate.check_hook_call_sites(tmp_path))


@pytest.mark.vp("VP1-BND-003")
def test_bnd_003_fails_closed_without_the_hook_definitions(tmp_path):
    _stage(tmp_path)
    assert any("could not be read" in v for v in gate.check_hook_call_sites(tmp_path))


# -- third round (review of batch A, round 2)


@pytest.mark.vp("VP1-BND-001")
@pytest.mark.parametrize("text,term", [
    ("TRAINID = 1\n", "train"), ("traindriver = 1\n", "train"), ("railnet = 1\n", "rail"),
    ("# ra­ilway\n", "railway"), ("# railwaý\n", "railway"),
], ids=["trainid", "traindriver", "railnet", "soft-hyphen", "combining-accent"])
def test_bnd_001_third_round_variants(tmp_path, text, term):
    _tree(tmp_path, {"core/sample.py": text})
    assert any(f"forbidden term {term!r}" in v for v in gate.check_forbidden_terms(tmp_path))


@pytest.mark.vp("VP1-BND-001")
@pytest.mark.parametrize("text", ["# rаilway\n", "X = 'rаilway'\n"],
                         ids=["comment", "string"])
def test_bnd_001_refuses_a_word_mixing_scripts(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert any("mixes ASCII and other letters" in v for v in gate.check_forbidden_terms(tmp_path))


@pytest.mark.vp("VP1-BND-001")
def test_bnd_001_reads_dotfiles_and_refuses_non_ascii_names(tmp_path):
    _tree(tmp_path, {"core/.railway.py": "x = 1\n", "core/rаil.py": "x = 1\n"})
    v = gate.check_forbidden_terms(tmp_path)
    assert any(".railway.py" in x and "railway" in x for x in v)
    assert any("non-ASCII file name" in x for x in v)


@pytest.mark.vp("VP1-BND-001")
@pytest.mark.parametrize("text", ["# a strained link\n", "# trailing\n", "# constraint\n",
                                  "# training data\n", "x = handrail\n"])
def test_bnd_001_inside_word_exceptions(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert gate.check_forbidden_terms(tmp_path) == []


@pytest.mark.vp("VP1-BND-002")
@pytest.mark.parametrize("text", [
    "from sys import modules\nm = modules[n]\n", "import sys as s\nm = s.modules[n]\n",
    "import builtins\nf = getattr(builtins, '__import__')\n", "import pydoc\nx = pydoc.locate(n)\n",
    "import pickle\n", "import logging.config\n", "x = __spec__.loader\n",
    "x = f.__globals__\n", "x = h.authorise.__self__\n", "g = globals()\n",
], ids=["from-sys", "sys-as", "builtins", "pydoc", "pickle", "logging.config", "__spec__",
        "__globals__", "__self__", "globals"])
def test_bnd_002_third_round_variants(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert gate.check_imports(tmp_path), text


@pytest.mark.vp("VP1-BND-002")
@pytest.mark.parametrize("text", ["P = '../profiles'\n", "P = '/srv/profiles'\n",
                                  "P = 'profiles\\\\mcx'\n", "P = 'Profiles/mcx'\n"])
def test_bnd_002_path_strings_ending_in_profiles(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert any("names the profiles package" in v for v in gate.check_imports(tmp_path))


@pytest.mark.vp("VP1-BND-003")
@pytest.mark.parametrize("text", [
    f"def f(self, x):\n    p = {H} if x else None\n    return p\n",
    f"def f(self, d):\n    p = {H} or d\n",
    f"def f(self):\n    ps = [{H}]\n    return ps[0].poke()\n",
    f"def f(self):\n    return ({H},)[0]\n",
    "def f(self):\n    h = self._hooks\n    return getattr(h, 'session_policy').poke()\n",
    "def f(self):\n    return self._hooks.__dict__['session_policy']\n",
    f"def f(self):\n    g = getattr\n    return g({H}, 'poke')\n",
    f"def f(self, other):\n    return other(self._hooks.session_policy)\n",
], ids=["ifexp", "or", "list", "tuple-subscript", "bundle-alias", "bundle-dict",
        "getattr-alias", "passed-as-argument"])
def test_bnd_003_only_known_shapes_pass(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert gate.check_hook_call_sites(tmp_path), text


@pytest.mark.vp("VP1-BND-003")
def test_the_core_sees_a_hook_through_its_protocol_only():
    """VP1-BND-003 at run time: whatever route core code takes, an undeclared
    method of a hook is not there; the declared ones are the hook's own."""
    from core import loader
    from core.audit import Auditor, MemorySink
    from core.session import SessionManager
    loaded = loader.load(ROOT / "profiles" / "mcx")
    raw = loaded.hooks.identity_resolver
    assert hasattr(raw, "register_group")                    # provisioning, not IF-IDR
    mgr = SessionManager(loaded, Auditor(MemorySink(), "p"))
    view = mgr._hooks.identity_resolver
    with pytest.raises(AttributeError, match="declares no 'register_group'"):
        view.register_group
    # nothing on the view, nor a method's __self__, is the hook itself
    for route in (lambda: view._target, lambda: getattr(view, "_target"),
                  lambda: view.resolve.__self__):
        with pytest.raises(AttributeError):
            route()
    with pytest.raises(AttributeError):
        view.resolve = None
    assert sorted(dir(view)) == sorted(gate.hook_methods(ROOT)["identity_resolver"])


@pytest.mark.vp("VP1-BND-005")
@pytest.mark.parametrize("text,expect", [
    ("from service.config import Release\n", "service.config"),
    ("import service.config as sc\n", "service.config"),
    ("from tools import check_boundary\n", "'tools'"),
    ("from sys import modules\n", "'sys'"),
    ("import inspect\n", "'inspect'"),
    ("from core.hooks import freeze\nx = freeze.__globals__\n", "__globals__"),
    ("from core.hooks import SessionRequest\nm = SessionRequest.__module__\n", "__module__"),
], ids=["service-config", "service-as", "tools", "sys", "inspect", "__globals__", "__module__"])
def test_bnd_005_third_round_variants(tmp_path, text, expect):
    _tree(tmp_path, {"profiles/mcx/hooks.py": text})
    assert any(expect in v for v in gate.check_profile_callbacks(tmp_path))


@pytest.mark.vp("VP1-BND-005")
def test_bnd_005_super_init_is_fine(tmp_path):
    _tree(tmp_path, {"profiles/mcx/hooks.py":
                     "class A(object):\n    def __init__(self):\n        super().__init__()\n"})
    assert gate.check_profile_callbacks(tmp_path) == []


@pytest.mark.vp("VP1-BND-005")
def test_bnd_005_the_main_module_guard_is_fine(tmp_path):
    _tree(tmp_path, {"profiles/mcx/hooks.py":
                     "if __name__ == '__main__':\n    pass\n"})
    assert gate.check_profile_callbacks(tmp_path) == []
    _tree(tmp_path, {"profiles/mcx/hooks.py": "x = f.__name__\nimport __main__\n"})
    assert gate.check_profile_callbacks(tmp_path) == [
        "profiles/mcx/hooks.py:1: profile uses __name__; interpreter internals reach past "
        "the named imports",
        "profiles/mcx/hooks.py:2: profile imports '__main__'; a profile imports the standard "
        "library, profiles and named core symbols only"]



@pytest.mark.vp("VP1-BND-002")
@pytest.mark.parametrize("text", [
    "def f(self):\n    m = self._hooks.session_policy.authorise\n"
    "    return getattr(m, '__self__').poke()\n",
    "import operator\nx = operator.attrgetter('__globals__')\n",
], ids=["getattr-self-string", "attrgetter-string"])
def test_bnd_002_refused_names_as_strings(tmp_path, text):
    _tree(tmp_path, {"core/sample.py": text})
    assert any("as a string" in v for v in gate.check_imports(tmp_path))


@pytest.mark.vp("VP1-BND-005")
@pytest.mark.parametrize("text,expect", [
    ("from core.hooks import freeze\nx = getattr(freeze, '__globals__')\n", "__globals__"),
    ("import operator\nx = operator.attrgetter('__globals__')\n", "__globals__"),
    ("from core.model import Profile\nx = vars(Profile)\n", "vars()"),
], ids=["getattr-string", "attrgetter", "vars"])
def test_bnd_005_refused_names_as_strings(tmp_path, text, expect):
    _tree(tmp_path, {"profiles/mcx/hooks.py": text})
    assert any(expect in v for v in gate.check_profile_callbacks(tmp_path))


@pytest.mark.vp("VP1-BND-003")
def test_a_hook_patched_after_the_view_was_made_is_the_one_called(monkeypatch):
    from core import loader
    from core.audit import Auditor, MemorySink
    from core.session import SessionManager
    loaded = loader.load(ROOT / "profiles" / "mcx")
    mgr = SessionManager(loaded, Auditor(MemorySink(), "p"))
    monkeypatch.setattr(loaded.hooks.priority_policy, "compare", lambda a, b: 42)
    assert mgr._hooks.priority_policy.compare(1, 2) == 42
    assert mgr._hooks.priority_policy.compare.__name__ == "compare"
