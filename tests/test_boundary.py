"""TS-BND — the boundary gates as pytest cases.

PLT-VER-002 requires these to run on every change and produce evidence. The
gate is also a standalone tool (`tools/check_boundary.py`) so it can run in a
pre-commit hook, but the authoritative record is a CI test result.

The last two tests are the ones that matter most: they inject a violation and
assert the gate fails. A gate that has never been seen to fail is not evidence
that the boundary holds — only evidence that the gate is quiet.
"""

from __future__ import annotations

import re
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


def test_qos_check_detects_a_literal_in_core(tmp_path):
    _stage(tmp_path, core_extra="qos_identifier = 65\n")
    violations = gate.check_no_qos_mapping_in_core(tmp_path)
    assert violations and "QoS literal" in violations[0]


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
    # Parameter order inside the id is pytest's choice, not ours: compare the
    # parts, so "frmcs-Rel-13" and "Rel-13-frmcs" both pass and "Rel-130" does not.
    params = [i.split("[", 1)[1].rstrip("]").replace(f"Rel-{given}", "<rel>")
              for i in at_release]
    assert all(sorted(p.split("-")) == ["<rel>", "frmcs"] for p in params), at_release


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


# --------------------------------------------------------------------------
# RES-OP-09 batch B: VP1-BND-007, 008, 016, 022, 023 against planted variants
# --------------------------------------------------------------------------

_RUNTIME_COPY = ("core", "service")


def _runtime(tmp_path, files=None, patches=None, drop=()):
    """A copy of the process (core/, service/), the profile packages'
    profile.yaml, the release suite and the release image file, with
    `files` added, `patches` ({path: (old, new)}) applied and `drop` removed."""
    import shutil
    for pkg in _RUNTIME_COPY:
        shutil.copytree(ROOT / pkg, tmp_path / pkg,
                        ignore=shutil.ignore_patterns("__pycache__"))
    for rel in ("tests/test_release.py", "tools/release.Containerfile",
                *[str(p.relative_to(ROOT)) for p in (ROOT / "profiles").glob("*/profile.yaml")]):
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
    for rel, (old, new) in (patches or {}).items():
        path = tmp_path / rel
        text = path.read_text(encoding="utf-8")
        assert text.count(old) == 1, (rel, old)
        path.write_text(text.replace(old, new), encoding="utf-8")
    for rel, text in (files or {}).items():
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(text, encoding="utf-8")
    for rel in drop:
        (tmp_path / rel).unlink()
    return tmp_path


@pytest.mark.vp("VP1-BND-007", "VP1-BND-008", "VP1-BND-016", "VP1-BND-023")
@pytest.mark.parametrize("fn", [gate.check_no_default_profile, gate.check_no_hot_reload,
                                gate.check_time_discipline,
                                gate.check_release_knowledge_is_in_one_module,
                                gate.check_release_is_a_deployment_parameter],
                         ids=["007", "008", "016", "022", "023"])
def test_batch_b_gates_pass_the_unchanged_copy(tmp_path, fn):
    assert fn(_runtime(tmp_path)) == []


def _lines(root, expected):
    """`expected` with each {L:<text>} replaced by the number of the first
    line of that entry's file containing <text>."""
    def one(entry):
        rel = entry.split(":", 1)[0]
        def num(m):
            text = (root / rel).read_text(encoding="utf-8").splitlines()
            return str(next(n for n, l in enumerate(text, 1) if m.group(1) in l))
        return re.sub(r"\{L:(.+?)\}", num, entry)
    return [one(e) for e in expected]


_ENV_SAMPLE = "import os\nenv = os.environ\nok = True\n"


@pytest.mark.vp("VP1-BND-007")
@pytest.mark.parametrize("files,patches,expected", [
    ({}, {"service/config.py": ('env.get("MCX_PROFILE", "")', 'env.get("MCX_PROFILE", "mcx")')},
     ["service/config.py:{L:raw_profiles =}: MCX_PROFILE is read with a fallback value; the profile is "
      "stated or the process does not start",
      "service/config.py:{L:raw_profiles =}: defaults to the profile 'mcx'"]),
    ({}, {"service/config.py": ('env.get("MCX_PROFILE", "")', 'env.get("MCX_PROFILE","x")')},
     ["service/config.py:{L:raw_profiles =}: MCX_PROFILE is read with a fallback value; the profile is "
      "stated or the process does not start"]),
    ({"core/sample.py": _ENV_SAMPLE + 'x = os.environ.get("MCX_PROFILE") or "mcx"\n'}, {},
     ["core/sample.py:4: MCX_PROFILE is read with a fallback value; the profile is stated "
      "or the process does not start", "core/sample.py:4: defaults to the profile 'mcx'"]),
    ({"core/sample.py": _ENV_SAMPLE + 'x = os.getenv("MCX_PROFILE", default="x").strip()\n'},
     {}, ["core/sample.py:4: MCX_PROFILE is read with a fallback value; the profile is "
          "stated or the process does not start"]),
    ({"service/sample.py": _ENV_SAMPLE + 'KEY = "MCX_PROFILE"\nx = env.get(KEY, "y")\n'}, {},
     ["service/sample.py:5: MCX_PROFILE is read with a fallback value; the profile is "
      "stated or the process does not start"]),
    ({"service/sample.py": _ENV_SAMPLE + 'def f():\n    raw = env.get("MCX_PROFILE")\n'
      '    if not raw:\n        raw = "y"\n    return raw\n'}, {},
     ["service/sample.py:7: MCX_PROFILE is given a fallback value through 'raw'; the "
      "profile is stated or the process does not start"]),
    ({"service/sample.py": _ENV_SAMPLE + 'def f():\n    raw = env.get("MCX_PROFILE")\n'
      '    return raw.strip() or "y"\n'}, {},
     ["service/sample.py:6: MCX_PROFILE is given a fallback value through 'raw'; the "
      "profile is stated or the process does not start"]),
    ({"service/sample.py": _ENV_SAMPLE + 'x = env.get("MCX_PROFILE") if ok else "y"\n'}, {},
     ["service/sample.py:4: MCX_PROFILE is read with a fallback value; the profile is "
      "stated or the process does not start"]),
    ({"service/sample.py": _ENV_SAMPLE + 'os.environ.setdefault("MCX_PROFILE", "y")\n'}, {},
     ["service/sample.py:4: MCX_PROFILE is given a value (setdefault); the profile is "
      "stated or the process does not start"]),
    ({"service/sample.py": _ENV_SAMPLE + 'os.environ["MCX_PROFILE"] = "y"\n'}, {},
     ["service/sample.py:4: MCX_PROFILE is given a value; the profile is stated or the "
      "process does not start"]),
    ({"service/sample.py": _ENV_SAMPLE + 'D = {"MCX_PROFILE": "y"}\nenv.update(MCX_PROFILE="y")\n'},
     {}, ["service/sample.py:4: MCX_PROFILE is given a value; the profile is stated or "
          "the process does not start",
          "service/sample.py:5: MCX_PROFILE is given a value; the profile is stated or "
          "the process does not start"]),
    ({"core/sample.py": "def f(profile='x'):\n    pass\n"}, {},
     ["core/sample.py:1: parameter 'profile' has a default; a profile is never assumed"]),
    ({"core/sample.py": "def f(*, profile_names=('x',)):\n    pass\n"}, {},
     ["core/sample.py:1: parameter 'profile_names' has a default; a profile is never "
      "assumed"]),
    ({"core/sample.py": "f = lambda hooks='h': hooks\n"}, {},
     ["core/sample.py:1: parameter 'hooks' has a default; a profile is never assumed"]),
    ({"service/sample.py": "from dataclasses import dataclass, field\n\n@dataclass\nclass C:\n"
      "    hooks: str = 'profiles.x.hooks'\n"
      "    profile_names: tuple = field(default_factory=lambda: ('x',))\n"}, {},
     ["service/sample.py:5: field 'hooks' has a default; a profile is never assumed",
      "service/sample.py:6: field 'profile_names' has a default; a profile is never assumed"]),
    ({"core/sample.py": "def g(name='utility'):\n    return name\n"}, {},
     ["core/sample.py:1: defaults to the profile 'utility'"]),
    ({"service/sample.py": "class C:\n    kind = 'frmcs'\n"}, {},
     ["service/sample.py:2: defaults to the profile 'frmcs'"]),
    ({"tools/mcx.Containerfile": "FROM x\nENV MCX_PROFILE=mcx\n"}, {},
     ["tools/mcx.Containerfile:2: sets MCX_PROFILE; a built image or unit must not choose "
      "the profile"]),
    ({"deploy/compose.yaml": "services:\n  mcx:\n    environment:\n      MCX_PROFILE: mcx\n"},
     {}, ["deploy/compose.yaml:4: sets MCX_PROFILE; a built image or unit must not choose "
          "the profile"]),
    ({"deploy/mcx.env": "MCX_PROFILE=frmcs\n"}, {},
     ["deploy/mcx.env:1: sets MCX_PROFILE; a built image or unit must not choose the "
      "profile"]),
    ({}, {"service/config.py": ('env.get("MCX_PROFILE", "")', '""')},
     ["service/config.py: MCX_PROFILE is not read; the profile must be stated by the "
      "deployment"]),
    ({"core/sample.py": "def f(:\n"}, {},
     ["core/sample.py: cannot be parsed, so this gate cannot clear it"]),
], ids=["config-default", "config-default-no-space", "or-fallback", "getenv-keyword",
        "bound-key", "holder-reassigned", "holder-or", "conditional", "setdefault",
        "environ-write", "mapping-and-update", "unannotated-param", "kwonly-param",
        "lambda-param", "dataclass-fields", "profile-name-default", "profile-name-field",
        "containerfile", "compose", "env-file", "not-read", "unparseable"])
def test_bnd_007_catches_the_variants(tmp_path, files, patches, expected):
    root = _runtime(tmp_path, files, patches)
    assert gate.check_no_default_profile(root) == _lines(root, expected)


@pytest.mark.vp("VP1-BND-007")
def test_bnd_007_leaves_stated_reads_alone(tmp_path):
    root = _runtime(tmp_path, {"service/sample.py": _ENV_SAMPLE + (
        'a = env.get("MCX_PROFILE", "")\nb = (env.get("MCX_PROFILE") or "").strip()\n'
        'c = env["MCX_PROFILE"]\nname = "mcx"\n'
        'def f(profile=None, profiles_root="p", *, hooks=()):\n    return profile\n'
        'from dataclasses import dataclass, field\n@dataclass\nclass C:\n'
        '    profile_names: tuple = field(default_factory=tuple)\n    hooks: object = None\n'),
        "tools/x.Containerfile": "# set MCX_PROFILE when you run it\nFROM x\n",
        "docs/run.md": "MCX_PROFILE=mcx python -m service\n",
        "docs/example.env": "MCX_PROFILE=mcx\n", "tests/run.env": "MCX_PROFILE=mcx\n"})
    assert gate.check_no_default_profile(root) == []


@pytest.mark.vp("VP1-BND-008")
@pytest.mark.parametrize("files,patches,expected", [
    ({"service/sample.py": "import signal\ndef go(loop, cb):\n"
      "    loop.add_signal_handler(signal.SIGUSR1, cb)\n"}, {},
     ["service/sample.py:3: registers a signal handler (add_signal_handler); the only one "
      "is the SIGTERM/SIGINT stop",
      "service/sample.py:3: refers to SIGUSR1; the process handles SIGTERM and SIGINT only"]),
    ({"core/sample.py": "import os\ndef changed(p, t):\n    return os.stat(p).st_mtime > t\n"},
     {}, ["core/sample.py:3: reads 'st_mtime': polling a file for change"]),
    ({"core/sample.py": "import os\nm = os.path.getmtime('p')\n"}, {},
     ["core/sample.py:2: reads 'getmtime': polling a file for change"]),
    ({}, {"service/__main__.py": ("    for sig in (signal.SIGTERM, signal.SIGINT):\n",
                                  "    signal.signal(signal.SIGTERM, lambda *_: stop.set())\n"
                                  "    for sig in (signal.SIGTERM, signal.SIGINT):\n")},
     ["service/__main__.py:{L:signal.signal(signal.SIGTERM}: registers a signal handler "
      "(signal); the only one is the SIGTERM/SIGINT stop"]),
    ({}, {"service/__main__.py": ("    for sig in (signal.SIGTERM, signal.SIGINT):\n"
                                  "        signal.signal(sig, lambda *_: stop.set())",
                                  "    for sig in (signal.SIGTERM, signal.SIGINT):\n"
                                  "        signal.signal(sig, lambda *_: profile.reload())")},
     ["service/__main__.py:{L:reload()}: registers a signal handler (signal); the only one "
      "is the SIGTERM/SIGINT stop"]),
    ({"core/sample.py": "import signal\nsignal.signal(1, None)\n"}, {},
     ["core/sample.py:2: registers a signal handler (signal); the only one is the "
      "SIGTERM/SIGINT stop"]),
    ({"core/sample.py": "import signal, threading\nstop = threading.Event()\n"
      "for sig in (signal.SIGTERM, signal.SIGINT):\n    signal.signal(sig, lambda *_: stop.set())\n"},
     {}, ["core/sample.py:4: registers a signal handler (signal); the only one is the "
          "SIGTERM/SIGINT stop"]),
    ({}, {"service/__main__.py": ("    for sig in (signal.SIGTERM, signal.SIGINT):\n",
                                  "    for sig in (signal.SIGTERM, signal.SIGTERM):\n")},
     ["service/__main__.py:{L:signal.signal(sig}: registers a signal handler (signal); the "
      "only one is the SIGTERM/SIGINT stop"]),
    ({}, {"service/__main__.py": ("        signal.signal(sig, lambda *_: stop.set())",
                                  "        signal.signal(sig, lambda *_: stop.set())\n"
                                  "        profile_watch()")},
     ["service/__main__.py:{L:signal.signal(sig}: registers a signal handler (signal); the "
      "only one is the SIGTERM/SIGINT stop"]),
    ({"service/sample.py": "SIGUSR2 = 12\n"}, {},
     ["service/sample.py:1: refers to SIGUSR2; the process handles SIGTERM and SIGINT only"]),
    ({"service/sample.py": "from signal import signal as s\n"}, {},
     ["service/sample.py:1: imports from signal; use signal.<name> so the gate can see it"]),
    ({"service/sample.py": "import signal\nh = getattr(signal, 'SIGHUP')\n"}, {},
     ["service/sample.py:2: names SIGHUP; the process handles SIGTERM and SIGINT only"]),
    ({"service/sample.py": "import signal\nsignal.setitimer(signal.ITIMER_REAL, 5)\n"}, {},
     ["service/sample.py:2: registers a signal handler (setitimer); the only one is the "
      "SIGTERM/SIGINT stop"]),
    ({"service/sample.py": "import watchdog.observers\nfrom watchfiles import watch\n"
      "import importlib\nimportlib.reload(watchdog)\n"}, {},
     ["service/sample.py:1: imports 'watchdog.observers': a watcher or reloader",
      "service/sample.py:2: imports 'watchfiles': a watcher or reloader",
      "service/sample.py:3: imports 'importlib': a watcher or reloader"]),
    ({"service/sample.py": "import threading\nfrom core import loader\n"
      "t = threading.Timer(60, loader.startup, ([], None))\n"}, {},
     ["service/sample.py:3: refers to the loader's 'startup'; only build_runtime starts "
      "it, once"]),
    ({"service/sample.py": "from core.loader import startup, load\n"}, {},
     ["service/sample.py:1: imports the loader's 'startup'; only build_runtime starts it",
      "service/sample.py:1: imports the loader's 'load'; only build_runtime starts it"]),
    ({"service/sample.py": "import core.loader\nx = core.loader.load('p')\n"
      "import core.loader as L\ny = L.read_package('p')\n"}, {},
     ["service/sample.py:2: refers to the loader's 'load'; only build_runtime starts it, "
      "once",
      "service/sample.py:4: refers to the loader's 'read_package'; only build_runtime "
      "starts it, once"]),
    ({}, {"service/runtime.py": (
        "    loaded = loader.startup(config.profile_names, config.profiles_root, env)\n",
        "    for _ in range(2):\n"
        "        loaded = loader.startup(config.profile_names, config.profiles_root, env)\n")},
     ["service/runtime.py:{L:        loaded = loader.startup}: refers to the loader's "
      "'startup'; only build_runtime starts it, once",
      "service/runtime.py: build_runtime calls loader.startup 0 times; once, at start"]),
    ({}, {"service/runtime.py": (
        "    loaded = loader.startup(config.profile_names, config.profiles_root, env)\n",
        "    loaded = loader.startup(config.profile_names, config.profiles_root, env)\n"
        "    loaded = loader.startup(config.profile_names, config.profiles_root, env)\n")},
     ["service/runtime.py: build_runtime calls loader.startup 2 times; once, at start"]),
    ({"service/sample.py": "from .runtime import build_runtime\n"
      "def again(env, clock):\n    return build_runtime(env, clock)\n"}, {},
     ["service/sample.py:1: imports build_runtime; main imports it, under its name, and "
      "calls it once, at start",
      "service/sample.py:3: refers to build_runtime; main calls it once, at start"]),
    ({}, {"service/__main__.py": ("        runtime = build_runtime(env, utc_ms)\n",
                                  "        runtime = [build_runtime(env, utc_ms) for _ in "
                                  "range(2)][-1]\n")},
     ["service/__main__.py:{L:for _ in range(2)][-1]}: refers to build_runtime; main calls "
      "it once, at start",
      "service/__main__.py: main calls build_runtime 0 times; once, at start"]),
    ({}, {"service/__main__.py": ("        runtime = build_runtime(env, utc_ms)\n",
                                  "        runtime = build_runtime(env, utc_ms)\n"
                                  "        runtime = build_runtime(env, utc_ms)\n")},
     ["service/__main__.py: main calls build_runtime 2 times; once, at start"]),
], ids=["add-signal-handler", "st-mtime", "getmtime", "second-handler", "handler-not-stop",
        "core-signal", "stop-in-core", "stop-for-one-signal", "stop-loop-does-more",
        "signal-name-bare", "from-signal", "signal-name-string", "setitimer", "watchers",
        "timer-on-loader", "imports-loader", "loader-load", "startup-in-loop",
        "startup-twice", "build-runtime-elsewhere", "build-runtime-in-comprehension",
        "build-runtime-twice"])
def test_bnd_008_catches_the_variants(tmp_path, files, patches, expected):
    root = _runtime(tmp_path, files, patches)
    assert gate.check_no_hot_reload(root) == sorted(_lines(root, expected), key=gate._by_line)


@pytest.mark.vp("VP1-BND-008")
def test_bnd_008_leaves_the_stop_and_plain_stat_alone(tmp_path):
    root = _runtime(tmp_path, {"service/sample.py":
                               "import os, signal\nsize = os.stat('p').st_size\n"
                               "s = signal.SIGTERM\n"})
    assert gate.check_no_hot_reload(root) == []


@pytest.mark.vp("VP1-BND-016")
@pytest.mark.parametrize("files,patches,expected", [
    ({}, {"service/logs.py": ("import json\n", "import json\nimport time\n"
                                               "STAMP = time.strftime('%H:%M', time.localtime())\n")},
     ["service/logs.py:{L:STAMP}: localtime: local or zoneless time",
      "service/logs.py:{L:STAMP}: strftime: local or zoneless time"]),
    ({"core/sample.py": "import datetime\nfrom datetime import datetime as dt\n"
      "a = dt.fromtimestamp(0)\nb = datetime.datetime.now()\nc = dt(2020, 1, 1)\n"
      "d = a.astimezone()\ne = dt.utcnow()\nf = dt.today()\n"}, {},
     ["core/sample.py:3: fromtimestamp without a zone is local or zoneless time",
      "core/sample.py:4: datetime.now() without a zone is local or zoneless "
      "time",
      "core/sample.py:5: a datetime without a zone is local or zoneless time",
      "core/sample.py:6: astimezone() without a zone is local or zoneless time",
      "core/sample.py:7: utcnow: local or zoneless time",
      "core/sample.py:8: today: local or zoneless time"]),
    ({"core/sample.py": "def wait(timeout_s: float, seconds=1):\n    pass\n"}, {},
     ["core/sample.py:1: parameter 'seconds' counts seconds; durations are in milliseconds",
      "core/sample.py:1: parameter 'timeout_s' counts seconds; durations are in milliseconds"]),
    ({"service/sample.py": "class C:\n    delay_s: int = 0\n    hold_secs: int = 0\n"}, {},
     ["service/sample.py:2: field 'delay_s' counts seconds; durations are in milliseconds",
      "service/sample.py:3: field 'hold_secs' counts seconds; durations are in milliseconds"]),
    ({}, {"service/config.py": ("SECONDS_FORMS = {", "IDLE = ('MCX_IDLE_TIMEOUT', "
                                "'MCX_RETRY_S', 'MCX_HOLD_MIN', 'MCX_CACHE_TTL_MS')\n"
                                "SECONDS_FORMS = {")},
     ["service/config.py:{L:MCX_IDLE_TIMEOUT}: setting MCX_CACHE_TTL_MS has no seconds form "
      "in SECONDS_FORMS (PLT-GEN-011)",
      "service/config.py:{L:MCX_IDLE_TIMEOUT}: setting MCX_HOLD_MIN counts in a unit other "
      "than milliseconds (PLT-GEN-011)",
      "service/config.py:{L:MCX_IDLE_TIMEOUT}: setting MCX_IDLE_TIMEOUT names a duration "
      "without stating milliseconds (_ms) (PLT-GEN-011)",
      "service/config.py:{L:MCX_IDLE_TIMEOUT}: setting MCX_RETRY_S counts in a unit other "
      "than milliseconds (PLT-GEN-011)"]),
    ({}, {"core/validation.py": ('"no_answer_ms", "no_answer_s", "group_over_limit"),',
                                 '"no_answer_ms", "no_answer_s", "group_over_limit", "hold_timeout",\n'
                                 '                "ring_s"),')},
     ["core/validation.py:{L:\"hold_timeout\"}: schema key 'hold_timeout' names a duration "
      "without stating milliseconds (_ms) (PLT-GEN-011)",
      "core/validation.py:{L:\"ring_s\"}: schema key 'ring_s' counts in a unit other than "
      "milliseconds (PLT-GEN-011)"]),
    ({}, {"core/model.py": ("    no_answer_ms: Optional[int] = None",
                            "    no_answer_ms: Optional[int] = None\n"
                            "    ring_timeout: Optional[int] = None")},
     ["core/model.py:{L:ring_timeout}: configuration field 'ring_timeout' names a duration "
      "without stating milliseconds (_ms) (PLT-GEN-011)"]),
    ({"service/sample.py": "import logging\n"
      "f = logging.Formatter('%(asctime)s %(message)s', datefmt='%H')\n"}, {},
     ["service/sample.py:2: a log format with asctime renders local time",
      "service/sample.py:2: datefmt formats local time"]),
    ({"core/sample.py": "import time\nstamp = time.time()\n"},
     {}, ["core/sample.py:2: reads the wall clock; it is read in service/clock.py alone "
          "(utc_ms)"]),
    ({"service/sample.py": "from time import time\nimport time as t\nz = t.timezone\n"
      "w = t.time()\nimport datetime as D\nn = D.datetime.now()\n"
      "from datetime import datetime as dt\nm = dt.now()\n"}, {},
     ["service/sample.py:1: imports from time; use time.<name> so the gate can see it",
      "service/sample.py:3: time.timezone: the local zone",
      "service/sample.py:4: reads the wall clock; it is read in service/clock.py alone "
      "(utc_ms)",
      "service/sample.py:6: datetime.now() without a zone is local or zoneless "
      "time",
      "service/sample.py:8: datetime.now() without a zone is local or zoneless "
      "time"]),
], ids=["service-logs-local-time", "datetime-forms", "seconds-params", "seconds-fields",
        "settings-names", "schema-keys", "model-field",
        "log-format", "wall-clock", "time-imports"])
def test_bnd_016_catches_the_variants(tmp_path, files, patches, expected):
    root = _runtime(tmp_path, files, patches)
    assert gate.check_time_discipline(root) == _lines(root, expected)


@pytest.mark.vp("VP1-BND-016")
def test_bnd_016_leaves_utc_and_ms_alone(tmp_path):
    root = _runtime(tmp_path, {"service/sample.py":
                               "import datetime, time\nu = datetime.timezone.utc\n"
                               "a = datetime.datetime.now(u)\n"
                               "b = datetime.datetime.fromtimestamp(0, tz=u)\n"
                               "c = datetime.datetime(2020, 1, 1, tzinfo=u)\n"
                               "d = a.astimezone(u)\nm = time.monotonic()\n"
                               "def f(timeout_ms: int, session_expires_ms=0):\n    pass\n"
                               "class C:\n    timers_ms: dict = None\n"})
    assert gate.check_time_discipline(root) == []


@pytest.mark.vp("VP1-BND-016")
def test_bnd_016_seconds_are_the_named_wire_values_only():
    assert gate.WIRE_SECONDS == frozenset({
        ("core/sip.py", "seconds"), ("service/session_timer.py", "seconds"),
        ("service/sip_core.py", "seconds"), ("core/rtcp.py", "seconds")})


@pytest.mark.vp("VP1-BND-022")
@pytest.mark.parametrize("text,expected", [
    ("def f(cfg):\n    return cfg.release.number >= 19\n", ["2: release compared to a literal"]),
    ("def f(release):\n    return release >= 21\n", ["2: release compared to a literal"]),
    ("def f(release):\n    return release in (17, 18)\n", ["2: release compared to a literal"]),
    ("def f(release, rel):\n    return release == '19' or rel == b'Rel-19'\n",
     ["2: release compared to a literal"]),
    ("def f(mcx_rel_num):\n    return 13 > mcx_rel_num\n", ["2: release compared to a literal"]),
    ("def f(release):\n    return int(release) != -1\n", ["2: release compared to a literal"]),
    ("def f(cfgRelease):\n    return cfgRelease in range(17, 19)\n",
     ["2: release compared to a literal"]),
    ("def f(release):\n    match release:\n        case 17 | 18:\n            return 1\n",
     ["2: release matched against a literal"]),
    ("def f(release):\n    return {17: 'a', 18: 'b'}[release]\n",
     ["2: a table indexed by release"]),
    ("def f(self):\n    return {17: 'a'}.get(self.release)\n",
     ["2: a table indexed by release"]),
    ("from core.release import Release\nX = Release.REL_19\n",
     ["2: names one release (REL_19)"]),
], ids=["attribute", "unlisted-release", "membership", "string-and-bytes", "other-name",
        "int-cast", "camel-and-range", "match", "table", "table-get", "member"])
@pytest.mark.parametrize("where", ["profiles/common/tables.py", "service/sample.py",
                                   "tools/sample.py", "core/sample.py"])
def test_bnd_022_catches_the_variants(tmp_path, where, text, expected):
    root = _runtime(tmp_path, {where: text})
    assert gate.check_release_knowledge_is_in_one_module(root) == [
        f"{where}:{e} outside core/release.py" for e in expected]


@pytest.mark.vp("VP1-BND-022")
def test_bnd_022_reads_tests_but_lets_them_name_a_release(tmp_path):
    root = _runtime(tmp_path, {"tests/test_other.py":
                               "from core.release import Release\nR = Release.REL_19\n"
                               "def test_x(release):\n    assert release == 19\n",
                               "tests/test_conformance.py": "def f(release):\n"
                               "    return int(release) < 18\n"})
    assert gate.check_release_knowledge_is_in_one_module(root) == [
        "tests/test_other.py:4: release compared to a literal outside core/release.py"]


@pytest.mark.vp("VP1-BND-022")
def test_bnd_022_leaves_counts_messages_and_other_words_alone(tmp_path):
    root = _runtime(tmp_path, {"service/sample.py":
                               "def f(at_release, msg, MsgType, released, correlation_id):\n"
                               "    return (len(at_release) == 3, msg == MsgType.RELEASE,\n"
                               "            released == 1, correlation_id == 'rel1',\n"
                               "            MsgType.RELEASE == 4)\n"
                               "# if release >= 19: is how not to write it\n"
                               "DOC = 'release >= 19'\n"})
    assert gate.check_release_knowledge_is_in_one_module(root) == []


_RELEASE_READ = '(env.get("MCX_RELEASE") or "").strip()'


@pytest.mark.vp("VP1-BND-023")
@pytest.mark.parametrize("patches,files,drop,expected", [
    ({"service/config.py": (_RELEASE_READ, '(env.get("MCX_RELEASE") or "19").strip()')}, {}, (),
     ["service/config.py:{L:raw_release = }: MCX_RELEASE is read with a fallback value; a "
      "guessed release is silent on the wire"]),
    ({"service/config.py": (_RELEASE_READ, 'env.get("MCX_RELEASE","19").strip()')}, {}, (),
     ["service/config.py:{L:raw_release = }: MCX_RELEASE is read with a fallback value; a "
      "guessed release is silent on the wire"]),
    ({"service/config.py": (_RELEASE_READ, '(os.getenv("MCX_RELEASE") or '
                                           'os.getenv("MCX_DEFAULT_RELEASE") or "")')}, {}, (),
     ["service/config.py:{L:raw_release = }: MCX_RELEASE is read with a fallback value; a "
      "guessed release is silent on the wire"]),
    ({"service/config.py": ("        if not raw_release:\n",
                            "        if not raw_release:\n            raw_release = '19'\n"
                            "        if not raw_release:\n")}, {}, (),
     ["service/config.py:{L:raw_release = '19'}: MCX_RELEASE is given a fallback value "
      "through 'raw_release'; a guessed release is silent on the wire"]),
    ({}, {"core/sample.py": "import os\nos.environ.setdefault('MCX_RELEASE', '19')\n"}, (),
     ["core/sample.py:2: MCX_RELEASE is given a value (setdefault); a guessed release is "
      "silent on the wire"]),
    ({"service/config.py": (_RELEASE_READ, '""')}, {}, (),
     ["service/config.py: the release is not read from the environment"]),
    ({"tests/test_release.py": ("RELEASES = tuple(range(13, 21))",
                                "RELEASES = tuple(int(r) for r in SUPPORTED)")}, {}, (),
     ["tests/test_release.py: RELEASES is not written out as literals"]),
    ({"tests/test_release.py": ("    assert tuple(int(r) for r in SUPPORTED) == RELEASES",
                                "    assert RELEASES")}, {}, (),
     ["tests/test_release.py: RELEASES is not asserted equal to core.release.SUPPORTED in a "
      "test; a new release would go untested"]),
    ({}, {}, ("tests/test_release.py",),
     ["no per-release conformance suite (tests/test_release.py)"]),
], ids=["or-fallback", "default-no-space", "another-variable", "reassigned", "setdefault",
        "not-read", "suite-not-literal", "suite-not-pinned", "no-suite"])
def test_bnd_023_catches_the_variants(tmp_path, patches, files, drop, expected):
    root = _runtime(tmp_path, files, patches, drop)
    assert gate.check_release_is_a_deployment_parameter(root) == _lines(root, expected)


# -- batch B, the independent review's probes (round 1) ------------------------


_K8S = ("spec:\n  containers:\n    - name: mcx\n      env:\n"
        "        - name: MCX_PROFILE\n          value: mcx\n")


@pytest.mark.vp("VP1-BND-007")
@pytest.mark.parametrize("files,expected", [
    ({"deploy/k8s/deployment.yaml": _K8S}, ["deploy/k8s/deployment.yaml:5"]),
    ({"deploy/defaults.json": '{"MCX_PROFILE": "mcx"}\n'}, ["deploy/defaults.json:1"]),
    ({"deploy/env.json": '[{"name": "MCX_PROFILE", "value": "mcx"}]\n'}, ["deploy/env.json:1"]),
    ({"tools/x.Containerfile": "FROM x\nENV A=1 MCX_PROFILE=mcx\nENV MCX_PROFILE mcx\n"},
     ["tools/x.Containerfile:2", "tools/x.Containerfile:3"]),
    ({"deploy/mcx.service": "[Service]\nEnvironment=MCX_PROFILE=mcx\n"}, ["deploy/mcx.service:2"]),
    ({"deploy/run.sh": "export MCX_PROFILE=frmcs\n"}, ["deploy/run.sh:1"]),
], ids=["k8s-name-value", "json-mapping", "json-name-value", "containerfile-forms",
        "systemd", "shell"])
def test_bnd_007_reads_every_deployment_file(tmp_path, files, expected):
    root = _runtime(tmp_path, files)
    assert gate.check_no_default_profile(root) == [
        f"{e}: sets MCX_PROFILE; a built image or unit must not choose the profile"
        for e in expected]


@pytest.mark.vp("VP1-BND-007")
def test_bnd_007_leaves_ci_comments_and_empty_values_alone(tmp_path):
    root = _runtime(tmp_path, {
        ".github/workflows/x.yml": "env:\n  MCX_PROFILE: mcx\n",
        "deploy/a.yaml": "# MCX_PROFILE: mcx\n- name: MCX_PROFILE\n# value: x\n",
        "deploy/b.env": "MCX_PROFILE=\n", "deploy/c.json": '{"MCX_PROFILE": ""}\n'})
    assert gate.check_no_default_profile(root) == []


@pytest.mark.vp("VP1-BND-008")
@pytest.mark.parametrize("files,expected", [
    ({"service/sample.py": "import os\nfrom service import runtime as R\n"
      "def reload(rt):\n    return R.build_runtime(os.environ, rt.clock)\n"},
     ["service/sample.py:4: refers to build_runtime; main calls it once, at start"]),
    ({"service/sample.py": "from core import validation\n"
      "def reload(raw):\n    return validation.build(raw, 'x')\n"},
     ["service/sample.py:3: refers to validation.build; only the loader builds a profile, "
      "at start"]),
    ({"service/sample.py": "from core.validation import build as b\n"},
     ["service/sample.py:1: imports validation.build; only the loader builds a profile, "
      "at start"]),
    ({"core/sample.py": "from . import validation as v\nx = v.build({}, 'x')\n"},
     ["core/sample.py:2: refers to validation.build; only the loader builds a profile, "
      "at start"]),
    ({"core/sample.py": "from .loader import load\n"},
     ["core/sample.py:1: imports the loader's 'load'; only build_runtime starts it"]),
    ({"service/sample.py": "import signal as sg\ndef go(h):\n    sg.signal(10, h)\n"},
     ["service/sample.py:3: registers a signal handler (signal); the only one is the "
      "SIGTERM/SIGINT stop"]),
], ids=["build-runtime-attribute", "validation-build", "import-build", "relative-build",
        "relative-loader", "aliased-signal"])
def test_bnd_008_review_probes(tmp_path, files, expected):
    assert gate.check_no_hot_reload(_runtime(tmp_path, files)) == sorted(expected,
                                                                          key=gate._by_line)


@pytest.mark.vp("VP1-BND-016")
@pytest.mark.parametrize("text,expected", [
    ("import datetime\nD = datetime.datetime\nu = datetime.timezone.utc\n"
     "a = D.fromtimestamp(0, None)\nb = D.fromtimestamp(0, tz=None)\nc = D.now(None)\n"
     "d = D.now(tz=None)\ne = a.astimezone(None)\nf = datetime.datetime(2020, 1, 1, tzinfo=None)\n"
     "g = datetime.datetime(2020, 1, 1)\nh = a.replace(tzinfo=None)\n"
     "z = datetime.timezone(datetime.timedelta(hours=1))\ni = D.now(z)\n",
     ["4: fromtimestamp with a zone other than UTC",
      "5: fromtimestamp with a zone other than UTC",
      "6: datetime.now() with a zone other than UTC",
      "7: datetime.now() with a zone other than UTC",
      "8: astimezone() with a zone other than UTC",
      "9: a datetime with a zone other than UTC",
      "10: a datetime without a zone is local or zoneless time",
      "11: replace(tzinfo=) with a zone other than UTC",
      "12: a fixed zone: times are UTC",
      "13: datetime.now() with a zone other than UTC"]),
    ("import datetime, logging\nlog = logging.getLogger('x')\n"
     "log.info('started %s', datetime.datetime.now(datetime.timezone.utc).isoformat())\n",
     ["3: isoformat: a time rendered as text; times are UTC epoch milliseconds"]),
    ("import email.utils\ns = email.utils.formatdate(0, localtime=True)\n"
     "t = email.utils.format_datetime(None)\n",
     ["2: formatdate: local or zoneless time", "2: localtime= renders local time",
      "3: format_datetime: a time rendered as text; times are UTC epoch milliseconds"]),
    ("import os\nk = os.environ.get('MCX_KEEPALIVE_TIMEOUT')\n"
     "SETTINGS = ('MCX_SIP_KEEPALIVE', 'MCX_RETRY_AFTER', 'MCX_REFRESH', 'MCX_IDLE')\n",
     ["2: setting MCX_KEEPALIVE_TIMEOUT names a duration without stating milliseconds "
      "(_ms) (PLT-GEN-011)",
      "3: setting MCX_IDLE names a duration without stating milliseconds (_ms) (PLT-GEN-011)",
      "3: setting MCX_REFRESH names a duration without stating milliseconds (_ms) "
      "(PLT-GEN-011)",
      "3: setting MCX_RETRY_AFTER names a duration without stating milliseconds (_ms) "
      "(PLT-GEN-011)",
      "3: setting MCX_SIP_KEEPALIVE names a duration without stating milliseconds (_ms) "
      "(PLT-GEN-011)"]),
    ("def f(auditor, RecordType, t):\n"
     "    auditor.emit(RecordType.X, 'c', ring=t, elapsed_sec=3, started_at=5,\n"
     "                 detail={'wait_s': 1, 'inner': {'hold_timeout': 2}, 'gap_ms': 4})\n",
     ["2: audit detail 'elapsed_sec' counts in a unit other than milliseconds (PLT-GEN-011)",
      "2: audit detail 'started_at' names a time without stating milliseconds (_ms) "
      "(PLT-GEN-011)",
      "3: audit detail 'hold_timeout' names a duration without stating milliseconds (_ms) "
      "(PLT-GEN-011)",
      "3: audit detail 'wait_s' counts in a unit other than milliseconds (PLT-GEN-011)"]),
    ("SECONDS_FORMS = {'MCX_IDLE_TIMEOUT': 'MCX_IDLE_TIMEOUT_MS'}\n",
     ["1: setting MCX_IDLE_TIMEOUT names a duration without stating milliseconds (_ms) "
      "(PLT-GEN-011)",
      "1: setting MCX_IDLE_TIMEOUT_MS has no seconds form in SECONDS_FORMS (PLT-GEN-011)"]),
], ids=["zones", "isoformat-in-log", "email-dates", "settings-anywhere", "audit-keys",
        "seconds-form-not-ruled"])
def test_bnd_016_review_probes(tmp_path, text, expected):
    root = _runtime(tmp_path, {"service/sample.py": text})
    assert gate.check_time_discipline(root) == [f"service/sample.py:{e}" for e in expected]


@pytest.mark.vp("VP1-BND-016")
def test_bnd_016_schema_keys_read_with_get_and_subscript(tmp_path):
    anchor = '    ms = _whole(c, path, item, "no_answer_ms", NO_ANSWER_MIN_MS, "milliseconds")\n'
    root = _runtime(tmp_path, patches={"core/validation.py": (
        anchor, anchor + '    hold = item.get("hold_timeout") or item["ring_s"]\n')})
    assert gate.check_time_discipline(root) == _lines(root, [
        "core/validation.py:{L:hold_timeout}: schema key 'hold_timeout' names a duration "
        "without stating milliseconds (_ms) (PLT-GEN-011)",
        "core/validation.py:{L:hold_timeout}: schema key 'ring_s' counts in a unit other than "
        "milliseconds (PLT-GEN-011)"])


def _quoting(root, name):
    """(file, line) of every line under core/ and service/ quoting `name`."""
    out = []
    for pkg in ("core", "service"):
        for path in sorted((root / pkg).rglob("*.py")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if f'"{name}"' in line or f"'{name}'" in line:
                    out.append((path.relative_to(root).as_posix(), n))
    return out


_SESSION_FORM = 'SECONDS_FORMS = {"MCX_SESSION_EXPIRES": "MCX_SESSION_EXPIRES_MS"}'
_RING_FORM = 'SECONDS_FORMS = {"no_answer_s": "no_answer_ms", "timers_s": "timers_ms"}'


@pytest.mark.vp("VP1-BND-016")
@pytest.mark.parametrize("new", [
    'SECONDS_FORMS = {}',                                              # not declared
    'SECONDS_FORMS = {"MCX_SESSION_EXPIRES": "MCX_SESSION_EXPIRY"}',   # beside a bad name
    'OTHER = {"MCX_SESSION_EXPIRES": "MCX_SESSION_EXPIRES_MS"}',       # another mapping
    'SECONDS_FORMS = {"MCX_SESSION_EXPIRE": "MCX_SESSION_EXPIRES_MS"}',  # not its pair
], ids=["undeclared", "bad-ms-name", "other-mapping", "not-the-pair"])
def test_bnd_016_the_session_seconds_form_is_exempt_only_while_declared(tmp_path, new):
    """PLT-GEN-011 as amended 2026-10-18: MCX_SESSION_EXPIRES (seconds) is
    allowed beside MCX_SESSION_EXPIRES_MS while service/config.py declares
    the pair. Undeclared, every use of the seconds name is refused, and the
    millisecond setting has no seconds form."""
    root = _runtime(tmp_path, patches={"service/config.py": (_SESSION_FORM, new)})
    lines = sorted(set(_quoting(root, "MCX_SESSION_EXPIRES")))
    ms_lines = sorted(set(_quoting(root, "MCX_SESSION_EXPIRES_MS")))
    assert lines and {f for f, _ in lines} == {"service/config.py"}
    assert ms_lines
    want = [f"{f}:{n}: setting MCX_SESSION_EXPIRES names a duration without stating "
            "milliseconds (_ms) (PLT-GEN-011)" for f, n in lines]
    want += [f"{f}:{n}: setting MCX_SESSION_EXPIRES_MS has no seconds form in "
             "SECONDS_FORMS (PLT-GEN-011)" for f, n in ms_lines]
    # Undeclared, the field holding the stated seconds is no longer exempt.
    field = next(n for n, l in enumerate((root / "service/config.py").read_text().splitlines(), 1)
                 if l.strip().startswith("session_expires_s:"))
    want.append(f"service/config.py:{field}: field 'session_expires_s' counts seconds; "
                "durations are in milliseconds")
    if "EXPIRY" in new:
        want.append(f"service/config.py:{lines[0][1]}: setting MCX_SESSION_EXPIRY names a "
                    "duration without stating milliseconds (_ms) (PLT-GEN-011)")
    if "EXPIRE\"" in new:
        form = next(n for n, l in enumerate((root / "service/config.py").read_text()
                                             .splitlines(), 1) if l.startswith("SECONDS_FORMS"))
        want.append(f"service/config.py:{form}: setting MCX_SESSION_EXPIRE names a "
                    "duration without stating milliseconds (_ms) (PLT-GEN-011)")
    assert gate.check_time_discipline(root) == sorted(want, key=gate._by_line)


@pytest.mark.vp("VP1-BND-016")
def test_bnd_016_the_profile_seconds_forms_are_exempt_only_while_declared(tmp_path):
    root = _runtime(tmp_path, patches={"core/validation.py": (_RING_FORM, "SECONDS_FORMS = {}")})
    text = (root / "core/validation.py").read_text().splitlines()
    ct = next(n for n, l in enumerate(text, 1)
              if '"no_answer_ms", "no_answer_s", "group_over_limit")' in l)
    floor = next(n for n, l in enumerate(text, 1) if '"timers_ms", "timers_s"' in l)
    model_text = (root / "core/model.py").read_text().splitlines()
    fields = [(next(n for n, l in enumerate(model_text, 1) if l.startswith(f"    {f}:")), f)
              for f in ("no_answer_s", "timers_s")]
    assert gate.check_time_discipline(root) == sorted([
        f"core/model.py:{n}: field {f!r} counts seconds; durations are in milliseconds"
        for n, f in fields] + [
        f"core/validation.py:{ct}: schema key 'no_answer_ms' has no seconds form in "
        "SECONDS_FORMS (PLT-GEN-011)",
        f"core/validation.py:{ct}: schema key 'no_answer_s' counts in a unit other than "
        "milliseconds (PLT-GEN-011)",
        f"core/validation.py:{floor}: schema key 'timers_ms' has no seconds form in "
        "SECONDS_FORMS (PLT-GEN-011)",
        f"core/validation.py:{floor}: schema key 'timers_s' counts in a unit other than "
        "milliseconds (PLT-GEN-011)"], key=gate._by_line)


@pytest.mark.vp("VP1-BND-016")
def test_bnd_016_a_new_duration_needs_both_forms(tmp_path):
    """A duration added to the configuration with its seconds form declared
    passes; one without, or declared outside a configuration module, or as
    a pair that is not one, does not."""
    good = _runtime(tmp_path / "good", patches={"service/config.py": (
        _SESSION_FORM, 'SECONDS_FORMS = {"MCX_SESSION_EXPIRES": "MCX_SESSION_EXPIRES_MS", '
                       '"MCX_RETRY_S": "MCX_RETRY_MS"}\nRETRY = ("MCX_RETRY_S", "MCX_RETRY_MS")')})
    assert gate.check_time_discipline(good) == []
    bad = _runtime(tmp_path / "bad", files={"service/sample.py":
                                           'SECONDS_FORMS = {"MCX_RETRY_S": "MCX_RETRY_MS"}\n'},
                   patches={"service/config.py": (
                       _SESSION_FORM, _SESSION_FORM + '\nRETRY = ("MCX_HOLD_S", "MCX_RETRY_MS")\n'
                       'X = {"MCX_HOLD_S": "MCX_RETRY_MS"}')})
    assert gate.check_time_discipline(bad) == _lines(bad, [
        "service/config.py:{L:RETRY = }: setting MCX_HOLD_S counts in a unit other than "
        "milliseconds (PLT-GEN-011)",
        "service/config.py:{L:RETRY = }: setting MCX_RETRY_MS has no seconds form in "
        "SECONDS_FORMS (PLT-GEN-011)",
        "service/config.py:{L:X = }: setting MCX_HOLD_S counts in a unit other than "
        "milliseconds (PLT-GEN-011)",
        "service/config.py:{L:X = }: setting MCX_RETRY_MS has no seconds form in "
        "SECONDS_FORMS (PLT-GEN-011)",
        "service/sample.py:1: setting MCX_RETRY_MS has no seconds form in SECONDS_FORMS "
        "(PLT-GEN-011)",
        "service/sample.py:1: setting MCX_RETRY_S counts in a unit other than milliseconds "
        "(PLT-GEN-011)"])


@pytest.mark.vp("VP1-BND-016")
@pytest.mark.parametrize("seconds, ms, ok", [
    ("no_answer_s", "no_answer_ms", True), ("timers_s", "timers_ms", True),
    ("MCX_SESSION_EXPIRES", "MCX_SESSION_EXPIRES_MS", True), ("MCX_X_S", "MCX_X_MS", True),
    ("no_answer", "no_answer_ms", False), ("MCX_X_SEC", "MCX_X_MS", False),
    ("ring_s", "no_answer_ms", False), ("MCX_X", "MCX_X", False), ("x_s", "x_s", False),
    (1, "x_ms", False), ("ab_s", "ab_xx", False), ("AB", "AB_XX", False),
])
def test_bnd_016_what_a_seconds_pair_is(seconds, ms, ok):
    assert gate._ms_pair(seconds, ms) is ok


@pytest.mark.vp("VP1-BND-022")
@pytest.mark.parametrize("text,expected", [
    ("MIN_REL = 19\ndef f(release):\n    return release >= MIN_REL\n",
     ["1: a release number held", "3: release compared to a literal"]),
    ("NEW = frozenset({18, 19, 20})\ndef f(release):\n    return int(release) in NEW\n",
     ["3: release compared to a literal"]),
    ("TABLE = {17: 'a', 18: 'b'}\ndef f(release, cfg):\n"
     "    return TABLE[int(release)], TABLE.get(cfg.release)\n",
     ["3: a table indexed by release"]),
    ("import os\ndef f(env):\n    return int(os.environ['MCX_RELEASE']) >= 19 or "
     "int(env.get('MCX_RELEASE')) >= 19\n", ["3: release compared to a literal"]),
    ("from core.release import Release, parse_release\ndef f(x):\n"
     "    return x >= Release(19) or x >= parse_release('19')\n",
     ["3: a release built from a literal"]),
    ("def f(release):\n    return release.name == 'REL_19' or str(release) in ('R19', 'R20')\n",
     ["2: release compared to a literal"]),
], ids=["named-number", "named-set", "named-table", "env-read", "built", "member-strings"])
def test_bnd_022_review_probes(tmp_path, text, expected):
    root = _runtime(tmp_path, {"service/sample.py": text})
    assert gate.check_release_knowledge_is_in_one_module(root) == [
        f"service/sample.py:{e} outside core/release.py" for e in expected]


_PIN = "    assert tuple(int(r) for r in SUPPORTED) == RELEASES == (13, 14, 15, 16, 17, 18, 19, 20)"


@pytest.mark.vp("VP1-BND-023")
@pytest.mark.parametrize("files,patches,expected", [
    ({}, {"tools/release.Containerfile": ("FROM ", "ENV A=1 MCX_RELEASE=18\nFROM ")},
     ["tools/release.Containerfile:{L:MCX_RELEASE=18}: sets MCX_RELEASE; a built image or "
      "unit must not choose the release"]),
    ({"deploy/mcx.env": "MCX_RELEASE=18\n"}, {},
     ["deploy/mcx.env:1: sets MCX_RELEASE; a built image or unit must not choose the "
      "release"]),
    ({"tests/test_release.py": "from core.release import SUPPORTED\n"
      "RELEASES = (13, 14, 15, 16, 17, 18, 19, 20)\n"
      "def test_pin():\n" + _PIN + "\n"}, {},
     ["tests/test_release.py: no test is parametrised over RELEASES"]),
    ({}, {"tests/test_release.py": (_PIN, "    _ = tuple(int(r) for r in SUPPORTED) == RELEASES")},
     ["tests/test_release.py: RELEASES is not asserted equal to core.release.SUPPORTED in a "
      "test; a new release would go untested"]),
    ({}, {"tests/test_release.py": ("RELEASES = tuple(range(13, 21))",
                                    "RELEASES = tuple(range(13, 21))\n"
                                    "pytestmark = pytest.mark.skip('later')")},
     ["tests/test_release.py: line {L:pytestmark}: the suite is skipped"]),
    ({}, {"tests/test_release.py": ('@pytest.mark.vp("VP1-BND-023")\n'
                                    'def test_the_suite_covers_every_supported_release',
                                    '@pytest.mark.vp("VP1-BND-023")\n@pytest.mark.skip("x")\n'
                                    'def test_the_suite_covers_every_supported_release')},
     ["tests/test_release.py: RELEASES is not asserted equal to core.release.SUPPORTED in a "
      "test; a new release would go untested"]),
    ({}, {"tests/test_release.py": (_PIN, "    tuple(int(r) for r in SUPPORTED) == RELEASES")},
     ["tests/test_release.py: RELEASES is not asserted equal to core.release.SUPPORTED in a "
      "test; a new release would go untested"]),
    ({}, {"tests/test_release.py": ("RELEASES = tuple(range(13, 21))",
                                    "RELEASES = tuple(range(13, 21))\n"
                                    "pytest.skip('later', allow_module_level=True)")},
     ["tests/test_release.py: line {L:pytest.skip(}: the suite is skipped"]),
], ids=["containerfile", "env-file", "suite-without-parametrised-tests", "pin-without-assert",
        "module-skip", "pin-skipped", "pin-as-expression", "module-skip-call"])
def test_bnd_023_review_probes(tmp_path, files, patches, expected):
    root = _runtime(tmp_path, files, patches)
    got = gate.check_release_is_a_deployment_parameter(root)
    want = _lines(root, [e for e in expected if "line {L:" not in e])
    for e in expected:
        if "line {L:" in e:
            needle = re.search(r"\{L:(.+?)\}", e).group(1)
            n = next(i for i, l in enumerate((root / "tests/test_release.py").read_text()
                                              .splitlines(), 1) if needle in l)
            want.append(re.sub(r"\{L:.+?\}", str(n), e))
    assert got == want


# -- batch B, the independent review's probes (round 2) and mutation gaps ------


@pytest.mark.vp("VP1-BND-007", "VP1-BND-023")
@pytest.mark.parametrize("key", ["MCX_PROFILE", "MCX_RELEASE"])
@pytest.mark.parametrize("rel,text,line", [
    ("deploy/Dockerfile.prod", "FROM x\nENV {k}=18\n", 2),
    ("deploy/.env.production", "{k}=18\n", 1),
    ("deploy/k8s.yaml", "env:\n  - value: x\n    name: {k}\n", 3),
    ("deploy/env.json", '[\n  {{\n    "value": "x",\n    "name": "{k}"\n  }}\n]\n', 4),
], ids=["dockerfile-suffix", "env-suffix", "value-then-name", "json-value-then-name"])
def test_bnd_007_023_deployment_file_forms(tmp_path, key, rel, text, line):
    root = _runtime(tmp_path, {rel: text.format(k=key)})
    what = "profile" if key == "MCX_PROFILE" else "release"
    fn = gate.check_no_default_profile if key == "MCX_PROFILE" else \
        gate.check_release_is_a_deployment_parameter
    assert fn(root) == [f"{rel}:{line}: sets {key}; a built image or unit must not choose "
                        f"the {what}"]


@pytest.mark.vp("VP1-BND-008")
@pytest.mark.parametrize("files,patches,expected", [
    ({"service/sample.py": "from .runtime import build_runtime as rebuild\n"
      "def reload(rt):\n    return rebuild({}, rt.clock)\n"}, {},
     ["service/sample.py:1: imports build_runtime; main imports it, under its name, and "
      "calls it once, at start"]),
    ({}, {"service/__main__.py": ("from .runtime import build_runtime\n",
                                  "from .runtime import build_runtime as br\n")},
     ["service/__main__.py:{L:import build_runtime as br}: imports build_runtime; main "
      "imports it, under its name, and calls it once, at start"]),
    ({"service/sample.py": "from core import loader\ndef r(d):\n    return loader.reread(d)\n"
      "from core.loader import reread\n"}, {},
     ["service/sample.py:3: refers to the loader's 'reread'; only build_runtime starts it, "
      "once",
      "service/sample.py:4: imports the loader's 'reread'; only build_runtime starts it"]),
    ({"service/sample.py": "def edit(rt):\n    object.__setattr__(rt.loaded.profile, "
      "'call_types', ())\n"}, {},
     ["service/sample.py:2: object.__setattr__ changes a frozen value; the profile is not "
      "modified at run time"]),
    ({"service/sample.py": "import dataclasses\nfrom dataclasses import replace\n"
      "def edit(rt, p):\n    a = dataclasses.replace(rt.loaded.profile, call_types=())\n"
      "    return replace(p.profile), dataclasses.replace(p.request)\n"}, {},
     ["service/sample.py:4: replace() on the loaded profile; the profile is not modified "
      "at run time",
      "service/sample.py:5: replace() on the loaded profile; the profile is not modified "
      "at run time"]),
    ({"service/sample.py": "class C:\n    def __init__(self, lp):\n        self.loaded = lp\n"
      "    def swap(self, lp):\n        self.loaded, self._hooks = lp, lp.hooks\n"}, {},
     ["service/sample.py:5: sets 'loaded' after construction; the profile is held as loaded",
      "service/sample.py:5: sets '_hooks' after construction; the profile is held as "
      "loaded"]),
    ({"service/sample.py": "def again(rt, lp):\n    rt.health.set_profile(lp)\n"}, {},
     ["service/sample.py:2: refers to set_profile; build_runtime reports the profile once, "
      "at start"]),
    ({}, {"service/runtime.py": ("    health.set_profile(loaded)\n", "")},
     ["service/runtime.py: build_runtime reports the profile 0 times; once, at start"]),
    ({}, {"service/runtime.py": ("    health.set_profile(loaded)\n",
                                 "    health.set_profile(loaded)\n    health.set_profile(loaded)\n")},
     ["service/runtime.py: build_runtime reports the profile 2 times; once, at start"]),
    ({"service/sample.py": "import os, sys\ndef restart():\n"
      "    os.execv(sys.executable, [sys.executable, '-m', 'service'])\n"}, {},
     ["service/sample.py:3: os.execv restarts or forks the process; a new profile is a new "
      "deployment"]),
    ({"service/sample.py": "from ..core import validation as v\nx = v.build({}, 'x')\n"
      "from ..core.validation import build\nfrom ..core.loader import load\n"
      "import core.validation\ny = core.validation.build({}, 'x')\n"}, {},
     ["service/sample.py:2: refers to validation.build; only the loader builds a profile, "
      "at start",
      "service/sample.py:3: imports validation.build; only the loader builds a profile, at "
      "start",
      "service/sample.py:4: imports the loader's 'load'; only build_runtime starts it",
      "service/sample.py:6: refers to validation.build; only the loader builds a profile, "
      "at start"]),
], ids=["build-runtime-alias", "main-alias", "new-loader-function", "setattr", "replace",
        "holder-set-later", "second-report", "no-report", "two-reports", "exec", "two-levels-up"])
def test_bnd_008_review_probes_round_2(tmp_path, files, patches, expected):
    root = _runtime(tmp_path, files, patches)
    assert gate.check_no_hot_reload(root) == sorted(_lines(root, expected), key=gate._by_line)


@pytest.mark.vp("VP1-BND-016")
@pytest.mark.parametrize("text,expected", [
    ("import os\nk = os.environ.get('MCX_RING_TIMER')\nm = 'MCX_MAX_AGE'\n"
     "t = ('MCX_SESSION_TIMER_MODE', 'MCX_TIMER_REFRESHER_ROLE')\n",
     ["2: setting MCX_RING_TIMER names a duration without stating milliseconds (_ms) "
      "(PLT-GEN-011)",
      "3: setting MCX_MAX_AGE names a duration without stating milliseconds (_ms) "
      "(PLT-GEN-011)"]),
    ("import datetime\nD = datetime.datetime\na = D.fromisoformat('2020-01-01')\n"
     "b = D.combine(a.date(), a.time())\nc = D.combine(a.date(), a.time(), None)\n"
     "d = D.fromordinal(1)\ne = D.now(cfg.zone)\n",
     ["3: fromisoformat: local or zoneless time",
      "4: combine() without a zone is local or zoneless time",
      "5: combine() with a zone other than UTC",
      "6: fromordinal: local or zoneless time",
      "7: datetime.now() with a zone other than UTC"]),
], ids=["trailing-duration-words", "other-constructors"])
def test_bnd_016_review_probes_round_2(tmp_path, text, expected):
    root = _runtime(tmp_path, {"service/sample.py": text})
    assert gate.check_time_discipline(root) == [f"service/sample.py:{e}" for e in expected]


@pytest.mark.vp("VP1-BND-016")
def test_bnd_016_utc_named_any_way_is_utc(tmp_path):
    root = _runtime(tmp_path, {"service/sample.py":
                               "import datetime\nfrom datetime import UTC as Z, datetime as D\n"
                               "U = datetime.timezone.utc\n"
                               "a = D.now(Z)\nb = D.now(U)\nc = D.combine(a.date(), a.time(), U)\n"
                               "class C:\n    timer_refresher: str = ''\n"})
    assert gate.check_time_discipline(root) == []


@pytest.mark.vp("VP1-BND-022")
@pytest.mark.parametrize("files,expected", [
    ({"service/limits.py": "LIMIT = 19\nBY_ID = {17: 'a', 18: 'b'}\n",
      "service/sample.py": "from .limits import LIMIT as L, BY_ID\n"
      "def f(release):\n    return release >= L, BY_ID[release]\n"},
     ["service/sample.py:3: a table indexed by release",
      "service/sample.py:3: release compared to a literal"]),
    ({"service/limits.py": "MIN_REL = 19\nBY_REL = {17: 'a'}\nrel_floor = (17, 18)\n"},
     ["service/limits.py:1: a release number held", "service/limits.py:2: a release number held",
      "service/limits.py:3: a release number held"]),
    ({"service/sample.py": "from core.release import parse, Release as R\n"
      "from core import release as cr\n"
      "def f(x):\n    return (x >= parse('19'),\n            x >= R['REL_19'],\n"
      "            x >= R(int('19')),\n            x >= R(18 + 1),\n"
      "            x >= cr.parse('20'))\n"},
     [f"service/sample.py:{n}: a release built from a literal" for n in range(4, 9)]),
], ids=["imported-constants", "held-numbers", "builders"])
def test_bnd_022_review_probes_round_2(tmp_path, files, expected):
    root = _runtime(tmp_path, files)
    assert gate.check_release_knowledge_is_in_one_module(root) == [
        f"{e} outside core/release.py" for e in expected]


@pytest.mark.vp("VP1-BND-022")
def test_bnd_022_leaves_counts_and_non_release_numbers_alone(tmp_path):
    root = _runtime(tmp_path, {"service/sample.py":
                               "from core.release import parse, SUPPORTED\n"
                               "rel_count = 0\nrelease_retries = 3\n"
                               "def f(text, release):\n    return parse(text), release in SUPPORTED\n"})
    assert gate.check_release_knowledge_is_in_one_module(root) == []


# -- batch B, the independent review's probes (round 3) ------------------------


@pytest.mark.vp("VP1-BND-008")
@pytest.mark.parametrize("text,expected", [
    ("def swap(rt):\n    setattr(rt, 'loaded', None)\n",
     ["2: sets a profile holder by name; the profile is held as loaded"]),
    ("def swap(rt):\n    rt.__dict__['loaded'] = None\n    vars(rt.loaded)['profile'] = None\n",
     ["2: sets a profile holder by name; the profile is held as loaded",
      "3: sets a profile holder by name; the profile is held as loaded"]),
    ("import dataclasses\nfrom dataclasses import replace as dc\ndef swap(rt, x):\n"
     "    return dataclasses.replace(rt, loaded=None), dc(x.loaded, profile=None)\n",
     ["4: replace() on the loaded profile; the profile is not modified at run time"] * 2),
    ("class Swap:\n    def __init__(self, rt, new):\n        rt.loaded = new\n"
     "        self.loaded = new\n",
     ["3: sets 'loaded' after construction; the profile is held as loaded"]),
], ids=["setattr", "dict-and-vars", "replace-keyword-and-alias", "other-objects-init"])
def test_bnd_008_review_probes_round_3(tmp_path, text, expected):
    root = _runtime(tmp_path, {"service/sample.py": text})
    assert gate.check_no_hot_reload(root) == [f"service/sample.py:{e}" for e in expected]


@pytest.mark.vp("VP1-BND-016")
def test_bnd_016_plural_trailing_duration_words(tmp_path):
    root = _runtime(tmp_path, {"service/sample.py":
                               "S = ('MCX_FLOOR_TIMERS', 'MCX_CACHE_MAX_AGES')\n"})
    assert gate.check_time_discipline(root) == [
        "service/sample.py:1: setting MCX_CACHE_MAX_AGES names a duration without stating "
        "milliseconds (_ms) (PLT-GEN-011)",
        "service/sample.py:1: setting MCX_FLOOR_TIMERS names a duration without stating "
        "milliseconds (_ms) (PLT-GEN-011)"]


@pytest.mark.vp("VP1-BND-022")
def test_bnd_022_constants_reached_as_attributes(tmp_path):
    root = _runtime(tmp_path, {
        "service/limits.py": "FLOOR = 19\nBY_ID = {17: 'a'}\nclass Limits:\n    CEILING = 20\n",
        "service/sample.py": "from service import limits\nimport service.limits as L\n"
        "from .limits import Limits\n"
        "def f(release):\n    return (release >= limits.FLOOR,\n"
        "            release >= L.FLOOR,\n            release >= Limits.CEILING,\n"
        "            L.BY_ID[release])\n"})
    assert gate.check_release_knowledge_is_in_one_module(root) == [
        f"service/sample.py:{n}: {what} outside core/release.py"
        for n, what in ((5, "release compared to a literal"),
                        (6, "release compared to a literal"),
                        (7, "release compared to a literal"),
                        (8, "a table indexed by release"))]


@pytest.mark.vp("VP1-BND-022")
def test_bnd_022_a_named_table_read_with_get(tmp_path):
    root = _runtime(tmp_path, {
        "service/limits.py": "BY_ID = {17: 'a'}\n",
        "service/sample.py": "from service import limits\nfrom .limits import BY_ID\n"
        "TABLE = {18: 'b'}\n"
        "def f(release):\n    a = TABLE.get(release)\n    b = BY_ID.get(release)\n"
        "    return a, b, limits.BY_ID.get(release)\n"})
    assert gate.check_release_knowledge_is_in_one_module(root) == [
        f"service/sample.py:{n}: a table indexed by release outside core/release.py"
        for n in (5, 6, 7)]


@pytest.mark.vp("VP1-BND-016")
def test_bnd_016_a_seconds_field_needs_its_milliseconds_sibling_in_configuration(tmp_path):
    root = _runtime(tmp_path, files={"service/sample.py":
                                     "class Probe:\n    hold_s: int = 0\n    hold_ms: int = 0\n"},
                    patches={"core/model.py": ("    no_answer_s: Optional[int] = None",
                                               "    no_answer_s: Optional[int] = None\n"
                                               "    ring_s: Optional[int] = None")})
    assert gate.check_time_discipline(root) == _lines(root, [
        "core/model.py:{L:    ring_s: Optional}: field 'ring_s' counts seconds; durations "
        "are in milliseconds",
        "service/sample.py:2: field 'hold_s' counts seconds; durations are in milliseconds"])


@pytest.mark.vp("VP1-BND-016")
def test_bnd_016_a_seconds_form_is_exempt_only_where_it_is_declared(tmp_path):
    """Read anywhere else, MCX_SESSION_EXPIRES would skip the rule that the
    milliseconds apply; and a millisecond setting outside the configuration
    modules still needs its seconds form."""
    root = _runtime(tmp_path, {"service/sample.py":
                               "import os\nx = int(os.environ.get('MCX_SESSION_EXPIRES') or 0)\n"
                               "y = os.environ.get('MCX_IDLE_TIMEOUT_MS')\n"})
    assert gate.check_time_discipline(root) == [
        "service/sample.py:2: setting MCX_SESSION_EXPIRES names a duration without stating "
        "milliseconds (_ms) (PLT-GEN-011)",
        "service/sample.py:3: setting MCX_IDLE_TIMEOUT_MS has no seconds form in SECONDS_FORMS "
        "(PLT-GEN-011)"]


@pytest.mark.vp("VP1-BND-016")
def test_bnd_016_a_paired_field_must_hold_a_declared_form(tmp_path):
    root = _runtime(tmp_path, patches={"core/model.py": (
        "    no_answer_s: Optional[int] = None",
        "    no_answer_s: Optional[int] = None\n    hold_timeout_s: Optional[int] = None\n"
        "    hold_timeout_ms: Optional[int] = None")})
    assert gate.check_time_discipline(root) == _lines(root, [
        "core/model.py:{L:hold_timeout_s}: field 'hold_timeout_s' counts seconds; durations "
        "are in milliseconds"])


# --------------------------------------------------------------------------
# RES-OP-09 batch C: VP1-BND-011, 013, 014, 015
# --------------------------------------------------------------------------


def _with_profiles(tmp_path, files=None, patches=None):
    """`_runtime` with the profile packages whole (their hooks too)."""
    import shutil
    root = _runtime(tmp_path)
    shutil.rmtree(root / "profiles")
    shutil.copytree(ROOT / "profiles", root / "profiles",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for rel, (old, new) in (patches or {}).items():
        path = root / rel
        text = path.read_text(encoding="utf-8")
        assert text.count(old) == 1, (rel, old)
        path.write_text(text.replace(old, new), encoding="utf-8")
    for rel, text in (files or {}).items():
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(text, encoding="utf-8")
    return root


@pytest.mark.vp("VP1-BND-011", "VP1-BND-013", "VP1-BND-014", "VP1-BND-015")
@pytest.mark.parametrize("fn", [gate.check_priority_table_declarative,
                                gate.check_no_priority_table_in_core,
                                gate.check_resolver_receives_context,
                                gate.check_floor_machine_isolated],
                         ids=["011", "013", "014", "015"])
def test_batch_c_gates_pass_the_unchanged_copy(tmp_path, fn):
    assert fn(_with_profiles(tmp_path)) == []


_EVALUATE = '''    def evaluate(self, request: SessionRequest,
                 resolution: Resolution) -> PriorityDecision:
'''
_INTERPRETER_CHANGED = ("profiles/common/tables.py: the table interpreter has changed since "
                        "it was reviewed; review it and update INTERPRETER_FINGERPRINT")
_BINDS = ("not the table interpreter profiles/common/tables.py:TablePriorityPolicy; priority "
          "logic belongs in the profile's table")
_DECIDES = "priority is the profile's table"


@pytest.mark.vp("VP1-BND-011")
@pytest.mark.parametrize("files,patches,expected", [
    ({}, {"profiles/mcx/hooks.py": ("    TableSessionPolicy,\n)\n",
                                    "    TableSessionPolicy,\n)\n\n\nclass MyPolicy("
                                    "TablePriorityPolicy):\n    pass\n"),
          "profiles/mcx/profile.yaml": ("profiles.mcx.hooks:TablePriorityPolicy",
                                        "profiles.mcx.hooks:MyPolicy")},
     [f"profiles/mcx/profile.yaml: priority_policy binds profiles/mcx/hooks.py:MyPolicy, {_BINDS}"]),
    ({}, {"profiles/mcx/profile.yaml": ("profiles.mcx.hooks:TablePriorityPolicy",
                                        "profiles.mcx.hooks:Missing")},
     ["profiles/mcx/profile.yaml: profile.hooks.priority_policy ('profiles.mcx.hooks:Missing') "
      "does not resolve to a class in the tree"]),
    ({}, {"profiles/common/tables.py": (_EVALUATE, _EVALUATE +
                                        "        if request.call_type == 'emergency':\n"
                                        "            return None\n")},
     [f"profiles/common/tables.py:{{L:== 'emergency'}}: the priority policy decides on the "
      f"literal 'emergency'; {_DECIDES}"]),
    ({}, {"profiles/common/tables.py": (_EVALUATE, _EVALUATE +
                                        "        match request.call_type:\n"
                                        "            case _:\n                pass\n")},
     [f"profiles/common/tables.py:{{L:match request.call_type}}: the priority policy branches "
      f"with match; {_DECIDES}"]),
    ({}, {"profiles/common/tables.py": (_EVALUATE, _EVALUATE + "        boost = 9\n")},
     ["profiles/common/tables.py:{L:boost = 9}: the priority policy contains the literal 9"]),
], ids=["subclass-bound", "binding-unresolved", "literal-compare", "match", "integer"])
def test_bnd_011_catches_the_variants(tmp_path, files, patches, expected):
    root = _with_profiles(tmp_path, files, patches)
    if "profiles/common/tables.py" in patches:      # the reviewed interpreter changed too
        expected = [_INTERPRETER_CHANGED] + expected
    assert gate.check_priority_table_declarative(root) == _lines(root, expected)


@pytest.mark.vp("VP1-BND-011")
def test_bnd_011_follows_an_alias_of_the_interpreter(tmp_path):
    root = _with_profiles(tmp_path, patches={
        "profiles/mcx/hooks.py": ("    TableSessionPolicy,\n)\n",
                                  "    TableSessionPolicy,\n)\nPolicy = TablePriorityPolicy\n"),
        "profiles/mcx/profile.yaml": ("profiles.mcx.hooks:TablePriorityPolicy",
                                      "profiles.mcx.hooks:Policy")})
    assert gate.check_priority_table_declarative(root) == []


@pytest.mark.vp("VP1-BND-011")
@pytest.mark.parametrize("old,new", [
    ("class TablePriorityPolicy:\n", "class TablePriorityPolicy(object):\n"),
    (_EVALUATE, _EVALUATE + "        request = request\n"),
    (_EVALUATE, _EVALUATE + "        urgency_text = str(request.urgency).lower()\n"),
    (_EVALUATE, _EVALUATE + "        table = {}\n        table.get(request.call_type)\n"),
    (_EVALUATE, _EVALUATE + "        from profiles.common.decide import decide\n"
                            "        decide(request)\n"),
], ids=["base-class", "rebinding", "string-method", "dict-lookup", "imported-helper"])
def test_bnd_011_any_change_to_the_interpreter_needs_review(tmp_path, old, new):
    root = _with_profiles(tmp_path, patches={"profiles/common/tables.py": (old, new)})
    assert _INTERPRETER_CHANGED in gate.check_priority_table_declarative(root)


@pytest.mark.vp("VP1-BND-011")
def test_bnd_011_the_interpreters_name_is_not_rebound(tmp_path):
    root = _with_profiles(tmp_path)
    path = root / "profiles/common/tables.py"
    path.write_text(path.read_text() + "\n\nclass _Evil(TablePriorityPolicy):\n    pass\n\n\n"
                    "TablePriorityPolicy = _Evil\n")
    line = len(path.read_text().splitlines())
    got = gate.check_priority_table_declarative(root)
    assert (f"profiles/common/tables.py:{line}: rebinds TablePriorityPolicy after its "
            "definition; the interpreter is the code as defined") in got


@pytest.mark.vp("VP1-BND-011")
def test_bnd_011_a_docstring_is_not_a_change():
    import ast as _ast
    src = (ROOT / "profiles/common/tables.py").read_text()
    assert gate.interpreter_fingerprint(ROOT) == gate.INTERPRETER_FINGERPRINT
    assert '"""First-match evaluation' in src


@pytest.mark.vp("VP1-BND-013")
@pytest.mark.parametrize("text,expected", [
    ("PRIORITY_LEVELS = {'emergency': 9, 'private': 5}\n",
     ["1: core contains a label-to-level mapping, which is a priority table"]),
    ("def f(a, b):\n    return a.level > b.level\n",
     ["2: compares a priority value in f; priority decisions are IF-PRI's (PRIORITY_USES lists "
      "the reviewed comparisons)"]),
    ("def f(rs):\n    return sorted(rs, key=lambda r: r.urgency)\n",
     ["2: orders by a priority value or request field in f; the order is IF-PRI's"]),
    ("from core.hooks import PriorityDecision\ndef d():\n    return PriorityDecision(level=9)\n",
     ["3: builds a PriorityDecision from literals or a condition; a priority is IF-PRI's",
      "3: passes level=9; a priority is IF-PRI's"]),
], ids=["named-table", "compare-outside-uses", "order-by-urgency", "decision-literal"])
def test_bnd_013_catches_the_variants(tmp_path, text, expected):
    root = _with_profiles(tmp_path, {"core/sample.py": text})
    assert gate.check_no_priority_table_in_core(root) == [f"core/sample.py:{e}" for e in expected]


@pytest.mark.vp("VP1-BND-013")
def test_bnd_013_the_reviewed_uses_are_these():
    assert {k: sorted(v[0]) for k, v in gate.PRIORITY_USES.items()} == {
        ("core/floor.py", "FloorControl._enqueue"): ["floor_priority"],
        ("core/floor.py", "FloorControl._on_request_taken"): ["_holder_priority",
                                                               "floor_priority"],
        ("core/session.py", "SessionManager.preemption_victims"): ["scope"],
        ("core/session.py", "SessionManager._check_bearer"): [
            "arp_level", "preemption_capability", "priority"],
        ("core/validation.py", "_priority_totality"): ["urgency"],
        ("core/validation.py", "_bearer_totality"): [],
        ("core/validation.py", "_partner_inbound"): ["from_label", "max_level", "seen_labels",
                                                     "to_level"],
    }


_RESOLVE = "                resolution = invoker.call(\"IF-IDR\", \"resolve\",\n"


@pytest.mark.vp("VP1-BND-014")
def test_bnd_014_needs_a_call_site(tmp_path):
    root = _with_profiles(tmp_path)
    p = root / "core/session.py"
    p.write_text(p.read_text().replace("identity_resolver.resolve,", "identity_resolver.lookup,")
                 .replace("identity_resolver.determine_participants,",
                          "identity_resolver.choose,"))
    assert gate.check_resolver_receives_context(root) == [
        "core: no identity_resolver.resolve call site found"]


@pytest.mark.vp("VP1-BND-015")
def test_bnd_015_resolves_a_two_level_relative_import():
    import ast as _ast
    tree = _ast.parse("from ..x import y\nfrom . import z\n")
    assert gate._imports_of(tree, "core.pkg.mod") == [
        (1, "core.x"), (1, "core.x.y"), (2, "core.pkg"), (2, "core.pkg.z")]
    assert gate._imports_of(tree, "core.pkg", is_package=True) == [
        (1, "core.x"), (1, "core.x.y"), (2, "core.pkg"), (2, "core.pkg.z")]


# -- batch C, the independent review's probes (round 1) ------------------------


_MINE = "def _mine(self, request, resolution):\n    return None\n"


@pytest.mark.vp("VP1-BND-011")
@pytest.mark.parametrize("where", ["profiles/mcx/hooks.py", "profiles/common/tables.py"])
@pytest.mark.parametrize("how, message", [
    ("TablePriorityPolicy.evaluate = _mine\n", "changes TablePriorityPolicy.evaluate"),
    ("setattr(TablePriorityPolicy, 'evaluate', _mine)\n", "setattr on TablePriorityPolicy"),
    ("del TablePriorityPolicy.compare\n", "changes TablePriorityPolicy.compare"),
], ids=["assign", "setattr", "del"])
def test_bnd_011_the_interpreter_is_not_patched(tmp_path, where, how, message):
    root = _with_profiles(tmp_path, {})
    path = root / where
    path.write_text(path.read_text() + "\n\n" + _MINE + how)
    line = len(path.read_text().splitlines())
    assert gate.check_priority_table_declarative(root) == [
        f"{where}:{line}: {message}; the table interpreter is not altered by a profile"]


@pytest.mark.vp("VP1-BND-013")
@pytest.mark.parametrize("text,expected", [
    ("def lvl(r):\n    if r.call_type == 'emergency':\n        return 9\n"
     "    elif r.call_type == 'private':\n        return 5\n    return 1\n",
     ["2: compares a request field with the literal 'emergency'; a priority is IF-PRI's, "
      "not derived from a label or number",
      "4: compares a request field with the literal 'private'; a priority is IF-PRI's, not "
      "derived from a label or number"]),
    ("from operator import attrgetter\ndef o(rs):\n    return sorted(rs, key=attrgetter('urgency'))\n",
     ["3: orders by a priority value or request field in o; the order is IF-PRI's"]),
    ("from core.hooks import PriorityDecision\ndef d():\n"
     "    return PriorityDecision(9, 's', True, False, 9, 'em')\n",
     ["3: builds a PriorityDecision from literals or a condition; a priority is IF-PRI's"]),
    ("from core.hooks import PriorityDecision\ndef d(high, low, urgent):\n"
     "    return PriorityDecision(high if urgent else low, 's', True, False, 0, 'em')\n",
     ["3: builds a PriorityDecision from literals or a condition; a priority is IF-PRI's"]),
    ("def f():\n    level = -5\n    floor_priority = 5.0\n",
     ["2: sets a priority value to -5; a priority is IF-PRI's",
      "3: sets a priority value to 5.0; a priority is IF-PRI's"]),
    ("def f(r):\n    label = 'emergency' if r.x else 'normal'\n",
     ["2: sets a priority value to 'emergency'; a priority is IF-PRI's",
      "2: sets a priority value to 'normal'; a priority is IF-PRI's"]),
    ("def f(active, incoming):\n"
     "    return [s for s in active if incoming.call_type == 'emergency-group']\n",
     ["2: compares a request field with the literal 'emergency-group'; a priority is IF-PRI's, "
      "not derived from a label or number"]),
], ids=["if-elif-returns", "attrgetter", "positional-decision", "conditional-decision",
        "signed-and-float",
        "conditional-label", "comprehension"])
def test_bnd_013_review_probes(tmp_path, text, expected):
    root = _with_profiles(tmp_path, {"core/sample.py": text})
    assert gate.check_no_priority_table_in_core(root) == [f"core/sample.py:{e}" for e in expected]


@pytest.mark.vp("VP1-BND-013")
@pytest.mark.parametrize("rel, old, new, expected", [
    ("core/session.py", "            if candidate.scope != incoming.scope:\n",
     "            order = sorted(self.active, key=lambda s: s.request.call_type)\n"
     "            if candidate.scope != incoming.scope:\n",
     ["core/session.py:{L:order = sorted}: orders by a priority value or request field in "
      "SessionManager.preemption_victims; the order is IF-PRI's"]),
    ("core/session.py", "            if candidate.scope != incoming.scope:\n",
     "            if candidate.request.urgency != incoming.label:\n                continue\n"
     "            if candidate.scope != incoming.scope:\n",
     ["core/session.py:{L:candidate.request.urgency != incoming.label}: compares a priority "
      "value in SessionManager.preemption_victims; priority decisions are IF-PRI's "
      "(PRIORITY_USES lists the reviewed comparisons)"]),
    ("core/floor.py", "class FloorControl:\n",
     "class _Other:\n    def _enqueue(self, a, b):\n        return a.urgency > b.urgency\n\n\n"
     "class FloorControl:\n",
     ["core/floor.py:{L:return a.urgency > b.urgency}: compares a priority value in "
      "_Other._enqueue; priority decisions are IF-PRI's (PRIORITY_USES lists the reviewed "
      "comparisons)"]),
    ("core/validation.py", "def _priority_totality(",
     "def level_for(label):\n    if label == 'emergency':\n        return 9\n    return 1\n\n\n"
     "def _priority_totality(",
     ["core/validation.py:{L:if label == 'emergency'}: compares a priority value in level_for; "
      "priority decisions are IF-PRI's (PRIORITY_USES lists the reviewed comparisons)",
      "core/validation.py:{L:if label == 'emergency'}: compares a priority value with the "
      "literal 'emergency'; a priority is IF-PRI's, not derived from a label or number"]),
], ids=["sort-in-reviewed-function", "other-names-in-reviewed-function", "same-name-other-class",
        "new-function-in-validation"])
def test_bnd_013_reviewed_uses_are_narrow(tmp_path, rel, old, new, expected):
    root = _with_profiles(tmp_path, patches={rel: (old, new)})
    assert gate.check_no_priority_table_in_core(root) == _lines(root, expected)


@pytest.mark.vp("VP1-BND-013")
def test_bnd_013_reads_the_interface_definitions_too(tmp_path):
    root = _with_profiles(tmp_path)
    path = root / "core/hooks.py"
    path.write_text(path.read_text() + "\n\ndef level_for(label):\n"
                    "    return 9 if label == 'emergency' else 1\n")
    line = len(path.read_text().splitlines())
    assert gate.check_no_priority_table_in_core(root) == [
        f"core/hooks.py:{line}: compares a priority value in level_for; priority decisions are "
        "IF-PRI's (PRIORITY_USES lists the reviewed comparisons)",
        f"core/hooks.py:{line}: compares a priority value with the literal 'emergency'; a "
        "priority is IF-PRI's, not derived from a label or number"]


_ADHOC = "                resolution, refusal = self._adhoc_members(invoker, request)\n"


@pytest.mark.vp("VP1-BND-014")
@pytest.mark.parametrize("files,patches,expected", [
    ({}, {"core/session.py": (_ADHOC, "                resolution, refusal = self._adhoc_members("
                                      "invoker, dataclasses.replace(request, location=None))\n")},
     ["core/session.py:{L:self._adhoc_members(invoker, dataclasses}: _adhoc_members reaches the "
      "resolver and is not given its caller's request"]),
    ({}, {"core/session.py": (_RESOLVE, "                request, _ = dataclasses.replace("
                                        "request), 0\n" + _RESOLVE)},
     ["core/session.py:{L:request, _ = }: the request is rebuilt before the resolver sees it; "
      "only the core's adding helpers (REQUEST_ENRICHERS) may change it"]),
    ({}, {"core/session.py": (_RESOLVE, "                for request in (request,):\n"
                                        "                    pass\n" + _RESOLVE)},
     ["core/session.py:{L:for request in}: the request is rebuilt before the resolver sees it; "
      "only the core's adding helpers (REQUEST_ENRICHERS) may change it"]),
    ({}, {"core/session.py": (_RESOLVE, "                object.__setattr__(request, 'location', "
                                        "None)\n" + _RESOLVE)},
     ["core/session.py:{L:object.__setattr__(request}: the request is rebuilt before the "
      "resolver sees it; only the core's adding helpers (REQUEST_ENRICHERS) may change it"]),
    ({"core/sample.py": "class M:\n    def find(self, target, request):\n"
      "        r = self._hooks.identity_resolver\n        return r.resolve(target, None)\n"}, {},
     ["core/sample.py:3: the resolver is held in a name; call it where it is, so its request "
      "can be seen"]),
    ({"core/sample.py": "class M:\n    def find(self, target, request):\n"
      "        fn = self._hooks.identity_resolver.resolve\n        return fn(target, None)\n"}, {},
     ["core/sample.py:3: the resolver is held in a name; call it where it is, so its request "
      "can be seen"]),
    ({"core/sample.py": "class M:\n    def find(self, target, request):\n"
      "        def inner(request=None):\n"
      "            return self._hooks.identity_resolver.resolve(target, request)\n"
      "        return inner()\n"}, {},
     ["core/sample.py:5: inner reaches the resolver and is not given its caller's request"]),
    ({"core/sample.py": "class M:\n    def find(self, criteria, request):\n"
      "        return self._hooks.identity_resolver.determine_participants(criteria, None)\n"},
     {}, ["core/sample.py:3: the resolver is not given the request the function received; it "
          "must see the whole request"]),
    ({"core/sample.py": "class M:\n    def a(self, target, request):\n"
      "        return self._hooks.identity_resolver.resolve(target, request)\n"
      "    def b(self, target, request):\n        return self.a(target, request)\n"
      "    def c(self, target, request):\n        request = None\n"
      "        return self.b(target, request)\n"}, {},
     ["core/sample.py:7: the request is rebuilt before the resolver sees it; only the core's "
      "adding helpers (REQUEST_ENRICHERS) may change it"]),
    ({"core/sample.py": "request = None\nclass M:\n    def a(self, target, request):\n"
      "        return self._hooks.identity_resolver.resolve(target, request)\n"
      "    def c(self, target):\n        return self.a(target, request)\n"}, {},
     ["core/sample.py:6: a reaches the resolver and is not given its caller's request"]),
], ids=["adhoc-caller-strips", "tuple", "for", "object-setattr", "aliased-resolver",
        "aliased-method", "nested-shadow", "determine-participants", "two-callers-up",
        "module-request"])
def test_bnd_014_review_probes(tmp_path, files, patches, expected):
    root = _with_profiles(tmp_path, files, patches)
    assert gate.check_resolver_receives_context(root) == _lines(root, expected)


@pytest.mark.vp("VP1-BND-014")
def test_bnd_014_the_reviewed_origins_are_these():
    assert gate.REQUEST_ORIGINS == {
        ("core/session.py", "SessionManager.receive_inbound"): "map_inbound"}


@pytest.mark.vp("VP1-BND-015")
@pytest.mark.parametrize("files, expected", [
    ({"core/pkg/__init__.py": "from .. import sip\n"},
     ["core/pkg/__init__.py:1: floor control reaches 'core.sip' (core.floor -> core.pkg)"]),
    ({"core/pkg/__init__.py": "from . import net\n", "core/pkg/net.py": "import _socket\n"},
     ["core/pkg/net.py:1: floor control reaches '_socket' (core.floor -> core.pkg -> "
      "core.pkg.net)"]),
], ids=["package-up", "package-down"])
def test_bnd_015_follows_packages(tmp_path, files, expected):
    anchor = "from dataclasses import dataclass, field, replace\n"
    root = _with_profiles(tmp_path, files, {"core/floor.py": (anchor,
                                                              anchor + "from core import pkg\n")})
    assert gate.check_floor_machine_isolated(root) == expected


@pytest.mark.vp("VP1-BND-015")
def test_bnd_015_the_forbidden_modules_are_these():
    assert gate.FLOOR_FORBIDDEN == (
        "core.sip", "core.rtcp", "core.codec", "core.mcinfo", "core.session", "core.loader",
        "service", "socket", "ssl", "asyncio", "selectors", "http", "urllib", "requests",
        "email", "select", "socketserver", "xmlrpc", "ftplib", "smtplib", "telnetlib",
        "profiles", "_socket", "_ssl", "multiprocessing", "subprocess", "httpx", "urllib3",
        "aiohttp", "websocket", "websockets", "zmq", "grpc", "concurrent", "logging.handlers",
        "logging.config")
    assert gate.FLOOR_ALLOWED == (
        "__future__", "dataclasses", "enum", "typing", "abc", "collections", "functools",
        "itertools", "heapq", "bisect", "math", "operator", "types", "copy", "logging")


@pytest.mark.vp("VP1-BND-015")
@pytest.mark.parametrize("module", ["imaplib", "wsgiref.simple_server", "time", "os"])
def test_bnd_015_refuses_what_it_is_not_allowed(tmp_path, module):
    anchor = "from dataclasses import dataclass, field, replace\n"
    root = _with_profiles(tmp_path, {}, {"core/floor.py": (anchor,
                                                           anchor + f"import {module}\n")})
    line = (root / "core/floor.py").read_text().splitlines().index(f"import {module}") + 1
    assert gate.check_floor_machine_isolated(root) == [
        f"core/floor.py:{line}: floor control reaches {module!r} (core.floor), which is not "
        "among the modules it may use (FLOOR_ALLOWED)"]


@pytest.mark.vp("VP1-BND-015")
@pytest.mark.parametrize("module", ["multiprocessing", "subprocess", "concurrent.futures",
                                    "aiohttp"])
def test_bnd_015_refuses_processes_and_other_networking(tmp_path, module):
    anchor = "from dataclasses import dataclass, field, replace\n"
    root = _with_profiles(tmp_path, {}, {"core/floor.py": (anchor,
                                                           anchor + f"import {module}\n")})
    line = (root / "core/floor.py").read_text().splitlines().index(f"import {module}") + 1
    assert gate.check_floor_machine_isolated(root) == [
        f"core/floor.py:{line}: floor control reaches {module!r} (core.floor)"]


@pytest.mark.vp("VP1-BND-015")
@pytest.mark.parametrize("files,line,expected", [
    ({}, "from core import sip\n", ["'core.sip' (core.floor)"]),
    ({}, "from service.media import MediaPlane\n",
     ["'service.media' (core.floor)", "'service.media.MediaPlane' (core.floor)"]),
    ({}, "import asyncio, ssl\n", ["'asyncio' (core.floor)", "'ssl' (core.floor)"]),
    ({}, "from . import rtcp\n", ["'core.rtcp' (core.floor)"]),
    ({}, "from .codec import Codec\n", ["'core.codec' (core.floor)",
                                       "'core.codec.Codec' (core.floor)"]),
    ({"core/helper.py": "import socket\n"}, "from . import helper\n",
     ["'socket' (core.floor -> core.helper)"]),
], ids=["core-sip", "service-media", "asyncio-ssl", "relative-rtcp", "relative-codec",
        "transitive"])
def test_bnd_015_catches_the_variants(tmp_path, files, line, expected):
    anchor = "from dataclasses import dataclass, field, replace\n"
    root = _with_profiles(tmp_path, files, {"core/floor.py": (anchor, anchor + line)})
    floor_line = next(n for n, l in enumerate((root / "core/floor.py").read_text().splitlines(), 1)
                      if l == line.rstrip("\n"))
    where = {"socket": "core/helper.py:1"}
    assert gate.check_floor_machine_isolated(root) == [
        f"{where.get(e.split(chr(39))[1], f'core/floor.py:{floor_line}')}: floor control "
        f"reaches {e}" for e in expected]


# -- batch C, the independent review's probes (round 2) ------------------------

_HOOKS = "profiles/mcx/hooks.py"
_TABLES = "profiles/common/tables.py"
_NOT_ALTERED = "the table interpreter is not altered by a profile"
_OWN = "a profile alters only its own instances (self)"


@pytest.mark.vp("VP1-BND-011")
@pytest.mark.parametrize("where,text,expected", [
    (_HOOKS, "import profiles.common.tables as _t\n_t.TablePriorityPolicy.evaluate = _mine\n",
     ["{L:_t.TablePriorityPolicy.evaluate =}: changes _t.TablePriorityPolicy.evaluate"]),
    (_HOOKS, "_k = TablePriorityPolicy\n_k.evaluate = _mine\n",
     ["{L:_k.evaluate =}: changes _k.evaluate"]),
    (_HOOKS, "def _p():\n    k = TablePriorityPolicy\n    k.evaluate = None\n",
     ["{L:k = TablePriorityPolicy}: holds TablePriorityPolicy in another name",
      "{L:k.evaluate = None}: changes k.evaluate from outside it"]),
    (_HOOKS, "a, b = TablePriorityPolicy, 1\na.evaluate = None\n",
     ["{L:a, b = }: holds TablePriorityPolicy in another name",
      "{L:a.evaluate = None}: changes a.evaluate from outside it"]),
    (_HOOKS, "type.__setattr__(TablePriorityPolicy, 'evaluate', _mine)\n",
     ["{L:type.__setattr__}: __setattr__ on TablePriorityPolicy"]),
    (_HOOKS, "import profiles.common.tables as _t\nsetattr(_t.TablePriorityPolicy, 'evaluate', 1)\n",
     ["{L:setattr(_t.}: setattr on _t.TablePriorityPolicy"]),
    (_HOOKS, "import profiles.common.tables as _t\n_t._matches = lambda r, a: True\n",
     ["{L:_t._matches =}: changes _t._matches"]),
    (_HOOKS, "import profiles.common.tables as _t\nclass _E(TablePriorityPolicy):\n    pass\n"
             "_t.TablePriorityPolicy = _E\n",
     ["{L:_t.TablePriorityPolicy = _E}: changes _t.TablePriorityPolicy"]),
    (_HOOKS, "X = vars()\n", ["{L:X = vars()}: calls vars(), which reaches every name"]),
    (_HOOKS, "X = TablePriorityPolicy.__dict__\n",
     ["{L:X = TablePriorityPolicy.__dict__}: reads __dict__, which reaches every name"]),
    (_TABLES, "globals()['TablePriorityPolicy'] = type('X', (), {})\n",
     ["{L:globals()[}: calls globals(), which reaches every name"]),
], ids=["through-module", "alias", "local-alias", "tuple-alias", "type-setattr",
        "setattr-through-module", "helper-from-profile", "class-replaced", "vars", "dict",
        "globals"])
def test_bnd_011_review_probes_round_2(tmp_path, where, text, expected):
    root = _with_profiles(tmp_path)
    path = root / where
    path.write_text(path.read_text() + "\n\n" + _MINE + text)
    got = gate.check_priority_table_declarative(root)
    assert [v for v in got if v != _INTERPRETER_CHANGED] == _lines(
        root, [f"{where}:{e}; {_OWN if e.endswith('from outside it') else _NOT_ALTERED}"
               for e in expected])


@pytest.mark.vp("VP1-BND-011")
def test_bnd_011_helpers_are_bound_once(tmp_path):
    root = _with_profiles(tmp_path)
    path = root / _TABLES
    path.write_text(path.read_text() + "\n\n_matches = lambda r, a: True\n")
    line = len(path.read_text().splitlines())
    # The fingerprint hashes the def, which is unchanged: only this rule sees it.
    assert gate.check_priority_table_declarative(root) == [
        f"{_TABLES}:{line}: rebinds _matches after its definition; the interpreter is the code "
        "as defined"]


@pytest.mark.vp("VP1-BND-011")
def test_bnd_011_the_interpreter_names_are_these():
    assert gate._interpreter_names(ROOT) == {"TablePriorityPolicy", "_matches"}


_LIT = "a priority is IF-PRI's, not derived from a label or number"


@pytest.mark.vp("VP1-BND-013")
@pytest.mark.parametrize("rel,text,expected", [
    ("core/sample.py", "def f(r):\n    ct = r.call_type\n    if ct == 'emergency':\n"
     "        return 9\n", [f"3: compares a request field with the literal 'emergency'; {_LIT}"]),
    ("core/sample.py", "def f(r):\n    ct = r.call_type.lower()\n    c2 = ct\n"
     "    return c2 == 'emergency'\n",
     [f"4: compares a request field with the literal 'emergency'; {_LIT}"]),
    ("core/sample.py", "EMERGENCY_TYPES = ('emergency',)\ndef f(r):\n"
     "    if r.call_type in EMERGENCY_TYPES:\n        return 9\n",
     [f"3: compares a request field with the literal 'emergency'; {_LIT}"]),
    ("core/sample.py", "def f(r):\n    return 9 if r.call_type.startswith('emerg') else 1\n",
     ["2: tests a request field against the literal 'emerg' (startswith); a priority is "
      "IF-PRI's, not derived from a label"]),
    ("core/sample.py", "def f(r):\n    match r.call_type:\n        case 'emergency':\n"
     "            return 9\n",
     ["2: branches on a request field or priority value with match; a priority is IF-PRI's"]),
    ("core/sample.py", "def f(r):\n    return getattr(r, 'call_type') == 'emergency'\n",
     [f"2: compares a request field with the literal 'emergency'; {_LIT}"]),
    ("core/sample.py", "def f(r):\n    return r.attributes['urgency'] == 'high'\n",
     ["2: compares a priority value in f; priority decisions are IF-PRI's (PRIORITY_USES "
      "lists the reviewed comparisons)",
      f"2: compares a priority value with the literal 'high'; {_LIT}"]),
    ("core/sample.py", "def f(r):\n    return {'emergency': 9, 'private': 5}.get(r.call_type, 1)\n",
     ["2: looks up a request field in the label table written inline; a priority is IF-PRI's",
      "2: maps labels onto numbers inline; a label-to-level mapping is a priority table"]),
    ("core/sample.py", "RANKS = {'emergency': 9, 'private': 5}\ndef f(r):\n"
     "    return RANKS.get(r.call_type, 1)\ndef g(r):\n    return RANKS[r.call_type]\n",
     ["3: looks up a request field in the label table RANKS; a priority is IF-PRI's",
      "5: looks up a request field in the label table RANKS; a priority is IF-PRI's"]),
    ("core/sample.py", "def _rank(s):\n    return s.request.urgency\ndef f(xs):\n"
     "    return sorted(xs, key=_rank)\n",
     ["4: orders by a priority value or request field in f; the order is IF-PRI's"]),
    ("core/sample.py", "import operator\ndef f(a, b):\n    return operator.gt(a.level, b.level)\n",
     ["3: compares a priority value in f; priority decisions are IF-PRI's (PRIORITY_USES "
      "lists the reviewed comparisons)"]),
    ("core/sample.py", "def f(a, b):\n    return b.level.__lt__(a.level)\n",
     ["2: compares a priority value in f; priority decisions are IF-PRI's (PRIORITY_USES "
      "lists the reviewed comparisons)"]),
    ("core/sample.py", "from core.hooks import PriorityDecision\ndef f(r):\n"
     "    n = 9 if r.adhoc else 1\n    return PriorityDecision(level=n, floor_priority=n)\n",
     ["3: chooses 9 by the request's adhoc; a priority is IF-PRI's",
      "4: builds a PriorityDecision from literals or a condition; a priority is IF-PRI's"]),
    ("core/sample.py", "from core.hooks import PriorityDecision\ndef f():\n"
     "    return PriorityDecision(**{'level': 9})\n",
     ["3: builds a PriorityDecision from an unpacked mapping; a priority is IF-PRI's, field "
      "by field"]),
    ("core/sample.py", "import dataclasses\ndef f(d):\n"
     "    return dataclasses.replace(d, floor_priority=d.floor_priority + 5)\n",
     ["3: replaces floor_priority with a computed value; a priority is IF-PRI's as decided"]),
    ("core/sample.py", "def f():\n    prio = 9\n",
     ["2: sets a priority value to 9; a priority is IF-PRI's"]),
    ("service/sample.py", "def lvl(r):\n    if r.call_type == 'emergency':\n        return 9\n"
     "    return 1\n", [f"2: compares a request field with the literal 'emergency'; {_LIT}"]),
], ids=["local-field", "local-chain", "constant-collection", "startswith", "match", "getattr",
        "subscript", "inline-table", "named-table-lookup", "key-function", "operator",
        "dunder", "literal-local-decision", "unpacked-decision", "replace", "prio",
        "service"])
def test_bnd_013_review_probes_round_2(tmp_path, rel, text, expected):
    root = _with_profiles(tmp_path, {rel: text})
    assert gate.check_no_priority_table_in_core(root) == [f"{rel}:{e}" for e in expected]


@pytest.mark.vp("VP1-BND-013")
@pytest.mark.parametrize("text", [
    "def f():\n    return {'accepted': 0, 'refused': 0}\n",
    "def f(p, r):\n    t = p.call_type(r.call_type)\n    return t.session_type == 'private'\n",
    "BUDGETS = {'IF-IDR': 50, 'IF-PRI': 5}\n",
], ids=["counters", "declared-lookup", "module-constant"])
def test_bnd_013_accepts_counters_and_declarations(tmp_path, text):
    assert gate.check_no_priority_table_in_core(_with_profiles(tmp_path,
                                                                {"core/sample.py": text})) == []


_ADHOC_CRITERIA = '        found = invoker.call("IF-IDR", "determine_participants",\n'
_REBUILT = ("the request is rebuilt before the resolver sees it; only the core's adding "
            "helpers (REQUEST_ENRICHERS) may change it")
_IN_PLACE = ("writes or holds an object's field table (vars, __dict__); values, the request "
             "among them, are not altered in place")
_HELD = "the resolver is held in a name; call it where it is, so its request can be seen"


@pytest.mark.vp("VP1-BND-014")
@pytest.mark.parametrize("files,patches,expected", [
    ({}, {"core/session.py": (_ADHOC, "                _m = self._adhoc_members\n"
                                      "                resolution, refusal = _m(invoker, request)\n")},
     ["core/session.py:{L:_m = self._adhoc_members}: _adhoc_members is referred to other than "
      "by a call; its callers must be seen to pass the request"]),
    ({}, {"core/session.py": (_ADHOC, "                resolution, refusal = getattr(self, "
                                      "'_adhoc_members')(invoker, request)\n")},
     ["core/session.py:{L:getattr(self, '_adhoc_members')}: _adhoc_members is looked up by "
      "name; its callers must be seen to pass the request"]),
    ({}, {"core/session.py": (_ADHOC_CRITERIA, "        vars(request).update(location=None)\n"
                                               + _ADHOC_CRITERIA)},
     ["core/session.py:{L:vars(request).update}: " + _REBUILT,
      "core/session.py:{L:vars(request).update}: " + _IN_PLACE]),
    ({}, {"core/session.py": (_ADHOC_CRITERIA, "        request.__dict__['location'] = None\n"
                                               + _ADHOC_CRITERIA)},
     ["core/session.py:{L:request.__dict__}: " + _REBUILT,
      "core/session.py:{L:request.__dict__}: " + _IN_PLACE]),
    ({"core/sample.py": "class M:\n    def f(self, t, request):\n"
      "        (r,) = (self._hooks.identity_resolver,)\n        return r.resolve(t, request)\n"},
     {}, ["core/sample.py:3: " + _HELD]),
    ({"core/sample.py": "class M:\n    def f(self, t, request):\n"
      "        return getattr(self._hooks, 'identity_resolver').resolve(t, request)\n"},
     {}, ["core/sample.py:3: " + _HELD]),
    ({"core/sample.py": "class M:\n    def f(self, t, request):\n"
      "        rs = [self._hooks.identity_resolver.resolve]\n        return rs[0](t, request)\n"},
     {}, ["core/sample.py:3: " + _HELD]),
], ids=["alias-caller", "getattr-caller", "vars-update", "dict-store", "tuple-held",
        "getattr-held", "list-held"])
def test_bnd_014_review_probes_round_2(tmp_path, files, patches, expected):
    root = _with_profiles(tmp_path, files, patches)
    assert gate.check_resolver_receives_context(root) == _lines(root, expected)


# -- batch C, the independent review's probes (round 3) ------------------------



@pytest.mark.vp("VP1-BND-011")
@pytest.mark.parametrize("text,expected", [
    ("from core.model import Profile as _P\n_orig = _P.call_type\n"
     "def _ct(self, cid):\n    return _orig(self, cid)\n_P.call_type = _ct\n",
     f"{{L:_P.call_type = _ct}}: changes _P.call_type from outside it; {_OWN}"),
    ("from core.hooks import PriorityDecision as _PD\n_PD.__init__ = lambda *a: None\n",
     f"{{L:_PD.__init__ =}}: changes _PD.__init__ from outside it; {_OWN}"),
    ("from core.model import Profile\na, b = Profile, 1\nsetattr(a, 'call_type', None)\n",
     [f"{{L:a, b = Profile}}: hands the core class Profile on; {_OWN}",
      f"{{L:setattr(a, 'call_type'}}: setattr on a; {_OWN}"]),
    ("TablePriorityPolicy.__delattr__('compare')\n",
     f"{{L:TablePriorityPolicy.__delattr__}}: __delattr__ on TablePriorityPolicy; "
     f"{_NOT_ALTERED}"),
], ids=["core-class-patched", "decision-init-patched", "setattr-through-tuple", "dunder-on-class"])
def test_bnd_011_review_probes_round_3(tmp_path, text, expected):
    root = _with_profiles(tmp_path)
    path = root / _HOOKS
    path.write_text(path.read_text() + "\n\n" + text)
    expected = expected if isinstance(expected, list) else [expected]
    assert gate.check_priority_table_declarative(root) == _lines(
        root, [f"{_HOOKS}:{e}" for e in expected])


@pytest.mark.vp("VP1-BND-011")
def test_bnd_011_a_profile_may_set_its_own_instances(tmp_path):
    root = _with_profiles(tmp_path)
    path = root / _HOOKS
    path.write_text(path.read_text() + "\n\nclass _Z:\n    def __init__(self):\n"
                    "        self.x = 1\n        object.__setattr__(self, 'y', 2)\n")
    assert gate.check_priority_table_declarative(root) == []


_FIELD = f"compares a request field with the literal 'emergency'; {_LIT}"


@pytest.mark.vp("VP1-BND-013")
@pytest.mark.parametrize("text,expected", [
    ("EMERG = 'emergency'\ndef f(r):\n    if r.call_type == EMERG:\n        return 9\n"
     "def g(r):\n    return r.call_type.startswith(EMERG)\n",
     [f"3: {_FIELD}", "6: tests a request field against the literal 'emergency' (startswith); "
      "a priority is IF-PRI's, not derived from a label"]),
    ("def f(r):\n    ct = r.call_type or ''\n    return ct == 'emergency'\n", [f"3: {_FIELD}"]),
    ("def f(r):\n    ct = str(r.call_type)\n    return ct == 'emergency'\n", [f"3: {_FIELD}"]),
    ("def f(r):\n    ct = f'{r.call_type}'\n    return ct == 'emergency'\n", [f"3: {_FIELD}"]),
    ("def f(r):\n    ct, n = r.call_type, 1\n    return ct == 'emergency'\n", [f"3: {_FIELD}"]),
    ("def f(r):\n    for ct in (r.call_type,):\n        return ct == 'emergency'\n",
     [f"3: {_FIELD}"]),
    ("def f(r):\n    with r.call_type as ct:\n        return ct == 'emergency'\n",
     [f"3: {_FIELD}"]),
    ("def f(r):\n    return r.call_type == 'EMERGENCY'.lower()\n", [f"2: {_FIELD}"]),
    ("TABLE = {'emergency': (9, 'national'), 'private': (5, 'local')}\ndef f(r):\n"
     "    return TABLE[r.call_type]\n",
     ["3: looks up a request field in the label table TABLE; a priority is IF-PRI's"]),
    ("TABLE = dict(emergency=9, private=5)\ndef f(r):\n    return TABLE.get(r.call_type, 1)\n",
     ["3: looks up a request field in the label table TABLE; a priority is IF-PRI's"]),
    ("def f(r):\n    return {'emergency': 9}.get(r.call_type, 1)\n",
     ["2: looks up a request field in the label table written inline; a priority is IF-PRI's"]),
    ("def _rank(s):\n    return s.request.urgency\ndef f(xs):\n"
     "    return sorted(xs, key=lambda s: _rank(s))\n",
     ["4: orders by a priority value or request field in f; the order is IF-PRI's"]),
    ("from core.hooks import PriorityDecision\ndef f():\n    n = 4 + 5\n"
     "    return PriorityDecision(level=n)\n",
     ["4: builds a PriorityDecision from literals or a condition; a priority is IF-PRI's"]),
    ("def f():\n    t = {'emergency': 9, 'private': 5}\n    return t\n",
     ["2: maps labels onto numbers inline; a label-to-level mapping is a priority table"]),
    ("def f(a, x):\n    return a.level.__gt__(x)\n",
     ["2: compares a priority value in f; priority decisions are IF-PRI's (PRIORITY_USES "
      "lists the reviewed comparisons)"]),
], ids=["text-constant", "or-default", "str", "f-string", "tuple-unpacking", "for-target",
        "with-target", "folded-literal", "tuple-valued-table", "dict-call-table",
        "one-key-inline-table", "lambda-calls-key", "folded-decision", "table-in-function",
        "dunder-on-the-value"])
def test_bnd_013_review_probes_round_3(tmp_path, text, expected):
    root = _with_profiles(tmp_path, {"core/sample.py": text})
    assert gate.check_no_priority_table_in_core(root) == [f"core/sample.py:{e}" for e in expected]




@pytest.mark.vp("VP1-BND-014")
@pytest.mark.parametrize("files,patches,expected", [
    ({}, {"core/session.py": (_ADHOC_CRITERIA, "        r = request\n"
                                               "        vars(r).update(application=None)\n"
                                               + _ADHOC_CRITERIA)},
     ["core/session.py:{L:vars(r).update}: " + _IN_PLACE]),
    ({"core/sample.py": "def _scrub(req):\n    vars(req)['location'] = None\n"}, {},
     ["core/sample.py:2: " + _IN_PLACE]),
    ({"core/sample.py": "def _scrub(req):\n    d = req.__dict__\n    d.clear()\n"}, {},
     ["core/sample.py:2: " + _IN_PLACE]),
    ({"core/sample.py": "def _names(m):\n    return [k for k in vars(m)]\n"}, {}, []),
    ({}, {"core/session.py": (_ADHOC_CRITERIA, "        request.location = None\n"
                                               + _ADHOC_CRITERIA)},
     ["core/session.py:{L:request.location = None}: " + _REBUILT]),
    ({"core/sample.py": "class M:\n    def f(self, t, request):\n"
      "        self._keep(self._hooks.identity_resolver.resolve)\n"}, {},
     ["core/sample.py:3: " + _HELD,
      "core/sample.py:3: the resolver is not given the request the function received; it "
      "must see the whole request"]),
], ids=["alias", "helper", "held", "read-only", "attribute-store", "handed-to-another-call"])
def test_bnd_014_review_probes_round_3(tmp_path, files, patches, expected):
    root = _with_profiles(tmp_path, files, patches)
    assert gate.check_resolver_receives_context(root) == _lines(root, expected)


@pytest.mark.vp("VP1-BND-011")
@pytest.mark.parametrize("text", ["def _matches(rule, value):\n    return rule is value\n",
                                  "from profiles.common.base import _matches\n"],
                         ids=["def", "import"])
def test_bnd_011_a_helper_is_not_redefined(tmp_path, text):
    root = _with_profiles(tmp_path)
    path = root / _TABLES
    path.write_text(path.read_text() + "\n\n" + text)
    line = len(path.read_text().splitlines()) - text.count("\n") + 1
    got = gate.check_priority_table_declarative(root)
    assert [v for v in got if v != _INTERPRETER_CHANGED] == [
        f"{_TABLES}:{line}: rebinds _matches after its definition; the interpreter is the code "
        "as defined"]


# -- batch C, the independent review's probes (round 4) ------------------------


@pytest.mark.vp("VP1-BND-011")
@pytest.mark.parametrize("text,expected", [
    ("from core.model import Profile as _P\nclass _X:\n    def go(self):\n        self = _P\n"
     "        self.call_type = lambda s, c: None\n",
     ["{L:self = _P}: hands the core class _P on",
      "{L:self.call_type = lambda}: changes self.call_type from outside it"]),
    ("from core.model import Profile as _P\nclass _X:\n    @classmethod\n    def go(cls):\n"
     "        cls = _P\n        cls.call_type = None\n",
     ["{L:cls = _P}: hands the core class _P on",
      "{L:cls.call_type = None}: changes cls.call_type from outside it"]),
    ("from core.model import Profile as _P\ndef _go(self):\n    self.call_type = None\n"
     "_go(_P)\n", ["{L:self.call_type = None}: changes self.call_type from outside it",
                    "{L:_go(_P)}: hands the core class _P on"]),
    ("def _go(self):\n    setattr(self, 'call_type', None)\n",
     ["{L:setattr(self, 'call_type'}: setattr on self"]),
], ids=["self-rebound", "cls-rebound", "self-in-a-function", "setattr-self-in-a-function"])
def test_bnd_011_review_probes_round_4(tmp_path, text, expected):
    root = _with_profiles(tmp_path)
    path = root / _HOOKS
    path.write_text(path.read_text() + "\n\n" + text)
    assert gate.check_priority_table_declarative(root) == _lines(
        root, [f"{_HOOKS}:{e}; {_OWN}" for e in expected])


@pytest.mark.vp("VP1-BND-013")
@pytest.mark.parametrize("text,expected", [
    ("from core.hooks import PriorityDecision\nNINE = 9\ndef f():\n"
     "    return PriorityDecision(NINE, 's', True, False, NINE, 'x')\n",
     ["4: builds a PriorityDecision from literals or a condition; a priority is IF-PRI's"]),
    ("from core.hooks import PriorityDecision\nclass K:\n    N = 9\ndef f():\n"
     "    return PriorityDecision(level=K.N)\n",
     ["5: builds a PriorityDecision from literals or a condition; a priority is IF-PRI's",
      "5: passes level=9; a priority is IF-PRI's"]),
    ("ORDER = ['private', 'group', 'emergency']\ndef f(r):\n    return ORDER.index(r.call_type)\n",
     ["3: looks up a request field in the label table ORDER; a priority is IF-PRI's"]),
    ("PAIRS = (('emergency', 9), ('private', 5))\ndef f(r):\n    for k, v in PAIRS:\n"
     "        if k == r.call_type:\n            return v\n",
     ["4: compares a request field with a member of the literal collection PAIRS; a priority "
      "is IF-PRI's, not derived from a label or number"]),
    ("TABLE = dict(zip(('emergency', 'private'), (9, 5)))\ndef f(r):\n"
     "    return TABLE[r.call_type]\n",
     ["3: looks up a request field in the label table TABLE; a priority is IF-PRI's"]),
    ("def f(r):\n    return {k: 9 for k in ('emergency',)}.get(r.call_type, 1)\n",
     ["2: looks up a request field in the label table written inline; a priority is IF-PRI's"]),
    ("import re\ndef f(r):\n    return re.match('emerg', r.call_type)\n",
     ["3: tests a request field against the literal 'emerg' (match); a priority is IF-PRI's, "
      "not derived from a label"]),
    ("def f(r):\n    return {r.call_type} & {'emergency'}\n",
     ["2: tests a request field against the literal 'emergency' (a set operation); a priority "
      "is IF-PRI's, not derived from a label"]),
    ("def f(r):\n    if r.adhoc_alert_group:\n        return 9\n    return 1\n",
     ["3: returns 9 chosen by the request's adhoc_alert_group; a priority is IF-PRI's"]),
    ("def f(d):\n    level = getattr(d, 'nothing', 9)\n",
     ["2: sets a priority value to 9; a priority is IF-PRI's"]),
    ("def f(r):\n    ct = r.call_type if r else ''\n    return ct == 'emergency'\n",
     [f"3: {_FIELD}"]),
    ("def f(r):\n    n, ct = 1, r.call_type\n    return ct == 'emergency'\n", [f"3: {_FIELD}"]),
    ("def f(r, x):\n    ct, n = r.call_type, x\n    return n == 'other'\n", []),
], ids=["module-constant-decision", "class-constant-decision", "list-index", "pairs-loop",
        "zip-table", "comprehension-table", "re-match", "set-operation", "request-flag",
        "getattr-default", "conditional-taint", "second-of-a-pair", "untainted-neighbour"])
def test_bnd_013_review_probes_round_4(tmp_path, text, expected):
    root = _with_profiles(tmp_path, {"core/sample.py": text})
    assert gate.check_no_priority_table_in_core(root) == [f"core/sample.py:{e}" for e in expected]


@pytest.mark.vp("VP1-BND-013")
def test_bnd_013_the_request_attributes_are_read_from_the_interface():
    attributes = gate._request_attributes(ROOT)
    assert {"call_type", "application", "urgency", "adhoc_alert_group", "initiator",
            "location"} <= attributes


_OTHER_NAME = ("reaches an object's field table through another name; values, the request "
               "among them, are not altered in place")


@pytest.mark.vp("VP1-BND-014")
@pytest.mark.parametrize("text,line", [
    ("def f(request):\n    v = vars\n    v(request).update(application=None)\n", 2),
    ("def f(request):\n    getattr(request, '__dict__').update(application=None)\n", 2),
], ids=["vars-held", "getattr-dict"])
def test_bnd_014_review_probes_round_4(tmp_path, text, line):
    root = _with_profiles(tmp_path, {"core/sample.py": text})
    assert gate.check_resolver_receives_context(root) == [f"core/sample.py:{line}: {_OTHER_NAME}"]


# -- batch C, the independent review's probes (round 5) ------------------------


@pytest.mark.vp("VP1-BND-011")
@pytest.mark.parametrize("text,expected", [
    ("from core.model import Profile as _P\nclass _X:\n    def go(self):\n"
     "        self.call_type = None\n_X.go(_P)\n",
     ["{L:_X.go(_P)}: hands the core class _P on"]),
    ("class _X:\n    @staticmethod\n    def go(self):\n        self.call_type = None\n",
     ["{L:self.call_type = None}: changes self.call_type from outside it"]),
    ("class _X:\n    def go(self):\n        self.p.call_type = None\n",
     ["{L:self.p.call_type}: changes self.p.call_type from outside it"]),
    ("from core.model import Profile as _P\nclass _X:\n    def go(self):\n"
     "        self.call_type = None\nx = _P\n_X.go(x)\n",
     ["{L:x = _P}: hands the core class _P on"]),
], ids=["class-called-with-core-class", "staticmethod-self", "chain-through-self",
        "core-class-aliased"])
def test_bnd_011_review_probes_round_5(tmp_path, text, expected):
    root = _with_profiles(tmp_path)
    path = root / _HOOKS
    path.write_text(path.read_text() + "\n\n" + text)
    assert gate.check_priority_table_declarative(root) == _lines(
        root, [f"{_HOOKS}:{e}; {_OWN}" for e in expected])


@pytest.mark.vp("VP1-BND-011")
def test_bnd_011_a_profile_may_name_core_classes_in_place(tmp_path):
    root = _with_profiles(tmp_path)
    path = root / _HOOKS
    path.write_text(path.read_text() + "\n\nfrom typing import Dict, Optional, Tuple\n"
                    "from core.model import Profile as _P\n"
                    "def _f(x: Optional[_P]) -> _P:\n    y: Dict[str, Tuple[_P, ...]] = {}\n"
                    "    return isinstance(x, (_P, int)) and _P.call_type\n")
    assert gate.check_priority_table_declarative(root) == []


_CHOSEN = "a priority is IF-PRI's"


@pytest.mark.vp("VP1-BND-013")
@pytest.mark.parametrize("text,expected", [
    ("def f(r):\n    return 9 if r.adhoc_alert_group else 1\n",
     [f"2: chooses 9 by the request's adhoc_alert_group; {_CHOSEN}"]),
    ("def f(r):\n    n = 1\n    if r.adhoc_alert_group:\n        n = 9\n    return n\n",
     [f"4: sets 9 chosen by the request's adhoc_alert_group; {_CHOSEN}"]),
    ("HIGH = 9\ndef f(r):\n    if r.adhoc_alert_group:\n        return HIGH\n",
     [f"4: returns 9 chosen by the request's adhoc_alert_group; {_CHOSEN}"]),
    ("def f(r):\n    alert = r.adhoc_alert_group\n    if alert:\n        return 9\n",
     [f"4: returns 9 chosen by the request's alert; {_CHOSEN}"]),
    ("def f(r):\n    if r.adhoc_alert_group is True:\n        return 9\n",
     [f"3: returns 9 chosen by the request's adhoc_alert_group; {_CHOSEN}"]),
    ("def f(r):\n    return 1 + 8 * r.adhoc_alert_group\n",
     [f"2: scales 8 by the request's adhoc_alert_group; {_CHOSEN}"]),
    ("import re\n_E = re.compile('emerg')\ndef f(r):\n    return _E.match(r.call_type)\n",
     ["4: looks up a request field in the label table _E; a priority is IF-PRI's",
      "4: tests a request field against the literal 'emerg' (match); a priority is IF-PRI's, "
      "not derived from a label"]),
    ("_T = {}\n_T['emergency'] = 9\ndef f(r):\n    return _T.get(r.call_type, 1)\n",
     ["4: looks up a request field in the label table _T; a priority is IF-PRI's"]),
    ("KEYS = ('emergency', 'private')\nVALS = (9, 5)\nTABLE = dict(zip(KEYS, VALS))\n"
     "def f(r):\n    return TABLE[r.call_type]\n",
     ["5: looks up a request field in the label table TABLE; a priority is IF-PRI's"]),
    ("def f(r):\n    return ('private', 'group', 'emergency').index(r.call_type)\n",
     ["2: looks up a request field in the label table written inline; a priority is IF-PRI's"]),
    ("def f(r):\n    if r.adhoc:\n        return 404\n    return 200\n", []),
], ids=["conditional-expression", "assigned-in-branch", "constant-returned", "flag-in-a-local",
        "is-true", "scaled-by-flag", "compiled-pattern", "filled-table", "zip-of-constants",
        "inline-index", "status-codes-are-not-levels"])
def test_bnd_013_review_probes_round_5(tmp_path, text, expected):
    root = _with_profiles(tmp_path, {"core/sample.py": text})
    assert gate.check_no_priority_table_in_core(root) == [f"core/sample.py:{e}" for e in expected]


@pytest.mark.vp("VP1-BND-013")
def test_bnd_013_the_common_attributes_are_these():
    assert gate._COMMON_ATTRIBUTES == {"attributes", "media", "location", "target", "request_id",
                                       "initiator", "participants"}


# -- batch C, the independent review's probes (round 6) ------------------------


@pytest.mark.vp("VP1-BND-013")
@pytest.mark.parametrize("text,expected", [
    ("def f(request):\n    if request.attributes.get('emergency') == 'true':\n        return 9\n",
     [f"2: compares a request field with the literal 'true'; {_LIT}"]),
    ("VIPS = ('sip:chief@x',)\ndef f(s):\n    return 9 if s.request.initiator in VIPS else 1\n",
     [f"3: compares a request field with the literal 'sip:chief@x'; {_LIT}"]),
    ("from core.hooks import SessionRequest\ndef f(r: SessionRequest):\n"
     "    if 'video' in r.media:\n        return 9\n",
     [f"3: compares a request field with the literal 'video'; {_LIT}"]),
    ("def f(request):\n    if request.target.startswith('sip:emergency'):\n        return 9\n",
     ["2: tests a request field against the literal 'sip:emergency' (startswith); a priority "
      "is IF-PRI's, not derived from a label"]),
    ("def f(r, base):\n    return base + 5 if r.adhoc_alert_group else base\n",
     [f"2: chooses 5 by the request's adhoc_alert_group; {_CHOSEN}"]),
    ("def f(r, n):\n    if r.adhoc_alert_group:\n        n += 5\n    return n\n",
     [f"3: sets 5 chosen by the request's adhoc_alert_group; {_CHOSEN}"]),
    ("def f(r, base):\n    return max(base, 9) if r.adhoc_alert_group else base\n",
     [f"2: chooses 9 by the request's adhoc_alert_group; {_CHOSEN}"]),
    ("import dataclasses\ndef f(d, r):\n"
     "    return dataclasses.replace(d, preemption_capability=r.adhoc_alert_group)\n",
     ["3: replaces preemption_capability with a computed value; a priority is IF-PRI's as "
      "decided"]),
    ("def f(r):\n    table = {'emergency': 9}\n    return table.get(r.call_type, 1)\n",
     ["3: looks up a request field in the label table table; a priority is IF-PRI's"]),
    ("def f(rule):\n    return rule.media == 'audio'\n", []),
    ("def f(sessions):\n    return sorted(sessions, key=lambda s: s.request.adhoc_alert_group)\n",
     ["2: orders by a priority value or request field in f; the order is IF-PRI's"]),
    ("def f(request):\n    return request.attributes.get('core.active_sessions', '0')\n", []),
], ids=["attributes-of-the-request", "initiator-of-session-request", "annotated-request-media",
        "request-target", "adjusted-arm", "augmented-in-branch", "max-in-arm",
        "decision-field-from-request", "table-in-a-local", "common-name-elsewhere",
        "ordered-by-a-flag", "key-is-not-a-literal"])
def test_bnd_013_review_probes_round_6(tmp_path, text, expected):
    root = _with_profiles(tmp_path, {"core/sample.py": text})
    assert gate.check_no_priority_table_in_core(root) == [f"core/sample.py:{e}" for e in expected]


# -- batch C: the rebuilt helpers' own probes ------------------------------------


@pytest.mark.vp("VP1-BND-011")
def test_bnd_011_an_opaque_rebinding_does_not_resolve(tmp_path):
    root = _with_profiles(tmp_path, patches={
        "profiles/mcx/hooks.py": ("    TableSessionPolicy,\n)\n",
                                  "    TableSessionPolicy,\n)\nPolicy = dict(x=TablePriorityPolicy)\n"),
        "profiles/mcx/profile.yaml": ("profiles.mcx.hooks:TablePriorityPolicy",
                                      "profiles.mcx.hooks:Policy")})
    assert gate.check_priority_table_declarative(root) == _lines(root, [
        "profiles/mcx/profile.yaml: profile.hooks.priority_policy ('profiles.mcx.hooks:Policy') "
        "does not resolve to a class in the tree",
        "profiles/mcx/hooks.py:{L:Policy = dict}: holds TablePriorityPolicy in another name; the "
        "table interpreter is not altered by a profile"])


@pytest.mark.vp("VP1-BND-014")
@pytest.mark.parametrize("text,expected", [
    ("class M:\n    def f(self, target, request, other):\n        request = self._located(other)\n"
     "        return self._hooks.identity_resolver.resolve(target, request)\n",
     ["core/sample.py:3: the request is rebuilt before the resolver sees it; only the core's "
      "adding helpers (REQUEST_ENRICHERS) may change it"]),
    ("class M:\n    def f(self, target, request):\n"
     "        return self._hooks.identity_resolver.resolve(target, request=request)\n", []),
    ("class M:\n    def f(self, target, *, request):\n"
     "        return self._hooks.identity_resolver.resolve(target, request)\n", []),
    ("class M:\n    def f(self, target, request):\n        def helper(request):\n"
     "            request = None\n            return request\n"
     "        return self._hooks.identity_resolver.resolve(target, request)\n", []),
], ids=["enricher-given-another", "request-by-keyword", "keyword-only-parameter",
        "nested-function-is-its-own"])
def test_bnd_014_what_counts_as_the_request(tmp_path, text, expected):
    root = _with_profiles(tmp_path, {"core/sample.py": text})
    assert gate.check_resolver_receives_context(root) == expected


@pytest.mark.vp("VP1-BND-011")
def test_bnd_011_the_last_binding_is_the_one_followed(tmp_path):
    root = _with_profiles(tmp_path, patches={
        "profiles/mcx/hooks.py": ("    TableSessionPolicy,\n)\n",
                                  "    TableSessionPolicy,\n)\n"
                                  "TablePriorityPolicy = dict(x=TablePriorityPolicy)\n")})
    got = gate.check_priority_table_declarative(root)
    assert ("profiles/mcx/profile.yaml: profile.hooks.priority_policy "
            "('profiles.mcx.hooks:TablePriorityPolicy') does not resolve to a class in the tree"
            ) in got


@pytest.mark.vp("VP1-BND-011")
def test_bnd_011_a_name_the_interpreter_reads_is_bound_once(tmp_path):
    root = _with_profiles(tmp_path)
    path = root / _TABLES
    path.write_text(path.read_text() + "\n\nHookContractViolation = RuntimeError\n")
    line = len(path.read_text().splitlines())
    assert gate.check_priority_table_declarative(root) == [
        f"{_TABLES}:{line}: rebinds HookContractViolation after its definition; the "
        "interpreter is the code as defined"]


@pytest.mark.vp("VP1-BND-014")
@pytest.mark.parametrize("old,new", [
    ("        request = self._located(request)\n",
     "        request = _located(request)\n"),
    ("        request = self._located(request)\n",
     "        request = self._cells._located(request)\n"),
    ("        request = self._located(request)\n",
     "        request = self._located(dataclasses.replace(request, location=None), request)\n"),
    ("        request = self._located(request)\n",
     "        request = cells._located(request)\n"),
], ids=["module-function", "other-receiver", "request-not-first", "other-name-receiver"])
def test_bnd_014_an_enricher_is_the_cores_own_method_given_the_request(tmp_path, old, new):
    root = _with_profiles(tmp_path, patches={"core/session.py": (old, new)})
    assert gate.check_resolver_receives_context(root) == _lines(root, [
        f"core/session.py:{{L:{new.strip()[:30]}}}: the request is rebuilt before the resolver "
        "sees it; only the core's adding helpers (REQUEST_ENRICHERS) may change it"])
