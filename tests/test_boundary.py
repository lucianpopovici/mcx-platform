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


def test_forbidden_term_check_detects_an_injected_violation(tmp_path):
    _stage(tmp_path, core_extra="# a railway-specific note\n")
    violations = gate.check_forbidden_terms(tmp_path)
    assert violations and "railway" in violations[0]


def test_import_check_detects_an_injected_violation(tmp_path):
    _stage(tmp_path, core_extra="from profiles.mcx import hooks\n")
    violations = gate.check_imports(tmp_path)
    assert violations and "profiles.mcx" in violations[0]


def test_hook_call_site_check_detects_an_undeclared_method(tmp_path):
    _stage(tmp_path,
           core_extra="def f(h):\n    return h.priority_policy.recalculate()\n")
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
    assert violations and "Leaky" in violations[0]


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
