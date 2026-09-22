"""The railway profile against its own governing document (PLT-CONF-AUDIT CA-15).

This file is deliberately NOT part of `test_conformance.py`. That suite is
profile-agnostic by design — its docstring says a test needing
`if profile.name == ...` would be evidence the abstraction had failed. This
one is the opposite kind of test: it holds one profile to a document that
governs only that profile.

Both are legitimate, and the boundary rule is unaffected: tests may know which
profile they are testing. Only `core/` may not.

Source: UIC FRMCS SRS (AT-7800) v2.1.0, in `docs/`. The clauses below read
cleanly as prose. The Annex A table that assigns QoS parameters per
communication session does NOT survive PDF extraction, and is recorded as
CA-16 rather than guessed at — so this file checks the constraints the
document states in words, not the per-session values.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PROFILE = ROOT / "profiles" / "frmcs" / "profile.yaml"

# Clause 14.6.2.1 (M): "shall support the standardized 5QI values 5, 8, 65, 69"
FRMCS_MANDATORY_5QI = {5, 8, 65, 69}
# Clause 14.6.2.2 (O-Vx): "should support the standardized 5QI values 70"
FRMCS_OPTIONAL_5QI = {70}

# Clause 14.6.5.3 (M): "shall apply the ARP values 1 to 8".
# Note 1: "ARP values 9-15 are a national matter."
FRMCS_ARP_MIN, FRMCS_ARP_MAX = 1, 8


@pytest.fixture(scope="module")
def bearer_rules():
    with PROFILE.open() as fh:
        return yaml.safe_load(fh)["bearer"]["rules"]


def test_every_5qi_is_one_the_frmcs_system_supports(bearer_rules):
    """Clause 14.6.2. This profile requested 5QI 67 for its ETCS bearer --
    Mission Critical Video in TS 23.501, and not in the FRMCS set at all."""
    permitted = FRMCS_MANDATORY_5QI | FRMCS_OPTIONAL_5QI
    used = {r["decision"]["qos_identifier"] for r in bearer_rules}
    assert used <= permitted, sorted(used - permitted)
    assert 67 not in used, "5QI 67 is Mission Critical Video and clause " \
                           "14.6.2.1 does not list it"


def test_every_arp_level_is_within_the_mandatory_range(bearer_rules):
    """Clause 14.6.5.3. A level of 9 or above is legal in TS 23.501, whose
    range is 1-15, but Note 1 makes 9-15 "a national matter" -- so a profile
    using one is not portable across FRMCS deployments."""
    for rule in bearer_rules:
        arp = rule["decision"]["arp_level"]
        assert FRMCS_ARP_MIN <= arp <= FRMCS_ARP_MAX, (rule["match"], arp)


def test_the_5qi_values_are_consistent_with_the_media_they_carry(bearer_rules):
    """Cross-check against TS 23.501, so this file fails if either document's
    constraint is broken rather than only the railway one."""
    from core.qos import media_of
    for rule in bearer_rules:
        expected = media_of(rule["decision"]["qos_identifier"])
        media = rule["match"]["media"]
        if expected is not None and media != "*":
            assert media == expected, (rule["match"], expected)
