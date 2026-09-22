"""The railway profile against its own governing document (PLT-CONF-AUDIT CA-15).

This file is deliberately NOT part of `test_conformance.py`. That suite is
profile-agnostic by design — its docstring says a test needing
`if profile.name == ...` would be evidence the abstraction had failed. This
one is the opposite kind of test: it holds one profile to a document that
governs only that profile.

Both are legitimate, and the boundary rule is unaffected: tests may know which
profile they are testing. Only `core/` may not.

Source: UIC FRMCS SRS (AT-7800) v2.1.0, in `docs/`.

Annex A assigns a 5QI per communication session and is the authoritative
table: clause 14.6.6.1 (M-V3) says the QoS parameter values that shall be
applied "are listed in Annex A". It does not survive PDF extraction, so its
contents were read from the document by hand (PLT-CONF-AUDIT CA-16):

    FRMCS Signalling (4)      5QI 5 / 69      Emergency Voice (6)   5QI 65 GBR
    Pre-defined Default (5)   5QI 8           Voice (7)             5QI 65 GBR
    Urgent Data (8)           5QI 8           General Data (9)      5QI 8
    TCMS (10)                 5QI 8           ATP Compl. Data (12)  5QI 8
    ATO (13)                  5QI 8           ATP Regular Data (11) 5QI 4  GBR

**The document contradicts itself, and this file follows Annex A.** Clause
14.6.2.1 (M) says the FRMCS system "shall support the standardized 5QI values
5, 8, 65, 69", with 70 optional under 14.6.2.2 — but Annex A assigns **5QI 4**
to ATP Regular Data, and 4 is in neither list. 14.6.2.1 states which values a
system must support; Annex A states which are actually used. Where they
disagree, the per-session table is what a deployment has to interoperate with.

Recorded as FRMCS-OP-01. It is a question for UIC, not something to resolve
here, and it is the reason the permitted set below is derived from Annex A
rather than from the clause that reads like a definitive list.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PROFILE = ROOT / "profiles" / "frmcs" / "profile.yaml"

# Every 5QI Annex A assigns to a communication session.
ANNEX_A_5QI = {4, 5, 8, 65, 69}
# Clause 14.6.2.1 (M), narrower than Annex A -- see FRMCS-OP-01 above.
CLAUSE_14_6_2_5QI = {5, 8, 65, 69, 70}

# Clause 14.6.5.3 (M): "shall apply the ARP values 1 to 8".
# Note 1: "ARP values 9-15 are a national matter."
FRMCS_ARP_MIN, FRMCS_ARP_MAX = 1, 8


@pytest.fixture(scope="module")
def bearer_rules():
    with PROFILE.open() as fh:
        return yaml.safe_load(fh)["bearer"]["rules"]


def test_every_5qi_is_one_annex_a_assigns(bearer_rules):
    """This profile requested 5QI 67 for its ETCS bearer -- Mission Critical
    Video in TS 23.501, and in neither FRMCS list."""
    used = {r["decision"]["qos_identifier"] for r in bearer_rules}
    assert used <= ANNEX_A_5QI, sorted(used - ANNEX_A_5QI)
    assert 67 not in used, "5QI 67 is Mission Critical Video; FRMCS uses it " \
                           "for nothing"


def test_the_etcs_bearer_uses_the_annex_a_value_for_atp_regular_data(bearer_rules):
    """Annex A note (11): "ATP Regular Data" is ETCS on-board to ETCS
    trackside, and Annex A gives it 5QI 4 with a guaranteed bit rate.

    Pinned on its own because it is the one assignment that cannot be derived
    from the prose clauses -- an earlier revision of this profile guessed 69
    from them and was wrong.
    """
    etcs = next(r for r in bearer_rules
                if r["match"].get("call_type") == "etcs-ipcon")
    assert etcs["decision"]["qos_identifier"] == 4


def test_general_data_uses_the_annex_a_value(bearer_rules):
    """Annex A gives 5QI 8 to General Data, Urgent Data, TCMS, ATP Compl.
    Data and ATO alike -- every data session that is not ATP Regular Data."""
    fallback = next(r for r in bearer_rules
                    if r["match"].get("call_type") == "*"
                    and r["match"].get("media") == "data")
    assert fallback["decision"]["qos_identifier"] == 8


def test_the_two_frmcs_clauses_disagree_and_that_is_recorded(bearer_rules):
    """FRMCS-OP-01, pinned so it cannot be quietly forgotten.

    If a future SRS revision adds 4 to clause 14.6.2.1, this test fails and
    the open point can be closed. That is the intent: the discrepancy is
    load-bearing for the ETCS bearer, which is the safety-relevant one.
    """
    assert 4 in ANNEX_A_5QI and 4 not in CLAUSE_14_6_2_5QI
    used = {r["decision"]["qos_identifier"] for r in bearer_rules}
    assert used - CLAUSE_14_6_2_5QI == {4}


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
