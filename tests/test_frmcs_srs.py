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


# -- FRS appendix J: priority ordering (PLT-CONF-AUDIT CA-17) -------------------

# UIC FRMCS FRS (FU-7120) v2.1.0, table J-1 "Priority ordering". The appendix
# states the rule plainly: "The ordering of priorities is according to the
# row's. In total seven priority levels are defined and are numbered with
# letters A to G", and a higher-priority application "can take over resources
# from lower priority FRMCS applications".
#
# The seven CATEGORY boundaries do not survive PDF extraction. The ROW ORDER
# does, and the row order is what the appendix says the ordering is. So this
# encodes relative order between the applications this profile models, which
# is exactly as much as the document supports and no more.
FRS_ROW_ORDER = (
    "10.11",        # REC-alert / REC-voice / REC-data
    "10.18", "10.19",
    "11.34", "11.4",        # ATP -- ETCS on-board to trackside
    "10.3", "10.4", "10.5", "10.6", "10.8",     # 10.8 shunting voice
    "11.3", "11.15",
    "10.10", "10.23",
    "11.5",                 # ATO
    "11.9", "11.18", "11.33", "11.19",
    "11.27", "11.28",
    "10.2", "11.2",         # generic voice, generic data
)

# Which FRS application each of this profile's applications is.
PROFILE_APPLICATION_TO_FRS = {
    "rec": "10.11",
    "etcs": "11.4",
    "shunting": "10.8",
    "ato": "11.5",
}


@pytest.fixture(scope="module")
def priority_rules():
    with PROFILE.open() as fh:
        return yaml.safe_load(fh)["priority"]["rules"]


def test_priority_levels_follow_the_frs_row_order(priority_rules):
    """The defect CA-17 found.

    ATO was at level 80 and shunting at 60, so under congestion this profile
    would have pre-empted a shunting call to make room for automatic train
    operation data. Table J-1 puts 10.8 above 11.5.
    """
    level = {}
    for rule in priority_rules:
        app = rule["match"].get("application")
        if app in PROFILE_APPLICATION_TO_FRS:
            level[app] = rule["decision"]["level"]

    assert set(level) == set(PROFILE_APPLICATION_TO_FRS), sorted(level)

    ranked = sorted(level, key=lambda a: FRS_ROW_ORDER.index(
        PROFILE_APPLICATION_TO_FRS[a]))
    levels = [level[a] for a in ranked]
    assert levels == sorted(levels, reverse=True), \
        list(zip(ranked, levels))
    assert len(set(levels)) == len(levels), "two applications share a level"

    # The pair the appendix's own example turns on, asserted directly.
    assert level["shunting"] > level["ato"]
    assert level["rec"] > level["etcs"] > level["shunting"]


# SRS Annex A note (7): "Voice" include FRS applications 10.18-10.19 (ARP=3),
# 10.3-10.6 (ARP=5), 10.10+10.23 (ARP=6), 10.2 (ARP=8).
# Note (8): "Urgent Data" includes 11.15 (ARP=5), 11.34 (ARP=3).
# Note (9): "General Data" includes 11.3 (ARP=5), 11.9 (ARP=6).
FRS_APPLICATION_ARP = {
    "10.18": 3, "10.19": 3, "11.34": 3,
    "10.3": 5, "10.4": 5, "10.5": 5, "10.6": 5, "11.3": 5, "11.15": 5,
    "10.10": 6, "10.23": 6, "11.9": 6,
    "10.2": 8,
}


def test_the_driver_controller_bearer_uses_the_arp_its_application_is_given(
        bearer_rules):
    """A driver-to-controller call is FRS 10.3/10.4, which note (7) gives
    ARP=5. It was falling through to the catch-all at ARP 6, which the same
    note reserves for ground-to-ground (10.10) and public address (10.23)."""
    rule = next(r for r in bearer_rules
                if r["match"].get("call_type") == "driver-controller")
    assert rule["decision"]["arp_level"] == FRS_APPLICATION_ARP["10.3"] == 5


def test_shunting_has_no_invented_qos(bearer_rules):
    """SHUNT-OP-01. SRS Annex A note (1) lists 10.8 among the FRS applications
    "not yet covered", so the SRS assigns shunting voice no communication
    session, no 5QI and no ARP.

    This profile therefore must NOT carry a shunting-specific bearer rule:
    there is nothing to transcribe, and inventing one is the failure this
    audit exists to prevent. Shunting falls through to the catch-all, and that
    is recorded rather than dressed up as conformance.
    """
    assert not any(r["match"].get("call_type") == "shunting-group"
                   for r in bearer_rules)
