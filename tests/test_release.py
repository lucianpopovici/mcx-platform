"""The 3GPP release as a deployment parameter (PLT-REL-001..008, VP1-REL-*).

`MCX_RELEASE` selects the release once, at start. This file proves the gate
actually gates: for each supported release, everything that release defines
encodes and everything it does not is refused.

The tables in `core/release.py` were extracted mechanically from the eight
published versions of TS 24.380 in `docs/3GPP/`. The expectations below are
written out as literals rather than derived from those tables, because a test
that imports the table it is checking proves only that the table equals itself
(PLT-CONF-AUDIT 4.10).
"""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import rtcp                                        # noqa: E402
from core.errors import StartupRefused                       # noqa: E402
from core.release import Release, parse, subtype_name        # noqa: E402

RELEASES = tuple(range(13, 21))


# -- the parameter itself ------------------------------------------------------


@pytest.mark.parametrize("text,expected", [
    ("17", Release.REL_17), ("Rel-17", Release.REL_17),
    ("rel-20", Release.REL_20), (" 13 ", Release.REL_13),
])
def test_release_is_parsed_from_the_forms_an_operator_would_write(text, expected):
    assert parse(text) is expected


@pytest.mark.parametrize("text", ["", "  ", "21", "12", "seventeen", "17.1", "R17x"])
def test_an_unsupported_release_is_refused_not_guessed(text):
    """PLT-REL-002. There is no default and no nearest match: a deployment
    that did not state a release does not start."""
    with pytest.raises(StartupRefused) as exc:
        parse(text)
    assert "MCX_RELEASE" in str(exc.value)


# -- what each release defines -------------------------------------------------


# subtype -> the first release that assigns it, per TS 24.380 table 8.2.2.1-1.
FIRST_RELEASE_OF_SUBTYPE = {
    0: 13, 1: 13, 2: 13, 3: 13, 4: 13, 5: 13, 6: 13,
    7: 19,      # Floor Revoke Request
    8: 13, 9: 13, 10: 13,
    11: 17,     # Unicast Media Flow Control
    14: 17,     # Floor Queued Cancel, then Queued Floor Requests from Rel-18
    15: 15,     # Floor Release Multi Talker
}


@pytest.mark.parametrize("release", RELEASES)
def test_a_release_encodes_exactly_what_it_defines(release):
    codec = rtcp.Codec(Release(release))
    for subtype, first in FIRST_RELEASE_OF_SUBTYPE.items():
        msg = rtcp.FloorMessage(rtcp.MsgType(subtype), 1, {})
        if release >= first:
            assert codec.encode(msg), (release, subtype)
        else:
            with pytest.raises(rtcp.ReleaseRefused):
                codec.encode(msg)


@pytest.mark.parametrize("release", RELEASES)
def test_a_release_refuses_a_field_it_does_not_define(release):
    """Field 25 (Floor Revoke Request User ID) arrives in Rel-19; fields 21-24
    in Rel-17; 15-20 in Rel-15."""
    codec = rtcp.Codec(Release(release))
    for field_id, first in ((14, 13), (20, 15), (24, 17), (25, 19)):
        msg = rtcp.message(rtcp.MsgType.GRANTED, 1, (field_id, b"\x00\x00"))
        if release >= first:
            assert codec.encode(msg), (release, field_id)
        else:
            with pytest.raises(rtcp.ReleaseRefused):
                codec.encode(msg)


@pytest.mark.parametrize("release", RELEASES)
def test_floor_revoke_cause_7_is_refused_before_rel_19(release):
    """Clause 8.2.10.2. The cause is only checkable on a Floor Revoke: the
    same field carries the Deny namespace on a Floor Deny, where #7 (Queue
    full) has existed since Rel-13."""
    codec = rtcp.Codec(Release(release))
    revoke = rtcp.message(rtcp.MsgType.REVOKE, 1, rtcp.f_reject(7, "x"))
    if release >= 19:
        assert codec.encode(revoke)
    else:
        with pytest.raises(rtcp.ReleaseRefused):
            codec.encode(revoke)
    # ... and the Deny namespace is never gated by it.
    assert codec.encode(rtcp.message(rtcp.MsgType.DENY, 1, rtcp.f_reject(7, "x")))


# -- the hazard this parameter exists for --------------------------------------


def test_subtype_14_means_different_messages_either_side_of_rel_18():
    """The reason a release parameter is not a feature flag.

    Subtype 14 is assigned in Rel-17 AND in Rel-18, to DIFFERENT messages. A
    deployment that guesses wrong does not fail: it decodes the packet and
    acts on the wrong message. Nothing in the bytes distinguishes them.
    """
    assert subtype_name(Release.REL_17, 14) == "Floor Queued Cancel"
    assert subtype_name(Release.REL_18, 14) == "Queued Floor Requests"
    assert subtype_name(Release.REL_19, 14) == "Queued Floor Requests"
    assert subtype_name(Release.REL_16, 14) is None

    # And the codec reports the release-correct meaning, which `MsgType`
    # cannot: it has one name per value.
    msg = rtcp.FloorMessage(rtcp.MsgType(14), 1, {})
    assert rtcp.Codec(Release.REL_17).name_of(msg) != \
        rtcp.Codec(Release.REL_18).name_of(msg)


def test_a_rel_17_deployment_refuses_a_rel_19_message_on_the_wire():
    """Receiving, not just sending. A Rel-17 deployment handed a Floor Revoke
    Request must say so rather than interpret it."""
    rel19, rel17 = rtcp.Codec(Release.REL_19), rtcp.Codec(Release.REL_17)
    wire = rel19.encode(rtcp.message(rtcp.MsgType.REVOKE_REQUEST, 1))
    assert rel19.decode(wire).type is rtcp.MsgType.REVOKE_REQUEST
    with pytest.raises(rtcp.ReleaseRefused) as exc:
        rel17.decode(wire)
    assert "Rel-17" in str(exc.value) and "Rel-19" in str(exc.value)


def test_wrong_release_is_distinguishable_from_malformed():
    """An operator must be able to tell "my peer is newer than me" from "my
    peer is broken". Both would otherwise be one counter and one log line."""
    assert issubclass(rtcp.ReleaseRefused, ValueError)
    assert not issubclass(rtcp.ReleaseRefused, rtcp.RtcpError)
    assert not issubclass(rtcp.RtcpError, rtcp.ReleaseRefused)


def test_every_supported_release_round_trips_a_basic_call():
    """Whatever the release, the Rel-13 core of floor control still works.
    A gate that broke ordinary operation at an older release would be worse
    than no gate."""
    for release in RELEASES:
        codec = rtcp.Codec(Release(release))
        for mtype in (rtcp.MsgType.REQUEST, rtcp.MsgType.GRANTED,
                      rtcp.MsgType.TAKEN, rtcp.MsgType.RELEASE,
                      rtcp.MsgType.IDLE, rtcp.MsgType.DENY):
            m = rtcp.message(mtype, 42, rtcp.f_sequence(3))
            assert codec.decode(codec.encode(m)) == m


# -- the deployment parameter, end to end -------------------------------------


def test_health_reports_the_release_the_process_is_speaking():
    """PLT-REL-001. Reading the deployment's configuration is not always
    possible from where the question is being asked."""
    from service.runtime import Health
    health = Health()
    health.set_release(Release.REL_17)
    assert health.snapshot()["release"] == "Rel-17"


def test_config_refuses_a_deployment_that_did_not_state_a_release():
    """PLT-REL-002, at the configuration boundary rather than the parser."""
    from service.config import Config
    base = {"MCX_PROFILE": "mcx", "MCX_IDMS": "stub", "MCX_DATA_DIR": "/tmp/x"}
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(base)
    assert "MCX_RELEASE" in str(exc.value)
    assert Config.from_env({**base, "MCX_RELEASE": "17"}).release is Release.REL_17


def test_the_release_is_independent_of_the_profile():
    """PLT-REL-003. The whole point: these are two axes, not one."""
    from service.config import Config
    base = {"MCX_IDMS": "stub", "MCX_DATA_DIR": "/tmp/x"}
    seen = set()
    for profile in ("mcx", "frmcs", "utility"):
        for release in ("17", "19"):
            cfg = Config.from_env(
                {**base, "MCX_PROFILE": profile, "MCX_RELEASE": release})
            seen.add((cfg.profile_names[0], cfg.release))
    assert len(seen) == 6, seen


# -- CA-12: the TS 24.379 signalling layer -------------------------------------


def test_warning_code_179_does_not_exist_before_rel_17():
    """PLT-CONF-AUDIT CA-12, the one signalling constant that is release-bound.

    TS 24.379 table 4.4.2-2 grew from 44 codes in Rel-13 to 95 in Rel-20. The
    platform emits three of them, and 179 ("service not authorized with the
    interconnected system") arrives in Rel-17. Spelled out rather than derived
    from the table being checked.
    """
    from core.release import supports_sip_warning
    for release in RELEASES:
        assert supports_sip_warning(Release(release), 100) is True
        assert supports_sip_warning(Release(release), 145) is True
        assert supports_sip_warning(Release(release), 179) is (release >= 17)
        assert supports_sip_warning(Release(release), 196) is (release >= 20)
    # 129-135 are allocated in no published release.
    for code in range(129, 136):
        assert supports_sip_warning(Release.REL_20, code) is False


def test_a_release_without_the_code_still_explains_the_refusal():
    """The degradation rule. A deployment older than Rel-17 must not emit 179
    -- but it must still say why it refused, and it must not raise: turning a
    policy refusal into a fault is the one thing the refusal path may never
    do (PLT-ICD-001 refusal-vs-failure).
    """
    from core.sip import Adapter, DialogContext, Status

    ctx = DialogContext(call_id="c1", local_uri="sip:ps.mcptt.example")
    phrase = "service not authorized with the interconnected system"

    modern = Adapter("sip:ps.mcptt.example", Release.REL_17)
    old = Adapter("sip:ps.mcptt.example", Release.REL_16)

    a = modern.reject("partner-not-permitted", ctx)
    b = old.reject("partner-not-permitted", ctx)

    assert a.headers.get("Warning") == f'399 ps.mcptt.example "179 {phrase}"'
    assert b.headers.get("Warning") == f'399 ps.mcptt.example "{phrase}"'
    # the refusal itself is unchanged: same status, still not a fault
    assert a.status is b.status is Status.FORBIDDEN
    assert b.status.code < 500


def test_a_release_bound_code_is_gated_but_a_rel_13_code_is_not():
    """Codes 100 and 145 are Rel-13 and must be emitted at every release --
    a gate that suppressed them would make every deployment less legible."""
    from core.sip import Adapter, DialogContext

    ctx = DialogContext(call_id="c1", local_uri="sip:ps.mcptt.example")
    for release in RELEASES:
        adapter = Adapter("sip:ps.mcptt.example", Release(release))
        assert '"145 unable to determine called party"' in \
            adapter.reject("unknown-target", ctx).headers.get("Warning")
        assert '"100 function not allowed due to user authorisation"' in \
            adapter.reject("not-authorised", ctx).headers.get("Warning")
