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
from core.release import SUPPORTED, Release, parse, subtype_name  # noqa: E402

RELEASES = tuple(range(13, 21))


@pytest.mark.vp("VP1-BND-023")
def test_the_suite_covers_every_supported_release():
    """RELEASES is written out, not read from core/release.py; this keeps it
    honest. A release added to the platform fails here until the suite's
    expectations for it are written."""
    assert tuple(int(r) for r in SUPPORTED) == RELEASES == (13, 14, 15, 16, 17, 18, 19, 20)


# -- the parameter itself ------------------------------------------------------


@pytest.mark.parametrize("text,expected", [
    ("17", Release.REL_17), ("Rel-17", Release.REL_17),
    ("rel-20", Release.REL_20), (" 13 ", Release.REL_13),
])
@pytest.mark.vp("VP1-REL-001")
def test_release_is_parsed_from_the_forms_an_operator_would_write(text, expected):
    assert parse(text) is expected


@pytest.mark.vp("VP1-REL-001")
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


@pytest.mark.vp("VP1-REL-003")
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


@pytest.mark.vp("VP1-REL-003")
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


@pytest.mark.vp("VP1-REL-003")
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


@pytest.mark.vp("VP1-REL-004")
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


@pytest.mark.vp("VP1-REL-005")
def test_a_rel_17_deployment_refuses_a_rel_19_message_on_the_wire():
    """Receiving, not just sending. A Rel-17 deployment handed a Floor Revoke
    Request must say so rather than interpret it."""
    rel19, rel17 = rtcp.Codec(Release.REL_19), rtcp.Codec(Release.REL_17)
    wire = rel19.encode(rtcp.message(rtcp.MsgType.REVOKE_REQUEST, 1))
    assert rel19.decode(wire).type is rtcp.MsgType.REVOKE_REQUEST
    with pytest.raises(rtcp.ReleaseRefused) as exc:
        rel17.decode(wire)
    assert "Rel-17" in str(exc.value) and "Rel-19" in str(exc.value)


@pytest.mark.vp("VP1-REL-005")
def test_wrong_release_is_distinguishable_from_malformed():
    """An operator must be able to tell "my peer is newer than me" from "my
    peer is broken". Both would otherwise be one counter and one log line."""
    assert issubclass(rtcp.ReleaseRefused, ValueError)
    assert not issubclass(rtcp.ReleaseRefused, rtcp.RtcpError)
    assert not issubclass(rtcp.RtcpError, rtcp.ReleaseRefused)


@pytest.mark.vp("VP1-REL-002")
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


@pytest.mark.vp("VP1-REL-001")
def test_config_refuses_a_deployment_that_did_not_state_a_release():
    """PLT-REL-002, at the configuration boundary rather than the parser."""
    from service.config import Config
    base = {"MCX_PROFILE": "mcx", "MCX_IDMS": "stub", "MCX_RECORDER": "none", "MCX_BEARER": "none", "MCX_STRICT_RELEASE": "false",
            "MCX_ADHOC_LIST_MAX": "100", "MCX_NETWORK_FILE": "/tmp/x/network.yaml",
            "MCX_HTTP_TLS": "off", "MCX_FLOOR_UNRECORDED": "deny", "MCX_FOREIGN_INITIATOR": "refuse", "MCX_ARP_VULNERABILITY_CHECK": "true", "MCX_ENV": "test",
            "MCX_DATA_DIR": "/tmp/x"}
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(base)
    assert "MCX_RELEASE" in str(exc.value)
    assert Config.from_env({**base, "MCX_RELEASE": "17"}).release is Release.REL_17


@pytest.mark.vp("VP1-REL-002")
def test_the_release_is_independent_of_the_profile():
    """PLT-REL-003. The whole point: these are two axes, not one."""
    from service.config import Config
    base = {"MCX_IDMS": "stub", "MCX_RECORDER": "none", "MCX_BEARER": "none", "MCX_STRICT_RELEASE": "false",
            "MCX_ADHOC_LIST_MAX": "100", "MCX_NETWORK_FILE": "/tmp/x/network.yaml",
            "MCX_HTTP_TLS": "off", "MCX_FLOOR_UNRECORDED": "deny", "MCX_FOREIGN_INITIATOR": "refuse", "MCX_ARP_VULNERABILITY_CHECK": "true", "MCX_ENV": "test",
            "MCX_DATA_DIR": "/tmp/x"}
    from core.release import SUPPORTED
    profiles = sorted(p.parent.name for p in (ROOT / "profiles").glob("*/profile.yaml"))
    seen = set()
    for profile in profiles:
        for release in SUPPORTED:
            cfg = Config.from_env(
                {**base, "MCX_PROFILE": profile, "MCX_RELEASE": str(int(release))})
            seen.add((cfg.profile_names[0], cfg.release))
    assert len(seen) == len(SUPPORTED) * len(profiles) == 24, seen


# -- CA-12: the TS 24.379 signalling layer -------------------------------------


@pytest.mark.vp("VP1-REL-007")
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


@pytest.mark.vp("VP1-REL-007")
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


@pytest.mark.vp("VP1-REL-007")
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


def test_the_three_interworking_codes_are_not_in_table_4_4_2_2():
    """PLT-CONF-AUDIT CA-09.

    TS 29.379 table 4.2.2-1 allocates 300, 301 and 302 from Rel-17 onward --
    V16.5.0 clause 4.2.2 still said only "Existing warning texts as specified
    in 3GPP TS 24.379 will be used", and the table first appears in V17.5.0.

    They are deliberately absent from SIP_WARNING_INTRODUCED, which models one
    table in one document: TS 24.379's 4.4.2-2, which reserves the range and
    assigns no meanings. Keeping them out is what stops the emission path from
    ever putting an LMR media-security code on a refusal from a platform that
    performs no IWF role.

    Values spelled out rather than read from the table being checked.
    """
    from core.release import supports_sip_warning
    for release in RELEASES:
        for code in (300, 301, 302):
            assert supports_sip_warning(Release(release), code) is False
        # ...and the rest of the range 24.379 reserved was never allocated.
        for code in (303, 325, 350):
            assert supports_sip_warning(Release(release), code) is False


def test_session_types_and_indications_by_release():
    """PLT-CONF-AUDIT CA-20. Tabulated from all seven versions of TS 24.379 in
    docs/3GPP by where each value is first used; spelled out, not imported.
    Ad hoc group calls begin at Rel-18, with their own emergency indication."""
    from core.release import supports_mc_indicator, supports_session_type
    first = {"prearranged": 13, "chat": 13, "private": 13, "first-to-answer": 14,
             "ambient-listening": 14, "adhoc": 18}
    for release in RELEASES:
        for value, introduced in first.items():
            assert supports_session_type(Release(release), value) is (release >= introduced)
        for ind in ("emergency-ind", "imminentperil-ind", "broadcast-ind"):
            assert supports_mc_indicator(Release(release), ind) is True
        assert supports_mc_indicator(Release(release), "adhoc-emergency-ind") is (release >= 18)
        assert supports_session_type(Release(release), "conference") is False


# -- VP1-REL-003..007, exhaustively (review of 2026-09-28) -----------------------

# Spelled out from TS 24.380 table 8.2.2.1-1, table 8.2.3.1-2 and clause
# 8.2.10.2 of V13.14.0 through V19.2.0, not read from core/release.py.
FIRST_RELEASE_OF_TYPE = {0: 13, 1: 13, 2: 13, 3: 13, 4: 13, 5: 13, 6: 13, 7: 19,
                         8: 13, 9: 13, 10: 13, 11: 17, 14: 17, 15: 15}
# Types whose subtype is 'x....' in the table (may carry the acknowledgement
# flag, bit 4); the same in every release.
ACK_CAPABLE_TYPES = {1, 2, 3, 4, 5, 9, 11, 14}
FIRST_RELEASE_OF_FIELD = {**{f: 13 for f in range(15)}, **{f: 15 for f in range(15, 21)},
                          **{f: 17 for f in range(21, 25)}, 25: 19}
FIRST_RELEASE_OF_REVOKE_CAUSE = {1: 13, 2: 13, 3: 13, 4: 13, 6: 13, 7: 19, 255: 13}


def _expected_subtype(release, five_bits):
    """'ok', 'release' (well-formed but outside this release) or 'malformed'
    (a subtype no release defines)."""
    mtype, ack = five_bits & 0x0F, bool(five_bits & 0x10)
    if mtype not in FIRST_RELEASE_OF_TYPE or (ack and mtype not in ACK_CAPABLE_TYPES):
        return "malformed"
    return "ok" if release >= FIRST_RELEASE_OF_TYPE[mtype] else "release"


def _outcome(fn):
    try:
        fn()
    except rtcp.ReleaseRefused:
        return "release"
    except rtcp.RtcpError:
        return "malformed"
    return "ok"


@pytest.mark.vp("VP1-REL-003")
@pytest.mark.parametrize("release", RELEASES)
def test_vp1_rel_003_every_five_bit_subtype_is_read_or_refused(release):
    """All 32 values of the five-bit subtype, on the wire: a type the release
    has is read; a type a later release has is refused as wrong release; 12,
    13 and the flag on a type whose entry is '0....' (no release defines
    them) are refused as malformed."""
    codec = rtcp.Codec(Release(release))
    template = bytearray(codec.encode(rtcp.message(rtcp.MsgType.REQUEST, 1)))
    got = {}
    for v in range(32):
        wire = bytes([0x80 | v]) + bytes(template[1:])
        got[v] = _outcome(lambda: codec.decode(wire))
    assert got == {v: _expected_subtype(release, v) for v in range(32)}
    # Pinned for one release so the expectation function is checked too.
    if release == 17:
        assert [v for v in range(32) if got[v] == "ok"] == [
            0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 14, 15, 17, 18, 19, 20, 21, 25, 27, 30]
        assert [v for v in range(32) if got[v] == "release"] == [7]


@pytest.mark.vp("VP1-REL-003")
@pytest.mark.parametrize("release", RELEASES)
def test_vp1_rel_003_every_type_field_and_revoke_cause_encodes_or_is_refused(release):
    """Emission: every assigned message type, every field id 0-255 and every
    revoke cause 0-255 (and the largest), each encodes exactly when the
    release defines it and is otherwise refused (ReleaseRefused). The
    unassigned types 12 and 13 cannot be built at all."""
    codec = rtcp.Codec(Release(release))
    types = {int(t): _outcome(lambda t=t: codec.encode(rtcp.message(t, 1)))
             for t in rtcp.MsgType}
    assert types == {t: ("ok" if release >= first else "release")
                     for t, first in FIRST_RELEASE_OF_TYPE.items()}
    for unassigned in (12, 13):
        with pytest.raises(ValueError):
            rtcp.MsgType(unassigned)
    fields = {f: _outcome(lambda f=f: codec.encode(
        rtcp.message(rtcp.MsgType.GRANTED, 1, (f, b"\x00\x00")))) for f in range(256)}
    assert fields == {f: ("ok" if release >= FIRST_RELEASE_OF_FIELD.get(f, 99) else "release")
                      for f in range(256)}
    causes = {c: _outcome(lambda c=c: codec.encode(
        rtcp.message(rtcp.MsgType.REVOKE, 1, rtcp.f_reject(c)))) for c in (*range(256), 65535)}
    assert causes == {c: ("ok" if release >= FIRST_RELEASE_OF_REVOKE_CAUSE.get(c, 99)
                          else "release") for c in (*range(256), 65535)}


@pytest.mark.vp("VP1-REL-003")
@pytest.mark.parametrize("release", RELEASES)
def test_vp1_rel_003_a_field_no_release_defines_is_malformed_on_the_wire(release):
    """Received, an id beyond the table (26-255) is malformed; an id a later
    release defines is the wrong release."""
    codec = rtcp.Codec(Release(release))
    base = codec.encode(rtcp.message(rtcp.MsgType.REQUEST, 1))

    def with_field(fid):
        body = bytes([fid, 2, 0, 0])
        return bytes([base[0], base[1]]) + (len(base + body) // 4 - 1).to_bytes(2, "big") \
            + base[4:] + body
    got = {f: _outcome(lambda f=f: codec.decode(with_field(f))) for f in range(15, 256)}
    for f in range(15, 256):
        first = FIRST_RELEASE_OF_FIELD.get(f)
        if first is None:
            assert got[f] == "malformed", f
        elif release < first:
            assert got[f] == "release", f


@pytest.mark.vp("VP1-REL-004")
def test_vp1_rel_004_one_packet_read_at_each_release():
    """The same subtype-14 bytes, decoded by each release's codec: Floor
    Queued Cancel at Rel-17, Queued Floor Requests at Rel-18, 19 and 20, and
    refused as the wrong release before Rel-17. The bytes do not differ: the
    Rel-17 and Rel-18 encoders produce the same packet."""
    wire = rtcp.Codec(Release.REL_18).encode(rtcp.message(rtcp.MsgType(14), 7))
    assert rtcp.Codec(Release.REL_17).encode(rtcp.message(rtcp.MsgType(14), 7)) == wire
    reported = {}
    for release in RELEASES:
        codec = rtcp.Codec(Release(release))
        try:
            reported[release] = codec.name_of(codec.decode(wire))
        except rtcp.ReleaseRefused:
            reported[release] = "refused"
    assert reported == {13: "refused", 14: "refused", 15: "refused", 16: "refused",
                        17: "Floor Queued Cancel", 18: "Queued Floor Requests",
                        19: "Queued Floor Requests", 20: "Queued Floor Requests"}


# -- VP1-REL-006: the release in every record of a real call --------------------

from tests.test_sip_transport import (  # noqa: E402,F401  (fixtures)
    LOCAL, SDP, U, Flow, answer, clock, invite, msg, pki, register, sip_env)


@pytest.mark.vp("VP1-REL-006")
@pytest.mark.parametrize("release", ["17", "19"])
def test_vp1_rel_006_every_stored_record_of_a_call_carries_the_release(tmp_path, pki, clock,
                                                                        release):
    """A private call answered, acknowledged and released, and a refused
    call, through the SIP core into the durable store: every record read back
    carries name/version/16-hex hash of the profile, the configured release,
    the network's triple and the environment."""
    import re
    from core import loader
    from service.runtime import build_runtime
    from service.sip_core import SipCore
    from core.session import Platform
    rt = build_runtime(sip_env(tmp_path, pki, MCX_RELEASE=release), clock, platform=Platform())
    core = SipCore(rt, LOCAL, clock)
    try:
        flows = {u: Flow(u) for u in U}
        for u, f in flows.items():
            register(core, u, f)
        core.on_bytes(invite("c1", U[0], U[1], "private"), flows[U[0]])
        (leg,) = flows[U[1]].requests("INVITE")
        core.on_bytes(answer(leg, 200, SDP), flows[U[1]])
        core.on_bytes(msg("ACK", LOCAL, "c1", 1, U[0], U[1], branch="z9hG4bKack"),
                      flows[U[0]])
        core.on_bytes(msg("BYE", LOCAL, "c1", 2, U[0], U[1], to_tag="mcx"), flows[U[0]])
        core.on_bytes(invite("c2", U[0], U[1], "no-such-call-type"), flows[U[0]])
        records = rt.store.audit_records()
    finally:
        core.close()
        rt.close()
    profile_hash = loader.load(ROOT / "profiles" / "mcx").profile.content_hash[:16]
    pattern = re.compile(rf"mcx/[^/+]+/{profile_hash}\+Rel-{release}"
                         rf"\+test-net/1/[0-9a-f]{{16}}\+test")
    assert records and all(pattern.fullmatch(r["profile"]) for r in records), \
        {r["profile"] for r in records}
    kinds = {r["type"] for r in records}
    assert {"hook-invocation", "session-admitted", "session-established",
            "session-released", "session-refused"} <= kinds, kinds


# -- VP1-REL-007: every release-bound warning code, at every release -------------

# First release of each code the platform emits, from TS 24.379 table 4.4.2-2
# (V13.19.0 to V20.0.0), spelled out.
FIRST_RELEASE_OF_WARNING = {100: 13, 116: 13, 122: 13, 141: 13, 145: 13, 179: 17,
                            185: 18, 186: 18, 187: 18, 189: 18, 201: 20}


@pytest.mark.vp("VP1-REL-007")
@pytest.mark.parametrize("release", RELEASES)
def test_vp1_rel_007_every_warning_text_is_gated_at_every_release(release):
    """Every refusal with a TS 24.379 code: from its first release the
    Warning carries the code and phrase; before it, the phrase alone. The
    status is the same at every release and a 4xx/5xx, and nothing raises."""
    from core.sip import WARNING_TEXTS, Adapter, DialogContext
    assert {code for code, _ in WARNING_TEXTS.values()} <= set(FIRST_RELEASE_OF_WARNING)
    ctx = DialogContext(call_id="c1", local_uri="sip:ps.mcptt.example")
    adapter = Adapter("sip:ps.mcptt.example", Release(release))
    newest = Adapter("sip:ps.mcptt.example", Release.REL_20)
    for reason, (code, text) in WARNING_TEXTS.items():
        r = adapter.reject(reason, ctx)
        expected = f"{code} {text}" if release >= FIRST_RELEASE_OF_WARNING[code] else text
        assert r.headers.get("Warning") == f'399 ps.mcptt.example "{expected}"', reason
        assert r.status is newest.reject(reason, ctx).status
        assert 400 <= r.status.code < 600


def _adhoc_invite():
    from core.sip import Headers, Request
    from tests import mcpttinfo_fixture as mcf
    return Request("INVITE", "sip:ps.mcptt.example", Headers([
        ("Content-Type", mcf.CONTENT_TYPE)]), body=mcf.multipart(SDP, mcf.adhoc_xml()))


@pytest.mark.vp("VP1-REL-007")
@pytest.mark.parametrize("release", RELEASES)
def test_vp1_rel_007_the_ad_hoc_codes_at_every_release(release):
    """185 and 186 (Rel-18) answer an ad hoc INVITE step 0 refused. Before
    Rel-18 there are no ad hoc calls to refuse as such (the session type does
    not exist), so the same INVITE is answered with the Rel-13 code 100 and
    its own phrase: never a code the release lacks, and never a raise."""
    from core.sip import Adapter, DialogContext
    ctx = DialogContext(call_id="c1", local_uri="sip:ps.mcptt.example")
    adapter = Adapter("sip:ps.mcptt.example", Release(release))   # no ad hoc call types
    got = {reason: adapter.reject(reason, ctx, invite=_adhoc_invite(), authorisation=True)
           for reason in ("not-authorised", "call-type-not-permitted")}
    if release >= 18:
        expected = {"not-authorised": "185 user not authorised to initiate the adhoc group call",
                    "call-type-not-permitted": "186 the MCPTT system do not support adhoc "
                                               "group call"}
    else:
        expected = {"not-authorised": "100 function not allowed due to user authorisation",
                    "call-type-not-permitted": "100 function not allowed due to local policy"}
    assert {k: r.headers.get("Warning") for k, r in got.items()} == {
        k: f'399 ps.mcptt.example "{v}"' for k, v in expected.items()}
    assert [r.status.code for r in got.values()] == [403, 403]
