"""TS-SIG — SIP signalling, registration, inbound rejection, SDP negotiation.

ENV-UNIT: no socket. VP1-SIG-001 (interoperability against two independent SIP
core implementations) cannot run here by construction and stays open.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.audit import Auditor, MemorySink  # noqa: E402
from core.hooks import MediaKind, SessionRequest  # noqa: E402
from core.session import Platform, SessionManager, Signal, SignalType  # noqa: E402
from core.release import Release  # noqa: E402
from core.sip import (  # noqa: E402
    ANSWER_MODE_AUTO,
    ANSWER_MODE_MANUAL,
    CT_SDP,
    FEATURE_TAG_DATA,
    FEATURE_TAG_PTT,
    FEATURE_TAG_VIDEO,
    Adapter,
    DialogContext,
    Headers,
    InboundGuard,
    RegistrationStore,
    Request,
    SipError,
    Status,
    build_offer,
    negotiate,
    offered_payload_types,
)

PROFILES = ROOT / "profiles"

AMR_WB = (97, "AMR-WB/16000/1")
AMR = (96, "AMR/8000/1")


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now

    def advance(self, ms):
        self.now += ms


def well_formed(method="INVITE", uri="sip:grp@mcptt.example", call_id="c1",
                cseq="1 INVITE", body="", content_type=None) -> Request:
    h = Headers([
        ("Via", "SIP/2.0/TLS proxy.mcptt.example;branch=z9hG4bKabc"),
        ("From", "<sip:u0@mcptt.example>;tag=1"),
        ("To", "<sip:grp@mcptt.example>"),
        ("Call-ID", call_id),
        ("CSeq", cseq),
    ])
    if content_type:
        h.add("Content-Type", content_type)
    return Request(method=method, uri=uri, headers=h, body=body)


# --------------------------------------------------------------------------
# Headers
# --------------------------------------------------------------------------


def test_headers_are_case_insensitive_and_multivalued():
    h = Headers()
    h.add("Via", "one").add("via", "two")
    assert h.get("VIA") == "one"
    assert h.get_all("Via") == ("one", "two")
    h.set("Via", "only")
    assert h.get_all("Via") == ("only",)


def test_message_renders_with_content_length():
    msg = well_formed(body="v=0\r\n", content_type=CT_SDP)
    rendered = msg.render()
    assert rendered.startswith("INVITE sip:grp@mcptt.example SIP/2.0")
    assert "Content-Length: 5" in rendered          # len("v=0\r\n")
    assert rendered.endswith("v=0\r\n")


# --------------------------------------------------------------------------
# VP1-SIG-002 — registration
# --------------------------------------------------------------------------


def test_vp1_sig_002_registration_state_per_service_id():
    clock = Clock()
    store = RegistrationStore(clock=clock)
    store.register("sip:u0@mcptt.example", "sip:u0@10.0.0.1", expires_ms=60000)
    store.register("sip:u1@mcptt.example", "sip:u1@10.0.0.2", expires_ms=60000)
    assert store.is_registered("sip:u0@mcptt.example")
    assert store.registered_ids() == ("sip:u0@mcptt.example",
                                      "sip:u1@mcptt.example")


def test_vp1_sig_002_registration_expires():
    clock = Clock()
    store = RegistrationStore(clock=clock)
    store.register("sip:u0@mcptt.example", "sip:u0@10.0.0.1", expires_ms=1000)
    assert store.is_registered("sip:u0@mcptt.example")
    clock.advance(1000)
    assert not store.is_registered("sip:u0@mcptt.example")
    assert store.get("sip:u0@mcptt.example") is None


def test_vp1_sig_002_reregistration_refreshes():
    clock = Clock()
    store = RegistrationStore(clock=clock)
    store.register("sip:u0@mcptt.example", "sip:u0@10.0.0.1", expires_ms=1000)
    clock.advance(900)
    store.register("sip:u0@mcptt.example", "sip:u0@10.0.0.1", expires_ms=1000)
    clock.advance(500)
    assert store.is_registered("sip:u0@mcptt.example")


def test_lookup_does_not_renew_an_expired_registration():
    clock = Clock()
    store = RegistrationStore(clock=clock)
    store.register("sip:u0@mcptt.example", "c", expires_ms=100)
    clock.advance(200)
    store.get("sip:u0@mcptt.example")
    assert not store.is_registered("sip:u0@mcptt.example")


def test_deregistration_removes_state():
    store = RegistrationStore(clock=Clock())
    store.register("sip:u0@mcptt.example", "c", expires_ms=60000)
    store.deregister("sip:u0@mcptt.example")
    assert store.registered_ids() == ()


# --------------------------------------------------------------------------
# VP1-SIG-003 — feature tags
# --------------------------------------------------------------------------


def test_vp1_sig_003_invite_carries_feature_tags():
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
    req = SessionRequest(request_id="c1", initiator="sip:u0@mcptt.example",
                         target="grp:alpha", call_type="prearranged-group",
                         media=(MediaKind.VOICE,))
    msg = adapter.render(Signal(SignalType.INVITE, target="sip:u1@mcptt.example"),
                         ctx, req)
    assert FEATURE_TAG_PTT in msg.headers.get("Contact")
    accept = msg.headers.get("Accept-Contact")
    assert FEATURE_TAG_PTT in accept
    assert "require" in accept and "explicit" in accept


def test_vp1_sig_003_feature_tag_follows_media():
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
    for media, expected in ((MediaKind.VOICE, FEATURE_TAG_PTT),
                            (MediaKind.VIDEO, FEATURE_TAG_VIDEO),
                            (MediaKind.DATA, FEATURE_TAG_DATA)):
        req = SessionRequest(request_id="c1", initiator="sip:u0@mcptt.example",
                             target="t", call_type="x", media=(media,))
        msg = adapter.render(Signal(SignalType.INVITE, target="sip:u1@x"), ctx, req)
        assert expected in msg.headers.get("Contact")


def test_auto_answer_renders_answer_mode():
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
    req = SessionRequest(request_id="c1", initiator="sip:u0@mcptt.example",
                         target="t", call_type="x", media=(MediaKind.VOICE,))

    # TS 24.379 clause 11.1.1.2.1: forced and non-forced automatic
    # commencement are mutually exclusive branches. `auto_answer` in this
    # platform means "establishes without callee action" (VP1-CC-004), which
    # is the forced branch, so Priv-Answer-Mode alone.
    auto = adapter.render(Signal(SignalType.INVITE, target="sip:u1@x",
                                 detail={"auto_answer": True}), ctx, req)
    assert auto.headers.get("Priv-Answer-Mode") == ANSWER_MODE_AUTO
    assert not auto.headers.has("Answer-Mode")

    manual = adapter.render(Signal(SignalType.INVITE, target="sip:u1@x",
                                   detail={"auto_answer": False}), ctx, req)
    assert manual.headers.get("Answer-Mode") == ANSWER_MODE_MANUAL
    assert not manual.headers.has("Priv-Answer-Mode")


def test_invite_asserts_the_participating_function_not_the_caller():
    """TS 24.379 6.3.2.2.6.2 item 7. This test used to assert the opposite --
    that the INVITE carried the caller's identity -- and so pinned the defect
    (PLT-CONF-AUDIT CA-20). The caller goes in <mcptt-calling-user-id>."""
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19,
                      _declared(("x", ("private",))))
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
    req = SessionRequest(request_id="c1", initiator="sip:u0@mcptt.example",
                         target="t", call_type="x", media=(MediaKind.VOICE,))
    msg = adapter.render(Signal(SignalType.INVITE, target="sip:u1@x"), ctx, req)
    assert msg.headers.get("P-Asserted-Identity") == "<sip:server@mcptt.example>"
    assert "<mcpttURI>sip:u0@mcptt.example</mcpttURI>" in msg.body


def test_without_an_mcptt_body_the_caller_is_still_asserted():
    """A gateway leg, or a call type declared with no signature, carries no
    MCPTT info body, so P-Asserted-Identity is the only place the caller can
    travel. The first CA-20 fix moved it for these too (found by review)."""
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
    req = SessionRequest(request_id="c1", initiator="sip:u0@mcptt.example",
                         target="t", call_type="undeclared", media=(MediaKind.VOICE,))
    msg = adapter.render(Signal(SignalType.INVITE, target="sip:gw@x"), ctx, req)
    assert msg.headers.get("P-Asserted-Identity") == "<sip:u0@mcptt.example>"
    assert msg.headers.get("Content-Type") == "application/sdp"


# --------------------------------------------------------------------------
# VP1-SIG-004 — malformed, replayed, unknown session
# --------------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["Via", "From", "To", "Call-ID", "CSeq"])
def test_vp1_sig_004_missing_mandatory_header_is_400(missing):
    msg = well_formed()
    headers = Headers([(n, v) for n, v in msg.headers.items()
                       if n.lower() != missing.lower()])
    guard = InboundGuard()
    response = guard.check(Request(method=msg.method, uri=msg.uri,
                                   headers=headers))
    assert response is not None and response.status is Status.BAD_REQUEST
    assert missing.lower() in (response.headers.get("Warning") or "").lower()


def test_vp1_sig_004_malformed_cseq_is_400():
    guard = InboundGuard()
    response = guard.check(well_formed(cseq="not-a-cseq"))
    assert response.status is Status.BAD_REQUEST


def test_vp1_sig_004_body_without_content_type_is_400():
    guard = InboundGuard()
    response = guard.check(well_formed(body="v=0"))
    assert response.status is Status.BAD_REQUEST


def test_vp1_sig_004_replay_is_rejected():
    guard = InboundGuard()
    first = guard.check(well_formed(call_id="c9", cseq="1 INVITE"))
    assert first is None
    replay = guard.check(well_formed(call_id="c9", cseq="1 INVITE"))
    assert replay is not None and replay.status is Status.LOOP_DETECTED


def test_vp1_sig_004_unknown_session_is_481():
    guard = InboundGuard()
    response = guard.check(well_formed(method="BYE", call_id="ghost",
                                       cseq="2 BYE"),
                           known_sessions=("c1", "c2"))
    assert response.status is Status.CALL_DOES_NOT_EXIST


def test_in_dialog_request_for_a_known_session_passes():
    guard = InboundGuard()
    assert guard.check(well_formed(method="BYE", call_id="c1", cseq="2 BYE"),
                       known_sessions=("c1",)) is None


def test_rejection_echoes_dialog_identifying_headers():
    guard = InboundGuard()
    response = guard.check(well_formed(cseq="bad"))
    for name in ("Via", "From", "To", "Call-ID"):
        assert response.headers.has(name)


def test_replay_window_is_bounded():
    guard = InboundGuard(window=8)
    for i in range(20):
        guard.check(well_formed(call_id=f"c{i}", cseq="1 INVITE"))
    assert len(guard._seen) <= 8


# --------------------------------------------------------------------------
# Refusal mapping
# --------------------------------------------------------------------------


@pytest.mark.parametrize("reason,expected", [
    ("unknown-target", Status.NOT_FOUND),
    ("no-binding", Status.TEMPORARILY_UNAVAILABLE),
    ("no-location-binding", Status.TEMPORARILY_UNAVAILABLE),
    ("not-authorised", Status.FORBIDDEN),
    ("call-type-not-permitted", Status.FORBIDDEN),
    ("capacity-exhausted", Status.SERVICE_UNAVAILABLE),
    ("recording-unavailable", Status.SERVICE_UNAVAILABLE),
    ("qos-unavailable", Status.SERVICE_UNAVAILABLE),
    ("hook-error", Status.SERVER_ERROR),
    ("hook-timeout", Status.SERVER_ERROR),
    ("hook-contract-violation", Status.SERVER_ERROR),
])
def test_refusal_maps_to_the_right_status(reason, expected):
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
    assert adapter.reject(reason, ctx).status is expected


def test_policy_refusal_is_distinguishable_from_a_fault():
    """An operator reading a trace must be able to tell a decision from a fault.

    The status class alone cannot carry this: `capacity-exhausted` is correctly
    a 503, the same class as an internal error. The distinction is the Warning
    header — a policy refusal names a specific 3GPP warning code, an internal
    fault carries none.
    """
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")

    for reason in ("unknown-target", "not-authorised", "capacity-exhausted",
                   "call-type-not-permitted", "recording-unavailable"):
        response = adapter.reject(reason, ctx)
        warning = response.headers.get("Warning")
        assert warning is not None, f"{reason} carries no warning"
        assert warning.split()[0].isdigit()

    for reason in ("hook-error", "hook-timeout", "hook-contract-violation"):
        response = adapter.reject(reason, ctx)
        assert response.status.code >= 500
        assert response.headers.get("Warning") is None


def test_authorisation_and_capacity_refusals_use_different_statuses():
    """PLT-PRI-008: capacity exhaustion must stay distinguishable from an
    authorisation refusal at the protocol level, not only in the audit trail."""
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
    assert adapter.reject("capacity-exhausted", ctx).status is not \
        adapter.reject("not-authorised", ctx).status


def test_refusal_carries_a_warning_header():
    """The exact shape of TS 24.379 clause 4.4.1, whose own example reads

        Warning: 399 "100 User not authorised to make group calls"

    399 is the RFC 3261 warn-code; the MC code sits inside the quoted text.
    Both were previously in the wrong position (PLT-CONF-AUDIT CA-02).
    """
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
    warning = adapter.reject("unknown-target", ctx).headers.get("Warning")
    assert warning == '399 mcptt.example "145 unable to determine called party"'


def test_unmapped_reason_defaults_to_server_error():
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
    assert adapter.reject("something-new", ctx).status is Status.SERVER_ERROR


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def test_parse_invite_builds_a_session_request():
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    body = build_offer([AMR_WB])
    msg = well_formed(body=body, content_type=CT_SDP)
    msg.headers.add("P-Asserted-Identity", "<sip:u0@mcptt.example>")
    parsed = adapter.parse_invite(msg)
    assert parsed.initiator == "sip:u0@mcptt.example"
    assert parsed.media == (MediaKind.VOICE,)
    assert parsed.request_id == "c1"


def _declared(*pairs):
    """Call types as the adapter sees them: an id and a signature, nothing else."""
    from types import SimpleNamespace
    from core.mcinfo import Signature
    return [SimpleNamespace(id=i, mc_signature=Signature(*sig)) for i, sig in pairs]


def test_parse_invite_selects_the_call_type_declaring_the_signature():
    """TS 24.379 annex F.1 body in, the declaring call type out (PLT-ICD-001 2.6).
    The body is literal text, not rendered by the module under test."""
    from tests import mcpttinfo_fixture as mcf
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19, _declared(
        ("grp", ("prearranged",)), ("emg", ("prearranged", True)), ("p2p", ("private",))))
    sdp = build_offer([AMR_WB])
    for xml, want in (
            (mcf.mcinfo_xml("prearranged", "sip:g@x"), "grp"),
            (mcf.mcinfo_xml("prearranged", "sip:g@x", emergency=True), "emg"),
            (mcf.mcinfo_xml("private", "sip:u9@x"), "p2p"),
            (mcf.mcinfo_xml("chat", "sip:g@x"), ""),               # declared by nobody
            (mcf.mcinfo_xml("prearranged", "sip:g@x", imminent_peril=True), "")):
        parsed = adapter.parse_invite(well_formed(body=mcf.multipart(sdp, xml),
                                                  content_type=mcf.CONTENT_TYPE))
        assert parsed.call_type == want, xml
    assert parsed.target == "sip:g@x"      # from <mcptt-request-uri>, not the R-URI


def test_ad_hoc_does_not_exist_before_rel_18():
    """An ad hoc request at Rel-17 selects nothing, even where a call type
    declares it: TS 24.379 has no ad hoc group call before Rel-18."""
    from tests import mcpttinfo_fixture as mcf
    body = mcf.multipart(build_offer([AMR_WB]),
                         mcf.mcinfo_xml("adhoc", "sip:g@x", adhoc_emergency=True))
    for release, want in ((Release.REL_17, ""), (Release.REL_18, "rec")):
        adapter = Adapter("sip:server@mcptt.example", release,
                          _declared(("rec", ("adhoc", True))))
        parsed = adapter.parse_invite(well_formed(body=body, content_type=mcf.CONTENT_TYPE))
        assert parsed.call_type == want, release


def test_parse_invite_leaves_unknown_call_type_empty_for_policy_to_refuse():
    """The adapter guesses nothing: an absent call type stays absent."""
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    parsed = adapter.parse_invite(well_formed(body="", content_type=None))
    assert parsed.call_type == ""


def test_parse_invite_treats_resource_priority_as_advisory():
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    msg = well_formed()
    msg.headers.add("Resource-Priority", "mcpttq.0")
    parsed = adapter.parse_invite(msg)
    assert parsed.attributes["sip.resource_priority"] == "mcpttq.0"
    assert parsed.urgency is None      # the client does not set its own urgency


def test_parse_rejects_a_non_invite():
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    with pytest.raises(SipError):
        adapter.parse_invite(well_formed(method="BYE"))


# --------------------------------------------------------------------------
# VP1-MED-002 — SDP negotiation
# --------------------------------------------------------------------------


def test_vp1_med_002_offer_with_an_acceptable_codec_negotiates():
    offer = build_offer([AMR_WB, AMR])
    assert negotiate(offer, supported=[97]) == 97


def test_vp1_med_002_offer_with_no_acceptable_codec_is_refused():
    offer = build_offer([AMR])
    assert negotiate(offer, supported=[97]) is None


def test_negotiation_prefers_the_offerer_ordering():
    offer = build_offer([AMR_WB, AMR])
    assert negotiate(offer, supported=[96, 97]) == 97


def test_offer_must_contain_a_codec():
    with pytest.raises(SipError):
        build_offer([])


def test_offered_payload_types_parsed():
    assert offered_payload_types(build_offer([AMR_WB, AMR])) == (97, 96)


# --------------------------------------------------------------------------
# Integration — session manager signals through the adapter
# --------------------------------------------------------------------------


@pytest.fixture
def wired():
    mcx = loader.load(PROFILES / "mcx")
    resolver = mcx.hooks.identity_resolver
    for i in range(3):
        resolver.register_user(f"sip:u{i}@mcptt.example")
    resolver.register_group("grp:alpha", [f"sip:u{i}@mcptt.example"
                                          for i in range(3)])
    sink = MemorySink()
    auditor = Auditor(sink, mcx.profile.identifier(), clock=Clock())
    return (SessionManager(mcx, auditor, clock=Clock()),
            Adapter("sip:server@mcptt.example", Release.REL_19), sink)


def test_established_session_renders_invites_with_feature_tags(wired):
    manager, adapter, _ = wired
    request = SessionRequest(request_id="c1", initiator="sip:u0@mcptt.example",
                             target="grp:alpha", call_type="prearranged-group",
                             media=(MediaKind.VOICE,))
    session, signals, refusal = manager.establish(request)
    assert refusal is None
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example",
                        sdp=build_offer([AMR_WB]))
    rendered = [adapter.render(s, ctx, request) for s in signals
                if s.type is SignalType.INVITE]
    assert len(rendered) == 2
    for msg in rendered:
        assert msg.method == "INVITE"
        assert FEATURE_TAG_PTT in msg.headers.get("Contact")
        assert msg.headers.get("Content-Type") == CT_SDP
        assert msg.body.startswith("v=0")


def test_refused_session_renders_the_mapped_status(wired):
    manager, adapter, _ = wired
    request = SessionRequest(request_id="c2", initiator="sip:u0@mcptt.example",
                             target="grp:nonexistent",
                             call_type="prearranged-group",
                             media=(MediaKind.VOICE,))
    session, signals, refusal = manager.establish(request)
    assert session is None
    ctx = DialogContext(call_id="c2", local_uri="sip:server@mcptt.example")
    rejects = [adapter.render(s, ctx, request) for s in signals
               if s.type is SignalType.RESPONSE_REJECT]
    assert len(rejects) == 1
    assert rejects[0].status is Status.NOT_FOUND


def test_release_renders_bye_per_member(wired):
    manager, adapter, _ = wired
    request = SessionRequest(request_id="c3", initiator="sip:u0@mcptt.example",
                             target="grp:alpha", call_type="prearranged-group",
                             media=(MediaKind.VOICE,))
    manager.establish(request)
    ctx = DialogContext(call_id="c3", local_uri="sip:server@mcptt.example")
    byes = [adapter.render(s, ctx) for s in manager.release("c3")
            if s.type is SignalType.BYE]
    assert len(byes) == 3
    assert all(m.method == "BYE" for m in byes)
    assert all("BYE" in m.headers.get("CSeq") for m in byes)


def test_qos_and_recording_signals_are_not_sip(wired):
    manager, adapter, _ = wired
    request = SessionRequest(request_id="c4", initiator="sip:u0@mcptt.example",
                             target="grp:alpha", call_type="prearranged-group",
                             media=(MediaKind.VOICE,))
    _, signals, _ = manager.establish(request)
    ctx = DialogContext(call_id="c4", local_uri="sip:server@mcptt.example")
    for signal in signals:
        rendered = adapter.render(signal, ctx, request)
        if signal.type in (SignalType.RESERVE_QOS, SignalType.START_RECORDING):
            assert rendered is None


def test_every_reserved_reason_code_has_a_status_mapping():
    """Guard against a silent default.

    An unmapped reason code falls through to 500, which would report a policy
    refusal as an internal fault. Adding a reason code without a status is the
    kind of omission only a test like this catches.
    """
    from core.errors import RESERVED_REASON_CODES
    from core.sip import REASON_TO_STATUS
    unmapped = sorted(RESERVED_REASON_CODES - set(REASON_TO_STATUS))
    assert unmapped == [], f"reason codes with no SIP status: {unmapped}"


def test_every_non_fault_reason_code_has_a_warning_text():
    """Faults deliberately carry no Warning; every other refusal must.

    A reason code may get its text from the specification table or from
    LOCAL_WARNING_TEXTS, but it may not fall through both silently -- that is
    how a refusal would arrive as a bare status with nothing in the trace to
    say it was a decision rather than a fault.
    """
    from core.errors import CORE_ORIGINATED, RESERVED_REASON_CODES
    from core.sip import LOCAL_WARNING_TEXTS, WARNING_TEXTS
    faults = {"hook-error", "hook-timeout", "hook-contract-violation"}
    expected = RESERVED_REASON_CODES - faults - {"resolver-unavailable"}
    covered = set(WARNING_TEXTS) | set(LOCAL_WARNING_TEXTS)
    missing = sorted(expected - covered)
    assert missing == [], f"reason codes with no warning text: {missing}"
    assert CORE_ORIGINATED & covered


def test_every_specification_warning_code_is_in_the_specification_table():
    """PLT-CONF-AUDIT CA-02.

    The eleven codes this replaced were all invented, and none of them was
    right. Worse, several collided: `partner-not-permitted` emitted 110,
    which TS 24.379 table 4.4.2-2 defines as "user declined the call
    invitation". A peer would not have failed to understand it; it would have
    understood it to mean something that did not happen.

    Every pair below is quoted from table 4.4.2-2 of TS 24.379 V17.15.0.
    """
    from core.sip import WARNING_TEXTS
    assert WARNING_TEXTS == {
        "unknown-target": (145, "unable to determine called party"),
        "not-authorised": (100, "function not allowed due to user authorisation"),
        "call-type-not-permitted": (100, "function not allowed due to local policy"),
        "partner-not-permitted":
            (179, "service not authorized with the interconnected system"),
    }


def test_no_reason_code_is_mapped_and_excused_at_once():
    """A reason is either given a specification code or explicitly recorded as
    having none. Both would mean the rationale no longer describes the code."""
    from core.sip import REFUSALS_WITHOUT_WARNING_TEXT, WARNING_TEXTS
    assert not (set(WARNING_TEXTS) & set(REFUSALS_WITHOUT_WARNING_TEXT))


def test_local_warning_texts_carry_no_three_digit_prefix():
    """A local text must not be mistakable for an MC warn-code.

    Table 4.4.2-1 adds the MC form with "=/", an incremental alternative, so a
    plain RFC 3261 warn-text stays legal -- but only as long as it cannot be
    parsed as `DIGIT DIGIT DIGIT SP text` by a peer that tries.
    """
    from core.sip import LOCAL_WARNING_TEXTS
    for reason, text in LOCAL_WARNING_TEXTS.items():
        head = text.split()[0]
        assert not (len(head) == 3 and head.isdigit()), (reason, text)


def test_the_icsi_is_in_its_own_accept_contact_header_field():
    """TS 24.379 clause 6.3.2.1.x requires TWO Accept-Contact header fields.

    One combined header used to be emitted, with no ICSI reference at all
    (PLT-CONF-AUDIT CA-06). The flows in annex F show the pair verbatim.
    """
    adapter = Adapter("sip:server@mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
    req = SessionRequest(request_id="c1", initiator="sip:u0@mcptt.example",
                         target="t", call_type="x", media=(MediaKind.VOICE,))
    invite = adapter.render(Signal(SignalType.INVITE, target="sip:u1@x",
                                   detail={}), ctx, req)

    values = invite.headers.get_all("Accept-Contact")
    assert len(values) == 2, values
    assert values[0] == "*;+g.3gpp.mcptt;require;explicit"
    assert values[1] == \
        '*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt";require;explicit'
    # Literal, not the module constant: importing it would let a wrong ICSI
    # pass, because the renderer and the assertion would move together.
    assert "urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt" in \
        invite.headers.get("Contact")


def test_resource_priority_namespaces_are_not_constants_in_core():
    """PLT-CONF-AUDIT CA-06.

    TS 24.379 clause 6.3.3.1.19 retrieves the Resource-Priority namespace from
    the service configuration document (TS 24.484); RFC 8101 registers the
    values. Two literals used to sit in core/sip.py labelled as RFC 4412
    constants -- deployment configuration in the one module that is forbidden
    to hold any.
    """
    import core.sip as sip
    assert not hasattr(sip, "RP_NAMESPACE_NORMAL")
    assert not hasattr(sip, "RP_NAMESPACE_EMERGENCY")


def test_warning_agent_is_a_host_name_for_a_public_service_identity():
    """PLT-CONF-AUDIT CA-02b, second attempt.

    TS 24.379 clause 4.2: a participating or controlling function is reachable
    at a public service identity, which has no userinfo part. The first fix
    for the `mcx` placeholder split on "@" and then on ":", so every URI of
    that shape yielded the scheme -- `Warning: 399 sip "..."`. Every test in
    this file used a `user@host` URI, which is the one shape that masks it.

    Each form below is asserted separately: they fail independently.
    """
    ctx = lambda uri: DialogContext(call_id="c1", local_uri=uri)  # noqa: E731

    for uri, host in (
        ("sip:ps.mcptt.example", "ps.mcptt.example"),
        ("sip:ps.mcptt.example:5060", "ps.mcptt.example"),
        ("sips:ps.mcptt.example:5061", "ps.mcptt.example"),
        ("sip:server@mcptt.example", "mcptt.example"),
        ("sip:[2001:db8::1]:5060", "[2001:db8::1]"),
    ):
        warning = Adapter(uri, Release.REL_19).reject("unknown-target", ctx(uri)) \
            .headers.get("Warning")
        assert warning == \
            f'399 {host} "145 unable to determine called party"', (uri, warning)
        assert " sip " not in warning and " sips " not in warning


def test_the_inbound_guard_uses_the_same_warning_shape():
    """Clause 4.4.1 conformance was claimed module-wide but only reached
    Adapter.reject; the guard's rejections still carried the literal `mcx`."""
    from core.sip import InboundGuard
    guard = InboundGuard()
    request = Request(method="INVITE", uri="sip:ps.mcptt.example",
                      headers=Headers([("To", "<sip:ps.mcptt.example>")]),
                      body="")
    response = guard.check(request)
    assert response is not None, "a request missing Via/From/CSeq must be refused"
    warning = response.headers.get("Warning")
    assert warning is not None, "the refusal must say why"
    assert warning.startswith('399 ps.mcptt.example "'), warning
    assert "mcx" not in warning


def test_non_base_feature_tags_carry_the_plus_prefix():
    """IETF RFC 3840 clause 5 (PLT-CONF-AUDIT CA-10).

    Base tags carry no prefix; every other tag "MUST" have a leading "+".
    None of the MC tags is a base tag. TS 24.379's own Contact examples are
    inconsistent -- six omit the prefix, two include it -- so this is pinned
    against the RFC rather than against the examples.
    """
    from core.sip import (FEATURE_TAG_DATA, FEATURE_TAG_ICSI_REF,
                          FEATURE_TAG_PTT, FEATURE_TAG_VIDEO)
    base_tags = {"audio", "video", "data", "control", "mobility", "isfocus",
                 "actor", "text", "automata", "class", "duplex",
                 "description", "events", "priority", "methods", "schemes",
                 "application", "language", "type"}
    for tag in (FEATURE_TAG_PTT, FEATURE_TAG_DATA, FEATURE_TAG_VIDEO,
                FEATURE_TAG_ICSI_REF):
        assert tag.startswith("+"), tag
        assert tag.lstrip("+") not in base_tags, tag

    adapter = Adapter("sip:ps.mcptt.example", Release.REL_19)
    ctx = DialogContext(call_id="c1", local_uri="sip:ps.mcptt.example")
    req = SessionRequest(request_id="c1", initiator="sip:u0@mcptt.example",
                         target="t", call_type="x", media=(MediaKind.VOICE,))
    invite = adapter.render(Signal(SignalType.INVITE, target="sip:u1@x",
                                   detail={}), ctx, req)
    assert "+g.3gpp.mcptt" in invite.headers.get("Contact")
    for value in invite.headers.get_all("Accept-Contact"):
        assert "+g.3gpp." in value, value


def test_the_three_mc_feature_tags_are_the_ones_the_specifications_define():
    """PLT-CONF-AUDIT CA-07. Confirmed against TS 24.379 (MCPTT),
    TS 24.281 (MCVideo) and TS 24.282 (MCData), all of which are now in
    `docs/3GPP/`. Both the MCData and MCVideo tags were marked unverified
    until those two documents arrived."""
    from core.sip import FEATURE_TAG_DATA, FEATURE_TAG_PTT, FEATURE_TAG_VIDEO
    assert FEATURE_TAG_PTT == "+g.3gpp.mcptt"
    assert FEATURE_TAG_VIDEO == "+g.3gpp.mcvideo"
    assert FEATURE_TAG_DATA == "+g.3gpp.mcdata"


def test_no_refusal_emits_an_interworking_warning_code():
    """PLT-CONF-AUDIT CA-09. TS 24.379 table 4.4.2-2 reserves 301-350 for
    interworking and defers their meaning; TS 29.379 table 4.2.2-1 then
    allocates exactly three, 300, 301 and 302, all of them Land Mobile Radio
    media security and codec negotiation at an IWF:

        300  LMR end-to-end encryption not permitted
        301  LMR end-to-end encryption required
        302  LMR codec required

    This platform is not an IWF and terminates no LMR media, so none of its
    refusals may ever carry one. `gateway-unavailable` is the one that would
    tempt a future reader -- it is about interworking, and 301 is an
    interworking code -- but it reports that the gateway is unreachable, which
    is not what any of the three means.

    The whole reason space is swept rather than the one tempting member, so a
    reason code added later is covered without anybody remembering to do it.
    """
    from core.sip import REASON_TO_STATUS

    for release in (13, 14, 15, 16, 17, 18, 19, 20):
        adapter = Adapter("sip:server@mcptt.example", Release(release))
        ctx = DialogContext(call_id="c1", local_uri="sip:server@mcptt.example")
        for reason in REASON_TO_STATUS:
            warning = adapter.reject(reason, ctx).headers.get("Warning")
            if warning is None:
                continue
            quoted = warning.split('"')
            assert len(quoted) >= 2, f"{reason}: malformed Warning {warning!r}"
            head = quoted[1].split(" ", 1)[0]
            if not head.isdigit():
                continue
            assert int(head) < 300, (
                f"{reason} at Rel-{release} emits MC code {head}, which is in "
                f"the interworking range TS 29.379 owns")


def test_timer_b_on_a_ringing_invite_asks_for_a_cancel_instead_of_ending():
    """SIP-OP-15: in 'Proceeding' the INVITE is kept for 64*T1 after the
    CANCEL it now needs (RFC 3261 9.1); in 'Calling' Timer B ends it."""
    from core.sip import Headers, Request
    from service.sip_txn import ClientTransactions
    now = [0]
    txns = ClientTransactions(lambda: now[0], t1=500)

    def inv(branch):
        return Request("INVITE", "sip:b@x", Headers([
            ("Via", f"SIP/2.0/TLS x;branch={branch}"), ("CSeq", "1 INVITE")]))
    ringing, silent = txns.start(inv("z9hG4bKa"), None), txns.start(inv("z9hG4bKb"), None)
    txns.proceed(ringing)
    now[0] = 32_000
    fired = txns.tick()
    assert set(map(id, fired)) == {id(ringing), id(silent)}
    assert silent.done and not ringing.done and ringing.cancelled
    assert txns.find("z9hG4bKa", "INVITE") is ringing
    now[0] = 63_999
    assert txns.tick() == [] and not ringing.done
    now[0] = 64_000
    assert txns.tick() == [ringing] and ringing.done


def test_the_ring_limit_replaces_timer_b_once_the_invite_is_proceeding():
    from core.sip import Headers, Request
    from service.sip_txn import ClientTransactions
    now = [0]
    txns = ClientTransactions(lambda: now[0], t1=500)
    req = Request("INVITE", "sip:b@x", Headers([
        ("Via", "SIP/2.0/TLS x;branch=z9hG4bKra"), ("CSeq", "1 INVITE")]))
    t = txns.start(req, None, answer_by=90_000)
    assert t.expires_at == 32_000                  # Timer B while 'Calling'
    now[0] = 1_000
    txns.proceed(t)
    assert t.expires_at == 90_000
    txns.proceed(t)                                # a second 1xx changes nothing
    assert t.expires_at == 90_000
    now[0] = 89_999
    assert txns.tick() == []
    now[0] = 90_000
    assert txns.tick() == [t] and t.cancelled and not t.done
