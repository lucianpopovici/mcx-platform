"""CC-OP-01: joining a group call already ongoing (TS 24.379 10.1.1.4.2 steps
9 and 15), rejoining, and late call entry (10.1.1.4.6). Owner decisions of
2026-11-23:

1. A caller whose call type differs from the ongoing call's joins the call as
   it is (an in-progress upgrade is R2, PLT-CC-006/007).
2. A party already in the call that sends a new INVITE rejoins: its new dialog
   replaces the old one, which is ended; it keeps its relay endpoint and its
   place on the floor.
3. A member who registers while its group has a call ongoing is invited into
   it (late entry), once per registration.
4. Each join writes a participant-joined audit record.

Step 9 asks "if an MCPTT group call for the group identity is already
ongoing"; before this, each such INVITE started a second session of the same
group, so the group had two controlling functions (PLT-CC-002) and every
member was invited twice."""

from __future__ import annotations

import threading

import pytest

from core.audit import RecordType
from core.session import JOIN_KINDS, SessionState
from core.sip import ReceivedResponse, canonical_uri
from service.sip_core import _tag
from tests import mcpttinfo_fixture as mcf
from tests.test_group_initiator_leaves import _member_bye
from tests.test_session_timer import (  # noqa: F401  (fixtures)
    TIMER, _group_call, _released_as, contact_uri, responses)
from tests.test_sip_transport import (  # noqa: F401  (fixtures)
    LOCAL, SDP, U, Flow, _limit_decided, answer, clock, core, env, invite, msg, pki,
    register, rt, sip_env, world)

WARNING_123 = '399 mcptt.example "123 MCPTT session already exists"'


def _join(core, world, cid, who, call_type="prearranged-group", extra=()):
    world[who].sent.clear()
    core.on_bytes(invite(cid, who, "grp:alpha", call_type, extra=list(extra)), world[who])
    return [m for m in world[who].messages()
            if isinstance(m, ReceivedResponse) and m.headers.get("Call-ID") == cid]


def _ack(core, world, cid, who, ok):
    core.on_bytes(msg("ACK", contact_uri(ok.headers.get("Contact")), cid, 1, who, LOCAL,
                      branch=f"z9hG4bKack{cid}", to_tag=_tag(cid)), world[who])


def _joined_bye(core, world, cid, who, cseq=2):
    core.on_bytes(msg("BYE", LOCAL, cid, cseq, who, LOCAL, to_tag=_tag(cid)), world[who])


def _records(rt, cid, kind):
    return [r["detail"] for r in rt.store.audit_records(cid) if r["type"] == kind]


def _group_sessions(rt):
    return [s.correlation_id for s in rt.manager._sessions.values()
            if s.state is SessionState.ESTABLISHED and s.resolution.group_id == "grp:alpha"]


# -- joining ------------------------------------------------------------------------

@pytest.mark.vp("VP1-CC-002")
@pytest.mark.vp("VP1-CC-005")
def test_a_member_who_invites_the_group_joins_the_call_in_progress(core, rt, world):
    """u2 hung up, then INVITEs grp:alpha again: it joins g1 (200 OK, SDP
    answer, warning 123, step 15h-j), no second session is started and no
    member is invited again."""
    legs = _group_call(core, world, "g1")
    _member_bye(core, world, legs, U[2])
    invites = {u: len(world[u].requests("INVITE")) for u in U if u != U[2]}
    (trying, ok) = _join(core, world, "j1", U[2])
    assert (trying.code, ok.code) == (100, 200)
    assert ok.headers.get_all("Warning") == (WARNING_123,)
    assert ok.headers.get("Content-Type") == "application/sdp" and "m=audio" in ok.body
    assert _group_sessions(rt) == ["g1"] and rt.manager.session("j1") is None
    assert {u: len(world[u].requests("INVITE")) for u in U if u != U[2]} == invites
    assert world[U[2]].requests("INVITE") == []
    media = core.calls["g1"].media
    assert U[2] in media.endpoints
    # The joiner's dialog is the session's: the same focus Contact (clause 4.5).
    assert contact_uri(ok.headers.get("Contact")) == core.calls["g1"].session_uri
    # Members in the call besides the initiator, as participant-left counts.
    assert _records(rt, "g1", "participant-joined") == [
        {"participant": U[2], "how": "invite", "members": 3, "call_id": "j1"}]
    assert _records(rt, "j1", "session-refused") == []


def test_the_joiner_is_answered_with_the_call_s_codec_alone(core, world):
    """No transcoding (VP-OP-03): a joiner offering PCMA first and the call's
    PCMU second is answered with PCMU only, relayed to and from it under 0."""
    legs = _group_call(core, world, "g2")
    _member_bye(core, world, legs, U[1])
    offer = SDP.replace("RTP/AVP 0", "RTP/AVP 8 0").replace(
        "a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000")
    assert "PCMA" in offer
    world[U[1]].sent.clear()
    core.on_bytes(msg("INVITE", LOCAL, "j2", 1, U[1], LOCAL, ctype=mcf.CONTENT_TYPE,
                      body=mcf.body_for("prearranged-group", "grp:alpha", offer)),
                  world[U[1]])
    (ok,) = responses(world[U[1]], 200)
    audio = [l for l in ok.body.splitlines() if l.startswith(("m=audio", "a=rtpmap"))]
    assert audio[0].endswith("RTP/AVP 0") and audio[1:] == ["a=rtpmap:0 PCMU/8000"]
    ep = core.calls["g2"].media.endpoints[U[1]]
    assert (ep.rx_pt, ep.tx_pt) == (0, 0)


def test_a_caller_asking_another_call_type_joins_the_call_as_it_is(core, rt, world):
    """Decision 1: emergency-group asked while prearranged-group is ongoing;
    the call keeps its type, priority and decision (upgrade is R2)."""
    legs = _group_call(core, world, "g3")
    _member_bye(core, world, legs, U[1])
    before = rt.manager.session("g3")
    (_, ok) = _join(core, world, "j3", U[1], call_type="emergency-group")
    assert ok.code == 200
    after = rt.manager.session("g3")
    assert after.request.call_type == "prearranged-group"
    assert after.priority == before.priority and after.decision == before.decision
    assert _group_sessions(rt) == ["g3"]


@pytest.mark.vp("VP1-CC-002")
def test_simultaneous_origination_gives_one_session_and_one_invitation_each(
        core, rt, world):
    """u0 and u1 both call grp:alpha, u1's INVITE arriving while the call u0
    started is still being set up (u1 itself still being invited): one
    session. u1 joins by its own INVITE; the platform's invitation to it is
    CANCELled at its first provisional response (RFC 3261 9.1); u2 and u3 are
    invited once; u0 is answered, the call now having a second party."""
    core.on_bytes(invite("s1", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    (to_u1,) = world[U[1]].requests("INVITE")
    (_, ok) = _join(core, world, "s2", U[1])
    assert ok.code == 200 and ok.headers.get_all("Warning") == (WARNING_123,)
    assert _group_sessions(rt) == ["s1"]
    assert [len(world[u].requests("INVITE")) for u in U[2:]] == [1, 1]
    assert [r.code for r in responses(world[U[0]])] == [100, 200]
    world[U[1]].sent.clear()
    core.on_bytes(answer(to_u1, 180), world[U[1]])
    (cancel,) = world[U[1]].requests("CANCEL")
    assert cancel.headers.get("Call-ID") == to_u1.headers.get("Call-ID")
    core.on_bytes(answer(to_u1, 487), world[U[1]])
    assert rt.manager.session("s1").state is SessionState.ESTABLISHED
    for u in U[2:]:
        core.on_bytes(answer(world[u].requests("INVITE")[0], 200, SDP), world[u])
    assert [r.code for r in responses(world[U[0]])] == [100, 200]


def test_a_cancelled_invitation_to_the_only_other_party_does_not_fail_the_call(
        core, rt, world):
    """u0 calls; u2 and u3 refuse; u1 joins by its own INVITE while its
    invitation is still pending, which is then refused 487: the call goes
    on, u0 and u1 in it."""
    core.on_bytes(invite("s3", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    for u in U[2:]:
        core.on_bytes(answer(world[u].requests("INVITE")[0], 486), world[u])
    (to_u1,) = world[U[1]].requests("INVITE")
    _join(core, world, "s4", U[1])
    core.on_bytes(answer(to_u1, 180), world[U[1]])
    core.on_bytes(answer(to_u1, 487), world[U[1]])
    assert rt.manager.session("s3").state is SessionState.ESTABLISHED
    assert world[U[0]].requests("BYE") == []


# -- rejoin (decision 2) ----------------------------------------------------------------

def test_a_member_in_the_call_that_invites_again_rejoins_and_keeps_its_place(core, rt,
                                                                             world):
    from core import rtcp
    legs = _group_call(core, world, "r1")
    media = core.calls["r1"].media
    ep = media.endpoints[U[1]]
    ep.remote_floor = ("192.0.2.9", 6000)
    media.on_floor(U[1], ("192.0.2.9", 6000),
                   media.codec.encode(rtcp.message(rtcp.MsgType.REQUEST, 7)))
    assert media.floor.queue == (U[1],)
    (_, ok) = _join(core, world, "rj1", U[1])
    assert ok.code == 200
    (bye,) = world[U[1]].requests("BYE")
    assert bye.headers.get("Call-ID") == legs[U[1]].headers.get("Call-ID")
    assert media.endpoints[U[1]] is ep and media.floor.queue == (U[1],)
    assert _records(rt, "r1", "participant-joined") == [
        {"participant": U[1], "how": "rejoin", "members": 3, "call_id": "rj1"}]
    assert _records(rt, "r1", "participant-left") == []
    # The old leg's BYE answered: nothing more happens.
    core.on_bytes(answer(bye, 200), world[U[1]])
    assert rt.manager.session("r1").state is SessionState.ESTABLISHED
    assert U[1] in media.endpoints


def test_a_joined_participant_that_invites_again_replaces_its_joined_dialog(core, rt,
                                                                            world):
    legs = _group_call(core, world, "r2")
    _member_bye(core, world, legs, U[2])
    _join(core, world, "rj2a", U[2])
    (_, ok) = _join(core, world, "rj2b", U[2])
    assert ok.code == 200
    (bye,) = world[U[2]].requests("BYE")
    assert bye.headers.get("Call-ID") == "rj2a"
    assert "rj2a" not in core.calls and "rj2b" in core.calls
    assert [d["how"] for d in _records(rt, "r2", "participant-joined")] == ["invite", "rejoin"]


def test_the_initiator_that_invites_again_rejoins_its_own_call(core, rt, world):
    _group_call(core, world, "r3")
    world[U[0]].sent.clear()
    core.on_bytes(invite("rj3", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    byes = world[U[0]].requests("BYE")
    assert [b.headers.get("Call-ID") for b in byes] == ["r3"]
    assert [r.code for r in responses(world[U[0]])
            if r.headers.get("Call-ID") == "rj3"] == [100, 200]
    assert rt.manager.session("r3").state is SessionState.ESTABLISHED
    assert core.calls["r3"].initiator_via == "rj3"
    assert core._still_in(core.calls["r3"], U[0])
    # Still the initiator (review F2): under MCX_GROUP_INITIATOR_LEAVES=release
    # its hanging up releases the call.
    _joined_bye(core, world, "rj3", U[0])
    assert _released_as(rt, "r3") == [("session-released", "normal")]


# -- what is refused --------------------------------------------------------------------

def test_a_full_call_refuses_the_joiner_486_with_warning_122(core, rt, world):
    """Step 15d: the session decision allows 3, the caller and u1, u2 are in
    (u3 not invited): u3's join is refused 486 + 122 and audited under its
    own Call-ID; nothing changes in the call."""
    _limit_decided(rt, 3)
    core.on_bytes(invite("f1", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    for u in U[1:3]:
        core.on_bytes(answer(world[u].requests("INVITE")[0], 200, SDP), world[u])
    rs = _join(core, world, "fj1", U[3])
    assert [r.code for r in rs] == [100, 486]
    assert rs[-1].headers.get("Warning") == '399 mcptt.example "122 too many participants"'
    assert [d["reason_code"] for d in _records(rt, "fj1", "session-refused")] == \
        ["participant-limit-exceeded"]
    assert U[3] not in core.calls["f1"].media.endpoints
    assert _records(rt, "f1", "participant-joined") == []


def test_a_member_who_left_a_full_call_may_join_it_again(core, rt, world):
    _limit_decided(rt, 3)
    core.on_bytes(invite("f2", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    legs = {u: world[u].requests("INVITE")[0] for u in U[1:3]}
    for u in U[1:3]:
        core.on_bytes(answer(legs[u], 200, SDP), world[u])
    _member_bye(core, world, legs, U[1])
    assert [r.code for r in _join(core, world, "fj2", U[1])] == [100, 200]


def test_a_non_member_is_refused_before_anything_is_said_of_the_call(core, rt, world):
    """403 warning 116, as for originating (SVC-OP-07, before step 1b): an
    outsider learns nothing of whether a call is ongoing."""
    _group_call(core, world, "n1")
    out = "sip:u9@mcptt.example"
    flow = Flow(out)
    register(core, out, flow)
    flow.sent.clear()
    core.on_bytes(invite("nj1", out, "grp:alpha", "prearranged-group"), flow)
    (_, refused) = [m for m in flow.messages() if isinstance(m, ReceivedResponse)]
    assert refused.code == 403 and "116" in refused.headers.get("Warning")


def test_an_offer_without_the_call_s_codec_is_refused_488(core, rt, world):
    legs = _group_call(core, world, "c1")
    _member_bye(core, world, legs, U[3])
    sdp = SDP.replace("RTP/AVP 0", "RTP/AVP 8").replace("rtpmap:0 PCMU", "rtpmap:8 PCMA")
    assert "PCMU" not in sdp
    world[U[3]].sent.clear()
    core.on_bytes(msg("INVITE", LOCAL, "cj1", 1, U[3], LOCAL, ctype=mcf.CONTENT_TYPE,
                      body=mcf.body_for("prearranged-group", "grp:alpha", sdp)),
                  world[U[3]])
    codes = [m.code for m in world[U[3]].messages() if isinstance(m, ReceivedResponse)]
    assert codes[-1] == 488
    assert U[3] not in core.calls["c1"].media.endpoints


# -- the joined dialog ------------------------------------------------------------------

def test_a_joined_participant_that_hangs_up_leaves_the_call(core, rt, world):
    legs = _group_call(core, world, "d1")
    _member_bye(core, world, legs, U[3])
    (_, ok) = _join(core, world, "dj1", U[3])
    _ack(core, world, "dj1", U[3], ok)
    _joined_bye(core, world, "dj1", U[3])
    assert [r.code for r in responses(world[U[3]], method="BYE")] == [200]
    assert U[3] not in core.calls["d1"].media.endpoints and "dj1" not in core.calls
    assert _records(rt, "d1", "participant-left")[-1] == {
        "participant": U[3], "role": "member", "cause": "normal", "remaining": 2}
    assert rt.manager.session("d1").state is SessionState.ESTABLISHED


def test_the_last_member_leaving_through_its_joined_dialog_ends_the_call(core, rt, world):
    core.on_bytes(invite("d2", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    for u in U[1:]:
        core.on_bytes(answer(world[u].requests("INVITE")[0], 486), world[u])
    # Every invitation refused: the call failed; u1 then calls the group itself.
    assert rt.manager.session("d2") is None
    core.on_bytes(invite("d3", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    for u in U[2:]:
        core.on_bytes(answer(world[u].requests("INVITE")[-1], 486), world[u])
    _join(core, world, "dj3", U[1])
    to_u1 = world[U[1]].requests("INVITE")
    _joined_bye(core, world, "dj3", U[1])
    assert _released_as(rt, "d3") == [("session-released", "normal")]
    assert [b.headers.get("Call-ID") for b in world[U[0]].requests("BYE")] == ["d3"]
    assert to_u1 == []


def test_the_call_s_release_ends_each_joined_dialog_once(core, rt, world):
    legs = _group_call(core, world, "d4")
    _member_bye(core, world, legs, U[2])
    (_, ok) = _join(core, world, "dj4", U[2])
    _ack(core, world, "dj4", U[2], ok)
    world[U[2]].sent.clear()
    core.on_bytes(msg("BYE", LOCAL, "d4", 2, U[0], LOCAL, to_tag=_tag("d4")), world[U[0]])
    assert [b.headers.get("Call-ID") for b in world[U[2]].requests("BYE")] == ["dj4"]
    assert "dj4" not in core.calls and "d4" not in core.calls


def test_a_joined_dialog_that_is_not_acked_leaves_alone(core, rt, world, clock):
    legs = _group_call(core, world, "d5")
    _member_bye(core, world, legs, U[3])
    _join(core, world, "dj5", U[3])
    for _ in range(80):
        clock.now += 1000
        core.tick()
    assert "dj5" not in core.calls
    assert rt.manager.session("d5").state is SessionState.ESTABLISHED
    assert _records(rt, "d5", "participant-left")[-1]["cause"] == "ack-timeout"


def test_a_joined_dialog_whose_session_expires_leaves_alone(core, rt, world, clock):
    legs = _group_call(core, world, "d6", callee_extra=[
        "Session-Expires: 86400;refresher=uas", "Require: timer"])
    _member_bye(core, world, legs, U[3])
    (_, ok) = _join(core, world, "dj6", U[3], extra=[
        "Supported: timer", "Session-Expires: 120;refresher=uac"])
    _ack(core, world, "dj6", U[3], ok)
    t0 = clock.now
    while "dj6" in core.calls:
        assert clock.now < t0 + 600_000
        clock.now += 1000
        core.tick()
    assert [b.headers.get("Call-ID") for b in world[U[3]].requests("BYE")] == ["dj6"]
    assert _records(rt, "d6", "participant-left")[-1]["cause"] == "session-expired"
    assert rt.manager.session("d6").state is SessionState.ESTABLISHED


def test_a_joiner_whose_registration_expired_leaves_at_its_refresh(core, rt, world, clock):
    """SIP-OP-21's refusal of the joiner's own refresh (404, warning 141):
    the joiner leaves, cause registration-expired, and the call goes on --
    it is a member, not the call's caller."""
    legs = _group_call(core, world, "d7", callee_extra=[
        "Session-Expires: 86400;refresher=uas", "Require: timer"])
    _member_bye(core, world, legs, U[3])
    register(core, U[3], world[U[3]], n=7, expires=60)
    (_, ok) = _join(core, world, "dj7", U[3], extra=list(TIMER))
    _ack(core, world, "dj7", U[3], ok)
    clock.now += 61_000
    core.tick()
    world[U[3]].sent.clear()
    core.on_bytes(msg("UPDATE", LOCAL, "dj7", 3, U[3], LOCAL, to_tag=_tag("dj7"),
                      extra=list(TIMER)), world[U[3]])
    (refused,) = responses(world[U[3]], method="UPDATE")
    assert refused.code == 404 and "141" in refused.headers.get("Warning")
    assert world[U[3]].requests("BYE") == []
    assert _records(rt, "d7", "participant-left")[-1]["cause"] == "registration-expired"
    assert rt.manager.session("d7").state is SessionState.ESTABLISHED


def test_a_refresh_in_the_joined_dialog_is_answered(core, rt, world):
    legs = _group_call(core, world, "d8")
    _member_bye(core, world, legs, U[1])
    (_, ok) = _join(core, world, "dj8", U[1], extra=list(TIMER))
    _ack(core, world, "dj8", U[1], ok)
    world[U[1]].sent.clear()
    core.on_bytes(msg("UPDATE", LOCAL, "dj8", 3, U[1], LOCAL, to_tag=_tag("dj8"),
                      extra=list(TIMER)), world[U[1]])
    assert [r.code for r in responses(world[U[1]], method="UPDATE")] == [200]


def test_with_the_initiator_gone_a_joined_member_counts_for_item_2(tmp_path, pki, clock):
    """MCX_GROUP_INITIATOR_LEAVES=continue: u0 leaves with u1 and a joined u3
    in the call -- two members, so it goes on; when u3 leaves, one remains,
    and the call is released (6.3.8.1 item 2)."""
    from tests.test_group_initiator_leaves import _initiator_bye, _world
    (tmp_path / "w").mkdir()
    rt, core, flows = _world(tmp_path / "w", pki, clock, "continue")
    try:
        legs = _group_call(core, flows, "i2")
        _member_bye(core, flows, legs, U[2])
        _member_bye(core, flows, legs, U[3], cseq=3)
        (_, ok) = _join(core, flows, "ij2", U[3])
        _ack(core, flows, "ij2", U[3], ok)
        _initiator_bye(core, flows, "i2")
        assert rt.manager.session("i2").state is SessionState.ESTABLISHED
        _joined_bye(core, flows, "ij2", U[3])
        assert _released_as(rt, "i2") == [("session-released", "normal")]
    finally:
        core.close()
        rt.close()


# -- late call entry (decision 3) -------------------------------------------------------

def _unregistered_u3(core, world):
    register(core, U[3], world[U[3]], n=5, expires=0)
    world[U[3]].sent.clear()


@pytest.mark.vp("VP1-CC-005")
def test_a_member_who_registers_during_the_call_is_invited_once(core, rt, world):
    """10.1.1.4.6: u3 was not registered when the call started (its leg was
    dead on arrival); it registers: it is invited, as the members were; it
    answers and is in. A refresh of its registration invites nobody."""
    _unregistered_u3(core, world)
    core.on_bytes(invite("l1", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    for u in U[1:3]:
        core.on_bytes(answer(world[u].requests("INVITE")[0], 200, SDP), world[u])
    assert world[U[3]].requests("INVITE") == []
    register(core, U[3], world[U[3]], n=6)
    (late,) = world[U[3]].requests("INVITE")
    first = world[U[1]].sent[0]
    assert "<mcptt-calling-group-id" in late.body and "<mcptt-calling-group-id" in first
    core.on_bytes(answer(late, 200, SDP), world[U[3]])
    assert U[3] in core.calls["l1"].media.endpoints
    assert _records(rt, "l1", "participant-joined") == [
        {"participant": U[3], "how": "late-entry", "members": 3,
         "call_id": late.headers.get("Call-ID")}]
    register(core, U[3], world[U[3]], n=7)
    assert len(world[U[3]].requests("INVITE")) == 1


@pytest.mark.vp("VP1-CC-005")
def test_a_member_left_out_by_the_limit_is_not_invited_when_it_registers(core, rt, world):
    """The session decision kept u0..u2 (limit 3): u3 is not one of the
    call's members, and registering does not make it one."""
    _limit_decided(rt, 3)
    _unregistered_u3(core, world)
    core.on_bytes(invite("l2", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    register(core, U[3], world[U[3]], n=6)
    assert world[U[3]].requests("INVITE") == []


def test_no_late_entry_for_a_party_already_in_the_call(core, rt, world, clock):
    """u1 is in the call; its registration lapses and it registers again:
    nothing is sent to it."""
    _group_call(core, world, "l3")
    register(core, U[1], world[U[1]], n=5, expires=60)
    clock.now += 61_000
    world[U[1]].sent.clear()
    register(core, U[1], world[U[1]], n=6)
    assert world[U[1]].requests("INVITE") == []


def test_no_late_entry_into_a_private_call_or_without_a_call(core, rt, world):
    _unregistered_u3(core, world)
    core.on_bytes(invite("l4", U[0], U[1], "private"), world[U[0]])
    register(core, U[3], world[U[3]], n=6)
    assert world[U[3]].requests("INVITE") == []


def test_a_late_entry_that_is_refused_changes_nothing(core, rt, world):
    _unregistered_u3(core, world)
    core.on_bytes(invite("l5", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    for u in U[1:3]:
        core.on_bytes(answer(world[u].requests("INVITE")[0], 200, SDP), world[u])
    register(core, U[3], world[U[3]], n=6)
    (late,) = world[U[3]].requests("INVITE")
    core.on_bytes(answer(late, 486), world[U[3]])
    assert rt.manager.session("l5").state is SessionState.ESTABLISHED
    assert _records(rt, "l5", "participant-joined") == []


# -- the core's side ------------------------------------------------------------------

def test_the_record_type_and_join_kinds_are_pinned():
    assert RecordType.PARTICIPANT_JOINED.value == "participant-joined"
    assert JOIN_KINDS == ("invite", "rejoin", "late-entry")


def test_participant_joined_refuses_an_unknown_kind_and_ignores_no_session(core, rt, world):
    _group_call(core, world, "k1")
    with pytest.raises(ValueError):
        rt.manager.participant_joined("k1", U[1], "walk-in", 3, "x")
    rt.manager.participant_joined("nope", U[1], "invite", 3, "x")
    assert rt.store.audit_records("nope") == []


def test_admit_join_is_the_decision_s_limit(core, rt, world):
    _limit_decided(rt, 3)
    core.on_bytes(invite("k2", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    assert rt.manager.admit_join("k2", 2) is None
    refusal = rt.manager.admit_join("k2", 3)
    assert (refusal.reason_code, refusal.detail) == (
        "participant-limit-exceeded",
        "the call has 3 participants, the session decision allows 3")
    with pytest.raises(ValueError):
        rt.manager.admit_join("nope", 1)


def test_a_joiner_becomes_a_member_so_the_release_reaches_it(core, rt, world):
    legs = _group_call(core, world, "k3")
    _member_bye(core, world, legs, U[3])
    out_of_set = rt.manager.session("k3").members
    _join(core, world, "kj3", U[3])
    assert rt.manager.session("k3").members == out_of_set     # u3 was a member already
    assert [canonical_uri(m) for m in rt.manager.session("k3").members].count(U[3]) == 1


# -- VP1-CC-002: one controlling function per group call, under concurrency --------------

@pytest.mark.vp("VP1-CC-002")
def test_concurrent_calls_and_simultaneous_origination_keep_one_controller_per_call(
        tmp_path, pki, clock):
    """Three groups, each with two members calling it at once from their own
    threads, through the core's lock as the TLS transport takes it
    (service/sip_tls.py), while every member answers. Sampled after every
    message: each group has at most one established session, controlled
    here; at the end exactly one per group, every member a party of it, and
    each member invited at most once."""
    from core.session import Platform
    from service.runtime import build_runtime
    from service.sip_core import SipCore
    from tests.network_fixture import network_yaml
    groups = {f"grp:g{g}": [f"sip:g{g}m{i}@mcptt.example" for i in range(4)]
              for g in range(3)}
    env = sip_env(tmp_path, pki)
    env["MCX_NETWORK_FILE"] = str(network_yaml(
        tmp_path, trusted_cores=["core-client.example"], core_ca=pki / "core-ca.crt",
        groups=[{"id": g, "members": m} for g, m in groups.items()]))
    rt = build_runtime(env, clock, platform=Platform())
    core = SipCore(rt, LOCAL, clock)
    flows = {u: Flow(u) for m in groups.values() for u in m}
    for u, f in flows.items():
        register(core, u, f)
        f.sent.clear()
    seen, faults = [], []

    def sample():
        per = {}
        for s in rt.manager._sessions.values():
            if s.state is SessionState.ESTABLISHED:
                per.setdefault(s.resolution.group_id, []).append(s)
        seen.append({g: len(v) for g, v in per.items()})
        assert all(s.controlling for v in per.values() for s in v)

    def send(raw, flow):
        with core.lock:
            core.on_bytes(raw, flow)
            sample()

    def caller(g, i):
        try:
            u = groups[g][i]
            send(invite(f"{g}-{i}", u, g, "prearranged-group"), flows[u])
        except BaseException as exc:          # noqa: BLE001
            faults.append(exc)

    barrier = threading.Barrier(6)
    threads = [threading.Thread(target=lambda g=g, i=i: (barrier.wait(), caller(g, i)))
               for g in groups for i in (0, 1)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert faults == []
        for g, members in groups.items():
            for u in members:
                for req in flows[u].requests("INVITE"):
                    send(answer(req, 200, SDP), flows[u])
        assert all(n == 1 for snap in seen for n in snap.values())
        established = {}
        for s in rt.manager._sessions.values():
            if s.state is SessionState.ESTABLISHED:
                established.setdefault(s.resolution.group_id, []).append(s.correlation_id)
        assert sorted(established) == sorted(groups)
        assert all(len(v) == 1 for v in established.values())
        for g, members in groups.items():
            (cid,) = established[g]
            call_ = core.calls[cid]
            assert all(core._still_in(call_, u) for u in members), g
            assert all(len(flows[u].requests("INVITE")) <= 1 for u in members)
    finally:
        core.close()
        rt.close()


# -- review of the mutation run ----------------------------------------------------------

def _limited_call(core, rt, world, cid, limit=3, answering=(1, 2)):
    _limit_decided(rt, limit)
    core.on_bytes(invite(cid, U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    legs = {U[i]: world[U[i]].requests("INVITE")[0] for i in answering}
    for u, req in legs.items():
        core.on_bytes(answer(req, 200, SDP), world[u])
    return legs


def test_a_party_in_a_full_call_may_rejoin_it(core, rt, world):
    """The limit counts the others: a rejoining party takes its own place."""
    _limited_call(core, rt, world, "m1")
    assert [r.code for r in _join(core, world, "mj1", U[1])] == [100, 200]


def test_the_initiator_of_a_full_call_may_rejoin_it(core, rt, world):
    _limited_call(core, rt, world, "m2")
    world[U[0]].sent.clear()
    core.on_bytes(invite("mj2", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    assert [r.code for r in responses(world[U[0]]) if r.headers.get("Call-ID") == "mj2"] \
        == [100, 200]


def test_a_member_still_ringing_takes_a_place(core, rt, world):
    """u1 rings, u2 is in: with the caller that is three of three, so the
    truncated-out u3, joining, is refused."""
    _limited_call(core, rt, world, "m3", answering=(2,))
    assert [r.code for r in _join(core, world, "mj3", U[3])] == [100, 486]


def test_after_the_initiator_left_its_place_is_free(tmp_path, pki, clock):
    """continue: the initiator left a call of three at its limit of 3; u3,
    truncated out at setup, may join."""
    from tests.test_group_initiator_leaves import _initiator_bye, _world
    (tmp_path / "w").mkdir()
    rt, core, flows = _world(tmp_path / "w", pki, clock, "continue")
    try:
        _limited_call(core, rt, flows, "m4")
        ok = responses(flows[U[0]], 200)[-1]
        _ack(core, flows, "m4", U[0], ok)
        _initiator_bye(core, flows, "m4")
        assert rt.manager.session("m4").state is SessionState.ESTABLISHED
        assert [r.code for r in _join(core, flows, "mj4", U[3])] == [100, 200]
    finally:
        core.close()
        rt.close()


def test_a_rejoin_spelled_with_another_host_case_keeps_the_same_endpoint(core, rt, world):
    _group_call(core, world, "m5")
    media = core.calls["m5"].media
    ep = media.endpoints[U[1]]
    flow = world[U[1]]
    flow.sent.clear()
    core.on_bytes(invite("mj5", "sip:u1@MCPTT.EXAMPLE", "grp:alpha", "prearranged-group"),
                  flow)
    assert [m.code for m in flow.messages() if isinstance(m, ReceivedResponse)] == [100, 200]
    assert [u for u in media.endpoints if canonical_uri(u) == U[1]] == [U[1]]
    assert media.endpoints[U[1]] is ep


def test_a_rejoin_by_a_joined_participant_keeps_its_endpoint_and_is_no_departure(
        core, rt, world):
    legs = _group_call(core, world, "m6")
    _member_bye(core, world, legs, U[2])
    _join(core, world, "mj6a", U[2])
    ep = core.calls["m6"].media.endpoints[U[2]]
    left = _records(rt, "m6", "participant-left")
    _join(core, world, "mj6b", U[2])
    assert core.calls["m6"].media.endpoints[U[2]] is ep
    assert _records(rt, "m6", "participant-left") == left


def test_a_release_from_outside_the_sip_core_reaches_a_joined_member(core, rt, world):
    """u3 was left out at setup (limit 3) and joined when u1 left: it is one
    of the session's members now, so a release the SIP core did not start
    (an operator's, a pre-emption) sends its joined dialog a BYE. Nobody is
    recorded as having left."""
    legs = _limited_call(core, rt, world, "m7")
    assert U[3] not in rt.manager.session("m7").members
    _member_bye(core, world, legs, U[1])
    (_, ok) = _join(core, world, "mj7", U[3])
    _ack(core, world, "mj7", U[3], ok)
    assert U[3] in rt.manager.session("m7").members
    left = _records(rt, "m7", "participant-left")
    world[U[3]].sent.clear()
    rt.release("m7", "pre-empted")
    assert [b.headers.get("Call-ID") for b in world[U[3]].requests("BYE")] == ["mj7"]
    assert "mj7" not in core.calls
    assert _records(rt, "m7", "participant-left") == left


def test_a_release_that_faults_still_ends_the_joined_dialogs(core, rt, world, monkeypatch):
    legs = _group_call(core, world, "m8")
    _member_bye(core, world, legs, U[3])
    (_, ok) = _join(core, world, "mj8", U[3])
    _ack(core, world, "mj8", U[3], ok)
    world[U[3]].sent.clear()

    def down(*a, **k):
        raise RuntimeError("store down")
    monkeypatch.setattr(rt, "release", down)
    core.on_bytes(msg("BYE", LOCAL, "m8", 2, U[0], LOCAL, to_tag=_tag("m8")), world[U[0]])
    assert [b.headers.get("Call-ID") for b in world[U[3]].requests("BYE")] == ["mj8"]
    assert "mj8" not in core.calls


def test_a_joined_dialog_is_the_host_session_s_in_logs(core, rt, world):
    """Its messages are logged under the session it joined (RES-OP-04)."""
    legs = _group_call(core, world, "m9")
    _member_bye(core, world, legs, U[2])
    _join(core, world, "mj9", U[2])
    assert core._cid_of("mj9") == "m9"


def test_joining_writes_nothing_to_the_store(core, rt, world, monkeypatch):
    """The session joined is already stored; the join adds no row and
    rewrites none."""
    legs = _group_call(core, world, "m10")
    _member_bye(core, world, legs, U[1])
    written = []
    monkeypatch.setattr(rt, "_persist", lambda s: written.append(s.correlation_id))
    _join(core, world, "mj10", U[1])
    assert written == []


def test_an_unwritable_join_record_is_logged_as_lost(core, rt, world, caplog):
    _group_call(core, world, "m11")

    def down(*a, **k):
        raise OSError("audit store down")
    rt.manager._auditor.emit = down
    rt.manager.participant_joined("m11", U[1], "invite", 3, "x")
    assert any("participant-joined record lost" in r.getMessage() for r in caplog.records)


def test_a_refused_late_entry_is_not_repeated_at_the_next_refresh(core, rt, world):
    _unregistered_u3(core, world)
    core.on_bytes(invite("m12", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    for u in U[1:3]:
        core.on_bytes(answer(world[u].requests("INVITE")[0], 200, SDP), world[u])
    register(core, U[3], world[U[3]], n=6)
    (late,) = world[U[3]].requests("INVITE")
    core.on_bytes(answer(late, 486), world[U[3]])
    register(core, U[3], world[U[3]], n=7)
    assert len(world[U[3]].requests("INVITE")) == 1


@pytest.mark.vp("VP1-CC-005")
def test_no_late_entry_when_the_call_is_full(core, rt, world):
    """Limit 3, u1 not registered when the call starts (so never in it): u0
    and u2 take part; u3, left out by the limit, joins by its INVITE -- three
    of three. u1 registers: the call is full, so it is not invited."""
    register(core, U[1], world[U[1]], n=5, expires=0)
    _limit_decided(rt, 3)
    core.on_bytes(invite("m13", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    core.on_bytes(answer(world[U[2]].requests("INVITE")[0], 200, SDP), world[U[2]])
    assert [r.code for r in _join(core, world, "mj13", U[3])] == [100, 200]
    world[U[1]].sent.clear()
    register(core, U[1], world[U[1]], n=6)
    assert world[U[1]].requests("INVITE") == []


def test_a_joined_participant_takes_a_place(core, rt, world):
    """Limit 3: u0, u2 and u3 (joined) are in; u1, who left, is refused."""
    legs = _limited_call(core, rt, world, "m14")
    _member_bye(core, world, legs, U[1])
    _join(core, world, "mj14", U[3])
    assert [r.code for r in _join(core, world, "mj14b", U[1])] == [100, 486]


# -- review of CC-OP-01 ------------------------------------------------------------------

def test_a_release_from_outside_reaches_the_rejoined_initiator(core, rt, world):
    """Review F1: the initiator rejoined (its own dialog ended); a release the
    SIP core did not start sends the new dialog a BYE."""
    _group_call(core, world, "v1")
    world[U[0]].sent.clear()
    core.on_bytes(invite("vj1", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    ok = [r for r in responses(world[U[0]], 200) if r.headers.get("Call-ID") == "vj1"][-1]
    _ack(core, world, "vj1", U[0], ok)
    world[U[0]].sent.clear()
    rt.release("v1", "pre-empted")
    assert [b.headers.get("Call-ID") for b in world[U[0]].requests("BYE")] == ["vj1"]
    assert "vj1" not in core.calls


def test_a_release_from_outside_reaches_an_initiator_that_left_and_joined_again(
        tmp_path, pki, clock):
    from tests.test_group_initiator_leaves import _initiator_bye, _world
    (tmp_path / "w").mkdir()
    rt, core, flows = _world(tmp_path / "w", pki, clock, "continue")
    try:
        _group_call(core, flows, "v2")
        _initiator_bye(core, flows, "v2")
        (_, ok) = _join(core, flows, "vj2", U[0])
        _ack(core, flows, "vj2", U[0], ok)
        flows[U[0]].sent.clear()
        rt.release("v2", "pre-empted")
        assert [b.headers.get("Call-ID") for b in flows[U[0]].requests("BYE")] == ["vj2"]
    finally:
        core.close()
        rt.close()


def test_a_rejoined_initiator_s_lapsed_registration_releases_the_call(core, rt, world, clock):
    """Review F2: SIP-OP-21 follows the initiator into its new dialog: its
    refresh there after its registration expired is refused 404/141 and the
    whole call is released (cause registration-expired), whatever the
    setting."""
    _group_call(core, world, "v3")
    register(core, U[0], world[U[0]], n=8, expires=60)
    world[U[0]].sent.clear()
    core.on_bytes(invite("vj3", U[0], "grp:alpha", "prearranged-group", extra=list(TIMER)),
                  world[U[0]])
    ok = [r for r in responses(world[U[0]], 200) if r.headers.get("Call-ID") == "vj3"][-1]
    _ack(core, world, "vj3", U[0], ok)
    clock.now += 61_000
    core.tick()
    core.on_bytes(msg("UPDATE", LOCAL, "vj3", 3, U[0], LOCAL, to_tag=_tag("vj3"),
                      extra=list(TIMER)), world[U[0]])
    assert [r.code for r in responses(world[U[0]], method="UPDATE")] == [404]
    assert _released_as(rt, "v3") == [("session-released", "registration-expired")]
    for u in U[1:]:
        assert len(world[u].requests("BYE")) == 1, u


def test_under_continue_a_rejoined_initiator_leaves_as_the_initiator(tmp_path, pki, clock):
    """Review F2: with MCX_GROUP_INITIATOR_LEAVES=continue its hanging up in
    the new dialog is the initiator's leaving, recorded so."""
    from tests.test_group_initiator_leaves import _world
    (tmp_path / "w").mkdir()
    rt, core, flows = _world(tmp_path / "w", pki, clock, "continue")
    try:
        _group_call(core, flows, "v4")
        core.on_bytes(invite("vj4", U[0], "grp:alpha", "prearranged-group"), flows[U[0]])
        ok = [r for r in responses(flows[U[0]], 200) if r.headers.get("Call-ID") == "vj4"][-1]
        _ack(core, flows, "vj4", U[0], ok)
        _joined_bye(core, flows, "vj4", U[0])
        assert rt.manager.session("v4").state is SessionState.ESTABLISHED
        assert _records(rt, "v4", "participant-left")[-1] == {
            "participant": U[0], "role": "initiator", "cause": "normal", "remaining": 3}
        assert not core._still_in(core.calls["v4"], U[0])
    finally:
        core.close()
        rt.close()


def test_a_rejoined_holder_s_call_is_released_when_its_alias_is_taken_over(tmp_path, pki):
    """Review F2: the displaced-holder release (FA-OP-01 item 4) finds the
    holder in the call through its new dialog."""
    from tests.test_functional_alias import ENG, _start, publish, utility_env
    rt, core = _start(utility_env(tmp_path, pki, take_over=[ENG[1]],
                                  MCX_DISPLACED_HOLDER_CALLS="release"))
    try:
        f0 = Flow(ENG[0])
        legs = {u: Flow(u) for u in ENG[1:] + [f"sip:x{i}@utility.example" for i in range(5)]}
        for u, f in legs.items():
            core.on_bytes(msg("REGISTER", "sip:utility.example", f"r-{u}", 1, u, u,
                              extra=[f"Contact: <{u}>"]), f)
        core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="a"), f0)
        core.on_bytes(msg("REGISTER", "sip:utility.example", "r-e0", 1, ENG[0], ENG[0],
                          extra=[f"Contact: <{ENG[0]}>"]), f0)
        core.on_bytes(invite("sw1", ENG[0], "grp:sw", "prearranged-group"), f0)
        for u, f in legs.items():
            for req in f.requests("INVITE"):
                core.on_bytes(answer(req, 200, SDP), f)
        core.on_bytes(invite("swj", ENG[0], "grp:sw", "prearranged-group", from_tag="ft9"), f0)
        assert core.calls["sw1"].initiator_via == "swj"
        core.on_bytes(publish(ENG[1], ["control-engineer"], take_over="true", call_id="b"),
                      legs[ENG[1]])
        assert rt.manager.session("sw1").state is SessionState.RELEASED
    finally:
        core.close()
        rt.close()


def test_an_initiator_alone_after_every_invitation_failed_is_released(core, rt, world):
    """Review F3: u0 INVITEs the group again before anyone answered (487 on
    its first INVITE, 200 on the second); then every member refuses: only
    the initiator is left, and the call is released (6.3.8.1 item 2)."""
    core.on_bytes(invite("v5", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    core.on_bytes(invite("vj5", U[0], "grp:alpha", "prearranged-group", from_tag="ft5"),
                  world[U[0]])
    assert [(r.headers.get("Call-ID"), r.code) for r in responses(world[U[0]])
            if r.code >= 200] == [("v5", 487), ("vj5", 200)]
    for u in U[1:]:
        core.on_bytes(answer(world[u].requests("INVITE")[0], 486), world[u])
    assert _released_as(rt, "v5") == [("session-released", "no-participants")]
    assert [b.headers.get("Call-ID") for b in world[U[0]].requests("BYE")] == ["vj5"]


@pytest.mark.parametrize("case", ["codec", "no-media"])
def test_a_join_refused_for_the_media_is_the_joiner_s_last_record(core, rt, world, case):
    """Review F4: every failed INVITE has its own last record (PLT-SIG-005)."""
    legs = _group_call(core, world, "v6")
    _member_bye(core, world, legs, U[3])
    sdp = SDP.replace("RTP/AVP 0", "RTP/AVP 8").replace("rtpmap:0 PCMU", "rtpmap:8 PCMA")
    if case == "no-media":
        core.calls["v6"].media = None
        sdp = SDP
    core.on_bytes(msg("INVITE", LOCAL, "vj6", 1, U[3], LOCAL, ctype=mcf.CONTENT_TYPE,
                      body=mcf.body_for("prearranged-group", "grp:alpha", sdp)), world[U[3]])
    last = rt.store.audit_records("vj6")[-1]
    assert (last["type"], last["detail"]["join_of"], last["detail"]["reason_code"]) == (
        "session-failed", "v6", "")
    assert last["detail"]["detail"] == ("the offer does not carry the call's codec"
                                        if case == "codec" else
                                        "the group call in progress has no media to join")


def test_a_fault_in_one_call_s_late_entry_spares_the_others(tmp_path, pki, clock,
                                                           monkeypatch, caplog):
    """Review F5: two group calls wait for u3; inviting it into the first
    faults; it is still invited into the second, and its REGISTER keeps its
    one 200."""
    from core.session import Platform
    from service.runtime import build_runtime
    from service.sip_core import SipCore
    from tests.network_fixture import network_yaml
    env = sip_env(tmp_path, pki)
    env["MCX_NETWORK_FILE"] = str(network_yaml(
        tmp_path, fname="two.yaml", trusted_cores=["core-client.example"],
        core_ca=pki / "core-ca.crt",
        groups=[{"id": "grp:alpha", "members": list(U)},
                {"id": "grp:beta", "members": list(U)}]))
    rt = build_runtime(env, clock, platform=Platform())
    core = SipCore(rt, LOCAL, clock)
    try:
        flows = {u: Flow(u) for u in U}
        for u in U[:3]:
            register(core, u, flows[u])
        core.on_bytes(invite("v7a", U[0], "grp:alpha", "prearranged-group"), flows[U[0]])
        core.on_bytes(invite("v7b", U[1], "grp:beta", "prearranged-group"), flows[U[1]])
        assert rt.manager.session("v7b") is not None
        real = core._invite_leg

        def faulty(call, sig, late=False):
            if late and call.cid == "v7a":
                raise RuntimeError("leg fault")
            return real(call, sig, late=late)
        monkeypatch.setattr(core, "_invite_leg", faulty)
        register(core, U[3], flows[U[3]])
        codes = [m.code for m in flows[U[3]].messages() if isinstance(m, ReceivedResponse)]
        assert codes == [200]
        (late,) = flows[U[3]].requests("INVITE")
        assert "grp:beta" in late.body
        assert any("session v7a: late entry of" in r.getMessage() for r in caplog.records)
    finally:
        core.close()
        rt.close()


def test_no_late_entry_for_a_member_who_left_the_call(core, rt, world, clock):
    """Owner decision 2026-11-23 (review F6): u1 hung up, its registration
    lapsed and it registers again: it is not invited back; it may INVITE."""
    legs = _group_call(core, world, "v8")
    _member_bye(core, world, legs, U[1])
    register(core, U[1], world[U[1]], n=5, expires=0)
    world[U[1]].sent.clear()
    register(core, U[1], world[U[1]], n=6)
    assert world[U[1]].requests("INVITE") == []
    assert [r.code for r in _join(core, world, "vj8", U[1])] == [100, 200]


def test_no_late_entry_for_an_initiator_that_left(tmp_path, pki, clock):
    from tests.test_group_initiator_leaves import _initiator_bye, _world
    (tmp_path / "w").mkdir()
    rt, core, flows = _world(tmp_path / "w", pki, clock, "continue")
    try:
        _group_call(core, flows, "v9")
        _initiator_bye(core, flows, "v9")
        register(core, U[0], flows[U[0]], n=5, expires=0)
        flows[U[0]].sent.clear()
        register(core, U[0], flows[U[0]], n=6)
        assert flows[U[0]].requests("INVITE") == []
    finally:
        core.close()
        rt.close()


def test_a_join_needs_membership_even_to_a_group_named_by_a_functional_identity(
        core, rt, world):
    """Review F7: step 1a does not check a group the resolver reached through
    a functional identity; the join does (step 15a): a non-member is refused
    403 warning 116, and is not made a member."""
    import dataclasses as dc
    _group_call(core, world, "v10")
    resolver = rt.manager._hooks.identity_resolver

    class Via:
        def __getattr__(self, name):
            return getattr(resolver, name)

        def resolve(self, target, request):
            r = resolver.resolve(target, request)
            return dc.replace(r, resolved_from="control-room") if r.group_id else r
    rt.manager._hooks = dc.replace(rt.manager._hooks, identity_resolver=Via())
    out = "sip:u9@mcptt.example"
    flow = Flow(out)
    register(core, out, flow)
    flow.sent.clear()
    core.on_bytes(invite("vj10", out, "grp:alpha", "prearranged-group"), flow)
    (_, refused) = [m for m in flow.messages() if isinstance(m, ReceivedResponse)]
    assert refused.code == 403 and "116" in refused.headers.get("Warning")
    assert out not in rt.manager.session("v10").members


@pytest.mark.vp("VP1-CC-005")
def test_the_invitations_are_the_member_set_once_each_and_nobody_else(core, rt, world):
    """Review F8: a registered non-member and the initiator are not invited;
    each other member is, exactly once."""
    out = "sip:u9@mcptt.example"
    flow = Flow(out)
    register(core, out, flow)
    flow.sent.clear()
    _group_call(core, world, "v11")
    assert flow.requests() == []
    assert world[U[0]].requests("INVITE") == []
    assert [len(world[u].requests("INVITE")) for u in U[1:]] == [1, 1, 1]


def _initiator_rejoins(core, world, cid, extra=()):
    core.on_bytes(invite(cid, U[0], "grp:alpha", "prearranged-group",
                         extra=list(extra)), world[U[0]])
    ok = [r for r in responses(world[U[0]], 200) if r.headers.get("Call-ID") == cid][-1]
    _ack(core, world, cid, U[0], ok)


def test_an_initiator_that_rejoins_twice_keeps_its_role(core, rt, world):
    _group_call(core, world, "w1")
    _initiator_rejoins(core, world, "wj1a")
    _initiator_rejoins(core, world, "wj1b")
    assert core.calls["w1"].initiator_via == "wj1b" and "wj1a" not in core.calls
    _joined_bye(core, world, "wj1b", U[0])
    assert _released_as(rt, "w1") == [("session-released", "normal")]


def test_with_the_rejoined_initiator_in_the_call_one_member_is_enough(core, rt, world):
    """Review F2: the initiator is a party through its new dialog, so 6.3.8.1
    item 2's "one or no participants" is not reached while it and one member
    remain."""
    legs = _group_call(core, world, "w2")
    _initiator_rejoins(core, world, "wj2")
    _member_bye(core, world, legs, U[1])
    _member_bye(core, world, legs, U[2])
    assert rt.manager.session("w2").state is SessionState.ESTABLISHED
    _member_bye(core, world, legs, U[3])
    assert _released_as(rt, "w2") == [("session-released", "normal")]


def test_under_continue_a_rejoined_initiator_s_lapsed_registration_still_releases(
        tmp_path, pki, clock):
    """SIP-OP-21 over SIP-OP-24, as for the original dialog."""
    from tests.test_group_initiator_leaves import _world
    (tmp_path / "w").mkdir()
    rt, core, flows = _world(tmp_path / "w", pki, clock, "continue")
    try:
        _group_call(core, flows, "w3")
        register(core, U[0], flows[U[0]], n=8, expires=60)
        _initiator_rejoins(core, flows, "wj3", extra=TIMER)
        clock.now += 61_000
        core.tick()
        core.on_bytes(msg("UPDATE", LOCAL, "wj3", 3, U[0], LOCAL, to_tag=_tag("wj3"),
                          extra=list(TIMER)), flows[U[0]])
        assert _released_as(rt, "w3") == [("session-released", "registration-expired")]
    finally:
        core.close()
        rt.close()


def test_a_member_s_refresh_after_the_rejoined_initiator_s_registration_lapsed(
        core, rt, world, clock):
    """SIP-OP-21 decision 2, the initiator in the call by its new dialog: a
    callee's refresh is answered 481 and the call released."""
    legs = _group_call(core, world, "w4")
    register(core, U[0], world[U[0]], n=8, expires=60)
    _initiator_rejoins(core, world, "wj4")
    clock.now += 61_000
    cid = legs[U[1]].headers.get("Call-ID")
    world[U[1]].sent.clear()
    core.on_bytes(msg("UPDATE", LOCAL, cid, 2, U[1], U[0], from_tag="callee",
                      to_tag=f"{cid}-l", extra=list(TIMER)), world[U[1]])
    assert [r.code for r in responses(world[U[1]], method="UPDATE")] == [481]
    assert _released_as(rt, "w4") == [("session-released", "registration-expired")]
    assert [b.headers.get("Call-ID") for b in world[U[0]].requests("BYE")][-1] == "wj4"


def test_the_platform_s_refresh_after_the_rejoined_initiator_s_registration_lapsed(
        core, rt, world, clock):
    """The platform refreshes the members' legs: the first refresh due after
    the rejoined initiator's registration expired is not sent; the call is
    released instead."""
    _group_call(core, world, "w5")
    register(core, U[0], world[U[0]], n=8, expires=60)
    _initiator_rejoins(core, world, "wj5")
    t0 = clock.now
    while rt.manager.session("w5").state is SessionState.ESTABLISHED:
        assert clock.now < t0 + 3_600_000, "never released"
        clock.now += 10_000
        core.tick()
    assert _released_as(rt, "w5") == [("session-released", "registration-expired")]
    assert all(len(world[u].requests("INVITE")) == 1 for u in U[1:])


# -- re-review of CC-OP-01 ---------------------------------------------------------------

@pytest.mark.parametrize("order", ["crossing", "make-before-break"])
def test_the_old_leg_s_bye_after_a_rejoin_leaves_the_new_dialog_alone(core, rt, world,
                                                                      order):
    """Re-review G1: u1 rejoins; the BYE of its old leg -- crossing the
    platform's, or sent by a client that makes the new dialog before breaking
    the old -- is answered 200 and is no departure: the new dialog keeps the
    relay endpoint, nothing is recorded as having left, late entry still
    counts u1 as in the call."""
    legs = _group_call(core, world, "y1")
    ep = core.calls["y1"].media.endpoints[U[1]]
    _join(core, world, "yj1", U[1])
    _member_bye(core, world, legs, U[1])
    assert [r.code for r in responses(world[U[1]], method="BYE")][-1] == 200
    assert core.calls["y1"].media.endpoints.get(U[1]) is ep
    assert _records(rt, "y1", "participant-left") == []
    assert "yj1" in core.calls and canonical_uri(U[1]) not in core.calls["y1"].departed
    assert rt.manager.session("y1").state is SessionState.ESTABLISHED


def test_a_bye_on_a_leg_the_platform_hung_up_ends_nothing(core, rt, world):
    """The same for a leg the platform ended (its answer unusable): the
    member's late BYE does not end the call."""
    core.on_bytes(invite("y2", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    bad = SDP.replace("RTP/AVP 0", "RTP/AVP 8").replace("rtpmap:0 PCMU", "rtpmap:8 PCMA")
    reqs = {u: world[u].requests("INVITE")[0] for u in U[1:]}
    core.on_bytes(answer(reqs[U[1]], 200, SDP), world[U[1]])
    core.on_bytes(answer(reqs[U[2]], 200, bad), world[U[2]])
    _member_bye(core, world, reqs, U[2])
    assert rt.manager.session("y2").state is SessionState.ESTABLISHED
    assert _records(rt, "y2", "participant-left") == []


def test_a_joined_member_s_refresh_after_the_caller_s_registration_lapsed(
        core, rt, world, clock):
    """Re-review G2, SIP-OP-21 decision 2 ("whoever sends it"): u0 is in its
    own dialog and its registration lapses; u3, joined, refreshes: 481 (its
    dialog ends, no BYE to it) and the call is released."""
    legs = _group_call(core, world, "y3")
    _member_bye(core, world, legs, U[3])
    register(core, U[0], world[U[0]], n=8, expires=60)
    (_, ok) = _join(core, world, "yj3", U[3], extra=list(TIMER))
    _ack(core, world, "yj3", U[3], ok)
    clock.now += 61_000
    world[U[3]].sent.clear()
    core.on_bytes(msg("UPDATE", LOCAL, "yj3", 3, U[3], LOCAL, to_tag=_tag("yj3"),
                      extra=list(TIMER)), world[U[3]])
    assert [r.code for r in responses(world[U[3]], method="UPDATE")] == [481]
    assert world[U[3]].requests("BYE") == []
    assert _released_as(rt, "y3") == [("session-released", "registration-expired")]
    assert "yj3" not in core.calls


def test_the_platform_s_refresh_of_a_joined_dialog_after_the_caller_s_lapse(
        core, rt, world, clock):
    """The platform refreshes the joined dialog (its joiner runs no timer):
    that refresh, due after u0's registration expired, is not sent; the call
    is released."""
    legs = _group_call(core, world, "y4", callee_extra=[
        "Session-Expires: 86400;refresher=uas", "Require: timer"])
    _member_bye(core, world, legs, U[3])
    register(core, U[0], world[U[0]], n=8, expires=60)
    (_, ok) = _join(core, world, "yj4", U[3])
    _ack(core, world, "yj4", U[3], ok)
    assert core.calls["yj4"].timer is not None
    t0 = clock.now
    world[U[3]].sent.clear()
    while rt.manager.session("y4").state is SessionState.ESTABLISHED:
        assert clock.now < t0 + 3_600_000, "never released"
        clock.now += 10_000
        core.tick()
    assert _released_as(rt, "y4") == [("session-released", "registration-expired")]
    assert [r.method for r in world[U[3]].requests()] == ["BYE"]


def test_an_initiator_that_left_and_comes_back_is_a_member(tmp_path, pki, clock):
    """Owner decision 2026-11-23: under continue the initiator gave up its role
    when it left; INVITEing the group again is a join like anyone's -- its
    leaving afterwards is a member's, and the call goes on."""
    from tests.test_group_initiator_leaves import _initiator_bye, _world
    (tmp_path / "w").mkdir()
    rt, core, flows = _world(tmp_path / "w", pki, clock, "continue")
    try:
        _group_call(core, flows, "y5")
        _initiator_bye(core, flows, "y5")
        (_, ok) = _join(core, flows, "yj5", U[0])
        _ack(core, flows, "yj5", U[0], ok)
        assert core.calls["y5"].initiator_via is None
        assert _records(rt, "y5", "participant-joined")[-1]["how"] == "invite"
        _joined_bye(core, flows, "yj5", U[0])
        assert rt.manager.session("y5").state is SessionState.ESTABLISHED
        assert _records(rt, "y5", "participant-left")[-1]["role"] == "member"
    finally:
        core.close()
        rt.close()
