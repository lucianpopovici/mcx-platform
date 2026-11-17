"""SIP-OP-24 (owner decision 2026-11-17): MCX_GROUP_INITIATOR_LEAVES.

TS 24.379 6.3.8.1 item 3: "the call is a pre-arranged group call [or, from
Rel-18, an adhoc group call] and if it is according to local policy, the
initiator of the group call leaves the MCPTT session" -- the controlling
function releases the session. The deployment states that policy:
"release" (the call ends for everyone) or "continue" (the initiator goes,
the call is the members' while two or more remain: item 2 releases it when
"there are only one or no participants"). A private call ends when its
initiator leaves whatever this says (6.3.8.2 item 3), and an initiator whose
registration expires releases its call, group or private (SIP-OP-21)."""

from __future__ import annotations

import pytest

from core.session import Platform
from service.config import GROUP_INITIATOR_LEAVES_VALUES, Config
from service.runtime import StartupRefused, build_runtime
from service.sip_core import SipCore, _tag
from tests.test_session_timer import (  # noqa: F401  (fixtures)
    TIMER, _group_call, _registered_for, _released_as, call, contact_uri, from_initiator,
    responses)
from tests.test_sip_transport import (  # noqa: F401  (fixtures)
    LOCAL, SDP, U, Clock, Flow, answer, clock, invite, msg, pki, register, sip_env)


def _world(tmp_path, pki, clock, policy):
    rt = build_runtime(sip_env(tmp_path, pki, MCX_GROUP_INITIATOR_LEAVES=policy), clock,
                       platform=Platform())
    core = SipCore(rt, LOCAL, clock)
    flows = {u: Flow(u) for u in U}
    for u in U:
        register(core, u, flows[u])
        flows[u].sent.clear()
    return rt, core, flows


@pytest.fixture(params=["release", "continue"])
def policy(request):
    return request.param


@pytest.fixture
def world_of(tmp_path, pki, clock):
    made = []

    def build(policy):
        (tmp_path / policy).mkdir()
        made.append(_world(tmp_path / policy, pki, clock, policy))
        return made[-1]
    yield build
    for rt, core, _ in made:
        core.close()
        rt.close()


def _initiator_bye(core, flows, cid, cseq=2):
    core.on_bytes(msg("BYE", LOCAL, cid, cseq, U[0], LOCAL, to_tag=_tag(cid)), flows[U[0]])


def _member_bye(core, flows, legs, u, cseq=2):
    """A member hangs up its leg: its tag ("callee", as answer() gives it) in
    From, the platform's in To."""
    cid = legs[u].headers.get("Call-ID")
    core.on_bytes(msg("BYE", LOCAL, cid, cseq, u, U[0], from_tag="callee",
                      to_tag=f"{cid}-l"), flows[u])


# -- the setting --------------------------------------------------------------

def test_the_choices_are_pinned():
    assert GROUP_INITIATOR_LEAVES_VALUES == ("release", "continue")


def test_it_is_required_with_no_default(tmp_path, pki):
    env = sip_env(tmp_path, pki)
    env.pop("MCX_GROUP_INITIATOR_LEAVES")
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(env)
    assert str(exc.value) == (
        "MCX_GROUP_INITIATOR_LEAVES is not set: state whether a group call is released "
        "when its initiator leaves it (TS 24.379 6.3.8.1 item 3, a local policy; "
        "PLT-VP-R1 SIP-OP-24) ('release' or 'continue'); there is no default")
    with pytest.raises(StartupRefused) as exc:
        Config.from_env({**env, "MCX_GROUP_INITIATOR_LEAVES": "sometimes"})
    assert "must be 'release' or 'continue'" in str(exc.value)


def test_the_value_is_reported(world_of, policy):
    rt, _, _ = world_of(policy)
    assert rt.health.snapshot()["settings"]["MCX_GROUP_INITIATOR_LEAVES"] == policy


# -- release ------------------------------------------------------------------

def test_release_the_initiators_bye_ends_the_group_call_for_everyone(world_of):
    rt, core, flows = world_of("release")
    _group_call(core, flows, "gl1")
    _initiator_bye(core, flows, "gl1")
    assert rt.manager.session("gl1").state.value == "released"
    assert _released_as(rt, "gl1") == [("session-released", "normal")]
    for u in U[1:]:
        assert len(flows[u].requests("BYE")) == 1, u
    assert flows[U[0]].requests("BYE") == []


# -- continue -----------------------------------------------------------------

def test_continue_the_initiator_leaves_and_the_members_call_goes_on(world_of):
    """Three members: the initiator's BYE is answered 200 and only it goes --
    no BYE to any member, the session established, the initiator's relay
    endpoint closed and its dialog gone (a second BYE is 481), the floor told
    it left (it held the floor, by the implicit request, so the floor moves
    on)."""
    rt, core, flows = world_of("continue")
    _group_call(core, flows, "gl2")
    media = core.calls["gl2"].media
    assert media.floor.holder == U[0] and U[0] in media.endpoints
    _initiator_bye(core, flows, "gl2")
    assert [m.code for m in flows[U[0]].messages()
            if getattr(m, "code", 0) and m.headers.get("CSeq") == "2 BYE"] == [200]
    assert rt.manager.session("gl2").state.value == "established"
    assert all(flows[u].requests("BYE") == [] for u in U[1:])
    assert U[0] not in media.endpoints and media.floor.holder != U[0]
    assert U[0] not in media.floor.queue
    left = [t for t in media.floor.history if t.event.type.value == "participant-left"]
    assert [t.event.participant for t in left] == [U[0]]
    _initiator_bye(core, flows, "gl2", cseq=3)
    assert [m.code for m in flows[U[0]].messages()
            if getattr(m, "code", 0) and m.headers.get("CSeq") == "3 BYE"] == [481]


def test_continue_the_call_ends_when_one_member_remains(world_of):
    """6.3.8.1 item 2 once the initiator has gone: u1 leaves (two remain, the
    call goes on), u2 leaves (one remains): released, BYE to u3, none to the
    initiator who already left."""
    rt, core, flows = world_of("continue")
    legs = _group_call(core, flows, "gl3")
    _initiator_bye(core, flows, "gl3")
    _member_bye(core, flows, legs, U[1])
    assert rt.manager.session("gl3").state.value == "established"
    assert U[1] not in core.calls["gl3"].media.endpoints
    _member_bye(core, flows, legs, U[2])
    assert rt.manager.session("gl3").state.value == "released"
    assert _released_as(rt, "gl3") == [("session-released", "normal")]
    assert len(flows[U[3]].requests("BYE")) == 1
    assert flows[U[0]].requests("BYE") == []
    assert flows[U[1]].requests("BYE") == [] and flows[U[2]].requests("BYE") == []


def test_continue_with_one_member_the_initiators_leaving_ends_the_call(world_of):
    """Two members leave first; with one left, the initiator's BYE releases
    the call (item 2 holds as soon as it would be one participant)."""
    rt, core, flows = world_of("continue")
    legs = _group_call(core, flows, "gl4")
    _member_bye(core, flows, legs, U[1])
    _member_bye(core, flows, legs, U[2])
    assert rt.manager.session("gl4").state.value == "established"
    _initiator_bye(core, flows, "gl4")
    assert rt.manager.session("gl4").state.value == "released"
    assert len(flows[U[3]].requests("BYE")) == 1


def test_continue_a_private_call_still_ends_when_its_initiator_leaves(world_of):
    rt, core, flows = world_of("continue")
    call(core, flows, "gl5")
    _initiator_bye(core, flows, "gl5")
    assert rt.manager.session("gl5").state.value == "released"
    assert len(flows[U[1]].requests("BYE")) == 1


def test_continue_an_initiator_whose_session_expires_is_sent_a_bye_and_goes(world_of,
                                                                           clock):
    """Its dialog's session expired (it never refreshed): RFC 4028 section 10
    sends it a BYE; under continue the members' call goes on."""
    rt, core, flows = world_of("continue")
    _group_call(core, flows, "gl6", callee_extra=["Supported: timer"])
    start, answered = clock.now, set()
    while not flows[U[0]].requests("BYE"):
        assert clock.now < start + 3_600_000, "no BYE to the initiator"
        clock.now += 10_000
        for u in U[1:]:                  # the members answer the platform's refreshes
            for r in flows[u].requests("UPDATE") + flows[u].requests("INVITE")[1:]:
                key = (u, r.headers.get("CSeq"))
                if key not in answered:
                    answered.add(key)
                    core.on_bytes(answer(r, 200, SDP if r.method == "INVITE" else "",
                                         extra=["Session-Expires: 1800;refresher=uas"]),
                                  flows[u])
        core.tick()
    assert rt.manager.session("gl6").state.value == "established"
    assert all(flows[u].requests("BYE") == [] for u in U[1:])


def test_continue_an_initiator_whose_registration_expires_releases_the_call(world_of,
                                                                           clock):
    """SIP-OP-21 wins: an expired registration is not a leaving. At the call's
    next refresh it is released for everyone, cause registration-expired."""
    rt, core, flows = world_of("continue")
    t0 = clock.now
    _registered_for(core, flows, 60)
    _group_call(core, flows, "gl7")
    clock.now = t0 + 60_000
    core.on_bytes(from_initiator("UPDATE", "gl7", 2, extra=TIMER), flows[U[0]])
    assert rt.manager.session("gl7").state.value == "released"
    assert _released_as(rt, "gl7") == [("session-released", "registration-expired")]
    for u in U[1:]:
        assert len(flows[u].requests("BYE")) == 1, u


def test_continue_once_the_initiator_left_its_registration_no_longer_bears(world_of,
                                                                          clock):
    """After the initiator left, the call is the members'; its registration
    running out later releases nothing: a member's refresh is answered and
    the platform's own refreshes of the members' legs go on."""
    rt, core, flows = world_of("continue")
    t0 = clock.now
    _registered_for(core, flows, 60)
    legs = _group_call(core, flows, "gl8")
    _initiator_bye(core, flows, "gl8")
    clock.now = t0 + 120_000
    cid = legs[U[1]].headers.get("Call-ID")
    core.on_bytes(msg("UPDATE", LOCAL, cid, 2, U[1], U[0], from_tag="callee",
                      to_tag=f"{cid}-l"), flows[U[1]])
    assert [r.code for r in responses(flows[U[1]], method="UPDATE")] == [200]
    answered = set()
    for _ in range(100):
        clock.now += 10_000
        for u in U[1:]:                  # each refresh the platform sends is answered once
            for r in flows[u].requests("UPDATE") + flows[u].requests("INVITE")[1:]:
                key = (u, r.headers.get("CSeq"))
                if key not in answered:
                    answered.add(key)
                    core.on_bytes(answer(r, 200, SDP if r.method == "INVITE" else "",
                                         extra=["Session-Expires: 1800;refresher=uas"]),
                                  flows[u])
        core.tick()
    assert answered                      # the platform did refresh the members' legs
    assert rt.manager.session("gl8").state.value == "established"
    assert _released_as(rt, "gl8") == []


def test_which_call_types_are_group_calls():
    """The policy is for group calls only: prearranged and ad hoc, by the
    call type's MCPTT signature; private calls and call types without a
    signature (SDS, data) are not. Pinned over every shipped profile."""
    import types
    from pathlib import Path
    from core import loader
    from core.release import Release
    from core.sip import Adapter
    got = {}
    for name in ("mcx", "frmcs", "utility"):
        lp = loader.load(Path(__file__).resolve().parents[1] / "profiles" / name)
        adapter = Adapter("sip:x@example.org", Release.REL_19,
                          call_types=lp.profile.call_types)
        probe = types.SimpleNamespace(adapter=adapter)
        for ct in lp.profile.call_types:
            fake = types.SimpleNamespace(sr=types.SimpleNamespace(call_type=ct.id))
            got[(name, ct.id)] = SipCore._is_group_call(probe, fake)
    assert {k for k, v in got.items() if v} == {
        ("mcx", "prearranged-group"), ("mcx", "emergency-group"),
        ("mcx", "imminent-peril-group"), ("mcx", "coordination-group"),
        ("frmcs", "rec-broadcast"), ("frmcs", "shunting-group"),
        ("utility", "crew-call"), ("utility", "switching-order")}
    assert not got[("mcx", "private")] and not got[("frmcs", "driver-controller")]


# -- review of SIP-OP-24 ------------------------------------------------------

class _Recorded:
    """An endpoint's I/O, keeping what is sent on the floor channel."""

    def __init__(self, io):
        self.io, self.floor = io, []

    def __getattr__(self, name):
        return getattr(self.io, name)

    def send_floor(self, addr, data):
        self.floor.append(data)

    def send_rtp(self, addr, data):
        pass


def _floor_wired(media):
    """Give every endpoint a floor address (the test SDP has no floor m-line)
    and record what the relay sends each."""
    recs = {}
    for u, ep in media.endpoints.items():
        ep.remote_floor = ("192.0.2.9", 6000)
        ep.remote_rtp = ep.remote_rtp or ("192.0.2.9", 6002)
        recs[u] = ep.io = _Recorded(ep.io)
    return recs


def _told(media, rec):
    return [media.codec.decode(d).type.name for d in rec.floor]


def _faults(caplog):
    return [r.getMessage() for r in caplog.records if r.levelname in ("ERROR", "CRITICAL")]


def test_continue_the_members_are_told_the_floor_is_idle(world_of):
    """The initiator held the floor (implicit request): when it leaves every
    member is sent Floor Idle, and nothing goes to the leaver."""
    rt, core, flows = world_of("continue")
    _group_call(core, flows, "gr1")
    media = core.calls["gr1"].media
    recs = _floor_wired(media)
    _initiator_bye(core, flows, "gr1")
    assert {u: _told(media, recs[u]) for u in U[1:]} == {u: ["IDLE"] for u in U[1:]}
    assert recs[U[0]].floor == []


def test_continue_the_queued_member_is_granted_the_others_told_taken(world_of):
    from core import rtcp
    rt, core, flows = world_of("continue")
    _group_call(core, flows, "gr2")
    media = core.calls["gr2"].media
    recs = _floor_wired(media)
    media.on_floor(U[1], ("192.0.2.9", 6000),
                   media.codec.encode(rtcp.message(rtcp.MsgType.REQUEST, 99)))
    assert media.floor.queue == (U[1],)
    for r in recs.values():
        r.floor.clear()
    _initiator_bye(core, flows, "gr2")
    assert media.floor.holder == U[1]
    assert _told(media, recs[U[1]]) == ["GRANTED"]
    assert _told(media, recs[U[2]]) == ["TAKEN"] and _told(media, recs[U[3]]) == ["TAKEN"]
    assert recs[U[0]].floor == []


def test_continue_with_exactly_two_members_the_call_goes_on(world_of):
    """The boundary of item 2: two members remain, so two participants; only
    a leaving that would leave one releases."""
    rt, core, flows = world_of("continue")
    legs = _group_call(core, flows, "gr3")
    _member_bye(core, flows, legs, U[3])
    _initiator_bye(core, flows, "gr3")
    assert rt.manager.session("gr3").state.value == "established"
    assert flows[U[1]].requests("BYE") == [] and flows[U[2]].requests("BYE") == []


def test_release_a_member_who_leaves_goes_from_the_media_and_the_floor(world_of):
    """In either setting a member who hangs up while the call goes on leaves
    the relay and the floor (it is no longer sent anything, nor queued)."""
    from core import rtcp
    rt, core, flows = world_of("release")
    legs = _group_call(core, flows, "gr4")
    media = core.calls["gr4"].media
    media.on_floor(U[2], ("192.0.2.9", 6000),
                   media.codec.encode(rtcp.message(rtcp.MsgType.REQUEST, 7)))
    _member_bye(core, flows, legs, U[2])
    assert U[2] not in media.endpoints and U[2] not in media.floor.queue
    assert rt.manager.session("gr4").state.value == "established"


def test_continue_an_initiator_that_leaves_before_its_ack_does_not_end_the_call(
        world_of, clock):
    """It may BYE before ACKing the 2xx: its dialog is over, and the missing
    ACK (Timer H) does not end the members' call."""
    rt, core, flows = world_of("continue")
    core.on_bytes(invite("gr5", U[0], "grp:alpha", "prearranged-group", extra=list(TIMER)),
                  flows[U[0]])
    for u in U[1:]:
        (req,) = flows[u].requests("INVITE")
        core.on_bytes(answer(req, 200, SDP), flows[u])
    _initiator_bye(core, flows, "gr5")
    for _ in range(80):
        clock.now += 1000
        core.tick()
    assert rt.manager.session("gr5").state.value == "established"
    assert _released_as(rt, "gr5") == []


def test_continue_an_initiator_whose_session_expires_after_its_registration_releases(
        world_of, clock):
    """Review of SIP-OP-24, F1: registered for 60 s, its session 120 s, never
    refreshed. Its dialog expires after its registration did: that expiry is
    the refresh it would have sent, so SIP-OP-21 releases the call for
    everyone, whatever the setting."""
    rt, core, flows = world_of("continue")
    t0 = clock.now
    _registered_for(core, flows, 60)
    core.on_bytes(invite("gr6", U[0], "grp:alpha", "prearranged-group",
                         extra=["Supported: timer", "Session-Expires: 120;refresher=uac"]),
                  flows[U[0]])
    for u in U[1:]:
        (req,) = flows[u].requests("INVITE")
        core.on_bytes(answer(req, 200, SDP, extra=["Session-Expires: 1800;refresher=uas",
                                                   "Require: timer"]), flows[u])
    ok = responses(flows[U[0]], 200)[-1]
    core.on_bytes(msg("ACK", contact_uri(ok.headers.get("Contact")), "gr6", 1, U[0], LOCAL,
                      branch="z9hG4bKackgr6", to_tag=_tag("gr6")), flows[U[0]])
    while rt.manager.session("gr6").state.value == "established":
        assert clock.now < t0 + 600_000, "never released"
        clock.now += 1000
        core.tick()
    assert _released_as(rt, "gr6") == [("session-released", "registration-expired")]
    assert len(flows[U[0]].requests("BYE")) == 1
    for u in U[1:]:
        assert len(flows[u].requests("BYE")) == 1, u


def test_continue_requests_from_the_departed_initiator_are_481(world_of):
    rt, core, flows = world_of("continue")
    _group_call(core, flows, "gr7")
    _initiator_bye(core, flows, "gr7")
    core.on_bytes(from_initiator("UPDATE", "gr7", 3, extra=TIMER), flows[U[0]])
    core.on_bytes(from_initiator("INVITE", "gr7", 4, extra=TIMER), flows[U[0]])
    codes = [(m.headers.get("CSeq"), m.code) for m in flows[U[0]].messages()
             if getattr(m, "code", 0)]
    assert ("3 UPDATE", 481) in codes and ("4 INVITE", 481) in codes
    assert rt.manager.session("gr7").state.value == "established"


def test_continue_a_member_answering_after_the_initiator_left_joins_cleanly(world_of,
                                                                            caplog):
    """Review of SIP-OP-24, F3: no fault reading the departed initiator's
    relay endpoint; the late member joins the media."""
    rt, core, flows = world_of("continue")
    core.on_bytes(invite("gr8", U[0], "grp:alpha", "prearranged-group", extra=list(TIMER)),
                  flows[U[0]])
    reqs = {u: flows[u].requests("INVITE")[0] for u in U[1:]}
    for u in U[1:3]:
        core.on_bytes(answer(reqs[u], 200, SDP), flows[u])
    ok = responses(flows[U[0]], 200)[-1]
    core.on_bytes(msg("ACK", contact_uri(ok.headers.get("Contact")), "gr8", 1, U[0], LOCAL,
                      branch="z9hG4bKackgr8", to_tag=_tag("gr8")), flows[U[0]])
    _initiator_bye(core, flows, "gr8")
    caplog.clear()
    core.on_bytes(answer(reqs[U[3]], 200, SDP), flows[U[3]])
    assert _faults(caplog) == []
    media = core.calls["gr8"].media
    assert U[3] in media.endpoints and U[0] not in media.endpoints


def test_a_refresh_answered_after_its_member_left_is_dropped_cleanly(world_of, clock,
                                                                    caplog):
    """Review of SIP-OP-24, F3: a member hangs up while the platform's refresh
    of its leg is outstanding, then answers it: no fault."""
    rt, core, flows = world_of("release")
    legs = _group_call(core, flows, "gr9")
    while not flows[U[1]].requests("INVITE")[1:]:
        clock.now += 10_000
        core.tick()
    (refresh,) = flows[U[1]].requests("INVITE")[1:]
    _member_bye(core, flows, legs, U[1], cseq=2)
    caplog.clear()
    core.on_bytes(answer(refresh, 200, SDP), flows[U[1]])
    assert _faults(caplog) == []
    assert rt.manager.session("gr9").state.value == "established"


def test_an_unrecordable_departure_ends_only_that_member(world_of, clock):
    """Review of SIP-OP-24, F4: the floor record of a member's departure
    fails (audit store down, MCX_FLOOR_UNRECORDED=deny): the departure
    stands -- it is a fact -- and the rest of the call goes on."""
    rt, core, flows = world_of("release")
    _group_call(core, flows, "gr10")
    call_ = core.calls["gr10"]
    leg = next(l for l in call_.legs.values() if l.uri == U[1])
    leg.timer.expires_at = clock.now + 1

    def store_down(transition):
        raise OSError("audit store down")
    call_.media.floor._observer = store_down
    clock.now += 5
    core.tick()
    assert rt.manager.session("gr10").state.value == "established"
    assert U[1] not in call_.media.endpoints
    assert len(flows[U[1]].requests("BYE")) == 1
    assert flows[U[2]].requests("BYE") == [] and flows[U[3]].requests("BYE") == []


def test_continue_nothing_more_goes_to_the_departed_initiator(world_of, clock, caplog):
    """It ran no timer, so the platform refreshed its dialog: after it left,
    no refresh is sent to it, nothing faults, and the members' call stays."""
    rt, core, flows = world_of("continue")
    core.on_bytes(invite("gr11", U[0], "grp:alpha", "prearranged-group"), flows[U[0]])
    for u in U[1:]:
        (req,) = flows[u].requests("INVITE")
        core.on_bytes(answer(req, 200, SDP, extra=["Session-Expires: 86400;refresher=uas",
                                                   "Require: timer"]), flows[u])
    ok = responses(flows[U[0]], 200)[-1]
    core.on_bytes(msg("ACK", contact_uri(ok.headers.get("Contact")), "gr11", 1, U[0], LOCAL,
                      branch="z9hG4bKackgr11", to_tag=_tag("gr11")), flows[U[0]])
    assert core.calls["gr11"].timer is not None
    _initiator_bye(core, flows, "gr11")
    flows[U[0]].sent.clear()
    caplog.clear()
    for _ in range(200):
        clock.now += 30_000
        core.tick()
    assert flows[U[0]].requests() == []
    assert _faults(caplog) == [] and not [r for r in caplog.records
                                          if "session timer" in r.getMessage()]
    assert rt.manager.session("gr11").state.value == "established"


# -- the participant-left record (owner decision 2026-11-17) --------------------

def _left(rt, cid):
    return [r["detail"] for r in rt.store.audit_records(cid) if r["type"] == "participant-left"]


def test_the_record_type_is_pinned():
    from core.audit import RecordType
    assert RecordType.PARTICIPANT_LEFT.value == "participant-left"


def test_the_initiator_leaving_a_call_that_goes_on_is_recorded(world_of):
    rt, core, flows = world_of("continue")
    _group_call(core, flows, "pl1")
    _initiator_bye(core, flows, "pl1")
    assert _left(rt, "pl1") == [{"participant": U[0], "role": "initiator",
                                 "cause": "normal", "remaining": 3}]


def test_a_member_leaving_a_call_that_goes_on_is_recorded(world_of):
    rt, core, flows = world_of("release")
    legs = _group_call(core, flows, "pl2")
    _member_bye(core, flows, legs, U[2])
    assert _left(rt, "pl2") == [{"participant": U[2], "role": "member",
                                 "cause": "normal", "remaining": 2}]
    types = [r["type"] for r in rt.store.audit_records("pl2")]
    assert types.index("participant-left") > types.index("session-established")


def test_a_member_whose_session_expired_is_recorded_with_that_cause(world_of, clock):
    rt, core, flows = world_of("release")
    _group_call(core, flows, "pl3")
    leg = next(l for l in core.calls["pl3"].legs.values() if l.uri == U[1])
    leg.timer.expires_at = clock.now + 1
    clock.now += 5
    core.tick()
    assert _left(rt, "pl3") == [{"participant": U[1], "role": "member",
                                 "cause": "session-expired", "remaining": 2}]


def test_a_departure_that_ends_the_call_is_told_by_its_release_only(world_of):
    rt, core, flows = world_of("release")
    _group_call(core, flows, "pl4")
    _initiator_bye(core, flows, "pl4")
    assert _left(rt, "pl4") == []
    assert _released_as(rt, "pl4") == [("session-released", "normal")]


def test_after_the_initiator_left_the_members_departures_are_recorded_then_the_release(
        world_of):
    rt, core, flows = world_of("continue")
    legs = _group_call(core, flows, "pl5")
    _initiator_bye(core, flows, "pl5")
    _member_bye(core, flows, legs, U[1])
    _member_bye(core, flows, legs, U[2])      # one left: released (item 2)
    assert [(d["participant"], d["remaining"]) for d in _left(rt, "pl5")] == \
        [(U[0], 3), (U[1], 2)]
    assert _released_as(rt, "pl5") == [("session-released", "normal")]


def test_an_unwritable_departure_record_does_not_hold_the_departure(world_of, caplog):
    rt, core, flows = world_of("continue")
    _group_call(core, flows, "pl6")

    def store_down(*a, **k):
        raise OSError("audit store down")
    rt.manager._auditor.emit = store_down
    _initiator_bye(core, flows, "pl6")
    assert core.calls["pl6"].initiator_left
    assert rt.manager.session("pl6").state.value == "established"
    assert any("participant-left record lost" in r.getMessage() for r in caplog.records)


def test_the_manager_refuses_an_unknown_role_and_ignores_a_session_not_established(
        world_of):
    rt, core, flows = world_of("release")
    _group_call(core, flows, "pl7")
    with pytest.raises(ValueError):
        rt.manager.participant_left("pl7", U[1], "caller", "normal", 2)
    rt.manager.participant_left("nope", U[1], "member", "normal", 2)
    assert rt.store.audit_records("nope") == []
    _initiator_bye(core, flows, "pl7")                  # release: ended
    rt.manager.participant_left("pl7", U[1], "member", "normal", 2)
    assert _left(rt, "pl7") == []


def test_still_in_follows_each_member_s_leg(world_of):
    """Review of SIP-OP-24 (re-review): the member half of `_still_in`, which
    the displaced-holder release reads -- a member who hung up is no longer a
    party; one still in is, whatever the case of its host (the user part is
    case-sensitive, RFC 3261 19.1.4)."""
    rt, core, flows = world_of("release")
    legs = _group_call(core, flows, "pl8")
    call_ = core.calls["pl8"]
    _member_bye(core, flows, legs, U[2])
    assert core._still_in(call_, U[1]) and core._still_in(call_, "sip:u1@MCPTT.EXAMPLE")
    assert not core._still_in(call_, "sip:U1@mcptt.example")
    assert not core._still_in(call_, U[2])
    assert core._still_in(call_, U[0])
    assert not core._still_in(call_, "sip:nobody@example.org")
