"""TS-CC and TS-HOOK — session establishment, the §8.1 sequence, pre-emption.

ENV-UNIT: no SIP, no media. The session manager emits abstract signals, so the
invocation sequence and its failure modes are testable before a SIP adapter
exists.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.audit import Auditor, MemorySink, RecordType  # noqa: E402
from core.errors import HookContractViolation  # noqa: E402
from core.hooks import (  # noqa: E402
    MediaKind,
    PriorityDecision,
    Resolution,
    ResolutionKind,
    SessionRequest,
)
from core.invoke import DeadlineMode, HookFailure, Invoker  # noqa: E402
from core.session import (  # noqa: E402
    Platform,
    SessionManager,
    SessionState,
    SignalType,
)

PROFILES = ROOT / "profiles"


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


@pytest.fixture
def mcx():
    return loader.load(PROFILES / "mcx")


@pytest.fixture
def sink():
    return MemorySink()


@pytest.fixture
def manager(mcx, sink):
    resolver = mcx.hooks.identity_resolver
    for i in range(6):
        resolver.register_user(f"sip:u{i}@mcptt.example")
    resolver.register_group("grp:alpha", [f"sip:u{i}@mcptt.example"
                                          for i in range(4)])
    resolver.register_group("grp:pair", ["sip:u0@mcptt.example",
                                         "sip:u1@mcptt.example"])
    auditor = Auditor(sink, mcx.profile.identifier(), clock=Clock())
    return SessionManager(mcx, auditor, clock=Clock())


def req(call_type="prearranged-group", target="grp:alpha", rid="s1",
        initiator="sip:u0@mcptt.example", media=(MediaKind.VOICE,), **kw):
    return SessionRequest(request_id=rid, initiator=initiator, target=target,
                          call_type=call_type, media=media, **kw)


def types(signals):
    return [s.type for s in signals]


# --------------------------------------------------------------------------
# VP1-CC-005 — group call establishment
# --------------------------------------------------------------------------


def test_vp1_cc_005_group_call_invites_exactly_the_member_set(manager):
    session, signals, refusal = manager.establish(req())
    assert refusal is None and session is not None
    assert session.state is SessionState.ESTABLISHED
    invited = {s.target for s in signals if s.type is SignalType.INVITE}
    # Four members, initiator not invited to its own session.
    assert invited == {f"sip:u{i}@mcptt.example" for i in (1, 2, 3)}
    assert len(invited) == 3


def test_vp1_cc_003_private_call_establishes(manager):
    session, signals, refusal = manager.establish(
        req(call_type="private", target="sip:u1@mcptt.example"))
    assert refusal is None
    assert session.resolution.kind is ResolutionKind.USER
    assert [s.target for s in signals if s.type is SignalType.INVITE] == \
        ["sip:u1@mcptt.example"]


def test_vp1_cc_006_session_decision_applied_verbatim(manager, mcx):
    session, signals, _ = manager.establish(
        req(call_type="emergency-group", rid="e1"))
    declared = mcx.profile.call_type("emergency-group")
    assert session.decision.auto_answer == declared.auto_answer
    invite = [s for s in signals if s.type is SignalType.INVITE][0]
    assert invite.detail["auto_answer"] is declared.auto_answer
    assert invite.detail["acknowledgement_required"] is \
        declared.acknowledgement_required


def test_vp1_cc_007_one_priority_decision_per_session(manager):
    session, _, _ = manager.establish(req())
    first = session.priority
    manager.establish(req(rid="s2"))
    assert session.priority is first        # unchanged for the session's life


def test_vp1_cc_002_one_controlling_function_per_session(manager):
    a, _, _ = manager.establish(req(rid="a"))
    b, _, _ = manager.establish(req(rid="b"))
    assert a.controlling and b.controlling
    assert a.correlation_id != b.correlation_id
    assert len({s.correlation_id for s in manager.active}) == len(manager.active)


def test_floor_machine_created_for_voice_sessions(manager):
    session, _, _ = manager.establish(req())
    assert session.floor is not None
    assert session.floor.holder == "sip:u0@mcptt.example"


def test_no_floor_machine_for_data_only_sessions(manager):
    session, _, _ = manager.establish(
        req(call_type="sds", target="grp:alpha", media=(MediaKind.DATA,)))
    assert session.floor is None


# --------------------------------------------------------------------------
# VP1-HOOK-032 — refusal establishes nothing
# --------------------------------------------------------------------------


def test_vp1_hook_032_refused_session_sends_no_invitation(manager):
    session, signals, refusal = manager.establish(req(call_type="unknown-type"))
    assert session is None
    assert refusal.reason_code == "call-type-not-permitted"
    assert SignalType.INVITE not in types(signals)
    assert types(signals) == [SignalType.RESPONSE_REJECT]
    assert manager.active == ()


def test_vp1_hook_032_refusal_is_audited(manager, sink):
    manager.establish(req(call_type="unknown-type"))
    refused = sink.of_type(RecordType.SESSION_REFUSED)
    assert len(refused) == 1
    assert refused[0].detail["reason_code"] == "call-type-not-permitted"
    assert sink.of_type(RecordType.SESSION_ESTABLISHED) == []


def test_participant_limit_refuses_before_establishment(manager):
    """A private call resolves to a 4-member group: over its limit of 2."""
    session, signals, refusal = manager.establish(
        req(call_type="private", target="grp:alpha"))
    assert session is None
    assert refusal.reason_code == "capacity-exhausted"
    assert SignalType.INVITE not in types(signals)


def test_unknown_target_fails_without_establishing(manager):
    session, signals, refusal = manager.establish(req(target="grp:nonexistent"))
    assert session is None
    assert refusal.reason_code == "unknown-target"
    assert SignalType.INVITE not in types(signals)


# --------------------------------------------------------------------------
# PLT-OAM-008 / QoS — core-originated refusals
# --------------------------------------------------------------------------


def test_recording_required_but_unavailable_refuses(mcx, sink):
    auditor = Auditor(sink, mcx.profile.identifier(), clock=Clock())
    mcx.hooks.identity_resolver.register_user("sip:u0@mcptt.example")
    mcx.hooks.identity_resolver.register_user("sip:u1@mcptt.example")
    mgr = SessionManager(mcx, auditor,
                         platform=Platform(recording_available=lambda: False))
    session, signals, refusal = mgr.establish(
        req(call_type="private", target="sip:u1@mcptt.example"))
    assert session is None
    assert refusal.reason_code == "recording-unavailable"
    assert SignalType.INVITE not in types(signals)


def test_qos_refusal_fails_rather_than_degrading(mcx, sink):
    auditor = Auditor(sink, mcx.profile.identifier(), clock=Clock())
    mcx.hooks.identity_resolver.register_user("sip:u0@mcptt.example")
    mcx.hooks.identity_resolver.register_user("sip:u1@mcptt.example")
    mgr = SessionManager(mcx, auditor,
                         platform=Platform(reserve_qos=lambda d: False))
    session, _, refusal = mgr.establish(
        req(call_type="private", target="sip:u1@mcptt.example"))
    assert session is None
    assert refusal.reason_code == "qos-unavailable"


def test_capacity_supplied_to_admission_hook(mcx, sink):
    auditor = Auditor(sink, mcx.profile.identifier(), clock=Clock())
    mcx.hooks.identity_resolver.register_user("sip:u0@mcptt.example")
    mcx.hooks.identity_resolver.register_user("sip:u1@mcptt.example")
    mgr = SessionManager(mcx, auditor,
                         platform=Platform(active_sessions=lambda: 2000))
    session, _, refusal = mgr.establish(
        req(call_type="private", target="sip:u1@mcptt.example"))
    assert session is None
    assert refusal.reason_code == "capacity-exhausted"


# --------------------------------------------------------------------------
# §8.1 ordering and failure propagation
# --------------------------------------------------------------------------


def test_invocation_order_matches_icd_section_8_1(manager, sink):
    """A local session never consults the interworking hook."""
    manager.establish(req())
    calls = [(r.detail["interface"], r.detail["method"])
             for r in sink.of_type(RecordType.HOOK_INVOCATION)]
    assert calls == [
        ("IF-IDR", "resolve"),
        ("IF-PRI", "evaluate"),
        ("IF-SES", "admit"),
        ("IF-SES", "decide"),
        ("IF-SES", "floor_policy"),
        ("IF-BER", "select"),
    ]


def test_external_target_inserts_the_interworking_call(manager, sink):
    """An EXTERNAL resolution adds IF-IWF.route immediately after IF-IDR."""
    manager.establish(req(call_type="private", target="tetra:1234", rid="ext"))
    calls = [(r.detail["interface"], r.detail["method"])
             for r in sink.for_session("ext")
             if r.type is RecordType.HOOK_INVOCATION]
    assert calls[:2] == [("IF-IDR", "resolve"), ("IF-IWF", "route")]


def test_sequence_stops_at_first_failure(manager, sink):
    """No hook after the failing one is invoked, and none is compensated."""
    manager.establish(req(target="grp:nonexistent"))
    calls = [r.detail["interface"] for r in sink.of_type(RecordType.HOOK_INVOCATION)]
    assert calls == ["IF-IDR"]


def test_vp1_hook_001_hook_exception_fails_session(mcx, sink):
    class Exploding:
        def __init__(self, profile):
            pass

        def evaluate(self, request, resolution):
            raise RuntimeError("boom")

        def compare(self, a, b):
            return 0

    mcx.hooks.identity_resolver.register_user("sip:u0@mcptt.example")
    mcx.hooks.identity_resolver.register_user("sip:u1@mcptt.example")
    broken = loader.LoadedHooks(
        identity_resolver=mcx.hooks.identity_resolver,
        priority_policy=Exploding(mcx.profile),
        session_policy=mcx.hooks.session_policy,
        bearer_selector=mcx.hooks.bearer_selector,
        interworking_gateway=mcx.hooks.interworking_gateway)
    lp = loader.LoadedProfile(profile=mcx.profile, hooks=broken, source=mcx.source)
    mgr = SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))

    session, signals, refusal = mgr.establish(
        req(call_type="private", target="sip:u1@mcptt.example"))
    assert session is None
    assert refusal.reason_code == "hook-error"
    assert SignalType.INVITE not in types(signals)
    failed = sink.of_type(RecordType.SESSION_FAILED)
    assert failed[0].detail["interface"] == "IF-PRI"


def test_vp1_hook_002_contract_violation_is_distinguished(mcx, sink):
    class BadResolver:
        def __init__(self, profile):
            pass

        def resolve(self, target, request):
            # USER kind with two members: violates §3.2 POST-1.
            return Resolution(kind=ResolutionKind.USER,
                              members=("sip:a@mcptt.example",
                                       "sip:b@mcptt.example"))

        def bind(self, i, s, l):
            pass

        def unbind(self, i, s):
            pass

        def identities_of(self, s):
            return ()

    hooks = loader.LoadedHooks(
        identity_resolver=BadResolver(mcx.profile),
        priority_policy=mcx.hooks.priority_policy,
        session_policy=mcx.hooks.session_policy,
        bearer_selector=mcx.hooks.bearer_selector,
        interworking_gateway=mcx.hooks.interworking_gateway)
    lp = loader.LoadedProfile(profile=mcx.profile, hooks=hooks, source=mcx.source)
    mgr = SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))

    session, _, refusal = mgr.establish(req(call_type="private", target="x"))
    assert session is None
    assert refusal.reason_code == "hook-contract-violation"
    assert refusal.reason_code != "hook-error"


# --------------------------------------------------------------------------
# VP1-HOOK-003/004 — audit
# --------------------------------------------------------------------------


def test_vp1_hook_003_every_invocation_audited(manager, sink):
    manager.establish(req())
    records = sink.of_type(RecordType.HOOK_INVOCATION)
    assert len(records) == 6
    for r in records:
        assert r.detail["interface"].startswith("IF-")
        assert "elapsed_ms" in r.detail
        assert r.detail["outcome"] == "ok"
        assert r.correlation_id == "s1"


def test_vp1_hook_004_decisions_recorded_in_full(manager, sink):
    manager.establish(req())
    admitted = sink.of_type(RecordType.SESSION_ADMITTED)[0]
    assert admitted.detail["priority"]
    assert admitted.detail["scope"]
    assert admitted.detail["members"] == 4
    established = sink.of_type(RecordType.SESSION_ESTABLISHED)[0]
    assert established.detail["qos_identifier"] == 65


def test_vp1_oam_001_profile_identity_on_every_record(manager, sink, mcx):
    manager.establish(req())
    assert sink.records
    for r in sink.records:
        assert r.profile == mcx.profile.identifier()
        assert r.profile.startswith("mcx/")


def test_vp1_oam_004_correlation_id_stable_across_records(manager, sink):
    manager.establish(req(rid="call-42"))
    manager.release("call-42")
    ids = {r.correlation_id for r in sink.records}
    assert ids == {"call-42"}
    assert len(sink.for_session("call-42")) == len(sink.records)


def test_audit_records_serialise(manager, sink):
    manager.establish(req())
    for r in sink.records:
        assert r.to_json().startswith("{")


# --------------------------------------------------------------------------
# Release
# --------------------------------------------------------------------------


def test_release_sends_bye_to_every_member(manager):
    session, _, _ = manager.establish(req())
    signals = manager.release("s1")
    byes = {s.target for s in signals if s.type is SignalType.BYE}
    assert byes == set(session.members)
    assert SignalType.RELEASE_QOS in types(signals)
    assert session.state is SessionState.RELEASED


def test_release_stops_the_floor_machine(manager):
    session, _, _ = manager.establish(req())
    manager.release("s1")
    assert session.floor.state.value == "released"
    assert session.floor.running_timers() == {}


def test_releasing_an_unknown_session_is_a_noop(manager):
    assert manager.release("no-such-session") == ()


def test_double_release_is_harmless(manager):
    manager.establish(req())
    manager.release("s1")
    assert manager.release("s1") == ()


# --------------------------------------------------------------------------
# §8.2 — pre-emption victim selection
# --------------------------------------------------------------------------


def test_preemption_requires_capability(manager):
    manager.establish(req(rid="victim"))
    weak = PriorityDecision(level=999, scope="public-safety",
                            preemption_capability=False,
                            preemption_vulnerability=False,
                            floor_priority=255, label="weak")
    assert manager.preemption_victims(weak) == ()


def test_preemption_selects_vulnerable_lower_priority_sessions(manager, mcx):
    manager.establish(req(rid="normal-call"))
    emergency = mcx.hooks.priority_policy.evaluate(
        req(call_type="emergency-group"),
        Resolution(kind=ResolutionKind.USER, members=("x",)))
    victims = manager.preemption_victims(emergency)
    assert [v.correlation_id for v in victims] == ["normal-call"]


def test_preemption_never_crosses_scopes(manager, mcx):
    """The invariant this whole design turns on."""
    manager.establish(req(rid="normal-call"))
    frmcs = loader.load(PROFILES / "frmcs")
    rail_emergency = frmcs.hooks.priority_policy.evaluate(
        req(call_type="rec-broadcast"),
        Resolution(kind=ResolutionKind.USER, members=("x",)))
    assert rail_emergency.preemption_capability is True
    assert rail_emergency.level > 90
    assert manager.preemption_victims(rail_emergency) == ()


def test_non_vulnerable_session_is_never_a_victim(manager, mcx):
    manager.establish(req(call_type="emergency-group", rid="emergency"))
    another = mcx.hooks.priority_policy.evaluate(
        req(call_type="emergency-group"),
        Resolution(kind=ResolutionKind.USER, members=("x",)))
    assert manager.preemption_victims(another) == ()


def test_higher_priority_still_cannot_preempt_a_non_vulnerable_session(manager):
    """Isolates the vulnerability guard: same scope, incoming strictly outranks,
    so `compare` alone would select it. Only the vulnerability flag stops it."""
    manager.establish(req(call_type="emergency-group", rid="emergency"))
    assert manager.session("emergency").priority.preemption_vulnerability is False
    overwhelming = PriorityDecision(level=255, scope="public-safety",
                                    preemption_capability=True,
                                    preemption_vulnerability=False,
                                    floor_priority=255, label="overwhelming")
    assert manager.preemption_victims(overwhelming) == ()


def test_scope_check_is_a_backstop_for_a_broken_compare(mcx, sink):
    """Isolates the scope guard.

    A profile whose `compare` wrongly ignores scope must still not produce
    cross-scope pre-emption: the manager checks scope independently. Two layers
    guard the invariant the whole design turns on, so each is tested with the
    other disabled.
    """
    class ScopeBlindPolicy:
        def __init__(self, profile):
            self._inner = mcx.hooks.priority_policy

        def evaluate(self, request, resolution):
            return self._inner.evaluate(request, resolution)

        def compare(self, a, b):
            return (a.level > b.level) - (a.level < b.level)   # ignores scope

    hooks = loader.LoadedHooks(
        identity_resolver=mcx.hooks.identity_resolver,
        priority_policy=ScopeBlindPolicy(mcx.profile),
        session_policy=mcx.hooks.session_policy,
        bearer_selector=mcx.hooks.bearer_selector,
        interworking_gateway=mcx.hooks.interworking_gateway)
    lp = loader.LoadedProfile(profile=mcx.profile, hooks=hooks, source=mcx.source)
    mcx.hooks.identity_resolver.register_user("sip:u0@mcptt.example")
    mcx.hooks.identity_resolver.register_group(
        "grp:alpha", ["sip:u0@mcptt.example", "sip:u1@mcptt.example"])
    mcx.hooks.identity_resolver.register_user("sip:u1@mcptt.example")
    mgr = SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))
    mgr.establish(req(rid="normal-call"))
    assert mgr.active

    foreign = PriorityDecision(level=255, scope="some-other-scope",
                               preemption_capability=True,
                               preemption_vulnerability=False,
                               floor_priority=255, label="foreign-emergency")
    assert mgr.preemption_victims(foreign) == ()


# --------------------------------------------------------------------------
# Invoker — deadlines
# --------------------------------------------------------------------------


def test_invoker_records_budget_overrun(sink):
    import time
    auditor = Auditor(sink, "p/1/h", clock=Clock())
    inv = Invoker(auditor, "c1", budgets_ms={"IF-PRI": 1})
    inv.call("IF-PRI", "evaluate", lambda: time.sleep(0.02))
    record = sink.of_type(RecordType.HOOK_INVOCATION)[0]
    assert record.detail["budget_overrun"] is True
    assert record.detail["outcome"] == "ok"


def test_invoker_enforce_mode_times_out(sink):
    import time
    auditor = Auditor(sink, "p/1/h", clock=Clock())
    inv = Invoker(auditor, "c1", budgets_ms={"IF-IDR": 10},
                  mode=DeadlineMode.ENFORCE)
    with pytest.raises(HookFailure) as exc:
        inv.call("IF-IDR", "resolve", lambda: time.sleep(0.5))
    assert exc.value.reason_code == "hook-timeout"
    assert sink.of_type(RecordType.HOOK_INVOCATION)[0].detail["outcome"] == "timeout"


def test_invoker_never_substitutes_a_default(sink):
    auditor = Auditor(sink, "p/1/h", clock=Clock())
    inv = Invoker(auditor, "c1")

    def raiser():
        raise ValueError("no")

    with pytest.raises(HookFailure):
        inv.call("IF-SES", "admit", raiser)


def test_invoker_does_not_distinguish_exception_types(sink):
    auditor = Auditor(sink, "p/1/h", clock=Clock())
    inv = Invoker(auditor, "c1")
    for exc_type in (ValueError, KeyError, RuntimeError):
        def raiser(e=exc_type):
            raise e("x")

        with pytest.raises(HookFailure) as caught:
            inv.call("IF-SES", "admit", raiser)
        assert caught.value.reason_code == "hook-error"
