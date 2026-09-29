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
    assert refusal.reason_code == "participant-limit-exceeded"
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
        # PLT-ICD-001 0.13 §8.1 step 0 (ICD-OP-09): the initiator's roles,
        # then authorisation, before anything about the target is looked up.
        ("IF-IDR", "identities_of"),
        ("IF-SES", "authorise"),
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
    assert calls[2:4] == [("IF-IDR", "resolve"), ("IF-IWF", "route")]


def test_sequence_stops_at_first_failure(manager, sink):
    """No hook after the failing one is invoked, and none is compensated."""
    manager.establish(req(target="grp:nonexistent"))
    calls = [(r.detail["interface"], r.detail["method"])
             for r in sink.of_type(RecordType.HOOK_INVOCATION)]
    assert calls == [("IF-IDR", "identities_of"), ("IF-SES", "authorise"),
                     ("IF-IDR", "resolve")]


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
        interworking_gateway=mcx.hooks.interworking_gateway,
        interconnection_gateway=mcx.hooks.interconnection_gateway)
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
        interworking_gateway=mcx.hooks.interworking_gateway,
        interconnection_gateway=mcx.hooks.interconnection_gateway)
    lp = loader.LoadedProfile(profile=mcx.profile, hooks=hooks, source=mcx.source)
    mgr = SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))

    session, _, refusal = mgr.establish(req(call_type="private", target="x"))
    assert session is None
    assert refusal.reason_code == "hook-contract-violation"
    assert refusal.reason_code != "hook-error"


# --------------------------------------------------------------------------
# VP1-HOOK-012 — the core enforces §3.2 POST-3 (RES-OP-01)
# --------------------------------------------------------------------------


def _with_resolver(mcx, sink, resolve):
    class Resolver:
        def __init__(self, profile):
            pass

        def resolve(self, target, request):
            return resolve(target)

        def bind(self, i, s, l):
            pass

        def unbind(self, i, s):
            pass

        def identities_of(self, s):
            return ()

    hooks = loader.LoadedHooks(
        identity_resolver=Resolver(mcx.profile),
        priority_policy=mcx.hooks.priority_policy,
        session_policy=mcx.hooks.session_policy,
        bearer_selector=mcx.hooks.bearer_selector,
        interworking_gateway=mcx.hooks.interworking_gateway,
        interconnection_gateway=mcx.hooks.interconnection_gateway)
    lp = loader.LoadedProfile(profile=mcx.profile, hooks=hooks, source=mcx.source)
    return SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))


@pytest.mark.vp("VP1-HOOK-012")
@pytest.mark.parametrize("foreign", [
    "sip:evil@other.example",            # another domain
    "sip:evil@frmcs.example",            # another profile's domain
    "sip:evil@mcptt.example:5060",       # a port: not written as a member is
    "sip:evil@mcptt.example;x=1",        # parameters, likewise
    "sip:evil@sub.mcptt.example",        # a subdomain is not the domain
    "evil@mcptt.example",                # no scheme
    "sip:mcptt.example",                 # no user
    "sip:@mcptt.example",                # empty user
    "sip:evil@other.example@mcptt.example",     # a second "@" (RFC 3261: escaped)
    "sip:evil@other.example;x=@mcptt.example",  # an "@" in a parameter
    "sip:evil@other.example?h=@mcptt.example",  # an "@" in a header
    "http:evil@mcptt.example",           # not a SIP URI
    "grp:evil@mcptt.example",
    "sip:evil@mcptt.example.",           # a trailing dot is another name
    "<sip:evil@mcptt.example>",          # brackets are not part of an identity
])
def test_a_resolution_with_a_member_outside_the_domains_is_a_contract_violation(
        mcx, sink, foreign):
    """A resolver, in-tree or substituted, that returns a member outside the
    profile's declared domains is refused by the core: no session, no
    invitation to anyone, the violation audited."""
    mgr = _with_resolver(mcx, sink, lambda t: Resolution(
        kind=ResolutionKind.GROUP, group_id=t,
        members=("sip:u0@mcptt.example", "sip:u1@mcptt.example", foreign)))
    session, signals, refusal = mgr.establish(req())
    assert session is None and refusal.reason_code == "hook-contract-violation"
    assert SignalType.INVITE not in types(signals)
    failed = sink.of_type(RecordType.SESSION_FAILED)
    assert failed and failed[0].detail["interface"] == "IF-IDR"
    assert not sink.of_type(RecordType.SESSION_ESTABLISHED)

    mgr = _with_resolver(mcx, sink, lambda t: Resolution(
        kind=ResolutionKind.USER, members=(foreign,)))
    session, _, refusal = mgr.establish(req(call_type="private", target=foreign))
    assert session is None and refusal.reason_code == "hook-contract-violation"


@pytest.mark.vp("VP1-HOOK-012")
def test_a_domain_in_another_case_is_the_same_domain(mcx, sink):
    """RFC 3261 19.1.4: hosts compare without case."""
    mgr = _with_resolver(mcx, sink, lambda t: Resolution(
        kind=ResolutionKind.GROUP, group_id=t,
        members=("sip:u0@mcptt.example", "sip:u1@MCPTT.Example")))
    session, _, refusal = mgr.establish(req())
    assert refusal is None and session is not None


@pytest.mark.vp("VP1-HOOK-012")
@pytest.mark.parametrize("member,domain", [
    ("sip:u@mcptt.example", "mcptt.example"), ("sips:u@mcptt.example", "mcptt.example"),
    ("SIP:u@MCPTT.Example", "mcptt.example"), ("sip:u%40x@mcptt.example", "mcptt.example"),
    ("sip:u@x@mcptt.example", None), ("sip:u:pw@mcptt.example", None),
    ("sip:u@mcptt.example;transport=tls", None), ("sip: u@mcptt.example", None),
    ("sip:u@mcptt.example ", None), ("tel:+331234", None), ("", None), (None, None),
    ("sip:u;x=1@mcptt.example", None), ("sip:u?h=1@mcptt.example", None),
    ("sip:<u>@mcptt.example", None), ("sip:u/v@mcptt.example", None),
])
def test_the_domain_of_an_identity(member, domain):
    """Stricter than RFC 3261, which lets a user part hold ';', '?' and '/':
    no MC service identity needs them, and each is a place for two parsers
    to disagree."""
    from core import identity
    assert identity.domain_of(member) == domain


def test_outside_compares_declared_domains_without_case():
    from core import identity
    assert identity.outside(["sip:u@mcptt.example", "sip:v@other.example"],
                            ["MCPTT.EXAMPLE"]) == ["sip:v@other.example"]


@pytest.mark.vp("VP1-HOOK-012")
def test_ad_hoc_participants_outside_the_domains_are_a_contract_violation(manager):
    """§3.5: determine_participants is held to the same rule."""
    good = Resolution(kind=ResolutionKind.GROUP, members=("sip:u1@mcptt.example",))
    manager._check_participants(good)
    bad = Resolution(kind=ResolutionKind.GROUP,
                     members=("sip:u1@mcptt.example", "sip:x@other.example"))
    with pytest.raises(HookContractViolation, match="outside the profile's declared"):
        manager._check_participants(bad)


# --------------------------------------------------------------------------
# RES-OP-07 — the core checks a floor policy and a bearer decision as returned
# --------------------------------------------------------------------------


def _altered(mcx, sink, *, floor=None, bearer=None, priority=None, decision=None,
             profile=None, **manager_kw):
    """A manager whose in-tree hooks' answers are changed by `floor`,
    `bearer` or `priority` (functions of the in-tree answer): a substituted
    hook, as the core sees one."""
    import dataclasses as dc
    resolver = mcx.hooks.identity_resolver
    for i in range(6):
        resolver.register_user(f"sip:u{i}@mcptt.example")
    resolver.register_group("grp:alpha", [f"sip:u{i}@mcptt.example" for i in range(4)])
    sp, bs, pp = (mcx.hooks.session_policy, mcx.hooks.bearer_selector,
                  mcx.hooks.priority_policy)

    class Session:
        def __getattr__(self, n):
            return getattr(sp, n)

        def floor_policy(self, request, resolution):
            got = sp.floor_policy(request, resolution)
            return floor(got) if floor else got

        def decide(self, request, resolution):
            got = sp.decide(request, resolution)
            return decision(got) if decision else got

    class Bearer:
        def __getattr__(self, n):
            return getattr(bs, n)

        def select(self, request, prio, media):
            got = bs.select(request, prio, media)
            return bearer(got) if bearer else got

    class Priority:
        def __getattr__(self, n):
            return getattr(pp, n)

        def evaluate(self, request, resolution):
            got = pp.evaluate(request, resolution)
            return priority(got) if priority else got

    hooks = dc.replace(mcx.hooks, session_policy=Session(), bearer_selector=Bearer(),
                       priority_policy=Priority())
    lp = loader.LoadedProfile(profile=profile or mcx.profile, hooks=hooks, source=mcx.source)
    return SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()),
                          **manager_kw)


def _refused_as_violation(mgr, sink, interface):
    session, signals, refusal = mgr.establish(req())
    assert session is None and refusal.reason_code == "hook-contract-violation"
    assert SignalType.INVITE not in types(signals)
    assert SignalType.RESERVE_QOS not in types(signals)
    failed = sink.of_type(RecordType.SESSION_FAILED)
    assert failed and failed[-1].detail["interface"] == interface
    assert not sink.of_type(RecordType.SESSION_ESTABLISHED)


def _floor(**kw):
    import dataclasses as dc
    return lambda fp: dc.replace(fp, **kw)


@pytest.mark.vp("VP1-HOOK-034")
@pytest.mark.parametrize("change", [
    _floor(queueing_enabled=False, max_queue_depth=2),     # POST-1
    _floor(queueing_enabled=True, max_queue_depth=0),      # POST-2
    _floor(max_queue_depth=-1),
    _floor(max_queue_depth=True),
    _floor(max_queue_depth=2.5),
    _floor(max_queue_depth="3"),
    _floor(timers_ms={"T99": 1000}),                       # POST-3
    _floor(timers_ms={"t2": 1000}),
    _floor(timers_ms={"T2": 0}),
    _floor(timers_ms={"T2": -5}),
    _floor(timers_ms={"T2": "4000"}),
    _floor(timers_ms={"T2": True}),
    _floor(queueing_enabled="no", max_queue_depth=8),
    _floor(queueing_enabled=False, max_queue_depth=-1),
    _floor(override_allowed="false"),
    _floor(initial_grant_to_initiator=None),
    _floor(timers_ms=None),
    lambda fp: _Shaped(fp),
    lambda fp: None,
], ids=["no-queue-depth", "queue-no-depth", "negative-depth", "bool-depth", "float-depth", "string-depth", "unknown-timer",
        "lowercase-timer", "zero-timer", "negative-timer", "string-timer", "bool-timer",
        "string-queueing", "no-queue-negative-depth", "string-override",
        "none-initial-grant", "none-timers", "not-a-floor-policy", "none"])
def test_an_inconsistent_floor_policy_from_a_hook_is_a_contract_violation(mcx, sink, change):
    """PLT-ICD-001 §5.3 POST-1/2/3 on what a hook returns, not only on the
    in-tree table (RES-OP-07)."""
    _refused_as_violation(_altered(mcx, sink, floor=change), sink, "IF-SES")


@pytest.mark.vp("VP1-HOOK-034")
@pytest.mark.parametrize("change", [
    _floor(queueing_enabled=False, max_queue_depth=0),
    _floor(queueing_enabled=True, max_queue_depth=1, timers_ms={"T1": 6000, "T3": 1}),
])
def test_a_consistent_floor_policy_is_accepted(mcx, sink, change):
    session, _, refusal = _altered(mcx, sink, floor=change).establish(req())
    assert refusal is None and session is not None


def _bearer(**kw):
    import dataclasses as dc
    return lambda b: dc.replace(b, **kw)


def _path(pid="p", transport="udp", primary=True):
    from core.hooks import PathSpec
    return PathSpec(path_id=pid, transport=transport, primary=primary)


def _path_weighted(weight):
    from core.hooks import PathSpec
    return PathSpec(path_id="p", transport="udp", primary=True, weight=weight)


class _Shaped:
    """Shaped like the value it wraps, but not one: its fields can change
    between the core's check and the core's use (the review's read-twice
    case), so it is refused whatever it reads as."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.mark.vp("VP1-HOOK-040")
@pytest.mark.parametrize("change", [
    _bearer(paths=()),                                                      # POST-1
    _bearer(paths=(_path(primary=False),)),
    _bearer(paths=(_path("a"), _path("b")), redundancy="multipath"),
    _bearer(paths=(_path("a"), _path("a", primary=False)), redundancy="multipath"),  # POST-2
    _bearer(paths=(_path("a"), _path("b", primary=False)), redundancy="single"),     # POST-3
    _bearer(redundancy="multihomed"),
    _bearer(redundancy="triple"),
    _bearer(paths=(_path(transport="quic"),)),
    _bearer(arp_level=0),                                                   # POST-4
    _bearer(arp_level=16),
    _bearer(arp_level=True),
    _bearer(qos_identifier="65"),
    _bearer(qos_identifier=True),
    _bearer(paths=(_path(primary=1),)),
    _bearer(paths=(_path(3),)),
    _bearer(arp_preemption_capability=0),
    _bearer(arp_preemption_vulnerability="no"),
    _bearer(arp_preemption_vulnerability=None),
    _bearer(paths=(_path("a"), _path("b", primary=False)), redundancy="triple"),
    _bearer(paths=("a",)),
    _bearer(paths=None),
    _bearer(paths=(_path_weighted(0),)),
    _bearer(paths=(_path_weighted("2"),)),
    _bearer(paths=(_path_weighted(True),)),
    lambda b: _Shaped(b),
    lambda b: None,
], ids=["no-path", "no-primary", "two-primaries", "duplicate-id",
        "single-two-paths", "multihomed-one-path", "unknown-redundancy", "unknown-transport",
        "arp-0", "arp-16", "arp-bool", "qos-str", "qos-bool", "int-primary", "int-id",
        "int-arp-capability", "string-vulnerability", "none-vulnerability",
        "unknown-redundancy-two-paths", "string-paths", "none-paths", "weight-0",
        "string-weight", "bool-weight", "not-a-bearer-decision", "none"])
def test_an_inconsistent_bearer_decision_from_a_hook_is_a_contract_violation(mcx, sink, change):
    """PLT-ICD-001 §6.1 POST-1 to 4 on what a hook returns (RES-OP-07)."""
    _refused_as_violation(_altered(mcx, sink, bearer=change), sink, "IF-BER")


@pytest.mark.vp("VP1-HOOK-041")
def test_arp_preemption_beyond_the_priority_decision_is_a_contract_violation(mcx, sink):
    """§6.1 POST-5: the in-tree selector never builds this, so only a
    substituted hook can, and only the core can refuse it (RES-OP-07)."""
    _refused_as_violation(_altered(mcx, sink, bearer=_bearer(arp_preemption_capability=True)),
                          sink, "IF-BER")


@pytest.mark.vp("VP1-HOOK-041")
def test_a_truthy_priority_flag_does_not_grant_arp_preemption(mcx, sink):
    """IF-PRI's value is not itself checked, so only True grants."""
    import dataclasses as dc
    mgr = _altered(mcx, sink, bearer=_bearer(arp_preemption_capability=True),
                   priority=lambda p: dc.replace(p, preemption_capability="false"))
    _refused_as_violation(mgr, sink, "IF-BER")


@pytest.mark.vp("VP1-HOOK-041")
def test_arp_preemption_the_priority_decision_grants_is_accepted(mcx, sink):
    import dataclasses as dc
    mgr = _altered(mcx, sink, bearer=_bearer(arp_preemption_capability=True),
                   priority=lambda p: dc.replace(p, preemption_capability=True))
    session, _, refusal = mgr.establish(req())
    assert refusal is None and session.bearer.arp_preemption_capability is True


@pytest.mark.vp("VP1-HOOK-040")
def test_a_consistent_multipath_bearer_decision_is_accepted(mcx, sink):
    mgr = _altered(mcx, sink, bearer=_bearer(
        paths=(_path("a"), _path("b", transport="sctp", primary=False)), redundancy="multihomed",
        arp_level=15))
    session, _, refusal = mgr.establish(req())
    assert refusal is None and [p.path_id for p in session.bearer.paths] == ["a", "b"]


@pytest.mark.vp("VP1-HOOK-040")
@pytest.mark.parametrize("change", [
    _bearer(paths=(_path(""),)),
    _bearer(paths=(_path("a", transport="tcp"), _path("b", primary=False)),
            redundancy="multipath", arp_level=1, qos_identifier=200),
    _bearer(arp_preemption_vulnerability=True),
    _bearer(paths=(_path_weighted(5),)),
], ids=["empty-id", "multipath-tcp-arp-1", "vulnerable", "weight-5"])
def test_bearer_decisions_profile_validation_accepts_are_accepted(mcx, sink, change):
    """The core refuses nothing a validated profile could hold: an empty path
    id, an operator 5QI, any valid ARP and weight (RES-OP-07 review)."""
    session, _, refusal = _altered(mcx, sink, bearer=change).establish(req())
    assert refusal is None and session is not None


# --------------------------------------------------------------------------
# RES-OP-12 — the session decision is applied as decided (§5.2 INV-1)
# --------------------------------------------------------------------------


def _decide(**kw):
    import dataclasses as dc
    return lambda d: dc.replace(d, **kw)


def _inverted(d):
    """Every field the profile would not choose, the model aside (POST-1
    ties it to the call type)."""
    import dataclasses as dc
    return dc.replace(d, auto_answer=not d.auto_answer,
                      acknowledgement_required=not d.acknowledgement_required,
                      recording_required=not d.recording_required,
                      max_participants=4)


@pytest.mark.vp("VP1-CC-006")
@pytest.mark.parametrize("call_type", ["prearranged-group", "emergency-group",
                                       "coordination-group"])
def test_vp1_cc_006_the_hook_s_decision_is_applied_not_the_table_s(mcx, sink, call_type):
    """Nothing is inferred from the call type: a decide() differing from the
    profile in every field is what the session follows."""
    declared = mcx.profile.call_type(call_type)
    session, signals, refusal = _altered(mcx, sink, decision=_inverted).establish(
        req(call_type=call_type))
    assert refusal is None
    assert session.decision.auto_answer is (not declared.auto_answer)
    assert session.decision.max_participants == 4
    invites = [s for s in signals if s.type is SignalType.INVITE]
    assert invites
    for invite in invites:
        assert invite.detail["auto_answer"] is (not declared.auto_answer)
        assert invite.detail["acknowledgement_required"] is \
            (not declared.acknowledgement_required)
    assert (SignalType.START_RECORDING in types(signals)) is (not declared.recording_required)


@pytest.mark.vp("VP1-HOOK-033")
@pytest.mark.parametrize("auto,ack", [(True, True), (True, False), (False, True),
                                      (False, False)])
def test_vp1_hook_033_every_answer_combination_is_signalled_as_decided(mcx, sink, auto, ack):
    """Emergency group calls are auto-answered in the table; a decision saying
    otherwise is followed, so nothing is inferred from urgency."""
    session, signals, refusal = _altered(
        mcx, sink, decision=_decide(auto_answer=auto, acknowledgement_required=ack)
    ).establish(req(call_type="emergency-group"))
    assert refusal is None
    invites = [s for s in signals if s.type is SignalType.INVITE]
    assert len(invites) == 3
    assert {(i.detail["auto_answer"], i.detail["acknowledgement_required"])
            for i in invites} == {(auto, ack)}


@pytest.mark.vp("VP1-HOOK-033")
@pytest.mark.parametrize("required,established", [(True, False), (False, True)])
def test_vp1_hook_033_recording_follows_the_decision_not_the_table(mcx, sink, required,
                                                                  established):
    """No recorder is available. The table requires recording for every mcx
    call type; only the decision says whether this session does."""
    mgr = _altered(mcx, sink, decision=_decide(recording_required=required),
                   platform=Platform(recording_available=lambda: False))
    session, signals, refusal = mgr.establish(req())
    assert (session is not None) is established
    if established:
        assert SignalType.START_RECORDING not in types(signals)
    else:
        assert refusal.reason_code == "recording-unavailable"


@pytest.mark.vp("VP1-CC-006")
def test_vp1_cc_006_a_changed_table_changes_nothing_the_hook_decided(mcx, sink):
    """The converse: the manager's profile says otherwise in every field the
    decision carries, and the session still follows the hook."""
    import dataclasses as dc
    changed = dc.replace(mcx.profile, call_types=tuple(
        dc.replace(ct, auto_answer=not ct.auto_answer,
                   acknowledgement_required=not ct.acknowledgement_required,
                   recording_required=not ct.recording_required, max_participants=1)
        for ct in mcx.profile.call_types))
    declared = mcx.profile.call_type("prearranged-group")
    session, signals, refusal = _altered(mcx, sink, profile=changed).establish(req())
    assert refusal is None and len(session.members) == 4
    invite = [s for s in signals if s.type is SignalType.INVITE][0]
    assert invite.detail["auto_answer"] is declared.auto_answer
    assert invite.detail["acknowledgement_required"] is declared.acknowledgement_required
    assert (SignalType.START_RECORDING in types(signals)) is declared.recording_required


@pytest.mark.vp("VP1-CC-006", "VP1-HOOK-033")
@pytest.mark.parametrize("limit,members", [
    (3, ("sip:u0@mcptt.example", "sip:u1@mcptt.example", "sip:u2@mcptt.example")),
    (2, ("sip:u0@mcptt.example", "sip:u1@mcptt.example")),
])
def test_vp1_cc_006_a_group_over_the_decided_limit_is_truncated(mcx, sink, limit, members):
    """grp:alpha has 4 members, u0 the caller among them; the profile allows
    200. TS 24.379 6.3.5.5: only `limit` participants take part, the caller
    one of them, the rest in the resolver's order (RES-OP-12)."""
    session, signals, refusal = _altered(
        mcx, sink, decision=_decide(max_participants=limit)).establish(req())
    assert refusal is None
    assert session.members == members and session.truncated_from == 4
    assert [s.target for s in signals if s.type is SignalType.INVITE] == [
        m for m in members if m != "sip:u0@mcptt.example"]
    established = sink.of_type(RecordType.SESSION_ESTABLISHED)[-1].detail
    assert established["members"] == members and established["truncated_from"] == 4


@pytest.mark.vp("VP1-CC-006")
def test_a_limit_leaving_no_one_to_invite_is_refused(mcx, sink):
    """A limit of 1 on a group the caller belongs to: truncation would keep
    only the caller, and a call with no callee is not established (RES-OP-12
    review; it used to be recorded as established and then answered 480)."""
    session, signals, refusal = _altered(
        mcx, sink, decision=_decide(max_participants=1)).establish(req())
    assert session is None and refusal.reason_code == "participant-limit-exceeded"
    assert refusal.detail == ("4 participants, the session decision allows 1, "
                              "so no one else can be invited")
    assert SignalType.INVITE not in types(signals)
    assert not sink.of_type(RecordType.SESSION_ESTABLISHED)


@pytest.mark.vp("VP1-CC-006")
@pytest.mark.parametrize("limit", [4, None])
def test_vp1_cc_006_a_group_within_the_decided_limit_is_whole(mcx, sink, limit):
    session, _, refusal = _altered(
        mcx, sink, decision=_decide(max_participants=limit)).establish(req())
    assert refusal is None and len(session.members) == 4
    assert session.truncated_from is None
    assert sink.of_type(RecordType.SESSION_ESTABLISHED)[-1].detail["truncated_from"] is None


@pytest.mark.vp("VP1-CC-006")
def test_a_caller_outside_the_group_takes_no_participant_place(mcx, sink):
    session, _, refusal = _altered(mcx, sink, decision=_decide(max_participants=2)).establish(
        req(initiator="sip:u5@mcptt.example"))
    assert refusal is None
    assert session.members == ("sip:u0@mcptt.example", "sip:u1@mcptt.example")


@pytest.mark.vp("VP1-CC-006")
def test_a_private_call_over_the_limit_is_refused_not_made_a_group_call(mcx, sink):
    """A private call whose target resolved to a group is not truncated to a
    smaller group call: 6.3.5.5 is about group sessions."""
    session, signals, refusal = _altered(mcx, sink).establish(
        req(call_type="private", target="grp:alpha"))
    assert session is None and refusal.reason_code == "participant-limit-exceeded"
    assert refusal.detail == "4 participants, the session decision allows 2"
    assert SignalType.INVITE not in types(signals)
    assert SignalType.RESERVE_QOS not in types(signals)


@pytest.mark.vp("VP1-CC-006")
def test_a_group_call_type_with_no_signature_is_truncated_too(mcx, sink):
    """coordination-group has no MCPTT signature (PRF-OP-01) but is a group
    call: truncated, not refused."""
    session, _, refusal = _altered(mcx, sink, decision=_decide(max_participants=2)).establish(
        req(call_type="coordination-group"))
    assert refusal is None and session.truncated_from == 4
    assert session.members == ("sip:u0@mcptt.example", "sip:u1@mcptt.example")


@pytest.mark.vp("VP1-CC-006")
def test_a_broadcast_area_over_the_limit_is_refused_not_truncated(mcx, sink):
    """6.3.5.5 truncates a group's members; a broadcast area is not a group,
    and which of its members to drop is nobody's stated policy."""
    import dataclasses as dc
    resolver = mcx.hooks.identity_resolver
    area = tuple(f"sip:u{i}@mcptt.example" for i in range(1, 4))

    class Area:
        def __getattr__(self, name):
            return getattr(resolver, name)

        def resolve(self, target, request):
            return Resolution(kind=ResolutionKind.BROADCAST_AREA, members=area)

    mgr = _altered(mcx, sink, decision=_decide(max_participants=2))
    mgr._hooks = dc.replace(mgr._hooks, identity_resolver=Area())
    session, signals, refusal = mgr.establish(req(target="area:yard"))
    assert session is None and refusal.reason_code == "participant-limit-exceeded"
    assert SignalType.INVITE not in types(signals)
    control = _altered(mcx, MemorySink(), decision=_decide(max_participants=3))
    control._hooks = dc.replace(control._hooks, identity_resolver=Area())
    session, _, refusal = control.establish(req(target="area:yard"))
    assert refusal is None and session.members == area


def test_a_session_decision_for_an_undeclared_call_type_is_a_violation(manager, mcx):
    decision = mcx.hooks.session_policy.decide(
        req(), Resolution(kind=ResolutionKind.USER, members=("x",)))
    with pytest.raises(HookContractViolation, match="undeclared call type 'nope'"):
        manager._check_decision(decision, req(call_type="nope"))


@pytest.mark.vp("VP1-CC-006")
def test_an_ad_hoc_call_over_the_decided_limit_is_warning_189(mcx, sink):
    listed = tuple(f"sip:u{i}@mcptt.example" for i in (1, 2, 3))
    mgr = _altered(mcx, sink, decision=_decide(max_participants=2), adhoc_list_max=10)
    session, _, refusal = mgr.establish(req(target="", adhoc=True, participants=listed))
    assert session is None
    assert refusal.reason_code == "adhoc-too-many-participants"
    control = _altered(mcx, MemorySink(), decision=_decide(max_participants=3),
                       adhoc_list_max=10)
    session, _, refusal = control.establish(req(target="", adhoc=True, participants=listed))
    assert refusal is None and session.members == listed


def _model(name):
    from core.hooks import ResolutionKind, SessionModel
    return {"broadcast": SessionModel.BROADCAST, "pre": SessionModel.PRE_ESTABLISHED,
            "kind": ResolutionKind.GROUP}[name]


@pytest.mark.vp("VP1-CC-006")
@pytest.mark.parametrize("change", [
    lambda d: _decide(model=_model("broadcast"))(d),
    lambda d: _decide(model=_model("pre"))(d),
    lambda d: _decide(model=_model("kind"))(d),
    _decide(max_participants=0),
    _decide(max_participants=-1),
    _decide(max_participants=True),
    _decide(max_participants="4"),
    _decide(auto_answer=1),
    _decide(acknowledgement_required=None),
    _decide(recording_required=0),
    lambda d: None,
], ids=["broadcast", "pre-established", "not-a-model", "limit-0", "limit-negative",
        "limit-bool", "limit-str", "int-auto-answer", "none-ack", "int-recording", "none"])
def test_an_inconsistent_session_decision_is_a_contract_violation(mcx, sink, change):
    """§5.2 POST-1 (the call type's own model) and POST-2 (a limit of at
    least 1, or none), and boolean flags (RES-OP-12)."""
    _refused_as_violation(_altered(mcx, sink, decision=change), sink, "IF-SES")


# --------------------------------------------------------------------------
# VP1-HOOK-003/004 — audit
# --------------------------------------------------------------------------


def test_vp1_hook_003_every_invocation_audited(manager, sink):
    manager.establish(req())
    records = sink.of_type(RecordType.HOOK_INVOCATION)
    assert len(records) == 8
    for r in records:
        assert r.detail["interface"].startswith("IF-")
        assert "elapsed_ms" in r.detail
        assert r.detail["outcome"] == "ok"
        assert r.correlation_id == "s1"


def _returned_by(sink, interface, method):
    [record] = [r for r in sink.of_type(RecordType.HOOK_INVOCATION)
                if (r.detail["interface"], r.detail["method"]) == (interface, method)]
    return record


def test_vp1_hook_004_decisions_recorded_in_full(manager, sink):
    """ICD-GEN-041: each decision is on its invocation's record, every field
    of it, as the hook returned it (RES-OP-02)."""
    manager.establish(req())
    got = {(r.detail["interface"], r.detail["method"]): r.detail["returned"]
           for r in sink.of_type(RecordType.HOOK_INVOCATION)}
    assert got[("IF-PRI", "evaluate")] == {
        "level": 20, "scope": "public-safety", "preemption_capability": False,
        "preemption_vulnerability": True, "floor_priority": 80, "label": "normal"}
    assert got[("IF-SES", "decide")] == {
        "model": "on-demand", "auto_answer": False, "acknowledgement_required": False,
        "recording_required": True, "max_participants": 200}
    assert got[("IF-BER", "select")] == {
        "qos_identifier": 65, "arp_level": 5, "arp_preemption_capability": False,
        "arp_preemption_vulnerability": True, "redundancy": "single",
        "paths": [{"path_id": "default", "transport": "udp", "primary": True,
                   "weight": 1, "attributes": {}}]}
    assert got[("IF-SES", "floor_policy")] == {
        "initial_grant_to_initiator": True, "queueing_enabled": True,
        "override_allowed": True, "max_queue_depth": 8,
        "timers_ms": {"T2": 4000, "T20": 100, "T3": 3000, "T8": 1000}}
    assert got[("IF-IDR", "resolve")] == {
        "kind": "group", "group_id": "grp:alpha", "resolved_from": None,
        "members": [f"sip:u{i}@mcptt.example" for i in range(4)]}
    assert got[("IF-SES", "authorise")] == got[("IF-SES", "admit")] == {
        "permitted": True, "reason_code": ""}
    assert got[("IF-IDR", "identities_of")] == []
    # The session records keep their summary of the same decisions.
    admitted = sink.of_type(RecordType.SESSION_ADMITTED)[0].detail
    assert (admitted["priority"], admitted["scope"], admitted["members"]) == (
        "normal", "public-safety", 4)
    established = sink.of_type(RecordType.SESSION_ESTABLISHED)[0].detail
    assert (established["qos_identifier"], established["recording"]) == (65, True)
    assert established["members"] == tuple(f"sip:u{i}@mcptt.example" for i in range(4))


def test_vp1_hook_004_every_field_of_every_decision_type(manager, sink):
    """Nothing is picked: the record has exactly the value type's fields, so a
    field added to a decision is recorded without touching the core."""
    import dataclasses as dc
    from core.hooks import BearerDecision, FloorPolicy, PriorityDecision, SessionDecision
    manager.establish(req())
    for (iface, method), cls in {("IF-PRI", "evaluate"): PriorityDecision,
                                 ("IF-SES", "decide"): SessionDecision,
                                 ("IF-SES", "floor_policy"): FloorPolicy,
                                 ("IF-BER", "select"): BearerDecision}.items():
        returned = _returned_by(sink, iface, method).detail["returned"]
        assert set(returned) == {f.name for f in dc.fields(cls)}


def test_vp1_hook_004_the_record_serialises_as_it_was_returned(manager, sink):
    import json
    manager.establish(req())
    record = _returned_by(sink, "IF-BER", "select")
    assert json.loads(record.to_json())["detail"]["returned"] == record.detail["returned"]
    assert json.loads(record.to_json())["detail"]["returned"]["paths"][0]["primary"] is True


@pytest.mark.vp("VP1-HOOK-004")
def test_a_refused_decision_is_recorded_as_returned(mcx, sink):
    """A decision its POST refused is on the record too: the trail shows what
    the profile returned, not only that it was refused."""
    mgr = _altered(mcx, sink, floor=_floor(queueing_enabled=False, max_queue_depth=2))
    mgr.establish(req())
    record = _returned_by(sink, "IF-SES", "floor_policy")
    assert record.detail["outcome"] == "contract-violation"
    assert record.detail["returned"]["queueing_enabled"] is False
    assert record.detail["returned"]["max_queue_depth"] == 2


@pytest.mark.vp("VP1-HOOK-004")
def test_a_look_alike_is_named_not_rendered(mcx, sink):
    mgr = _altered(mcx, sink, bearer=lambda b: _Shaped(b))
    mgr.establish(req())
    assert _returned_by(sink, "IF-BER", "select").detail["returned"] == {
        "unrepresentable": "_Shaped"}


def test_nothing_is_recorded_as_returned_when_the_hook_returned_nothing(sink):
    inv = Invoker(Auditor(sink, "p/1/h"), "c1")

    def raises():
        raise ValueError("boom")

    def violates():
        raise HookContractViolation("the hook's own verdict")

    for fn in (raises, violates):
        with pytest.raises(HookFailure):
            inv.call("IF-SES", "decide", fn)
    assert [r.detail["outcome"] for r in sink.records] == ["error", "contract-violation"]
    assert all("returned" not in r.detail for r in sink.records)


class _LyingDict(dict):
    def __getitem__(self, k):
        return "not what the core reads"


class _EvilInt(int):
    def __deepcopy__(self, memo):
        raise RuntimeError("profile code ran inside the audit")


def _liar():
    """A PriorityDecision subclass that reads one way, then another: frozen,
    and so passes freeze(), but not the core's own class."""
    from core.hooks import PriorityDecision

    class Liar(PriorityDecision):
        reads = [0]

        def __getattribute__(self, name):
            if name == "preemption_capability":
                Liar.reads[0] += 1
                return Liar.reads[0] > 1
            return super().__getattribute__(name)

    return Liar


@pytest.mark.vp("VP1-HOOK-004")
@pytest.mark.parametrize("change,named", [
    (lambda p: _Shaped(p), "_Shaped"),
    (lambda p: _liar()(**{f: getattr(p, f) for f in (
        "level", "scope", "preemption_capability", "preemption_vulnerability",
        "floor_priority", "label")}), "Liar"),
    (lambda p: __import__("dataclasses").replace(p, level=float("nan")), "float nan"),
    (lambda p: __import__("dataclasses").replace(p, floor_priority=float("inf")), "float inf"),
    (lambda p: __import__("dataclasses").replace(p, level=_EvilInt(20)), "_EvilInt"),
], ids=["look-alike", "lying-subclass", "nan", "inf", "int-subclass"])
def test_a_priority_decision_the_audit_cannot_record_is_refused(mcx, sink, change, named):
    """ICD-GEN-041: a decision absent from the trail cannot be relied on, so
    one the audit cannot record exactly is not acted on (RES-OP-02 review)."""
    _refused_as_violation(_altered(mcx, sink, priority=change), sink, "IF-PRI")
    record = _returned_by(sink, "IF-PRI", "evaluate")
    assert record.detail["outcome"] == "contract-violation"
    assert named in sink.of_type(RecordType.SESSION_FAILED)[-1].detail["detail"]
    record.to_json()


@pytest.mark.vp("VP1-HOOK-004")
def test_a_session_decision_the_audit_cannot_record_is_refused(mcx, sink):
    import dataclasses as dc
    sp = mcx.hooks.session_policy

    class Session:
        def __getattr__(self, n):
            return getattr(sp, n)

        def decide(self, request, resolution):
            return _Shaped(sp.decide(request, resolution))

    lp = loader.LoadedProfile(profile=mcx.profile, source=mcx.source,
                              hooks=dc.replace(mcx.hooks, session_policy=Session()))
    resolver = mcx.hooks.identity_resolver
    for i in range(4):
        resolver.register_user(f"sip:u{i}@mcptt.example")
    resolver.register_group("grp:alpha", [f"sip:u{i}@mcptt.example" for i in range(4)])
    mgr = SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))
    session, _, refusal = mgr.establish(req())
    assert session is None and refusal.reason_code == "hook-contract-violation"
    assert _returned_by(sink, "IF-SES", "decide").detail["returned"] == {
        "unrepresentable": "_Shaped"}


def test_a_value_the_audit_cannot_render_is_refused_without_running_it(sink):
    from collections.abc import Mapping as AbcMapping

    class Hostile(AbcMapping):
        def __getitem__(self, k):
            raise RuntimeError("profile code ran inside the audit")

        def __iter__(self):
            raise RuntimeError("profile code ran inside the audit")

        def __len__(self):
            return 1

    with pytest.raises(HookFailure) as exc:
        Invoker(Auditor(sink, "p/1/h"), "c1").call("IF-SES", "decide", Hostile)
    assert exc.value.reason_code == "hook-contract-violation"
    assert "Hostile" in exc.value.detail
    [record] = sink.records
    assert record.detail["returned"] == {"unrepresentable": "Hostile"}


def test_a_value_its_post_check_crashed_on_is_still_recorded(sink):
    from core.hooks import Admission

    def post(_):
        raise AttributeError("the check itself broke")

    with pytest.raises(HookFailure) as exc:
        Invoker(Auditor(sink, "p/1/h"), "c1").call(
            "IF-SES", "admit", lambda: Admission(permitted=True, reason_code=""), post=post)
    assert exc.value.reason_code == "hook-error"
    [record] = sink.records
    assert record.detail["outcome"] == "error"
    assert record.detail["returned"] == {"permitted": True, "reason_code": ""}


def test_nothing_is_recorded_as_returned_on_a_timeout(sink):
    import time as _t
    inv = Invoker(Auditor(sink, "p/1/h"), "c1", budgets_ms={"IF-SES": 1},
                  mode=DeadlineMode.ENFORCE)
    with pytest.raises(HookFailure) as exc:
        inv.call("IF-SES", "decide", lambda: _t.sleep(0.2))
    assert exc.value.reason_code == "hook-timeout"
    [record] = sink.records
    assert record.detail["outcome"] == "timeout" and "returned" not in record.detail


def test_every_interface_has_its_icd_deadline():
    """ICD-GEN-010: IF-ICX had none (RES-OP-02 review)."""
    from core.invoke import DEFAULT_BUDGETS_MS
    assert dict(DEFAULT_BUDGETS_MS) == {"IF-IDR": 50, "IF-PRI": 5, "IF-SES": 5,
                                        "IF-BER": 10, "IF-IWF": 20, "IF-ICX": 20}


def test_render_keeps_only_exact_core_types():
    from enum import Enum
    from core.hooks import FrozenDict, PathSpec, SessionDecision, SessionModel
    from core.invoke import plain, render

    class Colour(Enum):
        RED = "red"

    class Str(str):
        pass

    assert render(None) == (None, ()) and render(True) == (True, ())
    assert render(2.5) == (2.5, ()) and render(-3) == (-3, ())
    assert plain(SessionModel.ON_DEMAND) == "on-demand"
    assert plain((1, [2, (3,)])) == [1, [2, [3]]]
    assert plain(frozenset({"b", "a", "c"})) == ["a", "b", "c"]
    assert plain(FrozenDict({"k": (1,)})) == {"k": [1]} == plain({"k": [1]})
    assert plain(PathSpec(path_id="p", transport="udp", primary=True)) == {
        "path_id": "p", "transport": "udp", "primary": True, "weight": 1,
        "attributes": {}}
    for value, named in [(Colour.RED, "Colour"), (Str("x"), "Str"), (b"01", "bytes"),
                         (1j, "complex"), (object(), "object"), (int, "type"),
                         (SessionDecision, "type"), (float("nan"), "float nan"),
                         ({1: "x"}, "mapping key of type int"), (_EvilInt(3), "_EvilInt"),
                         (("ok", {"k": Str("y")}), "Str"),
                         (__import__("collections").namedtuple("Pair", "a b")(1, 2), "Pair"),
                         (__import__("core.hooks", fromlist=["Value"]).Value(), "Value"),
                         (_LyingDict({"k": "v"}), "_LyingDict")]:
        assert render(value)[1] == (named,), value
    assert plain({"a": b"x", "b": 1})["a"] == {"unrepresentable": "bytes"}


def test_a_value_too_deep_to_render_is_unreadable_not_a_crash(sink):
    deep = ()
    for _ in range(100000):
        deep = (deep,)
    with pytest.raises(HookFailure) as exc:
        Invoker(Auditor(sink, "p/1/h"), "c1").call("IF-IDR", "identities_of", lambda: deep)
    assert exc.value.reason_code == "hook-contract-violation"
    assert sink.records[0].detail["returned"] == {"unrepresentable": "unreadable"}


@pytest.mark.vp("VP1-HOOK-004")
def test_each_comparison_is_an_audited_invocation(manager, sink, mcx):
    """compare decided pre-emption victims with no record (RES-OP-02 review)."""
    manager.establish(req(rid="normal-call"))
    emergency = mcx.hooks.priority_policy.evaluate(
        req(call_type="emergency-group"),
        Resolution(kind=ResolutionKind.USER, members=("x",)))
    sink.records.clear()
    assert [v.correlation_id for v in manager.preemption_victims(emergency, "urgent")] == [
        "normal-call"]
    [record] = sink.of_type(RecordType.HOOK_INVOCATION)
    assert (record.correlation_id, record.detail["interface"], record.detail["method"],
            record.detail["outcome"]) == ("urgent", "IF-PRI", "compare", "ok")
    assert record.detail["returned"] > 0


@pytest.mark.parametrize("result", [True, "1", 1.0, None])
def test_a_comparison_that_is_not_an_integer_is_a_contract_violation(manager, mcx, result):
    import dataclasses as dc
    manager.establish(req(rid="normal-call"))
    emergency = mcx.hooks.priority_policy.evaluate(
        req(call_type="emergency-group"),
        Resolution(kind=ResolutionKind.USER, members=("x",)))
    pp = mcx.hooks.priority_policy

    class Priority:
        def __getattr__(self, n):
            return getattr(pp, n)

        def compare(self, a, b):
            return result

    manager._hooks = dc.replace(mcx.hooks, priority_policy=Priority())
    with pytest.raises(HookFailure) as exc:
        manager.preemption_victims(emergency, "urgent")
    assert exc.value.reason_code == "hook-contract-violation"


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
    assert manager.preemption_victims(weak, "incoming") == ()


def test_preemption_selects_vulnerable_lower_priority_sessions(manager, mcx):
    manager.establish(req(rid="normal-call"))
    emergency = mcx.hooks.priority_policy.evaluate(
        req(call_type="emergency-group"),
        Resolution(kind=ResolutionKind.USER, members=("x",)))
    victims = manager.preemption_victims(emergency, "incoming")
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
    assert manager.preemption_victims(rail_emergency, "incoming") == ()


def test_non_vulnerable_session_is_never_a_victim(manager, mcx):
    manager.establish(req(call_type="emergency-group", rid="emergency"))
    another = mcx.hooks.priority_policy.evaluate(
        req(call_type="emergency-group"),
        Resolution(kind=ResolutionKind.USER, members=("x",)))
    assert manager.preemption_victims(another, "incoming") == ()


def test_higher_priority_still_cannot_preempt_a_non_vulnerable_session(manager):
    """Isolates the vulnerability guard: same scope, incoming strictly outranks,
    so `compare` alone would select it. Only the vulnerability flag stops it."""
    manager.establish(req(call_type="emergency-group", rid="emergency"))
    assert manager.session("emergency").priority.preemption_vulnerability is False
    overwhelming = PriorityDecision(level=255, scope="public-safety",
                                    preemption_capability=True,
                                    preemption_vulnerability=False,
                                    floor_priority=255, label="overwhelming")
    assert manager.preemption_victims(overwhelming, "incoming") == ()


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
        interworking_gateway=mcx.hooks.interworking_gateway,
        interconnection_gateway=mcx.hooks.interconnection_gateway)
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
    assert mgr.preemption_victims(foreign, "incoming") == ()


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


# --------------------------------------------------------------------------
# Deferred floor start (a host that must invite the other parties first)
# --------------------------------------------------------------------------


def test_deferred_floor_is_built_but_not_started(mcx, sink):
    resolver = mcx.hooks.identity_resolver
    for i in range(3):
        resolver.register_user(f"sip:u{i}@mcptt.example")
    resolver.register_group("grp:x", [f"sip:u{i}@mcptt.example" for i in range(3)])
    m = SessionManager(mcx, Auditor(sink, mcx.profile.identifier(), clock=Clock()),
                       clock=Clock(), defer_floor_start=True)
    session, _, _ = m.establish(req(target="grp:x"))
    assert session.floor is not None
    assert session.floor.state.value == "start-stop"
    assert session.floor.running_timers() == {}
    actions = m.start_floor("s1")
    assert session.floor.holder == "sip:u0@mcptt.example" and actions
    assert m.start_floor("s1") == ()          # idempotent
    assert m.start_floor("nope") == ()


def test_start_floor_is_a_no_op_for_a_session_without_a_floor(manager):
    session, _, _ = manager.establish(req(call_type="sds", target="grp:alpha",
                                          media=(MediaKind.DATA,)))
    assert session.floor is None
    assert manager.start_floor("s1") == ()


# -- ICD-OP-09: IF-SES.authorise, before the target is looked up (§8.1 step 0) --


def _with_policy(mcx, sink, **override):
    """The mcx hooks, with the session policy's methods replaced by `override`."""
    base = mcx.hooks.session_policy

    class Policy:
        def __getattr__(self, name):
            return override.get(name) or getattr(base, name)

    for i in range(4):
        mcx.hooks.identity_resolver.register_user(f"sip:u{i}@mcptt.example")
    hooks = loader.LoadedHooks(
        identity_resolver=mcx.hooks.identity_resolver,
        priority_policy=mcx.hooks.priority_policy,
        session_policy=Policy(),
        bearer_selector=mcx.hooks.bearer_selector,
        interworking_gateway=mcx.hooks.interworking_gateway,
        interconnection_gateway=mcx.hooks.interconnection_gateway)
    lp = loader.LoadedProfile(profile=mcx.profile, hooks=hooks, source=mcx.source)
    return SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))


def test_a_refused_authorisation_stops_before_resolution(mcx, sink):
    from core.hooks import Admission
    mgr = _with_policy(mcx, sink, authorise=lambda r: Admission(False, "not-authorised"))
    session, _, refusal = mgr.establish(req(call_type="private",
                                            target="sip:u1@mcptt.example"))
    assert session is None and refusal.reason_code == "not-authorised"
    calls = [r.detail["method"] for r in sink.of_type(RecordType.HOOK_INVOCATION)]
    assert calls == ["identities_of", "authorise"]


def test_authorise_sees_the_roles_the_core_looked_up_not_the_requests(mcx, sink):
    seen = {}

    def authorise(r):
        from core.hooks import Admission
        seen.update(r.attributes)
        seen["_request"] = r
        return Admission(True, "")
    mgr = _with_policy(mcx, sink, authorise=authorise)
    mgr.establish(req(call_type="private", target="sip:u1@mcptt.example",
                      attributes={"initiator.roles": "dispatcher"}))
    assert seen["initiator.roles"] == ""        # u0 holds no functional identity
    assert "core.active_sessions" not in seen   # capacity is admit's, not authorise's


def test_authorise_cannot_see_who_is_called(mcx, sink):
    """§5.0 INV-1, structural: every field naming or selecting the called
    party is emptied before authorise sees the request (review of ICD-OP-09)."""
    seen = []

    def authorise(r):
        from core.hooks import Admission
        seen.append(r)
        return Admission(True, "")
    mgr = _with_policy(mcx, sink, authorise=authorise)
    mgr.establish(req(call_type="private", target="sip:u1@mcptt.example",
                      participants=("sip:u2@mcptt.example",),
                      participant_criteria="anyone", adhoc_alert_group=True))
    (r,) = seen
    assert (r.target, tuple(r.participants), r.participant_criteria,
            r.adhoc_alert_group) == ("", (), None, False)
    assert (r.initiator, r.call_type) == ("sip:u0@mcptt.example", "private")


def test_no_hook_sees_roles_the_request_carried(mcx, sink):
    """The core writes `initiator.roles` once, before step 0; every hook after
    that sees the core's value (review of ICD-OP-09: resolve and decide used
    to see the client's)."""
    from core.hooks import Admission
    seen = {}
    r_ = mcx.hooks.identity_resolver
    orig = r_.resolve

    def resolve(target, request):
        seen["resolve"] = request.attributes.get("initiator.roles")
        return orig(target, request)
    r_.resolve = resolve
    base = mcx.hooks.session_policy

    def decide(request, res):
        seen["decide"] = request.attributes.get("initiator.roles")
        return base.decide(request, res)
    mgr = _with_policy(mcx, sink, decide=decide)
    session, _, _ = mgr.establish(req(call_type="private", target="sip:u1@mcptt.example",
                                      attributes={"initiator.roles": "dispatcher"}))
    assert seen == {"resolve": "", "decide": ""}
    assert session.request.attributes["initiator.roles"] == ""


def test_admit_on_an_undeclared_call_type_is_a_contract_violation(mcx):
    """A subclass whose authorise lets through what the table lacks is a
    profile defect, reported as one (review of ICD-OP-09)."""
    res = Resolution(kind=ResolutionKind.USER, members=("sip:a@mcptt.example",))
    prio = mcx.hooks.priority_policy.evaluate(req(call_type="private"), res)
    with pytest.raises(HookContractViolation) as exc:
        mcx.hooks.session_policy.admit(req(call_type="nope"), res, prio)
    assert "undeclared call type 'nope'" in str(exc.value)


@pytest.mark.parametrize("method", ["authorise", "admit"])
@pytest.mark.parametrize("permitted, code", [
    (True, "not-authorised"),        # a permission carrying a code
    (False, ""),                     # a refusal without one
    (False, "made-up-code"),         # a refusal with a code nobody declared
])
def test_an_ill_formed_admission_is_a_contract_violation(mcx, sink, method, permitted, code):
    """§5.1 POST-2 and POST-3, checked by the core for both methods."""
    from core.errors import HOOK_CONTRACT_VIOLATION
    from core.hooks import Admission
    bad = lambda *a: Admission(permitted, code)      # noqa: E731
    mgr = _with_policy(mcx, sink, **{method: bad})
    session, _, refusal = mgr.establish(req(call_type="private",
                                            target="sip:u1@mcptt.example"))
    assert session is None and refusal.reason_code == HOOK_CONTRACT_VIOLATION


def test_the_table_policy_splits_authorisation_from_admission():
    """authorise: the call type and the initiator's roles. admit: what
    depends on the target. Pinned for the frmcs shunting call type."""
    from core.hooks import Admission
    frmcs = loader.load(PROFILES / "frmcs")
    policy = frmcs.hooks.session_policy

    def r(roles):
        return req(call_type="shunting-group", target="adhoc",
                   attributes={"initiator.roles": roles})
    assert policy.authorise(r("")) == Admission(False, "not-authorised")
    assert policy.authorise(r("train-driver,x")) == Admission(False, "not-authorised")
    assert policy.authorise(r("shunting-team-leader")) == Admission(True, "")
    assert policy.authorise(req(call_type="nope")) == \
        Admission(False, "call-type-not-permitted")
    # admit no longer re-checks roles: authorise did.
    res = Resolution(kind=ResolutionKind.GROUP, group_id="g",
                     members=("sip:a@frmcs.example",))
    prio = frmcs.hooks.priority_policy.evaluate(r(""), res)
    assert policy.admit(r(""), res, prio) == Admission(True, "")


def test_admit_sees_the_same_roles_and_the_capacity(mcx, sink):
    """§5.1: admission keeps the roles authorisation saw (a profile may still
    read them there), and gains the session count."""
    seen = {}
    base = mcx.hooks.session_policy

    def admit(r, res, prio):
        seen.update(r.attributes)
        return base.admit(r, res, prio)
    mgr = _with_policy(mcx, sink, admit=admit)
    mgr.establish(req(call_type="private", target="sip:u1@mcptt.example",
                      attributes={"initiator.roles": "forged"}))
    assert seen["initiator.roles"] == "" and seen["core.active_sessions"] == "0"
