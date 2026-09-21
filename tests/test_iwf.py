"""TS-IWF — interworking with a non-MC system.

Covers the defect this suite exists because of: before the EXTERNAL resolution
kind, IF-IWF was unreachable through the session manager. An external target
died at IF-IDR with `unknown-target` and the gateway hook was never called. The
old tests passed only because they invoked `route()` directly.

Every test here goes through `SessionManager`, never straight to the hook.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.audit import Auditor, MemorySink, RecordType  # noqa: E402
from core.hooks import MediaKind, ResolutionKind, SessionRequest  # noqa: E402
from core.session import SessionManager, SessionState, SignalType  # noqa: E402
from core.sip import Adapter, DialogContext, Status  # noqa: E402

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
def wired(mcx):
    resolver = mcx.hooks.identity_resolver
    for i in range(3):
        resolver.register_user(f"sip:u{i}@mcptt.example")
    resolver.register_group("grp:alpha", [f"sip:u{i}@mcptt.example"
                                          for i in range(3)])
    sink = MemorySink()
    auditor = Auditor(sink, mcx.profile.identifier(), clock=Clock())
    return SessionManager(mcx, auditor, clock=Clock()), sink, mcx


def req(target, call_type="private", rid="x1",
        initiator="sip:u0@mcptt.example", media=(MediaKind.VOICE,), **kw):
    return SessionRequest(request_id=rid, initiator=initiator, target=target,
                          call_type=call_type, media=media, **kw)


def types(signals):
    return [s.type for s in signals]


# --------------------------------------------------------------------------
# Outbound — the regression the EXTERNAL kind exists to prevent
# --------------------------------------------------------------------------


def test_external_target_reaches_the_interworking_hook(wired):
    """REGRESSION: this failed with `unknown-target` before the fix."""
    manager, sink, _ = wired
    session, signals, refusal = manager.establish(req("tetra:1234"))
    assert refusal is None, f"external target refused: {refusal}"
    assert session is not None
    interfaces = [r.detail["interface"]
                  for r in sink.of_type(RecordType.HOOK_INVOCATION)]
    assert "IF-IWF" in interfaces


def test_external_resolution_carries_no_members(wired):
    manager, _, _ = wired
    session, _, _ = manager.establish(req("tetra:1234"))
    assert session.resolution.kind is ResolutionKind.EXTERNAL
    assert session.resolution.members == ()
    assert session.resolution.resolved_from == "tetra:1234"


def test_routed_session_invites_only_the_gateway(wired):
    """A routed session must not ALSO fan out locally: doing both would place
    the same call twice."""
    manager, _, _ = wired
    session, signals, _ = manager.establish(req("tetra:1234"))
    invites = [s for s in signals if s.type is SignalType.INVITE]
    assert len(invites) == 1
    assert invites[0].target == "sip:iwf@mcptt.example"
    assert invites[0].detail["external_target"] == "tetra:1234"
    assert session.gateway == "sip:iwf@mcptt.example"
    assert session.members == ()


def test_routed_session_emits_a_route_signal(wired):
    manager, _, _ = wired
    _, signals, _ = manager.establish(req("tetra:1234"))
    routes = [s for s in signals if s.type is SignalType.ROUTE_EXTERNAL]
    assert len(routes) == 1
    assert routes[0].detail["system"] == "tetra"


def test_local_session_never_consults_the_gateway(wired):
    """IF-IWF is consulted only for an EXTERNAL resolution, so a local call
    pays nothing for interworking being configured."""
    manager, sink, _ = wired
    manager.establish(req("grp:alpha", call_type="prearranged-group"))
    interfaces = [r.detail["interface"]
                  for r in sink.of_type(RecordType.HOOK_INVOCATION)]
    assert "IF-IWF" not in interfaces


def test_unrouted_external_target_is_refused_not_localised(wired, mcx):
    """If the resolver calls a target foreign and no gateway is produced, the
    only safe answer is refusal: falling back to local establishment would
    deliver the call to the wrong party."""
    manager, _, _ = wired

    class NoRoute:
        def __init__(self, profile):
            pass

        def route(self, request, resolution):
            return None

        def map_inbound(self, foreign):
            raise NotImplementedError

    hooks = loader.LoadedHooks(
        identity_resolver=mcx.hooks.identity_resolver,
        priority_policy=mcx.hooks.priority_policy,
        session_policy=mcx.hooks.session_policy,
        bearer_selector=mcx.hooks.bearer_selector,
        interworking_gateway=NoRoute(mcx.profile),
        interconnection_gateway=mcx.hooks.interconnection_gateway)
    lp = loader.LoadedProfile(profile=mcx.profile, hooks=hooks, source=mcx.source)
    sink = MemorySink()
    mgr = SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))

    session, signals, refusal = mgr.establish(req("tetra:1234"))
    assert session is None
    assert refusal.reason_code == "gateway-unavailable"
    assert SignalType.INVITE not in types(signals)


def test_routed_session_still_passes_priority_and_admission(wired, sink=None):
    """Interworking does not bypass policy: a routed session is prioritised and
    admitted exactly like a local one."""
    manager, sink, _ = wired
    manager.establish(req("tetra:1234"))
    calls = [(r.detail["interface"], r.detail["method"])
             for r in sink.of_type(RecordType.HOOK_INVOCATION)]
    assert ("IF-PRI", "evaluate") in calls
    assert ("IF-SES", "admit") in calls
    assert ("IF-BER", "select") in calls


def test_routed_session_releases_toward_the_gateway(wired):
    manager, _, _ = wired
    manager.establish(req("tetra:1234"))
    signals = manager.release("x1")
    byes = [s for s in signals if s.type is SignalType.BYE]
    assert [b.target for b in byes] == ["sip:iwf@mcptt.example"]


def test_a_profile_without_interworking_produces_no_external_resolution():
    """PLT-HOK-052: a profile declaring no interworking is valid and routes
    nothing; an unknown target stays unknown."""
    import copy
    import yaml
    from core.validation import build
    from profiles.common.tables import DirectoryResolver, ResolutionFailure

    raw = yaml.safe_load((PROFILES / "mcx" / "profile.yaml").read_text())
    raw = copy.deepcopy(raw)
    del raw["interworking"]
    profile = build(raw, "h")
    resolver = DirectoryResolver(profile)
    with pytest.raises(ResolutionFailure) as exc:
        resolver.resolve("tetra:1234", req("tetra:1234"))
    assert exc.value.reason_code == "unknown-target"


# --------------------------------------------------------------------------
# Inbound
# --------------------------------------------------------------------------


def test_inbound_request_is_mapped_and_established(wired):
    manager, sink, _ = wired
    session, signals, refusal = manager.receive_inbound({
        "request_id": "in1", "call_type": "private",
        "initiator": "sip:u0@mcptt.example", "target": "sip:u1@mcptt.example",
        "system": "tetra"})
    assert refusal is None
    assert session is not None
    assert session.state is SessionState.ESTABLISHED
    interfaces = [r.detail["interface"]
                  for r in sink.of_type(RecordType.HOOK_INVOCATION)]
    assert interfaces[0] == "IF-IWF"          # map_inbound first
    assert "IF-IDR" in interfaces             # then the ordinary sequence


def test_inbound_gets_no_privilege_from_the_gateway(wired):
    """PLT-ICD-001 §7.2 INV-1: a mapped request is admitted like any other."""
    manager, _, _ = wired
    session, _, refusal = manager.receive_inbound({
        "request_id": "in2", "call_type": "private",
        "initiator": "sip:u0@mcptt.example", "target": "sip:nobody@mcptt.example",
        "system": "tetra"})
    assert session is None
    assert refusal.reason_code == "unknown-target"


def test_inbound_priority_assertion_is_advisory(wired):
    """A foreign system that could set its own priority could pre-empt local
    emergency calls. IF-PRI decides, from the mapped request."""
    manager, _, mcx = wired
    session, _, _ = manager.receive_inbound({
        "request_id": "in3", "call_type": "private",
        "initiator": "sip:u0@mcptt.example", "target": "sip:u1@mcptt.example",
        "system": "tetra", "priority": "255"})
    expected = mcx.profile.call_type("private")
    assert session.priority.label == "normal-private"
    assert session.priority.preemption_capability is False
    assert expected is not None


def test_inbound_with_an_undeclared_call_type_is_rejected(wired):
    manager, _, _ = wired
    session, _, refusal = manager.receive_inbound({
        "request_id": "in4", "call_type": "rec-broadcast",
        "initiator": "sip:u0@mcptt.example", "target": "sip:u1@mcptt.example",
        "system": "tetra"})
    assert session is None
    assert refusal.reason_code == "hook-contract-violation"


def test_inbound_from_an_undeclared_domain_is_rejected(wired):
    manager, _, _ = wired
    session, _, refusal = manager.receive_inbound({
        "request_id": "in5", "call_type": "private",
        "initiator": "sip:intruder@elsewhere.example",
        "target": "sip:u1@mcptt.example", "system": "tetra"})
    assert session is None
    assert refusal.reason_code == "hook-contract-violation"


def test_inbound_is_audited_with_its_source(wired):
    manager, sink, _ = wired
    manager.receive_inbound({
        "request_id": "in6", "call_type": "private",
        "initiator": "sip:u0@mcptt.example", "target": "sip:u1@mcptt.example",
        "system": "tetra"})
    admitted = sink.of_type(RecordType.SESSION_ADMITTED)
    assert any(r.detail.get("inbound_from") == "tetra" for r in admitted)


# --------------------------------------------------------------------------
# SIP rendering of a routed session
# --------------------------------------------------------------------------


def test_routed_invite_renders_toward_the_gateway(wired):
    manager, _, _ = wired
    request = req("tetra:1234")
    _, signals, _ = manager.establish(request)
    adapter = Adapter("sip:server@mcptt.example")
    ctx = DialogContext(call_id="x1", local_uri="sip:server@mcptt.example")
    invites = [adapter.render(s, ctx, request) for s in signals
               if s.type is SignalType.INVITE]
    assert len(invites) == 1
    assert invites[0].uri == "sip:iwf@mcptt.example"


def test_gateway_unavailable_renders_as_service_unavailable():
    adapter = Adapter("sip:server@mcptt.example")
    ctx = DialogContext(call_id="x", local_uri="sip:server@mcptt.example")
    assert adapter.reject("gateway-unavailable", ctx).status is \
        Status.SERVICE_UNAVAILABLE


def test_external_resolution_with_members_is_a_contract_violation(wired, mcx):
    """A session has either members or a gateway, never both. A resolver that
    returns EXTERNAL *and* a member set has broken §3.2, and establishing it
    would place the call locally and externally at once."""
    from core.hooks import Resolution

    class Contradictory:
        def __init__(self, profile):
            pass

        def resolve(self, target, request):
            return Resolution(kind=ResolutionKind.EXTERNAL,
                              members=("sip:u1@mcptt.example",),
                              resolved_from=target)

        def bind(self, i, s, l):
            pass

        def unbind(self, i, s):
            pass

        def identities_of(self, s):
            return ()

    hooks = loader.LoadedHooks(
        identity_resolver=Contradictory(mcx.profile),
        priority_policy=mcx.hooks.priority_policy,
        session_policy=mcx.hooks.session_policy,
        bearer_selector=mcx.hooks.bearer_selector,
        interworking_gateway=mcx.hooks.interworking_gateway,
        interconnection_gateway=mcx.hooks.interconnection_gateway)
    lp = loader.LoadedProfile(profile=mcx.profile, hooks=hooks, source=mcx.source)
    sink = MemorySink()
    mgr = SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))

    session, signals, refusal = mgr.establish(req("tetra:1234"))
    assert session is None
    assert refusal.reason_code == "hook-contract-violation"
    assert SignalType.INVITE not in types(signals)


def test_external_resolution_without_resolved_from_is_a_contract_violation(mcx):
    """The foreign target must be recorded for audit (PLT-HOK-014)."""
    from core.hooks import Resolution

    class Forgetful:
        def __init__(self, profile):
            pass

        def resolve(self, target, request):
            return Resolution(kind=ResolutionKind.EXTERNAL, members=())

        def bind(self, i, s, l):
            pass

        def unbind(self, i, s):
            pass

        def identities_of(self, s):
            return ()

    hooks = loader.LoadedHooks(
        identity_resolver=Forgetful(mcx.profile),
        priority_policy=mcx.hooks.priority_policy,
        session_policy=mcx.hooks.session_policy,
        bearer_selector=mcx.hooks.bearer_selector,
        interworking_gateway=mcx.hooks.interworking_gateway,
        interconnection_gateway=mcx.hooks.interconnection_gateway)
    lp = loader.LoadedProfile(profile=mcx.profile, hooks=hooks, source=mcx.source)
    sink = MemorySink()
    mgr = SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))

    session, _, refusal = mgr.establish(req("tetra:1234"))
    assert session is None
    assert refusal.reason_code == "hook-contract-violation"
