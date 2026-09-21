"""TS-ICX — interconnection with a partner MC system.

The risk this suite exists for: interconnection is the one place where a system
outside your control can obtain authority inside yours. Unlike the shared-IWF
case, where two scopes contend outside both guarantees, here a partner's session
runs INSIDE your scope with whatever rights you mapped it to — and it will look
entirely correct in the audit trail.

So most of these tests are adversarial: they assert what a partner CANNOT do.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.audit import Auditor, MemorySink, RecordType  # noqa: E402
from core.errors import ProfileValidationError  # noqa: E402
from core.hooks import MediaKind, ResolutionKind, SessionRequest  # noqa: E402
from core.session import SessionManager, SignalType  # noqa: E402
from core.validation import build  # noqa: E402
from profiles.common.tables import PartnerMappingFailure  # noqa: E402

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
def frmcs():
    return loader.load(PROFILES / "frmcs")


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


@pytest.fixture
def raw_mcx():
    def _load():
        return copy.deepcopy(
            yaml.safe_load((PROFILES / "mcx" / "profile.yaml").read_text()))
    return _load


def req(target, call_type="private", rid="p1",
        initiator="sip:u0@mcptt.example", media=(MediaKind.VOICE,), **kw):
    return SessionRequest(request_id=rid, initiator=initiator, target=target,
                          call_type=call_type, media=media, **kw)


def types(signals):
    return [s.type for s in signals]


# --------------------------------------------------------------------------
# Routing
# --------------------------------------------------------------------------


def test_partner_target_resolves_as_partner_not_external(wired):
    """A partner MC system speaks MC protocols natively. Mistaking it for a
    legacy system would route it through translation it does not need."""
    manager, _, _ = wired
    session, _, refusal = manager.establish(req("icx:rail:sip:c1@frmcs.example"))
    assert refusal is None
    assert session.resolution.kind is ResolutionKind.PARTNER


def test_partner_session_invites_only_the_partner_gateway(wired):
    manager, _, _ = wired
    session, signals, _ = manager.establish(req("icx:rail:sip:c1@frmcs.example"))
    invites = [s for s in signals if s.type is SignalType.INVITE]
    assert len(invites) == 1
    assert invites[0].target == "sip:icx@frmcs.example"
    assert session.partner_id == "rail-operator"
    assert session.members == ()


def test_partner_route_records_the_trust_mechanism(wired):
    """A partner identity taken from an unauthenticated header is not an
    identity, so the mechanism travels with the route."""
    manager, _, _ = wired
    _, signals, _ = manager.establish(req("icx:rail:sip:c1@frmcs.example"))
    routed = [s for s in signals if s.type is SignalType.ROUTE_PARTNER]
    assert len(routed) == 1
    assert routed[0].detail["partner_id"] == "rail-operator"
    assert routed[0].detail["trust"] == "mutual-tls"


def test_local_session_never_consults_the_interconnection_hook(wired):
    manager, sink, _ = wired
    manager.establish(req("grp:alpha", call_type="prearranged-group"))
    interfaces = [r.detail["interface"]
                  for r in sink.of_type(RecordType.HOOK_INVOCATION)]
    assert "IF-ICX" not in interfaces


def test_call_type_not_allowed_with_partner_is_refused(wired):
    """The MCX profile permits only private and prearranged-group toward the
    partner. An emergency group call must not leave the system."""
    manager, _, _ = wired
    session, signals, refusal = manager.establish(
        req("icx:rail:sip:c1@frmcs.example", call_type="emergency-group"))
    assert session is None
    assert refusal.reason_code == "partner-not-permitted"
    assert SignalType.INVITE not in types(signals)


def test_outbound_assertion_is_advisory_and_labelled(wired):
    manager, _, _ = wired
    _, signals, _ = manager.establish(req("icx:rail:sip:c1@frmcs.example"))
    invite = [s for s in signals if s.type is SignalType.INVITE][0]
    asserted = invite.detail["asserted"]
    assert asserted["system"] == "mcx"
    assert asserted["label"] == "normal-private"
    assert asserted["scope"] == "public-safety"


# --------------------------------------------------------------------------
# Inbound priority mapping — the adversarial core of the design
# --------------------------------------------------------------------------


def test_partner_level_is_never_read(mcx):
    """A partner's own level is meaningless here. Mapping is keyed on LABEL;
    an asserted level must have no effect whatsoever."""
    icx = mcx.hooks.interconnection_gateway
    modest = icx.map_inbound_priority("rail-operator",
                                      {"label": "operational", "level": "5"})
    inflated = icx.map_inbound_priority("rail-operator",
                                        {"label": "operational", "level": "999"})
    assert modest == inflated
    assert modest.level == 25


def test_mapping_is_capped_by_the_declared_ceiling(mcx):
    icx = mcx.hooks.interconnection_gateway
    rights = icx.rights("rail-operator")
    for entry_label in ("railway-emergency", "etcs-data", "operational"):
        decision = icx.map_inbound_priority("rail-operator",
                                            {"label": entry_label})
        assert decision.level <= rights.max_level


def test_partner_cannot_outrank_a_local_emergency(mcx):
    """The ceiling is set below the local emergency level on purpose. A partner
    system's most urgent traffic must not displace local emergency traffic."""
    icx = mcx.hooks.interconnection_gateway
    mapped = icx.map_inbound_priority("rail-operator",
                                      {"label": "railway-emergency"})
    local_emergency = next(r.decision for r in mcx.profile.priority.rules
                           if r.decision.label == "emergency")
    assert mapped.level < local_emergency.level


def test_partner_session_occupies_a_local_scope(mcx):
    """A partner never introduces a scope of its own: it is arbitrated by local
    rules, in a local scope, or the scope guarantee means nothing."""
    icx = mcx.hooks.interconnection_gateway
    mapped = icx.map_inbound_priority("rail-operator", {"label": "operational"})
    assert mapped.scope in {s.id for s in mcx.profile.preemption_scopes}
    assert mapped.scope == "public-safety"


def test_partner_cannot_preempt_unless_explicitly_granted(mcx):
    icx = mcx.hooks.interconnection_gateway
    for label in ("railway-emergency", "etcs-data", "operational"):
        mapped = icx.map_inbound_priority("rail-operator", {"label": label})
        assert mapped.preemption_capability is False


def test_partner_session_is_always_locally_vulnerable(mcx):
    """A foreign session must never be harder to displace than a local one."""
    icx = mcx.hooks.interconnection_gateway
    mapped = icx.map_inbound_priority("rail-operator",
                                      {"label": "railway-emergency"})
    assert mapped.preemption_vulnerability is True


def test_unmapped_label_is_refused_not_defaulted(mcx):
    """No mapping means no authority. A default would grant a partner a level
    nobody chose for it."""
    icx = mcx.hooks.interconnection_gateway
    with pytest.raises(PartnerMappingFailure) as exc:
        icx.map_inbound_priority("rail-operator", {"label": "something-new"})
    assert exc.value.reason_code == "partner-not-permitted"


def test_undeclared_partner_gets_nothing(mcx):
    """An unknown partner must not be more powerful than a declared one."""
    from core.errors import HookContractViolation
    icx = mcx.hooks.interconnection_gateway
    with pytest.raises(HookContractViolation):
        icx.rights("some-other-system")
    with pytest.raises(HookContractViolation):
        icx.map_inbound_priority("some-other-system", {"label": "operational"})


def test_the_two_profiles_declare_asymmetric_rights(mcx, frmcs):
    """Each operator declares what the OTHER may do here. The two need not
    agree, and in a real deployment they will not."""
    ps_view = mcx.hooks.interconnection_gateway.rights("rail-operator")
    rail_view = frmcs.hooks.interconnection_gateway.rights(
        "public-safety-operator")
    assert ps_view.scope != rail_view.scope
    assert ps_view.max_level != rail_view.max_level
    assert ps_view.allowed_call_types != rail_view.allowed_call_types


def test_partner_cannot_outrank_railway_emergency_in_the_rail_system(frmcs):
    icx = frmcs.hooks.interconnection_gateway
    mapped = icx.map_inbound_priority("public-safety-operator",
                                      {"label": "emergency"})
    rail_emergency = next(r.decision for r in frmcs.profile.priority.rules
                          if r.decision.label == "railway-emergency")
    assert mapped.level < rail_emergency.level
    assert mapped.preemption_capability is False


# --------------------------------------------------------------------------
# Validation of the scope-mapping model
# --------------------------------------------------------------------------


def test_mapping_above_the_ceiling_is_rejected(raw_mcx):
    raw = raw_mcx()
    raw["interconnection"]["partners"][0]["inbound"]["priority_map"][0]["to_level"] = 95
    with pytest.raises(ProfileValidationError) as exc:
        build(raw, "h")
    assert any("exceeds the partner ceiling" in d.message for d in exc.value.defects)


def test_undeclared_partner_scope_is_rejected(raw_mcx):
    raw = raw_mcx()
    raw["interconnection"]["partners"][0]["inbound"]["scope"] = "railway"
    with pytest.raises(ProfileValidationError) as exc:
        build(raw, "h")
    assert any(d.code == "unresolved-reference" and "scope" in d.path
               for d in exc.value.defects)


def test_undeclared_allowed_call_type_is_rejected(raw_mcx):
    raw = raw_mcx()
    raw["interconnection"]["partners"][0]["inbound"]["allowed_call_types"] = \
        ["rec-broadcast"]
    with pytest.raises(ProfileValidationError) as exc:
        build(raw, "h")
    assert any("allowed_call_types" in d.path for d in exc.value.defects)


def test_empty_priority_map_is_rejected(raw_mcx):
    """A partner with no mapping cannot be given a local priority at all."""
    raw = raw_mcx()
    raw["interconnection"]["partners"][0]["inbound"]["priority_map"] = []
    with pytest.raises(ProfileValidationError) as exc:
        build(raw, "h")
    assert any("priority_map" in d.path for d in exc.value.defects)


def test_unknown_trust_mechanism_is_rejected(raw_mcx):
    raw = raw_mcx()
    raw["interconnection"]["partners"][0]["trust"] = "trust-me"
    with pytest.raises(ProfileValidationError) as exc:
        build(raw, "h")
    assert any("trust" in d.path for d in exc.value.defects)


def test_duplicate_partner_prefix_is_rejected(raw_mcx):
    raw = raw_mcx()
    partner = copy.deepcopy(raw["interconnection"]["partners"][0])
    partner["id"] = "second-operator"
    raw["interconnection"]["partners"].append(partner)
    with pytest.raises(ProfileValidationError) as exc:
        build(raw, "h")
    assert any(d.code == "duplicate" for d in exc.value.defects)


def test_duplicate_from_label_is_rejected(raw_mcx):
    raw = raw_mcx()
    entries = raw["interconnection"]["partners"][0]["inbound"]["priority_map"]
    entries.append(copy.deepcopy(entries[0]))
    with pytest.raises(ProfileValidationError) as exc:
        build(raw, "h")
    assert any(d.code == "duplicate" and "from_label" in d.path
               for d in exc.value.defects)


def test_a_profile_without_interconnection_is_valid(raw_mcx):
    """PLT-HOK-052's analogue: no partners declared is a valid deployment."""
    raw = raw_mcx()
    del raw["interconnection"]
    profile = build(raw, "h")
    assert profile.interconnection is None
    assert profile.partner("anything") is None


def test_no_interconnection_means_no_partner_resolution(raw_mcx):
    from profiles.common.tables import DirectoryResolver, ResolutionFailure
    raw = raw_mcx()
    del raw["interconnection"]
    resolver = DirectoryResolver(build(raw, "h"))
    with pytest.raises(ResolutionFailure) as exc:
        resolver.resolve("icx:rail:sip:c1@frmcs.example",
                         req("icx:rail:sip:c1@frmcs.example"))
    assert exc.value.reason_code == "unknown-target"


# --------------------------------------------------------------------------
# Defence in depth — each guard tested with the other layers disabled
# --------------------------------------------------------------------------


def test_runtime_ceiling_holds_when_validation_is_bypassed(mcx):
    """Isolates the runtime cap.

    Validation rejects a mapping above the ceiling, so the `min()` in the hook
    looks redundant — until a profile object reaches the runtime without having
    passed this validator: a hand-built object, a future loader, a profile
    edited in place. The ceiling is the security property; it gets two layers.
    """
    from core import model
    from profiles.common.tables import TableInterconnectionGateway

    partner = model.PartnerConfig(
        id="rogue", domains=("elsewhere.example",), target_prefix="icx:x:",
        gateway="sip:gw@elsewhere.example", trust="mutual-tls",
        inbound_scope="public-safety",
        inbound_max_level=60,
        inbound_may_preempt=False,
        inbound_allowed_call_types=("private",),
        # Deliberately above the ceiling — what validation would have refused.
        inbound_priority_map=(
            model.PriorityMapEntry(from_label="anything", to_level=255,
                                   to_label="inflated"),),
        outbound_assert_label=True)
    import dataclasses
    tampered = dataclasses.replace(
        mcx.profile,
        interconnection=model.Interconnection(partners=(partner,)))

    icx = TableInterconnectionGateway(tampered)
    mapped = icx.map_inbound_priority("rogue", {"label": "anything"})
    assert mapped.level == 60, "runtime ceiling did not cap an over-range mapping"


def test_partner_cannot_assert_its_own_scope(mcx):
    """Isolates the scope guard. A partner asserting a scope it uses at home
    must still land in the LOCAL scope its rights declare — otherwise a foreign
    system could introduce a scope and escape local arbitration entirely."""
    icx = mcx.hooks.interconnection_gateway
    mapped = icx.map_inbound_priority(
        "rail-operator", {"label": "operational", "scope": "railway"})
    assert mapped.scope == "public-safety"


def test_partner_target_without_a_route_is_refused_not_localised(wired, mcx):
    """Isolates the routing guard, the analogue of gateway-unavailable: a
    partner target that produces no route must never fall back to local
    establishment, which would deliver the call to the wrong party."""
    class NoPartnerRoute:
        def __init__(self, profile):
            self._profile = profile

        def route(self, request, resolution):
            return None

        def rights(self, partner_id):
            raise AssertionError("must not be reached")

        def map_inbound_priority(self, partner_id, asserted):
            raise AssertionError("must not be reached")

        def map_outbound(self, request, priority):
            return {}

    hooks = loader.LoadedHooks(
        identity_resolver=mcx.hooks.identity_resolver,
        priority_policy=mcx.hooks.priority_policy,
        session_policy=mcx.hooks.session_policy,
        bearer_selector=mcx.hooks.bearer_selector,
        interworking_gateway=mcx.hooks.interworking_gateway,
        interconnection_gateway=NoPartnerRoute(mcx.profile))
    lp = loader.LoadedProfile(profile=mcx.profile, hooks=hooks, source=mcx.source)
    sink = MemorySink()
    mgr = SessionManager(lp, Auditor(sink, mcx.profile.identifier(), clock=Clock()))

    session, signals, refusal = mgr.establish(req("icx:rail:sip:c1@frmcs.example"))
    assert session is None
    assert refusal.reason_code == "partner-unavailable"
    assert SignalType.INVITE not in types(signals)
