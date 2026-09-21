"""Table-driven hook implementations shared by profile authors.

This is a library FOR profiles, not part of the core: `core/` does not import
it, and it may know about profile-shaped concepts that the core may not.

The three policy hooks here are pure functions of the request and the frozen
profile (PLT-ICD-001 §2.1 ICD-GEN-005), so they are directly property-testable.
"""

from __future__ import annotations

from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from core import model
from core.errors import (
    CALL_TYPE_NOT_PERMITTED,
    CAPACITY_EXHAUSTED,
    NOT_AUTHORISED,
    NO_BINDING,
    NO_LOCATION_BINDING,
    UNKNOWN_TARGET,
    HookContractViolation,
    PlatformError,
)
from core.hooks import (
    Admission,
    BearerDecision,
    FloorPolicy,
    InterworkingRoute,
    LocationContext,
    MCServiceId,
    MediaKind,
    PathSpec,
    PriorityDecision,
    Resolution,
    ResolutionKind,
    SessionDecision,
    SessionModel,
    SessionRequest,
    TargetRef,
)


class ResolutionFailure(PlatformError):
    """Raised by a resolver per PLT-ICD-001 §3.2 POST-5. Carries a reason code."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {detail}" if detail else reason_code)


def _matches(rule_value: str, actual: Optional[str]) -> bool:
    return rule_value == "*" or rule_value == (actual if actual is not None else "*")


# --------------------------------------------------------------------------
# IF-PRI
# --------------------------------------------------------------------------


class TablePriorityPolicy:
    """First-match evaluation over the profile's declarative priority table.

    Totality is guaranteed by validation (PLT-PRF-005), so `evaluate` never
    fails to produce a decision.
    """

    def __init__(self, profile: model.Profile) -> None:
        self._profile = profile

    def evaluate(self, request: SessionRequest,
                 resolution: Resolution) -> PriorityDecision:
        call_type = self._profile.call_type(request.call_type)
        urgency = request.urgency or (call_type.urgency if call_type else None)
        application = request.application or (
            call_type.application if call_type else None)

        for rule in self._profile.priority.rules:
            m = rule.match
            if (_matches(m.call_type, request.call_type)
                    and _matches(m.application, application)
                    and _matches(m.urgency, urgency)):
                d = rule.decision
                return PriorityDecision(
                    level=d.level,
                    scope=d.scope,
                    preemption_capability=d.preemption_capability,
                    preemption_vulnerability=d.preemption_vulnerability,
                    floor_priority=d.floor_priority,
                    label=d.label,
                )
        raise HookContractViolation(
            f"priority table is not total: no rule matches call type "
            f"{request.call_type!r}; validation should have rejected this profile")

    def compare(self, a: PriorityDecision, b: PriorityDecision) -> int:
        # PLT-ICD-001 §4.2 POST-1. Zero means NO RELATION, not equality: the
        # core never pre-empts on zero, so cross-scope pre-emption cannot occur.
        if a.scope != b.scope:
            return 0
        if a.level > b.level:
            return 1
        if a.level < b.level:
            return -1
        return 0


# --------------------------------------------------------------------------
# IF-SES
# --------------------------------------------------------------------------

# Key under which the core supplies the current active session count.
#
# OPEN (ICD gap): PLT-ICD-001 §5.1 INV-2 states the core supplies current
# session counts to the admission hook, but `SessionRequest` carries no such
# field, so it arrives through `attributes`. This is an interface defect to fix
# in ICD v0.2 by adding an explicit field; raised rather than papered over.
ACTIVE_SESSIONS_KEY = "core.active_sessions"
ACTIVE_BY_URGENCY_PREFIX = "core.active_sessions."


class TableSessionPolicy:
    """Admission and session shape derived from the profile's call type table."""

    def __init__(self, profile: model.Profile) -> None:
        self._profile = profile

    # -- admission ------------------------------------------------------

    def admit(self, request: SessionRequest, resolution: Resolution,
              priority: PriorityDecision) -> Admission:
        declared = self._profile.call_type(request.call_type)
        if declared is None:
            return self._refuse(CALL_TYPE_NOT_PERMITTED)

        if declared.initiator_roles and not self._initiator_permitted(request,
                                                                     declared):
            return self._refuse(NOT_AUTHORISED)

        if declared.max_participants is not None and \
                len(resolution.members) > declared.max_participants:
            return self._refuse(CAPACITY_EXHAUSTED)

        capacity = self._capacity_check(request, declared)
        if capacity is not None:
            return self._refuse(capacity)

        return Admission(permitted=True, reason_code="")

    def _refuse(self, code: str) -> Admission:
        # PLT-ICD-001 §5.1 POST-3: the code must be one the profile declared.
        if code not in self._profile.admission.reject_reason_codes:
            raise HookContractViolation(
                f"reason code {code!r} is not declared in this profile's "
                f"reject_reason_codes")
        return Admission(permitted=False, reason_code=code)

    def _initiator_permitted(self, request: SessionRequest,
                             declared: model.CallType) -> bool:
        held = request.attributes.get("initiator.roles", "")
        roles = {r for r in (s.strip() for s in held.split(",")) if r}
        return bool(roles & set(declared.initiator_roles))

    def _capacity_check(self, request: SessionRequest,
                        declared: model.CallType) -> Optional[str]:
        adm = self._profile.admission
        active = _int_attr(request.attributes, ACTIVE_SESSIONS_KEY)
        if active is None:
            return None  # core supplied no count; nothing to enforce here
        if active >= adm.max_concurrent_sessions:
            return CAPACITY_EXHAUSTED

        # Reserved capacity: sessions of a lower urgency may not consume the
        # headroom reserved for a higher one (PLT-PRI-007).
        reserved_for_others = 0
        for urgency, count in adm.reserved_for_urgency.items():
            if urgency == declared.urgency:
                continue
            used = _int_attr(request.attributes,
                             ACTIVE_BY_URGENCY_PREFIX + urgency) or 0
            reserved_for_others += max(0, count - used)
        if declared.urgency not in adm.reserved_for_urgency:
            if active + reserved_for_others >= adm.max_concurrent_sessions:
                return CAPACITY_EXHAUSTED
        return None

    # -- shape ----------------------------------------------------------

    def decide(self, request: SessionRequest,
               resolution: Resolution) -> SessionDecision:
        declared = self._profile.call_type(request.call_type)
        if declared is None:
            raise HookContractViolation(
                f"decide called for undeclared call type {request.call_type!r}")
        return SessionDecision(
            model=SessionModel(declared.session_model),
            auto_answer=declared.auto_answer,
            acknowledgement_required=declared.acknowledgement_required,
            recording_required=declared.recording_required,
            max_participants=declared.max_participants,
        )

    def floor_policy(self, request: SessionRequest,
                     resolution: Resolution) -> FloorPolicy:
        declared = self._profile.call_type(request.call_type)
        if declared is None:
            raise HookContractViolation(
                f"floor_policy called for undeclared call type "
                f"{request.call_type!r}")
        f = declared.floor
        return FloorPolicy(
            initial_grant_to_initiator=f.initial_grant_to_initiator,
            queueing_enabled=f.queueing_enabled,
            override_allowed=f.override_allowed,
            max_queue_depth=f.max_queue_depth,
            timers_ms=dict(f.timers_ms),
        )


def _int_attr(attributes: Mapping[str, str], key: str) -> Optional[int]:
    raw = attributes.get(key)
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# IF-BER
# --------------------------------------------------------------------------


class TableBearerSelector:
    """First-match evaluation over the profile's bearer table.

    Totality is guaranteed by validation (PLT-PRF-006).
    """

    def __init__(self, profile: model.Profile) -> None:
        self._profile = profile

    def select(self, request: SessionRequest, priority: PriorityDecision,
               media: Sequence[MediaKind]) -> BearerDecision:
        if not media:
            raise HookContractViolation("select called with no media component")
        primary_media = media[0].value
        for rule in self._profile.bearer.rules:
            if (_matches(rule.match.call_type, request.call_type)
                    and _matches(rule.match.media, primary_media)):
                return self._build(rule.decision, priority)
        raise HookContractViolation(
            f"bearer table is not total: no rule matches "
            f"({request.call_type!r}, {primary_media!r})")

    def _build(self, spec: model.BearerDecisionSpec,
               priority: PriorityDecision) -> BearerDecision:
        # PLT-ICD-001 §6.1 POST-5: ARP pre-emption may not exceed what the
        # priority decision authorises.
        if spec.arp_preemption_capability and not priority.preemption_capability:
            raise HookContractViolation(
                "bearer rule requests ARP pre-emption capability, but the "
                f"priority decision {priority.label!r} does not authorise it")
        return BearerDecision(
            qos_identifier=spec.qos_identifier,
            arp_level=spec.arp_level,
            arp_preemption_capability=spec.arp_preemption_capability,
            arp_preemption_vulnerability=spec.arp_preemption_vulnerability,
            paths=tuple(
                PathSpec(path_id=p.id, transport=p.transport, primary=p.primary,
                         weight=p.weight, attributes=dict(p.attributes))
                for p in spec.paths),
            redundancy=spec.redundancy,
        )

    def on_path_event(self, session_id: str,
                      event: Mapping[str, str]) -> Optional[BearerDecision]:
        # PLT-ICD-001 §6.2 POST-3: unrecognised events return None, never raise.
        return None


# --------------------------------------------------------------------------
# IF-IDR — directory resolution
# --------------------------------------------------------------------------


class DirectoryResolver:
    """Directory-backed resolution. No functional addressing.

    R1 uses an in-memory directory; the group source becomes the GMS documents
    once PLT-GRP-001 is implemented against a store.
    """

    def __init__(self, profile: model.Profile) -> None:
        self._profile = profile
        self._users: Dict[MCServiceId, None] = {}
        self._groups: Dict[str, Tuple[MCServiceId, ...]] = {}

    # -- provisioning (not part of IF-IDR) -------------------------------

    def register_user(self, service_id: MCServiceId) -> None:
        self._require_declared_domain(service_id)
        self._users[service_id] = None

    def register_group(self, group_id: str,
                       members: Sequence[MCServiceId]) -> None:
        for m in members:
            self._require_declared_domain(m)
        # Deduplicate, preserve declaration order (PLT-ICD-001 §3.2 POST-2).
        seen, ordered = set(), []
        for m in members:
            if m not in seen:
                seen.add(m)
                ordered.append(m)
        self._groups[group_id] = tuple(ordered)

    def _require_declared_domain(self, service_id: MCServiceId) -> None:
        # PLT-IDM-008: never resolve outside the profile's declared domains.
        domain = service_id.rpartition("@")[2]
        if domain not in self._profile.identity.domains:
            raise ResolutionFailure(
                NOT_AUTHORISED,
                f"{service_id!r} is outside this profile's declared domains")

    # -- IF-IDR ----------------------------------------------------------

    def resolve(self, target: TargetRef, request: SessionRequest) -> Resolution:
        if not target:
            raise ResolutionFailure(UNKNOWN_TARGET, "empty target")
        if target in self._groups:
            members = self._groups[target]
            if not members:
                raise ResolutionFailure(UNKNOWN_TARGET,
                                        f"group {target!r} has no members")
            return Resolution(kind=ResolutionKind.GROUP, members=members,
                              group_id=target, resolved_from=None)
        if target in self._users:
            return Resolution(kind=ResolutionKind.USER, members=(target,),
                              group_id=None, resolved_from=None)
        raise ResolutionFailure(UNKNOWN_TARGET, f"{target!r} is not known")

    def bind(self, identity: str, service_id: MCServiceId,
             location: Optional[LocationContext]) -> None:
        raise ResolutionFailure(
            NO_BINDING,
            "this profile declares no functional identities, so nothing can be bound")

    def unbind(self, identity: str, service_id: MCServiceId) -> None:
        return None  # PLT-ICD-001 §3.3 POST-2: unbinding nothing is a no-op

    def identities_of(self, service_id: MCServiceId) -> Sequence[str]:
        return ()


class FunctionalResolver(DirectoryResolver):
    """Directory resolution plus functional and location-dependent addressing.

    `bind` on a held single-holder identity REPLACES the existing holder.

    OPEN (ICD-OP-02): replace-versus-refuse is operationally significant for
    driver handover and must be confirmed against the UIC FRS. Replacement is
    implemented here because a stale binding blocking a handover is the worse
    failure of the two, but this is a provisional choice.
    """

    def __init__(self, profile: model.Profile) -> None:
        super().__init__(profile)
        # identity id -> {location key value or "": (service_id, ...)}
        self._bindings: Dict[str, Dict[str, Tuple[MCServiceId, ...]]] = {}

    def bind(self, identity: str, service_id: MCServiceId,
             location: Optional[LocationContext]) -> None:
        declared = self._profile.functional_identity(identity)
        if declared is None:
            raise ResolutionFailure(
                UNKNOWN_TARGET, f"functional identity {identity!r} is not declared")
        self._require_declared_domain(service_id)
        slot = self._location_slot(declared, location, for_binding=True)
        held = self._bindings.setdefault(identity, {})
        if declared.multiplicity == "single":
            held[slot] = (service_id,)
        else:
            current = held.get(slot, ())
            if service_id not in current:
                held[slot] = current + (service_id,)

    def unbind(self, identity: str, service_id: MCServiceId) -> None:
        for slot, holders in list(self._bindings.get(identity, {}).items()):
            remaining = tuple(h for h in holders if h != service_id)
            if remaining:
                self._bindings[identity][slot] = remaining
            else:
                del self._bindings[identity][slot]

    def identities_of(self, service_id: MCServiceId) -> Sequence[str]:
        return tuple(sorted(
            identity for identity, slots in self._bindings.items()
            if any(service_id in holders for holders in slots.values())))

    def resolve(self, target: TargetRef, request: SessionRequest) -> Resolution:
        declared = self._profile.functional_identity(target)
        if declared is None:
            return super().resolve(target, request)

        slot = self._location_slot(declared, request.location, for_binding=False)
        holders = self._bindings.get(target, {}).get(slot, ())
        if not holders:
            raise ResolutionFailure(
                NO_BINDING,
                f"functional identity {target!r} is declared but currently unheld")

        # PLT-RAIL-004 / PLT-ICD-001 §3.2 INV-3.
        if declared.multiplicity == "single" and len(holders) != 1:
            raise HookContractViolation(
                f"single-holder identity {target!r} resolved to {len(holders)} "
                "holders")

        kind = (ResolutionKind.GROUP if declared.resolves_to == "group"
                else ResolutionKind.USER)
        return Resolution(
            kind=kind,
            members=holders,
            group_id=target if kind is ResolutionKind.GROUP else None,
            resolved_from=target,  # PLT-HOK-014
        )

    def _location_slot(self, declared: model.FunctionalIdentity,
                       location: Optional[LocationContext],
                       for_binding: bool) -> str:
        if not declared.location_dependent:
            return ""
        key = declared.location_key or ""
        value = (location.attributes.get(key) if location else None)
        if not value:
            raise ResolutionFailure(
                NO_LOCATION_BINDING,
                f"identity {declared.id!r} depends on location attribute {key!r}, "
                "which was not reported")
        return value


# --------------------------------------------------------------------------
# IF-IWF
# --------------------------------------------------------------------------


class PrefixInterworkingGateway:
    """Prefix-matched routing to a legacy system. A profile with no
    interworking block routes nothing and remains valid (PLT-HOK-052)."""

    def __init__(self, profile: model.Profile) -> None:
        self._profile = profile

    def route(self, request: SessionRequest,
              resolution: Resolution) -> Optional[InterworkingRoute]:
        iw = self._profile.interworking
        if iw is None:
            return None
        for r in iw.routes:
            if r.target_prefix and request.target.startswith(r.target_prefix):
                return InterworkingRoute(system=iw.system or "",
                                         gateway=r.gateway,
                                         attributes=dict(r.attributes))
        return None

    def map_inbound(self, foreign: Mapping[str, str]) -> SessionRequest:
        call_type = foreign.get("call_type", "")
        if not self._profile.declares_call_type(call_type):
            raise HookContractViolation(
                f"inbound request names undeclared call type {call_type!r}")
        initiator = foreign.get("initiator", "")
        domain = initiator.rpartition("@")[2]
        if domain not in self._profile.identity.domains:
            raise HookContractViolation(
                f"inbound initiator {initiator!r} is outside declared domains")
        declared = self._profile.call_type(call_type)
        return SessionRequest(
            request_id=foreign.get("request_id", ""),
            initiator=initiator,
            target=foreign.get("target", ""),
            call_type=call_type,
            media=tuple(MediaKind(m) for m in declared.media),
            application=declared.application,
            urgency=declared.urgency,
            location=None,
            # Priority asserted by a foreign system is advisory only; IF-PRI
            # decides from the mapped request (PLT-ICD-001 §7.2 INV-2).
            attributes={"interworking.source": foreign.get("system", "")},
        )
