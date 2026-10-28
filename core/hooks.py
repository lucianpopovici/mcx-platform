"""Profile hook interfaces.

These five Protocols are the ONLY places where deployment-specific behaviour
is allowed to diverge. Nothing below this line may import a profile package,
and no core module may branch on the profile name.

Core rule: call types, urgency labels, application ids and pre-emption
scopes are opaque strings declared by the profile. The core never enumerates
them, so adding a call type is a config change, not a code change.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
import re
from typing import (Any, Iterable, Mapping, Optional, Protocol, Sequence, Tuple,
                    runtime_checkable)

# --------------------------------------------------------------------------
# Opaque identifiers. Profile-defined vocabulary, core-defined plumbing.
# --------------------------------------------------------------------------

MCServiceId = str  # e.g. "sip:user-4711@example.org"
GroupId = str
TargetRef = str  # service id, group id, or a functional identity
CallTypeId = str  # profile-declared, e.g. "private", "prearranged-group"
ApplicationId = str  # profile-declared application category, or None
UrgencyId = str  # profile-declared, e.g. "normal", "emergency"
PreemptionScope = str  # sessions only arbitrate against the same scope


class MediaKind(Enum):
    VOICE = "voice"
    VIDEO = "video"
    DATA = "data"


class SessionModel(Enum):
    ON_DEMAND = "on-demand"
    PRE_ESTABLISHED = "pre-established"
    BROADCAST = "broadcast"


class ResolutionKind(Enum):
    USER = "user"
    GROUP = "group"
    BROADCAST_AREA = "broadcast-area"
    # The target belongs to a non-MC system. No local member set exists; the
    # session is routed to a gateway instead of being established locally.
    EXTERNAL = "external"
    # The target belongs to a partner MC system. Like EXTERNAL it carries no
    # local members, but the far side speaks MC protocols natively: what is
    # needed is policy reconciliation, not protocol translation.
    PARTNER = "partner"


# --------------------------------------------------------------------------
# Value objects passed across the hook boundary. All frozen: a hook must not
# be able to mutate the session state it is consulted about.
# --------------------------------------------------------------------------



class FrozenDict(dict):
    """A dict that refuses to change. A dict subclass rather than
    MappingProxyType so that a value still serialises to JSON, survives
    dataclasses.asdict and copy.deepcopy, and compares equal to a plain dict
    with the same items (RES-OP-06). Its items are filled in `__new__`, so
    calling `__init__` again on a live one does nothing."""

    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        self = dict.__new__(cls)
        dict.__init__(self, *args, **kwargs)
        return self

    def __init__(self, *args, **kwargs) -> None:            # filled in __new__
        pass

    def _refuse(self, *args, **kwargs):
        raise TypeError("a hook value's mapping is read-only")

    __setitem__ = __delitem__ = __ior__ = _refuse           # type: ignore[assignment]
    update = pop = popitem = clear = setdefault = _refuse    # type: ignore[assignment]

    @classmethod
    def fromkeys(cls, iterable, value=None):                 # type: ignore[override]
        return cls(dict.fromkeys(iterable, value))

    def __hash__(self) -> int:                               # type: ignore[override]
        return hash(frozenset(self.items()))

    def __reduce__(self):
        # Also how copy and deepcopy rebuild one (deepcopy copies the items):
        # dict's own reduction would refill it through __setitem__.
        return (FrozenDict, (dict(self),))


# What may sit in a hook value as it is: types whose instances cannot change.
_IMMUTABLE = (str, bytes, int, float, complex, bool, type(None), Enum)


def freeze(value: Any) -> Any:
    """`value` with nothing mutable left in it, at any depth: a mapping
    becomes a FrozenDict, a list or tuple a tuple, a set a frozenset, a
    bytearray bytes, each of their items frozen in turn. A Value is already
    frozen. Anything else is refused: whether an arbitrary object can change
    cannot be told, and a hook value has no need of one (RES-OP-06 review)."""
    if isinstance(value, _IMMUTABLE) or _is_frozen_value(value):
        return value
    if isinstance(value, Mapping):
        return FrozenDict({freeze(k): freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(freeze(v) for v in value)
    if isinstance(value, bytearray):
        return bytes(value)
    raise TypeError(f"a hook value cannot hold a {type(value).__name__}: "
                    "it may be mutable")


def _is_frozen_value(value: Any) -> bool:
    """A Value whose type really is frozen: a frozen dataclass that freezes
    its fields with Value's own __post_init__. Deriving from Value is not
    enough (RES-OP-06 review G1: a profile's non-frozen Value subclass)."""
    cls = type(value)
    params = getattr(cls, "__dataclass_params__", None)
    return isinstance(value, Value) and params is not None and params.frozen and \
        cls.__post_init__ is Value.__post_init__


class Value:
    """The base of every value that crosses a hook boundary (PLT-ICD-001
    ICD-GEN-001, VP1-BND-004: every type frozen, no mutable field).

    `frozen=True` stops a field being reassigned, not a dict or list in it
    being changed in place: `request.attributes["x"] = "y"` used to succeed
    (PLT-VP-R1 RES-OP-06). So on construction every field is replaced by
    `freeze(field)`: a copy with nothing mutable in it at any depth. The copy
    matters: a read-only view of the caller's own dict would still change
    when the caller changed it. It goes by the value, not by how the field is
    declared, so no spelling of a type can leave a dict in place. A
    subclass must not define its own `__post_init__` (the gate checks).
    """

    def __post_init__(self) -> None:
        for f in dataclasses.fields(self):          # type: ignore[arg-type]
            value = getattr(self, f.name)
            if "Sequence[" in str(f.type) and value is not None:
                if isinstance(value, (str, bytes, bytearray, set, frozenset, Mapping)):
                    # A string would become its characters; a set or a
                    # mapping has no order a sequence could keep.
                    raise TypeError(f"{type(self).__name__}.{f.name}: expected an "
                                    f"ordered sequence of items, not {type(value).__name__}")
                if not isinstance(value, (list, tuple)):
                    value = tuple(value)          # a generator, range, keys view...
            object.__setattr__(self, f.name, freeze(value))


@dataclass(frozen=True)
class LocationContext(Value):
    """Whatever the access network and the client reported.

    Cell and tracking area are the common cases. A profile needing richer
    location semantics carries them in `attributes`, so the core never learns a
    deployment's location vocabulary.
    """

    cell_id: Optional[str] = None
    tracking_area: Optional[str] = None
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SessionRequest(Value):
    request_id: str
    initiator: MCServiceId
    target: TargetRef
    call_type: CallTypeId
    media: Sequence[MediaKind]
    application: Optional[ApplicationId] = None
    urgency: Optional[UrgencyId] = None
    location: Optional[LocationContext] = None
    attributes: Mapping[str, str] = field(default_factory=dict)
    # An ad hoc group call (TS 24.379 clause 17) names no group: the members
    # are listed by the caller (`participants`, from an RFC 5366 URI list) or
    # described by criteria that the profile evaluates (`participant_criteria`,
    # from <call-participants-criterias>). PLT-ICD-001 section 3.5.
    adhoc: bool = False
    participants: Sequence[MCServiceId] = ()
    participant_criteria: Optional[str] = None
    # <adhoc-grp-emg-alert-grp-ind> true: the call follows an ad hoc
    # emergency alert and names that alert's group (17.4.2.2 step 7A).
    adhoc_alert_group: bool = False


# PLT-ICD-001 §3.2 (since 0.33, PLT-VP-R1 FA-OP-01 item 4): a functional
# identity keyed by an identification value, which a profile declares with an
# identification_key, is written sip:<value>.<identity>@<domain>, e.g.
# sip:42.duty-officer@example.org: the value alphanumeric, the identity one
# the profile declares so keyed, the domain one the profile serves.
_KEYED = re.compile(r"(?i:sips?):([A-Za-z0-9]+)\.([A-Za-z0-9_-]+)@([A-Za-z0-9.-]+)")


def keyed_identity(text: str, keyed: Iterable[str],
                   domains: Iterable[str]) -> Optional[Tuple[str, str]]:
    """(identity, value) when `text` is a keyed functional identity of one of
    `keyed` within one of `domains`, else None. The host is compared without
    case; the value and the identity exactly."""
    m = _KEYED.fullmatch(text.strip()) if isinstance(text, str) else None
    if m is None or m.group(2) not in set(keyed) or \
            m.group(3).lower() not in {d.lower() for d in domains}:
        return None
    return m.group(2), m.group(1)


@dataclass(frozen=True)
class Resolution(Value):
    """The outcome of resolving a target.

    EXTERNAL carries no members: `resolved_from` holds the foreign target and
    the interworking hook supplies the gateway.
    """

    kind: ResolutionKind
    members: Sequence[MCServiceId]
    group_id: Optional[GroupId] = None
    # What the target string denoted, for audit: a functional identity that
    # resolved to a user must be traceable after the fact.
    resolved_from: Optional[str] = None


@dataclass(frozen=True)
class PriorityDecision(Value):
    level: int  # higher wins, profile-defined range
    scope: PreemptionScope
    preemption_capability: bool
    preemption_vulnerability: bool
    floor_priority: int
    label: str  # for logs and audit records


@dataclass(frozen=True)
class Admission(Value):
    permitted: bool
    reason_code: str  # "" when permitted; a profile-defined code otherwise


@dataclass(frozen=True)
class FloorPolicy(Value):
    initial_grant_to_initiator: bool
    queueing_enabled: bool
    override_allowed: bool
    max_queue_depth: int
    # "insert" (TS 24.380 6.3.4.4.7 item 2e) or "deny" (a recorded deviation):
    # a pre-emptor at a queue already at max_queue_depth (PLT-ICD-001 5.3).
    preemption_at_full_queue: str
    # 24.380 timer overrides, name -> milliseconds. The engine owns the
    # state machine; the profile owns the constants.
    timers_ms: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class SessionDecision(Value):
    model: SessionModel
    auto_answer: bool
    acknowledgement_required: bool
    recording_required: bool
    max_participants: Optional[int] = None


@dataclass(frozen=True)
class PathSpec(Value):
    path_id: str
    transport: str  # "udp", "tcp", "sctp"
    primary: bool
    weight: int = 1
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class BearerDecision(Value):
    qos_identifier: int  # 5QI / QCI
    arp_level: int
    arp_preemption_capability: bool
    arp_preemption_vulnerability: bool
    paths: Sequence[PathSpec]
    redundancy: str  # "single", "multipath", "multihomed"


@dataclass(frozen=True)
class PartnerRoute(Value):
    """Where a partner MC system is reached, and under whose authority."""

    partner_id: str
    gateway: str
    # How the partner system authenticated itself. A partner identity taken
    # from an unauthenticated header is not an identity.
    trust: str = ""
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PartnerRights(Value):
    """What a partner system may do inside THIS system.

    Defaults are the safe ones: no pre-emption, no call types. A partner gains
    a capability only by an explicit declaration.
    """

    scope: PreemptionScope           # local scope partner sessions occupy
    max_level: int = 0               # ceiling on any mapped priority level
    may_preempt: bool = False
    allowed_call_types: Sequence[CallTypeId] = ()


@dataclass(frozen=True)
class InterworkingRoute(Value):
    system: str  # profile-declared legacy system identifier
    gateway: str
    attributes: Mapping[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------
# The five hooks.
# --------------------------------------------------------------------------


@runtime_checkable
class IdentityResolver(Protocol):
    """Hook 1. Turns a target reference into concrete members.

    The simplest implementation is a directory lookup. A profile may instead
    resolve role-based or location-dependent identities, which is why `location`
    is passed in and why bindings are mutable at runtime.
    """

    def resolve(
        self, target: TargetRef, request: SessionRequest
    ) -> Resolution: ...

    def bind(
        self, identity: str, service_id: MCServiceId, location: Optional[LocationContext]
    ) -> None: ...

    def unbind(self, identity: str, service_id: MCServiceId) -> None: ...

    def identities_of(self, service_id: MCServiceId) -> Sequence[str]: ...

    def kind_of(self, target: TargetRef, request: SessionRequest) -> ResolutionKind:
        """What `target` is -- a user, a group, or a foreign system's -- without
        its members (PLT-ICD-001 section 3.6): what an ad hoc caller's list
        entry is, before any group is resolved over its members. Raises as
        `resolve` does for a target it does not know."""
        ...

    def determine_participants(
        self, criteria: str, request: SessionRequest
    ) -> Resolution:
        """Who meets the caller's criteria for an ad hoc group call (TS 24.379
        17.4.2.2 step 12 ii: "based on the local policy"). The criteria string
        is opaque to the core; what it means is the profile's. Returns a GROUP
        resolution, or raises with `adhoc-participants-undetermined`
        (PLT-ICD-001 section 3.5)."""
        ...


@runtime_checkable
class PriorityPolicy(Protocol):
    """Hook 2. Priority, pre-emption rights, and arbitration between them.

    `compare` must return 0 (no relation) whenever the two decisions carry
    different scopes. Cross-scope pre-emption is never implicit.
    """

    def evaluate(
        self, request: SessionRequest, resolution: Resolution
    ) -> PriorityDecision: ...

    def compare(self, a: PriorityDecision, b: PriorityDecision) -> int: ...


@runtime_checkable
class SessionPolicy(Protocol):
    """Hook 3. Whether the session happens, and in what shape."""

    def authorise(self, request: SessionRequest) -> Admission:
        """Whether this initiator may start this call type at all, decided
        before anything about the target is looked up (TS 24.379 17.4.2.2
        steps 4 and 5; PLT-ICD-001 section 5.0). The request carries the
        initiator's roles in `initiator.roles`. What depends on the target --
        participant limits, capacity -- is `admit`'s."""
        ...

    def admit(
        self,
        request: SessionRequest,
        resolution: Resolution,
        priority: PriorityDecision,
    ) -> Admission: ...

    def decide(
        self, request: SessionRequest, resolution: Resolution
    ) -> SessionDecision: ...

    def floor_policy(
        self, request: SessionRequest, resolution: Resolution
    ) -> FloorPolicy: ...


@runtime_checkable
class BearerSelector(Protocol):
    """Hook 4. QoS mapping and, where a profile requires it, multi-path selection."""

    def select(
        self,
        request: SessionRequest,
        priority: PriorityDecision,
        media: Sequence[MediaKind],
    ) -> BearerDecision: ...

    def on_path_event(
        self, session_id: str, event: Mapping[str, str]
    ) -> Optional[BearerDecision]: ...


@runtime_checkable
class InterconnectionGateway(Protocol):
    """Hook 6 (IF-ICX). Sessions spanning this system and a partner MC system.

    Distinct from IF-IWF because the problem is different. A partner speaks the
    same protocols, so nothing needs translating; what needs reconciling is
    policy. Two systems' priority LEVELS are not commensurable — one system's
    90 and another's 95 are numbers in unrelated scales — so mapping is
    declared pair-wise and never derived by comparing them.
    """

    def route(
        self, request: SessionRequest, resolution: Resolution
    ) -> Optional[PartnerRoute]: ...

    def rights(self, partner_id: str) -> PartnerRights: ...

    def map_inbound_priority(
        self, partner_id: str, asserted: Mapping[str, str]
    ) -> PriorityDecision: ...

    def map_outbound(
        self, request: SessionRequest, priority: PriorityDecision
    ) -> Mapping[str, str]: ...


@runtime_checkable
class InterworkingGateway(Protocol):
    """Hook 5. Routing to a non-MC system, where a profile declares one."""

    def route(
        self, request: SessionRequest, resolution: Resolution
    ) -> Optional[InterworkingRoute]: ...

    def map_inbound(self, foreign: Mapping[str, str]) -> SessionRequest: ...


__all__ = [n for n in dir() if not n.startswith("_")]
