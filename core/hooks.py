"""Profile hook interfaces.

These five Protocols are the ONLY places where MCX and FRMCS behaviour is
allowed to diverge. Nothing below this line may import a profile package,
and no core module may branch on the profile name.

Core rule: call types, urgency labels, application ids and pre-emption
scopes are opaque strings declared by the profile. The core never enumerates
them, so adding a call type is a config change, not a code change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Optional, Protocol, Sequence, runtime_checkable

# --------------------------------------------------------------------------
# Opaque identifiers. Profile-defined vocabulary, core-defined plumbing.
# --------------------------------------------------------------------------

MCServiceId = str  # e.g. "sip:driver-4711@rail.example"
GroupId = str
TargetRef = str  # service id, group id, or a functional identity
CallTypeId = str  # "private", "prearranged-group", "railway-emergency", ...
ApplicationId = str  # FRMCS application category, or None for plain MCX voice
UrgencyId = str  # "normal", "emergency", "imminent-peril", "rec", ...
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


# --------------------------------------------------------------------------
# Value objects passed across the hook boundary. All frozen: a hook must not
# be able to mutate the session state it is consulted about.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LocationContext:
    """Whatever the access network and the client reported.

    Generic MCX uses cell/TAI. FRMCS location-dependent addressing uses
    track section, direction and train id, carried in `attributes` so the
    core never learns railway vocabulary.
    """

    cell_id: Optional[str] = None
    tracking_area: Optional[str] = None
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SessionRequest:
    request_id: str
    initiator: MCServiceId
    target: TargetRef
    call_type: CallTypeId
    media: Sequence[MediaKind]
    application: Optional[ApplicationId] = None
    urgency: Optional[UrgencyId] = None
    location: Optional[LocationContext] = None
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Resolution:
    kind: ResolutionKind
    members: Sequence[MCServiceId]
    group_id: Optional[GroupId] = None
    # What the target string denoted, for audit: a functional identity that
    # resolved to a user must be traceable after the fact.
    resolved_from: Optional[str] = None


@dataclass(frozen=True)
class PriorityDecision:
    level: int  # higher wins, profile-defined range
    scope: PreemptionScope
    preemption_capability: bool
    preemption_vulnerability: bool
    floor_priority: int
    label: str  # for logs and audit records


@dataclass(frozen=True)
class Admission:
    permitted: bool
    reason_code: str  # "" when permitted; a profile-defined code otherwise


@dataclass(frozen=True)
class FloorPolicy:
    initial_grant_to_initiator: bool
    queueing_enabled: bool
    override_allowed: bool
    max_queue_depth: int
    # 24.380 timer overrides, name -> milliseconds. The engine owns the
    # state machine; the profile owns the constants.
    timers_ms: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class SessionDecision:
    model: SessionModel
    auto_answer: bool
    acknowledgement_required: bool
    recording_required: bool
    max_participants: Optional[int] = None


@dataclass(frozen=True)
class PathSpec:
    path_id: str
    transport: str  # "udp", "tcp", "sctp"
    primary: bool
    weight: int = 1
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class BearerDecision:
    qos_identifier: int  # 5QI / QCI
    arp_level: int
    arp_preemption_capability: bool
    arp_preemption_vulnerability: bool
    paths: Sequence[PathSpec]
    redundancy: str  # "single", "multipath", "multihomed"


@dataclass(frozen=True)
class InterworkingRoute:
    system: str  # "p25", "tetra", "gsm-r", ...
    gateway: str
    attributes: Mapping[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------
# The five hooks.
# --------------------------------------------------------------------------


@runtime_checkable
class IdentityResolver(Protocol):
    """Hook 1. Turns a target reference into concrete members.

    Plain MCX looks up a directory. FRMCS resolves functional identities and
    location-dependent addresses, which is why `location` is passed in and
    why bindings are mutable at runtime.
    """

    def resolve(
        self, target: TargetRef, request: SessionRequest
    ) -> Resolution: ...

    def bind(
        self, identity: str, service_id: MCServiceId, location: Optional[LocationContext]
    ) -> None: ...

    def unbind(self, identity: str, service_id: MCServiceId) -> None: ...

    def identities_of(self, service_id: MCServiceId) -> Sequence[str]: ...


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
    """Hook 4. QoS mapping and, for FRMCS, multi-bearer path selection."""

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
class InterworkingGateway(Protocol):
    """Hook 5. Legacy system routing: P25/TETRA for MCX, GSM-R for FRMCS."""

    def route(
        self, request: SessionRequest, resolution: Resolution
    ) -> Optional[InterworkingRoute]: ...

    def map_inbound(self, foreign: Mapping[str, str]) -> SessionRequest: ...


__all__ = [n for n in dir() if not n.startswith("_")]
