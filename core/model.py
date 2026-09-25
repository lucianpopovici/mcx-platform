"""Frozen profile model.

The in-memory representation of a validated profile. Every type here is
immutable (PLT-PRF-009): sequences are tuples, mappings are MappingProxyType.
Construction happens only in `validation.build()`, after every check has passed.

The core reads these objects; it never enumerates the identifier values inside
them (PLT-PRF-020).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Optional, Tuple

from .mcinfo import Signature


def freeze_map(d: Optional[Mapping]) -> Mapping:
    return MappingProxyType(dict(d or {}))


@dataclass(frozen=True)
class Declared:
    id: str
    label: str


@dataclass(frozen=True)
class Application:
    id: str
    label: str
    media: Tuple[str, ...]
    safety_relevant: bool


@dataclass(frozen=True)
class FloorConfig:
    initial_grant_to_initiator: bool
    queueing_enabled: bool
    override_allowed: bool
    max_queue_depth: int
    timers_ms: Mapping[str, int]


@dataclass(frozen=True)
class CallType:
    id: str
    label: str
    media: Tuple[str, ...]
    session_model: str
    urgency: str
    application: Optional[str]
    auto_answer: bool
    acknowledgement_required: bool
    recording_required: bool
    max_participants: Optional[int]
    initiator_roles: Tuple[str, ...]
    floor: FloorConfig
    # How a native MCPTT client asks for this call type (TS 24.379 annex F.1),
    # or None when it cannot: the call type is reachable only some other way
    # (a gateway, MCData) or TS 24.379 cannot tell it apart from another.
    # Declared, never inferred (PLT-ICD-001 section 2.6).
    mc_signature: Optional[Signature] = None
    # How long an invited member may ring (the leg's INVITE is in
    # 'Proceeding') before the core CANCELs it, in seconds. Service policy,
    # declared per call type (PLT-VP-R1 SIP-OP-15, PLT-ICD-001 2.7). The
    # loader requires it; None only in a CallType built by hand, and then
    # the transaction layer's Timer B is the only limit.
    no_answer_s: Optional[int] = None


@dataclass(frozen=True)
class FunctionalIdentity:
    id: str
    label: str
    binding: str
    location_dependent: bool
    location_key: Optional[str]
    multiplicity: str
    resolves_to: str


@dataclass(frozen=True)
class Identity:
    domains: Tuple[str, ...]
    functional: Tuple[FunctionalIdentity, ...]
    # Serving cell (ECGI or NCGI, as TS 24.379 annex F.3 writes it) -> the
    # location attributes it stands for, e.g. {"track_section": "S1"}. How a
    # reported cell becomes the location a functional identity is keyed on
    # (PLT-ICD-001 2.8; PLT-VP-R1 ADHOC-OP-03).
    cells: Mapping[str, Mapping[str, str]] = field(default_factory=dict)


@dataclass(frozen=True)
class PriorityMatch:
    call_type: str
    application: str
    urgency: str


@dataclass(frozen=True)
class PriorityDecisionSpec:
    level: int
    scope: str
    preemption_capability: bool
    preemption_vulnerability: bool
    floor_priority: int
    label: str


@dataclass(frozen=True)
class PriorityRule:
    match: PriorityMatch
    decision: PriorityDecisionSpec


@dataclass(frozen=True)
class Priority:
    default_scope: str
    rules: Tuple[PriorityRule, ...]


@dataclass(frozen=True)
class PathSpecConfig:
    id: str
    transport: str
    primary: bool
    weight: int
    attributes: Mapping[str, str]


@dataclass(frozen=True)
class BearerMatch:
    call_type: str
    media: str


@dataclass(frozen=True)
class BearerDecisionSpec:
    qos_identifier: int
    arp_level: int
    arp_preemption_capability: bool
    arp_preemption_vulnerability: bool
    redundancy: str
    paths: Tuple[PathSpecConfig, ...]


@dataclass(frozen=True)
class BearerRule:
    match: BearerMatch
    decision: BearerDecisionSpec


@dataclass(frozen=True)
class Bearer:
    rules: Tuple[BearerRule, ...]


@dataclass(frozen=True)
class InterworkingRouteConfig:
    target_prefix: str
    gateway: str
    attributes: Mapping[str, str]


@dataclass(frozen=True)
class Interworking:
    system: Optional[str]
    gateway: Optional[str]
    routes: Tuple[InterworkingRouteConfig, ...]


@dataclass(frozen=True)
class PriorityMapEntry:
    """One pair-wise mapping from a partner's asserted decision to a local one.

    Keyed on the partner's LABEL, never its level: levels in two systems are
    numbers in unrelated scales and comparing them is meaningless.
    """

    from_label: str
    to_level: int
    to_label: str


@dataclass(frozen=True)
class PartnerConfig:
    id: str
    domains: Tuple[str, ...]
    target_prefix: str
    gateway: str
    trust: str
    # Inbound: what the partner may do here. Defaults are restrictive.
    inbound_scope: str
    inbound_max_level: int
    inbound_may_preempt: bool
    inbound_allowed_call_types: Tuple[str, ...]
    inbound_priority_map: Tuple[PriorityMapEntry, ...]
    # Outbound: what we assert to the partner.
    outbound_assert_label: bool


@dataclass(frozen=True)
class Interconnection:
    partners: Tuple[PartnerConfig, ...]


@dataclass(frozen=True)
class Admission:
    max_concurrent_sessions: int
    reserved_for_urgency: Mapping[str, int]
    reject_reason_codes: Tuple[str, ...]


@dataclass(frozen=True)
class Codec:
    """A voice codec the deployment may carry. Opaque to the core: it is a
    payload type and an rtpmap string, never a name the core recognises."""

    payload_type: int
    name: str            # SDP rtpmap value, e.g. "AMR-WB/16000"


@dataclass(frozen=True)
class Media:
    codecs: Tuple[Codec, ...]


@dataclass(frozen=True)
class HookPaths:
    identity_resolver: str
    priority_policy: str
    session_policy: str
    bearer_selector: str
    interworking_gateway: str
    interconnection_gateway: str


@dataclass(frozen=True)
class Profile:
    """A validated, immutable profile.

    `content_hash` is computed over the canonicalised source (PLT-PRF-011) and
    appears in the startup log, on the health endpoint and on every audit
    record (PLT-OAM-001).
    """

    name: str
    version: str
    description: str
    hooks: HookPaths
    urgencies: Tuple[Declared, ...]
    preemption_scopes: Tuple[Declared, ...]
    applications: Tuple[Application, ...]
    call_types: Tuple[CallType, ...]
    identity: Identity
    priority: Priority
    bearer: Bearer
    interworking: Optional[Interworking]
    interconnection: Optional[Interconnection]
    admission: Admission
    media: Media
    content_hash: str

    # -- lookups ---------------------------------------------------------
    # Convenience only. These return declared members; they never imply the
    # core knows what any identifier means.

    def call_type(self, call_type_id: str) -> Optional[CallType]:
        for c in self.call_types:
            if c.id == call_type_id:
                return c
        return None

    def declares_call_type(self, call_type_id: str) -> bool:
        return self.call_type(call_type_id) is not None

    def functional_identity(self, identity_id: str) -> Optional[FunctionalIdentity]:
        for f in self.identity.functional:
            if f.id == identity_id:
                return f
        return None

    def partner(self, partner_id: str) -> Optional[PartnerConfig]:
        if self.interconnection is None:
            return None
        for p in self.interconnection.partners:
            if p.id == partner_id:
                return p
        return None

    def identifier(self) -> str:
        """The triple that must appear in logs, health and audit records."""
        return f"{self.name}/{self.version}/{self.content_hash[:16]}"
