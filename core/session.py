"""Session control — the §8.1 establishment sequence.

Implements PLT-ICD-001 §8.1 exactly and in order, with no step reordered and no
compensating call to a hook already invoked when a later step fails.

  1  IF-IDR.resolve
  2  IF-IWF.route
  3  IF-PRI.evaluate
  4  IF-SES.admit          -- refusal stops here, nothing is established
  5  IF-SES.decide
  6  IF-SES.floor_policy   -- voice/video only
  7  IF-BER.select
  8  reserve QoS, establish, fan out invitations

This module is transport-agnostic on purpose. It emits abstract signalling
actions that a SIP adapter renders into TS 24.379 messages; nothing here parses
or builds SIP, so the sequence is testable in ENV-UNIT (PLT-FC-004's argument,
applied to session control).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from . import floor as floor_mod
from .audit import Auditor, RecordType
from .errors import (
    GATEWAY_UNAVAILABLE,
    PARTNER_NOT_PERMITTED,
    PARTNER_UNAVAILABLE,
    QOS_UNAVAILABLE,
    RECORDING_UNAVAILABLE,
)
from .hooks import (
    BearerDecision,
    MediaKind,
    ResolutionKind,
    PriorityDecision,
    Resolution,
    SessionDecision,
    SessionRequest,
)
from .invoke import HookFailure, Invoker
from .loader import LoadedProfile


class SessionState(Enum):
    PENDING = "pending"
    ESTABLISHED = "established"
    RELEASED = "released"
    FAILED = "failed"


class SignalType(Enum):
    INVITE = "invite"
    RESPONSE_OK = "response-ok"
    RESPONSE_REJECT = "response-reject"
    BYE = "bye"
    RESERVE_QOS = "reserve-qos"
    RELEASE_QOS = "release-qos"
    START_RECORDING = "start-recording"
    ROUTE_EXTERNAL = "route-external"
    ROUTE_PARTNER = "route-partner"


@dataclass(frozen=True)
class Signal:
    type: SignalType
    target: Optional[str] = None
    detail: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class Refusal:
    reason_code: str
    detail: str = ""


@dataclass
class Session:
    """One session's record. `priority` is taken once, at admission, and is
    immutable for the session's life (PLT-PRI-001)."""

    correlation_id: str
    request: SessionRequest
    resolution: Resolution
    priority: PriorityDecision
    decision: SessionDecision
    bearer: BearerDecision
    state: SessionState = SessionState.PENDING
    floor: Optional[floor_mod.FloorControl] = None
    controlling: bool = True
    members: Tuple[str, ...] = ()
    # Set when the session was routed to a non-MC system or a partner MC
    # system. A session has either members or a gateway, never both.
    gateway: Optional[str] = None
    partner_id: Optional[str] = None


class Platform:
    """Environment the session manager depends on but does not own.

    Kept as callables rather than an interface so tests can substitute a
    failing recorder or a refusing network without a mock framework.
    """

    def __init__(self,
                 recording_available: Callable[[], bool] = lambda: True,
                 reserve_qos: Callable[[BearerDecision], bool] = lambda d: True,
                 active_sessions: Callable[[], int] = lambda: 0) -> None:
        self.recording_available = recording_available
        self.reserve_qos = reserve_qos
        self.active_sessions = active_sessions


class SessionManager:
    """Establishes and releases sessions for one loaded profile."""

    def __init__(self, loaded: LoadedProfile, auditor: Auditor,
                 platform: Optional[Platform] = None,
                 clock: Optional[Callable[[], int]] = None,
                 functions: Optional[Mapping[str, str]] = None) -> None:
        self._loaded = loaded
        self._hooks = loaded.hooks
        self._profile = loaded.profile
        self._auditor = auditor
        self._platform = platform or Platform()
        self._clock = clock or (lambda: 0)
        self._sessions: Dict[str, Session] = {}
        # Names of the functions hosting each role for this deployment, merged
        # into the admission and establishment audit records (PLT-CC-001,
        # VP1-CC-001). Opaque to the core: e.g. {"controlling_function": ...}.
        self._functions = dict(functions or {})

    # -- observation ----------------------------------------------------

    def session(self, correlation_id: str) -> Optional[Session]:
        return self._sessions.get(correlation_id)

    @property
    def active(self) -> Tuple[Session, ...]:
        return tuple(s for s in self._sessions.values()
                     if s.state is SessionState.ESTABLISHED)

    # -- establishment ---------------------------------------------------

    def establish(self, request: SessionRequest) -> Tuple[
            Optional[Session], Tuple[Signal, ...], Optional[Refusal]]:
        """Run the §8.1 sequence. Returns (session, signals, refusal).

        Exactly one of `session` and `refusal` is non-None.
        """
        cid = request.request_id
        invoker = Invoker(self._auditor, cid)
        signals: List[Signal] = []

        try:
            # 1 — IF-IDR
            resolution = invoker.call("IF-IDR", "resolve",
                                      self._hooks.identity_resolver.resolve,
                                      request.target, request,
                                      post=self._check_resolution)

            # 2 — IF-IWF, only when resolution says the target is foreign.
            #
            # Consulted conditionally rather than on every session: a local
            # session pays nothing, and "this call leaves the MC domain" is an
            # explicit resolution outcome rather than something inferred from a
            # hook's return value.
            # 2b — IF-ICX, for a target in a partner MC system. Separate from
            # IF-IWF because nothing needs translating; what needs reconciling
            # is policy, and the partner's own levels are never read.
            partner = None
            if resolution.kind is ResolutionKind.PARTNER:
                partner = invoker.call(
                    "IF-ICX", "route",
                    self._hooks.interconnection_gateway.route,
                    request, resolution)
                if partner is None:
                    return self._refuse(cid, request, PARTNER_UNAVAILABLE,
                                        "no partner route for a partner target")
                rights = invoker.call(
                    "IF-ICX", "rights",
                    self._hooks.interconnection_gateway.rights,
                    partner.partner_id)
                if rights.allowed_call_types and \
                        request.call_type not in rights.allowed_call_types:
                    return self._refuse(
                        cid, request, PARTNER_NOT_PERMITTED,
                        f"call type {request.call_type!r} is not permitted "
                        f"with partner {partner.partner_id!r}")
                signals.append(Signal(SignalType.ROUTE_PARTNER,
                                      target=partner.gateway,
                                      detail={"partner_id": partner.partner_id,
                                              "trust": partner.trust}))

            route = None
            if resolution.kind is ResolutionKind.EXTERNAL:
                route = invoker.call("IF-IWF", "route",
                                     self._hooks.interworking_gateway.route,
                                     request, resolution)
                if route is None:
                    # The resolver called the target foreign and the gateway
                    # hook produced no route. Refusing is the only safe answer:
                    # falling back to local establishment would deliver the
                    # call to the wrong party.
                    return self._refuse(cid, request, GATEWAY_UNAVAILABLE,
                                        "no gateway for an external target")
                signals.append(Signal(SignalType.ROUTE_EXTERNAL,
                                      target=route.gateway,
                                      detail={"system": route.system}))

            # 3 — IF-PRI
            priority = invoker.call("IF-PRI", "evaluate",
                                    self._hooks.priority_policy.evaluate,
                                    request, resolution)

            # 4 — IF-SES.admit
            enriched = self._with_capacity(request)
            admission = invoker.call("IF-SES", "admit",
                                     self._hooks.session_policy.admit,
                                     enriched, resolution, priority)
            if not admission.permitted:
                return self._refuse(cid, request, admission.reason_code,
                                    "admission refused")

            # 5 — IF-SES.decide
            decision = invoker.call("IF-SES", "decide",
                                    self._hooks.session_policy.decide,
                                    request, resolution)

            # PLT-OAM-008: a session requiring recording is not established
            # when no recorder is available.
            if decision.recording_required and \
                    not self._platform.recording_available():
                return self._refuse(cid, request, RECORDING_UNAVAILABLE,
                                    "recording required but unavailable")

            # 6 — IF-SES.floor_policy, voice/video only
            floor_policy = None
            if self._has_floor_media(request):
                floor_policy = invoker.call(
                    "IF-SES", "floor_policy",
                    self._hooks.session_policy.floor_policy, request, resolution)

            # 7 — IF-BER
            bearer = invoker.call("IF-BER", "select",
                                  self._hooks.bearer_selector.select,
                                  request, priority, tuple(request.media))

            # 8 — reserve and establish
            if not self._platform.reserve_qos(bearer):
                # The core requests the QoS the profile returned; refusal by
                # the network fails the session rather than silently degrading
                # it (PLT-ICD-001 §6.1 INV-2).
                return self._refuse(cid, request, QOS_UNAVAILABLE,
                                    "network refused the requested QoS")
            signals.append(Signal(SignalType.RESERVE_QOS, detail={
                "qos_identifier": bearer.qos_identifier,
                "arp_level": bearer.arp_level,
                "paths": tuple(p.path_id for p in bearer.paths)}))

        except HookFailure as failure:
            return self._fail(cid, request, failure)

        session = Session(
            correlation_id=cid, request=request, resolution=resolution,
            priority=priority, decision=decision, bearer=bearer,
            members=tuple(resolution.members),
        )

        if floor_policy is not None:
            session.floor = floor_mod.FloorControl(
                floor_mod.Policy.from_hook(floor_policy), clock=self._clock)
            session.floor.handle(floor_mod.Event(
                floor_mod.EventType.SESSION_ESTABLISHED,
                participant=request.initiator,
                floor_priority=priority.floor_priority))

        if decision.recording_required:
            signals.append(Signal(SignalType.START_RECORDING))

        if partner is not None:
            # Like a routed session: the partner gateway alone, never also a
            # local fan-out. The resolution carries no local members.
            session.gateway = partner.gateway
            session.partner_id = partner.partner_id
            asserted = self._hooks.interconnection_gateway.map_outbound(
                request, priority)
            signals.append(Signal(SignalType.INVITE, target=partner.gateway,
                                  detail={
                                      "auto_answer": decision.auto_answer,
                                      "acknowledgement_required":
                                          decision.acknowledgement_required,
                                      "partner_target":
                                          resolution.resolved_from or request.target,
                                      "asserted": dict(asserted)}))
        elif route is not None:
            # A routed session establishes toward the gateway ONLY. It is never
            # also fanned out locally: the resolution carries no members, and
            # doing both would place the same call twice.
            session.gateway = route.gateway
            signals.append(Signal(SignalType.INVITE, target=route.gateway, detail={
                "auto_answer": decision.auto_answer,
                "acknowledgement_required": decision.acknowledgement_required,
                "external_target": resolution.resolved_from or request.target,
                "system": route.system}))
        else:
            # Fan out to exactly the resolved member set, no more and no fewer
            # (PLT-CC-004). The initiator is not invited to its own session.
            for member in resolution.members:
                if member == request.initiator:
                    continue
                signals.append(Signal(SignalType.INVITE, target=member, detail={
                    "auto_answer": decision.auto_answer,
                    "acknowledgement_required":
                        decision.acknowledgement_required}))

        session.state = SessionState.ESTABLISHED
        self._sessions[cid] = session

        self._auditor.emit(RecordType.SESSION_ADMITTED, cid,
                           call_type=request.call_type,
                           initiator=request.initiator,
                           priority=priority.label, scope=priority.scope,
                           members=len(resolution.members),
                           resolved_from=resolution.resolved_from,
                           **self._functions)
        self._auditor.emit(RecordType.SESSION_ESTABLISHED, cid,
                           members=tuple(resolution.members),
                           qos_identifier=bearer.qos_identifier,
                           recording=decision.recording_required,
                           **self._functions)
        return session, tuple(signals), None

    # -- inbound from a non-MC system -------------------------------------

    def receive_inbound(self, foreign: Mapping[str, str]) -> Tuple[
            Optional[Session], Tuple[Signal, ...], Optional[Refusal]]:
        """Accept a session request relayed by a gateway (PLT-ICD-001 §7.2).

        The mapped request re-enters the ordinary sequence at IF-IDR and
        receives NO privilege from having arrived through a gateway: it is
        resolved, prioritised and admitted exactly like a local request.
        Priority the foreign system asserted is advisory; IF-PRI decides.
        """
        cid = str(foreign.get("request_id") or "")
        invoker = Invoker(self._auditor, cid)
        try:
            request = invoker.call("IF-IWF", "map_inbound",
                                   self._hooks.interworking_gateway.map_inbound,
                                   foreign)
        except HookFailure as failure:
            placeholder = SessionRequest(
                request_id=cid, initiator=str(foreign.get("initiator") or ""),
                target=str(foreign.get("target") or ""),
                call_type=str(foreign.get("call_type") or ""), media=())
            return self._fail(cid, placeholder, failure)

        self._auditor.emit(RecordType.SESSION_ADMITTED, cid,
                           inbound_from=str(foreign.get("system") or ""),
                           mapped_call_type=request.call_type,
                           asserted_priority=str(foreign.get("priority") or ""))
        return self.establish(request)

    # -- release ---------------------------------------------------------

    def release(self, correlation_id: str,
                cause: str = "normal") -> Tuple[Signal, ...]:
        session = self._sessions.get(correlation_id)
        if session is None or session.state is not SessionState.ESTABLISHED:
            return ()
        if session.floor is not None:
            session.floor.handle(floor_mod.Event(
                floor_mod.EventType.SESSION_RELEASED))
        session.state = SessionState.RELEASED
        if session.gateway is not None:
            signals = [Signal(SignalType.BYE, target=session.gateway)]
        else:
            signals = [Signal(SignalType.BYE, target=m) for m in session.members]
        signals.append(Signal(SignalType.RELEASE_QOS))
        self._auditor.emit(RecordType.SESSION_RELEASED, correlation_id,
                           cause=cause)
        return tuple(signals)

    def abandon(self, correlation_id: str, reason: str) -> Tuple[Signal, ...]:
        """Forget a session that was established here but never became live,
        e.g. every invited party refused (PLT-SIG-005). Unlike `release`, the
        session is REMOVED, not kept in state RELEASED, so nothing about it
        remains to be found. The audit record is the only trace. Returns
        the signals to undo what
        establishment reserved (empty when there was nothing to abandon)."""
        session = self._sessions.pop(correlation_id, None)
        if session is None:
            return ()
        if session.floor is not None:
            session.floor.handle(floor_mod.Event(
                floor_mod.EventType.SESSION_RELEASED))
        self._auditor.emit(RecordType.SESSION_FAILED, correlation_id,
                           call_type=session.request.call_type,
                           initiator=session.request.initiator,
                           reason_code="", detail=reason, abandoned=True)
        return (Signal(SignalType.RELEASE_QOS),)

    # -- pre-emption -----------------------------------------------------

    def preemption_victims(self, incoming: PriorityDecision) -> Tuple[Session, ...]:
        """§8.2 steps 2–3. Selection only: the caller releases the victims.

        Every gate must pass. Cross-scope pairs are excluded by `compare`
        returning 0, and the capability and vulnerability flags are checked
        independently of it (PLT-PRI-002).
        """
        if not incoming.preemption_capability:
            return ()
        policy = self._hooks.priority_policy
        victims = []
        for session in self.active:
            candidate = session.priority
            if not candidate.preemption_vulnerability:
                continue
            if candidate.scope != incoming.scope:
                continue
            if policy.compare(incoming, candidate) <= 0:
                continue
            victims.append(session)
        return tuple(victims)

    # -- internals -------------------------------------------------------

    def _has_floor_media(self, request: SessionRequest) -> bool:
        return any(m in (MediaKind.VOICE, MediaKind.VIDEO) for m in request.media)

    def _with_capacity(self, request: SessionRequest) -> SessionRequest:
        """Supply current session counts to the admission hook.

        FINDING: PLT-ICD-001 §5.1 INV-2 says the core supplies these, but
        `SessionRequest` has no field for them, so they travel in `attributes`.
        An explicit field belongs in ICD v0.2.
        """
        attributes = dict(request.attributes)
        attributes["core.active_sessions"] = str(self._platform.active_sessions())
        return SessionRequest(
            request_id=request.request_id, initiator=request.initiator,
            target=request.target, call_type=request.call_type,
            media=request.media, application=request.application,
            urgency=request.urgency, location=request.location,
            attributes=attributes)

    def _check_resolution(self, resolution: Resolution) -> None:
        """PLT-ICD-001 §3.2 POST-1: kind and member count must agree."""
        from .errors import HookContractViolation
        if resolution.kind is ResolutionKind.USER and len(resolution.members) != 1:
            raise HookContractViolation(
                f"USER resolution returned {len(resolution.members)} members")
        if resolution.kind is ResolutionKind.GROUP:
            if not resolution.group_id:
                raise HookContractViolation("GROUP resolution has no group_id")
            if not resolution.members:
                raise HookContractViolation("GROUP resolution has no members")
        if resolution.kind in (ResolutionKind.EXTERNAL, ResolutionKind.PARTNER):
            if resolution.members:
                raise HookContractViolation(
                    f"{resolution.kind.value} resolution must carry no members, "
                    f"found {len(resolution.members)}")
            if not resolution.resolved_from:
                raise HookContractViolation(
                    f"{resolution.kind.value} resolution must record the target "
                    "in resolved_from")
        if len(set(resolution.members)) != len(resolution.members):
            raise HookContractViolation("resolution contains duplicate members")

    def _refuse(self, cid: str, request: SessionRequest, reason_code: str,
                detail: str):
        # PLT-HOK-033: nothing is established, no invitation is sent.
        self._auditor.emit(RecordType.SESSION_REFUSED, cid,
                           call_type=request.call_type,
                           initiator=request.initiator,
                           reason_code=reason_code, detail=detail)
        return None, (Signal(SignalType.RESPONSE_REJECT,
                             target=request.initiator,
                             detail={"reason_code": reason_code}),), \
            Refusal(reason_code=reason_code, detail=detail)

    def _fail(self, cid: str, request: SessionRequest, failure: HookFailure):
        self._auditor.emit(RecordType.SESSION_FAILED, cid,
                           call_type=request.call_type,
                           interface=failure.interface, method=failure.method,
                           reason_code=failure.reason_code,
                           detail=failure.detail)
        return None, (Signal(SignalType.RESPONSE_REJECT,
                             target=request.initiator,
                             detail={"reason_code": failure.reason_code}),), \
            Refusal(reason_code=failure.reason_code, detail=failure.detail)
