"""Session control — the §8.1 establishment sequence.

Implements PLT-ICD-001 §8.1 exactly and in order, with no step reordered and no
compensating call to a hook already invoked when a later step fails.

  0  IF-IDR.identities_of, IF-SES.authorise
                       -- refusal stops here, before the target is looked up
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

import dataclasses
import hashlib
import logging
from types import MappingProxyType
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from . import identity
from . import qos as qos_spec
from . import floor as floor_mod
from .audit import Auditor, RecordType
from .errors import (
    ADHOC_PARTICIPANTS_UNDETERMINED,
    ADHOC_TOO_MANY_PARTICIPANTS,
    GATEWAY_UNAVAILABLE,
    NOT_AUTHORISED,
    NO_BINDING,
    NO_LOCATION_BINDING,
    PARTNER_NOT_PERMITTED,
    PARTICIPANT_LIMIT_EXCEEDED,
    PARTNER_UNAVAILABLE,
    QOS_UNAVAILABLE,
    RECORDING_UNAVAILABLE,
    UNKNOWN_TARGET,
    HookContractViolation,
)
from .hooks import (
    Admission,
    BearerDecision,
    FloorPolicy,
    MediaKind,
    PathSpec,
    ResolutionKind,
    PriorityDecision,
    SessionModel,
    Resolution,
    SessionDecision,
    SessionRequest,
)
from .invoke import HookFailure, Invoker
from .loader import LoadedProfile
from .validation import FLOOR_TIMERS, PREEMPTION_AT_FULL_QUEUE, REDUNDANCY, TRANSPORTS

log = logging.getLogger("mcx.session")


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
    # The §8.1 step that refused, when a transport needs to say more than the
    # code: "authorise" for step 0 (TS 24.379 17.4.2.2 steps 3B-5 answer an
    # authorisation refusal of an ad hoc call differently). Empty otherwise.
    step: str = ""


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
    # Set when the group had more members than the session decision allows
    # (TS 24.379 6.3.5.5): how many it had. `members` are those that take part.
    truncated_from: Optional[int] = None


# RES-OP-14: what a floor transition the audit store cannot take does.
FLOOR_UNRECORDED = ("deny", "allow")



class _CountingAuditor:
    """MCX_FLOOR_UNRECORDED=allow: the floor's records, written or counted
    (RES-OP-14)."""

    def __init__(self, auditor: Auditor) -> None:
        self._auditor = auditor

    def emit(self, record_type: RecordType, correlation_id: str, **detail: Any):
        return self._auditor.emit_or_count(record_type, correlation_id, **detail)

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
                 functions: Optional[Mapping[str, str]] = None,
                 defer_floor_start: bool = False,
                 adhoc_list_max: Optional[int] = None,
                 cells: Optional[Mapping[str, Mapping[str, str]]] = None,
                 floor_unrecorded: str = "deny") -> None:
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
        # When True the floor machine is built at establishment but started
        # by `start_floor`. A host that must first invite the other parties
        # sets this so the initiator's grant timers do not run while callees
        # are still ringing.
        self._defer_floor = defer_floor_start
        # The deployment's cap on an ad hoc participant list (the host's
        # MCX_ADHOC_LIST_MAX, required there). None only for a manager built
        # by hand, and then the call type's limit alone applies.
        self._adhoc_list_max = adhoc_list_max
        # Serving cell -> location attributes: deployment data, supplied by
        # the host (the network profile; PLT-ICD-001 2.8, PRF-OP-03).
        self._cells = dict(cells or {})
        # RES-OP-14 (owner ruling 2026-10-16, MCX_FLOOR_UNRECORDED, required
        # in the service): a floor transition the audit store cannot take is
        # "deny": undone and not sent, so the floor stops until the store
        # recovers (PLT-FC-011 kept); or "allow": it stands and is sent, and
        # the transitions lost are counted and written as one `audit-gap`
        # record when the store takes records again.
        if floor_unrecorded not in FLOOR_UNRECORDED:
            raise ValueError(f"floor_unrecorded {floor_unrecorded!r} is not one of "
                             f"{', '.join(FLOOR_UNRECORDED)}")
        self._floor_unrecorded = floor_unrecorded

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
        request = self._located(request)

        try:
            # 0 — IF-SES.authorise, before anything about the target is
            # looked up (ICD-OP-09; TS 24.379 17.4.2.2 authorises in steps 4
            # and 5 and determines participants in step 12). Otherwise an
            # unauthorised caller learns from the refusal whether a user
            # exists or a role is held: "nobody matches" against "not allowed".
            #
            # The roles are the core's, written once, here: every hook from
            # now on sees them, and none sees what the request carried
            # under that name (review of ICD-OP-09).
            request = self._with_roles(request, invoker)
            authorisation = invoker.call(
                "IF-SES", "authorise", self._hooks.session_policy.authorise,
                self._without_target(request), post=self._check_admission)
            if not authorisation.permitted:
                return self._refuse(cid, request, authorisation.reason_code,
                                    "not authorised to start this call type",
                                    step="authorise")

            # 1 — IF-IDR. An ad hoc group call names no group; its members
            # come from the caller's list or criteria (§3.5).
            if request.adhoc:
                resolution, refusal = self._adhoc_members(invoker, request)
                if refusal is not None:
                    return self._refuse(cid, request, *refusal)
            else:
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
                                     enriched, resolution, priority,
                                     post=self._check_admission)
            if not admission.permitted:
                return self._refuse(cid, request, admission.reason_code,
                                    "admission refused")

            # 5 — IF-SES.decide
            decision = invoker.call("IF-SES", "decide",
                                    self._hooks.session_policy.decide,
                                    request, resolution,
                                    post=lambda d: self._check_decision(d, request))

            # §5.2 INV-1: the decision's limit is applied as decided, whatever
            # the profile's table says (RES-OP-12).
            truncated_from = None
            limit = decision.max_participants
            if limit is not None and len(resolution.members) > limit:
                over = (f"{len(resolution.members)} participants, "
                        f"the session decision allows {limit}")
                if request.adhoc:
                    # 17.4.2.2: an ad hoc call over its limit is refused, 189.
                    return self._refuse(cid, request, ADHOC_TOO_MANY_PARTICIPANTS, over)
                if not self._is_group_call(request, resolution):
                    return self._refuse(cid, request, PARTICIPANT_LIMIT_EXCEEDED, over)
                if self._over_limit(request) == "refuse":
                    # The profile's recorded deviation from 6.3.5.5 (RES-OP-12
                    # ruling 1 as a setting, 2026-10-16): 486 + 122 as for a
                    # call already full (10.1.2).
                    return self._refuse(cid, request, PARTICIPANT_LIMIT_EXCEEDED,
                                        over + " (group_over_limit: refuse)")
                # 6.3.5.5 and 10.1.1.4.1: a group call is not refused; only
                # `limit` of its members take part, and the 200 OK says so
                # with warning 122.
                kept = self._first_members(resolution.members, request.initiator, limit)
                if not [m for m in kept if m != request.initiator]:
                    # A limit of 1 on a group the caller belongs to leaves no
                    # one to invite: a call with no callee is not established.
                    return self._refuse(cid, request, PARTICIPANT_LIMIT_EXCEEDED,
                                        over + ", so no one else can be invited")
                truncated_from = len(resolution.members)
                resolution = dataclasses.replace(resolution, members=kept)

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
                    self._hooks.session_policy.floor_policy, request, resolution,
                    post=lambda p: self._check_floor_policy_for(p, request))

            # 7 — IF-BER
            bearer = invoker.call("IF-BER", "select",
                                  self._hooks.bearer_selector.select,
                                  request, priority, tuple(request.media),
                                  post=lambda b: self._check_bearer(b, priority))

            # 7b — IF-ICX.map_outbound: what the partner is told, before any
            # QoS is reserved, so a failing hook leaves nothing to undo.
            asserted = None
            if partner is not None:
                asserted = invoker.call(
                    "IF-ICX", "map_outbound",
                    self._hooks.interconnection_gateway.map_outbound,
                    request, priority)

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
            members=tuple(resolution.members), truncated_from=truncated_from,
        )

        if floor_policy is not None:
            # Every floor transition goes to the audit trail under the
            # session's correlation id, whoever drives the machine (PLT-FC-011,
            # RES-OP-03).
            session.floor = floor_mod.FloorControl(
                floor_mod.Policy.from_hook(floor_policy), clock=self._clock,
                observer=self._floor_observer(cid))

        if decision.recording_required:
            signals.append(Signal(SignalType.START_RECORDING))

        if partner is not None:
            # Like a routed session: the partner gateway alone, never also a
            # local fan-out. The resolution carries no local members.
            session.gateway = partner.gateway
            session.partner_id = partner.partner_id
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
                    # For <mcptt-calling-group-id> (TS 24.379 10.1.1.4.1.1 item
                    # 4b; for an ad hoc call the generated identity, 17.4.2.1.1
                    # item 4b).
                    "group_id": resolution.group_id,
                    # 17.4.2.1.1 item 4c: the criteria travel to each member.
                    "participant_criteria": request.participant_criteria,
                    "auto_answer": decision.auto_answer,
                    "acknowledgement_required":
                        decision.acknowledgement_required}))

        session.state = SessionState.ESTABLISHED
        self._sessions[cid] = session
        unreported = self._unreported_floor_deviation(request, floor_policy)
        if unreported:
            log.warning("session %s: %s", cid, unreported[0]["consequence"],
                        extra={"correlation_id": cid})
        try:
            self._auditor.emit(RecordType.SESSION_ADMITTED, cid,
                               call_type=request.call_type,
                               initiator=request.initiator,
                               priority=priority.label, scope=priority.scope,
                               members=len(resolution.members),
                               resolved_from=resolution.resolved_from,
                               **self._functions)
            self._auditor.emit(RecordType.SESSION_ESTABLISHED, cid,
                               members=tuple(resolution.members),
                               truncated_from=truncated_from,
                               qos_identifier=bearer.qos_identifier,
                               recording=decision.recording_required,
                               **({"deviations": unreported} if unreported else {}),
                               **self._functions)
        except BaseException:
            # Not recorded, so not established: a session left here would
            # count toward capacity and be a pre-emption candidate, with no
            # record of it ever (review of RES-OP-14). Its trail is closed
            # where it can be: a failure record, best effort.
            self._sessions.pop(cid, None)
            self._emit_unless_lost(RecordType.SESSION_FAILED, cid,
                                   call_type=request.call_type,
                                   initiator=request.initiator,
                                   reason_code="", detail="establishment not recorded")
            raise
        # The floor starts after the session's own records, so the trail
        # reads admitted, established, then the floor.
        if session.floor is not None and not self._defer_floor:
            session.floor.handle(floor_mod.Event(
                floor_mod.EventType.SESSION_ESTABLISHED,
                participant=request.initiator,
                floor_priority=priority.floor_priority))
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
        # A read-only copy: the gateway must not change what the core reads
        # back below, nor the caller's own mapping (RES-OP-06).
        foreign = MappingProxyType(dict(foreign))
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
        # A release is never undone nor held up by the audit trail: a session
        # kept up because its record could not be written is the unsafe way
        # to fail. A record that cannot be written is logged as lost, and the
        # release completes (RES-OP-03 review).
        self._final_floor(session)
        session.state = SessionState.RELEASED
        if session.gateway is not None:
            signals = [Signal(SignalType.BYE, target=session.gateway)]
        else:
            signals = [Signal(SignalType.BYE, target=m) for m in session.members]
        signals.append(Signal(SignalType.RELEASE_QOS))
        self._emit_unless_lost(RecordType.SESSION_RELEASED, correlation_id,
                               cause=cause)
        return tuple(signals)

    def _final_floor(self, session: Session) -> None:
        """End the session's floor; its last transition stands even if its
        record cannot be written (FloorControl.handle `final`)."""
        if session.floor is None:
            return
        try:
            session.floor.handle(floor_mod.Event(floor_mod.EventType.SESSION_RELEASED),
                                 final=True)
        except Exception:                                   # noqa: BLE001
            log.exception("session %s: floor release not recorded; released anyway",
                          session.correlation_id,
                          extra={"correlation_id": session.correlation_id})

    def _emit_unless_lost(self, record_type: RecordType, correlation_id: str,
                          **detail: Any) -> None:
        try:
            self._auditor.emit(record_type, correlation_id, **detail)
        except Exception:                                   # noqa: BLE001
            log.exception("session %s: %s record lost; the session ended anyway",
                          correlation_id, record_type.value,
                          extra={"correlation_id": correlation_id})

    # -- floor audit (PLT-FC-011, RES-OP-14) ------------------------------

    def _floor_observer(self, cid: str) -> Callable[[floor_mod.Transition], None]:
        auditor = self.floor_auditor()
        return lambda transition: auditor.emit(
            RecordType.FLOOR_TRANSITION, cid, **transition.as_record())

    def floor_auditor(self) -> Any:
        """What records the floor's work: its transitions, and the IF-PRI
        evaluations a floor request makes (a host's Invoker for those uses
        this). Under "deny" the auditor itself: a failed write reaches the
        caller, and FloorControl.handle undoes the transition. Under "allow"
        one whose failed write is counted into the auditor's gap and lets the
        work go on (Auditor.emit_or_count)."""
        return self._auditor if self._floor_unrecorded == "deny" else \
            _CountingAuditor(self._auditor)

    def floor_audit_state(self) -> Dict[str, Any]:
        """For the health document: the setting, the floor's records lost
        since the process started (transitions and floor-request IF-PRI
        evaluations), and the gap still to be written, if any."""
        return {"floor_unrecorded": self._floor_unrecorded,
                **self._auditor.gap_state()}

    def start_floor(self, correlation_id: str) -> Tuple[floor_mod.Action, ...]:
        """Start a deferred floor machine; returns its opening actions.
        Idempotent: a machine already started returns nothing."""
        session = self._sessions.get(correlation_id)
        if session is None or session.floor is None or \
                session.floor.state is not floor_mod.FloorState.START_STOP:
            return ()
        return session.floor.handle(floor_mod.Event(
            floor_mod.EventType.SESSION_ESTABLISHED,
            participant=session.request.initiator,
            floor_priority=session.priority.floor_priority))

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
        self._final_floor(session)
        self._emit_unless_lost(RecordType.SESSION_FAILED, correlation_id,
                               call_type=session.request.call_type,
                               initiator=session.request.initiator,
                               reason_code="", detail=reason, abandoned=True)
        return (Signal(SignalType.RELEASE_QOS),)

    # -- pre-emption -----------------------------------------------------

    def preemption_victims(self, incoming: PriorityDecision,
                           correlation_id: str) -> Tuple[Session, ...]:
        """§8.2 steps 2–3. Selection only: the caller releases the victims.

        Every gate must pass. Cross-scope pairs are excluded by `compare`
        returning 0, and the capability and vulnerability flags are checked
        independently of it (PLT-PRI-002).

        Each `compare` is an invocation like any other (ICD-GEN-040/041),
        audited under the incoming session's `correlation_id`; one that fails
        raises HookFailure, and the caller fails the incoming session
        (ICD-GEN-021), as for any hook on its path.
        """
        if not incoming.preemption_capability:
            return ()
        policy = self._hooks.priority_policy
        invoker = Invoker(self._auditor, correlation_id)
        victims = []
        for session in self.active:
            candidate = session.priority
            if not candidate.preemption_vulnerability:
                continue
            if candidate.scope != incoming.scope:
                continue
            if invoker.call("IF-PRI", "compare", policy.compare, incoming, candidate,
                            post=self._check_comparison) <= 0:
                continue
            victims.append(session)
        return tuple(victims)

    # -- internals -------------------------------------------------------

    def _has_floor_media(self, request: SessionRequest) -> bool:
        return any(m in (MediaKind.VOICE, MediaKind.VIDEO) for m in request.media)

    def _with_roles(self, request: SessionRequest,
                    invoker: Invoker) -> SessionRequest:
        """The functional identities the initiator holds (`initiator.roles`,
        read by call types that restrict who may start them), looked up
        through IF-IDR `identities_of`, for authorisation and admission.

        FINDING (ADHOC-OP-01 work, 2026-09-25): nothing supplied
        `initiator.roles` before, so every call type declaring
        `initiator_roles` was refused not-authorised to every caller.
        Always written by the core, never taken from the request.
        """
        attributes = dict(request.attributes)
        roles = invoker.call("IF-IDR", "identities_of",
                             self._hooks.identity_resolver.identities_of,
                             request.initiator)
        attributes["initiator.roles"] = ",".join(roles)
        # replace(), not a field-by-field rebuild: a rebuild silently dropped
        # every field added to SessionRequest after it was written.
        return dataclasses.replace(request, attributes=attributes)

    @staticmethod
    def _without_target(request: SessionRequest) -> SessionRequest:
        """What authorise may see (§5.0 INV-1): the request with every field
        that names or selects the called party emptied. The guarantee that
        the answer cannot depend on the target is then structural, not a
        convention each profile must keep."""
        return dataclasses.replace(request, target="", participants=(),
                                   participant_criteria=None,
                                   adhoc_alert_group=False)

    def _with_capacity(self, request: SessionRequest) -> SessionRequest:
        """What admission needs and cannot find out itself: current session
        counts.

        FINDING: PLT-ICD-001 §5.1 INV-2 says the core supplies these, but
        `SessionRequest` has no field for them, so they travel in `attributes`.
        An explicit field belongs in ICD v0.2.
        """
        attributes = dict(request.attributes)
        attributes["core.active_sessions"] = str(self._platform.active_sessions())
        return dataclasses.replace(request, attributes=attributes)

    def _check_admission(self, admission: Admission) -> None:
        """PLT-ICD-001 §5.1 POST-2 and POST-3, for authorise and admit alike:
        a permission carries no code, and a refusal carries a code the
        profile declared. The core checks it rather than trust the hook:
        a refusal with no code would reach the caller unexplained."""
        if admission.permitted:
            if admission.reason_code:
                raise HookContractViolation(
                    f"permitted, with reason code {admission.reason_code!r}")
        elif admission.reason_code not in \
                self._profile.admission.reject_reason_codes:
            raise HookContractViolation(
                f"refused with reason code {admission.reason_code!r}, which the "
                "profile does not declare")

    def _outside_domains(self, members) -> List[str]:
        """PLT-ICD-001 §3.2 POST-3 (PLT-IDM-008): the members not within one
        of the profile's declared domains (core/identity.py, RES-OP-01)."""
        return identity.outside(members, self._profile.identity.domains)

    def _check_resolution(self, resolution: Resolution) -> None:
        """PLT-ICD-001 §3.2 POST-1: kind and member count must agree; POST-2:
        no duplicates; POST-3: every member within a declared domain."""
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
        outside = self._outside_domains(resolution.members)
        if outside:
            raise HookContractViolation(
                f"resolution returned {len(outside)} member(s) outside the "
                f"profile's declared domains: {', '.join(map(repr, outside[:3]))}")

    def _check_decision(self, decision: SessionDecision,
                        request: SessionRequest) -> None:
        """PLT-ICD-001 §5.2 POST-1 and POST-2 on what `decide` returned
        (RES-OP-12). POST-1's "consistent with the call type's declared
        session model" is read as the same model: the model is declared per
        call type and nothing else could make another one consistent."""
        if type(decision) is not SessionDecision:
            raise HookContractViolation(
                f"session decision is a {type(decision).__name__}, not a SessionDecision")
        for name in ("auto_answer", "acknowledgement_required", "recording_required"):
            if type(getattr(decision, name)) is not bool:
                raise HookContractViolation(
                    f"session decision {name} {getattr(decision, name)!r} is not a boolean")
        declared = self._profile.call_type(request.call_type)
        if declared is None:
            raise HookContractViolation(
                f"session decision for undeclared call type {request.call_type!r}")
        if decision.model is not SessionModel(declared.session_model):
            raise HookContractViolation(
                f"session decision model {decision.model!r} is not call type "
                f"{declared.id!r}'s declared {declared.session_model!r} (§5.2 POST-1)")
        limit = decision.max_participants
        if limit is not None and (type(limit) is not int or limit < 1):
            raise HookContractViolation(
                f"session decision max_participants {limit!r} is neither None nor "
                "an integer of at least 1 (§5.2 POST-2)")

    def _is_group_call(self, request: SessionRequest, resolution: Resolution) -> bool:
        """A group session in the sense of TS 24.379 6.3.5.5: a group
        resolved for a call type that is not a private call. A private call
        whose target resolved to a group is not made a smaller group call."""
        if resolution.kind is not ResolutionKind.GROUP:
            return False
        declared = self._profile.call_type(request.call_type)
        signature = declared.mc_signature if declared is not None else None
        return signature is None or signature.session_type != "private"

    def _over_limit(self, request: SessionRequest) -> str:
        """The call type's `group_over_limit`: "truncate" or "refuse". Only
        reached for a group call, whose call type `_is_group_call` found."""
        declared = self._profile.call_type(request.call_type)
        if declared is None:
            raise HookContractViolation(
                f"group call for undeclared call type {request.call_type!r}")
        return declared.group_over_limit

    def _unreported_floor_deviation(self, request: SessionRequest,
                                    policy: Optional[FloorPolicy]) -> list:
        """The startup report lists `deny` where the call type DECLARES both
        queueing and override. A hook may compute both flags (§5.3), so a
        session whose policy enables them where the declaration does not runs
        `deny` unreported: say so in its own record (review, 2026-10-16)."""
        if policy is None or policy.preemption_at_full_queue != "deny" or \
                not (policy.queueing_enabled and policy.override_allowed):
            return []
        declared = self._profile.call_type(request.call_type)
        if declared is not None and declared.floor.queueing_enabled and \
                declared.floor.override_allowed:
            return []                        # reported at startup
        return [{"setting": f"call_types[{request.call_type}].floor."
                            "preemption_at_full_queue",
                 "value": "deny", "ref": "FC-OP-07",
                 "departs_from": "TS 24.380 6.3.4.4.7 item 2e",
                 "consequence": "the floor policy enables queueing and override where "
                                "the call type declares otherwise, so a pre-emptor "
                                "meeting a full queue is denied queue-full, which the "
                                "startup report does not list"}]

    def _check_floor_policy_for(self, policy: FloorPolicy,
                                request: SessionRequest) -> None:
        """§5.3 POST-1..5, and POST-5 read as equality: the pre-emptor's
        place is the call type's declared choice, so what the service reports
        at startup is what runs (review of the 2026-10-16 settings)."""
        self._check_floor_policy(policy)
        declared = self._profile.call_type(request.call_type)
        if declared is not None and policy.preemption_at_full_queue != \
                declared.floor.preemption_at_full_queue:
            raise HookContractViolation(
                f"floor policy preemption_at_full_queue "
                f"{policy.preemption_at_full_queue!r} is not the call type's declared "
                f"{declared.floor.preemption_at_full_queue!r} (§5.3 POST-5)")

    @staticmethod
    def _first_members(members: Sequence[str], initiator: str,
                       limit: int) -> Tuple[str, ...]:
        """The `limit` participants of a group call over its limit.

        TS 24.379 6.3.5.5 NOTE 2 counts the session's participants, so the
        initiator, when a member, is one of them and always kept. The others
        are taken in the resolver's order: the platform has no
        <on-network-required> members, and which to prefer is otherwise
        operator policy (NOTE 3), which the profile states in that order."""
        keep = limit - 1 if initiator in members else limit
        others = [m for m in members if m != initiator][:keep]
        return tuple(m for m in members if m == initiator or m in others)

    @staticmethod
    def _check_comparison(result: int) -> None:
        """§4.2: `compare` returns an integer; `True` is not one."""
        if type(result) is not int:
            raise HookContractViolation(
                f"compare returned {type(result).__name__}, not an integer")

    @staticmethod
    def _check_floor_policy(policy: FloorPolicy) -> None:
        """PLT-ICD-001 §5.3 POST-1/2/3, checked on what the hook returned:
        profile validation checks the in-tree tables, not a hook that computes
        its policy (RES-OP-07). The value must be a FloorPolicy itself, not
        something shaped like one: only a Value is known to read the same
        twice, so a check on anything else proves nothing about what the
        floor machine is then built from."""
        if type(policy) is not FloorPolicy:
            raise HookContractViolation(
                f"floor policy is a {type(policy).__name__}, not a FloorPolicy")
        for name in ("initial_grant_to_initiator", "queueing_enabled", "override_allowed"):
            if not isinstance(getattr(policy, name), bool):
                raise HookContractViolation(
                    f"floor policy {name} {getattr(policy, name)!r} is not a boolean")
        depth = policy.max_queue_depth
        # A negative depth needs no clause of its own: POST-1 or POST-2 refuses it.
        if isinstance(depth, bool) or not isinstance(depth, int):
            raise HookContractViolation(
                f"floor policy max_queue_depth {depth!r} is not an integer")
        if not policy.queueing_enabled and depth != 0:
            raise HookContractViolation(
                f"floor policy disables queueing but sets max_queue_depth {depth}")
        if policy.queueing_enabled and depth < 1:
            raise HookContractViolation(
                "floor policy enables queueing with max_queue_depth 0")
        if type(policy.preemption_at_full_queue) is not str or \
                policy.preemption_at_full_queue not in PREEMPTION_AT_FULL_QUEUE:
            raise HookContractViolation(
                f"floor policy preemption_at_full_queue "
                f"{policy.preemption_at_full_queue!r} is not one of "
                f"{', '.join(PREEMPTION_AT_FULL_QUEUE)}")
        if not isinstance(policy.timers_ms, Mapping):
            raise HookContractViolation(
                f"floor policy timers_ms is a {type(policy.timers_ms).__name__}, "
                "not a mapping")
        for name, ms in policy.timers_ms.items():
            if name not in FLOOR_TIMERS:
                raise HookContractViolation(
                    f"floor policy names {name!r}, which is not a TS 24.380 timer")
            if isinstance(ms, bool) or not isinstance(ms, int) or ms <= 0:
                raise HookContractViolation(
                    f"floor policy timer {name} is {ms!r}, not a positive integer "
                    "of milliseconds")

    @staticmethod
    def _check_bearer(bearer: BearerDecision, priority: PriorityDecision) -> None:
        """PLT-ICD-001 §6.1 POST-1/2/3/5, and of POST-4 what the core can
        know: the ARP level is within TS 23.501 5.7.2.2. Which 5QIs a network
        offers is deployment knowledge (RES-OP-07). Each check is one profile
        validation makes of an in-tree bearer rule, so a profile that
        validates cannot fail here."""
        if type(bearer) is not BearerDecision:
            raise HookContractViolation(
                f"bearer decision is a {type(bearer).__name__}, not a BearerDecision")
        paths = bearer.paths
        if not isinstance(paths, tuple):
            raise HookContractViolation(
                f"bearer decision paths is a {type(paths).__name__}, not a sequence")
        if not all(type(p) is PathSpec for p in paths):
            raise HookContractViolation("bearer decision paths are not all PathSpecs")
        if not all(isinstance(p.primary, bool) for p in paths):
            raise HookContractViolation("bearer decision path primary flags "
                                        f"{[p.primary for p in paths]!r} are not booleans")
        primaries = sum(1 for p in paths if p.primary)
        if primaries != 1:
            raise HookContractViolation(
                f"bearer decision has {len(paths)} paths and {primaries} primary; "
                "exactly one primary is required")
        ids = [p.path_id for p in paths]
        if not all(isinstance(i, str) for i in ids) or len(set(ids)) != len(ids):
            raise HookContractViolation(
                f"bearer decision path ids {ids!r} are not distinct strings")
        for p in paths:
            if p.transport not in TRANSPORTS:
                raise HookContractViolation(
                    f"bearer decision path {p.path_id!r} transport {p.transport!r} "
                    f"is not one of {', '.join(TRANSPORTS)}")
            if isinstance(p.weight, bool) or not isinstance(p.weight, int) or p.weight < 1:
                raise HookContractViolation(
                    f"bearer decision path {p.path_id!r} weight {p.weight!r} is not "
                    "an integer of at least 1")
        if bearer.redundancy not in REDUNDANCY:
            raise HookContractViolation(
                f"bearer decision redundancy {bearer.redundancy!r} is not one of "
                f"{', '.join(REDUNDANCY)}")
        if bearer.redundancy == "single" and len(paths) != 1:
            raise HookContractViolation(
                f"bearer decision redundancy 'single' with {len(paths)} paths")
        if bearer.redundancy != "single" and len(paths) < 2:
            raise HookContractViolation(
                f"bearer decision redundancy {bearer.redundancy!r} with one path")
        for name in ("qos_identifier", "arp_level"):
            v = getattr(bearer, name)
            if isinstance(v, bool) or not isinstance(v, int):
                raise HookContractViolation(f"bearer decision {name} {v!r} is not an integer")
        if not qos_spec.ARP_MIN <= bearer.arp_level <= qos_spec.ARP_MAX:
            raise HookContractViolation(
                f"bearer decision ARP level {bearer.arp_level} is outside "
                f"{qos_spec.ARP_MIN}..{qos_spec.ARP_MAX} (TS 23.501 5.7.2.2)")
        for name in ("arp_preemption_capability", "arp_preemption_vulnerability"):
            if not isinstance(getattr(bearer, name), bool):
                raise HookContractViolation(
                    f"bearer decision {name} {getattr(bearer, name)!r} is not a boolean")
        # `is not True`: IF-PRI's decision is not itself checked, and a truthy
        # "false" there must not grant what only True grants.
        if bearer.arp_preemption_capability and priority.preemption_capability is not True:
            raise HookContractViolation(
                "bearer decision asks for ARP pre-emption capability, which the "
                "priority decision does not grant (§6.1 POST-5)")

    def _located(self, request: SessionRequest) -> SessionRequest:
        """PLT-ICD-001 2.8: a reported serving cell the deployment maps gains
        the location attributes it stands for (e.g. track_section), which
        is what functional identities are keyed on. Attributes the request
        already carries are kept: the map fills in, it does not overrule.
        An unmapped cell leaves the request as it is."""
        loc = request.location
        if loc is None or not loc.cell_id:
            return request
        mapped = self._cells.get(loc.cell_id)
        if not mapped:
            return request
        attributes = {**mapped, **loc.attributes}
        return dataclasses.replace(
            request, location=dataclasses.replace(loc, attributes=attributes))

    # -- ad hoc group calls (TS 24.379 clause 17; PLT-ICD-001 §3.5) -------

    def adhoc_group_id(self, correlation_id: str) -> str:
        """The ad hoc group identity the controlling function generates
        (17.4.2.2 step 10): stable for the session, in the profile's first
        declared domain. The Call-ID is hashed, not embedded, because it may
        hold characters a SIP URI user part cannot."""
        digest = hashlib.sha256(correlation_id.encode("utf-8")).hexdigest()[:16]
        return f"sip:adhoc-{digest}@{self._profile.identity.domains[0]}"

    def _adhoc_members(self, invoker: Invoker, request: SessionRequest
                       ) -> Tuple[Optional[Resolution], Optional[Tuple[str, str]]]:
        """(resolution, None), or (None, (reason_code, detail)) to refuse.

        In the order of 17.4.2.2 (Rel-18 numbering):
          step 6   a list longer than the limit: 189. The limits are the call
                   type's `max_participants` and the deployment's list cap
                   (ADHOC-OP-04); the caller is not counted, since it is
                   never invited.
          step 7   a list AND criteria: 187.
          step 7A  a call following an ad hoc emergency alert names the
                   alert's group; this platform keeps no such groups, so
                   the group "does not exist": 187.
          step 12  i: each listed entry is a user to invite, resolved through
                   IF-IDR so the profile's directory and domain rules apply;
                   an entry that yields no user (unknown, outside the
                   domains, a group, an unheld or location-less functional
                   identity) is left out. ii: criteria go to the profile.
                   Neither a list nor criteria: nothing to determine, 187.
        Criteria that find more members than the limit are also 189: the
        limit is on the call's size, whatever named its members. That check
        is the session decision's, after IF-SES `decide` (RES-OP-12).

        Step 6 is the one place the core reads the call type's declared
        limit rather than the session decision's: 17.4.2.2 checks the list
        against the configured <max-no-participants> before step 12
        determines the participants, and `decide` needs them (PLT-ICD-001
        §5.2, "Checked and applied by the core").
        """
        listed = tuple(u for u in dict.fromkeys(request.participants)
                       if u != request.initiator)
        criteria = request.participant_criteria
        call_type = self._profile.call_type(request.call_type)
        limit = call_type.max_participants if call_type else None
        if limit is not None and len(listed) > limit:
            return None, (ADHOC_TOO_MANY_PARTICIPANTS,
                          f"{len(listed)} participants listed, limit {limit}")
        # The deployment's cap, checked before any entry is resolved: every
        # entry costs a hook call and an audit record (PLT-VP-R1
        # ADHOC-OP-04). The caller has been authorised by now (ICD-OP-09).
        cap = self._adhoc_list_max
        if cap is not None and len(listed) > cap:
            return None, (ADHOC_TOO_MANY_PARTICIPANTS,
                          f"{len(listed)} participants listed, deployment limit {cap}")
        if listed and criteria is not None:
            return None, (ADHOC_PARTICIPANTS_UNDETERMINED,
                          "both a participant list and criteria were given")
        if request.adhoc_alert_group:
            return None, (ADHOC_PARTICIPANTS_UNDETERMINED,
                          "no ad hoc emergency alert group is kept by this platform")
        if not listed and criteria is None:
            return None, (ADHOC_PARTICIPANTS_UNDETERMINED,
                          "no participant list and no criteria")
        group_id = self.adhoc_group_id(request.request_id)
        if listed:
            members: List[str] = []
            for entry in listed:
                try:
                    one = invoker.call("IF-IDR", "resolve",
                                       self._hooks.identity_resolver.resolve,
                                       entry, request,
                                       post=self._check_resolution)
                except HookFailure as failure:
                    if failure.reason_code in (UNKNOWN_TARGET, NOT_AUTHORISED,
                                               NO_BINDING, NO_LOCATION_BINDING):
                        continue          # yields no user this profile can invite
                    raise
                if one.kind is ResolutionKind.USER and one.members[0] not in members:
                    members.append(one.members[0])
            if not members:
                return None, (ADHOC_PARTICIPANTS_UNDETERMINED,
                              "no listed participant is a user of this profile")
            return Resolution(kind=ResolutionKind.GROUP, members=tuple(members),
                              group_id=group_id, resolved_from="adhoc:list"), None
        found = invoker.call("IF-IDR", "determine_participants",
                             self._hooks.identity_resolver.determine_participants,
                             criteria, request, post=self._check_participants)
        members = [m for m in found.members if m != request.initiator]
        if not members:
            return None, (ADHOC_PARTICIPANTS_UNDETERMINED,
                          "the criteria matched only the caller")
        return Resolution(kind=ResolutionKind.GROUP, members=tuple(members),
                          group_id=group_id,
                          resolved_from=found.resolved_from or "adhoc:criteria"), None

    def _check_participants(self, resolution: Resolution) -> None:
        """§3.5 POST: a GROUP resolution with at least one member, no
        duplicates, and no group identity -- the ad hoc identity is the
        controlling function's to generate (17.4.2.2 step 10), not the
        profile's."""
        if resolution.kind is not ResolutionKind.GROUP:
            raise HookContractViolation(
                f"determine_participants returned {resolution.kind.value}, not group")
        if resolution.group_id is not None:
            raise HookContractViolation(
                "determine_participants must not name a group identity")
        if not resolution.members:
            raise HookContractViolation("determine_participants returned no members")
        if len(set(resolution.members)) != len(resolution.members):
            raise HookContractViolation("determine_participants returned duplicates")
        outside = self._outside_domains(resolution.members)
        if outside:
            raise HookContractViolation(
                f"determine_participants returned {len(outside)} member(s) outside "
                f"the profile's declared domains: {', '.join(map(repr, outside[:3]))}")

    def _refuse(self, cid: str, request: SessionRequest, reason_code: str,
                detail: str, step: str = ""):
        # PLT-HOK-033: nothing is established, no invitation is sent.
        self._auditor.emit(RecordType.SESSION_REFUSED, cid,
                           call_type=request.call_type,
                           initiator=request.initiator,
                           reason_code=reason_code, detail=detail)
        return None, (Signal(SignalType.RESPONSE_REJECT,
                             target=request.initiator,
                             detail={"reason_code": reason_code}),), \
            Refusal(reason_code=reason_code, detail=detail, step=step)

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
