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

import dataclasses
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

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
    PARTNER_UNAVAILABLE,
    QOS_UNAVAILABLE,
    RECORDING_UNAVAILABLE,
    UNKNOWN_TARGET,
    HookContractViolation,
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
                 functions: Optional[Mapping[str, str]] = None,
                 defer_floor_start: bool = False,
                 adhoc_list_max: Optional[int] = None) -> None:
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
            enriched = self._with_capacity(request, invoker)
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
            if not self._defer_floor:
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

    def _with_capacity(self, request: SessionRequest,
                       invoker: Invoker) -> SessionRequest:
        """Supply what the admission hook needs and cannot find out itself:
        current session counts, and the functional identities the initiator
        holds (`initiator.roles`, read by call types that restrict who may
        start them), looked up through IF-IDR `identities_of`.

        FINDING: PLT-ICD-001 §5.1 INV-2 says the core supplies these, but
        `SessionRequest` has no field for them, so they travel in `attributes`.
        An explicit field belongs in ICD v0.2.

        FINDING (ADHOC-OP-01 work, 2026-09-25): nothing supplied
        `initiator.roles` before, so every call type declaring
        `initiator_roles` was refused not-authorised to every caller.
        Always written by the core, never taken from the request.
        """
        attributes = dict(request.attributes)
        attributes["core.active_sessions"] = str(self._platform.active_sessions())
        roles = invoker.call("IF-IDR", "identities_of",
                             self._hooks.identity_resolver.identities_of,
                             request.initiator)
        attributes["initiator.roles"] = ",".join(roles)
        # replace(), not a field-by-field rebuild: a rebuild silently dropped
        # every field added to SessionRequest after it was written.
        return dataclasses.replace(request, attributes=attributes)

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

    def _located(self, request: SessionRequest) -> SessionRequest:
        """PLT-ICD-001 2.8: a reported serving cell the profile maps gains
        the location attributes it stands for (e.g. track_section), which
        is what functional identities are keyed on. Attributes the request
        already carries are kept: the map fills in, it does not overrule.
        An unmapped cell leaves the request as it is."""
        loc = request.location
        if loc is None or not loc.cell_id:
            return request
        mapped = self._profile.identity.cells.get(loc.cell_id)
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
        limit is on the call's size, whatever named its members.
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
        # entry costs a hook call and an audit record, and this runs before
        # the caller is authorised (PLT-VP-R1 ADHOC-OP-04, ICD-OP-09).
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
        if limit is not None and len(members) > limit:
            return None, (ADHOC_TOO_MANY_PARTICIPANTS,
                          f"the criteria matched {len(members)}, limit {limit}")
        return Resolution(kind=ResolutionKind.GROUP, members=tuple(members),
                          group_id=group_id,
                          resolved_from=found.resolved_from or "adhoc:criteria"), None

    @staticmethod
    def _check_participants(resolution: Resolution) -> None:
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
