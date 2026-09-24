"""Floor control state machine (TS 24.380, controlling side).

PLT-FC-004 requires this to be independently testable: it has no dependency on
SIP, media or the network. Events go in, actions come out, and an injected clock
drives every timer, so a run is deterministic and reproducible.

Invariants the machine enforces rather than assumes:

  PLT-FC-003  at most one participant holds the floor, checked on every
              transition, not only where a grant is issued
  PLT-FC-005  arbitration uses the floor priority supplied by IF-PRI; the
              machine never derives a priority of its own
  PLT-FC-006  the queue is bounded and ordered by the session's floor policy
  PLT-FC-010  timer VALUES come from the profile; the transitions they drive
              are fixed here (PLT-PRF-031)
  PLT-FC-011  every transition is recorded with trigger, timestamp and result

Timer names were checked against TS 24.380 (V15.4.0 and V18.6.0 agree): this
module is the on-network floor control SERVER, so it uses the clause 6.3 server
timers T1/T2/T3/T4/T7/T8/T20. It previously used T203/T205/T206, which are
off-network PARTICIPANT timers from clause 7.2.3 — the wrong family. The
machine's structure never depended on the mapping; only the names did.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------


class FloorState(Enum):
    START_STOP = "start-stop"
    IDLE = "floor-idle"
    TAKEN = "floor-taken"
    REVOKING = "pending-revoke"
    RELEASED = "released"


class EventType(Enum):
    SESSION_ESTABLISHED = "session-established"
    SESSION_RELEASED = "session-released"
    FLOOR_REQUEST = "floor-request"
    FLOOR_RELEASE = "floor-release"
    FLOOR_REVOKE = "floor-revoke"
    FLOOR_ACK = "floor-ack"
    PARTICIPANT_LEFT = "participant-left"
    TIMER_EXPIRY = "timer-expiry"
    # "an indication from the media distributor ... that RTP media packets
    # are received" (TS 24.380 6.3.4.4.5, 6.3.4.5.3). It starts T2, restarts
    # T1 and stops T20; without it none of the three can be driven correctly.
    MEDIA_RECEIVED = "media-received"


class ActionType(Enum):
    SEND_GRANTED = "floor-granted"
    SEND_TAKEN = "floor-taken"
    SEND_DENY = "floor-deny"
    SEND_IDLE = "floor-idle"
    SEND_REVOKE = "floor-revoke"
    SEND_QUEUE_POSITION = "floor-queue-position-info"
    START_TIMER = "start-timer"
    STOP_TIMER = "stop-timer"


class DenyReason(Enum):
    """Deny causes. Kept distinct so an operator can tell a policy refusal from
    a capacity one when reading an audit trail."""

    QUEUEING_DISABLED = "queueing-disabled"
    QUEUE_FULL = "queue-full"
    ALREADY_QUEUED = "already-queued"
    ALREADY_HOLDER = "already-holder"
    NO_SESSION = "no-session"
    LOWER_PRIORITY = "lower-priority"


class RevokeReason(Enum):
    """Why the floor is being revoked. A separate namespace from DenyReason,
    as TS 24.380 8.2.10.2 is from 8.2.6.2. The media plane maps each to a
    <Reject Cause>; before FC-OP-02 every revoke went out as #255 "other"."""

    MEDIA_BURST_TOO_LONG = "media-burst-too-long"    # #2, on T2 expiry (6.3.4.4.4)
    PREEMPTED = "media-burst-pre-empted"             # #4, on pre-emption (6.3.4.4.7)
    OTHER = "other"                                  # #255


# Timer names are TS 24.380 names; values come from the profile.
# On-network floor control SERVER timers, TS 24.380 clause 6.3. This module is
# the controlling side, so these are the right family.
#
# The T2xx names used here previously (T203, T205, T206) are OFF-NETWORK
# PARTICIPANT timers, clause 7.2.3 — the wrong family entirely for a server
# implementing on-network floor control. Corrected against TS 24.380.
#
# What each timer DOES was checked on 2026-09-24 against the TS 24.380 timer
# table (start / stop / on expiry) and clauses 6.3.4.4 and 6.3.4.5, which are
# identical in V13.14, V17.7 and V20.0 (PLT-VP-R1 FC-OP-02). Before that, T8
# ended the grace period -- which is T3's job -- and nothing re-sent a Revoke.
T_STOP_TALKING = "T2"         # started by the holder's first RTP media; expiry revokes (#2)
T_STOP_TALKING_GRACE = "T3"   # started entering pending revoke; expiry -> floor idle
T_GRANTED_RETRY = "T20"       # started only when a QUEUED request is granted; re-sends Granted
T_REVOKE = "T8"               # started with each Floor Revoke; expiry re-sends it
T_END_OF_MEDIA = "T1"         # started at grant, restarted by RTP; expiry -> floor idle
T_INACTIVITY = "T4"           # inactivity (declared, not yet driven)
T_FLOOR_IDLE = "T7"           # floor idle (declared, not yet driven)

# Default values from the same table. T2 30 s, T20 1 s, T8 1 s were checked
# in CA-05; T1 4 s and T3 3 s were added with FC-OP-02.
DEFAULT_TIMERS_MS: Mapping[str, int] = {
    T_STOP_TALKING: 30000,
    T_GRANTED_RETRY: 1000,   # T20 default 1 s
    T_REVOKE: 1000,          # T8 default 1 s
    T_END_OF_MEDIA: 4000,    # T1 default 4 s (maximum 6 s)
    T_STOP_TALKING_GRACE: 3000,   # T3 default 3 s (0 s with audio cut-in)
}

# Counter C20 (Floor Granted): how many times Floor Granted is sent in all
# before T20 gives up and the floor simply stays taken (6.3.4.4.10). Default
# 3. Not yet configurable from the profile, which declares timers only.
C20_DEFAULT = 3


@dataclass(frozen=True)
class Event:
    type: EventType
    participant: Optional[str] = None
    floor_priority: int = 0
    timer: Optional[str] = None
    detail: str = ""


@dataclass(frozen=True)
class Action:
    type: ActionType
    target: Optional[str] = None        # None means every participant
    reason: Optional[DenyReason] = None
    revoke_reason: Optional[RevokeReason] = None
    timer: Optional[str] = None
    duration_ms: Optional[int] = None
    queue_position: Optional[int] = None


@dataclass(frozen=True)
class Transition:
    """One recorded transition (PLT-FC-011)."""

    sequence: int
    at_ms: int
    from_state: FloorState
    event: Event
    to_state: FloorState
    actions: Tuple[Action, ...]
    holder: Optional[str]
    queue: Tuple[str, ...]


@dataclass(frozen=True)
class QueueEntry:
    participant: str
    floor_priority: int
    arrival: int          # monotonic sequence, breaks priority ties
    at_ms: int
    # A pre-emptor: held in front of every other entry (TS 24.380 6.3.4.4.7
    # item 2e), whatever its priority and even where queueing was not
    # negotiated, until the revoked talker's grace is over.
    front: bool = False


@dataclass(frozen=True)
class Policy:
    """The subset of FloorPolicy the machine needs, decoupled from the hook
    types so this module has no dependency beyond the standard library."""

    initial_grant_to_initiator: bool = True
    queueing_enabled: bool = True
    override_allowed: bool = False
    max_queue_depth: int = 0
    timers_ms: Mapping[str, int] = field(default_factory=dict)

    def timer(self, name: str) -> int:
        return self.timers_ms.get(name, DEFAULT_TIMERS_MS.get(name, 0))

    @classmethod
    def from_hook(cls, floor_policy) -> "Policy":
        """Build from the IF-SES floor policy, without importing the hook types."""
        return cls(
            initial_grant_to_initiator=floor_policy.initial_grant_to_initiator,
            queueing_enabled=floor_policy.queueing_enabled,
            override_allowed=floor_policy.override_allowed,
            max_queue_depth=floor_policy.max_queue_depth,
            timers_ms=dict(floor_policy.timers_ms),
        )


class FloorInvariantViolation(Exception):
    """A transition would have broken an invariant. Raised rather than logged:
    a machine that has lost track of the floor holder must not keep running."""


# --------------------------------------------------------------------------
# Machine
# --------------------------------------------------------------------------


class FloorControl:
    """Controlling-side floor arbitration for one session.

    Usage is synchronous and total: `handle(event)` always returns the actions
    to perform, and never blocks or performs I/O.
    """

    def __init__(self, policy: Policy, clock: Optional[Callable[[], int]] = None):
        self._policy = policy
        self._now = clock or (lambda: 0)
        self._state = FloorState.START_STOP
        self._holder: Optional[str] = None
        self._holder_priority: int = 0
        self._queue: List[QueueEntry] = []
        self._participants: set = set()
        self._running_timers: Dict[str, int] = {}
        self._history: List[Transition] = []
        self._sequence = 0
        self._arrivals = 0
        self._c20 = 0                                   # Floor Granted sends so far
        self._revoke_reason: RevokeReason = RevokeReason.OTHER

    # -- observation ----------------------------------------------------

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def state(self) -> FloorState:
        return self._state

    @property
    def holder(self) -> Optional[str]:
        return self._holder

    @property
    def queue(self) -> Tuple[str, ...]:
        return tuple(e.participant for e in self._queue)

    @property
    def history(self) -> Tuple[Transition, ...]:
        return tuple(self._history)

    def running_timers(self) -> Mapping[str, int]:
        return dict(self._running_timers)

    # -- entry point ----------------------------------------------------

    def handle(self, event: Event) -> Tuple[Action, ...]:
        before = self._state
        handler = self._DISPATCH.get((self._state, event.type))
        if handler is None:
            # An event with no transition in this state is ignored, not an
            # error: a retransmitted release after the floor already went idle
            # is normal on a lossy link. It is still recorded.
            actions: Tuple[Action, ...] = ()
        else:
            actions = tuple(handler(self, event))
        self._apply_timer_actions(actions)
        self._check_invariants()
        # PLT-FC-011 records every TRANSITION. A media report whose only
        # effect is to refresh T1 is not one; recording it would add an
        # entry several times a second for as long as anyone talks.
        refresh_only = (event.type is EventType.MEDIA_RECEIVED
                        and self._state is before
                        and bool(actions)          # an ignored event IS recorded
                        and all(a.type is ActionType.START_TIMER
                                and a.timer == T_END_OF_MEDIA for a in actions))
        if not refresh_only:
            self._record(before, event, actions)
        return actions

    # -- invariants -----------------------------------------------------

    def _check_invariants(self) -> None:
        # PLT-FC-003: at most one holder, and only in a state that has one.
        if self._state in (FloorState.TAKEN, FloorState.REVOKING):
            if self._holder is None:
                raise FloorInvariantViolation(
                    f"state {self._state.value} with no floor holder")
        elif self._holder is not None:
            raise FloorInvariantViolation(
                f"state {self._state.value} must have no floor holder, "
                f"found {self._holder!r}")
        # PLT-FC-006: the queue never exceeds the declared depth.
        if len(self._queue) > self._policy.max_queue_depth and \
                self._policy.queueing_enabled:
            raise FloorInvariantViolation(
                f"queue depth {len(self._queue)} exceeds declared maximum "
                f"{self._policy.max_queue_depth}")
        # With queueing disabled, the one entry allowed is a pre-emptor
        # waiting out the revoked talker's grace (6.3.4.4.7 item 2e).
        if not self._policy.queueing_enabled and \
                any(not e.front for e in self._queue):
            raise FloorInvariantViolation(
                "queueing is disabled but the queue holds an ordinary request")
        if sum(e.front for e in self._queue) > 1:
            raise FloorInvariantViolation("more than one pre-emptor queued")
        # A participant appears in the queue at most once.
        seen = [e.participant for e in self._queue]
        if len(seen) != len(set(seen)):
            raise FloorInvariantViolation(f"duplicate queue entries: {seen}")
        if self._holder is not None and self._holder in seen:
            raise FloorInvariantViolation(
                f"floor holder {self._holder!r} is also queued")

    def _record(self, before: FloorState, event: Event,
                actions: Tuple[Action, ...]) -> None:
        self._sequence += 1
        self._history.append(Transition(
            sequence=self._sequence,
            at_ms=self._now(),
            from_state=before,
            event=event,
            to_state=self._state,
            actions=actions,
            holder=self._holder,
            queue=self.queue,
        ))

    def _apply_timer_actions(self, actions: Sequence[Action]) -> None:
        for a in actions:
            if a.type is ActionType.START_TIMER and a.timer:
                self._running_timers[a.timer] = self._now() + (a.duration_ms or 0)
            elif a.type is ActionType.STOP_TIMER and a.timer:
                self._running_timers.pop(a.timer, None)

    # -- helpers --------------------------------------------------------

    def _start(self, name: str) -> Action:
        return Action(ActionType.START_TIMER, timer=name,
                      duration_ms=self._policy.timer(name))

    @staticmethod
    def _stop(*names: str) -> List[Action]:
        return [Action(ActionType.STOP_TIMER, timer=n) for n in names]

    def _grant(self, participant: str, priority: int,
               from_queue: bool = False) -> List[Action]:
        """Enter 'G: Floor Taken' (TS 24.380 6.3.4.4.2).

        T1 starts for the new holder (item 4). T2 does NOT start here: it
        starts with the holder's first RTP media (6.3.4.4.5 item 1), so a
        talker is not charged for the time before speaking. T20 starts only
        when the grant serves a QUEUED request (item 2), with C20 at 1; a
        direct grant is answered by the request it responds to and is not
        re-sent. The machine used to start T2 and T20 on every grant.
        """
        self._state = FloorState.TAKEN
        self._holder = participant
        self._holder_priority = priority
        self._queue = [e for e in self._queue if e.participant != participant]
        actions = [
            Action(ActionType.SEND_GRANTED, target=participant),
            Action(ActionType.SEND_TAKEN, target=None),
            self._start(T_END_OF_MEDIA),
        ]
        if from_queue:
            self._c20 = 1
            actions.append(self._start(T_GRANTED_RETRY))
        return actions

    def _enter_idle(self) -> List[Action]:
        """Enter 'G: Floor Idle' (6.3.4.3.2), from a state that had a holder.

        With the queue empty: Floor Idle to everyone. With a queued request:
        straight to granting the head of the queue (item 3) -- WITHOUT a
        Floor Idle first. The machine used to broadcast Floor Idle and then
        grant, one message too many on every hand-over.
        """
        self._holder = None
        self._holder_priority = 0
        stop = self._stop(T_STOP_TALKING, T_GRANTED_RETRY, T_REVOKE,
                          T_STOP_TALKING_GRACE, T_END_OF_MEDIA)
        if not self._queue:
            self._state = FloorState.IDLE
            return stop + [Action(ActionType.SEND_IDLE, target=None)]
        head = self._queue[0]
        self._queue = self._queue[1:]
        return (stop + self._grant(head.participant, head.floor_priority,
                                   from_queue=True)
                + self._queue_position_updates())

    # The old name, kept for the call sites that read naturally with it.
    _next_from_queue = _enter_idle

    def _enter_revoke(self, reason: RevokeReason) -> List[Action]:
        """Enter 'G: pending Floor Revoke' (6.3.4.5.2) and, towards the holder,
        'U: pending Floor Revoke' (6.3.5.6.2).

        Floor Revoke carries the reason's cause. T3 (stop talking grace)
        bounds how long the revoked talker may go on; T8 re-sends the Revoke
        until then. The machine used to start only T8 and end the grace on
        its expiry, so a talker got T8's 1 s -- 100 ms in the mcx profile --
        instead of T3's 3 s, and a lost Revoke was never repeated.
        """
        self._state = FloorState.REVOKING
        self._revoke_reason = reason
        # T1 is stopped on the way in (6.3.4.4.4 item 1, 6.3.4.4.7 item 2a);
        # media during the grace restarts it (6.3.4.5.3). T2 and T20 have no
        # procedure in pending revoke (6.3.4.1: discarded), so stopping them
        # here only keeps them from firing into a state that ignores them.
        return self._stop(T_STOP_TALKING, T_GRANTED_RETRY, T_END_OF_MEDIA) + [
            Action(ActionType.SEND_REVOKE, target=self._holder, revoke_reason=reason),
            self._start(T_STOP_TALKING_GRACE),
            self._start(T_REVOKE),
        ]

    def _queue_position_updates(self) -> List[Action]:
        if not self._policy.queueing_enabled:
            return []        # not negotiated: no Queue Position Info (6.3.4.4.7 2f)
        return [
            Action(ActionType.SEND_QUEUE_POSITION, target=e.participant,
                   queue_position=i + 1)
            for i, e in enumerate(self._queue)
        ]

    def _enqueue(self, participant: str, priority: int) -> List[Action]:
        # PLT-FC-007: with queueing disabled the answer is deny, never a queue.
        if not self._policy.queueing_enabled:
            return [Action(ActionType.SEND_DENY, target=participant,
                           reason=DenyReason.QUEUEING_DISABLED)]
        if any(e.participant == participant for e in self._queue):
            return [Action(ActionType.SEND_DENY, target=participant,
                           reason=DenyReason.ALREADY_QUEUED)]
        if len(self._queue) >= self._policy.max_queue_depth:
            return [Action(ActionType.SEND_DENY, target=participant,
                           reason=DenyReason.QUEUE_FULL)]
        self._arrivals += 1
        self._queue.append(QueueEntry(participant=participant,
                                      floor_priority=priority,
                                      arrival=self._arrivals,
                                      at_ms=self._now()))
        # Ordered by floor priority, then arrival. Deterministic, and the tie
        # break is first-come so a queue cannot starve an equal-priority peer.
        self._queue.sort(key=lambda e: (not e.front, -e.floor_priority, e.arrival))
        return self._queue_position_updates()

    # -- transitions ----------------------------------------------------

    def _on_session_established(self, event: Event) -> List[Action]:
        self._state = FloorState.IDLE
        if event.participant:
            self._participants.add(event.participant)
            if self._policy.initial_grant_to_initiator:
                return self._grant(event.participant, event.floor_priority)
        return [Action(ActionType.SEND_IDLE, target=None)]

    def _on_request_idle(self, event: Event) -> List[Action]:
        if not event.participant:
            return []
        self._participants.add(event.participant)
        return self._grant(event.participant, event.floor_priority)

    def _on_request_taken(self, event: Event) -> List[Action]:
        participant = event.participant
        if not participant:
            return []
        self._participants.add(participant)
        if participant == self._holder:
            if self._state is FloorState.TAKEN:
                # 6.3.4.4.8: the holder asking again has lost its Floor
                # Granted; send it again, with what is left of T2 as the
                # Duration, and stay in Floor Taken. A Deny here would tell a
                # client it does not hold a floor that it does.
                return [Action(ActionType.SEND_GRANTED, target=participant,
                               duration_ms=self._t2_remaining())]
            return [Action(ActionType.SEND_DENY, target=participant,
                           reason=DenyReason.ALREADY_HOLDER)]
        # PLT-FC-005 / PLT-FC-008: override is a policy decision using the floor
        # priority from IF-PRI. Strictly greater, so equal priority never
        # interrupts an active talker.
        if self._policy.override_allowed and \
                event.floor_priority > self._holder_priority and \
                self._state is FloorState.TAKEN:
            return self._pre_empt(participant, event.floor_priority)
        return self._enqueue(participant, event.floor_priority)

    def _pre_empt(self, participant: str, priority: int) -> List[Action]:
        """6.3.4.4.7 item 2: revoke with #4 (Media Burst pre-empted) and put
        the pre-emptor in front of every queued request -- inserted, or moved
        if already queued (item 2e) -- whether or not queueing was
        negotiated. Queue Position Info only where it was (item 2f).

        One case is refused rather than followed: a queue already at its
        declared depth, with the pre-emptor not in it. Inserting would break
        the depth the profile declared (PLT-FC-006); pre-empting without
        inserting would revoke a talker for nobody, which is what this
        machine used to do with queueing disabled. The request is then an
        ordinary one and is denied as queue-full.
        """
        queued = any(e.participant == participant for e in self._queue)
        if not queued and self._policy.queueing_enabled and \
                len(self._queue) >= self._policy.max_queue_depth:
            return self._enqueue(participant, priority)
        self._arrivals += 1
        self._queue = [QueueEntry(participant=participant, floor_priority=priority,
                                  arrival=self._arrivals, at_ms=self._now(),
                                  front=True)] + \
            [e for e in self._queue if e.participant != participant]
        return self._enter_revoke(RevokeReason.PREEMPTED) + \
            self._queue_position_updates()

    def _t2_remaining(self) -> int:
        deadline = self._running_timers.get(T_STOP_TALKING)
        if deadline is None:
            # No media yet, so T2 has not started: all of it remains.
            return self._policy.timer(T_STOP_TALKING)
        return max(0, deadline - self._now())

    def _on_release(self, event: Event) -> List[Action]:
        if event.participant != self._holder:
            # A release from a non-holder removes any queue entry it has.
            before = len(self._queue)
            self._queue = [e for e in self._queue
                           if e.participant != event.participant]
            return self._queue_position_updates() if len(self._queue) != before else []
        return self._next_from_queue()

    def _on_revoke(self, event: Event) -> List[Action]:
        if self._holder is None:
            return []
        return self._enter_revoke(RevokeReason.OTHER)

    def _on_release_while_revoking(self, event: Event) -> List[Action]:
        """6.3.4.5.4: stop T1 and T3 (and T8), then Floor Idle, which serves
        the queue if it has anything in it."""
        if event.participant != self._holder:
            return []
        return self._enter_idle()

    def _on_media(self, event: Event) -> List[Action]:
        """RTP media from the holder (6.3.4.4.5; 6.3.4.5.3 while revoking).

        Floor Taken: start T2 if not running, restart T1, stop T20 -- media
        from the holder is the normative proof the grant arrived. Pending
        revoke: restart T1 only; the grace period is T3's to end. Media from
        anyone else changes nothing here (the media plane drops it).
        """
        if event.participant != self._holder or self._holder is None:
            return []
        actions: List[Action] = [self._start(T_END_OF_MEDIA)]
        if self._state is FloorState.TAKEN:
            if T_STOP_TALKING not in self._running_timers:
                actions.append(self._start(T_STOP_TALKING))
            if T_GRANTED_RETRY in self._running_timers:
                actions += self._stop(T_GRANTED_RETRY)
        return actions

    def _on_participant_left(self, event: Event) -> List[Action]:
        self._participants.discard(event.participant)
        if event.participant == self._holder:
            return self._next_from_queue()
        before = len(self._queue)
        self._queue = [e for e in self._queue if e.participant != event.participant]
        return self._queue_position_updates() if len(self._queue) != before else []

    def _on_timer(self, event: Event) -> List[Action]:
        name = event.timer
        self._running_timers.pop(name or "", None)
        # PLT-FC-012: a lost release must not leave the session without a floor
        # holder forever. T1 recovers a silent holder, T3 a revoked one.
        if name == T_STOP_TALKING and self._state is FloorState.TAKEN:
            # 6.3.4.4.4: ALWAYS revoke, with #2. The machine used to hand the
            # floor straight to the queue without revoking, so the talker who
            # ran over was never told.
            return self._enter_revoke(RevokeReason.MEDIA_BURST_TOO_LONG)
        if name == T_END_OF_MEDIA and self._state in (FloorState.TAKEN,
                                                      FloorState.REVOKING):
            # 6.3.4.4.3 / 6.3.4.5.6: the holder went silent; the floor is idle.
            return self._enter_idle()
        if name == T_STOP_TALKING_GRACE and self._state is FloorState.REVOKING:
            # 6.3.4.5.5: the grace is over; the floor is idle.
            return self._enter_idle()
        if name == T_REVOKE and self._state is FloorState.REVOKING:
            # 6.3.5.6.3: re-send the Revoke with the same cause, restart T8.
            # How often is an implementation option; T3 bounds it here.
            return [Action(ActionType.SEND_REVOKE, target=self._holder,
                           revoke_reason=self._revoke_reason),
                    self._start(T_REVOKE)]
        if name == T_GRANTED_RETRY and self._state is FloorState.TAKEN:
            # 6.3.4.4.9 / 6.3.4.4.10: re-send while C20 is below its limit,
            # then give up and stay in Floor Taken.
            if self._c20 >= C20_DEFAULT:
                return []
            self._c20 += 1
            return [Action(ActionType.SEND_GRANTED, target=self._holder),
                    self._start(T_GRANTED_RETRY)]
        return []

    def _on_ack(self, event: Event) -> List[Action]:
        """The holder acknowledged its grant: stop retransmitting it.

        FC-OP-01, closed 2026-09-24: TS 24.380 makes Floor Ack handling "an
        implementation option" (NOTE in 6.3.5.3.5 and throughout 6.3.5).
        The normative stop for T20 is the holder's RTP media (6.3.4.4.5
        item 3); stopping it on an ack as well is the option taken here.
        An ack from anyone else changes nothing.
        """
        if event.participant != self._holder or \
                T_GRANTED_RETRY not in self._running_timers:
            return []
        return [Action(ActionType.STOP_TIMER, timer=T_GRANTED_RETRY)]

    def _on_session_released(self, event: Event) -> List[Action]:
        actions = [
            Action(ActionType.STOP_TIMER, timer=t)
            for t in (T_STOP_TALKING, T_GRANTED_RETRY, T_REVOKE,
                      T_STOP_TALKING_GRACE, T_END_OF_MEDIA)
        ]
        self._state = FloorState.RELEASED
        self._holder = None
        self._holder_priority = 0
        self._queue = []
        self._participants.clear()
        return actions

    def _on_request_no_session(self, event: Event) -> List[Action]:
        return [Action(ActionType.SEND_DENY, target=event.participant,
                       reason=DenyReason.NO_SESSION)]

    # Transition table. A (state, event) pair absent here is ignored by
    # `handle`; VP1-FC-010 asserts that every pair is either handled or
    # harmlessly ignored, and that none raises.
    _DISPATCH: Dict[Tuple[FloorState, EventType], Callable] = {}


FloorControl._DISPATCH = {
    (FloorState.START_STOP, EventType.SESSION_ESTABLISHED):
        FloorControl._on_session_established,
    (FloorState.START_STOP, EventType.FLOOR_REQUEST):
        FloorControl._on_request_no_session,

    (FloorState.IDLE, EventType.FLOOR_REQUEST): FloorControl._on_request_idle,
    (FloorState.IDLE, EventType.PARTICIPANT_LEFT):
        FloorControl._on_participant_left,
    (FloorState.IDLE, EventType.TIMER_EXPIRY): FloorControl._on_timer,
    (FloorState.IDLE, EventType.SESSION_RELEASED):
        FloorControl._on_session_released,

    (FloorState.TAKEN, EventType.FLOOR_REQUEST): FloorControl._on_request_taken,
    (FloorState.TAKEN, EventType.FLOOR_RELEASE): FloorControl._on_release,
    (FloorState.TAKEN, EventType.FLOOR_REVOKE): FloorControl._on_revoke,
    (FloorState.TAKEN, EventType.FLOOR_ACK): FloorControl._on_ack,
    (FloorState.TAKEN, EventType.MEDIA_RECEIVED): FloorControl._on_media,
    (FloorState.REVOKING, EventType.MEDIA_RECEIVED): FloorControl._on_media,
    (FloorState.TAKEN, EventType.PARTICIPANT_LEFT):
        FloorControl._on_participant_left,
    (FloorState.TAKEN, EventType.TIMER_EXPIRY): FloorControl._on_timer,
    (FloorState.TAKEN, EventType.SESSION_RELEASED):
        FloorControl._on_session_released,

    (FloorState.REVOKING, EventType.FLOOR_RELEASE):
        FloorControl._on_release_while_revoking,
    (FloorState.REVOKING, EventType.FLOOR_REQUEST):
        FloorControl._on_request_taken,
    (FloorState.REVOKING, EventType.PARTICIPANT_LEFT):
        FloorControl._on_participant_left,
    (FloorState.REVOKING, EventType.TIMER_EXPIRY): FloorControl._on_timer,
    (FloorState.REVOKING, EventType.SESSION_RELEASED):
        FloorControl._on_session_released,
}
