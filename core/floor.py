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

OPEN: the timer-to-behaviour mapping below (notably T203 as the holder's
stop-talking timer and T205 as grant retransmission) needs confirming against
the current release of TS 24.380. The machine's structure does not depend on
that mapping; only the constants and which transition each name drives do.
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
    PARTICIPANT_LEFT = "participant-left"
    TIMER_EXPIRY = "timer-expiry"


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


# Timer names are TS 24.380 names; values come from the profile.
T_STOP_TALKING = "T203"       # holder has held the floor for its maximum
T_GRANTED_RETRY = "T205"      # retransmit a grant not yet acknowledged
T_REVOKE = "T206"             # holder must release after a revoke
DEFAULT_TIMERS_MS: Mapping[str, int] = {
    T_STOP_TALKING: 30000,
    T_GRANTED_RETRY: 100,
    T_REVOKE: 2000,
}


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

    # -- observation ----------------------------------------------------

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
        if len(self._queue) > self._policy.max_queue_depth:
            raise FloorInvariantViolation(
                f"queue depth {len(self._queue)} exceeds declared maximum "
                f"{self._policy.max_queue_depth}")
        if not self._policy.queueing_enabled and self._queue:
            raise FloorInvariantViolation(
                "queueing is disabled but the queue is not empty")
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

    def _grant(self, participant: str, priority: int) -> List[Action]:
        self._state = FloorState.TAKEN
        self._holder = participant
        self._holder_priority = priority
        self._queue = [e for e in self._queue if e.participant != participant]
        return [
            Action(ActionType.SEND_GRANTED, target=participant),
            Action(ActionType.SEND_TAKEN, target=None),
            Action(ActionType.START_TIMER, timer=T_STOP_TALKING,
                   duration_ms=self._policy.timer(T_STOP_TALKING)),
            Action(ActionType.START_TIMER, timer=T_GRANTED_RETRY,
                   duration_ms=self._policy.timer(T_GRANTED_RETRY)),
        ]

    def _go_idle(self) -> List[Action]:
        self._state = FloorState.IDLE
        self._holder = None
        self._holder_priority = 0
        return [
            Action(ActionType.STOP_TIMER, timer=T_STOP_TALKING),
            Action(ActionType.STOP_TIMER, timer=T_GRANTED_RETRY),
            Action(ActionType.STOP_TIMER, timer=T_REVOKE),
            Action(ActionType.SEND_IDLE, target=None),
        ]

    def _next_from_queue(self) -> List[Action]:
        """Release the floor, then grant it to the head of the queue if any."""
        actions = self._go_idle()
        if not self._queue:
            return actions
        head = self._queue[0]
        self._queue = self._queue[1:]
        actions += self._grant(head.participant, head.floor_priority)
        actions += self._queue_position_updates()
        return actions

    def _queue_position_updates(self) -> List[Action]:
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
        self._queue.sort(key=lambda e: (-e.floor_priority, e.arrival))
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
            return [Action(ActionType.SEND_DENY, target=participant,
                           reason=DenyReason.ALREADY_HOLDER)]
        # PLT-FC-005 / PLT-FC-008: override is a policy decision using the floor
        # priority from IF-PRI. Strictly greater, so equal priority never
        # interrupts an active talker.
        if self._policy.override_allowed and \
                event.floor_priority > self._holder_priority:
            revoked = self._holder
            self._state = FloorState.REVOKING
            pending = self._enqueue(participant, event.floor_priority) \
                if self._policy.queueing_enabled else []
            return [
                Action(ActionType.SEND_REVOKE, target=revoked),
                Action(ActionType.START_TIMER, timer=T_REVOKE,
                       duration_ms=self._policy.timer(T_REVOKE)),
            ] + pending
        return self._enqueue(participant, event.floor_priority)

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
        self._state = FloorState.REVOKING
        return [
            Action(ActionType.SEND_REVOKE, target=self._holder),
            Action(ActionType.START_TIMER, timer=T_REVOKE,
                   duration_ms=self._policy.timer(T_REVOKE)),
        ]

    def _on_release_while_revoking(self, event: Event) -> List[Action]:
        if event.participant != self._holder:
            return []
        return [Action(ActionType.STOP_TIMER, timer=T_REVOKE)] + \
            self._next_from_queue()

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
        # holder forever. Both the stop-talking and revoke timers recover it.
        if name == T_STOP_TALKING and self._state is FloorState.TAKEN:
            if self._queue:
                return self._next_from_queue()
            self._state = FloorState.REVOKING
            return [
                Action(ActionType.SEND_REVOKE, target=self._holder),
                Action(ActionType.START_TIMER, timer=T_REVOKE,
                       duration_ms=self._policy.timer(T_REVOKE)),
            ]
        if name == T_REVOKE and self._state is FloorState.REVOKING:
            return self._next_from_queue()
        if name == T_GRANTED_RETRY and self._state is FloorState.TAKEN:
            return [
                Action(ActionType.SEND_GRANTED, target=self._holder),
                Action(ActionType.START_TIMER, timer=T_GRANTED_RETRY,
                       duration_ms=self._policy.timer(T_GRANTED_RETRY)),
            ]
        return []

    def _on_session_released(self, event: Event) -> List[Action]:
        actions = [
            Action(ActionType.STOP_TIMER, timer=t)
            for t in (T_STOP_TALKING, T_GRANTED_RETRY, T_REVOKE)
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
