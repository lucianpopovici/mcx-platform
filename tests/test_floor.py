"""TS-FC — floor control state machine.

Runs in ENV-UNIT: no SIP, no media, no network, injected clock. This is what
PLT-FC-004 buys — the machine is exhaustively drivable before any signalling
exists.
"""

from __future__ import annotations

import itertools
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.floor import (  # noqa: E402
    ActionType,
    DenyReason,
    Event,
    EventType,
    FloorControl,
    FloorInvariantViolation,
    FloorState,
    Policy,
    T_GRANTED_RETRY,
    T_REVOKE,
    T_STOP_TALKING,
)


class Clock:
    """Injected time. Nothing in the machine reads a wall clock."""

    def __init__(self) -> None:
        self.now = 0

    def __call__(self) -> int:
        return self.now

    def advance(self, ms: int) -> None:
        self.now += ms


QUEUEING = Policy(initial_grant_to_initiator=True, queueing_enabled=True,
                  override_allowed=True, max_queue_depth=3,
                  timers_ms={T_STOP_TALKING: 30000, T_GRANTED_RETRY: 100,
                             T_REVOKE: 2000})

NO_QUEUEING = Policy(initial_grant_to_initiator=True, queueing_enabled=False,
                     override_allowed=False, max_queue_depth=0,
                     timers_ms={T_STOP_TALKING: 5000, T_REVOKE: 1000})


def machine(policy=QUEUEING, clock=None):
    return FloorControl(policy, clock=clock or Clock())


def establish(fc, participant="a", priority=100):
    return fc.handle(Event(EventType.SESSION_ESTABLISHED, participant=participant,
                           floor_priority=priority))


def request(fc, participant, priority=100):
    return fc.handle(Event(EventType.FLOOR_REQUEST, participant=participant,
                           floor_priority=priority))


def release(fc, participant):
    return fc.handle(Event(EventType.FLOOR_RELEASE, participant=participant))


def kinds(actions):
    return [a.type for a in actions]


# --------------------------------------------------------------------------
# VP1-FC-010 — exhaustive transitions
# --------------------------------------------------------------------------


def test_vp1_fc_010_every_state_event_pair_is_total():
    """No (state, event) pair may raise or corrupt the machine.

    Unhandled pairs are ignored by design; this asserts that the design holds
    for the whole product, not only the paths a happy-path test walks.
    """
    for state, event_type in itertools.product(FloorState, EventType):
        fc = _machine_in_state(state)
        if fc is None:
            continue
        event = Event(event_type, participant="z", floor_priority=50,
                      timer=T_STOP_TALKING)
        actions = fc.handle(event)          # must not raise
        assert isinstance(actions, tuple)
        assert fc.state in FloorState
        assert len(fc.history) >= 1


def _machine_in_state(state: FloorState):
    """Construct a machine genuinely in each state, not a forced one."""
    fc = machine()
    if state is FloorState.START_STOP:
        return fc
    establish(fc, "a")
    if state is FloorState.IDLE:
        release(fc, "a")
        assert fc.state is FloorState.IDLE
        return fc
    if state is FloorState.TAKEN:
        assert fc.state is FloorState.TAKEN
        return fc
    if state is FloorState.REVOKING:
        fc.handle(Event(EventType.FLOOR_REVOKE, participant="a"))
        assert fc.state is FloorState.REVOKING
        return fc
    if state is FloorState.RELEASED:
        fc.handle(Event(EventType.SESSION_RELEASED))
        assert fc.state is FloorState.RELEASED
        return fc
    return None


def test_vp1_fc_010_all_reachable_states_are_reached():
    reached = set()
    for state in FloorState:
        fc = _machine_in_state(state)
        if fc is not None:
            reached.add(state)
    assert reached == set(FloorState)


# --------------------------------------------------------------------------
# VP1-FC-011 — exactly one holder
# --------------------------------------------------------------------------


def test_vp1_fc_011_single_holder_under_concurrent_requests():
    fc = machine()
    establish(fc, "a", 100)
    for p in ("b", "c", "d"):
        request(fc, p, 100)
    assert fc.holder == "a"
    assert "a" not in fc.queue

    # Drain the queue: at every step exactly one holder, never two.
    seen = []
    while fc.holder is not None:
        seen.append(fc.holder)
        release(fc, fc.holder)
        assert fc.holder is None or fc.holder not in fc.queue
    assert len(seen) == len(set(seen)), "a participant held the floor twice"


def test_vp1_fc_011_invariant_is_enforced_not_assumed():
    """Corrupt the machine directly; the next transition must refuse to proceed."""
    fc = machine()
    establish(fc, "a")
    fc._holder = None                      # simulate a lost-holder bug
    with pytest.raises(FloorInvariantViolation):
        request(fc, "b")


def test_holder_cannot_also_be_queued():
    fc = machine()
    establish(fc, "a", 100)
    request(fc, "b", 100)
    release(fc, "a")
    assert fc.holder == "b"
    assert "b" not in fc.queue


def test_randomised_event_sequences_preserve_invariants():
    """Fuzz: the invariant checks run on every transition, so any violation
    surfaces as an exception rather than as a wrong answer later."""
    rng = random.Random(20260919)
    participants = ["a", "b", "c", "d"]
    for _ in range(200):
        fc = machine()
        establish(fc, "a", rng.choice([50, 100, 200]))
        for _ in range(40):
            ev = rng.choice([EventType.FLOOR_REQUEST, EventType.FLOOR_RELEASE,
                             EventType.FLOOR_REVOKE, EventType.PARTICIPANT_LEFT,
                             EventType.TIMER_EXPIRY])
            fc.handle(Event(ev, participant=rng.choice(participants),
                            floor_priority=rng.choice([50, 100, 200]),
                            timer=rng.choice([T_STOP_TALKING, T_REVOKE,
                                              T_GRANTED_RETRY])))


# --------------------------------------------------------------------------
# VP1-FC-012 — arbitration by floor priority
# --------------------------------------------------------------------------


def test_vp1_fc_012_queue_ordered_by_floor_priority_not_arrival():
    fc = machine()
    establish(fc, "holder", 100)
    request(fc, "low", 10)
    request(fc, "high", 250)
    request(fc, "mid", 100)
    assert fc.queue == ("high", "mid", "low")


def test_vp1_fc_012_equal_priority_breaks_by_arrival():
    fc = machine()
    establish(fc, "holder", 100)
    request(fc, "first", 100)
    request(fc, "second", 100)
    assert fc.queue == ("first", "second")


def test_vp1_fc_012_grant_follows_queue_order():
    fc = machine()
    establish(fc, "holder", 100)
    request(fc, "low", 10)
    request(fc, "high", 250)
    release(fc, "holder")
    assert fc.holder == "high"
    release(fc, "high")
    assert fc.holder == "low"


def test_override_requires_strictly_higher_priority():
    """Equal priority must never interrupt an active talker."""
    fc = machine()
    establish(fc, "a", 100)
    actions = request(fc, "b", 100)
    assert ActionType.SEND_REVOKE not in kinds(actions)
    assert fc.holder == "a"

    actions = request(fc, "c", 200)
    assert ActionType.SEND_REVOKE in kinds(actions)
    assert fc.state is FloorState.REVOKING


def test_override_disabled_queues_instead():
    policy = Policy(queueing_enabled=True, override_allowed=False,
                    max_queue_depth=3)
    fc = FloorControl(policy, clock=Clock())
    establish(fc, "a", 100)
    actions = request(fc, "b", 255)
    assert ActionType.SEND_REVOKE not in kinds(actions)
    assert fc.holder == "a" and fc.queue == ("b",)


# --------------------------------------------------------------------------
# VP1-FC-013 — bounded, ordered queue
# --------------------------------------------------------------------------


def test_vp1_fc_013_queue_bounded_and_excess_denied_not_dropped():
    fc = machine()                          # depth 3
    establish(fc, "holder", 300)            # high, so no override fires
    for p in ("p1", "p2", "p3"):
        request(fc, p, 100)
    assert len(fc.queue) == 3

    actions = request(fc, "p4", 100)
    assert ActionType.SEND_DENY in kinds(actions)
    deny = [a for a in actions if a.type is ActionType.SEND_DENY][0]
    assert deny.reason is DenyReason.QUEUE_FULL
    assert deny.target == "p4"              # denied, not silently dropped
    assert len(fc.queue) == 3


def test_vp1_fc_013_duplicate_request_denied():
    fc = machine()
    establish(fc, "holder", 300)
    request(fc, "p1", 100)
    actions = request(fc, "p1", 100)
    deny = [a for a in actions if a.type is ActionType.SEND_DENY][0]
    assert deny.reason is DenyReason.ALREADY_QUEUED
    assert fc.queue == ("p1",)


def test_vp1_fc_013_queue_positions_reported():
    fc = machine()
    establish(fc, "holder", 300)
    request(fc, "p1", 100)
    actions = request(fc, "p2", 100)
    positions = {a.target: a.queue_position for a in actions
                 if a.type is ActionType.SEND_QUEUE_POSITION}
    assert positions == {"p1": 1, "p2": 2}


def test_holder_requesting_again_is_denied():
    fc = machine()
    establish(fc, "a", 100)
    actions = request(fc, "a", 100)
    deny = [x for x in actions if x.type is ActionType.SEND_DENY][0]
    assert deny.reason is DenyReason.ALREADY_HOLDER


# --------------------------------------------------------------------------
# VP1-FC-014 — deny when queueing is disabled
# --------------------------------------------------------------------------


def test_vp1_fc_014_deny_not_queue_when_queueing_disabled():
    fc = machine(NO_QUEUEING)
    establish(fc, "a", 100)
    actions = request(fc, "b", 100)
    deny = [x for x in actions if x.type is ActionType.SEND_DENY][0]
    assert deny.reason is DenyReason.QUEUEING_DISABLED
    assert fc.queue == ()
    assert fc.holder == "a"


def test_vp1_fc_014_no_queue_entry_created_ever():
    fc = machine(NO_QUEUEING)
    establish(fc, "a", 100)
    for p in ("b", "c", "d", "e"):
        request(fc, p, 255)
    assert fc.queue == ()


def test_request_without_a_session_is_denied():
    fc = machine()
    actions = request(fc, "a", 100)
    deny = [x for x in actions if x.type is ActionType.SEND_DENY][0]
    assert deny.reason is DenyReason.NO_SESSION


# --------------------------------------------------------------------------
# VP1-FC-020 — timers come from the profile, transitions do not
# --------------------------------------------------------------------------


def test_vp1_fc_020_timer_values_follow_the_profile():
    fast = Policy(queueing_enabled=True, max_queue_depth=2,
                  timers_ms={T_STOP_TALKING: 1000, T_GRANTED_RETRY: 50,
                             T_REVOKE: 200})
    slow = Policy(queueing_enabled=True, max_queue_depth=2,
                  timers_ms={T_STOP_TALKING: 60000, T_GRANTED_RETRY: 500,
                             T_REVOKE: 5000})
    durations = {}
    for name, policy in (("fast", fast), ("slow", slow)):
        fc = FloorControl(policy, clock=Clock())
        actions = establish(fc, "a", 100)
        durations[name] = {a.timer: a.duration_ms for a in actions
                           if a.type is ActionType.START_TIMER}
    assert durations["fast"][T_STOP_TALKING] == 1000
    assert durations["slow"][T_STOP_TALKING] == 60000


def test_vp1_fc_020_transition_sequence_identical_across_timer_values():
    """The profile changes constants, never transitions (PLT-PRF-031)."""
    def run(policy):
        fc = FloorControl(policy, clock=Clock())
        establish(fc, "a", 100)
        request(fc, "b", 100)
        release(fc, "a")
        release(fc, "b")
        return [(t.from_state, t.event.type, t.to_state) for t in fc.history]

    fast = Policy(queueing_enabled=True, max_queue_depth=2,
                  timers_ms={T_STOP_TALKING: 1000})
    slow = Policy(queueing_enabled=True, max_queue_depth=2,
                  timers_ms={T_STOP_TALKING: 60000})
    assert run(fast) == run(slow)


def test_unknown_timer_name_falls_back_to_specification_default():
    fc = machine(Policy(queueing_enabled=True, max_queue_depth=1, timers_ms={}))
    actions = establish(fc, "a", 100)
    starts = {a.timer: a.duration_ms for a in actions
              if a.type is ActionType.START_TIMER}
    assert starts[T_STOP_TALKING] > 0


# --------------------------------------------------------------------------
# PLT-FC-012 — recovery, no permanently floorless session
# --------------------------------------------------------------------------


def test_stop_talking_timer_recovers_the_floor():
    clock = Clock()
    fc = machine(clock=clock)
    establish(fc, "a", 100)
    request(fc, "b", 100)
    clock.advance(30000)
    fc.handle(Event(EventType.TIMER_EXPIRY, timer=T_STOP_TALKING))
    assert fc.holder == "b"                 # queue head promoted


def test_revoke_timer_recovers_when_release_is_lost():
    clock = Clock()
    fc = machine(clock=clock)
    establish(fc, "a", 100)
    fc.handle(Event(EventType.FLOOR_REVOKE, participant="a"))
    assert fc.state is FloorState.REVOKING
    clock.advance(2000)
    fc.handle(Event(EventType.TIMER_EXPIRY, timer=T_REVOKE))
    assert fc.state is FloorState.IDLE and fc.holder is None


def test_lone_holder_timeout_revokes_then_goes_idle():
    clock = Clock()
    fc = machine(clock=clock)
    establish(fc, "a", 100)
    fc.handle(Event(EventType.TIMER_EXPIRY, timer=T_STOP_TALKING))
    assert fc.state is FloorState.REVOKING
    fc.handle(Event(EventType.TIMER_EXPIRY, timer=T_REVOKE))
    assert fc.state is FloorState.IDLE


def test_participant_leaving_while_holding_releases_the_floor():
    fc = machine()
    establish(fc, "a", 100)
    request(fc, "b", 100)
    fc.handle(Event(EventType.PARTICIPANT_LEFT, participant="a"))
    assert fc.holder == "b"


def test_participant_leaving_is_removed_from_the_queue():
    fc = machine()
    establish(fc, "holder", 300)
    request(fc, "p1", 100)
    request(fc, "p2", 100)
    fc.handle(Event(EventType.PARTICIPANT_LEFT, participant="p1"))
    assert fc.queue == ("p2",)


def test_retransmission_of_a_stale_release_is_harmless():
    fc = machine()
    establish(fc, "a", 100)
    release(fc, "a")
    before = fc.state
    release(fc, "a")                        # duplicate on a lossy link
    assert fc.state is before


# --------------------------------------------------------------------------
# VP1-FC-021 — transitions recorded
# --------------------------------------------------------------------------


def test_vp1_fc_021_every_transition_recorded_with_trigger_and_result():
    clock = Clock()
    fc = machine(clock=clock)
    establish(fc, "a", 100)
    clock.advance(10)
    request(fc, "b", 250)
    clock.advance(10)
    release(fc, "a")

    assert len(fc.history) == 3
    for t in fc.history:
        assert t.event.type in EventType
        assert t.to_state in FloorState
        assert t.at_ms >= 0
    assert [t.sequence for t in fc.history] == [1, 2, 3]
    assert fc.history[0].at_ms == 0 and fc.history[1].at_ms == 10


def test_vp1_fc_021_sequence_reconstructible_from_history_alone():
    """PLT-FC-011: the audit trail alone must let an operator replay the call."""
    fc = machine()
    establish(fc, "a", 100)
    request(fc, "b", 100)
    request(fc, "c", 200)
    release(fc, "a")

    replay = [(t.from_state, t.event.type, t.to_state, t.holder, t.queue)
              for t in fc.history]
    assert replay[0][0] is FloorState.START_STOP
    assert replay[-1][2] is FloorState.TAKEN
    assert replay[-1][3] == "c"             # higher priority promoted first
    assert replay[-1][4] == ("b",)


def test_history_records_actions_taken():
    fc = machine()
    establish(fc, "a", 100)
    grant = fc.history[0]
    assert ActionType.SEND_GRANTED in [a.type for a in grant.actions]
    assert ActionType.SEND_TAKEN in [a.type for a in grant.actions]


# --------------------------------------------------------------------------
# Session lifecycle
# --------------------------------------------------------------------------


def test_session_release_clears_state_and_stops_timers():
    fc = machine()
    establish(fc, "a", 100)
    request(fc, "b", 100)
    actions = fc.handle(Event(EventType.SESSION_RELEASED))
    assert fc.state is FloorState.RELEASED
    assert fc.holder is None and fc.queue == ()
    assert all(t in [a.timer for a in actions if a.type is ActionType.STOP_TIMER]
               for t in (T_STOP_TALKING, T_GRANTED_RETRY, T_REVOKE))
    assert fc.running_timers() == {}


def test_no_initial_grant_when_policy_declines_it():
    policy = Policy(initial_grant_to_initiator=False, queueing_enabled=True,
                    max_queue_depth=2)
    fc = FloorControl(policy, clock=Clock())
    actions = establish(fc, "a", 100)
    assert fc.state is FloorState.IDLE and fc.holder is None
    assert ActionType.SEND_IDLE in kinds(actions)


def test_policy_built_from_hook_floor_policy():
    """Policy.from_hook bridges IF-SES without importing the hook types."""
    class FakeFloorPolicy:
        initial_grant_to_initiator = True
        queueing_enabled = True
        override_allowed = False
        max_queue_depth = 5
        timers_ms = {T_STOP_TALKING: 1234}

    p = Policy.from_hook(FakeFloorPolicy())
    assert p.max_queue_depth == 5
    assert p.timer(T_STOP_TALKING) == 1234


# --------------------------------------------------------------------------
# FLOOR_ACK — stops grant retransmission (FC-OP-01)
# --------------------------------------------------------------------------


def _ack(fc, participant):
    return fc.handle(Event(EventType.FLOOR_ACK, participant=participant))


def test_ack_from_the_holder_stops_t205_only():
    fc = machine()
    establish(fc, "a")
    assert T_GRANTED_RETRY in fc.running_timers()
    actions = _ack(fc, "a")
    assert [(a.type, a.timer) for a in actions] == [
        (ActionType.STOP_TIMER, T_GRANTED_RETRY)]
    assert T_GRANTED_RETRY not in fc.running_timers()
    assert T_STOP_TALKING in fc.running_timers()      # the talk limit still runs
    assert fc.holder == "a"


def test_ack_from_a_non_holder_or_a_repeat_changes_nothing():
    fc = machine()
    establish(fc, "a")
    assert _ack(fc, "b") == ()
    assert T_GRANTED_RETRY in fc.running_timers()
    _ack(fc, "a")
    assert _ack(fc, "a") == ()


def test_ack_when_idle_is_ignored():
    fc = machine()
    establish(fc, "a")
    release(fc, "a")
    assert _ack(fc, "a") == ()
