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
    Action,
    ActionType,
    DenyReason,
    Event,
    EventType,
    FloorControl,
    FloorInvariantViolation,
    FloorState,
    Policy,
    T_END_OF_MEDIA,
    T_GRANTED_RETRY,
    T_REVOKE,
    T_STOP_TALKING,
    T_STOP_TALKING_GRACE,
    RevokeReason,
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


def media(fc, participant):
    return fc.handle(Event(EventType.MEDIA_RECEIVED, participant=participant))


def expire(fc, timer):
    return fc.handle(Event(EventType.TIMER_EXPIRY, timer=timer))


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


def test_vp1_fc_013_a_repeated_request_keeps_its_place():
    """TS 24.380 6.3.5.4.4 item 4: a participant already queued at the same
    priority that asks again gets Queue Position Info and keeps its place.
    It used to be denied, although it stayed queued and was granted later
    (RES-OP-10 review)."""
    fc = machine()
    establish(fc, "holder", 300)
    request(fc, "p0", 100)
    request(fc, "p1", 100)
    actions = request(fc, "p1", 100)
    assert actions == (Action(ActionType.SEND_QUEUE_POSITION, target="p1",
                              queue_position=2),)
    assert fc.queue == ("p0", "p1")


def test_a_repeated_request_without_queueing_is_answered_with_nothing():
    """Item 4 without queueing negotiated: the held pre-emptor asking again
    gets no Deny and no Queue Position Info, and is granted in its turn."""
    fc = machine(Policy(queueing_enabled=False, override_allowed=True,
                        max_queue_depth=0))
    establish(fc, "a", 100)
    request(fc, "b", 200)
    assert request(fc, "b", 200) == ()
    assert request(fc, "b", 150) == ()        # in front: nothing outranks it
    expire(fc, T_STOP_TALKING_GRACE)
    assert fc.holder == "b"


@pytest.mark.vp("VP1-FC-013")
def test_a_repeated_request_at_another_priority_is_repositioned():
    """Item 8: a queued participant asking at another priority is moved to
    follow the requests at its new priority."""
    fc = machine(Policy(queueing_enabled=True, override_allowed=False,
                        max_queue_depth=3))
    establish(fc, "holder", 300)
    for p, priority in (("p1", 100), ("p2", 50), ("p3", 50)):
        request(fc, p, priority)
    assert fc.queue == ("p1", "p2", "p3")
    actions = request(fc, "p3", 200)
    assert ActionType.SEND_DENY not in kinds(actions)
    assert fc.queue == ("p3", "p1", "p2")
    request(fc, "p3", 50)                      # down again: behind its peers
    assert fc.queue == ("p1", "p2", "p3")


def test_vp1_fc_013_queue_positions_reported():
    fc = machine()
    establish(fc, "holder", 300)
    request(fc, "p1", 100)
    actions = request(fc, "p2", 100)
    positions = {a.target: a.queue_position for a in actions
                 if a.type is ActionType.SEND_QUEUE_POSITION}
    assert positions == {"p1": 1, "p2": 2}


def test_holder_requesting_again_is_granted_again():
    """TS 24.380 6.3.4.4.8: a holder that asks again lost its Floor Granted.
    It is sent again, with the T2 that remains, and the floor stays taken.
    The machine used to answer with a Deny."""
    clock = Clock()
    fc = machine(clock=clock)
    establish(fc, "a", 100)
    actions = request(fc, "a", 100)
    assert kinds(actions) == [ActionType.SEND_GRANTED]
    assert actions[0].target == "a" and actions[0].duration_ms == 30000
    media(fc, "a")                          # T2 now runs
    clock.advance(12000)
    (again,) = request(fc, "a", 100)
    assert again.duration_ms == 18000
    assert fc.state is FloorState.TAKEN and fc.holder == "a"


def test_holder_requesting_while_revoked_is_denied():
    fc = machine()
    establish(fc, "a", 100)
    fc.handle(Event(EventType.FLOOR_REVOKE, participant="a"))
    actions = request(fc, "a", 100)
    assert [x.reason for x in actions if x.type is ActionType.SEND_DENY] == \
        [DenyReason.ALREADY_HOLDER]


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


def test_vp1_fc_014_no_queue_entry_for_any_request_when_override_is_off():
    """Queueing disabled and override not allowed: whatever the priority, no
    request is held. (The name this replaced, "no queue entry created ever",
    claimed more: see the next test.)"""
    fc = machine(NO_QUEUEING)
    establish(fc, "a", 100)
    for p in ("b", "c", "d", "e"):
        request(fc, p, 255)
    assert fc.queue == ()


def test_vp1_fc_014_with_override_only_a_pre_emptor_is_held():
    """VP1-FC-014 as amended (RES-OP-10 ruling 3): queueing disabled, an
    ordinary request is denied with no queue entry; a pre-emption, where
    override is allowed, is held in the one front place TS 24.380 6.3.4.4.7
    item 2e requires (FC-OP-07), with no Deny and no Queue Position Info;
    anything after it is denied."""
    fc = machine(Policy(queueing_enabled=False, override_allowed=True,
                        max_queue_depth=0))
    establish(fc, "a", 100)
    for p, priority in (("c", 100), ("d", 50)):              # not higher: ordinary
        actions = request(fc, p, priority)
        assert [(x.reason, x.target) for x in actions if x.type is ActionType.SEND_DENY] \
            == [(DenyReason.QUEUEING_DISABLED, p)]
        assert fc.queue == ()
    actions = request(fc, "b", 200)                          # higher: pre-emption
    assert ActionType.SEND_DENY not in kinds(actions)
    assert ActionType.SEND_QUEUE_POSITION not in kinds(actions)
    assert [x.target for x in actions if x.type is ActionType.SEND_REVOKE] == ["a"]
    assert (fc.state, fc.holder, fc.queue) == (FloorState.REVOKING, "a", ("b",))
    for p, priority in (("e", 250), ("f", 200)):             # the place is taken
        actions = request(fc, p, priority)
        assert [(x.reason, x.target) for x in actions if x.type is ActionType.SEND_DENY] \
            == [(DenyReason.QUEUEING_DISABLED, p)]
    assert fc.queue == ("b",)


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
        establish(fc, "a", 100)
        # T2 is started by the holder's first RTP media, not by the grant
        # (TS 24.380 6.3.4.4.5 item 1).
        actions = media(fc, "a")
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
    establish(fc, "a", 100)
    actions = media(fc, "a")
    starts = {a.timer: a.duration_ms for a in actions
              if a.type is ActionType.START_TIMER}
    assert starts[T_STOP_TALKING] == 30000    # table 11.1.3-1 default


# --------------------------------------------------------------------------
# PLT-FC-012 — recovery, no permanently floorless session
# --------------------------------------------------------------------------


def test_stop_talking_timer_recovers_the_floor():
    """T2 expiry always revokes with cause #2, even with a queue
    (TS 24.380 6.3.4.4.4); the queue head is granted when the pending-revoke
    state ends (6.3.4.5.5 -> 6.3.4.3.2 item 3)."""
    clock = Clock()
    fc = machine(clock=clock)
    establish(fc, "a", 100)
    media(fc, "a")
    request(fc, "b", 100)
    clock.advance(30000)
    actions = expire(fc, T_STOP_TALKING)
    assert fc.state is FloorState.REVOKING and fc.holder == "a"
    revokes = [a for a in actions if a.type is ActionType.SEND_REVOKE]
    assert len(revokes) == 1
    assert revokes[0].revoke_reason is RevokeReason.MEDIA_BURST_TOO_LONG
    expire(fc, T_STOP_TALKING_GRACE)
    assert fc.holder == "b"                 # queue head promoted


def test_revoke_timer_recovers_when_release_is_lost():
    """A lost Floor Release: T8 re-sends the Revoke (6.3.5.6.3), T3 ends
    the pending-revoke state (6.3.4.5.5)."""
    clock = Clock()
    fc = machine(clock=clock)
    establish(fc, "a", 100)
    fc.handle(Event(EventType.FLOOR_REVOKE, participant="a"))
    assert fc.state is FloorState.REVOKING
    clock.advance(1000)
    expire(fc, T_REVOKE)
    assert fc.state is FloorState.REVOKING   # T8 re-sends, does not end it
    clock.advance(2000)
    expire(fc, T_STOP_TALKING_GRACE)
    assert fc.state is FloorState.IDLE and fc.holder is None


def test_lone_holder_timeout_revokes_then_goes_idle():
    clock = Clock()
    fc = machine(clock=clock)
    establish(fc, "a", 100)
    media(fc, "a")
    expire(fc, T_STOP_TALKING)
    assert fc.state is FloorState.REVOKING
    expire(fc, T_STOP_TALKING_GRACE)
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


def _contended(clock):
    """a talks; b, of higher priority, pre-empts; a releases."""
    fc = machine(clock=clock)
    establish(fc, "a", 100)
    clock.advance(10)
    request(fc, "b", 250)
    clock.advance(10)
    release(fc, "a")
    return fc


def test_vp1_fc_021_every_transition_recorded_with_trigger_and_result():
    """Every record literal: trigger, timestamp and resulting state (RES-OP-03
    review: the assertions it replaced could not fail)."""
    fc = _contended(Clock())
    assert [(t.sequence, t.at_ms, t.event.type, t.event.participant, t.from_state,
             t.to_state, t.holder, t.queue) for t in fc.history] == [
        (1, 0, EventType.SESSION_ESTABLISHED, "a", FloorState.START_STOP,
         FloorState.TAKEN, "a", ()),
        (2, 10, EventType.FLOOR_REQUEST, "b", FloorState.TAKEN,
         FloorState.REVOKING, "a", ("b",)),
        (3, 20, EventType.FLOOR_RELEASE, "a", FloorState.REVOKING,
         FloorState.TAKEN, "b", ()),
    ]


def test_vp1_fc_021_sequence_reconstructible_from_history_alone():
    """PLT-FC-011: a chain, each transition starting where the last ended."""
    fc = machine()
    establish(fc, "a", 100)
    request(fc, "b", 100)
    request(fc, "c", 200)
    release(fc, "a")
    h = fc.history
    assert h[0].from_state is FloorState.START_STOP
    assert all(b.from_state is a.to_state for a, b in zip(h, h[1:]))
    assert [(t.to_state, t.holder, t.queue) for t in h] == [
        (FloorState.TAKEN, "a", ()),
        (FloorState.TAKEN, "a", ("b",)),
        # c outranks a and override is allowed: a is revoked, c queued ahead
        (FloorState.REVOKING, "a", ("c", "b")),
        (FloorState.TAKEN, "c", ("b",)),
    ]


@pytest.mark.vp("VP1-FC-021")
def test_a_transition_as_audit_data_is_literal_and_complete():
    """RES-OP-03: what goes to the audit trail, every field, enums as their
    TS 24.380 names."""
    fc = _contended(Clock())
    first, second = fc.history[0].as_record(), fc.history[1].as_record()
    assert first == {
        "sequence": 1, "floor_at_ms": 0,
        "from_state": "start-stop", "to_state": "floor-taken",
        "trigger": {"type": "session-established", "participant": "a",
                    "floor_priority": 100, "timer": None, "detail": ""},
        "actions": [
            {"type": "floor-granted", "target": "a", "reason": None,
             "revoke_reason": None, "timer": None, "duration_ms": None,
             "queue_position": None},
            {"type": "floor-taken", "target": None, "reason": None,
             "revoke_reason": None, "timer": None, "duration_ms": None,
             "queue_position": None},
            {"type": "start-timer", "target": None, "reason": None,
             "revoke_reason": None, "timer": "T1", "duration_ms": 4000,
             "queue_position": None},
        ],
        "holder": "a", "queue": [],
    }
    revoke = [a for a in second["actions"] if a["type"] == "floor-revoke"]
    assert revoke == [{"type": "floor-revoke", "target": "a", "reason": None,
                       "revoke_reason": "media-burst-pre-empted", "timer": None,
                       "duration_ms": None, "queue_position": None}]
    assert second["to_state"] == "pending-revoke" and second["queue"] == ["b"]


@pytest.mark.vp("VP1-FC-021")
def test_the_observer_is_told_each_recorded_transition_and_only_those():
    """Every recorded transition, as it is recorded; not a media report that
    only restarts T1, which the history does not record either."""
    told = []
    fc = FloorControl(QUEUEING, clock=Clock(), observer=told.append)
    establish(fc, "a")
    media(fc, "a")                            # first media starts T2: recorded
    media(fc, "a")                            # refresh only: not a transition
    request(fc, "b")
    release(fc, "zz")                         # ignored event: still recorded
    assert told == list(fc.history)
    assert [t.event.type for t in told] == [EventType.SESSION_ESTABLISHED,
                                            EventType.MEDIA_RECEIVED,
                                            EventType.FLOOR_REQUEST,
                                            EventType.FLOOR_RELEASE]


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
        preemption_at_full_queue = "insert"

    p = Policy.from_hook(FakeFloorPolicy())
    assert p.max_queue_depth == 5
    assert p.preemption_at_full_queue == "insert"
    assert p.timer(T_STOP_TALKING) == 1234


# --------------------------------------------------------------------------
# FLOOR_ACK — stops grant retransmission (FC-OP-01)
# --------------------------------------------------------------------------


def _ack(fc, participant):
    return fc.handle(Event(EventType.FLOOR_ACK, participant=participant))


def _granted_from_queue(fc):
    """'b' holds the floor through the queue, so T20 runs
    (TS 24.380 6.3.4.4.2 item 2 -- T20 is started only for a queued grant)."""
    establish(fc, "a")
    request(fc, "b")
    release(fc, "a")
    assert fc.holder == "b"


def test_ack_from_the_holder_stops_t205_only():
    fc = machine()
    _granted_from_queue(fc)
    assert T_GRANTED_RETRY in fc.running_timers()
    actions = _ack(fc, "b")
    assert [(a.type, a.timer) for a in actions] == [
        (ActionType.STOP_TIMER, T_GRANTED_RETRY)]
    assert T_GRANTED_RETRY not in fc.running_timers()
    assert T_END_OF_MEDIA in fc.running_timers()      # T1 still guards the burst
    assert fc.holder == "b"


def test_ack_from_a_non_holder_or_a_repeat_changes_nothing():
    fc = machine()
    _granted_from_queue(fc)
    assert _ack(fc, "a") == ()
    assert T_GRANTED_RETRY in fc.running_timers()
    _ack(fc, "b")
    assert _ack(fc, "b") == ()


def test_ack_when_idle_is_ignored():
    fc = machine()
    establish(fc, "a")
    release(fc, "a")
    assert _ack(fc, "a") == ()


# -- PLT-CONF-AUDIT CA-05 ------------------------------------------------------


def test_default_timer_values_match_the_specification_table():
    """TS 24.380 table 11.1.3-1 (floor control server procedures), V17.7.0,
    corroborated against V20.0.0.

    The three values are spelled out rather than imported, so that changing a
    default cannot move the code and the assertion together.

    Note what the specification actually says for T2: "Default **maximum**
    value: 30 seconds", and it is obtained from <time-limit> of <transmit-time>
    in TS 24.484 -- not from <fc-timers-counters> like T8 and T20. A deployment
    configuring it is setting a talk-time limit, not a retry interval.
    """
    from core.floor import DEFAULT_TIMERS_MS
    assert dict(DEFAULT_TIMERS_MS) == {
        "T1": 4000,       # Default value: 4 seconds
        "T2": 30000,      # Default maximum value: 30 seconds
        "T3": 3000,       # Default value: 3 seconds
        "T20": 1000,      # Default value: 1 second
        "T8": 1000,       # Default value: 1 second
    }


def test_the_known_timer_set_matches_the_server_procedures_table():
    """Every timer in table 11.1.3-1 that the platform can accept, and no
    off-network one. T11 and T12 are the dual-talker pair; they are absent
    deliberately, because floor override is not implemented -- a profile
    declaring one would be configuring a machine that does not exist.
    """
    from core.validation import FLOOR_TIMERS
    assert set(FLOOR_TIMERS) == {"T1", "T2", "T3", "T4", "T7", "T8", "T20"}
    assert not {"T11", "T12"} & set(FLOOR_TIMERS)
    # off-network participant timers stay rejected (PLT-CONF-AUDIT 3.2)
    assert not {"T201", "T203", "T205", "T206", "T207", "T230"} & set(FLOOR_TIMERS)


# -- PLT-VP-R1 FC-OP-02: TS 24.380 6.3.4 timer behaviour --------------------


def _starts(actions):
    return {a.timer for a in actions if a.type is ActionType.START_TIMER}


def _stops(actions):
    return {a.timer for a in actions if a.type is ActionType.STOP_TIMER}


def test_a_direct_grant_starts_t1_only():
    """6.3.4.4.2: T1 at every grant; T20 only for a queued one (item 2);
    T2 not at all (it waits for media, 6.3.4.4.5 item 1)."""
    fc = machine()
    assert _starts(establish(fc, "a")) == {T_END_OF_MEDIA}


def test_a_queued_grant_starts_t1_and_t20_and_sends_no_idle():
    fc = machine()
    establish(fc, "a")
    request(fc, "b")
    actions = release(fc, "a")
    assert _starts(actions) == {T_END_OF_MEDIA, T_GRANTED_RETRY}
    assert ActionType.SEND_IDLE not in kinds(actions)       # 6.3.4.3.2 item 3
    assert fc.holder == "b"


def test_first_media_starts_t2_later_media_only_refreshes_t1():
    clock = Clock()
    fc = machine(clock=clock)
    establish(fc, "a")
    assert _starts(media(fc, "a")) == {T_END_OF_MEDIA, T_STOP_TALKING}
    t2_started = fc.running_timers()[T_STOP_TALKING]
    clock.advance(1000)
    assert _starts(media(fc, "a")) == {T_END_OF_MEDIA}      # T2 keeps running
    assert fc.running_timers()[T_STOP_TALKING] == t2_started


def test_holder_media_stops_t20():
    fc = machine()
    establish(fc, "a")
    request(fc, "b")
    release(fc, "a")
    assert T_GRANTED_RETRY in _stops(media(fc, "b"))         # 6.3.4.4.5 item 3
    assert T_GRANTED_RETRY not in fc.running_timers()


def test_media_from_a_non_holder_changes_nothing():
    fc = machine()
    establish(fc, "a")
    before = dict(fc.running_timers())
    assert media(fc, "b") == ()
    assert fc.running_timers() == before


def test_refresh_only_media_is_not_recorded_but_ignored_media_is():
    """One history entry per RTP packet would grow without bound during a
    burst; a refresh of T1 is not a transition. An ignored event still is,
    so the totality guarantee (every event leaves a trace) holds."""
    fc = machine()
    establish(fc, "a")
    media(fc, "a")                     # starts T2: recorded
    n = len(fc.history)
    for _ in range(50):
        media(fc, "a")
    assert len(fc.history) == n
    media(fc, "z")                     # not the holder: ignored, recorded
    assert len(fc.history) == n + 1


def test_t1_expiry_idles_the_floor():
    fc = machine()
    establish(fc, "a")
    actions = expire(fc, T_END_OF_MEDIA)
    assert fc.state is FloorState.IDLE and ActionType.SEND_IDLE in kinds(actions)


def test_t2_expiry_revokes_with_cause_2_even_with_a_queue():
    fc = machine()
    establish(fc, "a")
    media(fc, "a")
    request(fc, "b")
    actions = expire(fc, T_STOP_TALKING)
    assert fc.state is FloorState.REVOKING and fc.holder == "a"
    assert [a.revoke_reason for a in actions
            if a.type is ActionType.SEND_REVOKE] == [RevokeReason.MEDIA_BURST_TOO_LONG]
    assert ActionType.SEND_GRANTED not in kinds(actions)
    assert _starts(actions) == {T_STOP_TALKING_GRACE, T_REVOKE}
    assert {T_END_OF_MEDIA, T_STOP_TALKING} <= _stops(actions)   # 6.3.4.4.4


def test_t8_resends_the_revoke_with_the_same_cause():
    fc = machine()
    establish(fc, "a")
    media(fc, "a")
    expire(fc, T_STOP_TALKING)
    actions = expire(fc, T_REVOKE)
    assert [a.revoke_reason for a in actions
            if a.type is ActionType.SEND_REVOKE] == [RevokeReason.MEDIA_BURST_TOO_LONG]
    assert _starts(actions) == {T_REVOKE}
    assert fc.state is FloorState.REVOKING


def test_media_while_revoking_restarts_t1_and_t1_expiry_idles():
    """6.3.4.5.3 (RTP restarts T1) and 6.3.4.5.6 (T1 expiry -> idle)."""
    fc = machine()
    establish(fc, "a")
    fc.handle(Event(EventType.FLOOR_REVOKE, participant="a"))
    assert _starts(media(fc, "a")) == {T_END_OF_MEDIA}
    expire(fc, T_END_OF_MEDIA)
    assert fc.state is FloorState.IDLE


def test_release_while_revoking_stops_every_timer():
    fc = machine()
    establish(fc, "a")
    media(fc, "a")
    fc.handle(Event(EventType.FLOOR_REVOKE, participant="a"))
    release(fc, "a")
    assert fc.state is FloorState.IDLE and fc.running_timers() == {}


def test_t20_is_bounded_by_c20():
    fc = machine()
    establish(fc, "a")
    request(fc, "b")
    release(fc, "a")
    resent = 0
    for _ in range(10):
        resent += kinds(expire(fc, T_GRANTED_RETRY)).count(ActionType.SEND_GRANTED)
    assert resent == 2                                   # C20 = 3 incl. the first
    assert fc.state is FloorState.TAKEN and fc.holder == "b"   # 6.3.4.4.10
    assert T_GRANTED_RETRY not in fc.running_timers()


def test_pre_emption_revokes_with_cause_4():
    fc = machine()                      # QUEUEING allows override
    establish(fc, "a", 100)
    media(fc, "a")
    actions = request(fc, "b", 200)
    assert [a.revoke_reason for a in actions
            if a.type is ActionType.SEND_REVOKE] == [RevokeReason.PREEMPTED]
    assert {T_END_OF_MEDIA, T_GRANTED_RETRY} <= _stops(actions)  # 6.3.4.4.7 2a/2b
    release(fc, "a")
    assert fc.holder == "b"


def test_a_pre_emptor_stays_in_front_of_later_higher_priority_requests():
    """6.3.4.4.7 item 2e: in front of ALL queued requests, until granted --
    a request arriving during the grace, however high, queues behind it."""
    fc = machine(Policy(queueing_enabled=True, override_allowed=True,
                        max_queue_depth=3))
    establish(fc, "a", 200)
    request(fc, "c", 150)                   # below the holder: just queued
    request(fc, "b", 210)                   # pre-empts
    assert fc.state is FloorState.REVOKING and fc.queue == ("b", "c")
    request(fc, "d", 900)                   # during the grace
    assert fc.queue == ("b", "d", "c")
    release(fc, "a")
    assert fc.holder == "b"


def test_an_already_queued_pre_emptor_is_moved_to_the_front():
    """The reviewer's scenario: A (3) holds, queue C (3), B (2); B's priority
    rises to 9 and B asks again. B must be moved in front, not denied
    ALREADY_QUEUED -- otherwise A is pre-empted in C's favour."""
    fc = machine(Policy(queueing_enabled=True, override_allowed=True,
                        max_queue_depth=3))
    establish(fc, "a", 3)
    request(fc, "c", 3)
    request(fc, "b", 2)
    assert fc.queue == ("c", "b")
    actions = request(fc, "b", 9)
    assert ActionType.SEND_DENY not in kinds(actions)
    assert fc.state is FloorState.REVOKING and fc.queue == ("b", "c")
    release(fc, "a")
    assert fc.holder == "b" and fc.queue == ("c",)


def test_pre_emption_without_queueing_still_hands_over():
    """6.3.4.4.7 item 2e applies even where queueing was not negotiated; the
    machine used to revoke the talker and give the pre-emptor nothing
    (PLT-VP-R1 FC-OP-07). No Queue Position Info is sent (item 2f)."""
    fc = machine(Policy(queueing_enabled=False, override_allowed=True,
                        max_queue_depth=0))
    establish(fc, "a", 100)
    actions = request(fc, "b", 200)
    assert ActionType.SEND_QUEUE_POSITION not in kinds(actions)
    assert fc.state is FloorState.REVOKING
    expire(fc, T_STOP_TALKING_GRACE)
    assert fc.holder == "b" and fc.queue == ()
    # an ordinary request is still denied, not queued
    denied = request(fc, "c", 100)
    assert [a.reason for a in denied if a.type is ActionType.SEND_DENY] == \
        [DenyReason.QUEUEING_DISABLED]


def test_a_full_queue_refuses_a_new_pre_emptor_rather_than_revoking_for_nobody():
    fc = machine(Policy(queueing_enabled=True, override_allowed=True,
                        max_queue_depth=1))
    establish(fc, "a", 100)
    request(fc, "c", 50)
    actions = request(fc, "b", 200)
    assert [a.reason for a in actions if a.type is ActionType.SEND_DENY] == \
        [DenyReason.QUEUE_FULL]
    assert fc.state is FloorState.TAKEN and fc.holder == "a"


def test_operator_revoke_uses_the_generic_cause():
    fc = machine()
    establish(fc, "a")
    actions = fc.handle(Event(EventType.FLOOR_REVOKE, participant="a"))
    assert [a.revoke_reason for a in actions
            if a.type is ActionType.SEND_REVOKE] == [RevokeReason.OTHER]


def _busy_floor(fc):
    """Denials, a T2 revoke and its T8 resend, a T3 hand-over, T20 up to C20,
    a pre-emption and a T1 expiry."""
    establish(fc, "a", 100)
    media(fc, "a")
    for p in ("b", "b", "c", "d", "e"):
        request(fc, p)
    for timer in ("T2", "T8", "T3", "T20", "T20", "T20", "T20"):
        expire(fc, timer)
    request(fc, "f", 250)
    for timer in ("T8", "T3", "T1"):
        expire(fc, timer)


@pytest.mark.vp("VP1-FC-021")
def test_the_audit_feed_is_the_history_through_timers_denials_and_pre_emption():
    """RES-OP-03 review: the feed was compared with the history on one short
    sequence only. Here every recorded transition of a busy floor."""
    told = []
    fc = FloorControl(QUEUEING, clock=Clock(), observer=told.append)
    _busy_floor(fc)
    assert told == list(fc.history)
    T, R = FloorState.TAKEN, FloorState.REVOKING
    assert [(t.event.type.value, t.event.participant or t.event.timer, t.to_state,
             t.holder, t.queue) for t in told] == [
        ("session-established", "a", T, "a", ()),
        ("media-received", "a", T, "a", ()),
        ("floor-request", "b", T, "a", ("b",)),
        ("floor-request", "b", T, "a", ("b",)),                   # keeps its place
        ("floor-request", "c", T, "a", ("b", "c")),
        ("floor-request", "d", T, "a", ("b", "c", "d")),
        ("floor-request", "e", T, "a", ("b", "c", "d")),          # queue full
        ("timer-expiry", "T2", R, "a", ("b", "c", "d")),
        ("timer-expiry", "T8", R, "a", ("b", "c", "d")),
        ("timer-expiry", "T3", T, "b", ("c", "d")),
        ("timer-expiry", "T20", T, "b", ("c", "d")),
        ("timer-expiry", "T20", T, "b", ("c", "d")),
        ("timer-expiry", "T20", T, "b", ("c", "d")),              # C20 reached
        ("timer-expiry", "T20", T, "b", ("c", "d")),
        ("floor-request", "f", R, "b", ("f", "c", "d")),          # pre-emption
        ("timer-expiry", "T8", R, "b", ("f", "c", "d")),
        ("timer-expiry", "T3", T, "f", ("c", "d")),
        ("timer-expiry", "T1", T, "c", ("d",)),
    ]
    denies = [a.reason.value for t in told for a in t.actions
              if a.type is ActionType.SEND_DENY]
    revokes = [a.revoke_reason.value for t in told for a in t.actions
               if a.type is ActionType.SEND_REVOKE]
    assert denies == ["queue-full"]
    assert revokes == ["media-burst-too-long", "media-burst-too-long",
                       "media-burst-pre-empted", "media-burst-pre-empted"]


class _FailingAudit:
    def __init__(self):
        self.fail, self.written = False, []

    def __call__(self, transition):
        if self.fail:
            raise OSError("audit store unavailable")
        self.written.append(transition)


def _state_of(fc):
    return (fc.state, fc.holder, fc.queue, fc.running_timers(), fc.history)


@pytest.mark.vp("VP1-FC-021")
@pytest.mark.parametrize("step", [
    lambda fc: request(fc, "c"),                 # queued
    lambda fc: request(fc, "z", 250),            # pre-emption
    lambda fc: release(fc, "a"),                 # the queue's head granted
    lambda fc: expire(fc, "T2"),                 # revoke
    lambda fc: media(fc, "a"),                   # first media: T2 starts
    lambda fc: release(fc, "nobody"),            # ignored, still recorded
], ids=["request", "pre-emption", "release", "timer", "first-media", "ignored"])
def test_a_transition_whose_record_fails_is_undone(step):
    """RES-OP-03 review: the transition was kept and its actions never sent,
    so the floor moved on unannounced. Now it is undone, and done again once
    the record can be written, with no gap in the sequence."""
    audit = _FailingAudit()
    fc = FloorControl(QUEUEING, clock=Clock(), observer=audit)
    establish(fc, "a", 100)
    request(fc, "b")
    before = _state_of(fc)
    audit.fail = True
    with pytest.raises(OSError):
        step(fc)
    assert _state_of(fc) == before
    audit.fail = False
    actions = step(fc)
    assert actions or fc.history[-1].event.participant == "nobody"
    assert [t.sequence for t in fc.history] == [1, 2, 3]
    assert audit.written == list(fc.history)


_BUSY_STEPS = (
    [lambda fc: establish(fc, "a", 100), lambda fc: media(fc, "a")]
    + [(lambda p: lambda fc: request(fc, p))(p) for p in ("b", "b", "c", "d", "e")]
    + [(lambda t: lambda fc: expire(fc, t))(t)
       for t in ("T2", "T8", "T3", "T20", "T20", "T20", "T20")]
    + [lambda fc: request(fc, "f", 250)]
    + [(lambda t: lambda fc: expire(fc, t))(t) for t in ("T8", "T3", "T1")]
)


@pytest.mark.vp("VP1-FC-021")
@pytest.mark.parametrize("failing", range(len(_BUSY_STEPS)))
def test_a_failed_then_retried_step_leaves_no_trace_in_what_follows(failing):
    """Undo is total: the busy floor with any one step's record failing once
    and the step retried ends exactly as the floor where nothing failed --
    every transition, action, counter and timer (C20, revoke causes and
    priorities included)."""
    def run(fail_at):
        audit = _FailingAudit()
        clock = Clock()
        fc = FloorControl(QUEUEING, clock=clock, observer=audit)
        for i, step in enumerate(_BUSY_STEPS):
            if i == fail_at:
                audit.fail = True
                with pytest.raises(OSError):
                    step(fc)
                audit.fail = False
            step(fc)
            clock.advance(5)
        return ([t.as_record() for t in fc.history], fc.running_timers(),
                [t.as_record() for t in audit.written])

    control = run(None)
    assert run(failing) == control
    assert control[0] == control[2]


@pytest.mark.vp("VP1-FC-021")
def test_a_final_transition_stands_when_its_record_fails():
    """The session is ending, which the audit trail cannot stop: the floor
    is released all the same, and the error still raised for the caller to
    log (RES-OP-03 review)."""
    audit = _FailingAudit()
    fc = FloorControl(QUEUEING, clock=Clock(), observer=audit)
    establish(fc, "a")
    request(fc, "b")
    audit.fail = True
    with pytest.raises(OSError):
        fc.handle(Event(EventType.SESSION_RELEASED), final=True)
    assert (fc.state, fc.holder, fc.queue) == (FloorState.RELEASED, None, ())
    assert fc.history[-1].event.type is EventType.SESSION_RELEASED


@pytest.mark.vp("VP1-FC-013")
def test_vp1_fc_013_a_profile_s_queue_is_bounded_and_drains_in_declared_order():
    """With a profile's own floor policy (mcx prearranged-group, as its hook
    returns it): requests beyond its max_queue_depth are denied, not dropped,
    and the queue is granted in floor-priority order, then arrival order
    (prior review gap of VP1-FC-013)."""
    from core import loader
    from core.hooks import MediaKind, Resolution, ResolutionKind, SessionRequest
    lp = loader.load(ROOT / "profiles" / "mcx")
    request_ = SessionRequest(request_id="q1", initiator="sip:h@mcptt.example",
                              target="grp:alpha", call_type="prearranged-group",
                              media=(MediaKind.VOICE,))
    hook_policy = lp.hooks.session_policy.floor_policy(
        request_, Resolution(kind=ResolutionKind.GROUP, members=("x",), group_id="g"))
    fc = FloorControl(Policy.from_hook(hook_policy), clock=Clock())
    depth = fc.policy.max_queue_depth
    assert fc.policy.queueing_enabled and depth == 8
    establish(fc, "holder", 255)                 # nothing outranks it
    asks = [(f"p{i}", priority) for i, priority in
            enumerate((10, 50, 10, 90, 50, 10, 90, 50, 70, 30))]
    denied = []
    for participant, priority in asks:
        actions = request(fc, participant, priority)
        denied += [a.target for a in actions if a.type is ActionType.SEND_DENY
                   and a.reason is DenyReason.QUEUE_FULL]
        assert len(fc.queue) <= depth
    assert denied == ["p8", "p9"] and len(fc.queue) == depth
    expected = [p for p, _ in sorted(asks[:depth], key=lambda a: (-a[1], asks.index(a)))]
    granted = []
    while fc.queue:
        release(fc, fc.holder)
        granted.append(fc.holder)
    assert granted == expected == ["p3", "p6", "p1", "p4", "p7", "p0", "p2", "p5"]


# --------------------------------------------------------------------------
# VP1-BND-015 — the machine stands alone (PLT-FC-004)
# --------------------------------------------------------------------------


@pytest.mark.vp("VP1-BND-015")
def test_importing_the_floor_machine_loads_no_sip_media_or_network():
    """In a fresh, isolated interpreter, importing core.floor loads nothing
    of SIP, media, the service, profiles or the network, and from the core
    only core.floor itself."""
    import subprocess
    code = ("import sys; sys.path.insert(0, %r); import core.floor; "
            "print('\\n'.join(sorted(sys.modules)))" % str(ROOT))
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, r.stderr
    loaded = set(r.stdout.split())
    forbidden = {"core.sip", "core.rtcp", "core.codec", "core.mcinfo", "core.session",
                 "core.loader", "service", "profiles", "socket", "_socket", "ssl", "_ssl",
                 "select", "selectors", "asyncio", "http", "urllib", "email", "multiprocessing",
                 "subprocess", "concurrent"}
    assert sorted(m for m in loaded if m.split(".")[0] in forbidden or m in forbidden) == []
    assert sorted(m for m in loaded if m.split(".")[0] == "core") == ["core", "core.floor"]


@pytest.mark.vp("VP1-BND-015")
def test_the_floor_machine_runs_alone_on_an_injected_clock():
    """ENV-UNIT: built with nothing but a policy and an injected clock, it
    grants, times out on that clock, and goes idle (T1, 6.3.4.4.3)."""
    clock = Clock()
    clock.advance(5000)
    fc = FloorControl(NO_QUEUEING, clock=clock)
    actions = establish(fc, "a")
    assert fc.state is FloorState.TAKEN and fc.holder == "a"
    assert ActionType.SEND_GRANTED in kinds(actions)
    assert fc.running_timers()[T_END_OF_MEDIA] == 5000 + 4000
    clock.advance(4000)
    expire(fc, T_END_OF_MEDIA)
    assert fc.state is FloorState.IDLE and fc.holder is None
