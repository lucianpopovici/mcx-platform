# Task 3 — media plane and RTCP

**Read `CLAUDE.md` first.** Tasks 1 and 2 must be complete: this needs a running
process with SIP sessions established.

## Objective

Carry media. `core/floor.py` is a complete, exhaustively tested TS 24.380 floor
control state machine whose messages have never reached the wire. Build the
media plane: RTP forwarding between participants, and RTCP carriage for floor
control.

## Cases this closes

| Case | Pass criterion (verbatim) |
|---|---|
| VP1-FC-001 | Request, granted, taken, deny, release, idle, revoke and queue position all sent and parsed per TS 24.380 |
| VP1-FC-002 | Every message matches TS 24.380 encoding; trace comparator reports no deviation |
| VP1-MED-001 | Media flows using only codecs declared by the loaded profile |
| VP1-MED-003 | Media from the floor holder reaches every participant; verified by capture at each endpoint |
| VP1-MED-004 | A non-holder transmitting produces no media at any other participant |

Requirements: PLT-FC-001, -002; PLT-MED-001, -003; PLT-MED-005 (R2, exercised
early by `VP1-MED-004`).

## What already exists — do not rebuild it

- `core/floor.py`: `FloorControl` with states, the full event and action
  vocabulary (`SEND_GRANTED`, `SEND_TAKEN`, `SEND_DENY`, `SEND_IDLE`,
  `SEND_REVOKE`, `SEND_QUEUE_POSITION`, `START_TIMER`, `STOP_TIMER`), priority
  arbitration, bounded ordered queueing, override, revoke, timer-driven recovery,
  and a full transition history. It enforces its own invariants and raises
  `FloorInvariantViolation` rather than continuing corrupted.
- `Policy.from_hook(floor_policy)` bridges the IF-SES floor policy without
  importing hook types.
- `SessionManager` already constructs a `FloorControl` per voice/video session
  and drives `SESSION_ESTABLISHED` and `SESSION_RELEASED`.

**Your job is encoding and transport of the actions it already emits, plus RTP
forwarding. Do not reimplement arbitration — it is done, and mutation-tested.**

## Design constraints

1. **The state machine stays authoritative.** Feed it events; send what it
   returns. If you find yourself deciding who gets the floor, stop — that
   decision belongs to `FloorControl` and, for priority, to IF-PRI via
   `floor_priority`.
2. **Timers come from the profile** (PLT-FC-010). The machine already emits
   `START_TIMER` / `STOP_TIMER` actions with durations taken from the profile.
   Your transport schedules them and feeds back `TIMER_EXPIRY`. Do not hardcode
   an interval.
3. **`VP1-MED-004`: a non-holder's media must not reach anyone.** Enforce at the
   forwarding point, not by trusting clients.
4. **`VP1-MED-001`: only codecs the profile declares.** The negotiated payload
   type comes from `negotiate()`; the forwarder must not pass anything else.
5. **RTCP encoding must match TS 24.380 exactly** (`VP1-FC-002`). This is the one
   place in this task with real protocol risk. Build the trace comparator
   alongside, not afterwards.
6. **Injected clock**, as everywhere.

## Known traps

- The timer-to-behaviour mapping in `core/floor.py` (`T203` stop-talking, `T205`
  grant retransmission, `T206` revoke) is flagged in that module's docstring as
  **needing confirmation against the current TS 24.380 release**. Confirm it
  before building encoding on top of it. The machine's structure does not depend
  on the mapping; only which transition each name drives does.
- `VP1-FC-002` requires a trace comparator reporting no deviation. `VP-OP-02` is
  open: whether specification-derived expected flows suffice, or golden captures
  from a third-party implementation are required. Do not close the case on
  self-generated expectations without recording which you used.
- Media replication for a group call is per-participant; `VP1-MED-003` demands
  capture **at each endpoint**, not at the forwarder. Design for that from the
  start.
- Floor control across an interworking gateway or an interconnection is **not**
  resolved (ICD-OP-06, ICX-OP-03). Do not invent semantics for it here; those
  paths are R3/R4 and the open points exist precisely so the decision is made
  deliberately.

## Definition of done

```bash
python3 -m pytest tests/ -q
python3 tools/check_boundary.py --root .
```

Plus, demonstrably: a two-party call with audible media; a group call with
contention where the queue drains in floor-priority order; a packet capture whose
RTCP matches TS 24.380; a non-holder transmitting with no media reaching any
other endpoint; and the trace comparator reporting no deviation on a full call.

**This closes R1.** After it, all 99 verification cases should pass, and the R1
exit criterion — two clients completing a prearranged group call with floor
arbitration — is demonstrable end to end.

## Out of scope

MBS/broadcast delivery, off-network (ProSe), MCVideo — all R4. Media security
(SRTP) is R2 and follows the key management work, not this task.
