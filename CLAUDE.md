# CLAUDE.md — project context

Read this before touching anything. It is the shared context for every task in
this repository; individual task briefs are in `CLAUDE-1-service.md`,
`CLAUDE-2-sip-transport.md` and `CLAUDE-3-media.md`.

## What this is

A 3GPP mission-critical services platform (MCPTT / MCData) that runs as either a
public-safety deployment or a railway FRMCS deployment, from one codebase and one
image, with the profile chosen at deploy time.

**Current state: a thoroughly tested library that has never run as a process.**
280 tests pass, 18 boundary gates pass, and there is no entry point, no socket,
and no media path. The three task briefs close exactly that gap.

## The one rule

> **`core/` must never learn that a specific profile exists.**

Call types, urgencies, applications and pre-emption scopes are opaque strings the
core cannot enumerate, compare against literals, or order. Everything
deployment-specific lives in a profile: a YAML package plus six hook
implementations.

This is enforced. `python3 tools/check_boundary.py --root .` runs 18 static gates
and will fail the build for `if profile.name == "frmcs"`, for an import from
`core/` into `profiles/`, or for the word "railway" in a `core/` docstring.

**If a gate blocks you, it is probably right.** Do not weaken a gate to get a
change through. Classify the failure (procedure in `docs/PLT-ANL-R1.md` §3):
leak → fix the core; profile defect → fix the profile and add a validation rule;
interface change → revise the ICD and update every in-tree profile in the same
change set.

## Commands

```bash
python3 -m pytest tests/ -q                   # must stay green (430+ tests)
python3 tools/check_boundary.py --root .      # must stay 18/18
MCX_PROFILE=mcx MCX_IDMS=stub MCX_DATA_DIR=/tmp/mcx python3 -m service   # run it
MCX_PROFILE=mcx     python3 -m pytest tests/test_conformance.py -q
MCX_PROFILE=frmcs   python3 -m pytest tests/test_conformance.py -q
MCX_PROFILE=utility python3 -m pytest tests/test_conformance.py -q
```

## Architecture in one pass

```
core/hooks.py       the six profile interfaces — read this first
core/loader.py      read, validate, freeze, hash, resolve hooks
core/validation.py  strict validation; unknown keys are ERRORS
core/model.py       the frozen profile model
core/errors.py      reason codes (closed vocabulary) and exceptions
core/audit.py       audit records; every one carries the profile triple
core/invoke.py      the hook invocation boundary: deadlines, error mapping
core/session.py     the establishment sequence (PLT-ICD-001 §8.1)
core/floor.py       TS 24.380 floor control; no SIP, no media, injected clock
core/sip.py         TS 24.379 adapter; renders/parses, touches no socket
service/            the host process: `python -m service` (env config, SQLite store, HTTP)
service/sip_*.py    SIP over TLS: sip_txn (transactions), sip_core (dispatch, no socket), sip_tls (the only SIP socket)
service/media.py    RTP relay gated by the floor + floor control over UDP; MediaSession is pure, UdpMediaPlane owns the sockets
core/rtcp.py        TS 24.380 floor messages as RTCP APP packets (encoding UNVERIFIED, see FC-OP-03)
tools/trace_compare.py  floor trace comparator, independent of the encoder
profiles/common/    shared table-driven hook implementations
profiles/{mcx,frmcs,utility}/
```

`SessionManager.establish()` returns `(session, signals, refusal)`. `Signal` is
an abstract instruction — INVITE, BYE, RESERVE_QOS, START_RECORDING,
ROUTE_EXTERNAL, ROUTE_PARTNER. `service/sip_core.py` consumes them via
`Runtime.on_signals`, and `service/media.py` carries the media they set up.

## Conventions that are not negotiable

- **Injected clocks.** No module reads a wall clock. Every time-dependent
  component takes a `clock` callable returning integer milliseconds. This is why
  the floor machine and registration store are testable without sleeping, and
  `VP1-BND-016` fails a build that calls `time.time()` in `core/`.
- **UTC and milliseconds** everywhere, in config, logs and audit records.
- **Reason codes are a closed vocabulary** (`core/errors.py`). Core-originated
  codes cannot be redeclared by a profile. Every reserved code must have a SIP
  status mapping — `tests/test_sip.py` enforces this, so adding a code without a
  mapping fails.
- **Refusal vs failure.** A policy refusal returns a value; a fault raises.
  Never report a refusal as a server error or vice versa.
- **No default is ever substituted** for a missing hook, an unmapped label, an
  unrouted target or an unknown partner. Refuse instead. Several tests exist
  solely to pin this.

## Testing expectations

New behaviour needs tests that would fail without it. The suite has been
mutation-tested throughout: deliberately breaking a guard must turn a test red.
When you add a guard, check it the same way — break it on purpose, confirm a
test fails, restore it. Guards that are masked by another layer (two layers
protecting one invariant) need a test that isolates each with the other
disabled; `tests/test_icx.py` has worked examples.

## Protocol constants

Every constant set in this codebase that has been checked against its
specification has been wrong. Five for five. `docs/PLT-CONF-AUDIT.md` records
what was checked, what it was, and what is still unverified.

**Before you add or change a protocol constant**, read it from the documents in
`docs/3GPP/` — the `.docx` originals, not the PDFs. Automated extraction of a
PDF table does not fail loudly; it returns a plausible invented table. That
happened once already and is written up in PLT-CONF-AUDIT 2.

**A test that pins a constant must spell the value out as a literal.** If it
imports the constant it is checking, the code and the test move together and
the test proves nothing. One such test was written during the v0.3 audit and
caught only by mutation testing (PLT-CONF-AUDIT 4.10).

**The declared Rel-17 baseline is not what the code implements** — the RTCP
layer carries four Rel-19 values, one of which (subtype 14) means a different
message in the two releases. Unresolved: CA-11.

## Documents

| Doc | Use it for |
|---|---|
| `docs/PLT-SRS.md` | 207 requirements, phased R1–R4. Cite IDs in commits. |
| `docs/PLT-ICD-001.md` | The six hook contracts: PRE/POST/INV, §8.1 sequence, reason codes |
| `docs/PLT-VP-R1.md` | R1 verification plan: 99 cases with exact pass criteria |
| `docs/PLT-ANL-R1.md` | The three analyses and the gate-failure procedure |
| `core/PROFILE_BOUNDARY.md` | Why the boundary sits where it does |

## Status and honesty

All three task briefs have been worked. R1 is still **not** complete, and the
reasons are specific, not general:

- **VP1-SIG-001** needs two independent SIP cores; none was available, and
  which two is VP-OP-01. Nothing has run against a third-party core.
- **VP1-FC-002** cannot close: the TS 24.380 text was not available, so the RTCP
  encoding and the comparator are both from memory (FC-OP-03).
- **VP1-DOC-001**'s "schema-valid" clause: PARTIAL. Everything TS 24.481
  specifies is validated; the OMA-defined remainder needs
  OMA-TS-XDM_Group-V1_1_1, which is not a 3GPP deliverable (SVC-OP-01).
- **VP1-MED-001**: enforcement exists, but the codec set is a placeholder (MED-OP-01).
- **VP1-CC-001**: roles are named in the audit record but not independently
  deployable (SIP-OP-03).

The FRMCS profile is a **stub** with placeholder values, not reconciled with the
UIC FRS/SRS, and must not be used as safety-case input. Open points are
recorded across the documents; VP-R1 §11 holds the ones raised while building.

When you hit something the specification does not answer, **record it as an open
point rather than guessing quietly.** Several existing open points are
interface defects found exactly that way, and they are more valuable written down
than resolved by assumption. The same goes for specifications you cannot read:
say so in the code, as `core/rtcp.py` does, rather than asserting conformance.
