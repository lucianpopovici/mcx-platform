# CLAUDE.md — project context

Read this before touching anything. It is the shared context for every task in
this repository; individual task briefs are in `CLAUDE-1-service.md`,
`CLAUDE-2-sip-transport.md` and `CLAUDE-3-media.md`.

## What this is

A 3GPP mission-critical services platform (MCPTT / MCData) that runs as either a
public-safety deployment or a railway FRMCS deployment, from one codebase and one
image, with the profile chosen at deploy time.

**Current state: a process that has completed calls through third-party SIP
cores.** 908 tests pass and 20 boundary gates pass. `python3 -m service` runs.
Registration and group-call setup have passed through Kamailio 5.7.4 as a
proxy, and the terminating path has passed through Asterisk 20.6 as a B2BUA
(PLT-VP-R1 §7.1.1). The first thing those runs found was that the shipped
process could not establish a call at all, and that nothing in the suite
could tell: see "the suite tests what it injects" below.

## The one rule

> **`core/` must never learn that a specific profile exists.**

Call types, urgencies, applications and pre-emption scopes are opaque strings the
core cannot enumerate, compare against literals, or order. Everything
deployment-specific lives in a profile: a YAML package plus six hook
implementations.

This is enforced. `python3 tools/check_boundary.py --root .` runs 20 static gates
and will fail the build for `if profile.name == "frmcs"`, for an import from
`core/` into `profiles/`, or for the word "railway" in a `core/` docstring.

**If a gate blocks you, it is probably right.** Do not weaken a gate to get a
change through. Classify the failure (procedure in `docs/PLT-ANL-R1.md` §3):
leak → fix the core; profile defect → fix the profile and add a validation rule;
interface change → revise the ICD and update every in-tree profile in the same
change set.

## Commands

```bash
python3 -m pytest tests/ -q                   # must stay green (600+ tests)
python3 tools/check_boundary.py --root .      # must stay 20/20
# run it -- every one of these is required and none has a default
MCX_PROFILE=mcx MCX_RELEASE=19 MCX_IDMS=stub MCX_RECORDER=none MCX_BEARER=none \
  MCX_STRICT_RELEASE=true MCX_ADHOC_LIST_MAX=100 MCX_NETWORK_FILE=examples/network.yaml \
  MCX_DATA_DIR=/tmp/mcx python3 -m service
# VP1-SIG-001: the real process against a third-party SIP core (needs the
# kamailio / asterisk packages; prints PASS/FAIL/OBSERVED per step)
python3 tools/interop/run.py --core kamailio
python3 tools/interop/run.py --core asterisk
# profile x release: both axes, every combination
for p in mcx frmcs utility; do for r in 17 19; do
  MCX_PROFILE=$p MCX_RELEASE=$r python3 -m pytest tests/test_conformance.py -q
done; done
python3 -m pytest tests/test_release.py -q    # release gating, all 8 releases
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
core/qos.py         TS 23.501 standardised 5QI table; 3GPP, never profile
core/floor.py       TS 24.380 floor control; no SIP, no media, injected clock
core/sip.py         TS 24.379 adapter; renders/parses, touches no socket
core/mcinfo.py      TS 24.379 annex F.1 MCPTT info body and multipart; no call types
service/            the host process: `python -m service` (env config, SQLite store, HTTP)
service/sip_*.py    SIP over TLS: sip_txn (transactions), sip_core (dispatch, no socket), sip_tls (the only SIP socket)
service/media.py    RTP relay gated by the floor + floor control over UDP; MediaSession is pure, UdpMediaPlane owns the sockets
core/rtcp.py        TS 24.380 floor messages as RTCP APP packets (constants read from source; byte layout never checked against a third-party capture, FC-OP-03)
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

Nine of the ten constant sets checked against their specification have been
wrong. The later defects were not wrong values but **absent rules**: eleven
RTCP field ids had no length constraint at all, so `decode` accepted them at
any length. A wrong value fails the first time it meets a conformant peer; a
missing rule never fails, it just accepts what it should not.

**`tools/trace_compare.py` does not import `core/`, and that is the point.**
It is the independent check on the encoder. Structural independence is not
epistemic independence, though: both were once written from the same
recollection and shared the same wrong belief about which messages carry a
Message Sequence Number, so the tool endorsed the defect. When you change one,
derive the change from the specification, not from the other. `docs/PLT-CONF-AUDIT.md` records
what was checked, what it was, and what is still unverified.

**The suite tests what it injects.** Every end-to-end test passes
`platform=Platform()`, which is permissive, and talks to the SIP core with
nothing in between. So it could not see that the real process refused every
call (`MCX_RECORDER` / `MCX_BEARER`, SVC-OP-05), nor that no ACK survived a
record-routing proxy (SIP-OP-09). Before trusting a green run for anything the
deployed process does, run `tools/interop/run.py`. And if you add a
capability to `Platform`, add the environment variable that lets the process
state it.

**The audit read constants, not the code around them.** Every declared
protocol constant in `core/` was checked. The string literals inside the
message builders and parsers were not, and that is where the worst defect was:
the platform read and wrote an MCPTT info body in a format that does not exist
(PLT-CONF-AUDIT CA-20). `service/sip_core.py` has had only the parts a finding
led to. Treat any message-building code you touch as unaudited.

**Write message bodies from the schema, never from this repository.**
`docs/3GPP/schemas/` holds the annex F.1 schema extracted verbatim
(`tools/spec/extract_xsd.py`), and `tests/test_mcinfo.py` validates against
it. Test fixtures (`tests/mcpttinfo_fixture.py`) and the interop user agent
spell the body out literally from the specification. The interop agent once
copied its body from the platform's tests, and so shared the platform's
invention on the one point that mattered most.

**A native MCPTT request becomes a call type only through a declared
signature** (`mc_signature` on each call type, PLT-ICD-001 §2.6). Nothing is
read from the request that TS 24.379 does not define; `application` and
`urgency` come from the call type's declaration.

**Before you add or change a protocol constant**, read it from the documents in
`docs/3GPP/` — the `.docx` originals, not the PDFs. Automated extraction of a
PDF table does not fail loudly; it returns a plausible invented table. That
happened once already and is written up in PLT-CONF-AUDIT 2.

**A test that pins a constant must spell the value out as a literal.** If it
imports the constant it is checking, the code and the test move together and
the test proves nothing. One such test was written during the v0.3 audit and
caught only by mutation testing (PLT-CONF-AUDIT 4.10).

**There is no single release baseline any more, and that is deliberate.** The
3GPP release is a deployment parameter (`MCX_RELEASE`), independent of the
profile. Any profile STARTS at any supported release, but not every call type
exists at every release. The FRMCS profile's group calls are ad hoc, which
TS 24.379 has only from Rel-18. `MCX_STRICT_RELEASE` (required, no default)
decides what happens then: `true` refuses to start, `false` starts and warns
in the log and the health document (REL-OP-02). Ad hoc calls that list their
participants are capped by `MCX_ADHOC_LIST_MAX` (required, no default;
ADHOC-OP-04), checked before any entry is resolved. Every process also names
a network profile, `MCX_NETWORK_FILE` (required, no default; NET-OP-01): the
PLMNs, the map from reported cells to locations, and the trusted SIP cores
with a CA of their own (ICD-OP-10). Its `name/version/hash` joins the profile
and release in every audit record. The conformance matrix being
green does not mean every call type is reachable. Release numbers live in
`core/release.py` and nowhere else — `VP1-BND-022` fails a build that compares
a release to a literal anywhere else.

Its tables were extracted mechanically from all eight published versions of
TS 24.380 in `docs/3GPP/`. If you add a protocol constant, add its release
alongside it, read from the documents.

**Both layers are covered.** TS 24.380 floor control and TS 24.379 signalling
have each been read across every published release. On the signalling side
only the warning codes move — code 179 arrives in Rel-17 — and a code the
configured release does not define is emitted without its number rather than
suppressed or raised.

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

- **VP1-SIG-001** PASSED on 2026-09-24 against Kamailio (proxy) and Asterisk
  (B2BUA; counting a B2BUA was decided in VP-OP-01). Two caveats go with it:
  through a B2BUA, originating calls fail and terminating calls lose their MC
  body (SIP-OP-12), and the keylog-decrypted capture is still owed (SIP-OP-02).
- **VP1-FC-002** PASSED on 2026-09-24 on specification-derived evidence, which
  VP-OP-02 accepts in place of third-party captures (PLT-VP-R1 §6.1, FC-OP-03).
  The floor-timer questions FC-OP-01/02 were a separate, narrower gap and were
  also CLOSED on 2026-09-24 (PLT-CONF-AUDIT CA-21): T1/T2/T3/T8/T20 and C20 now
  do what TS 24.380 6.3.4 says, driven by `MEDIA_RECEIVED` from the media plane.
  The profiles' timer values were written for the old behaviour and are the
  owner's call (PRF-OP-02).
- **VP1-DOC-001**'s "schema-valid" clause: CLOSED (SVC-OP-01, 2026-09-22).
  RFC 4826's `resource-lists.xsd` was the one file the OMA-defined XSD
  validation was skipping on; it is now in `docs/OMA/` and
  `tests/test_group_schema.py` validates the rendered group document against
  the real schema set instead of skipping. VP1-DOC-001 as a whole is still
  open on SVC-OP-03 (group configuration's source is deployment data, not the
  profile schema).
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
