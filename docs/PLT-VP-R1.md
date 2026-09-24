# Release 1 — Verification Plan

**Document:** PLT-VP-R1
**Version:** 0.3 (draft)
**Date:** 2026-09-19
**Status:** Draft for review — not baselined
**Verifies:** PLT-SRS v0.1, all 83 requirements marked R1
**References:** PLT-ICD-001 v0.1

---

## 1. Purpose and scope

This plan defines how each of the 83 R1 requirements of PLT-SRS is verified, by
which test case, and what constitutes a pass. §9 is the traceability matrix;
PLT-VER-008 requires every requirement to reach at least one verification
artefact, and the matrix is the evidence of that.

**R1 exit criterion (PLT-SRS §1.6):** two clients complete a prearranged group
call with floor arbitration, and both profile conformance suites pass.

### 1.1 What R1 does and does not verify

R1 verifies the core, the profile framework, the MCX profile, on-network MCPTT
private and prearranged group calls, and floor control.

Not in R1, and not verified here: MC security per TS 33.180 (R2), real identity
management (R2 — R1 runs a stub under PLT-IDM-007), MCData, emergency and
imminent-peril handling, pre-emption behaviour, the FRMCS profile, MBS, and
off-network operation. Requirements for these carry later phases and appear in
their own plans.

**One consequence worth stating plainly.** R1 has no pre-emption requirement in
scope, but `IF-PRI.compare` is fully exercised here (TS-HOOK-020..024) because
the properties it must hold are cheap to test now and expensive to retrofit once
R2 depends on them.

### 1.2 Verification methods

| Method | Meaning | Evidence |
|---|---|---|
| **T** Test | Automated, repeatable, pass/fail without judgement | CI run record |
| **D** Demonstration | Executed against a running system, observed | Recorded session + capture |
| **A** Analysis | Reasoned argument over design or measurement | Signed analysis note |
| **I** Inspection | Static examination of code, config or document | Gate result or review record |

R1 requirement methods, as specified: 54 T, 26 I, 3 A, 0 D.

### 1.3 Test case identification

`VP1-<SUITE>-<nnn>`. A test case may verify several requirements; a requirement
may need several cases. Both are recorded in §9.

### 1.4 Independence

Per PLT-SRS §18, conformance suites run against the same binary for both
profiles. The FRMCS profile is a stub in R1 (§14 of PLT-SRS is `[PROVISIONAL]`),
so its suite verifies **framework** behaviour only — that the core loads,
validates and operates against a second profile — not railway semantics. That
is sufficient for the boundary-leak detection PLT-VER-003 depends on, and is the
reason the FRMCS stub exists this early.

---

## 2. Test environment

### 2.1 Configurations

| ID | Name | Composition |
|---|---|---|
| ENV-UNIT | Unit | Core modules in isolation, no network, no SIP, no media |
| ENV-INT | Integration | Platform + SIP core + HTTP proxy + stub IdMS, containerised, single host |
| ENV-E2E | End-to-end | ENV-INT + two MC clients + packet capture + trace comparator |
| ENV-CI | Static | Source tree, static analysis and gate tooling only |

### 2.2 Instrumentation

| Item | Purpose | Used by |
|---|---|---|
| Trace comparator | Diffs captured signalling against expected message flow per call type | TS-CC, TS-FC, TS-E2E |
| Packet capture | SIP and RTP/RTCP on all interfaces, retained per run | TS-SIG, TS-FC, TS-MED, TS-E2E |
| Malformed profile corpus | One profile per rejection class of PLT-SRS §5.1 | TS-LOAD |
| Property-based test engine | Generates decision spaces from a loaded profile | TS-HOOK |
| Audit log reader | Parses structured audit output for assertions | TS-OAM |

### 2.3 Entry criteria

A requirement enters verification only when its implementation is merged and the
static gates of TS-BND pass. TS-BND failures block the suite: a boundary
violation invalidates the conformance argument for everything above it.

---

## 3. TS-LOAD — profile loading and validation

Environment: ENV-UNIT (validation), ENV-INT (startup behaviour).

The malformed-profile corpus is the substance of this suite. Each case supplies
a profile differing from the valid MCX profile in exactly one respect, so a
rejection is attributable to that one defect.

| Case | Title | Steps | Pass criterion |
|---|---|---|---|
| VP1-LOAD-001 | Valid profile loads | Start with the MCX profile | Process reaches ready; profile name, version and hash logged at start |
| VP1-LOAD-002 | No profile configured | Start with profile configuration absent | Refuses to start; diagnostic names the missing configuration; no listening socket opened |
| VP1-LOAD-003 | Named profile absent | Configure a profile name with no package | Refuses to start; diagnostic names the profile sought |
| VP1-LOAD-004 | Two profiles configured | Configure both MCX and FRMCS, not in test mode | Refuses to start; diagnostic states that exactly one profile is permitted |
| VP1-LOAD-005 | Test mode with production indicator | Set test mode and a production indicator together | Refuses to start; refusal attributable to the production indicator, not the profile |
| VP1-LOAD-006 | Test mode legitimate | Set test mode, no production indicator, two profiles | Starts; both profiles loaded and independently addressable |
| VP1-LOAD-010 | Unknown key rejected | Profile with one undeclared key | Rejected; diagnostic gives the key's path within the package |
| VP1-LOAD-011 | Undeclared urgency reference | Call type naming an undeclared urgency | Rejected; diagnostic names both the call type and the urgency |
| VP1-LOAD-012 | Undeclared scope reference | Priority rule naming an undeclared pre-emption scope | Rejected; diagnostic names the rule and the scope |
| VP1-LOAD-013 | Undeclared application reference | Call type naming an undeclared application | Rejected; diagnostic names both |
| VP1-LOAD-014 | Undeclared initiator role | Call type naming an undeclared role | Rejected; diagnostic names both |
| VP1-LOAD-015 | Priority table not total | Declared call type with no matching priority rule | Rejected; diagnostic names the uncovered call type |
| VP1-LOAD-016 | Bearer table not total | Declared (call type, media) with no matching bearer rule | Rejected; diagnostic names the uncovered combination |
| VP1-LOAD-017 | Undeclared reason code | Session policy returning a code outside the declared set | Rejected at validation where statically determinable; otherwise `hook-contract-violation` at runtime |
| VP1-LOAD-018 | Unknown floor timer name | Floor policy with a timer name not in TS 24.380 | Rejected; diagnostic names the timer |
| VP1-LOAD-020 | Hook missing | Profile omitting one of the five hooks | Rejected; diagnostic names the missing hook |
| VP1-LOAD-021 | Hook does not implement interface | Hook lacking a required method | Refuses to start; diagnostic names the hook and the missing method |
| VP1-LOAD-022 | No default hook substituted | Remove each hook in turn, five runs | Five refusals; no run starts with a substituted default |
| VP1-LOAD-030 | Validation failure prevents start | Any rejected profile | No listening socket; readiness never true; exit status non-zero |
| VP1-LOAD-031 | No partial start | Profile rejected after partial parse | No component initialised; no side effect on any configured store |
| VP1-LOAD-040 | Profile immutable after load | Attempt mutation of the loaded profile object from a test hook | Mutation rejected or has no effect; decisions unchanged thereafter |
| VP1-LOAD-041 | Content hash stable and sensitive | Load same profile twice; then alter one value and reload | Identical hash across identical loads; different hash after the alteration |
| VP1-LOAD-042 | Call type set is profile-determined | Request a call type declared in FRMCS while MCX is loaded | Rejected as undeclared; no session established |

---

## 4. TS-BND — boundary and static gates

Environment: ENV-CI. These run on every change (PLT-VER-002) and block merge.

| Case | Title | Steps | Pass criterion |
|---|---|---|---|
| VP1-BND-001 | No profile-specific identifiers in core | Scan `core/` for profile names and profile-specific domain terms, in identifiers, literals and comments | Zero matches. Any match fails the build and names file and line |
| VP1-BND-002 | Core does not import profiles | Static import-graph analysis | No edge from `core/` to `profiles/` |
| VP1-BND-003 | Hook interfaces are the only crossing | Static analysis of call sites | Every `core/` → profile call is through a §6 interface |
| VP1-BND-004 | Value objects immutable | Inspect all hook parameter and return types | Every type frozen; no mutable field |
| VP1-BND-005 | Hooks do not call back | Static analysis of profile packages | No reference from any profile to a core symbol other than the hook types |
| VP1-BND-006 | Single image, all profiles | Inspect build output | One artefact; both profile packages present; no per-profile build variant |
| VP1-BND-007 | No default profile in code or config | Inspect configuration defaults and code paths | No path yields a profile without explicit configuration |
| VP1-BND-008 | No hot reload mechanism | Inspect for reload handlers, watchers and signal handlers touching the profile | None present |
| VP1-BND-009 | Core owns the protocol state machines | Inspect floor control, SIP session and document modules | No transition, guard or state parameterised by profile input; timers excepted |
| VP1-BND-010 | Reference-point naming | Inspect module boundaries against PLT-SRS §3.1 | Each boundary corresponding to a reference point is named for it |
| VP1-BND-011 | Priority table is declarative | Inspect the MCX profile | Priority expressed as configuration data; no imperative priority logic in the hook |
| VP1-BND-012 | No QoS mapping in core | Inspect core for QoS identifier and ARP literals | None present outside the bearer hook interface types |
| VP1-BND-013 | No priority logic in core | Inspect core for priority comparison or ordering | All priority decisions traced to `IF-PRI` |
| VP1-BND-014 | Resolver receives full context | Inspect the resolve call site | Initiator, call type, application and location all passed |
| VP1-BND-015 | Floor state machine independently testable | Inspect its dependencies | No dependency on SIP, media or network; instantiable in ENV-UNIT |
| VP1-BND-016 | Time discipline | Inspect configuration, logs and audit records | All timestamps UTC; all durations in milliseconds; no local-time formatting |
| VP1-BND-020 | Both suites run per change | Inspect CI configuration | Both profile suites execute on every change; neither is skippable by branch or label |
| VP1-BND-021 | Per-profile suite exists | Inspect the suites | One suite per profile, both targeting the same built artefact |

---

## 5. TS-HOOK — hook contracts

Environment: ENV-UNIT, with property-based generation over the loaded profile's
declared decision space. Contracts are those of PLT-ICD-001.

| Case | Title | Steps | Pass criterion |
|---|---|---|---|
| VP1-HOOK-001 | Hook exception fails the session | Inject a raising hook at each of the five interfaces | Session fails with `hook-error`; no default result substituted; no session established |
| VP1-HOOK-002 | Contract violation distinguished | Return a value failing a POST check | Fails with `hook-contract-violation`, distinct from `hook-error` |
| VP1-HOOK-003 | Invocations audited | Establish a session | Audit trail contains one record per invocation with interface ID, correlation ID, elapsed time and outcome |
| VP1-HOOK-004 | Decisions audited in full | Establish a session | Priority, session and bearer decisions each recorded with all fields |
| VP1-HOOK-010 | Resolution kinds consistent | Resolve a user, a group, and an unknown target | `USER` → exactly 1 member; `GROUP` → `group_id` set and ≥ 1 member; unknown → raises |
| VP1-HOOK-011 | Member set well-formed | Resolve a group with a duplicated member in configuration | Returned members deduplicated and stably ordered across repeated calls |
| VP1-HOOK-012 | Domain restriction | Resolve a target outside the profile's declared domains | Refused; no member returned from an undeclared domain |
| VP1-HOOK-013 | `resolved_from` recorded | Resolve via any indirect reference | `resolved_from` populated and present in the audit record |
| VP1-HOOK-014 | No partial resolution | Resolve a group whose backing store is partially unavailable | Raises with `resolver-unavailable`; no partial member set returned |
| VP1-HOOK-015 | Resolution failure codes distinct | Resolve an unknown target, then an unheld declared identity | `unknown-target` and `no-binding` respectively; codes not conflated |
| VP1-HOOK-020 | Priority decision complete | Evaluate every declared call type | Every decision carries level, scope, both pre-emption flags, floor priority and label |
| VP1-HOOK-021 | Priority totality | Evaluate all declared call types | No evaluation fails to produce a decision |
| VP1-HOOK-022 | Cross-scope comparison is zero | Generate decision pairs with differing scopes | `compare` returns 0 for every such pair, unconditionally |
| VP1-HOOK-023 | Comparison properties | Property-based over the profile's decision space | Antisymmetry, transitivity within a scope, and reflexive equality all hold; no counterexample |
| VP1-HOOK-024 | Determinism | Evaluate identical inputs repeatedly within one process | Identical decisions every time |
| VP1-HOOK-030 | Admission returns, never raises | Drive refusal conditions | Refusal arrives as `permitted=False` with a code; no exception raised for a business decision |
| VP1-HOOK-031 | Reason codes declared | Drive every refusal path | Every code returned is a member of the profile's declared set |
| VP1-HOOK-032 | Refused session not established | Refuse admission | No SIP invitation sent; no session record created; refusal audited |
| VP1-HOOK-033 | Session decision applied verbatim | Vary auto-answer, acknowledgement, recording and participant limit | Observed behaviour matches the decision exactly; core infers nothing |
| VP1-HOOK-034 | Floor policy consistency | Return queueing disabled with non-zero depth, and the converse | Both rejected as contract violations |
| VP1-HOOK-040 | Bearer decision well-formed | Select for every declared (call type, media) | Exactly one primary path; unique path IDs; redundancy consistent with path count |
| VP1-HOOK-041 | ARP consistency | Return ARP pre-emption capability against a non-capable priority decision | Rejected as a contract violation |

---

## 6. TS-FC — floor control

Environment: ENV-UNIT for the state machine, ENV-E2E for protocol conformance.
PLT-FC-004 requires the machine to be testable without media or SIP, and this
suite depends on that: VP1-FC-010..014 run in ENV-UNIT.

| Case | Title | Steps | Pass criterion |
|---|---|---|---|
| VP1-FC-001 | Message set implemented | Exercise each message in ENV-E2E | Request, granted, taken, deny, release, idle, revoke and queue position all sent and parsed per TS 24.380 |
| VP1-FC-002 | RTCP encoding conformant | Capture floor control traffic | Every message matches TS 24.380 encoding; trace comparator reports no deviation |
| VP1-FC-010 | Exhaustive transitions | Drive every state/event pair in ENV-UNIT | Every defined transition reached; no undefined pair produces an unhandled state |
| VP1-FC-011 | Single floor holder | Concurrent requests from all participants, repeated | At no observed point does more than one participant hold the floor |
| VP1-FC-012 | Arbitration by floor priority | Competing requests at differing floor priorities | Highest floor priority granted; result traced to the `IF-PRI` decision, not to arrival order |
| VP1-FC-013 | Queue bounded and ordered | Requests exceeding `max_queue_depth` | Queue never exceeds the declared depth; grants follow declared order; excess requests denied not dropped |
| VP1-FC-014 | Deny when queueing disabled | Request while floor held, queueing disabled | Deny returned; no queue entry created |
| VP1-FC-020 | Timers taken from profile | Load two profiles differing only in floor timer values | Observed timing follows each profile; transition sequence identical in both |
| VP1-FC-021 | Transitions recorded | Complete a call with contention | Every transition recorded with trigger, timestamp and resulting state; sequence reconstructible from the audit trail alone |

---

## 7. TS-SIG, TS-CC, TS-MED, TS-DOC, TS-OAM

### 7.1 TS-SIG — SIP signalling (ENV-INT)

| Case | Title | Pass criterion |
|---|---|---|
| VP1-SIG-001 | Third-party SIP core interoperability | Platform completes registration and session setup against at least two distinct SIP core implementations, with no implementation-specific configuration |
| VP1-SIG-002 | Third-party registration | Registration state maintained per MC service ID; state observable and correct after client re-registration and after expiry |
| VP1-SIG-003 | Feature tags | Every request and response carries the MC service feature tags and media feature parameters of TS 24.379; verified by trace comparator |
| VP1-SIG-004 | Malformed request rejected | Malformed, replayed and unknown-session requests each rejected with the status code specified in TS 24.379 |
| VP1-SIG-005 | No state after failure | After each final failure response, session store contains no record; verified by direct inspection, not by absence of symptoms |
| VP1-SIG-006 | TLS enforced | Plaintext connection attempts refused on every external interface; mutual authentication performed where the peer supports it |
| VP1-SIG-007 | Stub IdMS refused in production | Start with the stub identity provider and a production indicator | Refuses to start |

#### 7.1.1 VP1-SIG-001 — executed 2026-09-24

Run with `python3 tools/interop/run.py --core kamailio|asterisk`. The platform
is started from its environment alone, identically for both cores, with no
`platform=` injection. The user agents (`tools/interop/ua.py`) import nothing
from `core/` or `service/`. Every message each agent sent and received is kept
in the run's `transcript.txt`.

| Core | Role it plays | Registration | Session setup | Verdict |
|---|---|---|---|---|
| Kamailio 5.7.4 | Record-routing proxy and registrar (S-CSCF stand-in) | PASS — the UE's REGISTER is relayed and the platform answers it as registrar of record | PASS — INVITE to the callee, 200 OK to the originator, both ACKs delivered through the proxy; teardown works both ways | **Passes** |
| Asterisk 20.6 | Back-to-back user agent (PBX); registers each user onward to the platform | PASS — UEs register with Asterisk, and Asterisk's onward registrations to the platform succeed | Terminating (platform → Asterisk → UE): PASS, including both ACKs and teardown. Originating (UE → Asterisk → platform): **not possible** — see SIP-OP-12 | **Pending the VP-OP-01 decision** |

**What the first runs found, all fixed in the same change set before the
runs above passed:**

1. The shipped process could not establish a call in any profile
   (SVC-OP-05). The platform capabilities `recording_available` and
   `reserve_qos` were hard-coded false, and every call type in every in-tree
   profile requires recording.
2. The platform ignored RFC 3261 §12 dialog routing (SIP-OP-09). Its 2xx
   carried no Record-Route, and its own ACK and BYE went to the peer's AoR
   with no Route header. Kamailio dropped both ACKs of every answered call.

Neither was visible to the suite: every end-to-end test injected a permissive
`Platform()` and talked to the core with nothing in between.

**Correction, same day (PLT-CONF-AUDIT CA-20).** The first recorded runs
proved less than this section first said. The user agent's MCPTT info body
was copied from the platform's own tests, and the platform's body format
turned out to be invented (`<mcptt-call_type>`, which exists in no release of
TS 24.379). So those runs showed SIP routing through each core, and nothing
about MC body interoperability. After CA-20a the user agent writes its body
from annex F.1, and the Kamailio run now also checks that the callee
receives a conformant MCPTT info body naming the caller and the group. It
passes. Through Asterisk the body is lost in the terminating direction too
(SIP-OP-12).

**VP1-SIG-001 therefore stays OPEN on one question, which is VP-OP-01 and not
a test result:** whether a back-to-back user agent counts as a "distinct SIP
core implementation". Kamailio is one, unambiguously. Asterisk regenerates
every message, so it cannot carry the MC info body on the originating path
(SIP-OP-12). If a B2BUA counts, VP1-SIG-001 passes on the terminating path
and the originating path becomes a documented deployment constraint. If it
does not, a second proxy is needed; no other proxy is packaged for this
environment, and reSIProcate `repro` is the independent candidate.

### 7.2 TS-CC — call control (ENV-E2E)

| Case | Title | Pass criterion |
|---|---|---|
| VP1-CC-001 | Function separation | Participating and controlling functions deployable and observable as distinct roles; a session names its controlling function in the audit record |
| VP1-CC-002 | Single controlling function | Across concurrent group calls including simultaneous origination on one group, exactly one controlling function exists per session at all times |
| VP1-CC-003 | Private call, manual commencement | Call established after callee acceptance; trace matches the expected flow |
| VP1-CC-004 | Private call, automatic commencement | Call established without callee action where the session decision sets auto-answer |
| VP1-CC-005 | Prearranged group call | Invitations sent to exactly the resolved member set, no more and no fewer; late joiners handled per the session decision |
| VP1-CC-006 | Session decision applied | Behaviour matches the session decision for every field; no field inferred by the core |
| VP1-CC-007 | One priority decision per session | Each session carries exactly one decision, taken at admission, unchanged for its lifetime |

### 7.3 TS-MED — media (ENV-E2E)

| Case | Title | Pass criterion |
|---|---|---|
| VP1-MED-001 | RTP with declared codecs | Media flows using only codecs declared by the loaded profile |
| VP1-MED-002 | SDP negotiation | Offer with no acceptable codec rejected; offer with an acceptable codec negotiated correctly |
| VP1-MED-003 | Replication to participants | Media from the floor holder reaches every participant; verified by capture at each endpoint |
| VP1-MED-004 | No media without floor | A non-holder transmitting produces no media at any other participant |

### 7.4 TS-DOC — document server (ENV-INT)

| Case | Title | Pass criterion |
|---|---|---|
| VP1-REL-001 | Release is selected, never defaulted | Process refuses to start with `MCX_RELEASE` unset, unsupported or unparseable; exit code 2 |
| VP1-REL-002 | Release and profile are independent | Conformance suite passes for every profile at every supported release; CI runs the matrix, no combination skippable |
| VP1-REL-003 | A release emits only what it defines | For each of the eight tabulated releases, every subtype, field id and revoke cause the release defines encodes, and everything it does not is refused |
| VP1-REL-004 | Subtype 14 is read per release | Rel-17 reports Floor Queued Cancel, Rel-18+ reports Queued Floor Requests, from identical bytes |
| VP1-REL-005 | Wrong release is not malformed | A Rel-19 message decoded at Rel-17 raises `ReleaseRefused`, counts `floor_wrong_release`, and does not count `floor_malformed` |
| VP1-REL-007 | Signalling warning codes are release-gated | A refusal whose TS 24.379 warning code post-dates the configured release carries the explanatory phrase without the number, keeps its 4xx/5xx status, and does not raise |
| VP1-REL-006 | Release is in the audit record | Every audit record's identity carries the profile triple and the release |
| VP1-DOC-001 | Group documents served | Group documents retrievable over HTTP per TS 24.481; schema-valid; content matches the profile's group configuration |

### 7.5 TS-OAM — observability (ENV-INT)

| Case | Title | Pass criterion |
|---|---|---|
| VP1-OAM-001 | Profile identity in logs and audit | Name, version and hash logged at start and present on every audit record; values match the health endpoint |
| VP1-OAM-002 | Health endpoint | Name, version and hash exposed; readiness false until the profile is validated and loaded |
| VP1-OAM-003 | Session lifecycle audited | Admission, refusal, establishment and release each produce an audit record; refusals carry their reason code |
| VP1-OAM-004 | Structured logs | Logs machine-parsable; one stable correlation identifier per session, present on every record of that session across all components |
| VP1-OAM-005 | Restart without committed-record loss | Restart an instance mid-run | No committed session record lost; platform returns to service |

---

## 8. Analyses

Each requires a written note, reviewed and signed. An analysis that cannot cite
a concrete artefact is not evidence.

| Case | Requirement | Argument required |
|---|---|---|
| VP1-ANL-001 | PLT-PRF-022 | Demonstrate by worked change that adding a call type, urgency and application to the MCX profile requires no change under `core/`. Evidence: the change set, showing files touched. |
| VP1-ANL-002 | PLT-PRF-023 | Demonstrate by the FRMCS stub's own history that introducing a profile touched no file under `core/`. Evidence: the diff. |
| VP1-ANL-003 | PLT-VER-003 | Define the procedure for handling a change that breaks one profile suite and not the other, including who classifies it and how a boundary defect is recorded. Evidence: the procedure, plus one worked example from the R1 period. |

> VP1-ANL-001 and VP1-ANL-002 are the two that matter most in R1. They are the
> only direct evidence that the architecture's central claim holds. If either
> cannot be argued from a real change set, the boundary is in the wrong place
> and R1 should not exit.

---

## 9. Traceability matrix

All 83 R1 requirements. Method as specified in PLT-SRS.

| Requirement | M | Verified by |
|---|---|---|
| PLT-GEN-001 | I | VP1-BND-006 |
| PLT-GEN-002 | T | VP1-LOAD-001 |
| PLT-GEN-003 | T | VP1-LOAD-002, VP1-LOAD-003, VP1-LOAD-004 |
| PLT-GEN-004 | I | VP1-BND-007 |
| PLT-GEN-005 | T | VP1-LOAD-005, VP1-LOAD-006 |
| PLT-GEN-006 | I | VP1-BND-001 |
| PLT-GEN-007 | I | VP1-BND-002, VP1-BND-003 |
| PLT-GEN-008 | T | VP1-OAM-002 |
| PLT-GEN-009 | T | VP1-OAM-005 |
| PLT-GEN-011 | I | VP1-BND-016 |
| PLT-PRF-001 | I | VP1-BND-003, VP1-BND-011 |
| PLT-PRF-002 | T | VP1-LOAD-001 |
| PLT-PRF-003 | T | VP1-LOAD-010 |
| PLT-PRF-004 | T | VP1-LOAD-011, VP1-LOAD-012, VP1-LOAD-013, VP1-LOAD-014 |
| PLT-PRF-005 | T | VP1-LOAD-015 |
| PLT-PRF-006 | T | VP1-LOAD-016 |
| PLT-PRF-007 | T | VP1-LOAD-030 |
| PLT-PRF-008 | T | VP1-LOAD-010, VP1-LOAD-011, VP1-LOAD-015 |
| PLT-PRF-009 | T | VP1-LOAD-040 |
| PLT-PRF-010 | I | VP1-BND-008 |
| PLT-PRF-011 | T | VP1-LOAD-041 |
| PLT-PRF-012 | I | VP1-LOAD-022, VP1-BND-007 |
| PLT-PRF-013 | T | VP1-LOAD-020, VP1-LOAD-021 |
| PLT-PRF-020 | I | VP1-BND-001, VP1-BND-009 |
| PLT-PRF-021 | T | VP1-LOAD-042 |
| PLT-PRF-022 | A | VP1-ANL-001 |
| PLT-PRF-023 | A | VP1-ANL-002 |
| PLT-PRF-030 | I | VP1-BND-009 |
| PLT-PRF-031 | I | VP1-BND-009, VP1-FC-020 |
| PLT-PRF-032 | I | VP1-BND-010 |
| PLT-HOK-001 | I | VP1-BND-004 |
| PLT-HOK-002 | I | VP1-BND-004, VP1-BND-005 |
| PLT-HOK-003 | T | VP1-HOOK-001, VP1-HOOK-002 |
| PLT-HOK-005 | T | VP1-HOOK-003, VP1-HOOK-004 |
| PLT-HOK-010 | T | VP1-HOOK-010, VP1-HOOK-011 |
| PLT-HOK-011 | I | VP1-BND-014 |
| PLT-HOK-014 | T | VP1-HOOK-013 |
| PLT-HOK-015 | T | VP1-HOOK-014, VP1-HOOK-015 |
| PLT-HOK-020 | T | VP1-HOOK-020, VP1-HOOK-021 |
| PLT-HOK-021 | I | VP1-BND-013 |
| PLT-HOK-022 | T | VP1-HOOK-022, VP1-HOOK-023 |
| PLT-HOK-023 | I | VP1-BND-011 |
| PLT-HOK-030 | T | VP1-HOOK-030, VP1-HOOK-031 |
| PLT-HOK-031 | T | VP1-HOOK-033 |
| PLT-HOK-032 | T | VP1-HOOK-034, VP1-FC-013, VP1-FC-014 |
| PLT-HOK-033 | T | VP1-HOOK-032 |
| PLT-HOK-040 | T | VP1-HOOK-040, VP1-HOOK-041 |
| PLT-HOK-043 | I | VP1-BND-012 |
| PLT-IDM-007 | T | VP1-SIG-007 |
| PLT-SIG-001 | T | VP1-SIG-001 |
| PLT-SIG-002 | T | VP1-SIG-002 |
| PLT-SIG-003 | T | VP1-SIG-003 |
| PLT-SIG-004 | T | VP1-SIG-004 |
| PLT-SIG-005 | T | VP1-SIG-005 |
| PLT-CC-001 | T | VP1-CC-001 |
| PLT-CC-002 | T | VP1-CC-002 |
| PLT-CC-003 | T | VP1-CC-003, VP1-CC-004 |
| PLT-CC-004 | T | VP1-CC-005 |
| PLT-CC-005 | T | VP1-CC-006, VP1-HOOK-033 |
| PLT-FC-001 | T | VP1-FC-002 |
| PLT-FC-002 | T | VP1-FC-001 |
| PLT-FC-003 | T | VP1-FC-011 |
| PLT-FC-004 | I | VP1-BND-015 |
| PLT-FC-005 | T | VP1-FC-012 |
| PLT-FC-006 | T | VP1-FC-013 |
| PLT-FC-007 | T | VP1-FC-014 |
| PLT-FC-010 | T | VP1-FC-020 |
| PLT-FC-011 | T | VP1-FC-021 |
| PLT-MED-001 | T | VP1-MED-001 |
| PLT-MED-002 | T | VP1-MED-002 |
| PLT-MED-003 | T | VP1-MED-003, VP1-MED-004 |
| PLT-GRP-001 | T | VP1-DOC-001 |
| PLT-PRI-001 | T | VP1-CC-007 |
| PLT-SEC-007 | T | VP1-SIG-006 |
| PLT-OAM-001 | T | VP1-OAM-001 |
| PLT-OAM-002 | T | VP1-OAM-003 |
| PLT-OAM-005 | T | VP1-OAM-004 |
| PLT-OAM-007 | T | VP1-OAM-002 |
| PLT-VER-001 | I | VP1-BND-021 |
| PLT-VER-002 | I | VP1-BND-020 |
| PLT-VER-003 | A | VP1-ANL-003 |
| PLT-VER-004 | T | VP1-BND-001 |
| PLT-VER-005 | T | VP1-FC-002, VP1-SIG-003, VP1-CC-003 |

### 9.1 Cases running ahead of their phase

Seven cases in §3–§7 trace to no R1 requirement. They are executed in R1 anyway,
deliberately: each verifies a property that is cheap to establish now and
expensive to retrofit once later work depends on it.

| Case | Verifies (later phase) |
|---|---|
| VP1-LOAD-017 | PLT-HOK-030 reason-code discipline, ICD §5.1 POST-3 |
| VP1-LOAD-018 | ICD §5.3 POST-3, floor timer name validation |
| VP1-LOAD-031 | PLT-PRF-007, no-side-effect property beyond the stated criterion |
| VP1-HOOK-012 | PLT-IDM-008 (R2) namespace partitioning |
| VP1-HOOK-024 | PLT-HOK-024 (R2) determinism |
| VP1-FC-010 | PLT-VER-006 (R2) exhaustive transition testing |
| VP1-MED-004 | PLT-MED-005 (R2) no media without floor |

These do not gate R1 exit. A failure is recorded and triaged against its own
phase, not treated as an R1 blocker.

---

## 10. Exit criteria

R1 verification is complete when all of the following hold:

1. Every case in §3–§7 has executed with a recorded result.
2. Every requirement in §9 has at least one passing verification artefact.
3. The three analyses in §8 are written, reviewed and signed.
4. Both profile conformance suites pass against the same built artefact.
5. All TS-BND gates pass on the commit under test.
6. An end-to-end prearranged group call between two clients completes with floor
   arbitration, captured and matched by the trace comparator.
7. Open points affecting R1 (§11) are closed or explicitly deferred with a
   recorded decision.

A case may not be waived. A requirement whose case cannot pass is deferred by
moving the requirement to a later phase in PLT-SRS, with the reason recorded —
not by relaxing its pass criterion.

---

## 11. Open points

| # | Question | Blocks |
|---|---|---|
| VP-OP-01 | Which two SIP core implementations satisfy VP1-SIG-001? Interoperability against a single core does not evidence PLT-SIG-001. **Narrowed 2026-09-24 (§7.1.1).** Kamailio 5.7.4 passes as a proxy. Asterisk 20.6 was run as the second core and passes the terminating path; the remaining question is whether a back-to-back user agent counts as a SIP core implementation at all, since by construction it cannot carry the MC info body on the originating path (SIP-OP-12). A decision, not a test. | VP1-SIG-001 |
| VP-OP-02 | ~~Golden captures or specification-derived flows?~~ **DECIDED 2026-09-21: specification-derived accepted.** See PLT-CONF-AUDIT §5. | closed |
| VP-OP-03 | Confirm the codec set per profile (PLT-SRS OP-06) before VP1-MED-001 can have a pass criterion. | VP1-MED-001 |
| VP-OP-04 | Is VP1-FC-010 exhaustive over the full state/event product, or over reachable pairs only? Exhaustive is preferable and needs the machine's state space bounded first. | VP1-FC-010 |
| VP-OP-05 | Define the production indicator referenced by PLT-GEN-005, PLT-IDM-007 and PLT-SEC-008. Three requirements depend on a term not yet specified. | VP1-LOAD-005, VP1-SIG-007 |
| SVC-OP-01 | ~~Full XSD validation of the OMA-defined remainder needs RFC 4826's `resource-lists.xsd`.~~ **CLOSED 2026-09-22 (PLT-CONF-AUDIT v1.3, 4.27).** The file is in `docs/OMA/`, transcribed from RFC 4826 §3.2 (not from its `schemaLocation` URL, which serves IANA's namespace-registry placeholder page, not the schema). `test_the_group_document_is_schema_valid` runs instead of skipping and passes. History: narrowed in v1.2 (4.27) to this one file; originally narrowed in v0.3 (CA-04) from "the schema was never obtained" to needing OMA-TS-XDM_Group-V1_1_1, which turned out not to be the actual blocker once the OMA-SUP-XSD schema files themselves were in `docs/OMA/`. | closed |
| SVC-OP-02 | Restart semantics for sessions that were `established` when the process died: records survive, but signalling and media state do not. Should they be released with a recovery cause, or resumed? Needs the SIP transport (task 2) to answer. | VP1-OAM-005 (beyond "no record lost") |
| SVC-OP-03 | Group configuration has no home in the profile schema, so it is read from deployment data (`MCX_GROUPS_FILE`). Confirm that is intended; "matches the profile's group configuration" in VP1-DOC-001 is otherwise unsatisfiable literally. | VP1-DOC-001 |
| SVC-OP-04 | No stub identity provider existed in the code. `MCX_IDMS=stub` is introduced as the explicit selector; it is required (no default) and refused under the production indicator. | VP1-SIG-007 |
| SIP-OP-01 | **CLOSED 2026-09-24.** Kamailio 5.7.4 and Asterisk 20.6 are both installable in the environment and both were exercised over real TLS (§7.1.1). The earlier statement that no third-party core was available had stopped being true without anyone rechecking it. | VP1-SIG-001 |
| SIP-OP-02 | TLS encrypts the wire, so a capture cannot show MC feature tags without session keys. The interoperability harness keeps every message at both user agents in plaintext (`transcript.txt`), and Kamailio and Asterisk log what they relayed, which together show the feature tags crossing a third-party core. **Still owed:** a keylog-decrypted packet capture. It is independent evidence of the wire itself, and nothing above replaces it. | VP1-SIG-001 evidence |
| SIP-OP-03 | Only the combined and controlling-only role sets start; `participating` alone is refused because a participating function must relay to a remote controlling function (MCPTT-4), which is not built. Roles are named in the audit record, but they are not yet independently deployable. | VP1-CC-001 (open) |
| SIP-OP-04 | Not built: CANCEL, dial-out to a next hop (so ROUTE_EXTERNAL / ROUTE_PARTNER legs fail 480), and media anchoring. The initiator's SDP is forwarded verbatim to callees and the first callee's answer back; task 3 replaces that. | PLT-SIG-001 completeness |
| SIP-OP-05 | Being registered does not make a user known to the resolver; users are provisioned from the groups file (group members plus an optional `users:` list). Confirm whether third-party registration should provision. | VP1-CC-003 |
| FRMCS-OP-02 | **CLOSED (PLT-CONF-AUDIT v1.7, 4.34).** Table J-1's bands were read from the document: FRS 10.3/10.4 are band D, so driver-to-controller voice now ranks with shunting instead of falling through to the catch-all below ATO. Originally: **From PLT-CONF-AUDIT v1.5 (4.32).** FRS table J-1 spreads this profile's single `voice-operational` application (FRS 10.3, 10.4, 10.10, 10.23, 10.2) across at least three of its seven priority bands, and it resolves to the catch-all decision at level 30 — below `ato`. So driver-to-controller voice ranks below automatic train operation data, inverting table J-1 a second time. Unlike the ATO/shunting swap this cannot be fixed by changing a number: the application vocabulary has to be split to match the bands, which changes what priority decisions exist and what the hooks return. A profile design change with safety-case consequences. | FRMCS profile fitness |
| SHUNT-OP-01 | **From PLT-CONF-AUDIT v1.5 (4.31).** SRS Annex A note (1) lists FRS 10.8 (shunting voice) and 11.12 (shunting data) among the applications "not yet covered", so the SRS gives shunting no communication session, no 5QI and no ARP. `shunting-group` therefore carries no bearer rule of its own and a test asserts it stays that way. Its PRIORITY is sound — FRS table J-1 does cover 10.8 — only the QoS assignment is absent. | FRMCS profile completeness |
| CA-18 | **CLOSED (PLT-CONF-AUDIT v1.6, 4.33).** Annex A table A.1-1 read by hand. Emergency Voice is ARP 2 and ATP Regular Data ARP 4; the profile carried 1 and 2. ARP 1 is reserved for FRMCS Signalling, so the emergency call had been out-ranking the control plane that establishes it. Whole table now pinned. | closed |
| FRMCS-OP-01 | **From PLT-CONF-AUDIT v1.1 (4.26).** The UIC FRMCS SRS contradicts itself: clause 14.6.2.1 (M) lists the standardised 5QIs an FRMCS system shall support as 5, 8, 65, 69 (70 optional), while Annex A assigns **5QI 4** to ATP Regular Data, which is the ETCS bearer. A deployment cannot interoperate using a value its own specification does not require it to support. This platform follows Annex A, since clause 14.6.6.1 (M-V3) makes the per-session table mandatory, and pins the discrepancy with a test so a later SRS revision closes it. A question for UIC, on the safety-relevant bearer. | FRMCS profile fitness |
| DATA-OP-01 | **From PLT-CONF-AUDIT v1.0 (4.25).** TS 24.282 defines MCData as three services, each with its own feature tag and ICSI (`.sds`, `.fd`, `.ipconn`), and TS 24.481 clause 7.2.8 requires a group document's "enabler" to name one of them. The platform can only announce data calls generically, because a call type cannot say which MCData service it is. A profile schema key and an ICD revision. | PLT-SIG completeness |
| BER-OP-02 | **From PLT-CONF-AUDIT v1.0 (4.23).** No profile requests 5QI 69, and the platform has no signalling-bearer concept: bearer decisions cover voice and data user-plane media only. TS 23.280 clause 5 calls for QCI 69 on SIP-1. Whether the platform should request a signalling bearer at all is an open design question, not a defect. | PLT-BER completeness |
| FC-OP-06 | **From PLT-CONF-AUDIT v0.7 (4.19).** The platform never sends a Floor Indicator field, whose bitmap (TS 24.380 table 8.2.3.15-2) carries "Emergency call", "Imminent peril call", "Broadcast group call" and "Queueing supported". The specification does not require the field, so this is conformant — but a platform whose purpose is priority and emergency handling signals none of it in the floor layer. A receiving client cannot tell an emergency floor grant from a routine one. | PLT-FC completeness |
| FC-OP-05 | **From PLT-CONF-AUDIT v0.7 (4.19).** The Message Sequence Number counter is per endpoint. Clause 8.2.3.10 says the field binds "a number of Floor Taken" messages together, which may mean one value shared across the set sent for a single floor event rather than a per-receiver counter. No receiver can observe the difference, so it is recorded rather than guessed at. | VP1-FC-002 |
| FC-OP-04 | **CLOSED in PLT-CONF-AUDIT v0.7 (4.16-4.18).** `SHAPE` is rewritten from the message content tables, and the investigation found a platform defect behind the tool defect: the Message Sequence Number was being sent on four messages that do not define it, and the comparator required it there. Originally recorded as: **From PLT-CONF-AUDIT v0.6 (CA-13).** `SHAPE` in `tools/trace_compare.py` has never been checked against the message content tables (TS 24.380 clauses 8.2.4-8.2.17) and is demonstrably incomplete: table 8.2.9-1 permits a Floor Taken to carry Floor Indicator, Audio SSRC, Functional Alias, List of Granted Users, Location and List of Locations, none of which `SHAPE` listed. The comparator therefore reports conformant traffic as deviating, so a clean run is weaker evidence than it appears. Fields this platform can encode have been added; the rest need the full extraction. | VP1-FC-002 (the only remaining blocker) |
| REL-OP-01 | **CLOSED in PLT-CONF-AUDIT v0.8 (4.20).** TS 24.379 was read across all seven published releases. Warning code 179 is Rel-17+ and was being emitted at older releases; the adapter now drops the number and keeps the phrase. Every other signalling constant the platform emits is stable from Rel-13, so release selection covers both layers. Originally recorded as: **From PLT-CONF-AUDIT v0.5 (CA-12).** Release selection covers the TS 24.380 floor control layer only, because that is where release dependence has been established from the specifications. TS 24.379 has **not** been examined for it at all — feature tags, header constructions, warning codes and MIME types may each have release boundaries, and the warning-code table demonstrably grew between Rel-17 and Rel-20 (18 new codes). A deployment configured `MCX_RELEASE=17` is therefore Rel-17 on the media plane and unexamined on the signalling plane. This must be stated to anyone relying on the parameter for interoperability. | PLT-REL-009, VP1-SIG-001 |
| SIP-OP-08 | **From PLT-CONF-AUDIT v0.3 (4.8).** TS 24.379 spells the automatic Answer-Mode value `"Auto"` in clause 11.1.1.2.1.1 and `"Automatic"` in clause 11.1.1.2.2.1 (pre-established session), in Rel-17 and Rel-20 alike. A conformant receiver must accept both. This platform emits `"Auto"` and does not implement pre-established sessions, so nothing is wrong today; the parser needs to tolerate both before that path is built. | PLT-SIG-003 |
| SIP-OP-07 | **From PLT-CONF-AUDIT v0.3 (CA-06b).** TS 24.379 clause 11.1.1.2.1 has three mutually exclusive commencement branches; the platform's `auto_answer` maps to the forced one, because `Answer-Mode: Auto` alone leaves establishment conditional on the invited client's own settings and VP1-CC-004 requires establishment without callee action. The platform therefore cannot express the **unforced automatic** branch. Adding it is a profile schema key, a validation rule, an ICD revision and three profiles in one change set. | PLT-CC-003 completeness |
| SIP-OP-06 | Defects found in `core/sip.py` while wiring it: `Adapter` responses do not echo the request's Via/From/To (the transport does it); `parse_invite` found media only in a top-level `application/sdp` body, not multipart (fixed); Content-Length counted characters, not octets (fixed). `resolver-unavailable` has a status mapping but no Warning text; `test_sip.py` excludes it deliberately, so it is left as is. | PLT-SIG-003 |
| FC-OP-01 | **CLOSED 2026-09-24 (PLT-CONF-AUDIT CA-21, 4.37).** What stops the Floor Granted retransmission is RTP media from the holder (TS 24.380 6.3.4.4.5 item 3); Floor Ack handling is an implementation option, and stopping T20 on the holder's Ack is kept. T20 now runs only for a queued grant and is bounded by C20 = 3. Originally: `FloorControl` re-armed the grant timer for as long as the holder held the floor, and whether an Ack was the right stop condition was unverified. | closed |
| FC-OP-02 | **CLOSED 2026-09-24 (PLT-CONF-AUDIT CA-21, 4.37).** Every timer's start, stop and expiry was read against TS 24.380 6.3.4.3-6.3.4.5 and 6.3.5.6. Eleven deviations were fixed (T2 from the first media packet; T20 only for queued grants, bounded by C20; T2 expiry always revokes with #2; T3 is the grace and T8 re-sends the Revoke; T1 driven by the media plane; causes #2, #4 and #255 on the wire; no Floor Idle before a queued grant; the pre-emptor goes in front of the queue; a holder asking again is granted again). VP1-FC-010 and VP1-FC-020 pass against the corrected machine. | closed |
| FC-OP-07 | **Open, deliberate deviation.** TS 24.380 6.3.4.4.7 item 2e puts a pre-emptor in front of the queue unconditionally. When the queue is already at the profile's declared depth and the pre-emptor is not in it, the platform does not pre-empt: the request is ordinary and denied queue-full. Inserting would exceed the declared depth (PLT-FC-006), and pre-empting without inserting would revoke the talker for nobody, which the machine used to do whenever queueing was disabled. With queueing disabled, the pre-emptor is now held and granted when the grace ends, as the clause requires. Options: keep this; or let a pre-emptor displace the last queued request. | PLT-FC-006, PLT-FC-008 |
| FC-OP-08 | **Open, low consequence.** The trace comparator treats a Floor Revoke sent to the holder as ending the holder's permission, because T3 expiry is invisible on the wire. A server granting someone else during the grace would therefore not be flagged, and a trace without timestamps cannot tell that from audio cut-in (T3 = 0). Tightening it needs timestamps in the trace, or a check that each hand-over tells the old holder who holds the floor now (6.3.5.5.9, 6.3.5.6.7). | VP1-FC-002 evidence strength |
| FC-OP-09 | **Open, not implemented.** 'U: not permitted but sends media' (6.3.5.7): a talker still sending after the grace is dropped silently, where the specification re-revokes it with cause #3. Audio cut-in (T3 = 0, 6.3.4.5.1) and floor-control-server-initiated revoke from another client (6.3.4.4.16, Rel-19+) are also absent. | PLT-FC completeness |
| FC-OP-10 | **Open, for 3GPP CT1.** Two inconsistencies in TS 24.380: 6.3.4.4.16 (Rel-19, Rel-20) revokes with "#8 Revoked by another MCPTT client", which table 8.2.10.2 lists as #7, with no #8; and 6.3.4.3.2's opening condition ("if no MCPTT client negotiated support of queueing") makes its own item 3, grant from the queue, unreachable when read literally. The platform follows the cause table and the evident intent. | none (recorded) |
| FC-OP-03 | **NARROWED in PLT-CONF-AUDIT v1.8.** The claim that these are "reconstructed from memory, not checked against TS 24.380" has been false since v0.6: the subtypes, field ids, field lengths, reject causes and timer defaults were all read from TS 24.380 across all eight published releases (CA-03, CA-05, CA-11, CA-13), and nine of them were wrong and were corrected. What remains unverified is narrower and unchanged by that work: **no third-party capture has ever been decoded.** The byte-level layout is self-consistent — `core/rtcp.py` and `tools/trace_compare.py` agree — and both now agree with the specification's field tables, but agreement with a table is not the same as interoperating with another implementation's encoder. VP1-FC-002 stays OPEN on that, and on that alone (VP-OP-02, still undecided). |
| FC-OP-04 | Floor control is carried on a separate `m=application <port> udp MCPTT` stream, one UDP port per participant, not multiplexed with voice RTCP. The SDP attributes for that stream, and the ack-required indication in the subtype, are not implemented and unverified. | VP1-FC-001/002 |
| FC-OP-05 | IF-PRI has no participant-specific input: a participant's floor priority is obtained by calling `evaluate` again with that participant as initiator. With the in-tree tables every participant of a session therefore has the same floor priority, so priority ordering is only exercised with an injected priority source. | PLT-FC-005 |
| MED-OP-01 | The `media.codecs` section is new in the profile schema (PLT-MED-001) and its values (AMR-WB 97, PCMU 0) are PLACEHOLDERS: the codec set per profile is still OP-06 / VP-OP-03. Enforcement is real; the pass criterion for VP1-MED-001 is not settled. The ICD is not affected (no hook changed) but every in-tree profile changed. | VP1-MED-001 |
| SVC-OP-05 | **CLOSED, and one part unreachable in R1.** The process could not establish a call in any profile: `fail_closed_platform()` hard-coded `recording_available` and `reserve_qos` to false, and every call type in every in-tree profile sets `recording_required: true`. Added `MCX_RECORDER` and `MCX_BEARER` (`none`\|`stub`), each required with no default and each stub refused under a production indicator. The production refusals cannot be reached in R1: the only known identity provider is the stub, which is refused first. Found by VP1-SIG-001, not by the suite. `test_a_process_built_from_environment_alone_can_establish_a_call` is the test that was missing. | VP1-SIG-001, VP1-CC-005 |
| SIP-OP-09 | **CLOSED 2026-09-24.** RFC 3261 §12 dialog routing was not implemented. The platform's 2xx carried no Record-Route (§12.1.1), and its ACK and BYE went to the peer's address-of-record with no Route (§12.2.1.1). Behind a record-routing proxy, both ACKs of every answered call were dropped. Fixed with route sets, remote targets and strict-route handling; eight mutants each killed by a dedicated test. | VP1-SIG-001 |
| SIP-OP-10 | **Open — a design question.** RFC 3261 §16.7 step 5 tells a proxy that received only a 503 to send a 500 upstream, and Kamailio does, regenerating the response. The platform's Warning header is lost with it. `capacity-exhausted` and `recording-unavailable` are both 503, and PLT-PRI-008's rule that a policy refusal stays distinguishable from a fault rests entirely on that Warning. So in any IMS deployment, the distinction does not survive one hop for exactly those two refusals. A 4xx does survive: the 404 with Warning 145 crossed Kamailio intact. The choice of status, or of a carrier other than Warning, is a PLT-SRS decision. | PLT-PRI-008 |
| SIP-OP-11 | **Split by PLT-CONF-AUDIT CA-20.** 20a is closed: the MCPTT info body, `P-Asserted-Identity` and the floor-control m-line are fixed. 20b is open: `Supported: timer, tdialog, norefersub`, `Require: timer` with `Session-Expires`, and `isfocus` with an MCPTT session identity in Contact (6.3.2.2.3, 6.3.2.1.5.2). Each commits the platform to a behaviour (RFC 4028, 4538, 4488, session-identity routing), so it is feature work, not a header patch. The first version of this row cited 6.3.3.1.2 and `P-Asserted-Service`; that was the wrong clause. | PLT-SIG-001 conformance |
| SIP-OP-12 | **A deployment constraint, not a platform defect, and it applies in both directions.** A back-to-back user agent re-originates every call with SDP alone. Originating (UE → B2BUA → platform): the MCPTT info body, both Accept-Contact fields and P-Asserted-Identity are lost, so the platform refuses the call (404, Warning 145), and the B2BUA strips the Warning on the way back. Terminating (platform → B2BUA → UE): the call completes, but the callee receives no MCPTT info body and so cannot tell which group is calling or who is. MCPTT clients behind a PBX that does not pass the body through lose MC semantics either way. | VP1-SIG-001, deployment guidance |
| SIP-OP-13 | **Open — found by independent review of the SIP-OP-09 fix, older than it.** Two defects in the platform acting as UAC toward callees: (1) after the first 2xx on a leg, its client transaction is finished, so a retransmitted 2xx gets no new ACK (RFC 3261 13.2.2.4), and a second 2xx from a forking proxy gets neither ACK nor BYE; (2) a callee's 3xx–6xx is never ACKed (17.1.1.3). Neither matters with nothing in between. Behind a proxy, both mean retransmissions until the proxy's timers expire. With UDP between the proxy and the callee, a lost ACK makes the callee end an answered call after 64·T1. The per-leg route set and remote target from SIP-OP-09 are what a re-ACK needs. | VP1-SIG-001 robustness |
| PRF-OP-01 | **Open — for the profile owner.** TS 24.379 cannot tell apart two pairs of call types: mcx `prearranged-group` and `coordination-group`, and utility `crew-call` and `switching-order`. Each pair is the same prearranged voice group call on the wire, and the MCPTT info body has no element for "coordination" or "switching". The second of each pair is declared `mc_signature: null`, so no native client can request it. Options: accept that; let the target group's configuration choose the call type (group data, not the request); or distinguish by something TS 24.379 does carry. | PLT-ICD-001 2.6 |
| REL-OP-02 | **Open — a decision.** A profile can declare call types that the configured release cannot carry. The case that exists: the FRMCS profile's group calls are ad hoc, which begins at Rel-18, so at `MCX_RELEASE=17` no client can request a Railway Emergency Call. Startup now reports this in the log and health document (ICD-SIG-006) and starts anyway. The alternative is to refuse to start. | PLT-REL-*, FRMCS deployments |
| ADHOC-OP-01 | **Open — a missing feature, and FRMCS depends on it.** An ad hoc group call INVITE (TS 24.379 17.2.2.1.1 item 10b) carries `<mcptt-request-uri>` only after an emergency alert or when the client knows an ad hoc group identity. Otherwise the participants are named some other way. The platform resolves only prearranged groups, so a conformant REC or shunting group call would be refused as "unable to determine called party" at any release. | FRMCS REC, SRS 10.2.2.1 |
| MED-OP-02 | One payload type per session (no transcoding). Not built: SRTP (R2), voice RTCP SR/RR relay, NAT latching (source must equal the SDP address), IPv6, media for routed/partner legs. Floor control across a gateway or interconnection is deliberately not addressed (ICD-OP-06, ICX-OP-03). | PLT-MED-* completeness |
| PRF-OP-02 | **Open — for the profile owner.** Every in-tree floor policy sets `T8: 100`, written when T8 was (wrongly) the grace period. It now sets the interval at which the Floor Revoke is re-sent, so a revoked talker receives about 30 Revokes during the 3 s default T3; TS 24.380's default T8 is 1 s. No profile sets T3, so a revoked talker's grace went from 100 ms to 3 s. The `T2` values (1-5 s) are maximum talk times, now counted from the first media packet rather than the grant. C20 (default 3) is fixed in the core; the profile schema has no counters. Decide: T8 per profile (1000 suggested), T3 per profile, whether 1-5 s talk limits are intended, and whether C20 should be configurable. | PLT-FC-010, PLT-PRF-031 |

---

## 12. Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-09-19 | Initial draft |
| 0.3 | 2026-09-24 | §7.1.1 corrected. The first runs' MC body was the platform's own invented format, copied into the user agent; after PLT-CONF-AUDIT CA-20a the agent writes annex F.1 bodies and Kamailio passes an added body check. SIP-OP-11 split into 20a (closed) and 20b (open) with corrected clauses; SIP-OP-12 widened to both directions. PRF-OP-01, REL-OP-02 and ADHOC-OP-01 opened. |
| 0.2 | 2026-09-24 | VP1-SIG-001 executed against Kamailio 5.7.4 (pass) and Asterisk 20.6 (terminating pass; originating path not possible through a B2BUA), recorded in §7.1.1. SIP-OP-01, SIP-OP-09 and SVC-OP-05 closed; SIP-OP-10 to SIP-OP-13 opened. VP-OP-01 narrowed to one decision. |
| 0.3 | 2026-09-24 | FC-OP-01 and FC-OP-02 closed by PLT-CONF-AUDIT CA-21: the floor timers' behaviour was read against TS 24.380 and eleven deviations fixed. FC-OP-07 (pre-emption into a full queue, deliberate), FC-OP-08 (comparator strength), FC-OP-09 (unimplemented floor procedures), FC-OP-10 (two TS 24.380 inconsistencies) and PRF-OP-02 (profile timer values written for the old behaviour) opened. FC-OP-03 and VP1-FC-002 are unaffected by this change and remain as v0.2 left them. |
