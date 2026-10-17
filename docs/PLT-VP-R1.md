# Release 1 — Verification Plan

**Document:** PLT-VP-R1
**Version:** 0.43 (draft)
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

R1 requirement methods, as specified: 66 T, 23 I, 3 A, 0 D (counted from §9; until 0.28 this read 54 T, 26 I, 3 A, which matched neither the old table nor PLT-SRS).

### 1.3 Test case identification

`VP1-<SUITE>-<nnn>`. A test case may verify several requirements; a requirement
may need several cases. Both are recorded in §9.

### 1.4 Independence

Per PLT-SRS §18, conformance suites run against the same core for every
profile: the shared part whose hash is identical in every release image
(VP1-BND-006). The FRMCS profile is a stub in R1 (§14 of PLT-SRS is `[PROVISIONAL]`),
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
| VP1-BND-006 | One core, one profile per image | Build every profile's image with `tools/package.py` and inspect | Each image carries exactly one profile package; the core hash is identical in every image; no shared code names a profile package; no per-profile build file |
| VP1-BND-007 | No default profile in code or config | Inspect configuration defaults and code paths | No path yields a profile without explicit configuration |
| VP1-BND-008 | No hot reload mechanism | Inspect for reload handlers, watchers and signal handlers touching the profile | None present |
| VP1-BND-009 | Core owns the protocol state machines | Inspect floor control, SIP session and document modules | No transition, guard or state parameterised by profile input; timers and the TS 24.380 configuration parameters and server options (queueing, override, queue depth, initial grant) excepted: the profile sets their values, and may thereby select between the core's fixed transitions, but never adds, removes or alters one. Every other profile read by a state-machine module (floor control, the SIP session and the session state machine, the documents) is listed in the gate with the reason it is not one of these, and a new read fails the gate until it is reviewed and listed (amended by RES-OP-10) |
| VP1-BND-010 | Reference-point naming | Inspect module boundaries against PLT-SRS §3.1 | Each boundary corresponding to a reference point is named for it |
| VP1-BND-011 | Priority table is declarative | Inspect the MCX profile | Priority expressed as configuration data; no imperative priority logic in the hook |
| VP1-BND-012 | No QoS mapping in core | Inspect core for QoS identifier and ARP literals | No priority-to-QoS mapping anywhere in the core. The TS 23.501 definition tables (the standardised 5QIs, the media each mission-critical 5QI was defined for, the ARP range) are a recorded exception, allowed in `core/qos.py` only, which mentions no priority; no QoS literal elsewhere in the core but the bearer hook interface types (amended by RES-OP-10) |
| VP1-BND-013 | No priority logic in core | Inspect core for priority comparison or ordering | All priority decisions traced to `IF-PRI` |
| VP1-BND-014 | Resolver receives full context | Inspect the resolve call site | Initiator, call type, application and location all passed |
| VP1-BND-015 | Floor state machine independently testable | Inspect its dependencies | No dependency on SIP, media or network; instantiable in ENV-UNIT |
| VP1-BND-016 | Time discipline | Inspect configuration, logs and audit records | All timestamps UTC; all durations in milliseconds; no local-time formatting |
| VP1-BND-020 | Both suites run per change | Inspect CI configuration | Both profile suites execute on every change; neither is skippable by branch or label |
| VP1-BND-021 | Per-profile suite exists | Inspect the suites | One suite per profile, all targeting the same core (same core hash, VP1-BND-006) |
| VP1-BND-022 | Release knowledge in one module | Scan every module for a comparison of a release to a literal | None outside `core/release.py` (and its own tests) |
| VP1-BND-023 | Release is a stated deployment parameter | Inspect the configuration code and the suites | `MCX_RELEASE` is read with no fallback value; a per-release conformance suite exists |

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
| VP1-FC-013 | Queue bounded and ordered | Requests exceeding `max_queue_depth` | Queue never exceeds the declared depth, but for at most one pre-emptor held in front where the floor policy declares `preemption_at_full_queue: insert` (TS 24.380 6.3.4.4.7 item 2e; amended 2026-10-16); grants follow declared order; excess requests denied not dropped |
| VP1-FC-014 | Deny when queueing disabled | Request while floor held, queueing disabled | An ordinary request: Deny returned, no queue entry created. A pre-emption where override is allowed: held in the one front place TS 24.380 6.3.4.4.7 item 2e requires, the talker revoked, no Deny (FC-OP-07); the pre-emptor asking again keeps its place and gets nothing (6.3.5.4.4 item 4; at another priority, by the interpretation recorded under FC-OP-07), any other request while it is held is denied (items 6 and 7) (amended by RES-OP-10) |
| VP1-FC-020 | Timers taken from profile | Load two profiles differing only in floor timer values | Observed timing follows each profile; transition sequence identical in both |
| VP1-FC-021 | Transitions recorded | Complete a call with contention | Every transition recorded with trigger, timestamp and resulting state; sequence reconstructible from the audit trail alone |

#### 6.1 VP1-FC-002 — PASSED 2026-09-24

VP-OP-02 (decided 2026-09-21, confirmed 2026-09-24) accepts
specification-derived flows in place of third-party captures. On that basis
the evidence is:

- every field id, field length and message subtype read from TS 24.380
  across all eight releases, nine of them corrected (PLT-CONF-AUDIT CA-03,
  CA-11)
- the comparator's per-message shapes rebuilt from the TS 24.380 message
  content tables, which also found a sender defect (CA-13)
- `tests/test_media_e2e.py::test_full_call_trace_has_no_deviation`: a group
  call with contention, floor control over real UDP sockets, and every
  captured datagram decoded by `tools/trace_compare.py`, with no deviation.
  The comparator imports nothing from `core/rtcp.py`, and
  `tests/test_media.py` pins that.

What this does not show, and was accepted by that decision: that another
implementation's encoder produces bytes this decoder accepts.

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
| Asterisk 20.6 | Back-to-back user agent (PBX); registers each user onward to the platform | PASS — UEs register with Asterisk, and Asterisk's onward registrations to the platform succeed | Terminating (platform → Asterisk → UE): PASS, including both ACKs and teardown. Originating (UE → Asterisk → platform): **not possible** — see SIP-OP-12 | **Passes** (a B2BUA counts: VP-OP-01, decided 2026-09-24) |

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

**VP1-SIG-001: PASSED, 2026-09-24.** VP-OP-01 was decided the same day: a
back-to-back user agent counts as a distinct SIP core implementation. So the
two cores are Kamailio 5.7.4 (a proxy) and Asterisk 20.6 (a B2BUA). Both pass
registration and session setup with the same platform configuration, and
Asterisk passes on the terminating path.

Two things go with the verdict and must not be dropped from it:

- **Through a B2BUA, originating calls do not work, and terminating calls
  lose their MC semantics** (SIP-OP-12). This is a deployment constraint
  that PBX-fronted deployments have to be told about. It is not a platform
  defect.
- **The keylog-decrypted packet capture is still owed** (SIP-OP-02). The
  pass rests on endpoint transcripts and each core's own logs. That is
  strong evidence, but none of it is a capture of the wire.

**Added 2026-09-24 (SIP-OP-14): a cancelled call, through both cores.** The
originator CANCELs a private call while the callee rings. Both runs pass five
checks:
- the CANCEL is answered 200;
- the INVITE ends with 487;
- the ringing callee receives a CANCEL;
- the callee's 487 is ACKed;
- nothing further reaches the callee.

Through Kamailio the 200 is the proxy's own hop-by-hop answer, so the
platform's handling of the inbound CANCEL is shown by the 487. Through
Asterisk the originator is attached to the platform directly, so the 200 is
the platform's own. The CANCEL toward the callee is the platform's in both
runs: Kamailio relays it statefully, and Asterisk mirrors it on its own leg.

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
| VP1-DOC-001 | Group documents served | Group documents retrievable over HTTP per TS 24.481; schema-valid; content matches the network profile's group configuration (SVC-OP-03) |

### 7.5 TS-OAM — observability (ENV-INT)

| Case | Title | Pass criterion |
|---|---|---|
| VP1-OAM-001 | Profile identity in logs and audit | Name, version and hash logged at start and present on every audit record, joined by the release and the network profile's name, version and hash (PLT-ICD-001 ICD-NET-002); values match the health endpoint |
| VP1-OAM-002 | Health endpoint | Name, version and hash exposed; readiness false until the profile is validated and loaded |
| VP1-OAM-003 | Session lifecycle audited | Admission, refusal, establishment and release each produce an audit record; refusals carry their reason code |
| VP1-OAM-004 | Structured logs | Logs machine-parsable; one stable correlation identifier per session, present on every record of that session across all components |
| VP1-OAM-005 | Restart without committed-record loss | Restart an instance mid-run | No committed session record lost; platform returns to service |


### 7.6 TS-REL — release selection (ENV-UNIT, ENV-INT)

The 3GPP release is a deployment parameter, independent of the profile
(PLT-REL-001 to 009). These cases were listed inside the TS-DOC table until
0.28.

| Case | Title | Pass criterion |
|---|---|---|
| VP1-REL-001 | Release is selected, never defaulted | Process refuses to start with `MCX_RELEASE` unset, unsupported or unparseable; exit code 2 |
| VP1-REL-002 | Release and profile are independent | Conformance suite passes for every profile at every supported release; CI runs the matrix, no combination skippable |
| VP1-REL-003 | A release emits only what it defines | For each of the eight tabulated releases, every subtype, field id and revoke cause the release defines encodes, and everything it does not is refused |
| VP1-REL-004 | Subtype 14 is read per release | Rel-17 reports Floor Queued Cancel, Rel-18+ reports Queued Floor Requests, from identical bytes |
| VP1-REL-005 | Wrong release is not malformed | A Rel-19 message decoded at Rel-17 raises `ReleaseRefused`, counts `floor_wrong_release`, and does not count `floor_malformed` |
| VP1-REL-006 | Release is in the audit record | Every audit record's identity carries the profile triple and the release |
| VP1-REL-007 | Signalling warning codes are release-gated | A refusal whose TS 24.379 warning code post-dates the configured release carries the explanatory phrase without the number, keeps its 4xx/5xx status, and does not raise |

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

All 92 R1 requirements. Method as specified in PLT-SRS. (Until 0.28 this table held 83: the nine PLT-REL requirements, R1 since PLT-SRS 0.2, were missing.)

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
| PLT-REL-001 | T | VP1-REL-001 |
| PLT-REL-002 | T | VP1-REL-001, VP1-BND-023 |
| PLT-REL-003 | T | VP1-REL-002 |
| PLT-REL-004 | T | VP1-REL-003, VP1-REL-004 |
| PLT-REL-005 | T | VP1-REL-006 |
| PLT-REL-006 | T | VP1-REL-005 |
| PLT-REL-007 | I | VP1-REL-002 |
| PLT-REL-008 | I | VP1-BND-022 |
| PLT-REL-009 | T | VP1-REL-007 |
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
4. Every profile conformance suite passes against the same core, and the
   core hash recorded for each released image matches (VP1-BND-006).
5. All TS-BND gates pass on the commit under test.
6. An end-to-end prearranged group call between two clients completes with floor
   arbitration, captured and matched by the trace comparator.
7. Open points affecting R1 (§11) are closed or explicitly deferred with a
   recorded decision.

**How criteria 1 to 3 are shown (since 0.28).** `tools/vp_results.py` writes
`docs/PLT-VP-R1-RESULTS.md` for one commit: every case of §3–§8 and every
requirement of §9 with its result and evidence. A test is evidence for a case
when it is named `test_vp1_<suite>_<nnn>` or marked `@pytest.mark.vp(...)`
(`tests/conftest.py` refuses a link to a case this plan does not define); the
boundary gates and `tools/interop/run.py --results` add theirs. Passing
evidence is not a result: whether it shows the pass criterion is judged in
`docs/PLT-VP-R1-REVIEWS.yaml`, and a review goes STALE when its evidence
changes. The register also checks §9 against PLT-SRS. First run, 2026-09-28,
after an independent review of every case: 16 of the 101 gating cases PASS,
78 PARTIAL, 4 FAIL, and the 3 analyses are not signed; 11 of 92 requirements
PASS. What the review found in the code, as opposed to in the tests, is RES-OP-01 to 10.

A case may not be waived. A requirement whose case cannot pass is deferred by
moving the requirement to a later phase in PLT-SRS, with the reason recorded —
not by relaxing its pass criterion.

---

## 11. Open points

| # | Question | Blocks |
|---|---|---|
| VP-OP-01 | ~~Which two SIP core implementations satisfy VP1-SIG-001?~~ **DECIDED 2026-09-24: a back-to-back user agent counts.** The two are Kamailio 5.7.4 (proxy) and Asterisk 20.6 (B2BUA), and VP1-SIG-001 passes (§7.1.1). The consequence of counting a B2BUA is SIP-OP-12, which travels with the verdict. | closed |
| VP-OP-02 | ~~Golden captures or specification-derived flows?~~ **DECIDED 2026-09-21: specification-derived accepted.** See PLT-CONF-AUDIT §5. | closed |
| VP-OP-03 | ~~Confirm the codec set per profile (PLT-SRS OP-06) before VP1-MED-001 can have a pass criterion.~~ **DECIDED 2026-09-25: the same set for every profile, in this order of preference: EVS, AMR-WB, AMR (AMR-NB), G.722, G.711 A-law, G.711 µ-law; no transcoding (R4, MED-OP-03).** Pass criterion for VP1-MED-001: a call uses the first of the profile's codecs the caller offers, every party uses that codec with the same payload layout, and the relay forwards only it (MED-OP-01). | closed |
| VP-OP-04 | Is VP1-FC-010 exhaustive over the full state/event product, or over reachable pairs only? Exhaustive is preferable and needs the machine's state space bounded first. | VP1-FC-010 |
| VP-OP-05 | **Open, R1 (owner decision 2026-09-26: recorded, kept in R1, not yet built).** Define the production indicator referenced by PLT-GEN-005, PLT-IDM-007 and PLT-SEC-008. **Today** (`core/loader.py` `is_production`, a proposal): production is opt-in, true only when `MCX_ENV` is `production`/`prod` or `MCX_PRODUCTION` is `1`/`true`/`yes`. It is read once at startup. The stub IdMS, recorder and bearer are refused under it. **Weaknesses found.** (1) A forgotten variable is not production, so the stubs run in production unannounced. (2) Making the variable required would stop forgetting, but not a change: the administrator who configures the stubs also sets the flag that allows them. A switch to a non-production value takes effect at the next restart, with nothing refusing it. (3) The value is recorded nowhere: not in the audit identity, not in the health document. Calls made while it was switched cannot be told apart afterwards. **Options.** (A) `MCX_ENV` required (`production`, `staging`, `test`, `dev`; no default), and the environment added to the audit identity and the health document, so a switch shows on every call and at startup. (B) As A, but the environment is declared in the network profile (hashed, change-controlled with the radio plan), and a non-production environment is refused on a network whose PLMNs are not test PLMNs (MCC 001 and the like; to be read from ITU-T E.212 before use). The variable then goes away or must agree with the file. (C) Only a network profile signed with a key the operator does not hold stops an administrator who controls every file; a larger step, not proposed for R1. Blocks the two R1 cases on the right, and SVC-OP-04 with them. | VP1-LOAD-005, VP1-SIG-007 (R1) |
| SVC-OP-01 | ~~Full XSD validation of the OMA-defined remainder needs RFC 4826's `resource-lists.xsd`.~~ **CLOSED 2026-09-22 (PLT-CONF-AUDIT v1.3, 4.27).** The file is in `docs/OMA/`, transcribed from RFC 4826 §3.2 (not from its `schemaLocation` URL, which serves IANA's namespace-registry placeholder page, not the schema). `test_the_group_document_is_schema_valid` runs instead of skipping and passes. History: narrowed in v1.2 (4.27) to this one file; originally narrowed in v0.3 (CA-04) from "the schema was never obtained" to needing OMA-TS-XDM_Group-V1_1_1, which turned out not to be the actual blocker once the OMA-SUP-XSD schema files themselves were in `docs/OMA/`. | closed |
| SVC-OP-02 | Restart semantics for sessions that were `established` when the process died: records survive, but signalling and media state do not. Should they be released with a recovery cause, or resumed? Needs the SIP transport (task 2) to answer. | VP1-OAM-005 (beyond "no record lost") |
| SVC-OP-03 | **CLOSED 2026-09-26 (decided: groups stay in the network profile).** The groups and the known users are keys of the network profile (`groups`, `users`; PLT-ICD-001 ICD-NET-005), required like its other keys (`[]` for none) and checked with them, every defect at once. `MCX_GROUPS_FILE` is refused if set. The groups count toward the network hash, so every audit record names the group data in force. VP1-DOC-001 reads "the network profile's group configuration". Tests in `tests/test_network.py`; mutation: every non-equivalent mutant killed (three equivalents: a defect is already recorded, and any defect refuses the file). | closed |
| SVC-OP-04 | No stub identity provider existed in the code. `MCX_IDMS=stub` is introduced as the explicit selector; it is required (no default) and refused under the production indicator. | VP1-SIG-007 |
| SIP-OP-01 | **CLOSED 2026-09-24.** Kamailio 5.7.4 and Asterisk 20.6 are both installable in the environment and both were exercised over real TLS (§7.1.1). The earlier statement that no third-party core was available had stopped being true without anyone rechecking it. | VP1-SIG-001 |
| SIP-OP-02 | TLS encrypts the wire, so a capture cannot show MC feature tags without session keys. The interoperability harness keeps every message at both user agents in plaintext (`transcript.txt`), and Kamailio and Asterisk log what they relayed, which together show the feature tags crossing a third-party core. **Still owed:** a keylog-decrypted packet capture. It is independent evidence of the wire itself, and nothing above replaces it. | VP1-SIG-001 evidence |
| SIP-OP-03 | Only the combined and controlling-only role sets start; `participating` alone is refused because a participating function must relay to a remote controlling function (MCPTT-4), which is not built. Roles are named in the audit record, but they are not yet independently deployable. | VP1-CC-001 (open) |
| SIP-OP-04 | Not built: dial-out to a next hop, so ROUTE_EXTERNAL and ROUTE_PARTNER legs fail 480. (Corrected 2026-09-25: CANCEL was built with SIP-OP-14. Media anchoring was built with the media plane, so the platform no longer forwards the initiator's SDP verbatim; it anchors media at its own ports.) | PLT-SIG-001 completeness |
| SIP-OP-05 | Being registered does not make a user known to the resolver; users are provisioned from the network profile (group members plus its `users` list, SVC-OP-03). Confirm whether third-party registration should provision. | VP1-CC-003 |
| FRMCS-OP-02 | **CLOSED (PLT-CONF-AUDIT v1.7, 4.34).** Table J-1's bands were read from the document: FRS 10.3/10.4 are band D, so driver-to-controller voice now ranks with shunting instead of falling through to the catch-all below ATO. Originally: **From PLT-CONF-AUDIT v1.5 (4.32).** FRS table J-1 spreads this profile's single `voice-operational` application (FRS 10.3, 10.4, 10.10, 10.23, 10.2) across at least three of its seven priority bands, and it resolves to the catch-all decision at level 30 — below `ato`. So driver-to-controller voice ranks below automatic train operation data, inverting table J-1 a second time. Unlike the ATO/shunting swap this cannot be fixed by changing a number: the application vocabulary has to be split to match the bands, which changes what priority decisions exist and what the hooks return. A profile design change with safety-case consequences. | FRMCS profile fitness |
| SHUNT-OP-01 | **From PLT-CONF-AUDIT v1.5 (4.31).** SRS Annex A note (1) lists FRS 10.8 (shunting voice) and 11.12 (shunting data) among the applications "not yet covered", so the SRS gives shunting no communication session, no 5QI and no ARP. `shunting-group` therefore carries no bearer rule of its own and a test asserts it stays that way. Its PRIORITY is sound — FRS table J-1 does cover 10.8 — only the QoS assignment is absent. | FRMCS profile completeness |
| CA-18 | **CLOSED (PLT-CONF-AUDIT v1.6, 4.33).** Annex A table A.1-1 read by hand. Emergency Voice is ARP 2 and ATP Regular Data ARP 4; the profile carried 1 and 2. ARP 1 is reserved for FRMCS Signalling, so the emergency call had been out-ranking the control plane that establishes it. Whole table now pinned. | closed |
| FRMCS-OP-01 | **From PLT-CONF-AUDIT v1.1 (4.26).** The UIC FRMCS SRS contradicts itself: clause 14.6.2.1 (M) lists the standardised 5QIs an FRMCS system shall support as 5, 8, 65, 69 (70 optional), while Annex A assigns **5QI 4** to ATP Regular Data, which is the ETCS bearer. A deployment cannot interoperate using a value its own specification does not require it to support. This platform follows Annex A, since clause 14.6.6.1 (M-V3) makes the per-session table mandatory, and pins the discrepancy with a test so a later SRS revision closes it. A question for UIC, on the safety-relevant bearer. | FRMCS profile fitness |
| DATA-OP-01 | **From PLT-CONF-AUDIT v1.0 (4.25).** TS 24.282 defines MCData as three services, each with its own feature tag and ICSI (`.sds`, `.fd`, `.ipconn`), and TS 24.481 clause 7.2.8 requires a group document's "enabler" to name one of them. The platform can only announce data calls generically, because a call type cannot say which MCData service it is. A profile schema key and an ICD revision. | PLT-SIG completeness |
| BER-OP-02 | **From PLT-CONF-AUDIT v1.0 (4.23).** No profile requests 5QI 69, and the platform has no signalling-bearer concept: bearer decisions cover voice and data user-plane media only. TS 23.280 clause 5 calls for QCI 69 on SIP-1. Whether the platform should request a signalling bearer at all is an open design question, not a defect. | PLT-BER completeness |
| FC-OP-06 | **From PLT-CONF-AUDIT v0.7 (4.19).** The platform never sends a Floor Indicator field, whose bitmap (TS 24.380 table 8.2.3.15-2) carries "Emergency call", "Imminent peril call", "Broadcast group call" and "Queueing supported". The specification does not require the field, so this is conformant — but a platform whose purpose is priority and emergency handling signals none of it in the floor layer. A receiving client cannot tell an emergency floor grant from a routine one. | PLT-FC completeness |
| FC-OP-05 | **From PLT-CONF-AUDIT v0.7 (4.19).** The Message Sequence Number counter is per endpoint. Clause 8.2.3.10 says the field binds "a number of Floor Taken" messages together, which may mean one value shared across the set sent for a single floor event rather than a per-receiver counter. No receiver can observe the difference, so it is recorded rather than guessed at. It does not block VP1-FC-002: under either reading every message is well-formed and every receiver sees the same thing. | none (recorded ambiguity) |
| FC-OP-04 | **CLOSED in PLT-CONF-AUDIT v0.7 (4.16-4.18).** `SHAPE` is rewritten from the message content tables, and the investigation found a platform defect behind the tool defect: the Message Sequence Number was being sent on four messages that do not define it, and the comparator required it there. Originally recorded as: **From PLT-CONF-AUDIT v0.6 (CA-13).** `SHAPE` in `tools/trace_compare.py` has never been checked against the message content tables (TS 24.380 clauses 8.2.4-8.2.17) and is demonstrably incomplete: table 8.2.9-1 permits a Floor Taken to carry Floor Indicator, Audio SSRC, Functional Alias, List of Granted Users, Location and List of Locations, none of which `SHAPE` listed. The comparator therefore reports conformant traffic as deviating, so a clean run is weaker evidence than it appears. Fields this platform can encode have been added; the rest need the full extraction. | VP1-FC-002 (the only remaining blocker) |
| REL-OP-01 | **CLOSED in PLT-CONF-AUDIT v0.8 (4.20).** TS 24.379 was read across all seven published releases. Warning code 179 is Rel-17+ and was being emitted at older releases; the adapter now drops the number and keeps the phrase. Every other signalling constant the platform emits is stable from Rel-13, so release selection covers both layers. Originally recorded as: **From PLT-CONF-AUDIT v0.5 (CA-12).** Release selection covers the TS 24.380 floor control layer only, because that is where release dependence has been established from the specifications. TS 24.379 has **not** been examined for it at all — feature tags, header constructions, warning codes and MIME types may each have release boundaries, and the warning-code table demonstrably grew between Rel-17 and Rel-20 (18 new codes). A deployment configured `MCX_RELEASE=17` is therefore Rel-17 on the media plane and unexamined on the signalling plane. This must be stated to anyone relying on the parameter for interoperability. | PLT-REL-009, VP1-SIG-001 |
| SIP-OP-08 | **From PLT-CONF-AUDIT v0.3 (4.8).** TS 24.379 spells the automatic Answer-Mode value `"Auto"` in clause 11.1.1.2.1.1 and `"Automatic"` in clause 11.1.1.2.2.1 (pre-established session), in Rel-17 and Rel-20 alike. A conformant receiver must accept both. This platform emits `"Auto"` and does not implement pre-established sessions, so nothing is wrong today; the parser needs to tolerate both before that path is built. | PLT-SIG-003 |
| SIP-OP-07 | **From PLT-CONF-AUDIT v0.3 (CA-06b).** TS 24.379 clause 11.1.1.2.1 has three mutually exclusive commencement branches; the platform's `auto_answer` maps to the forced one, because `Answer-Mode: Auto` alone leaves establishment conditional on the invited client's own settings and VP1-CC-004 requires establishment without callee action. The platform therefore cannot express the **unforced automatic** branch. Adding it is a profile schema key, a validation rule, an ICD revision and three profiles in one change set. | PLT-CC-003 completeness |
| SIP-OP-06 | Defects found in `core/sip.py` while wiring it: `Adapter` responses do not echo the request's Via/From/To (the transport does it); `parse_invite` found media only in a top-level `application/sdp` body, not multipart (fixed); Content-Length counted characters, not octets (fixed). `resolver-unavailable` has a status mapping but no Warning text; `test_sip.py` excludes it deliberately, so it is left as is. | PLT-SIG-003 |
| FC-OP-01 | **CLOSED 2026-09-24 (PLT-CONF-AUDIT CA-21, 4.37).** What stops the Floor Granted retransmission is RTP media from the holder (TS 24.380 6.3.4.4.5 item 3); Floor Ack handling is an implementation option, and stopping T20 on the holder's Ack is kept. T20 now runs only for a queued grant and is bounded by C20 = 3. Originally: `FloorControl` re-armed the grant timer for as long as the holder held the floor, and whether an Ack was the right stop condition was unverified. | closed |
| FC-OP-02 | **CLOSED 2026-09-24 (PLT-CONF-AUDIT CA-21, 4.37).** Every timer's start, stop and expiry was read against TS 24.380 6.3.4.3-6.3.4.5 and 6.3.5.6. Eleven deviations were fixed (T2 from the first media packet; T20 only for queued grants, bounded by C20; T2 expiry always revokes with #2; T3 is the grace and T8 re-sends the Revoke; T1 driven by the media plane; causes #2, #4 and #255 on the wire; no Floor Idle before a queued grant; the pre-emptor goes in front of the queue; a holder asking again is granted again). VP1-FC-010 and VP1-FC-020 pass against the corrected machine. | closed |
| FC-OP-07 | **CLOSED 2026-09-24 as an accepted deviation (decided: keep the refusal).** TS 24.380 6.3.4.4.7 item 2e puts a pre-emptor in front of the queue unconditionally. When the queue is already at the profile's declared depth and the pre-emptor is not in it, the platform does not pre-empt: the request is ordinary and denied queue-full. Inserting would exceed the declared depth (PLT-FC-006), and pre-empting without inserting would revoke the talker for nobody, which the machine used to do whenever queueing was disabled. With queueing disabled, the pre-emptor is now held and granted when the grace ends, as the clause requires. **Interpretation added 2026-10-01 (RES-OP-10):** the pre-emptor held in front that asks again keeps its place at whatever priority it asks with; 6.3.5.4.4 item 4 covers a repeat at the same priority, and items 7 and 8 read literally would deny it or move it out of the place item 2e gave it after its talker was already revoked. **A profile setting since 2026-10-16 (owner ruling):** `floor.preemption_at_full_queue`, required, `insert` (6.3.4.4.7 item 2e, one entry beyond the declared depth) or `deny` (this deviation). The in-tree profiles declare `deny`; it is reported at startup wherever queueing and override are both enabled (PLT-ICD-001 v0.22 §5.3 POST-5). | closed |
| FC-OP-08 | **Open, low consequence.** The trace comparator treats a Floor Revoke sent to the holder as ending the holder's permission, because T3 expiry is invisible on the wire. A server granting someone else during the grace would therefore not be flagged, and a trace without timestamps cannot tell that from audio cut-in (T3 = 0). Tightening it needs timestamps in the trace, or a check that each hand-over tells the old holder who holds the floor now (6.3.5.5.9, 6.3.5.6.7). | VP1-FC-002 evidence strength |
| FC-OP-09 | **Open, not implemented.** 'U: not permitted but sends media' (6.3.5.7): a talker still sending after the grace is dropped silently, where the specification re-revokes it with cause #3. Audio cut-in (T3 = 0, 6.3.4.5.1) and floor-control-server-initiated revoke from another client (6.3.4.4.16, Rel-19+) are also absent. | PLT-FC completeness |
| FC-OP-10 | **Open, for 3GPP CT1.** Two inconsistencies in TS 24.380: 6.3.4.4.16 (Rel-19, Rel-20) revokes with "#8 Revoked by another MCPTT client", which table 8.2.10.2 lists as #7, with no #8; and 6.3.4.3.2's opening condition ("if no MCPTT client negotiated support of queueing") makes its own item 3, grant from the queue, unreachable when read literally. The platform follows the cause table and the evident intent. | none (recorded) |
| FC-OP-03 | **CLOSED 2026-09-24.** The constants were read from TS 24.380 across all eight releases and corrected (CA-03, CA-05, CA-11, CA-13). The remaining gap, that no third-party capture has been decoded, is accepted by VP-OP-02: specification-derived flows in place of golden captures, decided 2026-09-21 and confirmed 2026-09-24. VP1-FC-002 passes (§6.1). The floor-timer behaviour this row used to defer to VP1-FC-010/020 (FC-OP-01/02) was fixed separately and is CLOSED (PLT-CONF-AUDIT CA-21, 4.37). | closed |
| FC-OP-11 | Floor control is carried on a separate `m=application <port> udp MCPTT` stream, one UDP port per participant, not multiplexed with voice RTCP. The SDP attributes for that stream, and the ack-required indication in the subtype, are not implemented and unverified. | VP1-FC-001/002 |
| FC-OP-12 | IF-PRI has no participant-specific input: a participant's floor priority is obtained by calling `evaluate` again with that participant as initiator. With the in-tree tables every participant of a session therefore has the same floor priority, so priority ordering is only exercised with an injected priority source. | PLT-FC-005 |
| MED-OP-01 | **CLOSED 2026-09-26 (VP-OP-03 decided).** Profiles declare codecs by rtpmap name in order of preference (`EVS/16000`, `AMR-WB/16000`, `AMR/8000`, `G722/8000`, `PCMA/8000`, `PCMU/8000`); a payload type number is no longer part of a profile. Validation refuses a malformed name, a duplicate (names compare without case, a missing channel count is 1), and formats that carry no voice (telephone-event, CN, red, ulpfec). **Choice.** `core/codec.py` picks the call's codec from the caller's offer by the profile's order, not the offer's; for AMR and AMR-WB the bandwidth-efficient layout wins when both are offered (TS 26.179 4.1.3). No codec in common: 488. **Every party** must use that codec with the same payload layout: AMR/AMR-WB octet-align, crc, robust-sorting, interleaving and channels (RFC 4867 8.3.1); EVS hf-only, evs-mode-switch and cmr (TS 26.445 A.3, MED-OP-04). Absent parameters take their defaults. A callee answering another codec or layout is hung up; an in-dialog offer that changes them gets 488; an ACK answer that does is ignored. **Numbers.** Each party may number the codec differently. A number in an SDP is what its author expects to receive, and each side sends with the other's (RFC 3264 5.1, 6.1). So each party has two: the number in the relay's SDP to it (it sends with that one, and the relay accepts no other from it) and the number in its own SDP (the relay rewrites the payload type to that one, keeping the marker bit). When the relay answers, it uses the offerer's number; when it offers, it keeps the number it gave that party before (RFC 3264 8.3.2). After a party renumbers by re-offer, its old number is accepted until its first packet under the new one. Only payload types 0..127 in ASCII digits are read (RFC 3550 5.1); others name nothing. The relay's receive thread survives a packet it cannot handle. `parse_sdp` and the codec reader take the same audio line, and the address only from it. **Verification.** `tests/test_codec.py`, and codec cases in test_media, test_media_e2e (real UDP: G.722, AMR-WB renumbered 97/101 in both directions) and test_session_timer (AMR-WB in dialog). Mutation testing over three rounds: every mutant killed except equivalents, which were removed as dead code or noted. An independent review found six issues and a re-review confirmed the fixes: the direction of payload type numbers was reversed (a callee answering another number would have been muted); a payload type above 127 raised inside the relay and silenced the sender for the rest of the call; non-ASCII digits raised outside the SIP error path; the mode-set rationale was wrong (MED-OP-05); a malformed first audio line could lend the address while another gave the codec; and several paths had no test. VP1-SIG-001 re-run: AMR-WB 97/101 through Kamailio, G.722 through Asterisk, both PASS. | closed |
| MED-OP-03 | **R4.** Transcoding (decided 2026-09-25): until then a call only works when every party shares the codec the caller's offer and the profile's order choose; a party that does not is refused (488) or hung up. TS 26.179 4.2.1 has the server's codec information include the codecs of 4.1.1 (AMR-WB, and EVS): a call whose codec is G.722 or G.711, because the caller offered neither AMR-WB nor EVS, offers MCPTT clients only a codec they are not required to have, and such a call is for interworking parties. Transcoding closes this. | R4 |
| MED-OP-04 | **CLOSED 2026-09-26.** The EVS parameters were read from TS 26.445 annex A, now in docs/3GPP (V12.17.0, V16.4.0 and V19.1.0 agree). `hf-only` and `evs-mode-switch` are confirmed: default 0 (A.3.1), and "when [it] is offered ... and the payload type is accepted, the answerer shall not modify or remove" it (A.3.3.1). The reading found a third of the same kind that had been missed: `cmr` (−1, 0, 1; default 0). It decides whether a CMR is carried in the payload (1: in every packet; −1: none in primary mode), and it is now must-match too. An answerer may add any of the three when it was not offered (A.3.3.1); the relay cannot reframe a payload, so that is refused as a mismatch. `dtx`, `br`, `bw` and the AMR-WB IO `mode-set` limit what is sent, not how, and fall under MED-OP-05. Tests pin all three, offered and not; mutation: every mutant killed. TS 26.179 checked against docs/3GPP (V13.2.0, V19.0.0): the citations stand. | closed |
| MED-OP-05 | **Open, low consequence.** Offer/answer limits of the relay. (1) Parameters that restrict what the SDP's author wants to receive (AMR `mode-set`; EVS `br`, `bw`, `dtx`/`dtx-recv`, `ch-aw-recv`) are not reconciled across parties: every party is given the caller's, and a callee's narrower mode-set is not passed back to the caller. (2) TS 26.179 4.1.3 has clients offer `ptime` 20 and `maxptime` 240; the relay's SDP carries neither. (3) The answer to the caller has one audio and one floor m-line, whatever the offer had, where RFC 3264 6 requires as many m-lines as the offer (pre-existing). (4) telephone-event is dropped from the answer, which is legal. (5) The relay answers `RTP/AVP` even to an `RTP/SAVP` offer, which TS 26.179 4.1.2 lets clients make; SRTP is R2 (MED-OP-02). Item (1) matters less than it looks: TS 26.179 4.1.3 has clients "offer no particular mode set". | R2 |
| SVC-OP-05 | **CLOSED, and one part unreachable in R1.** The process could not establish a call in any profile: `fail_closed_platform()` hard-coded `recording_available` and `reserve_qos` to false, and every call type in every in-tree profile sets `recording_required: true`. Added `MCX_RECORDER` and `MCX_BEARER` (`none`\|`stub`), each required with no default and each stub refused under a production indicator. The production refusals cannot be reached in R1: the only known identity provider is the stub, which is refused first. Found by VP1-SIG-001, not by the suite. `test_a_process_built_from_environment_alone_can_establish_a_call` is the test that was missing. | VP1-SIG-001, VP1-CC-005 |
| SIP-OP-09 | **CLOSED 2026-09-24.** RFC 3261 §12 dialog routing was not implemented. The platform's 2xx carried no Record-Route (§12.1.1), and its ACK and BYE went to the peer's address-of-record with no Route (§12.2.1.1). Behind a record-routing proxy, both ACKs of every answered call were dropped. Fixed with route sets, remote targets and strict-route handling; eight mutants each killed by a dedicated test. | VP1-SIG-001 |
| SIP-OP-10 | **CLOSED 2026-09-24 — decided: keep 503.** A proxy that receives only a 503 sends a 500 upstream and drops the Warning (RFC 3261 §16.7 step 6), so behind a proxy `capacity-exhausted` and `recording-unavailable` look like an internal fault. Accepted as is. This row first said the behaviour defeated PLT-PRI-008. It does not: PLT-PRI-008 (an R2 requirement) asks only that capacity exhaustion be distinguishable from **authorisation failure**, and a 500 remains distinct from the 403 of an authorisation refusal, which crosses a proxy intact. What is lost past the first proxy is the platform's own, stricter aim of telling a policy refusal from a fault. The platform's audit trail keeps the exact reason code for every refusal whatever the wire shows. **A deployment setting since 2026-10-16 (owner ruling):** `MCX_SERVICE_REFUSAL_STATUS`, required, `503` (RFC 3261 21.5.4) or `480`, for every refusal that was 503 (capacity, recording, QoS, gateway, partner) but `resolver-unavailable`. 480 crosses a proxy with its Warning but says the callee is unavailable, and is reported at startup as a deviation. `resolver-unavailable` stays 503 whatever the setting: it has no warning text, and a bare 480 would present a back-end failure as the callee being away. 480 is also not a failover trigger (RFC 3263): a client or proxy with another server does not retry there, as it would on 503; the startup report says so. TS 24.379 suggests (MAY) SIP 500 with Retry-After for a lack of resources (10.1.1.3.1.1 step 1); neither choice is that. | closed |
| SIP-OP-11 | **CLOSED 2026-09-25 (20b built: PLT-CONF-AUDIT 4.39).** 20a is closed: the MCPTT info body, `P-Asserted-Identity` and the floor-control m-line are fixed. 20b is open: `Supported: timer, tdialog, norefersub`, `Require: timer` with `Session-Expires`, and `isfocus` with an MCPTT session identity in Contact (6.3.2.2.3, 6.3.2.1.5.2). Each commits the platform to a behaviour (RFC 4028, 4538, 4488, session-identity routing), so it is feature work, not a header patch. The first version of this row cited 6.3.3.1.2 and `P-Asserted-Service`; that was the wrong clause. | PLT-SIG-001 conformance |
| SIP-OP-12 | **A deployment constraint, not a platform defect, and it applies in both directions.** A back-to-back user agent re-originates every call with SDP alone. Originating (UE → B2BUA → platform): the MCPTT info body, both Accept-Contact fields and P-Asserted-Identity are lost, so the platform refuses the call (404, Warning 145), and the B2BUA strips the Warning on the way back. Terminating (platform → B2BUA → UE): the call completes, but the callee receives no MCPTT info body and so cannot tell which group is calling or who is. MCPTT clients behind a PBX that does not pass the body through lose MC semantics either way. | VP1-SIG-001, deployment guidance |
| SIP-OP-13 | **CLOSED 2026-09-24.** The INVITE client transaction toward each callee now enters RFC 6026 'Accepted' on a 2xx and stays matchable for 64·T1 (Timer M), so a retransmitted 2xx is answered with the identical ACK and a 2xx from a second fork is ACKed and then ended with a BYE (RFC 3261 13.2.2.4). A 3xx–6xx is ACKed by the transaction with the INVITE's Request-URI, Call-ID, From, Route and top Via (17.1.1.3); on TLS, Timer D is zero. The independent review found a BYE from that second fork ended the real call, because BYEs on a leg were matched by Call-ID alone; they are now matched by tag (12.2.2), and a BYE for an unknown dialog gets 481. Both interop cores re-run: PASSED. | closed |
| SIP-OP-14 | **CLOSED 2026-09-24.** Every call-ending path now CANCELs the legs still being invited (RFC 3261 9.1): initiator BYE, callee BYE, every leg failing, the missing-ACK timeout, the initiator's CANCEL, and a fault during establishment. The CANCEL copies the INVITE's Request-URI, Call-ID, From, To, CSeq number, top Via and Route. A leg that has sent no provisional yet is CANCELled when its first one arrives, never before (9.1 MUST NOT). A 487 is ACKed by the INVITE transaction. A 2xx that crosses the CANCEL is ACKed and ended with a BYE, and the leg does not join even if the call goes on. The platform also now accepts CANCEL (it answered 501 before): matched to the INVITE by branch, sent-by and Call-ID (9.2, 17.2.3), answered 200, with the INVITE answered 487, and `Allow` lists it. The independent review found two more problems on call-ending paths, both fixed: legs invited before an establishment fault were left ringing, and an initiator's BYE on an early dialog left its INVITE unanswered and its transaction in the table for ever (15.1.2 — it now gets 487). Both interop cores re-run with a cancelled-call scenario: PASSED (§7.1.1). | closed |
| SIP-OP-15 | **CLOSED 2026-09-24 (decided: a per-call-type profile setting).** Each call type declares `no_answer_s`, required, in whole seconds of at least 1 (PLT-ICD-001 §2.7). Once a member rings, its INVITE's deadline is that limit instead of Timer B, so a call type may allow members to ring for less than 32 s or for more. A member that never rings is still ended by Timer B at 64·T1. The in-tree profiles declare 32 s everywhere, which keeps the old behaviour until the owner tunes them. Before the decision: **narrowed, open for the service owner.** A ringing leg ('Proceeding') is no longer destroyed when Timer B fires. RFC 3261 17.1.1.2 runs Timer B in 'Calling' only. The platform now treats that moment as its own no-answer limit: it CANCELs the callee and keeps the transaction 64·T1 longer (9.1), so the 487 is ACKed and a crossing 2xx is ACKed and ended rather than dropped. What remains is a choice: the no-answer limit is 64·T1 (32 s) because that is Timer B, not because anyone chose it. Options: keep it, or make it a profile value per call type. Edge case kept as the RFC letter has it: if a call ends while a leg is still in 'Calling', and Timer B then ends that leg, a 2xx arriving after Timer B has no transaction to match, and the callee's own timer ends that dialog. | VP1-SIG-001 robustness |
| PRF-OP-02 | **CLOSED 2026-09-24 (decided: the specification defaults).** Every floor policy that sets timers now states `T8: 1000` and `T3: 3000`, TS 24.380's defaults, pinned by a test. The T2 talk limits (1–5 s) and T20 (100 ms) are unchanged; C20 stays fixed in the core at 3. Originally: Every in-tree floor policy sets `T8: 100`, written when T8 was (wrongly) the grace period. It now sets the interval at which the Floor Revoke is re-sent, so a revoked talker receives about 30 Revokes during the 3 s default T3; TS 24.380's default T8 is 1 s. No profile sets T3, so a revoked talker's grace went from 100 ms to 3 s. The `T2` values (1-5 s) are maximum talk times, now counted from the first media packet rather than the grant. C20 (default 3) is fixed in the core; the profile schema has no counters. Decide: T8 per profile (1000 suggested), T3 per profile, whether 1-5 s talk limits are intended, and whether C20 should be configurable. | closed |
| PRF-OP-01 | **Open — for the profile owner.** TS 24.379 cannot tell apart two pairs of call types: mcx `prearranged-group` and `coordination-group`, and utility `crew-call` and `switching-order`. Each pair is the same prearranged voice group call on the wire, and the MCPTT info body has no element for "coordination" or "switching". The second of each pair is declared `mc_signature: null`, so no native client can request it. Options: accept that; let the target group's configuration choose the call type (group data, not the request); or distinguish by something TS 24.379 does carry. | PLT-ICD-001 2.6 |
| REL-OP-02 | **CLOSED 2026-09-24 — decided: a deployment parameter.** `MCX_STRICT_RELEASE=true` refuses to start when the profile declares call types the configured release cannot carry, and names them in the refusal. `false` starts and warns in the log and the health document. It is required, with no default, like `MCX_RELEASE`, so no deployment accepts unreachable emergency calls without having stated that it does. The case that exists: the FRMCS profile at Rel-17, where ad hoc group calls, including the REC, do not exist. Tested both ways against the real railway profile. | PLT-REL-*, FRMCS deployments |
| ADHOC-OP-01 | **CLOSED 2026-09-25.** Ad hoc group calls (TS 24.379 clause 17, Rel-18 onwards) are served when the caller lists the participants (an RFC 5366 URI list) or gives criteria (`<call-participants-criterias>`). Criteria are evaluated by the profile through a new IF-IDR operation, `determine_participants` (PLT-ICD-001 v0.7 §3.5). The FRMCS resolver matches its functional identities at the caller's location, and the directory resolver refuses criteria with 187. The controlling function generates the ad hoc group identity and sends it in every member INVITE and in the 200 OK. Refusals use warnings 187 and 189 (Rel-18 table 4.4.2-2). Found on the way: nothing supplied the initiator's roles to admission, so every FRMCS call type restricted to a role (REC, shunting, driver–controller) refused every caller. The core now supplies them (§3.4, §8.1 step 4a). The independent review found five defects, all fixed: the list was parsed for every INVITE with quadratic de-duplication; step 7A was claimed but not done; one unheld identity failed a whole list; ad hoc handling was not gated on release; and a private call carrying a list was refused. Originally: **Open — a missing feature, and FRMCS depends on it.** A conformant REC or shunting group call would be refused as "unable to determine called party" at any release. | closed |
| ADHOC-OP-02 | **Open, not implemented (clause 17).** Ad hoc emergency alerts and calls that follow one (7A is refused 187); joining an ongoing ad hoc session (7B); participants modify and rejoin (17.4.4, 17.4.5); timers TNG2 and TNG3; end-to-end security with a preconfigured group (step 11); Resource-Priority for ad hoc emergency and imminent-peril calls (17.4.2.1.1 items 6 and 7); warnings 185 and 186 (a missing role is reported as 100 "user authorisation", an unsupported release as the ordinary path). A caller-supplied ad hoc identity is never accepted; the platform always generates one, which step 10 allows. Rel-20 step 12 b (functional aliases in the list, invited by alias) is not followed: a listed alias that does not resolve to one user is left out. | PLT completeness, FRMCS |
| ADHOC-OP-03 | **CLOSED 2026-09-25 (decided: cells declared in the profile).** The core now reads the client's location report (`application/vnd.3gpp.mcptt-location-info+xml`, TS 24.379 annex F.3), taking the serving NCGI or ECGI. A cell map (first a profile section, then deployment data, `MCX_CELLS_FILE`, by PRF-OP-03) turns a cell into location attributes such as `track_section` (PLT-ICD-001 §2.8), so criteria such as `rec-area` resolve from a native client's call. Encrypted or malformed reports never refuse a call; they leave it without a location. Schemas for the location body were extracted verbatim for Rel-17, 18 and 20, and the test reports validate against them. Originally: **Open — FRMCS criteria need it.** No location reached the platform from SIP. **A deployment setting since 2026-10-16 (owner ruling):** `MCX_LOCATION_REPORTS`, required, `read` or `ignore`. Ignored, a call to a location-dependent identity is refused `no-location-binding`, and a profile that has one is reported at startup. Ignored, ad hoc criteria naming a location-dependent identity also contribute no one for it (warning 187 if nothing else matches); the startup report says both. | closed |
| PRF-OP-03 | **CLOSED 2026-09-25 (decided: deployment data).** The cell map is no longer a profile section. It is a deployment file, `MCX_CELLS_FILE` (since 0.16 the `cells` of the network profile, NET-OP-01), checked at startup against the loaded profile with the same rules (PLT-ICD-001 v0.11 §2.8). It is required, with no default, when the profile has location-dependent identities, and `none` states that there is no map. So an FRMCS deployment cannot start without saying how cells map to areas, or saying that they do not. Originally: **Open — for the profile owner.** Cell identities are network data; should they be in the profile or in deployment data? | closed |
| ADHOC-OP-04 | **CLOSED 2026-09-25 (decided: a deployment-wide cap, required, no default).** `MCX_ADHOC_LIST_MAX` states how many entries an ad hoc caller's participant list may hold, whatever the call type. It is the deployment's counterpart of the service configuration's `<max-no-participants>` (TS 24.379 17.4.2.2 step 6), so a longer list is refused with warning 189. The check comes before any entry is resolved, which is its point: resolution, and its audit records, happen before any participant is resolved. (Until ICD 0.13 this was also before the caller was authorised; since ICD-OP-09 closed, an unauthorised caller is refused first.) A missing, zero, negative or non-integer value refuses startup. Criteria are not affected; they remain bounded by the call type's `max_participants`. The call type limit still applies alongside the cap. Before the decision: `rec-broadcast` declares no `max_participants`, so its list was unbounded (20,000 entries cost about 7 s under the SIP lock). | closed |
| NET-OP-01 | **CLOSED 2026-09-25 (decided: a network profile, with a CA of its own for the cores).** Network facts are one file, `MCX_NETWORK_FILE` (required, no default; PLT-ICD-001 §2.8): name, version, PLMNs, the cell map, and the trusted SIP cores with their CA. Its `name/version/hash` joins the service profile and release in every audit record and in the health document, so a record says which cell meant which location, and which cores could assert any identity, on the day of the call. Cells must belong to a listed PLMN. The core CA closes ICD-OP-10: a self-signed root with `pathLenConstraint` 0, kept apart from `MCX_SIP_TLS_CA`, trusted as the parsed certificate; a trusted core needs both its issuance and a listed name, and its certificates assert no user identity. `MCX_CELLS_FILE` and `MCX_SIP_TRUSTED_PEERS` are refused if set. Verified by `tests/test_network.py`, the trusted-core cases in `tests/test_sip_transport.py` (including real TLS with a core certificate, a users'-CA certificate carrying the core's name, and a core-CA certificate with an unlisted name), mutation testing (every mutant killed), an independent review (three defects found and fixed: see ICD-OP-10), and VP1-SIG-001 re-run against Kamailio and Asterisk with the cores on their own CA. Open: PLT-ICD-001 ICD-OP-12 (how a two-digit MNC is written in six digits). |
| ICD-OP-09 | **CLOSED 2026-09-25 (decided: IF-SES `authorise`, before any target lookup; PLT-ICD-001 0.13 §5.0).** An unauthorised caller gets one refusal (403, `not-authorised`) whatever it calls, and nothing about the target is looked up. Pinned at SIP level for ad hoc calls (criteria matching someone or no one, lists of real, unknown and 101 entries, and list with criteria) and for the restricted private call type `driver-controller` (existing, unknown and foreign users). An authorised caller still gets 404 for an unknown target. Also verified by the hook order tests for §8.1 and for gateway requests, contract tests on both methods, mutation testing (every mutant killed), an independent review, and VP1-SIG-001 re-run against Kamailio and Asterisk. |
| ADHOC-OP-05 | **CLOSED 2026-09-25.** Refusals of ad hoc calls now follow TS 24.379 17.4.2.2 in the spec's order (PLT-ICD-001 ICD-ADH-006, -007). Step 3A: emergency together with imminent peril gets 150, before authorisation. Steps 3B and 3C: an unauthorised emergency or imminent peril ad hoc call gets the MCPTT info body setting that indication to false, with no MC code; this includes a kind the profile lacks, which nobody may start. Step 4: 185. Step 5: 186, only when the profile has no ad hoc call type at all. These apply only to refusals by authorisation (`Refusal.step`). Checked at SIP level (frmcs and mcx at Rel-19) and in the adapter at Rel-18, 19 and 20, with the bodies validated against the Rel-18 and Rel-20 schemas. Mutation testing killed every mutant except one equivalent. The independent review found three defects in the first version, all fixed and confirmed on re-review: the body was missing when no call type existed for the kind; 185 was sent alongside the body; and 186 was sent to a system that does support ad hoc calls. Left as is: a non-conformant `<emergency-ind>` in an ad hoc body counts as emergency (it is safer read so), so it is denied as `adhoc-emergency-ind`, and together with imminent peril it gets 150. Not covered: 6.3.3.1.14 (the same body for non-ad hoc emergency calls), which no in-tree profile can trigger, since none restricts an emergency call type. |
| SIP-OP-16 | **CLOSED 2026-09-25: recorded in error.** A limit exists. The TLS layer closes any connection whose unframed buffer passes 256 KiB (`MAX_FRAME`, `service/sip_tls.py`), so no single message can exceed that. The row was written from the independent review of ADHOC-OP-01 without checking the transport. | closed |
| SIP-OP-17 | **CLOSED 2026-09-25 (decided: `MCX_SESSION_EXPIRES`, a required deployment setting of at least 90 s; the REFER option tags carried as the specification says).** Every dialog now has an RFC 4028 session timer. **The caller's dialog.** The timer is negotiated on the INVITE: below 90 s, the answer is 422 with `Min-SE: 90`; a longer interval is lowered to the setting; the refresher is the request's, else `uac`; a caller without timers gets refresher `uas`, and the platform keeps that timer itself. **Each callee's leg.** The timer is negotiated from the callee's 2xx: an interval below 90 s is taken as 90; when the 2xx has no Session-Expires, the platform keeps a timer of its own and refreshes at the setting; a 422 from the callee is retried once with its Min-SE. **In-dialog UPDATE and re-INVITE** are accepted from the caller and from callees. The checks cover: the connection, both tags, and a rising CSeq; glare, and an offer while the platform's own offer awaits its answer (both 491); the early dialog (491). **Offers.** An offer that keeps the call's codec, at a unicast address, moves the relay's remote address and gets the same relay answer. Any other offer gets 488. An offerless re-INVITE gets the platform's offer, and the answer in its ACK is applied only when the ACK carries the dialog's tags. **When the platform refreshes**, it sends UPDATE at half the interval, or a re-INVITE when the peer does not allow UPDATE. Its ACK goes to the remote target that the 2xx left. On failure: 408 or 481 ends the dialog; 422 is retried with the Min-SE, which then goes with every later refresh; 491 is retried per RFC 3261 14.1; other failures are retried halfway to expiry. **Expiry.** When no refresh arrives, the platform sends BYE at the interval less min(32 s, a third). A callee's expiry ends that leg, and the call when no leg is left. **Contact.** The Contact on every dialog is a per-session GRUU with `isfocus`. The platform's dialog tags are keyed with a per-process secret, so a callee cannot compute the caller's. **Verification.** `tests/test_session_timer.py`: 102 cases. Mutation testing: every mutant killed except one equivalent (an equal CSeq is already 482 at the inbound guard). An independent review. It found six defects, all fixed, each pinned by a test: the timer stopped for peers without timers; a peer's interval was not bounded below; an ACK with foreign tags could carry the answer to an offerless re-INVITE, and so move media; the refresh retried after a 422 carried no Min-SE; in-dialog offers could point the relay at an unspecified or multicast address; the ACK to a refresh ignored the target refresh. The review also led to fault isolation in the timer tick and on the response path, and to offer/answer overlap checks. A re-review confirmed the fixes and found three more issues, fixed and pinned: a forged ACK used up the transaction, so the genuine answer was lost and later offers were refused 491; a refusal of the platform's own liveness refresh ended a live call (any final response now counts as alive); and a fault while ending an expired dialog was retried on every tick. VP1-SIG-001, re-run against Kamailio and Asterisk. It adds checks on the 200 OK's timer and focus Contact, and on a refresh UPDATE through Kamailio. Limits: SIP-OP-18. | closed |
| SIP-OP-18 | **Open, low consequence (item 6 decided and built).** Limits of the refresh implementation (SIP-OP-17). (1) The call's media is not renegotiated. An offer that changes codec, payload layout or media gets 488; a new unicast address, or a new payload type number, for the same codec is followed (MED-OP-01). RFC 2543-style hold (`c=0.0.0.0`) therefore also gets 488. (2) In the caller's early dialog, an UPDATE or re-INVITE gets 491, and a callee's gets 481, where RFC 3311 would allow a refresh. (3) A leg's re-INVITE whose 2xx is never ACKed does not end the leg, where RFC 3261 13.3.1.4 says it SHOULD. On the caller's dialog it ends the call, as before. (4) A 422 from a callee is retried once. (5) REFER and its option tags (`tdialog`, `norefersub`, `explicitsub`, `nosub`) are advertised without REFER being implemented, as decided. (6) **Decided 2026-09-25 and built: the identity is the TLS certificate; a refresh on a new connection is accepted, and the old connection is dropped.** An in-dialog UPDATE, re-INVITE or BYE on a new connection is accepted when that connection proves the dialog's party. A user's connection proves it when its certificate names the party. A core's connection proves it only when it comes from the same trusted core (the same core CA and a shared trusted DNS name): a core may assert any identity, but it may not take a user's dialog. Both tags and a rising CSeq are still required, and the move happens only when the request is answered 200. The dialog then belongs to the new connection, and the old one is dropped from it for good (a weak set of retired connections). An ACK is still accepted on the connection its request came in on, and so is the answer to a refresh the platform had sent there, which is ACKed and ignored. The TLS connection itself is not closed: it may carry other dialogs, or a core's other users. Leg Call-IDs are now random, so no member can compute another dialog's Call-ID or the platform's tag on it. The independent review found five defects in the first version, and a re-review one more, all fixed and pinned by tests: a trusted core could take a directly attached user's dialog and its media; a BYE from another connection was checked on one tag; a move while an ACK was outstanding ended the call; the platform's abandoned re-INVITE went unACKed; a refused request moved the dialog; and a refresh answer on the old connection was dropped. Registration (`flows_by_user`) is not moved; a reconnecting client re-REGISTERs. The ACK of an initial INVITE's 2xx is not moved either, so a reconnect between the 200 and the ACK still ends the call. (7) With no route set, a peer sends its in-dialog requests to the GRUU as Request-URI. A core that resolves GRUUs against its registrar (RFC 5627) would not find it, because it is never registered. Behind a Record-Routing core (Kamailio in VP1-SIG-001) it works. (8) For calls with no media relay, in-dialog offers are compared as text, ignoring the `o=` line, so a re-offer that changes other lines gets 488. (9) An answer in an ACK that the relay cannot use is logged, and the session goes on unchanged. RFC 3261 would end it with BYE. (10) The platform's dialog tags are keyed with a per-process secret, so two processes serving the same dialogs would disagree; one process serves a call from start to end (SVC-OP-02). (11) Loopback, and the relay's own address, are accepted as media addresses (interop runs on loopback); media the relay sends to itself is dropped by its source check. Deviation, recorded in PLT-CONF-AUDIT 4.39: for a peer without timers, the platform follows RFC 4028 (refresher `uas`, no `Require: timer`), not TS 24.379's unconditional `refresher=uac` and `Require`. **Item 6 is a deployment setting since 2026-10-16 (owner ruling):** `MCX_DIALOG_TAKEOVER`, required, `same-party` (as decided) or `never` (every dialog stays on the connection it was established on). Neither departs from a standard, so neither is reported as a deviation. With `never`, a client that reconnects loses control of its calls: its requests on the new connection get 481, and the call lasts until its session expires or the far end ends it. | R2 |
| MED-OP-02 | One payload type per session (no transcoding). Not built: SRTP (R2), voice RTCP SR/RR relay, NAT latching (source must equal the SDP address), IPv6, media for routed/partner legs. Floor control across a gateway or interconnection is deliberately not addressed (ICD-OP-06, ICX-OP-03). | PLT-MED-* completeness |
| RES-OP-01 | **CLOSED 2026-09-28.** A member outside the profile's declared domains could reach a call: the in-tree resolver returned group-source members unchecked, and the core did not enforce PLT-ICD-001 §3.2 POST-3. Now: the core checks every `resolve` and `determine_participants` result (a foreign member is `hook-contract-violation`: no session, no invitation, audited), and the resolver refuses a group whose source supplies one (never a partial group, POST-5). One grammar decides the domain everywhere (`core/identity.py`; the resolver keeps an identical copy, as a profile may import only hook types; registration uses it too): `sip:`/`sips:`, a user part with no `@ ; ? < > : /` or whitespace, one `@`, a host of DNS characters compared without case. This is deliberately stricter than RFC 3261, which allows `;`, `?` and `/` in a user part: no MC service identity needs them, and each is a place for two parsers to disagree; an independent reviewer checked that nothing the platform produces is refused. Profiles must declare domains as lower-case DNS names. The independent review found, and the fix closed, three more ways in: a second `@` (`sip:evil@other.example@mcptt.example`, read by its last `@` as local), any URI scheme, and case disagreements between the layers (a directory member spelled `MCPTT.Example` now reaches the user registered under the canonical form). Evidence: VP1-HOOK-012, re-reviewed PASS. Mutation: every non-equivalent mutant killed. Interop PASS on both cores. | closed |
| RES-OP-02 | **CLOSED 2026-09-29.** Found by the review of VP1-HOOK-004: the audit recorded only a few fields of each hook decision, where ICD-GEN-041 asks for each in full. Now every invocation's record carries `returned`, every field of what the hook returned, rendered by `core.invoke.render` as plain data, including a value its POST check refused or crashed on (ICD v0.20). Only exact types are rendered (the ICD's own value classes and enums, scalars, finite floats, and containers of these), and a value holding anything else is refused as `hook-contract-violation`, so the core never acts on a decision the trail does not hold exactly. The independent review found a look-alike or lying subclass of a priority or session decision that the core used but the trail recorded differently; IF-ICX `map_outbound` and IF-PRI `compare` called outside the invocation boundary, unaudited; a refused value dropped when its POST crashed; NaN and scalar subclasses reaching the audit store as invalid JSON or crashing it; and IF-ICX with no deadline. All fixed and re-reviewed; no in-tree value of any profile is refused. VP1-HOOK-004 now PASS. The part of VP1-CC-006 that is not about the audit is RES-OP-12. | VP1-HOOK-004 |
| RES-OP-03 | **CLOSED 2026-09-29.** Found by the review of VP1-FC-021: floor transitions lived only in the floor machine's memory, and `floor-transition` records were never written. Now the machine reports each transition it records to an observer, and the session manager writes it to the audit trail under the session's correlation id: trigger (every event field), time, state before and after, every action, holder and queue. A call's floor is rebuilt from the audit store alone, and matches the machine's history record for record (ENV-INT, over UDP and the SQLite store). The floor starts after the session's admitted and established records. A transition whose record cannot be written is undone, since its actions are never sent: the floor stays as the participants last saw it, a client's retransmission or a still-due timer takes it again, and one session's failure no longer stops the others' timers. A session's end is the exception: the core's release and abandon always complete, and a record they cannot write is logged as lost; the service now sends a release's BYEs before it marks the store row, so a failing store no longer keeps the other parties' legs up. The independent review found the unsafe first form of that (a failed record left the session established for good), weak and too narrow tests, and no media or store failure exercised end to end; all fixed and re-reviewed. VP1-FC-021 now PASS. What remains while the audit store is failing is RES-OP-14. | VP1-FC-021 |
| RES-OP-04 | **CLOSED 2026-09-29.** Found by the review of VP1-OAM-004: the JSON log lines carried no correlation id, so a call's logs could not be joined to its audit trail. Now `service/logs.py` keeps the session a piece of work is for in a scope (`session_context`), and a filter on the handler stamps it on every line logged inside, from any module, as `correlation_id`: the id the audit records carry. The service sets it wherever it starts work for a session: a SIP request, by the call its Call-ID names (a new INVITE's Call-ID is its session's id); a response, once matched to the platform's own request; each call's SIP timers and transaction timeouts; each media packet; each session's floor timers. The core, which cannot import the service, names the session on its own lines. A fault in one call's work is now logged in that call's scope and contained, where it used to escape as a bare "tick fault", skip every other call's timers, or end a connection's reader with a traceback that was not JSON. Two concurrent calls driven in-process through the SIP core and the UDP media plane, with the service's own filter and formatter, log every call-path line under their own ids (ENV-INT); the process's stderr handler is built with the same two (`configure`). The independent review found the escaping faults, a forged response logged under a live call's id, and an untested scope; all fixed and re-reviewed. A line about a request that only claims a call's Call-ID carries that id before the dialog is checked: it is about that call, if not from its party. Hooks do not log (ICD-GEN-042), so a hook run on a worker thread needs no scope. VP1-OAM-004 now PASS. | VP1-OAM-004 |
| RES-OP-05 | **CLOSED 2026-09-29 (owner ruling: plain HTTP for now).** Found by the review of VP1-SIG-006. The HTTP interface (`service/http.py`: `/healthz`, `/readyz`, and the TS 24.481 group documents) stays plain HTTP in R1, a recorded deviation from HTTP-1 in PLT-SRS §3.1 (HTTPS) and from VP1-SIG-006's "plaintext refused on every external interface". Until it gets TLS, the interface belongs on a network the deployment trusts: group documents name the members of every group, and nothing authenticates who asks for them. **A deployment setting since 2026-10-16 (owner ruling):** `MCX_HTTP_TLS`, required, `on` or `off`. On, `MCX_HTTP_TLS_CERT` and `MCX_HTTP_TLS_KEY` are required, and `MCX_HTTP_CLIENT_AUTH` (`required`, `optional` or `none`) with `MCX_HTTP_TLS_CA` unless `none`; TLS 1.2 at least, the handshake in the request's own thread with a 10 s limit (`service/http_tls.py`). Off is this deviation, reported at startup. The handler does not look at a client certificate, so `optional` grants what `none` does; either is warned at startup, and `MCX_HTTP_CLIENT_AUTH` is in the settings reported. After the handshake a read idle for 30 s ends the connection, every connection is cut 15 s after it was accepted however slowly it sends, and at most 64 are open at once, 8 from any one address (`service/http_tls.py`). Many hosts together can still take every slot and fail `/readyz`: the interface belongs on a network the deployment controls. Renegotiation is off; a renewed certificate takes effect at the next restart. | VP1-SIG-006 |
| RES-OP-06 | **CLOSED 2026-09-28.** Hook value objects were frozen but held plain `dict` and `list` fields that could be changed in place. Now every value type derives from `core.hooks.Value`, whose `__post_init__` replaces every field by `freeze(field)`: at any depth a mapping becomes a `FrozenDict` (a read-only dict subclass, filled in `__new__`, so values still serialise, survive `asdict`/`deepcopy` and pickle), a list or tuple a tuple, a set a frozenset, bytearray bytes; scalars, enums and genuinely frozen Values stay; anything else is refused, since whether it can change cannot be told. It goes by the value, not the annotation. A field declared as a sequence refuses a string, a set or a mapping (no order to keep) and takes any other iterable as a tuple. `receive_inbound` gives the gateway a read-only copy. `FrozenDict` was chosen over `MappingProxyType` after the first version broke `dataclasses.asdict` on `BearerDecision`. The VP1-BND-004 gate has a static half (every spelling of `dataclass`; each value type frozen, deriving from `Value`, without its own `__post_init__`, dunder methods or untyped class attributes; field types from an allow-list, aliases followed) and a runtime half that loads the tree's `core/hooks.py` and tries to change a `FrozenDict`, a `freeze()` result and a probe value, and checks every class the module makes, however made. An independent review found five ways past the first version and four past the second; each is now a test in `tests/test_boundary.py` or `tests/test_values.py`, and the re-review judged VP1-BND-004 PASS. | closed |
| RES-OP-07 | **CLOSED 2026-09-29.** Found by the reviews of VP1-HOOK-034 and 041: the core did not check a floor policy or bearer decision a hook returned, only profile validation and the in-tree selector did, so a substituted hook returning an inconsistent decision was accepted. The core now checks both as the hook's post-condition (`SessionManager._check_floor_policy`, `_check_bearer`), and a failure is `hook-contract-violation` on IF-SES or IF-BER before any QoS is reserved or INVITE sent (ICD v0.19 §5.3, §6.1). The value must be the value type itself, since only a frozen `Value` is known to read the same when checked and when used. Each check is one that profile validation makes, so no validated profile is refused: every call type and media set of all three profiles is swept through it. Only `True` grants pre-emption, as IF-PRI's decision is not itself checked. The independent review found a look-alike object read differently twice, unchecked flags, a truthy priority flag, malformed values filed as `hook-error`, and a check stricter than validation (an empty path id); all fixed and re-reviewed. VP1-HOOK-034, 040 and 041 now PASS. Left for the owner as ICD-OP-14: whether POST-5 also covers the vulnerability flag. | VP1-HOOK-034, VP1-HOOK-040, VP1-HOOK-041 |
| RES-OP-08 | **CLOSED 2026-10-01.** Found by the review of VP1-REL-002: the CI conformance matrix ran releases 17 and 19 only, and `tests/test_conformance.py` never read `MCX_RELEASE`, so the release axis changed nothing. CI now runs every in-tree profile at every supported release (3 × Rel-13..20, 24 jobs, `fail-fast: false`). The suite runs at the `MCX_RELEASE` it is given (an unsupported value fails collection; unset, as locally, it runs all releases and profiles) and gained release-dependent tests with spelled-out expectations: ad hoc call types unreachable before Rel-18, warning 179 from Rel-17, Floor Revoke cause 7 from Rel-19. The new gate VP1-REL-002 reads the parsed workflow: matrix = SUPPORTED × profiles with no include/exclude, setup steps pinned, exactly one suite step with the exact env and command, no conditions, failure escapes, workflow/job env, defaults, concurrency or trigger filters, and no pytest configuration or root conftest that could narrow a run. VP1-BND-020 now also reads `if`/`continue-on-error` from the parsed workflow. The results register (`tools/vp_results.py`) now takes gate evidence for any case family, not only VP1-BND. Residual, noted by the review: an edit to `tests/conftest.py` that both drops tests and deselects the collection-count test would pass the gate; it would be visible in review of that file. | VP1-REL-002, PLT-REL-003, PLT-REL-007 |
| RES-OP-09 | **Open; batch A closed (VP1-BND-001, 002, 003, 005 re-reviewed: pass, 2026-10-17).** Found by the review of TS-BND, which planted violations in a scratch copy: every gate passes at least one obvious variant of what it blocks (per case in the reviews file). Batch A: forbidden terms normalised and matched inside words; dynamic imports and interpreter internals refused as names, attributes and strings; the core holds each hook through a declared-method view (`core/loader.py`); a profile imports named core symbols only (owner's ruling). The accepted residue of each gate is in its reviews entry. Still open: 006 to 023 but 005. VP1-BND-010 checks something else: that the hook ids appear in `core/`, not that module boundaries are named for the PLT-SRS §3.1 reference points. | VP1-BND-001 to 023 |
| RES-OP-11 | **CLOSED 2026-10-17 (owner ruling: a required parameter).** `MCX_FOREIGN_INITIATOR=refuse|allow`, no default. `refuse`: a caller outside the profile's declared domains (by `core/identity.py`'s strict reading, so a second `@`, parameters or another scheme are outside too) is refused before any hook runs, core code `initiator-not-served`, SIP 404 with warning `141 user unknown to the participating function` (TS 24.379 10.1.1.3.1.1 step 2a, 11.1.1.3.1.1 step 4; PLT-ICD-001 v0.23 §9). `allow` serves it and is reported at startup as a departure from PLT-IDM-008. Over SIP the check comes right after the identity check, before the controlling function's step 3A and the session timer (TS 24.379 17.3.2.1.1 step 3 precedes 17.4.2.2 step 3A); the core makes it again for other callers. The asserted identity is P-Asserted-Identity's first `sip:`/`sips:` value, in whichever order a core sends `sip:` and `tel:` (RFC 3325 9.1). A request a gateway relays through the IF-IWF API (`receive_inbound`) is foreign by nature and not subject to it; a gateway's INVITE over SIP is an ordinary request and is, until an inbound gateway route exists. A refused initiator is recorded cut to 256 characters with its length. Considered and left as TS 24.379 has it: an emergency call from a foreign caller is refused too (no exception in the specification; one would be a new deviation). `allow` also lets a partner system's users in, classified by the local priority rules, not capped by the partner's interconnection ceiling (there is no inbound IF-ICX path); a foreign AoR still cannot register, whatever the setting. Interop edge: a core that adds a port to the asserted URI makes its users foreign. Covered by `tests/test_foreign_initiator.py`, not yet by a VP case (PLT-IDM-008 is R2). The interop harness and the tests' environments state `refuse`. Originally: Found by the review of RES-OP-01. The initiator's domain is not checked: a request from `sip:x@other.example` is established when the caller is authenticated as that identity. The initiator is authenticated, not resolved (ICD-OP-08), so PLT-ICD-001 §3.2 POST-3 does not cover it; but a trusted core may assert any identity, including a foreign one. Decide whether IDM-008 refuses a foreign initiator. | PLT-IDM-008 |
| RES-OP-12 | **CLOSED 2026-09-29 (owner rulings the same day).** Found while closing RES-OP-02: the core ignored the session decision's `max_participants` (the in-tree `admit` enforced the profile's own) and `model`. Now the core checks `decide`'s value (§5.2 POST-1 read as equality, POST-2, boolean flags) and applies the decision's limit itself; admission no longer does (ICD v0.21). **Ruling 1:** a group call over the limit is not refused but truncated, as TS 24.379 6.3.5.5 and 10.1.1.4.1 require: the caller and the next members in the resolver's order take part, and the 200 OK carries warning `122 too many participants`. The in-tree profiles used to refuse such a call, an emergency call included. An ad hoc call over it is refused 189; anything else over it (a private call whose target is a group, a broadcast area, a limit leaving no one to invite) with the new core code `participant-limit-exceeded`, SIP 486 + 122. **Ruling 2:** R1 runs on-demand sessions only, so the in-tree call types that are broadcast (frmcs `rec-broadcast`) or pre-established (frmcs `etcs-ipcon`, utility `telemetry-session`) by nature are declared on-demand until their release (PLT-SIG-006, R2; PLT-CC-010, R3), a recorded deviation pinned by a test; ICD-OP-15 revisits POST-1 for R2. The independent review found the refusal the in-tree profiles made to be against 6.3.5.5, the call type's limit still overriding the decision for ad hoc criteria, a 503 "maximum number of sessions reached" for a per-call limit, and a limit of 1 recording a call with no callee as established; all fixed and re-reviewed. VP1-CC-006 and VP1-HOOK-033 now PASS. The one place the core still reads the call type's own limit is the ad hoc step-6 list check, an exception ICD §5.2 names. **Ruling 1 is a profile setting since 2026-10-16 (owner ruling):** `group_over_limit` per call type, required, `truncate` (as ruled) or `refuse` (486 + 122, a deviation reported at startup); the in-tree profiles declare `truncate` (PLT-ICD-001 v0.22 ICD-LIM-001). | VP1-CC-006, VP1-HOOK-033 |
| RES-OP-13 | **CLOSED 2026-09-29 (owner ruling: declare it false in R1).** Found by the review of VP1-HOOK-033: the core carries a session decision's `acknowledgement_required` to the INVITE signal, but the platform has no acknowledged group call procedure (TS 24.379 `<on-network-required>` members, timer TNG1, the 183 "Unconfirmed" handling of 10.1.1.4.1), so five in-tree call types that required acknowledgement ran unacknowledged. They now declare it false until the procedure exists (PLT-RAIL-008, R3), a recorded deviation pinned by a test: mcx `emergency-group`, `imminent-peril-group` and `coordination-group`, frmcs `rec-broadcast`, utility `switching-order`. A substituted `decide` that returns true is still carried to the signal and nothing more. | VP1-HOOK-033 |
| RES-OP-14 | **CLOSED 2026-10-16 (owner ruling: a parameter to allow or deny an unrecorded floor).** `MCX_FLOOR_UNRECORDED`, required, no default. `deny` is the behaviour below: a floor transition the audit store cannot take is undone and not sent, so the floor stops while the store fails (PLT-FC-011 kept). `allow` lets it stand and be sent; so are the IF-PRI evaluations a floor request makes, the floor's other record (`SessionManager.floor_auditor`). The auditor counts each record lost, by type, into one pending gap (`core/audit.py`): logged at most every 10 s, one limit for failure and recovery so a flapping store does not log per packet; shown in the health document (`audit`); written as one `audit-gap` record ahead of the next record any writer makes, retried from the SIP tick, and at shutdown written or logged in full. While a gap is pending the store is tried at most once a second, so a store that fails slowly does not cost a write per packet under the core lock; the price is that up to a second of the floor's records after a recovery may still be counted lost (any other record written in that second ends the gap at once). The SQLite store waits at most 1 s on a lock; a plain record with a gap pending tries the gap first, so with the store down it costs two attempts. A failed admission or establishment record now also closes the session's trail with a best-effort `session-failed`. Session ids and the error in a gap are clipped (128 and 256 characters, up to 100 sessions), and a gap the store refuses never keeps the record behind it from being written. The gap's correlation id is `audit-gap`, so within one session's own trail the hole shows only as a jump in its floor sequence numbers. `allow` departs from PLT-FC-011 and from ICD-GEN-040/041 for the floor request's IF-PRI evaluation, and is reported at startup; with it, consequences (1) to (4) below no longer stop the floor (tested end to end), while (5) and (6) are unchanged. Found by the review and fixed in both modes: a session whose admission record could not be written stayed in memory, counted toward capacity; it is now removed. The interop harness and the tests' environments state `deny`. Before the ruling: From the review of RES-OP-03. Every floor transition is now written before its actions are sent, and undone if it cannot be, so a store that fails stops the floor rather than letting it run unrecorded. The consequences, to accept or change: (1) a deferred floor start whose record fails is not retried, and the call keeps a floor that denies every request; (2) the holder's first media report fails, so the holder's audio is not forwarded, and every packet retries the write and logs, about fifty a second, under the core lock; (3) a timer whose record fails is retried and logged every tick; (4) outside the SIP service (a manager that starts its floor itself), a failed start leaves the session established with the floor not started; (5) a released session whose store row cannot be marked released stays 'established' in the store, and is counted as recovered at the next restart (its BYEs are sent); (6) a floor invariant violation, which only a defect causes, still leaves its partial change in place, where a failed record is undone. Also recorded: each floor record is a synchronous commit (`synchronous=FULL`) made under the one core lock that RTP forwarding also takes, measured at about 0.9 ms here, to be measured on target hardware; and an ignored floor message is recorded by design, so an authenticated endpoint can cause a write per packet. | VP1-FC-021 |
| RES-OP-15 | **CLOSED 2026-10-16.** The inbound guard answers 400 to a request whose Call-ID is longer than 256 characters (`CALL_ID_MAX`) or is not RFC 3261 25.1's `callid = word [ "@" word ]`, before anything uses it; so is a request with more than one Call-ID header; a message that cannot be parsed at all is dropped, logged clipped. Such a Call-ID never becomes a correlation id. An ACK, which never reaches the guard, is checked first and dropped with only its length logged; a non-2xx ACK matched on its INVITE's branch must also carry that INVITE's Call-ID. Header values are trimmed of RFC 3261 whitespace only, and Content-Length must be ASCII digits. Peer text in an error message is clipped (`core/sip.py` `clip`, 80 characters and its length): a start or header line that cannot be parsed, a Session-Expires or Min-SE value, an SDP address (64) or port; and an unusable offer's reason is cut at 200 characters where it becomes an audit detail. The callee's To tag no longer goes into the platform's ACK branch (hashed). No audit key or log line carries an over-long Call-ID (`core/sip.py` `valid_call_id`, `tests/test_call_id.py`). A UUID@host is under 100 characters. Interop edges to watch: a SIP core that masks Call-IDs (Kamailio topoh, about 4/3 longer) pushes a client Call-ID over about 190 characters past the limit, and a non-conformant UA's base64 Call-ID with `=` padding is now refused 400, as RFC 3261 25.1 allows. Still open, notes: the HTTP access log line for a group document names no session; an initiator asserted by a trusted core goes into the audit record unbounded, a trust-domain question (RES-OP-11). Originally: From the review of RES-OP-04. A new INVITE's Call-ID becomes its session's correlation id in the audit trail and the logs, and nothing bounds its length but the framing limit (256 KiB). RFC 3261 sets no limit; a guard limit (e.g. 256 bytes, answered 400) would bound audit keys and log lines. Also noted: the HTTP access log line for an ad hoc group document names no session. | VP1-OAM-004 |
| RES-OP-10 | **CLOSED 2026-10-01 (owner ruling 2026-09-29: each as recommended; the cases amended).** (1) VP1-BND-012: the TS 23.501 tables in `core/qos.py` (standardised 5QIs, the media of the mission-critical 5QIs, the ARP range) are a recorded exception: 3GPP definitions, not a priority-to-QoS mapping, which stays in the profile (PLT-HOK-043). The gate now holds `core/qos.py` to those four tables with no mention of a priority, and elsewhere in the core catches a QoS literal in any statement, comparison, keyword or mapping, or a mission-critical 5QI value anywhere; the review's missed forms (annotated and tuple assignments, a table under a neutral name) are probed. (2) VP1-BND-009: the floor machine's queueing, override, queue depth and initial grant are TS 24.380 configuration parameters like its timers; the case excepts them. The gate now covers the SIP session and document modules the case names, each reading only the profile attributes it lists with its reason, and a floor guard on any other policy setting fails it. (3) VP1-FC-014: amended to the accepted FC-OP-07 behaviour, a pre-emptor held where override is allowed, pinned by a test; the test whose name claimed "no queue entry ever" is renamed. The independent review found the session state machine (`core/session.py`) outside the BND-009 gate and `self._profile`, aliases and `getattr` on the floor policy unseen; a function in `core/qos.py` that mapped labels onto 5QIs without naming a priority; false positives the QoS rule would raise (an ASCII range, "sharp"); and, behind the FC-014 wording, a deviation from TS 24.380 6.3.5.4.4: a participant already queued that asked again was denied, though it stayed queued and was granted later. Now the gate covers `core/session.py`, `service/media.py` and `service/http.py`, follows aliases, and pins the floor policy's fields; `core/qos.py` may define only its two lookups; the QoS rule matches whole words, skips comparisons and honours a reviewed `# not-qos` marker; and a repeated request keeps its place, with Queue Position Info where queueing was negotiated and nothing otherwise (item 4), or is repositioned at a new priority (item 8). What the static gates still cannot see is stated in them, and a line the QoS rule wrongly flags is exempt only by being listed in the gate with its reason. **One behaviour changed**, beyond the ruling: the 6.3.5.4.4 conformance fix above. A repeated floor request is no longer denied ("already queued"); the Deny reason is gone. | VP1-BND-012, VP1-BND-009, VP1-FC-014 |

---

## 12. Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-09-19 | Initial draft |
| 0.42 | 2026-10-17 | RES-OP-11 closed on the owner's ruling: `MCX_FOREIGN_INITIATOR=refuse|allow`, required; `refuse` answers a caller outside the declared domains 404 + 141 before any hook runs, `allow` is a reported deviation. |
| 0.43 | 2026-10-17 | RES-OP-09 batch A: gates VP1-BND-001, 002, 003 and 005 hardened and independently re-reviewed (pass). BND-005 follows the owner's ruling (named core symbols only); the core sees each hook through its Protocol methods only; `PROFILE_BOUNDARY.md` moved to `docs/`. |
| 0.41 | 2026-10-16 | RES-OP-15 closed: a Call-ID over 256 characters, not of RFC 3261's `callid` grammar, or repeated, is answered 400 by the inbound guard and names no session; ACKs with such a Call-ID are dropped with only their count and length logged; peer text in error messages is clipped. |
| 0.40 | 2026-10-16 | RES-OP-14 closed on the owner's ruling: `MCX_FLOOR_UNRECORDED=deny|allow`, required. `allow` keeps the floor running while the audit store fails; the records of the floor lost are counted into one `audit-gap` record, written ahead of the next record any writer makes (retried from the SIP tick, written or logged in full at shutdown); it is reported at startup as a departure from PLT-FC-011 and ICD-GEN-040/041. |
| 0.39 | 2026-10-16 | Owner ruling: six decisions become settings, each required with no default, a departure from the standard reported at startup (log, health `deviations`, a `configuration-accepted` audit record). Deployment: `MCX_SERVICE_REFUSAL_STATUS` (SIP-OP-10), `MCX_DIALOG_TAKEOVER` (SIP-OP-18 item 6), `MCX_LOCATION_REPORTS` (ADHOC-OP-03), `MCX_HTTP_TLS` and its files (RES-OP-05; HTTPS now built). Profile: `floor.preemption_at_full_queue` (FC-OP-07), `group_over_limit` (RES-OP-12 ruling 1). The in-tree profiles and the interop harness state the decided behaviour. |
| 0.38 | 2026-10-01 | RES-OP-08 closed: the conformance suite runs every profile at every supported release in CI, gated (VP1-REL-002 PASS). |
| 0.37 | 2026-10-01 | RES-OP-10 closed on the owner's ruling: VP1-BND-009, VP1-BND-012 and VP1-FC-014 amended; both gates hardened. Found on the way and fixed: a repeated floor request is answered per TS 24.380 6.3.5.4.4 (Queue Position Info or nothing, or repositioned), no longer denied. |
| 0.36 | 2026-09-29 | Owner rulings: RES-OP-13 closed (acknowledgement declared false in R1), RES-OP-05 closed (HTTP stays plaintext for now, a recorded deviation). |
| 0.35 | 2026-09-29 | RES-OP-04 closed: every log line about a session carries its correlation id. RES-OP-15 opened. |
| 0.34 | 2026-09-29 | RES-OP-03 closed: floor transitions are written to the audit trail, and a call's floor is rebuilt from it alone. RES-OP-14 opened. |
| 0.33 | 2026-09-29 | RES-OP-12 closed on the owner's rulings: the session decision is checked and applied by the core; a group call over its limit is truncated with warning 122 (TS 24.379 6.3.5.5); R1 call types are declared on-demand. RES-OP-13 opened. |
| 0.32 | 2026-09-29 | RES-OP-02 closed: every hook's returned value is recorded in full, and one that cannot be is refused. RES-OP-12 opened. |
| 0.31 | 2026-09-29 | RES-OP-07 closed: the core checks a hook's floor policy and bearer decision at runtime. |
| 0.30 | 2026-09-28 | RES-OP-06 closed: hook value objects hold nothing mutable; the VP1-BND-004 gate checks it. |
| 0.29 | 2026-09-28 | RES-OP-01 closed (a foreign group member could reach a call; now refused by the core and the resolver, with one identity grammar). RES-OP-11 opened (initiator domain). |
| 0.28 | 2026-09-28 | Results register (§10): `tools/vp_results.py`, `docs/PLT-VP-R1-RESULTS.md`, `docs/PLT-VP-R1-REVIEWS.yaml`. Plan defects it found, corrected: §9 lacked the nine R1 PLT-REL requirements (83 rows for 92), §1.2's method counts were wrong, the VP1-REL cases sat in the TS-DOC table (now §7.6), and gates VP1-BND-022/023 were run but not defined (now in §4). Independent review of every case: RES-OP-01 to 10 opened. |
| 0.27 | 2026-09-26 | VP-OP-05 widened and kept open in R1 (owner decision): how the production indicator is read today, three weaknesses (a forgotten flag, a flag its own author can switch, no record of either), and options A, B and C. |
| 0.26 | 2026-09-26 | SVC-OP-03 closed (decided): groups and users are part of the network profile; `MCX_GROUPS_FILE` refused. VP1-DOC-001 names the network profile. |
| 0.25 | 2026-09-26 | TS 26.179 read from docs/3GPP: citations confirmed; MED-OP-03 and MED-OP-05 annotated (4.2.1, 4.1.2, 4.1.3). |
| 0.24 | 2026-09-26 | MED-OP-04 closed: the EVS parameters read from TS 26.445 annex A; `cmr` added as must-match. |
| 0.23 | 2026-09-26 | VP-OP-03 decided and MED-OP-01 closed: one codec set for every profile (EVS, AMR-WB, AMR, G.722, PCMA, PCMU) in order of preference, chosen per call without transcoding, each party numbering it its own way. MED-OP-03 (transcoding, R4), MED-OP-04 (EVS parameters unverified) and MED-OP-05 (offer/answer limits) opened. |
| 0.22 | 2026-09-25 | SIP-OP-18 item 6 decided and built: a dialog moves to a new connection that proves the same party (certificate, or the same trusted core), and the old connection is dropped from it. |
| 0.21 | 2026-09-25 | SIP-OP-11 and SIP-OP-17 closed: RFC 4028 session timers with in-dialog UPDATE and re-INVITE (`MCX_SESSION_EXPIRES`), per-session GRUU Contact with isfocus, and the 24.379 option tags. SIP-OP-18 opened (limits). |
| 0.20 | 2026-09-25 | Two ids in §11 named two different open points each. The later rows are renumbered, the earlier ones keep their ids (they are the ones cited by `service/media.py`, PLT-CONF-AUDIT 4.16-4.19 and revision 0.6): floor control on a separate `m=application` stream, formerly the second FC-OP-04, is now **FC-OP-11**; IF-PRI having no participant-specific input, formerly the second FC-OP-05, is now **FC-OP-12**. No content changed. |
| 0.19 | 2026-09-25 | VP1-BND-006 rewritten for per-profile release images (PLT-SRS 0.3, PLT-GEN-001): each image carries exactly one profile and the core hash is identical across images, checked by building every image with `tools/package.py`. VP1-BND-021 and exit criterion 4 now refer to the same core instead of the same artefact. |
| 0.18 | 2026-09-25 | ADHOC-OP-05 closed: ad hoc refusals in the order of 17.4.2.2 (3A 150, 3B/3C body, 185, 186). |
| 0.17 | 2026-09-25 | ICD-OP-09 closed by decision: IF-SES `authorise` runs before any target lookup (ICD 0.13). ADHOC-OP-05 opened: the ad hoc authorisation warnings 185 and 186 and the 3B body. |
| 0.16 | 2026-09-25 | NET-OP-01 closed by decision: the network profile (`MCX_NETWORK_FILE`) holds PLMNs, the cell map and the trusted cores with their own CA, and joins the audit identity (VP1-OAM-001). ICD-OP-10 closed with it. |
| 0.15 | 2026-09-25 | PRF-OP-03 closed by decision: the cell map is deployment data (`MCX_CELLS_FILE`), required for profiles with location-dependent identities. |
| 0.14 | 2026-09-25 | ADHOC-OP-03 closed by decision: the client's location report is read and mapped through the profile's cell map (PLT-ICD-001 0.10 §2.8). PRF-OP-03 opened: whether cell identities belong in the profile or in deployment data. |
| 0.13 | 2026-09-25 | ICD-OP-08 closed in its R1 form (PLT-ICD-001 0.9): identity from the certificate or a trusted core, and each dialog bound to its connection. Both interop cores re-run, with a new impersonation check: PASSED. SIP-OP-16 corrected: a 256 KiB frame limit exists. SIP-OP-17 opened: re-INVITE is not supported. |
| 0.12 | 2026-09-25 | ADHOC-OP-04 closed by decision: `MCX_ADHOC_LIST_MAX`, a deployment-wide cap on an ad hoc participant list, required with no default and checked before any entry is resolved (warning 189). |
| 0.11 | 2026-09-25 | ADHOC-OP-01 closed: ad hoc group calls, by participant list or by criteria (PLT-ICD-001 0.7 §3.5). The initiator's roles now reach admission. ADHOC-OP-02 to ADHOC-OP-04 and SIP-OP-16 opened. SIP-OP-04 corrected: CANCEL and media anchoring are built. |
| 0.10 | 2026-09-24 | SIP-OP-15 closed by decision: the ring limit is the per-call-type profile field `no_answer_s` (PLT-ICD-001 0.6 §2.7), 32 s in every in-tree call type. |
| 0.9 | 2026-09-24 | SIP-OP-14 closed: the legs still being invited are CANCELled on every call-ending path, and the platform accepts CANCEL (it answered 501 before). An initiator's BYE on an early dialog now gets its INVITE a 487 (RFC 3261 15.1.2). SIP-OP-15 narrowed: a ringing leg is CANCELled at the no-answer limit instead of being dropped; whether that limit should stay at 64·T1 is left to the service owner. §7.1.1 gains the cancelled-call interop run through both cores. |
| 0.8 | 2026-09-24 | SIP-OP-13 closed: 2xx re-ACK, forked 2xx ACK-and-BYE, and non-2xx ACK on the platform's legs toward callees, with BYEs on a leg matched by dialog tag. PRF-OP-02 decided (T8 = 1 s, T3 = 3 s in every profile) and FC-OP-07 accepted as a deviation. SIP-OP-14 (no CANCEL of ringing legs) and SIP-OP-15 (Timer B while ringing) opened. |
| 0.7 | 2026-09-24 | FC-OP-01 and FC-OP-02 closed by PLT-CONF-AUDIT CA-21: the floor timers' behaviour was read against TS 24.380 and eleven deviations fixed. FC-OP-07 (pre-emption into a full queue, deliberate), FC-OP-08 (comparator strength), FC-OP-09 (unimplemented floor procedures), FC-OP-10 (two TS 24.380 inconsistencies) and PRF-OP-02 (profile timer values written for the old behaviour) opened. FC-OP-03 and VP1-FC-002 are unaffected by this change and remain as v0.2 left them. |
| 0.6 | 2026-09-24 | VP-OP-02 confirmed: VP1-FC-002 passes on specification-derived evidence (§6.1), and FC-OP-03 is closed. FC-OP-01 and FC-OP-02 are re-filed against the behaviour cases (VP1-FC-010, VP1-FC-020), with their stale "TS 24.380 not available" reasons corrected. FC-OP-05 is marked non-blocking. |
| 0.5 | 2026-09-24 | VP-OP-01 decided: a B2BUA counts, so VP1-SIG-001 passes against Kamailio and Asterisk, with SIP-OP-12 and SIP-OP-02 carried alongside the verdict. SIP-OP-10 decided: keep 503. Corrected this plan's earlier claim that the 503-to-500 rewrite defeats PLT-PRI-008; it does not. FC-OP-03 no longer calls VP-OP-02 undecided. |
| 0.4 | 2026-09-24 | REL-OP-02 closed by decision: `MCX_STRICT_RELEASE` (true refuses, false warns), required with no default. |
| 0.3 | 2026-09-24 | §7.1.1 corrected. The first runs' MC body was the platform's own invented format, copied into the user agent; after PLT-CONF-AUDIT CA-20a the agent writes annex F.1 bodies and Kamailio passes an added body check. SIP-OP-11 split into 20a (closed) and 20b (open) with corrected clauses; SIP-OP-12 widened to both directions. PRF-OP-01, REL-OP-02 and ADHOC-OP-01 opened. |
| 0.2 | 2026-09-24 | VP1-SIG-001 executed against Kamailio 5.7.4 (pass) and Asterisk 20.6 (terminating pass; originating path not possible through a B2BUA), recorded in §7.1.1. SIP-OP-01, SIP-OP-09 and SVC-OP-05 closed; SIP-OP-10 to SIP-OP-13 opened. VP-OP-01 narrowed to one decision. |
