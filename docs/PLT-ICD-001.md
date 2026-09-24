# Profile hook interfaces — Interface Control Document

**Document:** PLT-ICD-001
**Version:** 0.5 (draft)
**Date:** 2026-09-24
**Status:** Draft for review — not baselined
**Parent:** PLT-SRS v0.1 §6
**Implements:** `core/hooks.py`

---

## 1. Purpose

PLT-SRS §6 and §14A state *what* the six profile hooks must do. This document states
*how* they are called: the contract each side must honour, the ordering and
timing of invocations, what every error means, and which invariants the core
relies on.

An implementer of a profile should be able to write a conformant hook from this
document plus `core/hooks.py`, without reading core source.

### 1.1 Interface identification

| ID | Interface | Direction | SRS |
|---|---|---|---|
| IF-IDR | `IdentityResolver` | core → profile | PLT-HOK-010..015 |
| IF-PRI | `PriorityPolicy` | core → profile | PLT-HOK-020..024 |
| IF-SES | `SessionPolicy` | core → profile | PLT-HOK-030..033 |
| IF-BER | `BearerSelector` | core → profile | PLT-HOK-040..043 |
| IF-IWF | `InterworkingGateway` | core → profile | PLT-HOK-050..052 |
| IF-ICX | `InterconnectionGateway` | core → profile | PLT-ICX-001..033 |

All six are synchronous, in-process, single-direction calls. No hook calls back
into the core. There is no profile-initiated interface in this release; the
runtime events a profile must react to are delivered as hook invocations
(IF-BER `on_path_event`).

### 1.2 Conventions

Contracts are stated as **PRE** (caller guarantees), **POST** (implementer
guarantees) and **INV** (invariants the core relies on and verifies).

A contract violation by the profile is a **defect**, not a runtime condition to
be handled gracefully: the core fails the session and records the violation
(§7.3). Contracts are checked in test mode and at the boundary in production.

---

## 2. Common interface rules

### 2.1 Purity and effects

| ID | Rule |
|---|---|
| ICD-GEN-001 | A hook shall not mutate any object it receives. All parameter objects are frozen. |
| ICD-GEN-002 | A hook shall not retain a reference to a parameter object beyond the call. |
| ICD-GEN-003 | A hook shall not call into the core, directly or by any callback. |
| ICD-GEN-004 | A hook shall not block on network I/O on the session-establishment path except where §3 explicitly permits it (IF-IDR only). |
| ICD-GEN-005 | IF-PRI, IF-SES and IF-BER shall be pure functions of their inputs and the immutable loaded profile: same inputs, same outputs, for the process lifetime. |
| ICD-GEN-006 | IF-IDR is explicitly *not* pure: binding state changes over time. Its results shall be treated as valid only for the session that requested them. |

### 2.2 Timing

| ID | Rule |
|---|---|
| ICD-GEN-010 | The core shall apply a deadline to every hook invocation. Default budgets: IF-IDR 50 ms, IF-PRI 5 ms, IF-SES 5 ms, IF-BER 10 ms, IF-IWF 20 ms, IF-ICX 20 ms. |
| ICD-GEN-011 | On deadline expiry the core shall abandon the invocation, fail the session with `hook-timeout`, and record the interface and elapsed time. |
| ICD-GEN-012 | The core shall not retry a timed-out invocation on the session-establishment path. |
| ICD-GEN-013 | Budgets are deployment-configurable downward but not upward beyond the §6 latency allowance of PLT-SRS. |

### 2.3 Failure

| ID | Rule |
|---|---|
| ICD-GEN-020 | A hook signals refusal through its return value where the interface defines one (IF-SES `admit`), and failure by raising. |
| ICD-GEN-021 | The core shall treat any raised exception as session failure with `hook-error`. It shall never substitute a default result. |
| ICD-GEN-022 | The core shall not distinguish exception types. A profile needing a distinguishable outcome shall express it in the return value. |
| ICD-GEN-023 | A hook shall not raise to signal a business decision that the interface can express. Refusing admission by raising is a defect. |

### 2.4 Concurrency

| ID | Rule |
|---|---|
| ICD-GEN-030 | Hooks shall be safe for concurrent invocation from multiple session contexts. |
| ICD-GEN-031 | The core makes no ordering guarantee between invocations for different sessions. |
| ICD-GEN-032 | Within one session establishment the order is fixed (§6.1) and the core shall not reorder it. |
| ICD-GEN-033 | IF-IDR mutating operations (`bind`, `unbind`) may run concurrently with `resolve`. The implementer is responsible for internal consistency; the core does not serialise them. |

### 2.5 Audit

| ID | Rule |
|---|---|
| ICD-GEN-040 | Every invocation shall be recorded with interface ID, session correlation ID, elapsed time and outcome (PLT-OAM-002). |
| ICD-GEN-041 | Returned decisions shall be recorded in full. A decision absent from the audit trail cannot be relied on in a safety case. |
| ICD-GEN-042 | Hooks shall not log. Observability is the core's responsibility, so that one correlation scheme covers all interfaces. |

### 2.6 Call-type signatures (declared data, not a hook)

A native MCPTT client does not name a profile call type. It sends a TS 24.379
annex F.1 body: a `<session-type>` (`prearranged`, `chat`, `private`,
`first-to-answer`, `ambient-listening`, `adhoc`) and indications
(`<emergency-ind>`, `<imminentperil-ind>`, `<broadcast-ind>`, and from Rel-18
`<adhoc-emergency-ind>` for ad hoc calls). Turning that into a call type is
profile knowledge, so the profile declares it as data, and the core looks it
up. Adopted 2026-09-24 (PLT-CONF-AUDIT CA-20) in place of a hook operation,
because data can be checked at load time and code cannot.

Each `call_types[]` entry carries a **required** `mc_signature`:

```yaml
mc_signature: {session_type: prearranged, emergency: true}   # or
mc_signature: null     # no native MCPTT client can request this call type
```

| ID | Rule |
|---|---|
| ICD-SIG-001 | `mc_signature` is required on every call type. `null` states that the call type cannot be requested by a native MCPTT client. An absent key is a load error, so that no profile is silent on the question. |
| ICD-SIG-002 | `session_type` is one of the six annex F.1 values; `emergency`, `imminent_peril` and `broadcast` are booleans defaulting to false. |
| ICD-SIG-003 | No two call types in a profile may declare the same signature (`ambiguous-signature`). The core does not guess which one a client meant. |
| ICD-SIG-004 | The core selects the call type whose signature equals the request's exactly, and only if the configured release has that session type (`core/release.py`). Otherwise `call_type` is `""` and IF-SES refuses. |
| ICD-SIG-005 | The core renders the same signature into the INVITE it sends each invited member, together with `<mcptt-request-uri>`, `<mcptt-calling-user-id>` and `<mcptt-calling-group-id>` (TS 24.379 6.3.2.2.3 item 8, 10.1.1.4.1.1 item 4). |
| ICD-SIG-006 | At startup the core reports call types declared `null` and call types whose signature the configured release cannot carry, in the log and in the health document. Whether the second case is fatal is the deployment's stated choice, `MCX_STRICT_RELEASE` (required, no default): `true` refuses to start and names the call types; `false` starts and warns (REL-OP-02, decided 2026-09-24). |
| ICD-SIG-007 | `SessionRequest.application` and `urgency` are never taken from a native request, because TS 24.379 has no element for either. They come from the call type's declaration. |

---

## 3. IF-IDR — IdentityResolver

### 3.1 Purpose

Turns a target reference into a concrete member set. The only hook permitted to
consult mutable state, because functional-identity bindings change at runtime.

### 3.2 `resolve(target, request) -> Resolution`

**PRE**
1. `request.initiator` is authenticated and authorised for `request.call_type`.
2. `request.call_type` is declared in the loaded profile.
3. `target` is non-empty and syntactically well-formed.
4. `request.location` is present if the profile declares any location-dependent
   identity; it may still be `None` if the client reported none.

**POST**
1. Returns a `Resolution` whose `kind` is consistent with `members`:
   `USER` → exactly 1; `GROUP` → `group_id` set, ≥ 1 member;
   `BROADCAST_AREA` → ≥ 0 members; `EXTERNAL` → **no** members, and
   `resolved_from` carries the foreign target.
2. `members` contains no duplicates and is stably ordered.
3. Every member is within a domain declared by the profile (PLT-IDM-008).
4. `resolved_from` records the reference actually used, where it differs from
   `target` — mandatory for any functional or location-dependent resolution
   (PLT-HOK-014).
5. On failure to resolve, raises. Never returns an empty `USER` or partial
   `GROUP` result (PLT-HOK-015).

**INV**
1. The core treats the returned member set as complete and authoritative.
2. The core does not re-resolve during a session. A binding change after
   resolution does not alter the established member set.
3. A single-holder functional identity resolving to more than one member is a
   contract violation, detected by the core and recorded as such
   (PLT-RAIL-004).

**Errors**

| Condition | Reason code |
|---|---|
| Target is not known in any form | `unknown-target` |
| Functional identity exists but has no current holder | `no-binding` |
| Location-dependent identity with no usable location | `no-location-binding` |
| Group exists but caller may not address it | `not-authorised` |
| Backing store unreachable | `resolver-unavailable` |

> `no-binding` and `unknown-target` must remain distinguishable: an unheld role
> and a nonexistent role are different operational conditions (PLT-RAIL-005).

### 3.3 `bind(identity, service_id, location)` / `unbind(identity, service_id)`

**PRE**
1. `identity` is declared in the profile's functional identity list.
2. The caller is authorised to alter bindings for `identity`.
3. `location` is present when the identity is declared location-dependent.

**POST**
1. `bind` on a single-holder identity that is already held either replaces the
   existing holder or raises — the profile shall declare which, and shall not
   permit a second concurrent holder.
2. `unbind` for a binding that does not exist is a no-op, not an error.
3. Both operations are atomic with respect to concurrent `resolve`: a resolve
   observes either the old or the new binding, never a partial state.

**INV**
1. Bindings do not affect sessions already established.
2. Binding changes are audited independently of session records — the binding
   history is evidence in its own right.

### 3.4 `identities_of(service_id) -> Sequence[str]`

Read-only. Returns currently held identities for a user, for display and audit.
Returns an empty sequence for a user holding none; does not raise for an unknown
user.

---

## 4. IF-PRI — PriorityPolicy

### 4.1 `evaluate(request, resolution) -> PriorityDecision`

**PRE**
1. `resolution` is the result of a successful IF-IDR call for this request.
2. `request.call_type`, and `request.application` if present, are declared.

**POST**
1. Always returns a decision. The profile's rule table is required to be total
   over declared call types (PLT-PRF-005), so "no applicable rule" is a
   validation defect, not a runtime outcome.
2. `scope` is one of the profile's declared pre-emption scopes.
3. `level` and `floor_priority` are within the profile's declared ranges.
4. `label` is stable for a given decision and suitable for audit.

**INV**
1. The core performs no priority arithmetic of its own (PLT-HOK-021).
2. The decision is taken once, at admission, and is immutable for the session
   (PLT-PRI-001). Re-evaluation happens only on an explicit call-type change,
   such as emergency upgrade, which the core treats as a new admission.

### 4.2 `compare(a, b) -> int`

**PRE** Both arguments were produced by this same policy instance.

**POST**
1. Returns `0` whenever `a.scope != b.scope` — unconditionally. This is the
   cross-scope pre-emption bar (PLT-HOK-022, PLT-PRI-003).
2. Within one scope: `> 0` if `a` outranks `b`, `< 0` if `b` outranks `a`,
   `0` if neither outranks the other.
3. Antisymmetric: `sign(compare(a,b)) == -sign(compare(b,a))`.
4. Transitive within a scope.
5. Reflexive as equality: `compare(a,a) == 0`.

**INV**
1. `0` means *no relation*, not *equal*. The core never pre-empts on `0`, so an
   implementation that conflates the two silently disables pre-emption between
   genuinely equal-priority sessions — which is the safe direction, and is the
   intended reading.
2. Pre-emption additionally requires `a.preemption_capability` and
   `b.preemption_vulnerability` (PLT-PRI-002). `compare` alone never authorises
   pre-emption.

> **Verification.** Properties 2–5 and the scope rule are checked by
> property-based testing over the profile's own decision space (PLT-VER-007).

---

## 5. IF-SES — SessionPolicy

### 5.1 `admit(request, resolution, priority) -> Admission`

**PRE** IF-IDR and IF-PRI have both succeeded for this request.

**POST**
1. Returns `Admission`. Refusal is a return value, never an exception
   (ICD-GEN-023).
2. `permitted=True` → `reason_code` is the empty string.
3. `permitted=False` → `reason_code` is a member of the profile's declared
   `reject_reason_codes` set. An undeclared code is a contract violation.
4. Capacity refusal and authorisation refusal use distinct codes
   (PLT-PRI-008).

**INV**
1. A refused session is never established (PLT-HOK-033).
2. Reserved-capacity enforcement lives here, not in the core: the core knows
   current session counts and supplies them, but the admission rule is the
   profile's (PLT-PRI-007).

### 5.2 `decide(request, resolution) -> SessionDecision`

**PRE** Called only after `admit` returned `permitted=True`.

**POST**
1. `model` is consistent with the call type's declared session model.
2. `max_participants`, if set, is ≥ 1; `None` means unlimited.
3. `recording_required=True` binds: the core refuses establishment if recording
   is unavailable (PLT-OAM-008).

**INV**
1. The core applies the decision verbatim (PLT-CC-005). It does not infer
   auto-answer from urgency, or recording from call type.
2. The decision is immutable for the session.

### 5.3 `floor_policy(request, resolution) -> FloorPolicy`

**PRE** Called for sessions with a voice or video component. Not called for
data-only sessions.

**POST**
1. `queueing_enabled=False` → `max_queue_depth == 0`.
2. `queueing_enabled=True` → `max_queue_depth ≥ 1`.
3. `timers_ms` keys are TS 24.380 timer names. Unknown keys are a contract
   violation, detected at profile validation.
4. Omitted timers take the core's specification defaults.

**INV**
1. The profile supplies constants only. The floor state machine and its
   transitions are core-owned and not influenceable (PLT-PRF-031, PLT-FC-010).
2. A profile that needs a different transition is a signal the core state
   machine is wrong. It is escalated, not worked around here.

---

## 6. IF-BER — BearerSelector

### 6.1 `select(request, priority, media) -> BearerDecision`

**PRE**
1. The session is admitted; `priority` is the session's final decision.
2. `media` is non-empty.

**POST**
1. `paths` contains ≥ 1 entry; exactly one has `primary=True`.
2. `path_id` values are unique within the decision.
3. `redundancy=single` → exactly one path. `multipath`/`multihomed` → ≥ 2.
4. `qos_identifier` and `arp_level` are valid for the deployment's core network.
5. ARP pre-emption flags are consistent with the priority decision: a decision
   with `preemption_capability=False` shall not request
   `arp_preemption_capability=True`.

**INV**
1. The core performs no priority-to-QoS mapping (PLT-HOK-043).
2. The core requests the returned QoS from the network. Refusal by the network
   is a session failure, not a silent downgrade.

### 6.2 `on_path_event(session_id, event) -> Optional[BearerDecision]`

**PRE**
1. `session_id` identifies an established session.
2. `event` carries at minimum `path_id` and `type`
   (`up` | `down` | `degraded`).

**POST**
1. Returns `None` to leave the current decision unchanged.
2. A returned decision shall satisfy every POST of §6.1.
3. Shall not raise for an unrecognised event type; returns `None`.

**INV**
1. The core applies a returned decision without releasing the session
   (PLT-RAIL-012). A profile that cannot continue shall return `None` and let
   the core's own failure handling run.
2. Invocations for one session are serialised. Ordering across sessions is not
   guaranteed.
3. Path transfer shall complete within the §16 bound of PLT-SRS
   (PLT-NFR-005), which bounds this hook's budget in turn.

---

## 7. IF-IWF — InterworkingGateway

### 7.1 `route(request, resolution) -> Optional[InterworkingRoute]`

**PRE** IF-IDR has succeeded.

**POST**
1. `None` → the session is wholly internal. This is the common case and shall
   be cheap.
2. A returned route names a gateway reachable in this deployment.
3. Shall not raise for a target it does not recognise; returns `None`.

**INV** A profile with no interworking returns `None` always, and is valid
(PLT-HOK-052).

### 7.2 `map_inbound(foreign) -> SessionRequest`

**PRE** `foreign` originates from a trusted, authenticated gateway.

**POST**
1. Returns a `SessionRequest` whose `call_type` and `application` are declared
   in the profile.
2. `initiator` is within a declared domain.
3. Raises on a request that cannot be mapped. The core rejects it; it does not
   guess.

**INV**
1. An inbound mapped request re-enters the normal path at IF-IDR. It receives no
   privilege from having come through a gateway.
2. Priority asserted by a foreign system is advisory. IF-PRI decides, from the
   mapped request (PLT-SEC-010).

---

## 8. Invocation sequences

### 8.1 Session establishment — normal

```
1  IF-IDR.resolve(target, request)              → Resolution
2  IF-IWF.route(request, resolution)            → InterworkingRoute
      ── ONLY when resolution.kind is EXTERNAL ──
      ── if it returns None: refuse `gateway-unavailable`, stop ──
3  IF-PRI.evaluate(request, resolution)         → PriorityDecision
4  IF-SES.admit(request, resolution, priority)  → Admission
   ── if not permitted: reject, stop ──
5  IF-SES.decide(request, resolution)           → SessionDecision
6  IF-SES.floor_policy(request, resolution)     → FloorPolicy   [voice/video only]
7  IF-BER.select(request, priority, media)      → BearerDecision
8  core: reserve QoS, establish, then EITHER
        invite the resolved member set (local), OR
        invite the gateway alone (EXTERNAL) — never both
```

**Step 2 is conditional (changed in v0.2).** In v0.1 `route` was invoked on
every session, after `resolve`. That made interworking unreachable: an external
target is precisely what the identity resolver cannot resolve, so the sequence
died at step 1 with `unknown-target` and IF-IWF was never called. The hook was
dead code, and its unit tests passed only by calling `route()` directly.

A resolver now reports a foreign target as `ResolutionKind.EXTERNAL`, which:

1. makes "this call leaves the MC domain" an explicit, auditable resolution
   outcome rather than something inferred from a hook's return value;
2. costs a local session nothing, since IF-IWF is not consulted at all;
3. forces step 8 to branch, so a routed session can no longer be established
   locally *and* routed out — which v0.1 permitted and left unspecified.

Ordering is fixed (ICD-GEN-032). Each step may assume its predecessors
succeeded. If any raises, the sequence stops and the session fails; no
compensating call is made to hooks already invoked.

### 8.2 Pre-emption

```
1  steps 1–4 of §8.1 for the incoming session
2  core: select candidate victims from active sessions
3  for each candidate: IF-PRI.compare(incoming, candidate)
      compare ≤ 0                              → not a victim
      different scope (compare == 0)           → not a victim
      incoming.preemption_capability == False  → no pre-emption at all
      candidate.preemption_vulnerability False → not a victim
4  core: release victims with the pre-emption cause; audit both decisions
5  continue at step 5 of §8.1
```

The core never calls IF-PRI on the victim's behalf; each session's decision was
taken at its own admission and is retained for exactly this comparison.

### 8.3 Emergency upgrade

An in-progress upgrade (PLT-CC-007) is a new admission over the existing
session: IF-PRI and IF-SES are re-invoked with the new call type; IF-IDR is not.
The member set is preserved. If the new admission is refused, the session
continues unchanged at its original priority.

### 8.4 Path event

```
1  core: detect path event
2  IF-BER.on_path_event(session_id, event)
3  None            → no change
   BearerDecision  → apply, re-reserve QoS, continue session
```

---

## 9. Reason codes

Reason codes are profile-declared (PLT-PRF-004) but drawn from a core-reserved
namespace for conditions the core itself originates. Profiles may add their own;
they may not redefine these.

| Code | Origin | Meaning |
|---|---|---|
| `unknown-target` | IF-IDR | Target does not exist in any form |
| `no-binding` | IF-IDR | Functional identity exists, currently unheld |
| `no-location-binding` | IF-IDR | Location-dependent identity, no usable location |
| `resolver-unavailable` | IF-IDR | Resolver backing store unreachable |
| `not-authorised` | IF-IDR, IF-SES | Caller may not perform this action |
| `capacity-exhausted` | IF-SES | Admission refused on capacity |
| `call-type-not-permitted` | IF-SES | Call type not available to this initiator |
| `recording-unavailable` | core | Recording required, recorder unavailable |
| `qos-unavailable` | core | Network refused the requested QoS |
| `gateway-unavailable` | core | Target is external, no gateway route produced |
| `hook-timeout` | core | Hook exceeded its deadline |
| `hook-error` | core | Hook raised |
| `hook-contract-violation` | core | Returned value failed a POST check |

`hook-contract-violation` is distinguished from `hook-error` deliberately: the
first indicates a profile defect and should be alertable, the second may be an
environmental condition.

---

## 10. Versioning

| ID | Rule |
|---|---|
| ICD-VER-001 | This interface is versioned independently of the core and of profiles. |
| ICD-VER-002 | The loader verifies that each profile declares an interface version it supports, and refuses to start otherwise (PLT-PRF-013). |
| ICD-VER-003 | Adding an optional field to a parameter object is a minor change. Adding a method, adding a required field, or tightening a POST is a major change. |
| ICD-VER-004 | A major change requires every in-tree profile to be updated in the same change set. There is no compatibility shim. |
| ICD-VER-005 | Interface changes are recorded in §11 with their rationale. Growth in hook surface is the leading indicator of a misplaced boundary and is reviewed as such. |

---

## 11. Open points

| # | Question | Needed by |
|---|---|---|
| ICD-OP-01 | Is IF-IDR's 50 ms budget achievable against a real binding store under load, or does resolution need a cache with an explicit staleness bound? | R1 exit |
| ICD-OP-02 | Should `bind` on a held single-holder identity replace or refuse? Operationally significant for driver handover; confirm against UIC FRS. | R3 start |
| ICD-OP-03 | Does any profile need pre-emption between scopes under an explicit bridging policy, or is the unconditional bar permanent? | R3 start |
| ICD-OP-04 | Does IF-BER need a release/teardown call, or is path release wholly core-owned? | R3 start |
| ICD-OP-05 | Confirm that no profile requires a floor-control transition change (§5.3 INV-2). If one does, the core state machine is wrong. | R2 exit |
| ICD-OP-06 | Floor control across a gateway: TETRA and P25 PTT models do not map cleanly onto 24.380 grant, queue, override and revoke. Decide which are unsupported over IF-IWF rather than discovering it at interop. | R4 start |
| ICD-OP-07 | Media anchoring for a routed session: does the platform stay in the media path or hand off to the gateway? Affects recording obligations (PLT-OAM-008) for interworked calls. | R4 start |

---

## 12. Revision history

| Version | Date | Change |
|---|---|---|
| 0.5 | 2026-09-24 | ICD-SIG-006: `MCX_STRICT_RELEASE` decides whether a call type the release cannot carry is fatal at startup (REL-OP-02). |
| 0.4 | 2026-09-24 | §2.6 added: call-type signatures declared in the profile (ICD-SIG-001 to 007). Before this, the core read call type, target, application and urgency from `<mcptt-call_type>`, `<mcptt-target>`, `<mcptt-application>` and `<mcptt-urgency>`, elements that do not exist in TS 24.379 (PLT-CONF-AUDIT CA-20). All three in-tree profiles updated in the same change set. |
| 0.3 | 2026-09-19 | Added IF-ICX (interconnection with partner MC systems) as a sixth hook, with `ResolutionKind.PARTNER`, `partner-unavailable` and `partner-not-permitted`. Scope mapping is label-keyed, ceiling-capped and default-deny; a partner never introduces a scope and is always locally pre-emptible. |
| 0.2 | 2026-09-19 | §8.1 step 2 made conditional on `ResolutionKind.EXTERNAL`; step 8 branches between local fan-out and gateway routing; `EXTERNAL` added to §3.2 POST-1; `gateway-unavailable` added to §9; ICD-OP-06 and ICD-OP-07 opened. Fixes the defect that made IF-IWF unreachable. |
| 0.1 | 2026-09-19 | Initial draft |
