# Profile hook interfaces — Interface Control Document

**Document:** PLT-ICD-001
**Version:** 0.13 (draft)
**Date:** 2026-09-25
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

### 2.7 Ring limit (declared data, not a hook)

How long an invited member may be alerted before the core gives up on it is
service policy, and differs by call type. So each `call_types[]` entry
declares it. Adopted 2026-09-24 (PLT-VP-R1 SIP-OP-15). Before this, the limit
was 32 s for every call type, because that is 64·T1 (RFC 3261 Timer B), a
transport constant nobody chose.

```yaml
no_answer_s: 32        # seconds an invited member may ring
```

| ID | Rule |
|---|---|
| ICD-RNG-001 | `no_answer_s` is required on every call type: an integer of at least 1 second, with no default and no upper bound. An absent key, a non-integer (booleans included) or a value below 1 is a load error. |
| ICD-RNG-002 | The limit is counted from the INVITE the core sends each member. When the member's first provisional response arrives, the INVITE enters 'Proceeding' and Timer B stops (RFC 3261 17.1.1.2). The deadline is then the limit. If the limit expires while the member rings, the core CANCELs that member (9.1). |
| ICD-RNG-003 | A member that has sent no provisional ('Calling') is still ended by Timer B at 64·T1, whatever the limit, because a CANCEL may not be sent before a provisional (9.1). A limit longer than 64·T1 therefore applies only to members that ring. |
| ICD-RNG-004 | A member that reaches the limit counts as failed for the call. The call fails only if no other member is still invited or answered (the existing rule). |

All three in-tree profiles declare 32 for every call type, which keeps the
previous behaviour. The value per call type is the profile owner's choice.


### 2.8 Network profile (deployment data, not a hook and not the service profile)

Some facts belong to the network a deployment runs in, not to the service:
which PLMNs it is, which cell stands for which location attribute, and which
SIP cores may assert identities for their users. They change when the radio
plan or the core changes, not when the service does. They live in one file,
the network profile, named by `MCX_NETWORK_FILE` (required, no default) and
checked at startup against the loaded service profile. Adopted 2026-09-25
(PLT-VP-R1 NET-OP-01). It replaces `MCX_CELLS_FILE` (PRF-OP-03) and
`MCX_SIP_TRUSTED_PEERS` (ICD-OP-08), and closes ICD-OP-10.

```yaml
name: rail-ops
version: "3"                          # a string: quote numbers
plmns: ["001010"]                     # MCC then MNC, six digits (tPlmnIdentityFormat)
cells:                                # [] when there is no cell map
  - {cell: "0010100000000000000000000100100011", location: {track_section: S1}}
sip:
  trusted_cores: [core1.rail.example] # [] when no core is trusted
  core_ca: core-ca.pem                # "none" when no core is trusted
```

| ID | Rule |
|---|---|
| ICD-NET-001 | Every key above is required, and no other is accepted. An empty list or `none` is how a deployment says it has nothing there. `name` and `version` are strings of letters, digits, `.`, `_` and `-`. `plmns` is a non-empty list of distinct six-digit PLMN identities. Any defect refuses startup, and all defects are reported together. |
| ICD-NET-002 | The file and the core CA certificate are hashed together (SHA-256 over the canonical form, as PLT-PRF-011 does for the service profile). `name/version/hash[:16]` is the network identifier. It joins the service profile identifier and the release in every audit record (`<profile>+<release>+<network>`, extending PLT-REL-005) and appears in the health document. |
| ICD-NET-003 | `trusted_cores` lists fully qualified DNS names. A non-empty list needs `core_ca`: a file, relative to the network profile, holding exactly one certificate, and only CERTIFICATE PEM blocks. The core CA must be self-signed, have `pathLenConstraint` 0, have keyCertSign if it has keyUsage, and be valid at startup. When SIP is enabled it must not share a key or a subject name with any CA in `MCX_SIP_TLS_CA` (which also may hold only CERTIFICATE blocks), and must not have issued any of them. |
| ICD-NET-004 | The TLS listener trusts the core CA certificate as parsed and hashed at startup, not the file re-read. A peer is a trusted core when the core CA issued its certificate directly and the certificate carries a DNS name in `trusted_cores`. It may then assert any identity (RFC 3325 trust domain). A peer whose certificate the core CA issued asserts nothing else: no URI in it is a user's identity, so a core removed from the list asserts nothing at all. |
| ICD-LOC-001 | Each `cell` is an ECGI (6 digits then 28 binary digits) or an NCGI (6 digits then 36 binary digits), as annex F.3 writes them. Its first six digits must be one of `plmns`. Each `location` key must be the `location_key` of some functional identity in the loaded service profile, and a cell may appear once. |
| ICD-LOC-002 | The core reads the serving cell from the report. It prefers the NCGI, which Rel-18 carries in `<anyExt>`, to the ECGI. The cell becomes `LocationContext.cell_id`. Neighbour cells, coordinates and the rest are not read. |
| ICD-LOC-003 | A location is advisory, never a reason to refuse. A missing, malformed or non-report body, a DOCTYPE, or a cell sent with `type="Encrypted"` (the platform holds no key, F.3.3) all leave the request without a location. |
| ICD-LOC-004 | Before step 1 of §8.1, the core adds the mapped attributes of a reported cell to the request's location. Attributes the request already carries are kept, and an unmapped cell adds nothing. |
| ICD-LOC-005 | *Superseded by ICD-NET-001.* `cells` is always required, so every deployment states its map, or `[]`. Before 0.12 `MCX_CELLS_FILE` was required only when the service profile had location-dependent identities. |

The **core CA must issue only core certificates**. The platform cannot check
this. A core CA that also issues other certificates makes those holders cores
if they carry a listed name.

**Deployment requirements that follow**:
- The core CA's private key is as sensitive as the ability to assert any
  identity. Whoever holds it can make a core.
- `MCX_CELLS_FILE` and `MCX_SIP_TRUSTED_PEERS` are refused if set, rather than
  ignored, so an operator who sets one learns that it no longer applies.

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

Read-only. Returns the identities a user currently holds, for display and
audit, and, from v0.7, for admission. The core passes the initiator's
identities as `attributes["initiator.roles"]` (comma-separated), for call
types that restrict who may start them (`initiator_roles`). It looks them up
at §8.1 step 0 (step 4a before v0.13), and every hook from IF-SES `authorise`
onward sees them. The core always writes that attribute itself, so a request
cannot supply it. Returns an empty sequence for a user holding none,
and does not raise for an unknown user.

Before v0.7 nothing supplied `initiator.roles`, so every call type that
declared `initiator_roles` refused every caller: all three FRMCS call types
that restrict their initiators were unreachable. See §11 ICD-OP-08 for what
this now depends on.

### 3.5 `determine_participants(criteria, request) -> Resolution` (added in v0.7)

An ad hoc group call (TS 24.379 clause 17, Rel-18 onwards) names no group.
The caller either lists the users (an RFC 5366 URI list) or describes them
with criteria (`<call-participants-criterias>`, "a comma separated list",
17.2.2.1.1 item 12). The server then determines who meets them "based on
the local policy" (17.4.2.2 step 12 ii). What a criterion means is
profile knowledge, so it is a hook. `SessionRequest` gains
`adhoc`, `participants`, `participant_criteria` and `adhoc_alert_group`.

**PRE**
1. `request.adhoc` is true and `criteria` is the caller's string, uninterpreted.

**POST**
1. Returns a `GROUP` resolution with at least one member, no duplicates, and
   `group_id` None. The ad hoc group identity is the controlling function's
   to generate (17.4.2.2 step 10), and the core does so.
2. If nobody meets the criteria, or a criterion is not understood, raises with
   `adhoc-participants-undetermined`. A profile with no criteria vocabulary
   always raises.

**What the core does around it (§8.1 step 1, ad hoc variant)**, in the order of
17.4.2.2 (Rel-18 numbering):

| ID | Rule |
|---|---|
| ICD-ADH-001 | A list longer than the call type's `max_participants`, or longer than the deployment's cap (`MCX_ADHOC_LIST_MAX`, required, no default; v0.8), is refused `adhoc-too-many-participants` (warning 189, step 6). The caller is not counted. Both checks come before any entry is resolved. Criteria that find more members than the call type's limit are refused the same way; the deployment cap is on lists only. |
| ICD-ADH-002 | A list and criteria together (step 7), a call following an ad hoc emergency alert (step 7A: this platform keeps no alert groups), and a request with neither are refused `adhoc-participants-undetermined` (warning 187). |
| ICD-ADH-003 | Each listed entry is resolved with `resolve`. Entries that yield no user are left out: unknown, outside the domains, a group, or an unheld or location-less functional identity. `resolver-unavailable` still fails the call. If nobody is left, the refusal is 187. The caller is never a member. |
| ICD-ADH-004 | The core generates the ad hoc group identity (`sip:adhoc-<hash>@<first profile domain>`). It travels as `<mcptt-calling-group-id>` in each member's INVITE (17.4.2.1.1 item 4b) and in the 200 OK to the caller (17.4.2.2). Criteria, when used, travel in both as well (item 4c). |
| ICD-ADH-005 | Ad hoc handling exists only where the configured release has the `adhoc` session type (Rel-18). Before that, the request takes the ordinary path. |

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

### 5.0 `authorise(request) -> Admission`

Whether this initiator may start this call type at all. Added in v0.13
(ICD-OP-09). Called at §8.1 step 0, before anything about the called party is
looked up, so the answer to an unauthorised caller does not depend on the
target. TS 24.379 17.4.2.2 orders ad hoc calls the same way: it authorises the
user and the service in steps 4 and 5, and only then checks the list (step 6)
and determines who to call (step 12).

**PRE** The core has written the initiator's roles to
`request.attributes["initiator.roles"]` (§3.4), replacing any value the
request carried.

**POST**
1. Returns `Admission`. Refusal is a return value, never an exception.
2. `permitted=True` → `reason_code` is the empty string.
3. `permitted=False` → `reason_code` is a member of the profile's declared
   `reject_reason_codes`.
4. The core checks POST-2 and POST-3 itself, for `authorise` and `admit`
   alike. A violation fails the session with `hook-contract-violation`.

**INV**
1. The answer cannot depend on the called party. This is enforced by
   construction: the core passes a copy of the request with `target`,
   `participants`, `participant_criteria` and `adhoc_alert_group` emptied.
   The initiator, call type, media, application, urgency, location and
   attributes remain.
2. Anything that depends on the called party (participant limits, capacity
   per group, the partner's rights) belongs to `admit` or later.

The in-tree `TableSessionPolicy` refuses an undeclared call type with
`call-type-not-permitted` and an initiator holding none of the call type's
`initiator_roles` with `not-authorised`. Both checks were in `admit` before
v0.13.

**Deviation, deliberate.** For prearranged group calls, TS 24.379 10.1.1.4.2
looks the group up first (404, warning 163 "group does not exist") and only
then authorises the user (403, warning 119). The platform authorises first for
every call type. This is stricter: an unauthorised caller cannot learn which
groups exist either.

### 5.1 `admit(request, resolution, priority) -> Admission`

**PRE** `authorise` permitted this request, and IF-IDR and IF-PRI have both
succeeded for it. An `admit` given a call type the profile does not declare
may raise `HookContractViolation`. The in-tree policy does.

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
0  IF-IDR.identities_of(initiator)             → the initiator's roles (§3.4)
0  IF-SES.authorise(request without target)     → Admission   (v0.13, §5.0)
   ── if not permitted: reject, stop — nothing about the target looked up ──
1  IF-IDR.resolve(target, request)              → Resolution
      ── ad hoc (§3.5): IF-IDR.resolve per listed entry, OR
         IF-IDR.determine_participants(criteria, request) ──
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
1  steps 0–4 of §8.1 for the incoming session
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
| `adhoc-participants-undetermined` | core, IF-IDR | Ad hoc participants cannot be determined (TS 24.379 warning 187) |
| `adhoc-too-many-participants` | core | Ad hoc participants over the call type's limit (warning 189) |

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
| ICD-OP-08 | **CLOSED 2026-09-25 in its R1 form (decided: certificate identity plus trusted cores).** A request may assert only an identity its TLS connection authenticated (PLT-IDM-004 without OpenID Connect, which is R2). A peer whose verified certificate carries a DNS name listed in `MCX_SIP_TRUSTED_PEERS` (required, no default; `none`, or fully qualified names; since v0.12 `sip.trusted_cores` in the network profile, §2.8) is a SIP core that authenticated its users itself, and may assert any identity (RFC 3325 trust domain). Every other peer may assert only a `sip:` URI in its certificate's subjectAltName. The check runs on REGISTER (the AoR) and INVITE (the initiator, from P-Asserted-Identity or From), and a mismatch is 403 `identity-not-authenticated`. The scheme and host are compared without case and the user part exactly (RFC 3261 19.1.4). The independent review found that binding identity alone left calls open to other peers, so a dialog is now also bound to the connection it was set up on: a response must arrive on its request's connection and carry its Call-ID; branches are unguessable; a BYE for the call must come from the caller's connection with the caller's tag, and a BYE for a leg from that leg's connection; an ACK must come on its INVITE's connection, and so must a CANCEL; and a new INVITE may not reuse a live call's Call-ID. **Deployment requirements that follow**, which the platform cannot check: a trusted core must itself authenticate every user and police P-Asserted-Identity (strip it from untrusted sources); and core certificates must come from a CA that issues trusted DNS names only to cores (see ICD-OP-10). The interop Kamailio meets neither: it tests the trust mechanism, not a secure core. Originally: **From v0.7.** Admission now authorises on `initiator.roles`, and the initiator is taken from P-Asserted-Identity or From. PLT-IDM-004 (bind the authenticated identity to the request) is not enforced on the SIP path, so on a direct TLS connection a caller can assert someone else's identity and so their roles. Before v0.7 the role check failed closed for everyone, so the exposure is new in effect, but the weakness is older. Resolving it is PLT-IDM-004 work: bind the TLS client identity to the registered AoR. | closed |
| ICD-OP-09 | **CLOSED 2026-09-25 (decided: a new hook method, IF-SES `authorise`).** Authorisation is §8.1 step 0, after the core looks up the initiator's roles and before any target lookup (§5.0). The request `authorise` sees has the called party removed, so an unauthorised caller gets the same refusal whatever it calls: an existing or unknown user, a held or unheld role, criteria matching someone or no one, and a list over the limit. The core writes `initiator.roles` once, and every later hook sees that value. The independent review found no remaining oracle. It found three things, all fixed: `admit` crashed on an undeclared call type; later hooks still saw roles the client supplied; and the documents were not updated. It also found the two open points below. Originally: **From v0.7.** Resolution runs before admission (§8.1), so an unauthorised caller can tell "nobody matches" (187, 404) from "not allowed" (403, 100), and learn whether a user exists or a role is currently held. TS 24.379 17.4.2.2 authorises first (steps 4 and 5). The same was true for prearranged groups before ad hoc calls existed. | closed |
| ICD-OP-10 | **CLOSED 2026-09-25 (decided: a separate CA for cores, in the network profile).** The core CA is named by the network profile (§2.8), must be a self-signed root with `pathLenConstraint` 0, and must be kept apart from the users' anchors in `MCX_SIP_TLS_CA` (by key, by name, and by issuance). A trusted core needs both a certificate the core CA issued directly and a listed DNS name, and a certificate the core CA issued asserts no user identity (ICD-NET-003, -004). The independent review found three defects in the first version, all fixed before delivery: an intermediate under the users' root was accepted as the core CA; a TRUSTED CERTIFICATE block in the core CA file became an anchor unchecked and unhashed; and core-CA certificates could also authenticate user URIs. Originally: **From v0.9.** SIP cores and users share one trust anchor (`MCX_SIP_TLS_CA`). A core is recognised by a DNS name in its certificate, so any certificate from that CA carrying the name is trusted. That includes a user certificate, if enrolment lets a user choose DNS names. | closed |
| ICD-OP-11 | **From v0.9.** The inbound guard records a request's (Call-ID, CSeq) before the identity check runs. A refused, spoofed request therefore uses up that pair, and a genuine request that later carries the same pair is answered 482. This matters only if Call-IDs can be predicted. | R2 |
| ICD-OP-12 | **From v0.12.** TS 24.379 annex F.3 writes a PLMN as six digits (`\d{3}\d{3}`), and the ECGI and NCGI start with them. It does not say how a two-digit MNC fills three digits. The network profile's `plmns` must therefore be written exactly as the deployment's clients write the first six digits of a cell. Confirm against TS 23.003 and the client implementations before a network with a two-digit MNC is configured. | before a two-digit-MNC deployment |
| ICD-OP-13 | **From v0.13.** A request relayed by a gateway (§7.2) has two weaknesses. (1) Its audit trail records `session-admitted` before §8.1 runs, so a request refused at step 0 shows "admitted" and then "refused". (2) The gateway may name a local user as the initiator, and step 0 then authorises it with that user's roles. The gateway's word is taken for who is calling. Both predate v0.13. The remedy for the second is to authorise gateway-originated requests on the gateway's own rights. | R4 start |

---

## 12. Revision history

| Version | Date | Change |
|---|---|---|
| 0.13 | 2026-09-25 | Major change (ICD-VER-003): IF-SES gains `authorise(request)` (§5.0), called at §8.1 step 0 with the called party removed from the request. The roles lookup moves from step 4a to step 0. `admit`'s PRE now includes a successful `authorise`. The core checks POST-2 and POST-3 of both methods. All in-tree profiles implement it in the same change set: the call-type and role checks move from `admit` to `authorise`. §8.2 step 1 now reads steps 0–4. ICD-OP-09 closed; ICD-OP-13 opened. |
| 0.12 | 2026-09-25 | §2.8 becomes the network profile (`MCX_NETWORK_FILE`, NET-OP-01): PLMNs, the cell map, and the trusted SIP cores with a CA of their own (ICD-NET-001 to 004; ICD-LOC-001 gains the PLMN check; ICD-LOC-005 superseded). The network identifier joins the audit identity. ICD-OP-10 closed; ICD-OP-12 opened. `MCX_CELLS_FILE` and `MCX_SIP_TRUSTED_PEERS` are withdrawn and refused. A minor change: no hook or parameter object changes. |
| 0.11 | 2026-09-25 | §2.8: the cell map is deployment data (`MCX_CELLS_FILE`), not a profile section (PRF-OP-03). It is required when the profile has location-dependent identities (ICD-LOC-005). The profile schema is back to what it was before 0.10. |
| 0.10 | 2026-09-25 | §2.8 added: the cell map `identity.cells` (ICD-LOC-001 to 004). The core reads the client's location report (annex F.3) and applies the map, so location-dependent identities resolve from a native client's call. A minor change: an optional profile section, and no hook change. |
| 0.9 | 2026-09-25 | ICD-OP-08 closed in its R1 form: certificate identity plus trusted cores (`MCX_SIP_TRUSTED_PEERS`), and each dialog bound to its connection. ICD-OP-10 (shared trust anchor) and ICD-OP-11 (guard order) opened. The ICD surface is unchanged; this is a host requirement. |
| 0.8 | 2026-09-25 | ICD-ADH-001: the deployment-wide list cap `MCX_ADHOC_LIST_MAX` (PLT-VP-R1 ADHOC-OP-04). A minor change: no hook or parameter object changes. |
| 0.7 | 2026-09-25 | Major change (ICD-VER-003): IF-IDR gains `determine_participants` (§3.5). `SessionRequest` gains the ad hoc fields. §8.1 gains the ad hoc variant of step 1 and step 4a (`identities_of`, whose result admission now reads, §3.4). §9 gains two reason codes. All in-tree profiles implement the method in the same change set: the directory resolver refuses criteria, and the functional resolver matches functional identities. ICD-OP-08 and ICD-OP-09 opened. |
| 0.6 | 2026-09-24 | §2.7 added: the ring limit `no_answer_s`, required on every call type (ICD-RNG-001 to 004). It replaces the fixed 64·T1 limit (PLT-VP-R1 SIP-OP-15). All three in-tree profiles updated in the same change set, at 32 s. |
| 0.5 | 2026-09-24 | ICD-SIG-006: `MCX_STRICT_RELEASE` decides whether a call type the release cannot carry is fatal at startup (REL-OP-02). |
| 0.4 | 2026-09-24 | §2.6 added: call-type signatures declared in the profile (ICD-SIG-001 to 007). Before this, the core read call type, target, application and urgency from `<mcptt-call_type>`, `<mcptt-target>`, `<mcptt-application>` and `<mcptt-urgency>`, elements that do not exist in TS 24.379 (PLT-CONF-AUDIT CA-20). All three in-tree profiles updated in the same change set. |
| 0.3 | 2026-09-19 | Added IF-ICX (interconnection with partner MC systems) as a sixth hook, with `ResolutionKind.PARTNER`, `partner-unavailable` and `partner-not-permitted`. Scope mapping is label-keyed, ceiling-capped and default-deny; a partner never introduces a scope and is always locally pre-emptible. |
| 0.2 | 2026-09-19 | §8.1 step 2 made conditional on `ResolutionKind.EXTERNAL`; step 8 branches between local fan-out and gateway routing; `EXTERNAL` added to §3.2 POST-1; `gateway-unavailable` added to §9; ICD-OP-06 and ICD-OP-07 opened. Fixes the defect that made IF-IWF unreachable. |
| 0.1 | 2026-09-19 | Initial draft |
