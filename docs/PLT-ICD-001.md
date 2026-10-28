# Profile hook interfaces — Interface Control Document

**Document:** PLT-ICD-001
**Version:** 0.36 (draft)
**Date:** 2026-10-28
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
| ICD-GEN-001 | A hook shall not mutate any object it receives. All parameter objects are frozen, and hold nothing mutable: every value type derives from `core.hooks.Value`, which on construction replaces each field by a copy with nothing mutable in it at any depth (`core.hooks.freeze`: mappings become read-only `FrozenDict`s, lists and tuples tuples, sets frozensets; anything that is not a scalar, an enum, a frozen Value or one of these is refused). A field declared as a sequence refuses a string, a set or a mapping and takes any other iterable as a tuple. A mapping the core passes to a hook as an argument (IF-IWF `map_inbound`) is a read-only copy too. Since v0.18 (PLT-VP-R1 RES-OP-06); before, a frozen value's dict could be changed in place. |
| ICD-GEN-002 | A hook shall not retain a reference to a parameter object beyond the call. |
| ICD-GEN-003 | A hook shall not call into the core, directly or by any callback. |
| ICD-GEN-004 | A hook shall not block on network I/O on the session-establishment path except where §3 explicitly permits it (IF-IDR only). |
| ICD-GEN-005 | IF-PRI, IF-SES and IF-BER shall be pure functions of their inputs and the immutable loaded profile: same inputs, same outputs, for the process lifetime. |
| ICD-GEN-006 | IF-IDR is explicitly *not* pure: binding state changes over time. Its results shall be treated as valid only for the session that requested them. |

### 2.2 Timing

| ID | Rule |
|---|---|
| ICD-GEN-010 | The core shall apply a deadline to every hook invocation. Default budgets: IF-IDR 50 ms, IF-PRI 5 ms, IF-SES 5 ms, IF-BER 10 ms, IF-IWF 20 ms, IF-ICX 20 ms. (Before v0.20 the core applied none to IF-ICX, and called IF-ICX `map_outbound` and IF-PRI `compare` outside its invocation boundary, unaudited and without a deadline.) |
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
| ICD-GEN-041 | Returned decisions shall be recorded in full. A decision absent from the audit trail cannot be relied on in a safety case. **Since v0.20** (PLT-VP-R1 RES-OP-02): each invocation's record carries `returned`, every field of what the hook returned as plain data, whether the value was used or refused by its POST check; a hook that raised, or timed out under an enforced deadline, returned nothing, and nothing is recorded (an overrun measured after the call returned is recorded as usual). Only exact types are rendered: the value classes and enums of `core/hooks.py`, `str`, `int`, `bool`, `None`, a finite `float`, and dicts with string keys, tuples, lists and frozensets of these. Anything else, a subclass included, could show the audit one thing and the core another, or run the profile's code inside the audit, so a value holding one is refused as `hook-contract-violation`: the core never acts on a decision the trail does not hold exactly. Free-form maps such as a path's `attributes` are recorded like any other field, so a profile shall not put key material or credentials in them (PLT-SEC-009). |
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
| ICD-SIG-003 | No two call types in a profile may declare the same signature (`ambiguous-signature`). The core does not guess which one a client meant. A call type declared `group_selected: true` (ICD-SIG-008) is not counted: it is never chosen by its signature alone. |
| ICD-SIG-004 | The core selects the call type whose signature equals the request's exactly, and only if the configured release has that session type (`core/release.py`). Otherwise `call_type` is `""` and IF-SES refuses. |
| ICD-SIG-005 | The core renders the same signature into the INVITE it sends each invited member, together with `<mcptt-request-uri>`, `<mcptt-calling-user-id>` and `<mcptt-calling-group-id>` (TS 24.379 6.3.2.2.3 item 8, 10.1.1.4.1.1 item 4). |
| ICD-SIG-006 | At startup the core reports call types declared `null` and call types whose signature the configured release cannot carry, in the log and in the health document. Whether the second case is fatal is the deployment's stated choice, `MCX_STRICT_RELEASE` (required, no default): `true` refuses to start and names the call types; `false` starts and warns (REL-OP-02, decided 2026-09-24). |
| ICD-SIG-007 | `SessionRequest.application` and `urgency` are never taken from a native request, because TS 24.379 has no element for either. They come from the call type's declaration. |
| ICD-SIG-008 | A call type TS 24.379 cannot tell apart from another may be chosen by the target group (PLT-VP-R1 PRF-OP-01, decided 2026-10-22). It declares `group_selected: true` (optional, default false) with the signature a call to the group carries. That signature must be a call to a group (`prearranged` or `chat`) and must be declared by exactly one call type that is not group-selected, which every other group's calls get; otherwise, or without a signature, the profile does not load. A group in the network profile names it with `call_type` (ICD-NET-005). A call whose `<mcptt-request-uri>` is that group (compared exactly, as the resolver compares it) and whose signature equals that call type's exactly is that call type; any other call to the group (an emergency one, a private one) is what its signature says, and a group naming no call type changes nothing. The call type is then subject to everything a call type is: its initiator roles at `authorise`, its limits and its floor. Its members' INVITEs carry its signature (ICD-SIG-005). The health document's `call_types.selected_by_group` lists each group-selected call type with the groups that name it (beside ICD-SIG-006's report), and one no group names is warned of at startup. Two consequences, accepted: a caller without the call type's role is refused `not-authorised` calling the group but `unknown-target` calling a group that does not exist, so a group's group-selected call type shows through the refusal (an exception to §5.0's same-refusal property, which holds for a given call type); and a request through IF-IWF names its call type itself and is not subject to the group's choice. |

### 2.7 Ring limit (declared data, not a hook)

How long an invited member may be alerted before the core gives up on it is
service policy, and differs by call type. So each `call_types[]` entry
declares it. Adopted 2026-09-24 (PLT-VP-R1 SIP-OP-15). Before this, the limit
was 32 s for every call type, because that is 64·T1 (RFC 3261 Timer B), a
transport constant nobody chose.

```yaml
no_answer_ms: 32000    # milliseconds an invited member may ring
# or: no_answer_s: 32  # in seconds (PLT-GEN-011)
```

| ID | Rule |
|---|---|
| ICD-RNG-001 | Every call type states the limit as `no_answer_ms` (an integer number of milliseconds, at least 1000), or `no_answer_s` (an integer number of seconds, at least 1), or both (PLT-GEN-011 as amended); no default and no upper bound. Neither key, a non-integer (booleans included) or a value below its minimum in either key stated is a load error. With both, `no_answer_ms` is used; if it is not `no_answer_s` × 1000, the disagreement is reported at startup as a warning (log, health document, startup audit record). |
| ICD-RNG-002 | The limit is counted from the INVITE the core sends each member. When the member's first provisional response arrives, the INVITE enters 'Proceeding' and Timer B stops (RFC 3261 17.1.1.2). The deadline is then the limit. If the limit expires while the member rings, the core CANCELs that member (9.1). |
| ICD-RNG-003 | A member that has sent no provisional ('Calling') is still ended by Timer B at 64·T1, whatever the limit, because a CANCEL may not be sent before a provisional (9.1). A limit longer than 64·T1 therefore applies only to members that ring. |
| ICD-RNG-004 | A member that reaches the limit counts as failed for the call. The call fails only if no other member is still invited or answered (the existing rule). |

All three in-tree profiles declare 32000 for every call type, which keeps the
previous behaviour. The value per call type is the profile owner's choice.

**Over the participant limit (since v0.22).** Each call type also declares
what happens to a group call whose session decision allows fewer
participants than the group has (§5.2), and each floor policy declares a
pre-emptor's place at a full queue (§5.3 POST-5):

```yaml
group_over_limit: truncate      # or refuse
floor:
  preemption_at_full_queue: deny   # or insert
```

| ID | Rule |
|---|---|
| ICD-LIM-001 | `group_over_limit` is required on every call type, `truncate` or `refuse`, with no default. Anything else, or an absent key, is a load error. |
| ICD-LIM-002 | `floor.preemption_at_full_queue` is required in every floor policy, `insert` or `deny`, with no default. Anything else, or an absent key, is a load error. |
| ICD-LIM-003 | `refuse` and `deny` depart from TS 24.379 6.3.5.5 and TS 24.380 6.3.4.4.7 item 2e respectively. A profile may declare them; the service reports each one at startup (log, health document `deviations`, and the `configuration-accepted` audit record). |

The in-tree profiles declare `truncate` and `deny` everywhere: the decisions
as they stood (PLT-VP-R1 RES-OP-12 ruling 1, FC-OP-07).


### 2.8 Network profile (deployment data, not a hook and not the service profile)

Some facts belong to the network a deployment runs in, not to the service:
which PLMNs it is, which cell stands for which location attribute, and which
SIP cores may assert identities for their users. They change when the radio
plan or the core changes, not when the service does. They live in one file,
the network profile, named by `MCX_NETWORK_FILE` (required, no default) and
checked at startup against the loaded service profile. Adopted 2026-09-25
(PLT-VP-R1 NET-OP-01). It replaces `MCX_CELLS_FILE` (PRF-OP-03) and
`MCX_SIP_TRUSTED_PEERS` (ICD-OP-08), and closes ICD-OP-10. Since 0.16 it also
holds the groups and the known users (PLT-VP-R1 SVC-OP-03, decided
2026-09-26), replacing `MCX_GROUPS_FILE`.

```yaml
name: rail-ops
version: "3"                          # a string: quote numbers
environment: test                     # production, staging, test or dev (ICD-NET-006)
plmns: ["001010"]                     # MCC then MNC, six digits (tPlmnIdentityFormat)
cells:                                # [] when there is no cell map
  - {cell: "0010100000000000000000000100100011", location: {track_section: S1}}
sip:
  trusted_cores: [core1.rail.example] # [] when no core is trusted
  core_ca: core-ca.pem                # "none" when no core is trusted
groups:                               # [] when there is no group
  - id: "grp:alpha"
    display_name: "Alpha team"        # optional; the id when absent
    call_type: coordination-group     # optional: a group-selected call type (ICD-SIG-008)
    members: ["sip:u1@rail.example", "sip:u2@rail.example"]
users: ["sip:u9@rail.example"]         # known users in no group; [] for none
functional_aliases:                   # [] when no user may hold a functional identity
  - id: track-controller              # a functional identity the profile declares for users
    users: ["sip:u1@rail.example", "sip:u2@rail.example"]   # who may activate it
    take_over: ["sip:u2@rail.example"]                      # who of them may take it over
```

| ID | Rule |
|---|---|
| ICD-NET-001 | Every key above is required, and no other is accepted. An empty list or `none` is how a deployment says it has nothing there. `name` and `version` are strings of letters, digits, `.`, `_` and `-`. `plmns` is a non-empty list of distinct six-digit PLMN identities. A key repeated anywhere in the file is refused (YAML would keep the last value silently, so the file reviewed could differ from the file run; the service profile is read the same way since 0.25). Any defect refuses startup, and all defects are reported together. |
| ICD-NET-002 | The file and the core CA certificate are hashed together (SHA-256 over the canonical form, as PLT-PRF-011 does for the service profile). `name/version/hash[:16]` is the network identifier. It joins the service profile identifier and the release in every audit record (`<profile>+<release>+<network>+<environment>`, extending PLT-REL-005; the environment since 0.25) and appears in the health document. |
| ICD-NET-003 | `trusted_cores` lists fully qualified DNS names. A non-empty list needs `core_ca`: a file, relative to the network profile, holding exactly one certificate, and only CERTIFICATE PEM blocks. The core CA must be self-signed, have `pathLenConstraint` 0, have keyCertSign if it has keyUsage, and be valid at startup. When SIP is enabled it must not share a key or a subject name with any CA in `MCX_SIP_TLS_CA` (which also may hold only CERTIFICATE blocks), and must not have issued any of them. |
| ICD-NET-004 | The TLS listener trusts the core CA certificate as parsed and hashed at startup, not the file re-read. A peer is a trusted core when the core CA issued its certificate directly and the certificate carries a DNS name in `trusted_cores`. It may then assert any identity (RFC 3325 trust domain). A peer whose certificate the core CA issued asserts nothing else: no URI in it is a user's identity, so a core removed from the list asserts nothing at all. |
| ICD-NET-005 | `groups` is a list of groups, each with `id` and `members` and optionally `display_name` and `call_type` (since 0.26, ICD-SIG-008: a call type the service profile declares `group_selected: true`, or startup is refused), nothing else. Ids are distinct non-empty strings; a display name is a non-empty string; members are a non-empty list of non-empty strings, deduplicated in declaration order. `users` is a list of non-empty strings, deduplicated. No id may be both a group and a user, and no group may be a member of a group. Every group member is a known user. The groups and users provision the identity resolver (whose declared-domain check, PLT-IDM-008, applies to every member and user) and are the content of the group documents served (VP1-DOC-001). Being registered does not make a user known (PLT-VP-R1 SIP-OP-05, closed 2026-10-26): a REGISTER says where a user can be reached, the network profile says who exists, so a call to a user it does not list is `unknown-target` however the user registered. A caller is checked against the declared domains only, not against this list. A caller whose call is aimed at a group must be one of the group's `members` (since 0.29, PLT-VP-R1 SVC-OP-07; TS 24.379 6.3.5.2 step 5b): otherwise `not-group-member` (§9), whatever the call type, emergency and private included. A gateway that relays group calls (§7.2) needs its mapped callers listed as members. |
| ICD-NET-006 | `environment` is the production indicator of PLT-GEN-005, PLT-IDM-007 and PLT-SEC-008 (PLT-VP-R1 VP-OP-05, decided 2026-10-21): exactly one of `production`, `staging`, `test`, `dev`. Anything but `production` is refused unless every PLMN is a test PLMN: MCC 001 (the test network of the 3GPP test specifications), or 999-999 or 999-99 (ITU-T E.212 (06/2024) Appendix III.2.4, which suggests them for testing under MCC 999; 999-99 is written `999990`, pending ICD-OP-12). MCC 999 otherwise is for internal use within a private network, which may be operational, and codes assigned for testing by a regulator or for trials (E.212 Annex B, A.5.6, Annex G) cannot be told from operational ones, so a network on them runs as production. `production` is accepted on any PLMN. `MCX_ENV` (required, no default, the same four values) must equal it, and `MCX_PRODUCTION`, if set, must be `1`/`true`/`yes` exactly when it is `production` and `0`/`false`/`no` otherwise; any disagreement refuses startup. The environment is in every audit record (ICD-NET-002) and in the health document (`environment`, and `network.environment`). |
| ICD-NET-007 | `functional_aliases` lists, for each functional identity the service profile declares with `resolves_to: user`, the users who may activate it (`users`, known users, at least one) and those of them who may take it over from another holder (`take_over`, a subset, `[]` for none), optionally, for an identity the service profile keys by an identification value (§3.2 PRE-5), the values its users may hold it for (`values`, a non-empty list of patterns of letters, digits, `*` and `?`; absent, any value; since 0.33, FRMCS FRS 8.2.4.3.6), and, optionally for an identity the service profile declares `multiplicity: multi`, how many may hold it at once (`max_holders`, an integer of at least 1; absent, no limit; applied per location value of a location-dependent identity, and per identification value of a keyed one; since 0.32, PLT-VP-R1 FA-OP-01 item 3: TS 24.484 `<max-simultaneous-activations>`; a take-over at the limit displaces the earliest holder to activate, a platform choice: TS 24.379 does not say which): the platform's form of TS 24.484's `<FunctionalAliasList>` and `<allow-takeover-functional-alias-other-user>` (PLT-VP-R1 SVC-OP-06, decided 2026-10-23). Each identity is listed once; any defect refuses startup. A user activates over SIP, from Rel-15 (TS 24.379 clause 9A), an identity keyed by an identification value in its keyed form (§3.2 PRE-5; the identity alone is 403 `functional-alias-not-authorised`): a PUBLISH to the server with `Event: presence`, `Expires: 4294967295` to activate and `0` to deactivate (anything else 423 with `Min-Expires: 4294967295`; another event 489), `<mcptt-request-uri>` naming the user, who must be the one the connection authenticates (else 403 `identity-not-authenticated`), and the TS 24.379 9A.3.1 PIDF body listing the functional aliases wanted, all of them (what is held and not listed is deactivated), with `<take-over>true</take-over>` to take one over. All or nothing: a listed alias the user may not hold is 403 `functional-alias-not-authorised` (with warning 201 from Rel-20); a single-holder alias held by another, or a multi-holder one held by `max_holders` others at the requested location value, is 403 `functional-alias-held`, or, with take-over by one not allowed to, `functional-alias-take-over-not-allowed`; a location-dependent alias is held per value of its location key, taken from the location report the PUBLISH carries (annex F.3, the cell map applied), else from the cell the user last reported on a request, and with neither is 403 `functional-alias-location-unknown`. A PIDF whose `entity` is not the served user is 400. A 200 carries `SIP-ETag` (RFC 3903) and the `Expires` asked. Holders are stored durably, written ahead of the resolver (a store that fails is a 500 with nothing changed), and bound again at start where the network profile in force still allows them (a single-holder identity keeps its earliest stored holder, a multi-holder one its earliest `max_holders`, the store keeping the order holders activated; below Rel-15 the store is left as it is); the health document lists them (`functional_aliases`). Before Rel-15 a PUBLISH is 501 and `Allow` does not name it. A holder whose alias is taken over keeps the calls it is in because of it, or, with `MCX_DISPLACED_HOLDER_CALLS=release` (optional, SIP only, default `keep`; since 0.31), they are released with cause `functional-alias-taken-over`, the whole call: the calls it started as a call type that needs the alias (unless it holds another role the call type accepts) and the calls addressed to the alias that reached it, not an ad hoc call whose participants came from the alias, and never an emergency or imminent peril call (its call type's TS 24.379 indication); only a take-over releases, not the holder's own deactivation. From Rel-15 a user may subscribe to its own functional alias status (since 0.34, PLT-VP-R1 FA-OP-01 item 1; TS 24.379 9A.2.1.3, 9A.2.2.2.4-5): a SUBSCRIBE to the server with `Event: presence`, `<mcptt-request-uri>` naming the user, who must be the one the connection authenticates (else 403 `identity-not-authenticated`), and `<request-type>functional-alias-status-determination</request-type>` in `<anyExt>` (else 400), an `Accept` admitting `application/pidf+xml` if any (else 406), a Contact, and `Expires` 0 to fetch once, up to 4294967295 to subscribe, absent 3600. The 200 carries `Expires` and `Contact`, and a NOTIFY (RFC 6665) follows at once and after every change to what the user is told, carrying the TS 24.379 9A.3.1 per-user PIDF: one `functionalAlias` per alias the user holds (`status="activated"`) and per alias the user may hold and take over that is held as many times as it may be (`status="take-over-possible"`; never for a location-dependent alias), a keyed identity in its keyed form, with the `<p-id-fa>` of the user's own accepted PUBLISH that caused it. A SUBSCRIBE in the dialog refreshes it or, with `Expires: 0`, ends it; at the end a NOTIFY says `terminated;reason=timeout`. At most 8 subscriptions per user (403) and 4096 in all (503); kept in memory, not across a restart. Before Rel-15 a SUBSCRIBE is 501, and `Allow` names SUBSCRIBE from Rel-15. Not implemented: status of another user's aliases (no authorisation is configured for it, so 403), and location-triggered activation (9A.2.1.4, client-side). |
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
- `MCX_CELLS_FILE`, `MCX_SIP_TRUSTED_PEERS` and `MCX_GROUPS_FILE` are refused
  if set, rather than ignored, so an operator who sets one learns that it no
  longer applies.
- A change to the groups or users is a new network identifier: every audit
  record names the group data that was in force.

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
5. Since v0.33 (PLT-VP-R1 FA-OP-01 item 4), a functional identity the profile
   declares with an `identification_key` is keyed by an identification value
   rather than a location, and is written `sip:<value>.<identity>@<domain>`:
   the value alphanumeric, the identity as declared (letters, digits, `-` and
   `_`), the domain one the profile declares (compared without case);
   `core.hooks.keyed_identity` reads it, for the core and a profile alike. A
   target so written names that value's holders; the identity alone is not a
   target (`unknown-target`). An ad hoc criterion so written names that
   value's holders, and the identity alone names every value's holders. A
   user holds one value of an identity at a time (`unbind` names no value).
   An address so written is the identity's: a network profile user, group
   member or group id written so is refused at startup (in any domain), and
   a REGISTER for one is 403 `not-authorised` (review of FA-OP-01 item 4; an
   extension of PLT-IDM-008). The value is compared exactly (`T1` and `t1`
   are two values); `sips:` reads as `sip:`. The `.` and `-` of the form are
   the platform's encoding (FRMCS FRS 6.1.11 asks only that a functional
   identity be alphanumeric), and the FRS Organisation Code is not
   represented: one per deployment, the domain standing for it.

**POST**
1. Returns a `Resolution` whose `kind` is consistent with `members`:
   `USER` → exactly 1; `GROUP` → `group_id` set, ≥ 1 member;
   `BROADCAST_AREA` → ≥ 0 members; `EXTERNAL` → **no** members, and
   `resolved_from` carries the foreign target.
2. `members` contains no duplicates and is stably ordered.
3. Every member is within a domain declared by the profile (PLT-IDM-008): it
   is written `sip:user@host` or `sips:user@host`, with one `@` and no
   parameters, headers or port, and its host is a declared domain (compared
   without case). The core checks this on every result: a member outside is a
   contract violation (`hook-contract-violation`), and the session is refused
   (v0.17, PLT-VP-R1 RES-OP-01).
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

Since 0.27 the core is the only caller, for functional alias management
(ICD-NET-007; TS 24.379 clause 9A): it checks PRE-2 against the network
profile, settles take-over itself (it unbinds the holder it displaces before
it binds the new one, so POST-1's replace-or-raise is never reached), passes
the location value the user's location gave under the identity's location
key, and records every change (`binding-changed`, `binding-refused`). For an
identity keyed by an identification value (§3.2 PRE-5) the value is passed in
`location.attributes` under the identification key, as a location-dependent
identity's value is under its location key: the signature carries no other
place for it (since 0.33). A
resolver that will not go back after a failure part way is followed by the
core's ledger, recorded (`binding-changed` `rollback-incomplete`,
`dropped-on-rollback`), so the two never disagree; a bind that failed is
unbound as well (POST-2), recorded `rollback-uncertain` if that fails too.

**POST**
1. `bind` on a single-holder identity that is already held either replaces the
   existing holder or raises — the profile shall declare which, and shall not
   permit a second concurrent holder.
2. `unbind` for a binding that does not exist is a no-op, not an error.
3. Both operations are atomic with respect to concurrent `resolve`: a resolve
   observes either the old or the new binding, never a partial state.

**INV**
1. Bindings do not affect sessions already established, as far as the hook
   goes. Since v0.31 the service may end them on a take-over:
   `MCX_DISPLACED_HOLDER_CALLS=release` (default `keep`) releases the calls
   the displaced holder is in because of the alias (PLT-VP-R1 FA-OP-01 item
   4; ICD-NET-007).
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
3. Every member is within a declared domain, as in §3.2 POST-3; the core
   checks it (v0.17).
2. If nobody meets the criteria, or a criterion is not understood, raises with
   `adhoc-participants-undetermined`. A profile with no criteria vocabulary
   always raises.

**What the core does around it (§8.1 step 1, ad hoc variant)**, in the order of
17.4.2.2 (Rel-18 numbering):

| ID | Rule |
|---|---|
| ICD-ADH-001 | A list longer than the call type's `max_participants`, or longer than the deployment's cap (`MCX_ADHOC_LIST_MAX`, required, no default; v0.8; a whole number from 1 to 1 000 since v0.36, a larger one refusing startup, because each listed entry is resolved while every other call waits), is refused `adhoc-too-many-participants` (warning 189, step 6). The caller is not counted. Both checks come before any entry is resolved. Criteria that find more members than the call type's limit are refused the same way; the deployment cap is on lists only. |
| ICD-ADH-002 | A list and criteria together (step 7), a call following an ad hoc emergency alert (step 7A: this platform keeps no alert groups), and a request with neither are refused `adhoc-participants-undetermined` (warning 187). |
| ICD-ADH-003 | Each listed entry is resolved with `resolve`. Entries that yield no user are left out: unknown, outside the domains, a group, or an unheld or location-less functional identity. `resolver-unavailable` still fails the call. If nobody is left, the refusal is 187. The caller is never a member. |
| ICD-ADH-004 | The core generates the ad hoc group identity (`sip:adhoc-<hash>@<first profile domain>`). It travels as `<mcptt-calling-group-id>` in each member's INVITE (17.4.2.1.1 item 4b) and in the 200 OK to the caller (17.4.2.2). Criteria, when used, travel in both as well (item 4c). |
| ICD-ADH-005 | Ad hoc handling exists only where the configured release has the `adhoc` session type (Rel-18). Before that, the request takes the ordinary path. |
| ICD-ADH-006 | Before step 0, an ad hoc INVITE carrying `<imminentperil-ind>` (in the clear or encrypted) together with `<adhoc-emergency-ind>` (whatever its value) is refused 403 "150 invalid combinations of data received in MIME body" (17.4.2.2 step 3A, 6.3.3.1.25). This is checked on the request alone, and nothing is looked up or audited. From v0.14. |
| ICD-ADH-007 | When step 0 (`authorise`, §5.0) refuses an ad hoc call, the refusal follows the order of 17.4.2.2. (a) If the INVITE asked for emergency or imminent peril and the reason is `not-authorised` or `call-type-not-permitted`, the 403 carries an MCPTT info body setting that indication to false (steps 3B and 3C), and a plain warn-text with no MC code, since 3B and 3C skip step 4. (b) Otherwise `not-authorised` is 185 (step 4). (c) `call-type-not-permitted` is 186 (step 5) only when the profile declares no ad hoc call type at all; a profile that has some, asked for a kind it lacks, answers 100 "local policy". Refusals from later steps keep their ordinary codes. From v0.14 (PLT-VP-R1 ADHOC-OP-05). |

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
6. Returns an `int` (not a `bool`). The core checks this one (since v0.20).

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
   attributes remain. Since 0.26 the call type of a prearranged or chat call
   can itself depend on the target group (ICD-SIG-008): `authorise` still
   cannot see the target, but a group's group-selected call type shows
   through its answer (accepted, PLT-VP-R1 PRF-OP-01).
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
1. `model` is consistent with the call type's declared session model. Since
   v0.21 this is read as *equal to*: the model is declared per call type and
   nothing else could make another one consistent (see ICD-OP-15 for R2).
2. `max_participants`, if set, is ≥ 1; `None` means unlimited. It counts the
   session's participants: for a group, its members, the initiator among them
   when a member (TS 24.379 6.3.5.5 NOTE 2, `<on-network-max-participant-count>`);
   for an ad hoc call, the users invited, the caller not counted (17.4.2.2
   step 6, `<max-no-participants>`).
3. `recording_required=True` binds: the core refuses establishment if recording
   is unavailable (PLT-OAM-008).

**INV**
1. The core applies the decision verbatim (PLT-CC-005). It does not infer
   auto-answer from urgency, or recording from call type.
2. The decision is immutable for the session.

**Checked and applied by the core (since v0.21, PLT-VP-R1 RES-OP-12).** The
returned value must be a `SessionDecision` with boolean flags that satisfies
POST-1 and POST-2, or the session fails with `hook-contract-violation`. The
participant limit is the decision's, applied by the core; admission does not
apply it. A session over it:

- a group call (a `GROUP` resolution, for a call type that is not a private
  call) whose call type declares `group_over_limit: truncate` is **not
  refused**: only `max_participants` participants take part,
  the initiator always among them when a member and the others in the
  resolver's order, and the 200 OK to the originator carries warning
  `122 too many participants` (6.3.5.5, 10.1.1.4.1). The platform has no
  `<on-network-required>` members; which members to prefer is otherwise
  operator policy (6.3.5.5 NOTE 3), which the resolver states by its order.
  IF-SES `floor_policy` and IF-BER `select` see the members that take part;
  A limit that would leave only the initiator (1, on a group the initiator
  belongs to) invites no one, and is refused instead, `participant-limit-exceeded`;
- a group call whose call type declares `group_over_limit: refuse` (since
  v0.22, a recorded deviation from 6.3.5.5, reported at startup) is refused
  `participant-limit-exceeded`, SIP 486 with warning 122;
- an ad hoc call is refused, `adhoc-too-many-participants` (warning 189);
- anything else (a private call whose target resolved to a group, a broadcast
  area) is refused, `participant-limit-exceeded`: SIP 486 with warning
  `122 too many participants`, the pairing TS 24.379 10.1.2 uses for a call
  already at its limit. Before v0.21 these were `capacity-exhausted`, which
  renders as 503 "maximum number of sessions reached": a server condition, and
  one a caller may retry.

A routed or partner session has no local members, and the limit is not
applied to it here. One exception reads the call type's declared limit rather
than the decision's: 17.4.2.2 step 6 checks an ad hoc caller's list against
the configured `<max-no-participants>` before step 12 determines the
participants, and `decide` cannot be asked before then.

### 5.3 `floor_policy(request, resolution) -> FloorPolicy`

**PRE** Called for sessions with a voice or video component. Not called for
data-only sessions.

**POST**
1. `queueing_enabled=False` → `max_queue_depth == 0`.
2. `queueing_enabled=True` → `max_queue_depth ≥ 1`.
3. `timers_ms` keys are TS 24.380 timer names. Unknown keys are a contract
   violation, detected at profile validation. (In a profile's
   `call_types[].floor`, a timer may also be stated in seconds, `timers_s`,
   PLT-GEN-011 as amended: with both, the milliseconds apply and a
   disagreement is warned of at startup. `FloorPolicy.timers_ms` returned by
   the hook is in milliseconds only.)
4. Omitted timers take the core's specification defaults.
5. `preemption_at_full_queue` is `"insert"` or `"deny"` (since v0.22). It
   decides a pre-emptor's place when the queue is already at
   `max_queue_depth` and the pre-emptor is not in it: `insert` follows TS
   24.380 6.3.4.4.7 item 2e, putting it in front of every queued request, one
   entry beyond the declared depth until it is granted; `deny`, a recorded
   deviation (PLT-VP-R1 FC-OP-07), treats it as an ordinary request, denied
   queue-full, and the talker keeps the floor. It takes effect only where
   queueing and override are both enabled. With `insert`, the declared depth
   bounds the ordinary entries; the pre-emptor in front is the one beyond it.
   It must equal the call type's declared `floor.preemption_at_full_queue`
   (checked by the core): what the service reports at startup is what runs.
   The startup report lists `deny` where the call type declares queueing and
   override; a hook that enables both where the declaration does not has the
   deviation named in that session's `session-established` record
   (`deviations`).

**Checked by the core (since v0.19, PLT-VP-R1 RES-OP-07).** Profile
validation checks the in-tree floor tables. The core also checks what the hook
returns, so a hook that computes its policy is held to the same contract: the
value is a `FloorPolicy` itself, not an object shaped like one; its flags are
booleans; `max_queue_depth` is an integer and satisfies POST-1 and POST-2;
`preemption_at_full_queue` is one of POST-5's two strings and the call type's
declared one; and
each `timers_ms` entry names a timer in POST-3's set with a positive integer of
milliseconds. A failure is `hook-contract-violation` on IF-SES, before any
bearer is selected or QoS reserved.

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
   `arp_preemption_capability=True`; and, where the deployment states
   `MCX_ARP_VULNERABILITY_CHECK=true` (since v0.30, ICD-OP-14), a decision with
   `preemption_vulnerability=True` shall not set
   `arp_preemption_vulnerability=False`. The bearer may be more open to
   pre-emption than the priority decision, never less.

**Checked by the core (since v0.19, PLT-VP-R1 RES-OP-07).** The core checks
the returned value before it reserves QoS: it is a `BearerDecision` whose paths
are `PathSpec`s; POST-1 to POST-3; each transport and the redundancy are ones
profile validation allows, and each weight is an integer of at least 1; the
5QI and ARP level are integers and the ARP level is 1 to 15 (TS 23.501
5.7.2.2), which is as much of POST-4 as the core can know; both ARP flags are
booleans; and POST-5, where only `preemption_capability is True` grants. A
failure is `hook-contract-violation` on IF-BER. Each check is one profile
validation makes of a bearer rule, so a profile that validates is never
refused here. The vulnerability half of POST-5 is checked where the
deployment states `MCX_ARP_VULNERABILITY_CHECK=true` (required, no default;
`false` is a deviation the service reports). There the privilege is
immunity, so only `preemption_vulnerability is False` grants it: any other
value IF-PRI returns leaves the call open, as only `True` grants capability.
Profile validation does not pair bearer rules with priority rules, so a
profile that validates can still be refused here with the check on (every
in-tree profile passes it).

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
2. A returned decision shall satisfy every POST of §6.1. The core does not yet
   call this method (§8.4 is not implemented); when it does, it applies §6.1's
   check to the returned decision, against the session's own priority.
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
-  core: initiator within the declared domains (MCX_FOREIGN_INITIATOR=refuse, v0.23)
   ── if not: refuse initiator-not-served (404 + 141), stop — no hook runs ──
0  IF-IDR.identities_of(initiator)             → the initiator's roles (§3.4)
0  IF-SES.authorise(request without target)     → Admission   (v0.13, §5.0)
   ── if not permitted: reject, stop — nothing about the target looked up ──
1  IF-IDR.resolve(target, request)              → Resolution
      ── ad hoc (§3.5): IF-IDR.resolve per listed entry, OR
         IF-IDR.determine_participants(criteria, request) ──
1a core: the initiator of a call to a group is a member of it (v0.29)
      ── not ad hoc, not a functional identity's group; any call type ──
      ── if not: refuse not-group-member (403 + 116), stop ──
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
| `participant-limit-exceeded` | core | More participants than the session decision allows, in a session that is not a group call the core can truncate (§5.2; SIP 486, warning 122). Since v0.21 |
| `initiator-not-served` | core | The initiator is not within the profile's declared domains, and the deployment states `MCX_FOREIGN_INITIATOR=refuse` (PLT-IDM-008; PLT-VP-R1 RES-OP-11). Checked before step 0, so no hook runs; SIP 404 with warning `141 user unknown to the participating function`, as TS 24.379 answers a caller the participating function has no MCPTT ID for (10.1.1.3.1.1 step 2a, 11.1.1.3.1.1 step 4). Not applied to a request a gateway relays through the IF-IWF API (§7.2); a gateway's INVITE over SIP is subject to it. Since v0.23 |
| `functional-alias-not-authorised` | core | A functional alias the user may not hold (ICD-NET-007): not in the network profile's `functional_aliases` for the user, or not a functional identity the profile declares for users. SIP 403, with warning `201 user not authorized to change the functional alias status` from Rel-20 (TS 24.379 9A.2.2.2.3 step 4B), the phrase alone before. Since v0.27 |
| `functional-alias-held` | core | A single-holder functional alias another user holds, and the request does not take it over (9A.2.2.3.3 step 5). SIP 403. Since v0.27 |
| `functional-alias-take-over-not-allowed` | core | A take-over by a user the network profile does not allow to take over that alias (9A.2.2.3.3 step 6). SIP 403. Since v0.27 |
| `not-group-member` | core | A call whose caller is not a member of the group its target resolved to (ICD-NET-005; TS 24.379 6.3.5.2 step 5b), whatever its call type, a private call aimed at a group included, checked after IF-IDR `resolve` and before IF-PRI; not for an ad hoc call or a group named by a functional identity. The caller is compared as SIP compares URIs. SIP 403 with warning `116 user is not part of the MCPTT group` (every release). Since v0.29 |
| `functional-alias-location-unknown` | core | A location-dependent functional alias with no location to hold it at: the PUBLISH reports none and the user has reported no mapped cell (owner decision 2026-10-23). SIP 403. Since v0.27 |

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
| ICD-OP-01 | **CLOSED 2026-10-27 for R1 (owner: the budget is met with the in-memory store, as measured; the cache is decided with an external store, ICD-OP-16).** ~~Is IF-IDR's 50 ms budget achievable against a real binding store under load, or does resolution need a cache with an explicit staleness bound?~~ Measured with `tests/bench_idr.py` (PLT-SRS PLT-NFR-009: by measurement, under a stated load profile), timing each invocation as the core does (the resolver, the core's POST check and the rendering of its result for the audit, ICD-GEN-041), one call at a time, 1 000 runs per case, p50 / p99: with 100 000 users a user resolves in 0.02 / 0.05 ms; groups of 1 000, 5 000 and 20 000 members in 0.6 / 0.7, 3.5 / 8.6 and 14 / 34 ms, the time growing with the members and spent mostly in the core's per-member domain check (POST-3), so on the machine measured a group of about 30 000 members reaches the budget at p99; with 5 000 trains' drivers activated, `identities_of` 0.2 / 0.5 ms, one train's driver 0.03 / 0.08 ms, a driver's `unbind` 1.9 / 3.7 ms (it walks every train's slot; `bind` is constant, 0.02 ms), every driver by ad hoc criteria 4.1 / 7.8 ms, and 5 000 holders of the location-dependent `rec-area` in one section 3.3 / 6.3 ms. Every driver by criteria was 94 ms (p50) before: `FunctionalResolver.determine_participants` searched a list once per holder, quadratic in the holders; it is now linear, and so are the core's own list of listed ad hoc participants and the one-value-per-user check at restart, which had the same pattern (review; `tests/test_idr_budget.py`). An ad hoc call listing its participants resolves each entry in its own invocation, each within the budget; the step as a whole is about 25 µs per user entry (24 ms p50 for 1 000, its tail on the machine measured from 37 ms to 194 ms at p99), bounded by the deployment's `MCX_ADHOC_LIST_MAX`, at most 1 000 since 0.36 (owner decision 2026-10-28, from this review: it had no upper limit, the frmcs `rec-broadcast` declares no `max_participants`, and a cap of 5 000 could hold the lock for 125 ms or more), and, where a call type declares it, `max_participants`; no record flags the step as a whole. The cap bounds the entries, not the time: an entry naming a group is resolved, and its members checked, before it is left out, so 1 000 listed groups of 1 000 members hold the lock for about 0.7 s (PLT-VP-R1 ADHOC-OP-06). In R1 the binding store is the resolver's memory, provisioned from the network profile and the functional alias ledger; no external store is wired (`group_source` stays unset), so there is nothing for a cache to front. The budget is measured and recorded on every invocation, not enforced (ICD-GEN-011, `DeadlineMode.MEASURE`). The SIP core runs SIP, media and timers under one lock, so the time an invocation takes, within budget or not, is time no other call's media is relayed and no timer runs: a large group costs every call in progress that long, and the core's own work on the members after the hook (about 8 ms for 20 000) adds to it (review). Figures from a shared 2-CPU container, whose scheduler and garbage collection gave single runs of up to about 130 ms in cases whose p99 is under 1 ms; they scale with the machine, the growth with group size does not. | closed (R1) |
| ICD-OP-02 | **CLOSED 2026-10-23 (decided with PLT-VP-R1 SVC-OP-06: as TS 24.379 9A.2.2.3.3 steps 5 and 6).** Activating a held single-holder identity is refused, unless the request asks to take it over and the network profile allows that user to; the core then unbinds the holder before binding the new one (ICD-NET-007). Originally: should `bind` on a held single-holder identity replace or refuse? Operationally significant for driver handover; confirm against UIC FRS. | closed |
| ICD-OP-03 | Does any profile need pre-emption between scopes under an explicit bridging policy, or is the unconditional bar permanent? | R3 start |
| ICD-OP-04 | Does IF-BER need a release/teardown call, or is path release wholly core-owned? | R3 start |
| ICD-OP-05 | Confirm that no profile requires a floor-control transition change (§5.3 INV-2). If one does, the core state machine is wrong. | R2 exit |
| ICD-OP-06 | Floor control across a gateway: TETRA and P25 PTT models do not map cleanly onto 24.380 grant, queue, override and revoke. Decide which are unsupported over IF-IWF rather than discovering it at interop. | R4 start |
| ICD-OP-07 | Media anchoring for a routed session: does the platform stay in the media path or hand off to the gateway? Affects recording obligations (PLT-OAM-008) for interworked calls. | R4 start |
| ICD-OP-08 | **CLOSED 2026-09-25 in its R1 form (decided: certificate identity plus trusted cores). Amended in v0.15:** a dialog is bound to the party its connection authenticates, not to one connection. A new connection that proves the same party takes it over, and the old one is dropped (PLT-VP-R1 SIP-OP-18 item 6). A user's connection proves the party when its certificate names it; a core's connection only when it comes from the same trusted core. A core may not take a user's dialog. A request may assert only an identity its TLS connection authenticated (PLT-IDM-004 without OpenID Connect, which is R2). A peer whose verified certificate carries a DNS name listed in `MCX_SIP_TRUSTED_PEERS` (required, no default; `none`, or fully qualified names; since v0.12 `sip.trusted_cores` in the network profile, §2.8) is a SIP core that authenticated its users itself, and may assert any identity (RFC 3325 trust domain). Every other peer may assert only a `sip:` URI in its certificate's subjectAltName. The check runs on REGISTER (the AoR) and INVITE (the initiator, from P-Asserted-Identity or From), and a mismatch is 403 `identity-not-authenticated`. The scheme and host are compared without case and the user part exactly (RFC 3261 19.1.4). The independent review found that binding identity alone left calls open to other peers, so a dialog is now also bound to the connection it was set up on: a response must arrive on its request's connection and carry its Call-ID; branches are unguessable; a BYE for the call must come from the caller's connection with the caller's tag, and a BYE for a leg from that leg's connection; an ACK must come on its INVITE's connection, and so must a CANCEL; and a new INVITE may not reuse a live call's Call-ID. **Deployment requirements that follow**, which the platform cannot check: a trusted core must itself authenticate every user and police P-Asserted-Identity (strip it from untrusted sources); and core certificates must come from a CA that issues trusted DNS names only to cores (see ICD-OP-10). The interop Kamailio meets neither: it tests the trust mechanism, not a secure core. Originally: **From v0.7.** Admission now authorises on `initiator.roles`, and the initiator is taken from P-Asserted-Identity or From. PLT-IDM-004 (bind the authenticated identity to the request) is not enforced on the SIP path, so on a direct TLS connection a caller can assert someone else's identity and so their roles. Before v0.7 the role check failed closed for everyone, so the exposure is new in effect, but the weakness is older. Resolving it is PLT-IDM-004 work: bind the TLS client identity to the registered AoR. | closed |
| ICD-OP-09 | **CLOSED 2026-09-25 (decided: a new hook method, IF-SES `authorise`).** Authorisation is §8.1 step 0, after the core looks up the initiator's roles and before any target lookup (§5.0). The request `authorise` sees has the called party removed, so an unauthorised caller gets the same refusal whatever it calls: an existing or unknown user, a held or unheld role, criteria matching someone or no one, and a list over the limit. The core writes `initiator.roles` once, and every later hook sees that value. The independent review found no remaining oracle. It found three things, all fixed: `admit` crashed on an undeclared call type; later hooks still saw roles the client supplied; and the documents were not updated. It also found the two open points below. Originally: **From v0.7.** Resolution runs before admission (§8.1), so an unauthorised caller can tell "nobody matches" (187, 404) from "not allowed" (403, 100), and learn whether a user exists or a role is currently held. TS 24.379 17.4.2.2 authorises first (steps 4 and 5). The same was true for prearranged groups before ad hoc calls existed. | closed |
| ICD-OP-10 | **CLOSED 2026-09-25 (decided: a separate CA for cores, in the network profile).** The core CA is named by the network profile (§2.8), must be a self-signed root with `pathLenConstraint` 0, and must be kept apart from the users' anchors in `MCX_SIP_TLS_CA` (by key, by name, and by issuance). A trusted core needs both a certificate the core CA issued directly and a listed DNS name, and a certificate the core CA issued asserts no user identity (ICD-NET-003, -004). The independent review found three defects in the first version, all fixed before delivery: an intermediate under the users' root was accepted as the core CA; a TRUSTED CERTIFICATE block in the core CA file became an anchor unchecked and unhashed; and core-CA certificates could also authenticate user URIs. Originally: **From v0.9.** SIP cores and users share one trust anchor (`MCX_SIP_TLS_CA`). A core is recognised by a DNS name in its certificate, so any certificate from that CA carrying the name is trusted. That includes a user certificate, if enrolment lets a user choose DNS names. | closed |
| ICD-OP-11 | **From v0.9.** The inbound guard records a request's (Call-ID, CSeq) before the identity check runs. A refused, spoofed request therefore uses up that pair, and a genuine request that later carries the same pair is answered 482. This matters only if Call-IDs can be predicted. | R2 |
| ICD-OP-12 | **From v0.12.** TS 24.379 annex F.3 writes a PLMN as six digits (`\d{3}\d{3}`), and the ECGI and NCGI start with them. It does not say how a two-digit MNC fills three digits. The network profile's `plmns` must therefore be written exactly as the deployment's clients write the first six digits of a cell. Confirm against TS 23.003 and the client implementations before a network with a two-digit MNC is configured. Since 0.25 the answer also fixes how the test PLMN 999-99 is written (ICD-NET-006 takes `999990`, the trailing-zero form of the examples' `001010`): if a two-digit MNC is written otherwise, `TEST_PLMNS` in `service/network.py` changes with it. | before a two-digit-MNC deployment |
| ICD-OP-13 | **From v0.13.** A request relayed by a gateway (§7.2) has two weaknesses. (1) Its audit trail records `session-admitted` before §8.1 runs, so a request refused at step 0 shows "admitted" and then "refused". (2) The gateway may name a local user as the initiator, and step 0 then authorises it with that user's roles. The gateway's word is taken for who is calling. Both predate v0.13. The remedy for the second is to authorise gateway-originated requests on the gateway's own rights. | R4 start |
| ICD-OP-14 | **CLOSED 2026-10-26 (owner ruling: a deployment parameter, `MCX_ARP_VULNERABILITY_CHECK=true|false`, required, no default).** §6.1 POST-5 stated only capability: a bearer decision with `arp_preemption_vulnerability=False` under a priority decision with `preemption_vulnerability=True` was accepted, and made the session immune to network pre-emption that IF-PRI left it open to. Now, with `true`, the core refuses it as `hook-contract-violation` on IF-BER; with `false` it is accepted as before and the service reports the deviation. Checking every in-tree call type with the check on found one such pair: the frmcs `etcs-ipcon` bearer rule kept `arp_preemption_vulnerability: false` after PLT-CONF-AUDIT CA-19 made its priority vulnerable (band C, so a railway emergency call can take its resources, FRS appendix J); corrected to `true` (owner ruling the same day). Only an explicit `False` from IF-PRI grants immunity (review: a truthy value had passed as immune while the platform's own pre-emption read it as open). Open notes, not this item's defects: the bearer may be more open than the priority decision (in-tree, the mcx imminent-peril bearer rule is pre-emptable at the network while its priority is not), as POST-5 also allows for capability; an inbound IF-ICX path, when wired, gets `preemption_vulnerability=True` from the partner mapping, so with the check on every bearer rule such a call can reach must be pre-emptable; IF-PRI's own decision is not checked by the core (so `preemption_victims` reads the incoming call's capability by truthiness: a substituted IF-PRI returning `"false"` would make it capable, the same fail-open shape fixed here for the bearer), and the 5QI is checked only as an integer (TS 23.501 values are 0 to 255). | closed |
| ICD-OP-15 | **From v0.21.** §5.2 POST-1 is read as equality, and R1 runs on-demand sessions only (the in-tree call types that are pre-established or broadcast by nature are declared on-demand until their release, PLT-VP-R1 RES-OP-12). In TS 24.379, falling back to on-demand when no pre-established session exists is ordinary, and equality forbids a hook from choosing it. Revisit POST-1 with PLT-SIG-006 (pre-established sessions). | R2 start |
| ICD-OP-16 | **From v0.35 (owner decision 2026-10-27, closing ICD-OP-01 for R1).** When IF-IDR reads an external binding store (a group management or identity management server through `group_source`, or a functional alias store of the deployment's), each read is network I/O on the establishment path (ICD-GEN-004). Decide then whether resolution reads through a cache, and with which staleness bound (a required deployment setting, by the platform's rule for behaviour settings), and how a member change reaches a cached group; measure the result against the 50 ms budget with `tests/bench_idr.py` extended to the store. | with the first external binding store |

---

## 12. Revision history

| Version | Date | Change |
|---|---|---|
| 0.36 | 2026-10-28 | ICD-ADH-001: `MCX_ADHOC_LIST_MAX` is at most 1 000; a larger value refuses startup (owner decision 2026-10-28, from the review of ICD-OP-01: a listed ad hoc call resolves each entry, one IF-IDR invocation each, under the one SIP, media and timer lock, about 25 µs a user entry, so 1 000 users take about 24 ms at the median). It bounds the entries, not the time: an entry naming a group is resolved over all its members before it is left out (PLT-VP-R1 ADHOC-OP-06). A larger ad hoc call goes by criteria. No interface change; a major change for a deployment that states more than 1 000, which no longer starts. |
| 0.35 | 2026-10-27 | ICD-OP-01 closed for R1 (owner): IF-IDR's 50 ms budget is met with the in-memory binding store, measured with `tests/bench_idr.py` (p99 of 1 000 runs: a user 0.05 ms, a group of 20 000 members 34 ms, every one of 5 000 trains' drivers by criteria 7.8 ms); ad hoc criteria were quadratic in the holders (94 ms for 5 000) and are now linear, as are the core's list of listed ad hoc participants and a restart check (review). The single lock that serialises hook calls also stops media relay and timers while one runs (review). ICD-OP-16 opened: a cache and its staleness bound, decided with the first external binding store. No interface change. |
| 0.34 | 2026-10-27 | ICD-NET-007: functional alias status determination, a SUBSCRIBE to the presence event and NOTIFYs with the TS 24.379 9A.3.1 per-user PIDF, own status only (PLT-VP-R1 FA-OP-01 item 1). `Allow` names SUBSCRIBE from Rel-15. A minor change: no hook signature changes. |
| 0.33 | 2026-10-27 | §3.2 PRE-5 and §3.3: a functional identity keyed by an identification value (`identification_key` in the profile), written `sip:<value>.<identity>@<domain>` (`core.hooks.keyed_identity`), its value passed to `bind` under the key; ICD-NET-007: optional `values`, the patterns of values its users may hold it for (PLT-VP-R1 FA-OP-01 item 4, owner decision: option b and the format). The frmcs `train-driver` is keyed by `train_id`. A minor change for a profile that declares none; a major one for the frmcs profile's deployments, whose `train-driver` is now activated and called per train. |
| 0.32 | 2026-10-27 | §2.8 ICD-NET-007: optional `max_holders` for a multi-holder identity, refused `functional-alias-held` at the limit unless taken over, the earliest holders making room (PLT-VP-R1 FA-OP-01 item 3). A minor change: an optional network key. |
| 0.31 | 2026-10-27 | §2.8 ICD-NET-007 and §3.3 INV-1: `MCX_DISPLACED_HOLDER_CALLS=keep|release` (default `keep`), whether the calls a displaced holder is in because of the alias are released on a take-over (PLT-VP-R1 FA-OP-01 item 4, owner ruling). A minor change: an optional setting. |
| 0.30 | 2026-10-26 | §6.1 POST-5 and its core check: the vulnerability flag too, where the deployment states `MCX_ARP_VULNERABILITY_CHECK=true` (ICD-OP-14 closed, owner ruling: a required parameter, `false` a reported deviation). The frmcs `etcs-ipcon` bearer rule corrected to `arp_preemption_vulnerability: true`, as its priority rule. A major change for a deployment that turns it on; no hook signature change. |
| 0.29 | 2026-10-26 | §2.8 ICD-NET-005, §8.1 step 1a and §9: a group call's caller must be a member of the group, else `not-group-member`, SIP 403 with warning 116 (PLT-VP-R1 SVC-OP-07 decided: as TS 24.379 6.3.5.2 step 5b, no call type exempt). A new core-originated reason code; no hook change. |
| 0.28 | 2026-10-26 | §2.8 ICD-NET-005: registration never provisions a user, and a caller is checked against the declared domains only (PLT-VP-R1 SIP-OP-05 closed, option 1), nor against a group's members (PLT-VP-R1 SVC-OP-07, open). No interface change. |
| 0.27 | 2026-10-23 | §2.8: the network profile gains `functional_aliases` (ICD-NET-007; PLT-VP-R1 SVC-OP-06 decided, option B): who may activate each functional identity and take it over; users activate by SIP PUBLISH from Rel-15 (TS 24.379 clause 9A), the core binding through IF-IDR (§3.3 note), take-over as the standard has it (ICD-OP-02 closed), location from the PUBLISH's report or else the last reported cell, holders durable. §9: four core codes `functional-alias-*`. A minor change: no hook signature changes. Review: `SIP-ETag` on the 200, holders written ahead of the resolver, §3.3 rollback records. |
| 0.26 | 2026-10-22 | §2.6: ICD-SIG-008, a call type chosen by the target group (PLT-VP-R1 PRF-OP-01 decided, option 2 with matching signature): `group_selected: true` on the call type, `call_type` on the network profile's group (§2.8, ICD-NET-005); ICD-SIG-003 does not count it, and it must share its prearranged or chat signature with exactly one call type that is not group-selected (review). §5.0 INV-1 notes that a group-selected call type shows through the authorise refusal. The mcx `coordination-group` and utility `switching-order` become group-selected prearranged calls. A minor change: an optional profile key and an optional network key, no hook change. |
| 0.25 | 2026-10-21 | §2.8: the network profile gains `environment` (ICD-NET-006; PLT-VP-R1 VP-OP-05 decided, option B): the production indicator, declared with the radio plan, refused off a test PLMN unless it is `production`; `MCX_ENV` is required and must agree, and so must `MCX_PRODUCTION` when set (the `prod` spelling is withdrawn). The audit identity gains the environment. A key repeated in the network profile or a service profile is refused (review). A minor change: no hook or parameter object changes. |
| 0.24 | 2026-10-18 | PLT-GEN-011 as amended (PLT-SRS 0.5; PLT-VP-R1 RES-OP-09 batch B): a duration in a profile may be stated in milliseconds or in seconds. §2.7: the ring limit is `no_answer_ms` or `no_answer_s`, or both, `no_answer_ms` applying and a disagreement warned of at startup; `CallType` gains `no_answer_s` (as stated, or None). §5.3: a profile's `call_types[].floor` takes `timers_s` beside `timers_ms` per timer, the same way; `FloorConfig` gains `timers_s`. The hook's `FloorPolicy.timers_ms` stays in milliseconds. The in-tree profiles are unchanged. |
| 0.23 | 2026-10-17 | §9: core code `initiator-not-served` (PLT-VP-R1 RES-OP-11, owner ruling: `MCX_FOREIGN_INITIATOR=refuse|allow`, required). A minor change: no hook or parameter object changes. |
| 0.22 | 2026-10-16 | Owner ruling: two decisions become profile settings, required with no default. §2.7 and ICD-LIM-001..003: `group_over_limit` per call type (`truncate`, TS 24.379 6.3.5.5, or `refuse`); §5.3 POST-5: `preemption_at_full_queue` on `FloorPolicy` (`insert`, TS 24.380 6.3.4.4.7 item 2e, or `deny`), checked by the core. A deviation is reported at startup. A signature change: `FloorPolicy` gains a required field; the in-tree profiles state the previous behaviour, so none changes. |
| 0.21 | 2026-09-29 | §5.2: the core checks and applies the session decision (PLT-VP-R1 RES-OP-12). The participant limit is the decision's, and a group call over it is truncated with warning 122 instead of refused (TS 24.379 6.3.5.5, 10.1.1.4.1); the in-tree admission no longer refuses on it. A session over the limit that is not a truncatable group call is refused with the new core code `participant-limit-exceeded` (§9). POST-1 read as equality, POST-2 states what is counted. ICD-OP-15 opened. A minor change: signatures unchanged; a group call the in-tree profiles used to refuse is now established with fewer participants. |
| 0.20 | 2026-09-29 | ICD-GEN-041 made true (PLT-VP-R1 RES-OP-02): every invocation records what the hook returned, in full, and a value the audit cannot record exactly is refused. IF-ICX `map_outbound` and IF-PRI `compare` now go through the invocation boundary; `map_outbound` runs before QoS is reserved. IF-ICX gets the 20 ms deadline ICD-GEN-010 always gave it. §4.2 POST-6. A minor change: signatures unchanged; what is newly refused is a value holding a type the ICD's own value types do not declare. |
| 0.19 | 2026-09-29 | §5.3 and §6.1: the core checks the floor policy and bearer decision a hook returns (PLT-VP-R1 RES-OP-07). Before, only profile validation checked them, so a substituted hook was not held to its contract. A minor change: no POST is tightened, and a value that passes profile validation passes these checks. ICD-OP-14 opened. |
| 0.18 | 2026-09-28 | ICD-GEN-001 made true: value types hold nothing mutable (`Value`, `FrozenDict`); VP1-BND-004's gate checks it (PLT-VP-R1 RES-OP-06). A minor change: types and signatures unchanged. What now raises TypeError: a hook mutating a value it received; a value built holding an object that is not known to be immutable (e.g. a profile's own class); a sequence field given a string, a set or a mapping. |
| 0.17 | 2026-09-28 | §3.2 POST-3 made precise and enforced by the core; §3.5 gains POST-3 (PLT-VP-R1 RES-OP-01). The service profile's `identity.domains` must be lower-case DNS names. A minor change: no hook signature changes, but a resolver that returned members outside the declared domains, or written other than `sip[s]:user@host`, is now a contract violation. |
| 0.16 | 2026-09-26 | §2.8: the network profile gains `groups` and `users` (ICD-NET-005; PLT-VP-R1 SVC-OP-03 decided). `MCX_GROUPS_FILE` is withdrawn and refused. A minor change: no hook or parameter object changes. |
| 0.15 | 2026-09-25 | ICD-OP-08 amended: a dialog follows its party to a new connection that proves the same identity, and the old connection is dropped from it. The hook surface is unchanged. |
| 0.14 | 2026-09-25 | ICD-ADH-006 (step 3A, warning 150) and ICD-ADH-007 (how a step-0 refusal of an ad hoc call is rendered: 3B/3C body, 185, 186). A minor change: no hook or parameter object changes. |
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
