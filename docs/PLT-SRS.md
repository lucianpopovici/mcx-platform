# Mission-critical services platform — Software Requirements Specification

**Document:** PLT-SRS
**Version:** 0.2 (draft)
**Date:** 2026-09-19
**Status:** Draft for review — not baselined

---

## 1. Purpose and scope

### 1.1 Purpose

This document specifies the requirements for a mission-critical services platform
implementing 3GPP MC services (MCPTT, MCData, MCVideo), deployable as either a
generic mission-critical (MCX) system or a railway FRMCS system, from a single
codebase and a single deployable image.

### 1.2 Scope

In scope: the MC application plane (MC service servers, common services core),
the profile framework that specialises the platform per deployment, and the
interfaces to the SIP core, HTTP proxy and underlying transport.

Out of scope, procured or integrated rather than built: the SIP/IMS core, the
HTTP proxy, the 5GC/EPC and RAN, the MC client and UE, dispatcher consoles, and
the legacy systems reached through interworking.

### 1.3 Product concept

One core implements the profile-agnostic MC protocol machinery. A **profile** —
a validated, immutable configuration package plus six hook implementations —
specialises it. Exactly one profile is selected at deployment time. The MCX and
FRMCS profiles differ in identity resolution, priority, session policy, bearer
selection, interworking and interconnection, and in nothing else.

### 1.4 Definitions

| Term | Meaning |
|---|---|
| Core | Profile-agnostic MC service implementation |
| Profile | Configuration package + hook implementations for one deployment type |
| Hook | One of the six interfaces through which a profile influences the core |
| Controlling function | Per-session arbitrating function (TS 23.379) |
| Participating function | Per-user home-system function (TS 23.379) |
| CSC | Common services core: IdMS, KMS, GMS, CMS, LMS |
| Functional identity | Role-based address resolved dynamically (FRMCS) |
| REC | Railway emergency communication |
| Pre-emption scope | Partition within which priority arbitration is permitted |

### 1.5 Requirement notation

`PLT-<AREA>-<nnn>`. Each requirement carries a release phase and a verification
method.

**Modal verbs:** *shall* = mandatory; *should* = recommended, deviation requires
recorded justification; *may* = optional.

**Verification methods:** **T** test, **D** demonstration, **A** analysis,
**I** inspection.

### 1.6 Release phases

| Phase | Content | Exit criterion |
|---|---|---|
| **R1** | Core, profile framework, MCX profile, on-network MCPTT private and prearranged group calls, floor control | Two clients complete a group call with floor arbitration; both CI suites green |
| **R2** | Security (TS 33.180), MCData SDS, emergency and imminent-peril calls, full group/config management | End-to-end encrypted emergency group call; KMS-issued keys only |
| **R3** | FRMCS profile: functional addressing, REC, multi-bearer transport, MCData IPcon; interconnection with partner MC systems | FRMCS conformance suite green against unmodified core; a partner cannot exceed its declared ceiling |
| **R4** | MBS/broadcast delivery, off-network (ProSe), interworking (TETRA/P25/GSM-R), MCVideo | Interworked call to a legacy system; broadcast group call over MBS |

---

## 2. Applicable documents

### 2.1 3GPP

| Ref | Title |
|---|---|
| TS 22.179 | MCPTT over LTE — stage 1 |
| TS 22.280 | MC services common requirements — stage 1 |
| TS 22.282 | MCData — stage 1 |
| TS 22.289 | Mobile communication system for railways |
| TS 23.280 | Common functional architecture for MC services |
| TS 23.379 | Functional architecture for MCPTT |
| TS 23.282 | Functional architecture for MCData |
| TS 24.379 | MCPTT call control protocol |
| TS 24.380 | MCPTT media plane control protocol (floor control) |
| TS 24.282 | MCData signalling control protocol |
| TS 24.481 | MC group management protocol |
| TS 24.482 | MC identity management protocol |
| TS 24.483 | MC management object |
| TS 24.484 | MC configuration management protocol |
| TS 33.180 | Security of MC services |
| TS 23.247 | Multicast/broadcast services (5G MBS) |
| TS 23.468 | Group Communication System Enablers (GCSE_LTE) |
| TS 23.303 | Proximity-based services (ProSe) |

### 2.2 Railway

| Ref | Title |
|---|---|
| UIC FRMCS FRS | FRMCS Functional Requirements Specification |
| UIC FRMCS SRS | FRMCS System Requirements Specification |
| EN 50126 | RAMS specification and demonstration |
| EN 50128 | Software for railway control and protection |
| EN 50129 | Safety-related electronic systems for signalling |

> **Note.** All FRMCS-specific requirements in §14 are provisional pending
> reconciliation with the current UIC FRS/SRS baseline. They are marked
> `[PROVISIONAL]` and shall not be used as safety-case input until reconciled.

---

## 3. System context

### 3.1 External interfaces

| Interface | Peer | Protocol | Phase |
|---|---|---|---|
| SIP-2 | SIP core | SIP over TLS | R1 |
| HTTP-1 | HTTP proxy | HTTPS | R1 |
| CSC-1 | IdMS | OpenID Connect | R2 |
| CSC-4 | KMS | HTTPS, MIKEY-SAKKE material | R2 |
| CSC-8/9 | GMS | XCAP/HTTPS | R2 |
| Rx / N5 | PCRF / PCF | Diameter / HTTP2 | R3 |
| MB2 / xMB / MBS | BM-SC / MB-SMF | per TS 23.468 / TS 23.247 | R4 |
| OBAPP / TSAPP | FRMCS gateways | per UIC SRS | R3 |

### 3.2 Architectural constraint

**The core shall not know which profile is loaded.** Every requirement in this
document is written to that constraint; any requirement that appears to demand
profile-aware core behaviour is a defect in this document.

---

## 4. General platform requirements (PLT-GEN)

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-GEN-001 | R1 | The platform shall be built and distributed as a single deployable image containing all supported profiles. | I |
| PLT-GEN-002 | R1 | The platform shall select exactly one profile at process start, from deployment configuration. | T |
| PLT-GEN-003 | R1 | The platform shall refuse to start when no profile is configured, when the named profile is absent, or when more than one profile is configured. | T |
| PLT-GEN-004 | R1 | The platform shall not provide a default profile, and shall not infer a profile from any other configuration value. | I |
| PLT-GEN-005 | R1 | The platform shall load more than one profile only when explicitly started in test mode, which shall be refused when any production indicator is set. | T |
| PLT-GEN-006 | R1 | Source code under `core/` shall contain no identifier, literal or comment naming a specific profile or a profile-specific domain concept. Enforced as a CI gate. | I |
| PLT-GEN-007 | R1 | The core shall reach profile behaviour only through the interfaces defined in §6. | I |
| PLT-GEN-008 | R1 | The platform shall expose the loaded profile's name, version and content hash on its health endpoint. | T |
| PLT-GEN-009 | R1 | The platform shall operate correctly with no persistent state beyond its configured stores, such that any instance may be restarted without loss of committed session records. | T |
| PLT-GEN-010 | R2 | The platform shall support horizontal scaling of participating functions without session affinity to a specific instance. | T |
| PLT-GEN-011 | R1 | All time values in configuration and logs shall be UTC; all durations shall be expressed in milliseconds. | I |

---

## 4A. 3GPP release selection (PLT-REL)

The profile says what a deployment does. The release says which version of the
protocol it says it in. They are independent: any profile may run at any
supported release, so they are two parameters and a test matrix, not one
parameter with more values.

The reason this is a parameter rather than a build-time constant is that a
constant can be present in two releases and mean different things in each. TS
24.380 subtype 14 is *Floor Queued Cancel* in Rel-17 and *Queued Floor
Requests* from Rel-18. A deployment that assumes the wrong one does not fail
loudly — it decodes the packet and acts on the wrong message.

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-REL-001 | R1 | The platform shall select exactly one 3GPP release at process start, from deployment configuration, and shall hold it unchanged for the life of the process. | T |
| PLT-REL-002 | R1 | The platform shall refuse to start when no release is configured or when the configured release is not supported. It shall provide no default release and shall not infer one from the profile, the image or any other configuration value. | T |
| PLT-REL-003 | R1 | The release shall be independent of the profile: every supported profile shall be deployable at every supported release. | T |
| PLT-REL-004 | R1 | The platform shall not encode a message, field or cause code that the configured release does not define, and shall refuse rather than substitute a defined alternative. | T |
| PLT-REL-005 | R1 | Every audit record shall carry the configured release alongside the profile identity triple. | T |
| PLT-REL-006 | R1 | A received message that is well formed but uses a construct the configured release does not define shall be reported distinguishably from a malformed message. | T |
| PLT-REL-007 | R1 | The conformance suite shall run for every supported combination of profile and release on every change, with no combination skippable. | I |
| PLT-REL-008 | R1 | Release numbers shall appear in exactly one module. No other module shall compare a release to a literal. Enforced as a CI gate. | I |
| PLT-REL-009 | R2 | The platform shall apply release selection to the TS 24.379 signalling layer as it does to TS 24.380 floor control. | T |
| PLT-REL-010 | R3 | Each interconnection partner shall carry its own release, independent of the local one. | T |

**PLT-REL-009 and PLT-REL-010 are deliberately not R1.** R1 covers the floor
control layer only, which is where the release dependence has been established
from the specifications (PLT-CONF-AUDIT §3A). Claiming the SIP layer before it
has been examined would be the guess this section exists to prevent.

---

## 5. Profile framework (PLT-PRF)

### 5.1 Profile content and validation

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-PRF-001 | R1 | A profile shall consist of a declarative configuration package and implementations of the six hook interfaces, with no other mechanism for influencing core behaviour. | I |
| PLT-PRF-002 | R1 | The platform shall validate a profile against the published profile schema before use. | T |
| PLT-PRF-003 | R1 | Validation shall reject any key not defined in the schema. Unknown keys shall be errors, not warnings. | T |
| PLT-PRF-004 | R1 | Validation shall reject any unresolved internal reference, including a call type naming an undeclared urgency, application, pre-emption scope or initiator role. | T |
| PLT-PRF-005 | R1 | Validation shall reject a priority table that does not yield a decision for every declared call type. | T |
| PLT-PRF-006 | R1 | Validation shall reject a bearer table that does not yield a decision for every declared (call type, media) combination. | T |
| PLT-PRF-007 | R1 | Validation failure shall prevent process start. The platform shall not start in a degraded or partially-configured state. | T |
| PLT-PRF-008 | R1 | On validation failure the platform shall emit a diagnostic naming the failing element by its path within the profile package. | T |
| PLT-PRF-009 | R1 | After successful validation the profile shall be immutable for the lifetime of the process. | T |
| PLT-PRF-010 | R1 | The platform shall not support hot reload, partial reload or runtime modification of a loaded profile. A profile change shall require redeployment. | I |
| PLT-PRF-011 | R1 | The platform shall compute and record a cryptographic hash over the canonicalised profile content at load time. | T |
| PLT-PRF-012 | R1 | All six hooks shall be mandatory. The platform shall not supply a default implementation for any hook. | I |
| PLT-PRF-013 | R1 | The platform shall verify at load time that each configured hook implements its declared interface, and shall refuse to start otherwise. | T |

### 5.2 Vocabulary opacity

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-PRF-020 | R1 | Call type, urgency, application and pre-emption scope identifiers shall be opaque to the core. The core shall not enumerate, compare against literals, or order them. | I |
| PLT-PRF-021 | R1 | The set of supported call types shall be determined solely by the loaded profile. | T |
| PLT-PRF-022 | R1 | Adding a call type, urgency or application to a deployment shall require no change to code under `core/`. | A |
| PLT-PRF-023 | R1 | Introducing an additional profile shall require no change to code under `core/`. | A |

### 5.3 Profile-agnostic core scope

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-PRF-030 | R1 | The core shall own the SIP session state machines, the floor control state machine, media plane handling, document servers and MCData services, none of which shall be replaceable by a profile. | I |
| PLT-PRF-031 | R1 | A profile shall supply protocol timer values but shall not alter any protocol state machine transition. | I |
| PLT-PRF-032 | R1 | Internal module boundaries corresponding to a 3GPP reference point shall be named after that reference point. | I |

---

## 6. Profile hook interfaces (PLT-HOK)

### 6.1 Common

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-HOK-001 | R1 | Every value object crossing a hook boundary shall be immutable. | I |
| PLT-HOK-002 | R1 | A hook shall not mutate core session state; all influence shall be through its return value. | I |
| PLT-HOK-003 | R1 | The core shall treat a hook exception as a session failure with a defined reason code, and shall not continue with an assumed result. | T |
| PLT-HOK-004 | R2 | The core shall bound hook invocation latency and shall fail the session on expiry rather than blocking indefinitely. | T |
| PLT-HOK-005 | R1 | Hook invocations and their results shall be recorded in the audit trail of the session concerned. | T |

### 6.2 Identity resolver

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-HOK-010 | R1 | The identity resolver shall resolve a target reference to an ordered set of MC service IDs, a group, or a broadcast area. | T |
| PLT-HOK-011 | R1 | The resolver shall receive the initiator, call type, application and location context of the request. | I |
| PLT-HOK-012 | R3 | The resolver shall support dynamic binding and unbinding of role-based identities to users at runtime. | T |
| PLT-HOK-013 | R3 | The resolver shall support resolution that depends on reported location. | T |
| PLT-HOK-014 | R1 | A resolution shall record the reference it was derived from, for audit. | T |
| PLT-HOK-015 | R1 | Failure to resolve shall yield a defined reason code and shall not fall back to a partial member set. | T |

### 6.3 Priority policy

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-HOK-020 | R1 | The priority policy shall return a priority level, pre-emption scope, pre-emption capability and vulnerability flags, and a floor priority. | T |
| PLT-HOK-021 | R1 | The core shall obtain all priority and pre-emption decisions from this hook and shall implement no priority logic of its own. | I |
| PLT-HOK-022 | R1 | Priority comparison between decisions carrying different pre-emption scopes shall yield "no relation". Cross-scope pre-emption shall never occur implicitly. | T |
| PLT-HOK-023 | R1 | The policy shall be expressible as a declarative table in the profile package. | I |
| PLT-HOK-024 | R2 | The policy shall be deterministic: identical inputs shall yield identical decisions within a process lifetime. | T |

### 6.4 Session policy

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-HOK-030 | R1 | The session policy shall decide admission, returning either permission or a reason code drawn from the profile's declared closed set. | T |
| PLT-HOK-031 | R1 | The session policy shall determine session model, auto-answer, acknowledgement requirement, recording requirement and participant limit. | T |
| PLT-HOK-032 | R1 | The session policy shall supply the floor control policy: initial grant, queueing, override, queue depth and timer values. | T |
| PLT-HOK-033 | R1 | The core shall not initiate a session for which admission was refused. | T |

### 6.5 Bearer selector

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-HOK-040 | R1 | The bearer selector shall return a QoS identifier, ARP level and pre-emption flags for each media component. | T |
| PLT-HOK-041 | R3 | The bearer selector shall be able to return multiple transport paths with a designated primary and relative weights. | T |
| PLT-HOK-042 | R3 | The bearer selector shall be notified of path events and may return a revised decision. | T |
| PLT-HOK-043 | R1 | The core shall not map priority to QoS itself. | I |

### 6.6 Interworking gateway

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-HOK-050 | R4 | The interworking gateway hook shall determine whether a target requires routing to a non-MC system, and to which gateway. | T |
| PLT-HOK-051 | R4 | The hook shall map an inbound request from a non-MC system into a platform session request. | T |
| PLT-HOK-052 | R4 | A profile without interworking shall be valid; the core shall function with a hook that never routes externally. | T |

---

## 7. Identity and authentication (PLT-IDM)

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-IDM-001 | R2 | The platform shall authenticate MC service users against the IdMS using OpenID Connect per TS 24.482. | T |
| PLT-IDM-002 | R2 | The platform shall validate access token signature, issuer, audience, expiry and required scopes on every request. | T |
| PLT-IDM-003 | R2 | The platform shall reject a request whose token does not carry the scope required for the requested MC service. | T |
| PLT-IDM-004 | R2 | The platform shall bind the authenticated MC service ID to the SIP session and shall reject requests whose asserted identity differs from the bound identity. | T |
| PLT-IDM-005 | R2 | The platform shall support token refresh without interrupting an active session. | T |
| PLT-IDM-006 | R2 | The platform shall support multiple MC service IDs per user, authorised independently. | T |
| PLT-IDM-007 | R1 | In R1 the platform may operate with a stub identity provider, which shall be refused when any production indicator is set. | T |
| PLT-IDM-008 | R2 | Identity, group and configuration namespaces shall be partitioned per deployment; no request shall resolve an identity outside the loaded profile's declared domains. | T |

---

## 8. Session control (PLT-SIG, PLT-CC)

### 8.1 SIP signalling

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-SIG-001 | R1 | The platform shall interoperate with a third-party SIP core over TLS and shall not require a specific SIP core implementation. | T |
| PLT-SIG-002 | R1 | The platform shall process third-party registration and shall maintain registration state per MC service ID. | T |
| PLT-SIG-003 | R1 | The platform shall use the MC service feature tags and media feature parameters defined in TS 24.379. | T |
| PLT-SIG-004 | R1 | The platform shall reject a SIP request that is malformed, replayed, or references an unknown session, with the status code defined in TS 24.379. | T |
| PLT-SIG-005 | R1 | The platform shall not retain session state after a final failure response; state cleanup shall be verifiable. | T |
| PLT-SIG-006 | R2 | The platform shall support pre-established sessions per TS 24.379. | T |

### 8.2 Call control

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-CC-001 | R1 | The platform shall implement the participating and controlling MCPTT functions as separable roles per TS 23.379. | T |
| PLT-CC-002 | R1 | Exactly one controlling function shall exist per session. | T |
| PLT-CC-003 | R1 | The platform shall support on-demand private calls with and without automatic commencement. | T |
| PLT-CC-004 | R1 | The platform shall support prearranged group calls, fanning out invitations to the resolved member set. | T |
| PLT-CC-005 | R1 | The platform shall apply the session decision from the session policy hook without reinterpretation. | T |
| PLT-CC-006 | R2 | The platform shall support emergency and imminent-peril call origination, indication and cancellation per TS 24.379. | T |
| PLT-CC-007 | R2 | The platform shall support in-progress emergency upgrade of an ongoing group call. | T |
| PLT-CC-008 | R2 | The platform shall enforce the participant limit from the session decision, rejecting excess participants with a defined reason code. | T |
| PLT-CC-009 | R2 | The platform shall support chat group (restricted) calls. | T |
| PLT-CC-010 | R3 | The platform shall support broadcast group calls in which only declared originators may transmit. | T |
| PLT-CC-011 | R2 | The platform shall implement the call control timers of TS 24.379 using values supplied by the profile. | T |
| PLT-CC-012 | R2 | The platform shall release a session and notify participants when the controlling function becomes unavailable, rather than leaving an orphaned session. | T |

---

## 9. Floor control (PLT-FC)

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-FC-001 | R1 | The platform shall implement floor control per TS 24.380 over RTCP. | T |
| PLT-FC-002 | R1 | The platform shall implement the floor request, granted, taken, deny, release, idle, revoke and queue position messages. | T |
| PLT-FC-003 | R1 | Exactly one participant shall hold the floor in a session at any time. | T |
| PLT-FC-004 | R1 | The floor control state machine shall be implemented as a unit independently testable without media or SIP. | I |
| PLT-FC-005 | R1 | Floor arbitration shall use the floor priority supplied by the priority policy hook. | T |
| PLT-FC-006 | R1 | Floor queueing shall be enabled, bounded and ordered according to the floor policy from the session policy hook. | T |
| PLT-FC-007 | R1 | When queueing is disabled the platform shall deny rather than queue a floor request. | T |
| PLT-FC-008 | R2 | The platform shall support floor override by a higher-priority participant where the floor policy permits it. | T |
| PLT-FC-009 | R2 | The platform shall support floor revocation by an authorised participant and by policy expiry. | T |
| PLT-FC-010 | R1 | Floor control timers shall take their values from the profile; the transitions they drive shall be fixed in the core. | T |
| PLT-FC-011 | R1 | Every floor state transition shall be recorded with its trigger, timestamp and resulting state. | T |
| PLT-FC-012 | R2 | Loss of floor control messages shall not leave a session permanently without a floor holder; recovery shall occur within a bounded time. | T |

---

## 10. Media plane (PLT-MED)

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-MED-001 | R1 | The platform shall transport voice media as RTP with the codecs declared by the profile. | T |
| PLT-MED-002 | R1 | The platform shall negotiate media via SDP offer/answer and shall reject an offer with no acceptable codec. | T |
| PLT-MED-003 | R1 | The platform shall replicate media from the floor holder to all session participants. | T |
| PLT-MED-004 | R2 | The platform shall transport media as SRTP with keys derived from the MC key management, and shall not fall back to unprotected RTP when security is enabled. | T |
| PLT-MED-005 | R2 | The platform shall not transmit media from a participant that does not hold the floor. | T |
| PLT-MED-006 | R4 | The platform shall support delivery of group media over MBS/MBMS where available, with unicast fallback. | T |
| PLT-MED-007 | R4 | The platform shall support MCVideo media sessions per TS 23.281. | T |

---

## 11. Group, configuration and location management (PLT-GRP)

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-GRP-001 | R1 | The platform shall serve group documents per TS 24.481 over HTTP. | T |
| PLT-GRP-002 | R2 | The platform shall serve MC service configuration, user profile and UE configuration documents per TS 24.484. | T |
| PLT-GRP-003 | R2 | The platform shall notify subscribed clients of changes to group and configuration documents. | T |
| PLT-GRP-004 | R2 | The platform shall version configuration documents and shall reject an update based on a stale version. | T |
| PLT-GRP-005 | R2 | The platform shall support group creation, modification, deletion and membership management by an authorised administrator. | T |
| PLT-GRP-006 | R3 | The platform shall support temporary group formation from constituent groups. | T |
| PLT-GRP-007 | R2 | The platform shall accept location reports and shall make reported location available to the identity resolver hook. | T |
| PLT-GRP-008 | R2 | Location reporting triggers shall be configurable per user and per group. | T |
| PLT-GRP-009 | R2 | Group and configuration documents shall be scoped to the loaded profile's declared domains. | T |

---

## 12. MCData (PLT-DAT)

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-DAT-001 | R2 | The platform shall support MCData short data service for one-to-one and group delivery per TS 24.282. | T |
| PLT-DAT-002 | R2 | The platform shall support delivery and read notifications where requested. | T |
| PLT-DAT-003 | R2 | The platform shall enforce the SDS payload size limit and shall reject oversized payloads with a defined reason code. | T |
| PLT-DAT-004 | R3 | The platform shall support MCData file distribution with HTTP-based content retrieval. | T |
| PLT-DAT-005 | R3 | The platform shall support MCData IP connectivity (IPcon) sessions. | T |
| PLT-DAT-006 | R3 | IPcon sessions shall obtain their bearer decision from the bearer selector hook, including multi-path decisions. | T |
| PLT-DAT-007 | R3 | The platform shall apply the priority decision to IPcon sessions on the same basis as voice sessions. | T |
| PLT-DAT-008 | R3 | An IPcon session shall be establishable as a pre-established session surviving individual path failures. | T |

---

## 13. Priority, pre-emption and admission (PLT-PRI)

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-PRI-001 | R1 | Every session shall carry exactly one priority decision, obtained at admission. | T |
| PLT-PRI-002 | R2 | The platform shall pre-empt an existing session only when the incoming decision has pre-emption capability, the existing decision has pre-emption vulnerability, and both carry the same pre-emption scope. | T |
| PLT-PRI-003 | R2 | The platform shall never pre-empt across pre-emption scopes. | T |
| PLT-PRI-004 | R2 | A pre-empted session shall be released with a distinguishable cause, and its participants notified. | T |
| PLT-PRI-005 | R2 | The platform shall record, for each pre-emption, both decisions, the scope, and the sessions concerned. | T |
| PLT-PRI-006 | R2 | The platform shall enforce a configured maximum concurrent session count. | T |
| PLT-PRI-007 | R2 | The platform shall reserve capacity per urgency class as declared by the profile, and shall not admit lower-urgency sessions into reserved capacity. | T |
| PLT-PRI-008 | R2 | Capacity exhaustion shall yield a defined reason code, distinguishable from authorisation failure. | T |
| PLT-PRI-009 | R2 | Priority shall not be the sole mechanism protecting a safety-relevant service from overload; reserved capacity shall be independently configurable. | A |

---

## 14. FRMCS profile requirements (PLT-RAIL) `[PROVISIONAL]`

> These requirements define the FRMCS profile and its hook implementations. They
> do not constrain the core. Values and semantics require reconciliation with the
> UIC FRMCS FRS/SRS before baselining.

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-RAIL-001 | R3 | The FRMCS profile shall implement functional addressing, resolving role-based identities to users at call setup. | T |
| PLT-RAIL-002 | R3 | Functional identity bindings shall be established and released at runtime, and shall be queryable per user and per identity. | T |
| PLT-RAIL-003 | R3 | The profile shall support location-dependent addressing, resolving an identity using the reported location attribute declared for it. | T |
| PLT-RAIL-004 | R3 | A functional identity declared as single-holder shall not resolve to more than one user; conflicting binding shall be refused. | T |
| PLT-RAIL-005 | R3 | Failure to resolve a functional identity shall yield a distinct reason code separate from unknown-user. | T |
| PLT-RAIL-006 | R3 | The profile shall define a railway emergency communication call type, delivered as a broadcast session to all users in the addressed area. | T |
| PLT-RAIL-007 | R3 | REC shall carry the highest priority level within the railway pre-emption scope and shall be non-vulnerable to pre-emption. | T |
| PLT-RAIL-008 | R3 | REC shall auto-answer at receiving clients and shall require acknowledgement. | T |
| PLT-RAIL-009 | R3 | The profile shall define call types for shunting and for driver-to-controller communication. | T |
| PLT-RAIL-010 | R3 | The profile shall define application categories for safety-relevant data services carried over IPcon, each flagged as safety-relevant. | T |
| PLT-RAIL-011 | R3 | Safety-relevant data applications shall be assigned multi-homed transport with an identified primary and at least one alternate path. | T |
| PLT-RAIL-012 | R3 | Path failure shall trigger transfer to an alternate path within the bound defined in §16, without session release. | T |
| PLT-RAIL-013 | R3 | The FRMCS profile shall declare a single pre-emption scope, distinct from any non-railway scope. | I |
| PLT-RAIL-014 | R3 | All FRMCS call types shall require recording. | T |
| PLT-RAIL-015 | R4 | The profile shall route to GSM-R through the interworking hook, mapping call types and functional identities in both directions. | T |
| PLT-RAIL-016 | R3 | Implementing the FRMCS profile shall require no change to code under `core/`; any such change shall be raised as a boundary defect. | A |
| PLT-RAIL-017 | R3 | FRMCS gateways shall interface to the platform as MC clients; the core shall hold no gateway-specific logic. | I |

---

## 14A. Interconnection with partner MC systems (PLT-ICX)

Interconnection is distinct from interworking (§14 / PLT-HOK-050..052). A partner
MC system speaks MC protocols natively, so nothing is translated; what must be
reconciled is **policy**. It is also the only mechanism by which a system outside
the operator's control obtains authority *inside* their system, which is why the
requirements below are written as constraints on what a partner cannot do.

### 14A.1 The scope-mapping model

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-ICX-001 | R3 | The platform shall treat a target in a partner MC system as a distinct resolution outcome from a target in a non-MC system. | T |
| PLT-ICX-002 | R3 | A partner resolution shall carry no local members, and shall record the partner target for audit. | T |
| PLT-ICX-003 | R3 | A session routed to a partner shall be established toward the partner gateway only, and shall never also be established locally. | T |
| PLT-ICX-004 | R3 | The platform shall never derive a local priority from a partner's asserted priority level. Mapping shall be by declared label. | T |
| PLT-ICX-005 | R3 | Each partner shall be assigned a local pre-emption scope. A partner shall not introduce a pre-emption scope of its own. | T |
| PLT-ICX-006 | R3 | Each partner shall be assigned a maximum priority level. No mapping shall yield a level above it, enforced at validation and again at runtime. | T |
| PLT-ICX-007 | R3 | The ceiling for a partner shall be configurable below the local levels the operator wishes to protect, and the platform shall not prevent it being set to zero. | I |
| PLT-ICX-008 | R3 | A partner shall have no pre-emption capability unless explicitly granted to that partner. | T |
| PLT-ICX-009 | R3 | A session originating from a partner shall always be locally pre-emptible: it shall never be harder to displace than a local session. | T |
| PLT-ICX-010 | R3 | An assertion the profile does not map shall be refused. The platform shall not supply a default priority for an unmapped assertion. | T |
| PLT-ICX-011 | R3 | An undeclared partner shall receive no rights. The platform shall not supply default rights for an unknown partner. | T |
| PLT-ICX-012 | R3 | Each partner shall declare which call types are permitted with it; a call type outside that set shall be refused with a distinct reason code. | T |
| PLT-ICX-013 | R3 | A partner target for which no route is produced shall be refused, never established locally. | T |

### 14A.2 Trust and authentication

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-ICX-020 | R3 | A partner system shall be authenticated by a declared mechanism. A partner identity asserted in an unauthenticated field shall not be accepted as an identity. | T |
| PLT-ICX-021 | R3 | The authentication mechanism in force shall be recorded with the session. | T |
| PLT-ICX-022 | R3 | Rights shall be declared per partner. The platform shall not support a rights declaration applying to all partners collectively. | I |
| PLT-ICX-023 | R4 | Key management across a system boundary shall follow TS 33.180. Cross-domain key management is not in R3 scope and interconnection before R4 shall be confined to deployments sharing a security domain. | A |

### 14A.3 Asymmetry and governance

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-ICX-030 | R3 | Each deployment shall declare what a partner may do within it, independently of what that partner declares in return. The platform shall not require the two declarations to agree. | T |
| PLT-ICX-031 | R3 | A partner declaration shall be validated against the local profile: an undeclared scope, call type or reason code shall prevent start. | T |
| PLT-ICX-032 | R3 | A profile declaring no partners shall be valid, and shall produce no partner resolution. | T |
| PLT-ICX-033 | R3 | Every session involving a partner shall record the partner identity, the asserted values and the mapped local decision, so an operator can reconstruct what authority was granted and why. | T |

### 14A.4 Open points

| # | Question | Needed by |
|---|---|---|
| ICX-OP-01 | Confirm interconnection reference-point naming and whether the target release uses an MC gateway server as the edge entity (TS 23.280). | R3 start |
| ICX-OP-02 | Migration (a user of one system registering into another) is out of scope here and needs its own requirements. Decide whether it is required at all. | R3 planning |
| ICX-OP-03 | Floor control across an interconnection: which system arbitrates a group spanning both, and what happens to queue and override semantics. | R3 start |
| ICX-OP-04 | Cross-domain key management under TS 33.180 (PLT-ICX-023) is a substantial piece in its own right; scope it before committing to a date. | R4 planning |


---

## 15. Security (PLT-SEC)

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-SEC-001 | R2 | The platform shall implement MC security per TS 33.180. | T |
| PLT-SEC-002 | R2 | Key material shall be obtained from the KMS; the platform shall not generate long-term group or user key material itself. | I |
| PLT-SEC-003 | R2 | The platform shall support MIKEY-SAKKE key distribution for group, private call and client-server signalling keys. | T |
| PLT-SEC-004 | R2 | KMS domains shall be partitioned per deployment; key material shall not be shared across profiles or across deployments. | T |
| PLT-SEC-005 | R2 | The platform shall protect signalling between client and server with the client-server key. | T |
| PLT-SEC-006 | R2 | The platform shall support group key rekeying without session interruption, and shall support forced rekey on membership change. | T |
| PLT-SEC-007 | R1 | All external interfaces shall use TLS with mutual authentication where the peer supports it, and shall reject plaintext connections. | T |
| PLT-SEC-008 | R2 | Operation with security disabled shall be possible only in a development mode that is refused when any production indicator is set. | T |
| PLT-SEC-009 | R2 | The platform shall not log key material, token values, or media content. | I |
| PLT-SEC-010 | R2 | Authorisation shall be enforced at the controlling function, not only at the client or participating function. | T |
| PLT-SEC-011 | R3 | The platform shall support revocation of a user's authorisation taking effect on active sessions within a bounded time. | T |
| PLT-SEC-012 | R2 | Cryptographic algorithm selection shall be configurable, with a documented minimum acceptable set. | I |

---

## 16. Performance and capacity (PLT-NFR)

> Provisional targets. To be confirmed against the deployment's own KPIs;
> railway figures additionally against the UIC SRS.

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-NFR-001 | R2 | Group call setup, from request received to first invitation sent, shall complete within 300 ms at the specified load, excluding network transit. | T |
| PLT-NFR-002 | R2 | Floor grant, from floor request received to grant sent, shall complete within 100 ms at the specified load. | T |
| PLT-NFR-003 | R2 | Media forwarding shall add no more than 20 ms to the end-to-end path at the specified load. | T |
| PLT-NFR-004 | R3 | Emergency and railway-emergency session setup shall meet the above bounds while the platform is at its configured maximum concurrent session count. | T |
| PLT-NFR-005 | R3 | Transfer to an alternate transport path shall complete within 1 s of path failure detection, without session release. | T |
| PLT-NFR-006 | R2 | The platform shall sustain its configured maximum concurrent session count with no degradation of the above bounds. | T |
| PLT-NFR-007 | R2 | A single instance failure shall not release sessions hosted by other instances. | T |
| PLT-NFR-008 | R3 | Platform availability shall meet the target recorded in the deployment's RAMS specification. | A |
| PLT-NFR-009 | R2 | Performance figures shall be established by measurement under a documented load profile, not by estimation. | T |

---

## 17. Operations, logging and audit (PLT-OAM)

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-OAM-001 | R1 | The platform shall log the loaded profile's name, version and content hash at start, and shall include them in every audit record. | T |
| PLT-OAM-002 | R1 | The platform shall record an audit entry for every session admission, refusal, establishment, release and pre-emption. | T |
| PLT-OAM-003 | R2 | Audit records shall be tamper-evident and shall be retained for the period required by the deployment. | T |
| PLT-OAM-004 | R2 | The platform shall record the resolved member set and the reference it was resolved from, for every session. | T |
| PLT-OAM-005 | R1 | Logs shall be structured and machine-parsable, with a stable correlation identifier per session. | T |
| PLT-OAM-006 | R2 | The platform shall expose metrics for session counts, setup latency, floor grant latency, pre-emptions and admission refusals by reason code. | T |
| PLT-OAM-007 | R1 | The platform shall expose liveness and readiness endpoints; readiness shall be false until the profile is validated and loaded. | T |
| PLT-OAM-008 | R2 | The platform shall support recording of media for call types whose session decision requires it, and shall refuse to establish such a session when recording is unavailable. | T |
| PLT-OAM-009 | R2 | Operational interfaces shall be authenticated and authorised separately from MC service users. | T |

---

## 18. Verification and conformance (PLT-VER)

| ID | Phase | Requirement | V |
|---|---|---|---|
| PLT-VER-001 | R1 | A conformance suite shall exist per profile, exercising the same binary. | I |
| PLT-VER-002 | R1 | Both profile suites shall run in continuous integration on every change. | I |
| PLT-VER-003 | R1 | A change to the core that breaks one profile suite and not the other shall be treated as a boundary defect. | A |
| PLT-VER-004 | R1 | A CI gate shall reject any profile-specific identifier appearing under `core/`. | T |
| PLT-VER-005 | R1 | A trace comparison harness shall verify captured signalling against expected message flows per call type. | T |
| PLT-VER-006 | R2 | The floor control state machine shall be verified by exhaustive transition testing independent of media and SIP. | T |
| PLT-VER-007 | R2 | Profile validation shall be tested with deliberately malformed profiles covering each rejection class in §5.1. | T |
| PLT-VER-008 | R3 | Each requirement in this document shall be traceable to at least one verification artefact. | I |
| PLT-VER-009 | R3 | For the FRMCS deployment, verification evidence shall be structured to support the EN 50128/50129 assurance process. | A |
| PLT-VER-010 | R2 | The platform should be exercised against third-party implementations at an interoperability event before each major release. | D |

---

## 19. Open points

| # | Question | Owner | Needed by |
|---|---|---|---|
| OP-01 | Reconcile §14 against the current UIC FRMCS FRS/SRS baseline | — | R3 start |
| OP-02 | Confirm performance targets in §16 against deployment KPIs and UIC SRS | — | R2 exit |
| OP-03 | Determine software safety integrity level applicable to the FRMCS deployment, and which components fall in scope | — | R3 start |
| OP-04 | Decide whether MCVideo is in the target scope or is deferred indefinitely | — | R4 planning |
| OP-05 | Select the SIP core, IdMS and KMS products, and confirm each supports the interfaces in §3.1 | — | R2 start |
| OP-06 | Confirm codec set per profile | — | R1 exit |
| OP-07 | Define the load profile underlying §16 | — | R2 start |
| OP-08 | Decide off-network (ProSe) scope and whether it applies to both profiles | — | R4 planning |

---

## 20. Revision history

| Version | Date | Change |
|---|---|---|
| 0.2 | 2026-09-19 | Added §14A (PLT-ICX, 26 requirements) for interconnection with partner MC systems, distinct from interworking. R3 exit criterion extended. |
| 0.1 | 2026-09-19 | Initial draft |
