# Specification conformance audit — R1

**Document:** PLT-CONF-AUDIT
**Version:** 0.6
**Date:** 2026-09-21
**Scope:** every protocol constant in the codebase that was written from
recollection rather than read from a specification.

---

## 1. Why this exists

`FC-OP-03` recorded that the RTCP encoding in `core/rtcp.py` was "reconstructed
from memory, not checked against TS 24.380", and that `tools/trace_compare.py`
was written from the same recollection, so agreement between them was "a
consistency check only".

That is the circular-validation trap, and it was correct. The first constant set
ever checked against a real specification was wrong, and so was the second.

**Six of the seven constant sets checked have contained defects.** The one
exception, the floor control timer defaults, is recorded in 4.11 as
prominently as the failures. That is the prior to carry into the items still
unverified in §5, and it is strong enough that "probably fine" should not be
said about any of them.

The defects have also changed character. The early ones were wrong values.
The later ones are **absent rules** — eleven field ids with no length
constraint at all (4.12), a UTF-8 check applied to a binary field (4.13), a
comparator table missing most of what the specification permits (4.15). A
wrong value fails loudly the first time it meets a conformant peer. A missing
rule never fails at all; it just accepts things it should not, until one of
them matters.

---

## 2. Method, and how it changed

**Versions 0.1-0.2** worked from automated extraction of the ETSI PDF mirrors.
That method failed, and failed in the worst available way: asked for the floor
control subtype table, it returned a clean, plausible, sequential table that
does not exist in the specification. The real table is non-sequential, with
Floor Taken at 2 before Floor Deny at 3. **Automated extraction of a structured
table does not degrade into obvious nonsense; it invents plausible structure.**
A result from it is a lead, never a finding.

**Version 0.3** works from the source documents in `docs/3GPP/`, which are the
3GPP `.docx` originals. Paragraphs and table cells are read in document order,
so a table is read as a table. Where a value appears both in normative text and
in a signalling flow in the annexes, both were checked.

Two classes of limit remain, and both are recorded against specific findings
rather than waved at:

1. **Non-3GPP references.** TS 24.481 defines an MCS group document as the OMA
   XDM Group structure "with the MCS specific clarifications specified in this
   subclause". The OMA document is not a 3GPP deliverable and is not here, so
   the OMA-defined part of the structure cannot be schema-validated. Likewise
   RFC 8101, RFC 3840 and TS 29.379.
2. **Sibling service specifications.** TS 24.379 is the MCPTT specification.
   The MCData and MCVideo feature tags live in TS 24.282 and TS 24.281, which
   are not here, so those two constants remain unverified.

**Corroboration.** Every finding below was checked against at least two
releases (Rel-17 and Rel-20 for TS 24.379; Rel-17 and Rel-19 for TS 24.481).
Where the two disagree it is said so.

---

## 3. Findings from the PDF mirrors (v0.1-0.2)

### 3.1 RTCP floor control subtypes were uniformly one low

**Source:** ETSI TS 124 380 V18.6.0, table 8.2.2-1.

Every subtype in `core/rtcp.py` was one less than the specification: Floor
Request 0 where the specification says 1, through Floor Ack 9 where it says 10.
`encode` writes the enum value onto the wire with no offset, so **every floor
control message the platform sent would have been unintelligible to a conformant
peer.**

**Corroboration:** all 14 floor-control field IDs, the `MCPT` name and PT=204
already matched exactly. A systematic off-by-one on one table alongside perfect
agreement on sixteen constants is the signature of a transcription error in the
code, not of a faulty source.

**Circularity demonstrated:** correcting `core/rtcp.py` alone broke five tests —
the two hand-assembled "known answer" vectors and the comparator's own decoder,
both written from the same recollection. The comparator does not import
`core.rtcp`, so it was structurally independent but not *epistemically* so. All
three had to be corrected together.

**Status:** corrected. Subtypes 11 and 12 reserved so an inbound message decodes
rather than raising "unknown subtype".

### 3.2 Floor control used the wrong timer family entirely

**Source:** ETSI TS 124 380 V15.4.0 and V18.6.0, which agree.

`core/floor.py` implements the **on-network floor control server**. It was
parameterised with T201, T203, T205 and T206 — which clause 7.2.3 defines as
**off-network participant** timers. Not a mislabelling: the wrong family for the
role the platform implements.

| Was | Is | On-network server timer, clause 6.3 |
|---|---|---|
| T203 (off-network end of RTP media) | **T2** | stop talking |
| T205 (off-network floor granted) | **T20** | floor granted |
| T206 (off-network tx limit warning) | **T8** | media revoke |
| T201 (participant floor request) | removed | a server never drives it |

`core/validation.py` now accepts only the on-network set and **rejects** the
T2xx family, because a profile declaring an off-network timer for an on-network
deployment is making a category error that should fail validation rather than be
silently honoured. The off-network names are added when off-network operation
arrives (R4).

**Status:** corrected across `core/floor.py`, `core/validation.py`, all three
profiles and the tests.

### 3.3 Deny and Revoke cause codes were one namespace, not two

**Source:** TS 24.380 V17.7.0 clauses 8.2.6.2 and 8.2.10.2, re-verified for
this revision.

`core/rtcp.py` had a single `CAUSE_*` table. The specification has two, and
they collide: value 2 is "Internal floor control server error" in a Floor Deny
and "Media burst too long" in a Floor Revoke. A revoked talker would have been
told the server had an internal error.

**Status:** corrected. `DENY_*` (1-7, 255) and `REVOKE_*` (1, 2, 3, 4, 6, 255)
are separate namespaces; `CAUSE_*` remains as aliases of the Deny set.

---

## 3A. CA-11 — the release baseline, and its resolution

Found while re-verifying 3.3. Not a constant defect: a statement about the
whole codebase.

`CLAUDE.md` declared a **Rel-17 baseline**. The RTCP layer was not Rel-17:

| Constant | First defined in | What Rel-17 says |
|---|---|---|
| `REVOKE_REQUEST = 7` (subtype) | Rel-19 | subtype 00111 is not assigned |
| `FLOOR_REVOKE_REQUEST_USER_ID = 25` | Rel-19 | field 25 is not assigned |
| `REVOKE_BY_ANOTHER_CLIENT = 7` | Rel-19 | Floor Revoke has no cause #7 |
| `QUEUED_FLOOR_REQUESTS = 14` | **renamed in Rel-18** | subtype 01110 is **Floor Queued Cancel** |

None of the four values is wrong; all are correct for the release that
introduced them. The problem was that the project said one thing and the code
did another.

**Correction to v0.3:** that revision said subtype 14 changed meaning between
Rel-17 and Rel-19. It changed at **Rel-18**. The tables were later extracted
mechanically from all eight published versions of TS 24.380 (Rel-13 `de0`
through Rel-20 `k00`), which is what produced the exact boundary; the v0.3
figure was read off two releases and interpolated. Interpolation is a guess
with a citation attached.

### The resolution: the release is now a deployment parameter

Neither of the two options v0.3 offered — move the baseline to Rel-19, or
delete the four values — was right, because both answer "which release is this
platform?" when the real question is "which release is *this deployment*?" A
platform serving a Rel-17 fleet and a platform serving a Rel-19 fleet are the
same codebase, and the profile mechanism already exists to say so.

`MCX_RELEASE` now selects the release at process start, exactly as
`MCX_PROFILE` selects the profile, and on an independent axis: any profile at
any supported release (PLT-REL-001..008, `core/release.py`).

**Why this is not a feature flag.** The dangerous case is not a missing value,
which any decoder would reject. It is subtype 14: assigned in both Rel-17 and
Rel-18, to different messages, with nothing in the packet to distinguish them.
"Be liberal in what you accept" cannot help, because both readings are valid —
only the release decides. So the release governs *decoding* as well as
encoding, and `Codec.name_of` reports the release-correct meaning, which
`MsgType` structurally cannot: it holds one name per value, and subtype 14
needs two.

**Provenance.** Every table in `core/release.py` — subtype, field ID and revoke
cause, per release — was extracted mechanically from the eight `.docx`
originals rather than annotated by hand. The pre-existing release comments on
`FieldId` all turned out to be correct, which the extraction confirmed rather
than assumed.

**Status:** closed. Eight releases tabulated, six mutants checked and dead, two
new boundary gates (VP1-BND-022, VP1-BND-023), and the conformance suite now
runs as a profile × release matrix.

**What is NOT covered:** only the TS 24.380 floor control layer. TS 24.379 has
not been examined for release dependence — PLT-REL-009 and **REL-OP-01**.

---

## 4. Findings from the source documents (v0.3)

TS 24.379 and TS 24.481 became available in `docs/3GPP/`. This closes CA-02 and
CA-04, and closes CA-06 as far as the MCPTT specification can close it.

### 4.1 CA-02 — none of the eleven warning codes was right

**Source:** TS 24.379 V17.15.0 table 4.4.2-2, corroborated against V20.0.0.

Every code in `WARNING_TEXTS` was invented when `core/sip.py` was written, and
it was flagged as such at the time. **Zero of eleven were correct.** One
(`not-authorised` at 100) had the right number attached to the wrong text.

What makes this worse than a set of unrecognised codes is that the invented
numbers are all real codes meaning something else:

| Reason code | Emitted | What TS 24.379 says that code means |
|---|---|---|
| `partner-not-permitted` | 110 | **user declined the call invitation** |
| `capacity-exhausted` | 102 | too many simultaneous affiliations |
| `unknown-target` | 103 | maximum simultaneous MCPTT group calls reached |
| `no-binding` | 104 | isfocus not assigned |
| `no-location-binding` | 105 | subscription not allowed in a broadcast group call |
| `call-type-not-permitted` | 101 | service authorisation failed |
| `recording-unavailable` | 106 | user not authorised to join chat group |
| `qos-unavailable` | 107 | user not authorised to make private calls |
| `gateway-unavailable` | 108 | user not authorised to make chat group calls |
| `partner-unavailable` | 109 | user not authorised to make prearranged group calls |

A peer would not have failed to parse these. It would have parsed them and been
confidently misinformed — an operator's trace would have shown a called user
declining a call that was actually refused by partner policy.

**Corrected.** Four reason codes have a specification code whose own
description matches what the platform means:

| Reason code | Code | Text |
|---|---|---|
| `unknown-target` | 145 | unable to determine called party |
| `not-authorised` | 100 | function not allowed due to user authorisation |
| `call-type-not-permitted` | 100 | function not allowed due to local policy |
| `partner-not-permitted` | 179 | service not authorized with the interconnected system |

Code 100 takes a `<detailed reason>`, which the table defines as one of five
enumerated strings or free text. Two reasons above use two different enumerated
values, which is what that mechanism exists for.

**The other seven have no faithful code, and none was invented for them.** They
are listed in `REFUSALS_WITHOUT_WARNING_TEXT`, each with the reason the nearest
neighbour was rejected — for instance 141 is not `no-binding`, because it means
the participating function could not associate a public user identity with an
MCPTT ID, which is the opposite direction from a known identity that nobody
currently holds.

### 4.2 CA-02b — the Warning header itself was malformed

**Source:** TS 24.379 clause 4.4.1 and its example.

Found while correcting the codes, and more consequential than they are. The
specification's own example:

```
Warning: 399 "100 User not authorised to make group calls"
```

The clause body requires the warn-code 399 **and** "the host name set to the
host name of the MCPTT server"; the example above illustrates only the quoted
warn-text, and omits the host name its own clause mandates. Taken together:
399, then the host, then the MC 3-digit code **inside** the quoted warn-text.

The platform emitted

```
Warning: 100 mcx "target user not known"
```

— the MC code in the RFC 3261 warn-code position, where values below 300 are
not legal warn-codes at all, and the literal string `mcx` where the server's
host name belongs. **Every Warning header the platform emitted was invalid**,
independently of whether the code inside it was right.

**Corrected.** `Adapter` derives the host from its own URI; the rendering is
pinned by a test that asserts the complete header string.

### 4.3 CA-02c — the seven unmapped refusals still need a trace

Dropping the Warning header for the seven unmapped reasons would have broken
`PLT-PRI-008`: `capacity-exhausted` and `hook-error` are both 503, and the
Warning header was the only thing distinguishing a decision from a fault.

Table 4.4.2-1 defines the MC warn-text form with `=/`, an ABNF **incremental
alternative**: it adds a permitted shape, it does not replace RFC 3261's. A
plain warn-text therefore stays legal. The seven now emit
`Warning: 399 <host> "<plain text>"` with no code, and a test enforces that no
local text begins with three digits, so none can be misread as a code.

This is the same judgement as the platform's existing "refuse rather than
substitute a default" rule, applied to a protocol field: say nothing specific
rather than say something specific and wrong.

### 4.4 CA-06 — the ICSI was missing from every INVITE

**Source:** TS 24.379 clauses 6.3.2.1.x, 6.3.3.1.x and the flows in annex F,
which agree verbatim.

The specification requires **two** Accept-Contact header fields, not one
combined value: one carrying `g.3gpp.mcptt`, one carrying `g.3gpp.icsi-ref`
set to `urn:urn-7:3gpp-service.ims.icsi.mcptt`, each with `require` and
`explicit`. The platform sent one header, and the ICSI reference appeared
nowhere in the message — not in Accept-Contact and not in Contact.

**Corrected**, matching the wire format in the annex F flows:

```
Accept-Contact: *;+g.3gpp.mcptt;require;explicit
Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt";require;explicit
```

### 4.5 CA-06b — `Priv-Answer-Mode` was sent on every call

**Source:** TS 24.379 clause 11.1.1.2.1, corroborated by clause 6.3.2.2.5.2.

Clause 11.1.1.2.1 gives three **mutually exclusive** branches: forced automatic
commencement sends `Priv-Answer-Mode: Auto`; unforced automatic commencement
sends `Answer-Mode: Auto`; manual sends `Answer-Mode: Manual`. The platform
sent *both* headers for auto-answer, and `Priv-Answer-Mode: Manual` otherwise —
a value no branch produces.

`Priv-Answer-Mode` is the privileged forced-auto-answer request, and its mere
presence is a trigger condition at the terminating participating function
(clause 6.3.2.2.5.2); a user not authorised to force it is refused with warning
code 143. Sending it on every ordinary call makes every call look privileged.

**Corrected to the forced branch for auto-answer and the manual branch
otherwise.** Which branch `auto_answer` means is a decision, not a
transcription: `Answer-Mode: Auto` alone takes effect only if the invited
client's own settings already say auto-answer, so it would leave `VP1-CC-004`
("established without callee action") at the mercy of a handset setting. Only
the forced branch delivers what the verification case requires.

**New open point SIP-OP-07:** the platform consequently cannot express the
unforced automatic branch at all. Adding it is a profile schema key, a
validation rule, an ICD revision and three profiles in one change set — an
interface change, not an audit correction.

### 4.6 CA-06c — two constants that should never have been in `core/`

**Source:** TS 24.379 clauses 6.3.3.1.19 and 6.3.2.1.8.4.

`core/sip.py` carried:

```python
# RFC 4412 resource priority namespaces used for MC services.
RP_NAMESPACE_NORMAL = "mcpttp"
RP_NAMESPACE_EMERGENCY = "mcpttq"
```

Three things are wrong with those two lines:

1. **The citation.** RFC 4412 defines the Resource-Priority header field. The
   MCPTT namespaces are registered by RFC 8101, which TS 24.379 cites as [48].
2. **The values are unverifiable from anything in this repository.** The
   strings `mcpttp` and `mcpttq` appear nowhere in TS 24.379 in any release.
3. **They are not constants.** The specification retrieves the namespace from
   the `<resource-priority-namespace>` element of the service configuration
   document (TS 24.484). It is per-deployment configuration.

The third is the serious one. This is the platform's own boundary rule —
`core/` must never carry deployment-specific values — violated by a pair of
literals that looked like protocol constants because they were labelled as
protocol constants. The boundary gates did not catch it because they look for
profile *names*, not for configuration wearing a constant's costume.

**Corrected by deletion**, with a test asserting the names stay absent. Nothing
read them, so nothing broke — which is why this survived review three times.

### 4.7 CA-04 — the group document was invalid in four ways

**Source:** TS 24.481 V17.8.0 clauses 7.2.2, 7.2.8 and 7.2.6, with the
worked example in clause A.2; corroborated against V19.3.0.

| | Was | Is |
|---|---|---|
| Root element | `<list-service>` | `<group>`, with `<list-service>` beneath it |
| Namespace | `urn:ietf:params:xml:ns:resource-lists` | `urn:oma:xml:poc:list-service` |
| `<supported-services>` | absent | **mandatory** ("shall include") |
| Media type | `application/xml` | `application/vnd.oma.poc.groups+xml` (see below) |

The missing element is the one that matters. Clause 7.2.8 (Data semantics) says a group
document *is* an MCPTT group document **only if** `<supported-services>` is
present, contains a `<service>` whose `enabler` attribute is the MCPTT ICSI,
which contains a `<group-media>`, which contains `<mcptt-speech>`. The renderer
satisfied none of those five conditions, so a conformant group management
server would not have recognised the document as an MCPTT group at all.

**Corrected**, and each of the five conditions is pinned by its own assertion
so that dropping any one of them fails a test on its own.

**The media type has no normative basis in TS 24.481.** Clause 7.2.6 is one
sentence that defers entirely to OMA XDM Group. The string appears exactly once
in the whole document, as the `Content-Type` of an XCAP PUT in **Annex A, which
is informative**. `application/vnd.oma.poc.groups+xml` is still far better
grounded than `application/xml`, which had no basis at all, but it rests on an
informative example until the OMA document is obtained. This is part of CA-08,
not separate from it.

**`SVC-OP-01` narrows but does not close.** Clause 7.2.2 defines the structure
as OMA XDM Group's "with the MCS specific clarifications specified in this
subclause". Everything 24.481 itself specifies is now checked. Full XSD
validation of the OMA-defined remainder needs **OMA-TS-XDM_Group-V1_1_1**,
which is not a 3GPP deliverable — this is the one concrete document still
blocking `VP1-DOC-001`'s "schema-valid" clause.

### 4.8 Two constants that were already right

Recorded because "we checked and it was fine" is a finding, and because one of
them looks wrong in the document:

- **Answer-Mode values `Auto` and `Manual`** are correct for what this
  platform emits. The `"Automatic"` spelling appears once against 36
  occurrences of `"Auto"` in Rel-17, and once against 45 in Rel-20.

  **An earlier draft of this document called that an editorial error. It is
  not.** `"Automatic"` is a live normative value in clause 11.1.1.2.2.1, the
  private call over a **pre-established session**, unchanged from Rel-17 to
  Rel-20 — while clause 11.1.1.2.1.1, the on-demand case, says `"Auto"` for
  the identical meaning. It is an unresolved inconsistency inside 3GPP, not a
  typo that has been abandoned.

  The consequence is for the **receiver**, not the renderer: a parser that
  accepts only `"Auto"` is non-conformant on the pre-established path.
  Recorded as **SIP-OP-08**. This platform does not implement pre-established
  sessions, so nothing is wrong today.
- **The content types** `application/vnd.3gpp.mcptt-info+xml`,
  `application/vnd.3gpp.mcptt-location-info+xml`, `application/resource-lists+xml`
  and `application/sdp` all appear as written, the first 932 times.

### 4.9 A defect introduced by this audit's own correction

`Adapter.reject` was changed to take the warn-agent from the server's URI
instead of the literal `mcx`. The helper that extracted it split on `"@"` and
then on `":"`:

```python
tail = uri.split("@")[-1].strip("<>")
return tail.split(";")[0].split(":")[0] or uri
```

A participating or controlling function is reachable at a **public service
identity** (TS 24.379 clause 4.2), which has no userinfo: `sip:ps.mcptt.example`.
For every URI of that shape the `"@"` split is a no-op and the `":"` split
returns the **scheme**, so a realistic deployment would have emitted

```
Warning: 399 sip "145 unable to determine called party"
```

— the same class of defect it was written to fix. Every test in `test_sip.py`
constructed the adapter with `sip:server@mcptt.example`, the one shape that
masks it, and the test asserting the header therefore passed.

The same correction had also been applied to `Adapter.reject` only; the
`InboundGuard` rejection path still carried the literal `mcx`, so clause 4.4.1
conformance was claimed module-wide and reached one of two paths.

**Both corrected**, and pinned by a test that asserts a host name for five URI
shapes including a bare PSI and an IPv6 reference, plus one for the guard.

**This was found by an independent check, not by the work that produced it.**
That is the argument for keeping the final verification pass separate from the
implementation, and it is now the third time in this document that a fix has
needed its own audit.

### 4.10 A surviving mutant, in a test written for this audit

Changing the ICSI in `service/groups.py` to the MCVideo value left the suite
green. The pinning test imported `MCPTT_ICSI` from the module it was checking,
so the renderer and the assertion moved together — the same circular validation
this document exists to name, reintroduced by the fix for it.

Both ICSI assertions now spell the value out as a literal. **A conformance test
that imports the constant it is pinning is not a conformance test.**

---

### 4.11 CA-05 — the first constant set that was already right

**Source:** TS 24.380 V17.7.0 table 11.1.3-1 (floor control server
procedures), corroborated against V20.0.0, which is identical.

| Timer | Code | Specification |
|---|---|---|
| T2 (Stop talking) | 30000 ms | Default **maximum** value: 30 seconds |
| T8 (Floor Revoke) | 1000 ms | Default value: 1 second |
| T20 (Floor Granted) | 1000 ms | Default value: 1 second |

**Three for three.** After five consecutive constant sets that were wrong, this
one was not. It is recorded as prominently as the defects, because an audit
that only reports failures stops being evidence and becomes a search for
confirmation.

Two things the values alone do not show:

- **T2 is a maximum, not a duration.** The specification says "Default
  *maximum* value", and it is obtained from `<time-limit>` of `<transmit-time>`
  in TS 24.484 — a talk-time limit — while T8 and T20 come from
  `<fc-timers-counters>`. A deployment tuning T2 is changing how long a user
  may hold the floor, not a retry interval.
- **T11 and T12 are absent from `FLOOR_TIMERS` and should stay absent.** They
  are the dual-talker pair in the same table, and floor override is not
  implemented. A profile declaring one would be configuring a state machine
  that does not exist — the category error clause 3.2 is about.

**The clause reference published in v0.3 was wrong.** It said "TS 24.380 clause
15"; the timers are in clause 11.1. That reference was written from
recollection while listing what remained unverified — the habit this document
exists to correct, appearing in the document itself.

### 4.12 CA-03 — eleven fields had no length rule at all

**Source:** TS 24.380 clauses 8.2.3.2 to 8.2.3.27, corroborated across Rel-15,
Rel-17, Rel-19 and Rel-20, which agree on every value.

The method that unlocked this is worth stating: the field layouts are
ASCII-art diagrams that do not survive extraction, which is why this sat
unverified through four revisions. But **the prose beneath each diagram states
the length in words** — "has the value '2'", "has the value '6'", "is a 16 bit
binary value". It was readable all along, in a better form than the diagram.

The expected defect was a wrong number. The actual defect was worse:

| | Was | Is |
|---|---|---|
| Field 10, Source | classed variable-length | **fixed, 2 octets** |
| Field 14, SSRC | **no rule at all** | **fixed, 6 octets** |
| Fields 21, 23, 24 | **no rule at all** | fixed, 2 octets each |
| Fields 15-20, 22, 25 | **no rule at all** | variable |

Eleven of the twenty-six field ids were in neither the fixed nor the variable
group, so `decode` accepted them **at any length, without comment**. The
guard that now prevents this is not a better table — it is
`test_every_field_id_is_classified`, which fails if any field id is in no
group. A wrong entry is one bad field; a missing entry is a silent hole.

**Field 14 is the one that would have been guessed wrong.** An RFC 3550 SSRC
is 32 bits, so 4 is the obvious answer. The field is **6**: the SSRC plus 16
spare bits. It is also the third release-dependent name found in this audit —
"SSRC field" up to Rel-17, "Audio SSRC of Granted Participant" from Rel-18 —
though the length is unchanged from Rel-15 onward.

### 4.13 CA-03b — a valid Floor Request was being rejected as malformed

Found while re-classifying the fields, and the only defect in this audit with
a live operational effect on ordinary traffic.

The variable-length group was UTF-8 validated as a whole. Two of its members
are not text:

- **Track Info** (clause 8.2.3.13) begins with a `<Queueing Capability>`
  bitfield, followed by an 8-bit length, a text item and 32-bit references.
  **Any queueing capability value with the high bit set is not valid UTF-8**,
  so a conformant Floor Request carrying Track Info was rejected with "field
  TRACK_INFO is not UTF-8" — reported as a malformed message from a peer that
  was behaving correctly.
- **Source** (clause 8.2.3.12) is a 16-bit enumeration, validated as text
  because it was in the wrong group to begin with.

The UTF-8 check was not removed, it was narrowed to the five fields whose
value the specification defines as an ABNF string, plus the phrase half of
Reject Cause. Structured fields keep their framing checks and an opaque
payload.

### 4.14 The framing was already correct — checked, not assumed

TS 24.380 pads field values by two different rules: "(2 + multiple of 4)" for
User ID, Location and Functional Alias, and "(1 + multiple of 4)" for the list
fields, whose declared length **excludes** the internal padding. That second
family looked like a desynchronisation waiting to happen, since a declared
length shorter than the octets consumed would throw off every field after it.

Working it through, `_pad(2 + declared_length)` computes the right padding for
**both** families: for the list fields the declared length is `1 + S` and the
padded sum is the smallest `1 + 4k ≥ S`, which differs from `S` by
`(1 - S) mod 4` — exactly what `(-(3 + S)) mod 4` yields.

Recorded because "we checked the dangerous-looking thing and it was right" is
a finding, and because the alternative was to "fix" working code on a hunch.

### 4.15 CA-13 (new) — the trace comparator's message shapes are incomplete

`tools/trace_compare.py` carried the same two length defects and was corrected
independently, from the specification rather than from `core/rtcp.py`, which
it deliberately does not import. A new test asserts the two agree — agreement
is evidence only because they were derived separately (FC-OP-03).

But its `SHAPE` table, which says which fields each message may carry, has
never been checked against the message content tables in clauses 8.2.4 to
8.2.17. It is demonstrably incomplete: table 8.2.9-1 permits a Floor Taken to
carry Floor Indicator, Audio SSRC, Functional Alias, List of Granted Users,
Location and List of Locations, and `SHAPE` listed **none** of them.

**The comparator therefore reports conformant traffic as deviating.** The
fields this platform can actually encode have been added; the rest need the
full extraction. Until that is done, a clean comparator run means less than it
appears to, which is why `VP1-FC-002` stays open — now for a sharper reason
than "the constants are unverified".

---

## 5. NOT verified — the work that remains

CA-01 through CA-06 and CA-11 are closed. What is left, ordered by
consequence:

| # | What | Where to look | Status |
|---|---|---|---|
| CA-03 | Field value lengths, `core/rtcp.py` | TS 24.380 clause 8.2.3 | **Closed.** See 4.12-4.14. |
| CA-13 | `SHAPE` in `tools/trace_compare.py`: which fields each message may carry | TS 24.380 clauses 8.2.4-8.2.17 | **Open.** Demonstrably incomplete — the comparator reports conformant traffic as deviating. Now the only thing holding `VP1-FC-002`. |
| CA-11 | Release baseline | 3A above | **Closed.** The release is a deployment parameter (`MCX_RELEASE`). |
| CA-12 | Release dependence of the TS 24.379 layer | TS 24.379, all releases | **Open.** The floor control layer is release-parameterised; the SIP layer has not been examined at all. REL-OP-01, PLT-REL-009. |
| CA-05 | Timer defaults `DEFAULT_TIMERS_MS` (T2, T8, T20) | TS 24.380 clause 11.1, table 11.1.3-1 | **Closed, and correct.** See 4.11. |
| CA-07 | MCData and MCVideo feature tags | TS 24.282, TS 24.281 | **Open, blocked.** Neither specification is in this repository. Marked `# unverified` in `core/sip.py`. |
| CA-08 | Group document, OMA-defined parts | OMA-TS-XDM_Group-V1_1_1 | **Open, blocked.** Not a 3GPP deliverable. The single document still blocking `VP1-DOC-001`. |
| CA-09 | Interworking warning codes 301-350 | TS 29.379 | **Open, blocked.** Table 4.4.2-2 reserves the range and defers its meaning. Affects `gateway-unavailable` only; R4. |
| CA-10 | `+` prefix on feature tags in `Contact` | IETF RFC 3840 | **Open.** TS 24.379's own flows are inconsistent — six examples without the prefix, two with. The normative text specifies neither. RFC 3840 is the arbiter and is not here. Kept with the prefix. |

**Confirmed against a specification and pinned by test:** the 14 RTCP field
IDs, the `MCPT` name, PT=204, the floor control subtypes, the Deny and Revoke
cause namespaces, the on-network/off-network timer split, the four warning
codes, the Warning header shape, the MCPTT feature tag and ICSI, the
Accept-Contact pair, the Answer-Mode values and branches, the four content
types, and the group document structure and media type.

**Seven constant sets have now been checked against a primary source. Six
were wrong; one was right.** That is the prior for everything in the table
above — not a certainty of defect, but nowhere near a presumption of
correctness.

---

## 6. Consequences for the verification plan

- `VP1-DOC-001` moves from **OPEN** to **PARTIAL**. Its "schema-valid" clause
  is satisfied for everything TS 24.481 specifies, and blocked only on
  CA-08's OMA document. That is a much smaller gap than "the schema was never
  obtained".
- `VP1-SIG-001` gains real evidence. The SIP the platform emits was checked
  against the specification for the first time, and it was wrong in four
  independent ways — Warning codes, Warning shape, Accept-Contact, and
  Answer-Mode branches.
- `VP1-FC-002` stays **OPEN**, and CA-13 is now the only thing holding it.
  The reason has sharpened twice: it began as "the constants are unverified",
  became "the field lengths are unverified", and is now "the comparator flags
  conformant traffic as deviating, so a clean run proves less than it looks".
- `VP-OP-02` (specification-derived expected flows) is now carrying weight it
  could not carry before: the flows are derived from the documents in
  `docs/3GPP/`, not from recollection.
- **R1's exit criterion is closer but not met.** A trace comparator match still
  rests on CA-03.

---

## 7. Recommendation

**CA-13 is the last item closable from the documents already in this
repository**, and it is now the only thing holding `VP1-FC-002` and, through
it, R1's exit criterion. The method is the one that closed CA-03: the message
content tables in clauses 8.2.4 to 8.2.17 are ASCII art, but the field names
inside them extract cleanly, and the prose beneath says which are conditional.

CA-07 through CA-10 need four documents this project does not have. CA-08
(OMA XDM Group) is the only one with a verification case behind it.

**Do not schedule interoperability testing before CA-03 closes.** A field
length error desynchronises the parse, which presents as an unrelated failure
somewhere downstream and costs a day of test time to trace back.

---

## 8. Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-09-21 | Initial audit. Two defects found and corrected; six items recorded as unverified. |
| 0.2 | 2026-09-21 | CA-01 closed against the TS 24.380 source document. The PDF extraction that produced 0.1's subtype table was found to have invented a plausible sequential table; method rewritten in 2. |
| 0.6 | 2026-09-21 | CA-03 closed against TS 24.380 clause 8.2.3, read from the prose beneath each field diagram. Eleven of twenty-six field ids had no length rule at all; Source was in the wrong class and SSRC is 6 octets, not the 4 that would have been guessed. Track Info was being UTF-8 validated, so a conformant Floor Request carrying it was rejected as malformed. The field framing was checked and found already correct. New CA-13: the trace comparator's message shapes are incomplete and flag conformant traffic. |
| 0.5 | 2026-09-21 | CA-11 closed by making the 3GPP release a deployment parameter (`MCX_RELEASE`), on an axis independent of the profile. Per-release tables for subtypes, field IDs and revoke causes extracted mechanically from all eight published versions of TS 24.380. Corrects v0.3: subtype 14 changed meaning at Rel-18, not Rel-19. New CA-12: the TS 24.379 layer is not release-parameterised. |
| 0.4 | 2026-09-21 | CA-05 closed against TS 24.380 table 11.1.3-1: all three timer defaults correct — the first clean set in six. The clause reference published in 0.3 was itself written from recollection and was wrong; corrected. |
| 0.3 | 2026-09-21 | TS 24.379 and TS 24.481 read from source. CA-01 re-verified and written up as 3.3; release baseline mismatch recorded as CA-11. CA-02, CA-04 and CA-06 closed: 0 of 11 warning codes correct, the Warning header itself malformed, the ICSI absent from every INVITE, `Priv-Answer-Mode` on every call, two configuration values hard-coded in `core/`, and the group document invalid in four ways. All corrected and pinned. One surviving mutant in a test written for this audit, recorded in 4.10. |
