# Specification conformance audit — R1

**Document:** PLT-CONF-AUDIT
**Version:** 1.7
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

**Nine of the ten constant sets checked have contained defects.** The one
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
releases, and the release-dependence sweeps against every published one: all
eight of TS 24.380 (Rel-13 to Rel-20) and all seven of TS 24.379 (Rel-13 to
Rel-20). Where releases disagree it is said so, and the release at which they
diverge is given rather than interpolated — interpolating it is what produced
the one error this document has had to correct in itself (3A).

**Legacy formats.** TS 24.379 Rel-15 and Rel-16 ship as `.doc` rather than
`.docx` and were converted before extraction. Conversion is a transformation,
and the finding that matters from those two releases is an **absence** —
warning code 179 is not there — which a dropped table row would fake
perfectly.

So the boundary does not rest on them. Code 179 is absent from Rel-13 and
Rel-14 and present in Rel-17, all three native `.docx`, and the code table
only ever grows (44, 50, 52, 59, 77, 89, 95 codes across the seven releases,
each a superset of the last). Rel-15 and Rel-16 are bracketed by the native
files; the converted ones agree, which is corroboration rather than the
evidence itself.

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

### 4.16 CA-13 — the platform was sending a field its messages do not define

**Source:** TS 24.380 message content tables, clauses 8.2.4 to 8.2.17, and
clause 8.2.3.10, extracted from Rel-15, Rel-17, Rel-19 and Rel-20.

CA-13 was opened as a defect in a verification tool. It turned out to be a
defect in the platform that the tool was **agreeing with**.

Clause 8.2.3.10 states the Message Sequence Number field "is used to bind a
number of Floor Taken or bind a number of Floor Idle messages together", and
it appears in exactly those two message tables, in every release from Rel-15
to Rel-20. `service/media.py` attached it to **every outgoing message**, so
Floor Granted, Floor Deny, Floor Revoke and Floor Queue Position Info each
carried a field the specification does not define for them.

`SHAPE` in `tools/trace_compare.py` **required** it on four of those same
messages. So the comparator did not merely fail to catch the defect — it
would have flagged the corrected behaviour as a deviation.

This is FC-OP-03's warning arriving in its most complete form. The two
artefacts were structurally independent (the comparator does not import
`core.rtcp`) and still shared a false belief, because both were written by
the same hand from the same recollection. **Structural independence is not
epistemic independence, and only a specification breaks the tie.**

**Corrected:** the field is attached to Floor Taken and Floor Idle only, and
the counter advances only when it is carried — the procedures say "shall
include a Message Sequence Number field with a value increased with 1", so
incrementing per message left gaps in what a receiver sees.

### 4.17 CA-13b — `SHAPE` was wrong in both directions

Rewritten from the message content tables. It had never been checked against
them at all, and two rules govern what belongs:

**On-network only.** This platform is an on-network floor control server
(§3.2, the T2/T8/T20 timers). The specification marks several fields "only
applicable in off-network": User ID in most messages, and Queue Size, Queued
User ID, Queue Info and SSRC-of-queued in Floor Granted. `SHAPE` permitted
them, which would have concealed a genuine off-network leak.

**Fields that belong to a different message.** `SHAPE` permitted
`granted-party` in Floor Granted. Granted Party's Identity is a Floor **Taken**
field; table 8.2.5-1 does not list it.

And in the other direction, table 8.2.9-1 permits a Floor Taken to carry Floor
Indicator, Audio SSRC, Functional Alias, List of Granted Users, Location and
List of Locations — `SHAPE` listed none of them, so a conformant Floor Taken
carrying any one was reported as deviating.

### 4.18 A Deny cause was being sent in a Floor Revoke

Found while reading the send path. `SEND_REVOKE` built its Reject Cause with
`DENY_OTHER` rather than `REVOKE_OTHER`.

Both constants are 255, so **nothing was wrong on the wire and no test could
have caught it by observation**. It is recorded because it is precisely the
confusion §3.3 split the two tables to prevent, and because the next person to
change that line would have picked the neighbouring Deny cause — where the
numbers do not coincide, and a revoked talker is told the server had an
internal error.

Pinned by a test that reads the branch with comments stripped.

### 4.19 What this leaves

`VP1-FC-002` is no longer blocked on an unverified comparator. Two things
remain, both recorded rather than assumed:

- **CA-14:** `SHAPE` permits the union of fields across Rel-15 to Rel-20
  rather than narrowing per release. A superset can only miss a deviation,
  never invent one, so this is a sensitivity limit and not a false-positive
  source. Narrowing it means giving the comparator a release, which it
  currently has no way to know.
- **FC-OP-05:** the sequence counter is per endpoint. Clause 8.2.3.10 says the
  field binds "a number of Floor Taken" messages together, which may mean one
  value shared across the set sent for a single floor event. No receiver can
  observe the difference, so it is recorded rather than guessed at.

One observation that is not a defect: the platform never sends a **Floor
Indicator** field, whose bitmap (clause 8.2.3.15-2) carries "Emergency call",
"Imminent peril call", "Broadcast group call" and "Queueing supported". The
specification does not require it, so this is conformant — but a platform
whose purpose is priority and emergency handling is not signalling any of that
in the floor layer. Recorded as **FC-OP-06**.

### 4.20 CA-12 — the signalling layer, and the one constant that moves

**Source:** TS 24.379 table 4.4.2-2 and the constant sweep below, extracted
from all seven published releases in `docs/3GPP/` (Rel-13 `dj0` through
Rel-20 `k00`). Rel-15 and Rel-16 ship as legacy `.doc` rather than `.docx`
and were converted before extraction.

The release parameter covered TS 24.380 and left TS 24.379 unexamined, which
was recorded rather than glossed (REL-OP-01). This closes it.

**The warning code table is the part that moves**, and by a lot: 44 codes in
Rel-13, 95 in Rel-20, allocated in contiguous per-release blocks.

| First appears in | Codes |
|---|---|
| Rel-13 | 100-128, 136-150 |
| Rel-14 | 151-156 |
| Rel-15 | 157-158 |
| Rel-16 | 159-165 |
| Rel-17 | 166-183 |
| Rel-18 | 184-195 |
| Rel-20 | 196-201 |

(129-135 are allocated in no release at all.)

The platform emits three codes. Two — 100 and 145 — are Rel-13 and safe
everywhere. **The third, 179, arrives in Rel-17**, so a deployment configured
`MCX_RELEASE=13` through `16` was emitting a code its peers do not define, for
the interconnection refusal.

**Everything else on the signalling side is release-stable.** Checked across
all seven releases and present unchanged in every one: the `g.3gpp.mcptt`
feature tag, the `g.3gpp.icsi-ref` tag, the MCPTT ICSI value, the
`mcptt-info+xml`, `mcptt-location-info+xml` and `resource-lists+xml` MIME
types, and the five enumerated detailed reasons for code 100 — including the
two the platform uses, "local policy" and "user authorisation". So only the
warning codes needed a table.

**The degradation rule.** When the configured release has no such code, the
explanatory phrase goes out without the number:

```
Rel-17:  Warning: 399 ps.mcptt.example "179 service not authorized with ..."
Rel-16:  Warning: 399 ps.mcptt.example "service not authorized with ..."
```

Raising was the wrong answer and was tested against: turning a policy refusal
into a fault is the one thing the refusal path may never do, and it is the
distinction PLT-ICD-001 is built around. Emitting the number anyway was also
wrong — it is exactly the "confidently wrong" failure that 4.1 is about, just
displaced from the wrong table to the wrong release.

**Two codes changed their text without changing meaning** (148 "MCPTT group is
regrouped" → "group is regrouped" at Rel-16; 149 "SIP-INFO" → "SIP INFO" at
Rel-17). Neither is emitted here, and both are recorded so that a future
reader does not mistake an editorial change for a semantic one.

### 4.21 CA-10 closed — the `+` prefix is correct, and RFC 3840 says why

**Source:** IETF RFC 3840 clause 5, fetched from the RFC Editor.

TS 24.379's own signalling flows are inconsistent: six Contact examples write
`g.3gpp.mcptt` without a prefix, two write `+g.3gpp.mcptt`, and the normative
text specifies neither. The audit kept the prefix and recorded the ambiguity
rather than resolving it by majority vote on non-normative examples.

RFC 3840 settles it. **Base tags** — the twenty defined by that RFC, such as
`audio`, `video`, `isfocus` — appear with no prefix. For any other tag,
clause 5 states "a plus sign ('+') MUST be added as the first character", and
the ABNF makes it structural:

```
enc-feature-tag = base-tags / other-tags
other-tags      = "+" ftag-name
```

`g.3gpp.mcptt` and `g.3gpp.icsi-ref` are not base tags, so `+g.3gpp.mcptt` is
right in both Contact and Accept-Contact. **The code was already correct and
the specification's examples are editorially wrong.**

Recorded as a finding because "we checked and it was right" is one, and
because the next reader to notice the inconsistency should find the answer
here rather than re-deriving it.

### 4.22 The deleted Resource-Priority namespaces were the right values

**Source:** IETF RFC 8101, fetched from the RFC Editor.

4.6 deleted `RP_NAMESPACE_NORMAL = "mcpttp"` and
`RP_NAMESPACE_EMERGENCY = "mcpttq"` from `core/`, on the grounds that the
namespace is retrieved per deployment from the service configuration document
(TS 24.484) and that the citation to RFC 4412 was wrong.

RFC 8101 does register exactly those two namespaces — `mcpttp` with a
pre-emption algorithm and `mcpttq` with a queuing algorithm, each with
priority levels 0 to 15. So the **values** were right; what was wrong was
their being constants in the one module forbidden to hold configuration, and
the citation.

This matters for how the finding reads: it was not a transcription error. It
was a correct value in a place that made it uncheckable and undeployable, and
that is a different kind of defect from the other eight.

### 4.23 CA-15 — a data bearer was asking for the Mission Critical Video 5QI

**Source:** TS 23.501 table 5.7.4-1, identical in Rel-17 and Rel-19; and UIC
FRMCS SRS (AT-7800) v2.1.0 clauses 14.6.2 and 14.6.5.

`qos_identifier` was **never validated at all**. Every profile declared one and
nothing checked it, which is the same shape of defect as 4.12: not a wrong
value but an absent rule.

The railway profile's ETCS bearer requested **5QI 67**, which table 5.7.4-1
defines as *Mission Critical Video user plane*, on a rule matching
`media: data`. Two documents independently say that is wrong:

- TS 23.501 defines 67 for video. A video 5QI on a data bearer is not a
  preference the network can honour approximately; it is a request for
  characteristics that were specified for a different kind of traffic.
- FRMCS SRS clause 14.6.2.1 (M) lists the standardised 5QIs an FRMCS system
  **shall** support as **5, 8, 65 and 69**, with 70 optional under 14.6.2.2.
  **67 is not in the set at all.**

The same profile used **ARP level 9** for its general data bearer. That is
legal in TS 23.501, whose range is 1 to 15 — but FRMCS SRS clause 14.6.5.3 (M)
says an FRMCS system "shall apply the ARP values 1 to 8", and Note 1 records
that 9 to 15 are "a national matter". A profile using 9 is not portable across
FRMCS deployments.

**Corrected:** the ETCS bearer to 5QI 69 and the general data bearer to ARP 8.
The other two profiles were already right — 65 for voice and 70 for data,
both matching table 5.7.4-1 — which is the second clean result in the audit.

**The ARP range 1-15 was already enforced** and turns out to be correct. It had
simply never been read from TS 23.501 clause 5.7.2.2 before.

**New in `core/`:** `core/qos.py`, the standardised 5QI set and the five
mission-critical values with the media each was defined for. This is 3GPP
knowledge, not profile knowledge — a 5QI means the same thing in every
deployment — so it belongs there, while a profile's *choice* of 5QI does not.
The validator now refuses a mission-critical 5QI on a rule whose media
contradicts it, and leaves operator-specific values alone, because clause
5.7.3 permits pre-configured 5QIs whose characteristics cannot be known here.

**The boundary gates caught two mistakes in this change**, which is worth
recording because it is the third time they have earned their keep:

- `VP1-BND-001` rejected the first draft of `core/qos.py`, whose docstring
  named the railway profile while explaining the defect. Rewritten
  profile-neutral.
- `VP1-BND-012` rejected `ARP_OPERATOR_DOMAIN_MAX = 8`, added "for
  completeness". It was right to: which ARP levels a deployment may use is
  policy, not protocol, and nothing in `core/` consumed it. The 1-8 bound now
  lives in the railway profile's own suite.

### 4.24 CA-16 — Annex A read, and the derived value was wrong

**Source:** UIC FRMCS SRS (AT-7800) v2.1.0 Annex A, read from the document by
a human after the extraction failed.

FRMCS SRS clause 14.6.6.1 (M-V3) says the QoS parameter values that shall be
applied "are listed in Annex A". That table is the authoritative per-session
assignment and **it does not extract from the PDF**: the columns arrive as
isolated cells with no row structure, which is the failure mode §2 is about.
What does extract cleanly is the surrounding prose and the table's own notes.

v1.0 therefore derived 5QI 69 for the ETCS bearer from the clauses that read
cleanly, marked it as derived rather than transcribed, and said to confirm it
against Annex A.

**The derivation was wrong.** Annex A assigns:

| Communication session | 5QI |
|---|---|
| FRMCS Signalling (4) | 5 / 69 |
| Pre-defined Default (5) | 8 |
| Emergency Voice (6) | 65 (GBR) |
| Voice (7) | 65 (GBR) |
| Urgent Data (8) | 8 |
| General Data (9) | 8 |
| TCMS (10) | 8 |
| **ATP Regular Data (11)** | **4 (GBR)** |
| ATP Compl. Data (12) | 8 |
| ATO (13) | 8 |

ETCS is ATP Regular Data (note 11), so **5QI 4**, not 69. And the profile's
general data bearer should be **5QI 8**, not the 70 it carried — Annex A
assigns 70 to nothing at all.

**Why the derivation failed is worth more than the correction.** The reasoning
was: 67 is excluded, ETCS is delay-sensitive, 69 is "Mission Critical delay
sensitive signalling" and is in the mandatory set, therefore 69. Every step
was true and the conclusion was still wrong, because the actual selection
criterion was not the service label at all. 5QI 4 is GBR with priority level
50, and Annex A.3 derives the ETCS requirement from Subset-093's 2.6 s
transaction transfer delay. **A guaranteed bit rate was the requirement**; the
"Non-Conversational Video (Buffered Streaming)" label in TS 23.501 describes
the traffic class that happens to carry those characteristics.

This is the strongest argument in this document for reading the table rather
than reasoning toward it. A derivation from correct premises, clearly labelled
as a derivation, still put the wrong 5QI on the safety-relevant bearer.

It also vindicates one earlier design decision: `core/qos.py` cross-checks
media only for the five **mission-critical** 5QIs, whose Example Services
column names a service definitionally, and leaves the general-purpose values
alone because theirs describes a traffic class. Had that check covered every
5QI, it would now be rejecting the correct value.

### 4.25 CA-07 — both remaining feature tags confirmed, with a caveat

TS 24.281 and TS 24.282 arrived, so `+g.3gpp.mcvideo` and `+g.3gpp.mcdata` are
confirmed and the `# unverified` markers are gone.

**But `g.3gpp.mcdata` is rarely enough on its own.** TS 24.282 shows MCData is
three services, each with its own tag and ICSI — `.sds`, `.fd`, `.ipconn` —
and the service-specific forms outnumber the generic one in the document. TS
24.481 clause 7.2.8 agrees: an MCData group document's "enabler" attribute is
set to *one of* the SDS, FD or ES values, never a generic MCData one.

The platform has no way to say which MCData service a call type is, so it
announces data calls generically. Recorded as **DATA-OP-01**: it is a profile
schema key and an ICD revision, not an audit correction.

### 4.26 FRMCS-OP-01 — the SRS contradicts itself on 5QI 4

Clause 14.6.2.1 (M) says an FRMCS system "shall support the standardized 5QI
values 5, 8, 65, 69", and 14.6.2.2 adds 70 as optional. **Annex A assigns 5QI
4 to ATP Regular Data, and 4 is in neither list.**

The two clauses answer different questions — 14.6.2.1 which values a system
must support, Annex A which are actually used — but a deployment cannot
interoperate with a value its own specification does not require it to
support. Where they disagree this platform follows Annex A, because that is
what the per-session table is for and clause 14.6.6.1 makes it mandatory.

Pinned by a test, so a future SRS revision that adds 4 to 14.6.2.1 will fail
it and the open point can be closed. **This is a question for UIC**, and it
sits on the ETCS bearer, which is the safety-relevant one.

### 4.27 CA-08 — the schemas arrived, and one IETF file still stands in the way

**Source:** OMA-SUP-XSD_poc_listService V1.0.2 and OMA-SUP-XSD_xdm_extensions
V1.0.1, now in `docs/`.

The OMA schemas confirm the CA-04 structure a **third** time, from a machine
-readable source rather than prose: `<group>` is declared in
`urn:oma:xml:poc:list-service` as an `xs:sequence` of `<list-service>`, and
`<supported-services>` and `<service>` are declared in
`urn:oma:xml:xdm:extensions`.

They also carry something no prose reading had produced. `list-service-type`
is an **`xs:sequence`**:

```
display-name           minOccurs=0
list                   minOccurs=0
invite-members         minOccurs=0
max-participant-count  minOccurs=0
xs:any ##other         minOccurs=0 maxOccurs=unbounded
@uri                   use="required"
```

**Element order is a constraint**, and nothing was checking it. `check_rendered`
walked the tree by name and would have accepted `supported-services` before
`display-name`. The renderer happened to emit the right order; that was luck,
and it is now pinned in both the runtime check and a test, with a mutant to
prove the check can fail.

**Full XSD validation was written and skipped on one missing file, now
closed.** `poc_listService` imports `urn:ietf:params:xml:ns:resource-lists`
(RFC 4826) and types `display-name` and `entry` from it, with a
`schemaLocation` pointing at iana.org, which this build environment's egress
policy refuses. Without `resource-lists.xsd`, libxml2 could not resolve those
two QNames and the schema set could not be built at all. `common-policy` is
imported but **never referenced** — zero `cp:` QNames in the file — so it was
never needed.

`resource-lists.xsd` is now in `docs/OMA/`, transcribed from RFC 4826 §3.2
(the RFC's own published schema text, read from rfc-editor.org and copied
verbatim). One pitfall worth naming: the `schemaLocation` URL itself, at
iana.org, does not serve the schema — it serves IANA's XML-namespace-registry
placeholder page, an HTML document with the same `.xsd`-shaped URL, that
merely points a reader at the RFC. A validator fed that page instead of the
real schema would fail to build silently or validate against nothing, the
same failure mode as a wrong constant that meets no conformant peer.
`tests/test_group_schema.py::test_the_group_document_is_schema_valid` now
runs instead of skipping and passes.

The harness was not left unproven while the target was skipped:
`test_the_schema_harness_itself_works` builds a self-contained OMA schema
through the same loader and resolver and validates a document against it that
must fail, so a validator that returned True unconditionally would have been
caught.

### 4.28 CA-08 — the document validates, and the chain is now complete

**Source:** RFC 4826's `resource-lists.xsd`, added to `docs/OMA/`, plus the
OMA schemas already there.

**The transcription was checked, not taken on trust.** The schema was
hand-transcribed from RFC 4826, so it was cross-read against the RFC itself:
the target namespace, all five complexTypes (`listType`, `entryType`,
`entry-refType`, `externalType`, `display-nameType`), the `resource-lists`
top-level element, `elementFormDefault="qualified"`, the `display-nameType`
simpleContent extension carrying `xml:lang`, and the `xs:import` line
verbatim. Every one matches. Transcription is a transformation, and this
document's rule is that transformations get checked.

**The observation in that commit is worth keeping.** The `schemaLocation` the
OMA schema names does not serve the schema: IANA serves an HTML registry page
at that URL shape. A file pulled from it would have looked present, made the
skip disappear, and validated against nothing — the same failure shape as a
constant that is wrong but never meets a conformant peer.

**The chain needs one more file.** RFC 4826 itself imports the XML namespace:

```
<xs:import namespace="http://www.w3.org/XML/1998/namespace"
 schemaLocation="http://www.w3.org/2001/xml.xsd"/>
```

and types `<display-name>` with `<xs:attribute ref="xml:lang"/>`. libxml2 2.14
does not treat the XML namespace as predefined for schema validation, so that
attribute declaration must come from a file:

```
poc_listService  ->  resource-lists  ->  xml.xsd
```

**The validation was run anyway, and it passes.** Using a W3C `xml.xsd`
obtained out of tree, the schema set builds and the rendered group document is
**schema-valid**. The validation is also not vacuous — the same schema set
rejects:

| Document | Result |
|---|---|
| as rendered | **valid** |
| `supported-services` before `display-name` | rejected |
| `list` before `display-name` | rejected |
| `@uri` removed | rejected |

The middle two matter: **the schema independently confirms the ordering
constraint** that 4.27 derived by reading the content model, and that
`check_rendered` now enforces. Those assertions are in the test, so it cannot
pass by accepting everything.

**Status: closed.** `docs/OMA/xml.xsd` is now in the repository — fetched
from `http://www.w3.org/2001/xml.xsd` itself rather than trusted from
whatever happened to be installed locally, checked well-formed and buildable
standalone before being trusted, same as `resource-lists.xsd` in 4.27. A
repository has to carry its own schemas; validating against a copy that
happens to be present in one environment is the reproducibility version of
the same mistake this document keeps finding. `tests/test_group_schema.py`
now runs the full chain — `poc_listService -> resource-lists -> xml.xsd` —
instead of skipping, and passes, including the three negative assertions
above. `VP1-DOC-001`'s "schema-valid" clause is closed.

### 4.30 CA-17 — the railway profile pre-empted the wrong call

**Source:** UIC FRMCS FRS (FU-7120) v2.1.0 appendix J, table J-1 "Priority
ordering"; and FRMCS SRS (AT-7800) v2.1.0 Annex A notes (1), (7), (8), (9).

Appendix J states its own rule plainly: *"The ordering of priorities is
according to the row's. In total seven priority levels are defined and are
numbered with letters A to G"*, and a higher-priority application *"can take
over resources from lower priority FRMCS applications"*. Its worked example is
a REC-voice pre-empting an active ATO communication.

**The seven category boundaries do not survive PDF extraction. The row order
does** — and the row order is what the appendix says the ordering *is*. That
is enough to check relative rank without inferring where the bands fall.

| FRS row order (extract) | This profile |
|---|---|
| 10.11 REC | `rec` 95 |
| 11.4 ATP (ETCS) | `etcs` 85 |
| 10.8 Shunting voice | `shunting` **60** |
| 11.5 ATO | `ato` **80** |

**ATO and shunting were inverted.** Under congestion this profile would have
pre-empted a shunting call to free resources for automatic train operation
data, where the FRS puts shunting above ATO. Corrected to `shunting` 80,
`ato` 60.

**A second, smaller one.** SRS Annex A note (7) gives ARP per application
directly: *"'Voice' include FRS applications 10.18-10.19 (ARP=3), 10.3-10.6
(ARP=5), 10.10+10.23 (ARP=6), 10.2 (ARP=8)"*. A driver-to-controller call is
FRS 10.3/10.4, so **ARP 5** — it was falling through to the catch-all at ARP
6, which that same note reserves for ground-to-ground and public address. A
dedicated rule now carries it.

**The platform caught a third thing on its own.** The first version of that
rule asked for ARP pre-emption capability, and the loader refused it: *"bearer
rule requests ARP pre-emption capability, but the priority decision
'operational' does not authorise it"*. That refusal is correct, and it exposes
a real gap rather than a typo — see FRMCS-OP-02.

### 4.31 SHUNT-OP-01 — the SRS does not cover shunting

SRS Annex A note (1) lists the FRS applications "not yet covered", and **10.8
Shunting voice communication is among them** (as is 11.12 Shunting data). So
one of this profile's four call types models an application the SRS assigns no
communication session, no 5QI and no ARP.

Nothing was invented for it. `shunting-group` carries no bearer rule of its
own and falls through to the catch-all, and a test asserts that it stays that
way — because a plausible-looking shunting QoS row would be indistinguishable
from a transcribed one to the next reader, which is how every defect in this
document got in.

Shunting priority (level 80) is still meaningful: it comes from FRS table J-1,
which does cover 10.8. It is only the SRS *QoS* assignment that is absent.

### 4.32 FRMCS-OP-02 — the application vocabulary is too coarse for table J-1

FRS table J-1 puts 10.3/10.4 (on-train voice to and from the controller) in a
band above 11.5 (ATO). This profile has a single `voice-operational`
application covering 10.3, 10.4, 10.10, 10.23 and 10.2 — which table J-1
spreads across at least three of its seven bands — and it resolves to the
catch-all priority decision at level 30, below `ato`.

So driver-to-controller voice currently ranks below automatic train operation
data, which inverts table J-1 a second time. Unlike the ATO/shunting swap this
one **cannot be fixed by changing a number**: it needs the profile's
application vocabulary split to match the bands, which changes what priority
decisions exist and therefore what the hooks return.

That is a profile design change with safety-case consequences, not an audit
correction, and it is recorded rather than attempted. It is also the clearest
evidence yet for what `CLAUDE.md` already says: this profile is a stub and
must not be used as safety-case input.

### 4.33 CA-18 — a railway emergency call out-ranked the signalling that sets it up

**Source:** UIC FRMCS SRS (AT-7800) v2.1.0 Annex A table A.1-1, "Mapping of
FRS application to QoS system requirements and attribute values", read from
the document by hand — neither QoS column survives PDF extraction.

| Communication session | 5QI | ARP |
|---|---|---|
| FRMCS Signalling (4) | 5 / 69 | **1** |
| Pre-defined Default (5) | 8 | 8 |
| Emergency Voice (6) | 65 (GBR) | **2** |
| Voice (7) | 65 (GBR) | 3-8 |
| Urgent Data (8) | 8 | 3, 5 |
| General Data (9) | 8 | 5, 6 |
| TCMS (10) | 8 | 7 |
| ATP Regular Data (11) | 4 (GBR) | **4** |
| ATP Compl. Data (12) | 8 | 6 |
| ATO (13) | 8 | 6 |

**The table is trusted because it corroborates the notes**, which do extract:
Voice's ARP range 3-8 is exactly note (7)'s per-application 3/5/6/8; Urgent
Data's "3, 5" is note (8)'s 11.34=3 and 11.15=5; General Data's "5, 6" is note
(9)'s 11.3=5 and 11.9=6. Two representations of one assignment, obtained by
different means, agreeing.

**Two defects.** `rec-broadcast` carried **ARP 1** and should be 2;
`etcs-ipcon` carried **ARP 2** and should be 4.

The first is the interesting one. Table A.1-1 gives **ARP 1 to FRMCS
Signalling alone** — note (4): *"'FRMCS Signalling' refers to the FRMCS
internal signalling (related to MCX and 5G)"*. A railway emergency call is the
highest **user-plane** priority, not the highest priority outright. Giving it
ARP 1 put it above the signalling that establishes and maintains it, so under
contention the platform would have starved the control plane to protect the
call that depends on it.

The profile's original values were not random — 1 and 2 are a plausible
"emergency first, safety second" ordering, and that is the trap. The real
table has a reserved band above both, and it was invisible until someone read
it. A test now asserts that **no user-plane bearer uses ARP 1**, so the
reservation is written down rather than remembered.

**The rest of the table is pinned too**, not only the two rows that changed: a
5QI cross-check over the whole profile, the Voice band as a range rather than
a point, and the catch-all data rule identified as Pre-defined Default (5).

**CA-18 closes, and with it the QoS reconciliation.** Every bearer rule in the
railway profile is now transcribed from Annex A. What remains unreconciled is
structural, not numeric: SHUNT-OP-01 (the SRS covers no shunting application)
and FRMCS-OP-02 (the application vocabulary cannot express FRS table J-1's
bands).

### 4.34 CA-19 — nothing could pre-empt an ATO session, including the call the FRS names

**Source:** UIC FRMCS FRS (FU-7120) v2.1.0 table J-1, read from the document
by hand — the seven category boundaries do not survive PDF extraction even
though the row order does.

**First, a check that passed.** CA-17 encoded only the *row order*, stating
explicitly that the band boundaries could not be extracted. With the real
table in hand, the row order transcription is **identical**, and the bands are
**not** what a reasonable reading of that order would have suggested:

| | Inferred from row order | Table J-1 |
|---|---|---|
| Band B | 10.18, 10.19 | 10.18, 10.19, **11.34** |
| Band C | 11.34, 11.4 | **11.4 alone** |
| Band E | …, 11.19 | 11.19 is **not** in E |
| Band F | 11.27, 11.28 | **11.19**, 11.27, 11.28 |

Four of the seven bands would have been wrong. Nothing was committed from that
inference, because only what the extraction supported was encoded. That is the
rule this document has been arguing for, tested against a case where guessing
would have been wrong — and it is the first time the discipline has been
checked rather than merely followed.

**Now the defects the bands expose.** CA-17 corrected `level` and stopped
there. The priority ordering is carried by **three** fields, and the other two
were still inverted:

| | `level` | `floor_priority` | `preemption_vulnerability` |
|---|---|---|---|
| shunting (band D) | 80 ✓ | **180** ✗ | true ✓ |
| ato (band E) | 60 ✓ | **230** ✗ | **false** ✗ |

So after CA-17, ATO still out-ranked shunting on the floor, and — the serious
one — **`preemption_vulnerability: false` meant no call could pre-empt an
active ATO session at all**. `SessionManager.preemption_victims` skips any
candidate whose vulnerability flag is false, before it ever compares levels.

Appendix J's worked example is exactly this case, verbatim: *"When there is an
active ATO communication and a REC-voice is initiated and there is congestion
on the transportlayer of FRMCS, the REC-voice communication pre-empts the ATO
communication."* The profile made that impossible. ETCS carried the same flag
and was equally un-preemptable, including by a railway emergency call.

**A partial fix is its own hazard.** CA-17 looked complete — the levels were
right, a test proved the ordering, and three mutants died. It was still wrong,
because a test written against one field cannot notice the other two. The
lesson generalises past this profile: when an invariant is spread across
several fields, pinning one of them produces *confidence* without producing
*correctness*.

**Corrected**, with all three fields derived from band membership, and
`FRMCS-OP-02` closed along the way: FRS 10.3/10.4 are band D, so
driver-to-controller voice now ranks with shunting instead of falling through
to the catch-all below ATO.

The tests now assert band structure rather than pairwise order — same band,
same level; higher band, strictly higher level; and the same for
`floor_priority` — plus the appendix's worked example executed through the
platform's own selection logic rather than asserted about.

**What is still a judgement call.** Pre-emption *capability* now follows band
membership too (a band may take resources from the bands below it), which is
appendix J's stated rule. Whether a shunting call should in practice drop an
ATO session is an operator policy decision that CENELEC sign-off has to
confirm; the FRS states the principle, not the deployment's appetite for it.

---

## 5. NOT verified — the work that remains

CA-01 through CA-06 and CA-11 through CA-13 are closed. What is left,
ordered by consequence:

| # | What | Where to look | Status |
|---|---|---|---|
| CA-03 | Field value lengths, `core/rtcp.py` | TS 24.380 clause 8.2.3 | **Closed.** See 4.12-4.14. |
| CA-13 | Message shapes, `tools/trace_compare.py` and the send path | TS 24.380 clauses 8.2.4-8.2.17 | **Closed.** See 4.16-4.19. It was a platform defect, not only a tool defect. |
| CA-14 | Per-release narrowing of `SHAPE` | TS 24.380, all releases | **Open, low consequence.** The comparator permits the union across releases; a superset can miss a deviation but cannot invent one. |
| CA-11 | Release baseline | 3A above | **Closed.** The release is a deployment parameter (`MCX_RELEASE`). |
| CA-12 | Release dependence of the TS 24.379 layer | TS 24.379, all seven releases | **Closed.** See 4.20. Warning code 179 is Rel-17+; everything else the platform emits is stable from Rel-13. |
| CA-05 | Timer defaults `DEFAULT_TIMERS_MS` (T2, T8, T20) | TS 24.380 clause 11.1, table 11.1.3-1 | **Closed, and correct.** See 4.11. |
| CA-07 | MCData and MCVideo feature tags | TS 24.281, TS 24.282 | **Closed.** See 4.25. Both confirmed; DATA-OP-01 opened for the MCData service-specific ICSIs. |
| CA-15 | 5QI and ARP values in every profile | TS 23.501 table 5.7.4-1, FRMCS SRS 14.6 | **Closed.** See 4.23. |
| CA-16 | FRMCS Annex A per-session QoS assignment | UIC FRMCS SRS (AT-7800) Annex A | **Closed** by a human read of the table. See 4.24 — the value this audit derived was wrong. |
| FRMCS-OP-01 | SRS clause 14.6.2.1 excludes a 5QI Annex A assigns | UIC FRMCS SRS | **Open, for UIC.** See 4.26. |
| CA-17 | Railway priority ordering and per-application ARP | FRS appendix J, SRS Annex A notes | **Closed.** See 4.30. ATO and shunting were inverted. |
| CA-18 | Annex A ARP column | UIC FRMCS SRS Annex A table A.1-1 | **Closed** by a human read. See 4.33 — ARP 1 is reserved for FRMCS Signalling and the emergency call was taking it. |
| SHUNT-OP-01 | The SRS does not cover shunting (FRS 10.8) | UIC FRMCS SRS Annex A note (1) | **Open, for UIC.** See 4.31. |
| FRMCS-OP-02 | Application vocabulary too coarse for FRS table J-1 | FRS appendix J | **Closed** by 4.34: table J-1's bands were read, and FRS 10.3/10.4 are band D. |
| CA-19 | Priority ordering across all three fields, and pre-emption flags | FRS table J-1 | **Closed.** See 4.34. Nothing could pre-empt an ATO session, including the REC the appendix names. |
| CA-08 | Group document, OMA-defined parts | OMA XSDs + RFC 4826 `resource-lists.xsd` (all present) | **Closed.** See 4.27. Element order is enforced and full XSD validation runs and passes. |
| CA-09 | Interworking warning codes 301-350 | TS 29.379 | **Open, blocked.** Table 4.4.2-2 reserves the range and defers its meaning. Affects `gateway-unavailable` only; R4. |
| CA-10 | `+` prefix on feature tags in `Contact` | IETF RFC 3840 clause 5 | **Closed, and the code was right.** See 4.21. |

**Confirmed against a specification and pinned by test:** the 14 RTCP field
IDs, the `MCPT` name, PT=204, the floor control subtypes, the Deny and Revoke
cause namespaces, the on-network/off-network timer split, the four warning
codes, the Warning header shape, the MCPTT feature tag and ICSI, the
Accept-Contact pair, the Answer-Mode values and branches, the four content
types, and the group document structure and media type.

**Ten constant sets have now been checked against a primary source. Nine
were wrong; one was right.** Every constant the platform puts on the wire has
now been read from a specification, in every release it supports. That is the prior for everything in the table
above — not a certainty of defect, but nowhere near a presumption of
correctness.

---

## 6. Consequences for the verification plan

- `VP1-DOC-001`'s "schema-valid" clause is now **CLOSED**: the rendered group
  document validates against the real OMA + RFC 4826 schema set, not just
  TS 24.481's own elements. VP1-DOC-001 as a whole stays open on SVC-OP-03
  (group configuration's source), which is unrelated to schema validity.
- `VP1-SIG-001` gains real evidence. The SIP the platform emits was checked
  against the specification for the first time, and it was wrong in four
  independent ways — Warning codes, Warning shape, Accept-Contact, and
  Answer-Mode branches.
- `VP1-FC-002` can now be **attempted**. Every constant the comparator and the
  encoder share has been checked against TS 24.380, and the two were corrected
  from the specification separately, so agreement between them is evidence
  rather than a shared assumption. What remains is running it against a real
  capture, which is a test-environment question rather than a conformance one.
- `VP-OP-02` (specification-derived expected flows) is now carrying weight it
  could not carry before: the flows are derived from the documents in
  `docs/3GPP/`, not from recollection.
- **R1's exit criterion is closer but not met.** A trace comparator match still
  rests on CA-03.

---

## 7. Recommendation

**Nothing further can be closed from the documents in this repository.**
Every constant the platform puts on the wire has now been read from a
specification, in every release it supports.

What remains needs documents this project does not have: the three OMA
supporting schema files (CA-08, the only one with a verification case behind
it), TS 24.281 (CA-07) and TS 29.379 (CA-09, R4 only). Both IETF references
were fetched and are closed. CA-14 and FC-OP-05 are open by choice, both low-consequence and
both recorded with their reasoning rather than resolved by assumption.

**The remaining R1 work is no longer a conformance question.** `VP1-SIG-001`
needs a second, independent SIP core (VP-OP-01 is still undecided), and the
FRMCS profile is still a stub that has never been reconciled with the UIC
FRS/SRS. Neither is answerable from the 3GPP documents.

CA-07 through CA-09 need documents this project does not have. CA-08 is the
only one with a verification case behind it.

**Do not schedule interoperability testing before CA-03 closes.** A field
length error desynchronises the parse, which presents as an unrelated failure
somewhere downstream and costs a day of test time to trace back.

---

## 8. Revision history

| Version | Date | Change |
|---|---|---|
| 1.7 | 2026-09-22 | CA-19: table J-1's bands read by hand. CA-17's fix was incomplete — the priority ordering is carried by three fields and only `level` had been corrected, so ATO still out-ranked shunting on the floor and, more seriously, carried `preemption_vulnerability: false`, meaning nothing could pre-empt an active ATO session, including the REC the appendix's own worked example names. ETCS the same. All three fields now derive from band membership, and FRMCS-OP-02 closes. The band boundaries inferred in CA-17 would have been wrong in four of seven; nothing had been committed from that inference. |
| 1.6 | 2026-09-22 | CA-18 closed by a human read of Annex A table A.1-1. Two defects: the railway emergency call carried ARP 1, which the table reserves for FRMCS internal signalling, so it out-ranked the control plane that establishes it; and ATP Regular Data carried ARP 2 rather than 4. The whole table is now pinned, not only the rows that changed. The railway profile's QoS is fully transcribed; what remains unreconciled is structural rather than numeric. |
| 1.5 | 2026-09-22 | CA-17: the railway profile ranked ATO above shunting, inverting FRS table J-1 — under congestion it would have pre-empted a shunting call for automatic train operation data. Corrected, along with the driver-to-controller ARP, which SRS Annex A note (7) gives as 5 rather than the catch-all 6. New SHUNT-OP-01 (the SRS does not cover shunting at all), FRMCS-OP-02 (the application vocabulary is too coarse to express table J-1's bands) and CA-18 (the Annex A ARP column still needs a human read). |
| 1.4 | 2026-09-22 | CA-08 closure verified against a second concern: `resource-lists.xsd` was cross-read against RFC 4826 line by line (transcription is a transformation, and transformations get checked), and its own `xml.xsd` import turned the build red rather than skipping, since libxml2 does not treat the XML namespace as predefined. `docs/OMA/xml.xsd` added (fetched from `http://www.w3.org/2001/xml.xsd`, checked well-formed and buildable standalone). `test_the_group_document_is_schema_valid` runs and passes, including three new negative assertions -- two bad orderings and a missing `@uri` -- all rejected, so the pass is not vacuous. |
| 1.3 | 2026-09-22 | CA-08 closed. `resource-lists.xsd` added to `docs/OMA/`, transcribed from RFC 4826 §3.2 read at rfc-editor.org — not from the schema's own `schemaLocation` URL, which serves IANA's namespace-registry placeholder page (HTML, not a schema) rather than the file. `test_the_group_document_is_schema_valid` now runs instead of skipping and passes. Closes `VP1-DOC-001`'s "schema-valid" clause and SVC-OP-01. |
| 0.1 | 2026-09-21 | Initial audit. Two defects found and corrected; six items recorded as unverified. |
| 0.2 | 2026-09-21 | CA-01 closed against the TS 24.380 source document. The PDF extraction that produced 0.1's subtype table was found to have invented a plausible sequential table; method rewritten in 2. |
| 1.2 | 2026-09-22 | CA-08: the OMA schemas confirm the group document structure a third time and add a constraint no prose reading produced -- `list-service-type` is an `xs:sequence`, so element ORDER matters and nothing was checking it. Enforced in the runtime check and pinned. Full XSD validation is written and skips on one missing file, RFC 4826's `resource-lists.xsd`; the harness is proven separately so the skip is about that file and not untested machinery. |
| 1.1 | 2026-09-22 | CA-16 closed by a human read of FRMCS SRS Annex A. The 5QI this audit DERIVED for the ETCS bearer was wrong: Annex A assigns 4 (GBR), not the 69 derived from the prose clauses, and general data is 8 rather than 70. Every step of the derivation was true and the conclusion was still wrong, because the selection criterion was a guaranteed bit rate rather than the service label. New FRMCS-OP-01: clause 14.6.2.1 does not list 5QI 4, which Annex A assigns. |
| 1.0 | 2026-09-22 | CA-15 closed: `qos_identifier` was never validated, and the railway profile was requesting the Mission Critical Video 5QI for a data bearer and an ARP level outside the FRMCS mandatory range. CA-07 closed against TS 24.281 and TS 24.282. New `core/qos.py` carrying TS 23.501 table 5.7.4-1. New CA-16 (FRMCS Annex A does not extract) and DATA-OP-01 (MCData service-specific ICSIs). Nine of ten constant sets checked have contained defects. |
| 0.9 | 2026-09-22 | CA-10 closed against RFC 3840 clause 5: `g.3gpp.mcptt` is not a base tag, so the `+` prefix the code already used is correct and TS 24.379's prefix-less Contact examples are editorially wrong. RFC 8101 confirms `mcpttp`/`mcpttq` are the registered namespace names, so the constants deleted in 4.6 held the right values in the wrong place. Both RFCs fetched from the RFC Editor; neither is needed in the repository. |
| 0.8 | 2026-09-21 | CA-12 closed. TS 24.379 read across all seven published releases (Rel-15 and Rel-16 converted from legacy .doc). The warning code table grows from 44 codes to 95 in contiguous per-release blocks, and code 179 — one of the three the platform emits — does not exist before Rel-17; a deployment at Rel-13 to Rel-16 was emitting it. Every other signalling constant is stable from Rel-13. Release selection now covers both layers, so PLT-REL-009 lands in R1 rather than R2. |
| 0.7 | 2026-09-21 | CA-13 closed, and it was a platform defect rather than only a tool defect: the Message Sequence Number was attached to every outgoing message, where clause 8.2.3.10 defines it for Floor Taken and Floor Idle alone — and the trace comparator REQUIRED it on four messages that do not define it, so the tool agreed with the defect instead of catching it. `SHAPE` rewritten from the message content tables. A Deny cause was being sent in a Floor Revoke. New CA-14, FC-OP-05, FC-OP-06. |
| 0.6 | 2026-09-21 | CA-03 closed against TS 24.380 clause 8.2.3, read from the prose beneath each field diagram. Eleven of twenty-six field ids had no length rule at all; Source was in the wrong class and SSRC is 6 octets, not the 4 that would have been guessed. Track Info was being UTF-8 validated, so a conformant Floor Request carrying it was rejected as malformed. The field framing was checked and found already correct. New CA-13: the trace comparator's message shapes are incomplete and flag conformant traffic. |
| 0.5 | 2026-09-21 | CA-11 closed by making the 3GPP release a deployment parameter (`MCX_RELEASE`), on an axis independent of the profile. Per-release tables for subtypes, field IDs and revoke causes extracted mechanically from all eight published versions of TS 24.380. Corrects v0.3: subtype 14 changed meaning at Rel-18, not Rel-19. New CA-12: the TS 24.379 layer is not release-parameterised. |
| 0.4 | 2026-09-21 | CA-05 closed against TS 24.380 table 11.1.3-1: all three timer defaults correct — the first clean set in six. The clause reference published in 0.3 was itself written from recollection and was wrong; corrected. |
| 0.3 | 2026-09-21 | TS 24.379 and TS 24.481 read from source. CA-01 re-verified and written up as 3.3; release baseline mismatch recorded as CA-11. CA-02, CA-04 and CA-06 closed: 0 of 11 warning codes correct, the Warning header itself malformed, the ICSI absent from every INVITE, `Priv-Answer-Mode` on every call, two configuration values hard-coded in `core/`, and the group document invalid in four ways. All corrected and pinned. One surviving mutant in a test written for this audit, recorded in 4.10. |
