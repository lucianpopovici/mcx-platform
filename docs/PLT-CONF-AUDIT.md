# Specification conformance audit — R1

**Document:** PLT-CONF-AUDIT
**Version:** 0.1
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

**Two of two constant sets checked have contained defects.** That is the prior
to carry into the items still unverified in §4.

---

## 2. Method, and its limits

Specification text was obtained from the freely published ETSI mirrors of the
3GPP documents, via automated extraction of the PDFs.

**This is weaker than a human reading the document**, in two specific ways:

1. The extraction is an automated reading and can misreport.
2. The PDFs are large and the extraction truncates. Every table that sits
   beyond the truncation point could not be reached at all, which is why §4 is
   as long as it is.

Direct download into the build environment is blocked by its network policy, so
local parsing of the full documents was not possible.

**Corroboration used where available.** A finding was treated as solid only
where either (a) surrounding constants from the same table agreed exactly with
the code, making a selective extraction error unlikely, or (b) two independent
specification releases agreed.

---

## 3. Findings — both defects, both corrected

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

---

## 4. NOT verified — the work that remains

Each item below could not be reached by automated extraction. Each needs a human
with the document. They are ordered by consequence.

| # | What | Where to look | Why it matters |
|---|---|---|---|
| CA-01 | `CAUSE_*` in `core/rtcp.py`: 1 another-has-permission, 2 internal-error, 3 only-one-client, 4 retry-after, 5 receive-only, 6 no-resources, 255 other | TS 24.380 clause 8.2.6.2 (Floor Deny) and 8.2.10.2 (Floor Revoke) | Invented. A peer receiving a wrong cause code misreports why a floor request failed. |
| CA-02 | `WARNING_TEXTS` in `core/sip.py`: codes 100–110 and their phrases | TS 24.379 clause 4.4.2 | Invented wholesale when the file was written, and flagged as such at the time. |
| CA-03 | Field value lengths in `_FIXED` / `_VARIABLE`, `core/rtcp.py` | TS 24.380 clause 8.2.3 onward | A wrong length desynchronises the whole field parse, not just one field. |
| CA-04 | Group document structure and media type, `service/groups.py` | TS 24.481 | `SVC-OP-01`: the schema was never obtained. `VP1-DOC-001`'s "schema-valid" clause is open because of it. |
| CA-05 | Timer default values (T2, T8, T20) | TS 24.380 clause 6.3 | Names now correct; the defaults in `DEFAULT_TIMERS_MS` are still invented. |
| CA-06 | MC feature tags, `Accept-Contact` construction, Answer-Mode usage | TS 24.379 clauses 6.x, 7.x | Not yet examined at all. |

**The 14 field IDs, the `MCPT` name, PT=204 and the on-network/off-network timer
split are the only protocol constants in this codebase confirmed against a
specification.** Everything else in §4 remains on the same footing as the two
items that turned out to be wrong.

---

## 5. Consequences for the verification plan

- `VP1-FC-002` stays **OPEN**. The comparator and the encoder now agree with a
  specification rather than only with each other, which is a real improvement,
  but §2's limits mean this is not yet conformance evidence.
- `VP-OP-02` is **decided**: specification-derived expected flows are accepted;
  golden third-party captures are not required. This audit is what makes that
  decision meaningful — before it, "specification-derived" described flows that
  had never met a specification.
- R1's exit criterion requires a call "captured and matched by the trace
  comparator". Until CA-01 and CA-03 are closed, a match remains weaker evidence
  than the criterion implies.

---

## 6. Recommendation

Close CA-01 through CA-03 before any interoperability testing. They are a
morning's work for someone with the PDFs open, and on the evidence so far the
expected yield is not zero.

---

## 7. Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-09-21 | Initial audit. Two defects found and corrected; six items recorded as unverified. |
