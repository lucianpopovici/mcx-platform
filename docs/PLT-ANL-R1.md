# Release 1 — Analysis record

**Document:** PLT-ANL-R1
**Version:** 0.1
**Date:** 2026-09-21
**Verifies:** PLT-VP-R1 §8 (VP1-ANL-001, -002, -003)

---

## 0. Why these three exist

PLT-VP-R1 §8 states it plainly: VP1-ANL-001 and -002 are "the only direct
evidence that the architecture's central claim holds. If either cannot be
argued from a real change set, the boundary is in the wrong place and R1 should
not exit."

They are therefore performed as **worked changes**, not written arguments. Each
cites a commit whose diff anyone can re-inspect.

### 0.1 Provenance of the evidence

Two repositories were involved and they differ in what they can evidence.

The working copy in which these experiments were performed was placed under
version control from a snapshot, with no history of the work preceding it.
Written against that copy alone, §1 and §2 could only be experiments performed
on top of a single opaque commit.

The project repository is not that. Its history was reconstructed as genuine
intermediate states: commit `d9d5d5b` ("loader and validator") contains
`core/errors.py`, `loader.py`, `model.py`, `validation.py` and no `floor.py`,
`session.py` or `sip.py`, because those did not yet exist. Each commit's
contents match its message. Verified by inspection, 2026-09-21.

Two consequences:

1. §1 and §2 remain experiments performed *on top of* the current head, which
   is the right form regardless: they evidence how the code behaves now, which
   is what PLT-PRF-022 and PLT-PRF-023 assert.
2. §3's worked examples are stronger than a procedure illustrated by
   hypotheticals: both classifications can be re-derived from the project
   history rather than taken on trust.

---

## 1. VP1-ANL-001 — adding a call type, urgency and application

**Requirement:** PLT-PRF-022 — adding a call type, urgency or application to a
deployment shall require no change to code under `core/`.

**Method:** added to the MCX profile an urgency (`elevated`), an application
(`coordination`), a call type (`coordination-group`) using both, and a priority
rule placing it at level 50 — above normal, below imminent-peril and emergency.

**Evidence:** commit `VP1-ANL-001: add a call type, urgency and application to
the MCX profile`.

| Measure | Result |
|---|---|
| Files changed | 1 |
| Files changed under `core/` | **0** |
| Files changed outside `profiles/` | 0 |
| Test suite | 280 passed |
| Boundary gates | 18/18 |

The new call type loads, evaluates to the intended priority and scope, and
carries its own floor policy (queue depth 6, T203 3500 ms) — behaviour the core
supplied without knowing the call type exists.

**Verdict: PASS.** No qualification.

---

## 2. VP1-ANL-002 — introducing an additional profile

**Requirement:** PLT-PRF-023 — introducing an additional profile shall require
no change to code under `core/`.

**Method:** added `profiles/utility`, a third deployment (energy utility field
and control-room operations) with its own urgencies, applications, three call
types, a functional identity, priority and bearer tables, and — deliberately —
no interworking or interconnection block at all. Every hook is a shared table
implementation used unchanged.

**Evidence:** commit `VP1-ANL-002: introduce a third profile (utility
operator)`.

| Measure | Result |
|---|---|
| Files changed under `core/` | **0** |
| Files added under `profiles/` | 3 |
| Files changed elsewhere | 1 (`.github/workflows/ci.yml`) |
| Conformance suite against the new profile | 13 passed, **suite unmodified** |
| Test suite | 280 passed |
| Boundary gates | 18/18 (after the CI entry — see below) |

The conformance suite passing unmodified is the stronger result. It contains no
profile-specific assertion, so a third deployment needed no new test: every
check derives from the loaded profile's own declarations.

**Finding — and the reason to run this rather than assert it.** Adding a profile
is not entirely free outside `core/`. `VP1-BND-020` **failed** until
`.github/workflows/ci.yml` gained a matrix entry for the new profile, because a
profile with no CI suite produces no evidence. The gate caught this without
being prompted.

PLT-PRF-023 as written concerns code under `core/` and is satisfied. But the
honest statement of the cost is: **one package directory, one CI matrix entry.**

**Verdict: PASS**, with the checklist item above recorded.

**Recommendation:** amend PLT-PRF-023 to name the CI entry explicitly, so the
requirement states the whole cost rather than the part that flatters the design.

---

## 3. VP1-ANL-003 — handling a suite that breaks for one profile only

**Requirement:** PLT-VER-003 — a change to the core that breaks one profile
suite and not the other shall be treated as a boundary defect.

### 3.1 Procedure

1. **Detection.** CI runs the boundary gate, then the unit suite, then one
   conformance job per profile. A conformance job failing for some profiles and
   not others raises a boundary defect. It is not a test failure to be fixed in
   the test.
2. **Classification.** The author of the change classifies it, in the pull
   request, as one of:
   - **(a) Leak** — core behaviour now depends on something only some profiles
     declare. Fix the core, not the profile or the test.
   - **(b) Profile defect** — the core is right and a profile's data is wrong.
     Fix the profile; add a validation rule so the class cannot recur.
   - **(c) Interface change** — the hook contract genuinely needs to change.
     Requires an ICD revision and all in-tree profiles updated in the same
     change set (ICD-VER-004).
3. **Record.** The classification and its reasoning go in the commit message.
   A change classified (a) may not merge until the core no longer distinguishes
   the profiles.
4. **Review.** Growth in hook surface is the leading indicator of a misplaced
   boundary (ICD-VER-005) and is reviewed as such at each release.

### 3.2 Worked example

Available from this session, as a near-miss of exactly the kind the procedure
exists for.

Adding IF-ICX (interconnection) modified five files under `core/`: `hooks.py`,
`session.py`, `loader.py`, `model.py`, `validation.py`. On the face of it that
looks like a leak.

**Classification: (c) interface change.** The claim the architecture makes is
that adding a *profile* requires no core change (PLT-PRF-023, verified in §2).
Adding a *hook* is a core change by definition — it extends the contract itself.
The discriminator applied: after the change, does the core distinguish between
profiles? It does not. All three profiles load, and the MCX and FRMCS profiles
declare partners while `utility` declares none, which the core handles through
the same path.

Per ICD-VER-004, every in-tree profile was updated in the same change set, and
ICD-001 was revised to v0.3.

**A second, real instance** from the same session, classified **(a)**:
`core/hooks.py` docstrings named FRMCS, TETRA, P25 and railway concepts. Caught
by `VP1-BND-001`, which failed the build. Fixed by making the docstrings
profile-neutral — the core, not the gate. That is the procedure operating
correctly on a genuine leak.

**Verdict: PASS.** Procedure defined, with two worked classifications.

---

## 4. Residual risk

| # | Risk | Mitigation |
|---|---|---|
| ANL-R-01 | §1 and §2 are single experiments, not exhaustive. A call type or profile shape not yet attempted could require a core change. | Re-run both as recurring checks whenever a profile gains a feature class not previously exercised. |
| ANL-R-02 | The `utility` profile was written by the same author as the framework, so it may unconsciously avoid awkward shapes. | The next profile should be written by someone who has not read `core/`. That is the real test of PLT-PRF-023. |
| ANL-R-03 | No pre-snapshot history exists, so the analyses cannot speak to how the boundary held during original construction. | Accepted and recorded in §0.1. Future changes are under version control. |

---

## 5. Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-09-21 | Initial record. VP1-ANL-001 PASS, VP1-ANL-002 PASS with a recorded checklist item, VP1-ANL-003 PASS. |
