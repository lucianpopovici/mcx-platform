# Release 1 — Analysis record

**Document:** PLT-ANL-R1
**Version:** 0.3
**Date:** 2026-10-28
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

### 1.1 Re-run on the current core (2026-10-28)

The record above is of 2026-09-21, at 280 tests and 18 gates. Since then the
core has gained functional aliases, ad hoc calls, the session layer's SIP
binding and much else, so the experiment was repeated on the current head
(`f61c724`, after ADHOC-OP-06): an urgency (`heightened`), an application
(`incident-command`, safety relevant), a call type (`incident-command-group`,
group-selected, using both, with a floor policy no other call type has: queue
depth 3, T2 2500 ms) and a priority rule placing it at level 60, between
`elevated` (50) and `imminent-peril` (70).

**Evidence:** `docs/analysis/VP1-ANL-001-rerun.patch` (the change set, to apply
with `git am` on `f61c724`), and `docs/analysis/VP1-ANL-001-demo.py`, which
establishes a call of the new call type and of two shipped ones through
`SessionManager` on the patched tree.

| Measure | Result |
|---|---|
| Files changed | 1 (`profiles/mcx/profile.yaml`, 40 lines added) |
| Files changed under `core/` | **0** |
| Files under `core/` naming the new call type | 0 |
| Boundary gates | 21/21 pass |
| Test suite | 3 225 passed, **2 failed** (below) |
| Established | `incident-command-group`: priority `heightened`, level 60, floor queue depth 3 and T2 2500 ms, its own declaration (the shipped `coordination-group`: 6 and 3500 ms) |

**Finding.** Two tests failed:
`test_health_says_which_call_types_no_client_can_request` (tests/test_service.py)
and `test_a_prearranged_call_to_a_choosing_group_is_its_call_type`
(tests/test_sip_transport.py). Both assert the health document's
`selected_by_group` for the shipped mcx profile as a literal, and the new call
type is one more entry in it. They are platform tests that pin the shipped
profile's data, not the core and not the conformance suite (which passed
unmodified); the core behaved as intended. The cost of adding a call type to a
shipped profile is therefore the profile file **plus the expectations of the
tests that pin that profile's contents**.

**Verdict: PASS.** PLT-PRF-022 concerns code under `core/`, which needed no
change. **Recommendation:** have those two tests derive the expected entries
from the loaded profile, as the conformance suite does, so the requirement's
claim holds for the test suite too.

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

### 2.1 Re-run on the current core (2026-10-28)

Repeated on `f61c724` with a fourth profile, `metro` (an urban metro and tram
operator), written for the re-run rather than renamed from another: a private
call, a station group call, an emergency group call that needs a
location-dependent role (`line-controller`, per `line_id`), its own urgencies,
applications, scope, priority, bearer and admission tables and codec list, and
no interworking or interconnection partners. Every hook is a shared table
implementation, unchanged.

**Evidence:** `docs/analysis/VP1-ANL-002-rerun.patch`.

**Method, and why it is not the one PLT-VP-R1 §8 names.** §8 asks for the
demonstration "by the FRMCS stub's own history". That history cannot give it:
`profiles/frmcs/profile.yaml` arrived in the initial commit `fb413ea` with
`core/hooks.py`, its hooks in `d9d5d5b` with the loader, model and validation,
and 17 of the 24 commits touching `profiles/frmcs` also touch `core/`, because
the framework and that profile were built together. A profile introduced into
a finished core is what the requirement is about, so the analysis introduces
fresh ones instead: `utility` in 2026-09 (§2) and `metro` now. The owner
accepted the substitution and amended PLT-VP-R1 §8 to name it (2026-10-28,
PLT-VP-R1 0.64).

| Measure | Result |
|---|---|
| Files changed under `core/` | **0** |
| Files added under `profiles/` | 3 |
| Files changed elsewhere | 2: `.github/workflows/ci.yml` (the conformance matrix entry; without it VP1-BND-020 and VP1-REL-002 fail) and `tools/check_boundary.py` (the reviewed workflow's fingerprint, `REVIEWED_WORKFLOW`, re-pinned; without it VP1-BND-006 fails) |
| Conformance suite against the new profile, Rel-13 to Rel-20 | 18 passed at each of the 8 releases, **suite unmodified** |
| Boundary gates | 21/21 pass (after the two changes above) |
| Test suite | 3 264 passed, **6 failed**, each pinning the three in-tree profiles or the CI matrix literal: `test_the_release_is_independent_of_the_profile` (tests/test_release.py, 3 × 8 combinations), `test_there_are_profiles_to_build` (tests/test_packaging.py), and four of the boundary gate's own self-tests in tests/test_boundary.py (`test_bnd_020_a_new_profile_needs_its_suite`, `test_bnd_020_catches_the_variants[profile-dropped]`, `test_the_matrix_gate_fails_when_a_combination_would_go_unrun[missing-profile]`, `test_bnd_006_review_probes_round_1[packager-ships-another-profile]`) |

**Findings.**

1. The CI entry of 2026-09-21 still applies, and now brings a second edit: the
   boundary gate pins the reviewed workflow's fingerprint (VP1-BND-006), so the
   matrix entry is re-pinned there too.
2. Six platform tests pin the set of in-tree profiles or the CI matrix as
   literals, four of them the boundary gate's self-tests; a fourth profile fails
   them until their expectations are updated. (v0.2 as first written said one;
   the review counted six.)
3. **A profile's name is constrained by the core's vocabulary.** The profile was
   first called `transit`. VP1-BND-001 adds every in-tree profile name to the
   terms forbidden in `core/`, matched inside words, and `transit` occurs in
   `transition` (the TS 24.380 floor-control term, 40 times in three files of `core/`). The
   gate failed the build. Renaming the core's words would have been a core
   change for a profile; the profile was renamed instead. Accepted as the
   gate's documented behaviour (a false positive to rename, `INSIDE_WORD_EXCEPTIONS`),
   but it is part of the cost: a profile's name must not occur inside a word of
   the core.

**Verdict: PASS.** No file under `core/` changed. The whole cost of a profile on
this head: one package directory, one CI matrix entry and its re-pinned
fingerprint, six pinned test expectations (packaging, the release matrix and
four gate self-tests), and a name the core does not contain.
**Recommendations:** amend PLT-PRF-023's note to list that checklist; have
those six tests read the in-tree profiles rather than pin three.

---

## 3. VP1-ANL-003 — handling a suite that breaks for one profile only

**Requirement:** PLT-VER-003 — a change to the core that breaks one profile
suite and not the other shall be treated as a boundary defect.

### 3.1 Procedure

1. **Detection.** CI runs the boundary gate, then the unit suite, then one
   conformance job per profile. A conformance job failing for some profiles and
   not others raises a boundary defect. It is not a test failure to be fixed in
   the test.
2. **Classification and record** (as amended 2026-10-28, owner decision). The
   author of every commit that changes `core/` together with a profile, or that
   a split conformance job made necessary, states its class and the reasoning
   in the commit message, as one of:
   - **(a) Leak** — core behaviour now depends on something only some profiles
     declare. Fix the core, not the profile or the test.
   - **(b) Profile defect** — the core is right and a profile's data is wrong.
     Fix the profile; add a validation rule so the class cannot recur.
   - **(c) Interface change** — the hook contract genuinely needs to change.
     Requires an ICD revision and all in-tree profiles updated in the same
     change set (ICD-VER-004).
3. **Check.** The independent review that change receives checks the class
   as part of the review. A change classified (a) may not be committed until
   the core no longer distinguishes the profiles. (Before the amendment, step 2
   put the class in a pull request and step 3 in the commit message, and nothing
   checked it; the project commits directly, §3.3 finding 3.)
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

### 3.3 Worked examples from the R1 period (to 2026-10-28)

Re-derivable from the project history:

- **(c) interface change, `bdca845`** (ADHOC-OP-06): IF-IDR gained `kind_of`. Four
  files under `core/` changed (`hooks.py`, `loader.py`, `session.py`, `sip.py`),
  PLT-ICD-001 was revised to 0.37 and marked a major change under ICD-VER-003,
  and every in-tree profile gained the method in the same change set (in
  `profiles/common/tables.py`, the directory and the functional resolver each
  implementing it). After it the core does not
  distinguish the profiles.
- **(c) interface change, `3ea4872`** (FA-OP-01 item 4): a functional identity
  keyed by an identification value. A profile could not say "one holder per
  train" before; saying it needed `identification_key` in the profile model and
  its validation, `keyed_identity` in `core/hooks.py`, and their use in
  `core/functional.py` and `core/session.py` (PLT-ICD-001 0.33, a
  major change for the frmcs deployments). It is the case ANL-R-01 foresaw: a
  feature class not previously exercised. Classified (c), not (a): the core reads
  a declared attribute, not a profile's name, and every profile declaring none
  behaves as before.
- **(c) interface change, with the (b) profile defect it found, `c324c5a`**
  (ICD-OP-14): the core's check of §6.1 POST-5 was tightened (core/session.py;
  PLT-ICD-001 0.30, a major change for a deployment that turns it on), and
  checking every in-tree call type against it found the frmcs `etcs-ipcon`
  bearer immune to network pre-emption while its priority decision left it
  open. That defect is (b): the core was right and the profile's data was
  corrected; the check that found it is now the core's
  (`MCX_ARP_VULNERABILITY_CHECK`), so the class cannot recur unseen. It is the
  one example where a single profile's suite would likely have broken (not
  observed: it was found by checking, not by a failing job).

**Findings.**

1. None of these commit messages carries the procedure's classification label
   (step 3); the classes above were assigned after the fact, by the author of
   this record, from the reasoning the messages give. The procedure's record
   and its "who" were not followed; its substance -- fix the core for a leak,
   the data for a defect, the ICD and every profile for an interface change --
   was.
2. The detection path (step 1, a conformance job failing for some profiles and
   not others) has not fired in the R1 period: every example was found by
   design work or review.
3. The procedure as written does not fit how the project works: step 2 puts the
   classification in a pull request and step 3 in the commit message, while the
   project commits directly; and nothing checks the author's classification.

**Amendment (owner decision 2026-10-28), now in §3.1:** steps 2 and 3 became
one: the author states the class, (a), (b) or (c), and its reasoning in the
message of every commit that changes `core/` and a profile together, or that a
split conformance job made necessary; and the independent review each such
change already gets checks the class as part of the review.

**Verdict: PASS**, the procedure defined, with five worked classifications,
three of them from the R1 period, and the findings above recorded.

---

## 4. Residual risk

| # | Risk | Mitigation |
|---|---|---|
| ANL-R-01 | §1 and §2 are single experiments, not exhaustive. A call type or profile shape not yet attempted could require a core change. | Re-run both as recurring checks whenever a profile gains a feature class not previously exercised. Re-run 2026-10-28 (§1.1, §2.1); `3ea4872` (§3.3) is such a feature class, and needed an interface change. |
| ANL-R-02 | The `utility` profile was written by the same author as the framework, so it may unconsciously avoid awkward shapes. | The next profile should be written by someone who has not read `core/`. That is the real test of PLT-PRF-023. |
| ANL-R-03 | No pre-snapshot history exists, so the analyses cannot speak to how the boundary held during original construction. | Accepted and recorded in §0.1. Future changes are under version control. The history does show one thing (§2.1, Method): the frmcs profile and `core/` were built together, so that history cannot evidence PLT-PRF-023. |

---

## 5. Revision history

| Version | Date | Change |
|---|---|---|
| 0.3 | 2026-10-28 | Owner decisions: the substituted method for VP1-ANL-002 accepted, PLT-VP-R1 §8 amended to name it; §3.1 amended (the class in the commit message, checked by the independent review). Independent review: VP1-ANL-001, -002 and -003 pass; signed by the owner (PLT-VP-R1-REVIEWS). |
| 0.2 | 2026-10-28 | §1.1 and §2.1: both experiments re-run on the current core (`f61c724`), the change sets and the call-establishment script kept in `docs/analysis/`; no file under `core/` changed in either. Findings: tests pinning the shipped mcx profile's data, and six pinning the in-tree profiles or the CI matrix; the workflow fingerprint re-pinned with the CI entry; a profile name the core contains (`transit`) refused by VP1-BND-001; §2.1 substitutes fresh profiles for the "FRMCS stub's history" §8 names, which cannot show it. §3.3: three worked classifications from the R1 period (one corrected to (c) with the (b) defect it found); the class is in no commit message, the detection path has not fired, and the procedure's PR step does not fit direct commits, with an amendment proposed. Corrections from the independent review included. |
| 0.1 | 2026-09-21 | Initial record. VP1-ANL-001 PASS, VP1-ANL-002 PASS with a recorded checklist item, VP1-ANL-003 PASS. |
