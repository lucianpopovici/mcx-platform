# mcx-platform

A mission-critical services platform (3GPP MCPTT / MCData) that runs as either a
generic public-safety deployment or a railway FRMCS deployment — from one
codebase: one release image per profile, around a core that is byte-identical
in every image (`tools/package.py`, VP1-BND-006).

---

## The one rule

> **`core/` must never learn that a specific profile exists.**

Call types, urgencies, applications and pre-emption scopes are opaque strings the
core cannot enumerate, compare against literals, or order. Everything that makes
a deployment different lives in a profile: a YAML package plus six hook
implementations. That is the whole design, and it is why adding a deployment is a
config change rather than a release.

This is enforced, not encouraged. `tools/check_boundary.py` runs 18 static gates
in CI and **will fail your build** for a line like `if profile.name == "frmcs"`,
for an import from `core/` into `profiles/`, or for the word "railway" in a
docstring under `core/`. If a gate blocks you, the gate is usually right — see
"When a gate fails" below.

---

## Quick start

```bash
pip install pyyaml pytest

python3 -m pytest tests/ -q              # 280 tests
python3 tools/check_boundary.py --root . # 18 boundary gates

# the conformance suite runs once per profile, against the same code
MCX_PROFILE=mcx     python3 -m pytest tests/test_conformance.py -q
MCX_PROFILE=frmcs   python3 -m pytest tests/test_conformance.py -q
MCX_PROFILE=utility python3 -m pytest tests/test_conformance.py -q
```

CI runs all of the above on every change, with no `continue-on-error` and no
conditional skips — a suite that can be skipped produces no evidence.

---

## Layout

| Path | What it is |
|---|---|
| `core/hooks.py` | The six profile interfaces. Start here. |
| `core/loader.py` | Read, validate, freeze, hash, resolve hooks |
| `core/validation.py` | Strict profile validation — unknown keys are errors |
| `core/floor.py` | TS 24.380 floor control, no SIP or media dependency |
| `core/session.py` | The establishment sequence (PLT-ICD-001 §8.1) |
| `core/sip.py` | TS 24.379 adapter, transport-free |
| `profiles/common/` | Shared table-driven hook implementations |
| `profiles/{mcx,frmcs,utility}/` | The three deployments |
| `tools/check_boundary.py` | The gates |
| `docs/` | Specification, interface control, verification plan, analyses |

---

## Adding a profile

Verified cost, from `VP1-ANL-002`: **one package directory, one CI matrix entry.**
Zero changes under `core/`.

1. `profiles/<name>/profile.yaml` — validated against `profiles/SCHEMA.yaml`
2. `profiles/<name>/hooks.py` — usually re-exports `profiles/common/tables.py`
3. Add `<name>` to the matrix in `.github/workflows/ci.yml`

The conformance suite needs no changes: it contains no profile-specific
assertion, so it exercises your profile from its own declarations. If you find
yourself wanting to add one, that is a finding — raise it rather than working
around it.

Adding a call type, urgency or application is `profile.yaml` alone
(`VP1-ANL-001`).

---

## When a gate fails

`tests/test_boundary.py` runs each gate as a test and also proves each one *can*
fail, by injecting a violation. A gate that has never been seen failing is not
evidence the boundary holds.

If a conformance job fails for one profile and not another, that is a **boundary
defect**, not a test to fix. Classify it in your PR (procedure in
`docs/PLT-ANL-R1.md` §3):

- **Leak** — core behaviour now depends on something only some profiles declare.
  Fix the core.
- **Profile defect** — the core is right, the data is wrong. Fix the profile and
  add a validation rule so the class cannot recur.
- **Interface change** — the hook contract genuinely must change. Requires an ICD
  revision and every in-tree profile updated in the same change set.

---

## Documents

| Doc | Contents |
|---|---|
| `docs/PLT-SRS.md` | 207 numbered requirements, phased R1–R4, traced to 3GPP TSs |
| `docs/PLT-ICD-001.md` | The six hook contracts: PRE / POST / INV, sequences, reason codes |
| `docs/PLT-VP-R1.md` | R1 verification plan — 99 cases, full traceability matrix |
| `docs/PLT-ANL-R1.md` | The three R1 analyses, performed as worked changes |
| `core/PROFILE_BOUNDARY.md` | Why the boundary is where it is |

---

## Status

R1 is **not** complete. 83 of 99 verification cases pass; the remaining 16 need a
live SIP core, RTCP on the wire, or media endpoints, and no further design closes
them. Standing up that environment is the next milestone.

Known gaps, all recorded rather than hidden:

- The FRMCS profile is a **stub**. Its values are placeholders and are not
  reconciled with the UIC FRS/SRS. It must not be used as safety-case input.
- 25 open points across the documents, several needing decisions rather than
  work — notably the undefined "production indicator" three requirements depend
  on, and which components fall under which SIL.
- Only the 83 R1 requirements have a verification plan. R2–R4 do not yet.
