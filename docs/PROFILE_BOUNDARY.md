# Profile boundary — design notes

## The rule

`core/` may not import from `profiles/`. Profiles are loaded by import path
at startup and reach the core only through the five Protocols in
`core/hooks.py`. A `grep -r "frmcs\|railway\|tetra\|p25" core/` returning
anything is a defect.

## Why the vocabulary is opaque

Call types, urgencies, applications and pre-emption scopes are strings the
core never enumerates. It cannot branch on `if urgency == "emergency"` because
it does not know that value exists. Every such question is answered by
`PriorityPolicy.compare` or `SessionPolicy.decide`. This is what makes a third
profile — a metro operator, a utility — a config drop rather than a release.

## Pre-emption scopes

`PriorityPolicy.compare` returns 0 for decisions carrying different scopes.
Each profile declares exactly one scope today, so this costs nothing now. It
is in the design because the alternative — comparing bare integer levels —
silently produces cross-domain pre-emption the day anything loads two scopes,
and by then the assumption is spread across the codebase.

## Timers

The floor-control engine owns the 24.380 state machine. Profiles supply
constants only. A profile that needs a different *transition* is a signal the
state machine is wrong, not a reason for a profile hook.

## Deployment

One core, one profile per image. `tools/package.py` builds each release
image from the shared part (core, service, profile framework) and exactly one
profile package; the shared part hashes the same in every image, and
VP1-BND-006 fails the build if it does not, or if code that ships in every
image names a specific profile. The profile is still selected by config at
deploy (`MCX_PROFILE`, no default), and an image refuses any profile it does
not carry. The loader validates
strictly (unknown keys are errors), freezes the result, and logs name +
version + content hash; that triple goes on `/healthz` and every audit record,
because the safety case needs to show which profile was running when.

Loading more than one profile is refused unless `MCX_TEST_MODE=1`. That flag
exists for the conformance harness and nothing else, and only the source tree
carries more than one profile to load.

Why per-profile images and not one image carrying everything: a delivery
should contain only what its deployment uses. A public-safety operator does
not receive railway code, and the FRMCS safety case (PLT-SRS OP-03) is argued
over the core plus one profile, not over profiles that are merely never
loaded. What makes this safe is the core hash: without it, per-profile builds
are where per-profile code drift starts.

## What the two suites are for

CI runs every profile suite against the same core, the one whose hash every
release image carries. That is the only
mechanical detector for railway logic leaking into the core. When a change to
floor control breaks the FRMCS suite but not the MCX one, the abstraction has
sprung a leak — fix the seam, not the test.

## Status of the FRMCS profile

`profiles/frmcs/profile.yaml` is a stub. Placeholder values throughout, not
reconciled with the UIC FRMCS FRS/SRS or 3GPP TS 22.289. It exists to keep the
boundary honest while the MCX profile is the one being implemented.

## Next

1. Write the loader and the strict validator — schema first, before session
   control, so the frozen-profile contract exists from commit one.
2. Implement the MCX hooks (`DirectoryResolver`, `TablePriorityPolicy`,
   `MCXSessionPolicy`, `SinglePathSelector`).
3. Build steps 1–4 of the call plan (SIP registration, private call, floor
   control, prearranged group call) against those interfaces.
4. Only then implement the FRMCS hooks. If that touches anything under
   `core/`, stop and move the seam.
