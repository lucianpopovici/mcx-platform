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

One image. One profile, selected by config at deploy. The loader validates
strictly (unknown keys are errors), freezes the result, and logs name +
version + content hash; that triple goes on `/healthz` and every audit record,
because the safety case needs to show which profile was running when.

Loading more than one profile is refused unless `MCX_TEST_MODE=1`. That flag
exists for the conformance harness and nothing else.

## What the two suites are for

CI runs both profile suites against the same binary. That is the only
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
