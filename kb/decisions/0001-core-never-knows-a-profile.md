---
id: 0001
title: The core never learns that a specific profile exists
status: accepted
date: 2026-09-21
closes: []
relates: [ICD-OP-05]
source: [CLAUDE.md "The one rule", core/PROFILE_BOUNDARY.md, docs/PLT-ANL-R1.md §3]
---

## Context
One platform serves public-safety MCX and railway FRMCS (and a utility profile). If `core/` branches on
a profile, every new profile becomes a core release and the safety case has to re-examine the core.

## Decision
Call types, urgencies, applications and pre-emption scopes are opaque strings to `core/`. It may not
enumerate them, compare them to literals or order them. Every deployment-specific answer comes from a
profile: a YAML package plus the hook implementations in `core/hooks.py`. `core/` never imports from
`profiles/`.

## Consequences
- A new profile is a configuration drop, not a core change (VP1-ANL-002).
- A profile that needs a different floor-control *transition* means the core state machine is wrong, not
  that a hook is missing (ICD-OP-05 asks whether any profile needs one).
- Pre-emption across scopes returns 0 from `compare`; nothing pre-empts across domains by accident.

## Enforced by
`python3 tools/check_boundary.py --root .` (static gates, VP1-BND-*). **Never weaken a gate to land a
change.** Classify the failure with PLT-ANL-R1 §3: leak → fix the core; profile defect → fix the profile
and add a validation rule; interface change → revise the ICD and every in-tree profile together.
