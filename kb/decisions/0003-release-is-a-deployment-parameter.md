---
id: 0003
title: The 3GPP release is a deployment parameter, independent of the profile
status: accepted
date: 2026-09-24
closes: [REL-OP-02, CA-11]
relates: [REL-OP-01, CA-12]
source: [docs/PLT-CONF-AUDIT.md §3A, docs/PLT-VP-R1.md §11 REL-OP-02, CLAUDE.md]
---

## Context
There used to be a single release baseline. Floor control (TS 24.380) and signalling (TS 24.379) change
across releases, and the FRMCS profile's group calls are ad hoc, which TS 24.379 has only from Rel-18.

## Decision
- `MCX_RELEASE` selects the release. It is required, has no default, and is never inferred from the
  profile or the image (PLT-REL-002). Any profile *starts* at any supported release.
- Release knowledge lives in `core/release.py` only. VP1-BND-022 fails a build that compares a release to
  a literal anywhere else.
- `MCX_STRICT_RELEASE` (required, no default) decides what happens when a profile declares call types the
  release cannot carry. `true` refuses to start and names them. `false` starts and warns in the log and the
  health document. Nobody gets unreachable emergency calls without having said so.
- A signalling constant the configured release does not define is emitted without its number rather than
  suppressed or raised (warning 179 is Rel-17+, REL-OP-01).

## Consequences
- The conformance matrix is profile × release. A green matrix does **not** mean every call type is
  reachable.
- The real case today: FRMCS at Rel-17 has no ad hoc group calls, including the REC.
- A new protocol constant carries its release, read from the documents.
