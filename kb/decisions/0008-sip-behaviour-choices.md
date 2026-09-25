---
id: 0008
title: SIP behaviour choices — keep 503 behind proxies; the ring limit is declared per call type; ad hoc lists are capped
status: accepted
date: 2026-09-25
closes: [SIP-OP-10, SIP-OP-15, ADHOC-OP-04]
relates: [ICD-OP-09, SIP-OP-13, SIP-OP-14]
source: [docs/PLT-VP-R1.md §11, docs/PLT-ICD-001.md §2.7]
---

## Keep 503 (SIP-OP-10, 2026-09-24)
A proxy that receives only a 503 sends 500 upstream and drops the Warning, so behind a proxy
`capacity-exhausted` and `recording-unavailable` look like faults. This is accepted. PLT-PRI-008 only
needs capacity exhaustion to be distinguishable from an **authorisation** refusal, and 403 survives a
proxy. The exact reason code is always in the audit record.

## Ring limit per call type (SIP-OP-15, 2026-09-24)
Each call type declares `no_answer_s` (required, whole seconds, ≥ 1). Once a member rings, that limit
replaces Timer B as its deadline. A member that never rings is still ended by Timer B at 64·T1. The
in-tree profiles declare 32 s everywhere, which keeps the old behaviour until the owner tunes them.

## Ad hoc participant-list cap (ADHOC-OP-04, 2026-09-25)
`MCX_ADHOC_LIST_MAX` (required, no default) caps a caller's participant list for every call type. A
longer list is refused with warning 189. The cap is checked **before** any entry is resolved, because
resolution and its audit records happen before authorisation (ICD-OP-09). Before this, `rec-broadcast`
had no bound: 20,000 entries cost about 7 s under the SIP lock. Criteria-based calls are still bounded
by the call type's `max_participants`.
