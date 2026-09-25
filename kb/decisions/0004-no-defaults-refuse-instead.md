---
id: 0004
title: No default is ever substituted; required settings refuse startup when missing
status: accepted
date: 2026-09-24
closes: [SVC-OP-05]
relates: [SVC-OP-04, ADHOC-OP-04, NET-OP-01, VP-OP-05]
source: [CLAUDE.md "Conventions that are not negotiable", docs/PLT-VP-R1.md §11]
---

## Decision
A missing hook, an unmapped label, an unrouted target or an unknown partner is **refused**, never
defaulted. Every deployment setting that changes behaviour is required, with no default:
`MCX_PROFILE`, `MCX_RELEASE`, `MCX_STRICT_RELEASE`, `MCX_IDMS`, `MCX_RECORDER`, `MCX_BEARER`,
`MCX_ADHOC_LIST_MAX`, `MCX_NETWORK_FILE`, `MCX_DATA_DIR`. Stubs are explicit values (`stub`) and are
refused under a production indicator.

Refusal and failure are different. A policy refusal returns a value with a reason code from the closed
vocabulary in `core/errors.py`. A fault raises an exception. One is never reported as the other.

## Why, concretely
SVC-OP-05: `fail_closed_platform()` hard-coded recording and QoS to unavailable while every call type
requires recording, so **the shipped process could not establish a call in any profile**. The suite
passed because every end-to-end test injects a permissive `Platform()`. The fix made those capabilities
stated environment variables. The rule that came out of it: if you add a capability to `Platform`, add
the variable that lets the process state it.

## Open around it
VP-OP-05: the "production indicator" that three requirements depend on is still undefined.
