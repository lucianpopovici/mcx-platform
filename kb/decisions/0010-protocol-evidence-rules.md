---
id: 0010
title: Protocol constants and message bodies come from the specification documents, never from this repository
status: accepted
date: 2026-09-21
closes: []
relates: [CA-13, CA-20, CA-16, CA-18, FC-OP-04]
source: [CLAUDE.md "Protocol constants", docs/PLT-CONF-AUDIT.md §1-2, 4.9, 4.10]
---

## Why this is a decision and not a style note
Nine of the first ten constant sets checked against their specification were wrong. The worst defect,
CA-20, was a message *body*, not a constant: the platform read and wrote an MCPTT info body in a format
that doesn't exist, so no conformant client could call it.

## Rules
1. Read constants from the `.docx` originals in `docs/3GPP/`, not the PDFs. Automated PDF table
   extraction fails silently: it returns a plausible invented table. That happened once (CA-16, and
   CA-18 needed a human read too).
2. Write message bodies from the schemas in `docs/3GPP/schemas/` (extracted verbatim by
   `tools/spec/extract_xsd.py`). Fixtures and the interop user agent spell bodies out from the
   specification. The interop agent once copied its body from the platform's tests and so shared the
   defect.
3. A test that pins a constant spells the value as a literal. Importing the constant under test proves
   nothing, and one such test survived until mutation testing caught it (CONF-AUDIT 4.10).
4. `tools/trace_compare.py` must not import `core/`. Structural independence isn't enough: when you
   change one, derive the change from the specification, not from the other (FC-OP-04, CA-13).
5. Treat any message-building code you touch as unaudited. The audit read constants, not the builders
   around them.
6. A new constant carries its release (0003).
7. A new guard needs a test that fails when the guard is broken on purpose (mutation check).
