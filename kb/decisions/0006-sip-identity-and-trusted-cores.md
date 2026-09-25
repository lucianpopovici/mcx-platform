---
id: 0006
title: SIP identity comes from the TLS certificate, or from a trusted core on a CA of its own
status: accepted
date: 2026-09-25
closes: [ICD-OP-08, ICD-OP-10]
relates: [ICD-OP-11, ICD-OP-09, NET-OP-01]
source: [docs/PLT-ICD-001.md §2.8, §11, docs/PLT-VP-R1.md §11 NET-OP-01]
---

## Decision (R1 form; OpenID Connect is R2)
- A request may assert only an identity its TLS connection authenticated: a `sip:` URI in the peer
  certificate's subjectAltName. The check runs on REGISTER (the AoR) and INVITE (P-Asserted-Identity or
  From). A mismatch returns 403 `identity-not-authenticated`.
- A **trusted core** may assert any identity (RFC 3325 trust domain). To count as one, a peer needs both
  a certificate issued directly by the **core CA** and a DNS name listed in the network profile's
  `sip.trusted_cores`. The core CA is a self-signed root with `pathLenConstraint` 0, kept apart from the
  users' anchors in `MCX_SIP_TLS_CA` by key, name and issuance. Its certificates assert no user identity.
- Each dialog is bound to the connection it was set up on. That covers responses, BYE, ACK and CANCEL,
  and a new INVITE may not reuse a live call's Call-ID.

## Why it took three passes
Sharing one anchor meant any user certificate carrying a core's DNS name was trusted as a core. An
independent review of the first core-CA version found three defects, all fixed: an intermediate under the
users' root was accepted as the core CA; a TRUSTED CERTIFICATE block was taken as an anchor unchecked; and
core-CA certificates could authenticate user URIs.

## Deployment obligations the platform cannot check
A trusted core must authenticate every user itself and strip P-Asserted-Identity from untrusted sources.
The core CA must issue trusted DNS names only to cores.

## Still open
ICD-OP-11: (Call-ID, CSeq) is recorded before the identity check, so a refused spoofed request uses up
that pair. ICD-OP-09: resolution runs before admission, so the response tells an unauthorised caller
whether someone exists.
