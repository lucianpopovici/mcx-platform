---
date: 2026-09-26 13:55
agent: Claude Code (Opus 5.5), claude.ai project "MCX Solution"
repo_commit_start: d18eefc (origin/main)
repo_commit_end: 0012bba + this kb commit
ids: [VP-OP-03, OP-06, MED-OP-01, MED-OP-03, MED-OP-04, MED-OP-05, CA-27, SVC-OP-03, SIP-OP-05, VP1-MED-001, VP1-DOC-001]
---

## Task
Implement the decided codec set (EVS, AMR-WB, AMR, G.722, PCMA, PCMU; one codec per call; no transcoding),
verify it against TS 26.445 and TS 26.179 once they were in docs/3GPP, then (owner decision) keep groups
in the network profile.

## Done
- Patch 0034 (merged upstream as b32d08b): core/codec.py, per-party payload type numbers in the relay,
  profiles by rtpmap name. Independent review found 6 defects (the RFC 3264 direction of payload types
  was reversed; PT > 127 crashed the relay thread; others) — all fixed, re-review confirmed.
- bbbc534 (patch 0035): TS 26.445 annex A read; `cmr` added to the EVS must-match set. MED-OP-04 closed.
- cb7bfec (patch 0036): TS 26.179 read from docs/3GPP (V13.2.0, V19.0.0); citations confirmed.
- 0012bba (patch 0037): SVC-OP-03 closed — `groups`/`users` in the network profile, MCX_GROUPS_FILE refused.
- Decision records 0011 (codec set) and 0012 (groups); 0007's "still open" and overlay OP-06 updated.

## Not verified
- Interop was run (Kamailio: AMR-WB renumbered 97/101; Asterisk: G.722) — both PASS on 0012bba. No
  real MCPTT client has been tried; EVS has never been exercised against a real endpoint.
- 0035, 0036 and 0037 were delivered as patches; the owner had not pushed 0035/0036 when 0037 was made,
  so they must be applied in order.

## Open / next
- R1 exit criterion 7. Proposed to the owner, not yet answered: VP-OP-05 — make `MCX_ENV` required
  (production | staging | test | dev) instead of opt-in `MCX_ENV`/`MCX_PRODUCTION` (today a forgotten
  variable lets the stub IdMS/recorder/bearer run in production). Closes SVC-OP-04 with it.
- SIP-OP-05 (third-party registration provisioning users?) and SVC-OP-02 (restart semantics) need the owner.
- MED-OP-05 item (5): an RTP/SAVP offer is answered RTP/AVP; offered to refuse with 488 until SRTP (R2).

## Do not touch
- Do not reorder or "simplify" rx_pt/tx_pt in service/media.py (see decisions/0011).
