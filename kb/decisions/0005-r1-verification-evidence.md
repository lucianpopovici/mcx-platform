---
id: 0005
title: What counts as R1 evidence — a B2BUA counts as a SIP core; specification-derived flows are accepted
status: accepted
date: 2026-09-24
closes: [VP-OP-01, VP-OP-02, SIP-OP-01]
relates: [SIP-OP-12, SIP-OP-02, FC-OP-03, FC-OP-08, VP1-SIG-001, VP1-FC-002]
source: [docs/PLT-VP-R1.md §6.1, §7.1.1, §11, docs/PLT-CONF-AUDIT.md §5]
---

## Decisions
1. **VP-OP-01 (2026-09-24):** a back-to-back user agent counts as one of the two third-party SIP cores for
   VP1-SIG-001. The two are Kamailio 5.7.4 (record-routing proxy) and Asterisk 20.6 (B2BUA). VP1-SIG-001
   passed on 2026-09-24.
2. **VP-OP-02 (2026-09-21):** specification-derived flows are accepted in place of golden third-party
   captures. VP1-FC-002 passed on 2026-09-24 on that basis.

## Consequences that travel with the verdicts
- **SIP-OP-12** (open, a deployment constraint): a B2BUA re-originates with SDP only. Originating calls
  through it are refused (the MCPTT info body and P-Asserted-Identity are lost). Terminating calls
  complete, but the callee can't tell which group or caller it is. Any VP1-SIG-001 claim must carry this.
- **SIP-OP-02** (open): the keylog-decrypted capture is still owed. Transcripts are kept in plaintext at
  both user agents.
- **FC-OP-08** (open, low): the trace comparator can't see T3 expiry on the wire.
- The interop Kamailio tests the trust mechanism, **not** a secure core (see 0006).

## How to re-run
`python3 tools/interop/run.py --core kamailio` and `--core asterisk` (needs the packages, or podman).
A green `pytest` run says nothing about what the deployed process does; run interop before relying on it.
