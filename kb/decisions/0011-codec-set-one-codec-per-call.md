---
id: 0011
title: One codec set for every profile; one codec per call; no transcoding before R4
status: accepted
date: 2026-09-25
closes: [VP-OP-03, OP-06, MED-OP-01, MED-OP-04]
relates: [MED-OP-02, MED-OP-03, MED-OP-05, CA-27, SIP-OP-18]
source: [docs/PLT-VP-R1.md §11, docs/PLT-CONF-AUDIT.md 4.40, core/codec.py]
---

## Decision
Every profile declares the same voice codecs by rtpmap name, in this order of preference: EVS/16000,
AMR-WB/16000, AMR/8000, G722/8000, PCMA/8000, PCMU/8000. Profiles carry no payload type numbers.
A call takes the first of these the caller offers (TS 26.179 4.1.2: preference order is operator policy),
the bandwidth-efficient AMR layout when both are offered (4.1.3), and every party must use that codec
with the same payload layout. Transcoding is R4 (MED-OP-03).

## Rules an agent must not undo
- **Payload type direction (RFC 3264 5.1, 6.1).** A number in an SDP is what its author expects to
  RECEIVE. Each party has `rx_pt` (the number in the relay's SDP to it: it sends with that, the relay
  accepts no other) and `tx_pt` (the number in its own SDP: the relay rewrites to it). The first version
  had this backwards and would have muted any callee that renumbered. The relay's answers use the
  offerer's number; its offers keep its own (8.3.2).
- **Must-match parameters.** AMR/AMR-WB: octet-align, crc, robust-sorting, interleaving, channels
  (RFC 4867 8.3.1). EVS: hf-only, evs-mode-switch, cmr (TS 26.445 A.3.1/A.3.3.1; V12.17, V16.4, V19.1
  agree). `cmr` was missed from recollection and found only by reading the spec. Parameters that limit
  what is sent (mode-set, br, bw, dtx) are not layout: MED-OP-05.
- Payload types are 0..127 ASCII digits only; anything else names nothing (a PT of 300 once crashed the
  relay's receive thread and silenced the sender for the call).

## Consequence recorded, not changed
TS 26.179 4.2.1: the server's codec information includes the client codecs (AMR-WB, EVS). A call on
G.722/G.711, because the caller offered neither, offers MCPTT clients a codec they need not have. Such
calls are for interworking parties until R4 (MED-OP-03).
