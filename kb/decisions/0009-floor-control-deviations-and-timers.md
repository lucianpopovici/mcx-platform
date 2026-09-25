---
id: 0009
title: Floor control — one accepted deviation from TS 24.380, and timers at the specification's defaults
status: accepted
date: 2026-09-24
closes: [FC-OP-07, PRF-OP-02, FC-OP-01, FC-OP-02]
relates: [CA-21, CA-05, FC-OP-09, FC-OP-10, ICD-OP-05]
source: [docs/PLT-VP-R1.md §11, docs/PLT-CONF-AUDIT.md 4.37]
---

## Accepted deviation: a pre-emptor meeting a full queue (FC-OP-07)
TS 24.380 6.3.4.4.7 item 2e puts a pre-emptor at the front of the queue unconditionally. When the queue is
already at the profile's declared depth and the pre-emptor isn't in it, the platform does **not**
pre-empt: the request is denied as queue-full. Inserting it would exceed the declared depth
(PLT-FC-006), and pre-empting without inserting would revoke the talker for nobody. With queueing
disabled, the pre-emptor is held and granted when the grace period ends, as the clause requires.
**Do not "fix" this toward the letter of the clause. It is deliberate.**

## Timer behaviour and values (CA-21, PRF-OP-02)
T1/T2/T3/T8/T20 and C20 follow TS 24.380 6.3.4, driven by `MEDIA_RECEIVED` from the media plane. Floor
Granted retransmission stops on RTP from the holder. T2 (talk limit) counts from the first media packet,
not from the grant. Every floor policy states `T8: 1000` and `T3: 3000`, the specification defaults,
pinned by a test. T2 limits (1–5 s) and T20 (100 ms) are unchanged. C20 is fixed in the core at 3.

## Still open
FC-OP-09: a talker still sending after the grace period is dropped silently, where the specification
re-revokes with cause #3. FC-OP-10: two inconsistencies in TS 24.380 itself, recorded for 3GPP CT1.
