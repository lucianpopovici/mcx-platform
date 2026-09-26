---
id: 0007
title: Network facts (PLMNs, cell map, trusted cores) are one deployment file, not part of the service profile
status: accepted
date: 2026-09-25
closes: [NET-OP-01, PRF-OP-03, ADHOC-OP-03]
relates: [ICD-OP-12, SVC-OP-03, CA-23, CA-24]
source: [docs/PLT-ICD-001.md §2.8, docs/PLT-VP-R1.md §11]
supersedes_note: ADHOC-OP-03 first put the cell map in the profile; PRF-OP-03 moved it to deployment data the same day.
---

## Decision
`MCX_NETWORK_FILE` (required, no default) names a **network profile**: name, version, PLMNs, the map from
reported cells to location attributes (such as `track_section`), and the trusted SIP cores with their CA.
Its `name/version/hash` joins the service profile and release in every audit record and the health
document. A record therefore shows which cell meant which location, and which cores could assert
identities, on the day of the call.

The old variables `MCX_CELLS_FILE` and `MCX_SIP_TRUSTED_PEERS` are **refused** if set.

## History, so an agent does not reintroduce it
1. ADHOC-OP-03: the core started reading the client's location report (TS 24.379 annex F.3, serving NCGI
   or ECGI). The cell map was first a profile section.
2. PRF-OP-03: cells are network data, so the map moved to a deployment file (`MCX_CELLS_FILE`).
3. NET-OP-01: that file became the `cells` of the network profile.

Encrypted or malformed location reports never refuse a call. They leave it without a location.

## Still open
ICD-OP-12: annex F.3 writes a PLMN as six digits and doesn't say how a two-digit MNC fills three. The
platform compares the six digits as written and doesn't guess. Settle this before any two-digit-MNC
deployment. SVC-OP-03 was closed on 2026-09-26: groups and users joined this file (decisions/0012).
