---
id: 0012
title: Groups and users are part of the network profile
status: accepted
date: 2026-09-26
closes: [SVC-OP-03]
relates: [SIP-OP-05, NET-OP-01, VP1-DOC-001, PLT-IDM-008]
source: [docs/PLT-ICD-001.md §2.8 ICD-NET-005, docs/PLT-VP-R1.md §11, service/network.py]
---

## Decision
The owner: "Groups should stay in the network profile." `groups` and `users` are required keys of
`MCX_NETWORK_FILE` (`[]` for none), validated with the rest of the file, every defect at once. They are
hashed with it, so the network identifier in every audit record names the group data in force.
`MCX_GROUPS_FILE` is refused if set (as `MCX_CELLS_FILE` and `MCX_SIP_TRUSTED_PEERS` are, 0007).

## Not the service profile
Groups are deployment data: the core must not learn any deployment's groups (0001), and they change with
the organisation, not with the service. Do not add a group section to the service profile schema.

## Still open
SIP-OP-05: being registered does not make a user known; whether third-party registration should
provision users is not decided.
