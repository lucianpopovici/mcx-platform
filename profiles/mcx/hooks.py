"""MCX profile hooks.

Generic public safety: directory resolution, table-driven policy, single-path
bearers, prefix-routed interworking. Nothing here is imported by `core/`.
"""

from __future__ import annotations

from profiles.common.tables import (
    TableInterconnectionGateway,
    DirectoryResolver,
    PrefixInterworkingGateway,
    TableBearerSelector,
    TablePriorityPolicy,
    TableSessionPolicy,
)

__all__ = [
    "PartnerGateway",
    "DirectoryResolver",
    "TablePriorityPolicy",
    "MCXSessionPolicy",
    "SinglePathSelector",
    "P25TetraGateway",
]


class MCXSessionPolicy(TableSessionPolicy):
    """No deviation from the table policy in R1. Named separately so the
    profile can diverge later without a profile.yaml change."""


class SinglePathSelector(TableBearerSelector):
    """Generic MCX rides a single PDU session; the profile's bearer table
    declares `redundancy: single` throughout, which validation enforces."""


class P25TetraGateway(PrefixInterworkingGateway):
    """Interworking to TETRA or P25 by target prefix (R4)."""


class PartnerGateway(TableInterconnectionGateway):
    """Partner reconciliation from the profile's interconnection table."""
