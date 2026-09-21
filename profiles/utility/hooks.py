"""Utility operator profile hooks.

A third profile, written to test PLT-PRF-023: introducing a profile must
require no change under core/. Every hook is the shared table implementation
unchanged — the divergence from the other profiles lives entirely in
profile.yaml, which is the claim the profile framework makes.
"""

from __future__ import annotations

from profiles.common.tables import (
    DirectoryResolver,
    PrefixInterworkingGateway,
    TableBearerSelector,
    TableInterconnectionGateway,
    TablePriorityPolicy,
    TableSessionPolicy,
)

__all__ = [
    "DirectoryResolver",
    "TablePriorityPolicy",
    "TableSessionPolicy",
    "TableBearerSelector",
    "PrefixInterworkingGateway",
    "TableInterconnectionGateway",
]
