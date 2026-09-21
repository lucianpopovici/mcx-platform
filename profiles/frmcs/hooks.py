"""FRMCS profile hooks — STUB.

Shape only. Its purpose in R1 is VP1-ANL-002: to demonstrate that introducing a
second profile touches no file under `core/`. Railway semantics are provisional
until PLT-SRS §14 is reconciled with the UIC FRS/SRS.

Note what is NOT here: multi-path selection and GSM-R mapping reuse the shared
table implementations unchanged, because the divergence lives in the profile's
data, not in its code. If that stops being true, the seam is wrong.
"""

from __future__ import annotations

from profiles.common.tables import (
    TableInterconnectionGateway,
    FunctionalResolver,
    PrefixInterworkingGateway,
    TableBearerSelector,
    TablePriorityPolicy,
    TableSessionPolicy,
)

__all__ = [
    "PartnerGateway",
    "FunctionalResolver",
    "TablePriorityPolicy",
    "FRMCSSessionPolicy",
    "MultiBearerSelector",
    "GSMRGateway",
]


class FRMCSSessionPolicy(TableSessionPolicy):
    """Table policy unchanged. REC broadcast semantics, acknowledgement
    collection and recording obligations are all expressed as call type data."""


class MultiBearerSelector(TableBearerSelector):
    """Multi-path decisions come from the profile's bearer table, which declares
    `redundancy: multihomed` with two SCTP paths for safety-relevant data.

    OPEN (ICD-OP-04): path teardown has no interface. `on_path_event` can revise
    a decision but cannot release a path, so transfer is currently additive only.
    """


class GSMRGateway(PrefixInterworkingGateway):
    """Interworking to GSM-R by target prefix (R4)."""


class PartnerGateway(TableInterconnectionGateway):
    """Partner reconciliation from the profile's interconnection table."""
