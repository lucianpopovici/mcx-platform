"""Standardised 5G QoS Identifiers (PLT-BER-00x, PLT-CONF-AUDIT CA-15).

TS 23.501 table 5.7.4-1, "Standardized 5QI to QoS characteristics mapping",
read from the Rel-17 and Rel-19 versions in `docs/3GPP/`, which are identical.

This is 3GPP knowledge, not profile knowledge: a 5QI means the same thing in
every deployment, which is why it can live in `core/` while the profile's
choice of which one to use cannot. The core never learns WHICH 5QI a
deployment picks -- only whether the one it picked exists and is being asked
to carry the kind of traffic it was defined for.

Before this, `qos_identifier` was accepted entirely unchecked, and an in-tree
profile was requesting the Mission Critical Video 5QI for a data bearer.
"""

from __future__ import annotations

from typing import Mapping, Optional

# Every value table 5.7.4-1 assigns. A 5QI outside this set is a
# "pre-configured" or operator-specific one (clause 5.7.3): legitimate, but
# its characteristics are not knowable here, so it is accepted and not
# cross-checked.
STANDARDISED_5QI = frozenset({
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    65, 66, 67, 69, 70, 71, 72, 73, 74, 75, 76,
    79, 80, 82, 83, 84, 85, 86, 87, 88, 89, 90,
})

# The mission-critical 5QIs, and the media each was defined to carry. Only
# these are cross-checked against a bearer rule's media: the rest are
# general-purpose and a profile may reasonably use them for anything.
MC_5QI_MEDIA: Mapping[int, str] = {
    65: "voice",        # Mission Critical user plane Push To Talk voice
    66: "voice",        # Non-Mission-Critical user plane Push To Talk voice
    67: "video",        # Mission Critical Video user plane
    69: "data",         # MC delay sensitive signalling (see the note below)
    70: "data",         # Mission Critical Data
}

# 69 is "Mission Critical delay sensitive signalling (e.g. MC-PTT signalling)".
# It is grouped with data here because that is the media kind a profile would
# declare for it; the platform has no separate signalling-bearer concept, which
# is recorded as BER-OP-02.

# TS 23.501 clause 5.7.2.2: "The range of the ARP priority level is 1 to 15
# with 1 as the highest priority."
#
# The same clause reserves levels 1-8 for services authorised to receive
# prioritised treatment within an operator domain. That narrower bound is NOT
# here: which levels a deployment may use is its own policy, and a profile
# that wants to hold itself to 1-8 says so in its own conformance suite.
# VP1-BND-012 rejected the constant when it was written here, correctly.
ARP_MIN, ARP_MAX = 1, 15


def is_standardised(qos_identifier: int) -> bool:
    return qos_identifier in STANDARDISED_5QI


def media_of(qos_identifier: int) -> Optional[str]:
    """The media kind this 5QI was defined to carry, or None when the value is
    not mission-critical and so carries no such expectation."""
    return MC_5QI_MEDIA.get(qos_identifier)
