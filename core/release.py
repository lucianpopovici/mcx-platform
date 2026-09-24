"""The 3GPP release a deployment speaks (PLT-REL-001..008).

A release is a deployment parameter, chosen at start like the profile and
frozen for the life of the process, but it is a DIFFERENT AXIS from the
profile. Any profile can run at any supported release: the profile says what
this deployment does, the release says which version of the protocol it says
it in. Two profiles and two releases are four deployments, not four profiles.

Why this exists at all
----------------------
Constants are not stable across releases, and the dangerous case is not a
value that is missing. It is a value that is present in both releases and
means something ELSE:

    subtype 14   Rel-17  Floor Queued Cancel
                 Rel-18+ Queued Floor Requests

A Rel-17 peer receiving subtype 14 from a Rel-18 deployment does not reject
it. It decodes it and acts on the wrong message. No amount of "be liberal in
what you accept" helps, because nothing about the packet says which one it is
-- only the release does.

Provenance
----------
Every table below was extracted mechanically from the eight published
versions of TS 24.380 in `docs/3GPP/` (Rel-13 `de0` through Rel-20 `k00`),
by reading table 8.2.2.1-1, table 8.2.3.1-2 and clauses 8.2.6.2 and 8.2.10.2
from each. Nothing here was written from recollection; PLT-CONF-AUDIT 2 is
about what happens when it is.

Scope
-----
Both layers. TS 24.380 floor control (subtypes, field ids, revoke causes) and
TS 24.379 signalling (warning codes). The 24.379 sweep is PLT-CONF-AUDIT
CA-12: every other constant the platform emits on the signalling side --
`g.3gpp.mcptt`, the ICSI, the MIME types, the Answer-Mode values -- is
present unchanged in all seven published releases, so only the warning codes
needed a table.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Mapping, Optional, Tuple

from .errors import StartupRefused


class Release(IntEnum):
    """3GPP release. Ordered, so `>=` is a support test."""

    REL_13 = 13
    REL_14 = 14
    REL_15 = 15
    REL_16 = 16
    REL_17 = 17
    REL_18 = 18
    REL_19 = 19
    REL_20 = 20

    def __str__(self) -> str:           # "Rel-17", the form the specs use
        return f"Rel-{int(self)}"


SUPPORTED: Tuple[Release, ...] = tuple(Release)

# --------------------------------------------------------------------------
# TS 24.380 table 8.2.2.1-1 — floor control specific messages
# --------------------------------------------------------------------------

# subtype -> first release in which the table assigns it.
SUBTYPE_INTRODUCED: Mapping[int, Release] = {
    0: Release.REL_13,    # Floor Request
    1: Release.REL_13,    # Floor Granted
    2: Release.REL_13,    # Floor Taken
    3: Release.REL_13,    # Floor Deny
    4: Release.REL_13,    # Floor Release
    5: Release.REL_13,    # Floor Idle
    6: Release.REL_13,    # Floor Revoke
    7: Release.REL_19,    # Floor Revoke Request
    8: Release.REL_13,    # Floor Queue Position Request
    9: Release.REL_13,    # Floor Queue Position Info
    10: Release.REL_13,   # Floor Ack
    11: Release.REL_17,   # Unicast Media Flow Control
    14: Release.REL_17,   # see SUBTYPE_MEANINGS
    15: Release.REL_15,   # Floor Release Multi Talker
}

# subtype -> ((from_release, name), ...), newest last. A subtype appears here
# only when its MEANING changed, not merely its wording.
SUBTYPE_MEANINGS: Mapping[int, Tuple[Tuple[Release, str], ...]] = {
    14: ((Release.REL_17, "Floor Queued Cancel"),
         (Release.REL_18, "Queued Floor Requests")),
}

_SUBTYPE_NAMES: Mapping[int, str] = {
    0: "Floor Request", 1: "Floor Granted", 2: "Floor Taken", 3: "Floor Deny",
    4: "Floor Release", 5: "Floor Idle", 6: "Floor Revoke",
    7: "Floor Revoke Request", 8: "Floor Queue Position Request",
    9: "Floor Queue Position Info", 10: "Floor Ack",
    11: "Unicast Media Flow Control", 15: "Floor Release Multi Talker",
}

# --------------------------------------------------------------------------
# TS 24.380 table 8.2.3.1-2 — floor control specific data fields
# --------------------------------------------------------------------------

FIELD_INTRODUCED: Mapping[int, Release] = {
    **{i: Release.REL_13 for i in range(0, 15)},    # ids 0-14
    **{i: Release.REL_15 for i in range(15, 21)},   # ids 15-20
    **{i: Release.REL_17 for i in range(21, 25)},   # ids 21-24
    25: Release.REL_19,                             # Floor Revoke Request User ID
}

# --------------------------------------------------------------------------
# Clause 8.2.10.2 — Floor Revoke causes. Clause 8.2.6.2's Deny causes are
# unchanged in every published release, so they need no table.
# --------------------------------------------------------------------------

REVOKE_CAUSE_INTRODUCED: Mapping[int, Release] = {
    1: Release.REL_13, 2: Release.REL_13, 3: Release.REL_13,
    4: Release.REL_13, 6: Release.REL_13,
    7: Release.REL_19,          # Revoked by another MCPTT client
    255: Release.REL_13,
}


def parse(text: str) -> Release:
    """`MCX_RELEASE` -> Release. Accepts "17" or "Rel-17"; refuses the rest.

    A refusal names what is supported, because the alternative -- guessing a
    release for a deployment that did not state one -- is how a platform ends
    up emitting a message its peers read as a different message.
    """
    raw = (text or "").strip()
    cleaned = raw.lower().removeprefix("rel-").removeprefix("rel").lstrip("-_ ")
    try:
        return Release(int(cleaned))
    except ValueError:
        raise StartupRefused(
            f"MCX_RELEASE={raw!r} is not a supported 3GPP release "
            f"(supported: {', '.join(str(r) for r in SUPPORTED)})") from None


def supports_subtype(release: Release, subtype: int) -> bool:
    introduced = SUBTYPE_INTRODUCED.get(subtype)
    return introduced is not None and release >= introduced


def supports_field(release: Release, field_id: int) -> bool:
    introduced = FIELD_INTRODUCED.get(field_id)
    return introduced is not None and release >= introduced


def supports_revoke_cause(release: Release, cause: int) -> bool:
    introduced = REVOKE_CAUSE_INTRODUCED.get(cause)
    return introduced is not None and release >= introduced


def subtype_name(release: Release, subtype: int) -> Optional[str]:
    """What this subtype MEANS at this release, or None if it is not assigned.

    This -- not the name of a `MsgType` member -- is what a trace, an audit
    record or a future handler should use. `MsgType` can carry only one name
    per value, and for subtype 14 one name is not enough.
    """
    if not supports_subtype(release, subtype):
        return None
    for from_release, name in reversed(SUBTYPE_MEANINGS.get(subtype, ())):
        if release >= from_release:
            return name
    return _SUBTYPE_NAMES.get(subtype)


def introduced_in(release: Release) -> Tuple[int, ...]:
    """Subtypes this release adds. Used by the per-release conformance suite
    to prove the gate actually gates something at each step."""
    return tuple(sorted(s for s, r in SUBTYPE_INTRODUCED.items() if r == release))


# --------------------------------------------------------------------------
# TS 24.379 table 4.4.2-2 — Warning texts (PLT-CONF-AUDIT CA-12)
# --------------------------------------------------------------------------

# Extracted from the seven published versions of TS 24.379 in `docs/3GPP/`
# (Rel-13 `dj0` through Rel-20 `k00`). Codes are allocated in contiguous
# blocks per release, which is why this compresses to seven ranges; 129-135
# are allocated in no release at all.
#
# The table grew from 44 codes to 95. The platform emits three of them, and
# one -- 179, for a refusal by the local system on an interconnection -- does
# not exist before Rel-17.
SIP_WARNING_INTRODUCED: Mapping[int, Release] = {
    **{c: Release.REL_13 for c in (*range(100, 129), *range(136, 151))},
    **{c: Release.REL_14 for c in range(151, 157)},
    **{c: Release.REL_15 for c in range(157, 159)},
    **{c: Release.REL_16 for c in range(159, 166)},
    **{c: Release.REL_17 for c in range(166, 184)},
    **{c: Release.REL_18 for c in range(184, 196)},
    **{c: Release.REL_20 for c in range(196, 202)},
}


def supports_sip_warning(release: Release, code: int) -> bool:
    """Whether this release's TS 24.379 table 4.4.2-2 defines that warning code.

    Table 4.4.2-2 reserves 301-350 for interworking without giving them
    meanings, deferring to TS 29.379. That document's table 4.2.2-1 allocates
    300, 301 and 302 -- LMR end-to-end encryption not permitted, required, and
    LMR codec required -- from Rel-17 onward, and nothing else in the range.

    They stay out of the table above, and this returns False for them, because
    they belong to a different document's table describing a role this platform
    does not perform: an IWF terminating Land Mobile Radio media security. The
    emission path consults this function only for codes in WARNING_TEXTS, none
    of which is in the 300 range, and none may become one (PLT-CONF-AUDIT
    CA-09; pinned by test_no_refusal_emits_an_interworking_warning_code).

    Note also that 300 sits OUTSIDE the 301-350 that table 4.4.2-2 reserved --
    the two specifications disagree about the lower bound (IWF-OP-01).
    """
    introduced = SIP_WARNING_INTRODUCED.get(code)
    return introduced is not None and release >= introduced


# TS 24.379 annex F.1, the MCPTT info body (PLT-CONF-AUDIT CA-20). Read from
# all seven published versions in docs/3GPP/TS24.379 (13.19, 14.16, 15.16,
# 16.14, 17.15, 18.13, 20.0) by counting where each value is used by a
# procedure; the first version that uses it is the one that introduced it.
#
# The consequence worth knowing: ad hoc group calls, and the ad hoc emergency
# indication, do not exist before Rel-18. A profile whose call types are
# declared with the ad hoc session type cannot be requested by any client at
# an earlier release; service startup reports which call types are affected.
SESSION_TYPE_INTRODUCED: Mapping[str, Release] = {
    "prearranged": Release.REL_13,
    "chat": Release.REL_13,
    "private": Release.REL_13,
    "first-to-answer": Release.REL_14,
    "ambient-listening": Release.REL_14,
    "adhoc": Release.REL_18,
}

MC_INDICATOR_INTRODUCED: Mapping[str, Release] = {
    "emergency-ind": Release.REL_13,
    "imminentperil-ind": Release.REL_13,
    "broadcast-ind": Release.REL_13,
    "adhoc-emergency-ind": Release.REL_18,
}


def supports_session_type(release: Release, session_type: str) -> bool:
    introduced = SESSION_TYPE_INTRODUCED.get(session_type)
    return introduced is not None and release >= introduced


def supports_mc_indicator(release: Release, name: str) -> bool:
    introduced = MC_INDICATOR_INTRODUCED.get(name)
    return introduced is not None and release >= introduced
