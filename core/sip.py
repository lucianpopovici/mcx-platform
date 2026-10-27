"""SIP message model and TS 24.379 adapter.

Splits into three pieces, none of which touches a socket:

  Headers/Message  a minimal SIP model, multi-valued headers preserved
  InboundGuard     the rejection rules of PLT-SIG-004 (malformed, replayed,
                   unknown session) with the status codes TS 24.379 specifies
  Adapter          renders the session layer's abstract `Signal`s into SIP, and
                   parses inbound INVITEs into a `SessionRequest`

Keeping this transport-free is what lets TS-SIG run in ENV-UNIT. A socket layer
sits above it and is the only part that needs a live SIP core.

CONFORMANCE: the Warning header codes and texts in WARNING_TEXTS were checked
against 3GPP TS 24.379 V17.15.0 table 4.4.2-2 (PLT-CONF-AUDIT CA-02) and every
one of the eleven values previously here was wrong. Only codes whose
specification description matches a platform reason code are carried now; the
reasons with no faithful code are listed in REFUSALS_WITHOUT_WARNING_TEXT and
deliberately emit no Warning header, because a code that means something else
to a conformant peer is worse than silence.
"""

from __future__ import annotations

import ipaddress

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .errors import (
    ADHOC_PARTICIPANTS_UNDETERMINED,
    ADHOC_TOO_MANY_PARTICIPANTS,
    CALL_TYPE_NOT_PERMITTED,
    IDENTITY_NOT_AUTHENTICATED,
    PARTICIPANT_LIMIT_EXCEEDED,
    INITIATOR_NOT_SERVED,
    CAPACITY_EXHAUSTED,
    FUNCTIONAL_ALIAS_HELD,
    FUNCTIONAL_ALIAS_LOCATION_UNKNOWN,
    FUNCTIONAL_ALIAS_NOT_AUTHORISED,
    NOT_GROUP_MEMBER,
    FUNCTIONAL_ALIAS_TAKE_OVER_NOT_ALLOWED,
    GATEWAY_UNAVAILABLE,
    PARTNER_NOT_PERMITTED,
    PARTNER_UNAVAILABLE,
    HOOK_CONTRACT_VIOLATION,
    HOOK_ERROR,
    HOOK_TIMEOUT,
    NO_BINDING,
    NO_LOCATION_BINDING,
    NOT_AUTHORISED,
    QOS_UNAVAILABLE,
    RECORDING_UNAVAILABLE,
    RESOLVER_UNAVAILABLE,
    UNKNOWN_TARGET,
)
from .hooks import LocationContext, MediaKind, SessionRequest
from . import codec as codec_mod
from . import identity
from . import mcinfo
from .release import (Release, supports_procedure, supports_session_type,
                      supports_sip_warning)
from .session import Signal, SignalType

# PLT-PRF-032: this module implements the SIP-2 reference point (PLT-SRS §3.1).
REFERENCE_POINT = "SIP-2"

# --------------------------------------------------------------------------
# TS 24.379 constants
# --------------------------------------------------------------------------

# Media feature tags, all three now confirmed (PLT-CONF-AUDIT CA-07):
#   g.3gpp.mcptt    TS 24.379 clauses 6.3.2.1.x, 6.3.3.1.x and the annex F flows
#   g.3gpp.mcvideo  TS 24.281
#   g.3gpp.mcdata   TS 24.282
FEATURE_TAG_PTT = "+g.3gpp.mcptt"
FEATURE_TAG_DATA = "+g.3gpp.mcdata"
FEATURE_TAG_VIDEO = "+g.3gpp.mcvideo"

# DATA-OP-01. `g.3gpp.mcdata` is real, but TS 24.282 shows it is rarely enough
# on its own: MCData is three services, and the specification uses a
# service-specific tag and ICSI for each --
#
#   g.3gpp.mcdata.sds      urn:urn-7:3gpp-service.ims.icsi.mcdata.sds
#   g.3gpp.mcdata.fd       urn:urn-7:3gpp-service.ims.icsi.mcdata.fd
#   g.3gpp.mcdata.ipconn   urn:urn-7:3gpp-service.ims.icsi.mcdata.ipconn
#
# TS 24.481 clause 7.2.8 agrees: an MCData group document's "enabler" attribute
# is set to ONE OF the SDS, FD or ES values, not to a generic MCData one.
#
# The platform cannot express which MCData service a call type is, so a data
# call is announced generically. Saying which would be a profile schema key and
# an ICD revision, not an audit correction.

# The IMS Communication Service Identifier for MCPTT. TS 24.379 requires it in
# both the Contact and a dedicated Accept-Contact header field, percent-encoded
# on the wire.
MCPTT_ICSI = "urn:urn-7:3gpp-service.ims.icsi.mcptt"
FEATURE_TAG_ICSI_REF = "+g.3gpp.icsi-ref"

# RFC 3840 base tag (no "+"): the Contact belongs to a conference focus.
# TS 24.379 6.3.3.1.2 item 1 (INVITEs to callees), 6.3.2.1.5.1 item 1c and
# 6.3.3.2.3.1 item 4c (provisional responses), 6.3.2.1.5.2 item 3c and
# 6.3.3.2.3.2 item 6c (the 200 OK to the originator).
FEATURE_TAG_ISFOCUS = "isfocus"

# RFC 4028 session timers (PLT-CONF-AUDIT CA-20b, PLT-VP-R1 SIP-OP-17).
# TS 24.379 requires them on every dialog the platform takes part in:
# `Supported: timer` and a Session-Expires without refresher on INVITEs to
# callees (6.3.3.1.2 items 6-7); `Require: timer` and Session-Expires on the
# 200 OK to the originator (6.3.3.2.3.2 items 2-3, 6.3.2.1.5.2 items 1-2).
# The interval the platform asks for is a deployment setting
# (MCX_SESSION_EXPIRES_MS); 90 s is the smallest RFC 4028 permits (section 4),
# and the platform accepts any interval down to it.
OPTION_TIMER = "timer"
MIN_SE_S = 90
# 6.3.3.2.3.2 items 8-10 and 6.3.2.1.5.2 items 4-5: the 200 OK to the
# originator. All four but "timer" are extensions of REFER, which the
# platform does not implement (REFER is not in Allow): carried because the
# specification says "shall", decided 2026-09-25 (PLT-CONF-AUDIT CA-20).
SUPPORTED_ON_ANSWER = ("timer", "tdialog", "norefersub", "explicitsub", "nosub")
# 6.3.2.1.5.1 item 2: provisional responses to the originator.
SUPPORTED_ON_PROVISIONAL = ("norefersub",)


@dataclass(frozen=True)
class SessionExpires:
    seconds: int
    refresher: Optional[str] = None       # "uac", "uas", or not stated


def parse_session_expires(value: Optional[str]) -> Optional[SessionExpires]:
    """RFC 4028 section 4: delta-seconds, then parameters; `refresher` is
    "uac" or "uas". Absent header: None. Malformed: SipError."""
    if value is None or not value.strip():
        return None
    head, *params = [p.strip() for p in value.split(";")]
    # ASCII digits only (SIP-OP-19): str.isdigit takes "²", which int()
    # refuses, and other scripts' digits, which int() reads.
    if not (head.isascii() and head.isdigit()) or len(head) > 10:
        raise SipError(f"Session-Expires {clip(value)}")
    refresher = None
    for p in params:
        name, _, v = p.partition("=")
        if name.strip().lower() == "refresher":
            refresher = v.strip().lower()
            if refresher not in ("uac", "uas"):
                raise SipError(f"Session-Expires refresher {clip(v)}")
    return SessionExpires(int(head), refresher)


def parse_min_se(value: Optional[str]) -> Optional[int]:
    if value is None or not value.strip():
        return None
    head = value.split(";", 1)[0].strip()
    if not (head.isascii() and head.isdigit()) or len(head) > 10:   # SIP-OP-19
        raise SipError(f"Min-SE {clip(value)}")
    return int(head)


def has_option(headers: "Headers", name: str, tag: str) -> bool:
    """Whether a Supported / Require style header lists option-tag `tag`."""
    return any(t.strip().lower() == tag
               for v in headers.get_all(name) for t in v.split(","))


def allows(headers: "Headers", method: str) -> bool:
    return any(m.strip().upper() == method
               for v in headers.get_all("Allow") for m in v.split(","))


@dataclass(frozen=True)
class SessionTimer:
    """A negotiated session timer, as seen from the request just answered
    or the 2xx just received. `refresher` is relative to that request:
    "uac" is whoever sent it, "uas" whoever answered it."""
    seconds: int
    refresher: str
    peer_supports: bool = True


def uas_session_timer(headers: "Headers", preferred: int):
    """RFC 4028 section 9, for a request the platform answers (an initial
    INVITE, or an UPDATE or re-INVITE on a dialog). Returns the SessionTimer
    to put in the 2xx, or an int: the Min-SE for a 422 (the request asked for
    less than RFC 4028 allows).

    The interval is what the request asked for, lowered to the deployment's
    `preferred` when that is shorter, and never below the request's Min-SE.
    The refresher is the request's; when it states none, "uac" if the peer
    supports timers (TS 24.379 6.3.2.1.5.2 item 2, 6.3.3.2.3.2 item 2), and
    otherwise "uas": the platform refreshes a peer that cannot (section 9).
    """
    se = parse_session_expires(headers.get("Session-Expires"))
    min_se = max(MIN_SE_S, parse_min_se(headers.get("Min-SE")) or 0)
    supports = has_option(headers, "Supported", OPTION_TIMER) or \
        has_option(headers, "Require", OPTION_TIMER)
    if se is not None and se.seconds < MIN_SE_S:
        return MIN_SE_S
    if se is None:
        seconds = max(preferred, min_se)
    else:
        seconds = min(se.seconds, max(preferred, min_se))
    if not supports:
        refresher = "uas"
    else:
        refresher = (se.refresher if se is not None else None) or "uac"
    return SessionTimer(seconds, refresher, supports)


def uac_session_timer(headers: "Headers") -> Optional[SessionTimer]:
    """RFC 4028 section 7.2, for a 2xx the platform receives. None: the peer
    runs no session timer on this dialog. A Session-Expires without a
    refresher is non-conformant; the platform then refreshes itself, which
    keeps the session alive rather than letting it lapse. An interval below
    90 s is one RFC 4028 forbids a UAS to choose (section 9); it is taken as
    90, or a peer answering 1 s would have its call ended, or refreshed
    twice a second, for ever (review of SIP-OP-17)."""
    se = parse_session_expires(headers.get("Session-Expires"))
    if se is None:
        return None
    return SessionTimer(max(se.seconds, MIN_SE_S), se.refresher or "uac")


# The "+" is required, not stylistic. IETF RFC 3840 clause 5: base tags (audio,
# video, isfocus and seventeen others) carry no prefix, and for every other tag
# "a plus sign ('+') MUST be added as the first character". The ABNF makes it
# structural -- other-tags = "+" ftag-name. TS 24.379's Contact examples are
# inconsistent about this and six of the eight are editorially wrong
# (PLT-CONF-AUDIT CA-10).


def _pct(value: str) -> str:
    """Percent-encode a feature tag value as TS 24.379 shows it on the wire."""
    return value.replace(":", "%3A")

# The methods the platform accepts (RFC 3261 20.5). UPDATE (RFC 3311) is
# here for session refresh (RFC 4028); REFER is not implemented.
ALLOW = "INVITE, ACK, BYE, CANCEL, UPDATE, REGISTER, OPTIONS"


def allow(release: Release) -> str:
    """The Allow header for this release: PUBLISH from Rel-15, where TS 24.379
    clause 9A gives it a use (functional alias management, SVC-OP-06)."""
    return ALLOW + (", PUBLISH, SUBSCRIBE"
                    if supports_procedure(release, "functional-alias") else "")

# Content types carried on MC signalling.
CT_MC_INFO = "application/vnd.3gpp.mcptt-info+xml"
CT_RESOURCE_LISTS = "application/resource-lists+xml"
CT_LOCATION_INFO = "application/vnd.3gpp.mcptt-location-info+xml"
CT_SDP = "application/sdp"

# Resource-Priority namespaces are NOT constants and are deliberately absent.
# TS 24.379 clauses 6.3.3.1.19 and 6.3.2.1.8.4 retrieve the namespace from the
# <resource-priority-namespace> element of <normal-resource-priority>,
# <emergency-resource-priority> or <imminent-peril-resource-priority> in the
# service configuration document (TS 24.484). The namespace VALUES are
# registered by IETF RFC 8101, not RFC 4412 -- 4412 defines only the header
# field. Two namespace literals previously sat here; they were deployment
# configuration wearing the costume of a protocol constant, and the core is the
# one place they could not correctly live (PLT-CONF-AUDIT CA-06).
#
# The session layer supplies the rendered value via `signal.detail`.

# RFC 5373 answer mode. Both values confirmed against TS 24.379 V17.15.0
# clauses 6.3.2.2.5.x and 10.1.1.4.1.
ANSWER_MODE_AUTO = "Auto"
ANSWER_MODE_MANUAL = "Manual"


class Status(Enum):
    TRYING = (100, "Trying")
    RINGING = (180, "Ringing")
    OK = (200, "OK")
    BAD_REQUEST = (400, "Bad Request")
    FORBIDDEN = (403, "Forbidden")
    NOT_FOUND = (404, "Not Found")
    NOT_ACCEPTABLE = (406, "Not Acceptable")
    REQUEST_TIMEOUT = (408, "Request Timeout")
    INTERVAL_TOO_BRIEF = (423, "Interval Too Brief")
    SESSION_INTERVAL_TOO_SMALL = (422, "Session Interval Too Small")
    TEMPORARILY_UNAVAILABLE = (480, "Temporarily Unavailable")
    CALL_DOES_NOT_EXIST = (481, "Call/Transaction Does Not Exist")
    LOOP_DETECTED = (482, "Loop Detected")
    BUSY_HERE = (486, "Busy Here")
    REQUEST_TERMINATED = (487, "Request Terminated")
    NOT_ACCEPTABLE_HERE = (488, "Not Acceptable Here")
    BAD_EVENT = (489, "Bad Event")
    REQUEST_PENDING = (491, "Request Pending")
    SERVER_ERROR = (500, "Server Internal Error")
    NOT_IMPLEMENTED = (501, "Not Implemented")
    SERVICE_UNAVAILABLE = (503, "Service Unavailable")

    @property
    def code(self) -> int:
        return self.value[0]

    @property
    def phrase(self) -> str:
        return self.value[1]


# Refusal reason code -> SIP status. A refusal must not be reported as a server
# error, and a server error must not be reported as a refusal: an operator
# reading a trace has to be able to tell a policy decision from a fault.
REASON_TO_STATUS: Mapping[str, Status] = {
    UNKNOWN_TARGET: Status.NOT_FOUND,
    NO_BINDING: Status.TEMPORARILY_UNAVAILABLE,
    NO_LOCATION_BINDING: Status.TEMPORARILY_UNAVAILABLE,
    NOT_AUTHORISED: Status.FORBIDDEN,
    CALL_TYPE_NOT_PERMITTED: Status.FORBIDDEN,
    CAPACITY_EXHAUSTED: Status.SERVICE_UNAVAILABLE,
    # 10.1.2: a call already at its maximum number of participants is refused
    # 486 with warning 122, the one refusal TS 24.379 pairs with 122.
    PARTICIPANT_LIMIT_EXCEEDED: Status.BUSY_HERE,
    RECORDING_UNAVAILABLE: Status.SERVICE_UNAVAILABLE,
    QOS_UNAVAILABLE: Status.SERVICE_UNAVAILABLE,
    RESOLVER_UNAVAILABLE: Status.SERVICE_UNAVAILABLE,
    # The gateway to a non-MC system could not be reached or produced no
    # route. A service-level condition, not a fault in the platform.
    GATEWAY_UNAVAILABLE: Status.SERVICE_UNAVAILABLE,
    # A partner system unreachable is a service condition; a partner asking for
    # something it was never granted is a refusal, and must not look like a fault.
    PARTNER_UNAVAILABLE: Status.SERVICE_UNAVAILABLE,
    PARTNER_NOT_PERMITTED: Status.FORBIDDEN,
    HOOK_TIMEOUT: Status.SERVER_ERROR,
    HOOK_ERROR: Status.SERVER_ERROR,
    HOOK_CONTRACT_VIOLATION: Status.SERVER_ERROR,
    # TS 24.379 17.4.2.2 steps 6, 7, 7A and 12: both are 403.
    ADHOC_PARTICIPANTS_UNDETERMINED: Status.FORBIDDEN,
    ADHOC_TOO_MANY_PARTICIPANTS: Status.FORBIDDEN,
    IDENTITY_NOT_AUTHENTICATED: Status.FORBIDDEN,
    # TS 24.379 10.1.1.3.1.1 step 2a and the other participating-function
    # procedures: no binding of the caller to an MCPTT ID is 404, warning 141.
    INITIATOR_NOT_SERVED: Status.NOT_FOUND,
    # TS 24.379 9A.2.2.2.3 steps 4A-4B and 9A.2.2.3.3 steps 4a, 5 and 6: 403.
    FUNCTIONAL_ALIAS_NOT_AUTHORISED: Status.FORBIDDEN,
    FUNCTIONAL_ALIAS_HELD: Status.FORBIDDEN,
    FUNCTIONAL_ALIAS_TAKE_OVER_NOT_ALLOWED: Status.FORBIDDEN,
    FUNCTIONAL_ALIAS_LOCATION_UNKNOWN: Status.FORBIDDEN,
    # TS 24.379 6.3.5.2 step 5b: 403.
    NOT_GROUP_MEMBER: Status.FORBIDDEN,
}

# Not covered by that setting: a resolver that cannot answer is a back-end
# failure with no warning text, and a bare 480 would present it as the callee
# being away (review of the 2026-10-16 settings).
KEEP_503 = frozenset({RESOLVER_UNAVAILABLE})

# The statuses a deployment may give the refusals mapped to 503 above
# (MCX_SERVICE_REFUSAL_STATUS, owner ruling 2026-10-16 on SIP-OP-10).
SERVICE_REFUSAL_STATUS: Mapping[int, Status] = {
    503: Status.SERVICE_UNAVAILABLE,
    480: Status.TEMPORARILY_UNAVAILABLE,
}

# TS 24.379 clause 4.4.1: the RFC 3261 warn-code is always 399 (miscellaneous
# warning). The 3-digit MC code is part of the quoted warn-text, not the
# warn-code -- codes below 300 are not legal RFC 3261 warn-codes at all.
WARNING_CODE_MISC = 399

# Warning texts, from TS 24.379 V17.15.0 table 4.4.2-2. Each entry is carried
# only because the specification's own description of that code matches what
# the platform reason code means. Nothing here is approximated: see
# REFUSALS_WITHOUT_WARNING_TEXT for the refusals that have no faithful code.
#
# Code 100 takes a <detailed reason>, which table 4.4.2-2 defines as one of
# "group definition", "access policy", "local policy", "user authorisation" or
# "pre-established session not supported", or a free text string. Two reasons
# below use two different specification-enumerated detailed reasons, which is
# exactly what that mechanism is for.
WARNING_TEXTS: Mapping[str, Tuple[int, str]] = {
    # "The participating function was unable to determine the called party
    # from the information received in the SIP request."
    UNKNOWN_TARGET: (145, "unable to determine called party"),
    NOT_AUTHORISED: (100, "function not allowed due to user authorisation"),
    CALL_TYPE_NOT_PERMITTED: (100, "function not allowed due to local policy"),
    # "The MCPTT service is not authorized between the local and the
    # interconnected system and is rejected in the local system."
    PARTNER_NOT_PERMITTED: (179,
                            "service not authorized with the interconnected system"),
    # Rel-18 onwards; texts from table 4.4.2-2 of V18.13.0 and V20.0.0, which
    # agree. "The MCPTT server can not determine the adhoc group participants
    # based on the input parameters." (Clause 17.4.2.2 step 7A spells it
    # "cant"; the table is followed.)
    ADHOC_PARTICIPANTS_UNDETERMINED: (187, "can't determine the adhoc group participants"),
    # "The maximum number of allowed adhoc group participants exceeded the
    # configured limit."
    ADHOC_TOO_MANY_PARTICIPANTS: (189,
                                  "maximum number of allowed adhoc group participants exceeded"),
    # "The group call has reached its maximum number of participants."
    PARTICIPANT_LIMIT_EXCEEDED: (122, "too many participants"),
    # "The participating function is unable to associate the public user
    # identity with an MCPTT ID." A caller outside the domains this
    # deployment serves is one it has no MCPTT ID for (RES-OP-11).
    INITIATOR_NOT_SERVED: (141, "user unknown to the participating function"),
    # Rel-20 onwards (V20.0.0 table 4.4.2-2 and 9A.2.2.2.3 step 4B): a
    # functional alias the user may not hold. Before Rel-20 the step is a
    # bare 403, and the phrase goes out without the code (reject()).
    FUNCTIONAL_ALIAS_NOT_AUTHORISED: (201, "user not authorized to change the "
                                           "functional alias status"),
    # "The MCPTT user is not authorised to join the group call because the
    # MCPTT user is not a member of the MCPTT group." 6.3.5.2 step 5b, every
    # release from Rel-13 (V13.19.0 and V17.15.0 tables agree).
    NOT_GROUP_MEMBER: (116, "user is not part of the MCPTT group"),
}

# Refusals that TS 24.379 table 4.4.2-2 has no code for, with the reason each
# was not mapped to a near neighbour. These emit the SIP status alone.
#
# The temptation is to reach for an adjacent code. Resist it: the eleven codes
# this table replaced were all plausible neighbours, and one of them (110)
# tells a conformant peer "user declined the call invitation" when what
# actually happened was a partner policy refusal. That is a worse outcome than
# a bare 403, because it is confidently wrong rather than merely terse.
#
# They still carry a Warning header, but a plain RFC 3261 one with no MC code.
# Table 4.4.2-1 defines the MC form with "=/", an ABNF INCREMENTAL ALTERNATIVE:
# it adds a permitted shape for warn-text, it does not replace RFC 3261's. A
# warn-text that does not begin with three digits therefore stays legal and
# cannot be mistaken for a code. It is what lets a trace tell a policy refusal
# from a fault when both are 503 (`capacity-exhausted`), without emitting a false
# code to buy it. That aim is the platform's own and stricter than PLT-PRI-008,
# which asks only that capacity exhaustion be distinguishable from authorisation
# failure. It holds at the platform's edge only: a proxy turns a lone 503 into
# a 500 and drops the Warning, which was accepted (PLT-VP-R1 SIP-OP-10).
LOCAL_WARNING_TEXTS: Mapping[str, str] = {
    IDENTITY_NOT_AUTHENTICATED: "asserted identity is not the authenticated one",
    NO_BINDING: "identity has no current holder",
    NO_LOCATION_BINDING: "location required for this identity",
    CAPACITY_EXHAUSTED: "maximum number of sessions reached",
    RECORDING_UNAVAILABLE: "recording unavailable",
    QOS_UNAVAILABLE: "requested quality of service unavailable",
    GATEWAY_UNAVAILABLE: "interworking gateway unavailable",
    PARTNER_UNAVAILABLE: "partner system unavailable",
    # 9A.2.2.3.3 steps 5 and 6 send a bare 403; these say which.
    FUNCTIONAL_ALIAS_HELD: "functional alias held by another user",
    FUNCTIONAL_ALIAS_TAKE_OVER_NOT_ALLOWED: "take-over of the functional alias not allowed",
    FUNCTIONAL_ALIAS_LOCATION_UNKNOWN: "no location to hold the functional alias at",
}

# The same two refusals of an ad hoc group call, when step 0 (authorisation,
# PLT-ICD-001 §5.0) refused it (TS 24.379 17.4.2.2 steps 4 and 5; PLT-VP-R1
# ADHOC-OP-05). Rel-18 onwards; texts from table 4.4.2-2 of V18.13.0 and
# V20.0.0, which agree. The steps spell 185 "user is not authorised"; the
# table is followed, as for 187.
#
# 185: "The MCPTT user identified by the MCPTT ID is not authorised to
# initiate the adhoc group call" -- authorise's `not-authorised`. 186: "The
# MCPTT system doesn't support the adhoc group call" -- only when the profile
# declares no ad hoc call type at all. A profile that has some, asked for an
# ad hoc call of a kind it lacks, does support ad hoc calls; that stays
# 100 "local policy", which is true (review of ADHOC-OP-05).
ADHOC_WARNING_TEXTS: Mapping[str, Tuple[int, str]] = {
    NOT_AUTHORISED: (185, "user not authorised to initiate the adhoc group call"),
    CALL_TYPE_NOT_PERMITTED: (186, "the MCPTT system do not support adhoc group call"),
}

# Step 3A (6.3.3.1.25): an ad hoc call may carry <adhoc-emergency-ind> or
# <imminentperil-ind>, not both.
INVALID_COMBINATION = (150, "invalid combinations of data received in MIME body")

# 10.1.1.4.1: the 200 OK to a group call that has more members than
# <on-network-max-participant-count> carries this; only that many take part
# (6.3.5.5). Table 4.4.2-2: "The group call has reached its maximum number of
# participants." (PLT-VP-R1 RES-OP-12)
TOO_MANY_PARTICIPANTS = WARNING_TEXTS[PARTICIPANT_LIMIT_EXCEEDED]

# Steps 3B and 3C answer with a body and skip steps 4 and 5, so no MC code
# goes with it: 185 would say the user may not start ad hoc calls at all,
# which a caller authorised for ordinary ones is not (review of ADHOC-OP-05).
# A plain RFC 3261 warn-text keeps the trace readable (see LOCAL_WARNING_TEXTS).
PRIORITY_ADHOC_REFUSED = "priority adhoc group call not authorised"

REFUSALS_WITHOUT_WARNING_TEXT: Mapping[str, str] = {
    # 141 ("user unknown to the participating function": it cannot associate
    # the public user identity with an MCPTT ID) is the nearest. Here the
    # identity is associated perfectly well; it is simply not the one this
    # connection authenticated. Table 4.4.2-2 of V18.13.0 has no such code.
    IDENTITY_NOT_AUTHENTICATED: "no code for an asserted identity the "
                                "connection did not authenticate",
    # 141 is the nearest, but it is the opposite direction: it means the
    # participating function could not associate a public user identity with
    # an MCPTT ID. `no-binding` means a known identity that nobody holds.
    NO_BINDING: "no code for a functional identity with no current holder",
    NO_LOCATION_BINDING: "no location-binding code in table 4.4.2-2",
    # 103, 122, 124 and 164 are all per-user or per-group maxima. The table
    # has no code for server admission capacity.
    CAPACITY_EXHAUSTED: "no code for server admission capacity",
    RECORDING_UNAVAILABLE: "no recording code in table 4.4.2-2",
    QOS_UNAVAILABLE: "no bearer/QoS code in table 4.4.2-2",
    # Table 4.4.2-2 reserves 301-350 for interworking and defers their meaning
    # to TS 29.379. That document has now been read (PLT-CONF-AUDIT CA-09) and
    # its table 4.2.2-1 allocates three codes and no more:
    #
    #   300  LMR end-to-end encryption not permitted
    #   301  LMR end-to-end encryption required
    #   302  LMR codec required
    #
    # All three are about Land Mobile Radio media security and codec
    # negotiation at an IWF. None of them means the interworking gateway is
    # unreachable, which is what `gateway-unavailable` reports, so this
    # refusal still has no faithful code. The deferral is now a finding.
    GATEWAY_UNAVAILABLE: "TS 29.379 table 4.2.2-1 allocates only 300-302, all "
                         "LMR media security; none means gateway unreachable",
    # 179 and 180 are authorisation, not reachability.
    PARTNER_UNAVAILABLE: "179/180 mean not authorised, not unreachable",
    RESOLVER_UNAVAILABLE: "an internal condition, not an MC protocol one",
}


def _host_of(uri: str) -> str:
    """The host part of a SIP URI, for the Warning header's warn-agent.

    TS 24.379 clause 4.4.1 requires the host name of the MCPTT server there.

    A server is normally reachable at a public service identity (clause 4.2),
    which has NO userinfo part: `sip:ps.mcptt.example`. Splitting on "@" and
    then on ":" yields the scheme for those, so a first attempt at this
    returned "sip" for every realistic deployment URI and was masked by tests
    that all used a `user@host` form.
    """
    text = uri.strip().lstrip("<")
    text = text.split(">")[0]                     # <sip:a@b>;tag=1
    if "@" in text:
        hostport = text.rsplit("@", 1)[1]
    else:
        _, _, hostport = text.partition(":")      # drop the scheme
        hostport = hostport or text
    hostport = hostport.split(";")[0].split(",")[0]
    if hostport.startswith("["):                  # IPv6 reference
        return hostport.split("]")[0] + "]"
    return hostport.split(":")[0] or uri


class SipError(Exception):
    """A message could not be parsed or rendered."""


# --------------------------------------------------------------------------
# Message model
# --------------------------------------------------------------------------


class Headers:
    """Case-insensitive, order-preserving, multi-valued header container."""

    def __init__(self, initial: Optional[Iterable[Tuple[str, str]]] = None) -> None:
        self._items: List[Tuple[str, str]] = list(initial or [])

    def add(self, name: str, value: str) -> "Headers":
        self._items.append((name, value))
        return self

    def set(self, name: str, value: str) -> "Headers":
        lowered = name.lower()
        self._items = [(n, v) for n, v in self._items if n.lower() != lowered]
        return self.add(name, value)

    def get(self, name: str) -> Optional[str]:
        lowered = name.lower()
        for n, v in self._items:
            if n.lower() == lowered:
                return v
        return None

    def get_all(self, name: str) -> Tuple[str, ...]:
        lowered = name.lower()
        return tuple(v for n, v in self._items if n.lower() == lowered)

    def has(self, name: str) -> bool:
        return self.get(name) is not None

    def items(self) -> Tuple[Tuple[str, str], ...]:
        return tuple(self._items)

    def __contains__(self, name: str) -> bool:
        return self.has(name)

    def __repr__(self) -> str:
        return f"Headers({self._items!r})"


@dataclass(frozen=True)
class Request:
    method: str
    uri: str
    headers: Headers = field(default_factory=Headers)
    body: str = ""

    def render(self) -> str:
        lines = [f"{self.method} {self.uri} SIP/2.0"]
        lines += [f"{n}: {v}" for n, v in self.headers.items()]
        lines.append(f"Content-Length: {len(self.body.encode('utf-8'))}")
        return "\r\n".join(lines) + "\r\n\r\n" + self.body


@dataclass(frozen=True)
class Response:
    status: Status
    headers: Headers = field(default_factory=Headers)
    body: str = ""

    def render(self) -> str:
        lines = [f"SIP/2.0 {self.status.code} {self.status.phrase}"]
        lines += [f"{n}: {v}" for n, v in self.headers.items()]
        lines.append(f"Content-Length: {len(self.body.encode('utf-8'))}")
        return "\r\n".join(lines) + "\r\n\r\n" + self.body


@dataclass(frozen=True)
class ReceivedResponse:
    """A response as it arrived. Any status code is representable, unlike
    `Response`, which only carries the codes this platform originates."""

    code: int
    reason: str
    headers: Headers = field(default_factory=Headers)
    body: str = ""


_COMPACT = {"v": "Via", "f": "From", "t": "To", "i": "Call-ID", "m": "Contact",
            "c": "Content-Type", "l": "Content-Length", "k": "Supported",
            "x": "Session-Expires",                    # RFC 4028 section 4
            "o": "Event", "u": "Allow-Events"}         # RFC 6665 8.2.1
_REQUEST_LINE = re.compile(r"^([A-Za-z]+) (\S+) SIP/2\.0$")
# [0-9], not \d: \d takes any script's digits, which int() reads (SIP-OP-19).
_STATUS_LINE = re.compile(r"^SIP/2\.0 ([0-9]{3})(?: (.*))?$")


def split_frame(data: bytes) -> Optional[Tuple[bytes, int]]:
    """Return (head, total_length) once `data` holds a complete message, else
    None. Framing is by Content-Length (RFC 3261 §18.3): required on a stream
    transport, so an absent one is taken as zero."""
    end = data.find(b"\r\n\r\n")
    if end < 0:
        return None
    head = data[:end]
    length = 0
    for line in head.decode("utf-8", "replace").split("\r\n")[1:]:
        name, _, value = line.partition(":")
        name = name.strip(" \t")
        if _COMPACT.get(name.lower(), name).lower() == "content-length":
            value = value.strip(" \t")
            # ASCII digits only: int() would also take Unicode digits and "_".
            if not (value.isascii() and value.isdigit()):
                raise SipError("malformed Content-Length")
            length = int(value)
    total = end + 4 + length
    return (head, total) if len(data) >= total else None


def parse_message(data: bytes):
    """Parse one complete framed message into a Request or ReceivedResponse.

    Compact header forms are expanded. Continuation lines are unfolded. Raises
    SipError for anything that is not a SIP message; whether a well-formed
    message is *acceptable* is `InboundGuard`'s question, not this one's.
    """
    frame = split_frame(data)
    if frame is None:
        raise SipError("incomplete message")
    head_bytes, total = frame
    try:
        head = head_bytes.decode("utf-8")
        body = data[len(head_bytes) + 4:total].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SipError(f"message is not UTF-8: {exc}") from exc
    lines: List[str] = []
    for raw in head.split("\r\n"):
        if raw[:1] in (" ", "\t") and lines:
            lines[-1] += " " + raw.strip(" \t")
        else:
            lines.append(raw)
    start, header_lines = lines[0], lines[1:]
    headers = Headers()
    for line in header_lines:
        name, sep, value = line.partition(":")
        if not sep or not name.strip(" \t"):
            # Clipped: the line is the sender's, and the error is logged.
            raise SipError(f"malformed header line {clip(line)}")
        name = name.strip(" \t")
        # RFC 3261 LWS is spaces and tabs; str.strip() would also take
        # Unicode whitespace (U+0085, U+00A0) off a value.
        headers.add(_COMPACT.get(name.lower(), name), value.strip(" \t"))
    headers = Headers([(n, v) for n, v in headers.items()
                       if n.lower() != "content-length"])
    m = _STATUS_LINE.match(start)
    if m:
        return ReceivedResponse(int(m.group(1)), m.group(2) or "", headers, body)
    m = _REQUEST_LINE.match(start)
    if m:
        return Request(m.group(1), m.group(2), headers, body)
    raise SipError(f"malformed start line {clip(start)}")


# --------------------------------------------------------------------------
# Registration (PLT-SIG-002)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Registration:
    service_id: str
    contact: str
    expires_at_ms: int
    instance_id: Optional[str] = None


class RegistrationStore:
    """Third-party registration state per MC service ID.

    Expiry is evaluated against the injected clock, never a wall clock, so a
    test can age a registration without sleeping.
    """

    def __init__(self, clock=lambda: 0) -> None:
        self._now = clock
        self._by_id: Dict[str, Registration] = {}

    def register(self, service_id: str, contact: str, expires_ms: int,
                 instance_id: Optional[str] = None) -> Registration:
        reg = Registration(service_id=service_id, contact=contact,
                           expires_at_ms=self._now() + expires_ms,
                           instance_id=instance_id)
        self._by_id[service_id] = reg
        return reg

    def deregister(self, service_id: str) -> None:
        self._by_id.pop(service_id, None)

    def get(self, service_id: str) -> Optional[Registration]:
        reg = self._by_id.get(service_id)
        if reg is None:
            return None
        if reg.expires_at_ms <= self._now():
            # Expired registrations are not returned, and are not silently
            # renewed by being looked up.
            return None
        return reg

    def is_registered(self, service_id: str) -> bool:
        return self.get(service_id) is not None

    def registered_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(i for i in self._by_id if self.is_registered(i)))


# --------------------------------------------------------------------------
# Inbound guard (PLT-SIG-004)
# --------------------------------------------------------------------------

_REQUIRED_HEADERS = ("Via", "From", "To", "Call-ID", "CSeq")
_CSEQ = re.compile(r"^[0-9]+\s+[A-Z]+$")          # [0-9], not \d (SIP-OP-19)


# RES-OP-15: a new INVITE's Call-ID becomes its session's correlation id in
# the audit trail and in every log line about it. RFC 3261 sets no length, so
# the guard does: a Call-ID longer than this, or not of RFC 3261 25.1's
# `callid = word [ "@" word ]`, is answered 400 before anything uses it.
# Clients use a random part and a host (a UUID@host is under 100 bytes).
CALL_ID_MAX = 256
_WORD = r"[A-Za-z0-9\-.!%*_+`'~()<>:\\\"/\[\]?{}]+"
_CALL_ID = re.compile(rf"{_WORD}(?:@{_WORD})?")


def clip(text: str, limit: int = 80) -> str:
    """A peer's text for an error message or a log line: its repr, cut to
    `limit` characters, with its length when cut (RES-OP-15 review). Error
    messages built from what a peer sent end up in the log and the audit."""
    shown = repr(text[:limit])
    return shown if len(text) <= limit else f"{shown}... ({len(text)} characters)"


def valid_call_id(value: Optional[str]) -> bool:
    """RFC 3261 25.1 `callid`, at most CALL_ID_MAX characters."""
    return value is not None and len(value) <= CALL_ID_MAX and \
        _CALL_ID.fullmatch(value) is not None


class InboundGuard:
    """Rejects malformed, replayed and unknown-session requests.

    Replay detection is by (Call-ID, CSeq), which is where SIP puts transaction
    identity. The window is bounded so the store cannot grow without limit.
    """

    def __init__(self, window: int = 4096) -> None:
        self._seen: Dict[Tuple[str, str], None] = {}
        self._window = window

    def check(self, request: Request,
              known_sessions: Sequence[str] = ()) -> Optional[Response]:
        """Return a rejection Response, or None if the request may proceed."""
        malformed = self._malformed(request)
        if malformed is not None:
            return _reject(Status.BAD_REQUEST, request, detail=malformed)

        call_id = request.headers.get("Call-ID") or ""
        cseq = request.headers.get("CSeq") or ""
        key = (call_id, cseq)

        # In-dialog requests must name a session that exists.
        if request.method in ("BYE", "ACK", "INFO", "UPDATE") and \
                call_id not in known_sessions:
            return _reject(Status.CALL_DOES_NOT_EXIST, request,
                           detail="no such session")

        if key in self._seen:
            return _reject(Status.LOOP_DETECTED, request,
                           detail="retransmission outside transaction")
        self._remember(key)
        return None

    def _malformed(self, request: Request) -> Optional[str]:
        if not request.method or not request.method.isupper():
            return "missing or invalid method"
        if not request.uri:
            return "missing request URI"
        for name in _REQUIRED_HEADERS:
            if not request.headers.has(name):
                return f"missing {name} header"
        cseq = request.headers.get("CSeq") or ""
        if not _CSEQ.match(cseq.strip()):
            return "malformed CSeq"
        if len(request.headers.get_all("Call-ID")) != 1:
            # Single-valued (RFC 3261 20.8): two would let two readers see two
            # calls, and the second would sit unchecked in transaction memory.
            return "Call-ID header not exactly once"
        call_id = request.headers.get("Call-ID")
        if call_id is not None and len(call_id) > CALL_ID_MAX:
            return f"Call-ID longer than {CALL_ID_MAX} characters"
        if not valid_call_id(call_id):
            return "malformed Call-ID"
        if request.body and not request.headers.has("Content-Type"):
            return "body present without Content-Type"
        return None

    def _remember(self, key: Tuple[str, str]) -> None:
        if len(self._seen) >= self._window:
            # Bounded: drop the oldest. Python dicts preserve insertion order.
            self._seen.pop(next(iter(self._seen)))
        self._seen[key] = None


def _reject(status: Status, request: Request, detail: str = "") -> Response:
    headers = Headers()
    for name in ("Via", "From", "To", "Call-ID", "CSeq"):
        value = request.headers.get(name)
        if value is not None:
            headers.add(name, value)
    if detail:
        # Same TS 24.379 clause 4.4.1 shape as Adapter.reject. The warn-agent
        # was the literal "mcx" here too; the guard has no Adapter to ask, so
        # it takes the host from the request it is refusing.
        host = _host_of(request.headers.get("To") or request.uri or "")
        headers.add("Warning", f'{WARNING_CODE_MISC} {host} "{detail}"')
    return Response(status=status, headers=headers)


# --------------------------------------------------------------------------
# Adapter
# --------------------------------------------------------------------------

_MEDIA_TAGS = {
    MediaKind.VOICE: FEATURE_TAG_PTT,
    MediaKind.VIDEO: FEATURE_TAG_VIDEO,
    MediaKind.DATA: FEATURE_TAG_DATA,
}


@dataclass(frozen=True)
class DialogContext:
    """What the adapter needs to address a message. Supplied by the session
    layer; the adapter invents no identity of its own."""

    call_id: str
    local_uri: str
    cseq: int = 1
    sdp: str = ""
    # The MCPTT session identity (TS 24.379 clause 4.5), when the session
    # has one; the Contact carries it.
    session_uri: str = ""
    # RFC 4028 on an INVITE: the interval asked for (0: none), and the Min-SE
    # a 422 imposed (0: none yet).
    session_expires: int = 0
    min_se: int = 0


class Adapter:
    """Renders abstract signals into TS 24.379 messages and parses inbound ones."""

    def __init__(self, local_uri: str, release: Release,
                 call_types: Sequence[Any] = (), *,
                 service_refusal_status: int = 503,
                 read_location: bool = True,
                 group_call_types: Optional[Mapping[str, str]] = None) -> None:
        """`call_types` are the loaded profile's; the adapter reads only each
        one's `id` and `mc_signature` (PLT-ICD-001 2.6) and learns nothing
        else about the profile.

        `service_refusal_status` (MCX_SERVICE_REFUSAL_STATUS, SIP-OP-10) is the
        status of every refusal REASON_TO_STATUS maps to 503 but those in
        KEEP_503: 503, or 480.
        `read_location` (MCX_LOCATION_REPORTS, ADHOC-OP-03): False ignores
        the client's location report. The defaults are the decided behaviour;
        the service always passes the deployment's stated values.
        `group_call_types` (PRF-OP-01): group id -> the call type a call to
        that group is, from the network profile's groups, when the call
        carries that call type's signature exactly."""
        if service_refusal_status not in SERVICE_REFUSAL_STATUS:
            raise ValueError(f"service refusal status {service_refusal_status!r} "
                             f"is not one of {sorted(SERVICE_REFUSAL_STATUS)}")
        self._service_status = SERVICE_REFUSAL_STATUS[service_refusal_status]
        self._read_location = read_location is True
        self.reads_location = self._read_location
        self._local = local_uri
        self._host = _host_of(local_uri)
        self._by_signature: Dict[mcinfo.Signature, str] = {}
        self._signature_of: Dict[str, mcinfo.Signature] = {}
        for ct in call_types:
            sig = getattr(ct, "mc_signature", None)
            if sig is not None:
                # A group-selected call type shares its signature with
                # another (PRF-OP-01): never chosen by the signature alone.
                if not getattr(ct, "group_selected", False):
                    self._by_signature[sig] = ct.id
                self._signature_of[ct.id] = sig
        self._group_call_types: Dict[str, str] = dict(group_call_types or {})
        # Step 5 (186) is for a system with no ad hoc call type at all.
        self._any_adhoc = any(sig.session_type == "adhoc" for sig in self._by_signature)
        # PLT-REL-009. Table 4.4.2-2 grew from 44 codes in Rel-13 to 95 in
        # Rel-20, and one of the three this platform emits (179) does not
        # exist before Rel-17 (PLT-CONF-AUDIT CA-12).
        self._release = release

    # -- rendering -------------------------------------------------------

    def render(self, signal: Signal, context: DialogContext,
               request: Optional[SessionRequest] = None):
        if signal.type is SignalType.INVITE:
            return self._invite(signal, context, request)
        if signal.type is SignalType.RESPONSE_OK:
            return Response(status=Status.OK, headers=self._common(context))
        if signal.type is SignalType.RESPONSE_REJECT:
            return self.reject(str(signal.detail.get("reason_code", "")), context)
        if signal.type is SignalType.BYE:
            return Request(method="BYE", uri=signal.target or "",
                           headers=self._common(context, cseq_method="BYE"))
        return None    # QoS and recording signals are not SIP

    def _invite(self, signal: Signal, context: DialogContext,
                request: Optional[SessionRequest]) -> Request:
        headers = self._common(context, cseq_method="INVITE")
        media = tuple(request.media) if request else (MediaKind.VOICE,)
        tags = self._feature_tags(media)

        icsi = f'{FEATURE_TAG_ICSI_REF}="{_pct(MCPTT_ICSI)}"'
        headers.set("Contact", self.focus_contact(context.session_uri, media))
        # 6.3.3.1.2 items 6-7: Supported: timer, and a Session-Expires with
        # the refresher left to the callee to choose (RFC 4028 section 7.1).
        # UPDATE is allowed so the callee can refresh without an offer.
        headers.set("Supported", OPTION_TIMER)
        headers.set("Allow", ALLOW)
        if context.session_expires:
            headers.set("Session-Expires", str(context.session_expires))
        if context.min_se:
            headers.set("Min-SE", str(context.min_se))         # RFC 4028 7.4

        # TS 24.379 requires TWO Accept-Contact header fields, not one
        # combined value: one carrying the service feature tag and one
        # carrying the ICSI reference, each with "require" and "explicit"
        # (IETF RFC 3841). Omitting the ICSI field is what the single
        # combined header used to do (PLT-CONF-AUDIT CA-06).
        headers.add("Accept-Contact", f"*;{';'.join(tags)};require;explicit")
        headers.add("Accept-Contact", f"*;{icsi};require;explicit")

        # TS 24.379 clause 11.1.1.2.1.1 step 14 makes these MUTUALLY EXCLUSIVE:
        #
        #   force of automatic commencement requested -> Priv-Answer-Mode: Auto
        #   automatic commencement, not forced        -> Answer-Mode: Auto
        #   manual commencement                       -> Answer-Mode: Manual
        #
        # This used to emit Answer-Mode AND Priv-Answer-Mode together for
        # auto-answer, and Priv-Answer-Mode: Manual otherwise, which is not a
        # value that branch produces at all (PLT-CONF-AUDIT CA-06).
        #
        # `auto_answer` from the session decision means the call establishes
        # without callee action (VP1-CC-004), so it is the FORCED branch:
        # Answer-Mode: Auto alone only takes effect if the invited client's own
        # settings already say auto-answer (clause 6.3.2.2.5.2), which would
        # leave establishment at the mercy of a handset setting.
        #
        # SIP-OP-07: the platform therefore cannot currently express the
        # non-forced automatic branch. Adding it is a profile schema change and
        # an ICD revision, not an audit correction.
        #
        # SIP-OP-08: clause 11.1.1.2.2.1 (private call over a PRE-ESTABLISHED
        # session) spells the same value "Automatic", in Rel-17 and Rel-20
        # alike, where clause 11.1.1.2.1.1 spells it "Auto". A receiver must
        # accept both. This renderer emits "Auto" and does not implement the
        # pre-established path at all.
        if signal.detail.get("auto_answer"):
            headers.set("Priv-Answer-Mode", ANSWER_MODE_AUTO)
        else:
            headers.set("Answer-Mode", ANSWER_MODE_MANUAL)

        sig = self._signature_of.get(request.call_type) if request else None
        if request is not None:
            # TS 24.379 6.3.2.2.6.2 item 7: an INVITE towards a terminating
            # MCPTT client asserts the PARTICIPATING FUNCTION's identity, and
            # the caller travels in <mcptt-calling-user-id> (CA-20). Where no
            # MCPTT body is sent -- a gateway or partner leg, a call type
            # declared with no signature -- there is nowhere else for the
            # caller to travel, so the caller is asserted as before. The
            # first version of this fix changed both (found by review).
            headers.set("P-Asserted-Identity",
                        f"<{self._local}>" if sig is not None else f"<{request.initiator}>")
            priority = signal.detail.get("resource_priority")
            if priority:
                headers.set("Resource-Priority", str(priority))

        if sig is None:
            # No MCPTT representation (a gateway leg, MCData): SDP alone.
            headers.set("Content-Type", CT_SDP)
            return Request(method="INVITE", uri=signal.target or "",
                           headers=headers, body=context.sdp)
        # 6.3.2.2.3 item 8 and 6.3.2.2.9: the MCPTT info body goes to the
        # terminating client. Without it the callee cannot tell which group
        # is calling or who is (10.1.1.4.1.1 item 4, CA-20).
        info = mcinfo.McInfo(
            session_type=sig.session_type,
            request_uri=signal.target,
            calling_user_id=request.initiator,
            calling_group_id=signal.detail.get("group_id"),
            # 17.4.2.1.1 item 4c.
            participant_criteria=signal.detail.get("participant_criteria"),
            emergency=True if sig.emergency else None,
            imminent_peril=True if sig.imminent_peril else None,
            broadcast=True if sig.broadcast else None)
        ctype, body = mcinfo.build_multipart((
            mcinfo.Part(CT_SDP, context.sdp),
            mcinfo.Part(CT_MC_INFO, mcinfo.render(info, self._release))))
        headers.set("Content-Type", ctype)
        return Request(method="INVITE", uri=signal.target or "",
                       headers=headers, body=body)

    def reject(self, reason_code: str, context: DialogContext,
               invite: Optional[Request] = None,
               authorisation: bool = False) -> Response:
        """Refuse, with the Warning header shape of TS 24.379 clause 4.4.1.

            Warning: 399 mcptt.example "100 function not allowed due to ..."

        399 is the RFC 3261 warn-code, the host name is this server's, and the
        MC 3-digit code lives inside the quoted warn-text. A refusal with no
        specification-defined code carries no Warning at all.

        `invite` is the refused INVITE and `authorisation` says step 0
        refused it. Such a refusal of an ad hoc call is answered as TS 24.379
        17.4.2.2 orders it (ADHOC-OP-05): steps 3B and 3C when it asked for
        emergency or imminentperil-ind (a body, no MC code), else step 4
        (185) or step 5 (186).
        """
        status = REASON_TO_STATUS.get(reason_code, Status.SERVER_ERROR)
        if status is Status.SERVICE_UNAVAILABLE and reason_code not in KEEP_503:
            status = self._service_status
        headers = self._common(context)
        info = self._adhoc_info(invite) if authorisation else None
        if info is not None and (info.emergency or info.imminent_peril) and \
                reason_code in ADHOC_WARNING_TEXTS:
            # Steps 3B (6.3.3.1.13.11) and 3C (6.3.3.1.13.12): not authorised
            # for that kind of ad hoc call -- including when the profile has
            # no such call type, so nobody is -- and told so in the body, so
            # the client does not believe itself in that state.
            refused = mcinfo.McInfo(
                emergency=False if info.emergency else None,
                imminent_peril=False if info.imminent_peril else None)
            headers.add("Warning", f'{WARNING_CODE_MISC} {self._host} '
                                   f'"{PRIORITY_ADHOC_REFUSED}"')
            headers.set("Content-Type", CT_MC_INFO)
            return Response(status=status, headers=headers,
                            body=mcinfo.render(refused, self._release, adhoc=True))
        warning = WARNING_TEXTS.get(reason_code)
        if info is not None and (reason_code != CALL_TYPE_NOT_PERMITTED
                                 or not self._any_adhoc):
            warning = ADHOC_WARNING_TEXTS.get(reason_code, warning)
        if warning is not None:
            code, text = warning
            if supports_sip_warning(self._release, code):
                headers.add("Warning",
                            f'{WARNING_CODE_MISC} {self._host} "{code} {text}"')
            else:
                # The release this deployment speaks has no such code, so the
                # explanatory phrase goes out without it. Emitting the number
                # anyway would be meaningless to a conformant peer of that
                # release; raising would turn a policy refusal into a fault,
                # which is the one thing the refusal path must never do.
                headers.add("Warning",
                            f'{WARNING_CODE_MISC} {self._host} "{text}"')
        else:
            local = LOCAL_WARNING_TEXTS.get(reason_code)
            if local is not None:
                headers.add("Warning",
                            f'{WARNING_CODE_MISC} {self._host} "{local}"')
        return Response(status=status, headers=headers)

    def invalid_adhoc_indications(self, invite: Request) -> bool:
        """17.4.2.2 step 3A (6.3.3.1.25): an ad hoc INVITE carrying
        <imminentperil-ind> together with <adhoc-emergency-ind>, whatever
        their values (encrypted counts as carried)."""
        info = self._adhoc_info(invite)
        if info is None:
            return False
        imminent = info.imminent_peril is not None or \
            "imminentperil-ind" in info.encrypted
        return imminent and info.emergency is not None

    def too_many_participants(self) -> str:
        """The Warning header value for a group call over its limit."""
        code, text = TOO_MANY_PARTICIPANTS
        return f'{WARNING_CODE_MISC} {self._host} "{code} {text}"'

    def reject_invalid_combination(self, context: DialogContext) -> Response:
        code, text = INVALID_COMBINATION
        headers = self._common(context)
        headers.add("Warning", f'{WARNING_CODE_MISC} {self._host} "{code} {text}"')
        return Response(status=Status.FORBIDDEN, headers=headers)

    def _adhoc_info(self, invite: Optional[Request]) -> Optional["mcinfo.McInfo"]:
        """The MCPTT info of `invite` when it asks for an ad hoc group call
        this release understands, else None. The INVITE was parsed once
        already, successfully; a failure here only means no ad hoc refusal."""
        if invite is None or not supports_session_type(self._release, "adhoc"):
            return None
        try:
            raw = mcinfo.mcinfo_of(invite.headers.get("Content-Type") or "",
                                   invite.body)
            info = mcinfo.parse(raw) if raw is not None else None
        except mcinfo.McInfoError:
            return None
        return info if info is not None and info.session_type == "adhoc" else None

    def focus_contact(self, session_uri: str,
                      media: Sequence[MediaKind] = (MediaKind.VOICE,)) -> str:
        """The Contact the platform puts on every dialog it creates or
        answers as the MCPTT server: the MCPTT session identity (clause 4.5;
        the server's own URI where no session has one), the service feature
        tag, the ICSI reference and `isfocus` (6.3.3.1.2 item 1 on INVITEs to
        callees; 6.3.2.1.5.1 item 1, 6.3.3.2.3.1 item 4 on provisional
        responses; 6.3.2.1.5.2 item 3, 6.3.3.2.3.2 items 5-6 on the 200 OK).
        It used to be the bare server URI on responses and lack `isfocus`
        everywhere (PLT-CONF-AUDIT CA-20b)."""
        icsi = f'{FEATURE_TAG_ICSI_REF}="{_pct(MCPTT_ICSI)}"'
        tags = ";".join(self._feature_tags(media))
        return f"<{session_uri or self._local}>;{tags};{icsi};{FEATURE_TAG_ISFOCUS}"

    def _feature_tags(self, media: Sequence[MediaKind]) -> Tuple[str, ...]:
        tags = []
        for kind in media:
            tag = _MEDIA_TAGS.get(kind)
            if tag and tag not in tags:
                tags.append(tag)
        return tuple(tags) or (FEATURE_TAG_PTT,)

    def _common(self, context: DialogContext,
                cseq_method: str = "INVITE") -> Headers:
        return Headers([
            ("Via", f"SIP/2.0/TLS {_host(self._local)};branch=z9hG4bK{context.call_id}"),
            ("From", f"<{context.local_uri}>;tag={context.call_id}-l"),
            ("To", f"<{self._local}>"),
            ("Call-ID", context.call_id),
            ("CSeq", f"{context.cseq} {cseq_method}"),
            ("Max-Forwards", "70"),
        ])

    # -- parsing ---------------------------------------------------------

    def parse_invite(self, message: Request) -> SessionRequest:
        """Build a SessionRequest from an inbound INVITE.

        The call type is the profile call type that declares the signature
        of the MCPTT info body (TS 24.379 annex F.1; PLT-ICD-001 2.6), or ""
        when none does, the body is absent, or the configured release has no
        such session type -- and "" is left for the session policy to refuse.
        Nothing is inferred. The target is <mcptt-request-uri> (10.1.1.2.1.1
        item 14b for a group, 11.1.1.2.1.1 for a user); the Request-URI of a
        conformant INVITE is the participating function's own identity.

        A body that is present and malformed raises SipError: a client that
        sent one is broken, and refusing it is VP1-SIG-004's business.
        """
        if message.method != "INVITE":
            raise SipError(f"expected INVITE, found {message.method}")

        initiator = _asserted_identity(message.headers.get_all("P-Asserted-Identity")) \
            or _uri(message.headers.get("From") or "")
        target = _uri(message.uri)
        if not initiator or not target:
            raise SipError("INVITE lacks a usable initiator or target")

        media = self._media_from_offer(message)
        content_type = message.headers.get("Content-Type") or ""
        try:
            raw = mcinfo.mcinfo_of(content_type, message.body)
            info = mcinfo.parse(raw) if raw is not None else mcinfo.McInfo()
            # Clause 17 exists from Rel-18 (core/release.py); before it an
            # "adhoc" session type is just one no call type can declare.
            adhoc = info.session_type == "adhoc" and \
                supports_session_type(self._release, "adhoc")
            # TS 24.379 17.2.2.1.1 item 11: an ad hoc caller may list the
            # users to call as an RFC 5366 URI list. Read for ad hoc calls
            # only: other INVITEs may carry resource lists for other reasons
            # (clause 4.8), and are none of this code's business.
            listed = mcinfo.participants_of(content_type, message.body) \
                if adhoc else None
        except mcinfo.McInfoError as exc:
            raise SipError(f"MCPTT info body: {exc}") from None
        sig = info.signature()
        call_type = ""
        to = _uri(info.request_uri) if info.request_uri else target
        if sig is not None and supports_session_type(self._release, sig.session_type):
            call_type = self._by_signature.get(sig, "")
            # PRF-OP-01: the target group's call type, when the call carries
            # its signature exactly; any other call to the group (an
            # emergency one, say) is what its signature says.
            chosen = self._group_call_types.get(to)
            if chosen is not None and self._signature_of.get(chosen) == sig:
                call_type = chosen

        attributes = {}
        answer_mode = message.headers.get("Answer-Mode")
        if answer_mode:
            attributes["sip.answer_mode"] = answer_mode
        resource_priority = message.headers.get("Resource-Priority")
        if resource_priority:
            # Advisory only: IF-PRI decides. Recorded so a trace shows what the
            # client asked for alongside what the platform decided.
            attributes["sip.resource_priority"] = resource_priority

        return SessionRequest(
            request_id=message.headers.get("Call-ID") or "",
            initiator=initiator,
            target=to,
            call_type=call_type,
            media=media,
            # TS 24.379 has no element for either. The profile's declaration
            # of the call type supplies both (profiles/common/tables.py).
            application=None,
            urgency=None,
            # 17.2.2.1.1 item 14a (and 10.1.1.2.1.1 for other group calls):
            # the client's location report, when it sent one. The serving
            # cell only; what the cell means is the profile's (section 2.8),
            # applied by the session layer.
            location=_location(content_type, message.body) if self._read_location
            else None,
            attributes=attributes,
            # Clause 17: an ad hoc call's members are listed or described,
            # never a group the core already knows (PLT-ICD-001 section 3.5).
            adhoc=adhoc,
            adhoc_alert_group=bool(adhoc and info.adhoc_alert_group),
            participants=tuple(_uri(u) for u in listed or ()) if adhoc else (),
            participant_criteria=info.participant_criteria if adhoc else None,
        )

    def _media_from_offer(self, message: Request) -> Tuple[MediaKind, ...]:
        try:
            sdp = mcinfo.sdp_of(message.headers.get("Content-Type") or "",
                                message.body)
        except mcinfo.McInfoError as exc:
            raise SipError(str(exc)) from None
        kinds: List[MediaKind] = []
        for line in sdp.splitlines():
            if not line.startswith("m="):
                continue
            fields = line[2:].split()
            kind = fields[0] if fields else ""
            # TS 24.380 (V20.0.0 table and example "m=application 20032 udp
            # MCPTT"): media "application", proto "udp", fmt "MCPTT" is the
            # floor control channel of a voice call, not data media. Every
            # conformant MCPTT offer carries it; counting it as DATA made
            # every real voice call look like voice plus data (CA-20).
            if kind == "application" and fields[-1:] == ["MCPTT"]:
                continue
            mapped = {"audio": MediaKind.VOICE, "video": MediaKind.VIDEO,
                      "application": MediaKind.DATA}.get(kind)
            if mapped and mapped not in kinds:
                kinds.append(mapped)
        return tuple(kinds)


# --------------------------------------------------------------------------
# SDP (minimal — negotiation only, no media handling)
# --------------------------------------------------------------------------


def build_offer(codecs: Sequence[Tuple[int, str]], port: int = 49170,
                address: str = "0.0.0.0") -> str:
    """Build an audio offer. `codecs` is (payload type, rtpmap) pairs."""
    if not codecs:
        raise SipError("an offer must contain at least one codec")
    payloads = " ".join(str(pt) for pt, _ in codecs)
    lines = [
        "v=0",
        f"o=- 0 0 IN IP4 {address}",
        "s=-",
        f"c=IN IP4 {address}",
        "t=0 0",
        f"m=audio {port} RTP/AVP {payloads}",
    ]
    lines += [f"a=rtpmap:{pt} {name}" for pt, name in codecs]
    return "\r\n".join(lines) + "\r\n"


# --------------------------------------------------------------------------
# SDP endpoint description (for media anchoring)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SdpInfo:
    """Where a party wants media sent, and what it offers."""

    address: str
    audio_port: int
    payload_types: Tuple[int, ...]
    floor_port: Optional[int] = None     # m=application ... MCPTT, if present


def parse_sdp(body: str) -> SdpInfo:
    """Extract the audio and floor-control endpoints from an SDP body.

    The body may be a multipart part or carry trailing non-SDP text, so only
    lines that are recognisably SDP are read. Raises SipError when there is no
    usable audio media line or no connection address.
    """
    session_addr: Optional[str] = None
    audio: Optional[Tuple[int, Tuple[int, ...]]] = None
    audio_addr: Optional[str] = None
    floor_port: Optional[int] = None
    current: Optional[str] = None
    # The audio line is the first usable one, the same line core/codec.py
    # reads the codec from; its c= is the one that counts (review of
    # MED-OP-01: a malformed or second audio line must not lend its address).
    in_audio = False
    for raw in body.splitlines():
        line = raw.strip()
        if line.startswith("m="):
            parts = line[2:].split()
            current = parts[0] if parts else None
            in_audio = False
            # ASCII digits only: str.isdigit takes characters like "²" that
            # int() refuses.
            if audio is None and codec_mod.is_audio_line(parts):
                in_audio = True
                audio = (int(parts[1]),
                         tuple(pt for pt in map(codec_mod.payload_type, parts[3:])
                               if pt is not None))
            elif current == "application" and "MCPTT" in line.upper() \
                    and len(parts) >= 2 and parts[1].isascii() and parts[1].isdigit():
                floor_port = int(parts[1])
        elif line.startswith("c="):
            fields = line[2:].split()
            addr = fields[2] if len(fields) >= 3 else None
            if current is None:
                session_addr = addr
            elif in_audio and audio_addr is None:
                audio_addr = addr
    if audio is None:
        raise SipError("SDP has no audio media line")
    address = audio_addr or session_addr
    if not address:
        raise SipError("SDP has no connection address")
    _check_media_address(address)
    if not 0 < audio[0] <= 65535:
        # Port 0 declines the stream (RFC 3264 6); nothing to relay to.
        raise SipError(f"SDP audio port {clip(str(audio[0]), 12)} is not usable")
    if floor_port is not None and not 0 < floor_port <= 65535:
        floor_port = None                     # the floor stream declined
    return SdpInfo(address, audio[0], audio[1], floor_port)


def _check_media_address(address: str) -> None:
    """An address the relay will send a party's media to. Unspecified
    (0.0.0.0: RFC 2543-style hold, and on Linux delivery to this host),
    multicast and the limited broadcast address are refused: the relay sends
    one party's stream to one unicast peer. A name that is not an IP literal
    is left as it was. Found by the review of SIP-OP-17, where an in-dialog
    offer could re-point a relay after admission as often as it liked."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return
    if ip.is_unspecified or ip.is_multicast or \
            ip == ipaddress.ip_address("255.255.255.255"):
        raise SipError(f"SDP connection address {clip(address, 64)} is not a unicast peer")


def build_sdp(address: str, audio_port: int, floor_port: Optional[int],
              codecs: Sequence[Tuple[int, str]],
              fmtp: Optional[Mapping[int, str]] = None) -> str:
    """An SDP body advertising exactly `codecs` at `address`, with the
    format parameters in `fmtp` (by payload type) where given."""
    if not codecs:
        raise SipError("an SDP body must advertise at least one codec")
    lines = ["v=0", f"o=- 0 0 IN IP4 {address}", "s=-",
             f"c=IN IP4 {address}", "t=0 0",
             f"m=audio {audio_port} RTP/AVP "
             + " ".join(str(pt) for pt, _ in codecs)]
    for pt, name in codecs:
        lines.append(f"a=rtpmap:{pt} {name}")
        if fmtp and fmtp.get(pt):
            lines.append(f"a=fmtp:{pt} {fmtp[pt]}")
    if floor_port is not None:
        lines.append(f"m=application {floor_port} udp MCPTT")
    return "\r\n".join(lines) + "\r\n"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def canonical_uri(uri: str) -> str:
    """A SIP URI for comparison: scheme and host lower-cased, the user part
    left as it is -- RFC 3261 19.1.4 compares the user part case-sensitively,
    and so do the directory and the registration store."""
    return identity.canonical(uri)


# TS 24.379 9A.2.1.2: a functional alias PUBLISH activates with Expires
# 4294967295 (the RFC 3261 maximum) and deactivates with 0; anything else is
# answered 423 with this as Min-Expires (9A.2.2.2.3 step 5).
FUNCTIONAL_ALIAS_EXPIRES = 4294967295


@dataclass(frozen=True)
class AliasPublish:
    """A functional alias status change as the SIP request carries it
    (TS 24.379 9A.2.1.2): the user it is for (<mcptt-request-uri>), who sent
    it (P-Asserted-Identity or From), what it asks (the PIDF body), Expires,
    and the location it reports, if any."""
    served: str
    originating: str
    change: "mcinfo.AliasStatusChange"
    expires: Optional[int]
    location: Optional[LocationContext]


def parse_publish(message: Request, read_location: bool = True) -> AliasPublish:
    """A functional alias PUBLISH (Rel-15 on). A body without the MCPTT info
    naming the served user, or without the PIDF, raises SipError."""
    if message.method != "PUBLISH":
        raise SipError(f"expected PUBLISH, found {message.method}")
    content_type = message.headers.get("Content-Type") or ""
    try:
        raw = mcinfo.mcinfo_of(content_type, message.body)
        info = mcinfo.parse(raw) if raw is not None else mcinfo.McInfo()
        change = mcinfo.alias_status_change(content_type, message.body)
    except mcinfo.McInfoError as exc:
        raise SipError(f"functional alias status change: {exc}") from None
    if not info.request_uri:
        raise SipError("functional alias status change names no user "
                       "(<mcptt-request-uri>)")
    originating = _asserted_identity(message.headers.get_all("P-Asserted-Identity")) \
        or _uri(message.headers.get("From") or "")
    raw_expires = (message.headers.get("Expires") or "").strip()
    expires = int(raw_expires) if raw_expires.isascii() and raw_expires.isdigit() else None
    return AliasPublish(
        served=canonical_uri(_uri(info.request_uri)),
        originating=canonical_uri(originating),
        change=change, expires=expires,
        location=_location(content_type, message.body) if read_location else None)


@dataclass(frozen=True)
class AliasSubscribe:
    """A subscription to functional alias status as the initial SIP SUBSCRIBE
    carries it (TS 24.379 9A.2.1.3): the user whose status it asks for
    (<mcptt-request-uri>), who sent it (P-Asserted-Identity or From), the
    Expires it asks (None when absent), and whether its Accept admits
    application/pidf+xml (an absent Accept does: RFC 3856 6.7)."""
    served: str
    originating: str
    expires: Optional[int]
    accepts_pidf: bool


def subscribe_expires(message: Request) -> Optional[int]:
    """The Expires of a SUBSCRIBE: None when absent; ASCII digits only
    (SIP-OP-19), at most 4294967295 (RFC 3261 20.19), else SipError."""
    values = message.headers.get_all("Expires")
    if not values:
        return None
    raw = values[0].strip()
    if len(values) != 1 or not (raw.isascii() and raw.isdigit()) or \
            int(raw) > FUNCTIONAL_ALIAS_EXPIRES:
        raise SipError(f"Expires {clip(raw)} is not one delta-seconds value up to "
                       f"{FUNCTIONAL_ALIAS_EXPIRES}")
    return int(raw)


def accepts_pidf(message: Request) -> bool:
    """Whether the request's Accept admits application/pidf+xml: absent, or
    naming it, application/* or */* with a q above 0 (RFC 3261 20.1, RFC
    3856 6.7)."""
    values = message.headers.get_all("Accept")
    if not values:
        return True
    ranges = set()
    for value in values:
        for v in value.split(","):
            kind, *params = [x.strip().lower() for x in v.split(";")]
            q = next((x.partition("=")[2].strip() for x in params
                      if x.partition("=")[0].strip() == "q"), "1")
            if not re.fullmatch(r"0(?:\.0{0,3})?", q):       # q=0: not acceptable
                ranges.add(kind)
    return bool(ranges & {mcinfo.CT_PIDF, "application/*", "*/*"})


def parse_subscribe(message: Request) -> AliasSubscribe:
    """An initial functional alias status SUBSCRIBE (Rel-15 on). One whose
    MCPTT info does not name the served user, or does not ask for
    functional-alias-status-determination, raises SipError."""
    if message.method != "SUBSCRIBE":
        raise SipError(f"expected SUBSCRIBE, found {message.method}")
    content_type = message.headers.get("Content-Type") or ""
    try:
        raw = mcinfo.mcinfo_of(content_type, message.body)
        info = mcinfo.parse(raw) if raw is not None else mcinfo.McInfo()
    except mcinfo.McInfoError as exc:
        raise SipError(f"functional alias status subscription: {exc}") from None
    if info.request_type != mcinfo.FA_STATUS_DETERMINATION:
        raise SipError("the subscription does not ask for "
                       f"{mcinfo.FA_STATUS_DETERMINATION} (<request-type>)")
    if not info.request_uri:
        raise SipError("functional alias status subscription names no user "
                       "(<mcptt-request-uri>)")
    originating = _asserted_identity(message.headers.get_all("P-Asserted-Identity")) \
        or _uri(message.headers.get("From") or "")
    return AliasSubscribe(
        served=canonical_uri(_uri(info.request_uri)),
        originating=canonical_uri(originating),
        expires=subscribe_expires(message), accepts_pidf=accepts_pidf(message))


def _location(content_type: str, body: str) -> Optional["LocationContext"]:
    report = mcinfo.location_of(content_type, body)
    if report is None or report.cell is None:
        return None
    return LocationContext(cell_id=report.cell)


def _asserted_identity(values: Sequence[str]) -> str:
    """The identity P-Asserted-Identity asserts: its first sip: or sips:
    value, else its first value. RFC 3325 9.1 allows one sip: and one tel:,
    as one header or two, in either order, and TS 24.379 binds the MCPTT ID
    to the SIP public user identity (review of RES-OP-11: an S-CSCF that
    asserted tel: first had its user taken as foreign)."""
    found = []
    for value in values:
        found += re.findall(r"<([^>]+)>", value) or [v for v in value.split(",") if v.strip()]
    found = [f.split(";")[0].strip() for f in found if f.strip()]
    for f in found:
        if f.lower().startswith(("sip:", "sips:")):
            return f
    return found[0] if found else ""


def _uri(value: str) -> str:
    match = re.search(r"<([^>]+)>", value)
    candidate = match.group(1) if match else value.strip()
    return candidate.split(";")[0].strip()


def _host(uri: str) -> str:
    return uri.rpartition("@")[2] or uri
