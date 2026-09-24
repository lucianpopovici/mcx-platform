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

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .errors import (
    CALL_TYPE_NOT_PERMITTED,
    CAPACITY_EXHAUSTED,
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
from .hooks import MediaKind, SessionRequest
from . import mcinfo
from .release import Release, supports_session_type, supports_sip_warning
from .session import Signal, SignalType

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

# The "+" is required, not stylistic. IETF RFC 3840 clause 5: base tags (audio,
# video, isfocus and seventeen others) carry no prefix, and for every other tag
# "a plus sign ('+') MUST be added as the first character". The ABNF makes it
# structural -- other-tags = "+" ftag-name. TS 24.379's Contact examples are
# inconsistent about this and six of the eight are editorially wrong
# (PLT-CONF-AUDIT CA-10).


def _pct(value: str) -> str:
    """Percent-encode a feature tag value as TS 24.379 shows it on the wire."""
    return value.replace(":", "%3A")

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
    REQUEST_TIMEOUT = (408, "Request Timeout")
    TEMPORARILY_UNAVAILABLE = (480, "Temporarily Unavailable")
    CALL_DOES_NOT_EXIST = (481, "Call/Transaction Does Not Exist")
    LOOP_DETECTED = (482, "Loop Detected")
    BUSY_HERE = (486, "Busy Here")
    NOT_ACCEPTABLE_HERE = (488, "Not Acceptable Here")
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
# cannot be mistaken for a code. This is what keeps PLT-PRI-008's invariant --
# a policy refusal must be distinguishable from a fault in the trace, and both
# are 503 for `capacity-exhausted` -- without emitting a false code to buy it.
LOCAL_WARNING_TEXTS: Mapping[str, str] = {
    NO_BINDING: "identity has no current holder",
    NO_LOCATION_BINDING: "location required for this identity",
    CAPACITY_EXHAUSTED: "maximum number of sessions reached",
    RECORDING_UNAVAILABLE: "recording unavailable",
    QOS_UNAVAILABLE: "requested quality of service unavailable",
    GATEWAY_UNAVAILABLE: "interworking gateway unavailable",
    PARTNER_UNAVAILABLE: "partner system unavailable",
}

REFUSALS_WITHOUT_WARNING_TEXT: Mapping[str, str] = {
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
            "c": "Content-Type", "l": "Content-Length", "k": "Supported"}
_REQUEST_LINE = re.compile(r"^([A-Za-z]+) (\S+) SIP/2\.0$")
_STATUS_LINE = re.compile(r"^SIP/2\.0 (\d{3})(?: (.*))?$")


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
        if _COMPACT.get(name.strip().lower(), name.strip()).lower() == "content-length":
            try:
                length = int(value.strip())
            except ValueError:
                raise SipError("malformed Content-Length")
            if length < 0:
                raise SipError("negative Content-Length")
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
            lines[-1] += " " + raw.strip()
        else:
            lines.append(raw)
    start, header_lines = lines[0], lines[1:]
    headers = Headers()
    for line in header_lines:
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            raise SipError(f"malformed header line {line!r}")
        name = name.strip()
        headers.add(_COMPACT.get(name.lower(), name), value.strip())
    headers = Headers([(n, v) for n, v in headers.items()
                       if n.lower() != "content-length"])
    m = _STATUS_LINE.match(start)
    if m:
        return ReceivedResponse(int(m.group(1)), m.group(2) or "", headers, body)
    m = _REQUEST_LINE.match(start)
    if m:
        return Request(m.group(1), m.group(2), headers, body)
    raise SipError(f"malformed start line {start!r}")


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
_CSEQ = re.compile(r"^\d+\s+[A-Z]+$")


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


class Adapter:
    """Renders abstract signals into TS 24.379 messages and parses inbound ones."""

    def __init__(self, local_uri: str, release: Release,
                 call_types: Sequence[Any] = ()) -> None:
        """`call_types` are the loaded profile's; the adapter reads only each
        one's `id` and `mc_signature` (PLT-ICD-001 2.6) and learns nothing
        else about the profile."""
        self._local = local_uri
        self._host = _host_of(local_uri)
        self._by_signature: Dict[mcinfo.Signature, str] = {}
        self._signature_of: Dict[str, mcinfo.Signature] = {}
        for ct in call_types:
            sig = getattr(ct, "mc_signature", None)
            if sig is not None:
                self._by_signature[sig] = ct.id
                self._signature_of[ct.id] = sig
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
        headers.set("Contact", f"<{self._local}>;{';'.join(tags)};{icsi}")

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
            emergency=True if sig.emergency else None,
            imminent_peril=True if sig.imminent_peril else None,
            broadcast=True if sig.broadcast else None)
        ctype, body = mcinfo.build_multipart((
            mcinfo.Part(CT_SDP, context.sdp),
            mcinfo.Part(CT_MC_INFO, mcinfo.render(info, self._release))))
        headers.set("Content-Type", ctype)
        return Request(method="INVITE", uri=signal.target or "",
                       headers=headers, body=body)

    def reject(self, reason_code: str, context: DialogContext) -> Response:
        """Refuse, with the Warning header shape of TS 24.379 clause 4.4.1.

            Warning: 399 mcptt.example "100 function not allowed due to ..."

        399 is the RFC 3261 warn-code, the host name is this server's, and the
        MC 3-digit code lives inside the quoted warn-text. A refusal with no
        specification-defined code carries no Warning at all.
        """
        status = REASON_TO_STATUS.get(reason_code, Status.SERVER_ERROR)
        headers = self._common(context)
        warning = WARNING_TEXTS.get(reason_code)
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

        initiator = _uri(message.headers.get("P-Asserted-Identity")
                         or message.headers.get("From") or "")
        target = _uri(message.uri)
        if not initiator or not target:
            raise SipError("INVITE lacks a usable initiator or target")

        media = self._media_from_offer(message)
        content_type = message.headers.get("Content-Type") or ""
        try:
            raw = mcinfo.mcinfo_of(content_type, message.body)
            info = mcinfo.parse(raw) if raw is not None else mcinfo.McInfo()
        except mcinfo.McInfoError as exc:
            raise SipError(f"MCPTT info body: {exc}") from None
        sig = info.signature()
        call_type = ""
        if sig is not None and supports_session_type(self._release, sig.session_type):
            call_type = self._by_signature.get(sig, "")

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
            target=_uri(info.request_uri) if info.request_uri else target,
            call_type=call_type,
            media=media,
            # TS 24.379 has no element for either. The profile's declaration
            # of the call type supplies both (profiles/common/tables.py).
            application=None,
            urgency=None,
            location=None,
            attributes=attributes,
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


def offered_payload_types(sdp: str) -> Tuple[int, ...]:
    for line in sdp.splitlines():
        if line.startswith("m=audio"):
            parts = line.split()
            return tuple(int(p) for p in parts[3:] if p.isdigit())
    return ()


def negotiate(offer_sdp: str, supported: Sequence[int]) -> Optional[int]:
    """Return the first mutually supported payload type, or None.

    None means the offer is not acceptable: the caller answers 488, it does not
    pick a codec the other side did not offer (PLT-MED-002).
    """
    for pt in offered_payload_types(offer_sdp):
        if pt in supported:
            return pt
    return None


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
    for raw in body.splitlines():
        line = raw.strip()
        if line.startswith("m="):
            parts = line[2:].split()
            current = parts[0] if parts else None
            if current == "audio" and audio is None and len(parts) >= 4 \
                    and parts[1].isdigit():
                audio = (int(parts[1]),
                         tuple(int(p) for p in parts[3:] if p.isdigit()))
            elif current == "application" and "MCPTT" in line.upper() \
                    and len(parts) >= 2 and parts[1].isdigit():
                floor_port = int(parts[1])
        elif line.startswith("c="):
            fields = line[2:].split()
            addr = fields[2] if len(fields) >= 3 else None
            if current is None:
                session_addr = addr
            elif current == "audio" and audio_addr is None:
                audio_addr = addr
    if audio is None:
        raise SipError("SDP has no audio media line")
    address = audio_addr or session_addr
    if not address:
        raise SipError("SDP has no connection address")
    return SdpInfo(address, audio[0], audio[1], floor_port)


def build_sdp(address: str, audio_port: int, floor_port: Optional[int],
              codecs: Sequence[Tuple[int, str]]) -> str:
    """An SDP body advertising exactly `codecs` at `address`."""
    if not codecs:
        raise SipError("an SDP body must advertise at least one codec")
    lines = ["v=0", f"o=- 0 0 IN IP4 {address}", "s=-",
             f"c=IN IP4 {address}", "t=0 0",
             f"m=audio {audio_port} RTP/AVP "
             + " ".join(str(pt) for pt, _ in codecs)]
    lines += [f"a=rtpmap:{pt} {name}" for pt, name in codecs]
    if floor_port is not None:
        lines.append(f"m=application {floor_port} udp MCPTT")
    return "\r\n".join(lines) + "\r\n"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _uri(value: str) -> str:
    match = re.search(r"<([^>]+)>", value)
    candidate = match.group(1) if match else value.strip()
    return candidate.split(";")[0].strip()


def _host(uri: str) -> str:
    return uri.rpartition("@")[2] or uri
