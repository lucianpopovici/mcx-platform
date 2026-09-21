"""SIP message model and TS 24.379 adapter.

Splits into three pieces, none of which touches a socket:

  Headers/Message  a minimal SIP model, multi-valued headers preserved
  InboundGuard     the rejection rules of PLT-SIG-004 (malformed, replayed,
                   unknown session) with the status codes TS 24.379 specifies
  Adapter          renders the session layer's abstract `Signal`s into SIP, and
                   parses inbound INVITEs into a `SessionRequest`

Keeping this transport-free is what lets TS-SIG run in ENV-UNIT. A socket layer
sits above it and is the only part that needs a live SIP core.

OPEN: the 3GPP Warning header codes in WARNING_TEXTS are the ones this
implementation emits; they must be confirmed against TS 24.379 §4.4 of the
target release before interoperability testing (VP-OP-01). The status codes
themselves are RFC 3261 and are not in doubt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

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
from .session import Signal, SignalType

# --------------------------------------------------------------------------
# TS 24.379 constants
# --------------------------------------------------------------------------

# Media feature tags (TS 24.379 §6.2 / §7). One per MC service.
FEATURE_TAG_PTT = "+g.3gpp.mcptt"
FEATURE_TAG_DATA = "+g.3gpp.mcdata"
FEATURE_TAG_VIDEO = "+g.3gpp.mcvideo"

# Content types carried on MC signalling.
CT_MC_INFO = "application/vnd.3gpp.mcptt-info+xml"
CT_RESOURCE_LISTS = "application/resource-lists+xml"
CT_LOCATION_INFO = "application/vnd.3gpp.mcptt-location-info+xml"
CT_SDP = "application/sdp"

# RFC 4412 resource priority namespaces used for MC services.
RP_NAMESPACE_NORMAL = "mcpttp"
RP_NAMESPACE_EMERGENCY = "mcpttq"

# RFC 5373 answer mode.
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

# Warning header texts. See the OPEN note in the module docstring.
WARNING_TEXTS: Mapping[str, Tuple[int, str]] = {
    UNKNOWN_TARGET: (103, "target user not known"),
    NO_BINDING: (104, "identity has no current holder"),
    NO_LOCATION_BINDING: (105, "location required for this identity"),
    NOT_AUTHORISED: (100, "function not allowed due to authorisation"),
    CALL_TYPE_NOT_PERMITTED: (101, "call type not available to this user"),
    CAPACITY_EXHAUSTED: (102, "maximum number of sessions reached"),
    RECORDING_UNAVAILABLE: (106, "recording unavailable"),
    QOS_UNAVAILABLE: (107, "requested quality of service unavailable"),
    GATEWAY_UNAVAILABLE: (108, "interworking gateway unavailable"),
    PARTNER_UNAVAILABLE: (109, "partner system unavailable"),
    PARTNER_NOT_PERMITTED: (110, "not permitted with this partner system"),
}


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
        headers.add("Warning", f'399 mcx "{detail}"')
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

    def __init__(self, local_uri: str) -> None:
        self._local = local_uri

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

        headers.set("Contact", f"<{self._local}>;{';'.join(tags)}")
        # `require;explicit` so the request is routed only to a client that
        # actually supports the service (TS 24.379).
        headers.set("Accept-Contact",
                    f"*;{';'.join(tags)};require;explicit")

        if signal.detail.get("auto_answer"):
            headers.set("Answer-Mode", ANSWER_MODE_AUTO)
            headers.set("Priv-Answer-Mode", ANSWER_MODE_AUTO)
        else:
            headers.set("Answer-Mode", ANSWER_MODE_MANUAL)

        if request is not None:
            headers.set("P-Asserted-Identity", f"<{request.initiator}>")
            priority = signal.detail.get("resource_priority")
            if priority:
                headers.set("Resource-Priority", str(priority))

        headers.set("Content-Type", CT_SDP)
        return Request(method="INVITE", uri=signal.target or "",
                       headers=headers, body=context.sdp)

    def reject(self, reason_code: str, context: DialogContext) -> Response:
        status = REASON_TO_STATUS.get(reason_code, Status.SERVER_ERROR)
        headers = self._common(context)
        warning = WARNING_TEXTS.get(reason_code)
        if warning is not None:
            code, text = warning
            headers.add("Warning", f'{code} mcx "{text}"')
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

        Nothing profile-specific is inferred: call type arrives in the MC info
        body, and an absent or unknown value is left for the profile's session
        policy to refuse.
        """
        if message.method != "INVITE":
            raise SipError(f"expected INVITE, found {message.method}")

        initiator = _uri(message.headers.get("P-Asserted-Identity")
                         or message.headers.get("From") or "")
        target = _uri(message.uri)
        if not initiator or not target:
            raise SipError("INVITE lacks a usable initiator or target")

        media = self._media_from_offer(message)
        info = _parse_mc_info(message.body)

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
            target=info.get("target", target),
            call_type=info.get("call_type", ""),
            media=media,
            application=info.get("application"),
            urgency=info.get("urgency"),
            location=None,
            attributes=attributes,
        )

    def _media_from_offer(self, message: Request) -> Tuple[MediaKind, ...]:
        content_type = (message.headers.get("Content-Type") or "").lower()
        # MC INVITEs carry SDP inside multipart/mixed alongside the MC info
        # body (TS 24.379), so a top-level application/sdp is not required.
        if CT_SDP not in content_type and "multipart" not in content_type:
            return ()
        kinds: List[MediaKind] = []
        for line in message.body.splitlines():
            if not line.startswith("m="):
                continue
            kind = line[2:].split()[0] if len(line) > 2 else ""
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


def _parse_mc_info(body: str) -> Dict[str, str]:
    """Extract MC info fields from a multipart body, if present.

    Deliberately forgiving: a missing or unparsable body yields an empty map and
    the session policy refuses the resulting request, rather than the adapter
    guessing a call type.
    """
    out: Dict[str, str] = {}
    for field_name in ("call_type", "application", "urgency", "target"):
        match = re.search(rf"<mcptt-{field_name}>([^<]+)</mcptt-{field_name}>", body)
        if match:
            out[field_name] = match.group(1).strip()
    return out
