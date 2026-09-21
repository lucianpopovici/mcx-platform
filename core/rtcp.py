"""Floor control messages on the wire: RTCP APP packets (TS 24.380 §8).

Pure encode/decode; no socket, no clock, no floor logic. The state machine in
`floor.py` decides; this module only turns its decisions into bytes and bytes
into typed messages.

OPEN (FC-OP-03): the TS 24.380 text was NOT available when this was written.
The packet layout, message-type subtypes, field identifiers and field
encodings below are reconstructed from memory of the specification and are
unverified. `decode` is strict so that a deviation is loud, but strictness is
against THIS description, not against the standard. VP1-FC-002 cannot be
closed on this module alone; it needs the specification (or golden captures,
VP-OP-02) to check every constant in this file.

Layout (RFC 3550 §6.7 APP packet):

    0                   1                   2                   3
    |V=2|P|  subtype  |  PT=204       |            length             |
    |                           SSRC                                  |
    |                      name = "MCPT"                              |
    |  Field ID | Length |   value ...  (padded to a 32-bit boundary) |

`length` counts 32-bit words in the packet minus one. A field's Length counts
the value octets only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum

from . import release as rel
from .release import Release
from typing import Dict, Optional, Tuple

RTCP_VERSION = 2
PT_APP = 204
NAME = b"MCPT"


class ReleaseRefused(ValueError):
    """A message uses something the deployment's 3GPP release does not define.

    Deliberately distinct from RtcpError: the bytes are well formed, and the
    only thing wrong is that this deployment does not speak that release. An
    operator reading a log must be able to tell "my peer is newer than me"
    from "my peer is broken".
    """


class RtcpError(ValueError):
    """The bytes are not a well-formed floor control message."""


class MsgType(IntEnum):
    """RTCP APP subtype values, TS 24.380 table 8.2.2-1.

    These are 1-based in the specification. They were previously 0-based here,
    which put every floor control message on the wire one subtype low — see the
    commit that corrected them.
    """

    REQUEST = 0                                                 # 00000
    GRANTED = 1                                                 # x0001
    DENY = 3                                                    # x0011
    RELEASE = 4                                                 # x0100
    IDLE = 5                                                    # x0101
    TAKEN = 2                                                   # x0010
    REVOKE = 6                                                  # 00110
    QUEUE_POSITION_REQUEST = 8                                  # 01000
    QUEUE_POSITION_INFO = 9                                     # x1001
    ACK = 10                                                    # 01010
    # Not implemented, reserved so an inbound message decodes rather than
    # raising "unknown subtype":
    UNICAST_MEDIA_FLOW_CONTROL = 11                             # x1011
    QUEUED_FLOOR_REQUESTS = 14                                  # x1110
    RELEASE_MULTI_TALKER = 15                                   # 01111
    REVOKE_REQUEST = 7                                          # 00111



# Bit 4 of the five-bit subtype field: "acknowledgement required". The message
# TYPE is the low four bits. Masking all five would reject an acknowledged
# Floor Idle (10101) as an unknown type.
ACK_REQUIRED = 0x10
TYPE_MASK = 0x0F

# Messages whose table 8.2.2.1-1 entry begins 'x' may carry the flag; the rest
# have a literal 0 there, so setting it yields a subtype the table never defines.
ACK_CAPABLE = frozenset({
    MsgType.GRANTED, MsgType.TAKEN, MsgType.DENY, MsgType.RELEASE,
    MsgType.IDLE, MsgType.QUEUE_POSITION_INFO,
    MsgType.UNICAST_MEDIA_FLOW_CONTROL, MsgType.QUEUED_FLOOR_REQUESTS,
})


class FieldId(IntEnum):
    FLOOR_PRIORITY = 0                                   # Release 13
    DURATION = 1                                         # Release 13
    REJECT_CAUSE = 2                                     # Release 13
    QUEUE_INFO = 3                                       # Release 13
    GRANTED_PARTY = 4                                    # Release 13
    PERMISSION_TO_REQUEST = 5                            # Release 13
    USER_ID = 6                                          # Release 13
    QUEUE_SIZE = 7                                       # Release 13
    SEQUENCE_NUMBER = 8                                  # Release 13
    QUEUED_USER_ID = 9                                   # Release 13
    SOURCE = 10                                          # Release 13
    TRACK_INFO = 11                                      # Release 13
    ACKED_MESSAGE_TYPE = 12                              # Release 13
    FLOOR_INDICATOR = 13                                 # Release 13
    AUDIO_SSRC_OF_GRANTED_PARTICIPANT = 14               # Release 13
    GRANTED_USERS = 15                                   # Release 15
    LIST_OF_SSRC =	16                                   # Release 15
    FUNCTIONAL_ALIAS = 17                                # Release 15
    LIST_OF_FUNCTIONAL_ALIASES = 18                      # Release 15
    LOCATION = 19                                        # Release 15
    LIST_OF_LOCATION = 20                                # Release 15
    QUEUED_FLOOR_REQUESTS_PURPOSE = 21                   # Release 17
    LIST_OF_QUEUED_USERS = 22                            # Release 17
    RESPONSE_STATE = 23                                  # Release 17
    MEDIA_FLOW_CONTROL_INDICATOR = 24                    # Release 17
    FLOOR_REVOKE_REQUEST_USER_ID = 25                    # Release 19


# Field value lengths, TS 24.380 clause 8.2.3.2 through 8.2.3.27 (PLT-CONF-AUDIT
# CA-03). Read from the prose under each field's diagram -- "has the value '2'",
# "has the value '6'" -- which states the length in words. The ASCII-art diagrams
# above them do not survive extraction, and are the reason this went unchecked
# for so long; the prose was there all along.
#
# Every field id must appear in exactly one of the three groups below.
# `test_every_field_id_is_classified` enforces that, because the failure mode
# this replaces was not a wrong entry -- it was fields with NO entry, which the
# decoder accepted at any length without comment.

# id -> exact value length in octets.
_FIXED = {
    FieldId.FLOOR_PRIORITY: 2,               # 8.2.3.2
    FieldId.DURATION: 2,                     # 8.2.3.3
    FieldId.QUEUE_INFO: 2,                   # 8.2.3.5
    FieldId.PERMISSION_TO_REQUEST: 2,        # 8.2.3.7
    FieldId.QUEUE_SIZE: 2,                   # 8.2.3.9
    FieldId.SEQUENCE_NUMBER: 2,              # 8.2.3.10
    # 8.2.3.12. A 16-bit binary value, NOT a variable-length item: this sat in
    # the variable group, so it was never length-checked and was handed to the
    # UTF-8 validator as if it were text.
    FieldId.SOURCE: 2,
    FieldId.ACKED_MESSAGE_TYPE: 2,           # 8.2.3.14
    FieldId.FLOOR_INDICATOR: 2,              # 8.2.3.15
    # 8.2.3.16. SIX, not four: an RFC 3550 SSRC is 32 bits and the field
    # carries 16 spare bits after it. Called the "SSRC field" up to Rel-17 and
    # renamed "Audio SSRC of Granted Participant" in Rel-18; the length is the
    # same in every release from Rel-15 on.
    FieldId.AUDIO_SSRC_OF_GRANTED_PARTICIPANT: 6,
    FieldId.QUEUED_FLOOR_REQUESTS_PURPOSE: 2,   # 8.2.3.23
    FieldId.RESPONSE_STATE: 2,                  # 8.2.3.25
    FieldId.MEDIA_FLOW_CONTROL_INDICATOR: 2,    # 8.2.3.26
}

# Variable-length fields whose value is a text string (an ABNF string value in
# the specification's own tables). Only these may be UTF-8 validated.
_TEXT = (
    FieldId.GRANTED_PARTY,                   # 8.2.3.6, coded as <User ID>
    FieldId.USER_ID,                         # 8.2.3.8
    FieldId.QUEUED_USER_ID,                  # 8.2.3.11, coded as <User ID>
    FieldId.FUNCTIONAL_ALIAS,                # 8.2.3.19
    FieldId.FLOOR_REVOKE_REQUEST_USER_ID,    # 8.2.3.27, coded as <User ID>
)

# Variable-length fields with internal binary structure. Validating these as
# UTF-8 is wrong and was actively harmful for Track Info, whose first octet is
# a <Queueing Capability> bitfield: any value with the high bit set is not
# valid UTF-8, so a conformant Floor Request carrying Track Info was rejected
# as malformed. The framing is still checked; the payload is opaque here.
_STRUCTURED = (
    FieldId.TRACK_INFO,                      # 8.2.3.13
    FieldId.GRANTED_USERS,                   # 8.2.3.17
    FieldId.LIST_OF_SSRC,                    # 8.2.3.18
    FieldId.LIST_OF_FUNCTIONAL_ALIASES,      # 8.2.3.20
    FieldId.LOCATION,                        # 8.2.3.21
    FieldId.LIST_OF_LOCATION,                # 8.2.3.22
    FieldId.LIST_OF_QUEUED_USERS,            # 8.2.3.24
)

# 8.2.3.4 is its own shape: a 16-bit <Reject Cause> followed by an optional
# <Reject Phrase> text item, so it is neither fixed nor wholly text.
_CAUSE_AND_PHRASE = (FieldId.REJECT_CAUSE,)

_VARIABLE = _TEXT + _STRUCTURED + _CAUSE_AND_PHRASE

# Reject causes (16-bit). See the OPEN note above.
# Floor Deny rejection causes, clause 8.2.6.2.
DENY_ANOTHER_HAS_PERMISSION = 1
DENY_INTERNAL_ERROR = 2
DENY_ONLY_ONE_PARTICIPANT = 3
DENY_RETRY_AFTER = 4
DENY_RECEIVE_ONLY = 5
DENY_NO_RESOURCES = 6
DENY_QUEUE_FULL = 7
DENY_OTHER = 255

# Floor Revoke causes, clause 8.2.10.2. A SEPARATE namespace: the same number
# means something different here. 2 is "media burst too long", not "internal
# error"; 3 is "no permission to send", not "only one participant". Sharing one
# flat set between the two messages sends the wrong reason on every revoke.
REVOKE_ONLY_ONE_CLIENT = 1
REVOKE_MEDIA_BURST_TOO_LONG = 2
REVOKE_NO_PERMISSION = 3
REVOKE_PREEMPTED = 4
REVOKE_NO_RESOURCES = 6
REVOKE_BY_ANOTHER_CLIENT = 7
REVOKE_OTHER = 255

# Deprecated aliases, kept so existing call sites keep compiling. They carry
# the DENY meanings; using one in a Floor Revoke message is a defect.
CAUSE_ANOTHER_HAS_PERMISSION = DENY_ANOTHER_HAS_PERMISSION
CAUSE_INTERNAL_ERROR = DENY_INTERNAL_ERROR
CAUSE_ONLY_ONE_CLIENT = DENY_ONLY_ONE_PARTICIPANT
CAUSE_RETRY_AFTER = DENY_RETRY_AFTER
CAUSE_RECEIVE_ONLY = DENY_RECEIVE_ONLY
CAUSE_NO_RESOURCES = DENY_NO_RESOURCES
CAUSE_OTHER = DENY_OTHER


@dataclass(frozen=True)
class FloorMessage:
    type: MsgType
    ssrc: int
    fields: Dict[int, bytes] = field(default_factory=dict)

    # -- typed accessors -------------------------------------------------

    def _u16(self, fid: FieldId) -> Optional[int]:
        v = self.fields.get(fid)
        return None if v is None else struct.unpack(">H", v)[0]

    @property
    def sequence(self) -> Optional[int]:
        return self._u16(FieldId.SEQUENCE_NUMBER)

    @property
    def priority(self) -> Optional[int]:
        v = self.fields.get(FieldId.FLOOR_PRIORITY)
        return None if v is None else v[0]

    @property
    def duration_s(self) -> Optional[int]:
        return self._u16(FieldId.DURATION)

    @property
    def reject_cause(self) -> Optional[Tuple[int, str]]:
        v = self.fields.get(FieldId.REJECT_CAUSE)
        if v is None:
            return None
        return struct.unpack(">H", v[:2])[0], v[2:].decode("utf-8")

    @property
    def queue_info(self) -> Optional[Tuple[int, int]]:
        v = self.fields.get(FieldId.QUEUE_INFO)
        return None if v is None else (v[0], v[1])

    @property
    def granted_party(self) -> Optional[str]:
        v = self.fields.get(FieldId.GRANTED_PARTY)
        return None if v is None else v.decode("utf-8")

    @property
    def permission_to_request(self) -> Optional[bool]:
        v = self._u16(FieldId.PERMISSION_TO_REQUEST)
        return None if v is None else bool(v)

    @property
    def acked_type(self) -> Optional[MsgType]:
        v = self.fields.get(FieldId.ACKED_MESSAGE_TYPE)
        return None if v is None else MsgType(v[0])


# --------------------------------------------------------------------------
# Field constructors
# --------------------------------------------------------------------------


def f_priority(p: int) -> Tuple[int, bytes]:
    return FieldId.FLOOR_PRIORITY, bytes([p & 0xFF, 0])


def f_duration(seconds: int) -> Tuple[int, bytes]:
    return FieldId.DURATION, struct.pack(">H", seconds)


def f_reject(cause: int, phrase: str = "") -> Tuple[int, bytes]:
    return FieldId.REJECT_CAUSE, struct.pack(">H", cause) + phrase.encode("utf-8")


def f_queue_info(position: int, priority: int) -> Tuple[int, bytes]:
    return FieldId.QUEUE_INFO, bytes([position & 0xFF, priority & 0xFF])


def f_granted_party(uri: str) -> Tuple[int, bytes]:
    return FieldId.GRANTED_PARTY, uri.encode("utf-8")


def f_permission(allowed: bool) -> Tuple[int, bytes]:
    return FieldId.PERMISSION_TO_REQUEST, struct.pack(">H", 1 if allowed else 0)


def f_user_id(uri: str) -> Tuple[int, bytes]:
    return FieldId.USER_ID, uri.encode("utf-8")


def f_sequence(n: int) -> Tuple[int, bytes]:
    return FieldId.SEQUENCE_NUMBER, struct.pack(">H", n & 0xFFFF)


def f_acked(t: MsgType) -> Tuple[int, bytes]:
    return FieldId.ACKED_MESSAGE_TYPE, bytes([int(t), 0])


# --------------------------------------------------------------------------
# Encode / decode
# --------------------------------------------------------------------------


def _pad(n: int) -> int:
    return (-n) % 4


def encode(msg: FloorMessage, release: Release) -> bytes:
    """Serialise, refusing anything the deployment's release does not define.

    The release is required, not defaulted. A default would be a guess about
    which peers this deployment talks to, and getting it wrong is silent:
    subtype 14 is a valid message in both Rel-17 and Rel-18 and means a
    different thing in each.
    """
    if not rel.supports_subtype(release, int(msg.type)):
        introduced = rel.SUBTYPE_INTRODUCED.get(int(msg.type))
        raise ReleaseRefused(
            f"subtype {int(msg.type)} ({msg.type.name}) is not defined in "
            f"{release}" + (f"; introduced in {introduced}" if introduced else ""))
    body = b""
    for fid in sorted(msg.fields):
        value = msg.fields[fid]
        if not rel.supports_field(release, fid):
            introduced = rel.FIELD_INTRODUCED.get(fid)
            raise ReleaseRefused(
                f"field id {fid} is not defined in {release}"
                + (f"; introduced in {introduced}" if introduced else ""))
        if len(value) > 255:
            raise RtcpError(f"field {fid} is {len(value)} octets; maximum 255")
        # The Reject Cause field carries two DIFFERENT namespaces depending on
        # the message carrying it (clause 8.2.6.2 vs 8.2.10.2), so the cause
        # can only be release-checked here, where the message type is known.
        if fid == int(FieldId.REJECT_CAUSE) and msg.type is MsgType.REVOKE \
                and len(value) >= 2:
            cause = struct.unpack(">H", value[:2])[0]
            if not rel.supports_revoke_cause(release, cause):
                introduced = rel.REVOKE_CAUSE_INTRODUCED.get(cause)
                raise ReleaseRefused(
                    f"floor revoke cause #{cause} is not defined in {release}"
                    + (f"; introduced in {introduced}" if introduced else ""))
        body += bytes([int(fid), len(value)]) + value + b"\x00" * _pad(2 + len(value))
    total = 12 + len(body)
    assert total % 4 == 0
    head = struct.pack(">BBH", (RTCP_VERSION << 6) | int(msg.type), PT_APP,
                       total // 4 - 1)
    return head + struct.pack(">I", msg.ssrc) + NAME + body


def decode(data: bytes, release: Release) -> FloorMessage:
    """Strict: any deviation from the layout above raises RtcpError.

    Also strict about the release: a subtype or field the configured release
    does not define is refused rather than interpreted, because interpreting
    it would mean reading it under a release this deployment does not speak.
    """
    if len(data) < 12:
        raise RtcpError(f"{len(data)} octets is shorter than an APP header")
    if len(data) % 4:
        raise RtcpError("length is not a multiple of 4 octets")
    b0, pt, words = struct.unpack(">BBH", data[:4])
    if b0 >> 6 != RTCP_VERSION:
        raise RtcpError(f"version {b0 >> 6}, expected {RTCP_VERSION}")
    if b0 & 0x20:
        raise RtcpError("padding bit set")
    if pt != PT_APP:
        raise RtcpError(f"packet type {pt}, expected {PT_APP}")
    if (words + 1) * 4 != len(data):
        raise RtcpError(f"length field says {(words + 1) * 4} octets, got {len(data)}")
    if data[8:12] != NAME:
        raise RtcpError(f"name {data[8:12]!r}, expected {NAME!r}")
    try:
        mtype = MsgType(b0 & TYPE_MASK)
    except ValueError:
        raise RtcpError(f"unknown message type {b0 & TYPE_MASK}") from None
    if not rel.supports_subtype(release, int(mtype)):
        introduced = rel.SUBTYPE_INTRODUCED.get(int(mtype))
        raise ReleaseRefused(
            f"received subtype {int(mtype)}, which {release} does not define"
            + (f" (introduced in {introduced})" if introduced else ""))
    ssrc = struct.unpack(">I", data[4:8])[0]

    fields: Dict[int, bytes] = {}
    i = 12
    while i < len(data):
        if i + 2 > len(data):
            raise RtcpError("truncated field header")
        fid, length = data[i], data[i + 1]
        end = i + 2 + length
        if end > len(data):
            raise RtcpError(f"field {fid} overruns the packet")
        try:
            known = FieldId(fid)
        except ValueError:
            raise RtcpError(f"unknown field id {fid}") from None
        if not rel.supports_field(release, fid):
            introduced = rel.FIELD_INTRODUCED.get(fid)
            raise ReleaseRefused(
                f"received field {known.name}, which {release} does not define"
                + (f" (introduced in {introduced})" if introduced else ""))
        if known in _FIXED and length != _FIXED[known]:
            raise RtcpError(f"field {known.name} has length {length}, "
                            f"expected {_FIXED[known]}")
        if known is FieldId.REJECT_CAUSE and length < 2:
            raise RtcpError("reject cause shorter than 2 octets")
        if fid in fields:
            raise RtcpError(f"duplicate field {known.name}")
        value = data[i + 2:end]
        pad = _pad(2 + length)
        if data[end:end + pad] != b"\x00" * pad or end + pad > len(data):
            raise RtcpError(f"field {known.name} padding is not zero/complete")
        if known in _TEXT or known is FieldId.REJECT_CAUSE:
            try:
                (value[2:] if known is FieldId.REJECT_CAUSE else value).decode("utf-8")
            except UnicodeDecodeError:
                raise RtcpError(f"field {known.name} is not UTF-8") from None
        fields[fid] = value
        i = end + pad
    return FloorMessage(mtype, ssrc, fields)


def message(mtype: MsgType, ssrc: int, *fields: Tuple[int, bytes]) -> FloorMessage:
    return FloorMessage(mtype, ssrc, {int(k): v for k, v in fields})


class Codec:
    """An encoder/decoder bound to one 3GPP release.

    The deployment builds exactly one of these at start and everything on the
    media path uses it, so there is no call site that could reach the wire
    without having stated a release.
    """

    __slots__ = ("release",)

    def __init__(self, release: Release) -> None:
        self.release = release

    def encode(self, msg: FloorMessage) -> bytes:
        return encode(msg, self.release)

    def decode(self, data: bytes) -> FloorMessage:
        return decode(data, self.release)

    def name_of(self, msg: FloorMessage) -> Optional[str]:
        """What this message means AT THIS RELEASE -- see release.subtype_name.
        `MsgType` carries one name per value and subtype 14 needs two."""
        return rel.subtype_name(self.release, int(msg.type))
