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
from typing import Dict, Optional, Tuple

RTCP_VERSION = 2
PT_APP = 204
NAME = b"MCPT"


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


# Fixed-size fields: id -> value length in octets. Others are variable.
_FIXED = {
    FieldId.FLOOR_PRIORITY: 2, FieldId.DURATION: 2, FieldId.QUEUE_INFO: 2,
    FieldId.PERMISSION_TO_REQUEST: 2, FieldId.SEQUENCE_NUMBER: 2,
    FieldId.ACKED_MESSAGE_TYPE: 2, FieldId.FLOOR_INDICATOR: 2,
    FieldId.QUEUE_SIZE: 2,
}
_VARIABLE = (FieldId.REJECT_CAUSE, FieldId.GRANTED_PARTY, FieldId.USER_ID,
             FieldId.QUEUED_USER_ID, FieldId.SOURCE, FieldId.TRACK_INFO)

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


def encode(msg: FloorMessage) -> bytes:
    body = b""
    for fid in sorted(msg.fields):
        value = msg.fields[fid]
        if len(value) > 255:
            raise RtcpError(f"field {fid} is {len(value)} octets; maximum 255")
        body += bytes([int(fid), len(value)]) + value + b"\x00" * _pad(2 + len(value))
    total = 12 + len(body)
    assert total % 4 == 0
    head = struct.pack(">BBH", (RTCP_VERSION << 6) | int(msg.type), PT_APP,
                       total // 4 - 1)
    return head + struct.pack(">I", msg.ssrc) + NAME + body


def decode(data: bytes) -> FloorMessage:
    """Strict: any deviation from the layout above raises RtcpError."""
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
        if known in _VARIABLE:
            try:
                (value[2:] if known is FieldId.REJECT_CAUSE else value).decode("utf-8")
            except UnicodeDecodeError:
                raise RtcpError(f"field {known.name} is not UTF-8") from None
        fields[fid] = value
        i = end + pad
    return FloorMessage(mtype, ssrc, fields)


def message(mtype: MsgType, ssrc: int, *fields: Tuple[int, bytes]) -> FloorMessage:
    return FloorMessage(mtype, ssrc, {int(k): v for k, v in fields})
