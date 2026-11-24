"""TS 24.380 floor control and RTP, for the independent MC client.

Written from TS 24.380 clause 8 (RTCP APP "MCPT" packets, the field table of
8.2.3 and the message tables of 8.2.4-8.2.13, numbered as in V19.2.0) and
RFC 3550. It imports nothing
from `core` or `service`, nor from tools/trace_compare.py: the platform's
encoder, this client and the comparator are three readings, and Wireshark's
RTCP dissector a fourth that none of them wrote.
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple

APP = 204                       # RTCP APP (RFC 3550 6.7)
NAME = b"MCPT"                  # TS 24.380 8.2.2: floor control messages

# Table 8.2.2.1-1: message type -> subtype (the low four bits; bit 4 is the
# acknowledgement-required flag where the table shows an "x").
REQUEST, GRANTED, TAKEN, DENY, RELEASE, IDLE, REVOKE = 0, 1, 2, 3, 4, 5, 6
QUEUE_POSITION_REQUEST, QUEUE_POSITION_INFO, ACK = 8, 9, 10
NAMES = {REQUEST: "request", GRANTED: "granted", TAKEN: "taken", DENY: "deny",
         RELEASE: "release", IDLE: "idle", REVOKE: "revoke",
         QUEUE_POSITION_REQUEST: "queue-position-request",
         QUEUE_POSITION_INFO: "queue-position-info", ACK: "ack"}
ACK_REQUIRED = 0x10

# 8.2.3: field identifiers this client writes or reads.
F_PRIORITY, F_DURATION, F_REJECT_CAUSE, F_QUEUE_INFO = 0, 1, 2, 3
F_GRANTED_PARTY, F_SOURCE, F_MESSAGE_TYPE = 4, 10, 12
SOURCE_PARTICIPANT = 0          # 8.2.3.12: '0' the floor participant is the source


def _field(fid: int, value: bytes) -> bytes:
    """8.2.3.1: field id, length, value, padded to a 32-bit boundary."""
    raw = bytes([fid, len(value)]) + value
    return raw + b"\0" * (-len(raw) % 4)


def encode(subtype: int, ssrc: int, fields: List[Tuple[int, bytes]] = ()) -> bytes:
    body = NAME + b"".join(_field(f, v) for f, v in fields)
    length = (4 + len(body)) // 4          # in 32-bit words, minus one
    return struct.pack(">BBHI", 0x80 | subtype, APP, length, ssrc) + body


def floor_request(ssrc: int, priority: int) -> bytes:
    """8.2.4: Floor Priority is mandatory (8.2.3.2: priority, then spare)."""
    return encode(REQUEST, ssrc, [(F_PRIORITY, bytes([priority, 0]))])


def floor_release(ssrc: int) -> bytes:
    return encode(RELEASE, ssrc)


def queue_position_request(ssrc: int) -> bytes:
    return encode(QUEUE_POSITION_REQUEST, ssrc)


def floor_ack(ssrc: int, acked_subtype: int) -> bytes:
    """8.2.13 (Table 8.2.13-1): Source (8.2.3.12), the floor participant,
    and Message Type (8.2.3.14), the acknowledged message's type -- as
    6.2.4.x have the participant send it ("shall include the Message Type
    field ... and shall include the Source field set to '0'")."""
    return encode(ACK, ssrc, [(F_SOURCE, struct.pack(">H", SOURCE_PARTICIPANT)),
                              (F_MESSAGE_TYPE, bytes([acked_subtype & 0x1F, 0]))])


def decode(data: bytes) -> Optional[Dict]:
    """A floor control message, or None for anything else."""
    if len(data) < 12 or data[0] >> 6 != 2 or data[1] != APP or data[8:12] != NAME:
        return None
    subtype = data[0] & 0x1F
    fields: Dict[int, bytes] = {}
    i = 12
    while i + 2 <= len(data):
        fid, ln = data[i], data[i + 1]
        fields[fid] = data[i + 2:i + 2 + ln]
        i += 2 + ln + (-(2 + ln) % 4)
    return {"type": NAMES.get(subtype & 0x0F, f"subtype-{subtype & 0x0F}"),
            "subtype": subtype & 0x0F, "ack_required": bool(subtype & ACK_REQUIRED),
            "ssrc": struct.unpack(">I", data[4:8])[0], "fields": fields}


def rtp(pt: int, seq: int, ts: int, ssrc: int, payload: bytes = b"\x55" * 32) -> bytes:
    """RFC 3550 5.1: version 2, no padding, extension or CSRC."""
    return struct.pack(">BBHII", 0x80, pt & 0x7F, seq & 0xFFFF, ts & 0xFFFFFFFF,
                       ssrc) + payload


def rtp_pt(data: bytes) -> Optional[int]:
    if len(data) < 12 or data[0] >> 6 != 2 or 200 <= data[1] <= 204:
        return None
    return data[1] & 0x7F


class Endpoint:
    """A client's two UDP sockets: voice (RTP) and floor control, each bound
    on 127.0.0.1, sending from the port it advertises in its SDP."""

    def __init__(self, name: str):
        self.name = name
        self.ssrc = struct.unpack(">I", os.urandom(4))[0]
        self.rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtp_sock.bind(("127.0.0.1", 0))
        self.floor_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.floor_sock.bind(("127.0.0.1", 0))
        self.rtp_port = self.rtp_sock.getsockname()[1]
        self.floor_port = self.floor_sock.getsockname()[1]
        self.remote_rtp: Optional[Tuple[str, int]] = None
        self.remote_floor: Optional[Tuple[str, int]] = None
        self.floor_rx: List[Dict] = []
        self.rtp_rx: List[int] = []           # payload types received
        self.lock = threading.Lock()
        self.closed = False
        self.seq = 0
        for sock, sink in ((self.rtp_sock, self._on_rtp), (self.floor_sock, self._on_floor)):
            sock.settimeout(0.2)
            threading.Thread(target=self._reader, args=(sock, sink), daemon=True).start()

    def _reader(self, sock: socket.socket, sink) -> None:
        while not self.closed:
            try:
                data, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            sink(data)

    def _on_rtp(self, data: bytes) -> None:
        pt = rtp_pt(data)
        if pt is not None:
            with self.lock:
                self.rtp_rx.append(pt)

    def _on_floor(self, data: bytes) -> None:
        msg = decode(data)
        if msg is None:
            return
        with self.lock:
            self.floor_rx.append(msg)
        if msg["ack_required"] and self.remote_floor:
            # 6.2.x: a message flagged "acknowledgement required" is answered
            # with Floor Ack.
            self.floor_sock.sendto(floor_ack(self.ssrc, msg["subtype"]), self.remote_floor)

    # -- sending ------------------------------------------------------------------
    def send_floor(self, data: bytes) -> None:
        assert self.remote_floor, f"{self.name}: no floor address learnt"
        self.floor_sock.sendto(data, self.remote_floor)

    def talk(self, pt: int, seconds: float, interval: float = 0.02) -> int:
        """Send a burst of RTP at 50 packets/s; returns the packet count."""
        assert self.remote_rtp, f"{self.name}: no media address learnt"
        n, end = 0, time.time() + seconds
        while time.time() < end:
            self.seq += 1
            self.rtp_sock.sendto(rtp(pt, self.seq, self.seq * 160, self.ssrc),
                                 self.remote_rtp)
            n += 1
            time.sleep(interval)
        return n

    def wait_floor(self, kind: str, timeout: float = 10.0, after: int = 0) -> Dict:
        """The first floor message of type `kind` at index >= `after`."""
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                for msg in self.floor_rx[after:]:
                    if msg["type"] == kind:
                        return msg
            time.sleep(0.02)
        with self.lock:
            seen = [m["type"] for m in self.floor_rx]
        raise TimeoutError(f"{self.name}: no floor {kind}; received {seen}")

    def mark(self) -> int:
        with self.lock:
            return len(self.floor_rx)

    def close(self) -> None:
        self.closed = True
        for s in (self.rtp_sock, self.floor_sock):
            try:
                s.close()
            except OSError:
                pass
