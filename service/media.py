"""Media plane: RTP forwarding gated by the floor, and floor control over RTCP.

`MediaSession` is pure: it holds no socket and reads no clock. Bytes arrive via
`on_rtp` / `on_floor`, bytes leave through each endpoint's `io`. That is what
lets the whole call be captured and asserted per endpoint (VP1-MED-003)
without a network, and what `UdpMediaPlane` (bottom of this file) then wires to
real sockets.

Authority stays where it was put:
  * WHO holds the floor is `core.floor.FloorControl`'s decision. This module
    feeds it events and sends what it returns. It never decides.
  * A floor request's priority is what IF-PRI says for that participant, never
    what the client asserts (PLT-FC-005).
  * Timer durations are the profile's, carried by the machine; this module
    only fires TIMER_EXPIRY when the machine's own deadline passes.

Enforcement is at the forwarding point, keyed on the SOCKET a packet arrived
on (each participant has its own relay port) and its declared source address,
not on anything inside the packet (VP1-MED-004, VP1-MED-001).
"""

from __future__ import annotations

import logging
import socket
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional, Protocol, Tuple

from core import floor as fl
from core.release import Release
from core import rtcp
from core.rtcp import MsgType

log = logging.getLogger("mcx.media")

Addr = Tuple[str, int]
PLATFORM_SSRC = 0x4D435801
RTP_MIN_HEADER = 12
NOT_QUEUED = 255
TRACE_LIMIT = 20000

_DENY_CAUSE = {
    fl.DenyReason.QUEUEING_DISABLED: rtcp.DENY_ANOTHER_HAS_PERMISSION,
    fl.DenyReason.LOWER_PRIORITY: rtcp.DENY_ANOTHER_HAS_PERMISSION,
    fl.DenyReason.QUEUE_FULL: rtcp.DENY_QUEUE_FULL,   # cause #7 exists
    fl.DenyReason.ALREADY_QUEUED: rtcp.DENY_OTHER,
    fl.DenyReason.ALREADY_HOLDER: rtcp.DENY_OTHER,
    fl.DenyReason.NO_SESSION: rtcp.DENY_INTERNAL_ERROR,
}

# TS 24.380 8.2.10.2; which cause each situation carries is 6.3.4.4.4 (#2)
# and 6.3.4.4.7 (#4).
_REVOKE_CAUSE = {
    fl.RevokeReason.MEDIA_BURST_TOO_LONG: rtcp.REVOKE_MEDIA_BURST_TOO_LONG,
    fl.RevokeReason.PREEMPTED: rtcp.REVOKE_PREEMPTED,
    fl.RevokeReason.OTHER: rtcp.REVOKE_OTHER,
}

# How often, at most, the holder's media is reported to the floor machine
# after its first packet. Well inside T1's 4 s default, which it keeps alive;
# a profile with a shorter T1 is reported to at least four times per T1.
MEDIA_NOTIFY_MS = 250


class EndpointIO(Protocol):
    rtp_port: int
    floor_port: int

    def send_rtp(self, addr: Addr, data: bytes) -> None: ...
    def send_floor(self, addr: Addr, data: bytes) -> None: ...
    def close(self) -> None: ...


@dataclass
class Endpoint:
    uri: str
    io: EndpointIO
    remote_rtp: Optional[Addr] = None
    remote_floor: Optional[Addr] = None
    seq: int = 0

    @property
    def rtp_port(self) -> int:
        return self.io.rtp_port

    @property
    def floor_port(self) -> int:
        return self.io.floor_port


@dataclass(frozen=True)
class TraceEntry:
    direction: str          # "in" (from a client) | "out" (to a client)
    uri: str
    at_ms: int
    data: bytes


class MediaSession:
    def __init__(self, cid: str, floor: fl.FloorControl, payload_type: int,
                 clock: Callable[[], int],
                 io_factory: Callable[[str], EndpointIO],
                 priority_of: Callable[[str], int],
                 codec: rtcp.Codec) -> None:
        self.codec = codec              # PLT-REL-004: the deployment's release
        self.cid = cid
        self.floor = floor
        self.payload_type = payload_type
        self._now = clock
        self._io_factory = io_factory
        self._priority_of = priority_of
        self.endpoints: Dict[str, Endpoint] = {}
        self.trace: Deque[TraceEntry] = deque(maxlen=TRACE_LIMIT)
        self.counters: Dict[str, int] = {
            "rtp_forwarded": 0, "rtp_dropped_not_holder": 0,
            "rtp_dropped_codec": 0, "rtp_dropped_source": 0,
            "rtp_dropped_malformed": 0, "floor_in": 0, "floor_out": 0,
            "floor_malformed": 0, "floor_unexpected": 0,
            "floor_wrong_release": 0,
            "floor_dropped_source": 0}
        self.closed = False
        self._media_seen_holder: Optional[str] = None
        self._media_seen_at = 0
        self._notify_ms = min(MEDIA_NOTIFY_MS,
                              floor.policy.timer(fl.T_END_OF_MEDIA) // 4)

    # -- endpoints -------------------------------------------------------

    def add(self, uri: str) -> Endpoint:
        ep = self.endpoints.get(uri)
        if ep is None:
            ep = Endpoint(uri, self._io_factory(uri))
            self.endpoints[uri] = ep
        return ep

    def set_remote(self, uri: str, rtp: Addr, floor: Optional[Addr]) -> None:
        ep = self.endpoints[uri]
        ep.remote_rtp, ep.remote_floor = rtp, floor
        # A party that becomes reachable after the floor started must learn
        # the current state, or it would never hear Taken/Idle.
        self.sync_to(uri)

    def close(self) -> None:
        self.closed = True
        for ep in self.endpoints.values():
            ep.io.close()

    # -- RTP ---------------------------------------------------------------

    def on_rtp(self, uri: str, src: Addr, data: bytes) -> bool:
        """Forward one packet from `uri`'s relay port. True if forwarded."""
        ep = self.endpoints.get(uri)
        if self.closed or ep is None or ep.remote_rtp is None \
                or src != ep.remote_rtp:
            self.counters["rtp_dropped_source"] += 1
            return False
        if len(data) < RTP_MIN_HEADER or data[0] >> 6 != 2:
            self.counters["rtp_dropped_malformed"] += 1
            return False
        # VP1-MED-001: only the negotiated payload type, which is itself
        # drawn from the profile's declared codecs.
        if data[1] & 0x7F != self.payload_type:
            self.counters["rtp_dropped_codec"] += 1
            return False
        # VP1-MED-004: only the floor holder's media goes anywhere.
        if self.floor.holder != uri:
            self.counters["rtp_dropped_not_holder"] += 1
            return False
        # TS 24.380 6.3.4.4.5 / 6.3.4.5.3: the floor control server learns of
        # the holder's media from the media distributor -- this is it. The
        # first packet after a grant goes at once (it starts T2 and stops
        # T20); after that, at most every MEDIA_NOTIFY_MS, which keeps T1
        # (4 s by default) alive without an event per packet.
        now = self._now()
        if uri != self._media_seen_holder or \
                now - self._media_seen_at >= self._notify_ms:
            self._media_seen_holder, self._media_seen_at = uri, now
            self.apply(self.floor.handle(fl.Event(
                fl.EventType.MEDIA_RECEIVED, participant=uri)))
        for other in self.endpoints.values():
            if other.uri != uri and other.remote_rtp is not None:
                other.io.send_rtp(other.remote_rtp, data)
                self.counters["rtp_forwarded"] += 1
        return True

    # -- floor control in ---------------------------------------------------

    def on_floor(self, uri: str, src: Addr, data: bytes) -> None:
        ep = self.endpoints.get(uri)
        if self.closed or ep is None or ep.remote_floor is None \
                or src != ep.remote_floor:
            self.counters["floor_dropped_source"] += 1
            return
        self._trace("in", uri, data)
        self.counters["floor_in"] += 1
        try:
            msg = self.codec.decode(data)
        except rtcp.ReleaseRefused as exc:
            # Well-formed, but it uses something this release does not define.
            # Counted apart from malformed: "my peer is newer than me" is an
            # operational fact, not a broken sender (PLT-REL-006).
            self.counters["floor_wrong_release"] += 1
            log.warning("floor message from %s outside %s: %s",
                        uri, self.codec.release, exc)
            return
        except rtcp.RtcpError as exc:
            self.counters["floor_malformed"] += 1
            log.warning("malformed floor message from %s: %s", uri, exc)
            return
        t = msg.type
        if t is MsgType.REQUEST:
            self._request(uri)
        elif t is MsgType.RELEASE:
            self.apply(self.floor.handle(fl.Event(
                fl.EventType.FLOOR_RELEASE, participant=uri)))
        elif t is MsgType.ACK:
            self.apply(self.floor.handle(fl.Event(
                fl.EventType.FLOOR_ACK, participant=uri)))
        elif t is MsgType.QUEUE_POSITION_REQUEST:
            self._queue_position(uri)
        else:
            # A server-to-client message arriving from a client.
            self.counters["floor_unexpected"] += 1

    def _request(self, uri: str) -> None:
        try:
            priority = self._priority_of(uri)
        except Exception:  # noqa: BLE001 - IF-PRI failed; do not guess
            log.exception("floor priority unavailable for %s", uri)
            self._send(uri, rtcp.message(
                MsgType.DENY, PLATFORM_SSRC,
                rtcp.f_reject(rtcp.DENY_INTERNAL_ERROR, "priority-unavailable")))
            return
        self.apply(self.floor.handle(fl.Event(
            fl.EventType.FLOOR_REQUEST, participant=uri,
            floor_priority=priority)))

    def _queue_position(self, uri: str) -> None:
        queue = self.floor.queue
        position = queue.index(uri) + 1 if uri in queue else NOT_QUEUED
        self._send(uri, rtcp.message(
            MsgType.QUEUE_POSITION_INFO, PLATFORM_SSRC,
            rtcp.f_queue_info(position, self._safe_priority(uri))))

    # -- floor control out ----------------------------------------------------

    def apply(self, actions: Tuple[fl.Action, ...]) -> None:
        """Send what the machine decided. Timer actions need no handling: the
        machine records its own deadlines and `tick` fires them."""
        A = fl.ActionType
        holder = self.floor.holder
        for a in actions:
            if a.type is A.SEND_GRANTED and a.target:
                # A new grant: the holder's next packet is a "first" packet
                # again, and must reach the machine at once.
                self._media_seen_holder = None
                self._send(a.target, self._granted(a.target, a.duration_ms))
            elif a.type is A.SEND_TAKEN:
                for uri in self._everyone_but(holder):
                    self._send(uri, self._taken(holder))
            elif a.type is A.SEND_IDLE:
                for uri in list(self.endpoints):
                    self._send(uri, self._idle())
            elif a.type is A.SEND_DENY and a.target:
                cause = _DENY_CAUSE.get(a.reason, rtcp.DENY_OTHER) \
                    if a.reason else rtcp.DENY_OTHER
                self._send(a.target, rtcp.message(
                    MsgType.DENY, PLATFORM_SSRC,
                    rtcp.f_reject(cause, a.reason.value if a.reason else "")))
            elif a.type is A.SEND_REVOKE and a.target:
                # Clause 8.2.10.2 causes, a separate namespace from 8.2.6.2
                # (PLT-CONF-AUDIT 3.3). Every revoke used to go out as #255;
                # T2 expiry is #2 and pre-emption #4 (FC-OP-02).
                reason = a.revoke_reason or fl.RevokeReason.OTHER
                self._send(a.target, rtcp.message(
                    MsgType.REVOKE, PLATFORM_SSRC,
                    rtcp.f_reject(_REVOKE_CAUSE[reason], reason.value)))
            elif a.type is A.SEND_QUEUE_POSITION and a.target:
                self._send(a.target, rtcp.message(
                    MsgType.QUEUE_POSITION_INFO, PLATFORM_SSRC,
                    rtcp.f_queue_info(a.queue_position or 0,
                                      self._safe_priority(a.target))))

    def sync_to(self, uri: str) -> None:
        """Tell one party the current floor state (a late answerer, or the
        first delivery after its endpoint became known)."""
        st = self.floor.state
        if st is fl.FloorState.IDLE:
            self._send(uri, self._idle())
        elif st in (fl.FloorState.TAKEN, fl.FloorState.REVOKING):
            holder = self.floor.holder
            if holder == uri:
                self._send(uri, self._granted(uri))
            elif holder is not None:
                self._send(uri, self._taken(holder))

    def tick(self) -> None:
        """Fire the machine's own timers that have come due."""
        now = self._now()
        for _ in range(64):              # bounded: a timer may re-arm itself
            due = sorted((d, n) for n, d in self.floor.running_timers().items()
                         if d <= now)
            if not due:
                return
            _, name = due[0]
            self.apply(self.floor.handle(fl.Event(
                fl.EventType.TIMER_EXPIRY, timer=name)))

    # -- message construction --------------------------------------------------

    def _safe_priority(self, uri: str) -> int:
        try:
            return self._priority_of(uri)
        except Exception:  # noqa: BLE001
            return 0

    def _granted(self, uri: str, duration_ms: Optional[int] = None) -> rtcp.FloorMessage:
        # Duration is T2: all of it on a new grant, what remains of it on a
        # repeated one (6.3.4.4.8 item 1a) -- rounded down, as it always
        # was, so a talker is never told it has more time than it has.
        ms = self.floor.policy.timer(fl.T_STOP_TALKING) if duration_ms is None \
            else duration_ms
        seconds = ms // 1000
        return rtcp.message(MsgType.GRANTED, PLATFORM_SSRC,
                            rtcp.f_priority(self._safe_priority(uri)),
                            rtcp.f_duration(seconds))

    def _taken(self, holder: Optional[str]) -> rtcp.FloorMessage:
        return rtcp.message(MsgType.TAKEN, PLATFORM_SSRC,
                            rtcp.f_granted_party(holder or ""),
                            rtcp.f_permission(True))

    def _idle(self) -> rtcp.FloorMessage:
        return rtcp.message(MsgType.IDLE, PLATFORM_SSRC)

    def _everyone_but(self, holder: Optional[str]) -> List[str]:
        return [u for u in self.endpoints if u != holder]

    def _send(self, uri: str, msg: rtcp.FloorMessage) -> None:
        ep = self.endpoints.get(uri)
        if ep is None or ep.remote_floor is None or self.closed:
            return                      # not reachable (yet): sync_to catches up
        # TS 24.380 clause 8.2.3.10: the Message Sequence Number field "is used
        # to bind a number of Floor Taken or bind a number of Floor Idle
        # messages together", and it appears in those two message tables and
        # nowhere else, in every release from Rel-15 to Rel-20.
        #
        # This used to add it to EVERY outgoing message, so Floor Granted,
        # Floor Deny, Floor Revoke and Floor Queue Position Info each carried a
        # field the specification does not define for them (PLT-CONF-AUDIT
        # CA-13). The trace comparator required it there too, so the tool
        # agreed with the defect instead of catching it.
        # The counter advances only when the field is carried: the procedures
        # say "shall include a Message Sequence Number field with a value
        # increased with 1". Incrementing on every send, as this did, left
        # gaps in the sequence a receiver sees once the field stopped being
        # attached to every message.
        #
        # FC-OP-05: the counter is per endpoint. Clause 8.2.3.10 says the field
        # binds "a number of Floor Taken" messages together, which may mean one
        # value shared across the set sent for a single floor event rather than
        # a per-receiver counter. No receiver can observe the difference, so
        # this is recorded rather than guessed at.
        if msg.type in (MsgType.TAKEN, MsgType.IDLE):
            ep.seq += 1
            msg = rtcp.FloorMessage(
                msg.type, msg.ssrc,
                {**msg.fields, **dict([rtcp.f_sequence(ep.seq)])})
        data = self.codec.encode(msg)
        ep.io.send_floor(ep.remote_floor, data)
        self.counters["floor_out"] += 1
        self._trace("out", uri, data)

    def _trace(self, direction: str, uri: str, data: bytes) -> None:
        self.trace.append(TraceEntry(direction, uri, self._now(), data))


# ==========================================================================
# UDP driver
# ==========================================================================


class UdpEndpointIO:
    """Two UDP sockets for one participant: voice and floor control."""

    def __init__(self, plane: "UdpMediaPlane", session_id: str, uri: str) -> None:
        self._plane = plane
        self._rtp = plane.bind()
        self._floor = plane.bind()
        self.rtp_port = self._rtp.getsockname()[1]
        self.floor_port = self._floor.getsockname()[1]
        self._session_id, self._uri = session_id, uri
        self._stop = threading.Event()
        self._threads = [
            threading.Thread(target=self._loop, args=(self._rtp, "rtp"), daemon=True),
            threading.Thread(target=self._loop, args=(self._floor, "floor"),
                             daemon=True)]
        for t in self._threads:
            t.start()

    def _loop(self, sock: socket.socket, kind: str) -> None:
        while not self._stop.is_set():
            try:
                data, src = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            self._plane.deliver(self._session_id, self._uri, kind, src, data)

    def send_rtp(self, addr: Addr, data: bytes) -> None:
        self._sendto(self._rtp, addr, data)

    def send_floor(self, addr: Addr, data: bytes) -> None:
        self._sendto(self._floor, addr, data)

    @staticmethod
    def _sendto(sock: socket.socket, addr: Addr, data: bytes) -> None:
        try:
            sock.sendto(data, addr)
        except OSError as exc:
            log.warning("send to %s failed: %s", addr, exc)

    def close(self) -> None:
        self._stop.set()
        for s in (self._rtp, self._floor):
            try:
                s.close()
            except OSError:
                pass


class UdpMediaPlane:
    """Owns the relay sockets and the sessions they serve."""

    def __init__(self, address: str, port_range: Optional[Tuple[int, int]],
                 clock: Callable[[], int], release: Release,
                 lock: Optional[threading.RLock] = None) -> None:
        # One codec for the process: every session the plane opens speaks the
        # release the deployment was started with, and no session can be given
        # a different one (PLT-REL-004).
        self.codec = rtcp.Codec(release)
        self.address = address               # advertised in SDP, and bound
        self._range = port_range             # None: OS-assigned (tests)
        self._now = clock
        self.lock = lock or threading.RLock()
        self._sessions: Dict[str, MediaSession] = {}
        self._next = port_range[0] if port_range else 0

    def bind(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        if self._range is None:
            sock.bind((self.address, 0))
            return sock
        lo, hi = self._range
        for _ in range(hi - lo + 1):
            port = self._next
            self._next = lo if self._next >= hi else self._next + 1
            try:
                sock.bind((self.address, port))
                return sock
            except OSError:
                continue
        sock.close()
        raise OSError(f"no free port in {lo}-{hi}")

    def open(self, cid: str, floor: fl.FloorControl, payload_type: int,
             priority_of: Callable[[str], int]) -> MediaSession:
        session = MediaSession(
            cid, floor, payload_type, self._now,
            lambda uri: UdpEndpointIO(self, cid, uri), priority_of, self.codec)
        self._sessions[cid] = session
        return session

    def close(self, cid: str) -> None:
        session = self._sessions.pop(cid, None)
        if session is not None:
            session.close()

    def close_all(self) -> None:
        for cid in list(self._sessions):
            self.close(cid)

    def deliver(self, cid: str, uri: str, kind: str, src: Addr,
                data: bytes) -> None:
        with self.lock:
            session = self._sessions.get(cid)
            if session is None:
                return
            if kind == "rtp":
                session.on_rtp(uri, src, data)
            else:
                session.on_floor(uri, src, data)

    def tick(self) -> None:
        for session in list(self._sessions.values()):
            session.tick()
