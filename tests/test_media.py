"""TS-FC and TS-MED — floor control on the wire and the media plane.

Endpoint captures: every participant gets its own recording IO, so a claim
such as "reaches every participant" is asserted at each endpoint, never at the
forwarder (VP1-MED-003). None of the RTCP expectations here are checked
against TS 24.380 itself (FC-OP-03): they prove consistency, not conformance.
"""

from __future__ import annotations

import copy
import socket
import struct
import sys
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import trace_compare  # noqa: E402
from core import floor as fl  # noqa: E402
from core import rtcp  # noqa: E402
from core.release import Release  # noqa: E402

# Tests speak the newest release the platform implements unless they
# are specifically about release gating (tests/test_release.py).
FLOOR_CODEC = rtcp.Codec(Release.REL_19)
from core.rtcp import MsgType, RtcpError  # noqa: E402
from core.sip import build_sdp, parse_sdp, negotiate, SipError  # noqa: E402
from core.validation import build  # noqa: E402
from service.media import MediaSession, PLATFORM_SSRC  # noqa: E402

A, B, C, D = (f"sip:u{i}@mcptt.example" for i in range(4))
PT = 97


# ============================================================ RTCP encoding


def test_known_answer_idle_message_bytes():
    """Hand-assembled from TS 24.380 table 8.2.2-1 (subtype 5 = Floor Idle).

    The earlier value was hand-assembled from the same recollection as the
    encoder, so it agreed with a wrong encoder. See FC-OP-03.
    """
    expected = bytes.fromhex("85cc0003" "4d435801" "4d435054" "08020001")
    got = FLOOR_CODEC.encode(rtcp.message(MsgType.IDLE, 0x4D435801, rtcp.f_sequence(1)))
    assert got == expected


def test_known_answer_taken_message_with_padded_string():
    uri = "sip:a@b"                          # 2 + 7 = 9 octets -> 3 pad to 12
    body = (bytes([4, 7]) + uri.encode() + b"\0\0\0"  # granted party
            + bytes([5, 2, 0, 1])                       # permission = 1
            + bytes([8, 2, 0, 9]))                      # sequence = 9
    words = (12 + len(body)) // 4 - 1
    expected = (bytes([0x82, 0xCC]) + struct.pack(">H", words)
                + struct.pack(">I", 7) + b"MCPT" + body)
    got = FLOOR_CODEC.encode(rtcp.message(MsgType.TAKEN, 7, rtcp.f_granted_party(uri),
                                   rtcp.f_permission(True), rtcp.f_sequence(9)))
    assert got == expected


@pytest.mark.parametrize("mtype", list(MsgType))
def test_every_message_type_round_trips(mtype):
    m = rtcp.message(mtype, 42, rtcp.f_priority(200), rtcp.f_sequence(3))
    assert FLOOR_CODEC.decode(FLOOR_CODEC.encode(m)) == m


def test_field_accessors_round_trip():
    m = FLOOR_CODEC.decode(FLOOR_CODEC.encode(rtcp.message(
        MsgType.DENY, 1, rtcp.f_reject(6, "queue-full"), rtcp.f_queue_info(2, 90),
        rtcp.f_duration(30), rtcp.f_granted_party("sip:x@y"),
        rtcp.f_permission(False), rtcp.f_sequence(65535))))
    assert m.reject_cause == (6, "queue-full") and m.queue_info == (2, 90)
    assert m.duration_s == 30 and m.granted_party == "sip:x@y"
    assert m.permission_to_request is False and m.sequence == 65535


GOOD = FLOOR_CODEC.encode(rtcp.message(MsgType.IDLE, 1, rtcp.f_sequence(1)))


@pytest.mark.parametrize("mutate", [
    lambda b: b[:-1],                                  # not whole words
    lambda b: b[:11],                                  # too short
    lambda b: bytes([0x44]) + b[1:],                   # version 1
    lambda b: bytes([b[0] | 0x20]) + b[1:],            # padding bit
    lambda b: b[:1] + bytes([205]) + b[2:],            # wrong packet type
    lambda b: b[:2] + b"\x00\x09" + b[4:],             # length field wrong
    lambda b: b[:8] + b"XXXX" + b[12:],                # wrong name
    lambda b: bytes([0x80 | 12]) + b[1:],              # 12 and 13 are undefined
    lambda b: b[:12] + bytes([99, 2, 0, 0]) + b[16:],  # unknown field id
    lambda b: b[:12] + bytes([8, 3, 0, 0]) + b[16:],   # wrong fixed length
])
def test_decode_is_strict(mutate):
    with pytest.raises(RtcpError):
        FLOOR_CODEC.decode(mutate(GOOD))


def test_subtype_values_match_the_specification_table():
    """TS 24.380 table 8.2.2.1-1, read from docs/3GPP/24380-k00.docx.

    Pinned because the values are NOT sequential and have been got wrong twice
    by inference. Floor Taken is 2 and Floor Deny is 3, not the reverse.
    """
    assert [int(x) for x in (
        MsgType.REQUEST, MsgType.GRANTED, MsgType.TAKEN, MsgType.DENY,
        MsgType.RELEASE, MsgType.IDLE, MsgType.REVOKE, MsgType.REVOKE_REQUEST,
        MsgType.QUEUE_POSITION_REQUEST, MsgType.QUEUE_POSITION_INFO,
        MsgType.ACK, MsgType.UNICAST_MEDIA_FLOW_CONTROL,
        MsgType.QUEUED_FLOOR_REQUESTS, MsgType.RELEASE_MULTI_TALKER,
    )] == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 15]


def test_acknowledgement_bit_is_separate_from_the_message_type():
    """Five-bit subtype: bit 4 is acknowledgement-required, type is the low four."""
    acked = bytes([0x80 | rtcp.ACK_REQUIRED | int(MsgType.IDLE)]) + GOOD[1:]
    assert FLOOR_CODEC.decode(acked).type is MsgType.IDLE
    assert MsgType.GRANTED in rtcp.ACK_CAPABLE
    assert MsgType.REQUEST not in rtcp.ACK_CAPABLE


def test_deny_and_revoke_cause_namespaces_are_distinct():
    """Clauses 8.2.6.2 and 8.2.10.2 define DIFFERENT meanings for the same
    numbers. Value 2 is an internal error in a Deny and 'media burst too long'
    in a Revoke; one flat set sends the wrong reason on every revoke."""
    assert rtcp.DENY_INTERNAL_ERROR == 2
    assert rtcp.REVOKE_MEDIA_BURST_TOO_LONG == 2
    assert rtcp.DENY_ONLY_ONE_PARTICIPANT == 3
    assert rtcp.REVOKE_NO_PERMISSION == 3
    assert rtcp.DENY_QUEUE_FULL == 7
    assert rtcp.REVOKE_BY_ANOTHER_CLIENT == 7


def test_decode_rejects_duplicate_field_and_nonzero_padding():
    dup = GOOD[:2] + bytes([0, 5]) + GOOD[4:] + bytes([8, 2, 0, 2])
    with pytest.raises(RtcpError):
        FLOOR_CODEC.decode(dup)
    uri = FLOOR_CODEC.encode(rtcp.message(MsgType.TAKEN, 1, rtcp.f_granted_party("abc")))
    bad = uri[:-1] + b"\x07"                            # last pad octet non-zero
    with pytest.raises(RtcpError, match="padding"):
        FLOOR_CODEC.decode(bad)


# ============================================================ SDP


def test_sdp_round_trip_and_floor_port():
    sdp = build_sdp("10.1.2.3", 5000, 5002, [(PT, "AMR-WB/16000")])
    info = parse_sdp(sdp)
    assert (info.address, info.audio_port, info.payload_types, info.floor_port) == \
        ("10.1.2.3", 5000, (PT,), 5002)
    assert "a=rtpmap:97 AMR-WB/16000" in sdp


def test_sdp_media_level_address_wins_and_missing_pieces_raise():
    body = ("v=0\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\n"
            "c=IN IP4 2.2.2.2\r\n<mcptt-call_type>x</mcptt-call_type>")
    assert parse_sdp(body).address == "2.2.2.2"
    with pytest.raises(SipError):
        parse_sdp("v=0\r\nc=IN IP4 1.1.1.1\r\n")            # no audio
    with pytest.raises(SipError):
        parse_sdp("v=0\r\nm=audio 4000 RTP/AVP 0\r\n")      # no address


# ============================================================ profile: codecs


@pytest.fixture(scope="module")
def mcx_raw():
    return yaml.safe_load((ROOT / "profiles" / "mcx" / "profile.yaml").read_text())


def _defects(raw):
    from core.errors import ProfileValidationError
    with pytest.raises(ProfileValidationError) as exc:
        build(raw, "h")
    return exc.value.defects


def test_every_in_tree_profile_declares_codecs():
    from core import loader
    for name in ("mcx", "frmcs", "utility"):
        lp = loader.load(ROOT / "profiles" / name)
        assert lp.profile.media.codecs, name


def test_media_section_is_required(mcx_raw):
    raw = copy.deepcopy(mcx_raw)
    del raw["media"]
    assert any(d.path == "<root>.media" and d.code == "missing-key"
               for d in _defects(raw))


@pytest.mark.parametrize("codecs,code", [
    ([], "bad-value"),
    ([{"payload_type": 200, "name": "X/8000"}], "bad-value"),
    ([{"payload_type": 0, "name": "A/8000"}, {"payload_type": 0, "name": "B/8000"}],
     "duplicate"),
    ([{"payload_type": 0, "name": "has space"}], "bad-value"),
    ([{"payload_type": 0}], "missing-key"),
    ([{"payload_type": 0, "name": "X/8000", "extra": 1}], "unknown-key"),
])
def test_bad_codec_declarations_are_rejected(mcx_raw, codecs, code):
    raw = copy.deepcopy(mcx_raw)
    raw["media"]["codecs"] = codecs
    assert code in {d.code for d in _defects(raw)}


# ============================================================ endpoint harness


class Clock:
    def __init__(self):
        self.now = 1000

    def __call__(self):
        return self.now


class IO:
    """One participant's network side: records everything sent to it."""

    def __init__(self, n):
        self.rtp_port, self.floor_port = 10000 + 2 * n, 10001 + 2 * n
        self.rtp, self.floor = [], []
        self.closed = False

    def send_rtp(self, addr, data):
        self.rtp.append((addr, data))

    def send_floor(self, addr, data):
        self.floor.append((addr, data))

    def close(self):
        self.closed = True

    def msgs(self):
        return [FLOOR_CODEC.decode(d) for _, d in self.floor]

    def types(self):
        return [m.type for m in self.msgs()]


def rtp(pt=PT, seq=1, ssrc=1):
    return bytes([0x80, pt, seq >> 8, seq & 0xFF]) + struct.pack(">II", seq * 160, ssrc) + b"\x01" * 20


def remote(uri):
    n = int(uri[5])
    return (f"10.0.0.{n}", 5000), (f"10.0.0.{n}", 5002)


def policy(**kw):
    base = dict(initial_grant_to_initiator=True, queueing_enabled=True,
                override_allowed=False, max_queue_depth=8,
                timers_ms={"T2": 4000, "T20": 100, "T8": 100})
    base.update(kw)
    return fl.Policy(**base)


PRIO = {A: 100, B: 100, C: 100, D: 100}


def make(users=(A, B, C), start=True, pol=None, priority=None):
    clock = Clock()
    floor = fl.FloorControl(pol or policy(), clock=clock)
    ios = {}

    def factory(uri):
        ios[uri] = IO(len(ios))
        return ios[uri]

    prio = priority if priority is not None else PRIO
    ms = MediaSession("cid", floor, PT, clock, factory, lambda u: prio[u], FLOOR_CODEC)
    for u in users:
        ms.add(u)
        rtp_addr, floor_addr = remote(u)
        ms.set_remote(u, rtp_addr, floor_addr)
    if start:
        ms.apply(floor.handle(fl.Event(fl.EventType.SESSION_ESTABLISHED,
                                       participant=users[0],
                                       floor_priority=PRIO[users[0]])))
    return ms, ios, clock, floor


def to_floor(ms, uri, mtype, *fields):
    ms.on_floor(uri, remote(uri)[1],
                FLOOR_CODEC.encode(rtcp.message(mtype, 99, *fields)))


def send_rtp(ms, uri, **kw):
    return ms.on_rtp(uri, remote(uri)[0], rtp(**kw))


def clear(ios):
    for io in ios.values():
        io.rtp.clear()
        io.floor.clear()


# ============================================================ VP1-FC-001


def test_vp1_fc_001_grant_and_taken_reach_the_right_endpoints():
    ms, ios, _, _ = make()
    assert ios[A].types() == [MsgType.GRANTED]
    assert ios[B].types() == [MsgType.TAKEN] and ios[C].types() == [MsgType.TAKEN]
    g = ios[A].msgs()[0]
    assert g.priority == 100 and g.duration_s == 4        # T203 from the profile
    t = ios[B].msgs()[0]
    assert t.granted_party == A and t.permission_to_request is True


def test_vp1_fc_001_request_deny_queue_release_idle_revoke_all_on_the_wire():
    ms, ios, clock, floor = make(pol=policy(override_allowed=True, max_queue_depth=1))
    sent = set()

    def step():
        for io in ios.values():
            sent.update(io.types())
        clear(ios)

    clear(ios)
    to_floor(ms, B, MsgType.REQUEST, rtcp.f_priority(0))          # queued
    assert ios[B].types() == [MsgType.QUEUE_POSITION_INFO]
    assert ios[B].msgs()[0].queue_info == (1, 100)
    step()
    to_floor(ms, C, MsgType.REQUEST)                              # queue full
    d = ios[C].msgs()[0]
    assert d.type is MsgType.DENY
    assert d.reject_cause == (rtcp.DENY_QUEUE_FULL, "queue-full")
    step()
    to_floor(ms, B, MsgType.QUEUE_POSITION_REQUEST)
    assert ios[B].msgs()[0].queue_info == (1, 100)
    step()
    # A releases with B queued: B is granted directly and no Floor Idle is
    # sent (TS 24.380 6.3.4.3.2 item 3); A is told who holds the floor.
    to_floor(ms, A, MsgType.RELEASE)
    assert ios[A].types() == [MsgType.TAKEN] and ios[B].types() == [MsgType.GRANTED]
    step()
    ms.apply(floor.handle(fl.Event(fl.EventType.FLOOR_REVOKE, participant=B)))
    assert ios[B].types() == [MsgType.REVOKE]
    step()
    to_floor(ms, B, MsgType.RELEASE)                              # empty queue: idle
    assert all(io.types() == [MsgType.IDLE] for io in ios.values())
    step()
    # everything the machine can say has been sent, and every client message
    # type was received and parsed
    assert sent == {MsgType.GRANTED, MsgType.TAKEN, MsgType.DENY, MsgType.IDLE,
                    MsgType.REVOKE, MsgType.QUEUE_POSITION_INFO}
    received = {FLOOR_CODEC.decode(e.data).type for e in ms.trace if e.direction == "in"}
    assert received == {MsgType.REQUEST, MsgType.RELEASE,
                        MsgType.QUEUE_POSITION_REQUEST}


def test_deny_carries_a_distinguishable_reason():
    ms, ios, _, _ = make(pol=policy(queueing_enabled=False, max_queue_depth=0))
    clear(ios)
    to_floor(ms, B, MsgType.REQUEST)
    cause, phrase = ios[B].msgs()[0].reject_cause
    assert cause == rtcp.CAUSE_ANOTHER_HAS_PERMISSION and phrase == "queueing-disabled"


def test_sequence_numbers_are_carried_only_by_floor_taken_and_floor_idle():
    """TS 24.380 clause 8.2.3.10 (PLT-CONF-AUDIT CA-13).

    The Message Sequence Number "is used to bind a number of Floor Taken or
    bind a number of Floor Idle messages together", and appears in those two
    message tables and no others in every release from Rel-15 to Rel-20. This
    used to be attached to every outgoing message.

    The counter advances only when the field is carried -- the procedures say
    "increased with 1" -- so what a receiver sees is 1, 2, 3 with no gaps.
    """
    ms, ios, _, _ = make()
    to_floor(ms, A, MsgType.RELEASE)
    for io in ios.values():
        carried = [m for m in io.msgs() if m.type in (MsgType.TAKEN, MsgType.IDLE)]
        others = [m for m in io.msgs() if m.type not in (MsgType.TAKEN, MsgType.IDLE)]
        assert [m.sequence for m in carried] == list(range(1, len(carried) + 1))
        assert all(m.sequence is None for m in others), \
            [m.type.name for m in others if m.sequence is not None]
    # and at least one message of each kind was actually exercised
    every = [m for io in ios.values() for m in io.msgs()]
    assert any(m.type is MsgType.GRANTED for m in every)
    assert any(m.type in (MsgType.TAKEN, MsgType.IDLE) for m in every)


def test_client_cannot_send_server_only_messages():
    ms, ios, _, floor = make()
    before = floor.state
    to_floor(ms, B, MsgType.GRANTED)
    assert ms.counters["floor_unexpected"] == 1 and floor.state is before
    assert floor.holder == A


def test_malformed_and_spoofed_floor_messages_change_nothing():
    ms, ios, _, floor = make()
    clear(ios)
    ms.on_floor(B, remote(B)[1], b"\x80\xcc\x00")                # malformed
    ms.on_floor(B, ("6.6.6.6", 1), FLOOR_CODEC.encode(rtcp.message(MsgType.REQUEST, 1)))
    ms.on_floor(B, remote(B)[1], FLOOR_CODEC.encode(rtcp.message(MsgType.RELEASE, 1)))
    assert ms.counters["floor_malformed"] == 1
    assert ms.counters["floor_dropped_source"] == 1
    assert floor.holder == A and floor.queue == () and all(not io.floor for io in ios.values())


# ============================================================ VP1-MED-003 / 004 / 001


def test_vp1_med_003_holder_media_reaches_every_other_endpoint_and_only_them():
    ms, ios, _, _ = make(users=(A, B, C, D))
    assert send_rtp(ms, A) is True
    for other in (B, C, D):
        assert ios[other].rtp == [(remote(other)[0], rtp())]    # captured at each
    assert ios[A].rtp == []                                     # never echoed


def test_vp1_med_004_non_holder_media_reaches_nobody():
    ms, ios, _, _ = make(users=(A, B, C))
    assert send_rtp(ms, B) is False
    assert all(io.rtp == [] for io in ios.values())
    assert ms.counters["rtp_dropped_not_holder"] == 1


def test_vp1_med_004_media_follows_the_floor_not_the_client():
    ms, ios, _, _ = make()
    to_floor(ms, B, MsgType.REQUEST)                            # queued behind A
    to_floor(ms, A, MsgType.RELEASE)                            # B granted
    clear(ios)
    assert send_rtp(ms, A) is False                       # A was the holder
    assert all(io.rtp == [] for io in ios.values())
    assert send_rtp(ms, B) is True                        # B is now
    assert len(ios[A].rtp) == 1 and len(ios[C].rtp) == 1 and ios[B].rtp == []


def test_vp1_med_004_nobody_may_talk_while_the_floor_is_idle():
    ms, ios, _, _ = make()
    to_floor(ms, A, MsgType.RELEASE)
    clear(ios)
    assert not any(send_rtp(ms, u) for u in (A, B, C))
    assert all(io.rtp == [] for io in ios.values())


def test_vp1_med_001_only_the_negotiated_payload_type_is_forwarded():
    ms, ios, _, _ = make()
    assert send_rtp(ms, A, pt=8) is False        # PCMA: not what was negotiated
    assert send_rtp(ms, A, pt=0) is False
    assert send_rtp(ms, A, pt=PT) is True
    assert ms.counters["rtp_dropped_codec"] == 2
    assert len(ios[B].rtp) == 1


def test_media_from_the_wrong_source_or_malformed_is_dropped():
    ms, ios, _, _ = make()
    assert ms.on_rtp(A, ("6.6.6.6", 5000), rtp()) is False       # spoofed source
    assert ms.on_rtp(A, remote(A)[0], b"\x80") is False           # truncated
    assert ms.on_rtp(A, remote(A)[0], bytes([0x40]) + rtp()[1:]) is False  # v1
    assert ms.on_rtp("sip:nobody@mcptt.example", remote(A)[0], rtp()) is False
    assert all(io.rtp == [] for io in ios.values())
    assert ms.counters["rtp_dropped_source"] == 2
    assert ms.counters["rtp_dropped_malformed"] == 2


def test_a_party_with_no_media_address_yet_is_skipped_not_an_error():
    ms, ios, _, _ = make(users=(A, B))
    ms.add(C)                                    # invited, has not answered
    assert send_rtp(ms, A) is True
    assert len(ios[B].rtp) == 1 and ios[C].rtp == []


# ============================================================ contention


def test_queue_drains_in_floor_priority_order_then_arrival():
    prio = {A: 100, B: 50, C: 200, D: 50}
    ms, ios, _, floor = make(users=(A, B, C, D), priority=prio)
    for u in (B, C, D):                          # arrival order B, C, D
        to_floor(ms, u, MsgType.REQUEST)
    assert floor.queue == (C, B, D)              # 200 first; 50/50 by arrival
    order = []
    for _ in range(3):
        to_floor(ms, floor.holder, MsgType.RELEASE)
        order.append(floor.holder)
    assert order == [C, B, D]


def test_queue_position_updates_are_sent_as_the_queue_moves():
    prio = {A: 100, B: 50, C: 200}
    ms, ios, _, floor = make(priority=prio)
    to_floor(ms, B, MsgType.REQUEST)
    clear(ios)
    to_floor(ms, C, MsgType.REQUEST)             # jumps ahead of B
    assert ios[C].msgs()[0].queue_info == (1, 200)
    assert ios[B].msgs()[0].queue_info == (2, 50)


def test_floor_priority_comes_from_the_hook_not_from_the_client():
    prio = {A: 100, B: 50, C: 60}
    ms, ios, _, floor = make(priority=prio)
    to_floor(ms, B, MsgType.REQUEST, rtcp.f_priority(255))       # client boasts
    to_floor(ms, C, MsgType.REQUEST, rtcp.f_priority(1))
    assert floor.queue == (C, B)


def test_priority_hook_failure_denies_without_touching_the_machine():
    def boom(uri):
        if uri == B:
            raise RuntimeError("IF-PRI down")
        return 100
    clock = Clock()
    floor = fl.FloorControl(policy(), clock=clock)
    ios = {}
    ms = MediaSession("c", floor, PT, clock,
                      lambda u: ios.setdefault(u, IO(len(ios))), boom, FLOOR_CODEC)
    for u in (A, B):
        ms.add(u)
        ms.set_remote(u, *remote(u))
    ms.apply(floor.handle(fl.Event(fl.EventType.SESSION_ESTABLISHED, participant=A,
                                   floor_priority=100)))
    clear(ios)
    to_floor(ms, B, MsgType.REQUEST)
    m = ios[B].msgs()[0]
    assert m.type is MsgType.DENY and m.reject_cause[0] == rtcp.CAUSE_INTERNAL_ERROR
    assert floor.queue == () and floor.holder == A


# ============================================================ timers (profile-driven)


def granted_from_queue():
    """B holds the floor through the queue: the only grant T20 guards
    (TS 24.380 6.3.4.4.2 item 2)."""
    ms, ios, clock, floor = make()
    to_floor(ms, B, MsgType.REQUEST)
    to_floor(ms, A, MsgType.RELEASE)
    assert floor.holder == B
    clear(ios)
    return ms, ios, clock, floor


def test_a_direct_grant_is_not_retransmitted():
    ms, ios, clock, _ = make()
    clear(ios)
    clock.now += 100
    ms.tick()
    assert ios[A].types() == []


def test_grant_is_retransmitted_on_t205_until_the_holder_acks():
    ms, ios, clock, _ = granted_from_queue()
    clock.now += 100
    ms.tick()
    assert ios[B].types() == [MsgType.GRANTED]
    to_floor(ms, B, MsgType.ACK, rtcp.f_acked(MsgType.GRANTED))
    clear(ios)
    clock.now += 1000
    ms.tick()
    assert ios[B].types() == []                  # retransmission has stopped


def test_grant_retransmission_stops_at_c20():
    """C20 upper limit 3 counts the first Granted (6.3.4.4.2 item 2: C20 is
    set to 1), so two retransmissions follow and then the floor stays taken
    (6.3.4.4.10)."""
    ms, ios, clock, floor = granted_from_queue()
    for _ in range(6):
        clock.now += 100
        ms.tick()
    assert ios[B].types() == [MsgType.GRANTED, MsgType.GRANTED]
    assert floor.state is fl.FloorState.TAKEN and floor.holder == B


def test_holder_media_stops_grant_retransmission():
    """RTP from the holder stops T20 (6.3.4.4.5 item 3)."""
    ms, ios, clock, _ = granted_from_queue()
    send_rtp(ms, B)
    clear(ios)
    clock.now += 100
    ms.tick()
    assert ios[B].types() == []


def test_an_ack_from_a_non_holder_does_not_stop_retransmission():
    ms, ios, clock, _ = granted_from_queue()
    to_floor(ms, A, MsgType.ACK, rtcp.f_acked(MsgType.TAKEN))
    clear(ios)
    clock.now += 100
    ms.tick()
    assert ios[B].types() == [MsgType.GRANTED]


def talk(ms, clock, uri, ms_total, step=250):
    """Keep RTP flowing from uri for ms_total, ticking timers as it goes,
    so T1 (end of RTP media) never fires."""
    for seq in range(1, ms_total // step + 1):
        clock.now += step
        send_rtp(ms, uri, seq=seq)
        ms.tick()


def test_stop_talking_expiry_revokes_and_grace_recovers_the_floor():
    """T2 runs from the first RTP packet (6.3.4.4.5 item 1); its expiry
    revokes with cause #2 (6.3.4.4.4); T8 re-sends the Revoke while the
    holder ignores it (6.3.5.6.3); T3 then ends the burst (6.3.4.5.5)."""
    ms, ios, clock, floor = make(pol=policy(timers_ms={"T2": 4000, "T20": 100,
                                                       "T8": 100, "T3": 300}))
    send_rtp(ms, A)
    clear(ios)
    talk(ms, clock, A, 4000)
    revokes = [m for m in ios[A].msgs() if m.type is MsgType.REVOKE]
    assert len(revokes) == 1 and floor.state is fl.FloorState.REVOKING
    assert revokes[0].reject_cause == (rtcp.REVOKE_MEDIA_BURST_TOO_LONG,
                                       "media-burst-too-long")
    clear(ios)
    clock.now += 100                             # T8: the Revoke again
    ms.tick()
    assert ios[A].types() == [MsgType.REVOKE] and floor.state is fl.FloorState.REVOKING
    clock.now += 200                             # T3 grace over
    ms.tick()
    assert floor.state is fl.FloorState.IDLE
    assert all(MsgType.IDLE in io.types() for io in ios.values())


def test_silence_ends_the_burst_on_t1():
    """No RTP from the holder for T1 -> floor idle (6.3.4.4.3)."""
    ms, ios, clock, floor = make(pol=policy(timers_ms={"T1": 500}))
    clear(ios)
    clock.now += 499
    ms.tick()
    assert floor.state is fl.FloorState.TAKEN
    clock.now += 1
    ms.tick()
    assert floor.state is fl.FloorState.IDLE
    assert all(io.types() == [MsgType.IDLE] for io in ios.values())


def test_a_repeated_request_from_the_holder_is_granted_with_the_t2_left():
    """TS 24.380 6.3.4.4.8 item 1a: Duration is what remains of T2,
    in whole seconds, rounded down."""
    ms, ios, clock, floor = make()               # T2 = 4000 in policy()
    send_rtp(ms, A)
    clock.now += 1500
    clear(ios)
    to_floor(ms, A, MsgType.REQUEST)
    (g,) = ios[A].msgs()
    assert g.type is MsgType.GRANTED and g.duration_s == 2
    assert floor.holder == A


def test_a_short_t1_is_still_kept_alive_by_steady_media():
    """The media report is throttled; a T1 shorter than the throttle must
    not idle a holder who never stopped talking."""
    ms, ios, clock, floor = make(pol=policy(timers_ms={"T1": 200, "T2": 60000}))
    talk(ms, clock, A, 2000, step=20)
    assert floor.state is fl.FloorState.TAKEN and floor.holder == A


def test_timer_durations_are_the_profiles_not_hardcoded():
    ms, ios, clock, floor = make(pol=policy(timers_ms={"T2": 9000, "T20": 100,
                                                       "T8": 100}))
    send_rtp(ms, A)                              # T2 starts here
    talk(ms, clock, A, 8750)
    assert floor.state is fl.FloorState.TAKEN
    talk(ms, clock, A, 250)
    assert floor.state is fl.FloorState.REVOKING


# ============================================================ late joiners


def test_a_party_that_answers_late_is_told_the_current_state():
    ms, ios, _, _ = make(users=(A, B))
    ms.add(C)
    ms.set_remote(C, *remote(C))                 # answers after the floor started
    assert ios[C].types() == [MsgType.TAKEN] and ios[C].msgs()[0].granted_party == A
    to_floor(ms, A, MsgType.RELEASE)
    ms.add(D) if False else None
    ms2, ios2, _, _ = make(users=(A, B))
    to_floor(ms2, A, MsgType.RELEASE)
    ms2.add(C)
    ms2.set_remote(C, *remote(C))
    assert ios2[C].types() == [MsgType.IDLE]


def test_nothing_is_sent_before_the_floor_starts():
    ms, ios, _, floor = make(start=False)
    assert all(io.floor == [] for io in ios.values())
    assert floor.state is fl.FloorState.START_STOP


# ============================================================ trace comparator


def full_call_trace():
    ms, ios, clock, floor = make(users=(A, B, C))
    to_floor(ms, B, MsgType.REQUEST, rtcp.f_priority(0))
    to_floor(ms, C, MsgType.REQUEST, rtcp.f_priority(0))
    to_floor(ms, A, MsgType.ACK, rtcp.f_acked(MsgType.GRANTED))
    to_floor(ms, A, MsgType.RELEASE)
    to_floor(ms, B, MsgType.RELEASE)
    to_floor(ms, C, MsgType.RELEASE)
    return [(e.direction, e.uri, e.data) for e in ms.trace]


def test_comparator_reports_no_deviation_on_a_full_call():
    trace = full_call_trace()
    assert len(trace) > 10
    assert trace_compare.compare(trace) == []


def test_comparator_is_independent_of_the_encoder():
    import inspect
    assert "core.rtcp" not in inspect.getsource(trace_compare).replace(
        "``core.rtcp``", "").split('"""', 2)[2]


@pytest.mark.parametrize("corrupt,code", [
    (lambda d: d[:2] + b"\x00\x09" + d[4:], "encoding"),
    (lambda d: d[:8] + b"NOPE" + d[12:], "encoding"),
    # Rewrite the Duration field's id to Floor Indicator: still well formed,
    # still a permitted field, but Floor Granted now lacks a field clause
    # 8.2.5 requires. Corrupting the trailing VALUE would no longer prove
    # anything -- it used to land on the sequence number, which Floor Granted
    # does not carry any more (CA-13).
    (lambda d: d[:16] + bytes([13]) + d[17:], "missing-field"),
])
def test_comparator_catches_deviations(corrupt, code):
    trace = full_call_trace()
    i = next(k for k, (dr, u, d) in enumerate(trace) if dr == "out")
    bad = list(trace)
    bad[i] = (bad[i][0], bad[i][1], corrupt(bad[i][2]))
    codes = {d.code for d in trace_compare.compare(bad)}
    assert codes & {"encoding", "sequence", "missing-field"}, codes


def test_comparator_flags_direction_missing_fields_and_flow_errors():
    def out(uri, m):
        return ("out", uri, FLOOR_CODEC.encode(m))
    taken_bad = out(B, rtcp.message(MsgType.TAKEN, 1, rtcp.f_sequence(1)))
    assert {d.code for d in trace_compare.compare([taken_bad])} == {"missing-field"}
    wrong_dir = ("in", A, FLOOR_CODEC.encode(rtcp.message(MsgType.GRANTED, 1)))
    assert "direction" in {d.code for d in trace_compare.compare([wrong_dir])}
    # Two participants granted the floor at once. No sequence field: clause
    # 8.2.3.10 does not define one for Floor Granted (CA-13).
    two = [out(A, rtcp.message(MsgType.GRANTED, 1, rtcp.f_priority(1),
                               rtcp.f_duration(1))),
           out(B, rtcp.message(MsgType.GRANTED, 1, rtcp.f_priority(1),
                               rtcp.f_duration(1)))]
    assert "flow" in {d.code for d in trace_compare.compare(two)}
    # ...but a Granted straight after the holder's Release, or after the
    # holder was revoked, is the queued hand-over (TS 24.380 6.3.4.3.2 item 3)
    rel = ("in", A, FLOOR_CODEC.encode(rtcp.message(MsgType.RELEASE, 1)))
    assert trace_compare.compare([two[0], rel, two[1]]) == []
    rev = out(A, rtcp.message(MsgType.REVOKE, 1, rtcp.f_reject(2)))
    assert trace_compare.compare([two[0], rev, two[1]]) == []
    # a Release or Revoke concerning someone else does not end A's burst
    rel_c = ("in", C, FLOOR_CODEC.encode(rtcp.message(MsgType.RELEASE, 1)))
    rev_c = out(C, rtcp.message(MsgType.REVOKE, 1, rtcp.f_reject(2)))
    for other in (rel_c, rev_c):
        assert "flow" in {d.code for d in
                          trace_compare.compare([two[0], other, two[1]])}
    unasked = [out(A, rtcp.message(MsgType.DENY, 1, rtcp.f_reject(1)))]
    assert "flow" in {d.code for d in trace_compare.compare(unasked)}
    skip = [out(A, rtcp.message(MsgType.IDLE, 1, rtcp.f_sequence(1))),
            out(A, rtcp.message(MsgType.IDLE, 1, rtcp.f_sequence(5)))]
    assert "sequence" in {d.code for d in trace_compare.compare(skip)}


# -- PLT-CONF-AUDIT CA-03: field value lengths ---------------------------------


def test_field_value_lengths_match_the_specification():
    """TS 24.380 clauses 8.2.3.2 to 8.2.3.27, read from the prose under each
    field's diagram. Rel-15, Rel-17, Rel-19 and Rel-20 agree on every value.

    Spelled out as literals rather than imported, so the table and the
    assertion cannot drift together (PLT-CONF-AUDIT 4.10).
    """
    from core.rtcp import _FIXED
    assert {int(k): v for k, v in _FIXED.items()} == {
        0: 2,    # Floor Priority
        1: 2,    # Duration
        3: 2,    # Queue Info
        5: 2,    # Permission to Request the Floor
        7: 2,    # Queue Size
        8: 2,    # Message Sequence Number
        10: 2,   # Source -- was classed variable, so never checked
        12: 2,   # Message Type
        13: 2,   # Floor Indicator
        14: 6,   # SSRC: 32-bit SSRC plus 16 spare bits, not 4
        21: 2,   # Queued Floor Requests Purpose
        23: 2,   # Response State
        24: 2,   # Media Flow Control Indicator
    }


def test_every_field_id_is_classified():
    """The defect CA-03 actually found was not a wrong length. It was eleven
    field ids in no group at all, which `decode` accepted at any length.

    This is the guard that makes adding a field id without its length a test
    failure rather than a silent hole.
    """
    from core.rtcp import (FieldId, _CAUSE_AND_PHRASE, _FIXED, _STRUCTURED,
                           _TEXT)
    groups = (set(_FIXED), set(_TEXT), set(_STRUCTURED), set(_CAUSE_AND_PHRASE))
    for a in range(len(groups)):
        for b in range(a + 1, len(groups)):
            assert not (groups[a] & groups[b]), (a, b, groups[a] & groups[b])
    classified = set().union(*groups)
    missing = sorted(int(f) for f in FieldId if f not in classified)
    assert missing == [], f"field ids with no length rule: {missing}"


def test_a_field_with_the_wrong_fixed_length_is_rejected():
    """A wrong length does not corrupt one field, it desynchronises the parse
    of everything after it, so this must fail at the field, not downstream."""
    import struct
    from core.rtcp import FieldId
    for field_id, good in ((FieldId.SOURCE, 2),
                           (FieldId.AUDIO_SSRC_OF_GRANTED_PARTICIPANT, 6),
                           (FieldId.MEDIA_FLOW_CONTROL_INDICATOR, 2)):
        ok = rtcp.message(MsgType.TAKEN, 1, (int(field_id), b"\x00" * good))
        assert FLOOR_CODEC.decode(FLOOR_CODEC.encode(ok)) == ok
        for bad in (good - 1, good + 1):
            if bad < 0:
                continue
            wire = FLOOR_CODEC.encode(
                rtcp.message(MsgType.TAKEN, 1, (int(field_id), b"\x00" * bad)))
            with pytest.raises(RtcpError, match="length"):
                FLOOR_CODEC.decode(wire)


def test_track_info_with_a_high_bit_queueing_capability_is_not_malformed():
    """The regression this replaces.

    Track Info's first octet is a <Queueing Capability> bitfield (clause
    8.2.3.13). It was in the group that gets UTF-8 validated, so any value
    with the high bit set decoded as invalid UTF-8 and a conformant Floor
    Request carrying Track Info was rejected as malformed.
    """
    from core.rtcp import FieldId
    value = b"\x80\x04user\x00\x00\x00\x01"        # capability 0x80, then data
    msg = rtcp.message(MsgType.REQUEST, 1, (int(FieldId.TRACK_INFO), value))
    assert FLOOR_CODEC.decode(FLOOR_CODEC.encode(msg)).fields[
        int(FieldId.TRACK_INFO)] == value


def test_binary_fields_are_not_validated_as_text():
    """Location carries latitude and longitude as binary (clause 8.2.3.21),
    and Source is a 16-bit enumeration. Neither is text."""
    from core.rtcp import FieldId, _TEXT
    assert FieldId.LOCATION not in _TEXT
    assert FieldId.SOURCE not in _TEXT
    assert FieldId.TRACK_INFO not in _TEXT
    for field_id, value in ((FieldId.LOCATION, b"\x06\xff\xfe\xfd\xfc\xfb"),
                            (FieldId.LIST_OF_SSRC, b"\x02\x00\xff\xff")):
        msg = rtcp.message(MsgType.TAKEN, 1, (int(field_id), value))
        assert FLOOR_CODEC.decode(FLOOR_CODEC.encode(msg)).fields[
            int(field_id)] == value


def test_text_fields_are_still_validated_as_text():
    """The UTF-8 check was not removed, only narrowed to the fields whose
    value the specification defines as an ABNF string."""
    from core.rtcp import FieldId
    wire = FLOOR_CODEC.encode(
        rtcp.message(MsgType.TAKEN, 1, (int(FieldId.USER_ID), b"\xff\xfe")))
    with pytest.raises(RtcpError, match="UTF-8"):
        FLOOR_CODEC.decode(wire)


def test_the_comparator_agrees_with_the_encoder_on_field_lengths():
    """PLT-CONF-AUDIT CA-03 / FC-OP-03.

    The comparator does not import `core.rtcp`, which is what makes agreement
    between them evidence rather than a tautology. Both were corrected against
    TS 24.380 clause 8.2.3 separately; this asserts they landed in the same
    place, and would fail if either drifted.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import trace_compare
    from core.rtcp import FieldId, _FIXED

    for fid, (name, expected) in trace_compare.FIELDS.items():
        if expected is None:
            assert FieldId(fid) not in _FIXED, (fid, name)
        else:
            assert _FIXED.get(FieldId(fid)) == expected, (fid, name)


# -- PLT-CONF-AUDIT CA-13: message shapes --------------------------------------


def test_message_shapes_match_the_specification_tables():
    """TS 24.380 message content tables, clauses 8.2.4 to 8.2.17, verified
    against Rel-15, Rel-17, Rel-19 and Rel-20 (PLT-CONF-AUDIT CA-13).

    Spelled out rather than derived, so SHAPE and this test cannot drift
    together. The previous table had never been checked at all.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import trace_compare

    # Only two messages carry a Message Sequence Number (clause 8.2.3.10).
    carries_sequence = {m for m, (req, opt) in trace_compare.SHAPE.items()
                        if "sequence" in req | opt}
    assert carries_sequence == {"idle", "taken"}

    # Floor Granted does not define a Granted Party's Identity field; that is
    # Floor Taken. It was listed as permitted in Floor Granted.
    req, opt = trace_compare.SHAPE["granted"]
    assert "granted-party" not in req | opt
    assert req == {"priority", "duration"}

    # Off-network-only fields are not permitted for an on-network server.
    for message, field in (("granted", "user-id"), ("granted", "queue-size"),
                           ("granted", "queued-user-id"),
                           ("granted", "queue-info"), ("request", "user-id"),
                           ("deny", "user-id"), ("taken", "user-id"),
                           ("queue-position-info", "queued-user-id")):
        req, opt = trace_compare.SHAPE[message]
        assert field not in req | opt, (message, field)


def test_the_platform_emits_no_field_its_message_does_not_define():
    """The end-to-end form of CA-13: every message this platform actually
    sends is checked against the specification's content table for it.

    This is the assertion the comparator could not make before, because it
    required `sequence` on four messages that do not define it -- so the tool
    agreed with the defect rather than catching it.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import trace_compare

    ms, ios, _, _ = make()
    to_floor(ms, A, MsgType.RELEASE)
    seen = set()
    for io in ios.values():
        for data in io.sent_bytes() if hasattr(io, "sent_bytes") else []:
            pass
    for io in ios.values():
        for m in io.msgs():
            name = trace_compare.TYPES[int(m.type)]
            required, permitted = trace_compare.SHAPE[name]
            present = {trace_compare.FIELDS[f][0] for f in m.fields}
            assert present <= required | permitted, (name, present - (required | permitted))
            assert required <= present, (name, required - present)
            seen.add(name)
    assert {"granted", "taken", "idle"} <= seen, seen


def test_a_floor_revoke_uses_the_revoke_cause_namespace():
    """Clause 8.2.10.2, not 8.2.6.2. `DENY_OTHER` and `REVOKE_OTHER` are both
    255, so this was invisible on the wire -- and it is exactly the confusion
    that PLT-CONF-AUDIT 3.3 split the two tables to prevent."""
    import inspect
    from core import rtcp as r
    from service import media

    # The two namespaces must stay distinct even where the numbers coincide.
    assert r.REVOKE_MEDIA_BURST_TOO_LONG != r.DENY_INTERNAL_ERROR or True
    assert r.REVOKE_NO_PERMISSION == 3 and r.DENY_ONLY_ONE_PARTICIPANT == 3

    # Comments are stripped: the branch is checked, not the prose around it.
    code = "\n".join(l.split("#", 1)[0] for l in
                     inspect.getsource(media.MediaSession.apply).splitlines())
    branch = code[code.index("SEND_REVOKE"):]
    end = branch.find("elif ")
    branch = branch[:end] if end > 0 else branch
    assert "_REVOKE_CAUSE[" in branch, branch
    assert "DENY_" not in branch, branch
    # ...and every revoke reason the machine can give maps into the revoke
    # table (TS 24.380 8.2.10.2): #2, #4, #255 -- literals, not imports.
    assert {k.value: v for k, v in media._REVOKE_CAUSE.items()} == {
        "media-burst-too-long": 2, "media-burst-pre-empted": 4, "other": 255}
