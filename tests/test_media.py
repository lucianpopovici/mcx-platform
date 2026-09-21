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
    got = rtcp.encode(rtcp.message(MsgType.IDLE, 0x4D435801, rtcp.f_sequence(1)))
    assert got == expected


def test_known_answer_taken_message_with_padded_string():
    uri = "sip:a@b"                          # 2 + 7 = 9 octets -> 3 pad to 12
    body = (bytes([4, 7]) + uri.encode() + b"\0\0\0"  # granted party
            + bytes([5, 2, 0, 1])                       # permission = 1
            + bytes([8, 2, 0, 9]))                      # sequence = 9
    words = (12 + len(body)) // 4 - 1
    expected = (bytes([0x82, 0xCC]) + struct.pack(">H", words)
                + struct.pack(">I", 7) + b"MCPT" + body)
    got = rtcp.encode(rtcp.message(MsgType.TAKEN, 7, rtcp.f_granted_party(uri),
                                   rtcp.f_permission(True), rtcp.f_sequence(9)))
    assert got == expected


@pytest.mark.parametrize("mtype", list(MsgType))
def test_every_message_type_round_trips(mtype):
    m = rtcp.message(mtype, 42, rtcp.f_priority(200), rtcp.f_sequence(3))
    assert rtcp.decode(rtcp.encode(m)) == m


def test_field_accessors_round_trip():
    m = rtcp.decode(rtcp.encode(rtcp.message(
        MsgType.DENY, 1, rtcp.f_reject(6, "queue-full"), rtcp.f_queue_info(2, 90),
        rtcp.f_duration(30), rtcp.f_granted_party("sip:x@y"),
        rtcp.f_permission(False), rtcp.f_sequence(65535))))
    assert m.reject_cause == (6, "queue-full") and m.queue_info == (2, 90)
    assert m.duration_s == 30 and m.granted_party == "sip:x@y"
    assert m.permission_to_request is False and m.sequence == 65535


GOOD = rtcp.encode(rtcp.message(MsgType.IDLE, 1, rtcp.f_sequence(1)))


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
        rtcp.decode(mutate(GOOD))


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
    assert rtcp.decode(acked).type is MsgType.IDLE
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
        rtcp.decode(dup)
    uri = rtcp.encode(rtcp.message(MsgType.TAKEN, 1, rtcp.f_granted_party("abc")))
    bad = uri[:-1] + b"\x07"                            # last pad octet non-zero
    with pytest.raises(RtcpError, match="padding"):
        rtcp.decode(bad)


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
        return [rtcp.decode(d) for _, d in self.floor]

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
    ms = MediaSession("cid", floor, PT, clock, factory, lambda u: prio[u])
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
                rtcp.encode(rtcp.message(mtype, 99, *fields)))


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
    to_floor(ms, A, MsgType.RELEASE)                              # idle, B granted
    assert ios[A].types()[0] is MsgType.IDLE and MsgType.GRANTED in ios[B].types()
    step()
    ms.apply(floor.handle(fl.Event(fl.EventType.FLOOR_REVOKE, participant=B)))
    assert ios[B].types() == [MsgType.REVOKE]
    step()
    # everything the machine can say has been sent, and every client message
    # type was received and parsed
    assert sent == {MsgType.GRANTED, MsgType.TAKEN, MsgType.DENY, MsgType.IDLE,
                    MsgType.REVOKE, MsgType.QUEUE_POSITION_INFO}
    received = {rtcp.decode(e.data).type for e in ms.trace if e.direction == "in"}
    assert received == {MsgType.REQUEST, MsgType.RELEASE,
                        MsgType.QUEUE_POSITION_REQUEST}


def test_deny_carries_a_distinguishable_reason():
    ms, ios, _, _ = make(pol=policy(queueing_enabled=False, max_queue_depth=0))
    clear(ios)
    to_floor(ms, B, MsgType.REQUEST)
    cause, phrase = ios[B].msgs()[0].reject_cause
    assert cause == rtcp.CAUSE_ANOTHER_HAS_PERMISSION and phrase == "queueing-disabled"


def test_sequence_numbers_are_per_endpoint_and_increase():
    ms, ios, _, _ = make()
    to_floor(ms, A, MsgType.RELEASE)
    for io in ios.values():
        seqs = [m.sequence for m in io.msgs()]
        assert seqs == list(range(1, len(seqs) + 1))


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
    ms.on_floor(B, ("6.6.6.6", 1), rtcp.encode(rtcp.message(MsgType.REQUEST, 1)))
    ms.on_floor(B, remote(B)[1], rtcp.encode(rtcp.message(MsgType.RELEASE, 1)))
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
                      lambda u: ios.setdefault(u, IO(len(ios))), boom)
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


def test_grant_is_retransmitted_on_t205_until_the_holder_acks():
    ms, ios, clock, _ = make()
    clear(ios)
    clock.now += 100
    ms.tick()
    assert ios[A].types() == [MsgType.GRANTED]
    clock.now += 100
    ms.tick()
    assert ios[A].types() == [MsgType.GRANTED, MsgType.GRANTED]
    to_floor(ms, A, MsgType.ACK, rtcp.f_acked(MsgType.GRANTED))
    clear(ios)
    clock.now += 1000
    ms.tick()
    assert ios[A].types() == []                  # retransmission has stopped


def test_an_ack_from_a_non_holder_does_not_stop_retransmission():
    ms, ios, clock, _ = make()
    to_floor(ms, B, MsgType.ACK, rtcp.f_acked(MsgType.TAKEN))
    clear(ios)
    clock.now += 100
    ms.tick()
    assert ios[A].types() == [MsgType.GRANTED]


def test_stop_talking_expiry_revokes_and_revoke_timer_recovers_the_floor():
    ms, ios, clock, floor = make()
    to_floor(ms, A, MsgType.ACK)
    clear(ios)
    clock.now += 4000                            # T203 from the profile
    ms.tick()
    assert MsgType.REVOKE in ios[A].types() and floor.state is fl.FloorState.REVOKING
    clear(ios)
    clock.now += 100                             # T206 from the profile
    ms.tick()
    assert floor.state is fl.FloorState.IDLE
    assert all(MsgType.IDLE in io.types() for io in ios.values())


def test_timer_durations_are_the_profiles_not_hardcoded():
    ms, ios, clock, floor = make(pol=policy(timers_ms={"T2": 9000, "T20": 100,
                                                       "T8": 100}))
    to_floor(ms, A, MsgType.ACK)
    clear(ios)
    clock.now += 8999
    ms.tick()
    assert floor.state is fl.FloorState.TAKEN
    clock.now += 1
    ms.tick()
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
    (lambda d: d[:-2] + b"\x00\x00", "flow"),                 # sequence field value
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
        return ("out", uri, rtcp.encode(m))
    taken_bad = out(B, rtcp.message(MsgType.TAKEN, 1, rtcp.f_sequence(1)))
    assert {d.code for d in trace_compare.compare([taken_bad])} == {"missing-field"}
    wrong_dir = ("in", A, rtcp.encode(rtcp.message(MsgType.GRANTED, 1)))
    assert "direction" in {d.code for d in trace_compare.compare([wrong_dir])}
    two = [out(A, rtcp.message(MsgType.GRANTED, 1, rtcp.f_priority(1),
                               rtcp.f_duration(1), rtcp.f_sequence(1))),
           out(B, rtcp.message(MsgType.GRANTED, 1, rtcp.f_priority(1),
                               rtcp.f_duration(1), rtcp.f_sequence(1)))]
    assert "flow" in {d.code for d in trace_compare.compare(two)}
    unasked = [out(A, rtcp.message(MsgType.DENY, 1, rtcp.f_reject(1),
                                   rtcp.f_sequence(1)))]
    assert "flow" in {d.code for d in trace_compare.compare(unasked)}
    skip = [out(A, rtcp.message(MsgType.IDLE, 1, rtcp.f_sequence(1))),
            out(A, rtcp.message(MsgType.IDLE, 1, rtcp.f_sequence(5)))]
    assert "sequence" in {d.code for d in trace_compare.compare(skip)}
