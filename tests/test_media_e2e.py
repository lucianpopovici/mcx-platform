"""A group call end to end: SIP signalling through `SipCore`, media and floor
control over real UDP sockets on loopback, captured at every endpoint.

Signalling flows are in-process fakes (task 2 covers TLS); everything about
media is real datagrams.
"""

from __future__ import annotations

import re
import socket
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import trace_compare  # noqa: E402
from core import rtcp  # noqa: E402
from core.release import Release  # noqa: E402
from core.rtcp import MsgType  # noqa: E402
from core.session import Platform  # noqa: E402
from core.sip import build_sdp, parse_sdp  # noqa: E402
from service.runtime import build_runtime  # noqa: E402
from service.sip_core import SipCore  # noqa: E402
from tests import mcpttinfo_fixture as mcf  # noqa: E402
from tests.test_sip_transport import (  # noqa: E402
    Clock, Flow, U, answer, invite, msg, pki, register, sip_env, LOCAL)

PT = 97
CODEC = [(PT, "AMR-WB/16000")]          # the AUDIO codec
# Floor control speaks a 3GPP release; tests use the newest the platform
# implements unless they are about release gating (tests/test_release.py).
FLOOR_CODEC = rtcp.Codec(Release.REL_19)


class UE:
    """A client's media side: a voice socket and a floor-control socket."""

    def __init__(self, uri):
        self.uri = uri
        self.rtp = self._sock()
        self.floor = self._sock()
        self.relay_rtp = self.relay_floor = None

    @staticmethod
    def _sock():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        return s

    def sdp(self, codecs=CODEC, fmtp=None):
        return build_sdp("127.0.0.1", self.rtp.getsockname()[1],
                         self.floor.getsockname()[1], codecs, fmtp)

    def learn_relay(self, sdp_text):
        info = parse_sdp(sdp_text)
        self.relay_rtp = (info.address, info.audio_port)
        self.relay_floor = (info.address, info.floor_port)
        return info

    def send_voice(self, pt=PT, seq=1):
        pkt = (bytes([0x80, pt, seq >> 8, seq & 0xFF])
               + struct.pack(">II", seq * 160, 7) + b"\x02" * 20)
        self.rtp.sendto(pkt, self.relay_rtp)
        return pkt

    def send_floor(self, mtype, *fields):
        self.floor.sendto(FLOOR_CODEC.encode(rtcp.message(mtype, 1, *fields)),
                          self.relay_floor)

    def voice(self, timeout=1.0):
        self.rtp.settimeout(timeout)
        try:
            return self.rtp.recvfrom(2048)[0]
        except socket.timeout:
            return None

    def floor_msg(self, timeout=1.0):
        self.floor.settimeout(timeout)
        try:
            return FLOOR_CODEC.decode(self.floor.recvfrom(2048)[0])
        except socket.timeout:
            return None

    def close(self):
        self.rtp.close()
        self.floor.close()


@pytest.fixture
def call(tmp_path, pki, request):
    clock = Clock()
    rt = build_runtime(sip_env(tmp_path, pki, **getattr(request, "param", {})), clock,
                       platform=Platform())
    core = SipCore(rt, LOCAL, clock)
    flows = {u: Flow(u) for u in U}
    ues = {u: UE(u) for u in U}
    with core.lock:
        for u in U:
            register(core, u, flows[u])
            flows[u].sent.clear()
    yield rt, core, flows, ues, clock
    for ue in ues.values():
        ue.close()
    core.close()
    rt.close()


def group_invite(ue0, cid="e2e", sdp=None):
    """A conformant prearranged group call request (TS 24.379 10.1.1.2.1.1)."""
    return msg("INVITE", LOCAL, cid, 1, U[0], LOCAL,
               body=mcf.body_for("prearranged-group", "grp:alpha", sdp or ue0.sdp()),
               ctype=mcf.CONTENT_TYPE)


def setup_call(call, answering=(1, 2)):
    rt, core, flows, ues, clock = call
    with core.lock:
        core.on_bytes(group_invite(ues[U[0]]), flows[U[0]])
        legs = {u: flows[u].requests("INVITE") for u in U[1:]}
        for u, (req,) in legs.items():
            assert parse_sdp(mcf.sdp_of(req)).payload_types == (PT,)
            ues[u].learn_relay(mcf.sdp_of(req))
        for i in answering:
            u = U[i]
            core.on_bytes(answer(legs[u][0], 200, ues[u].sdp()), flows[u])
    ok = [m for m in flows[U[0]].messages()
          if getattr(m, "code", None) == 200][0]
    ues[U[0]].learn_relay(ok.body)
    return legs


# ------------------------------------------------------------------ anchoring


def test_sdp_is_anchored_at_the_platform_and_carries_only_the_negotiated_codec(call):
    rt, core, flows, ues, _ = call
    legs = setup_call(call)
    for u in U[1:]:
        info = parse_sdp(mcf.sdp_of(legs[u][0]))
        assert info.address == core.media.address           # not the caller's
        assert info.audio_port != ues[U[0]].rtp.getsockname()[1]
        assert info.payload_types == (PT,)
        assert info.floor_port is not None
    ok = [m for m in flows[U[0]].messages() if getattr(m, "code", None) == 200][0]
    assert parse_sdp(ok.body).address == core.media.address
    # every participant has its OWN relay port: identity is the socket
    ports = {ues[u].relay_rtp for u in U[:3]}
    assert len(ports) == 3


# ------------------------------------------------------------------ VP1-FC-001 on real UDP


def test_floor_grant_and_taken_arrive_over_udp(call):
    rt, core, flows, ues, _ = call
    setup_call(call)
    g = ues[U[0]].floor_msg()
    assert g.type is MsgType.GRANTED and g.duration_s == 4    # profile's T203
    for u in (U[1], U[2]):
        t = ues[u].floor_msg()
        assert t.type is MsgType.TAKEN and t.granted_party == U[0]


# ------------------------------------------------------------------ VP1-MED-003 / 004


def test_vp1_med_003_holder_voice_reaches_every_participant(call):
    rt, core, flows, ues, _ = call
    setup_call(call)
    pkt = ues[U[0]].send_voice()
    assert ues[U[1]].voice() == pkt and ues[U[2]].voice() == pkt   # each endpoint
    assert ues[U[0]].voice(0.3) is None                            # not echoed


def test_vp1_med_004_non_holder_voice_reaches_no_one(call):
    rt, core, flows, ues, _ = call
    setup_call(call)
    ues[U[1]].send_voice()
    assert ues[U[0]].voice(0.4) is None and ues[U[2]].voice(0.4) is None
    assert core.media._sessions["e2e"].counters["rtp_dropped_not_holder"] == 1


def test_vp1_med_001_only_the_negotiated_codec_is_forwarded(call):
    rt, core, flows, ues, _ = call
    setup_call(call)
    ues[U[0]].send_voice(pt=8)                       # PCMA, not negotiated
    assert ues[U[1]].voice(0.4) is None and ues[U[2]].voice(0.4) is None
    good = ues[U[0]].send_voice(pt=PT, seq=2)
    assert ues[U[1]].voice() == good


# ------------------------------------------------------------------ contention over the wire


def test_contention_hands_the_floor_over_and_media_follows(call):
    rt, core, flows, ues, _ = call
    setup_call(call)
    for u in U[:3]:
        while ues[u].floor_msg(0.2):                 # drain opening messages
            pass
    ues[U[1]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
    q = ues[U[1]].floor_msg()
    assert q.type is MsgType.QUEUE_POSITION_INFO and q.queue_info[0] == 1
    ues[U[2]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
    assert ues[U[2]].floor_msg().queue_info[0] == 2

    ues[U[0]].send_floor(MsgType.RELEASE)            # queue drains: u1 first
    seen = {}
    for u in U[:3]:
        seen[u] = []
        while True:
            m = ues[u].floor_msg(0.3)
            if m is None:
                break
            seen[u].append(m.type)
    # queue non-empty: the head is granted directly, no Floor Idle
    # (TS 24.380 6.3.4.3.2 item 3)
    assert MsgType.IDLE not in seen[U[0]]
    assert MsgType.GRANTED in seen[U[1]]
    assert MsgType.TAKEN in seen[U[0]] and MsgType.TAKEN in seen[U[2]]

    # media now follows the floor
    ues[U[0]].send_voice()
    assert ues[U[1]].voice(0.4) is None and ues[U[2]].voice(0.4) is None
    pkt = ues[U[1]].send_voice(seq=5)
    assert ues[U[0]].voice() == pkt and ues[U[2]].voice() == pkt


@pytest.mark.vp("VP1-FC-002")
def test_full_call_trace_has_no_deviation(call):
    rt, core, flows, ues, _ = call
    setup_call(call)
    ues[U[1]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
    ues[U[0]].send_floor(MsgType.ACK, rtcp.f_acked(MsgType.GRANTED))
    ues[U[0]].send_floor(MsgType.RELEASE)
    for u in U[:3]:
        while ues[u].floor_msg(0.3):
            pass
    ms = core.media._sessions["e2e"]
    trace = [(e.direction, e.uri, e.data) for e in ms.trace]
    assert len(trace) >= 8
    assert trace_compare.compare(trace) == []


_TIME_WORD = re.compile(r"(?i)(^|_)(at|time|timestamp|ts|when|since|until|expires|expiry|"
                        r"timeout|interval|duration|delay|deadline|ttl|s|sec|secs|seconds)$")


def _time_keys(value, path=""):
    """Every mapping key under `value` that names a time or a duration."""
    if isinstance(value, dict):
        for k, v in value.items():
            if _TIME_WORD.search(str(k)) or str(k).endswith("_ms"):
                yield f"{path}.{k}", v
            yield from _time_keys(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _time_keys(v, f"{path}[{i}]")


def _milliseconds(v) -> bool:
    """A count of milliseconds: a number (a measured duration may be
    fractional, hook-invocation elapsed_ms), none, or named timers of them
    (a floor policy's timers_ms)."""
    if isinstance(v, dict):
        return all(_milliseconds(x) for x in v.values())
    return v is None or type(v) in (int, float)


@pytest.mark.vp("VP1-BND-016")
def test_every_audit_record_of_a_call_carries_utc_milliseconds_only(call):
    """PLT-GEN-011 over the audit trail of a whole call: every record is
    stamped `at_ms` from the injected UTC millisecond clock, and every time
    or duration anywhere in a record is a number named _ms."""
    rt, core, flows, ues, clock = call
    start = clock.now
    setup_call(call)
    clock.now += 1234
    ues[U[1]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
    ues[U[0]].send_floor(MsgType.RELEASE)
    for u in U[:3]:
        while ues[u].floor_msg(0.3):
            pass
    clock.now += 4321
    with core.lock:
        core.on_bytes(msg("BYE", LOCAL, "e2e", 2, U[0], "grp:alpha"), flows[U[0]])
    trail = rt.store.audit_records()
    assert len(trail) >= 5
    assert {r["type"] for r in trail} >= {"session-established", "floor-transition",
                                          "session-released"}
    for r in trail:
        assert type(r["at_ms"]) is int and start <= r["at_ms"] <= clock.now, r
        assert [k for k in r if k != "at_ms" and _TIME_WORD.search(k)] == [], r
        for key, v in _time_keys(r["detail"], r["type"]):
            assert key.endswith("_ms") and _milliseconds(v), (key, v)
    assert {r["at_ms"] for r in trail} > {start}


# ------------------------------------------------------------------ VP1-MED-001/002 via SIP


def test_offer_with_no_profile_codec_is_refused_488_and_leaves_nothing(call):
    rt, core, flows, ues, _ = call
    body = mcf.body_for("prearranged-group", "grp:alpha",
                        build_sdp("127.0.0.1", 5000, 5002, [(18, "G729/8000"),
                                                            (111, "opus/48000/2")]))
    with core.lock:
        core.on_bytes(msg("INVITE", LOCAL, "nocodec", 1, U[0], LOCAL,
                          body=body, ctype=mcf.CONTENT_TYPE),
                      flows[U[0]])
    assert flows[U[0]].codes() == [100, 488]
    assert rt.store.has_session("nocodec") is False
    assert rt.manager.session("nocodec") is None
    assert not any(flows[u].requests("INVITE") for u in U[1:])   # nobody invited
    assert "nocodec" not in core.media._sessions


def test_callee_answering_with_another_codec_is_hung_up_not_relayed(call):
    rt, core, flows, ues, _ = call
    with core.lock:
        core.on_bytes(group_invite(ues[U[0]], "wrongpt"), flows[U[0]])
        (req,) = flows[U[1]].requests("INVITE")
        bad = build_sdp("127.0.0.1", 6000, 6002, [(8, "PCMA/8000")])
        core.on_bytes(answer(req, 200, bad), flows[U[1]])
    assert [r.method for r in flows[U[1]].requests()][-2:] == ["ACK", "BYE"]
    assert 200 not in flows[U[0]].codes()                 # caller not answered
    ms = core.media._sessions["wrongpt"]
    assert ms.endpoints[U[1]].remote_rtp is None          # never becomes a target


def test_session_end_closes_the_media_session(call):
    rt, core, flows, ues, _ = call
    setup_call(call)
    with core.lock:
        core.on_bytes(msg("BYE", LOCAL, "e2e", 2, U[0], "grp:alpha"), flows[U[0]])
    assert "e2e" not in core.media._sessions


def test_floor_does_not_start_while_callees_are_still_ringing(call):
    """Otherwise the initiator's T1 would run out before anyone answered."""
    rt, core, flows, ues, clock = call
    with core.lock:
        core.on_bytes(group_invite(ues[U[0]], "ring"), flows[U[0]])
        floor = rt.manager.session("ring").floor
        assert floor.state.value == "start-stop" and floor.running_timers() == {}
        clock.now += 20_000                    # past every floor timer, under Timer B
        core.tick()
        assert floor.state.value == "start-stop"
        (req,) = flows[U[1]].requests("INVITE")
        core.on_bytes(answer(req, 200, ues[U[1]].sdp()), flows[U[1]])
        assert floor.state.value == "floor-taken" and floor.holder == U[0]
        # a direct grant runs T1 only: T2 waits for the first RTP packet and
        # T20 is for queued grants (TS 24.380 6.3.4.4.2, 6.3.4.4.5)
        assert set(floor.running_timers()) == {"T1"}


# ------------------------------------------------------------------ MED-OP-01: one codec, each party's own number


def _audio_lines(sdp_text):
    return [ln for ln in sdp_text.splitlines()
            if ln.startswith(("m=audio", "a=rtpmap", "a=fmtp"))]


def test_med_op_01_the_profile_order_picks_the_codec_and_every_party_is_offered_it(call):
    """The caller lists PCMU, PCMA, AMR-WB (octet-aligned and not), EVS is
    absent: the profile's order picks AMR-WB, in the bandwidth-efficient
    layout (TS 26.179 4.1.3), and the callee offers and the caller's answer
    carry exactly that, with the caller's number and parameters."""
    rt, core, flows, ues, _ = call
    offer = ues[U[0]].sdp([(0, "PCMU/8000"), (8, "PCMA/8000"),
                           (99, "AMR-WB/16000"), (98, "AMR-WB/16000")],
                          {99: "octet-align=1", 98: "mode-set=0,1,2"})
    with core.lock:
        core.on_bytes(group_invite(ues[U[0]], "order", offer), flows[U[0]])
        (req,) = flows[U[1]].requests("INVITE")
        assert _audio_lines(mcf.sdp_of(req))[1:] == [
            "a=rtpmap:98 AMR-WB/16000", "a=fmtp:98 mode-set=0,1,2"]
        core.on_bytes(answer(req, 200, ues[U[1]].sdp([(98, "AMR-WB/16000")])),
                      flows[U[1]])
    ok = [m for m in flows[U[0]].messages() if getattr(m, "code", None) == 200][0]
    lines = _audio_lines(ok.body)
    assert lines[0].endswith(" RTP/AVP 98")
    assert lines[1:] == ["a=rtpmap:98 AMR-WB/16000", "a=fmtp:98 mode-set=0,1,2"]


def test_med_op_01_a_callee_numbering_the_codec_differently_gets_its_own_number(call):
    """RTP payload types over real UDP (RFC 3264 5.1, 6.1): the relay offers
    AMR-WB as 97; U1 answers 101, U2 97. The caller's packet reaches U1 as
    101 and U2 unchanged, marker bit kept. U1 itself sends with the offer's
    number, 97, which reaches the caller as its own 97."""
    rt, core, flows, ues, _ = call
    with core.lock:
        core.on_bytes(group_invite(ues[U[0]], "renum"), flows[U[0]])
        legs = {u: flows[u].requests("INVITE")[0] for u in U[1:3]}
        for u in U[1:3]:
            ues[u].learn_relay(mcf.sdp_of(legs[u]))
        core.on_bytes(answer(legs[U[1]], 200, ues[U[1]].sdp([(101, "AMR-WB/16000")])),
                      flows[U[1]])
        core.on_bytes(answer(legs[U[2]], 200, ues[U[2]].sdp()), flows[U[2]])
    ok = [m for m in flows[U[0]].messages() if getattr(m, "code", None) == 200][0]
    ues[U[0]].learn_relay(ok.body)
    assert parse_sdp(ok.body).payload_types == (PT,)       # the caller's own
    pkt = ues[U[0]].send_voice(pt=0x80 | PT)                 # marker set
    assert ues[U[1]].voice() == bytes([0x80, 0x80 | 101]) + pkt[2:]
    assert ues[U[2]].voice() == pkt
    ms = core.media._sessions["renum"]
    assert (ms.endpoints[U[1]].rx_pt, ms.endpoints[U[1]].tx_pt) == (PT, 101)
    assert (ms.endpoints[U[2]].rx_pt, ms.endpoints[U[2]].tx_pt) == (PT, PT)
    # U1 takes the floor and talks, with the offer's number
    for u in U[:3]:
        while ues[u].floor_msg(0.2):
            pass
    ues[U[0]].send_floor(MsgType.RELEASE)
    ues[U[1]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
    while True:
        m = ues[U[1]].floor_msg()
        assert m is not None
        if m.type is MsgType.GRANTED:
            break
    ues[U[1]].send_voice(pt=101, seq=5)                  # its own answer's: not the codec
    assert ues[U[0]].voice(0.4) is None
    pkt = ues[U[1]].send_voice(pt=PT, seq=6)
    assert ues[U[0]].voice() == pkt and ues[U[2]].voice() == pkt


@pytest.mark.parametrize("fmtp", ["octet-align=1", "crc=1", "robust-sorting=1",
                                  "interleaving=2"])
def test_rfc_4867_a_callee_answering_another_payload_layout_is_hung_up(call, fmtp):
    rt, core, flows, ues, _ = call
    with core.lock:
        core.on_bytes(group_invite(ues[U[0]], "layout"), flows[U[0]])
        (req,) = flows[U[1]].requests("INVITE")
        core.on_bytes(answer(req, 200, ues[U[1]].sdp(CODEC, {PT: fmtp})), flows[U[1]])
    assert [r.method for r in flows[U[1]].requests()][-2:] == ["ACK", "BYE"]
    assert 200 not in flows[U[0]].codes()


def test_a_callee_answering_the_layout_with_explicit_defaults_is_relayed(call):
    rt, core, flows, ues, _ = call
    with core.lock:
        core.on_bytes(group_invite(ues[U[0]], "defaults"), flows[U[0]])
        (req,) = flows[U[1]].requests("INVITE")
        core.on_bytes(answer(req, 200, ues[U[1]].sdp(CODEC, {PT: "octet-align=0;crc=0"})),
                      flows[U[1]])
    assert "BYE" not in [r.method for r in flows[U[1]].requests()]
    assert 200 in flows[U[0]].codes()


def test_g722_static_payload_type_end_to_end(call):
    rt, core, flows, ues, _ = call
    offer = ues[U[0]].sdp([(9, "G722/8000"), (0, "PCMU/8000")])
    with core.lock:
        core.on_bytes(group_invite(ues[U[0]], "g722", offer), flows[U[0]])
        (req,) = flows[U[1]].requests("INVITE")
        assert parse_sdp(mcf.sdp_of(req)).payload_types == (9,)
        ues[U[1]].learn_relay(mcf.sdp_of(req))
        core.on_bytes(answer(req, 200, ues[U[1]].sdp([(9, "G722/8000")])), flows[U[1]])
    ok = [m for m in flows[U[0]].messages() if getattr(m, "code", None) == 200][0]
    ues[U[0]].learn_relay(ok.body)
    pkt = ues[U[0]].send_voice(pt=9)
    assert ues[U[1]].voice() == pkt


def test_a_caller_offering_only_numbers_rtp_cannot_carry_is_488(call):
    """Review of MED-OP-01: payload type 300 names nothing (RFC 3550 5.1)."""
    rt, core, flows, ues, _ = call
    body = mcf.body_for("prearranged-group", "grp:alpha",
                        build_sdp("127.0.0.1", 5000, 5002, [(300, "AMR-WB/16000")]))
    with core.lock:
        core.on_bytes(msg("INVITE", LOCAL, "pt300", 1, U[0], LOCAL,
                          body=body, ctype=mcf.CONTENT_TYPE), flows[U[0]])
    assert flows[U[0]].codes() == [100, 488]
    assert "pt300" not in core.media._sessions


def test_a_callee_answering_a_number_rtp_cannot_carry_is_hung_up(call):
    rt, core, flows, ues, _ = call
    with core.lock:
        core.on_bytes(group_invite(ues[U[0]], "pt300b"), flows[U[0]])
        (req,) = flows[U[1]].requests("INVITE")
        core.on_bytes(answer(req, 200, ues[U[1]].sdp([(300, "AMR-WB/16000")])), flows[U[1]])
    assert [r.method for r in flows[U[1]].requests()][-2:] == ["ACK", "BYE"]
    assert core.media._sessions["pt300b"].endpoints[U[1]].tx_pt is None



@pytest.mark.vp("VP1-FC-021")
def test_vp1_fc_021_a_contended_call_is_rebuilt_from_the_audit_store_alone(call):
    """ENV-INT (RES-OP-03): a group call with contention, completed through
    the runtime; its floor is rebuilt from the floor-transition records in
    the audit store, and matches the machine's own sequence record for
    record. Before, the history lived only in the floor machine's memory."""
    rt, core, flows, ues, _ = call
    setup_call(call)
    for u in U[:3]:
        while ues[u].floor_msg(0.2):
            pass
    ues[U[1]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
    ues[U[1]].floor_msg()
    ues[U[2]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
    ues[U[2]].floor_msg()
    ues[U[0]].send_floor(MsgType.RELEASE)
    for u in U[:3]:
        while ues[u].floor_msg(0.3):
            pass
    floor = rt.manager.session("e2e").floor
    with core.lock:
        core.on_bytes(msg("BYE", LOCAL, "e2e", 2, U[0], "grp:alpha"), flows[U[0]])

    trail = rt.store.audit_records("e2e")
    records = [r["detail"] for r in trail if r["type"] == "floor-transition"]
    u0, u1, u2 = U[:3]
    # The call as the trail tells it: trigger, who, state before and after,
    # holder and queue after.
    assert [(d["trigger"]["type"], d["trigger"]["participant"], d["from_state"],
             d["to_state"], d["holder"], d["queue"]) for d in records] == [
        ("session-established", u0, "start-stop", "floor-taken", u0, []),
        ("floor-request", u1, "floor-taken", "floor-taken", u0, [u1]),
        ("floor-request", u2, "floor-taken", "floor-taken", u0, [u1, u2]),
        ("floor-release", u0, "floor-taken", "floor-taken", u1, [u2]),
        ("session-released", None, "floor-taken", "released", None, []),
    ]
    # A chain: numbered without a gap, each starting where the last ended.
    assert [d["sequence"] for d in records] == list(range(1, len(records) + 1))
    assert all(b["from_state"] == a["to_state"] for a, b in zip(records, records[1:]))
    # And the machine's own history, field by field.
    assert records == [t.as_record() for t in floor.history]
    assert all(r["at_ms"] == r["detail"]["floor_at_ms"]
               for r in trail if r["type"] == "floor-transition")
    # The session's own records come first, the release's after the floor's.
    types_ = [r["type"] for r in trail if r["type"] != "hook-invocation"]
    assert types_[:3] == ["session-admitted", "session-established", "floor-transition"]
    assert types_.index("session-released") > max(
        i for i, t in enumerate(types_) if t == "floor-transition")


def _floor_records(rt, cid="e2e"):
    return [r["detail"] for r in rt.store.audit_records(cid)
            if r["type"] == "floor-transition"]


@pytest.mark.vp("VP1-FC-021")
def test_the_holder_s_first_media_is_in_the_audit_store(call):
    """The first RTP after a grant starts T2 (TS 24.380 6.3.4.4.5): a
    transition, recorded. The packets after it only keep T1 alive, and are
    not (RES-OP-03 review: no e2e test sent media)."""
    rt, core, flows, ues, _ = call
    setup_call(call)
    before = len(_floor_records(rt))
    for seq in range(1, 4):
        ues[U[0]].send_voice(seq=seq)
        assert ues[U[1]].voice() is not None
    added = _floor_records(rt)[before:]
    assert [(d["trigger"]["type"], d["trigger"]["participant"]) for d in added] == [
        ("media-received", U[0])]
    assert {"type": "start-timer", "timer": "T2"}.items() <= next(
        a for a in added[0]["actions"] if a["timer"] == "T2").items()


@pytest.mark.vp("VP1-FC-021")
def test_a_floor_request_whose_record_fails_is_not_taken_until_retransmitted(call):
    """RES-OP-03 review: with the audit store failing, a request used to
    queue its sender with no Queue Position Info sent. Now nothing changes
    and nothing is sent; the client's retransmission is taken once the store
    works again."""
    rt, core, flows, ues, _ = call
    setup_call(call)
    for u in U[:3]:
        while ues[u].floor_msg(0.2):
            pass
    floor = rt.manager.session("e2e").floor
    emit = rt.store.emit
    failing = {"on": True}

    def flaky(record):
        if failing["on"] and record.type.value == "floor-transition":
            raise OSError("audit store unavailable")
        emit(record)

    rt.store.emit = flaky
    try:
        ues[U[1]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
        assert ues[U[1]].floor_msg(0.4) is None
        assert floor.queue == () and floor.holder == U[0]
        failing["on"] = False
        ues[U[1]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
        q = ues[U[1]].floor_msg()
        assert q.type is MsgType.QUEUE_POSITION_INFO and q.queue_info[0] == 1
        assert floor.queue == (U[1],)
    finally:
        rt.store.emit = emit
    records = _floor_records(rt)
    assert [d["sequence"] for d in records] == list(range(1, len(records) + 1))
    assert records[-1]["trigger"]["type"] == "floor-request"
    assert records == [t.as_record() for t in floor.history]


@pytest.mark.vp("VP1-FC-021")
def test_a_media_report_whose_record_failed_is_made_by_the_next_packet(call):
    """The relay reports the holder's media at most every notify interval.
    A report whose record failed was undone, so the next packet reports it
    again at once rather than an interval later (RES-OP-03)."""
    rt, core, flows, ues, _ = call
    setup_call(call)
    emit = rt.store.emit
    failing = {"on": True}

    def flaky(record):
        if failing["on"] and record.type.value == "floor-transition":
            raise OSError("audit store unavailable")
        emit(record)

    rt.store.emit = flaky
    try:
        before = len(_floor_records(rt))
        ues[U[0]].send_voice(seq=1)
        ues[U[1]].voice(0.3)
        assert len(_floor_records(rt)) == before
        failing["on"] = False
        ues[U[0]].send_voice(seq=2)                # the clock has not moved
        assert ues[U[1]].voice() is not None
    finally:
        rt.store.emit = emit
    assert [d["trigger"]["type"] for d in _floor_records(rt)[before:]] == ["media-received"]


@pytest.fixture
def json_logs():
    """Every line the service logs, through its own filter and formatter."""
    import io
    import json
    import logging
    from service import logs
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    handler.addFilter(logs.CorrelationFilter())
    handler.setFormatter(logs.JsonFormatter())
    handler.setLevel(logging.INFO)
    root = logging.getLogger()
    saved = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    yield lambda: [json.loads(l) for l in out.getvalue().splitlines()]
    root.removeHandler(handler)
    root.setLevel(saved)


@pytest.mark.vp("VP1-OAM-004")
def test_vp1_oam_004_two_calls_log_under_their_own_correlation_ids(call, json_logs):
    """ENV-INT (RES-OP-04): two concurrent calls through the process. Every
    log line about one of them -- from the media receive threads, the SIP
    timers, the session layer -- is JSON and carries that call's id, the id
    its audit records carry; a line about neither carries none."""
    rt, core, flows, ues, clock = call
    second = {u: UE(u) for u in U}
    try:
        for cid, side in (("call-a", ues), ("call-b", second)):
            with core.lock:
                core.on_bytes(group_invite(side[U[0]], cid=cid), flows[U[0]])
                for u in (U[1], U[2]):
                    leg = flows[u].requests("INVITE")[-1]      # this call's leg
                    side[u].learn_relay(mcf.sdp_of(leg))
                    core.on_bytes(answer(leg, 200, side[u].sdp()), flows[u])
            ok = [m for m in flows[U[0]].messages() if getattr(m, "code", None) == 200
                  and m.headers.get("Call-ID") == cid][0]
            side[U[0]].learn_relay(ok.body)
        with core.lock:
            core.on_bytes(b"not sip at all\r\n\r\n", flows[U[3]])
        # A malformed floor packet into each call: logged by that call's
        # media receive thread.
        for side in (ues, second):
            side[U[0]].floor.sendto(b"\x80\xcc\x00\x01junk", side[U[0]].relay_floor)
        deadline = __import__("time").time() + 2
        while __import__("time").time() < deadline and sum(
                "malformed floor" in l["message"] for l in json_logs()) < 2:
            __import__("time").sleep(0.05)
        # The caller never ACKs its 200 OK: after 64*T1 the SIP timers end
        # each call, logging as they do.
        clock.now += 40_000
        with core.lock:
            core.tick()
    finally:
        for ue in second.values():
            ue.close()

    got = json_logs()
    about = {c: [l for l in got if l.get("correlation_id") == c] for c in ("call-a", "call-b")}
    for cid in ("call-a", "call-b"):
        messages = [l["message"] for l in about[cid]]
        assert any(m.startswith("malformed floor message from ") for m in messages), messages
        assert f"no ACK for 2xx call-id={cid}: ending session" in messages
        # Every line naming the call carries its id, and only its id.
        assert all(l.get("correlation_id") == cid for l in got if cid in l["message"])
    assert not any(l.get("correlation_id") for l in got
                   if l["message"].startswith("dropped unparseable message"))
    # Every line from the call path is some call's, but the one about bytes
    # that could not be parsed at all, which name no call.
    session_lines = [l for l in got if l["logger"] in ("mcx.sip", "mcx.media", "mcx.session")
                     and not l["message"].startswith("dropped unparseable message")]
    assert session_lines
    assert {l.get("correlation_id") for l in session_lines} == {"call-a", "call-b"}
    # And the audit trail joins on the same ids.
    for cid in ("call-a", "call-b"):
        assert {r["correlation_id"] for r in rt.store.audit_records(cid)} == {cid}
        assert rt.store.audit_records(cid)



# Not VP1-FC-021 evidence: under allow transitions are, by the deployment's
# choice, not all recorded (RES-OP-14, a reported deviation).
@pytest.mark.parametrize("call", [{"MCX_FLOOR_UNRECORDED": "allow"}], indirect=True)
def test_with_unrecorded_allowed_the_floor_runs_and_the_gap_is_written(call):
    """RES-OP-14 (owner ruling 2026-10-16): with MCX_FLOOR_UNRECORDED=allow a
    request is taken while the store fails -- Queue Position Info sent, the
    sender queued -- and the next record the store takes is preceded by one
    audit-gap record counting what it lost."""
    rt, core, flows, ues, clock = call
    setup_call(call)
    for u in U[:3]:
        while ues[u].floor_msg(0.2):
            pass
    floor = rt.manager.session("e2e").floor
    emit = rt.store.emit
    failing = {"on": True}

    def flaky(record):
        if failing["on"]:
            raise OSError("audit store unavailable")
        emit(record)

    rt.store.emit = flaky
    try:
        ues[U[1]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
        q = ues[U[1]].floor_msg()
        assert q.type is MsgType.QUEUE_POSITION_INFO and q.queue_info[0] == 1
        assert floor.queue == (U[1],)
        audit = rt.health.snapshot()["audit"]
        assert audit["floor_unrecorded"] == "allow"
        assert audit["unrecorded_floor_records"] >= 1
        lost = audit["pending_gap"]["unrecorded"]
        failing["on"] = False
        clock.now += 1_000                 # past the retry interval (GAP_RETRY_MS)
        ues[U[2]].send_floor(MsgType.REQUEST, rtcp.f_priority(0))
        assert ues[U[2]].floor_msg().type is MsgType.QUEUE_POSITION_INFO
    finally:
        rt.store.emit = emit
    gaps = [r for r in rt.store.audit_records("audit-gap") if r["type"] == "audit-gap"]
    assert len(gaps) == 1
    gap = gaps[0]["detail"]
    assert gap["unrecorded"] == lost and gap["sessions"] == ["e2e"]
    # U1's IF-PRI evaluation (the floor request's own hook record) and its
    # floor transition
    assert gap["by_type"] == {"floor-transition": 1, "hook-invocation": 1}
    assert gap["error"] == "OSError: audit store unavailable"
    after = rt.store.audit_records()
    i = next(n for n, r in enumerate(after) if r["type"] == "audit-gap")
    assert after[i + 1]["type"] == "hook-invocation"        # U2's IF-PRI, then
    assert after[i + 2]["type"] == "floor-transition"
    assert after[i + 2]["detail"]["trigger"]["participant"] == U[2]
    assert rt.health.snapshot()["audit"]["pending_gap"] is None
    # the trail says where the hole is: sequences jump by what was lost
    seqs = [d["sequence"] for d in _floor_records(rt)]
    assert seqs[-1] - seqs[-2] == gap["by_type"]["floor-transition"] + 1


# Not VP1-FC-021 evidence: under allow transitions are, by the deployment's
# choice, not all recorded (RES-OP-14, a reported deviation).
@pytest.mark.parametrize("call", [{"MCX_FLOOR_UNRECORDED": "allow"}], indirect=True)
def test_with_unrecorded_allowed_a_whole_call_runs_with_its_floor_unrecorded(call):
    """RES-OP-14 consequences 1-3, end to end under allow: every floor record
    fails from before the deferred floor start, and still the initiator is
    granted, the others told the floor is taken, the holder's voice is
    forwarded, and the call ends; the gap is written ahead of its end."""
    rt, core, flows, ues, clock = call
    emit = rt.store.emit

    def floor_down(record):
        if record.type.value == "floor-transition":
            raise OSError("audit store unavailable")
        emit(record)

    rt.store.emit = floor_down
    try:
        setup_call(call)
        assert ues[U[0]].floor_msg().type is MsgType.GRANTED          # (1) deferred start
        assert ues[U[1]].floor_msg().type is MsgType.TAKEN
        for seq in range(1, 4):                                       # (2) media
            ues[U[0]].send_voice(seq=seq)
            assert ues[U[1]].voice() is not None
        assert rt.manager.session("e2e").floor.holder == U[0]
    finally:
        rt.store.emit = emit
    clock.now += 1_000
    with core.lock:
        core.on_bytes(msg("BYE", LOCAL, "e2e", 2, U[0], "grp:alpha"), flows[U[0]])
    assert rt.manager.session("e2e").state.value == "released"
    trail = [r["type"] for r in rt.store.audit_records()]
    gap_at = trail.index("audit-gap")
    assert "session-released" in trail[gap_at + 1:]
    gap = rt.store.audit_records("audit-gap")[0]["detail"]
    assert gap["by_type"]["floor-transition"] >= 2 and gap["sessions"] == ["e2e"]


@pytest.mark.parametrize("call", [{"MCX_FLOOR_UNRECORDED": "allow"}], indirect=True)
def test_the_sip_tick_writes_a_pending_gap_with_no_other_record(call):
    rt, core, flows, ues, clock = call
    emit = rt.store.emit
    rt.store.emit = lambda rec: (_ for _ in ()).throw(OSError("down"))
    from core.audit import RecordType
    rt.auditor.emit_or_count(RecordType.FLOOR_TRANSITION, "lonely")
    rt.store.emit = emit
    with core.lock:
        core.tick()                             # within the retry interval
    assert rt.store.audit_records("audit-gap") == []
    clock.now += 1_000
    with core.lock:
        core.tick()
    assert [r["detail"]["sessions"] for r in rt.store.audit_records("audit-gap")] == \
        [["lonely"]]
