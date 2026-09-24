"""A group call end to end: SIP signalling through `SipCore`, media and floor
control over real UDP sockets on loopback, captured at every endpoint.

Signalling flows are in-process fakes (task 2 covers TLS); everything about
media is real datagrams.
"""

from __future__ import annotations

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

    def sdp(self):
        return build_sdp("127.0.0.1", self.rtp.getsockname()[1],
                         self.floor.getsockname()[1], CODEC)

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
def call(tmp_path, pki):
    clock = Clock()
    rt = build_runtime(sip_env(tmp_path, pki), clock, platform=Platform())
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


def group_invite(ue0, cid="e2e"):
    """A conformant prearranged group call request (TS 24.379 10.1.1.2.1.1)."""
    return msg("INVITE", LOCAL, cid, 1, U[0], LOCAL,
               body=mcf.body_for("prearranged-group", "grp:alpha", ue0.sdp()),
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


# ------------------------------------------------------------------ VP1-MED-001/002 via SIP


def test_offer_with_no_profile_codec_is_refused_488_and_leaves_nothing(call):
    rt, core, flows, ues, _ = call
    body = mcf.body_for("prearranged-group", "grp:alpha",
                        build_sdp("127.0.0.1", 5000, 5002, [(8, "PCMA/8000")]))
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
