"""RFC 4028 session timers, in-dialog UPDATE and re-INVITE, and the focus
Contact (PLT-CONF-AUDIT CA-20b; PLT-VP-R1 SIP-OP-17; TS 24.379 6.3.3.1.2,
6.3.2.1.5, 6.3.3.2.3)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.errors import StartupRefused  # noqa: E402
from core.sip import (Headers, ReceivedResponse, SessionTimer, SipError,  # noqa: E402
                      parse_min_se, parse_sdp, parse_session_expires, uac_session_timer,
                      uas_session_timer)
from service.session_timer import DialogTimer  # noqa: E402
from service.sip_core import _tag  # noqa: E402
from tests.test_sip_transport import (  # noqa: E402,F401  (fixtures)
    LOCAL, SDP, U, Clock, Flow, answer, clock, core, env, invite, msg, pki, rt,
    sip_env, world)

TIMER = ["Supported: timer"]
SID_PREFIX = LOCAL + ";gr=urn:uuid:"


def H(*pairs):
    return Headers(list(pairs))


# ============================================================ negotiation (pure)


@pytest.mark.parametrize("headers, preferred, expected", [
    # no Session-Expires, timer supported: the deployment's, refreshed by the UAC
    (H(("Supported", "timer")), 300, SessionTimer(300, "uac", True)),
    (H(("Require", "timer")), 300, SessionTimer(300, "uac", True)),
    # asked for more than the deployment's: lowered to it
    (H(("Supported", "timer"), ("Session-Expires", "1800")), 300,
     SessionTimer(300, "uac", True)),
    # asked for less: kept
    (H(("Supported", "timer"), ("Session-Expires", "120")), 300,
     SessionTimer(120, "uac", True)),
    # never below the request's Min-SE
    (H(("Supported", "timer"), ("Session-Expires", "1000"), ("Min-SE", "400")), 300,
     SessionTimer(400, "uac", True)),
    (H(("Supported", "timer"), ("Min-SE", "400")), 300, SessionTimer(400, "uac", True)),
    # the request's refresher stands
    (H(("Supported", "timer"), ("Session-Expires", "600;refresher=uas")), 900,
     SessionTimer(600, "uas", True)),
    # a peer without timers: the platform refreshes, and no Require
    (H(), 300, SessionTimer(300, "uas", False)),
    (H(("Session-Expires", "600;refresher=uac")), 900, SessionTimer(600, "uas", False)),
    # exactly the smallest allowed
    (H(("Supported", "timer"), ("Session-Expires", "90")), 300,
     SessionTimer(90, "uac", True)),
])
def test_uas_negotiation(headers, preferred, expected):
    assert uas_session_timer(headers, preferred) == expected


@pytest.mark.parametrize("se", ["89", "1", "0"])
def test_an_interval_below_90_is_a_422(se):
    assert uas_session_timer(H(("Session-Expires", se)), 300) == 90


@pytest.mark.parametrize("value", ["abc", "-5", "600;refresher=me", "12345678901", ""])
def test_malformed_session_expires(value):
    if value == "":
        assert parse_session_expires(value) is None
    else:
        with pytest.raises(SipError):
            parse_session_expires(value)


def test_session_expires_parameters():
    assert parse_session_expires(" 600 ; refresher=UAS ;x=1").refresher == "uas"
    assert parse_session_expires("600").refresher is None
    assert parse_min_se("90;x") == 90 and parse_min_se(None) is None
    with pytest.raises(SipError):
        parse_min_se("ninety")


def test_uac_negotiation():
    assert uac_session_timer(H()) is None
    assert uac_session_timer(H(("Session-Expires", "600;refresher=uas"))) == \
        SessionTimer(600, "uas")
    # no refresher: non-conformant, and the platform refreshes
    assert uac_session_timer(H(("Session-Expires", "600"))) == SessionTimer(600, "uac")


def test_dialog_timer_arithmetic():
    """RFC 4028 section 10: refresh at half; the watcher's deadline is the
    interval less min(32 s, a third)."""
    t = DialogTimer.start(1_000, 600, we_refresh=True)
    assert (t.refresh_at, t.expires_at) == (301_000, 601_000)
    assert not t.refresh_due(300_999) and t.refresh_due(301_000)
    t.pending = True
    assert not t.refresh_due(400_000)
    w = DialogTimer.start(0, 1800, we_refresh=False)
    assert (w.refresh_at, w.expires_at) == (None, 1_768_000)
    assert not w.refresh_due(10**9)
    short = DialogTimer.start(0, 90, we_refresh=False)
    assert short.expires_at == 60_000                       # a third, not 32 s
    assert not short.expired(59_999) and short.expired(60_000)
    t.retry_later(401_000)
    assert (t.pending, t.refresh_at) == (False, 501_000)
    t.retry_later(600_000)                                  # too late to retry
    assert t.refresh_at is None


# ============================================================ configuration


@pytest.mark.parametrize("value", [None, "", "89", "0", "ten", "1.5", "-90", "1234567"])
def test_the_session_interval_must_be_stated(tmp_path, pki, value):
    from service.config import Config
    env = sip_env(tmp_path, pki)
    env.pop("MCX_SESSION_EXPIRES")
    if value is not None:
        env["MCX_SESSION_EXPIRES"] = value
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(env)
    assert "MCX_SESSION_EXPIRES" in str(exc.value)


@pytest.mark.parametrize("value", ["90", "300", "86400"])
def test_the_session_interval_is_read(tmp_path, pki, value):
    from service.config import Config
    cfg = Config.from_env(sip_env(tmp_path, pki, MCX_SESSION_EXPIRES=value))
    assert cfg.sip.session_expires == int(value)


# ============================================================ helpers


def responses(flow, code=None, method="INVITE"):
    return [m for m in flow.messages() if isinstance(m, ReceivedResponse)
            and (code is None or m.code == code)
            and (m.headers.get("CSeq") or "").endswith(method)]


def contact_uri(value):
    return value.split("<", 1)[1].split(">", 1)[0]


# An MCPTT callee refreshes its own leg (6.2.3.1.1 item 5, refresher "uas").
# A day long, so that the callee's leg stays out of the way of tests about
# the caller's dialog.
CALLEE_REFRESHES = ["Session-Expires: 86400;refresher=uas", "Require: timer"]


def call(core, world, cid, extra=TIMER, callee_extra=CALLEE_REFRESHES):
    """u0 calls u1 (private); u1 answers; u0 ACKs. Returns the 200 to u0 and
    the INVITE u1 got."""
    core.on_bytes(invite(cid, U[0], U[1], "private", extra=list(extra)), world[U[0]])
    leg = world[U[1]].requests("INVITE")[-1]
    core.on_bytes(answer(leg, 200, SDP, extra=list(callee_extra)), world[U[1]])
    (ok,) = responses(world[U[0]], 200)
    core.on_bytes(msg("ACK", contact_uri(ok.headers.get("Contact")), cid, 1, U[0], LOCAL,
                      branch=f"z9hG4bKack{cid}", to_tag=_tag(cid)), world[U[0]])
    return ok, leg


def from_initiator(method, cid, cseq, body="", ctype=None, extra=(), flow_extra=()):
    return msg(method, LOCAL, cid, cseq, U[0], LOCAL, to_tag=_tag(cid),
               body=body, ctype=ctype, extra=list(extra))


def from_callee(method, leg, cseq, body="", ctype=None, extra=()):
    cid = leg.headers.get("Call-ID")
    return msg(method, LOCAL, cid, cseq, U[1], LOCAL, to_tag=f"{cid}-l",
               from_tag="callee", body=body, ctype=ctype, extra=list(extra))


def reply(req, code=200, extra=(), body=""):
    """A peer's response to a request the platform sent within a dialog."""
    lines = [f"SIP/2.0 {code} X"]
    for v in req.headers.get_all("Via"):
        lines.append(f"Via: {v}")
    for n in ("From", "To", "Call-ID", "CSeq"):
        lines.append(f"{n}: {req.headers.get(n)}")
    lines += list(extra)
    if body:
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


# ============================================================ the focus Contact


def test_every_dialog_of_a_call_carries_one_session_identity(core, world):
    """TS 24.379 clause 4.5: one GRUU per session, the Contact of the leg
    INVITEs (6.3.3.1.2 item 1), the 180 (6.3.3.2.3.1) and the 200
    (6.3.3.2.3.2), each with the feature tags and isfocus."""
    core.on_bytes(invite("si1", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    invites = [world[u].requests("INVITE")[0] for u in U[1:]]
    core.on_bytes(answer(invites[0], 180), world[U[1]])
    core.on_bytes(answer(invites[0], 200, SDP), world[U[1]])
    (ringing,) = responses(world[U[0]], 180)
    (ok,) = responses(world[U[0]], 200)
    contacts = [m.headers.get("Contact") for m in invites + [ringing, ok]]
    uris = {contact_uri(c) for c in contacts}
    assert len(uris) == 1
    (sid,) = uris
    assert sid.startswith(SID_PREFIX)
    for c in contacts:
        params = c.split(">", 1)[1].split(";")
        assert "isfocus" in params and "+g.3gpp.mcptt" in params
        assert '+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt"' in params
    for secret in ("u0", "u1", "alpha"):                    # clause 4.5
        assert secret not in sid
    assert ringing.headers.get("Supported") == "norefersub"   # 6.3.2.1.5.1 item 2


def test_each_call_gets_its_own_session_identity(core, world):
    a, _ = call(core, world, "si2")
    world[U[0]].sent.clear()
    b, _ = call(core, world, "si3")
    assert contact_uri(a.headers.get("Contact")) != contact_uri(b.headers.get("Contact"))


# ============================================================ the initial INVITE


def test_the_200_to_a_timer_capable_originator(core, world):
    ok, _ = call(core, world, "t1", extra=TIMER + ["Session-Expires: 600"])
    assert ok.headers.get("Session-Expires") == "600;refresher=uac"
    assert ok.headers.get("Require") == "timer"
    assert ok.headers.get("Supported") == "timer, tdialog, norefersub, explicitsub, nosub"
    assert "UPDATE" in ok.headers.get("Allow")


def test_the_200_to_an_originator_without_timers(core, world):
    """RFC 4028 section 9: the platform refreshes, and requires nothing."""
    ok, _ = call(core, world, "t2", extra=())
    assert ok.headers.get("Session-Expires") == "1800;refresher=uas"
    assert ok.headers.get("Require") is None


def test_the_leg_invite_asks_for_a_timer_and_leaves_the_refresher_open(core, world):
    _, leg = call(core, world, "t3")
    assert leg.headers.get("Supported") == "timer"
    assert leg.headers.get("Session-Expires") == "1800"          # 6.3.3.1.2 item 6
    assert leg.headers.get("Min-SE") is None
    assert "UPDATE" in leg.headers.get("Allow")


def test_a_too_small_interval_is_refused_before_anything_happens(core, rt, world):
    core.on_bytes(invite("t4", U[0], U[1], "private",
                         extra=TIMER + ["Session-Expires: 60"]), world[U[0]])
    (r,) = responses(world[U[0]])
    assert (r.code, r.headers.get("Min-SE")) == (422, "90")
    assert rt.manager.session("t4") is None and not world[U[1]].requests("INVITE")
    assert rt.store.audit_records("t4") == []


def test_a_malformed_session_expires_is_a_400(core, world):
    core.on_bytes(invite("t5", U[0], U[1], "private",
                         extra=["Session-Expires: soon"]), world[U[0]])
    assert [r.code for r in responses(world[U[0]])][-1] == 400


def test_a_new_invite_reusing_a_live_call_id_is_still_400(core, world):
    call(core, world, "t6")
    from tests import mcpttinfo_fixture as mcf
    core.on_bytes(msg("INVITE", LOCAL, "t6", 3, U[0], LOCAL,
                      body=mcf.body_for("private", U[1], SDP), ctype=mcf.CONTENT_TYPE),
                  world[U[0]])
    assert responses(world[U[0]])[-1].code == 400


# ============================================================ the originator refreshes


def test_an_update_refreshes_the_session(core, rt, world, clock):
    call(core, world, "r1", extra=TIMER + ["Session-Expires: 600"])
    clock.now += 500_000                               # before 568 s
    core.on_bytes(from_initiator("UPDATE", "r1", 2, extra=TIMER + ["Session-Expires: 600"]),
                  world[U[0]])
    (ok,) = responses(world[U[0]], 200, "UPDATE")
    assert ok.headers.get("Session-Expires") == "600;refresher=uac"
    assert ok.headers.get("Require") == "timer"
    assert contact_uri(ok.headers.get("Contact")).startswith(SID_PREFIX)
    clock.now += 500_000                               # past the first deadline
    core.tick()
    assert rt.manager.session("r1").state.value == "established"
    assert not world[U[0]].requests("BYE")


def test_without_a_refresh_the_session_expires(core, rt, world, clock):
    """RFC 4028 section 10: the watcher sends BYE at the interval less 32 s."""
    call(core, world, "r2", extra=TIMER + ["Session-Expires: 600"])
    clock.now += 568_000 - 1
    core.tick()
    assert rt.manager.session("r2").state.value == "established"
    clock.now += 1
    core.tick()
    assert world[U[0]].requests("BYE") and world[U[1]].requests("BYE")
    assert rt.manager.session("r2").state.value == "released"
    assert any(r["detail"].get("cause") == "session-expired"
               for r in rt.store.audit_records("r2") if r["type"] == "session-released")


def test_a_re_invite_with_the_same_offer_refreshes(core, rt, world, clock):
    ok, _ = call(core, world, "r3", extra=TIMER + ["Session-Expires: 600"])
    core.on_bytes(from_initiator("INVITE", "r3", 2, body=SDP, ctype="application/sdp",
                                 extra=TIMER + ["Session-Expires: 600",
                                                "Record-Route: <sip:p.example;lr>"]),
                  world[U[0]])
    (re_ok,) = [r for r in responses(world[U[0]], 200) if r.headers.get("CSeq") == "2 INVITE"]
    # the same relay answer as the first 200 gave
    assert re_ok.body == ok.body and re_ok.headers.get("Content-Type") == "application/sdp"
    assert re_ok.headers.get("Session-Expires") == "600;refresher=uac"
    # RFC 3261 12.2: a re-INVITE does not change the route set
    assert re_ok.headers.get("Record-Route") is None


def test_a_re_invite_moving_the_address_keeps_the_codec(core, rt, world):
    call(core, world, "r4")
    moved = SDP.replace("10.0.0.1", "10.9.9.9").replace("49170", "50000")
    core.on_bytes(from_initiator("INVITE", "r4", 2, body=moved, ctype="application/sdp"),
                  world[U[0]])
    assert responses(world[U[0]])[-1].code == 200
    ep = core.calls["r4"].media.endpoints[U[0]]
    assert ep.remote_rtp == ("10.9.9.9", 50000)


def test_a_re_invite_changing_the_codec_is_488_and_changes_nothing(core, rt, world):
    call(core, world, "r5")
    other = SDP.replace("RTP/AVP 0", "RTP/AVP 8").replace("0 PCMU/8000", "8 PCMA/8000")
    other = other.replace("10.0.0.1", "10.7.7.7")
    core.on_bytes(from_initiator("INVITE", "r5", 2, body=other, ctype="application/sdp"),
                  world[U[0]])
    assert responses(world[U[0]])[-1].code == 488
    assert core.calls["r5"].media.endpoints[U[0]].remote_rtp == ("10.0.0.1", 49170)
    assert rt.manager.session("r5").state.value == "established"


def test_a_re_invite_renumbering_the_codec_is_accepted_under_the_new_number(core, rt, world):
    """MED-OP-01: the same codec under another payload type number is the
    same call codec; the relay's answer uses the offer's number (RFC 3264
    6.1), and both directions use it from then on."""
    call(core, world, "r5b")
    other = SDP.replace("RTP/AVP 0", "RTP/AVP 100").replace("a=rtpmap:0 PCMU/8000",
                                                            "a=rtpmap:100 PCMU/8000")
    assert other != SDP
    core.on_bytes(from_initiator("INVITE", "r5b", 2, body=other, ctype="application/sdp"),
                  world[U[0]])
    last = responses(world[U[0]])[-1]
    assert last.code == 200
    assert parse_sdp(last.body).payload_types == (100,)
    ep = core.calls["r5b"].media.endpoints[U[0]]
    assert (ep.rx_pt, ep.tx_pt) == (100, 100)


# -- MED-OP-01 in dialog, with a codec whose payload layout can differ --------

AMRWB = ("v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n"
         "m=audio 49170 RTP/AVP 97\r\na=rtpmap:97 AMR-WB/16000\r\n"
         "a=fmtp:97 mode-set=0,1,2\r\n")


def amr_sdp(pt=97, fmtp="", host="10.0.0.1"):
    body = AMRWB.replace("10.0.0.1", host).replace("RTP/AVP 97", f"RTP/AVP {pt}") \
        .replace("rtpmap:97", f"rtpmap:{pt}").replace("a=fmtp:97 mode-set=0,1,2\r\n", "")
    return body + (f"a=fmtp:{pt} {fmtp}\r\n" if fmtp else "")


def amr_call(core, world, cid, callee_pt=101):
    """u0 calls u1 (private) with AMR-WB as 97; u1 answers it as
    `callee_pt`."""
    from tests import mcpttinfo_fixture as mcf
    core.on_bytes(msg("INVITE", LOCAL, cid, 1, U[0], LOCAL,
                      body=mcf.body_for("private", U[1], AMRWB),
                      ctype=mcf.CONTENT_TYPE, extra=list(TIMER)), world[U[0]])
    leg = world[U[1]].requests("INVITE")[-1]
    core.on_bytes(answer(leg, 200, amr_sdp(callee_pt, host="10.0.0.2"),
                         extra=list(CALLEE_REFRESHES)), world[U[1]])
    (ok,) = responses(world[U[0]], 200)
    core.on_bytes(msg("ACK", contact_uri(ok.headers.get("Contact")), cid, 1, U[0], LOCAL,
                      branch=f"z9hG4bKack{cid}", to_tag=_tag(cid)), world[U[0]])
    return ok, leg


def pts(core, cid, uri):
    ep = core.calls[cid].media.endpoints[uri]
    return ep.rx_pt, ep.tx_pt, ep.remote_rtp


def test_amr_call_numbers(core, world):
    ok, leg = amr_call(core, world, "m1")
    assert "a=fmtp:97 mode-set=0,1,2" in leg.body
    assert pts(core, "m1", U[0]) == (97, 97, ("10.0.0.1", 49170))
    assert pts(core, "m1", U[1]) == (97, 101, ("10.0.0.2", 49170))


@pytest.mark.parametrize("fmtp", ["octet-align=1", "crc=1", "interleaving=4"])
def test_a_re_invite_changing_the_payload_layout_is_488_and_changes_nothing(core, world, fmtp):
    amr_call(core, world, "m2")
    before = pts(core, "m2", U[0])
    core.on_bytes(from_initiator("INVITE", "m2", 2, body=amr_sdp(97, fmtp, "10.7.7.7"),
                                 ctype="application/sdp"), world[U[0]])
    assert responses(world[U[0]])[-1].code == 488
    assert pts(core, "m2", U[0]) == before


def test_a_callee_update_renumbering_is_answered_with_its_number(core, world):
    _, leg = amr_call(core, world, "m3")
    core.on_bytes(from_callee("UPDATE", leg, 2, body=amr_sdp(102, host="10.0.0.9"),
                              ctype="application/sdp"), world[U[1]])
    r = responses(world[U[1]], method="UPDATE")[-1]
    assert r.code == 200 and parse_sdp(r.body).payload_types == (102,)
    assert pts(core, "m3", U[1]) == (102, 102, ("10.0.0.9", 49170))
    assert pts(core, "m3", U[0]) == (97, 97, ("10.0.0.1", 49170))   # untouched


def test_a_callee_update_changing_the_layout_is_488_and_changes_nothing(core, world):
    _, leg = amr_call(core, world, "m4")
    before = pts(core, "m4", U[1])
    core.on_bytes(from_callee("UPDATE", leg, 2, body=amr_sdp(101, "octet-align=1", "10.0.0.9"),
                              ctype="application/sdp"), world[U[1]])
    assert responses(world[U[1]], method="UPDATE")[-1].code == 488
    assert pts(core, "m4", U[1]) == before


def test_an_ack_answer_renumbering_changes_only_what_the_relay_sends(core, world):
    """The relay offered (offerless re-INVITE) its receive number, 97; the
    answer's 99 is what the caller wants to receive (RFC 3264 5.1), and the
    caller still sends 97 (6.1)."""
    amr_call(core, world, "m5")
    core.on_bytes(from_initiator("INVITE", "m5", 2), world[U[0]])
    offer = responses(world[U[0]])[-1]
    assert offer.code == 200 and parse_sdp(offer.body).payload_types == (97,)
    assert "a=fmtp:97 mode-set=0,1,2" in offer.body
    core.on_bytes(msg("ACK", LOCAL, "m5", 2, U[0], LOCAL, to_tag=_tag("m5"),
                      branch="z9hG4bKm5ack2", body=amr_sdp(99, host="10.8.8.8"),
                      ctype="application/sdp"), world[U[0]])
    assert pts(core, "m5", U[0]) == (97, 99, ("10.8.8.8", 49170))


def test_the_relays_later_offer_to_a_callee_carries_its_receive_number(core, world):
    """The callee answered 101 to the relay's 97 and sends 97: an offer the
    relay makes later keeps 97 (RFC 3264 8.3.2), not the callee's 101."""
    _, leg = amr_call(core, world, "m5b")
    core.on_bytes(from_callee("INVITE", leg, 2), world[U[1]])
    r = responses(world[U[1]])[-1]
    assert r.code == 200 and parse_sdp(r.body).payload_types == (97,)
    assert "a=rtpmap:97 AMR-WB/16000" in r.body
    assert pts(core, "m5b", U[1])[:2] == (97, 101)


def test_an_ack_answer_changing_the_layout_is_ignored(core, world):
    amr_call(core, world, "m6")
    before = pts(core, "m6", U[0])
    core.on_bytes(from_initiator("INVITE", "m6", 2), world[U[0]])
    core.on_bytes(msg("ACK", LOCAL, "m6", 2, U[0], LOCAL, to_tag=_tag("m6"),
                      branch="z9hG4bKm6ack2", body=amr_sdp(99, "crc=1", "10.8.8.8"),
                      ctype="application/sdp"), world[U[0]])
    assert pts(core, "m6", U[0]) == before


@pytest.mark.parametrize("m_line", ["RTP/AVP 300", "RTP/AVP 128", "RTP/AVP ²"])
def test_a_re_offer_with_a_number_rtp_cannot_carry_is_488(core, world, m_line):
    """Review of MED-OP-01: a number outside 0..127 (or not ASCII digits)
    names nothing; it neither crashes the relay nor is accepted."""
    amr_call(core, world, "m7")
    before = pts(core, "m7", U[0])
    pt = m_line.split()[-1]
    body = AMRWB.replace("RTP/AVP 97", m_line).replace("rtpmap:97", f"rtpmap:{pt}") \
        .replace("fmtp:97", f"fmtp:{pt}")
    core.on_bytes(from_initiator("INVITE", "m7", 2, body=body, ctype="application/sdp"),
                  world[U[0]])
    assert responses(world[U[0]])[-1].code == 488
    assert pts(core, "m7", U[0]) == before


def test_an_offerless_re_invite_gets_our_offer_and_its_ack_the_answer(core, world):
    call(core, world, "r6")
    core.on_bytes(from_initiator("INVITE", "r6", 2), world[U[0]])
    r = responses(world[U[0]])[-1]
    assert r.code == 200 and "m=audio" in r.body
    moved = SDP.replace("10.0.0.1", "10.8.8.8")
    core.on_bytes(msg("ACK", LOCAL, "r6", 2, U[0], LOCAL, to_tag=_tag("r6"),
                      branch="z9hG4bKr6ack2", body=moved, ctype="application/sdp"),
                  world[U[0]])
    assert core.calls["r6"].media.endpoints[U[0]].remote_rtp[0] == "10.8.8.8"


def test_a_refresh_below_90_is_a_422(core, world):
    call(core, world, "r7")
    core.on_bytes(from_initiator("UPDATE", "r7", 2, extra=["Session-Expires: 30"]),
                  world[U[0]])
    r = responses(world[U[0]], method="UPDATE")[-1]
    assert (r.code, r.headers.get("Min-SE")) == (422, "90")


# ============================================================ dialog checks


def test_a_refresh_from_another_connection_or_tag_is_481(core, world):
    call(core, world, "d1")
    stranger = Flow("stranger")
    core.on_bytes(from_initiator("UPDATE", "d1", 2), stranger)
    assert stranger.codes() == [481]
    core.on_bytes(msg("UPDATE", LOCAL, "d1", 3, U[0], LOCAL, to_tag="wrong"), world[U[0]])
    core.on_bytes(msg("UPDATE", LOCAL, "d1", 4, U[0], LOCAL, to_tag=_tag("d1"),
                      from_tag="other"), world[U[0]])
    assert [r.code for r in responses(world[U[0]], method="UPDATE")] == [481, 481]


def test_an_unknown_call_id_is_481(core, world):
    core.on_bytes(from_initiator("UPDATE", "nosuch", 2), world[U[0]])
    assert world[U[0]].codes()[-1] == 481


def test_a_cseq_that_does_not_rise_is_500(core, world):
    call(core, world, "d2")
    core.on_bytes(from_initiator("UPDATE", "d2", 5), world[U[0]])
    core.on_bytes(from_initiator("UPDATE", "d2", 5, extra=["X: again"])
                  .replace(b"z9hG4bKd25UPDATE", b"z9hG4bKd25bis"), world[U[0]])
    codes = [r.code for r in responses(world[U[0]], method="UPDATE")]
    assert codes[0] == 200 and codes[-1] in (482, 500)
    core.on_bytes(from_initiator("UPDATE", "d2", 4), world[U[0]])
    assert responses(world[U[0]], method="UPDATE")[-1].code == 500


def test_an_update_in_the_early_dialog_is_491(core, world):
    core.on_bytes(invite("d3", U[0], U[1], "private"), world[U[0]])
    core.on_bytes(from_initiator("UPDATE", "d3", 2), world[U[0]])
    assert responses(world[U[0]], method="UPDATE")[-1].code == 491


def test_glare_with_our_own_refresh_is_491(core, world, clock):
    call(core, world, "d4", extra=())                   # the platform refreshes
    clock.now += 900_000
    core.tick()
    assert world[U[0]].requests("INVITE")               # our refresh is out
    core.on_bytes(from_initiator("UPDATE", "d4", 2), world[U[0]])
    assert responses(world[U[0]], method="UPDATE")[-1].code == 491


# ============================================================ the platform refreshes


def _our_refresh(flow, method):
    return [r for r in flow.requests(method)][-1]


def test_the_platform_refreshes_an_originator_without_timers(core, rt, world, clock):
    """No Allow: UPDATE from the originator, so a re-INVITE with the SDP it
    already has, at half the interval; the 2xx is ACKed, and re-ACKed."""
    ok, _ = call(core, world, "p1", extra=())
    clock.now += 900_000 - 1
    core.tick()
    assert not world[U[0]].requests("INVITE")
    clock.now += 1
    core.tick()
    req = _our_refresh(world[U[0]], "INVITE")
    assert req.headers.get("Session-Expires") == "1800;refresher=uac"
    assert req.headers.get("To").endswith("tag=ft")
    assert _tag("p1") in req.headers.get("From")
    assert "m=audio" in req.body
    assert contact_uri(req.headers.get("Contact")) == contact_uri(ok.headers.get("Contact"))
    core.on_bytes(reply(req, 200, extra=["Session-Expires: 1800;refresher=uac"], body=SDP),
                  world[U[0]])
    acks = world[U[0]].requests("ACK")
    assert len(acks) == 1 and acks[0].headers.get("CSeq").endswith("ACK")
    core.on_bytes(reply(req, 200, extra=["Session-Expires: 1800;refresher=uac"], body=SDP),
                  world[U[0]])
    assert len(world[U[0]].requests("ACK")) == 2
    # timer restarted from the 2xx: nothing at the old expiry
    clock.now += 900_000 + 1
    core.tick()
    assert rt.manager.session("p1").state.value == "established"


def test_the_platform_refreshes_with_update_when_allowed(core, world, clock):
    call(core, world, "p2", extra=["Allow: INVITE, ACK, BYE, UPDATE"])
    clock.now += 900_000
    core.tick()
    req = _our_refresh(world[U[0]], "UPDATE")
    assert not req.body and req.headers.get("Supported") == "timer"
    core.on_bytes(reply(req, 200, extra=["Session-Expires: 1800;refresher=uac"]),
                  world[U[0]])
    assert not world[U[0]].requests("ACK")


@pytest.mark.parametrize("code", [481, 408])
def test_a_refresh_answered_481_or_408_ends_the_call(core, rt, world, clock, code):
    call(core, world, f"p3{code}", extra=["Allow: UPDATE"])
    clock.now += 900_000
    core.tick()
    core.on_bytes(reply(_our_refresh(world[U[0]], "UPDATE"), code), world[U[0]])
    assert rt.manager.session(f"p3{code}").state.value == "released"
    assert world[U[1]].requests("BYE")


def test_an_unanswered_refresh_ends_the_call(core, rt, world, clock):
    call(core, world, "p4", extra=["Allow: UPDATE"])
    clock.now += 900_000
    core.tick()
    clock.now += 64 * 500
    core.tick()
    assert rt.manager.session("p4").state.value == "released"


def test_a_refresh_answered_422_is_resent_with_its_min_se(core, world, clock):
    call(core, world, "p5", extra=["Allow: UPDATE"])
    clock.now += 900_000
    core.tick()
    first = _our_refresh(world[U[0]], "UPDATE")
    core.on_bytes(reply(first, 422, extra=["Min-SE: 3600"]), world[U[0]])
    second = _our_refresh(world[U[0]], "UPDATE")
    assert second is not first
    assert second.headers.get("Session-Expires") == "3600;refresher=uac"
    assert second.headers.get("Min-SE") == "3600"            # RFC 4028 7.4
    core.on_bytes(reply(second, 200, extra=["Session-Expires: 3600;refresher=uac"]),
                  world[U[0]])
    clock.now += 1_800_000
    core.tick()
    assert _our_refresh(world[U[0]], "UPDATE").headers.get("Min-SE") == "3600"


def test_a_refresh_answered_491_is_retried_later(core, world, clock):
    """RFC 3261 14.1: the initiator owns its dialog's Call-ID, so the
    platform waits 0-2 s there."""
    call(core, world, "p6", extra=["Allow: UPDATE"])
    clock.now += 900_000
    core.tick()
    core.on_bytes(reply(_our_refresh(world[U[0]], "UPDATE"), 491), world[U[0]])
    assert len(world[U[0]].requests("UPDATE")) == 1
    t = core.calls["p6"].timer
    assert clock.now <= t.refresh_at < clock.now + 2_000
    clock.now += 2_000
    core.tick()
    assert len(world[U[0]].requests("UPDATE")) == 2


def test_a_leg_refresh_answered_491_waits_as_the_call_id_owner(core, world, clock):
    """The platform chose the leg's Call-ID: 2.1-4 s."""
    _, leg = call(core, world, "p9",
                  callee_extra=["Session-Expires: 600;refresher=uac", "Allow: UPDATE"])
    clock.now += 300_000
    core.tick()
    core.on_bytes(reply(world[U[1]].requests("UPDATE")[-1], 491), world[U[1]])
    t = core.calls["p9"].legs[leg.headers.get("Call-ID")].timer
    assert clock.now + 2_100 <= t.refresh_at < clock.now + 4_000


def test_a_refresh_answered_500_is_retried_before_expiry(core, rt, world, clock):
    # a timer-capable caller that asks the platform to refresh: a
    # negotiated timer, which refusals do not keep alive
    call(core, world, "p7", extra=TIMER + ["Session-Expires: 1800;refresher=uas",
                                            "Allow: UPDATE"])
    clock.now += 900_000
    core.tick()
    core.on_bytes(reply(_our_refresh(world[U[0]], "UPDATE"), 500), world[U[0]])
    clock.now += 450_000                                  # halfway to expiry
    core.tick()
    assert len(world[U[0]].requests("UPDATE")) == 2
    assert rt.manager.session("p7").state.value == "established"


def test_refreshes_that_keep_failing_end_the_call_at_expiry(core, rt, world, clock):
    # a timer-capable caller that asks the platform to refresh: a
    # negotiated timer, which refusals do not keep alive
    call(core, world, "p8", extra=TIMER + ["Session-Expires: 1800;refresher=uas",
                                            "Allow: UPDATE"])
    for _ in range(40):                                   # 2400 s > 1800 s
        clock.now += 60_000
        core.tick()
        for r in world[U[0]].requests("UPDATE"):
            core.on_bytes(reply(r, 500), world[U[0]])
    assert rt.manager.session("p8").state.value == "released"


# ============================================================ callee legs


def test_a_callee_that_refreshes_is_watched(core, rt, world, clock):
    _, leg = call(core, world, "l1",
                  callee_extra=["Session-Expires: 600;refresher=uas", "Require: timer"])
    clock.now += 300_000
    core.tick()                     # the callee refreshes: the platform does not
    assert len(world[U[1]].requests("INVITE")) == 1 and not world[U[1]].requests("UPDATE")
    clock.now += 200_000
    core.on_bytes(from_callee("UPDATE", leg, 1, extra=TIMER + ["Session-Expires: 600"]),
                  world[U[1]])
    r = responses(world[U[1]], method="UPDATE")[-1]
    assert r.code == 200 and r.headers.get("Session-Expires") == "600;refresher=uac"
    assert r.headers.get("Supported") == "timer"
    clock.now += 500_000
    core.tick()
    assert rt.manager.session("l1").state.value == "established"
    clock.now += 100_000                                    # no second refresh
    core.tick()
    assert world[U[1]].requests("BYE")
    assert rt.manager.session("l1").state.value == "released"   # private: the call too
    assert world[U[0]].requests("BYE")


def test_a_callee_leaving_the_refresh_to_us_gets_updates(core, world, clock):
    _, leg = call(core, world, "l2",
                  callee_extra=["Session-Expires: 600;refresher=uac", "Allow: UPDATE"])
    clock.now += 300_000
    core.tick()
    req = world[U[1]].requests("UPDATE")[-1]
    assert req.headers.get("To").endswith("tag=callee")
    assert req.headers.get("From").endswith(f"tag={leg.headers.get('Call-ID')}-l")
    assert req.headers.get("CSeq") == "2 UPDATE"


def test_a_callee_without_timers_is_refreshed_by_the_platform(core, rt, world, clock):
    """RFC 4028 7.2: no Session-Expires in the callee's 2xx, no timer of its
    own. The platform keeps one and refreshes at the deployment's interval,
    and a callee that no longer answers is found out (review of SIP-OP-17)."""
    _, leg = call(core, world, "l3", callee_extra=["Allow: UPDATE"])
    clock.now += 900_000
    core.tick()
    req = world[U[1]].requests("UPDATE")[-1]
    # its 2xx has no Session-Expires either: the platform's timer goes on
    core.on_bytes(reply(req, 200), world[U[1]])
    # (the caller keeps its own side alive meanwhile)
    core.on_bytes(from_initiator("UPDATE", "l3", 2, extra=TIMER), world[U[0]])
    clock.now += 900_000
    core.tick()
    assert len(world[U[1]].requests("UPDATE")) == 2
    assert rt.manager.session("l3").state.value == "established"
    clock.now += 64 * 500                                   # unanswered: 408
    core.tick()
    assert rt.manager.session("l3").state.value == "released"


def test_an_originator_without_timers_stays_watched(core, rt, world, clock):
    """The same on the caller's dialog: a caller without RFC 4028 answers
    the platform's refresh without Session-Expires, and the platform's timer
    must not stop there (review of SIP-OP-17, E1)."""
    call(core, world, "l9", extra=["Allow: UPDATE"])
    clock.now += 900_000
    core.tick()
    core.on_bytes(reply(world[U[0]].requests("UPDATE")[-1], 200), world[U[0]])
    clock.now += 900_000
    core.tick()
    assert len(world[U[0]].requests("UPDATE")) == 2
    clock.now += 64 * 500
    core.tick()
    assert rt.manager.session("l9").state.value == "released"


def test_a_peer_that_turns_its_timer_off_ends_the_platforms_watch(core, world, clock):
    """RFC 4028 7.2: a timer-capable peer may turn the timer off with a 2xx
    lacking Session-Expires; that timer was the peer's, not the platform's own."""
    call(core, world, "l10", extra=TIMER + ["Session-Expires: 600;refresher=uas",
                                            "Allow: UPDATE"])
    clock.now += 300_000
    core.tick()
    core.on_bytes(reply(world[U[0]].requests("UPDATE")[-1], 200), world[U[0]])
    assert core.calls["l10"].timer is None


def test_a_callee_re_invite_moving_its_address(core, world):
    _, leg = call(core, world, "l4")
    moved = SDP.replace("10.0.0.1", "10.6.6.6")
    core.on_bytes(from_callee("INVITE", leg, 1, body=moved, ctype="application/sdp"),
                  world[U[1]])
    assert responses(world[U[1]])[-1].code == 200
    assert core.calls["l4"].media.endpoints[U[1]].remote_rtp[0] == "10.6.6.6"


def test_a_callee_refresh_from_another_tag_is_481(core, world):
    _, leg = call(core, world, "l5")
    cid = leg.headers.get("Call-ID")
    core.on_bytes(msg("UPDATE", LOCAL, cid, 1, U[1], LOCAL, to_tag=f"{cid}-l",
                      from_tag="fork"), world[U[1]])
    assert world[U[1]].codes()[-1] == 481


def test_a_422_from_a_callee_is_retried_once_with_its_min_se(core, world):
    core.on_bytes(invite("l6", U[0], U[1], "private"), world[U[0]])
    first = world[U[1]].requests("INVITE")[-1]
    core.on_bytes(answer(first, 422, extra=["Min-SE: 2000"]), world[U[1]])
    second = world[U[1]].requests("INVITE")[-1]
    assert second is not first
    assert second.headers.get("Session-Expires") == "2000"
    assert second.headers.get("Min-SE") == "2000"
    assert second.headers.get("CSeq") == "2 INVITE"
    assert second.headers.get("Call-ID") == first.headers.get("Call-ID")
    core.on_bytes(answer(second, 422, extra=["Min-SE: 4000"]), world[U[1]])
    assert len(world[U[1]].requests("INVITE")) == 2           # once only
    assert responses(world[U[0]])[-1].code >= 400


@pytest.mark.parametrize("min_se", [None, "abc", "1800", "100000"])
def test_a_422_that_asks_for_nothing_usable_fails_the_leg(core, world, min_se):
    core.on_bytes(invite(f"l7{min_se}", U[0], U[1], "private"), world[U[0]])
    first = world[U[1]].requests("INVITE")[-1]
    extra = [f"Min-SE: {min_se}"] if min_se else []
    core.on_bytes(answer(first, 422, extra=extra), world[U[1]])
    assert len(world[U[1]].requests("INVITE")) == 1



def test_a_callee_refresh_from_another_connection_is_481(core, world):
    _, leg = call(core, world, "l8")
    other = Flow("other")
    core.on_bytes(from_callee("UPDATE", leg, 1), other)
    assert other.codes() == [481]


def test_a_refresh_moves_the_remote_target(core, world, clock):
    """RFC 3261 12.2.2 / RFC 3311: an in-dialog request's Contact is the new
    remote target, where the platform's next request on the dialog goes."""
    call(core, world, "m1", extra=TIMER + ["Session-Expires: 600"])
    core.on_bytes(from_initiator("UPDATE", "m1", 2, extra=TIMER + [
        "Session-Expires: 600", "Contact: <sip:u0@10.5.5.5;transport=tls>"]),
        world[U[0]])
    clock.now += 568_000
    core.tick()                                           # expired: BYE
    (bye,) = world[U[0]].requests("BYE")
    assert bye.uri == "sip:u0@10.5.5.5;transport=tls"


def test_a_refresh_can_hand_the_refreshing_to_the_platform(core, world, clock):
    """An UPDATE with refresher=uas makes the platform the refresher; its
    Allow says the originator now takes UPDATE, so the refresh is one."""
    call(core, world, "m2", extra=TIMER + ["Session-Expires: 600"])
    core.on_bytes(from_initiator("UPDATE", "m2", 2, extra=TIMER + [
        "Session-Expires: 600;refresher=uas", "Allow: INVITE, ACK, BYE, UPDATE"]),
        world[U[0]])
    (r,) = responses(world[U[0]], 200, "UPDATE")
    assert r.headers.get("Session-Expires") == "600;refresher=uas"
    clock.now += 300_000
    core.tick()
    assert world[U[0]].requests("UPDATE") and not world[U[0]].requests("INVITE")


def test_without_a_relay_only_the_same_offer_is_accepted(core, world):
    """A call the platform relays no media for (media is None) cannot move
    anything: the original offer again is answered as before, any other 488."""
    ok, _ = call(core, world, "m3")
    core.calls["m3"].media = None
    # a re-offer may bump the origin version (RFC 3264 8): still the same
    core.on_bytes(from_initiator("INVITE", "m3", 2, body=SDP.replace("o=- 0 0", "o=- 0 1"),
                                 ctype="application/sdp"), world[U[0]])
    first = responses(world[U[0]])[-1]
    assert first.code == 200 and first.body == ok.body
    core.on_bytes(from_initiator("INVITE", "m3", 3, body=SDP.replace("10.0.0.1", "10.4.4.4"),
                                 ctype="application/sdp"), world[U[0]])
    assert responses(world[U[0]])[-1].code == 488



# ============================================================ review of SIP-OP-17


@pytest.mark.parametrize("refresher", ["uas", "uac"])
def test_a_peer_interval_below_90_is_taken_as_90(core, rt, world, clock, refresher):
    """A callee answering Session-Expires: 1 would have its call ended at
    0.7 s, or be refreshed twice a second (E2)."""
    call(core, world, f"v1{refresher}",
         callee_extra=[f"Session-Expires: 1;refresher={refresher}", "Allow: UPDATE"])
    clock.now += 10_000
    core.tick()
    assert not world[U[1]].requests("BYE") and not world[U[1]].requests("UPDATE")
    leg = next(iter(core.calls[f"v1{refresher}"].legs.values()))
    assert leg.timer.seconds == 90


def test_the_platforms_tags_are_not_a_plain_hash_of_the_call_id():
    """A callee knows the caller's Call-ID (its own leg's is derived from it);
    the tag the caller's dialog is bound by must not be computable from it."""
    import hashlib
    assert _tag("c1") != "mcx-" + hashlib.sha1(b"c1").hexdigest()[:10]
    assert _tag("c1") == _tag("c1") and len(_tag("c1")) == 4 + 16


def test_an_ack_with_foreign_tags_cannot_carry_the_answer(core, world):
    """E5: absorb_ack matches Call-ID, CSeq and connection only. On a shared
    core connection a callee could race the caller's ACK and move its media."""
    call(core, world, "v2")
    core.on_bytes(from_initiator("INVITE", "v2", 2), world[U[0]])     # offerless
    evil = SDP.replace("10.0.0.1", "6.6.6.6")
    core.on_bytes(msg("ACK", LOCAL, "v2", 2, U[0], LOCAL, to_tag="bogus", from_tag="bogus",
                      branch="z9hG4bKv2evil", body=evil, ctype="application/sdp"),
                  world[U[0]])
    assert core.calls["v2"].media.endpoints[U[0]].remote_rtp[0] == "10.0.0.1"


@pytest.mark.parametrize("address, port", [("0.0.0.0", "49170"), ("224.0.0.1", "49170"),
                                           ("255.255.255.255", "49170"), ("10.1.1.1", "0")])
def test_an_offer_to_no_unicast_peer_is_488(core, world, address, port):
    call(core, world, "v3")
    bad = SDP.replace("10.0.0.1", address).replace("49170", port)
    core.on_bytes(from_initiator("INVITE", "v3", 2, body=bad, ctype="application/sdp"),
                  world[U[0]])
    assert responses(world[U[0]])[-1].code == 488
    assert core.calls["v3"].media.endpoints[U[0]].remote_rtp == ("10.0.0.1", 49170)


def test_parse_sdp_refuses_what_the_relay_cannot_send_to():
    from core.sip import parse_sdp
    for bad in ("0.0.0.0", "224.1.2.3", "255.255.255.255", "ff02::1", "::"):
        with pytest.raises(SipError):
            parse_sdp(SDP.replace("10.0.0.1", bad))
    with pytest.raises(SipError):
        parse_sdp(SDP.replace("49170", "0"))
    assert parse_sdp(SDP.replace("10.0.0.1", "127.0.0.1")).address == "127.0.0.1"
    assert parse_sdp(SDP.replace("10.0.0.1", "media.example")).address == "media.example"
    declined = SDP + "m=application 0 udp MCPTT\r\n"
    assert parse_sdp(declined).floor_port is None


def test_an_initial_offer_to_no_unicast_peer_fails_the_call(core, world):
    from tests import mcpttinfo_fixture as mcf
    body = mcf.body_for("private", U[1], SDP.replace("10.0.0.1", "0.0.0.0"))
    core.on_bytes(msg("INVITE", LOCAL, "v4", 1, U[0], LOCAL, body=body,
                      ctype=mcf.CONTENT_TYPE), world[U[0]])
    assert responses(world[U[0]])[-1].code == 488
    assert not world[U[1]].requests("INVITE")


def test_the_ack_to_a_refresh_follows_the_new_target(core, world, clock):
    """E6: RFC 3261 12.2.1.1, the 2xx's Contact is the remote target, and
    the ACK is the first request that goes to it."""
    call(core, world, "v5", extra=())
    clock.now += 900_000
    core.tick()
    req = _our_refresh(world[U[0]], "INVITE")
    core.on_bytes(reply(req, 200, body=SDP, extra=[
        "Contact: <sip:u0@10.3.3.3;transport=tls>"]), world[U[0]])
    (ack,) = world[U[0]].requests("ACK")
    assert ack.uri == "sip:u0@10.3.3.3;transport=tls"


def test_a_session_timer_fault_does_not_stop_the_transactions(core, world, clock):
    """E10: a fault in one dialog's timer must not skip the 2xx
    retransmissions of another call in the same tick."""
    call(core, world, "v6", extra=["Allow: UPDATE"])
    clock.now += 899_000
    core.on_bytes(invite("v7", U[2], U[3], "private"), world[U[2]])
    core.on_bytes(answer(world[U[3]].requests("INVITE")[-1], 200, SDP), world[U[3]])
    before = world[U[2]].codes().count(200)

    def boom(call, leg):
        raise RuntimeError("injected")
    core._send_refresh = boom
    clock.now += 1_000                              # v6's refresh due, v7's 2xx too
    core.tick()                                     # must not raise
    assert world[U[2]].codes().count(200) > before  # v7's 2xx still retransmitted
    assert core.calls["v6"].timer.refresh_at is None     # not retried in a loop


def test_a_fault_on_a_response_does_not_end_the_reader(core, world):
    call(core, world, "v8")
    core._on_response = lambda resp, flow: (_ for _ in ()).throw(RuntimeError("x"))
    core.on_bytes(answer(world[U[1]].requests("INVITE")[-1], 200, SDP), world[U[1]])


def test_an_offer_while_ours_awaits_its_answer_is_491(core, world):
    """E8: our offer (the 2xx to an offerless re-INVITE) awaits the ACK."""
    call(core, world, "v9")
    core.on_bytes(from_initiator("INVITE", "v9", 2), world[U[0]])
    core.on_bytes(from_initiator("UPDATE", "v9", 3, body=SDP, ctype="application/sdp"),
                  world[U[0]])
    assert responses(world[U[0]], method="UPDATE")[-1].code == 491
    core.on_bytes(msg("ACK", LOCAL, "v9", 2, U[0], LOCAL, to_tag=_tag("v9"),
                      branch="z9hG4bKv9ack", body=SDP, ctype="application/sdp"),
                  world[U[0]])
    core.on_bytes(from_initiator("UPDATE", "v9", 4, body=SDP, ctype="application/sdp"),
                  world[U[0]])
    assert responses(world[U[0]], method="UPDATE")[-1].code == 200


def test_crossing_offerless_updates_are_not_glare(core, world, clock):
    """RFC 3311 5.2 is about offers: two UPDATEs without one do not collide."""
    call(core, world, "v10", extra=["Allow: UPDATE"])
    clock.now += 900_000
    core.tick()                                              # ours is out
    core.on_bytes(from_initiator("UPDATE", "v10", 2), world[U[0]])
    assert responses(world[U[0]], method="UPDATE")[-1].code == 200
    core.on_bytes(from_initiator("UPDATE", "v10", 3, body=SDP, ctype="application/sdp"),
                  world[U[0]])
    assert responses(world[U[0]], method="UPDATE")[-1].code == 491


def test_a_refresh_without_timer_support_makes_the_platform_keep_its_own(core, world, clock):
    """A caller that refreshes without listing `timer` (a different UA after
    a failover, say) makes the platform the refresher (RFC 4028 section 9);
    its later 2xx without Session-Expires must not stop the platform's timer."""
    call(core, world, "v11")
    core.on_bytes(from_initiator("UPDATE", "v11", 2, extra=["Allow: UPDATE"]), world[U[0]])
    r = responses(world[U[0]], 200, "UPDATE")[-1]
    assert r.headers.get("Session-Expires") == "1800;refresher=uas"
    assert r.headers.get("Require") is None
    clock.now += 900_000
    core.tick()
    core.on_bytes(reply(world[U[0]].requests("UPDATE")[-1], 200), world[U[0]])
    assert core.calls["v11"].timer is not None and core.calls["v11"].timer.own


def test_an_answer_that_never_came_does_not_block_later_offers(core, world, clock):
    """A callee's offerless re-INVITE whose 2xx (our offer) is never ACKed:
    once the 2xx gives up (64*T1), the callee may offer again."""
    _, leg = call(core, world, "v12")
    core.on_bytes(from_callee("INVITE", leg, 1), world[U[1]])       # offerless
    core.on_bytes(from_callee("UPDATE", leg, 2, body=SDP, ctype="application/sdp"),
                  world[U[1]])
    assert responses(world[U[1]], method="UPDATE")[-1].code == 491
    clock.now += 64 * 500
    core.tick()
    core.on_bytes(from_callee("UPDATE", leg, 3, body=SDP, ctype="application/sdp"),
                  world[U[1]])
    assert responses(world[U[1]], method="UPDATE")[-1].code == 200


# ============================================================ re-review of SIP-OP-17


def test_a_forged_ack_does_not_use_up_the_genuine_one(core, world):
    """G: the foreign ACK is refused AND leaves the transaction to the real
    one, whose answer then applies; later offers are not blocked."""
    call(core, world, "w1")
    core.on_bytes(from_initiator("INVITE", "w1", 2), world[U[0]])      # offerless
    core.on_bytes(msg("ACK", LOCAL, "w1", 2, U[0], LOCAL, to_tag="bogus", from_tag="bogus",
                      branch="z9hG4bKw1evil", body=SDP.replace("10.0.0.1", "6.6.6.6"),
                      ctype="application/sdp"), world[U[0]])
    core.on_bytes(msg("ACK", LOCAL, "w1", 2, U[0], LOCAL, to_tag=_tag("w1"),
                      branch="z9hG4bKw1ack", body=SDP.replace("10.0.0.1", "10.2.2.2"),
                      ctype="application/sdp"), world[U[0]])
    assert core.calls["w1"].media.endpoints[U[0]].remote_rtp[0] == "10.2.2.2"
    assert core.calls["w1"].awaiting_answer is False
    core.on_bytes(from_initiator("INVITE", "w1", 3, body=SDP, ctype="application/sdp"),
                  world[U[0]])
    assert responses(world[U[0]])[-1].code == 200


@pytest.mark.parametrize("code", [405, 488, 500, 501])
def test_any_answer_to_the_platforms_own_timer_says_the_peer_is_there(core, rt, world,
                                                                        clock, code):
    """B: a peer that never ran a timer and refuses the refresh method is
    alive; its call must not end for that."""
    call(core, world, f"w2{code}", extra=["Allow: UPDATE"])
    clock.now += 900_000
    core.tick()
    core.on_bytes(reply(world[U[0]].requests("UPDATE")[-1], code), world[U[0]])
    clock.now += 950_000                              # past the old expiry
    core.tick()
    assert rt.manager.session(f"w2{code}").state.value == "established"
    assert len(world[U[0]].requests("UPDATE")) == 2   # and it is still asked


def test_a_negotiated_timer_is_not_kept_alive_by_a_refusal(core, rt, world, clock):
    """Contrast: a peer-negotiated timer (own=False) that keeps failing
    expires, as RFC 4028 says."""
    call(core, world, "w3", extra=TIMER + ["Session-Expires: 1800;refresher=uas",
                                           "Allow: UPDATE"])
    for _ in range(40):
        clock.now += 60_000
        core.tick()
        for r in world[U[0]].requests("UPDATE"):
            core.on_bytes(reply(r, 500), world[U[0]])
    assert rt.manager.session("w3").state.value == "released"


def test_an_expiry_that_faults_removes_the_call_once(core, rt, world, clock):
    """C: a fault while ending an expired dialog is not retried every tick."""
    call(core, world, "w4", extra=TIMER + ["Session-Expires: 600"])
    calls = []

    def boom(call, leg, cause):
        calls.append(cause)
        raise RuntimeError("injected")
    core._dialog_gone = boom
    clock.now += 568_000
    core.tick()
    core.tick()
    assert calls == ["session-expired"]
    assert "w4" not in core.calls and "w4" not in core._dialogs
    assert rt.manager.session("w4").state.value == "released"


# ============================================================ reconnect (SIP-OP-18 item 6)
# Decided 2026-09-25: a request on a new connection that authenticates the
# same party is accepted, and the dialog moves there; the old one loses it.


def test_a_reconnected_caller_refreshes_and_the_dialog_moves(core, rt, world, clock):
    call(core, world, "x1", extra=TIMER + ["Session-Expires: 600"])
    old, new = world[U[0]], Flow(U[0])                   # same certificate identity
    core.on_bytes(from_initiator("UPDATE", "x1", 2, extra=TIMER + ["Session-Expires: 600"]),
                  new)
    assert new.codes() == [200]
    assert core.calls["x1"].flow is new
    # the old connection no longer acts on the dialog
    core.on_bytes(from_initiator("UPDATE", "x1", 3), old)
    assert responses(old, method="UPDATE")[-1].code == 481
    # and what the platform sends on it goes to the new one
    clock.now += 568_000
    core.tick()
    assert new.requests("BYE") and not old.requests("BYE")
    assert rt.manager.session("x1").state.value == "released"


def test_a_connection_that_is_not_the_caller_cannot_move_the_dialog(core, world):
    call(core, world, "x2")
    for n, f in enumerate((Flow("sip:u2@mcptt.example"), Flow("anon", uris=()),
                           Flow("other-core", uris=(), dns=("other-core.example",),
                                core=True))):
        core.on_bytes(from_initiator("UPDATE", "x2", 2 + n), f)
        assert f.codes() == [481]
    assert core.calls["x2"].flow is world[U[0]]


def _core(name="proxy"):
    return Flow(name, uris=(), dns=("core-client.example",), core=True)


def test_a_trusted_core_cannot_take_a_users_dialog(core, world):
    """A core may assert any identity, but not take over a dialog from a
    user's own connection: that would hand it the user's media (review of
    SIP-OP-18 item 6, P1)."""
    _, leg = call(core, world, "x3")
    proxy = _core()
    core.on_bytes(from_initiator("UPDATE", "x3", 2), proxy)
    assert proxy.codes() == [481] and core.calls["x3"].flow is world[U[0]]
    evil = SDP.replace("10.0.0.1", "203.0.113.66")
    core.on_bytes(from_callee("INVITE", leg, 1, body=evil, ctype="application/sdp"), proxy)
    assert proxy.codes()[-1] == 481
    assert core.calls["x3"].media.endpoints[U[1]].remote_rtp[0] == "10.0.0.1"


def test_a_core_dialog_moves_to_another_connection_of_that_core(core, world):
    from tests import mcpttinfo_fixture as mcf
    first, second = _core("proxy-1"), _core("proxy-2")
    core.on_bytes(msg("INVITE", LOCAL, "x3c", 1, U[0], LOCAL,
                      body=mcf.body_for("private", U[1], SDP), ctype=mcf.CONTENT_TYPE),
                  first)
    core.on_bytes(answer(world[U[1]].requests("INVITE")[-1], 200, SDP,
                         extra=CALLEE_REFRESHES), world[U[1]])
    core.on_bytes(from_initiator("UPDATE", "x3c", 2), second)
    assert second.codes() == [200] and core.calls["x3c"].flow is second
    # and the user's own certificate may take it from the core (identity =
    # certificate), but no other core name may
    other = Flow("oc", uris=(), dns=("other-core.example",), core=True)
    core.on_bytes(from_initiator("UPDATE", "x3c", 3), other)
    assert other.codes() == [481]
    mine = Flow(U[0])
    core.on_bytes(from_initiator("UPDATE", "x3c", 4), mine)
    assert mine.codes() == [200] and core.calls["x3c"].flow is mine


def test_leg_call_ids_reveal_nothing_about_the_call(core, world):
    """Random: a member cannot compute the caller's Call-ID, another leg's,
    or the platform's tag on it."""
    core.on_bytes(invite("x3d", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    ids = [world[u].requests("INVITE")[-1].headers.get("Call-ID") for u in U[1:]]
    assert len(set(ids)) == 3 and not any("x3d" in i for i in ids)


def test_the_tags_and_cseq_still_decide_before_anything_moves(core, world):
    call(core, world, "x4")
    new = Flow(U[0])
    core.on_bytes(msg("UPDATE", LOCAL, "x4", 2, U[0], LOCAL, to_tag="wrong"), new)
    core.on_bytes(from_initiator("UPDATE", "x4", 5), world[U[0]])
    core.on_bytes(from_initiator("UPDATE", "x4", 4), new)         # CSeq does not rise
    assert new.codes() == [481, 500]
    assert core.calls["x4"].flow is world[U[0]]


def test_a_reconnected_callee_moves_its_leg(core, world, clock):
    _, leg = call(core, world, "x5",
                  callee_extra=["Session-Expires: 600;refresher=uac", "Allow: UPDATE"])
    new = Flow(U[1])
    core.on_bytes(from_callee("UPDATE", leg, 1), new)
    assert new.codes() == [200]
    the_leg = core.calls["x5"].legs[leg.headers.get("Call-ID")]
    assert the_leg.flow is new
    core.on_bytes(from_callee("UPDATE", leg, 2), world[U[1]])       # the old one
    assert world[U[1]].codes()[-1] == 481


def test_our_refresh_outstanding_on_the_old_connection_is_abandoned(core, rt, world, clock):
    """Otherwise its 64*T1 timeout would read as 408 and end the call the
    reconnect just saved."""
    call(core, world, "x6", extra=["Allow: UPDATE"])              # the platform refreshes
    clock.now += 900_000
    core.tick()
    assert world[U[0]].requests("UPDATE")                          # out on the old one
    new = Flow(U[0])
    core.on_bytes(from_initiator("UPDATE", "x6", 2, extra=TIMER), new)
    assert new.codes() == [200]
    clock.now += 64 * 500
    core.tick()
    assert rt.manager.session("x6").state.value == "established"
    assert core.calls["x6"].refresh is None


def test_a_reconnected_party_may_hang_up(core, rt, world):
    call(core, world, "x7")
    new = Flow(U[0])
    core.on_bytes(from_initiator("BYE", "x7", 2), new)
    assert new.codes() == [200]
    assert rt.manager.session("x7").state.value == "released"
    stranger = Flow("sip:u3@mcptt.example")
    world[U[0]].sent.clear()
    call(core, world, "x8")
    core.on_bytes(from_initiator("BYE", "x8", 2), stranger)
    assert stranger.codes() == [481]


def test_a_reconnected_callee_may_hang_up_its_leg(core, rt, world):
    _, leg = call(core, world, "x9")
    new = Flow(U[1])
    core.on_bytes(from_callee("BYE", leg, 1), new)
    assert new.codes() == [200]
    assert rt.manager.session("x9").state.value == "released"     # private: the call


def test_an_ack_still_needs_the_dialogs_own_connection(core, world):
    """ACKs are not moved: the 2xx they acknowledge went out on a connection,
    and its transaction is matched there."""
    call(core, world, "x10")
    core.on_bytes(from_initiator("INVITE", "x10", 2), world[U[0]])   # offerless
    new = Flow(U[0])
    core.on_bytes(msg("ACK", LOCAL, "x10", 2, U[0], LOCAL, to_tag=_tag("x10"),
                      branch="z9hG4bKx10ack", body=SDP.replace("10.0.0.1", "10.9.1.1"),
                      ctype="application/sdp"), new)
    assert core.calls["x10"].media.endpoints[U[0]].remote_rtp[0] == "10.0.0.1"



def test_a_dropped_connection_cannot_take_the_dialog_back(core, world):
    """It authenticates the same party, but the dialog left it: dropped."""
    call(core, world, "x11")
    old, new, newer = world[U[0]], Flow(U[0]), Flow(U[0])
    core.on_bytes(from_initiator("UPDATE", "x11", 2), new)
    core.on_bytes(from_initiator("UPDATE", "x11", 3), old)
    assert responses(old, method="UPDATE")[-1].code == 481
    core.on_bytes(from_initiator("UPDATE", "x11", 4), newer)      # a further move is fine
    assert newer.codes() == [200] and core.calls["x11"].flow is newer
    core.on_bytes(from_initiator("UPDATE", "x11", 5), new)
    assert new.codes() == [200, 481]



@pytest.mark.parametrize("who", ["caller", "callee"])
def test_a_bye_from_a_new_connection_needs_both_tags(core, rt, world, who):
    """P2: from another connection the platform's (keyed) tag must match too."""
    _, leg = call(core, world, f"y1{who}")
    if who == "caller":
        new = Flow(U[0])
        core.on_bytes(msg("BYE", LOCAL, f"y1{who}", 2, U[0], LOCAL, to_tag="garbage"), new)
    else:
        new = Flow(U[1])
        cid = leg.headers.get("Call-ID")
        core.on_bytes(msg("BYE", LOCAL, cid, 2, U[1], LOCAL, to_tag="garbage",
                          from_tag="callee"), new)
    assert new.codes() == [481]
    assert rt.manager.session(f"y1{who}").state.value == "established"


@pytest.mark.parametrize("bad", ["488", "422"])
def test_a_refused_request_moves_nothing(core, world, bad):
    """P3: the move is the last thing done, and only for a 200."""
    call(core, world, f"y2{bad}")
    new = Flow(U[0])
    if bad == "488":
        other = SDP.replace("RTP/AVP 0", "RTP/AVP 8").replace("0 PCMU/8000", "8 PCMA/8000")
        core.on_bytes(from_initiator("INVITE", f"y2{bad}", 2, body=other,
                                     ctype="application/sdp"), new)
    else:
        core.on_bytes(from_initiator("UPDATE", f"y2{bad}", 2,
                                     extra=["Session-Expires: 30"]), new)
    assert new.codes()[-1] == int(bad)
    assert core.calls[f"y2{bad}"].flow is world[U[0]]


def test_an_ack_on_the_connection_the_dialog_left_still_completes(core, rt, world, clock):
    """P4: an offerless re-INVITE answered on the old connection, a move by
    UPDATE on the new, then the ACK on the old: its answer applies, and the
    call is not ended for a missing ACK."""
    call(core, world, "y3")
    core.on_bytes(from_initiator("INVITE", "y3", 2), world[U[0]])          # offerless
    new = Flow(U[0])
    core.on_bytes(from_initiator("UPDATE", "y3", 3), new)
    assert new.codes() == [200] and core.calls["y3"].flow is new
    core.on_bytes(msg("ACK", LOCAL, "y3", 2, U[0], LOCAL, to_tag=_tag("y3"),
                      branch="z9hG4bKy3ack", body=SDP.replace("10.0.0.1", "10.7.1.1"),
                      ctype="application/sdp"), world[U[0]])
    assert core.calls["y3"].media.endpoints[U[0]].remote_rtp[0] == "10.7.1.1"
    clock.now += 64 * 500
    core.tick()
    assert rt.manager.session("y3").state.value == "established"


def test_a_re_invite_2xx_never_acked_does_not_end_the_call(core, rt, world, clock):
    call(core, world, "y4")
    core.on_bytes(from_initiator("INVITE", "y4", 2, body=SDP, ctype="application/sdp"),
                  world[U[0]])
    clock.now += 64 * 500
    core.tick()
    assert rt.manager.session("y4").state.value == "established"
    assert core.calls["y4"].awaiting_answer is False


def test_our_abandoned_re_invite_is_still_acked_on_the_new_connection(core, rt, world, clock):
    """P5: the platform's refresh re-INVITE went out on the old connection;
    its 2xx arrives on the new one after the move, and is ACKed there, or the
    peer would end the session (RFC 3261 13.3.1.4)."""
    call(core, world, "y5", extra=())                        # the platform refreshes
    clock.now += 900_000
    core.tick()
    ours = world[U[0]].requests("INVITE")[-1]
    new = Flow(U[0])
    core.on_bytes(from_initiator("UPDATE", "y5", 2, extra=TIMER), new)
    assert new.codes() == [200]
    core.on_bytes(reply(ours, 200, body=SDP), new)
    assert len(new.requests("ACK")) == 1
    # a retransmission on the old connection, where the request went, is
    # ACKed there with the same ACK (N4)
    core.on_bytes(reply(ours, 200, body=SDP), world[U[0]])
    assert [a.render() for a in world[U[0]].requests("ACK")] == \
        [a.render() for a in new.requests("ACK")]
    assert rt.manager.session("y5").state.value == "established"


def test_retired_connections_are_not_kept_alive():
    import gc
    from service.sip_core import Call
    c = Call(cid="z", invite=None, sr=None, txn=None, flow=None, initiator="")
    f = Flow("x")
    c.retired.add(f)
    assert len(c.retired) == 1
    del f
    gc.collect()
    assert len(c.retired) == 0



def test_our_abandoned_re_invite_answered_on_the_old_connection_is_acked_there(
        core, rt, world, clock):
    """N4: the peer answers on the connection the request came in on
    (RFC 3261 18.2.2), which the dialog has since left."""
    call(core, world, "y6", extra=())
    clock.now += 900_000
    core.tick()
    ours = world[U[0]].requests("INVITE")[-1]
    new = Flow(U[0])
    core.on_bytes(from_initiator("UPDATE", "y6", 2, extra=TIMER), new)
    core.on_bytes(reply(ours, 200, body=SDP), world[U[0]])
    assert len(world[U[0]].requests("ACK")) == 1 and not new.requests("ACK")
    assert core.calls["y6"].flow is new                 # the dialog stays moved
    assert rt.manager.session("y6").state.value == "established"
    stranger = Flow("sip:u2@mcptt.example")             # not retired: still foreign
    core.on_bytes(reply(ours, 200, body=SDP), stranger)
    assert not stranger.requests("ACK")



def test_a_core_cannot_take_a_dialog_from_a_user_carrying_a_core_name(core, world):
    """The users' CA issued a certificate with a trusted core's DNS name
    (ICD-OP-10's impostor): its dialogs are a user's, not a core's."""
    from tests import mcpttinfo_fixture as mcf
    impostor = Flow(U[0], dns=("core-client.example",), core=False)
    core.on_bytes(msg("INVITE", LOCAL, "y7", 1, U[0], LOCAL,
                      body=mcf.body_for("private", U[1], SDP), ctype=mcf.CONTENT_TYPE),
                  impostor)
    core.on_bytes(answer(world[U[1]].requests("INVITE")[-1], 200, SDP,
                         extra=CALLEE_REFRESHES), world[U[1]])
    proxy = _core()
    core.on_bytes(from_initiator("UPDATE", "y7", 2), proxy)
    assert proxy.codes() == [481] and core.calls["y7"].flow is impostor


def test_a_callee_ack_on_the_connection_the_leg_left_completes(core, world):
    _, leg = call(core, world, "y8")
    core.on_bytes(from_callee("INVITE", leg, 1), world[U[1]])       # offerless
    new = Flow(U[1])
    core.on_bytes(from_callee("UPDATE", leg, 2), new)
    assert new.codes() == [200]
    cid = leg.headers.get("Call-ID")
    core.on_bytes(msg("ACK", LOCAL, cid, 1, U[1], LOCAL, to_tag=f"{cid}-l",
                      from_tag="callee", branch="z9hG4bKy8ack",
                      body=SDP.replace("10.0.0.1", "10.8.1.1"), ctype="application/sdp"),
                  world[U[1]])
    assert core.calls["y8"].media.endpoints[U[1]].remote_rtp[0] == "10.8.1.1"
