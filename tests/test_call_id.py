"""RES-OP-15: the Call-ID is bounded before it names anything.

A new INVITE's Call-ID becomes its session's correlation id in the audit
trail and in every log line about it (VP1-OAM-004). RFC 3261 sets no length;
the guard answers 400 to a Call-ID longer than 256 characters, or not of RFC
3261 25.1's `callid = word [ "@" word ]`, before anything uses it.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.sip import CALL_ID_MAX, InboundGuard, valid_call_id  # noqa: E402
from service.logs import CorrelationFilter  # noqa: E402
from tests.test_sip_transport import (  # noqa: E402,F401  (fixtures)
    LOCAL, U, Clock, Flow, clock, core, env, invite, msg, pki, rt, sip_env, world)


def test_the_limit_is_pinned():
    assert CALL_ID_MAX == 256


@pytest.mark.parametrize("value", [
    "a84b4c76e66710@pc33.atlanta.com",            # RFC 3261 section 4
    "f81d4fae-7dec-11d0-a765-00a0c91e6bf6@[2001:db8::1]",
    "x1", "x" * 256,
    "-.!%*_+`'~()<>:\\\"/[]?{}",                   # every word character
    "a" * 100 + "@" + "b" * 155,
])
def test_a_conformant_call_id_is_accepted(value):
    assert valid_call_id(value)


@pytest.mark.parametrize("value", [
    "x" * 257, "a" * 128 + "@" + "b" * 128,
    "", "@host", "local@", "a@b@c", "a b", "a;b", "a,b", "a=b", "a\tb", "é@host",
    None,
])
def test_anything_else_is_refused(value):
    assert not valid_call_id(value)


@pytest.mark.parametrize("call_id,detail", [
    ("x" * 257, "Call-ID longer than 256 characters"),
    ("a;b", "malformed Call-ID"),
])
def test_the_guard_answers_400_with_the_reason(call_id, detail):
    from core.sip import Headers, Request
    req = Request("OPTIONS", LOCAL, Headers([
        ("Via", "SIP/2.0/TLS h;branch=z9hG4bK1"), ("From", f"<{U[0]}>;tag=1"),
        ("To", f"<{LOCAL}>"), ("Call-ID", call_id), ("CSeq", "1 OPTIONS"),
        ("Max-Forwards", "70")]))
    r = InboundGuard().check(req)
    assert r is not None and r.status.code == 400
    assert detail in (r.headers.get("Warning") or r.status.phrase + str(r.body))


def test_a_long_call_id_never_becomes_a_session_or_a_log_key(core, rt, world, caplog):
    long_id = "c" * 300
    flow = world[U[0]]
    caplog.handler.addFilter(CorrelationFilter())
    with caplog.at_level(logging.DEBUG):
        core.on_bytes(invite(long_id, U[0], U[1], "private"), flow)
    assert flow.codes()[-1] == 400
    assert rt.manager.session(long_id) is None
    assert all(r.get("correlation_id") != long_id for r in rt.store.audit_records())
    assert all(getattr(r, "correlation_id", None) != long_id for r in caplog.records)
    assert all(long_id not in r.getMessage() for r in caplog.records)


def test_a_call_id_at_the_limit_is_a_call(core, rt, world):
    at_limit = "d" * CALL_ID_MAX
    core.on_bytes(invite(at_limit, U[0], U[1], "private"), world[U[0]])
    assert world[U[0]].codes()[-1] != 400
    assert rt.manager.session(at_limit) is not None


def test_the_log_scope_of_a_refused_call_id_names_no_session(core):
    """Whatever is logged about it carries no correlation id."""
    from core.sip import parse_message
    for bad in ("c" * 300, "a;b"):
        assert core._cid_of_message(parse_message(invite(bad, U[0], U[1], "private"))) is None
    good = parse_message(invite("ok1", U[0], U[1], "private"))
    assert core._cid_of_message(good) == "ok1"



def _raw(lines, body=""):
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def _invite_lines(call_id_lines, cid_for_tag="t"):
    return ["INVITE " + LOCAL + " SIP/2.0",
            "Via: SIP/2.0/TLS core.example;branch=z9hG4bKraw" + cid_for_tag,
            f"From: <{U[0]}>;tag=ft", f"To: <{LOCAL}>", *call_id_lines,
            "CSeq: 1 INVITE", "Max-Forwards: 70", "Content-Length: 0"]


@pytest.mark.parametrize("call_id_lines,name", [
    (["i: " + "c" * 300], "compact form"),
    (["Call-ID: " + "c" * 200, " " + "c" * 100], "folded"),
    (["Call-ID: ok-d1", "Call-ID: " + "c" * 300], "duplicate"),
    (["Call-ID: ok-d2", "Call-ID: ok-d3"], "duplicate, both valid"),
])
def test_every_spelling_of_a_bad_call_id_is_refused(core, world, caplog, call_id_lines, name):
    flow = world[U[0]]
    with caplog.at_level(logging.DEBUG):
        core.on_bytes(_raw(_invite_lines(call_id_lines, name.replace(" ", ""))), flow)
    assert flow.codes()[-1] == 400, name
    assert all("c" * 200 not in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("call_id_lines", [["Call-ID: " + "a" * 100_000],
                                           ["Call-ID: a;b"],
                                           ["Call-ID: x1", "Call-ID: x2"]])
def test_an_ack_with_a_bad_call_id_is_dropped_unlogged(core, world, caplog, call_id_lines):
    """ACKs never reach the guard; their Call-ID is checked first, and the
    log line gives only its length (review finding 1)."""
    ack = _raw(["ACK " + LOCAL + " SIP/2.0", "Via: SIP/2.0/TLS core.example;branch=z9hG4bKa1",
                f"From: <{U[0]}>;tag=ft", f"To: <{LOCAL}>;tag=x", *call_id_lines,
                "CSeq: 1 ACK", "Max-Forwards: 70", "Content-Length: 0"])
    before = core.counters["dropped_malformed"]
    with caplog.at_level(logging.DEBUG):
        core.on_bytes(ack, world[U[0]])
    assert core.counters["dropped_malformed"] == before + 1
    msgs = [r.getMessage() for r in caplog.records]
    assert any(m.startswith("ACK with a malformed Call-ID dropped") for m in msgs)
    assert all(len(m) < 200 for m in msgs)


def test_an_ack_on_an_invite_branch_must_carry_its_call_id(core, world, caplog):
    """A non-2xx ACK matched on its branch alone could reach the
    foreign-tags log line with any Call-ID (review finding 1)."""
    from core.sip import Headers, Request
    flow = world[U[0]]
    core.on_bytes(invite("br1", U[0], "sip:nobody@mcptt.example", "private"), flow)
    assert flow.codes()[-1] >= 400                            # a non-2xx final
    branch = core.server._txns and next(
        b for (b, m), t in core.server._txns.items() if t.call_id == "br1")
    ack = Request("ACK", LOCAL, Headers([
        ("Via", f"SIP/2.0/TLS core.example;branch={branch}"),
        ("From", f"<{U[0]}>;tag=ft"), ("To", f"<{LOCAL}>;tag=x"),
        ("Call-ID", "other-call"), ("CSeq", "1 ACK"), ("Max-Forwards", "70")]))
    assert core.server.absorb_ack(ack, flow) is None


def test_an_unparseable_header_line_is_logged_clipped(core, world, caplog):
    raw = ("INVITE " + LOCAL + " SIP/2.0\r\n" + "x" * 100_000 + "\r\n\r\n").encode()
    with caplog.at_level(logging.DEBUG):
        core.on_bytes(raw, world[U[0]])
    msgs = [r.getMessage() for r in caplog.records]
    assert any("100000 characters" in m for m in msgs)
    assert all(len(m) < 300 for m in msgs)


def test_only_rfc_whitespace_is_trimmed_from_a_header_value():
    from core.sip import parse_message
    m = parse_message(_raw(_invite_lines(["Call-ID: ok-w1 \u0085"])))
    assert m.headers.get("Call-ID") == "ok-w1 \u0085"
    assert not valid_call_id(m.headers.get("Call-ID"))
    m = parse_message(_raw(_invite_lines(["Call-ID: \t ok-w2 \t"])))
    assert m.headers.get("Call-ID") == "ok-w2"


# -- the same class: peer text in error messages (second review of RES-OP-15)


def test_clip_cuts_and_says_how_long():
    from core.sip import clip
    assert clip("abc") == "'abc'"
    assert clip("x" * 100) == repr("x" * 80) + "... (100 characters)"
    assert clip("x" * 100, 10) == repr("x" * 10) + "... (100 characters)"


@pytest.mark.parametrize("raw,where", [
    (b"X" * 100_000 + b"\r\n\r\n", "start line"),
    (b"INVITE sip:a SIP/2.0\r\n" + b"y" * 100_000 + b"\r\n\r\n", "header line"),
])
def test_an_unparseable_message_is_logged_clipped(core, world, caplog, raw, where):
    with caplog.at_level(logging.DEBUG):
        core.on_bytes(raw, world[U[0]])
    msgs = [r.getMessage() for r in caplog.records]
    assert any(f"malformed {where}" in m and "100000 characters" in m for m in msgs), msgs
    assert all(len(m) < 300 for m in msgs)


@pytest.mark.parametrize("parse,value", [("parse_session_expires", "9" * 50_000),
                                         ("parse_session_expires", "90;refresher=" + "z" * 50_000),
                                         ("parse_min_se", "x" * 50_000)])
def test_session_timer_errors_are_clipped(parse, value):
    import core.sip as sip
    from core.sip import SipError
    with pytest.raises(SipError) as exc:
        getattr(sip, parse)(value)
    assert len(str(exc.value)) < 200


@pytest.mark.parametrize("sdp_line", ["c=IN IP6 ff02::1%" + "z" * 5000,
                                      "c=IN IP4 0.0.0.0"], ids=["long-scope", "zero"])
def test_an_sdp_error_is_bounded_in_the_audit_and_the_log(core, rt, world, caplog, sdp_line):
    from tests.test_sip_transport import SDP
    from tests import mcpttinfo_fixture as mcf
    bad = "\r\n".join(sdp_line if l.startswith("c=") else l for l in SDP.split("\r\n"))
    with caplog.at_level(logging.DEBUG):
        core.on_bytes(msg("INVITE", LOCAL, "sdp1", 1, U[0], LOCAL,
                          body=mcf.body_for("private", U[1], bad), ctype=mcf.CONTENT_TYPE),
                      world[U[0]])
    for r in rt.store.audit_records("sdp1"):
        assert len(str(r["detail"])) < 1500
    assert all(len(r.getMessage()) < 400 for r in caplog.records)


@pytest.mark.parametrize("value", ["١٢", "1_0", "+5", "-1", " 5x"])
def test_content_length_is_ascii_digits_only(value):
    from core.sip import SipError, split_frame
    with pytest.raises(SipError):
        split_frame(f"INVITE sip:a SIP/2.0\r\nContent-Length: {value}\r\n\r\n".encode())


def test_the_outgoing_ack_branch_does_not_carry_the_callees_tag(core, world):
    """It is hashed, so a long To tag from a callee cannot lengthen what the
    platform sends."""
    from tests.test_sip_transport import answer, SDP
    from tests import mcpttinfo_fixture as mcf
    core.on_bytes(msg("INVITE", LOCAL, "ackb", 1, U[0], LOCAL,
                      body=mcf.body_for("private", U[1], SDP), ctype=mcf.CONTENT_TYPE),
                  world[U[0]])
    leg_invite = world[U[1]].requests("INVITE")[-1]
    long_tag = "t" * 5000
    core.on_bytes(answer(leg_invite, 200, SDP, tag=long_tag), world[U[1]])
    acks = world[U[1]].requests("ACK")
    assert acks and len(acks[-1].headers.get("Via")) < 200


def test_an_unusable_address_error_is_clipped_at_its_source():
    from core.sip import SipError, _check_media_address
    with pytest.raises(SipError) as exc:
        _check_media_address("ff02::1%" + "z" * 5000)
    assert len(str(exc.value)) < 200


def test_the_media_error_is_bounded_whatever_the_parser_says(core, rt, world, monkeypatch):
    """Defence in depth: the reason that becomes an audit detail is cut at
    200 characters even if a parser error is not."""
    import service.sip_core as sc
    from core.sip import SipError
    from tests.test_sip_transport import SDP
    from tests import mcpttinfo_fixture as mcf

    def boom(_):
        raise SipError("q" * 5000)
    monkeypatch.setattr(sc, "parse_sdp", boom)
    core.on_bytes(msg("INVITE", LOCAL, "me1", 1, U[0], LOCAL,
                      body=mcf.body_for("private", U[1], SDP), ctype=mcf.CONTENT_TYPE),
                  world[U[0]])
    failed = [r["detail"] for r in rt.store.audit_records("me1")
              if r["type"] == "session-failed"]
    assert failed and failed[0]["detail"].startswith("unusable SDP offer: qqq")
    assert len(failed[0]["detail"]) <= 200
