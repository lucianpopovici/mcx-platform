"""The ENV-E2E tools (tools/e2e/): their rules and codecs, without a capture.

The cases themselves are decided by tools/e2e/run.py from a packet capture
(PLT-VP-R1 ENV-E2E); these tests pin the pieces that run uses, so a rule that
stopped rejecting what it should would fail here, where tcpdump and tshark
are not needed.
"""

from __future__ import annotations

import ast
import json
import socket
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tools" / "e2e"))
sys.path.insert(0, str(ROOT / "tools" / "interop"))

import floor as fl  # noqa: E402
import trace_compare  # noqa: E402
from flows import EXPECTED, match_flow  # noqa: E402
from tags import check_message, kind  # noqa: E402

ICSI = 'urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt'
TAGS = f';+g.3gpp.mcptt;+g.3gpp.icsi-ref="{ICSI}"'
ACCEPT = ["Accept-Contact: *;+g.3gpp.mcptt;require;explicit",
          f'Accept-Contact: *;+g.3gpp.icsi-ref="{ICSI}";require;explicit']
PAS = "P-Asserted-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt"
PPS = "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcptt"


def sip(start, *headers, cseq="1 INVITE", to="<sip:b@x>"):
    lines = [start, "Via: SIP/2.0/TLS h;branch=z9hG4bK1", "From: <sip:a@x>;tag=1",
             f"To: {to}", "Call-ID: c", f"CSeq: {cseq}"] + list(headers)
    return "\r\n".join(lines) + "\r\nContent-Length: 0\r\n\r\n"


# -- the feature-tag table (VP1-SIG-003) -----------------------------------------------

def test_a_conformant_initial_invite_from_the_platform_passes():
    m = sip("INVITE sip:u2@x SIP/2.0", f"Contact: <sip:mcptt@x;gr=urn:uuid:1>{TAGS};isfocus",
            *ACCEPT, PAS)
    assert check_message(m, from_platform=True) == ("", "initial-invite")


def test_the_service_header_of_an_initial_invite_is_checked_on_each_side():
    """Owner decision 2026-11-24: P-Asserted-Service from the platform
    (6.3.3.1.2 item 3), P-Preferred-Service from a client (11.1.1.2.1.1
    item 7), each with the MCPTT ICSI."""
    plat = f"Contact: <sip:mcptt@x>{TAGS};isfocus"
    client = f"Contact: <sip:u1@h>{TAGS}"
    assert check_message(sip("INVITE sip:u2@x SIP/2.0", plat, *ACCEPT), True)[0] == \
        "P-Asserted-Service is [], not the MCPTT ICSI"
    assert check_message(sip("INVITE sip:u2@x SIP/2.0", plat, *ACCEPT, PPS), True)[0] == \
        "P-Asserted-Service is [], not the MCPTT ICSI"
    assert check_message(sip("INVITE sip:p@x SIP/2.0", client, *ACCEPT, PPS), False)[0] == ""
    assert check_message(sip("INVITE sip:p@x SIP/2.0", client, *ACCEPT, PAS), False)[0] == \
        "P-Preferred-Service is [], not the MCPTT ICSI"
    assert check_message(sip("INVITE sip:p@x SIP/2.0", client, *ACCEPT,
                             "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mcdata"),
                         False)[0].startswith("P-Preferred-Service is")


@pytest.mark.parametrize("contact,accept,why", [
    (f"<sip:mcptt@x>;+g.3gpp.mcptt;isfocus", ACCEPT, "Contact lacks the MCPTT ICSI"),
    (f'<sip:mcptt@x>;+g.3gpp.icsi-ref="{ICSI}";isfocus', ACCEPT,
     "Contact lacks +g.3gpp.mcptt"),
    (f"<sip:mcptt@x>{TAGS}", ACCEPT, "the platform's Contact lacks isfocus"),
    (f"<sip:mcptt@x>{TAGS};isfocus", ACCEPT[:1],
     f'no Accept-Contact *;+g.3gpp.icsi-ref="{ICSI}";require;explicit'),
    (f"<sip:mcptt@x>{TAGS};isfocus", ["Accept-Contact: *;+g.3gpp.mcptt;explicit", ACCEPT[1]],
     "no Accept-Contact *;+g.3gpp.mcptt;require;explicit"),
])
def test_each_missing_tag_of_an_initial_invite_is_named(contact, accept, why):
    verdict, rule = check_message(sip("INVITE sip:u2@x SIP/2.0", f"Contact: {contact}",
                                      *accept, PAS), from_platform=True)
    assert rule == "initial-invite" and verdict == why


def test_a_tag_inside_the_uri_is_not_a_header_parameter():
    """RFC 3261 20.10: feature tags are Contact header parameters, after the
    name-addr; the same text inside <...> is a URI parameter and does not count."""
    m = sip("SIP/2.0 200 OK", f"Contact: <sip:mcptt@x{TAGS};isfocus>")
    assert check_message(m, True)[0] == ("Contact lacks +g.3gpp.mcptt; Contact lacks the "
                                         "MCPTT ICSI; the platform's Contact lacks isfocus")


def test_a_client_is_not_a_focus_and_needs_no_isfocus():
    ok = sip("SIP/2.0 180 Ringing", f"Contact: <sip:u2@h>{TAGS}")
    assert check_message(ok, False) == ("", "dialog-response")
    bad = sip("SIP/2.0 200 OK", f"Contact: <sip:u2@h>{TAGS};isfocus")
    assert check_message(bad, False)[0] == "a client's Contact carries isfocus"


def test_register_and_target_refreshes_carry_the_tags():
    assert check_message(sip("REGISTER sip:x SIP/2.0", f"Contact: <sip:u1@h>{TAGS}",
                             cseq="1 REGISTER"), False) == ("", "register")
    assert check_message(sip("REGISTER sip:x SIP/2.0", "Contact: <sip:u1@h>",
                             cseq="1 REGISTER"), False)[0].startswith("Contact lacks")
    reinv = sip("INVITE sip:mcptt@x SIP/2.0", "Contact: <sip:u1@h>", to="<sip:b@x>;tag=9")
    assert check_message(sip("INVITE sip:mcptt@x SIP/2.0", f"Contact: <sip:u1@h>{TAGS}",
                             to="<sip:b@x>;tag=9"), False) == ("", "re-invite")
    assert kind(reinv) == "re-invite" and check_message(reinv, False)[0]
    upd = sip("UPDATE sip:u2@h SIP/2.0", f"Contact: <sip:mcptt@x>{TAGS}", cseq="2 UPDATE",
              to="<sip:b@x>;tag=9")
    assert check_message(upd, True)[0] == "the platform's Contact lacks isfocus"
    assert kind(sip("SIP/2.0 200 OK", cseq="2 UPDATE")) == "dialog-response"


@pytest.mark.parametrize("start,cseq", [
    ("ACK sip:u2@h SIP/2.0", "1 ACK"), ("BYE sip:u2@h SIP/2.0", "2 BYE"),
    ("CANCEL sip:x SIP/2.0", "1 CANCEL"), ("SIP/2.0 100 Trying", "1 INVITE"),
    ("SIP/2.0 488 Not Acceptable Here", "1 INVITE"), ("SIP/2.0 200 OK", "2 BYE"),
    ("SIP/2.0 200 OK", "1 REGISTER")])
def test_messages_ts_24_379_gives_no_tags_are_listed_as_such(start, cseq):
    assert check_message(sip(start, cseq=cseq), True)[0] == ""


@pytest.mark.parametrize("method", ["SUBSCRIBE", "NOTIFY", "MESSAGE", "PUBLISH", "OPTIONS",
                                    "PRACK", "REFER", "INFO"])
def test_a_method_the_table_does_not_list_fails(method):
    """Review H3: nothing passes unexamined, the request or its response."""
    req = sip(f"{method} sip:x SIP/2.0", f"Contact: <sip:u@h>{TAGS}", cseq=f"1 {method}")
    assert kind(req) == "unknown" and "not in the table" in check_message(req, False)[0]
    resp = sip("SIP/2.0 200 OK", cseq=f"1 {method}")
    assert kind(resp) == "unknown" and check_message(resp, True)[0]


def test_compact_contact_and_a_comma_joined_accept_contact_are_read():
    m = sip("INVITE sip:u2@x SIP/2.0", f"m: <sip:mcptt@x>{TAGS};isfocus",
            "Accept-Contact: " + ", ".join(a.split(": ", 1)[1] for a in ACCEPT), PAS)
    assert check_message(m, True) == ("", "initial-invite")


def test_a_tagged_message_needs_exactly_one_contact():
    m = sip("SIP/2.0 200 OK", f"Contact: <sip:a@x>{TAGS};isfocus",
            f"Contact: <sip:b@x>{TAGS};isfocus")
    assert check_message(m, True)[0] == "2 Contact header fields, expected one"
    assert check_message(sip("SIP/2.0 200 OK"), True)[0] == \
        "0 Contact header fields, expected one"


# -- expected flows (VP1-CC-003, VP1-CC-004) --------------------------------------------

def flat(name):
    return [m for step in EXPECTED[name] for m in step]


def test_the_expected_flow_is_matched_exactly():
    assert match_flow(flat("private-manual"), EXPECTED["private-manual"]) == (True, None)


def test_order_is_free_within_a_step_only():
    seq = flat("private-manual")
    i = seq.index(("P>c2", "INVITE"))
    swapped = seq[:i - 1] + [seq[i], seq[i - 1]] + seq[i + 1:]
    assert match_flow(swapped, EXPECTED["private-manual"])[0]
    j = seq.index(("P>c1", "180 INVITE"))
    across = seq[:j - 1] + [seq[j], seq[j - 1]] + seq[j + 1:]
    ok, why = match_flow(across, EXPECTED["private-manual"])
    assert not ok and why.startswith("step 3:")


def test_a_missing_extra_or_repeated_message_fails():
    seq = flat("private-auto")
    assert not match_flow(seq[:-1], EXPECTED["private-auto"])[0]
    ok, why = match_flow(seq + [("P>c1", "BYE")], EXPECTED["private-auto"])
    assert not ok and why == "1 message(s) beyond the flow: [('P>c1', 'BYE')]"
    with_ring = seq[:3] + [("c2>P", "180 INVITE")] + seq[3:]
    assert not match_flow(with_ring, EXPECTED["private-auto"])[0]


def test_the_manual_flow_rings_and_the_automatic_one_does_not():
    assert ("c2>P", "180 INVITE") in flat("private-manual")
    assert not any(k.startswith("18") for _, k in flat("private-auto"))


# -- the client's floor codec (VP1-FC-001) ---------------------------------------------

@pytest.mark.parametrize("data,name", [
    (fl.floor_request(7, 5), "request"), (fl.floor_release(7), "release"),
    (fl.queue_position_request(7), "queue-position-request"),
    (fl.floor_ack(7, fl.GRANTED), "ack")])
def test_the_client_s_messages_are_read_alike_by_the_comparator(data, name):
    """Two readings of TS 24.380 by different code agree on what the client
    sends (the third, Wireshark's, is the e2e run's)."""
    assert trace_compare.parse(data)[0] == name
    assert fl.decode(data)["type"] == name and fl.decode(data)["ssrc"] == 7


def test_a_field_is_padded_to_a_word():
    """8.2.3.1: a field whose value is not two octets is padded to 32 bits."""
    data = fl.encode(fl.TAKEN, 1, [(fl.F_GRANTED_PARTY, b"sip:a@x")])
    assert len(data) % 4 == 0 and data[12:14] == bytes([fl.F_GRANTED_PARTY, 7])
    assert data[12 + 2 + 7:] == b"\0" * 3
    assert fl.decode(data)["fields"][fl.F_GRANTED_PARTY] == b"sip:a@x"


def test_the_floor_request_carries_its_priority():
    m = fl.decode(fl.floor_request(1, 9))
    assert m["fields"][fl.F_PRIORITY] == bytes([9, 0])
    assert len(fl.floor_request(1, 9)) % 4 == 0


def test_rtp_and_non_floor_packets_are_told_apart():
    pkt = fl.rtp(96, 1, 160, 5)
    assert fl.rtp_pt(pkt) == 96 and fl.decode(pkt) is None
    assert fl.rtp_pt(fl.floor_release(5)) is None


def test_a_message_asking_for_an_acknowledgement_is_acknowledged():
    ep = fl.Endpoint("t")
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(2)
    try:
        ep.remote_floor = peer.getsockname()
        granted = bytearray(fl.encode(fl.GRANTED, 3, [(fl.F_DURATION, b"\0\x05"),
                                                       (fl.F_PRIORITY, b"\x05\0")]))
        granted[0] |= fl.ACK_REQUIRED
        peer.sendto(bytes(granted), ("127.0.0.1", ep.floor_port))
        data, _ = peer.recvfrom(100)
        assert trace_compare.parse(data)[0] == "ack"
        assert ep.wait_floor("granted")["ack_required"]
    finally:
        ep.close()
        peer.close()


# -- the runner's helpers --------------------------------------------------------------

def _e2e_run():
    """tools/e2e/run.py, loaded by path: tools/interop/run.py has the same
    module name."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("e2e_run", ROOT / "tools/e2e/run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_auto_answer_profile_differs_from_mcx_in_that_one_value(tmp_path):
    run = _e2e_run()
    from core import loader
    root = run.auto_answer_profiles(tmp_path)
    shipped = (ROOT / "profiles/mcx/profile.yaml").read_text().splitlines()
    copied = (root / "mcx/profile.yaml").read_text().splitlines()
    diff = [(a, b) for a, b in zip(shipped, copied) if a != b]
    assert len(shipped) == len(copied) and diff == [
        ("    auto_answer: false", "    auto_answer: true")]
    private = next(c for c in loader.load(root / "mcx").profile.call_types if c.id == "private")
    assert private.auto_answer is True


def test_a_damaged_key_log_line_is_refused(tmp_path):
    run = _e2e_run()
    (tmp_path / "keys-01.log").write_text("# c\nCLIENT_RANDOM aa bb\n")
    (tmp_path / "keys-02.log").write_text("SERVER_TRAFFIC_SECRET_0 cc dd\n")
    run.merge_keylogs(tmp_path)
    assert (tmp_path / "keys.log").read_text() == \
        "CLIENT_RANDOM aa bb\nSERVER_TRAFFIC_SECRET_0 cc dd\n"
    (tmp_path / "keys-03.log").write_text("SERVER_HANDSHAKE_TRAFFIC_SECRET \x17\x03 ee ff\n")
    with pytest.raises(RuntimeError):
        run.merge_keylogs(tmp_path)


def test_the_analysis_reads_sdp_and_labels_messages():
    import analyse
    body = ("v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 96 0\r\n"
            "a=rtpmap:96 AMR-WB/16000\r\na=rtpmap:0 PCMU/8000\r\n")
    text = sip("SIP/2.0 200 OK") + ("--b\r\nContent-Type: application/sdp\r\n\r\n"
                                    + body + "--b--\r\n")
    assert analyse.audio_formats(analyse.body_sdp(text)) == (
        [96, 0], {96: "AMR-WB/16000", 0: "PCMU/8000"})
    msg = {"peer_port": 5, "from_platform": True, "start": "SIP/2.0 200 OK", "text": text}
    assert analyse.label(msg, {5: "c1"}) == ("P>c1", "200 INVITE")
    req = {"peer_port": 6, "from_platform": False, "start": "BYE sip:x SIP/2.0", "text": ""}
    assert analyse.label(req, {6: "c2"}) == ("c2>P", "BYE")


def test_the_floor_names_come_from_wireshark_s_info_column():
    import re
    import analyse
    src = Path(analyse.__file__).read_text()
    pattern = re.search(r'm = re\.search\(r"(.+?)", info\)', src).group(1)
    for info, want in [("(MCPT) Floor Deny - Other reason", "Floor Deny"),
                       ("(MCPT) Floor Queue Position Info", "Floor Queue Position Info"),
                       ("(MCPT) Floor Granted", "Floor Granted")]:
        assert re.search(pattern, info).group(1) == want


class _FakeCapture:
    def __init__(self, log, code=None):
        self.log, self.p = log, type("P", (), {"poll": lambda s: code, "returncode": code})()


@pytest.mark.parametrize("loader", ["e2e", "interop"])
def test_the_capture_waits_for_tcpdump_and_says_why_it_cannot(tmp_path, loader):
    """Review H8: tcpdump's own "listening on" is waited for; a tcpdump that
    exits (no right to capture) is reported with what it said."""
    mod = _e2e_run() if loader == "e2e" else _interop_run()
    log = tmp_path / "tcpdump.log"
    log.write_text("tcpdump: listening on lo, link-type EN10MB\n")
    assert mod.wait_capture(_FakeCapture(log)) == ""
    log.write_text("tcpdump: lo: You don't have permission to capture on that device\n")
    assert "permission" in mod.wait_capture(_FakeCapture(log, code=1))
    log.write_text("")
    assert mod.wait_capture(_FakeCapture(log, code=1)) == "tcpdump exited 1"
    assert "said nothing" in mod.wait_capture(_FakeCapture(log), timeout=0.2)


def _interop_run():
    import importlib.util
    spec = importlib.util.spec_from_file_location("interop_run", ROOT / "tools/interop/run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_interop_capture_refuses_a_damaged_key_log_line(tmp_path):
    run = _interop_run()
    (tmp_path / "keys-01.log").write_text("# c\nCLIENT_RANDOM aa bb\n")
    run.merge_keylogs(tmp_path)
    assert (tmp_path / "keys.log").read_text() == "CLIENT_RANDOM aa bb\n"
    (tmp_path / "keys-02.log").write_text("CLIENT_RANDOM aa\n")
    with pytest.raises(RuntimeError, match="damaged"):
        run.merge_keylogs(tmp_path)


def test_the_interop_capture_tells_the_platform_s_messages_from_the_core_s():
    """Review H4, N1: through a proxy the platform's request keeps its own Via
    at the bottom (sent-by mcptt.example, no port), its response its own
    Contact; a B2BUA's carry neither. The requests are as Kamailio relayed
    them in a real --capture run (tests/data/interop/)."""
    run = _interop_run()
    for name in ("kamailio-relayed-invite", "kamailio-relayed-ack"):
        text = (DATA.parent / "interop" / f"{name}.txt").read_text().replace("\r\n", "\n") \
            .replace("\n", "\r\n")
        assert run._bottom_via_host(text) == "mcptt.example", name
        assert run.platform_made(text) and not run.platform_made(text, "kamailio.test")
    agent = ("INVITE sip:mcptt@mcptt.example SIP/2.0\r\n"
             "Via: SIP/2.0/TLS 127.0.0.1:6000;branch=z9hG4bKk\r\nContent-Length: 0\r\n\r\n")
    assert run._bottom_via_host(agent) == "127.0.0.1" and not run.platform_made(agent)
    joined = ("INVITE sip:u2@x SIP/2.0\r\nv: SIP/2.0/TLS 127.0.0.1:6000;branch=z9hG4bKk, "
              "SIP/2.0/TLS MCPTT.example:5061;branch=z9hG4bKp\r\nContent-Length: 0\r\n\r\n")
    assert run.platform_made(joined)
    ok = sip("SIP/2.0 200 OK", f"Contact: <sip:mcptt@mcptt.example>{TAGS};isfocus")
    assert run.platform_made(ok) and run._mc_tagged(ok)
    b2b = sip("SIP/2.0 200 OK", "Contact: <sip:asterisk@127.0.0.1:6000>")
    assert not run.platform_made(b2b) and not run._mc_tagged(b2b)


def test_a_floor_ack_names_its_source_and_the_message_it_acknowledges():
    """TS 24.380 8.2.13: Source (8.2.3.12) '0', the floor participant, and
    Message Type (8.2.3.14), in a padded field each (review H6)."""
    m = fl.decode(fl.floor_ack(7, fl.GRANTED | fl.ACK_REQUIRED))
    assert m["type"] == "ack" and m["fields"] == {10: b"\x00\x00", 12: b"\x11\x00"}
    assert fl.floor_ack(7, fl.GRANTED)[12:] == bytes([10, 2, 0, 0, 12, 2, 1, 0])


def test_the_callee_answers_as_ts_24_379_6_2_3_has_it():
    """Review H6: 180 with Require: timer; 200 with Require: timer and
    Session-Expires;refresher=uas, the INVITE's interval (or 1800); the
    ring lasts `ring_s`."""
    import mcclient
    sent = []
    c = object.__new__(mcclient.MCClient)
    c.respond = lambda inv, code, phrase, body="", extra=(): sent.append((code, list(extra)))
    c.answer_sdp = lambda offer: "v=0\n"
    c.learn = lambda sdp: None
    for invite, rings, interval in [
            (sip("INVITE sip:u2@x SIP/2.0", "Answer-Mode: Manual", "Session-Expires: 90"),
             True, "90"),
            (sip("INVITE sip:u2@x SIP/2.0", "Priv-Answer-Mode: Auto", "x: 120;refresher=uac"),
             False, "120"),
            (sip("INVITE sip:u2@x SIP/2.0", "Priv-Answer-Mode: Auto"), False, "1800")]:
        sent.clear()
        c.wait = lambda pattern, timeout=10.0, **kw: invite
        t0 = time.monotonic()
        c.answer_incoming(ring_s=0.2)
        assert (time.monotonic() - t0 >= 0.2) == rings
        assert sent == ([(180, ["Require: timer"])] if rings else []) + [
            (200, ["Require: timer", f"Session-Expires: {interval};refresher=uas"])]


def test_ua_respond_adds_the_extra_headers_before_the_body():
    import ua
    u = object.__new__(ua.UA)
    u.tag, u.user, u.host, u.port = "t", "u2", "h", 1
    out = []
    u.send = lambda lines, body="": out.append((lines, body)) or ""
    type(u).contact = property(lambda self: "<sip:u2@h>")
    try:
        u.respond(sip("INVITE sip:u2@x SIP/2.0"), 180, "Ringing", extra=["Require: timer"])
    finally:
        del type(u).contact
    lines = out[0][0]
    assert lines[0] == "SIP/2.0 180 Ringing" and lines[-2:] == ["Contact: <sip:u2@h>",
                                                                  "Require: timer"]


# -- independence (PLT-VP-R1 ENV-E2E) ---------------------------------------------------

@pytest.mark.parametrize("path", sorted(
    p.relative_to(ROOT).as_posix() for d in ("tools/e2e", "tools/interop")
    for p in (ROOT / d).glob("*.py")) + ["tools/trace_compare.py"])
def test_the_client_and_its_checkers_import_nothing_of_the_platform(path):
    """ENV-E2E: the client is "written from the specifications and importing
    nothing from core/ or service/"; so are the tools that judge the capture."""
    tree = ast.parse((ROOT / path).read_text())
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert [n for n in names if n.split(".")[0] in ("core", "service", "profiles")] == []


# -- the verdicts, from a recorded capture (tools/e2e/analyse.py judge) -------------------
#
# tests/data/e2e/ holds what tshark decoded from a real run of tools/e2e/run.py
# (decoded.json) and what the scenarios did (scenarios.json). The judge must
# pass it as captured, and fail each doctored copy below, naming the case.

import copy  # noqa: E402

DATA = ROOT / "tests" / "data" / "e2e"


def recorded():
    return (json.loads((DATA / "decoded.json").read_text()),
            json.loads((DATA / "scenarios.json").read_text()))


def verdicts(decoded, runs):
    import analyse
    r = analyse.judge(decoded, runs)
    return {c: v["passed"] for c, v in r["cases"].items()}, r


def run_of(runs, name):
    return next(r for r in runs if r["scenario"] == name)


def msgs_of(decoded, run):
    import analyse
    ids = {run["call_id"], run.get("callee_call_id")}
    return [m for m in decoded["messages"]
            if (analyse.header(m["text"], "Call-ID") or [""])[0] in ids]


def test_the_recorded_run_passes_every_case_and_exit_criterion_6():
    v, r = verdicts(*recorded())
    assert v == {c: True for c in ("VP1-SIG-003", "VP1-CC-003", "VP1-CC-004", "VP1-MED-001",
                                   "VP1-MED-002", "VP1-FC-001")}
    assert all(r["exit_criterion_6"].values()) and r["passed"]
    assert r["sip_messages"] == len(recorded()[0]["messages"]) > 40


def _fails(decoded, runs, case):
    v, r = verdicts(decoded, runs)
    assert not v[case] and not r["passed"], case
    others = {c: ok for c, ok in v.items() if c != case}
    return others


def test_a_contact_stripped_of_its_icsi_fails_sig_003():
    d, runs = recorded()
    m = next(m for m in d["messages"] if m["from_platform"] and m["start"] == "SIP/2.0 200 OK"
             and "isfocus" in m["text"])
    m["text"] = m["text"].replace(';+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt"', "")
    _fails(d, runs, "VP1-SIG-003")


@pytest.mark.parametrize("change,detail", [
    (lambda t: dict(t, undecrypted=[42]), "undecrypted in frames [42]"),
    (lambda t: dict(t, not_sip=[43]), "not SIP in frames [43]"),
    (lambda t: dict(t, application_frames=0), ""),
])
def test_an_unread_tls_record_fails_sig_003(change, detail):
    """Review H2: "all N messages" holds only when every encrypted record on
    the SIP ports decrypted and all application data was SIP."""
    d, runs = recorded()
    d["tls"] = change(d["tls"])
    _, r = verdicts(d, runs)
    step = r["cases"]["VP1-SIG-003"]["steps"][0]
    assert step["verdict"] == "FAIL" and detail in step["evidence"]
    _fails(d, runs, "VP1-SIG-003")


@pytest.mark.parametrize("scenario,case,start,old,new", [
    ("private-manual", "VP1-CC-003", "SIP/2.0 180", "Require: timer\r\n", ""),
    ("private-manual", "VP1-CC-003", "SIP/2.0 200", "Require: timer\r\n", ""),
    ("private-auto", "VP1-CC-004", "SIP/2.0 200", ";refresher=uas", ";refresher=uac"),
    ("private-auto", "VP1-CC-004", "SIP/2.0 200", "Session-Expires:", "X-Session-Expires:"),
])
def test_a_callee_that_is_not_a_conformant_client_fails(scenario, case, start, old, new):
    """Review H6: the harness's own answers are checked on the wire."""
    d, runs = recorded()
    m = next(m for m in msgs_of(d, run_of(runs, scenario))
             if not m["from_platform"] and m["start"].startswith(start))
    assert old in m["text"]
    m["text"] = m["text"].replace(old, new)
    _fails(d, runs, case)


def test_a_lost_ringing_fails_the_manual_flow():
    d, runs = recorded()
    ring = next(m for m in msgs_of(d, run_of(runs, "private-manual"))
                if m["start"].startswith("SIP/2.0 180") and not m["from_platform"])
    d["messages"].remove(ring)
    _fails(d, runs, "VP1-CC-003")


def test_a_caller_answered_before_the_callee_fails_cc_003():
    d, runs = recorded()
    ms = msgs_of(d, run_of(runs, "private-manual"))
    caller_ok = next(m for m in ms if m["from_platform"] and m["start"] == "SIP/2.0 200 OK"
                     and "INVITE" in m["text"].split("CSeq:")[1].split("\r\n")[0])
    d["messages"].remove(caller_ok)
    i = d["messages"].index(ms[0]) + 1
    d["messages"].insert(i, caller_ok)
    _fails(d, runs, "VP1-CC-003")


@pytest.mark.parametrize("scenario,case,old,new", [
    ("private-manual", "VP1-CC-003", "Answer-Mode: Manual", "Answer-Mode: Auto"),
    ("private-manual", "VP1-CC-003", "Answer-Mode: Manual",
     "Answer-Mode: Manual\r\nPriv-Answer-Mode: Manual"),
    ("private-auto", "VP1-CC-004", "Priv-Answer-Mode: Auto", "Answer-Mode: Auto"),
    ("private-auto", "VP1-CC-004", "Priv-Answer-Mode: Auto",
     "Priv-Answer-Mode: Auto\r\nAnswer-Mode: Auto"),
])
def test_the_wrong_answer_mode_header_fails(scenario, case, old, new):
    d, runs = recorded()
    inv = next(m for m in msgs_of(d, run_of(runs, scenario))
               if m["from_platform"] and m["start"].startswith("INVITE"))
    assert old in inv["text"]
    inv["text"] = inv["text"].replace(old, new)
    _fails(d, runs, case)


def test_ringing_in_the_automatic_call_fails_cc_004():
    d, runs = recorded()
    run = run_of(runs, "private-auto")
    ms = msgs_of(d, run)
    ok = next(m for m in ms if not m["from_platform"] and m["start"] == "SIP/2.0 200 OK")
    ring = dict(ok, start="SIP/2.0 180 Ringing",
                text=ok["text"].replace("SIP/2.0 200 OK", "SIP/2.0 180 Ringing", 1))
    d["messages"].insert(d["messages"].index(ok), ring)
    _fails(d, runs, "VP1-CC-004")


def test_an_undeclared_codec_relayed_fails_med_001():
    d, runs = recorded()
    c2 = run_of(runs, "group-floor")["clients"][1]
    pkt = next(p for p in d["rtp"] if p["dst"] == c2["rtp"])
    pkt["pt"] = 111
    _fails(d, runs, "VP1-MED-001")


def test_an_answer_offering_two_codecs_fails_med_001_and_002():
    d, runs = recorded()
    run = run_of(runs, "group-floor")
    ok = next(m for m in msgs_of(d, run) if m["from_platform"] and
              m["start"] == "SIP/2.0 200 OK" and "AMR-WB" in m["text"]
              and m["peer_port"] == run["clients"][0]["sip_port"])
    ok["text"] = ok["text"].replace("RTP/AVP 96", "RTP/AVP 96 0").replace(
        "a=rtpmap:96 AMR-WB/16000", "a=rtpmap:96 AMR-WB/16000\r\na=rtpmap:0 PCMU/8000")
    v, _ = verdicts(d, runs)
    assert not v["VP1-MED-001"] and not v["VP1-MED-002"]


def test_an_accepted_unacceptable_offer_fails_med_002():
    d, runs = recorded()
    refused = next(m for m in msgs_of(d, run_of(runs, "codec-refused"))
                   if m["start"].startswith("SIP/2.0 488"))
    refused["start"] = "SIP/2.0 200 OK"
    refused["text"] = refused["text"].replace("SIP/2.0 488 Not Acceptable Here", "SIP/2.0 200 OK")
    _fails(d, runs, "VP1-MED-002")


def test_a_refusal_that_is_not_488_fails_med_002():
    d, runs = recorded()
    refused = next(m for m in msgs_of(d, run_of(runs, "codec-refused"))
                   if m["start"].startswith("SIP/2.0 488"))
    refused["start"] = "SIP/2.0 403 Forbidden"
    refused["text"] = refused["text"].replace("SIP/2.0 488 Not Acceptable Here",
                                              "SIP/2.0 403 Forbidden")
    _fails(d, runs, "VP1-MED-002")


def test_a_callee_invited_for_the_refused_offer_fails_med_002():
    d, runs = recorded()
    run = run_of(runs, "codec-refused")
    first = msgs_of(d, run)[0]
    d["messages"].append(dict(first, frame=first["frame"] + 1, from_platform=True,
                              peer_port=run["clients"][1]["sip_port"],
                              start="INVITE sip:u2@mcptt.example SIP/2.0"))
    _fails(d, runs, "VP1-MED-002")


def _floor_frame(d, wireshark_name):
    return next(int(k) for k, v in d["names"].items() if v == wireshark_name)


def test_the_recorded_floor_packets_are_the_group_call_s_alone():
    """Each decoded floor packet is between a group-floor client and the relay;
    a doctored packet is therefore one the judge reads."""
    d, runs = recorded()
    g = run_of(runs, "group-floor")
    ports = {p for c in g["clients"] for p in (c["floor"], c["relay_floor"])}
    assert d["floor"] and all({p["src"], p["dst"]} <= ports for p in d["floor"])
    assert {int(k) for k in d["names"]} == {p["frame"] for p in d["floor"]} >= \
        {int(k) for k in d["fields"]}


def test_a_missing_revoke_fails_fc_001():
    d, runs = recorded()
    frame = _floor_frame(d, "floor revoke")
    d["floor"] = [p for p in d["floor"] if p["frame"] != frame]
    _fails(d, runs, "VP1-FC-001")


def test_a_message_type_never_seen_fails_fc_001_alone():
    """No Queue Position Request on the wire: only the 'each of the eight'
    step can tell (nothing else depends on it)."""
    d, runs = recorded()
    frame = _floor_frame(d, "floor queue position request")
    d["floor"] = [p for p in d["floor"] if p["frame"] != frame]
    v, r = verdicts(d, runs)
    steps = {s["name"][:20]: s["verdict"] for s in r["cases"]["VP1-FC-001"]["steps"]}
    assert not v["VP1-FC-001"] and list(steps.values()).count("FAIL") == 1
    assert steps["each of the eight me"] == "FAIL"


def test_wireshark_naming_a_server_message_from_a_client_fails_fc_001():
    """The comparator reads the bytes, Wireshark names the packet: if the
    names say a client sent Floor Granted, the direction step fails even
    where the comparator sees nothing wrong."""
    d, runs = recorded()
    request = sorted(int(k) for k, v in d["names"].items() if v == "floor request")[0]
    d["names"][str(request)] = "floor granted"
    d["fields"][str(request)]["rtcp.app_data.mcptt.duration"] = "1"
    v, r = verdicts(d, runs)
    failed = [s["name"][:20] for s in r["cases"]["VP1-FC-001"]["steps"]
              if s["verdict"] == "FAIL"]
    assert failed == ["each in its directio"]


def test_a_revoke_with_another_cause_fails_fc_001():
    d, runs = recorded()
    frame = _floor_frame(d, "floor revoke")
    d["fields"][str(frame)]["rtcp.app_data.mcptt.rej_cause.floor_revoke"] = "255"
    _fails(d, runs, "VP1-FC-001")


def test_a_granted_without_its_duration_fails_fc_001():
    d, runs = recorded()
    frame = _floor_frame(d, "floor granted")
    del d["fields"][str(frame)]["rtcp.app_data.mcptt.duration"]
    _fails(d, runs, "VP1-FC-001")


def test_a_server_message_sent_by_a_client_fails_fc_001():
    d, runs = recorded()
    frame = _floor_frame(d, "floor idle")
    p = next(p for p in d["floor"] if p["frame"] == frame)
    p["src"], p["dst"] = p["dst"], p["src"]
    _fails(d, runs, "VP1-FC-001")


def test_a_malformed_or_deviating_packet_fails_fc_001():
    d, runs = recorded()
    next(p for p in d["floor"] if p["frame"] == _floor_frame(d, "floor release")
         )["malformed"] = True
    _fails(d, runs, "VP1-FC-001")
    d, runs = recorded()
    p = next(p for p in d["floor"] if p["frame"] == _floor_frame(d, "floor taken"))
    raw = bytearray(bytes.fromhex(p["payload"]))
    raw[8:12] = b"XXXX"                      # not "MCPT": the comparator refuses it
    p["payload"] = raw.hex()
    _fails(d, runs, "VP1-FC-001")


def test_floor_granted_to_one_client_only_fails_exit_criterion_6_alone():
    """u2's Granted, and the Taken that told u1 of it, taken out: still a
    consistent floor trace (FC-001 passes), but the floor never went to u2."""
    import analyse
    d, runs = recorded()
    run = run_of(runs, "group-floor")
    u1, u2 = run["clients"][0]["floor"], run["clients"][1]["floor"]
    grant = next(p for p in d["floor"] if p["dst"] == u2
                 and d["names"][str(p["frame"])] == "floor granted")
    told = next(p for p in d["floor"] if p["dst"] == u1 and p["frame"] > grant["frame"]
                and d["names"][str(p["frame"])] == "floor taken")
    d["floor"] = [p for p in d["floor"] if p["frame"] not in (grant["frame"], told["frame"])]
    r = analyse.judge(d, runs)
    assert r["cases"]["VP1-FC-001"]["passed"]
    assert not r["exit_criterion_6"]["floor arbitrated: granted to each client in turn"]
    assert not r["passed"]
