"""TS-SIG transport cases (CLAUDE-2-sip-transport.md).

Unit tests drive `SipCore` with fake flows and a fake clock, so retransmission
and timers are exercised without sleeping. TLS cases open real loopback sockets.
None of this is run against a third-party SIP core: VP1-SIG-001 stays open.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import re
import socket
import ssl
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.errors import RESOLVER_UNAVAILABLE, StartupRefused  # noqa: E402
from core.hooks import MediaKind, SessionRequest  # noqa: E402
from core.session import Platform  # noqa: E402
from core.sip import (ReceivedResponse, Request, SipError, parse_message,  # noqa: E402
                      split_frame)
from profiles.common.tables import BackingStoreUnavailable, ResolutionFailure  # noqa: E402
from service.config import SipConfig  # noqa: E402
from service.runtime import build_runtime  # noqa: E402
from service.sip_core import SipCore, dialog_target  # noqa: E402
from tests import mcpttinfo_fixture as mcf  # noqa: E402
from service.sip_tls import TlsListener  # noqa: E402

U = [f"sip:u{i}@mcptt.example" for i in range(4)]
LOCAL = "sip:mcx@mcptt.example"
SDP = ("v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n"
       "m=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")


class Clock:
    def __init__(self):
        self.now = 10_000

    def __call__(self):
        return self.now


class Flow:
    """Records every message the core sends on it."""

    def __init__(self, name="flow"):
        self.name = name
        self.sent = []

    def send(self, text):
        self.sent.append(text)

    def messages(self):
        return [parse_message(t.encode()) for t in self.sent]

    def codes(self):
        return [m.code for m in self.messages() if isinstance(m, ReceivedResponse)]

    def requests(self, method=None):
        return [m for m in self.messages()
                if isinstance(m, Request) and (method is None or m.method == method)]


# ---------------------------------------------------------------- certificates


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    d = tmp_path_factory.mktemp("pki")
    now = datetime.datetime.now(datetime.timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def make(cn, issuer_name, issuer_key, ca=False, san=False):
        key = ec.generate_private_key(ec.SECP256R1())
        b = (x509.CertificateBuilder().subject_name(name(cn))
             .issuer_name(issuer_name).public_key(key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(minutes=1))
             .not_valid_after(now + datetime.timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True))
        if san:
            b = b.add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("localhost"),
                 x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        return key, b.sign(issuer_key, hashes.SHA256())

    def write(stem, key, cert):
        (d / f"{stem}.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        (d / f"{stem}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    ca_key, ca = make("test-ca", name("test-ca"), None or ec.generate_private_key(
        ec.SECP256R1()), ca=True)
    # self-signed: rebuild with its own key as issuer
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("test-ca"))
          .issuer_name(name("test-ca")).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=1))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
          .sign(ca_key, hashes.SHA256()))
    write("ca", ca_key, ca)
    k, c = make("mcx-server", ca.subject, ca_key, san=True)
    write("server", k, c)
    k, c = make("core-client", ca.subject, ca_key)
    write("client", k, c)
    # a client certificate from a CA the server does not trust
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_ca = (x509.CertificateBuilder().subject_name(name("rogue"))
                .issuer_name(name("rogue")).public_key(rogue_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .sign(rogue_key, hashes.SHA256()))
    k, c = make("intruder", rogue_ca.subject, rogue_key)
    write("rogue", k, c)
    return d


# ---------------------------------------------------------------------- fixtures


GROUPS_YAML = f"groups:\n  - id: 'grp:alpha'\n    members: {json.dumps(U)}\n"


def sip_env(tmp_path, pki, **over):
    g = tmp_path / "groups.yaml"
    g.write_text(GROUPS_YAML)
    env = {"MCX_PROFILE": "mcx", "MCX_RELEASE": "19", "MCX_IDMS": "stub",
            "MCX_RECORDER": "none", "MCX_BEARER": "none", "MCX_STRICT_RELEASE": "false",
           "MCX_DATA_DIR": str(tmp_path / "data"), "MCX_GROUPS_FILE": str(g),
           "MCX_HTTP_PORT": "0",
           "MCX_SIP_LISTEN": "127.0.0.1:0", "MCX_SIP_URI": LOCAL,
           "MCX_SIP_TLS_CERT": str(pki / "server.crt"),
           "MCX_SIP_TLS_KEY": str(pki / "server.key"),
           "MCX_SIP_TLS_CA": str(pki / "ca.crt"),
           "MCX_SIP_CLIENT_AUTH": "required",
           "MCX_SIP_ROLES": "controlling,participating",
           "MCX_MEDIA_ADDRESS": "127.0.0.1", "MCX_MEDIA_PORTS": "0"}
    env.update(over)
    return env


@pytest.fixture
def env(tmp_path, pki):
    return sip_env(tmp_path, pki)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def rt(env, clock):
    r = build_runtime(env, clock, platform=Platform())
    yield r
    r.close()


@pytest.fixture
def core(rt, clock):
    c = SipCore(rt, LOCAL, clock)
    yield c
    c.close()


def msg(method, uri, call_id, cseq, frm, to, *, branch=None, body="",
        ctype=None, extra=(), to_tag=None, from_tag="ft"):
    branch = branch or f"z9hG4bK{call_id}{cseq}{method}"
    h = [f"{method} {uri} SIP/2.0",
         f"Via: SIP/2.0/TLS core.example;branch={branch}",
         f"From: <{frm}>;tag={from_tag}",
         f"To: <{to}>" + (f";tag={to_tag}" if to_tag else ""),
         f"Call-ID: {call_id}", f"CSeq: {cseq} {method}", "Max-Forwards: 70"]
    h += list(extra)
    if ctype:
        h.append(f"Content-Type: {ctype}")
    h.append(f"Content-Length: {len(body.encode())}")
    return ("\r\n".join(h) + "\r\n\r\n" + body).encode()


def register(core, uri, flow, n=1, expires=3600):
    core.on_bytes(msg("REGISTER", "sip:mcptt.example", f"reg-{uri}-{n}", n, uri, uri,
                      extra=[f"Contact: <{uri}>;expires={expires}"]), flow)


def invite(call_id, frm, to, call_type, **kw):
    """A conformant client's INVITE (TS 24.379 10.1.1.2.1.1, 11.1.1.2.1.1):
    addressed to the participating function's own identity, with the target
    in <mcptt-request-uri> of a real multipart body. `to` is that target.

    This used to append <mcptt-call_type> to the SDP under a multipart
    Content-Type with no boundary lines -- a format of the platform's own
    invention that no client produces (PLT-CONF-AUDIT CA-20)."""
    return msg("INVITE", LOCAL, call_id, 1, frm, LOCAL,
               body=mcf.body_for(call_type, to, SDP), ctype=mcf.CONTENT_TYPE, **kw)


def answer(req: Request, code=200, body="", tag="callee", extra=()):
    """A callee's response to an INVITE the core sent it."""
    lines = [f"SIP/2.0 {code} X"]
    for v in req.headers.get_all("Via"):
        lines.append(f"Via: {v}")
    lines.append(f"From: {req.headers.get('From')}")
    lines.append(f"To: {req.headers.get('To')};tag={tag}")
    lines.append(f"Call-ID: {req.headers.get('Call-ID')}")
    lines.append(f"CSeq: {req.headers.get('CSeq')}")
    lines.extend(extra)
    if body:
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


@pytest.fixture
def world(core):
    """u0 (initiator) and u1..u3 registered, each on its own flow."""
    flows = {u: Flow(u) for u in U}
    for u in U:
        register(core, u, flows[u])
        flows[u].sent.clear()          # keep only what the test provokes
    return flows


# ============================================================ wire parsing


def test_parse_request_and_response_round_trip():
    raw = msg("INVITE", U[1], "c1", 1, U[0], U[1], body="hello", ctype="text/plain")
    r = parse_message(raw)
    assert isinstance(r, Request) and r.method == "INVITE" and r.uri == U[1]
    assert r.body == "hello" and r.headers.get("Call-ID") == "c1"
    assert parse_message(r.render().encode()).headers.get("CSeq") == "1 INVITE"
    resp = parse_message(b"SIP/2.0 486 Busy Here\r\nCSeq: 1 INVITE\r\n"
                         b"Content-Length: 0\r\n\r\n")
    assert isinstance(resp, ReceivedResponse) and resp.code == 486


def test_parse_expands_compact_forms_and_unfolds_lines():
    raw = (b"OPTIONS sip:x SIP/2.0\r\nv: SIP/2.0/TLS a;branch=z9hG4bK1\r\n"
           b"f: <sip:a@b>;tag=1\r\nt: <sip:c@d>\r\ni: id1\r\nCSeq: 1 OPTIONS\r\n"
           b"Subject: one\r\n two\r\nl: 0\r\n\r\n")
    r = parse_message(raw)
    assert r.headers.get("Call-ID") == "id1" and r.headers.get("Via")
    assert r.headers.get("Subject") == "one two"


def test_framing_waits_for_the_whole_body_and_counts_octets():
    raw = msg("MESSAGE", "sip:x", "c", 1, U[0], U[1], body="héllo", ctype="text/plain")
    assert split_frame(raw[:-1]) is None
    assert split_frame(raw) is not None
    assert parse_message(raw).body == "héllo"
    assert Request("MESSAGE", "sip:x", body="héllo").render().count("Content-Length: 6")


@pytest.mark.parametrize("junk", [b"garbage\r\n\r\n", b"GET / HTTP/1.1\r\n\r\n",
                                  b"INVITE sip:x SIP/2.0\r\nNoColon\r\n\r\n"])
def test_unparseable_messages_raise(junk):
    with pytest.raises(SipError):
        parse_message(junk)


def test_unparseable_input_is_dropped_and_counted_not_answered(core):
    f = Flow()
    core.on_bytes(b"garbage\r\n\r\n", f)
    assert f.sent == [] and core.counters["dropped_malformed"] == 1


# ============================================================ registration


def test_register_stores_state_and_answers_200(core, clock):
    f = Flow()
    register(core, U[1], f)
    assert f.codes() == [200]
    assert core.registrations.is_registered(U[1])
    clock.now += 3600 * 1000 + 1
    assert not core.registrations.is_registered(U[1])   # clock-driven expiry


def test_register_expires_zero_deregisters(core):
    f = Flow()
    register(core, U[1], f)
    register(core, U[1], f, n=2, expires=0)
    assert not core.registrations.is_registered(U[1])
    assert U[1] not in core.flows_by_user


def test_register_outside_declared_domain_is_refused_403(core):
    f = Flow()
    core.on_bytes(msg("REGISTER", "sip:x", "r1", 1, "sip:a@elsewhere.example",
                      "sip:a@elsewhere.example",
                      extra=["Contact: <sip:a@elsewhere.example>"]), f)
    assert f.codes() == [403]
    assert not core.registrations.is_registered("sip:a@elsewhere.example")


# ============================================================ guard and retransmission


def test_guard_runs_before_anything_acts_on_the_request(core, rt):
    f = Flow()
    called = []
    rt.establish = lambda *a, **k: called.append(1)
    bad = msg("INVITE", U[1], "bad1", 1, U[0], U[1]).replace(b"CSeq: 1 INVITE\r\n", b"")
    core.on_bytes(bad, f)
    assert f.codes() == [400] and called == []
    assert rt.store.audit_records() == []


def test_unknown_session_bye_is_answered_481(core):
    f = Flow()
    core.on_bytes(msg("BYE", U[1], "nosuch", 2, U[0], U[1]), f)
    assert f.codes() == [481]


def test_retransmission_of_a_rejected_request_gets_the_same_answer_not_a_replay_error(core):
    """The trap: the guard keys on (Call-ID, CSeq), so a legitimate
    retransmission would be rejected 482 unless the transaction layer answers
    it first."""
    f = Flow()
    bad = msg("BYE", U[1], "nosuch", 2, U[0], U[1])
    core.on_bytes(bad, f)
    core.on_bytes(bad, f)
    core.on_bytes(bad, f)
    assert f.codes() == [481, 481, 481]
    assert core.counters["guard_rejected"] == 1        # the guard saw it once


def test_a_genuine_replay_in_a_new_transaction_is_still_rejected(core):
    f = Flow()
    register(core, U[1], f, n=1)
    # same Call-ID and CSeq, different branch => a new transaction, a replay
    core.on_bytes(msg("REGISTER", "sip:mcptt.example", f"reg-{U[1]}-1", 1, U[1], U[1],
                      branch="z9hG4bKother",
                      extra=[f"Contact: <{U[1]}>;expires=3600"]), f)
    assert f.codes() == [200, 482]


def test_retransmitted_invite_reaches_the_session_manager_once(core, rt, world):
    raw = invite("s-retx", U[0], U[1], "private")
    core.on_bytes(raw, world[U[0]])
    first = list(world[U[0]].sent)
    core.on_bytes(raw, world[U[0]])
    core.on_bytes(raw, world[U[0]])
    admitted = [r for r in rt.store.audit_records("s-retx")
                if r["type"] == "session-admitted"]
    assert len(admitted) == 1
    assert len(world[U[1]].requests("INVITE")) == 1     # not invited twice
    assert world[U[0]].sent[:len(first)] == first


# ============================================================ VP1-CC-004 / PLT-CC-003


def test_vp1_cc_004_auto_answer_establishes_without_callee_action(core, rt, world):
    core.on_bytes(invite("auto1", U[0], "grp:alpha", "emergency-group"), world[U[0]])
    legs = {u: world[u].requests("INVITE") for u in U[1:]}
    assert all(len(v) == 1 for v in legs.values())
    for u, (req,) in legs.items():
        # Forced automatic commencement: TS 24.379 clause 11.1.1.2.1 branch a).
        # Answer-Mode: Auto alone would leave establishment conditional on the
        # invited client's own settings (clause 6.3.2.2.5.2), which is not
        # "without callee action".
        assert req.headers.get("Priv-Answer-Mode") == "Auto"
        assert not req.headers.has("Answer-Mode")
    assert world[U[0]].requests("INVITE") == []          # initiator not invited
    # the callee client answers with no user action: straight to 200, no 180
    core.on_bytes(answer(legs[U[1]][0], 200, SDP), world[U[1]])
    assert world[U[0]].codes() == [100, 200]
    assert rt.store.has_session("auto1")
    assert rt.manager.session("auto1") is not None


def test_private_call_without_auto_answer_rings_then_answers(core, rt, world):
    core.on_bytes(invite("man1", U[0], U[1], "private"), world[U[0]])
    (req,) = world[U[1]].requests("INVITE")
    assert req.headers.get("Answer-Mode") == "Manual"
    assert req.headers.get("Priv-Answer-Mode") is None
    core.on_bytes(answer(req, 180), world[U[1]])
    core.on_bytes(answer(req, 200, SDP), world[U[1]])
    assert world[U[0]].codes() == [100, 180, 200]
    # the callee got an ACK for its 200
    assert [r.method for r in world[U[1]].requests()][-1] == "ACK"


def test_mc_feature_tags_and_headers_are_on_the_wire(core, world):
    core.on_bytes(invite("tags1", U[0], U[1], "private"), world[U[0]])
    wire = world[U[1]].sent[0]                 # the exact bytes sent
    assert "Accept-Contact: *;+g.3gpp.mcptt;require;explicit" in wire
    assert "+g.3gpp.mcptt" in wire.split("Contact: ")[1].split("\r\n")[0]
    # TS 24.379 6.3.2.2.6.2 item 7: the participating function asserts ITS
    # OWN identity towards the terminating client. This test used to pin the
    # caller's identity here, which is the defect it now guards against.
    assert f"P-Asserted-Identity: <{LOCAL}>" in wire
    assert f"P-Asserted-Identity: <{U[0]}>" not in wire


# ============================================================ the MCPTT info body (CA-20)
#
# Literal expectations throughout; nothing below reads the renderer's constants.

def test_invite_to_the_callee_carries_the_mcptt_info_body(core, world):
    """6.3.2.2.3 item 8, 6.3.2.2.9, 10.1.1.4.1.1 item 4: the terminating client
    learns what kind of call it is, who is calling and which group, from the
    MCPTT info body -- which the platform did not send at all."""
    core.on_bytes(invite("g1", U[0], "grp:alpha", "emergency-group"), world[U[0]])
    (req,) = world[U[1]].requests("INVITE")
    assert (req.headers.get("Content-Type") or "").startswith("multipart/mixed;boundary=")
    xml = mcf.mcinfo_of(req)
    assert xml is not None, "no application/vnd.3gpp.mcptt-info+xml part"
    assert '<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0">' in xml
    assert "<session-type>prearranged</session-type>" in xml
    assert ('<mcptt-request-uri type="Normal"><mcpttURI>sip:u1@mcptt.example'
            "</mcpttURI></mcptt-request-uri>") in xml
    assert ('<mcptt-calling-user-id type="Normal"><mcpttURI>sip:u0@mcptt.example'
            "</mcpttURI></mcptt-calling-user-id>") in xml
    assert ('<mcptt-calling-group-id type="Normal"><mcpttURI>grp:alpha'
            "</mcpttURI></mcptt-calling-group-id>") in xml
    assert ('<emergency-ind type="Normal"><mcpttBoolean>true</mcpttBoolean>'
            "</emergency-ind>") in xml
    assert mcf.sdp_of(req).startswith("v=0")


def test_a_conformant_client_request_selects_the_declared_call_type(rt, core, world):
    """The inbound half: a body in the annex F.1 format, and nothing else,
    selects the mcx call type that declares its signature."""
    for cid, ct in (("s1", "prearranged-group"), ("s2", "emergency-group"),
                    ("s3", "imminent-peril-group")):
        core.on_bytes(invite(cid, U[0], "grp:alpha", ct), world[U[0]])
        recs = {r["correlation_id"]: r for r in rt.store.sessions()}
        assert recs[cid]["call_type"] == ct, (ct, recs[cid])


def test_the_invented_format_is_no_longer_understood(rt, core, world):
    """The format this platform used to read. A body carrying it has no
    <mcpttinfo>, so no call type is selected and the session policy refuses."""
    invented = SDP + "<mcptt-call_type>prearranged-group</mcptt-call_type>"
    core.on_bytes(msg("INVITE", LOCAL, "inv1", 1, U[0], LOCAL, body=invented,
                      ctype="application/sdp"), world[U[0]])
    assert world[U[0]].codes()[-1] >= 400
    assert not rt.store.has_session("inv1")


@pytest.mark.parametrize("ctype, body", [
    ("multipart/mixed;boundary=b", SDP + "<mcpttinfo/>"),       # no delimiter lines
    (mcf.CONTENT_TYPE, mcf.multipart(SDP, "<mcpttinfo><unclosed>")),
    (mcf.CONTENT_TYPE, mcf.multipart(SDP, '<!DOCTYPE x [<!ENTITY a "b">]><mcpttinfo/>')),
])
def test_a_malformed_body_is_refused_as_bad_request(rt, core, world, ctype, body):
    """VP1-SIG-004: refused with 400, and no session state left behind."""
    core.on_bytes(msg("INVITE", LOCAL, "bad1", 1, U[0], LOCAL, body=body, ctype=ctype),
                  world[U[0]])
    assert world[U[0]].codes()[-1] == 400
    assert not rt.store.has_session("bad1")


def test_the_floor_control_stream_is_not_data_media(core, world, rt):
    """TS 24.380 clause 14: every MCPTT voice offer carries
    "m=application <port> udp MCPTT". It is the floor control channel, and
    counting it as DATA made every real voice call look like voice + data."""
    offer = SDP + "m=application 20032 udp MCPTT\r\na=fmtp:MCPTT mc_queueing\r\n"
    core.on_bytes(msg("INVITE", LOCAL, "fc1", 1, U[0], LOCAL,
                      body=mcf.multipart(offer, mcf.mcinfo_xml("private", U[1])),
                      ctype=mcf.CONTENT_TYPE), world[U[0]])
    (req,) = world[U[1]].requests("INVITE")
    accept = " ".join(req.headers.get_all("Accept-Contact"))
    assert "+g.3gpp.mcdata" not in accept


# ============================================================ VP1-SIG-005


def assert_no_session_state(core, rt, cid):
    """Direct inspection of every place session state lives."""
    assert rt.store.has_session(cid) is False
    assert [s for s in rt.store.sessions() if s["correlation_id"] == cid] == []
    assert rt.manager.session(cid) is None
    assert cid not in core.calls
    assert not [k for k in core._dialogs if k == cid or k.startswith(cid + ".")]


def test_vp1_sig_005_callee_declines_leaves_no_session_state(core, rt, world):
    core.on_bytes(invite("f1", U[0], U[1], "private"), world[U[0]])
    assert rt.store.has_session("f1")              # live while inviting
    (req,) = world[U[1]].requests("INVITE")
    core.on_bytes(answer(req, 486), world[U[1]])
    assert world[U[0]].codes() == [100, 486]
    assert_no_session_state(core, rt, "f1")
    trail = [r["type"] for r in rt.store.audit_records("f1")]
    assert trail[-1] == "session-failed"           # the audit trail remains


def test_vp1_sig_005_refusal_leaves_no_session_state(env, clock):
    rt = build_runtime(env, clock)                 # fail-closed platform
    try:
        core = SipCore(rt, LOCAL, clock)
        f = Flow()
        core.on_bytes(invite("f2", U[0], U[1], "private"), f)
        assert f.codes() == [100, 503]
        assert_no_session_state(core, rt, "f2")
    finally:
        rt.close()


def test_vp1_sig_005_unregistered_callee_leaves_no_session_state(core, rt):
    f = Flow()
    core.on_bytes(invite("f3", U[0], U[1], "private"), f)
    assert f.codes() == [100, 480]
    assert_no_session_state(core, rt, "f3")


def test_vp1_sig_005_callee_timeout_leaves_no_session_state(core, rt, world, clock):
    core.on_bytes(invite("f4", U[0], U[1], "private"), world[U[0]])
    clock.now += 64 * 500 + 1
    core.tick()
    assert world[U[0]].codes() == [100, 480]       # 408 is not relayed upstream
    assert_no_session_state(core, rt, "f4")


def test_group_call_survives_one_decline_and_fails_only_when_all_do(core, rt, world):
    core.on_bytes(invite("g1", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    reqs = {u: world[u].requests("INVITE")[0] for u in U[1:]}
    core.on_bytes(answer(reqs[U[1]], 486), world[U[1]])
    core.on_bytes(answer(reqs[U[2]], 603), world[U[2]])
    assert 486 not in world[U[0]].codes() and rt.store.has_session("g1")
    core.on_bytes(answer(reqs[U[3]], 486), world[U[3]])
    assert world[U[0]].codes()[-1] == 486
    assert_no_session_state(core, rt, "g1")


# ============================================================ 2xx retransmission and ACK


def _answered_call(core, world, cid="k1"):
    core.on_bytes(invite(cid, U[0], U[1], "private"), world[U[0]])
    (req,) = world[U[1]].requests("INVITE")
    core.on_bytes(answer(req, 200, SDP), world[U[1]])


def test_2xx_is_retransmitted_until_ack_then_stops(core, world, clock):
    _answered_call(core, world)
    before = world[U[0]].codes().count(200)
    clock.now += 500
    core.tick()
    clock.now += 1000
    core.tick()
    assert world[U[0]].codes().count(200) == before + 2
    core.on_bytes(msg("ACK", LOCAL, "k1", 1, U[0], U[1], branch="z9hG4bKack"),
                  world[U[0]])
    n = world[U[0]].codes().count(200)
    clock.now += 10_000
    core.tick()
    assert world[U[0]].codes().count(200) == n


def test_missing_ack_ends_the_session_after_64_t1(core, rt, world, clock):
    _answered_call(core, world)
    for _ in range(80):
        clock.now += 500
        core.tick()
    rec = {s["correlation_id"]: s for s in rt.store.sessions()}["k1"]
    assert rec["state"] == "released"
    types = [r for r in rt.store.audit_records("k1") if r["type"] == "session-released"]
    assert types and types[-1]["detail"]["cause"] == "ack-timeout"


# ============================================================ BYE


def test_initiator_bye_releases_and_byes_the_callee(core, rt, world):
    _answered_call(core, world)
    core.on_bytes(msg("BYE", LOCAL, "k1", 2, U[0], U[1], to_tag="mcx"), world[U[0]])
    assert world[U[0]].codes()[-1] == 200
    assert [r.method for r in world[U[1]].requests()][-1] == "BYE"
    assert rt.manager.session("k1").state.value == "released"
    assert rt.store.sessions()[0]["state"] == "released"


def test_callee_bye_releases_and_byes_the_initiator(core, rt, world):
    _answered_call(core, world)
    leg = world[U[1]].requests("INVITE")[0].headers.get("Call-ID")
    # in the leg's dialog: the callee's tag in From, the platform's in To
    core.on_bytes(msg("BYE", LOCAL, leg, 2, U[1], U[0], from_tag="callee",
                      to_tag=f"{leg}-l"), world[U[1]])
    assert world[U[1]].codes()[-1] == 200
    byes = world[U[0]].requests("BYE")
    assert len(byes) == 1 and byes[0].headers.get("Call-ID") == "k1"
    assert rt.manager.session("k1").state.value == "released"


# ============================================================ VP1-CC-001 (partial)


def test_vp1_cc_001_audit_names_the_controlling_function(core, rt, world):
    _answered_call(core, world)
    for rec in rt.store.audit_records("k1"):
        if rec["type"] in ("session-admitted", "session-established"):
            assert rec["detail"]["controlling_function"] == LOCAL
            assert rec["detail"]["participating_function"] == LOCAL


def test_vp1_cc_001_roles_are_declared_and_separately_named(tmp_path, pki, clock):
    rt = build_runtime(sip_env(tmp_path, pki, MCX_SIP_ROLES="controlling"),
                       clock, platform=Platform())
    try:
        SipCore(rt, LOCAL, clock)
        rt.manager  # noqa: B018
        s, _, _ = rt.establish(SessionRequest(
            request_id="r1", initiator=U[0], target="grp:alpha",
            call_type="prearranged-group", media=(MediaKind.VOICE,)))
        d = [r for r in rt.store.audit_records("r1")
             if r["type"] == "session-established"][0]["detail"]
        assert d["controlling_function"] == LOCAL
        assert "participating_function" not in d       # role not hosted here
    finally:
        rt.close()


def test_participating_only_is_refused_not_faked(tmp_path, pki, clock):
    with pytest.raises(StartupRefused, match="SIP-OP-03"):
        build_runtime(sip_env(tmp_path, pki, MCX_SIP_ROLES="participating"), clock)


# ============================================================ VP1-HOOK-014


class PagedSource:
    """A directory whose second page is unavailable."""

    def __init__(self):
        self.pages = [[U[0], U[1]], BackingStoreUnavailable("shard 2 down")]
        self.read = []

    def members(self, group_id):
        out = []
        for page in self.pages:
            if isinstance(page, Exception):
                raise page
            self.read.append(tuple(page))
            out.extend(page)
        return out


def _resolver(rt):
    return rt.loaded.hooks.identity_resolver


def test_vp1_hook_014_partial_backing_store_raises_and_returns_no_members(rt):
    src = PagedSource()
    _resolver(rt).group_source = src
    req = SessionRequest(request_id="h1", initiator=U[0], target="grp:sharded",
                         call_type="prearranged-group", media=(MediaKind.VOICE,))
    with pytest.raises(ResolutionFailure) as exc:
        _resolver(rt).resolve("grp:sharded", req)
    assert exc.value.reason_code == RESOLVER_UNAVAILABLE
    assert src.read == [(U[0], U[1])]      # page 1 WAS read; none of it escaped


def test_vp1_hook_014_healthy_source_still_resolves_fully(rt):
    class Ok:
        def members(self, g):
            return [U[0], U[1], U[1]] if g == "grp:ok" else None
    _resolver(rt).group_source = Ok()
    req = SessionRequest(request_id="h2", initiator=U[0], target="grp:ok",
                         call_type="prearranged-group", media=(MediaKind.VOICE,))
    assert list(_resolver(rt).resolve("grp:ok", req).members) == [U[0], U[1]]
    with pytest.raises(ResolutionFailure) as exc:
        _resolver(rt).resolve("grp:none", req)
    assert exc.value.reason_code == "unknown-target"    # not confused with unavailable


def test_vp1_hook_014_reaches_the_wire_as_503_and_leaves_no_session(core, rt, world):
    _resolver(rt).group_source = PagedSource()
    core.on_bytes(invite("h3", U[0], "grp:sharded", "prearranged-group"), world[U[0]])
    assert world[U[0]].codes() == [100, 503]
    assert_no_session_state(core, rt, "h3")
    assert not any(world[u].requests("INVITE") for u in U[1:])   # nobody invited


# ============================================================ config refusals


@pytest.mark.parametrize("drop", ["MCX_SIP_URI", "MCX_SIP_TLS_CERT", "MCX_SIP_TLS_KEY",
                                  "MCX_SIP_TLS_CA", "MCX_SIP_CLIENT_AUTH",
                                  "MCX_SIP_ROLES"])
def test_sip_enabled_requires_every_security_setting(tmp_path, pki, clock, drop):
    e = sip_env(tmp_path, pki)
    del e[drop]
    with pytest.raises(StartupRefused):
        build_runtime(e, clock)


def test_client_auth_has_no_default_and_rejects_nonsense(tmp_path, pki, clock):
    with pytest.raises(StartupRefused, match="required' or 'optional"):
        build_runtime(sip_env(tmp_path, pki, MCX_SIP_CLIENT_AUTH="none"), clock)


def test_sip_disabled_when_no_listen_configured(tmp_path, pki):
    e = sip_env(tmp_path, pki)
    del e["MCX_SIP_LISTEN"]
    from service.config import Config
    assert Config.from_env(e).sip is None


# ============================================================ real TLS sockets


class Wire:
    """A TLS client speaking framed SIP."""

    def __init__(self, port, pki, cert="client", verify=True):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(str(pki / "ca.crt"))
        ctx.check_hostname = False
        if cert:
            ctx.load_cert_chain(str(pki / f"{cert}.crt"), str(pki / f"{cert}.key"))
        self.sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), 5),
                                    server_hostname="localhost")
        self.sock.settimeout(5)
        self.buf = b""

    def send(self, raw: bytes):
        self.sock.sendall(raw)

    def recv(self):
        while True:
            frame = split_frame(self.buf)
            if frame is not None:
                _, total = frame
                data, self.buf = self.buf[:total], self.buf[total:]
                return parse_message(data)
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError
            self.buf += chunk

    def close(self):
        self.sock.close()


@pytest.fixture
def server(env, tmp_path):
    rt = build_runtime(env, lambda: __import__("time").time_ns() // 1_000_000,
                       platform=Platform())
    from service.clock import utc_ms
    core = SipCore(rt, LOCAL, utc_ms)
    listener = TlsListener(core, rt.config.sip)
    listener.start()
    yield rt, core, listener
    listener.stop()
    rt.close()


def test_vp1_sig_006_plaintext_is_refused_and_counted(server):
    rt, core, listener = server
    s = socket.create_connection(("127.0.0.1", listener.bound_port), 5)
    s.settimeout(5)
    s.sendall(msg("REGISTER", "sip:x", "p1", 1, U[1], U[1],
                  extra=[f"Contact: <{U[1]}>"]))
    try:
        got = s.recv(4096)
    except ConnectionResetError:                # closing with unread input: RST
        got = b""
    assert got == b""                           # not a byte of SIP came back
    s.close()
    end = __import__("time").time() + 3
    while listener.counters["plaintext_refused"] < 1 and __import__("time").time() < end:
        __import__("time").sleep(0.02)
    assert listener.counters["plaintext_refused"] == 1
    assert listener.counters["accepted"] == 0
    assert core.registrations.registered_ids() == ()      # nothing was processed


def test_vp1_sig_006_client_without_certificate_is_refused_when_required(server):
    rt, core, listener = server
    with pytest.raises((ssl.SSLError, OSError, EOFError)):
        w = Wire(listener.bound_port, server_pki(rt), cert=None)
        w.send(msg("OPTIONS", "sip:x", "o1", 1, U[0], U[0]))
        w.recv()
    assert listener.counters["accepted"] == 0


def test_vp1_sig_006_client_with_untrusted_certificate_is_refused(server, pki):
    rt, core, listener = server
    with pytest.raises((ssl.SSLError, OSError, EOFError)):
        w = Wire(listener.bound_port, pki, cert="rogue")
        w.send(msg("OPTIONS", "sip:x", "o2", 1, U[0], U[0]))
        w.recv()
    assert listener.counters["accepted"] == 0


def server_pki(rt):
    return rt.config.sip.cert.parent


def test_vp1_sig_006_mutual_authentication_is_performed(server, pki):
    rt, core, listener = server
    w = Wire(listener.bound_port, pki)
    w.send(msg("OPTIONS", "sip:x", "o3", 1, U[0], U[0]))
    assert w.recv().code == 200
    assert listener.counters["mutual_auth"] == 1
    w.close()


def test_client_auth_optional_admits_a_peer_that_has_no_certificate(tmp_path, pki):
    rt = build_runtime(sip_env(tmp_path, pki, MCX_SIP_CLIENT_AUTH="optional"),
                       lambda: 0, platform=Platform())
    from service.clock import utc_ms
    listener = TlsListener(SipCore(rt, LOCAL, utc_ms), rt.config.sip)
    listener.start()
    try:
        w = Wire(listener.bound_port, pki, cert=None)
        w.send(msg("OPTIONS", "sip:x", "o4", 1, U[0], U[0]))
        assert w.recv().code == 200
        assert listener.counters["no_client_cert"] == 1
        # ... but a peer presenting a certificate it cannot back up is not
        with pytest.raises((ssl.SSLError, OSError, EOFError)):
            w2 = Wire(listener.bound_port, pki, cert="rogue")
            w2.send(msg("OPTIONS", "sip:x", "o5", 1, U[0], U[0]))
            w2.recv()
        w.close()
    finally:
        listener.stop()
        rt.close()


def test_private_call_end_to_end_over_tls(server, pki):
    """Registration and a private call, byte for byte over real TLS sockets."""
    rt, core, listener = server
    caller, callee = Wire(listener.bound_port, pki), Wire(listener.bound_port, pki)
    for w, u in ((caller, U[0]), (callee, U[1])):
        w.send(msg("REGISTER", "sip:mcptt.example", f"r-{u}", 1, u, u,
                   extra=[f"Contact: <{u}>;expires=600"]))
        assert w.recv().code == 200

    caller.send(invite("e2e", U[0], U[1], "private"))
    assert caller.recv().code == 100
    inv = callee.recv()
    assert isinstance(inv, Request) and inv.method == "INVITE"
    assert "+g.3gpp.mcptt" in inv.headers.get("Accept-Contact")
    callee.send(answer(inv, 180))
    assert caller.recv().code == 180
    callee.send(answer(inv, 200, SDP))
    ok = caller.recv()
    assert ok.code == 200 and "m=audio" in ok.body
    assert callee.recv().method == "ACK"
    caller.send(msg("ACK", LOCAL, "e2e", 1, U[0], U[1], branch="z9hG4bKe2eack"))
    assert rt.store.has_session("e2e")
    caller.send(msg("BYE", LOCAL, "e2e", 2, U[0], U[1]))
    assert caller.recv().code == 200
    assert callee.recv().method == "BYE"
    caller.close()
    callee.close()



# ============================================================ the real process


def test_process_serves_sip_over_tls_and_reports_counters(tmp_path, pki):
    from tests.test_service import free_port, get, spawn, stop, wait_ready
    http, sip = free_port(), free_port()
    e = sip_env(tmp_path, pki, MCX_SIP_LISTEN=f"127.0.0.1:{sip}")
    proc = spawn(e, http)
    try:
        wait_ready(http, proc)
        w = Wire(sip, pki)
        w.send(msg("REGISTER", "sip:mcptt.example", "pr1", 1, U[1], U[1],
                   extra=[f"Contact: <{U[1]}>;expires=60"]))
        assert w.recv().code == 200
        w.close()
        p = socket.create_connection(("127.0.0.1", sip), 5)
        p.sendall(b"REGISTER sip:x SIP/2.0\r\n\r\n")
        try:
            assert p.recv(100) == b""
        except ConnectionResetError:
            pass
        p.close()
        import time
        for _ in range(100):
            counters = json.loads(get(http, "/healthz")[1])["sip"]
            if counters["plaintext_refused"]:
                break
            time.sleep(0.05)
        assert counters["plaintext_refused"] == 1 and counters["accepted"] == 1
    finally:
        stop(proc)


def test_process_refuses_to_start_with_incomplete_sip_configuration(tmp_path, pki):
    from tests.test_service import free_port, spawn
    e = sip_env(tmp_path, pki)
    del e["MCX_SIP_CLIENT_AUTH"]
    proc = spawn(e, free_port())
    try:
        assert proc.wait(timeout=15) == 2
        assert b"MCX_SIP_CLIENT_AUTH" in proc.stderr.read()
    finally:
        proc.stdout.close()
        proc.stderr.close()


# ============================================================ dialogs through a proxy
#
# Every test above talks to the core with nothing in between, so none of them
# could tell a request sent to the peer's address-of-record from one sent the
# RFC 3261 section 12 way. Against Kamailio (VP1-SIG-001) the difference was
# the whole call: both ACKs of an answered call were dropped by the proxy,
# because the 200 OK carried no Record-Route and the platform's own ACK and
# BYE went to the AoR with no Route header. These tests put a proxy's
# Record-Route and a real Contact on the wire, which is all it takes.

P1 = "<sip:p1.example;transport=tls;lr>"
P2 = "<sip:p2.example;transport=tls;lr;ftag=abc>"
CALLEE_CONTACT = "<sip:u1@192.0.2.7:5071;transport=tls>"
CALLER_CONTACT = "<sip:u0@192.0.2.9:5073;transport=tls>"


def _proxied_private_call(core, world, cid="rr1"):
    """u0 calls u1 through two record-routing proxies, both directions."""
    core.on_bytes(invite(cid, U[0], U[1], "private",
                         extra=[f"Record-Route: {P2}, {P1}",
                                f"Contact: {CALLER_CONTACT}"]), world[U[0]])
    (req,) = world[U[1]].requests("INVITE")
    # The leg's proxies record-route the other way round.
    core.on_bytes(answer(req, 200, SDP, extra=[f"Record-Route: {P1}",
                                               f"Record-Route: {P2}",
                                               f"Contact: {CALLEE_CONTACT}"]),
                  world[U[1]])
    return req


def test_2xx_to_the_initiator_copies_record_route_in_order(core, world):
    """RFC 3261 12.1.1. One comma-joined header must come back as two values,
    in the order received -- not reversed, which is the UAC's job."""
    _proxied_private_call(core, world)
    (ok,) = [m for m in world[U[0]].messages()
             if isinstance(m, ReceivedResponse) and m.code == 200]
    from service.sip_core import _header_values
    assert _header_values(ok.headers.get_all("Record-Route")) == [P2, P1]


def test_ack_on_a_leg_goes_to_the_contact_through_the_reversed_route_set(core, world):
    """RFC 3261 12.1.2 and 12.2.1.1. The Request-URI keeps ;transport=tls --
    the first fix stripped URI parameters and lost it, with ;lr."""
    _proxied_private_call(core, world)
    (ack,) = world[U[1]].requests("ACK")
    assert ack.uri == "sip:u1@192.0.2.7:5071;transport=tls"
    assert list(ack.headers.get_all("Route")) == [P2, P1]


def test_bye_to_the_initiator_follows_the_invite_route_set(core, world):
    """The callee hangs up; the platform's BYE to the initiator goes to the
    initiator's Contact with the INVITE's Record-Route, unreversed."""
    req = _proxied_private_call(core, world)
    leg = req.headers.get("Call-ID")
    core.on_bytes(msg("BYE", LOCAL, leg, 2, U[1], LOCAL, from_tag="callee",
                      to_tag=f"{leg}-l"), world[U[1]])
    (bye,) = world[U[0]].requests("BYE")
    assert bye.uri == "sip:u0@192.0.2.9:5073;transport=tls"
    assert list(bye.headers.get_all("Route")) == [P2, P1]


def test_bye_on_a_leg_follows_that_legs_route_set(core, world):
    _proxied_private_call(core, world)
    core.on_bytes(msg("BYE", LOCAL, "rr1", 2, U[0], LOCAL, to_tag="x"), world[U[0]])
    (bye,) = world[U[1]].requests("BYE")
    assert bye.uri == "sip:u1@192.0.2.7:5071;transport=tls"
    assert list(bye.headers.get_all("Route")) == [P2, P1]


def test_without_a_proxy_nothing_changes(core, world):
    """No Record-Route and no Contact: the Request-URI falls back to the AoR
    and no Route header is invented. Every other test in this file is this case."""
    _answered_call(core, world, cid="plain")
    (ack,) = world[U[1]].requests("ACK")
    assert ack.uri == U[1] and not ack.headers.get_all("Route")


@pytest.mark.parametrize("routes, ruri, route_headers", [
    ([], "sip:t@h;transport=tls", []),
    (["<sip:p;lr>"], "sip:t@h;transport=tls", ["<sip:p;lr>"]),
    (["<sip:p;lr=on>"], "sip:t@h;transport=tls", ["<sip:p;lr=on>"]),
    # ;lrx is not ;lr
    (["<sip:p;lrx>", "<sip:q;lr>"], "sip:p;lrx", ["<sip:q;lr>", "<sip:t@h;transport=tls>"]),
    # strict router: it takes the Request-URI, the target goes last
    (["<sip:p;transport=tls>", "<sip:q;lr>"], "sip:p;transport=tls",
     ["<sip:q;lr>", "<sip:t@h;transport=tls>"]),
])
def test_dialog_target_loose_and_strict_routing(routes, ruri, route_headers):
    """RFC 3261 12.2.1.1, both branches."""
    assert dialog_target("sip:t@h;transport=tls", routes) == (ruri, route_headers)


# Found by an independent review of the routing change: each input below was
# handled wrongly by its first version.
@pytest.mark.parametrize("raw, values", [
    (['"a\\", b" <sip:p1;lr>, <sip:p2;lr>'], ['"a\\", b" <sip:p1;lr>', "<sip:p2;lr>"]),
    (['"x, <y>" <sip:p1;lr>', "<sip:p2;lr>"], ['"x, <y>" <sip:p1;lr>', "<sip:p2;lr>"]),
])
def test_header_values_respect_quoted_pairs(raw, values):
    from service.sip_core import _header_values
    assert _header_values(raw) == values


@pytest.mark.parametrize("value, uri", [
    ('"a<b" <sip:x@h;transport=tls>', "sip:x@h;transport=tls"),
    ('"a\\"<b" <sip:x@h;transport=tls>;expires=3', "sip:x@h;transport=tls"),
    ("sip:x@h;transport=tls", "sip:x@h"),      # addr-spec: header params
])
def test_addr_uri_ignores_angle_brackets_in_display_names(value, uri):
    from service.sip_core import _addr_uri
    assert _addr_uri(value) == uri


@pytest.mark.parametrize("routes, ruri", [
    (["<sip:p;lr?x=1>"], "sip:t@h;transport=tls"),                 # loose, headers after
    (["<sip:u;lr;x@p;transport=tls>"], "sip:u;lr;x@p;transport=tls"),  # ;lr in the user part is not ;lr
    (["<sip:p;maddr=192.0.2.1;method=INVITE?X=y>"], "sip:p;maddr=192.0.2.1"),  # strict: strip
])
def test_dialog_target_edge_cases(routes, ruri):
    assert dialog_target("sip:t@h;transport=tls", routes)[0] == ruri


# ============================================================ SIP-OP-13: the UAC's ACKs
#
# The platform is the UAC on every leg toward a callee. Two duties it did not
# carry out: re-ACK a retransmitted 2xx (RFC 3261 13.2.2.4) -- the INVITE
# transaction was finished on the first 2xx, so the retransmission matched
# nothing and was dropped -- and ACK a 3xx-6xx (17.1.1.3), which it never did.
# With nothing in between neither shows. Behind a proxy that forwards over
# UDP, a lost ACK makes the callee hang up an answered call after 64*T1.


def _leg_invite(world, u=U[1]):
    return world[u].requests("INVITE")[-1]


def test_a_retransmitted_2xx_gets_the_same_ack_again(core, world):
    _answered_call(core, world, cid="ra1")
    req = _leg_invite(world)
    core.on_bytes(answer(req, 200, SDP), world[U[1]])        # the retransmission
    acks = [t for t in world[U[1]].sent if t.startswith("ACK ")]
    assert len(acks) == 2 and acks[0] == acks[1]
    assert not world[U[1]].requests("BYE")                    # same dialog: kept


def test_the_2xx_window_closes_after_64_t1_without_failing_the_leg(core, rt, world, clock):
    _answered_call(core, world, cid="ra2")
    core.on_bytes(msg("ACK", LOCAL, "ra2", 1, U[0], U[1], branch="z9hG4bKra2"),
                  world[U[0]])
    clock.now += 64 * 500 + 1
    core.tick()                                               # Timer M
    assert rt.manager.session("ra2").state.value != "released"
    assert not world[U[1]].requests("BYE")
    core.on_bytes(answer(_leg_invite(world), 200, SDP), world[U[1]])
    assert len(world[U[1]].requests("ACK")) == 1             # now unmatched
    # the leg is still confirmed: hanging up reaches the callee
    core.on_bytes(msg("BYE", LOCAL, "ra2", 2, U[0], LOCAL, to_tag="x"), world[U[0]])
    assert len(world[U[1]].requests("BYE")) == 1


def test_a_second_fork_answering_is_acked_then_ended(core, rt, world):
    _answered_call(core, world, cid="ra3")
    req = _leg_invite(world)
    fork_contact = "<sip:u1@192.0.2.44:5071;transport=tls>"
    core.on_bytes(answer(req, 200, SDP, tag="fork2",
                         extra=[f"Contact: {fork_contact}"]), world[U[1]])
    ack, bye = world[U[1]].requests()[-2:]
    assert ack.method == "ACK" and bye.method == "BYE"
    for m in (ack, bye):
        assert m.headers.get("To").endswith(";tag=fork2")
        assert m.uri == "sip:u1@192.0.2.44:5071;transport=tls"
    assert bye.headers.get("CSeq") == "2 BYE"
    # the call itself goes on, and the fork's retransmission is re-ACKed only
    assert rt.manager.session("ra3").state.value != "released"
    core.on_bytes(answer(req, 200, SDP, tag="fork2",
                         extra=[f"Contact: {fork_contact}"]), world[U[1]])
    assert len(world[U[1]].requests("BYE")) == 1
    assert len(world[U[1]].requests("ACK")) == 3
    # the stray BYE's 200 closes its transaction
    n = len(core.client)
    core.on_bytes(answer(bye, 200, tag="fork2"), world[U[1]])
    assert len(core.client) == n - 1


def test_a_bye_from_the_stray_fork_does_not_end_the_call(core, rt, world):
    """RFC 3261 12.2.2: dialogs are matched by Call-ID and tags. The fork
    that answered second shares the leg's Call-ID; its BYE ends its own
    dialog only. A BYE for a dialog nobody knows gets 481."""
    _answered_call(core, world, cid="sf1")
    core.on_bytes(msg("ACK", LOCAL, "sf1", 1, U[0], U[1], branch="z9hG4bKsf1"),
                  world[U[0]])
    inv = _leg_invite(world)
    leg = inv.headers.get("Call-ID")
    core.on_bytes(answer(inv, 200, SDP, tag="fork2"), world[U[1]])
    core.on_bytes(msg("BYE", LOCAL, leg, 7, U[1], LOCAL, from_tag="fork2",
                      to_tag=f"{leg}-l"), world[U[1]])
    assert world[U[1]].codes()[-1] == 200
    core.on_bytes(msg("BYE", LOCAL, leg, 8, U[1], LOCAL, from_tag="nobody",
                      to_tag=f"{leg}-l"), world[U[1]])
    assert world[U[1]].codes()[-1] == 481
    assert rt.manager.session("sf1").state.value != "released"
    assert world[U[0]].requests("BYE") == []


def test_an_unanswered_stray_bye_does_not_touch_the_kept_dialog(core, world, clock):
    _answered_call(core, world, cid="ra5")
    core.on_bytes(msg("ACK", LOCAL, "ra5", 1, U[0], U[1], branch="z9hG4bKra5"),
                  world[U[0]])
    core.on_bytes(answer(_leg_invite(world), 200, SDP, tag="fork2"), world[U[1]])
    clock.now += 64 * 500 + 1
    core.tick()                                   # the stray BYE's Timer F
    core.on_bytes(msg("BYE", LOCAL, "ra5", 2, U[0], LOCAL, to_tag="x"), world[U[0]])
    byes = world[U[1]].requests("BYE")
    assert [b.headers.get("To").rsplit("tag=", 1)[1] for b in byes] == \
        ["fork2", "callee"]


def test_the_non_2xx_ack_carries_the_invites_route(core):
    """17.1.1.3: 'the ACK MUST contain ... the Route header fields of the
    request'. No leg INVITE carries a Route today (no outbound proxy), so
    the transaction is driven directly."""
    from service.sip_core import Leg
    from core.sip import Headers as H
    flow = Flow()
    inv = Request("INVITE", "sip:u1@mcptt.example", H([
        ("Via", "SIP/2.0/TLS mcptt.example;branch=z9hG4bKr1"),
        ("From", f"<{LOCAL}>;tag=a"), ("To", f"<{U[1]}>"),
        ("Call-ID", "rt1"), ("CSeq", "1 INVITE"),
        ("Route", "<sip:ob1.example;lr>"), ("Route", "<sip:ob2.example;lr>")]))
    txn = core.client.start(inv, flow, user=Leg(uri=U[1], call_id="rt1", flow=flow))
    core.on_bytes(answer(inv, 404, tag="nf"), flow)
    (ack,) = flow.requests("ACK")
    assert list(ack.headers.get_all("Route")) == ["<sip:ob1.example;lr>",
                                                  "<sip:ob2.example;lr>"]
    assert txn.done


def test_a_decline_is_acked_by_the_invite_transaction(core, world):
    """RFC 3261 17.1.1.3: same Request-URI, Call-ID, From and top Via as the
    INVITE (branch included), the response's To with its tag, CSeq number
    unchanged with method ACK."""
    core.on_bytes(invite("na1", U[0], U[1], "private"), world[U[0]])
    req = _leg_invite(world)
    core.on_bytes(answer(req, 486, tag="busy"), world[U[1]])
    (ack,) = world[U[1]].requests("ACK")
    assert ack.uri == req.uri
    assert ack.headers.get_all("Via")[0] == req.headers.get_all("Via")[0]
    for h in ("From", "Call-ID"):
        assert ack.headers.get(h) == req.headers.get(h)
    assert ack.headers.get("To") == f"{req.headers.get('To')};tag=busy"
    assert ack.headers.get("CSeq") == f"{req.headers.get('CSeq').split()[0]} ACK"
    assert list(ack.headers.get_all("Route")) == list(req.headers.get_all("Route"))


def test_an_answer_after_the_call_ended_is_acked_and_ended(core, rt, world):
    """A group call: u1 answers, the initiator hangs up while u2 still rings,
    then u2 answers. Its dialog must be ACKed and closed, not left to time out."""
    core.on_bytes(invite("la1", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    reqs = {u: _leg_invite(world, u) for u in U[1:]}
    core.on_bytes(answer(reqs[U[1]], 200, SDP), world[U[1]])
    core.on_bytes(msg("BYE", LOCAL, "la1", 2, U[0], LOCAL, to_tag="x"), world[U[0]])
    core.on_bytes(answer(reqs[U[2]], 200, SDP, tag="late"), world[U[2]])
    ack, bye = world[U[2]].requests()[-2:]
    assert (ack.method, bye.method) == ("ACK", "BYE")
    assert bye.headers.get("To").endswith(";tag=late")
    # and a decline after the end is still ACKed
    core.on_bytes(answer(reqs[U[3]], 603, tag="no"), world[U[3]])
    assert world[U[3]].requests()[-1].method == "ACK"


def test_a_non_2xx_after_the_2xx_is_discarded(core, rt, world):
    """RFC 6026 7.2: in 'Accepted' only 2xx responses are passed up."""
    _answered_call(core, world, cid="ra4")
    core.on_bytes(answer(_leg_invite(world), 500, tag="other"), world[U[1]])
    assert len(world[U[1]].requests("ACK")) == 1
    assert rt.manager.session("ra4").state.value != "released"


# ============================================================ CANCEL (SIP-OP-14, SIP-OP-15)


def _responses(flow, method):
    return [m for m in flow.messages() if isinstance(m, ReceivedResponse)
            and m.headers.get("CSeq").split()[1] == method]


def _ringing_group_call(core, world, cid):
    """u1 answers; u2 is ringing (180); u3 has said nothing yet."""
    core.on_bytes(invite(cid, U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    reqs = {u: _leg_invite(world, u) for u in U[1:]}
    core.on_bytes(answer(reqs[U[1]], 200, SDP), world[U[1]])
    core.on_bytes(answer(reqs[U[2]], 180, tag="r2"), world[U[2]])
    # the initiator ACKs its 200, or the call ends at 64*T1 for that reason
    ok = [r for r in _responses(world[U[0]], "INVITE") if r.code == 200][0]
    core.on_bytes(msg("ACK", LOCAL, cid, 1, U[0], LOCAL, branch=f"z9hG4bK{cid}ack",
                      to_tag=ok.headers.get("To").split("tag=")[1]), world[U[0]])
    return reqs


def test_ending_a_call_cancels_the_legs_still_ringing(core, world):
    """RFC 3261 9.1: the CANCEL copies the INVITE's Request-URI, Call-ID,
    To, From and CSeq number, has one Via -- the INVITE's top Via, branch
    included -- and the INVITE's Route headers."""
    reqs = _ringing_group_call(core, world, "cx1")
    core.on_bytes(msg("BYE", LOCAL, "cx1", 2, U[0], LOCAL, to_tag="x"), world[U[0]])
    (cancel,) = world[U[2]].requests("CANCEL")
    inv = reqs[U[2]]
    assert cancel.uri == inv.uri
    assert list(cancel.headers.get_all("Via")) == [inv.headers.get_all("Via")[0]]
    for h in ("From", "To", "Call-ID"):
        assert cancel.headers.get(h) == inv.headers.get(h)
    assert "tag=" not in cancel.headers.get("To")
    assert cancel.headers.get("CSeq") == f"{inv.headers.get('CSeq').split()[0]} CANCEL"
    assert list(cancel.headers.get_all("Route")) == list(inv.headers.get_all("Route"))
    # the answered leg is BYEd, not CANCELled
    assert world[U[1]].requests("CANCEL") == [] and world[U[1]].requests("BYE")


def test_a_leg_that_has_not_answered_at_all_is_cancelled_when_it_does(core, world):
    """9.1: 'If no provisional response has been received, the CANCEL
    request MUST NOT be sent; rather, the client MUST wait for the arrival
    of a provisional response before sending the request.'"""
    reqs = _ringing_group_call(core, world, "cx2")
    core.on_bytes(msg("BYE", LOCAL, "cx2", 2, U[0], LOCAL, to_tag="x"), world[U[0]])
    assert world[U[3]].requests("CANCEL") == []
    core.on_bytes(answer(reqs[U[3]], 100, tag="r3"), world[U[3]])
    assert len(world[U[3]].requests("CANCEL")) == 1
    core.on_bytes(answer(reqs[U[3]], 180, tag="r3"), world[U[3]])
    assert len(world[U[3]].requests("CANCEL")) == 1          # once only


def test_the_487_that_answers_a_cancel_is_acked_and_the_transactions_end(core, world):
    reqs = _ringing_group_call(core, world, "cx3")
    core.on_bytes(msg("BYE", LOCAL, "cx3", 2, U[0], LOCAL, to_tag="x"), world[U[0]])
    (cancel,) = world[U[2]].requests("CANCEL")
    core.on_bytes(answer(cancel, 200, tag="r2"), world[U[2]])
    core.on_bytes(answer(reqs[U[2]], 487, tag="r2"), world[U[2]])
    (ack,) = world[U[2]].requests("ACK")
    assert ack.headers.get("CSeq").endswith(" ACK")
    assert ack.headers.get_all("Via")[0] == reqs[U[2]].headers.get_all("Via")[0]
    assert world[U[2]].requests("BYE") == []
    from service.sip_txn import top_branch
    for method in ("INVITE", "CANCEL"):
        assert core.client.find(top_branch(reqs[U[2]].headers), method) is None


def test_a_2xx_that_crossed_the_cancel_is_acked_and_ended(core, world):
    reqs = _ringing_group_call(core, world, "cx4")
    core.on_bytes(msg("BYE", LOCAL, "cx4", 2, U[0], LOCAL, to_tag="x"), world[U[0]])
    core.on_bytes(answer(reqs[U[2]], 200, SDP, tag="r2"), world[U[2]])
    ack, bye = world[U[2]].requests()[-2:]
    assert (ack.method, bye.method) == ("ACK", "BYE")


def test_a_leg_ringing_past_the_limit_is_cancelled_and_cannot_join_late(core, rt, world,
                                                                       clock):
    """SIP-OP-15: the call goes on (u1 answered); u2 rings past 64*T1. It is
    CANCELled rather than forgotten, and a 2xx that crosses the CANCEL is
    ACKed and BYEd -- the leg does not join, and its 2xx is not dropped
    unmatched, which is what used to happen."""
    reqs = _ringing_group_call(core, world, "cx5")
    clock.now += 64 * 500
    core.tick()
    (cancel,) = world[U[2]].requests("CANCEL")
    assert rt.manager.session("cx5").state.value != "released"
    # u3 never sent a provisional: Timer B ends it without a CANCEL
    assert world[U[3]].requests("CANCEL") == []
    core.on_bytes(answer(reqs[U[2]], 200, SDP, tag="r2"), world[U[2]])
    ack, bye = world[U[2]].requests()[-2:]
    assert (ack.method, bye.method) == ("ACK", "BYE")
    assert U[2] not in core.media._sessions["cx5"].endpoints or \
        core.media._sessions["cx5"].endpoints[U[2]].remote_rtp is None
    # and the transaction is gone 64*T1 after the CANCEL
    clock.now += 64 * 500
    core.tick()
    from service.sip_txn import top_branch
    assert core.client.find(top_branch(reqs[U[2]].headers), "INVITE") is None


def test_a_private_call_ringing_past_the_limit_fails_and_cancels(core, rt, world, clock):
    core.on_bytes(invite("cx6", U[0], U[1], "private"), world[U[0]])
    req = _leg_invite(world)
    core.on_bytes(answer(req, 180, tag="r1"), world[U[1]])
    clock.now += 64 * 500
    core.tick()
    assert world[U[0]].codes()[-1] == 480
    (cancel,) = world[U[1]].requests("CANCEL")
    core.on_bytes(answer(req, 487, tag="r1"), world[U[1]])
    assert world[U[1]].requests()[-1].method == "ACK"
    assert_no_session_state(core, rt, "cx6")


def test_a_callee_that_never_answered_is_not_cancelled(core, rt, world, clock):
    """Timer B in 'Calling' (no provisional): nothing to CANCEL."""
    core.on_bytes(invite("cx7", U[0], U[1], "private"), world[U[0]])
    clock.now += 64 * 500 + 1
    core.tick()
    assert world[U[1]].requests("CANCEL") == []
    assert world[U[0]].codes() == [100, 480]


# -- the initiator's CANCEL (RFC 3261 9.2) ------------------------------------------


def _cancel_from_initiator(cid, branch=None):
    return msg("CANCEL", LOCAL, cid, 1, U[0], LOCAL,
               branch=branch or f"z9hG4bK{cid}1INVITE")


def test_the_initiators_cancel_ends_the_call_with_487(core, rt, world):
    core.on_bytes(invite("ic1", U[0], U[1], "private"), world[U[0]])
    req = _leg_invite(world)
    core.on_bytes(answer(req, 180, tag="r1"), world[U[1]])
    core.on_bytes(_cancel_from_initiator("ic1"), world[U[0]])
    (ok,) = _responses(world[U[0]], "CANCEL")
    assert ok.code == 200
    final = [r for r in _responses(world[U[0]], "INVITE") if r.code >= 200]
    assert [r.code for r in final] == [487]
    # 9.2: the two To tags SHOULD be the same
    assert ok.headers.get("To") == final[0].headers.get("To")
    assert len(world[U[1]].requests("CANCEL")) == 1
    assert_no_session_state(core, rt, "ic1")
    # the initiator's ACK for the 487 is absorbed, not answered
    n = len(world[U[0]].sent)
    core.on_bytes(msg("ACK", LOCAL, "ic1", 1, U[0], LOCAL,
                      branch="z9hG4bKic11INVITE",
                      to_tag=final[0].headers.get("To").split("tag=")[1]),
                  world[U[0]])
    assert len(world[U[0]].sent) == n


def test_a_cancel_for_no_transaction_is_481(core, world):
    core.on_bytes(_cancel_from_initiator("ic2", branch="z9hG4bKnothing"), world[U[0]])
    assert world[U[0]].codes() == [481]


def test_a_cancel_after_the_answer_changes_nothing(core, rt, world):
    _answered_call(core, world, cid="ic3")
    core.on_bytes(_cancel_from_initiator("ic3"), world[U[0]])
    assert [r.code for r in _responses(world[U[0]], "CANCEL")] == [200]
    assert 487 not in world[U[0]].codes()
    assert rt.manager.session("ic3").state.value != "released"
    assert world[U[1]].requests("CANCEL") == []


def test_a_retransmitted_cancel_gets_the_same_answer(core, rt, world):
    core.on_bytes(invite("ic4", U[0], U[1], "private"), world[U[0]])
    core.on_bytes(_cancel_from_initiator("ic4"), world[U[0]])
    core.on_bytes(_cancel_from_initiator("ic4"), world[U[0]])
    oks = _responses(world[U[0]], "CANCEL")
    assert [r.code for r in oks] == [200, 200]
    assert [r.code for r in _responses(world[U[0]], "INVITE") if r.code >= 200] == [487]


def test_options_advertises_cancel(core, world):
    core.on_bytes(msg("OPTIONS", LOCAL, "op1", 1, U[0], LOCAL), world[U[0]])
    (resp,) = world[U[0]].messages()
    assert "CANCEL" in [m.strip() for m in resp.headers.get("Allow").split(",")]


def test_the_cancel_carries_the_invites_route(core):
    """9.1: 'the CANCEL request MUST contain ... the Route header fields of
    the request being cancelled'. No leg INVITE carries a Route today, so
    the transaction is driven directly, as for the non-2xx ACK."""
    from service.sip_core import Leg
    from core.sip import Headers as H
    flow = Flow()
    inv = Request("INVITE", "sip:u1@mcptt.example", H([
        ("Via", "SIP/2.0/TLS mcptt.example;branch=z9hG4bKrc1"),
        ("From", f"<{LOCAL}>;tag=a"), ("To", f"<{U[1]}>"),
        ("Call-ID", "rc1"), ("CSeq", "1 INVITE"),
        ("Route", "<sip:ob1.example;lr>"), ("Route", "<sip:ob2.example;lr>")]))
    leg = Leg(uri=U[1], call_id="rc1", flow=flow)
    leg.txn = core.client.start(inv, flow, user=leg)
    core.client.proceed(leg.txn)
    core._send_cancel(leg)
    (cancel,) = flow.requests("CANCEL")
    assert list(cancel.headers.get_all("Route")) == ["<sip:ob1.example;lr>",
                                                     "<sip:ob2.example;lr>"]


# -- found by the independent review of SIP-OP-14 ------------------------------------


def test_legs_invited_before_an_establishment_fault_are_cancelled(core, world):
    """A fault part-way through a group call's legs: the initiator gets 500,
    and a leg already invited is CANCELled as soon as it rings -- not left
    ringing until the no-answer limit."""
    orig = core.adapter.render
    n = [0]

    def render(sig, ctx, req=None):
        if sig.type.name == "INVITE":
            n[0] += 1
            if n[0] == 2:
                raise RuntimeError("fault on the second leg")
        return orig(sig, ctx, req)
    core.adapter.render = render
    core.on_bytes(invite("ef1", U[0], "grp:alpha", "prearranged-group"), world[U[0]])
    assert world[U[0]].codes()[-1] == 500
    (req,) = world[U[1]].requests("INVITE")
    core.on_bytes(answer(req, 180, tag="r1"), world[U[1]])
    assert len(world[U[1]].requests("CANCEL")) == 1


def test_the_initiator_hanging_up_an_early_dialog_gets_its_invite_answered(core, rt,
                                                                           world, clock):
    """RFC 3261 15.1.2: a BYE on an early dialog; the pending INVITE MUST
    still be answered, with 487 recommended -- and its transaction ends."""
    core.on_bytes(invite("eb1", U[0], U[1], "private"), world[U[0]])
    req = _leg_invite(world)
    core.on_bytes(answer(req, 180, tag="r1"), world[U[1]])
    ringing = [r for r in _responses(world[U[0]], "INVITE") if r.code == 180][0]
    tag = ringing.headers.get("To").split("tag=")[1]
    core.on_bytes(msg("BYE", LOCAL, "eb1", 2, U[0], LOCAL, to_tag=tag), world[U[0]])
    assert [r.code for r in _responses(world[U[0]], "BYE")] == [200]
    assert [r.code for r in _responses(world[U[0]], "INVITE") if r.code >= 200] == [487]
    assert len(world[U[1]].requests("CANCEL")) == 1
    clock.now += 64 * 500
    core.tick()
    assert core.server.find("z9hG4bKeb11INVITE", "INVITE") is None


@pytest.mark.parametrize("change", [(b"core.example", b"evil.example"),
                                    (b"Call-ID: sb1", b"Call-ID: other")])
def test_a_cancel_must_match_more_than_the_branch(core, rt, world, change):
    """RFC 3261 9.2 -> 17.2.3: branch AND the top Via's sent-by; and the
    CANCEL's Call-ID is its INVITE's (9.1). Otherwise 481, call untouched."""
    core.on_bytes(invite("sb1", U[0], U[1], "private"), world[U[0]])
    req = _leg_invite(world)
    core.on_bytes(answer(req, 180, tag="r1"), world[U[1]])
    core.on_bytes(_cancel_from_initiator("sb1").replace(*change), world[U[2]])
    assert [r.code for r in _responses(world[U[2]], "CANCEL")] == [481]
    assert 487 not in world[U[0]].codes()
    assert world[U[1]].requests("CANCEL") == []


def test_a_cancelled_leg_that_rings_again_stays_out_of_the_call(core, rt, world, clock):
    reqs = _ringing_group_call(core, world, "cr1")
    clock.now += 64 * 500
    core.tick()                                     # u2 CANCELled, call goes on
    core.on_bytes(answer(reqs[U[2]], 180, tag="r2"), world[U[2]])
    leg = [l for l in core.calls["cr1"].legs.values() if l.uri == U[2]][0]
    assert leg.state == "failed" and len(world[U[2]].requests("CANCEL")) == 1
