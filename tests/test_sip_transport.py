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
from service.sip_core import SipCore  # noqa: E402
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
    env = {"MCX_PROFILE": "mcx", "MCX_IDMS": "stub",
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


def mc_body(call_type, target=None):
    t = f"<mcptt-target>{target}</mcptt-target>" if target else ""
    return SDP + f"<mcptt-call_type>{call_type}</mcptt-call_type>{t}"


def invite(call_id, frm, to, call_type, **kw):
    return msg("INVITE", to, call_id, 1, frm, to, body=mc_body(call_type),
               ctype="multipart/mixed;boundary=b", **kw)


def answer(req: Request, code=200, body="", tag="callee"):
    """A callee's response to an INVITE the core sent it."""
    lines = [f"SIP/2.0 {code} X"]
    for v in req.headers.get_all("Via"):
        lines.append(f"Via: {v}")
    lines.append(f"From: {req.headers.get('From')}")
    lines.append(f"To: {req.headers.get('To')};tag={tag}")
    lines.append(f"Call-ID: {req.headers.get('Call-ID')}")
    lines.append(f"CSeq: {req.headers.get('CSeq')}")
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
    assert f"P-Asserted-Identity: <{U[0]}>" in wire


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
    core.on_bytes(msg("BYE", LOCAL, leg, 2, U[1], U[0]), world[U[1]])
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
