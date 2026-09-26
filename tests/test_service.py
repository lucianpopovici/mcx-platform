"""TS-OAM, TS-DOC, TS-SIG-007 — the host process (CLAUDE-1-service.md).

Process-level cases start `python -m service` for real; the rest drive
`build_runtime` in-process with an injected clock.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.audit import RecordType  # noqa: E402
from core.errors import StartupRefused  # noqa: E402
from core.hooks import MediaKind, SessionRequest  # noqa: E402
from core.session import Platform, SignalType  # noqa: E402
from service import groups as groups_mod  # noqa: E402
from service.http import Server  # noqa: E402
from service.runtime import Health, build_runtime, fail_closed_platform  # noqa: E402
from tests.network_fixture import network_yaml  # noqa: E402

U = [f"sip:u{i}@mcptt.example" for i in range(4)]
GROUPS = [{"id": "grp:alpha", "display_name": "Alpha team", "members": U}]


class Clock:
    def __init__(self):
        self.now = 1_000

    def __call__(self):
        self.now += 1
        return self.now


@pytest.fixture
def env(tmp_path):
    return {"MCX_PROFILE": "mcx", "MCX_RELEASE": "19", "MCX_IDMS": "stub",
            "MCX_RECORDER": "none", "MCX_BEARER": "none", "MCX_STRICT_RELEASE": "false", "MCX_ADHOC_LIST_MAX": "100",
            "MCX_NETWORK_FILE": str(network_yaml(tmp_path, groups=GROUPS)),
            "MCX_DATA_DIR": str(tmp_path / "data"),
            "MCX_HTTP_PORT": "0"}


def with_network(env, fname, **kw):
    """`env` with a network profile of its own, beside the fixture's."""
    net = network_yaml(Path(env["MCX_NETWORK_FILE"]).parent, fname=fname, **kw)
    return {**env, "MCX_NETWORK_FILE": str(net)}


def permissive():
    return Platform()


def req(rid="s1", call_type="prearranged-group", target="grp:alpha"):
    return SessionRequest(request_id=rid, initiator=U[0], target=target,
                          call_type=call_type, media=(MediaKind.VOICE,))


def get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return r.status, r.read(), r.headers.get("Content-Type")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Content-Type")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def spawn(env, port):
    full = {**os.environ}
    for k in ("MCX_ENV", "MCX_PRODUCTION", "MCX_TEST_MODE"):
        full.pop(k, None)
    full.update(env)
    full["MCX_HTTP_PORT"] = str(port)
    return subprocess.Popen([sys.executable, "-m", "service"], cwd=ROOT, env=full,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def wait_ready(port, proc, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            raise AssertionError(f"exited early: {proc.stderr.read().decode()}")
        try:
            if get(port, "/readyz")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError("never became ready")


def stop(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=10)
    proc.stdout.close()
    proc.stderr.close()


# -- startup refusals (PLT-GEN-003, PLT-IDM-007) ------------------------------


@pytest.mark.parametrize("change", [
    {"MCX_PROFILE": ""},                       # none
    {"MCX_PROFILE": "nosuchprofile"},          # unknown
    {"MCX_PROFILE": "mcx,frmcs"},              # two
    {"MCX_IDMS": ""},                          # no identity provider named
    {"MCX_RELEASE": ""},                       # PLT-REL-002: no release named
    {"MCX_RELEASE": "21"},                     # unpublished release
    {"MCX_RELEASE": "seventeen"},              # not a release at all
])
def test_process_refuses_and_exits_nonzero(env, change):
    proc = spawn({**env, **change}, free_port())
    try:
        assert proc.wait(timeout=15) == 2
        assert b"startup refused" in proc.stderr.read()
    finally:
        proc.stdout.close(); proc.stderr.close()


def test_vp1_sig_007_stub_idms_refused_under_production_indicator(env):
    for indicator in ({"MCX_ENV": "production"}, {"MCX_PRODUCTION": "1"}):
        with pytest.raises(StartupRefused, match="stub identity provider"):
            build_runtime({**env, **indicator}, Clock())
    # ... and the refusal happened before anything durable was opened.
    assert not Path(env["MCX_DATA_DIR"]).exists()
    # Same environment without the indicator starts.
    build_runtime(env, Clock()).close()


def test_vp1_sig_007_process_exits_nonzero(env):
    proc = spawn({**env, "MCX_ENV": "production"}, free_port())
    try:
        assert proc.wait(timeout=15) == 2
        assert b"PLT-IDM-007" in proc.stderr.read()
    finally:
        proc.stdout.close(); proc.stderr.close()


def test_no_default_for_data_dir_or_idms(env):
    for key in ("MCX_DATA_DIR", "MCX_IDMS"):
        bad = {k: v for k, v in env.items() if k != key}
        with pytest.raises(StartupRefused):
            build_runtime(bad, Clock())


def test_group_member_outside_declared_domain_refuses_start(env, tmp_path):
    e = with_network(env, "elsewhere.yaml", groups=[
        {"id": "grp:x", "members": ["sip:a@elsewhere.example"]}])
    with pytest.raises(Exception, match="declared domains"):
        build_runtime(e, Clock())


# -- VP1-OAM-002: health and readiness ----------------------------------------


def test_vp1_oam_002_health_reports_identity_and_process_starts(env):
    port = free_port()
    proc = spawn(env, port)
    try:
        wait_ready(port, proc)
        status, body, _ = get(port, "/healthz")
        h = json.loads(body)
        assert status == 200 and h["ready"] is True
        p = h["profile"]
        assert p["name"] == "mcx" and p["version"] and len(p["hash"]) == 64
        assert p["identifier"] == f"mcx/{p['version']}/{p['hash'][:16]}"
        assert get(port, "/livez")[0] == 200
    finally:
        stop(proc)


def test_vp1_oam_002_startup_logs_triple_as_json(env):
    port = free_port()
    proc = spawn(env, port)
    try:
        wait_ready(port, proc)
        ident = json.loads(get(port, "/healthz")[1])["profile"]["identifier"]
        proc.send_signal(signal.SIGTERM)
        err = proc.stderr.read().decode()
        proc.wait(timeout=10)
    finally:
        proc.stdout.close(); proc.stderr.close()
    lines = [json.loads(l) for l in err.splitlines() if l.strip()]
    loaded = [l for l in lines if l["message"].startswith("profile loaded: ")
              and l["logger"] == "mcx.service"]
    assert len(loaded) == 1 and ident in loaded[0]["message"]


def test_vp1_oam_002_not_ready_until_profile_loaded_and_marked_ready(env):
    rt = build_runtime(env, Clock())
    try:
        assert rt.health.ready is False          # loaded, but not yet serving
        srv = Server(rt, "127.0.0.1", 0)
        import threading
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            assert get(srv.bound_port, "/readyz")[0] == 503
            assert get(srv.bound_port, "/docs/groups")[0] == 503
            body = json.loads(get(srv.bound_port, "/healthz")[1])
            assert body["ready"] is False and body["profile"]["name"] == "mcx"
            rt.health.set_ready(True)
            assert get(srv.bound_port, "/readyz")[0] == 200
        finally:
            srv.shutdown(); srv.server_close()
    finally:
        rt.close()


def test_vp1_oam_002_health_with_no_profile_is_never_ready():
    h = Health()
    h.set_ready(True)
    assert h.ready is False and h.snapshot()["profile"]["hash"] is None


def test_socket_not_bound_when_startup_refuses(env):
    port = free_port()
    proc = spawn({**env, "MCX_PROFILE": "nosuchprofile"}, port)
    try:
        proc.wait(timeout=15)
    finally:
        proc.stdout.close(); proc.stderr.close()
    with pytest.raises(OSError):
        get(port, "/livez")


# -- VP1-OAM-003: lifecycle audited, durably ------------------------------------


def test_vp1_oam_003_admission_refusal_establishment_release_audited(env):
    rt = build_runtime(env, Clock(), platform=permissive())
    try:
        session, signals, refusal = rt.establish(req("ok"))
        assert session is not None and refusal is None
        _, _, refused = rt.establish(req("bad", target="grp:nobody"))
        assert refused is not None
        rt.release("ok")

        ok = [r["type"] for r in rt.store.audit_records("ok")]
        assert "session-admitted" in ok and "session-established" in ok
        assert ok[-1] == "session-released"
        bad = rt.store.audit_records("bad")
        failed = [r for r in bad if r["type"] in ("session-refused", "session-failed")]
        assert failed and failed[0]["detail"]["reason_code"] == refused.reason_code
        # PLT-OAM-001 + PLT-REL-005: the record names the profile AND the
        # release. Either alone leaves an unanswerable question months later
        # -- the same profile at two releases does not put the same bytes on
        # the wire. NET-OP-01 adds the network profile: which cells meant
        # which location, and which cores could assert any identity.
        ident = (f"{rt.loaded.profile.identifier()}+Rel-19"
                 f"+test-net/1/{rt.network.content_hash[:16]}")
        assert all(r["profile"] == ident for r in rt.store.audit_records())
        assert rt.loaded.profile.identifier() in ident and "Rel-19" in ident
    finally:
        rt.close()


def test_default_process_platform_fails_closed_on_recording(env):
    rt = build_runtime(env, Clock())     # no platform injected: the real default
    try:
        _, _, refusal = rt.establish(req())      # prearranged-group records
        assert refusal is not None and refusal.reason_code == "recording-unavailable"
        assert rt.store.audit_records(req().request_id)[-1]["type"] == "session-refused"
    finally:
        rt.close()


def test_fail_closed_platform_is_not_the_permissive_default():
    p = fail_closed_platform()
    assert p.recording_available() is False
    assert p.reserve_qos(None) is False


def test_signals_are_handed_to_the_consumer_seam(env):
    rt = build_runtime(env, Clock(), platform=permissive())
    seen = []
    rt.on_signals = lambda s, sigs: seen.append((s.correlation_id, len(sigs)))
    try:
        rt.establish(req("a"))
        rt.release("a")
        assert [c for c, _ in seen] == ["a", "a"]
    finally:
        rt.close()


# -- VP1-OAM-005: restart without loss ------------------------------------------

CRASH = """
import os, signal, sys
sys.path.insert(0, %r)
from service.runtime import build_runtime
from core.session import Platform
from core.hooks import SessionRequest, MediaKind
t = [0]
def clock():
    t[0] += 1
    return t[0]
rt = build_runtime(dict(os.environ), clock, platform=Platform())
for i in range(3):
    s, _, r = rt.establish(SessionRequest(request_id="c%%d" %% i,
        initiator=%r, target="grp:alpha", call_type="prearranged-group",
        media=(MediaKind.VOICE,)))
    assert s is not None, r
rt.release("c2")
os.kill(os.getpid(), signal.SIGKILL)      # no close(), no flush, no atexit
"""


def test_vp1_oam_005_committed_records_survive_kill_and_service_returns(env):
    child = subprocess.run([sys.executable, "-c", CRASH % (str(ROOT), U[0])],
                           env={**os.environ, **env}, capture_output=True)
    assert child.returncode == -signal.SIGKILL, child.stderr.decode()

    rt = build_runtime(env, Clock())
    try:
        by_id = {s["correlation_id"]: s for s in rt.store.sessions()}
        assert set(by_id) == {"c0", "c1", "c2"}
        assert by_id["c0"]["state"] == "established"
        assert by_id["c2"]["state"] == "released"
        assert by_id["c0"]["members"] == U
        types = [r["type"] for r in rt.store.audit_records("c2")]
        assert types[-1] == "session-released"
        assert rt.recovered == 2
    finally:
        rt.close()

    # and the real process comes back into service over the same store
    port = free_port()
    proc = spawn(env, port)
    try:
        wait_ready(port, proc)
        assert get(port, "/readyz")[0] == 200
    finally:
        stop(proc)


# -- VP1-DOC-001 / PLT-GRP-001 --------------------------------------------------


def test_vp1_doc_001_group_document_matches_configuration(env):
    rt = build_runtime(env, Clock())
    rt.health.set_ready(True)
    srv = Server(rt, "127.0.0.1", 0)
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body, ctype = get(srv.bound_port, "/docs/groups")
        assert status == 200 and json.loads(body)["groups"] == ["grp:alpha"]
        status, body, ctype = get(srv.bound_port, "/docs/groups/grp%3Aalpha")
        assert status == 200 and ctype == groups_mod.MEDIA_TYPE
        # TS 24.481 clause 7.2.2: <group> is the root, <list-service> is
        # beneath it, and both are in the OMA list-service namespace. This
        # used to expect <list-service> as the root in the resource-lists
        # namespace, which is what the renderer wrongly emitted (CA-04).
        ns = "{urn:oma:xml:poc:list-service}"
        root = ET.fromstring(body)
        assert root.tag == ns + "group"
        service = root.find(ns + "list-service")
        assert service is not None and service.get("uri") == "grp:alpha"
        assert [e.get("uri") for e in service.iter(ns + "entry")] == U
        groups_mod.check_rendered(rt.groups.get("grp:alpha"), body)
        assert get(srv.bound_port, "/docs/groups/grp%3Anone")[0] == 404
        # served from the same source the resolver was provisioned from
        res = rt.loaded.hooks.identity_resolver.resolve("grp:alpha", req())
        assert list(res.members) == U
    finally:
        srv.shutdown(); srv.server_close(); rt.close()


def test_vp1_doc_001_group_document_over_real_process(env):
    port = free_port()
    proc = spawn(env, port)
    try:
        wait_ready(port, proc)
        status, body, _ = get(port, "/docs/groups/grp:alpha")
        assert status == 200 and b"sip:u3@mcptt.example" in body
    finally:
        stop(proc)


def test_check_rendered_detects_mismatch():
    g = groups_mod.Group("grp:a", "A", ("sip:a@x", "sip:b@x"))
    doc = groups_mod.render(g)
    groups_mod.check_rendered(g, doc)
    with pytest.raises(AssertionError):
        groups_mod.check_rendered(groups_mod.Group("grp:a", "A", ("sip:a@x",)), doc)


def test_a_malformed_group_refuses_start(env):
    e = with_network(env, "bad-group.yaml", groups=[{"id": "g", "members": []}])
    with pytest.raises(StartupRefused, match="members"):
        build_runtime(e, Clock())


# -- PLT-CONF-AUDIT CA-04 ------------------------------------------------------


def test_group_document_is_an_mcptt_group_document():
    """TS 24.481 clause 7.2.8 lists five conditions, all of which must hold
    before a conformant group management server treats this as an MCPTT group
    document. The renderer used to satisfy none of them: <supported-services>
    was absent entirely.

    Each assertion below is one of the five conditions, checked separately so
    that dropping any one of them turns a test red on its own.
    """
    from xml.etree import ElementTree as ET
    from service.groups import Group, render

    # Namespaces and the ICSI are spelled out rather than imported. Importing
    # them would let a wrong value pass: the renderer and the assertion would
    # move together, which is the circular validation PLT-CONF-AUDIT 2 is
    # about. Every literal below is quoted from TS 24.481 V17.8.0.
    group = Group("sip:alpha@mcptt.example", "Alpha", ("sip:u1@mcptt.example",))
    root = ET.fromstring(render(group))
    oxe = "{urn:oma:xml:xdm:extensions}"
    gi = "{urn:3gpp:ns:mcpttGroupInfo:1.0}"

    supported = root.find(".//" + oxe + "supported-services")
    assert supported is not None                                   # a)
    service = supported.find(oxe + "service")
    assert service is not None                                     # b)
    assert service.get("enabler") == \
        "urn:urn-7:3gpp-service.ims.icsi.mcptt"                    # c)
    media = service.find(oxe + "group-media")
    assert media is not None                                       # d)
    assert media.find(gi + "mcptt-speech") is not None             # e)


def test_group_document_media_type_is_the_oma_group_type():
    """TS 24.481 clause 7.2.6 defers to OMA XDM Group, and the XCAP PUT in the
    clause A.2 example carries the type on the wire. It is not
    application/xml, which is what this declared before CA-04."""
    from service.groups import MEDIA_TYPE
    assert MEDIA_TYPE == "application/vnd.oma.poc.groups+xml"


def test_group_document_root_is_group_in_the_oma_namespace():
    """The root element and its namespace were both wrong. Pinned separately
    from the structure test because they fail independently: a document with
    the right children under the wrong root is still rejected."""
    from xml.etree import ElementTree as ET
    from service.groups import Group, render

    root = ET.fromstring(render(Group("sip:a@x", "A", ("sip:u@x",))))
    assert root.tag == "{urn:oma:xml:poc:list-service}group"


# -- MCX_RECORDER (VP1-SIG-001, found against Kamailio) -----------------------

def _clock():
    n = [0]

    def tick():
        n[0] += 1
        return n[0]
    return tick


def test_a_process_built_from_environment_alone_can_establish_a_call(env):
    """The test whose absence let the process ship unable to serve.

    Every end-to-end test in this repository injects `platform=Platform()`,
    the permissive one. None of them built the platform the process builds for
    itself, so none of them noticed that `fail_closed_platform()` reported
    recording unavailable with no way to say otherwise, while every call type
    in every in-tree profile sets `recording_required: true`. The shipped
    process answered every INVITE with 503 "recording unavailable".

    It was found by running VP1-SIG-001 against Kamailio 5.7.4 — not by any
    test here, and not by reading the code.

    No `platform=` argument below, deliberately. That is the entire point.
    """
    env["MCX_RECORDER"] = "stub"
    env["MCX_BEARER"] = "stub"
    rt = build_runtime(env, _clock())
    session, signals, refusal = rt.establish(req())
    assert refusal is None, f"a process configured with a recorder refused: {refusal}"
    assert session is not None
    assert [s.target for s in signals if s.type is SignalType.INVITE] == [U[1], U[2], U[3]]


def test_the_default_process_still_refuses_a_call_that_must_be_recorded(env):
    """The fail-closed behaviour is the point of MCX_RECORDER=none, and stays.

    PLT-OAM-008: a session that must be recorded is not established when it
    cannot be. What was wrong was never this refusal, it was that no
    configuration could lift it.
    """
    env["MCX_RECORDER"] = "none"
    rt = build_runtime(env, _clock())
    session, _, refusal = rt.establish(req())
    assert session is None
    assert refusal is not None and refusal.reason_code == "recording-unavailable"


@pytest.mark.parametrize("var, bogus", [("MCX_RECORDER", "magnetic-tape"),
                                        ("MCX_BEARER", "hope")])
def test_each_platform_capability_must_be_named_explicitly(env, var, bogus):
    """Like MCX_IDMS, and for the same reason: a default here is a deployment
    silently getting a capability claim nobody made. Both of these were
    previously hard-coded to False with no way to state otherwise, which is
    the defect, and a default of True would have been a worse one."""
    without = {k: v for k, v in env.items() if k != var}
    with pytest.raises(StartupRefused) as exc:
        build_runtime(without, _clock())
    assert var in str(exc.value)

    with pytest.raises(StartupRefused) as exc:
        build_runtime({**env, var: bogus}, _clock())
    assert bogus in str(exc.value)


def test_a_production_indicator_refuses_every_stub(env):
    """Each stub claims a capability nothing provides, and a production system
    must make none of those claims.

    Note what this test cannot yet isolate: R1 has exactly one known identity
    provider and it is the stub, so a production indicator is refused at the
    IdMS check before the recorder or bearer check is reached. The two rules
    below are therefore unreachable in R1 and are here to be reached in R2,
    when a real IdMS exists (recorded as SVC-OP-05).
    """
    for indicator in ({"MCX_ENV": "production"}, {"MCX_PRODUCTION": "true"}):
        for stubbed in ({"MCX_RECORDER": "stub"}, {"MCX_BEARER": "stub"}, {}):
            with pytest.raises(StartupRefused):
                build_runtime({**env, **stubbed, **indicator}, _clock())

    from service.runtime import fail_closed_platform
    assert fail_closed_platform().recording_available() is False
    assert fail_closed_platform().reserve_qos(None) is False
    assert fail_closed_platform(True, True).recording_available() is True
    assert fail_closed_platform(True, True).reserve_qos(None) is True


def test_health_says_which_call_types_no_client_can_request(env):
    """PLT-ICD-001 2.6. Declared-unrequestable and release-unreachable call
    types are reported, so the gap is visible before the first refusal."""
    rt = build_runtime({**env, "MCX_RELEASE": "17"}, _clock())
    report = rt.health.snapshot()["call_types"]
    assert set(report) == {"strict_release", "not_requestable_by_mcptt_clients",
                           "unreachable_at_release"}
    assert report["strict_release"] is False
    assert "sds" in report["not_requestable_by_mcptt_clients"]
    assert report["unreachable_at_release"] == {}      # mcx declares no ad hoc call type



# -- MCX_STRICT_RELEASE (REL-OP-02, decided 2026-09-24) -------------------------

def _frmcs(env, release, strict):
    """The railway profile, whose group calls are ad hoc and so exist in
    TS 24.379 only from Rel-18. No groups: the fixture's members are mcx users."""
    e = with_network(env, "frmcs-net.yaml")
    e.update({"MCX_PROFILE": "frmcs", "MCX_RELEASE": release,
              "MCX_STRICT_RELEASE": strict})
    return e


def test_strict_release_refuses_a_release_that_cannot_carry_the_profile(env):
    """true: the railway profile at Rel-17 does not start, and the refusal
    names the call types and the reason."""
    with pytest.raises(StartupRefused) as exc:
        build_runtime(_frmcs(env, "17", "true"), _clock())
    text = str(exc.value)
    assert "MCX_STRICT_RELEASE=true" in text
    assert "rec-broadcast" in text and "shunting-group" in text
    assert "adhoc" in text


def test_non_strict_release_starts_and_reports_what_it_cannot_carry(env, caplog):
    """false: the same deployment starts, logs a warning per call type, and
    the health document says which ones and that strictness is off."""
    with caplog.at_level("WARNING", logger="mcx.service"):
        rt = build_runtime(_frmcs(env, "17", "false"), _clock())
    report = rt.health.snapshot()["call_types"]
    assert report["strict_release"] is False
    assert set(report["unreachable_at_release"]) == {"rec-broadcast", "shunting-group"}
    warned = [r.getMessage() for r in caplog.records if "cannot be requested" in r.getMessage()]
    assert len(warned) == 2 and all("MCX_STRICT_RELEASE=false" in w for w in warned)


@pytest.mark.parametrize("release", ["19", "20"])
def test_strict_release_starts_where_every_call_type_is_carried(env, release):
    rt = build_runtime(_frmcs(env, release, "true"), _clock())
    report = rt.health.snapshot()["call_types"]
    assert report["strict_release"] is True and report["unreachable_at_release"] == {}


@pytest.mark.parametrize("value", [None, "", "yes", "1", "TRUE-ish"])
def test_strict_release_must_be_stated_as_true_or_false(env, value):
    """Required with no default, like MCX_RELEASE: a silent false would let
    a deployment accept unreachable emergency calls nobody chose to accept."""
    e = {k: v for k, v in env.items() if k != "MCX_STRICT_RELEASE"}
    if value is not None:
        e["MCX_STRICT_RELEASE"] = value
    with pytest.raises(StartupRefused) as exc:
        build_runtime(e, _clock())
    assert "MCX_STRICT_RELEASE" in str(exc.value)


def test_strict_release_values_are_case_insensitive(env):
    for value in ("TRUE", "False"):
        build_runtime({**env, "MCX_STRICT_RELEASE": value}, _clock())


# -- MCX_ADHOC_LIST_MAX (ADHOC-OP-04, decided 2026-09-25) ----------------------

@pytest.mark.parametrize("value", [None, "", "  ", "0", "-3", "1.5", "ten", "+5"])
def test_the_ad_hoc_list_cap_must_be_stated_as_a_positive_integer(env, value):
    """Required with no default: an unbounded list is unbounded work done
    before any participant is resolved."""
    e = {k: v for k, v in env.items() if k != "MCX_ADHOC_LIST_MAX"}
    if value is not None:
        e["MCX_ADHOC_LIST_MAX"] = value
    with pytest.raises(StartupRefused) as exc:
        build_runtime(e, _clock())
    assert "MCX_ADHOC_LIST_MAX" in str(exc.value)


@pytest.mark.parametrize("value", ["1", "250", " 7 "])
def test_the_stated_ad_hoc_list_cap_reaches_the_session_layer(env, value):
    rt = build_runtime({**env, "MCX_ADHOC_LIST_MAX": value}, _clock())
    assert rt.config.adhoc_list_max == int(value)
    assert rt.manager._adhoc_list_max == int(value)
