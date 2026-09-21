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
from core.session import Platform  # noqa: E402
from service import groups as groups_mod  # noqa: E402
from service.http import Server  # noqa: E402
from service.runtime import Health, build_runtime, fail_closed_platform  # noqa: E402

U = [f"sip:u{i}@mcptt.example" for i in range(4)]
GROUPS_YAML = f"""
groups:
  - id: "grp:alpha"
    display_name: "Alpha team"
    members: {json.dumps(U)}
"""


class Clock:
    def __init__(self):
        self.now = 1_000

    def __call__(self):
        self.now += 1
        return self.now


@pytest.fixture
def env(tmp_path):
    g = tmp_path / "groups.yaml"
    g.write_text(GROUPS_YAML)
    return {"MCX_PROFILE": "mcx", "MCX_IDMS": "stub",
            "MCX_DATA_DIR": str(tmp_path / "data"), "MCX_GROUPS_FILE": str(g),
            "MCX_HTTP_PORT": "0"}


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
    Path(env["MCX_GROUPS_FILE"]).write_text(
        'groups:\n  - {id: "grp:x", members: ["sip:a@elsewhere.example"]}\n')
    with pytest.raises(Exception, match="declared domains"):
        build_runtime(env, Clock())


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
        ident = rt.loaded.profile.identifier()
        assert all(r["profile"] == ident for r in rt.store.audit_records())
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
        ns = "{urn:ietf:params:xml:ns:resource-lists}"
        root = ET.fromstring(body)
        assert root.get("uri") == "grp:alpha"
        assert [e.get("uri") for e in root.iter(ns + "entry")] == U
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


def test_malformed_groups_file_refuses_start(env):
    Path(env["MCX_GROUPS_FILE"]).write_text("groups:\n  - {id: g, members: []}\n")
    with pytest.raises(StartupRefused, match="members"):
        build_runtime(env, Clock())
