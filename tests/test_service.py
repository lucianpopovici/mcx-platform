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
            "MCX_HTTP_PORT": "0", "MCX_HTTP_TLS": "off",
            "MCX_FLOOR_UNRECORDED": "deny", "MCX_FOREIGN_INITIATOR": "refuse",
            "MCX_ENV": "test"}


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
@pytest.mark.vp("VP1-REL-001")
def test_process_refuses_and_exits_nonzero(env, change):
    proc = spawn({**env, **change}, free_port())
    try:
        assert proc.wait(timeout=15) == 2
        assert b"startup refused" in proc.stderr.read()
    finally:
        proc.stdout.close(); proc.stderr.close()


def _refusal(env, port):
    """Run the process; return its exit status, the messages it logged, and
    whether anything ever listened on `port`."""
    proc = spawn(env, port)
    try:
        status = proc.wait(timeout=15)
        lines = [json.loads(l)["message"] for l in proc.stderr.read().decode().splitlines()
                 if l.startswith("{")]
    finally:
        proc.stdout.close(); proc.stderr.close()
    with socket.socket() as s:
        listened = s.connect_ex(("127.0.0.1", port)) == 0
    return status, lines, listened


@pytest.mark.vp("VP1-BND-007")
@pytest.mark.parametrize("value", [None, "", "  ", " , "])
def test_no_profile_stated_no_process(env, value):
    """PLT-GEN-004: nothing supplies a profile the deployment did not state."""
    env = dict(env)
    env.pop("MCX_PROFILE")
    if value is not None:
        env["MCX_PROFILE"] = value
    status, messages, listened = _refusal(env, free_port())
    assert status == 2 and not listened
    assert messages == ["startup refused: no profile configured: exactly one profile must "
                        "be named at deployment; the platform provides no default"]


@pytest.mark.vp("VP1-BND-007")
def test_a_profiles_root_holding_one_profile_still_needs_it_named(env, tmp_path):
    """As a packaged image: the root holds one profile, and the process
    still refuses to start until the deployment names it."""
    import shutil
    root = tmp_path / "profiles"
    root.mkdir()
    for name in ("mcx", "common"):
        shutil.copytree(ROOT / "profiles" / name, root / name,
                        ignore=shutil.ignore_patterns("__pycache__"))
    env = {k: v for k, v in env.items() if k != "MCX_PROFILE"}
    status, messages, listened = _refusal({**env, "MCX_PROFILES_ROOT": str(root)},
                                          free_port())
    assert status == 2 and not listened
    assert messages == ["startup refused: no profile configured: exactly one profile must "
                        "be named at deployment; the platform provides no default"]


@pytest.mark.vp("VP1-BND-023")
@pytest.mark.parametrize("value", [None, "", "  "])
def test_no_release_stated_no_process(env, value):
    """PLT-REL-002: nothing supplies a release the deployment did not state."""
    env = dict(env)
    env.pop("MCX_RELEASE")
    if value is not None:
        env["MCX_RELEASE"] = value
    status, messages, listened = _refusal(env, free_port())
    assert status == 2 and not listened
    assert messages == [
        "startup refused: MCX_RELEASE is not set: state the 3GPP release this deployment "
        "speaks (PLT-REL-002); there is no default. A guessed release is silent -- subtype "
        "14 is a valid floor control message in Rel-17 and in Rel-18 and means a different "
        "one in each"]


@pytest.mark.vp("VP1-BND-008")
def test_the_profile_is_read_once_at_start(env, tmp_path):
    """PLT-PRF-010: a profile changed on disk under a running process is not
    picked up; the process keeps the one it loaded."""
    import shutil
    root = tmp_path / "profiles"
    shutil.copytree(ROOT / "profiles", root, ignore=shutil.ignore_patterns("__pycache__"))
    port = free_port()
    proc = spawn({**env, "MCX_PROFILES_ROOT": str(root)}, port)
    try:
        wait_ready(port, proc)
        before = json.loads(get(port, "/healthz")[1])["profile"]
        yaml_path = root / "mcx" / "profile.yaml"
        text = yaml_path.read_text(encoding="utf-8")
        assert text.count(f"version: {before['version']}") == 1
        yaml_path.write_text(text.replace(f"version: {before['version']}",
                                          "version: 9.9.9"), encoding="utf-8")
        os.utime(yaml_path, (time.time() + 60, time.time() + 60))
        time.sleep(1.5)
        after = json.loads(get(port, "/healthz")[1])["profile"]
        assert after == before and after["version"] != "9.9.9"
        assert proc.poll() is None
    finally:
        stop(proc)


# VP-OP-05 (decided 2026-10-21): production is the network profile's
# environment, which MCX_ENV, and MCX_PRODUCTION when set, must agree with.
_PRODUCTION_FORMS = [{"MCX_ENV": "production"},
                     *({"MCX_ENV": "production", "MCX_PRODUCTION": v}
                       for v in ("1", "true", "yes"))]


def _ids(e):
    return "+".join(f"{k}={v}" for k, v in e.items())


def in_production(env, indicator):
    """`env` on a production network (the test PLMN may run as production),
    with the indicator's variables."""
    return {**with_network(env, "production.yaml", groups=GROUPS,
                           environment="production"), **indicator}


@pytest.mark.vp("VP1-SIG-007")
@pytest.mark.parametrize("indicator", _PRODUCTION_FORMS, ids=_ids)
def test_vp1_sig_007_stub_idms_refused_under_production_indicator(env, indicator):
    with pytest.raises(StartupRefused) as exc:
        build_runtime(in_production(env, indicator), Clock())
    assert str(exc.value) == ("the stub identity provider is refused when a production "
                              "indicator is set (PLT-IDM-007)")
    # ... and the refusal happened before anything durable was opened.
    assert not Path(env["MCX_DATA_DIR"]).exists()


@pytest.mark.vp("VP1-SIG-007")
@pytest.mark.parametrize("environment", ["staging", "test", "dev"])
def test_vp1_sig_007_the_same_deployment_starts_outside_production(env, environment):
    """The control: the same deployment, with the stub, in each environment
    that is not production, starts; so the refusal turns on the indicator."""
    e = {**with_network(env, f"{environment}.yaml", groups=GROUPS,
                        environment=environment), "MCX_ENV": environment}
    rt = build_runtime(e, Clock())
    try:
        assert rt.health.snapshot()["environment"] == environment
    finally:
        rt.close()


@pytest.mark.vp("VP1-SIG-007")
@pytest.mark.parametrize("file_env,variables,says", [
    ("production", {"MCX_ENV": "test"},
     "MCX_ENV='test' disagrees with the network profile's environment 'production'"),
    ("test", {"MCX_ENV": "production"},
     "MCX_ENV='production' disagrees with the network profile's environment 'test'"),
    ("production", {"MCX_ENV": "production", "MCX_PRODUCTION": "0"},
     "MCX_PRODUCTION='0' disagrees with MCX_ENV='production'"),
    ("test", {}, "MCX_ENV is not set"),
], ids=["variable-says-test", "variable-says-production", "flag-disagrees", "unset"])
def test_vp1_sig_007_the_variable_cannot_switch_the_file(env, file_env, variables, says):
    """Changing a variable alone switches nothing: it must say what the
    network profile says, or the process does not start."""
    e = {k: v for k, v in env.items() if k not in ("MCX_ENV", "MCX_PRODUCTION")}
    e = {**with_network(e, f"{file_env}-x.yaml", groups=GROUPS, environment=file_env),
         **variables}
    with pytest.raises(StartupRefused) as exc:
        build_runtime(e, Clock())
    assert says in str(exc.value)
    assert not Path(env["MCX_DATA_DIR"]).exists()


@pytest.mark.vp("VP1-SIG-007")
@pytest.mark.parametrize("indicator", _PRODUCTION_FORMS, ids=_ids)
def test_vp1_sig_007_process_exits_nonzero(env, indicator):
    proc = spawn(in_production(env, indicator), free_port())
    try:
        assert proc.wait(timeout=15) == 2
        assert b"the stub identity provider is refused when a production indicator " \
               b"is set (PLT-IDM-007)" in proc.stderr.read()
        assert not Path(env["MCX_DATA_DIR"]).exists()
    finally:
        proc.stdout.close(); proc.stderr.close()


@pytest.mark.vp("VP1-LOAD-005")
@pytest.mark.parametrize("file_env,plmns,variable,says", [
    ("production", ("001010",), "production",
     "test mode requested while a production indicator is set (MCX_ENV=production); "
     "multi-profile loading is refused"),
    ("production", ("001010",), "test",
     "MCX_ENV='test' disagrees with the network profile's environment 'production'"),
    ("test", ("262010",), "test",
     "environment: test, but plmns 262010 are not test PLMNs"),
], ids=["production-file", "variable-says-test", "test-on-an-operational-network"])
def test_vp1_load_005_test_mode_against_the_network_profile(env, file_env, plmns, variable,
                                                             says):
    """End to end: two profiles in test mode, the process started, and the
    network profile deciding (review of VP-OP-05, finding 2)."""
    e = {**with_network(env, f"tm-{file_env}-{variable}.yaml", groups=GROUPS,
                        environment=file_env, plmns=plmns),
         "MCX_PROFILE": "mcx,frmcs", "MCX_TEST_MODE": "1", "MCX_ENV": variable}
    proc = spawn(e, free_port())
    try:
        assert proc.wait(timeout=15) == 2
        assert says.encode() in proc.stderr.read()
        assert not Path(env["MCX_DATA_DIR"]).exists()
    finally:
        proc.stdout.close(); proc.stderr.close()


@pytest.mark.vp("VP1-LOAD-005")
def test_vp1_load_005_test_mode_starts_on_a_test_network(env):
    """The control: the same two profiles and test mode, on a test network
    that says test, start."""
    e = {**env, "MCX_PROFILE": "mcx,frmcs", "MCX_TEST_MODE": "1"}
    port = free_port()
    proc = spawn(e, port)
    try:
        wait_ready(port, proc)
        health = json.loads(get(port, "/healthz")[1])
        assert (health["environment"], health["network"]["environment"]) == ("test", "test")
    finally:
        stop(proc)


@pytest.mark.vp("VP1-SIG-007")
def test_vp1_sig_007_a_process_without_mcx_env_exits_nonzero(env):
    """A forgotten MCX_ENV does not run the stub: it does not run at all."""
    proc = spawn({k: v for k, v in env.items() if k != "MCX_ENV"}, free_port())
    try:
        assert proc.wait(timeout=15) == 2
        assert b"MCX_ENV is not set" in proc.stderr.read()
        assert not Path(env["MCX_DATA_DIR"]).exists()
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
                 f"+test-net/1/{rt.network.content_hash[:16]}+test")
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
# What was committed, per session, as the killed process last saw it.
print({c: len(rt.store.audit_records(c)) for c in ("c0", "c1", "c2")}, flush=True)
os.kill(os.getpid(), signal.SIGKILL)      # no close(), no flush, no atexit
"""


def test_vp1_oam_005_committed_records_survive_kill_and_service_returns(env):
    child = subprocess.run([sys.executable, "-c", CRASH % (str(ROOT), U[0])],
                           env={**os.environ, **env}, capture_output=True)
    assert child.returncode == -signal.SIGKILL, child.stderr.decode()
    import ast
    before = ast.literal_eval(child.stdout.decode().strip().splitlines()[-1])

    rt = build_runtime(env, Clock())
    try:
        by_id = {s["correlation_id"]: s for s in rt.store.sessions()}
        # No committed record lost: each trail is what the killed process
        # committed, plus one release record for each session it cut off.
        assert {c: len(rt.store.audit_records(c)) for c in before} == {
            "c0": before["c0"] + 1, "c1": before["c1"] + 1, "c2": before["c2"]}
        assert set(by_id) == {"c0", "c1", "c2"}
        assert by_id["c0"]["members"] == U and by_id["c1"]["members"] == U
        types = [r["type"] for r in rt.store.audit_records("c2")]
        assert types[-1] == "session-released"
        # SVC-OP-02 (decided 2026-10-26, option 1): the two the killed process
        # left established are released at this start, before anything is
        # served, each audit trail ending in its own release record; the one
        # released before the kill is untouched.
        assert rt.recovered == 2
        assert {c: by_id[c]["state"] for c in by_id} == {
            "c0": "released", "c1": "released", "c2": "released"}
        assert by_id["c0"]["released_at_ms"] is not None
        for c in ("c0", "c1"):
            records = rt.store.audit_records(c)
            # Nothing the killed process committed is lost.
            assert {"session-admitted", "session-established"} <= {r["type"] for r in records}
            assert (records[-1]["type"], records[-1]["detail"]) == (
                "session-released", {"cause": "process-restart"})
        assert [r["detail"].get("cause") for r in rt.store.audit_records("c2")
                if r["type"] == "session-released"] == ["normal"]
        assert rt.health.snapshot()["sessions_released_at_start"] == 2
    finally:
        rt.close()
    rt = build_runtime(env, Clock(), platform=Platform())
    try:
        # A second start finds nothing left established, and calls are made.
        assert rt.recovered == 0
        assert rt.health.snapshot()["sessions_released_at_start"] == 0
        assert [r["type"] for r in rt.store.audit_records("c0")].count(
            "session-released") == 1
        session, _, refusal = rt.establish(SessionRequest(
            request_id="after", initiator=U[0], target="grp:alpha",
            call_type="prearranged-group", media=(MediaKind.VOICE,)))
        assert refusal is None and session is not None
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


def test_a_release_recorded_but_not_marked_is_not_released_again(env, monkeypatch):
    """Review of SVC-OP-02: a call ended normally whose row the store could
    not mark is only marked at the next start: its trail keeps the one
    release (normal), and it is not counted as cut off."""
    from service.store import SqliteStore
    rt = build_runtime(env, Clock(), platform=Platform())
    try:
        assert rt.establish(SessionRequest(
            request_id="n1", initiator=U[0], target="grp:alpha",
            call_type="prearranged-group", media=(MediaKind.VOICE,)))[0] is not None
        with monkeypatch.context() as m:
            m.setattr(SqliteStore, "mark_released",
                      lambda self, cid, at: (_ for _ in ()).throw(OSError("disk")))
            assert rt.release("n1")
        # A record of another kind after the release (a late floor or hook
        # record) does not make the release look missing.
        rt.auditor.emit(RecordType.HOOK_INVOCATION, "n1", interface="IF-PRI",
                        method="evaluate", elapsed_ms=0.0, outcome="ok",
                        budget_overrun=False)
    finally:
        rt.close()
    rt = build_runtime(env, Clock())
    try:
        assert rt.recovered == 1
        assert rt.health.snapshot()["sessions_released_at_start"] == 0
        assert [s["state"] for s in rt.store.sessions()] == ["released"]
        assert [r["detail"].get("cause") for r in rt.store.audit_records("n1")
                if r["type"] == "session-released"] == ["normal"]
    finally:
        rt.close()


def test_a_start_stopped_between_record_and_row_is_finished_once(env, monkeypatch):
    """Review of SVC-OP-02: a start that wrote the release record but could
    not mark the row refuses; the next start marks it, without a second
    record."""
    from service.store import SqliteStore
    rt = build_runtime(env, Clock(), platform=Platform())
    try:
        assert rt.establish(SessionRequest(
            request_id="k1", initiator=U[0], target="grp:alpha",
            call_type="prearranged-group", media=(MediaKind.VOICE,)))[0] is not None
    finally:
        rt.close()
    with monkeypatch.context() as m:
        m.setattr(SqliteStore, "mark_released",
                  lambda self, cid, at: (_ for _ in ()).throw(OSError("disk")))
        with pytest.raises(OSError):
            build_runtime(env, Clock())
    rt = build_runtime(env, Clock())
    try:
        assert (rt.recovered, rt.health.snapshot()["sessions_released_at_start"]) == (1, 0)
        assert [r["detail"].get("cause") for r in rt.store.audit_records("k1")
                if r["type"] == "session-released"] == ["process-restart"]
        assert [s["state"] for s in rt.store.sessions()] == ["released"]
    finally:
        rt.close()


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
    for indicator in _PRODUCTION_FORMS:
        for stubbed in ({"MCX_RECORDER": "stub"}, {"MCX_BEARER": "stub"}, {}):
            with pytest.raises(StartupRefused, match="stub identity provider"):
                build_runtime({**in_production(env, indicator), **stubbed}, _clock())

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
                           "unreachable_at_release", "selected_by_group"}
    assert report["strict_release"] is False
    assert report["not_requestable_by_mcptt_clients"] == ["sds"]
    # PRF-OP-01: chosen by its group, and the fixture's groups name none.
    assert report["selected_by_group"] == {"coordination-group": []}
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


def test_a_group_naming_a_call_type_it_may_not_choose_refuses_start(env):
    """PRF-OP-01: the process checks each group's call_type against the
    loaded service profile, before anything durable is opened."""
    bad = [{**GROUPS[0], "call_type": "prearranged-group"}, *GROUPS[1:]]
    with pytest.raises(StartupRefused) as exc:
        build_runtime(with_network(env, "bad-choice.yaml", groups=bad), Clock())
    assert "groups[0].call_type: 'prearranged-group' is not a call type the service " \
           "profile lets a group choose (group_selected: true); known: coordination-group" \
        in str(exc.value)
    assert not Path(env["MCX_DATA_DIR"]).exists()


def test_startup_says_what_no_caller_can_obtain(env, caplog):
    """Review of PRF-OP-01: a group-selected call type no group names, and a
    call type needing a role no user may activate (SVC-OP-06), are said at start."""
    with caplog.at_level("WARNING", logger="mcx.service"):
        build_runtime(env, _clock()).close()
        build_runtime(_frmcs(with_network(env, "frmcs2.yaml"), "19", "true"), _clock()).close()
    said = [r.getMessage() for r in caplog.records]
    assert ("call type 'coordination-group' is chosen by its group, and no group in the "
            "network profile names it: no client can request it") in said
    roles = sorted(m for m in said if "lets no user activate one" in m)
    assert roles == sorted(
        f"call type {cid!r} needs the initiator to hold {held}, and the network profile "
        "lets no user activate one (functional_aliases): every caller is refused "
        "not-authorised"
        for cid, held in (("driver-controller", "train-driver, track-controller"),
                          ("shunting-group", "shunting-team-leader"),
                          ("rec-broadcast", "train-driver, track-controller")))
