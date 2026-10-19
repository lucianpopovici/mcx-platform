"""The decisions of PLT-VP-R1 as settings (owner ruling 2026-10-16).

Six decisions that were fixed behaviour are now stated by the deployment or
the profile, each required with no default:

  MCX_SERVICE_REFUSAL_STATUS      503 | 480          SIP-OP-10
  MCX_DIALOG_TAKEOVER             same-party | never SIP-OP-18 item 6
  MCX_LOCATION_REPORTS            read | ignore      ADHOC-OP-03
  MCX_HTTP_TLS (+ cert, key, CA, client auth)  on | off   RES-OP-05
  floor.preemption_at_full_queue  insert | deny      FC-OP-07
  call_types[].group_over_limit   truncate | refuse  RES-OP-12 ruling 1

A value that departs from the standard the original decision followed is
allowed, and reported: in the log, the health document and the startup
audit record.
"""

from __future__ import annotations

import dataclasses as dc
import json
import logging
import socket
import ssl
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.audit import RecordType  # noqa: E402
from core.errors import ProfileValidationError, StartupRefused  # noqa: E402
from core.floor import (ActionType, DenyReason, Event, EventType, FloorControl,  # noqa: E402
                        FloorState, Policy, RevokeReason)
from core.hooks import FloorPolicy  # noqa: E402
from core.session import HookContractViolation  # noqa: E402
from core.sip import Adapter, DialogContext, Request, Headers  # noqa: E402
from core.release import Release  # noqa: E402
from service.config import Config  # noqa: E402
from service.runtime import STARTUP_CORRELATION_ID, build_runtime  # noqa: E402
from tests import mcpttinfo_fixture as mcf  # noqa: E402
from tests.network_fixture import network_yaml  # noqa: E402
from tests.test_sip_transport import (  # noqa: E402,F401  (fixtures)
    GROUPS, LOCAL, SDP, U, Clock, Flow, clock, core, pki, rt, sip_env, world)
from tests.test_session_timer import (  # noqa: E402
    TIMER, call, from_initiator, responses)

PROFILES = ROOT / "profiles"
SIP_SETTINGS = {"MCX_SERVICE_REFUSAL_STATUS": ("503", "480"),
                "MCX_DIALOG_TAKEOVER": ("same-party", "never"),
                "MCX_LOCATION_REPORTS": ("read", "ignore")}


def _plain_env(tmp_path, **over):
    env = {"MCX_PROFILE": "mcx", "MCX_RELEASE": "19", "MCX_IDMS": "stub",
           "MCX_RECORDER": "none", "MCX_BEARER": "none", "MCX_STRICT_RELEASE": "false",
           "MCX_ADHOC_LIST_MAX": "100",
           "MCX_NETWORK_FILE": str(network_yaml(tmp_path, groups=GROUPS)),
           "MCX_DATA_DIR": str(tmp_path / "data"), "MCX_HTTP_PORT": "0",
           "MCX_HTTP_TLS": "off", "MCX_FLOOR_UNRECORDED": "deny",
           "MCX_FOREIGN_INITIATOR": "refuse"}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


# ================================================================ required, no default


@pytest.mark.parametrize("key", sorted(SIP_SETTINGS) + ["MCX_HTTP_TLS"])
def test_each_setting_is_required_with_no_default(tmp_path, pki, key):
    env = sip_env(tmp_path, pki)
    env.pop(key)
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(env)
    assert f"{key} is not set" in str(exc.value) and "no default" in str(exc.value)
    with pytest.raises(StartupRefused) as exc:
        Config.from_env({**env, key: "  "})
    assert f"{key} is not set" in str(exc.value)


@pytest.mark.parametrize("key,bad", [
    ("MCX_SERVICE_REFUSAL_STATUS", "500"), ("MCX_SERVICE_REFUSAL_STATUS", "486"),
    ("MCX_DIALOG_TAKEOVER", "always"), ("MCX_LOCATION_REPORTS", "yes"),
    ("MCX_HTTP_TLS", "true")])
def test_a_value_outside_the_choices_is_refused(tmp_path, pki, key, bad):
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(sip_env(tmp_path, pki, **{key: bad}))
    assert f"{key}={bad!r} must be" in str(exc.value)


@pytest.mark.parametrize("key,values", sorted(SIP_SETTINGS.items()))
def test_each_stated_value_is_the_one_in_force(tmp_path, pki, key, values):
    attr = {"MCX_SERVICE_REFUSAL_STATUS": "service_refusal_status",
            "MCX_DIALOG_TAKEOVER": "dialog_takeover",
            "MCX_LOCATION_REPORTS": "location_reports"}[key]
    for v in values:
        got = getattr(Config.from_env(sip_env(tmp_path, pki, **{key: v.upper()})).sip, attr)
        assert str(got) == v


def test_the_sip_settings_are_read_only_with_sip(tmp_path):
    cfg = Config.from_env(_plain_env(tmp_path))
    assert cfg.sip is None and cfg.http_tls is None


# ================================================================ SIP-OP-10


def _adapter(status=503):
    return Adapter(LOCAL, Release.REL_19, service_refusal_status=status)


@pytest.mark.parametrize("reason,warning", [
    ("capacity-exhausted", "maximum number of sessions reached"),
    ("recording-unavailable", "recording unavailable"),
    ("qos-unavailable", "requested quality of service unavailable"),
    ("gateway-unavailable", "interworking gateway unavailable"),
    ("partner-unavailable", "partner system unavailable")])
@pytest.mark.parametrize("status", [503, 480])
def test_a_service_refusal_carries_the_stated_status_and_its_warning(reason, warning,
                                                                    status):
    r = _adapter(status).reject(reason, DialogContext(call_id="c", local_uri=LOCAL))
    assert r.status.code == status
    got = r.headers.get("Warning")
    assert (got is None) if warning is None else got.endswith(f'"{warning}"')


@pytest.mark.parametrize("reason,code", [
    ("not-authorised", 403), ("unknown-target", 404), ("no-binding", 480),
    # a back-end failure with no warning text stays 503 (review, 2026-10-16)
    ("resolver-unavailable", 503),
    ("participant-limit-exceeded", 486), ("hook-error", 500)])
def test_other_refusals_are_untouched_by_the_setting(reason, code):
    ctx = DialogContext(call_id="c", local_uri=LOCAL)
    assert _adapter(480).reject(reason, ctx).status.code == code
    assert _adapter(503).reject(reason, ctx).status.code == code


def test_the_adapter_refuses_a_status_it_has_no_mapping_for():
    with pytest.raises(ValueError):
        _adapter(500)


def test_the_process_answers_capacity_with_the_stated_status(tmp_path, pki, clock):
    from core.session import Platform
    from service.sip_core import SipCore
    from tests.test_sip_transport import invite
    env = sip_env(tmp_path, pki, MCX_SERVICE_REFUSAL_STATUS="480",
                  MCX_RECORDER="none")
    r = build_runtime(env, clock, platform=Platform(recording_available=lambda: False))
    c = SipCore(r, LOCAL, clock)
    try:
        f = Flow(U[0])
        c.on_bytes(invite("cap1", U[0], "grp:alpha", "prearranged-group"), f)
        assert f.codes()[-1] == 480
        last = [m for m in f.messages() if hasattr(m, "code")][-1]
        assert last.headers.get("Warning").endswith('"recording unavailable"')
    finally:
        c.close()
        r.close()


# ================================================================ ADHOC-OP-03


def _located_invite():
    xml = mcf.mcinfo_xml("prearranged", "sip:grp@x")
    body = mcf.with_parts(SDP, xml, (mcf.CT_LOCATION, mcf.location_report(ecgi=mcf.ECGI)))
    return Request("INVITE", LOCAL, Headers([
        ("From", f"<{U[0]}>;tag=1"), ("To", f"<{LOCAL}>"), ("Call-ID", "loc"),
        ("CSeq", "1 INVITE"), ("Content-Type", mcf.CONTENT_TYPE)]), body)


@pytest.mark.parametrize("read,expected", [(True, mcf.ECGI), (False, None)])
def test_the_location_report_is_read_or_ignored_as_stated(read, expected):
    req = Adapter(LOCAL, Release.REL_19, read_location=read).parse_invite(_located_invite())
    assert (req.location.cell_id if req.location else None) == expected


# ================================================================ SIP-OP-18 item 6


@pytest.fixture
def env(tmp_path, pki, request):
    return sip_env(tmp_path, pki, **getattr(request, "param", {}))


@pytest.mark.parametrize("env", [{"MCX_DIALOG_TAKEOVER": "never"}], indirect=True)
def test_with_takeover_never_a_reconnected_caller_cannot_move_the_dialog(core, world):
    call(core, world, "n1", extra=TIMER + ["Session-Expires: 600"])
    old, new = world[U[0]], Flow(U[0])                   # same certificate identity
    core.on_bytes(from_initiator("UPDATE", "n1", 2, extra=TIMER), new)
    assert new.codes() == [481]
    assert core.calls["n1"].flow is old
    core.on_bytes(from_initiator("UPDATE", "n1", 3, extra=TIMER), old)
    assert responses(old, method="UPDATE")[-1].code == 200


@pytest.mark.parametrize("env", [{"MCX_DIALOG_TAKEOVER": "same-party"}], indirect=True)
def test_with_takeover_same_party_it_can(core, world):
    call(core, world, "n2", extra=TIMER + ["Session-Expires: 600"])
    new = Flow(U[0])
    core.on_bytes(from_initiator("UPDATE", "n2", 2, extra=TIMER), new)
    assert new.codes() == [200] and core.calls["n2"].flow is new


# ================================================================ FC-OP-07


def _floor(choice):
    return FloorControl(Policy(queueing_enabled=True, override_allowed=True,
                               max_queue_depth=1, preemption_at_full_queue=choice),
                        clock=Clock())


def _request(fc, who, priority):
    return fc.handle(Event(EventType.FLOOR_REQUEST, participant=who,
                           floor_priority=priority))


def test_insert_puts_the_pre_emptor_in_front_of_a_full_queue():
    """TS 24.380 6.3.4.4.7 item 2e: in front of every queued request, the
    queue one beyond its declared depth until the pre-emptor is granted."""
    fc = _floor("insert")
    fc.handle(Event(EventType.SESSION_ESTABLISHED, participant="a", floor_priority=100))
    _request(fc, "c", 50)
    actions = _request(fc, "b", 200)
    assert [a.revoke_reason for a in actions if a.type is ActionType.SEND_REVOKE] == \
        [RevokeReason.PREEMPTED]
    assert list(fc.queue) == ["b", "c"]
    assert fc.state is FloorState.REVOKING
    # an ordinary request still finds the queue full
    later = _request(fc, "d", 60)
    assert [a.reason for a in later if a.type is ActionType.SEND_DENY] == \
        [DenyReason.QUEUE_FULL]
    # the revoked talker releases: b is granted, the queue is back at its depth
    fc.handle(Event(EventType.FLOOR_RELEASE, participant="a"))
    assert fc.holder == "b" and list(fc.queue) == ["c"]


def test_deny_refuses_it_queue_full_and_the_talker_keeps_the_floor():
    fc = _floor("deny")
    fc.handle(Event(EventType.SESSION_ESTABLISHED, participant="a", floor_priority=100))
    _request(fc, "c", 50)
    actions = _request(fc, "b", 200)
    assert [a.reason for a in actions if a.type is ActionType.SEND_DENY] == \
        [DenyReason.QUEUE_FULL]
    assert fc.state is FloorState.TAKEN and fc.holder == "a"


@pytest.mark.parametrize("bad", ["Insert", "", None, True, "queue"])
def test_a_hook_naming_neither_choice_is_a_contract_violation(bad):
    from core.session import SessionManager
    policy = FloorPolicy(initial_grant_to_initiator=True, queueing_enabled=True,
                         override_allowed=True, max_queue_depth=2,
                         preemption_at_full_queue=bad)
    with pytest.raises(HookContractViolation) as exc:
        SessionManager._check_floor_policy(policy)
    assert "preemption_at_full_queue" in str(exc.value)


# ================================================================ profile fields


def _profile_text(name, old, new):
    text = (PROFILES / name / "profile.yaml").read_text(encoding="utf-8")
    assert old in text
    return text.replace(old, new)


@pytest.mark.parametrize("old,new,where", [
    ("      preemption_at_full_queue: deny      # FC-OP-07, a recorded deviation\n", "",
     "preemption_at_full_queue"),
    ("preemption_at_full_queue: deny ", "preemption_at_full_queue: maybe ",
     "preemption_at_full_queue"),
    ("    group_over_limit: truncate        # TS 24.379 6.3.5.5\n", "",
     "group_over_limit"),
    ("group_over_limit: truncate ", "group_over_limit: drop ", "group_over_limit"),
    # null and empty are not a choice either (review: they loaded as the old
    # behaviour, unreported)
    ("preemption_at_full_queue: deny ", "preemption_at_full_queue: null ",
     "preemption_at_full_queue"),
    ("preemption_at_full_queue: deny ", "preemption_at_full_queue: ",
     "preemption_at_full_queue"),
    ("group_over_limit: truncate ", "group_over_limit: ~ ", "group_over_limit"),
    ("group_over_limit: truncate ", "group_over_limit: ", "group_over_limit"),
])
def test_the_profile_must_state_both_and_only_the_choices(tmp_path, old, new, where):
    import shutil
    shutil.copytree(PROFILES / "mcx", tmp_path / "mcx")
    shutil.copytree(PROFILES / "common", tmp_path / "common")
    (tmp_path / "mcx" / "profile.yaml").write_text(_profile_text("mcx", old, new),
                                                   encoding="utf-8")
    with pytest.raises(ProfileValidationError) as exc:
        loader.load(tmp_path / "mcx")
    assert where in str(exc.value)


def test_the_in_tree_profiles_state_the_decided_behaviour():
    """The decisions as they stood: FC-OP-07 keeps the refusal (a recorded
    deviation), RES-OP-12 ruling 1 truncates (TS 24.379 6.3.5.5)."""
    for name in ("mcx", "frmcs", "utility"):
        for ct in loader.load(PROFILES / name).profile.call_types:
            assert ct.floor.preemption_at_full_queue == "deny", (name, ct.id)
            assert ct.group_over_limit == "truncate", (name, ct.id)


# ================================================================ RES-OP-12 ruling 1


def test_refuse_turns_a_group_over_its_limit_away_486_122(tmp_path):
    from core.audit import Auditor, MemorySink
    from tests.test_session import _altered, _decide, req
    mcx = loader.load(PROFILES / "mcx")
    sink = MemorySink()
    refusing = dc.replace(mcx.profile, call_types=tuple(
        dc.replace(ct, group_over_limit="refuse") if ct.id == "prearranged-group" else ct
        for ct in mcx.profile.call_types))
    session, signals, refusal = _altered(
        mcx, sink, profile=refusing, decision=_decide(max_participants=2)).establish(req())
    assert session is None and refusal.reason_code == "participant-limit-exceeded"
    assert refusal.detail == ("4 participants, the session decision allows 2 "
                              "(group_over_limit: refuse)")
    assert not sink.of_type(RecordType.SESSION_ESTABLISHED)
    ctx = DialogContext(call_id="c", local_uri=LOCAL)
    r = Adapter(LOCAL, Release.REL_19).reject(refusal.reason_code, ctx)
    assert r.status.code == 486 and '"122 too many participants"' in r.headers.get("Warning")


# ================================================================ reported


def _started(rt):
    records = [r for r in rt.store.audit_records()
               if r["type"] == RecordType.CONFIGURATION_ACCEPTED.value]
    assert len(records) == 1 and records[0]["correlation_id"] == STARTUP_CORRELATION_ID
    return records[0]["detail"]


def test_the_in_tree_mcx_deployment_reports_its_deviations(tmp_path, caplog):
    loaded = loader.load(PROFILES / "mcx")
    held = sorted(ct.id for ct in loaded.profile.call_types
                  if ct.floor.queueing_enabled and ct.floor.override_allowed)
    assert held                                   # the setting takes effect somewhere
    with caplog.at_level(logging.WARNING, logger="mcx.service"):
        r = build_runtime(_plain_env(tmp_path), Clock())
    try:
        snap = r.health.snapshot()
        refs = sorted((d["setting"], d["ref"]) for d in snap["deviations"])
        assert refs == sorted(
            [("MCX_HTTP_TLS", "RES-OP-05")] +
            [(f"call_types[{c}].floor.preemption_at_full_queue", "FC-OP-07") for c in held])
        assert snap["settings"]["MCX_HTTP_TLS"] == "off"
        assert snap["settings"]["preemption_at_full_queue"] == {c: "deny" for c in held}
        assert set(snap["settings"]["group_over_limit"].values()) == {"truncate"}
        detail = _started(r)
        assert detail["deviations"] == snap["deviations"]
        assert detail["settings"] == snap["settings"]
        warned = [m for m in caplog.messages if m.startswith("deviation: ")]
        assert len(warned) == len(snap["deviations"])
        assert any("MCX_HTTP_TLS=off departs from PLT-SRS 3.1 HTTP-1" in m for m in warned)
    finally:
        r.close()


def test_a_sip_deployment_reports_each_departing_value(tmp_path, pki):
    env = sip_env(tmp_path, pki, MCX_PROFILE="frmcs",
                  MCX_SERVICE_REFUSAL_STATUS="480", MCX_LOCATION_REPORTS="ignore",
                  MCX_DIALOG_TAKEOVER="never",
                  MCX_NETWORK_FILE=str(network_yaml(
                      tmp_path, trusted_cores=["core-client.example"],
                      core_ca=pki / "core-ca.crt", fname="f.yaml")))
    r = build_runtime(env, Clock())
    try:
        snap = r.health.snapshot()
        by = {d["setting"]: d for d in snap["deviations"]}
        assert by["MCX_SERVICE_REFUSAL_STATUS"]["value"] == 480
        assert "RFC 3261 21.5.4" in by["MCX_SERVICE_REFUSAL_STATUS"]["departs_from"]
        located = sorted(f.id for f in r.loaded.profile.identity.functional
                         if f.location_dependent)
        assert located and by["MCX_LOCATION_REPORTS"]["consequence"] == (
            "calls to " + ", ".join(located) + " are refused no-location-binding, "
            "and ad hoc criteria naming them contribute no one (warning 187 if "
            "nothing else matches)")
        # stated, but not a departure from any standard
        assert "MCX_DIALOG_TAKEOVER" not in by
        assert snap["settings"]["MCX_DIALOG_TAKEOVER"] == "never"
        assert _started(r)["deviations"] == snap["deviations"]
    finally:
        r.close()


def test_ignoring_location_where_no_identity_needs_it_is_no_deviation(tmp_path, pki):
    r = build_runtime(sip_env(tmp_path, pki, MCX_LOCATION_REPORTS="ignore"), Clock())
    try:
        assert not any(d["setting"] == "MCX_LOCATION_REPORTS"
                       for d in r.health.snapshot()["deviations"])
    finally:
        r.close()


def test_a_profile_that_follows_3gpp_reports_no_profile_deviation(tmp_path):
    """insert and truncate are the 3GPP behaviour: only HTTP remains."""
    import shutil
    shutil.copytree(PROFILES, tmp_path / "profiles")
    p = tmp_path / "profiles" / "mcx" / "profile.yaml"
    p.write_text(p.read_text(encoding="utf-8").replace(
        "preemption_at_full_queue: deny", "preemption_at_full_queue: insert"),
        encoding="utf-8")
    r = build_runtime(_plain_env(tmp_path, MCX_PROFILES_ROOT=str(tmp_path / "profiles")),
                      Clock())
    try:
        assert [d["setting"] for d in r.health.snapshot()["deviations"]] == ["MCX_HTTP_TLS"]
    finally:
        r.close()


# ================================================================ RES-OP-05: HTTPS


def _https_env(tmp_path, pki, auth="required", **over):
    env = _plain_env(tmp_path, MCX_HTTP_TLS="on",
                     MCX_HTTP_TLS_CERT=str(pki / "server.crt"),
                     MCX_HTTP_TLS_KEY=str(pki / "server.key"),
                     MCX_HTTP_CLIENT_AUTH=auth,
                     MCX_HTTP_TLS_CA=None if auth == "none" else str(pki / "ca.crt"))
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


@pytest.mark.parametrize("change,message", [
    ({"MCX_HTTP_TLS_CERT": None}, "MCX_HTTP_TLS_CERT is not set"),
    ({"MCX_HTTP_TLS_KEY": "/nonexistent"}, "does not exist"),
    ({"MCX_HTTP_CLIENT_AUTH": None}, "MCX_HTTP_CLIENT_AUTH is not set"),
    ({"MCX_HTTP_CLIENT_AUTH": "maybe"}, "must be"),
    ({"MCX_HTTP_TLS_CA": None}, "MCX_HTTP_TLS_CA is not set"),
])
def test_https_states_every_file(tmp_path, pki, change, message):
    env = _https_env(tmp_path, pki)
    for k, v in change.items():
        env.pop(k) if v is None else env.__setitem__(k, v)
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(env)
    assert message in str(exc.value)


def test_a_ca_with_no_client_authentication_is_refused(tmp_path, pki):
    env = _https_env(tmp_path, pki, auth="none", MCX_HTTP_TLS_CA=str(pki / "ca.crt"))
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(env)
    assert "MCX_HTTP_CLIENT_AUTH=none" in str(exc.value)


@pytest.mark.parametrize("key", ["MCX_HTTP_TLS_CERT", "MCX_HTTP_TLS_KEY",
                                 "MCX_HTTP_TLS_CA", "MCX_HTTP_CLIENT_AUTH"])
def test_a_tls_setting_with_tls_off_is_refused_not_ignored(tmp_path, key):
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(_plain_env(tmp_path, **{key: "x"}))
    assert f"{key} is set but MCX_HTTP_TLS=off" in str(exc.value)


def test_a_certificate_that_will_not_load_refuses_startup(tmp_path, pki):
    env = _https_env(tmp_path, pki, MCX_HTTP_TLS_KEY=str(pki / "u0.key"))
    with pytest.raises(StartupRefused) as exc:
        build_runtime(env, Clock())
    assert "cannot be loaded" in str(exc.value)


@pytest.fixture
def https(tmp_path, pki, request):
    from service.http import Server
    r = build_runtime(_https_env(tmp_path, pki, auth=request.param), Clock())
    r.health.set_ready(True)
    s = Server(r, "127.0.0.1", 0)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    yield r, s.bound_port
    s.shutdown()
    s.server_close()
    r.close()


def _client(pki, cert=None):
    ctx = ssl.create_default_context(cafile=str(pki / "ca.crt"))
    if cert:
        ctx.load_cert_chain(str(pki / f"{cert}.crt"), str(pki / f"{cert}.key"))
    return ctx


def _get(port, ctx, path="/healthz"):
    with urllib.request.urlopen(f"https://127.0.0.1:{port}{path}", context=ctx,
                                timeout=5) as resp:
        return resp.status, json.loads(resp.read())


@pytest.mark.parametrize("https", ["required"], indirect=True)
def test_https_required_serves_a_client_with_a_certificate_only(https, pki):
    r, port = https
    status, body = _get(port, _client(pki, "u0"))
    assert status == 200 and body["settings"]["MCX_HTTP_TLS"] == "on"
    assert not any(d["setting"] == "MCX_HTTP_TLS" for d in body["deviations"])
    with pytest.raises((ssl.SSLError, OSError)):
        _get(port, _client(pki))                         # no certificate
    with pytest.raises((ssl.SSLError, OSError)):
        _get(port, _client(pki, "rogue"))                # one the CA did not issue


@pytest.mark.parametrize("https", ["optional", "none"], indirect=True)
def test_https_optional_or_none_serves_a_client_without_one(https, pki):
    _, port = https
    assert _get(port, _client(pki))[0] == 200


@pytest.mark.parametrize("https", ["none"], indirect=True)
def test_plain_http_to_the_https_port_gets_nothing(https):
    _, port = https
    with pytest.raises(Exception):
        urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5).read()


@pytest.mark.parametrize("https", ["none"], indirect=True)
def test_a_stalled_handshake_does_not_block_other_clients(https, pki):
    _, port = https
    stalled = socket.create_connection(("127.0.0.1", port))
    try:
        assert _get(port, _client(pki))[0] == 200
    finally:
        stalled.close()


@pytest.mark.parametrize("choice,front,entries,breaks", [
    ("insert", True, 2, False),     # depth 1, plus the one pre-emptor in front
    ("insert", True, 3, True),      # never two beyond
    ("insert", False, 2, True),     # an ordinary queue is still held to its depth
    ("deny", True, 2, True),        # deny keeps the depth outright
])
def test_the_depth_invariant_allows_only_the_inserted_pre_emptor(choice, front, entries,
                                                                 breaks):
    from core.floor import FloorInvariantViolation, QueueEntry
    fc = _floor(choice)
    fc.handle(Event(EventType.SESSION_ESTABLISHED, participant="a", floor_priority=100))
    fc._queue = [QueueEntry(f"p{i}", 50, i, 0, front=front and i == 0)
                 for i in range(entries)]
    if breaks:
        with pytest.raises(FloorInvariantViolation):
            fc._check_invariants()
    else:
        fc._check_invariants()


@pytest.mark.parametrize("env", [{"MCX_LOCATION_REPORTS": "ignore"}], indirect=True)
def test_the_process_ignores_location_when_told_to(core):
    assert core.adapter.parse_invite(_located_invite()).location is None


@pytest.mark.parametrize("env", [{"MCX_LOCATION_REPORTS": "read"}], indirect=True)
def test_the_process_reads_location_when_told_to(core):
    assert core.adapter.parse_invite(_located_invite()).location.cell_id == mcf.ECGI


def test_a_profile_that_refuses_over_limit_groups_reports_it(tmp_path):
    import shutil
    shutil.copytree(PROFILES, tmp_path / "profiles")
    p = tmp_path / "profiles" / "mcx" / "profile.yaml"
    p.write_text(p.read_text(encoding="utf-8").replace(
        "group_over_limit: truncate", "group_over_limit: refuse"), encoding="utf-8")
    r = build_runtime(_plain_env(tmp_path, MCX_PROFILES_ROOT=str(tmp_path / "profiles")),
                      Clock())
    try:
        refusing = sorted(d["setting"] for d in r.health.snapshot()["deviations"]
                          if d["ref"] == "RES-OP-12")
        # reported where it can take effect: not on a private or ad hoc call
        # type, which is refused over its limit whatever it states
        groups = [ct.id for ct in r.loaded.profile.call_types
                  if ct.mc_signature is None or
                  ct.mc_signature.session_type not in ("private", "adhoc")]
        assert "private" not in groups and len(groups) >= 3
        assert refusing == sorted(f"call_types[{c}].group_over_limit" for c in groups)
        assert set(r.health.snapshot()["settings"]["group_over_limit"].values()) == {"refuse"}
    finally:
        r.close()


@pytest.mark.parametrize("https", ["none"], indirect=True)
def test_a_stalled_handshake_is_dropped_after_the_timeout(https, monkeypatch):
    import time
    import service.http as http
    monkeypatch.setattr(http, "HANDSHAKE_TIMEOUT_S", 0.3)
    _, port = https
    stalled = socket.create_connection(("127.0.0.1", port))
    stalled.settimeout(5)
    started = time.monotonic()
    try:
        assert stalled.recv(1) == b""                 # the server closed it
        assert time.monotonic() - started < 3
    finally:
        stalled.close()



def test_a_queued_request_asking_again_keeps_a_place_behind_the_inserted_pre_emptor():
    """6.3.5.4.4 item 8 behind an item 2e insertion: the depth bounds the
    ordinary entries, so c is repositioned, not dropped (review finding 2)."""
    fc = _floor("insert")
    fc.handle(Event(EventType.SESSION_ESTABLISHED, participant="a", floor_priority=100))
    _request(fc, "c", 50)
    _request(fc, "b", 200)
    assert list(fc.queue) == ["b", "c"]
    actions = _request(fc, "c", 60)
    assert not [a for a in actions if a.type is ActionType.SEND_DENY]
    assert list(fc.queue) == ["b", "c"]
    assert [a.queue_position for a in actions
            if a.type is ActionType.SEND_QUEUE_POSITION and a.target == "c"] == [2]


def test_a_hook_choosing_other_than_the_declared_place_is_a_contract_violation():
    """§5.3 POST-5 as equality: the place reported at startup is what runs."""
    from core.audit import MemorySink
    from tests.test_session import _altered, req
    mcx = loader.load(PROFILES / "mcx")
    declared = mcx.profile.call_type("prearranged-group").floor.preemption_at_full_queue
    other = "insert" if declared == "deny" else "deny"
    sink = MemorySink()
    mgr = _altered(mcx, sink,
                   floor=lambda f: dc.replace(f, preemption_at_full_queue=other))
    session, _, refusal = mgr.establish(req())
    assert session is None and refusal.reason_code == "hook-contract-violation"
    assert "is not the call type's declared" in str(refusal.detail)


@pytest.mark.parametrize("key,value", [("MCX_SERVICE_REFUSAL_STATUS", "503"),
                                       ("MCX_DIALOG_TAKEOVER", "never"),
                                       ("MCX_LOCATION_REPORTS", "read")])
def test_a_sip_setting_without_sip_is_refused_not_ignored(tmp_path, key, value):
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(_plain_env(tmp_path, **{key: value}))
    assert f"{key} is set but SIP is not enabled" in str(exc.value)


@pytest.mark.parametrize("auth,warned", [("required", False), ("optional", True),
                                         ("none", True)])
def test_client_authentication_is_stated_and_a_weak_one_warned(tmp_path, pki, caplog,
                                                              auth, warned):
    with caplog.at_level(logging.WARNING, logger="mcx.service"):
        r = build_runtime(_https_env(tmp_path, pki, auth=auth), Clock())
    try:
        assert r.health.snapshot()["settings"]["MCX_HTTP_CLIENT_AUTH"] == auth
        assert _started(r)["settings"]["MCX_HTTP_CLIENT_AUTH"] == auth
        assert any(m.startswith(f"MCX_HTTP_CLIENT_AUTH={auth}: health and group documents")
                   for m in caplog.messages) is warned
    finally:
        r.close()


def test_a_refused_certificate_opens_no_store(tmp_path, pki):
    env = _https_env(tmp_path, pki, MCX_HTTP_TLS_KEY=str(pki / "u0.key"))
    with pytest.raises(StartupRefused):
        build_runtime(env, Clock())
    assert not (tmp_path / "data").exists()


def test_a_refusal_after_the_store_opened_closes_it(tmp_path, monkeypatch):
    from service import runtime as runtime_mod
    from service.store import SqliteStore
    closed = []
    real = SqliteStore.close
    monkeypatch.setattr(SqliteStore, "close", lambda self: (closed.append(1), real(self)))
    monkeypatch.setattr(runtime_mod, "behaviour_settings",
                        lambda *a: (_ for _ in ()).throw(StartupRefused("late")))
    with pytest.raises(StartupRefused):
        build_runtime(_plain_env(tmp_path), Clock())
    assert closed == [1]


def test_the_server_uses_the_context_startup_checked(tmp_path, pki):
    from service.http import Server
    r = build_runtime(_https_env(tmp_path, pki, auth="none"), Clock())
    try:
        assert r.http_context is not None
        assert r.http_context.options & ssl.OP_NO_RENEGOTIATION
        assert r.http_context.minimum_version is ssl.TLSVersion.TLSv1_2
        broken = dc.replace(r, http_context=None)
        with pytest.raises(ValueError):
            Server(broken, "127.0.0.1", 0)
    finally:
        r.close()


@pytest.mark.parametrize("https", ["none"], indirect=True)
def test_an_idle_connection_after_the_handshake_is_closed(https, pki, monkeypatch):
    import time
    from service.http import Handler
    monkeypatch.setattr(Handler, "timeout", 0.3)
    _, port = https
    raw = socket.create_connection(("127.0.0.1", port))
    conn = _client(pki).wrap_socket(raw, server_hostname="127.0.0.1")
    conn.settimeout(5)
    started = time.monotonic()
    try:
        assert conn.recv(1) == b""
        assert time.monotonic() - started < 3
    finally:
        conn.close()


@pytest.mark.parametrize("https", ["none"], indirect=True)
def test_connections_beyond_the_cap_are_closed_at_once(https, pki, monkeypatch):
    import service.http as http
    r, port = https
    monkeypatch.setattr(http, "HANDSHAKE_TIMEOUT_S", 5)
    held = [socket.create_connection(("127.0.0.1", port)) for _ in range(http.MAX_CONNECTIONS)]
    try:
        import time
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", port))
        extra.settimeout(3)
        try:
            assert extra.recv(1) == b""                 # closed, not served
        finally:
            extra.close()
    finally:
        for h in held:
            h.close()
    import time
    time.sleep(0.3)
    assert _get(port, _client(pki))[0] == 200       # the slots come back


def test_the_http_limits_are_pinned():
    from service import http, http_tls
    assert http.Handler.timeout == http_tls.IDLE_TIMEOUT_S == 30
    assert http_tls.MAX_CONNECTIONS == 64 and http_tls.HANDSHAKE_TIMEOUT_S == 10
    assert http.Server.request_queue_size == 128


def test_a_connection_whose_thread_cannot_start_gives_its_slot_back(tmp_path, monkeypatch):
    import socketserver
    from service.http import Server
    r = build_runtime(_plain_env(tmp_path), Clock())
    s = Server(r, "127.0.0.1", 0)
    try:
        def fail(self, request, address):
            raise RuntimeError("can't start new thread")
        monkeypatch.setattr(socketserver.ThreadingMixIn, "process_request", fail)
        a, b = socket.socketpair()
        for _ in range(3):
            with pytest.raises(RuntimeError):
                s.process_request(a, ("127.0.0.1", 1))
        assert s._slots._value == 64
        a.close(), b.close()
    finally:
        s.server_close()
        r.close()


@pytest.mark.parametrize("https", ["none"], indirect=True)
def test_a_trickled_request_is_cut_at_the_deadline(https, pki, monkeypatch):
    """The idle timeout bounds each read; a request line sent a byte at a time
    is ended by the overall deadline (re-review, finding A)."""
    import time
    from service import http
    monkeypatch.setattr(http, "REQUEST_DEADLINE_S", 1.0)
    _, port = https
    conn = _client(pki).wrap_socket(socket.create_connection(("127.0.0.1", port)),
                                    server_hostname="127.0.0.1")
    started = time.monotonic()
    try:
        with pytest.raises((OSError, ssl.SSLError)):
            for ch in b"GET /healthz HTTP/1.0\r\n" * 10:
                conn.send(bytes([ch]))
                time.sleep(0.2)
                if time.monotonic() - started > 6:
                    pytest.fail("still open after 6 s")
        assert time.monotonic() - started < 4
    finally:
        conn.close()


@pytest.mark.parametrize("https", ["none"], indirect=True)
def test_one_client_cannot_take_every_slot(https, pki):
    """MAX_PER_CLIENT from one address; the next is closed at once, and the
    remaining slots stay for others (here: the count, as every test client is
    127.0.0.1)."""
    import time
    from service import http_tls
    r, port = https
    held = [socket.create_connection(("127.0.0.1", port))
            for _ in range(http_tls.MAX_PER_CLIENT)]
    try:
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", port))
        extra.settimeout(3)
        try:
            assert extra.recv(1) == b""
        finally:
            extra.close()
    finally:
        for h in held:
            h.close()
    time.sleep(0.3)
    assert _get(port, _client(pki))[0] == 200


def test_the_per_client_limits_are_pinned():
    from service import http_tls
    assert http_tls.MAX_PER_CLIENT == 8 and http_tls.REQUEST_DEADLINE_S == 15


def test_a_handler_error_is_one_line_not_a_traceback(tmp_path, caplog):
    from service.http import Server
    r = build_runtime(_plain_env(tmp_path), Clock())
    s = Server(r, "127.0.0.1", 0)
    try:
        with caplog.at_level(logging.INFO, logger="mcx.http"):
            try:
                raise TimeoutError("timed out")
            except TimeoutError:
                s.handle_error(None, ("192.0.2.1", 1))
        got = [(r.getMessage(), r.exc_info) for r in caplog.records if r.name == "mcx.http"]
        assert got == [("192.0.2.1: HTTP connection ended: timed out", None)]
    finally:
        s.server_close()
        r.close()



def test_a_hook_that_widens_where_deny_applies_is_recorded_per_session(caplog):
    """The startup report lists deny where the call type declares queueing
    and override; a hook enabling them elsewhere puts the deviation in that
    session's own record (re-review, finding C)."""
    from core.audit import MemorySink
    from tests.test_session import _altered, req
    mcx = loader.load(PROFILES / "mcx")
    narrow = dc.replace(mcx.profile, call_types=tuple(
        dc.replace(ct, floor=dc.replace(ct.floor, override_allowed=False))
        if ct.id == "prearranged-group" else ct for ct in mcx.profile.call_types))
    sink = MemorySink()
    mgr = _altered(mcx, sink, profile=narrow,
                   floor=lambda f: dc.replace(f, override_allowed=True))
    session, _, refusal = mgr.establish(req())
    assert refusal is None
    detail = sink.of_type(RecordType.SESSION_ESTABLISHED)[-1].detail
    assert [(d["setting"], d["ref"]) for d in detail["deviations"]] == [
        ("call_types[prearranged-group].floor.preemption_at_full_queue", "FC-OP-07")]
    # and where the declaration already says so, nothing per session
    sink2 = MemorySink()
    session, _, _ = _altered(mcx, sink2).establish(req(rid="s2"))
    assert "deviations" not in sink2.of_type(RecordType.SESSION_ESTABLISHED)[-1].detail


def test_a_narrow_declaration_the_hook_keeps_records_nothing_per_session():
    from core.audit import MemorySink
    from tests.test_session import _altered, req
    mcx = loader.load(PROFILES / "mcx")
    narrow = dc.replace(mcx.profile, call_types=tuple(
        dc.replace(ct, floor=dc.replace(ct.floor, override_allowed=False))
        if ct.id == "prearranged-group" else ct for ct in mcx.profile.call_types))
    sink = MemorySink()
    _, _, refusal = _altered(mcx, sink, profile=narrow,
                             floor=lambda f: dc.replace(f, override_allowed=False)
                             ).establish(req())
    assert refusal is None
    assert "deviations" not in sink.of_type(RecordType.SESSION_ESTABLISHED)[-1].detail


def test_per_client_slots_come_back_in_full(tmp_path):
    from service import http_tls
    from service.http import Server
    r = build_runtime(_plain_env(tmp_path), Clock())
    s = Server(r, "127.0.0.1", 0)
    try:
        for _ in range(20):
            assert s._take("192.0.2.7")
            s._give_back("192.0.2.7")
        assert s._per_client == {}
        assert all(s._take("192.0.2.7") for _ in range(http_tls.MAX_PER_CLIENT))
        assert not s._take("192.0.2.7")
        assert s._take("192.0.2.8")                     # another address still may
    finally:
        s.server_close()
        r.close()


@pytest.mark.parametrize("fail", ["dup", "thread"])
def test_a_connection_with_no_deadline_is_closed_and_its_slot_returned(tmp_path,
                                                                    monkeypatch, fail):
    from service import http
    from service.http import Server
    r = build_runtime(_plain_env(tmp_path), Clock())
    s = Server(r, "127.0.0.1", 0)
    try:
        if fail == "dup":
            monkeypatch.setattr(http.os, "dup", lambda fd: (_ for _ in ()).throw(
                OSError(24, "Too many open files")))
        else:
            monkeypatch.setattr(http.threading.Timer, "start", lambda self: (
                _ for _ in ()).throw(RuntimeError("can't start new thread")))
        a, b = socket.socketpair()
        assert s._take("192.0.2.9")
        s.process_request_thread(a, ("192.0.2.9", 1))
        assert s._slots._value == 64 and s._per_client == {}
        b.settimeout(2)
        assert b.recv(1) == b""                          # closed, not left open
        b.close()
    finally:
        s.server_close()
        r.close()


# ===================================== durations in seconds (owner ruling 2026-10-18)


def _seconds_deployment(tmp_path, pki, ms, s, ring_ms, ring_s, timers=None):
    """A SIP deployment whose session interval and first mcx call type's
    ring limit are stated as given (None: not stated); `timers`, (old, new),
    replaces the first floor timer map of the profile."""
    import shutil
    shutil.copytree(PROFILES, tmp_path / "profiles", ignore=shutil.ignore_patterns("__pycache__"))
    p = tmp_path / "profiles" / "mcx" / "profile.yaml"
    old = "    no_answer_ms: 32000           # = 64*T1, the limit before it was declared (SIP-OP-15)\n"
    new = "".join(f"    {k}: {v}\n" for k, v in (("no_answer_ms", ring_ms), ("no_answer_s", ring_s))
                  if v is not None)
    text = p.read_text(encoding="utf-8").replace(old, new, 1)
    if timers:
        assert timers[0] in text
        text = text.replace(timers[0], timers[1], 1)
    p.write_text(text, encoding="utf-8")
    env = sip_env(tmp_path, pki, MCX_PROFILES_ROOT=str(tmp_path / "profiles"))
    env.pop("MCX_SESSION_EXPIRES_MS")
    for k, v in (("MCX_SESSION_EXPIRES_MS", ms), ("MCX_SESSION_EXPIRES", s)):
        if v is not None:
            env[k] = v
    return env


@pytest.mark.vp("VP1-BND-016")
def test_disagreeing_forms_use_the_milliseconds_and_warn(tmp_path, pki, caplog):
    """PLT-GEN-011 as amended 2026-10-18: either form is standard; with both,
    the milliseconds apply and a disagreement is warned of."""
    env = _seconds_deployment(tmp_path, pki, "600000", "1800", 45000, 32,
                              timers=("      timers_ms: {T2: 4000, T20: 100, T8: 1000, T3: 3000}\n",
                                      "      timers_ms: {T2: 1000, T8: 1000, T3: 3000}\n"
                                      "      timers_s: {T2: 3, T20: 1}\n"))
    with caplog.at_level(logging.WARNING, logger="mcx.service"):
        r = build_runtime(env, Clock())
    try:
        assert r.config.sip.session_expires_ms == 600_000
        first = r.loaded.profile.call_types[0]
        assert first.no_answer_ms == 45_000
        snap = r.health.snapshot()
        assert not [d for d in snap["deviations"] if "no_answer" in d["setting"]
                    or "SESSION_EXPIRES" in d["setting"] or "timers" in d["setting"]]
        ct_with_timers = next(ct for ct in r.loaded.profile.call_types if ct.floor.timers_s)
        assert dict(ct_with_timers.floor.timers_ms)["T2"] == 1000
        assert dict(ct_with_timers.floor.timers_ms)["T20"] == 1000
        assert snap["warnings"] == [
            {"setting": "MCX_SESSION_EXPIRES_MS",
             "message": "MCX_SESSION_EXPIRES=1800 s (1800000 ms) and "
                        "MCX_SESSION_EXPIRES_MS=600000 disagree; MCX_SESSION_EXPIRES_MS=600000 "
                        "is used"},
            {"setting": "call_types[private].no_answer_ms",
             "message": "call_types[private]: no_answer_s=32 s (32000 ms) and "
                        "no_answer_ms=45000 disagree; no_answer_ms=45000 is used"},
            {"setting": f"call_types[{ct_with_timers.id}].floor.timers_ms.T2",
             "message": f"call_types[{ct_with_timers.id}].floor: timers_s.T2=3 s (3000 ms) "
                        "and timers_ms.T2=1000 disagree; timers_ms.T2=1000 is used"}]
        detail = _started(r)
        assert detail["warnings"] == snap["warnings"]
        assert detail["deviations"] == snap["deviations"]
        assert [m for m in caplog.messages if m.startswith("setting: ")] == [
            "setting: " + w["message"] for w in snap["warnings"]]
    finally:
        r.close()


@pytest.mark.vp("VP1-BND-016")
@pytest.mark.parametrize("ms, s, ring_ms, ring_s", [
    ("1800000", "1800", 32000, 32),     # both forms, agreeing
    (None, "1800", None, 32),           # seconds alone
    ("1800000", None, 32000, None),     # milliseconds alone
])
def test_agreeing_or_single_forms_are_neither_deviation_nor_warning(
        tmp_path, pki, ms, s, ring_ms, ring_s):
    r = build_runtime(_seconds_deployment(tmp_path, pki, ms, s, ring_ms, ring_s), Clock())
    try:
        assert r.config.sip.session_expires_ms == 1_800_000
        assert r.loaded.profile.call_types[0].no_answer_ms == 32_000
        snap = r.health.snapshot()
        assert not [d for d in snap["deviations"] if "no_answer" in d["setting"]
                    or "SESSION_EXPIRES" in d["setting"]]
        assert snap["warnings"] == [] and _started(r)["warnings"] == []
    finally:
        r.close()


@pytest.mark.vp("VP1-BND-016")
def test_the_seconds_pairs_are_the_ones_handled():
    """A pair added to SECONDS_FORMS fails here until it is read, given
    priority and warned of like these three, and tested so."""
    from core import validation
    from service import config
    assert config.SECONDS_FORMS == {"MCX_SESSION_EXPIRES": "MCX_SESSION_EXPIRES_MS"}
    assert validation.SECONDS_FORMS == {"no_answer_s": "no_answer_ms", "timers_s": "timers_ms"}
