"""RES-OP-11 (owner ruling 2026-10-17): MCX_FOREIGN_INITIATOR=refuse|allow.

A trusted SIP core may assert any identity (ICD-OP-08), including one
outside the domains this deployment serves. `refuse` answers such a caller
404 with warning 141, "user unknown to the participating function", as TS
24.379 does when the participating function has no MCPTT ID for a caller
(10.1.1.3.1.1 step 2a, 11.1.1.3.1.1 step 4), before any hook runs
(PLT-IDM-008). `allow` serves it, a deviation reported at startup. A request
a gateway relays (IF-IWF map_inbound) is foreign by nature and not subject
to the setting.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.audit import MemorySink, RecordType  # noqa: E402
from core.errors import CORE_ORIGINATED, INITIATOR_NOT_SERVED, StartupRefused  # noqa: E402
from core.release import Release  # noqa: E402
from core.session import FOREIGN_INITIATOR  # noqa: E402
from core.sip import Adapter, DialogContext  # noqa: E402
from service.config import Config  # noqa: E402
from service.runtime import build_runtime  # noqa: E402
from tests.test_session import _altered, req  # noqa: E402
from tests.test_settings import _plain_env  # noqa: E402
from tests.test_sip_transport import (  # noqa: E402,F401  (fixtures)
    LOCAL, SDP, U, Clock, Flow, clock, core, env, msg, pki, rt, sip_env, world)
from tests import mcpttinfo_fixture as mcf  # noqa: E402

PROFILES = ROOT / "profiles"
FOREIGN = "sip:x@other.example"


def test_the_choices_and_the_code_are_pinned():
    assert FOREIGN_INITIATOR == ("refuse", "allow")
    assert INITIATOR_NOT_SERVED == "initiator-not-served"
    assert INITIATOR_NOT_SERVED in CORE_ORIGINATED


def test_it_is_required_with_no_default(tmp_path):
    env = _plain_env(tmp_path)
    env.pop("MCX_FOREIGN_INITIATOR")
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(env)
    assert "MCX_FOREIGN_INITIATOR is not set" in str(exc.value)
    with pytest.raises(StartupRefused) as exc:
        Config.from_env({**env, "MCX_FOREIGN_INITIATOR": "sometimes"})
    assert "must be 'refuse' or 'allow'" in str(exc.value)


@pytest.mark.parametrize("value", ["refuse", "allow"])
def test_the_value_is_reported_and_allow_is_a_deviation(tmp_path, value):
    r = build_runtime(_plain_env(tmp_path, MCX_FOREIGN_INITIATOR=value), Clock())
    try:
        snap = r.health.snapshot()
        assert snap["settings"]["MCX_FOREIGN_INITIATOR"] == value
        found = [d for d in snap["deviations"] if d["setting"] == "MCX_FOREIGN_INITIATOR"]
        assert bool(found) is (value == "allow")
        if found:
            assert found[0]["ref"] == "RES-OP-11"
            assert found[0]["departs_from"].startswith("PLT-SRS PLT-IDM-008")
            assert found[0]["consequence"] == (
                "a caller outside the profile's declared domains, as a trusted SIP "
                "core may assert, is served, including a partner system's users, whose "
                "priority is then not capped by its interconnection rules (there is no "
                "inbound IF-ICX path); such a caller still cannot register here")
        assert r.manager._foreign_initiator == value
    finally:
        r.close()


@pytest.fixture
def mcx():
    return loader.load(PROFILES / "mcx")


@pytest.mark.parametrize("initiator", [
    FOREIGN, "sip:u0@mcptt.example.evil", "sip:evil@other.example@mcptt.example",
    "tel:+3312345", "sip:u0@MCPTT.EXAMPLE;x=1",
    # "params": at the manager API only; over SIP, parameters are stripped
    # from the asserted URI before the core sees it.
], ids=["other-domain", "suffix", "two-ats", "tel", "params-at-the-api"])
def test_refuse_turns_away_a_caller_outside_the_domains_before_any_hook(mcx, initiator):
    sink = MemorySink()
    mgr = _altered(mcx, sink, foreign_initiator="refuse")
    session, signals, refusal = mgr.establish(req(rid="f1", initiator=initiator))
    assert session is None and refusal.reason_code == INITIATOR_NOT_SERVED
    assert refusal.step == "initiator"
    assert not sink.of_type(RecordType.HOOK_INVOCATION)           # nothing looked up
    refused = sink.of_type(RecordType.SESSION_REFUSED)[-1].detail
    assert refused["reason_code"] == INITIATOR_NOT_SERVED
    assert refused["detail"] == "initiator is outside the profile's declared domains"


def test_a_caller_in_the_domains_is_not_affected(mcx):
    for choice in FOREIGN_INITIATOR:
        mgr = _altered(mcx, MemorySink(), foreign_initiator=choice)
        session, _, refusal = mgr.establish(req(rid=f"in-{choice}",
                                                initiator="sip:u0@MCPTT.example"))
        assert refusal is None and session is not None


def test_allow_lets_a_foreign_caller_reach_the_hooks(mcx):
    sink = MemorySink()
    mgr = _altered(mcx, sink, foreign_initiator="allow")
    _, _, refusal = mgr.establish(req(rid="f2", initiator=FOREIGN))
    assert refusal is None or refusal.reason_code != INITIATOR_NOT_SERVED
    assert sink.of_type(RecordType.HOOK_INVOCATION)


def test_a_relayed_request_is_not_subject_to_the_setting(mcx, monkeypatch):
    from core.hooks import MediaKind, SessionRequest
    mgr = _altered(mcx, MemorySink(), foreign_initiator="refuse")
    relayed = SessionRequest(request_id="iw1", initiator="tetra:1234", target="grp:alpha",
                             call_type="prearranged-group", media=(MediaKind.VOICE,))
    monkeypatch.setattr(mcx.hooks.interworking_gateway, "map_inbound",
                        lambda foreign: relayed, raising=False)
    _, _, refusal = mgr.receive_inbound({"request_id": "iw1", "system": "tetra"})
    assert refusal is None or refusal.reason_code != INITIATOR_NOT_SERVED


def test_the_manager_refuses_an_unknown_choice(mcx):
    with pytest.raises(ValueError):
        _altered(mcx, MemorySink(), foreign_initiator="maybe")


def test_the_refusal_is_404_with_warning_141_at_every_release():
    from core.release import SUPPORTED
    for release in SUPPORTED:
        r = Adapter(LOCAL, release).reject(INITIATOR_NOT_SERVED,
                                           DialogContext(call_id="c", local_uri=LOCAL))
        assert r.status.code == 404
        assert r.headers.get("Warning").endswith(
            '"141 user unknown to the participating function"')


def test_a_trusted_core_asserting_a_foreign_caller_gets_404_141(core, rt, world):
    proxy = Flow("proxy", uris=(), dns=("core-client.example",), core=True)
    core.on_bytes(msg("INVITE", LOCAL, "fc1", 1, FOREIGN, LOCAL,
                      body=mcf.body_for("private", U[1], SDP), ctype=mcf.CONTENT_TYPE),
                  proxy)
    final = [m for m in proxy.messages() if getattr(m, "code", 0) >= 200][-1]
    assert final.code == 404
    assert final.headers.get("Warning").endswith(
        '"141 user unknown to the participating function"')
    assert not world[U[1]].requests("INVITE")                      # nobody rung



def _proxy():
    return Flow("proxy", uris=(), dns=("core-client.example",), core=True)


def _final(flow):
    return [m for m in flow.messages() if getattr(m, "code", 0) >= 200][-1]


@pytest.mark.parametrize("pai", [
    ["P-Asserted-Identity: <tel:+33123>, <sip:u0@mcptt.example>"],
    ["P-Asserted-Identity: <sip:u0@mcptt.example>, <tel:+33123>"],
    ["P-Asserted-Identity: <tel:+33123>", "P-Asserted-Identity: <sip:u0@mcptt.example>"],
], ids=["tel-first", "sip-first", "two-headers"])
def test_the_sip_identity_is_taken_from_p_asserted_identity_in_any_order(core, world, pai):
    """RFC 3325 9.1: one sip: and one tel:, either order, one header or two.
    The MCPTT ID is bound to the SIP public user identity (review, 1)."""
    from core.sip import parse_message
    raw = msg("INVITE", LOCAL, "pai1", 1, U[0], LOCAL, extra=pai,
              body=mcf.body_for("private", U[1], SDP), ctype=mcf.CONTENT_TYPE)
    assert core.adapter.parse_invite(parse_message(raw)).initiator == U[0]
    proxy = _proxy()
    core.on_bytes(raw, proxy)
    assert world[U[1]].requests("INVITE")                         # served, not 404


def test_a_refused_initiator_is_recorded_bounded(mcx):
    sink = MemorySink()
    mgr = _altered(mcx, sink, foreign_initiator="refuse")
    huge = "sip:" + "x" * 100_000 + "@other.example"
    mgr.establish(req(rid="b1", initiator=huge))
    recorded = sink.of_type(RecordType.SESSION_REFUSED)[-1].detail["initiator"]
    assert len(recorded) < 400 and recorded.endswith("(100018 characters)")


def test_the_participating_check_comes_before_the_controlling_one(core, world):
    """A foreign ad hoc INVITE carrying both indications is 404 + 141 (TS
    24.379 17.3.2.1.1 step 3), not 403 + 150 (17.4.2.2 step 3A)."""
    xml = mcf.adhoc_xml(criteria="x", emergency=True).replace(
        "</session-type>", '</session-type><imminentperil-ind type="Normal">'
        "<mcpttBoolean>true</mcpttBoolean></imminentperil-ind>", 1)
    proxy = _proxy()
    core.on_bytes(msg("INVITE", LOCAL, "ah1", 1, FOREIGN, LOCAL,
                      body=mcf.adhoc_body(SDP, xml), ctype=mcf.CONTENT_TYPE), proxy)
    assert _final(proxy).code == 404
    assert _final(proxy).headers.get("Warning").endswith(
        '"141 user unknown to the participating function"')


def test_a_foreign_emergency_caller_is_refused_too(core, world):
    """No emergency exception in TS 24.379; the RES-OP-11 row says so."""
    proxy = _proxy()
    core.on_bytes(msg("INVITE", LOCAL, "em1", 1, FOREIGN, LOCAL,
                      body=mcf.body_for("emergency-group", "grp:alpha", SDP),
                      ctype=mcf.CONTENT_TYPE), proxy)
    assert _final(proxy).code == 404
    assert all(not world[u].requests("INVITE") for u in U)


@pytest.fixture
def env(tmp_path, pki, request):
    return sip_env(tmp_path, pki, **getattr(request, "param", {}))


@pytest.mark.parametrize("env", [{"MCX_FOREIGN_INITIATOR": "allow"}], indirect=True)
def test_with_allow_a_foreign_caller_rings_the_callee(core, world):
    proxy = _proxy()
    core.on_bytes(msg("INVITE", LOCAL, "al1", 1, FOREIGN, LOCAL,
                      body=mcf.body_for("private", U[1], SDP), ctype=mcf.CONTENT_TYPE),
                  proxy)
    assert world[U[1]].requests("INVITE")
