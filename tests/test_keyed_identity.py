"""A functional identity keyed by an identification value (PLT-VP-R1 FA-OP-01
item 4, owner decision 2026-10-27, option b): the FRMCS FRS train function
identity, keyed by train ID (FRS 6.2.1.1), so there is one leading driver per
train. Written sip:<value>.<identity>@<domain> (owner: the format), e.g.
sip:1234.train-driver@frmcs.example.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.errors import ProfileValidationError, StartupRefused  # noqa: E402
from core.functional import AliasPolicy, Holding  # noqa: E402
from core.hooks import (LocationContext, MediaKind, SessionRequest,  # noqa: E402
                        keyed_identity)
from core.validation import build  # noqa: E402
from profiles.common.tables import ResolutionFailure  # noqa: E402
from service.network import load_network  # noqa: E402
from tests.network_fixture import network_yaml  # noqa: E402
from tests.test_sip_transport import pki  # noqa: E402,F401  (fixture)
from tests.test_functional_alias import (DRV, _manager, _records, _roles,  # noqa: E402
                                         RecordType)

PROFILES = ROOT / "profiles"
D = ("frmcs.example",)


def td(train, domain="frmcs.example"):
    return f"sip:{train}.train-driver@{domain}"


# ============================================================ the written form


@pytest.mark.parametrize("text,expected", [
    ("sip:1234.train-driver@frmcs.example", ("train-driver", "1234")),
    ("SIP:AB12.train-driver@FRMCS.Example", ("train-driver", "AB12")),
    ("sips:7.train-driver@frmcs.example", ("train-driver", "7")),
    (" sip:7.train-driver@frmcs.example ", ("train-driver", "7")),
    ("sip:7.train-driver@other.example", None),          # a domain not served
    ("sip:7.track-controller@frmcs.example", None),      # not a keyed identity
    ("sip:7.Train-driver@frmcs.example", None),          # the identity exactly
    ("sip:7-8.train-driver@frmcs.example", None),        # the value alphanumeric
    ("sip:7.8.train-driver@frmcs.example", None),
    ("sip:.train-driver@frmcs.example", None),
    ("sip:7.train-driver@frmcs.example;x=1", None),
    ("tel:7.train-driver@frmcs.example", None),
    ("train-driver", None),
    (None, None),
])
def test_the_keyed_form_is_read_exactly(text, expected):
    assert keyed_identity(text, ["train-driver"], D) == expected


# ============================================================ the profile


@pytest.fixture
def frmcs_raw():
    return yaml.safe_load((PROFILES / "frmcs" / "profile.yaml").read_text())


def _identity(raw, ident):
    return next(f for f in raw["identity"]["functional"] if f["id"] == ident)


def test_the_frmcs_train_driver_is_keyed_by_train_id(frmcs_raw):
    profile = build(frmcs_raw, "h")
    assert profile.functional_identity("train-driver").identification_key == "train_id"
    assert profile.functional_identity("track-controller").identification_key is None


@pytest.mark.parametrize("change,path,says", [
    ({"identification_key": "Train-ID"}, "identification_key",
     "expected a lower-case name such as unit_id"),
    ({"identification_key": 7}, "identification_key", "expected a string or null"),
    ({"location_dependent": True, "location_key": "track_section"}, "identification_key",
     "an identity is keyed by its location or by an identification value, not both"),
    ({"resolves_to": "group"}, "identification_key",
     "only an identity that resolves to a user is keyed by an identification value"),
    ({"id": "train.driver"}, ".id", "letters, digits, '-' and '_' only"),
], ids=["bad-name", "not-a-string", "with-location", "a-group", "a-dot-in-the-id"])
def test_a_keyed_identity_is_checked(frmcs_raw, change, path, says):
    raw = copy.deepcopy(frmcs_raw)
    entry = _identity(raw, "train-driver")
    entry.update(change)
    if "id" in change:            # the call types name the old id
        for ct in raw["call_types"]:
            ct["initiator_roles"] = [change["id"] if r == "train-driver" else r
                                     for r in ct["initiator_roles"]]
    with pytest.raises(ProfileValidationError) as exc:
        build(raw, "h")
    found = [(d.path, d.message) for d in exc.value.defects]
    assert any(path in p and says in m for p, m in found), found


# ============================================================ activation


def _frmcs(values=(), take_over=()):
    return _manager("frmcs", DRV, {
        "train-driver": AliasPolicy(users=frozenset(DRV), take_over=frozenset(take_over),
                                    values=tuple(values)),
        "track-controller": AliasPolicy(users=frozenset(DRV))},
        {})


def test_one_driver_per_train():
    mgr, loaded, _ = _frmcs(take_over=[DRV[2]])
    assert mgr.change_functional_aliases("p0", DRV[0], [td("T1")], False, None).accepted
    assert mgr.change_functional_aliases("p1", DRV[1], [td("T2")], False, None).accepted
    assert mgr.functional.holdings() == (Holding("train-driver", "T1", DRV[0]),
                                         Holding("train-driver", "T2", DRV[1]))
    assert _roles(loaded, DRV[0]) == _roles(loaded, DRV[1]) == ("train-driver",)
    held = mgr.change_functional_aliases("p2", DRV[2], [td("T1")], False, None)
    assert (held.reason_code, held.detail) == (
        "functional-alias-held", f"'train-driver' at 'T1' is held by {DRV[0]}")
    taken = mgr.change_functional_aliases("p3", DRV[2], [td("T1")], True, None)
    assert taken.displaced == (Holding("train-driver", "T1", DRV[0]),)
    # Changing train is a deactivation on one and an activation on the other.
    moved = mgr.change_functional_aliases("p4", DRV[1], [td("T3")], False, None)
    assert moved.activated == (Holding("train-driver", "T3", DRV[1]),)
    assert moved.deactivated == (Holding("train-driver", "T2", DRV[1]),)


def test_a_user_holds_one_value_of_an_identity():
    """Review of FA-OP-01 item 4 (H1): two trains in one PUBLISH are refused,
    since IF-IDR unbind names no value; the same train written twice is one
    holding (L1)."""
    mgr, loaded, _ = _frmcs()
    two = mgr.change_functional_aliases("p0", DRV[0], [td("T1"), td("T2")], False, None)
    assert (two.reason_code, two.detail) == (
        "functional-alias-not-authorised",
        f"{DRV[0]} may hold 'train-driver' for one value only")
    assert mgr.functional.holdings() == () and _roles(loaded, DRV[0]) == ()
    same = mgr.change_functional_aliases(
        "p1", DRV[0], [td("T1"), " SIPS:T1.train-driver@FRMCS.EXAMPLE "], False, None)
    assert same.accepted and same.activated == (Holding("train-driver", "T1", DRV[0]),)


def test_restore_keeps_one_value_per_user():
    mgr, loaded, sink = _frmcs()
    kept = mgr.restore_functional_aliases([Holding("train-driver", "T1", DRV[0]),
                                           Holding("train-driver", "T2", DRV[0])],
                                          "process-start")
    assert kept == (Holding("train-driver", "T1", DRV[0]),)
    assert [(r["slot"], r["reason"]) for r in _records(sink, RecordType.BINDING_CHANGED)
            if r["action"] == "dropped-at-restart"] == [("T2", "one-per-user")]


@pytest.mark.parametrize("alias,says", [
    ("train-driver", "'train-driver' is held per train_id: activate "
                     "sip:<train_id>.train-driver@<domain>"),
    ("sip:T1.train-driver@other.example",
     "may not hold 'sip:T1.train-driver@other.example'"),
    ("sip:S1.track-controller@frmcs.example",
     "may not hold 'sip:S1.track-controller@frmcs.example'"),
], ids=["no-train", "a-domain-not-served", "an-identity-not-keyed"])
def test_a_keyed_identity_is_activated_in_its_keyed_form_only(alias, says):
    mgr, _, sink = _frmcs()
    out = mgr.change_functional_aliases("p0", DRV[0], [alias], False, None)
    assert out.reason_code == "functional-alias-not-authorised" and says in out.detail
    assert mgr.functional.holdings() == ()


def test_the_trains_a_user_may_drive_are_the_deployment_s():
    """FRS 8.2.4.3.6: a role set may name a train number; `values` patterns."""
    mgr, _, _ = _frmcs(values=["T1*", "9?"])
    for ok in ("T1", "T15", "95"):
        assert mgr.change_functional_aliases(f"a-{ok}", DRV[0], [td(ok)], False,
                                             None).accepted
    for bad in ("T2", "9", "950"):
        out = mgr.change_functional_aliases(f"r-{bad}", DRV[0], [td(bad)], False, None)
        assert out.detail == f"{DRV[0]} may not hold 'train-driver' for train_id {bad}"


def test_restore_keeps_a_train_still_allowed():
    mgr, loaded, sink = _frmcs(values=["T1"])
    kept = mgr.restore_functional_aliases([
        Holding("train-driver", "T1", DRV[0]),
        Holding("train-driver", "T2", DRV[1]),        # no longer allowed
        Holding("train-driver", "", DRV[2])], "process-start")    # no train
    assert kept == (Holding("train-driver", "T1", DRV[0]),)
    assert _roles(loaded, DRV[0]) == ("train-driver",)
    assert [(r["holder"], r["reason"]) for r in _records(sink, RecordType.BINDING_CHANGED)
            if r["action"] == "dropped-at-restart"] == [(DRV[1], "not-allowed"),
                                                        (DRV[2], "not-allowed")]


# ============================================================ calls


def _call(mgr, rid, initiator, target, **kw):
    return mgr.establish(SessionRequest(request_id=rid, initiator=initiator, target=target,
                                        call_type="driver-controller",
                                        media=(MediaKind.VOICE,), **kw))


def test_a_call_to_a_train_s_driver_reaches_that_driver():
    mgr, _, _ = _frmcs()
    assert mgr.change_functional_aliases("p0", DRV[0], [td("T1")], False, None).accepted
    assert mgr.change_functional_aliases("p1", DRV[1], [td("T2")], False, None).accepted
    session, _, refusal = _call(mgr, "c1", DRV[1], td("T1"))
    assert refusal is None
    assert (session.members, session.resolution.resolved_from) == ((DRV[0],), td("T1"))
    # Addressed to the role: d0 is in it because of train T1.
    assert mgr.sessions_of_role("train-driver", DRV[0]) == ("c1",)
    _, _, refusal = _call(mgr, "c2", DRV[1], td("T9"))
    assert refusal.reason_code == "no-binding"


def test_the_identity_alone_is_not_a_call_target():
    mgr, loaded, _ = _frmcs()
    assert mgr.change_functional_aliases("p0", DRV[0], [td("T1")], False, None).accepted
    with pytest.raises(ResolutionFailure) as exc:
        loaded.hooks.identity_resolver.resolve("train-driver", SessionRequest(
            request_id="x", initiator=DRV[1], target="train-driver",
            call_type="driver-controller", media=(MediaKind.VOICE,)))
    assert (exc.value.reason_code, str(exc.value)) == (
        "unknown-target", "unknown-target: functional identity 'train-driver' is held per "
        "train_id; call sip:<train_id>.train-driver@<domain>")


def test_criteria_name_every_train_s_driver_or_one():
    """A railway emergency call's criteria train-driver reach every train's
    driver; a keyed criterion, that train's."""
    mgr, loaded, _ = _frmcs()
    for i, t in enumerate(("T1", "T2")):
        assert mgr.change_functional_aliases(f"p{i}", DRV[i], [td(t)], False,
                                             None).accepted
    r = loaded.hooks.identity_resolver
    request = SessionRequest(request_id="x", initiator=DRV[2], target="",
                             call_type="rec-broadcast", media=(MediaKind.VOICE,),
                             adhoc=True)
    assert r.determine_participants("train-driver", request).members == (DRV[0], DRV[1])
    assert r.determine_participants(td("T2"), request).members == (DRV[1],)


# ============================================================ the network profile


def _frmcs_functional():
    from core import loader
    return loader.load(PROFILES / "frmcs").profile.identity.functional


def test_values_are_read_for_a_keyed_identity(tmp_path):
    n = load_network(network_yaml(tmp_path, users=list(DRV), functional_aliases=[
        {"id": "train-driver", "users": list(DRV), "take_over": [],
         "values": ["T1*", "9?", "T1*"]}]), set(), None, None, _frmcs_functional())
    assert n.functional_aliases["train-driver"].values == ("T1*", "9?")


@pytest.mark.parametrize("where", ["users", "member", "group"])
def test_a_user_or_group_written_as_a_keyed_identity_is_refused(tmp_path, where):
    """Review of FA-OP-01 item 4 (M1): it would be shadowed by the identity,
    and reached by whoever activated that value; refused in any domain."""
    clash = "sip:john.train-driver@frmcs.example"
    users, groups = list(DRV), [{"id": "grp:a", "members": list(DRV)}]
    if where == "users":
        users.append(clash)
    elif where == "member":
        groups[0]["members"].append(clash)
    else:
        groups.append({"id": "sip:x.train-driver@elsewhere.example", "members": [DRV[0]]})
        clash = "sip:x.train-driver@elsewhere.example"
    with pytest.raises(StartupRefused) as exc:
        load_network(network_yaml(tmp_path, users=users, groups=groups,
                                  functional_aliases=[]), set(), None, None,
                     _frmcs_functional())
    assert ("users and groups: written as a keyed functional identity "
            f"(sip:<value>.<identity>@<domain>): {clash!r}") in str(exc.value)


@pytest.mark.parametrize("entry,says", [
    ({"id": "track-controller", "values": ["S1"]},
     "functional_aliases[0].values: 'track-controller' is not keyed by an identification "
     "value (identification_key)"),
    ({"id": "train-driver", "values": []}, "functional_aliases[0].values: expected a "
     "non-empty list of patterns of letters, digits, '*' and '?'"),
    ({"id": "train-driver", "values": ["T-1"]}, "expected a non-empty list of patterns"),
    ({"id": "train-driver", "values": "T1"}, "expected a non-empty list of patterns"),
], ids=["not-keyed", "empty", "a-bad-pattern", "not-a-list"])
def test_values_are_checked(tmp_path, entry, says):
    with pytest.raises(StartupRefused) as exc:
        load_network(network_yaml(tmp_path, users=list(DRV), functional_aliases=[
            {"users": list(DRV), "take_over": [], **entry}]), set(), None, None,
            _frmcs_functional())
    assert says in str(exc.value)


# ============================================================ end to end, over SIP


def test_a_driver_activates_a_train_and_is_called_on_it(tmp_path, pki):
    """PUBLISH sip:T1.train-driver@frmcs.example (9A.3.1 body), then a
    driver-to-controller call from the controller of S1 to that address
    reaches the driver; the health document lists the holder per train."""
    from tests import mcpttinfo_fixture as mcf
    from tests.test_functional_alias import CELL_S1, _last, _start, publish
    from tests.test_sip_transport import LOCAL, SDP, Flow, msg, network_yaml as ny, sip_env
    net = ny(tmp_path, fname="frmcs-net.yaml", trusted_cores=["core-client.example"],
             core_ca=pki / "core-ca.crt", users=DRV,
             cells=[{"cell": CELL_S1, "location": {"track_section": "S1"}}],
             functional_aliases=[
                 {"id": "track-controller", "users": DRV, "take_over": []},
                 {"id": "train-driver", "users": DRV, "take_over": [], "values": ["T*"]}])
    rt, core = _start(sip_env(tmp_path, pki, MCX_PROFILE="frmcs", MCX_RELEASE="19",
                              MCX_NETWORK_FILE=str(net)))
    try:
        f0, f1 = Flow(DRV[0]), Flow(DRV[1])
        core.on_bytes(msg("REGISTER", "sip:frmcs.example", "r0", 1, DRV[0], DRV[0],
                          extra=[f"Contact: <{DRV[0]}>"]), f0)
        core.on_bytes(publish(DRV[0], [td("T1")], call_id="a"), f0)
        assert _last(f0).code == 200
        assert rt.store.holdings() == [("train-driver", "T1", DRV[0])]
        assert rt.health.snapshot()["functional_aliases"] == [
            {"identity": "train-driver", "slot": "T1", "holder": DRV[0]}]
        core.on_bytes(publish(DRV[1], ["track-controller"], cell=CELL_S1, call_id="b"), f1)
        assert _last(f1).code == 200
        body = mcf.with_parts(SDP, mcf.mcinfo_xml("private", td("T1")),
                              (mcf.CT_LOCATION, mcf.location_report(ecgi=CELL_S1)))
        core.on_bytes(msg("INVITE", LOCAL, "dc1", 1, DRV[1], LOCAL, body=body,
                          ctype=mcf.CONTENT_TYPE), f1)
        assert len(f0.requests("INVITE")) == 1, f1.codes()
        admitted = [r["detail"] for r in rt.store.audit_records("dc1")
                    if r["type"] == "session-admitted"]
        assert [a["call_type"] for a in admitted] == ["driver-controller"]
    finally:
        core.close()
        rt.close()


def test_nobody_registers_as_a_keyed_identity(tmp_path, pki):
    """Review of FA-OP-01 item 4 (M1): the address is the identity's."""
    from tests.test_functional_alias import _start, frmcs_env
    from tests.test_sip_transport import Flow, msg
    rt, core = _start(frmcs_env(tmp_path, pki))
    try:
        clash = "sip:john.train-driver@frmcs.example"
        f = Flow(clash)
        core.on_bytes(msg("REGISTER", "sip:frmcs.example", "rj", 1, clash, clash,
                          extra=[f"Contact: <{clash}>"]), f)
        assert f.codes() == [403]
        ok = Flow(DRV[0])
        core.on_bytes(msg("REGISTER", "sip:frmcs.example", "r0", 1, DRV[0], DRV[0],
                          extra=[f"Contact: <{DRV[0]}>"]), ok)
        assert ok.codes() == [200]
    finally:
        core.close()
        rt.close()
