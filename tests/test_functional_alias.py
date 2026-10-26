"""Functional alias management (PLT-VP-R1 SVC-OP-06, decided 2026-10-23;
TS 24.379 clause 9A, Rel-15 on): who holds which functional identity.

The core procedure (core/functional.py, SessionManager.change_functional_
aliases) and the SIP PUBLISH that carries it (service/sip_core.py), end to
end. Bodies are written by hand here, not rendered by the code under test.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import loader  # noqa: E402
from core.audit import Auditor, MemorySink, RecordType  # noqa: E402
from profiles.common.tables import ResolutionFailure  # noqa: E402
from core.functional import AliasPolicy, Holding  # noqa: E402
from core.hooks import LocationContext, MediaKind, SessionRequest  # noqa: E402
from core.session import Platform, SessionManager  # noqa: E402
from tests import mcpttinfo_fixture as mcf  # noqa: E402

PROFILES = ROOT / "profiles"
ENG = [f"sip:e{i}@utility.example" for i in range(3)]
DRV = [f"sip:d{i}@frmcs.example" for i in range(3)]
CELL_S1 = mcf.ECGI
CELL_S2 = "001010" + "0000000000000000000100100100"


class Clock:
    def __init__(self):
        self.now = 1_000

    def __call__(self):
        self.now += 1
        return self.now


def _manager(profile, users, policy, cells=None):
    loaded = loader.load(PROFILES / profile)
    for u in users:
        loaded.hooks.identity_resolver.register_user(u)
    sink = MemorySink()
    mgr = SessionManager(loaded, Auditor(sink, loaded.profile.identifier(), clock=Clock()),
                         clock=Clock(), cells=cells or {}, functional_aliases=policy)
    return mgr, loaded, sink


def _utility(take_over=()):
    return _manager("utility", ENG, {"control-engineer": AliasPolicy(
        users=frozenset(ENG[:2]), take_over=frozenset(take_over))})


def _frmcs(take_over=()):
    cells = {CELL_S1: {"track_section": "S1"}, CELL_S2: {"track_section": "S2"}}
    return _manager("frmcs", DRV, {
        "train-driver": AliasPolicy(users=frozenset(DRV)),
        "track-controller": AliasPolicy(users=frozenset(DRV),
                                        take_over=frozenset(take_over))}, cells)


def _roles(loaded, user):
    return tuple(loaded.hooks.identity_resolver.identities_of(user))


def _records(sink, kind):
    return [dict(r.detail) for r in sink.records if r.type is kind]


# ============================================================ the core procedure


def test_an_allowed_user_activates_and_then_holds_the_role():
    mgr, loaded, sink = _utility()
    out = mgr.change_functional_aliases("p1", ENG[0], ["control-engineer"], False, None)
    assert out.accepted and out.activated == (Holding("control-engineer", "", ENG[0]),)
    assert _roles(loaded, ENG[0]) == ("control-engineer",)
    assert mgr.functional.holdings() == (Holding("control-engineer", "", ENG[0]),)
    assert _records(sink, RecordType.BINDING_CHANGED) == [{
        "action": "changed", "user": ENG[0], "take_over": False,
        "activated": [{"identity": "control-engineer", "slot": "", "holder": ENG[0]}],
        "deactivated": [], "displaced": []}]


def test_the_role_lets_its_holder_start_the_call_type_that_needs_it():
    """SVC-OP-06 closes the gap PRF-OP-01 left: a switching order from an
    engineer who activated control-engineer is admitted, held to 4."""
    mgr, loaded, _ = _utility()
    loaded.hooks.identity_resolver.register_group("grp:sw", ENG + [
        f"sip:x{i}@utility.example" for i in range(5)])
    for i in range(5):
        loaded.hooks.identity_resolver.register_user(f"sip:x{i}@utility.example")
    req = SessionRequest(request_id="s1", initiator=ENG[0], target="grp:sw",
                         call_type="switching-order", media=(MediaKind.VOICE,))
    _, _, refusal = mgr.establish(req)
    assert refusal.reason_code == "not-authorised"
    assert mgr.change_functional_aliases("p1", ENG[0], ["control-engineer"], False,
                                         None).accepted
    session, signals, refusal = mgr.establish(SessionRequest(
        request_id="s2", initiator=ENG[0], target="grp:sw",
        call_type="switching-order", media=(MediaKind.VOICE,)))
    assert refusal is None and session is not None


def test_a_switching_order_needs_the_role_and_membership_of_the_group():
    """SVC-OP-07: the role lets an engineer start a switching order, on a
    group the engineer is a member of; on one it is not, 403/116."""
    mgr, loaded, _ = _utility()
    others = [f"sip:x{i}@utility.example" for i in range(5)]
    for u in others:
        loaded.hooks.identity_resolver.register_user(u)
    loaded.hooks.identity_resolver.register_group("grp:sw", [ENG[0]] + others)
    assert mgr.change_functional_aliases("p1", ENG[1], ["control-engineer"], False,
                                         None).accepted
    _, _, refusal = mgr.establish(SessionRequest(
        request_id="s1", initiator=ENG[1], target="grp:sw",
        call_type="switching-order", media=(MediaKind.VOICE,)))
    assert refusal.reason_code == "not-group-member"
    assert mgr.change_functional_aliases("p2", ENG[1], [], False, None).accepted
    assert mgr.change_functional_aliases("p3", ENG[0], ["control-engineer"], False,
                                         None).accepted
    session, _, refusal = mgr.establish(SessionRequest(
        request_id="s2", initiator=ENG[0], target="grp:sw",
        call_type="switching-order", media=(MediaKind.VOICE,)))
    assert refusal is None and session is not None


@pytest.mark.parametrize("user,wanted,code", [
    (ENG[2], ["control-engineer"], "functional-alias-not-authorised"),     # not listed
    (ENG[0], ["no-such-role"], "functional-alias-not-authorised"),
    (ENG[0], ["control-engineer", "no-such-role"], "functional-alias-not-authorised"),
], ids=["a-user-not-allowed", "an-undeclared-identity", "all-or-nothing"])
def test_a_refused_activation_changes_nothing(user, wanted, code):
    mgr, loaded, sink = _utility()
    out = mgr.change_functional_aliases("p1", user, wanted, False, None)
    assert out.reason_code == code and not out.activated
    assert mgr.functional.holdings() == () and _roles(loaded, user) == ()
    assert [r["reason_code"] for r in _records(sink, RecordType.BINDING_REFUSED)] == [code]
    assert _records(sink, RecordType.BINDING_CHANGED) == []


def test_a_held_role_is_refused_unless_taken_over_by_one_allowed_to(monkeypatch):
    """9A.2.2.3.3 steps 5 and 6 (ICD-OP-02 settled): refuse, unless asked to
    take over and allowed to; the holder it is taken from loses it, by an
    unbind of its own (the resolver is not relied on to replace it)."""
    mgr, loaded, _ = _utility(take_over=[ENG[1]])
    resolver = loaded.hooks.identity_resolver
    unbinds, real_unbind = [], resolver.unbind

    def unbind(identity, user):
        unbinds.append((identity, user))
        return real_unbind(identity, user)
    monkeypatch.setattr(resolver, "unbind", unbind)
    assert mgr.change_functional_aliases("p1", ENG[0], ["control-engineer"], False,
                                         None).accepted
    held = mgr.change_functional_aliases("p2", ENG[1], ["control-engineer"], False, None)
    assert held.reason_code == "functional-alias-held"
    taken = mgr.change_functional_aliases("p3", ENG[1], ["control-engineer"], True, None)
    assert taken.accepted and taken.displaced == (Holding("control-engineer", "", ENG[0]),)
    assert unbinds == [("control-engineer", ENG[0])]
    assert (_roles(loaded, ENG[0]), _roles(loaded, ENG[1])) == ((), ("control-engineer",))
    back = mgr.change_functional_aliases("p4", ENG[0], ["control-engineer"], True, None)
    assert back.reason_code == "functional-alias-take-over-not-allowed"
    assert mgr.functional.holdings() == (Holding("control-engineer", "", ENG[1]),)


def test_a_request_lists_the_whole_set_wanted():
    """9A.2.2.2.3 steps 10-14: held and not listed is deactivated."""
    mgr, loaded, _ = _frmcs()
    s1 = LocationContext(cell_id=CELL_S1)
    assert mgr.change_functional_aliases("p1", DRV[0], ["train-driver", "track-controller"],
                                         False, s1).accepted
    assert _roles(loaded, DRV[0]) == ("track-controller", "train-driver")
    out = mgr.change_functional_aliases("p2", DRV[0], ["track-controller"], False, s1)
    assert out.deactivated == (Holding("train-driver", "", DRV[0]),) and not out.activated
    out = mgr.change_functional_aliases("p3", DRV[0], [], False, None)
    assert out.deactivated == (Holding("track-controller", "S1", DRV[0]),)
    assert _roles(loaded, DRV[0]) == () and mgr.functional.holdings() == ()


def test_a_location_dependent_role_is_held_per_location():
    mgr, loaded, _ = _frmcs()
    s1, s2 = LocationContext(cell_id=CELL_S1), LocationContext(cell_id=CELL_S2)
    assert mgr.change_functional_aliases("p1", DRV[0], ["track-controller"], False,
                                         s1).accepted
    assert mgr.change_functional_aliases("p2", DRV[1], ["track-controller"], False,
                                         s2).accepted
    held = mgr.change_functional_aliases("p3", DRV[2], ["track-controller"], False, s1)
    assert held.reason_code == "functional-alias-held"
    assert mgr.functional.holdings() == (Holding("track-controller", "S1", DRV[0]),
                                         Holding("track-controller", "S2", DRV[1]))
    # Moving to another section is a deactivation there and an activation here.
    moved = mgr.change_functional_aliases(
        "p4", DRV[0], ["track-controller"], False,
        LocationContext(attributes={"track_section": "S3"}))
    assert moved.activated == (Holding("track-controller", "S3", DRV[0]),)
    assert moved.deactivated == (Holding("track-controller", "S1", DRV[0]),)


@pytest.mark.parametrize("location", [None, LocationContext(cell_id="001010" + "1" * 28)],
                         ids=["none", "an-unmapped-cell"])
def test_a_location_dependent_role_needs_a_location(location):
    mgr, _, _ = _frmcs()
    out = mgr.change_functional_aliases("p1", DRV[0], ["track-controller"], False, location)
    assert out.reason_code == "functional-alias-location-unknown"
    assert "held per track_section, and no reported location gives one" in out.detail


def test_a_resolver_failing_part_way_leaves_every_holder_as_it_was(monkeypatch):
    mgr, loaded, _ = _utility(take_over=[ENG[1]])
    assert mgr.change_functional_aliases("p1", ENG[0], ["control-engineer"], False,
                                         None).accepted
    resolver = loaded.hooks.identity_resolver
    real = resolver.bind

    def failing(identity, user, location):
        if user == ENG[1]:
            raise ResolutionFailure("resolver-unavailable", "down")
        return real(identity, user, location)
    monkeypatch.setattr(resolver, "bind", failing)
    out = mgr.change_functional_aliases("p2", ENG[1], ["control-engineer"], True, None)
    assert out.reason_code == "resolver-unavailable"
    assert mgr.functional.holdings() == (Holding("control-engineer", "", ENG[0]),)
    assert (_roles(loaded, ENG[0]), _roles(loaded, ENG[1])) == (("control-engineer",), ())


def test_holders_kept_across_a_restart_are_bound_again_if_still_allowed():
    mgr, loaded, sink = _frmcs()
    kept = mgr.restore_functional_aliases([
        Holding("train-driver", "", DRV[0]),
        Holding("track-controller", "S2", DRV[1]),
        Holding("train-driver", "", "sip:gone@frmcs.example"),     # not allowed now
        Holding("track-controller", "", DRV[2]),                    # no location
        Holding("train-driver", "S1", DRV[2]),                      # not per location
        Holding("rec-area", "S1", DRV[2]),                          # not a user's
    ], "process-start")
    assert kept == (Holding("train-driver", "", DRV[0]),
                    Holding("track-controller", "S2", DRV[1]))
    assert _roles(loaded, DRV[1]) == ("track-controller",)
    dropped = [r for r in _records(sink, RecordType.BINDING_CHANGED)
               if r["action"] == "dropped-at-restart"]
    assert [(r["identity"], r["holder"]) for r in dropped] == [
        ("train-driver", "sip:gone@frmcs.example"), ("track-controller", DRV[2]),
        ("train-driver", DRV[2]), ("rec-area", DRV[2])]
    assert _roles(loaded, DRV[2]) == ()


def _down(*_):
    raise ResolutionFailure("resolver-unavailable", "down")


def test_the_holders_are_persisted_ahead_of_the_resolver_on_take_over():
    """Review SVC-OP-06 #2: before any IF-IDR call the store is given the
    holders less the one taken from, then the holders after the change."""
    mgr, _, _ = _utility(take_over=[ENG[1]])
    assert mgr.change_functional_aliases("p1", ENG[0], ["control-engineer"], False,
                                         None).accepted
    saved = []
    assert mgr.change_functional_aliases("p2", ENG[1], ["control-engineer"], True, None,
                                         persist=saved.append).accepted
    assert saved == [(), (Holding("control-engineer", "", ENG[1]),)]


def test_a_store_failing_before_the_resolver_changes_nothing(monkeypatch):
    mgr, loaded, sink = _utility()
    resolver = loaded.hooks.identity_resolver
    monkeypatch.setattr(resolver, "bind", _down)

    def failing(_):
        raise OSError("disk full")
    with pytest.raises(OSError):
        mgr.change_functional_aliases("p1", ENG[0], ["control-engineer"], False, None,
                                      persist=failing)
    assert mgr.functional.holdings() == ()
    assert _records(sink, RecordType.BINDING_CHANGED) == [{
        "action": "not-persisted", "stage": "before-resolver", "user": ENG[0],
        "wanted": ["control-engineer"], "detail": "disk full"}]


def test_a_store_failing_after_the_resolver_puts_the_resolver_back():
    mgr, loaded, sink = _utility()
    calls = []

    def second_fails(held):
        calls.append(held)
        if len(calls) == 2:
            raise OSError("disk full")
    with pytest.raises(OSError):
        mgr.change_functional_aliases("p1", ENG[0], ["control-engineer"], False, None,
                                      persist=second_fails)
    assert calls == [(), (Holding("control-engineer", "", ENG[0]),)]
    assert mgr.functional.holdings() == () and _roles(loaded, ENG[0]) == ()
    assert _records(sink, RecordType.BINDING_CHANGED) == [{
        "action": "not-persisted", "stage": "after-resolver", "user": ENG[0],
        "wanted": ["control-engineer"], "detail": "disk full"}]


def test_a_role_the_resolver_will_not_unbind_stays_in_the_ledger(monkeypatch):
    """Review SVC-OP-06 #1: a refused request whose rollback unbind fails
    leaves the ledger saying what the resolver holds, recorded and persisted,
    so the user can still deactivate it."""
    mgr, loaded, sink = _frmcs()
    resolver = loaded.hooks.identity_resolver
    real_bind, real_unbind = resolver.bind, resolver.unbind

    def bind(identity, user, location):
        if identity == "track-controller":
            _down()
        return real_bind(identity, user, location)
    monkeypatch.setattr(resolver, "bind", bind)
    monkeypatch.setattr(resolver, "unbind", _down)
    saved = []
    out = mgr.change_functional_aliases("p1", DRV[0], ["train-driver", "track-controller"],
                                        False, LocationContext(cell_id=CELL_S1),
                                        persist=saved.append)
    assert out.reason_code == "resolver-unavailable"
    left = (Holding("train-driver", "", DRV[0]),)
    assert mgr.functional.holdings() == left and _roles(loaded, DRV[0]) == ("train-driver",)
    assert saved == [(), left]
    # The failed bind is unbound too, in case the resolver took it; it will
    # not unbind, so that is recorded, without a holding in the ledger.
    assert _records(sink, RecordType.BINDING_CHANGED) == [{
        "action": "rollback-incomplete", "identity": "train-driver", "slot": "",
        "holder": DRV[0], "reason": "resolver-unavailable"}, {
        "action": "rollback-uncertain", "identity": "track-controller", "slot": "S1",
        "holder": DRV[0], "reason": "resolver-unavailable"}]
    monkeypatch.setattr(resolver, "unbind", real_unbind)
    assert mgr.change_functional_aliases("p2", DRV[0], [], False, None).deactivated == left
    assert _roles(loaded, DRV[0]) == ()


def test_a_holder_the_resolver_will_not_bind_again_is_dropped_and_recorded(monkeypatch):
    """Review SVC-OP-06 #3: take-over, the taker's bind fails and so does
    binding the holder again; the holder is dropped, recorded, persisted."""
    mgr, loaded, sink = _utility(take_over=[ENG[1]])
    assert mgr.change_functional_aliases("p1", ENG[0], ["control-engineer"], False,
                                         None).accepted
    monkeypatch.setattr(loaded.hooks.identity_resolver, "bind", _down)
    saved = []
    out = mgr.change_functional_aliases("p2", ENG[1], ["control-engineer"], True, None,
                                        persist=saved.append)
    assert out.reason_code == "resolver-unavailable"
    assert mgr.functional.holdings() == () and saved == [(), ()]
    assert _records(sink, RecordType.BINDING_CHANGED)[1:] == [{
        "action": "dropped-on-rollback", "identity": "control-engineer", "slot": "",
        "holder": ENG[0], "reason": "resolver-unavailable"}]


def test_a_store_failing_after_a_refusal_is_recorded(monkeypatch):
    mgr, loaded, sink = _utility()
    monkeypatch.setattr(loaded.hooks.identity_resolver, "bind", _down)
    calls = []

    def second_fails(held):
        calls.append(held)
        if len(calls) == 2:
            raise OSError("disk full")
    out = mgr.change_functional_aliases("p1", ENG[0], ["control-engineer"], False, None,
                                        persist=second_fails)
    assert out.reason_code == "resolver-unavailable"
    assert _records(sink, RecordType.BINDING_CHANGED) == [{
        "action": "not-persisted", "stage": "after-refusal", "user": ENG[0],
        "wanted": ["control-engineer"], "detail": "disk full"}]


def test_a_take_over_the_resolver_will_not_undo_keeps_the_taker(monkeypatch):
    """Re-review SVC-OP-06 Q1: the taker's later bind fails and its first one
    will not unbind; the holder taken from is not bound again (the resolver
    would replace the taker) but dropped, so the ledger has one holder."""
    mgr, loaded, sink = _manager("frmcs", DRV, {
        "train-driver": AliasPolicy(users=frozenset(DRV), take_over=frozenset(DRV)),
        "track-controller": AliasPolicy(users=frozenset(DRV))},
        {CELL_S1: {"track_section": "S1"}})
    s1 = LocationContext(cell_id=CELL_S1)
    assert mgr.change_functional_aliases("p1", DRV[0], ["train-driver"], False, None).accepted
    resolver = loaded.hooks.identity_resolver
    real_bind = resolver.bind

    def bind(identity, user, location):
        if identity == "track-controller":
            _down()
        return real_bind(identity, user, location)
    monkeypatch.setattr(resolver, "bind", bind)
    real_unbind = resolver.unbind
    monkeypatch.setattr(resolver, "unbind", lambda i, u: _down() if u == DRV[1]
                        else real_unbind(i, u))
    out = mgr.change_functional_aliases("p2", DRV[1], ["train-driver", "track-controller"],
                                        True, s1)
    assert out.reason_code == "resolver-unavailable"
    assert mgr.functional.holdings() == (Holding("train-driver", "", DRV[1]),)
    assert (_roles(loaded, DRV[0]), _roles(loaded, DRV[1])) == ((), ("train-driver",))
    assert [(r["action"], r["holder"], r["reason"])
            for r in _records(sink, RecordType.BINDING_CHANGED)[1:]] == [
        ("rollback-incomplete", DRV[1], "resolver-unavailable"),
        ("rollback-uncertain", DRV[1], "resolver-unavailable"),
        ("dropped-on-rollback", DRV[0], "taken-over")]


def test_a_bind_that_took_effect_before_failing_is_undone(monkeypatch):
    """Re-review SVC-OP-06 Q6: a bind the resolver took and then failed is
    unbound in the rollback."""
    mgr, loaded, _ = _utility()
    resolver = loaded.hooks.identity_resolver
    real = resolver.bind

    def took_then_failed(identity, user, location):
        real(identity, user, location)
        _down()
    monkeypatch.setattr(resolver, "bind", took_then_failed)
    out = mgr.change_functional_aliases("p1", ENG[0], ["control-engineer"], False, None)
    assert out.reason_code == "resolver-unavailable"
    assert _roles(loaded, ENG[0]) == () and mgr.functional.holdings() == ()


def test_restore_drops_a_location_no_cell_gives_any_more():
    """Re-review SVC-OP-06 Q4: a slot comes only from the cell map."""
    mgr, loaded, sink = _frmcs()
    kept = mgr.restore_functional_aliases([Holding("track-controller", "S9", DRV[0]),
                                           Holding("track-controller", "S1", DRV[1])],
                                          "process-start")
    assert kept == (Holding("track-controller", "S1", DRV[1]),) and _roles(loaded, DRV[0]) == ()
    assert [r for r in _records(sink, RecordType.BINDING_CHANGED)
            if r["action"] == "dropped-at-restart"] == [{
                "action": "dropped-at-restart", "identity": "track-controller", "slot": "S9",
                "holder": DRV[0], "reason": "unknown-location"}]


def test_restore_keeps_one_holder_of_a_single_holder_identity():
    """Review SVC-OP-06 #6: the first kept wins; the others are dropped."""
    mgr, loaded, sink = _utility()
    kept = mgr.restore_functional_aliases(
        [Holding("control-engineer", "", ENG[0]), Holding("control-engineer", "", ENG[0]),
         Holding("control-engineer", "", ENG[1])], "process-start")
    assert kept == (Holding("control-engineer", "", ENG[0]),)
    assert mgr.functional.holdings() == kept
    assert (_roles(loaded, ENG[0]), _roles(loaded, ENG[1])) == (("control-engineer",), ())
    assert [r for r in _records(sink, RecordType.BINDING_CHANGED)
            if r["action"] == "dropped-at-restart"] == [{
                "action": "dropped-at-restart", "identity": "control-engineer", "slot": "",
                "holder": ENG[1], "reason": "already-held"}]


def test_a_multi_holder_identity_has_no_holder_limit(monkeypatch):
    """`multiplicity: multi` (no shipped user identity declares it): a second
    holder needs no take-over, and restore keeps every holder."""
    import dataclasses
    mgr, loaded, _ = _utility()
    cls = type(loaded.profile)
    real = cls.functional_identity
    multi = dataclasses.replace(real(loaded.profile, "control-engineer"),
                                multiplicity="multi")
    monkeypatch.setattr(cls, "functional_identity",
                        lambda self, i: multi if i == "control-engineer" else real(self, i))
    both = (Holding("control-engineer", "", ENG[0]), Holding("control-engineer", "", ENG[1]))
    assert mgr.restore_functional_aliases(list(both), "process-start") == both
    mgr2, _, _ = _utility()
    for cid, user in (("p1", ENG[0]), ("p2", ENG[1])):
        assert mgr2.change_functional_aliases(cid, user, ["control-engineer"], False,
                                              None).accepted
    assert mgr2.functional.holdings() == both


# ============================================================ the PIDF body (9A.3.1)


def pidf(entity, aliases, take_over=None, client="client-1"):
    fas = "".join(f'<fa:functionalAlias functionalAliasID="{a}"/>' for a in aliases)
    tko = f"<fa:take-over>{take_over}</fa:take-over>" if take_over is not None else ""
    return ('<?xml version="1.0" encoding="UTF-8"?>\r\n'
            '<presence xmlns="urn:ietf:params:xml:ns:pidf" '
            f'xmlns:fa="urn:3gpp:ns:mcpttPresInfoFA:1.0" entity="{entity}">'
            f'<fa:p-id-fa>abc</fa:p-id-fa><tuple id="{client}"><status>{fas}{tko}</status>'
            "</tuple></presence>")


def publish_body(user, aliases, take_over=None, cell=None, entity=None):
    info = (f'<?xml version="1.0" encoding="UTF-8"?>\r\n<mcpttinfo xmlns="{mcf.NS}">'
            f'<mcptt-Params><mcptt-request-uri type="Normal"><mcpttURI>{user}</mcpttURI>'
            "</mcptt-request-uri></mcptt-Params></mcpttinfo>")
    parts = [(mcf.CT_MCINFO, info), ("application/pidf+xml",
                                     pidf(entity or user, aliases, take_over))]
    if cell is not None:
        parts.append((mcf.CT_LOCATION, mcf.location_report(ecgi=cell)))
    out = "".join(f"--{mcf.BOUNDARY}\r\nContent-Type: {c}\r\n\r\n{b}\r\n" for c, b in parts)
    return out + f"--{mcf.BOUNDARY}--\r\n"


def test_the_pidf_body_is_read_as_9a_3_1_writes_it():
    from core import mcinfo
    got = mcinfo.alias_status_change(mcf.CONTENT_TYPE, publish_body(
        ENG[0], ["control-engineer", "control-engineer", "x"], take_over="true"))
    assert got == mcinfo.AliasStatusChange(entity=ENG[0], client_id="client-1",
                                           aliases=("control-engineer", "x"),
                                           take_over=True)
    assert mcinfo.alias_status_change(mcf.CONTENT_TYPE, publish_body(ENG[0], [])).aliases == ()


@pytest.mark.parametrize("body,says", [
    ("<presence/>", "no application/pidf+xml part"),
    (pidf(ENG[0], ["a"]).replace("urn:ietf:params:xml:ns:pidf", "urn:other"),
     "the root element is not PIDF <presence>"),
    (pidf(ENG[0], ["a"]).replace('functionalAliasID="a"', ""),
     "a <functionalAlias> without functionalAliasID"),
    (pidf(ENG[0], ["a"]).replace('entity="sip:e0@utility.example"', ""),
     "expected one <tuple> for the user named in entity"),
    ('<!DOCTYPE x [<!ENTITY a "b">]>' + pidf(ENG[0], ["a"]),
     "document type declarations are not accepted"),
    (pidf(ENG[0], ["a"], take_over="maybe"), "not an xs:boolean"),
], ids=["no-pidf", "not-pidf", "no-alias-id", "no-entity", "a-doctype", "bad-take-over"])
def test_a_pidf_body_that_is_not_9a_3_1_is_refused(body, says):
    from core import mcinfo
    ctype = mcf.CONTENT_TYPE if body != "<presence/>" else "application/xml"
    wrapped = body if body == "<presence/>" else \
        f"--{mcf.BOUNDARY}\r\nContent-Type: application/pidf+xml\r\n\r\n{body}\r\n" \
        f"--{mcf.BOUNDARY}--\r\n"
    with pytest.raises(mcinfo.McInfoError) as exc:
        mcinfo.alias_status_change(ctype, wrapped)
    assert says in str(exc.value)


# ============================================================ PUBLISH, end to end

from tests.test_sip_transport import (  # noqa: E402
    LOCAL, SDP, Flow, invite, msg, network_yaml, pki, sip_env)
from service.runtime import build_runtime  # noqa: E402
from service.sip_core import SipCore  # noqa: E402

__all__ = ["pki"]           # the session fixture, shared


def publish(user, aliases, *, expires="4294967295", take_over=None, cell=None,
            frm=None, entity=None, event="presence", call_id=None, served=None):
    extra = [f"Event: {event}"] if event else []
    if expires is not None:
        extra.append(f"Expires: {expires}")
    return msg("PUBLISH", LOCAL, call_id or f"pub-{user}-{len(aliases)}-{expires}", 1,
               frm or user, LOCAL, extra=extra,
               body=publish_body(served or user, aliases, take_over, cell, entity),
               ctype=mcf.CONTENT_TYPE)


def utility_env(tmp_path, pki, release="19", take_over=()):
    users = ENG + [f"sip:x{i}@utility.example" for i in range(5)]
    net = network_yaml(tmp_path, fname="utility-net.yaml",
                       trusted_cores=["core-client.example"], core_ca=pki / "core-ca.crt",
                       groups=[{"id": "grp:sw", "members": users,
                                "call_type": "switching-order"}],
                       functional_aliases=[{"id": "control-engineer", "users": ENG[:2],
                                            "take_over": list(take_over)}])
    return sip_env(tmp_path, pki, MCX_PROFILE="utility", MCX_RELEASE=release,
                   MCX_NETWORK_FILE=str(net))


def _start(env):
    rt = build_runtime(env, Clock(), platform=Platform())
    return rt, SipCore(rt, LOCAL, Clock())


def _last(flow):
    return flow.messages()[-1]


def test_publish_activates_and_a_switching_order_follows(tmp_path, pki):
    rt, core = _start(utility_env(tmp_path, pki))
    try:
        f = Flow(ENG[0])
        core.on_bytes(publish(ENG[0], ["control-engineer"]), f)
        ok = _last(f)
        assert (ok.code, ok.headers.get("Expires")) == (200, "4294967295")
        assert rt.store.holdings() == [("control-engineer", "", ENG[0])]
        assert rt.health.snapshot()["functional_aliases"] == [
            {"identity": "control-engineer", "slot": "", "holder": ENG[0]}]
        core.on_bytes(invite("sw1", ENG[0], "grp:sw", "prearranged-group"), f)
        admitted = [x for x in rt.store.audit_records("sw1") if x["type"] == "session-admitted"]
        assert [x["detail"]["call_type"] for x in admitted] == ["switching-order"]
        # Expires 0 deactivates all of the user's aliases (9A.2.1.2).
        core.on_bytes(publish(ENG[0], ["control-engineer"], expires="0"), f)
        assert (_last(f).code, _last(f).headers.get("Expires")) == (200, "0")
        assert rt.store.holdings() == []
    finally:
        core.close()
        rt.close()


@pytest.mark.parametrize("release,warning", [
    ("19", '399 mcptt.example "user not authorized to change the functional alias status"'),
    ("20", '399 mcptt.example "201 user not authorized to change the functional alias '
           'status"'),
], ids=["rel-19-no-code", "rel-20-code-201"])
def test_an_activation_not_allowed_is_403_with_the_releases_warning(tmp_path, pki, release,
                                                                     warning):
    rt, core = _start(utility_env(tmp_path, pki, release=release))
    try:
        f = Flow(ENG[2])
        core.on_bytes(publish(ENG[2], ["control-engineer"]), f)
        refused = _last(f)
        assert refused.code == 403
        assert refused.headers.get("Warning") == warning
        assert rt.store.holdings() == []
    finally:
        core.close()
        rt.close()


@pytest.mark.parametrize("kw,code,header", [
    ({"expires": None}, 423, ("Min-Expires", "4294967295")),
    ({"expires": "3600"}, 423, ("Min-Expires", "4294967295")),
    ({"event": "dialog"}, 489, ("Allow-Events", "presence")),
    ({"event": None}, 489, ("Allow-Events", "presence")),
], ids=["no-expires", "a-short-expires", "another-event", "no-event"])
def test_publish_says_what_it_takes(tmp_path, pki, kw, code, header):
    rt, core = _start(utility_env(tmp_path, pki))
    try:
        f = Flow(ENG[0])
        core.on_bytes(publish(ENG[0], ["control-engineer"], **kw), f)
        got = _last(f)
        assert (got.code, got.headers.get(header[0])) == (code, header[1])
        assert rt.store.holdings() == []
    finally:
        core.close()
        rt.close()


@pytest.mark.parametrize("kw,flow_as", [
    ({"served": ENG[1]}, ENG[0]),          # for someone else
    ({}, ENG[1]),                          # a connection that is not the user
], ids=["for-another-user", "not-authenticated"])
def test_only_the_user_changes_the_users_aliases(tmp_path, pki, kw, flow_as):
    rt, core = _start(utility_env(tmp_path, pki))
    try:
        f = Flow(flow_as)
        core.on_bytes(publish(ENG[0], ["control-engineer"], **kw), f)
        got = _last(f)
        assert got.code == 403
        assert "asserted identity is not the authenticated one" in got.headers.get("Warning")
        assert rt.store.holdings() == []
    finally:
        core.close()
        rt.close()


def test_a_pidf_for_another_entity_is_a_bad_request(tmp_path, pki):
    rt, core = _start(utility_env(tmp_path, pki))
    try:
        f = Flow(ENG[0])
        core.on_bytes(publish(ENG[0], ["control-engineer"], entity=ENG[1]), f)
        assert _last(f).code == 400
        assert "the PIDF entity is not the user named in <mcptt-request-uri>" in \
            _last(f).headers.get("Warning")
    finally:
        core.close()
        rt.close()


@pytest.mark.parametrize("release", ["13", "14"])
def test_publish_does_not_exist_before_rel_15(tmp_path, pki, release):
    rt, core = _start(utility_env(tmp_path, pki, release=release))
    try:
        f = Flow(ENG[0])
        core.on_bytes(publish(ENG[0], ["control-engineer"]), f)
        got = _last(f)
        assert got.code == 501 and "PUBLISH" not in got.headers.get("Allow")
        assert rt.store.holdings() == []
    finally:
        core.close()
        rt.close()


def test_the_allow_header_names_publish_from_rel_15():
    from core.release import Release
    from core.sip import allow
    assert allow(Release.REL_14) == "INVITE, ACK, BYE, CANCEL, UPDATE, REGISTER, OPTIONS"
    assert allow(Release.REL_15) == ("INVITE, ACK, BYE, CANCEL, UPDATE, REGISTER, OPTIONS, "
                                     "PUBLISH")


def test_take_over_over_sip(tmp_path, pki):
    rt, core = _start(utility_env(tmp_path, pki, take_over=[ENG[1]]))
    try:
        f0, f1 = Flow(ENG[0]), Flow(ENG[1])
        core.on_bytes(publish(ENG[0], ["control-engineer"]), f0)
        core.on_bytes(publish(ENG[1], ["control-engineer"], call_id="t1"), f1)
        assert _last(f1).code == 403
        assert "functional alias held by another user" in _last(f1).headers.get("Warning")
        core.on_bytes(publish(ENG[1], ["control-engineer"], take_over="true",
                              call_id="t2"), f1)
        assert _last(f1).code == 200
        assert rt.store.holdings() == [("control-engineer", "", ENG[1])]
    finally:
        core.close()
        rt.close()


def test_holders_survive_a_restart(tmp_path, pki):
    env = utility_env(tmp_path, pki)
    rt, core = _start(env)
    core.on_bytes(publish(ENG[0], ["control-engineer"]), Flow(ENG[0]))
    core.close()
    rt.close()
    rt2, core2 = _start(env)
    try:
        assert rt2.manager.functional.holdings() == (Holding("control-engineer", "", ENG[0]),)
        assert tuple(rt2.loaded.hooks.identity_resolver.identities_of(ENG[0])) == \
            ("control-engineer",)
    finally:
        core2.close()
        rt2.close()


def frmcs_env(tmp_path, pki):
    net = network_yaml(tmp_path, fname="frmcs-net.yaml", trusted_cores=["core-client.example"],
                       core_ca=pki / "core-ca.crt", users=DRV,
                       cells=[{"cell": CELL_S1, "location": {"track_section": "S1"}},
                              {"cell": CELL_S2, "location": {"track_section": "S2"}}],
                       functional_aliases=[{"id": "track-controller", "users": DRV,
                                            "take_over": []}])
    return sip_env(tmp_path, pki, MCX_PROFILE="frmcs", MCX_RELEASE="19",
                   MCX_NETWORK_FILE=str(net))


def test_the_location_is_the_publishes_or_else_the_last_reported_cell(tmp_path, pki):
    """Owner decision 2026-10-23: the PUBLISH's location report decides; with
    none, the cell the user last reported; with neither, refused."""
    rt, core = _start(frmcs_env(tmp_path, pki))
    try:
        f0, f1 = Flow(DRV[0]), Flow(DRV[1])
        core.on_bytes(publish(DRV[0], ["track-controller"], call_id="l0"), f0)
        assert _last(f0).code == 403
        assert "no location to hold the functional alias at" in _last(f0).headers.get("Warning")
        core.on_bytes(publish(DRV[0], ["track-controller"], cell=CELL_S1, call_id="l1"), f0)
        assert _last(f0).code == 200
        # DRV[1] reports S2 on a call, then publishes with no location.
        sdp = SDP
        body = mcf.with_parts(sdp, mcf.mcinfo_xml("private", DRV[2]),
                              (mcf.CT_LOCATION, mcf.location_report(ecgi=CELL_S2)))
        core.on_bytes(msg("INVITE", LOCAL, "c-s2", 1, DRV[1], LOCAL, body=body,
                          ctype=mcf.CONTENT_TYPE), f1)
        core.on_bytes(publish(DRV[1], ["track-controller"], call_id="l2"), f1)
        assert _last(f1).code == 200, f1.codes()
        assert rt.store.holdings() == [("track-controller", "S1", DRV[0]),
                                       ("track-controller", "S2", DRV[1])]
    finally:
        core.close()
        rt.close()


def test_a_store_failing_is_a_500_with_nothing_changed(tmp_path, pki, monkeypatch):
    """Review SVC-OP-06 #2, end to end: the store is written ahead, so a
    store that fails leaves no role held and nothing to restore."""
    env = utility_env(tmp_path, pki)
    rt, core = _start(env)
    try:
        def failing(_):
            raise OSError("disk I/O error")
        monkeypatch.setattr(rt.store, "save_holdings", failing)
        f = Flow(ENG[0])
        core.on_bytes(publish(ENG[0], ["control-engineer"]), f)
        assert _last(f).code == 500
        assert rt.manager.functional.holdings() == ()
        assert tuple(rt.loaded.hooks.identity_resolver.identities_of(ENG[0])) == ()
    finally:
        core.close()
        rt.close()


def test_a_200_carries_an_entity_tag(tmp_path, pki):
    """RFC 3903 6: a 2xx to PUBLISH carries SIP-ETag."""
    rt, core = _start(utility_env(tmp_path, pki))
    try:
        f = Flow(ENG[0])
        core.on_bytes(publish(ENG[0], ["control-engineer"]), f)
        etag = _last(f).headers.get("SIP-ETag")
        assert _last(f).code == 200 and len(etag) == 16 and int(etag, 16) >= 0
    finally:
        core.close()
        rt.close()


def test_a_release_without_activation_leaves_the_stored_holders(tmp_path, pki):
    """Review SVC-OP-06 #7: started at Rel-14 by mistake, nothing is bound
    and nothing lost; back at Rel-19 the holder is restored."""
    env = utility_env(tmp_path, pki)
    rt, core = _start(env)
    core.on_bytes(publish(ENG[0], ["control-engineer"]), Flow(ENG[0]))
    core.close()
    rt.close()
    rt, core = _start(dict(env, MCX_RELEASE="14"))
    try:
        assert rt.manager.functional.holdings() == ()
        assert rt.store.holdings() == [("control-engineer", "", ENG[0])]
    finally:
        core.close()
        rt.close()
    rt, core = _start(env)
    try:
        assert rt.manager.functional.holdings() == (Holding("control-engineer", "", ENG[0]),)
    finally:
        core.close()
        rt.close()


def test_a_refused_publish_does_not_set_the_last_reported_cell(tmp_path, pki):
    """Review SVC-OP-06 #4: only an accepted PUBLISH's location is kept."""
    rt, core = _start(frmcs_env(tmp_path, pki))
    try:
        f = Flow(DRV[0])
        core.on_bytes(publish(DRV[0], ["train-driver"], cell=CELL_S2, call_id="r1"), f)
        assert _last(f).code == 403 and core.last_location == {}
        core.on_bytes(publish(DRV[0], ["track-controller"], call_id="r2"), f)
        assert "no location to hold the functional alias at" in _last(f).headers.get("Warning")
        # An accepted one's is: the next PUBLISH with none is held there.
        core.on_bytes(publish(DRV[0], ["track-controller"], cell=CELL_S1, call_id="r3"), f)
        core.on_bytes(publish(DRV[0], [], expires="0", call_id="r4"), f)
        core.on_bytes(publish(DRV[0], ["track-controller"], call_id="r5"), f)
        assert _last(f).code == 200
        assert rt.store.holdings() == [("track-controller", "S1", DRV[0])]
    finally:
        core.close()
        rt.close()


def test_a_store_failing_after_the_resolver_is_recorded_end_to_end(tmp_path, pki,
                                                                  monkeypatch):
    """Re-review SVC-OP-06 Q2: take-over, the second store write fails; 500,
    the holder kept, and the attempt recorded."""
    rt, core = _start(utility_env(tmp_path, pki, take_over=[ENG[1]]))
    try:
        core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="a"), Flow(ENG[0]))
        real, calls = rt.store.save_holdings, []

        def second_fails(held):
            calls.append(held)
            if len(calls) == 2:
                raise OSError("disk I/O error")
            return real(held)
        monkeypatch.setattr(rt.store, "save_holdings", second_fails)
        f = Flow(ENG[1])
        core.on_bytes(publish(ENG[1], ["control-engineer"], take_over="true", call_id="b"), f)
        assert _last(f).code == 500
        assert rt.manager.functional.holdings() == (Holding("control-engineer", "", ENG[0]),)
        recs = [x["detail"] for x in rt.store.audit_records("b") if x["type"] == "binding-changed"]
        assert recs == [{"action": "not-persisted", "stage": "after-resolver", "user": ENG[1],
                         "wanted": ["control-engineer"], "detail": "disk I/O error"}]
    finally:
        core.close()
        rt.close()
