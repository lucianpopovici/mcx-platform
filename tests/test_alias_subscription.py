"""Functional alias status determination (PLT-VP-R1 FA-OP-01 item 1; TS 24.379
9A.2.1.3, 9A.2.2.2.4-5, 9A.3.1): a user's SUBSCRIBE to the presence event,
and the NOTIFYs telling it which functional aliases it holds and which it may
take over.

Requests and expected bodies are written by hand here, not rendered by the
code under test.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.functional import AliasPolicy, Holding  # noqa: E402
from tests import mcpttinfo_fixture as mcf  # noqa: E402
from tests.test_functional_alias import (  # noqa: E402
    DRV, ENG, LOCAL, Flow, _manager, _start, _utility, msg, network_yaml, publish,
    sip_env, utility_env)
from tests.test_sip_transport import pki  # noqa: E402,F401

__all__ = ["pki"]

MAX = 4294967295
PIDF_NS = "urn:ietf:params:xml:ns:pidf"
FA_NS = "urn:3gpp:ns:mcpttPresInfoFA:1.0"


# ============================================================ the NOTIFY body (9A.3.1)


def test_the_status_document_is_the_9a_3_1_per_user_form():
    from core.mcinfo import alias_status_document
    got = alias_status_document("sip:e0@utility.example", "client-1",
                                [("control-engineer", "activated"),
                                 ('a"<&>', "take-over-possible")], p_id_fa="p&1")
    assert got == (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        '<presence xmlns="urn:ietf:params:xml:ns:pidf" '
        'xmlns:mcpttPIFA10="urn:3gpp:ns:mcpttPresInfoFA:1.0" '
        'entity="sip:e0@utility.example"><tuple id="client-1"><status>'
        '<mcpttPIFA10:functionalAlias functionalAliasID="control-engineer" '
        'status="activated"/>'
        '<mcpttPIFA10:functionalAlias functionalAliasID="a&quot;&lt;&amp;&gt;" '
        'status="take-over-possible"/>'
        '</status></tuple><mcpttPIFA10:p-id-fa>p&amp;1</mcpttPIFA10:p-id-fa>'
        '</presence>\r\n')
    root = ET.fromstring(got.split("\r\n", 1)[1])
    fas = root.findall(f"{{{PIDF_NS}}}tuple/{{{PIDF_NS}}}status/{{{FA_NS}}}functionalAlias")
    assert [(f.get("functionalAliasID"), f.get("status")) for f in fas] == [
        ("control-engineer", "activated"), ('a"<&>', "take-over-possible")]
    # RFC 3863: a <presence> holds its tuples first, then other namespaces.
    assert [c.tag for c in root] == [f"{{{PIDF_NS}}}tuple", f"{{{FA_NS}}}p-id-fa"]
    assert "p-id-fa" not in alias_status_document("sip:e0@utility.example", "c", [])
    # An empty p-id-fa is still the request's, and echoed (9A.2.2.2.5 2c).
    assert "<mcpttPIFA10:p-id-fa></mcpttPIFA10:p-id-fa>" in \
        alias_status_document("sip:e0@utility.example", "c", [], p_id_fa="")
    assert 'status="a&amp;b"' in alias_status_document("sip:e0@utility.example", "c",
                                                        [("x", "a&b")])


def test_request_type_and_p_id_fa_are_read():
    from core import mcinfo
    info = mcinfo.parse(subscribe_info(ENG[0]))
    assert info.request_type == "functional-alias-status-determination"
    assert mcinfo.parse(subscribe_info(ENG[0], rtype=None)).request_type is None
    from tests.test_functional_alias import publish_body
    change = mcinfo.alias_status_change(mcf.CONTENT_TYPE,
                                        publish_body(ENG[0], ["control-engineer"]))
    assert change.p_id_fa == "abc"


# ============================================================ what a user is told


def test_a_holder_is_told_activated_and_one_who_may_take_over_take_over_possible():
    mgr, _, _ = _utility(take_over=[ENG[1]])
    f = mgr.functional
    assert f.status_of(ENG[0]) == ()
    assert mgr.change_functional_aliases("p0", ENG[0], ["control-engineer"], False,
                                         None).accepted
    assert f.status_of(ENG[0]) == (("control-engineer", "activated"),)
    assert f.status_of(ENG[1]) == (("control-engineer", "take-over-possible"),)
    assert f.status_of(ENG[2]) == ()            # not one of its users
    mgr2, _, _ = _utility()                      # nobody may take over
    mgr2.change_functional_aliases("p0", ENG[0], ["control-engineer"], False, None)
    assert mgr2.functional.status_of(ENG[1]) == ()


def test_take_over_possible_needs_the_user_to_be_one_who_may_hold_it():
    """Only one of the alias's users is told it may take it over; a take_over
    entry that is not one of them (the network profile refuses that, a core
    policy can carry it) gives nothing."""
    mgr, _, _ = _manager("utility", ENG, {"control-engineer": AliasPolicy(
        users=frozenset(ENG[:2]), take_over=frozenset([ENG[1], ENG[2]]))})
    mgr.change_functional_aliases("p0", ENG[0], ["control-engineer"], False, None)
    assert mgr.functional.status_of(ENG[1]) == (("control-engineer", "take-over-possible"),)
    assert mgr.functional.status_of(ENG[2]) == ()


def test_an_identity_that_resolves_to_a_group_is_never_one_to_take_over():
    from tests.test_functional_alias import _frmcs
    mgr, _, _ = _frmcs()
    mgr.functional._policy["rec-area"] = AliasPolicy(users=frozenset(DRV),
                                                     take_over=frozenset(DRV))
    mgr.functional.add(Holding("rec-area", "S1", DRV[0]))
    mgr.functional._policy["rec-area"] = AliasPolicy(users=frozenset(DRV),
                                                     take_over=frozenset(DRV), max_holders=1)
    assert mgr.functional.status_of(DRV[1]) == ()


def test_a_keyed_alias_is_written_in_the_users_own_domain():
    import dataclasses
    mgr, loaded, _ = _manager("frmcs", DRV, {"train-driver": AliasPolicy(
        users=frozenset(DRV + ["sip:d9@rail2.example"]))})
    p = loaded.profile
    mgr.functional._profile = dataclasses.replace(p, identity=dataclasses.replace(
        p.identity, domains=["frmcs.example", "rail2.example"]))
    mgr.functional.add(Holding("train-driver", "T1", "sip:d9@rail2.example"))
    mgr.functional.add(Holding("train-driver", "T2", "sip:d9@Rail2.example"))
    assert mgr.functional.status_of("sip:d9@rail2.example") == (
        ("sip:T1.train-driver@rail2.example", "activated"),)
    assert mgr.functional.status_of("sip:d9@Rail2.example") == (
        ("sip:T2.train-driver@rail2.example", "activated"),)


def test_take_over_possible_needs_the_identity_held_to_its_limit(monkeypatch):
    import dataclasses
    mgr, loaded, _ = _manager("utility", ENG, {"control-engineer": AliasPolicy(
        users=frozenset(ENG), take_over=frozenset([ENG[2]]), max_holders=2)})
    cls = type(loaded.profile)
    real = cls.functional_identity
    multi = dataclasses.replace(real(loaded.profile, "control-engineer"),
                                multiplicity="multi")
    monkeypatch.setattr(cls, "functional_identity",
                        lambda self, i: multi if i == "control-engineer" else real(self, i))
    mgr.change_functional_aliases("p0", ENG[0], ["control-engineer"], False, None)
    assert mgr.functional.status_of(ENG[2]) == ()          # one of two
    mgr.change_functional_aliases("p1", ENG[1], ["control-engineer"], False, None)
    assert mgr.functional.status_of(ENG[2]) == (("control-engineer", "take-over-possible"),)
    # Without a limit there is always room, so nothing to take over.
    mgr2, loaded2, _ = _manager("utility", ENG, {"control-engineer": AliasPolicy(
        users=frozenset(ENG), take_over=frozenset([ENG[2]]))})
    for cid, user in (("q0", ENG[0]), ("q1", ENG[1])):
        mgr2.change_functional_aliases(cid, user, ["control-engineer"], False, None)
    assert mgr2.functional.status_of(ENG[2]) == ()


def test_a_keyed_identity_is_written_as_it_is_activated():
    mgr, _, _ = _manager("frmcs", DRV, {"train-driver": AliasPolicy(
        users=frozenset(DRV), take_over=frozenset(DRV[1:]), values=("T*",))})
    mgr.change_functional_aliases("p0", DRV[0], ["sip:T1.train-driver@FRMCS.example"],
                                  False, None)
    mgr.change_functional_aliases("p1", DRV[1], ["sip:T2.train-driver@frmcs.example"],
                                  False, None)
    f = mgr.functional
    assert f.status_of(DRV[0]) == (("sip:T1.train-driver@frmcs.example", "activated"),)
    assert f.status_of(DRV[1]) == (("sip:T1.train-driver@frmcs.example", "take-over-possible"),
                                   ("sip:T2.train-driver@frmcs.example", "activated"))
    assert f.status_of(DRV[2]) == (("sip:T1.train-driver@frmcs.example", "take-over-possible"),
                                   ("sip:T2.train-driver@frmcs.example", "take-over-possible"))
    # A value the user may not hold is not one it may take over.
    f.add(Holding("train-driver", "X9", DRV[0]))
    assert "sip:X9.train-driver@frmcs.example" not in dict(f.status_of(DRV[2]))
    # A user outside the profile's domains is told in the profile's domain.
    assert f.status_of("sip:z@elsewhere.example") == ()


def test_a_location_dependent_identity_is_one_alias():
    from tests.test_functional_alias import CELL_S1, CELL_S2, _frmcs
    from core.hooks import LocationContext
    mgr, _, _ = _frmcs(take_over=[DRV[0]])
    for cid, user, cell in (("a", DRV[0], CELL_S1), ("b", DRV[1], CELL_S2)):
        assert mgr.change_functional_aliases(cid, user, ["track-controller"], False,
                                             LocationContext(cell_id=cell)).accepted
    # DRV[0] holds it at S1: it is told it holds it.
    assert mgr.functional.status_of(DRV[0]) == (("track-controller", "activated"),)
    assert mgr.functional.status_of(DRV[2]) == ()
    # One allowed to take over is not told take-over-possible: whether its
    # activation takes the alias over depends on where it is then (review).
    mgr2, _, _ = _frmcs(take_over=[DRV[2]])
    mgr2.change_functional_aliases("b", DRV[1], ["track-controller"], False,
                                   LocationContext(cell_id=CELL_S2))
    assert mgr2.functional.status_of(DRV[2]) == ()


# ============================================================ SUBSCRIBE, end to end


def subscribe_info(user, rtype="functional-alias-status-determination"):
    ext = f"<anyExt><request-type>{rtype}</request-type></anyExt>" if rtype else ""
    return (f'<?xml version="1.0" encoding="UTF-8"?>\r\n<mcpttinfo xmlns="{mcf.NS}">'
            f'<mcptt-Params><mcptt-request-uri type="Normal"><mcpttURI>{user}</mcpttURI>'
            f"</mcptt-request-uri>{ext}</mcptt-Params></mcpttinfo>")


def subscribe(user, *, expires=str(MAX), call_id=None, cseq=1, to_tag=None, frm=None,
              served=None, event="presence", accept="application/pidf+xml",
              contact=None, rtype="functional-alias-status-determination", extra=(),
              body=True, from_tag="st"):
    h = [f"Event: {event}"] if event else []
    if expires is not None:
        h.append(f"Expires: {expires}")
    if accept is not None:
        h.append(f"Accept: {accept}")
    if contact is not False:
        h.append(f"Contact: <{contact or user}>")
    h += list(extra)
    return msg("SUBSCRIBE", LOCAL, call_id or f"sub-{user}", cseq, frm or user, LOCAL,
               to_tag=to_tag, from_tag=from_tag, extra=h,
               body=subscribe_info(served or user, rtype) if body else "",
               ctype=mcf.CT_MCINFO if body else None)


def answered(flow, code=200):
    """The subscriber answers every NOTIFY it has not answered yet."""
    out = []
    for n in flow.requests("NOTIFY")[len(getattr(flow, "_answered", [])):]:
        lines = [f"SIP/2.0 {code} X"] + [f"Via: {v}" for v in n.headers.get_all("Via")]
        for name in ("From", "To", "Call-ID", "CSeq"):
            lines.append(f"{name}: {n.headers.get(name)}")
        out.append(("\r\n".join(lines + ["Content-Length: 0"]) + "\r\n\r\n").encode())
    flow._answered = flow.requests("NOTIFY")
    return out


def responses(flow):
    return [m for m in flow.messages() if getattr(m, "code", None)]


def statuses(notify):
    root = ET.fromstring(notify.body.split("\r\n", 1)[1])
    fas = root.findall(f"{{{PIDF_NS}}}tuple/{{{PIDF_NS}}}status/{{{FA_NS}}}functionalAlias")
    pid = root.find(f"{{{FA_NS}}}p-id-fa")
    return (root.get("entity"), root.find(f"{{{PIDF_NS}}}tuple").get("id"),
            [(f.get("functionalAliasID"), f.get("status")) for f in fas],
            pid.text if pid is not None else None)


@pytest.fixture
def started(tmp_path, pki):  # noqa: F811
    rt, core = _start(utility_env(tmp_path, pki, take_over=[ENG[1]]))
    yield rt, core
    core.close()
    rt.close()


def test_a_subscription_is_answered_200_and_a_notify_follows(started):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0], extra=["Record-Route: <sip:p1.example;lr>",
                                           "Record-Route: <sip:p2.example;lr>"]), f)
    ok, notify = f.messages()
    assert ok.code == 200
    assert ok.headers.get("Expires") == str(MAX)
    assert ok.headers.get("Contact") == f"<{LOCAL}>"
    local_tag = ok.headers.get("To").split("tag=")[1]
    # RFC 3261 12.1.1: the route set comes back on the dialog-creating 200.
    assert list(ok.headers.get_all("Record-Route")) == ["<sip:p1.example;lr>", "<sip:p2.example;lr>"]
    assert notify.method == "NOTIFY" and notify.uri == ENG[0]
    assert list(notify.headers.get_all("Route")) == ["<sip:p1.example;lr>", "<sip:p2.example;lr>"]
    assert notify.headers.get("From") == f"<{LOCAL}>;tag={local_tag}"
    assert notify.headers.get("To") == f"<{ENG[0]}>;tag=st"
    assert notify.headers.get("Call-ID") == f"sub-{ENG[0]}"
    assert notify.headers.get("CSeq") == "1 NOTIFY"
    assert notify.headers.get("Event") == "presence"
    assert notify.headers.get("Subscription-State") == f"active;expires={MAX}"
    assert notify.headers.get("Content-Type") == "application/pidf+xml"
    assert notify.headers.get("Contact") == f"<{LOCAL}>"
    # Before any PUBLISH the platform knows no client ID of the user's.
    client = "mcx-" + hashlib.sha256(ENG[0].encode()).hexdigest()[:12]
    assert statuses(notify) == (ENG[0], client, [], None)
    assert list(core.alias_subs) == [(f"sub-{ENG[0]}", "st", "")]


def test_each_change_is_notified_to_whom_it_concerns(started):
    rt, core = started
    f0, f1, f2 = Flow(ENG[0]), Flow(ENG[1]), Flow(ENG[2])
    for u, f in ((ENG[0], f0), (ENG[1], f1), (ENG[2], f2)):
        core.on_bytes(subscribe(u), f)
    for f in (f0, f1, f2):
        f.sent.clear()
    core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="a"), f0)
    ok, notify = f0.messages()
    # The publisher's NOTIFY follows the 200 and echoes the p-id-fa.
    assert (ok.code, notify.headers.get("CSeq")) == (200, "2 NOTIFY")
    assert statuses(notify) == (ENG[0], "client-1", [("control-engineer", "activated")],
                                "abc")
    # e1 may take it over; e2 may not hold it and hears nothing.
    [n1] = f1.requests("NOTIFY")
    assert statuses(n1)[2:] == ([("control-engineer", "take-over-possible")], None)
    assert f2.sent == []
    # e1 takes it over: e0 is told it no longer holds it, e1 that it does.
    core.on_bytes(publish(ENG[1], ["control-engineer"], take_over="true", call_id="b"), f1)
    assert statuses(f0.requests("NOTIFY")[-1])[2:] == ([], None)
    assert statuses(f1.requests("NOTIFY")[-1])[2:] == (
        [("control-engineer", "activated")], "abc")
    assert f2.sent == []


def test_a_publish_that_changes_nothing_is_still_told_to_its_publisher_only(started):
    rt, core = started
    f0, f1 = Flow(ENG[0]), Flow(ENG[1])
    core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="a"), f0)
    for u, f in ((ENG[0], f0), (ENG[1], f1)):
        core.on_bytes(subscribe(u), f)
        f.sent.clear()
    core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="again"), f0)
    assert [m.code if hasattr(m, "code") else m.method for m in f0.messages()] == [
        200, "NOTIFY"]
    assert f1.sent == []
    # A refused PUBLISH tells nobody: its answer said it all.
    core.on_bytes(publish(ENG[1], ["control-engineer"], call_id="no"), f1)
    assert [m.code for m in f1.messages()] == [403]
    assert len(f0.requests("NOTIFY")) == 1


def test_expires_0_fetches_the_status_and_keeps_no_subscription(started):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="a"), f)
    f.sent.clear()
    core.on_bytes(subscribe(ENG[0], expires="0"), f)
    ok, notify = f.messages()
    assert (ok.code, ok.headers.get("Expires")) == (200, "0")
    assert notify.headers.get("Subscription-State") == "terminated;reason=timeout"
    assert statuses(notify)[2] == [("control-engineer", "activated")]
    assert core.alias_subs == {}


def test_a_subscription_without_expires_lasts_the_package_default(started):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0], expires=None), f)
    ok, notify = f.messages()
    assert ok.headers.get("Expires") == "3600"
    assert notify.headers.get("Subscription-State") == "active;expires=3600"


def test_a_subscription_is_refreshed_and_ended_in_its_dialog(started):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0]), f)
    tag = f.messages()[0].headers.get("To").split("tag=")[1]
    f.sent.clear()
    moved = Flow(ENG[0])                     # the subscriber reconnected
    core.on_bytes(subscribe(ENG[0], cseq=2, to_tag=tag, expires="600", body=False,
                            contact="sip:e0@10.0.0.9"), moved)
    ok, notify = moved.messages()
    assert (ok.code, ok.headers.get("Expires")) == (200, "600")
    assert notify.headers.get("Subscription-State") == "active;expires=600"
    assert (notify.uri, notify.headers.get("CSeq")) == ("sip:e0@10.0.0.9", "2 NOTIFY")
    assert f.sent == []
    # Out of order (RFC 3261 12.2.2), a wrong tag and a stranger are each
    # refused. CSeq 3 is new to the guard, and lower than 5.
    core.on_bytes(subscribe(ENG[0], cseq=5, to_tag=tag, body=False), moved)
    assert responses(moved)[-1].code == 200
    core.on_bytes(subscribe(ENG[0], cseq=3, to_tag=tag, body=False), moved)
    assert responses(moved)[-1].code == 500
    core.on_bytes(subscribe(ENG[0], cseq=6, to_tag="other", body=False), moved)
    assert responses(moved)[-1].code == 481
    core.on_bytes(subscribe(ENG[0], cseq=7, to_tag=tag, body=False), Flow(ENG[1]))
    assert core.alias_subs[(f"sub-{ENG[0]}", "st", "")].flow is moved
    # De-subscribe: 200, a terminated NOTIFY, and no subscription after.
    moved.sent.clear()
    core.on_bytes(subscribe(ENG[0], cseq=8, to_tag=tag, expires="0", body=False), moved)
    ok, notify = moved.messages()
    assert (ok.code, ok.headers.get("Expires")) == (200, "0")
    assert notify.headers.get("Subscription-State") == "terminated;reason=timeout"
    assert core.alias_subs == {}
    core.on_bytes(subscribe(ENG[0], cseq=9, to_tag=tag, body=False), moved)
    assert responses(moved)[-1].code == 481


def test_a_stranger_cannot_refresh_another_users_subscription(started):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0]), f)
    tag = f.messages()[0].headers.get("To").split("tag=")[1]
    other = Flow(ENG[1])
    core.on_bytes(subscribe(ENG[0], cseq=2, to_tag=tag, expires="0", body=False), other)
    assert other.messages()[-1].code == 403
    assert len(core.alias_subs) == 1


def test_a_subscription_ends_when_it_expires(started):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0], expires="60"), f)
    for r in answered(f):                    # else Timer F ends it first
        core.on_bytes(r, f)
    f.sent.clear()
    core.clock.now += 59_000
    core.tick()
    assert f.sent == [] and len(core.alias_subs) == 1
    core.clock.now += 1_000
    core.tick()
    [notify] = f.requests("NOTIFY")
    assert notify.headers.get("Subscription-State") == "terminated;reason=timeout"
    assert core.alias_subs == {}


@pytest.mark.parametrize("code,kept", [(200, True), (481, False), (500, True)])
def test_a_notify_answered_481_ends_the_subscription(started, code, kept):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0]), f)
    for r in answered(f, code):
        core.on_bytes(r, f)
    assert bool(core.alias_subs) is kept
    assert len(core.client) == 0          # the NOTIFY's transaction is done


def test_a_notify_that_times_out_waits_for_the_next_connection(started):
    """RFC 6665 4.2.2 lets it end the subscription; a 9A client never
    refreshes to learn that, so it waits, and is told on the user's next
    registration (review)."""
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0]), f)
    core.clock.now += 64 * 500 + 1
    core.tick()
    sub = core.alias_subs[(f"sub-{ENG[0]}", "st", "")]
    assert (sub.flow, sub.last) == (None, None)
    back = Flow(ENG[0])
    core.on_bytes(msg("REGISTER", "sip:utility.example", "r0", 1, ENG[0], ENG[0],
                      extra=[f"Contact: <{ENG[0]}>"]), back)
    # The 200 first, then the NOTIFY (review).
    assert [getattr(m, "code", None) or m.method for m in back.messages()] == [
        200, "NOTIFY"]
    assert back.requests("NOTIFY")[0].headers.get("CSeq") == "2 NOTIFY"
    assert core.alias_subs[(f"sub-{ENG[0]}", "st", "")].flow is back


def test_a_notify_whose_send_fails_is_told_on_the_next_connection(started):
    rt, core = started
    f0, f1 = Flow(ENG[0]), Flow(ENG[1])
    core.on_bytes(subscribe(ENG[1]), f1)

    def dead(text):
        raise OSError("connection reset")
    f1.send = dead
    core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="a"), f0)
    assert f0.codes() == [200]
    sub = core.alias_subs[(f"sub-{ENG[1]}", "st", "")]
    assert (sub.flow, sub.last) == (None, ())       # not told, and known not to be
    back = Flow(ENG[1])
    core.on_bytes(msg("REGISTER", "sip:utility.example", "r1", 1, ENG[1], ENG[1],
                      extra=[f"Contact: <{ENG[1]}>"]), back)
    [notify] = back.requests("NOTIFY")
    assert statuses(notify)[2] == [("control-engineer", "take-over-possible")]


def test_a_client_that_restarts_is_not_locked_out(started):
    """Each restart subscribes anew and leaves the last subscription with no
    connection: the oldest of those makes room (review)."""
    rt, core = started
    for i in range(10):
        f = Flow(ENG[0])
        core.on_bytes(subscribe(ENG[0], call_id=f"boot{i}"), f)
        assert f.codes() == [200], i
        core.on_flow_closed(f)
    assert sorted(k[0] for k in core.alias_subs) == [f"boot{i}" for i in range(2, 10)]
    # Live ones are not made room by: the ninth live subscription is refused.
    live = [Flow(ENG[1]) for _ in range(9)]
    for i, f in enumerate(live):
        core.on_bytes(subscribe(ENG[1], call_id=f"live{i}"), f)
    assert live[8].codes() == [403]


def test_stale_subscriptions_are_probed_when_the_user_registers(started):
    rt, core = started
    old = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0], call_id="old"), old)
    core.on_flow_closed(old)
    new = Flow(ENG[0])
    core.on_bytes(msg("REGISTER", "sip:utility.example", "r0", 1, ENG[0], ENG[0],
                      extra=[f"Contact: <{ENG[0]}>"]), new)
    # Nothing changed, but it had no connection: it is told, and its client,
    # which no longer knows it, answers 481 and it goes.
    for r in answered(new, 481):
        core.on_bytes(r, new)
    assert core.alias_subs == {}


def test_a_subscription_outlives_its_connection(started):
    """A 9A client asks for 4294967295 s and never refreshes (9A.2.1.3), so
    its subscription is kept when its connection closes, and what changed
    meanwhile is told on the connection it registers next (review)."""
    rt, core = started
    f0, f1 = Flow(ENG[0]), Flow(ENG[1])
    core.on_bytes(subscribe(ENG[0]), f0)
    core.on_bytes(subscribe(ENG[1]), f1)
    core.on_flow_closed(f1)
    assert [s.subscriber for s in core.alias_subs.values()] == [ENG[0], ENG[1]]
    assert core.alias_subs[(f"sub-{ENG[1]}", "st", "")].flow is None
    f1.sent.clear()
    core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="a"), f0)
    assert f1.sent == []                       # nowhere to send it yet
    back = Flow(ENG[1])
    core.on_bytes(msg("REGISTER", "sip:utility.example", "r0", 1, ENG[1], ENG[1],
                      extra=[f"Contact: <{ENG[1]}>"]), back)
    [notify] = back.requests("NOTIFY")
    assert notify.headers.get("CSeq") == "2 NOTIFY"
    assert statuses(notify)[2] == [("control-engineer", "take-over-possible")]
    # Told once there, it is not told again of nothing.
    core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="b"), f0)
    assert len(back.requests("NOTIFY")) == 1
    core.on_bytes(publish(ENG[0], [], expires="0", call_id="c"), f0)
    assert statuses(back.requests("NOTIFY")[-1])[2] == []   # and now it follows


def test_a_notify_goes_to_the_registered_connection_once_its_own_closed(tmp_path, pki):  # noqa: F811
    rt, core = _start(utility_env(tmp_path, pki, take_over=[ENG[0]]))
    try:
        f0, f1 = Flow(ENG[0]), Flow(ENG[1])
        core.on_bytes(subscribe(ENG[0]), f0)
        core.on_flow_closed(f0)
        reg = Flow(ENG[0])
        core.on_bytes(msg("REGISTER", "sip:utility.example", "r0", 1, ENG[0], ENG[0],
                          extra=[f"Contact: <{ENG[0]}>"]), reg)
        # It had no connection, so it is told on this one, changed or not.
        assert [statuses(n)[2] for n in reg.requests("NOTIFY")] == [[]]
        core.on_bytes(publish(ENG[1], ["control-engineer"], call_id="a"), f1)
        notify = reg.requests("NOTIFY")[-1]
        assert statuses(notify)[2] == [("control-engineer", "take-over-possible")]
    finally:
        core.close()
        rt.close()


def test_another_users_dialog_identifiers_change_nothing(started):
    rt, core = started
    f0, f1 = Flow(ENG[0]), Flow(ENG[1])
    core.on_bytes(subscribe(ENG[0]), f0)
    core.on_bytes(subscribe(ENG[1], call_id=f"sub-{ENG[0]}", cseq=2, expires="0"), f1)
    assert [m.code for m in f1.messages()] == [403]
    assert [s.subscriber for s in core.alias_subs.values()] == [ENG[0]]


def test_the_same_dialog_subscribed_again_is_the_same_subscription(started):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0]), f)
    core.on_bytes(subscribe(ENG[0], cseq=2, expires="600"), f)
    notifies = f.requests("NOTIFY")
    assert [n.headers.get("CSeq") for n in notifies] == ["1 NOTIFY", "2 NOTIFY"]
    assert notifies[1].headers.get("Subscription-State") == "active;expires=600"
    assert len(core.alias_subs) == 1
    core.on_bytes(subscribe(ENG[0], cseq=3, expires="0"), f)
    last = f.requests("NOTIFY")[-1]
    assert (last.headers.get("CSeq"), last.headers.get("Subscription-State")) == (
        "3 NOTIFY", "terminated;reason=timeout")
    assert core.alias_subs == {}


def test_a_fault_after_the_200_is_not_a_second_answer(started, monkeypatch, caplog):
    rt, core = started

    def broken(user):
        raise RuntimeError("boom")
    monkeypatch.setattr(rt.manager.functional, "status_of", broken)
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0]), f)
    assert f.codes() == [200]
    tag = f.messages()[0].headers.get("To").split("tag=")[1]
    core.on_bytes(subscribe(ENG[0], cseq=2, to_tag=tag, body=False), f)
    assert f.codes() == [200, 200]
    assert "functional alias status NOTIFY to sip:e0@utility.example failed" in caplog.text


def test_a_publish_that_faults_after_the_change_sends_no_p_id_fa(started, monkeypatch):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0]), f)
    f.sent.clear()
    real = core._final

    def final(txn, resp):
        if txn.request.method == "PUBLISH" and resp.status.code == 200:
            raise RuntimeError("boom")
        return real(txn, resp)
    monkeypatch.setattr(core, "_final", final)
    core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="a"), f)
    assert f.codes() == [500]
    [notify] = f.requests("NOTIFY")
    assert statuses(notify)[2:] == ([("control-engineer", "activated")], None)


def test_all_users_together_have_a_bound(started, monkeypatch):
    import service.sip_core as sc
    monkeypatch.setattr(sc, "MAX_ALIAS_SUBSCRIPTIONS", 2)
    rt, core = started
    for u in ENG:
        core.on_bytes(subscribe(u), Flow(u))
    f = Flow(ENG[2])
    core.on_bytes(subscribe(ENG[2], call_id="more"), f)
    assert len(core.alias_subs) == 2
    got = f.messages()[0]
    assert got.code == 503
    assert got.headers.get("Warning") == '399 mcx "at most 2 functional alias subscriptions"'


def test_compact_event_header_is_read(started):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0], event=None, extra=["o: presence"]), f)
    assert f.codes()[0] == 200


def test_the_event_id_is_part_of_the_subscription(started):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0], event="presence;id=7"), f)
    notify = f.requests("NOTIFY")[0]
    assert notify.headers.get("Event") == "presence;id=7"
    assert list(core.alias_subs) == [(f"sub-{ENG[0]}", "st", "7")]


def test_one_user_has_at_most_eight_subscriptions(started):
    rt, core = started
    f = Flow(ENG[0])
    for i in range(8):
        core.on_bytes(subscribe(ENG[0], call_id=f"s{i}"), f)
    core.on_bytes(subscribe(ENG[0], call_id="s8"), f)
    refused = responses(f)[-1]
    assert refused.code == 403
    assert refused.headers.get("Warning") == \
        '399 mcx "at most 8 functional alias subscriptions per user"'
    # A fetch keeps nothing, and a subscription made again is not one more.
    core.on_bytes(subscribe(ENG[0], call_id="s9", expires="0"), f)
    assert responses(f)[-1].code == 200
    core.on_bytes(subscribe(ENG[0], call_id="s0", cseq=2), f)
    assert responses(f)[-1].code == 200
    assert len(core.alias_subs) == 8


@pytest.mark.parametrize("kw,flow_as,code,header", [
    ({"event": "dialog"}, None, 489, ("Allow-Events", "presence")),
    ({"event": None}, None, 489, ("Allow-Events", "presence")),
    ({"served": ENG[1]}, None, 403,
     ("Warning", "asserted identity is not the authenticated one")),
    ({}, ENG[1], 403, ("Warning", "asserted identity is not the authenticated one")),
    ({"accept": "text/plain"}, None, 406, ("Accept", "application/pidf+xml")),
    ({"rtype": None}, None, 400,
     ("Warning", "does not ask for functional-alias-status-determination")),
    ({"rtype": "group-selection-change-request"}, None, 400,
     ("Warning", "does not ask for functional-alias-status-determination")),
    ({"body": False}, None, 400,
     ("Warning", "does not ask for functional-alias-status-determination")),
    ({"expires": "abc"}, None, 400, ("Warning", "is not one delta-seconds value")),
    ({"expires": str(MAX + 1)}, None, 400, ("Warning", "is not one delta-seconds value")),
    ({"contact": False}, None, 400, ("Warning", "SUBSCRIBE without a Contact")),
    ({"from_tag": ""}, None, 400, ("Warning", "SUBSCRIBE without a From tag")),
    ({"contact": 'sip:e0@h;x="1 2"'}, None, 400,
     ("Warning", "is not a SIP URI a request can be sent to")),
    ({"accept": "application/pidf+xml;q=0"}, None, 406, ("Accept", "application/pidf+xml")),
    ({"accept": "application/pidf+xml;q=0.000, text/plain"}, None, 406,
     ("Accept", "application/pidf+xml")),
], ids=["another-event", "no-event", "for-another-user", "not-authenticated",
        "no-pidf-accepted", "no-request-type", "another-request-type", "no-body",
        "bad-expires", "too-long-expires", "no-contact", "no-from-tag", "bad-contact",
        "q-0", "q-0.000"])
def test_a_subscription_is_refused_as_stated(started, kw, flow_as, code, header):
    rt, core = started
    f = Flow(flow_as or ENG[0])
    core.on_bytes(subscribe(ENG[0], **kw), f)
    [got] = f.messages()
    assert got.code == code
    assert header[1] in got.headers.get(header[0])
    assert core.alias_subs == {}


@pytest.mark.parametrize("accept", ["application/pidf+xml;q=0.5, text/plain", "*/*",
                                    "application/*", None, "application/pidf+xml;q=0.001"])
def test_an_accept_that_admits_pidf_is_enough(started, accept):
    rt, core = started
    f = Flow(ENG[0])
    core.on_bytes(subscribe(ENG[0], accept=accept), f)
    assert f.messages()[0].code == 200


def test_a_user_outside_the_domains_is_not_served(tmp_path, pki):  # noqa: F811
    rt, core = _start(utility_env(tmp_path, pki))
    try:
        f = Flow("sip:z@elsewhere.example")
        core.on_bytes(subscribe("sip:z@elsewhere.example"), f)
        assert f.messages()[0].code == 403
        assert core.alias_subs == {}
    finally:
        core.close()
        rt.close()


@pytest.mark.parametrize("release", ["13", "14"])
def test_subscribe_does_not_exist_before_rel_15(tmp_path, pki, release):  # noqa: F811
    rt, core = _start(utility_env(tmp_path, pki, release=release))
    try:
        f = Flow(ENG[0])
        core.on_bytes(subscribe(ENG[0]), f)
        got = f.messages()[0]
        assert got.code == 501 and "SUBSCRIBE" not in got.headers.get("Allow")
    finally:
        core.close()
        rt.close()


def test_a_notify_that_fails_does_not_fail_the_publish(started, monkeypatch, caplog):
    rt, core = started
    f0, f1 = Flow(ENG[0]), Flow(ENG[1])
    core.on_bytes(subscribe(ENG[0]), f0)
    core.on_bytes(subscribe(ENG[1]), f1)
    real = core._send_notify

    def broken(sub, p_id_fa=None):
        if sub.subscriber == ENG[0]:
            raise RuntimeError("boom")
        return real(sub, p_id_fa)
    monkeypatch.setattr(core, "_send_notify", broken)
    f0.sent.clear()
    f1.sent.clear()
    core.on_bytes(publish(ENG[0], ["control-engineer"], call_id="a"), f0)
    assert [m.code for m in f0.messages()] == [200]
    assert rt.store.holdings() == [("control-engineer", "", ENG[0])]
    assert len(f1.requests("NOTIFY")) == 1          # the others are still told
    assert "functional alias status NOTIFY to sip:e0@utility.example failed" in caplog.text


def test_a_keyed_identity_over_sip(tmp_path, pki):  # noqa: F811
    net = network_yaml(tmp_path, fname="frmcs-net.yaml",
                       trusted_cores=["core-client.example"],
                       core_ca=pki / "core-ca.crt", users=DRV,
                       functional_aliases=[{"id": "train-driver", "users": DRV,
                                            "take_over": [DRV[1]]}])
    rt, core = _start(sip_env(tmp_path, pki, MCX_PROFILE="frmcs", MCX_RELEASE="19",
                              MCX_NETWORK_FILE=str(net)))
    try:
        f0, f1 = Flow(DRV[0]), Flow(DRV[1])
        core.on_bytes(subscribe(DRV[1]), f1)
        core.on_bytes(publish(DRV[0], ["sip:T1.train-driver@frmcs.example"], call_id="a"), f0)
        assert f0.messages()[-1].code == 200
        assert statuses(f1.requests("NOTIFY")[-1])[2] == [
            ("sip:T1.train-driver@frmcs.example", "take-over-possible")]
    finally:
        core.close()
        rt.close()
