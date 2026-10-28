"""Ad hoc group calls (TS 24.379 clause 17; PLT-VP-R1 ADHOC-OP-01).

Driven through the SIP core with the frmcs profile, whose shunting-group and
rec-broadcast call types are ad hoc (mc_signature session_type adhoc). The
bodies the "client" sends are written by hand in tests/mcpttinfo_fixture.py,
not with core/mcinfo.py.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import mcinfo  # noqa: E402
from core.hooks import LocationContext, Resolution, ResolutionKind  # noqa: E402
from core.sip import ReceivedResponse  # noqa: E402
from service.runtime import build_runtime  # noqa: E402
from service.sip_core import SipCore  # noqa: E402
from tests import mcpttinfo_fixture as mcf  # noqa: E402
from tests.network_fixture import network_yaml  # noqa: E402
from tests.test_sip_transport import (  # noqa: E402,F401  (pki is a fixture)
    LOCAL, SDP, Clock, Flow, answer, msg, pki, register, sip_env)
from core.session import Platform  # noqa: E402

F = [f"sip:f{i}@frmcs.example" for i in range(6)]
YARD = LocationContext(attributes={"yard_id": "Y1"})
# The train a driver drives (FA-OP-01 item 4: train-driver is keyed by train_id).
T1 = LocationContext(attributes={"train_id": "T1"})


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def list_max():
    return "100"


@pytest.fixture
def list_entries():
    """MCX_ADHOC_LIST_ENTRIES: unset (the default, users) unless a test says."""
    return None


@pytest.fixture
def cells():
    """The network profile's cell map for the frmcs runtime: empty unless a
    test says so."""
    return []


@pytest.fixture
def rt(tmp_path, pki, clock, list_max, cells, list_entries):
    over = {"MCX_ADHOC_LIST_ENTRIES": list_entries} if list_entries else {}
    env = sip_env(tmp_path, pki, MCX_PROFILE="frmcs", MCX_RELEASE="19",
                  MCX_ADHOC_LIST_MAX=list_max, **over,
                  MCX_NETWORK_FILE=str(network_yaml(
                      tmp_path, cells=cells, trusted_cores=["core-client.example"],
                      core_ca=pki / "core-ca.crt", fname="frmcs-network.yaml",
                      groups=[{"id": "grp:yard", "members": list(F[1:3])},
                              {"id": "grp:crew", "members": [F[0], F[4], F[5]]},
                              {"id": "grp:pair", "members": list(F[1:3])}],
                      users=list(F))))
    r = build_runtime(env, clock, platform=Platform())
    resolver = r.loaded.hooks.identity_resolver
    resolver.bind("shunting-team-leader", F[0], YARD)   # may start shunting calls
    # train-driver is single-holder (multiplicity: single): one holder.
    resolver.bind("train-driver", F[3], T1)
    yield r
    r.close()


@pytest.fixture
def core(rt, clock):
    c = SipCore(rt, LOCAL, clock)
    yield c
    c.close()


@pytest.fixture
def world(core):
    flows = {u: Flow(u) for u in F}
    for u in F:
        register(core, u, flows[u])
        flows[u].sent.clear()
    return flows


def adhoc_invite(cid, xml, rl=None):
    return msg("INVITE", LOCAL, cid, 1, F[0], LOCAL,
               body=mcf.adhoc_body(SDP, xml, rl), ctype=mcf.CONTENT_TYPE)


def mcinfo_part(m):
    return mcf.part(m.headers.get("Content-Type"), m.body, mcf.CT_MCINFO)


def calling_group(xml):
    m = re.search(r"<mcptt-calling-group-id[^>]*><mcpttURI>([^<]+)</mcpttURI>", xml)
    return m.group(1) if m else None


def refusal(flow):
    (resp,) = [m for m in flow.messages() if isinstance(m, ReceivedResponse)
               and m.code >= 300]
    return resp.code, resp.headers.get("Warning") or ""


# ============================================================ listed participants


def test_a_listed_ad_hoc_call_invites_exactly_the_list(core, world):
    """17.4.2.2 step 12 i. Each member's INVITE names the ad hoc group the
    controlling function generated (17.4.2.1.1 item 4b) and the caller."""
    core.on_bytes(adhoc_invite("ah1", mcf.adhoc_xml(),
                               mcf.resource_list([F[1], F[2]])), world[F[0]])
    invited = [u for u in F[1:] if world[u].requests("INVITE")]
    assert invited == [F[1], F[2]]
    ids = set()
    for u in invited:
        xml = mcinfo_part(world[u].requests("INVITE")[0])
        assert "<session-type>adhoc</session-type>" in xml
        assert f"<mcptt-calling-user-id type=\"Normal\"><mcpttURI>{F[0]}" in xml
        assert f"<mcptt-request-uri type=\"Normal\"><mcpttURI>{u}" in xml
        ids.add(calling_group(xml))
    (gid,) = ids
    assert re.fullmatch(r"sip:adhoc-[0-9a-f]{16}@frmcs\.example", gid)


def test_the_answer_tells_the_caller_the_ad_hoc_group_identity(core, world):
    """17.4.2.2: the 200 OK carries <mcptt-calling-group-id> -- the caller
    has no other way to learn the group it created."""
    core.on_bytes(adhoc_invite("ah2", mcf.adhoc_xml(),
                               mcf.resource_list([F[1]])), world[F[0]])
    req = world[F[1]].requests("INVITE")[0]
    core.on_bytes(answer(req, 200, SDP), world[F[1]])
    (ok,) = [m for m in world[F[0]].messages()
             if isinstance(m, ReceivedResponse) and m.code == 200]
    assert ok.headers.get("Content-Type").startswith("multipart/mixed")
    assert mcf.part(ok.headers.get("Content-Type"), ok.body, "application/sdp")
    assert calling_group(mcinfo_part(ok)) == calling_group(mcinfo_part(req))


def test_the_caller_and_repeats_in_the_list_are_not_invited_twice(core, world):
    core.on_bytes(adhoc_invite("ah3", mcf.adhoc_xml(),
                               mcf.resource_list([F[0], F[1], F[1]])), world[F[0]])
    assert len(world[F[1]].requests("INVITE")) == 1
    assert world[F[0]].requests("INVITE") == []


def test_listed_entries_that_are_not_users_are_left_out(core, world):
    core.on_bytes(adhoc_invite("ah4", mcf.adhoc_xml(), mcf.resource_list(
        ["sip:nobody@frmcs.example", "sip:x@elsewhere.example", F[2]])), world[F[0]])
    assert [u for u in F[1:] if world[u].requests("INVITE")] == [F[2]]


def test_a_list_of_nobody_is_refused_187(core, world):
    core.on_bytes(adhoc_invite("ah5", mcf.adhoc_xml(), mcf.resource_list(
        ["sip:nobody@frmcs.example"])), world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "187 can't determine the adhoc group participants" in warning


def test_a_list_over_the_call_types_limit_is_refused_189(core, world):
    """17.4.2.2 step 6; the limit is shunting-group's max_participants: 30."""
    listed = [f"sip:p{i}@frmcs.example" for i in range(31)]
    core.on_bytes(adhoc_invite("ah6", mcf.adhoc_xml(), mcf.resource_list(listed)),
                  world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403
    assert "189 maximum number of allowed adhoc group participants exceeded" in warning


def test_exactly_the_limit_is_accepted(core, world):
    listed = [f"sip:p{i}@frmcs.example" for i in range(29)] + [F[1]]
    core.on_bytes(adhoc_invite("ah7", mcf.adhoc_xml(), mcf.resource_list(listed)),
                  world[F[0]])
    assert world[F[1]].requests("INVITE")


def test_nested_lists_are_read(core, world):
    core.on_bytes(adhoc_invite("ah8", mcf.adhoc_xml(),
                               mcf.resource_list([F[1], F[2]], nested=True)), world[F[0]])
    assert [u for u in F[1:] if world[u].requests("INVITE")] == [F[1], F[2]]


@pytest.mark.parametrize("extra", ['<entry-ref ref="lists/x"/>',
                                   '<external anchor="http://x.example/l"/>'])
def test_a_list_pointing_elsewhere_is_refused_not_shortened(core, world, extra):
    core.on_bytes(adhoc_invite("ah9", mcf.adhoc_xml(),
                               mcf.resource_list([F[1]], extra=extra)), world[F[0]])
    code, _ = refusal(world[F[0]])
    assert code == 400 and world[F[1]].requests("INVITE") == []


# ============================================================ criteria


def test_criteria_invite_everyone_holding_the_identity(core, world):
    """17.4.2.2 step 12 ii via IF-IDR determine_participants; the criteria
    travel to each member (17.4.2.1.1 item 4c) and back to the caller."""
    core.on_bytes(adhoc_invite("ac1", mcf.adhoc_xml(criteria="train-driver")),
                  world[F[0]])
    assert [u for u in F[1:] if world[u].requests("INVITE")] == [F[3]]
    req = world[F[3]].requests("INVITE")[0]
    assert ("<call-participants-criterias>train-driver"
            "</call-participants-criterias>") in mcinfo_part(req)
    core.on_bytes(answer(req, 200, SDP), world[F[3]])
    ok = [m for m in world[F[0]].messages()
          if isinstance(m, ReceivedResponse) and m.code == 200][0]
    assert "<call-participants-criterias>train-driver" in mcinfo_part(ok)


def test_a_location_dependent_criterion_without_a_location_adds_nobody(core, world):
    """No location reaches the platform from SIP yet (ADHOC-OP-03), so
    shunting-team-leader (per yard) matches nobody; train-driver still does."""
    core.on_bytes(adhoc_invite("ac2", mcf.adhoc_xml(
        criteria="shunting-team-leader, train-driver")), world[F[0]])
    assert [u for u in F[1:] if world[u].requests("INVITE")] == [F[3]]


@pytest.mark.parametrize("criteria", ["track-controller", "no-such-role,train-driver",
                                      " , "])
def test_criteria_that_find_nobody_or_are_not_understood_are_refused_187(
        core, world, criteria):
    core.on_bytes(adhoc_invite("ac3", mcf.adhoc_xml(criteria=criteria)), world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "187 " in warning
    assert not any(world[u].requests("INVITE") for u in F[1:])


def test_a_list_and_criteria_together_are_refused_187(core, world):
    """17.4.2.2 step 7."""
    core.on_bytes(adhoc_invite("ac4", mcf.adhoc_xml(criteria="train-driver"),
                               mcf.resource_list([F[1]])), world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "187 " in warning


@pytest.mark.parametrize("xml", [
    mcf.adhoc_xml(),                                         # nothing at all
    mcf.adhoc_xml(request_uri="sip:adhoc-alert@frmcs.example", alert_group=True),
])
def test_an_ad_hoc_call_naming_no_participants_is_refused_187(core, world, xml):
    """Neither a list nor criteria -- including a call after an ad hoc
    emergency alert, whose group this platform does not keep (7A)."""
    core.on_bytes(adhoc_invite("ac5", xml), world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "187 " in warning


def test_a_resolver_that_names_the_group_itself_breaks_the_contract(core, rt, world):
    """PLT-ICD-001 3.5: the ad hoc identity is the controlling function's."""
    rt.loaded.hooks.identity_resolver.determine_participants = \
        lambda criteria, request: Resolution(kind=ResolutionKind.GROUP,
                                             members=(F[3],), group_id="grp:mine")
    core.on_bytes(adhoc_invite("ac6", mcf.adhoc_xml(criteria="train-driver")),
                  world[F[0]])
    code, _ = refusal(world[F[0]])
    assert code == 500 and world[F[3]].requests("INVITE") == []


def test_each_call_gets_its_own_ad_hoc_identity(core, rt):
    ids = {rt.manager.adhoc_group_id(c) for c in ("a", "b", "a@host;x=<y>")}
    assert len(ids) == 3
    assert rt.manager.adhoc_group_id("a") == rt.manager.adhoc_group_id("a")


# ============================================================ the body, unit level


def test_criteria_and_alert_flag_are_read_from_anyext():
    info = mcinfo.parse(mcf.adhoc_xml(criteria="a,b", alert_group=True))
    assert info.participant_criteria == "a,b" and info.adhoc_alert_group is True


def test_criteria_cannot_be_rendered_before_rel_18():
    from core.release import Release
    info = mcinfo.McInfo(session_type="adhoc", participant_criteria="x")
    with pytest.raises(mcinfo.McInfoError):
        mcinfo.render(info, Release.REL_17)
    assert "<call-participants-criterias>x" in mcinfo.render(info, Release.REL_18)


@pytest.mark.parametrize("rl, why", [
    ('<!DOCTYPE x [<!ENTITY a "b">]><resource-lists/>', "document type"),
    ('<resource-lists xmlns="urn:other"/>', "root element"),
    ('<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists">'
     "<list><entry/></list></resource-lists>", "uri attribute"),
    ("<resource-lists", "well-formed"),
])
def test_a_malformed_participant_list_is_refused(rl, why):
    body = mcf.adhoc_body(SDP, mcf.adhoc_xml(), rl)
    with pytest.raises(mcinfo.McInfoError, match=why):
        mcinfo.participants_of(mcf.CONTENT_TYPE, body)


def test_no_list_is_not_an_empty_list():
    body = mcf.adhoc_body(SDP, mcf.adhoc_xml())
    assert mcinfo.participants_of(mcf.CONTENT_TYPE, body) is None


# ============================================================ the resolver, unit level


def test_criteria_read_location_dependent_identities_at_the_callers_location(rt):
    """FunctionalResolver: a multi-holder identity at the request's location,
    plus a location-free one; each holder once, in order."""
    from core.hooks import MediaKind, SessionRequest
    resolver = rt.loaded.hooks.identity_resolver
    s1 = LocationContext(attributes={"track_section": "S1"})
    for u in (F[1], F[2]):
        resolver.bind("rec-area", u, s1)
    resolver.bind("rec-area", F[5], LocationContext(attributes={"track_section": "S2"}))
    request = SessionRequest(request_id="r", initiator=F[0], target="",
                             call_type="rec-broadcast", media=(MediaKind.VOICE,),
                             location=s1, adhoc=True,
                             participant_criteria="rec-area,train-driver,rec-area")
    found = resolver.determine_participants(request.participant_criteria, request)
    assert found.kind is ResolutionKind.GROUP and found.group_id is None
    assert found.members == (F[1], F[2], F[3])


def test_the_directory_resolver_has_no_criteria(tmp_path):
    from core import loader
    from core.hooks import MediaKind, SessionRequest
    from profiles.common.tables import ResolutionFailure
    mcx = loader.load(ROOT / "profiles" / "mcx")
    request = SessionRequest(request_id="r", initiator="sip:a@mcptt.example",
                             target="", call_type="private", media=(MediaKind.VOICE,))
    with pytest.raises(ResolutionFailure) as exc:
        mcx.hooks.identity_resolver.determine_participants("anything", request)
    assert exc.value.reason_code == "adhoc-participants-undetermined"


def test_a_role_restricted_call_type_admits_a_caller_holding_the_role(core, world):
    """Nothing supplied initiator.roles before this change, so every call type
    with initiator_roles refused everyone. f0 holds shunting-team-leader."""
    core.on_bytes(adhoc_invite("rr1", mcf.adhoc_xml(), mcf.resource_list([F[1]])),
                  world[F[0]])
    assert world[F[1]].requests("INVITE")


def test_a_caller_without_the_role_is_still_refused(core, world):
    core.on_bytes(msg("INVITE", LOCAL, "rr2", 1, F[2], LOCAL,
                      body=mcf.adhoc_body(SDP, mcf.adhoc_xml(), mcf.resource_list([F[1]])),
                      ctype=mcf.CONTENT_TYPE), world[F[2]])
    code, warning = refusal(world[F[2]])
    assert (code, warning) == (403, '399 mcptt.example "185 user not authorised '
                                    'to initiate the adhoc group call"')
    assert world[F[1]].requests("INVITE") == []


def test_a_list_naming_only_the_caller_is_refused_187(core, rt, world):
    """The caller is not a participant it can invite; with nobody else
    listed there is nobody to call (and no session is left behind)."""
    core.on_bytes(adhoc_invite("ah10", mcf.adhoc_xml(), mcf.resource_list([F[0]])),
                  world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "187 " in warning
    assert rt.manager.session("ah10") is None


def test_a_listed_group_is_not_a_participant(core, world):
    """Step 12 i: each entry is an MCPTT user. A group identity in the list
    resolves to a group, which is not a user to invite, so it is left out."""
    core.on_bytes(adhoc_invite("ah11", mcf.adhoc_xml(), mcf.resource_list(["grp:yard"])),
                  world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "187 " in warning
    assert not any(world[u].requests("INVITE") for u in F[1:])


def test_criteria_matching_only_the_caller_are_refused_187(core, rt, world):
    rt.loaded.hooks.identity_resolver.bind("train-driver", F[0], T1)
    core.on_bytes(adhoc_invite("ac7", mcf.adhoc_xml(criteria="train-driver")),
                  world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "187 " in warning


# ============================================================ found by the independent review


@pytest.mark.parametrize("rl, criteria", [(mcf.resource_list([F[1]]), None),
                                          (None, "train-driver")])
def test_a_call_after_an_ad_hoc_emergency_alert_is_refused_187(core, world, rl, criteria):
    """17.4.2.2 step 7A: <adhoc-grp-emg-alert-grp-ind> true names an alert
    group, and this platform keeps none -- whatever else the body says."""
    xml = mcf.adhoc_xml(criteria=criteria, alert_group=True,
                        request_uri="sip:adhoc-alert@frmcs.example")
    core.on_bytes(adhoc_invite("rv1", xml, rl), world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "187 " in warning
    assert not any(world[u].requests("INVITE") for u in F[1:])


@pytest.mark.parametrize("extra", ["track-controller", "rec-area", "shunting-team-leader"])
def test_an_unresolvable_functional_identity_in_a_list_is_left_out(core, world, extra):
    """It yields no user (no holder, or no location from SIP); the rest of
    the list is still called rather than the whole call failing 480."""
    core.on_bytes(adhoc_invite("rv2", mcf.adhoc_xml(),
                               mcf.resource_list([F[1], extra])), world[F[0]])
    assert world[F[1]].requests("INVITE")


def test_the_caller_does_not_count_toward_the_limit(core, world):
    listed = [F[0]] + [f"sip:p{i}@frmcs.example" for i in range(29)] + [F[1]]
    core.on_bytes(adhoc_invite("rv3", mcf.adhoc_xml(), mcf.resource_list(listed)),
                  world[F[0]])
    assert world[F[1]].requests("INVITE")


def test_the_limit_is_checked_before_a_list_and_criteria_clash(core, world):
    """Step 6 (189) comes before step 7 (187)."""
    listed = [f"sip:p{i}@frmcs.example" for i in range(31)]
    core.on_bytes(adhoc_invite("rv4", mcf.adhoc_xml(criteria="train-driver"),
                               mcf.resource_list(listed)), world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "189 " in warning


def test_criteria_finding_more_than_the_limit_are_189_not_503(core, rt, world):
    many = tuple(f"sip:m{i}@frmcs.example" for i in range(31))
    rt.loaded.hooks.identity_resolver.determine_participants = \
        lambda criteria, request: Resolution(kind=ResolutionKind.GROUP, members=many)
    core.on_bytes(adhoc_invite("rv5", mcf.adhoc_xml(criteria="train-driver")),
                  world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "189 " in warning


def test_a_private_call_carrying_a_resource_list_is_not_read_as_ad_hoc(core, rt, world):
    """Other INVITEs may carry resource lists (TS 24.379 clause 4.8); only an
    ad hoc call's list is this code's business, so a list it could not use
    must not refuse a private call."""
    rt.loaded.hooks.identity_resolver.bind("train-driver", F[0], T1)
    xml = mcf.mcinfo_xml("private", F[1])
    body = mcf.adhoc_body(SDP, xml, mcf.resource_list([F[2]], extra='<entry-ref ref="x"/>'))
    core.on_bytes(msg("INVITE", LOCAL, "rv6", 1, F[0], LOCAL, body=body,
                      ctype=mcf.CONTENT_TYPE), world[F[0]])
    assert world[F[1]].requests("INVITE")
    assert world[F[2]].requests("INVITE") == []


def test_ad_hoc_is_not_understood_before_rel_18(tmp_path, pki, clock):
    """At Rel-17 "adhoc" is a session type no call type can declare: the
    request is refused as such, not with a Rel-18 ad hoc warning code."""
    env = sip_env(tmp_path, pki, MCX_PROFILE="frmcs", MCX_RELEASE="17",
                  MCX_NETWORK_FILE=str(network_yaml(
                      tmp_path, trusted_cores=["core-client.example"],
                      core_ca=pki / "core-ca.crt", fname="g17-network.yaml",
                      users=list(F))))
    r = build_runtime(env, clock, platform=Platform())
    c = SipCore(r, LOCAL, clock)
    try:
        flows = {u: Flow(u) for u in F[:2]}
        for u in F[:2]:
            register(c, u, flows[u])
            flows[u].sent.clear()
        c.on_bytes(adhoc_invite("rv7", mcf.adhoc_xml(criteria="train-driver")),
                   flows[F[0]])
        code, warning = refusal(flows[F[0]])
        # The ordinary path: no call type of the profile is this one, so
        # authorisation refuses it (403, 100) before anything is looked up
        # (ICD-OP-09), as for any session type the release lacks. Not an ad
        # hoc refusal: no 187, and no participant was resolved.
        assert code == 403 and "100 function not allowed" in warning
        assert "187" not in warning
    finally:
        c.close()
        r.close()


def test_a_large_list_is_read_in_linear_time():
    """The de-duplication was quadratic: 20,000 entries took 1.7 s under the
    SIP lock (found by review)."""
    import time
    listed = [f"sip:p{i}@frmcs.example" for i in range(20_000)]
    body = mcf.adhoc_body(SDP, mcf.adhoc_xml(), mcf.resource_list(listed + listed[:10]))
    started = time.monotonic()
    got = mcinfo.participants_of(mcf.CONTENT_TYPE, body)
    assert time.monotonic() - started < 0.5
    assert len(got) == 20_000 and got[0] == listed[0] and got[-1] == listed[-1]


def test_warn_text_is_a_valid_quoted_string():
    """RFC 3261 25.1: a caller-chosen quote or backslash is escaped, control
    characters removed, so the warn-text cannot end early."""
    from service.sip_core import _quoted
    assert _quoted('a"b\\c\r\nX: y') == 'a\\"b\\\\c  X: y'


# ============================================================ the deployment's list cap (ADHOC-OP-04)


def _count_resolves(rt):
    resolver = rt.loaded.hooks.identity_resolver
    calls = []
    original = resolver.resolve

    def counting(target, request):
        calls.append(target)
        return original(target, request)
    resolver.resolve = counting
    return calls


@pytest.mark.parametrize("list_max", ["3"])
def test_a_list_over_the_deployment_cap_is_refused_189_before_any_lookup(core, rt, world):
    """The cap applies before a single entry is resolved: that is its point."""
    calls = _count_resolves(rt)
    listed = [F[1], F[2], "sip:p1@frmcs.example", "sip:p2@frmcs.example"]
    core.on_bytes(adhoc_invite("cap1", mcf.adhoc_xml(), mcf.resource_list(listed)),
                  world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "189 " in warning
    assert calls == []
    assert not any(world[u].requests("INVITE") for u in F[1:])


@pytest.mark.parametrize("list_max", ["3"])
def test_a_list_at_the_cap_goes_ahead_and_the_caller_is_not_counted(core, world):
    listed = [F[0], F[1], F[2], "sip:p1@frmcs.example"]
    core.on_bytes(adhoc_invite("cap2", mcf.adhoc_xml(), mcf.resource_list(listed)),
                  world[F[0]])
    assert world[F[1]].requests("INVITE") and world[F[2]].requests("INVITE")


@pytest.mark.parametrize("list_max", ["2"])
def test_the_cap_bounds_a_call_type_that_declares_no_limit(core, rt, world):
    """rec-broadcast declares no max_participants: before the cap, its list
    was unbounded (the reviewer's 20,001-entry case)."""
    rt.loaded.hooks.identity_resolver.bind("train-driver", F[0], T1)
    calls = _count_resolves(rt)
    listed = [F[1], F[2], "sip:p1@frmcs.example"]
    core.on_bytes(adhoc_invite("cap3", mcf.adhoc_xml(emergency=True),
                               mcf.resource_list(listed)), world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "189 " in warning and calls == []


@pytest.mark.parametrize("list_max", ["1"])
def test_the_cap_does_not_limit_criteria(core, rt, world):
    """The decision was a cap on list length; criteria are bounded by the
    call type's max_participants alone."""
    many = (F[1], F[2], F[3])
    rt.loaded.hooks.identity_resolver.determine_participants = \
        lambda criteria, request: Resolution(kind=ResolutionKind.GROUP, members=many)
    core.on_bytes(adhoc_invite("cap4", mcf.adhoc_xml(criteria="train-driver")),
                  world[F[0]])
    assert all(world[u].requests("INVITE") for u in many)


# ============================================================ ICD-OP-09: authorise first


def _unauthorised_adhoc(core, world, cid, xml, rl=None):
    """F1 holds no role; the shunting call type needs shunting-team-leader."""
    core.on_bytes(msg("INVITE", LOCAL, cid, 1, F[1], LOCAL,
                      body=mcf.adhoc_body(SDP, xml, rl), ctype=mcf.CONTENT_TYPE),
                  world[F[1]])
    return refusal(world[F[1]])


def _refusal_and_lookups(rt, flow, cid):
    looked_up = [r["detail"]["method"] for r in rt.store.audit_records(cid)
                 if r["type"] == "hook-invocation"]
    refused = [r["detail"]["reason_code"] for r in rt.store.audit_records(cid)
               if r["type"] == "session-refused"]
    return refusal(flow), looked_up, refused


def test_an_unauthorised_ad_hoc_caller_learns_nothing_about_the_target(core, rt, world):
    """TS 24.379 17.4.2.2 authorises (steps 4, 5) before it checks the list
    length (step 6) or determines who to call (step 12). One answer, however
    the target is given, and nobody is looked up, let alone invited."""
    cases = [
        (mcf.adhoc_xml(criteria="train-driver"), None),         # matches F3
        (mcf.adhoc_xml(criteria="no-such-role"), None),         # matches nobody
        (mcf.adhoc_xml(), mcf.resource_list([F[2], F[3]])),     # real users
        (mcf.adhoc_xml(), mcf.resource_list(["sip:ghost@frmcs.example"])),
        # over the call type's limit (30) and the deployment cap (100):
        # would be 189 for an authorised caller
        (mcf.adhoc_xml(), mcf.resource_list(
            [f"sip:x{i}@frmcs.example" for i in range(101)])),
        (mcf.adhoc_xml(criteria="train-driver"), mcf.resource_list([F[2]])),
    ]
    seen = set()
    for n, (xml, rl) in enumerate(cases):
        world[F[1]].sent.clear()
        cid = f"ua{n}"
        core.on_bytes(msg("INVITE", LOCAL, cid, 1, F[1], LOCAL,
                          body=mcf.adhoc_body(SDP, xml, rl), ctype=mcf.CONTENT_TYPE),
                      world[F[1]])
        (code, warning), looked_up, refused = _refusal_and_lookups(rt, world[F[1]], cid)
        assert code == 403 and looked_up == ["identities_of", "authorise"], n
        assert refused == ["not-authorised"], n
        seen.add(warning)
    assert len(seen) == 1                    # the same words every time
    assert all(not world[u].requests("INVITE") for u in F if u != F[1])


def test_an_unauthorised_private_caller_learns_nothing_about_the_target(core, rt, world):
    """The same for a restricted call type that is not ad hoc (frmcs
    driver-controller, for train drivers and controllers). F1 holds neither."""
    targets = [F[2], "sip:ghost@frmcs.example", "sip:x@other.example"]
    seen = set()
    for n, target in enumerate(targets):
        world[F[1]].sent.clear()
        cid = f"up{n}"
        core.on_bytes(msg("INVITE", LOCAL, cid, 1, F[1], LOCAL,
                          body=mcf.body_for("private", target, SDP),
                          ctype=mcf.CONTENT_TYPE), world[F[1]])
        (code, warning), looked_up, refused = _refusal_and_lookups(rt, world[F[1]], cid)
        assert code == 403 and looked_up == ["identities_of", "authorise"], target
        assert refused == ["not-authorised"], target
        seen.add(warning)
    assert len(seen) == 1
    # For contrast: the train driver, authorised, is told the target is unknown.
    core.on_bytes(msg("INVITE", LOCAL, "up-ok", 1, F[3], LOCAL,
                      body=mcf.body_for("private", "sip:ghost@frmcs.example", SDP),
                      ctype=mcf.CONTENT_TYPE), world[F[3]])
    (code, _), looked_up, _ = _refusal_and_lookups(rt, world[F[3]], "up-ok")
    assert code == 404 and "resolve" in looked_up


# ============================================================ ADHOC-OP-05: 3A-3C, 185, 186


def _imminent(xml):
    """The ad hoc body with <imminentperil-ind> true (annex F.1 order: after
    session-type and the URIs, before anyExt)."""
    flag = ('<imminentperil-ind type="Normal"><mcpttBoolean>true</mcpttBoolean>'
            "</imminentperil-ind>")
    return xml.replace("</session-type>", "</session-type>" + flag, 1)


def _final(flow):
    (resp,) = [m for m in flow.messages() if isinstance(m, ReceivedResponse)
               and m.code >= 300]
    return resp


def _send(core, world, cid, sender, xml, rl=None):
    core.on_bytes(msg("INVITE", LOCAL, cid, 1, sender, LOCAL,
                      body=mcf.adhoc_body(SDP, xml, rl), ctype=mcf.CONTENT_TYPE),
                  world[sender])
    return _final(world[sender])


PRIORITY = '399 mcptt.example "priority adhoc group call not authorised"'


def test_an_unauthorised_emergency_ad_hoc_call_is_told_it_is_not_one(core, world):
    """Step 3B: rec-broadcast is for train drivers and controllers; F1 is
    neither. The body says the emergency was not granted; no MC code, since
    3B skips step 4 (185)."""
    resp = _send(core, world, "x3b", F[1], mcf.adhoc_xml(criteria="rec-area", emergency=True))
    assert (resp.code, resp.headers.get("Warning")) == (403, PRIORITY)
    assert resp.headers.get("Content-Type") == mcf.CT_MCINFO
    assert "<anyExt><adhoc-emergency-ind>false</adhoc-emergency-ind></anyExt>" in resp.body
    assert "<session-type>" not in resp.body and "<emergency-ind" not in resp.body
    assert all(not world[u].requests("INVITE") for u in F if u != F[1])


def test_a_caller_authorised_for_ordinary_ad_hoc_calls_is_not_told_185(core, world):
    """The shunting team leader may start ad hoc calls, just not emergency
    ones. 185 would tell it otherwise (review of ADHOC-OP-05)."""
    resp = _send(core, world, "x3b2", F[0], mcf.adhoc_xml(criteria="rec-area", emergency=True))
    assert (resp.code, resp.headers.get("Warning")) == (403, PRIORITY)
    assert "185" not in resp.headers.get("Warning")


def test_an_ad_hoc_kind_nobody_may_start_is_answered_3c(core, world):
    """Step 3C (6.3.3.1.13.12): frmcs declares no imminent peril ad hoc call
    type, so nobody is authorised for one, and 3C comes before step 5."""
    resp = _send(core, world, "x3c", F[3], _imminent(mcf.adhoc_xml(criteria="train-driver")))
    assert (resp.code, resp.headers.get("Warning")) == (403, PRIORITY)
    assert '<imminentperil-ind type="Normal"><mcpttBoolean>false</mcpttBoolean>' in resp.body


@pytest.mark.parametrize("emergency", [True, False])
def test_both_indications_are_an_invalid_combination(core, rt, world, emergency):
    """Step 3A (6.3.3.1.25), before authorisation: <imminentperil-ind> with
    <adhoc-emergency-ind>, whatever its value. Nothing is looked up."""
    xml = _imminent(mcf.adhoc_xml(criteria="train-driver", emergency=emergency))
    resp = _send(core, world, f"x3a{emergency}", F[0], xml)
    assert (resp.code, resp.headers.get("Warning")) == (
        403, '399 mcptt.example "150 invalid combinations of data received in MIME body"')
    assert not resp.body and rt.store.audit_records(f"x3a{emergency}") == []


def test_an_ad_hoc_kind_the_profile_lacks_without_an_indication_is_local_policy(core, world):
    """frmcs supports ad hoc calls, so 186 ("the system does not support
    them") would be false for a kind it lacks. <broadcast-ind> makes such a
    kind: no frmcs ad hoc call type declares it."""
    xml = mcf.adhoc_xml(criteria="train-driver").replace(
        "</session-type>", "</session-type><broadcast-ind>true</broadcast-ind>", 1)
    resp = _send(core, world, "x100", F[0], xml)
    assert (resp.code, resp.headers.get("Warning")) == (
        403, '399 mcptt.example "100 function not allowed due to local policy"')


def test_an_unauthorised_ordinary_ad_hoc_call_carries_no_body(core, world):
    resp = _send(core, world, "x185", F[1], mcf.adhoc_xml(criteria="train-driver"))
    assert "185 " in resp.headers.get("Warning") and not resp.body
    assert resp.headers.get("Content-Type") is None


def test_an_ad_hoc_system_without_ad_hoc_is_refused_186(tmp_path, pki, clock):
    """Step 5: the mcx profile declares no ad hoc call type at all."""
    from service.runtime import build_runtime
    from service.sip_core import SipCore
    U0 = "sip:u0@mcptt.example"
    r = build_runtime(sip_env(tmp_path, pki), clock, platform=Platform())
    c = SipCore(r, LOCAL, clock)
    try:
        f = Flow(U0)
        register(c, U0, f)
        f.sent.clear()
        c.on_bytes(msg("INVITE", LOCAL, "x186", 1, U0, LOCAL,
                       body=mcf.adhoc_body(SDP, mcf.adhoc_xml(criteria="anyone")),
                       ctype=mcf.CONTENT_TYPE), f)
        resp = _final(f)
        assert (resp.code, resp.headers.get("Warning")) == (
            403, '399 mcptt.example "186 the MCPTT system do not support adhoc group call"')
    finally:
        c.close()
        r.close()


def test_the_ad_hoc_codes_are_for_authorisation_refusals_only(core, rt, world):
    """A later step's `not-authorised` (here a criteria resolver that raises
    it) is not step 4, so it is not 185 (review of ADHOC-OP-05)."""
    from profiles.common.tables import ResolutionFailure
    resolver = rt.loaded.hooks.identity_resolver

    def refuse(criteria, request):
        raise ResolutionFailure("not-authorised", "criteria not addressable")
    resolver.determine_participants = refuse
    resp = _send(core, world, "xlate", F[0], mcf.adhoc_xml(criteria="train-driver"))
    assert resp.code == 403 and "185" not in resp.headers.get("Warning")
    assert "100 function not allowed due to user authorisation" in resp.headers.get("Warning")


# ============================================================ groups in the list (ADHOC-OP-06)


def _spy_resolve(rt, monkeypatch):
    resolver = rt.loaded.hooks.identity_resolver
    seen = []
    real = resolver.resolve

    def resolve(target, request):
        seen.append(target)
        return real(target, request)
    monkeypatch.setattr(resolver, "resolve", resolve)
    return seen


def _answer_all(core, world, cid_users):
    for u in cid_users:
        core.on_bytes(answer(world[u].requests("INVITE")[0], 200, SDP, tag=f"t{u[5]}"), world[u])
    (ok,) = [m for m in world[F[0]].messages()
             if isinstance(m, ReceivedResponse) and m.code == 200]
    return ok


def test_users_only_leaves_a_listed_group_out_unresolved_and_says_so(core, rt, world,
                                                                     monkeypatch):
    """MCX_ADHOC_LIST_ENTRIES unset (users, owner decision 2026-10-28): a
    listed group is told apart by IF-IDR kind_of, never resolved over its
    members, left out, and the caller is told in the 200's Warning."""
    assert rt.health.snapshot()["settings"]["MCX_ADHOC_LIST_ENTRIES"] == "users"
    seen = _spy_resolve(rt, monkeypatch)
    core.on_bytes(adhoc_invite("ag1", mcf.adhoc_xml(),
                               mcf.resource_list(["grp:yard", F[4], "grp:crew"])), world[F[0]])
    assert "grp:yard" not in seen and "grp:crew" not in seen
    assert [u for u in F[1:] if world[u].requests("INVITE")] == [F[4]]
    ok = _answer_all(core, world, [F[4]])
    assert ok.headers.get_all("Warning") == (
        '399 mcptt.example "listed group left out, only users may be listed: '
        'grp:yard and 1 more"',)
    admitted = [r for r in rt.store.audit_records("ag1") if r["type"] == "session-admitted"]
    assert admitted[0]["detail"]["omitted_groups"] == ["grp:yard", "grp:crew"]
    assert rt.manager.session("ag1").omitted_groups == ("grp:yard", "grp:crew")


def test_users_only_with_nothing_but_groups_is_refused_187_saying_why(core, world):
    core.on_bytes(adhoc_invite("ag2", mcf.adhoc_xml(), mcf.resource_list(["grp:yard"])),
                  world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "187 " in warning


def test_a_list_of_users_only_carries_no_warning(core, world):
    core.on_bytes(adhoc_invite("ag3", mcf.adhoc_xml(), mcf.resource_list([F[1]])),
                  world[F[0]])
    ok = _answer_all(core, world, [F[1]])
    assert ok.headers.get_all("Warning") == ()


@pytest.mark.parametrize("list_entries", ["users-and-groups"])
def test_users_and_groups_invites_each_groups_members(core, rt, world, list_entries):
    """A listed group stands for its members, the caller excepted (F0 is in
    grp:crew), each once, in the order listed; reported as a deviation."""
    snap = rt.health.snapshot()
    assert snap["settings"]["MCX_ADHOC_LIST_ENTRIES"] == "users-and-groups"
    assert [d for d in snap["deviations"] if d["setting"] == "MCX_ADHOC_LIST_ENTRIES"] == [{
        "setting": "MCX_ADHOC_LIST_ENTRIES", "value": "users-and-groups",
        "ref": "ADHOC-OP-06",
        "departs_from": "TS 24.379 17.4.2.2 step 12 i (the listed participants are users)",
        "consequence": "an ad hoc caller's list may name groups, each standing for its "
                       "members, who are invited; the members of every listed group "
                       "count against MCX_ADHOC_LIST_MAX"}]
    core.on_bytes(adhoc_invite("ag4", mcf.adhoc_xml(),
                               mcf.resource_list([F[5], "grp:yard", "grp:crew"])), world[F[0]])
    assert rt.manager.session("ag4").members == (F[5], F[1], F[2], F[4])
    assert rt.manager.session("ag4").omitted_groups == ()
    ok = _answer_all(core, world, [F[5], F[1], F[2], F[4]])
    assert ok.headers.get_all("Warning") == ()


@pytest.mark.parametrize("list_entries,list_max", [("users-and-groups", "3")])
def test_users_and_groups_counts_every_member_against_the_cap(core, rt, world, monkeypatch,
                                                              list_entries, list_max):
    """Two entries, four people (F1, F2 of grp:yard; F4, F5 of grp:crew): past
    the cap of 3, refused 189, and no group is resolved after the cap is
    passed."""
    seen = _spy_resolve(rt, monkeypatch)
    core.on_bytes(adhoc_invite("ag5", mcf.adhoc_xml(),
                               mcf.resource_list(["grp:yard", "grp:crew", "grp:yard2"])),
                  world[F[0]])
    code, warning = refusal(world[F[0]])
    assert "189 " in warning
    assert seen == ["grp:yard", "grp:crew"]
    assert rt.manager.session("ag5") is None
    refused = [r for r in rt.store.audit_records("ag5") if r["type"] == "session-refused"]
    assert "pass the deployment limit 3" in refused[0]["detail"]["detail"]


@pytest.mark.parametrize("list_entries,list_max", [("users-and-groups", "3")])
def test_users_and_groups_at_the_cap_is_served(core, rt, world, list_entries, list_max):
    core.on_bytes(adhoc_invite("ag6", mcf.adhoc_xml(),
                               mcf.resource_list(["grp:yard", F[5]])), world[F[0]])
    assert rt.manager.session("ag6").members == (F[1], F[2], F[5])


def test_kind_of_tells_each_target_apart_without_members(rt):
    from core.hooks import SessionRequest, MediaKind
    from profiles.common.tables import ResolutionFailure
    r = rt.loaded.hooks.identity_resolver
    req = SessionRequest(request_id="k", initiator=F[0], target="", call_type="rec-broadcast",
                         media=(MediaKind.VOICE,))
    assert r.kind_of("grp:yard", req) is ResolutionKind.GROUP
    assert r.kind_of(F[1], req) is ResolutionKind.USER
    assert r.kind_of("sip:T1.train-driver@frmcs.example", req) is ResolutionKind.USER
    assert r.kind_of("sip:T9.train-driver@frmcs.example", req) is ResolutionKind.USER
    assert r.kind_of("rec-area", req) is ResolutionKind.GROUP
    for target, code in (("train-driver", "unknown-target"), ("", "unknown-target"),
                         ("sip:nobody@frmcs.example", "unknown-target")):
        with pytest.raises(ResolutionFailure) as exc:
            r.kind_of(target, req)
        assert exc.value.reason_code == code


def test_a_directory_tells_partner_foreign_group_and_user_apart_as_resolve_does():
    from core import loader
    from core.hooks import SessionRequest, MediaKind
    from profiles.common.tables import BackingStoreUnavailable, ResolutionFailure
    r = loader.load(ROOT / "profiles" / "mcx").hooks.identity_resolver
    u = "sip:u1@mcptt.example"
    r.register_user(u)
    r.register_group("grp:a", [u])
    req = SessionRequest(request_id="k", initiator=u, target="", call_type="private",
                         media=(MediaKind.VOICE,))
    assert [r.kind_of(t, req) for t in ("icx:rail:x", "tetra:123", "grp:a", u)] == [
        ResolutionKind.PARTNER, ResolutionKind.EXTERNAL, ResolutionKind.GROUP,
        ResolutionKind.USER]

    asked = []

    class Source:
        def members(self, gid):
            asked.append(gid)
            if gid == "grp:down":
                raise BackingStoreUnavailable("down")
            return [u] if gid == "grp:ext" else None
    r.group_source = Source()
    assert r.kind_of("grp:ext", req) is ResolutionKind.GROUP
    assert r.kind_of(u, req) is ResolutionKind.USER
    # A registered user is answered without asking the source (review).
    assert asked == ["grp:ext"]
    r.register_group("grp:empty", [])
    with pytest.raises(ResolutionFailure) as exc:
        r.kind_of("grp:empty", req)       # as resolve has it
    assert exc.value.reason_code == "unknown-target"
    with pytest.raises(ResolutionFailure) as exc:
        r.kind_of("grp:down", req)
    assert exc.value.reason_code == "resolver-unavailable"


def test_kind_of_returning_no_resolution_kind_is_a_contract_violation(rt, monkeypatch):
    from core.audit import Auditor, MemorySink
    from core.hooks import SessionRequest, MediaKind
    from core.invoke import HookFailure, Invoker
    monkeypatch.setattr(rt.loaded.hooks.identity_resolver, "kind_of", lambda t, r: "group")
    req = SessionRequest(request_id="kv", initiator=F[0], target="", call_type="rec-broadcast",
                         media=(MediaKind.VOICE,), participants=(F[1],))
    with pytest.raises(HookFailure) as exc:
        rt.manager._adhoc_members(Invoker(Auditor(MemorySink(), "t"), "t"), req)
    assert (exc.value.interface, exc.value.method, exc.value.reason_code) == (
        "IF-IDR", "kind_of", "hook-contract-violation")
    assert "kind_of returned 'group', not a resolution kind" in exc.value.detail


def test_the_omitted_group_warning_is_one_quoted_string():
    """The entry is the caller's text: in the warn-text (RFC 3261 25.1) a
    quote or backslash is escaped, a control character replaced, and the
    entry cut at 128 characters."""
    from core.release import Release
    from core.sip import Adapter
    a = Adapter(LOCAL, Release.REL_19, ())
    assert a.omitted_groups(['grp:"x"\\y\r\nInjected: 1']) == (
        '399 mcptt.example "listed group left out, only users may be listed: '
        'grp:\\"x\\"\\\\y??Injected: 1"')
    assert a.omitted_groups(["g" * 300, "h"]) == (
        '399 mcptt.example "listed group left out, only users may be listed: '
        + "g" * 128 + ' and 1 more"')


def test_a_foreign_entry_is_not_resolved(core, rt, world, monkeypatch):
    """kind_of says partner or foreign: no user to invite, so no resolve."""
    seen = _spy_resolve(rt, monkeypatch)
    real = rt.loaded.hooks.identity_resolver.kind_of
    monkeypatch.setattr(rt.loaded.hooks.identity_resolver, "kind_of",
                        lambda t, r: ResolutionKind.EXTERNAL if t == "tetra:9"
                        else ResolutionKind.PARTNER if t == "icx:9" else real(t, r))
    core.on_bytes(adhoc_invite("ag7", mcf.adhoc_xml(),
                               mcf.resource_list(["tetra:9", "icx:9", F[1]])), world[F[0]])
    assert seen == [F[1]]
    assert rt.manager.session("ag7").members == (F[1],)


def test_users_only_never_takes_a_groups_members_whatever_the_hook_says(core, rt, world,
                                                                       monkeypatch):
    """A resolver whose kind_of calls a group a user, and whose resolve then
    returns the group: in users mode its members are still not invited."""
    real = rt.loaded.hooks.identity_resolver.kind_of
    monkeypatch.setattr(rt.loaded.hooks.identity_resolver, "kind_of",
                        lambda t, r: ResolutionKind.USER if t == "grp:yard" else real(t, r))
    core.on_bytes(adhoc_invite("ag8", mcf.adhoc_xml(),
                               mcf.resource_list(["grp:yard", F[4]])), world[F[0]])
    assert rt.manager.session("ag8").members == (F[4],)
    # Left out all the same, and said so (review).
    assert rt.manager.session("ag8").omitted_groups == ("grp:yard",)


@pytest.mark.parametrize("list_entries,list_max", [("users-and-groups", "3")])
def test_overlapping_groups_count_in_full(core, rt, world, monkeypatch, list_entries, list_max):
    """Review of ADHOC-OP-06: grp:yard and grp:pair hold the same two users.
    Counted after repeats were removed they were two, and every such group
    was resolved; counted in full they are four, past the cap of 3."""
    seen = _spy_resolve(rt, monkeypatch)
    core.on_bytes(adhoc_invite("ag9", mcf.adhoc_xml(),
                               mcf.resource_list(["grp:yard", "grp:pair", "grp:crew"])),
                  world[F[0]])
    code, warning = refusal(world[F[0]])
    assert "189 " in warning
    assert seen == ["grp:yard", "grp:pair"]


def test_the_caller_spelled_otherwise_is_not_invited(core, rt, world):
    """Review of ADHOC-OP-06: the caller compared as SIP compares URIs, in
    the list as in a group."""
    # The caller's roles are held by the spelling it calls with.
    rt.loaded.hooks.identity_resolver.bind("shunting-team-leader", "sip:f0@FRMCS.example", YARD)
    core.on_bytes(msg("INVITE", LOCAL, "ag10", 1, "sip:f0@FRMCS.example", LOCAL,
                      body=mcf.adhoc_body(SDP, mcf.adhoc_xml(), mcf.resource_list([F[0], F[1]])),
                      ctype=mcf.CONTENT_TYPE), world[F[0]])
    assert rt.manager.session("ag10").request.initiator == "sip:f0@FRMCS.example"
    assert rt.manager.session("ag10").members == (F[1],)


@pytest.mark.parametrize("list_max", ["3"])
def test_groups_a_resolver_calls_users_still_count_against_the_cap(core, rt, world, monkeypatch,
                                                                  list_max):
    """Review: a kind_of that says user of every group cannot have the core
    resolve more than the cap's worth: each such group's members count."""
    seen = _spy_resolve(rt, monkeypatch)
    monkeypatch.setattr(rt.loaded.hooks.identity_resolver, "kind_of",
                        lambda t, r: ResolutionKind.USER)
    core.on_bytes(adhoc_invite("ag11", mcf.adhoc_xml(),
                               mcf.resource_list(["grp:yard", "grp:crew", "grp:pair"])),
                  world[F[0]])
    code, warning = refusal(world[F[0]])
    assert "189 " in warning
    assert seen == ["grp:yard", "grp:crew"]


def test_criteria_leave_out_the_caller_spelled_otherwise(core, rt, world):
    """Review: the criteria path compares the caller as SIP compares URIs too."""
    rt.loaded.hooks.identity_resolver.bind("train-driver", F[0],
                                           LocationContext(attributes={"train_id": "T7"}))
    rt.loaded.hooks.identity_resolver.bind("shunting-team-leader", "sip:f0@FRMCS.example", YARD)
    core.on_bytes(msg("INVITE", LOCAL, "ag12", 1, "sip:f0@FRMCS.example", LOCAL,
                      body=mcf.adhoc_body(SDP, mcf.adhoc_xml(criteria="train-driver")),
                      ctype=mcf.CONTENT_TYPE), world[F[0]])
    session = rt.manager.session("ag12")
    assert session is not None and session.members == (F[3],)
