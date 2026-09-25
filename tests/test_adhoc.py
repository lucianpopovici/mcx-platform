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
from tests.test_sip_transport import (  # noqa: E402,F401  (pki is a fixture)
    LOCAL, SDP, Clock, Flow, answer, msg, pki, register, sip_env)
from core.session import Platform  # noqa: E402

F = [f"sip:f{i}@frmcs.example" for i in range(6)]
YARD = LocationContext(attributes={"yard_id": "Y1"})


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def list_max():
    return "100"


@pytest.fixture
def cells_file():
    """MCX_CELLS_FILE for the frmcs runtime: none unless a test says so."""
    return "none"


@pytest.fixture
def rt(tmp_path, pki, clock, list_max, cells_file):
    g = tmp_path / "frmcs-groups.yaml"
    g.write_text(f"groups:\n  - id: 'grp:yard'\n    members: {json.dumps(F[1:3])}\n"
                 f"users: {json.dumps(F)}\n")
    env = sip_env(tmp_path, pki, MCX_PROFILE="frmcs", MCX_RELEASE="19",
                  MCX_GROUPS_FILE=str(g), MCX_ADHOC_LIST_MAX=list_max,
                  MCX_CELLS_FILE=cells_file)
    r = build_runtime(env, clock, platform=Platform())
    resolver = r.loaded.hooks.identity_resolver
    resolver.bind("shunting-team-leader", F[0], YARD)   # may start shunting calls
    # train-driver is single-holder (multiplicity: single): one holder.
    resolver.bind("train-driver", F[3], None)
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
    assert code == 403 and "user authorisation" in warning
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
    rt.loaded.hooks.identity_resolver.bind("train-driver", F[0], None)
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
    rt.loaded.hooks.identity_resolver.bind("train-driver", F[0], None)
    xml = mcf.mcinfo_xml("private", F[1])
    body = mcf.adhoc_body(SDP, xml, mcf.resource_list([F[2]], extra='<entry-ref ref="x"/>'))
    core.on_bytes(msg("INVITE", LOCAL, "rv6", 1, F[0], LOCAL, body=body,
                      ctype=mcf.CONTENT_TYPE), world[F[0]])
    assert world[F[1]].requests("INVITE")
    assert world[F[2]].requests("INVITE") == []


def test_ad_hoc_is_not_understood_before_rel_18(tmp_path, pki, clock):
    """At Rel-17 "adhoc" is a session type no call type can declare: the
    request is refused as such, not with a Rel-18 ad hoc warning code."""
    g = tmp_path / "g17.yaml"
    g.write_text(f"groups: []\nusers: {json.dumps(F)}\n")
    env = sip_env(tmp_path, pki, MCX_PROFILE="frmcs", MCX_RELEASE="17",
                  MCX_GROUPS_FILE=str(g))
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
        # The ordinary path: resolution of the request's target fails first
        # (404, 145), as for any session type the release lacks. (An ad hoc
        # refusal would be 403 -- its 187 text is suppressed before Rel-18,
        # so the status is what tells the paths apart.)
        assert code == 404 and "145 " in warning
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
    rt.loaded.hooks.identity_resolver.bind("train-driver", F[0], None)
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
