"""A private call's callee is the one entry of its resource list (TS 24.379
11.1.1.2.1.1 item 9; 11.1.1.3.1.1 items 8 and 9). Owner decision 2026-11-24,
batch C review H1: the platform read <mcptt-request-uri> instead, so a
client written to the specification could not make a private call."""

from __future__ import annotations

import pytest

from core.sip import ReceivedResponse
from tests import mcpttinfo_fixture as mcf
from tests.test_sip_transport import (  # noqa: F401  (fixtures)
    LOCAL, SDP, U, clock, core, env, msg, pki, rt, sip_env, world)

W145 = '399 mcptt.example "145 unable to determine called party"'


def _invite(core, world, cid, body):
    world[U[0]].sent.clear()
    core.on_bytes(msg("INVITE", LOCAL, cid, 1, U[0], LOCAL, body=body,
                      ctype=mcf.CONTENT_TYPE), world[U[0]])
    return [m for m in world[U[0]].messages() if isinstance(m, ReceivedResponse)
            and m.code >= 200]


def _private(request_uri=None, rl=None):
    return mcf.multipart(SDP, mcf.mcinfo_xml("private", request_uri), rl)


def test_the_callee_is_the_resource_list_s_entry(core, world, rt):
    _invite(core, world, "p1", _private(rl=mcf.resource_list([U[1]])))
    assert len(world[U[1]].requests("INVITE")) == 1
    assert rt.manager.session("p1").request.target == U[1]


def test_mcptt_request_uri_does_not_name_a_private_call_s_callee(core, world, rt):
    """The list says u2, <mcptt-request-uri> says u3: u2 is called."""
    _invite(core, world, "p2", _private(U[3], mcf.resource_list([U[2]])))
    assert world[U[2]].requests("INVITE") and world[U[3]].requests("INVITE") == []


@pytest.mark.parametrize("case,body", [
    ("no list", lambda: _private(U[1])),
    ("two entries", lambda: _private(rl=mcf.resource_list([U[1], U[2]]))),
    ("nested two", lambda: _private(rl=mcf.resource_list([U[1], U[2]], nested=True))),
    ("entry-ref", lambda: _private(rl=mcf.resource_list([U[1]],
                                                        extra='<entry-ref ref="x"/>'))),
    ("not xml", lambda: _private(rl="<resource-lists")),
])
def test_no_single_callee_is_refused_403_warning_145(core, world, rt, case, body):
    """11.1.1.3.1.1 item 8 (no list) and item 9 (more than one entry); a list
    it cannot read for one callee is the same. Nobody is invited, and the
    resolver's failure is the INVITE's last record under its Call-ID, as for
    any unknown target."""
    (final,) = _invite(core, world, "p3", body())
    assert (final.code, final.headers.get("Warning")) == (403, W145), case
    assert all(world[u].requests("INVITE") == [] for u in U[1:])
    last = rt.store.audit_records("p3")[-1]
    assert (last["type"], last["detail"]["reason_code"]) == ("session-failed",
                                                             "unknown-target")


def test_a_named_callee_nobody_knows_stays_404(core, world):
    """Item 8 and 9 are about the list; a callee it names that the platform
    does not know is the resolver's unknown target, 404 with 145 as before."""
    (final,) = _invite(core, world, "p4",
                       _private(rl=mcf.resource_list(["sip:nobody@mcptt.example"])))
    assert (final.code, final.headers.get("Warning")) == (404, W145)


def test_a_group_call_is_untouched_by_the_rule(core, world):
    """A group call names its group in <mcptt-request-uri> (10.1.1.2.1.1);
    a resource list beside it does not change the target."""
    body = mcf.multipart(SDP, mcf.mcinfo_xml("prearranged", "grp:alpha"),
                         mcf.resource_list([U[3]]))
    _invite(core, world, "p5", body)
    assert all(len(world[u].requests("INVITE")) == 1 for u in U[1:])


def test_the_callee_s_invite_is_to_the_callee_and_asserts_the_mcptt_service(core, world):
    """RFC 3261 8.1.1.2: To is the callee, and the dialog's later requests
    carry it (12.2.1.1); 6.3.3.1.2 item 3: P-Asserted-Service is the MCPTT
    ICSI (batch C review H5; owner decision 2026-11-24)."""
    _invite(core, world, "p6", _private(rl=mcf.resource_list([U[1]])))
    (leg,) = world[U[1]].requests("INVITE")
    assert leg.headers.get("To") == f"<{U[1]}>"
    assert leg.headers.get_all("P-Asserted-Service") == \
        ("urn:urn-7:3gpp-service.ims.icsi.mcptt",)


def test_each_group_member_s_invite_is_to_that_member(core, world):
    body = mcf.multipart(SDP, mcf.mcinfo_xml("prearranged", "grp:alpha"))
    _invite(core, world, "p7", body)
    for u in U[1:]:
        (leg,) = world[u].requests("INVITE")
        assert (leg.headers.get("To"), leg.headers.get("P-Asserted-Service")) == \
            (f"<{u}>", "urn:urn-7:3gpp-service.ims.icsi.mcptt")


def test_only_a_target_failure_becomes_403_145(core, world, rt):
    """Items 8 and 9 replace the unknown-target refusal alone: a private call
    naming no callee that IF-SES fails on first (a hook error, before
    anything about the target is looked up) is refused as that, 500."""
    import dataclasses as dc
    sp = rt.manager._hooks.session_policy

    class Broken:
        def __getattr__(self, name):
            return getattr(sp, name)

        def authorise(self, request):
            raise RuntimeError("IF-SES down")

    rt.manager._hooks = dc.replace(rt.manager._hooks, session_policy=Broken())
    (final,) = _invite(core, world, "p8", _private(U[1]))
    assert final.code == 500 and final.headers.get("Warning") is None
    assert rt.store.audit_records("p8")[-1]["detail"]["reason_code"] == "hook-error"


def test_a_group_nobody_knows_stays_404_145(core, world):
    """A group call carries no resource list; an unknown group is the
    resolver's unknown target, 404 -- not the private call's 403."""
    (final,) = _invite(core, world, "p9",
                       mcf.multipart(SDP, mcf.mcinfo_xml("prearranged", "grp:nope")))
    assert (final.code, final.headers.get("Warning")) == (404, W145)
