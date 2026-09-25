"""The client's location report (TS 24.379 annex F.3) and the profile's cell
map (PLT-ICD-001 2.8; PLT-VP-R1 ADHOC-OP-03)."""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import mcinfo  # noqa: E402
from tests import mcpttinfo_fixture as mcf  # noqa: E402
from tests.test_adhoc import (  # noqa: E402,F401  (fixtures)
    F, LOCAL, SDP, Flow, adhoc_invite, clock, core, list_max, msg, pki, refusal, rt,
    world)
from core.hooks import LocationContext  # noqa: E402

lxml = pytest.importorskip("lxml.etree")


def body_with(report):
    return mcf.with_parts(SDP, mcf.adhoc_xml(), (mcf.CT_LOCATION, report))


# ============================================================ the parser


@pytest.mark.parametrize("report, cell", [
    (mcf.location_report(ecgi=mcf.ECGI), mcf.ECGI),
    (mcf.location_report(ncgi=mcf.NCGI), mcf.NCGI),
    (mcf.location_report(ecgi=mcf.ECGI, ncgi=mcf.NCGI), mcf.NCGI),   # NR preferred
])
def test_the_serving_cell_is_read(report, cell):
    got = mcinfo.location_of(mcf.CONTENT_TYPE, body_with(report))
    assert got is not None and got.cell == cell


@pytest.mark.parametrize("report", [
    mcf.location_report(ecgi=mcf.ECGI, encrypted=True),            # no key: F.3.3
    mcf.location_report(ncgi=mcf.NCGI, encrypted=True),
    mcf.location_report(ecgi="00101" + "0" * 28),                  # 5 digits
    mcf.location_report(ecgi="001010" + "2" * 28),                 # not binary
    mcf.location_report(ecgi="００１０１０" + "0" * 28),              # non-ASCII digits
    mcf.location_report(ncgi=mcf.ECGI),                            # E-UTRA length as NR
])
def test_an_unreadable_cell_is_no_cell(report):
    got = mcinfo.location_of(mcf.CONTENT_TYPE, body_with(report))
    assert got is None or got.cell is None


@pytest.mark.parametrize("report", [
    "<location-info", '<!DOCTYPE x [<!ENTITY a "b">]><location-info/>',
    '<location-info xmlns="urn:other"/>',
    f'<location-info xmlns="{mcf.NS_LOC}"><Configuration/></location-info>',
])
def test_a_body_that_is_not_a_report_is_no_location(report):
    assert mcinfo.location_of(mcf.CONTENT_TYPE, body_with(report)) is None


def _report_inner():
    return mcf.location_report(ecgi=mcf.ECGI).split("?>", 1)[1].strip()


def test_a_report_under_another_root_element_is_not_read():
    """Everything else about it is a valid report with a readable cell."""
    inner = _report_inner().replace("<location-info ", "<other ").replace(
        "</location-info>", "</other>")
    assert mcinfo.location_of(mcf.CONTENT_TYPE, body_with(inner)) is None


def test_a_document_type_declaration_is_refused_even_when_the_report_is_valid():
    """The entity would expand to a valid ECGI; the declaration alone is
    enough to refuse the body (entity expansion is an attack vector)."""
    inner = _report_inner().replace(mcf.ECGI, "&cell;")
    doc = f'<!DOCTYPE location-info [<!ENTITY cell "{mcf.ECGI}">]>' + inner
    assert mcinfo.location_of(mcf.CONTENT_TYPE, body_with(doc)) is None


def test_no_location_part_is_no_location():
    assert mcinfo.location_of(mcf.CONTENT_TYPE,
                              mcf.adhoc_body(SDP, mcf.adhoc_xml())) is None


@pytest.mark.parametrize("spec", ["id0", "k00"])
@pytest.mark.parametrize("report", [mcf.location_report(ecgi=mcf.ECGI),
                                    mcf.location_report(ncgi=mcf.NCGI),
                                    mcf.location_report(ecgi=mcf.ECGI, encrypted=True)])
def test_the_fixture_reports_are_schema_valid(spec, report):
    """The reports the tests send are conformant, so what is read from them
    is what a conformant client sends (Rel-18 and Rel-20 schemas)."""
    schema = lxml.XMLSchema(lxml.parse(
        str(ROOT / "docs" / "3GPP" / "schemas" / f"mcpttlocation-24379-{spec}.xsd")))
    doc = lxml.fromstring(report.split("?>", 1)[1].strip().encode())
    assert schema.validate(doc), schema.error_log


# ============================================================ the network profile's cell map
# (loading, the PLMN check and the rest of the file: tests/test_network.py)


from core.errors import StartupRefused  # noqa: E402
from service.network import load_network  # noqa: E402
from tests.network_fixture import network_yaml  # noqa: E402

KEYS = {"track_section", "yard_id"}


def load_cells(tmp_path, entries, keys=KEYS):
    return load_network(network_yaml(tmp_path, cells=entries), keys).cells


def test_a_cell_map_is_read(tmp_path):
    got = load_cells(tmp_path, [
        {"cell": mcf.ECGI, "location": {"track_section": "S1"}},
        {"cell": mcf.NCGI, "location": {"track_section": "S2", "yard_id": "Y1"}}])
    assert dict(got[mcf.ECGI]) == {"track_section": "S1"}
    assert dict(got[mcf.NCGI]) == {"track_section": "S2", "yard_id": "Y1"}


@pytest.mark.parametrize("entries, says", [
    ([{"cell": "123", "location": {"track_section": "S1"}}], "ECGI"),
    ([{"cell": "００１０１０" + "0" * 28, "location": {"track_section": "S1"}}], "ECGI"),
    ([{"cell": mcf.ECGI, "location": {"platform": "P1"}}], "not a location_key"),
    ([{"cell": mcf.ECGI, "location": {}}], "non-empty mapping"),
    ([{"cell": mcf.ECGI, "location": {"track_section": 7}}], "non-empty string"),
    ([{"cell": mcf.ECGI, "location": {"track_section": "S1"}},
      {"cell": mcf.ECGI, "location": {"track_section": "S2"}}], "already mapped"),
    ([{"cell": mcf.ECGI}], "exactly 'cell' and 'location'"),
    ([{"cell": mcf.ECGI, "location": {"track_section": "S1"}, "name": "x"}],
     "exactly 'cell' and 'location'"),
    ([{"cell": "001011" + mcf.ECGI[6:], "location": {"track_section": "S1"}}],
     "PLMN 001011 is not one of this network's plmns (001010)"),
])
def test_a_bad_cell_map_refuses_startup(tmp_path, entries, says):
    with pytest.raises(StartupRefused) as exc:
        load_cells(tmp_path, entries)
    assert says in str(exc.value)


def test_every_defect_is_reported_at_once(tmp_path):
    with pytest.raises(StartupRefused) as exc:
        load_cells(tmp_path, [{"cell": "1", "location": {"x": "y"}},
                              {"cell": mcf.ECGI, "location": {"q": "z"}}])
    assert "2 defect(s)" in str(exc.value)


def test_a_profile_without_location_keys_accepts_no_cell(tmp_path):
    """mcx has no location keys, so any key in a cell map is unknown."""
    with pytest.raises(StartupRefused) as exc:
        load_cells(tmp_path, [{"cell": mcf.ECGI, "location": {"track_section": "S1"}}],
                   keys=set())
    assert "not a location_key of the profile (known: none)" in str(exc.value)


def test_the_runtime_checks_the_map_against_the_profile(tmp_path, pki, clock):
    from service.runtime import build_runtime
    from tests.test_sip_transport import sip_env
    net = network_yaml(tmp_path, cells=[{"cell": mcf.ECGI,
                                         "location": {"track_section": "S1"}}],
                       fname="n.yaml")
    with pytest.raises(StartupRefused) as exc:
        build_runtime(sip_env(tmp_path, pki, MCX_NETWORK_FILE=str(net),
                              MCX_RELEASE="19"), clock)
    assert "not a location_key" in str(exc.value)


# ============================================================ end to end: REC by area


@pytest.fixture
def cells():
    """Overrides test_adhoc's: the frmcs runtime starts with a real cell map,
    ECGI -> track section S1 and NCGI -> S2, in its network profile."""
    return [{"cell": mcf.ECGI, "location": {"track_section": "S1"}},
            {"cell": mcf.NCGI, "location": {"track_section": "S2"}}]


@pytest.fixture
def area(rt):
    """rec-area holders F1, F2 at track section S1 and F5 at S2."""
    resolver = rt.loaded.hooks.identity_resolver
    for u in (F[1], F[2]):
        resolver.bind("rec-area", u, LocationContext(attributes={"track_section": "S1"}))
    resolver.bind("rec-area", F[5], LocationContext(attributes={"track_section": "S2"}))
    return rt


def rec_invite(cid, report=None):
    extra = [(mcf.CT_LOCATION, report)] if report is not None else []
    body = mcf.with_parts(SDP, mcf.adhoc_xml(criteria="rec-area"), *extra)
    return msg("INVITE", LOCAL, cid, 1, F[0], LOCAL, body=body, ctype=mcf.CONTENT_TYPE)


def invited(world):
    return [u for u in F[1:] if world[u].requests("INVITE")]


def test_a_reported_cell_selects_the_area(core, area, world):
    core.on_bytes(rec_invite("loc1", mcf.location_report(ecgi=mcf.ECGI)), world[F[0]])
    assert invited(world) == [F[1], F[2]]


def test_another_cell_selects_another_area(core, area, world):
    core.on_bytes(rec_invite("loc2", mcf.location_report(ncgi=mcf.NCGI)), world[F[0]])
    assert invited(world) == [F[5]]


@pytest.mark.parametrize("report", [
    None,
    mcf.location_report(ecgi=mcf.ECGI, encrypted=True),
    mcf.location_report(ecgi="001010" + "1" * 28),                 # not in the map
])
def test_no_usable_location_still_matches_nobody(core, area, world, report):
    core.on_bytes(rec_invite("loc3", report), world[F[0]])
    code, warning = refusal(world[F[0]])
    assert code == 403 and "187 " in warning and invited(world) == []


def test_the_map_fills_in_but_does_not_overrule(rt):
    """Attributes a request already carries are kept (section 2.8)."""
    from core.hooks import MediaKind, SessionRequest
    request = SessionRequest(request_id="r", initiator=F[0], target="", call_type="x",
                             media=(MediaKind.VOICE,),
                             location=LocationContext(cell_id=mcf.ECGI,
                                                      attributes={"yard_id": "Y9"}))
    located = rt.manager._located(request)
    assert dict(located.location.attributes) == {"track_section": "S1", "yard_id": "Y9"}
    kept = rt.manager._located(dataclasses.replace(
        request, location=LocationContext(cell_id=mcf.ECGI,
                                          attributes={"track_section": "S9"})))
    assert dict(kept.location.attributes) == {"track_section": "S9"}
    assert rt.manager._located(dataclasses.replace(request, location=None)).location is None
