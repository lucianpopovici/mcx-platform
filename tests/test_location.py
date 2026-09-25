"""The client's location report (TS 24.379 annex F.3) and the profile's cell
map (PLT-ICD-001 2.8; PLT-VP-R1 ADHOC-OP-03)."""

from __future__ import annotations

import copy
import dataclasses
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import mcinfo  # noqa: E402
from core.validation import build  # noqa: E402
from tests import mcpttinfo_fixture as mcf  # noqa: E402
from tests.test_adhoc import (  # noqa: E402,F401  (fixtures)
    F, LOCAL, SDP, Flow, adhoc_invite, clock, core, list_max, msg, pki, refusal, rt,
    world)
from tests.test_loader import expect_defects, mutate, mcx_raw  # noqa: E402,F401
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


# ============================================================ the profile's cell map


@pytest.fixture
def frmcs_raw():
    import yaml
    return yaml.safe_load((ROOT / "profiles" / "frmcs" / "profile.yaml").read_text())


def test_a_cell_map_is_read_into_the_model(frmcs_raw):
    raw = copy.deepcopy(frmcs_raw)
    raw["identity"]["cells"] = [
        {"cell": mcf.ECGI, "location": {"track_section": "S1"}},
        {"cell": mcf.NCGI, "location": {"track_section": "S2", "yard_id": "Y1"}}]
    prof = build(raw, "h")
    assert dict(prof.identity.cells[mcf.ECGI]) == {"track_section": "S1"}
    assert dict(prof.identity.cells[mcf.NCGI]) == {"track_section": "S2", "yard_id": "Y1"}


@pytest.mark.parametrize("cells, code", [
    ("not-a-list", "bad-type"),
    ([{"cell": "123", "location": {"track_section": "S1"}}], "bad-value"),
    ([{"cell": mcf.ECGI, "location": {"platform": "P1"}}], "unknown-key"),
    ([{"cell": mcf.ECGI, "location": {}}], "bad-value"),
    ([{"cell": mcf.ECGI, "location": {"track_section": 7}}], "bad-value"),
    ([{"cell": mcf.ECGI, "location": {"track_section": "S1"}},
      {"cell": mcf.ECGI, "location": {"track_section": "S2"}}], "duplicate"),
    ([{"cell": mcf.ECGI}], "missing-key"),
    ([{"cell": mcf.ECGI, "location": {"track_section": "S1"}, "name": "x"}], "unknown-key"),
])
def test_a_bad_cell_map_is_refused(frmcs_raw, cells, code):
    raw = copy.deepcopy(frmcs_raw)
    raw["identity"]["cells"] = cells
    expect_defects(raw, codes=[code], path_contains="identity.cells")


def test_a_profile_without_location_keys_accepts_no_cells(mutate):
    raw = mutate()                                    # mcx: no functional identities
    raw["identity"]["cells"] = [{"cell": mcf.ECGI, "location": {"track_section": "S1"}}]
    expect_defects(raw, codes=["unknown-key"], path_contains="identity.cells")


# ============================================================ end to end: REC by area


def _with_cells(rt, cells):
    prof = rt.manager._profile
    rt.manager._profile = dataclasses.replace(
        prof, identity=dataclasses.replace(prof.identity, cells=cells))


@pytest.fixture
def area(rt):
    """rec-area holders F1, F2 at track section S1 and F5 at S2; the
    profile maps ECGI to S1 and NCGI to S2."""
    resolver = rt.loaded.hooks.identity_resolver
    for u in (F[1], F[2]):
        resolver.bind("rec-area", u, LocationContext(attributes={"track_section": "S1"}))
    resolver.bind("rec-area", F[5], LocationContext(attributes={"track_section": "S2"}))
    _with_cells(rt, {mcf.ECGI: {"track_section": "S1"}, mcf.NCGI: {"track_section": "S2"}})
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
    _with_cells(rt, {mcf.ECGI: {"track_section": "S1", "yard_id": "Y1"}})
    from core.hooks import MediaKind, SessionRequest
    request = SessionRequest(request_id="r", initiator=F[0], target="", call_type="x",
                             media=(MediaKind.VOICE,),
                             location=LocationContext(cell_id=mcf.ECGI,
                                                      attributes={"track_section": "S9"}))
    located = rt.manager._located(request)
    assert dict(located.location.attributes) == {"track_section": "S9", "yard_id": "Y1"}
    assert rt.manager._located(dataclasses.replace(request, location=None)).location is None
