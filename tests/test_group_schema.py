"""XSD validation of the group document (PLT-CONF-AUDIT CA-08, VP1-DOC-001).

`VP1-DOC-001` requires the group document to be "schema-valid". Everything up
to now has been structural assertion: `service/groups.check_rendered` walks the
tree and checks the elements TS 24.481 names. That catches a missing element.
It cannot catch element ORDER, an attribute's type, or a cardinality — and the
OMA content model is an `xs:sequence`, so order is a real constraint.

This file does the real thing, driven by the schemas in `docs/OMA/`.

Why it can skip
---------------
`OMA-SUP-XSD_poc_listService` imports `urn:ietf:params:xml:ns:resource-lists`
(RFC 4826) and types its `display-name` and `entry` elements from it:

    <xs:element name="display-name" type="rl:display-nameType" .../>
    <xs:element name="entry"        type="rl:entryType"        .../>

Its `schemaLocation` points at iana.org, which this build environment cannot
reach. Without `resource-lists.xsd` present, libxml2 cannot resolve those two
QNames and the schema set cannot be built at all.

So the validation is written, and skips with an exact reason until that one
file is added to `docs/OMA/`. Dropping in a hand-written stand-in for the IETF
schema would make the test pass and prove nothing, which is the failure mode
this whole audit exists to avoid.

`test_the_schema_harness_itself_works` exercises the loader and resolver
against a self-contained OMA schema, so the machinery is not itself unproven
while the target validation is skipped.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

lxml_etree = pytest.importorskip("lxml.etree")

DOCS = ROOT / "docs" / "OMA"

# Remote schemaLocation -> the local file that satisfies it. The OMA schemas
# are published as .txt; the content is XSD.
LOCAL_SCHEMAS = {
    "urn:oma:xml:poc:list-service":
        "OMA-SUP-XSD_poc_listService-V1_0_2-20090922-A.txt",
    "urn:oma:xml:xdm:extensions":
        "OMA-SUP-XSD_xdm_extensions-V1_0_1-20160503-A.txt",
    "urn:oma:xml:xdm:resource-list:oma-uriusage":
        "OMA-SUP-XSD_xdm_rsrclst_uriusage-V1_0_2-20160503-A.txt",
}

# The one file that is not here. RFC 4826 appendix A publishes it; IANA serves
# it at the schemaLocation the OMA schema names.
RESOURCE_LISTS = "resource-lists.xsd"


def _schema_path(name: str) -> Path:
    return DOCS / name


def _have_resource_lists() -> bool:
    return any((DOCS / n).is_file()
               for n in (RESOURCE_LISTS, "OMA-SUP-XSD_resource_lists.txt"))


class _LocalResolver(lxml_etree.Resolver):
    """Serve imports from `docs/OMA/` instead of the network.

    An import this map does not cover resolves to nothing, which makes the
    schema build fail loudly rather than silently validating against less than
    it claims to.
    """

    def __init__(self, extra: dict) -> None:
        self._by_tail = {
            "poc_listService-v1_0.xsd": LOCAL_SCHEMAS["urn:oma:xml:poc:list-service"],
            "resource-lists.xsd": RESOURCE_LISTS,
            **extra,
        }

    def resolve(self, url, public_id, context):
        tail = url.rsplit("/", 1)[-1]
        name = self._by_tail.get(tail)
        if name and (DOCS / name).is_file():
            return self.resolve_filename(str(DOCS / name), context)
        return None


def _parser() -> "lxml_etree.XMLParser":
    parser = lxml_etree.XMLParser(load_dtd=False, no_network=True)
    parser.resolvers.add(_LocalResolver({}))
    return parser


def test_the_schema_harness_itself_works():
    """Proves the loader and resolver, so the skip below is a statement about
    one missing file and not about untested machinery.

    Uses a self-contained OMA schema -- zero imports -- and a document that
    does not satisfy it, so a validator that always returned True would fail
    this test.
    """
    path = _schema_path("OMA-SUP-XSD_xdm_search-V1_0_1-20160503-A.txt")
    assert path.is_file(), path
    schema = lxml_etree.XMLSchema(lxml_etree.parse(str(path), _parser()))
    wrong = lxml_etree.fromstring(b"<not-a-search-document/>")
    assert not schema.validate(wrong), "the validator accepts anything"


@pytest.mark.skipif(not _have_resource_lists(),
                    reason=f"docs/OMA/{RESOURCE_LISTS} (RFC 4826) is not in the "
                           f"repository; OMA-SUP-XSD_poc_listService imports "
                           f"urn:ietf:params:xml:ns:resource-lists and types "
                           f"display-name and entry from it, so the schema "
                           f"set cannot be built without it")
def test_the_group_document_is_schema_valid():
    """VP1-DOC-001's "schema-valid" clause, done properly."""
    from service.groups import Group, render

    schema = lxml_etree.XMLSchema(lxml_etree.parse(
        str(_schema_path(LOCAL_SCHEMAS["urn:oma:xml:poc:list-service"])),
        _parser()))
    group = Group("sip:alpha@mcptt.example", "Alpha",
                  ("sip:u1@mcptt.example", "sip:u2@mcptt.example"))
    doc = lxml_etree.fromstring(render(group))
    assert schema.validate(doc), schema.error_log


def test_the_content_model_order_is_what_the_schema_requires():
    """`list-service-type` is an `xs:sequence`, read from
    OMA-SUP-XSD_poc_listService:

        display-name          minOccurs=0
        list                  minOccurs=0
        invite-members        minOccurs=0
        max-participant-count minOccurs=0
        xs:any ##other        minOccurs=0 maxOccurs=unbounded
        @uri                  use=required

    So `supported-services`, which is in another namespace, must come AFTER
    `display-name` and `list` -- it matches the trailing wildcard. Nothing
    checked this before: `check_rendered` walks the tree by name and would
    accept any order. This runs whether or not the IETF schema is present.
    """
    from xml.etree import ElementTree as ET
    from service.groups import Group, render

    ls = "{urn:oma:xml:poc:list-service}"
    oxe = "{urn:oma:xml:xdm:extensions}"
    root = ET.fromstring(render(Group("sip:a@x", "A", ("sip:u@x",))))

    assert root.tag == ls + "group"
    service = root.find(ls + "list-service")
    assert service is not None
    assert service.get("uri"), "@uri is use=required"

    order = [child.tag for child in service]
    assert order == [ls + "display-name", ls + "list", oxe + "supported-services"], order
