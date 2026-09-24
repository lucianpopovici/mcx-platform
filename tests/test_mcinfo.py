"""TS 24.379 annex F.1 -- the MCPTT info body (PLT-CONF-AUDIT CA-20).

The rendered body is validated against the schema printed in the
specification itself, extracted verbatim to docs/3GPP/schemas by
tools/spec/extract_xsd.py, for each release whose schema differs in what the
platform uses. Names and the namespace are also spelled out as literals.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import mcinfo  # noqa: E402
from core.release import Release  # noqa: E402

lxml = pytest.importorskip("lxml.etree")
SCHEMAS = ROOT / "docs" / "3GPP" / "schemas"
# TS 24.379 version -> the TS 24.481 version whose GKTP schema it imports
SCHEMA_OF = {Release.REL_17: ("hf0", "h80"), Release.REL_18: ("id0", "i30"),
             Release.REL_20: ("k00", "j30")}


def _schema(release):
    spec, gktp = SCHEMA_OF[release]
    driver = f'''<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
      <xs:import namespace="urn:3gpp:ns:mcpttGKTP:1.0"
                 schemaLocation="{SCHEMAS / f'mcpttgktp-24481-{gktp}.xsd'}"/>
      <xs:import namespace="urn:3gpp:ns:mcpttInfo:1.0"
                 schemaLocation="{SCHEMAS / f'mcpttinfo-24379-{spec}.xsd'}"/>
    </xs:schema>'''
    return lxml.XMLSchema(lxml.fromstring(driver.encode()))


def _doc(text):
    return lxml.fromstring(text.split("?>", 1)[1].strip().encode())


FULL = mcinfo.McInfo(session_type="prearranged", request_uri="sip:u1@x",
                     calling_user_id="sip:u0@x", called_party_id="sip:u1@x",
                     calling_group_id="sip:grp@x", client_id="urn:uuid:0",
                     emergency=True, imminent_peril=False, broadcast=True)


def test_the_extracted_schemas_are_present_and_say_where_they_came_from():
    for release, (spec, gktp) in SCHEMA_OF.items():
        for name in (f"mcpttinfo-24379-{spec}.xsd", f"mcpttgktp-24481-{gktp}.xsd"):
            text = (SCHEMAS / name).read_text()
            assert "Extracted verbatim by tools/spec/extract_xsd.py" in text, name


@pytest.mark.parametrize("release", list(SCHEMA_OF))
def test_every_field_the_platform_sends_is_schema_valid(release):
    schema = _schema(release)
    assert schema.validate(_doc(mcinfo.render(FULL, release))), schema.error_log


@pytest.mark.parametrize("release", [Release.REL_18, Release.REL_20])
def test_ad_hoc_emergency_is_schema_valid_where_it_exists(release):
    info = mcinfo.McInfo(session_type="adhoc", request_uri="sip:grp@x", emergency=True)
    text = mcinfo.render(info, release)
    assert "<anyExt><adhoc-emergency-ind>true</adhoc-emergency-ind></anyExt>" in text
    assert "<emergency-ind" not in text
    schema = _schema(release)
    assert schema.validate(_doc(text)), schema.error_log


def test_ad_hoc_emergency_cannot_be_rendered_before_rel_18():
    with pytest.raises(mcinfo.McInfoError):
        mcinfo.render(mcinfo.McInfo(session_type="adhoc", emergency=True), Release.REL_17)


@pytest.mark.parametrize("release", list(SCHEMA_OF))
def test_the_format_the_platform_used_to_read_is_invalid(release):
    """What was parsed before CA-20. The schema rejects it in every release."""
    bad = ('<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>'
           "<mcptt-call_type>prearranged-group</mcptt-call_type>"
           "<mcptt-target>grp:alpha</mcptt-target></mcptt-Params></mcpttinfo>")
    assert not _schema(release).validate(lxml.fromstring(bad.encode()))


def test_render_uses_the_annex_f1_names_and_namespace():
    text = mcinfo.render(FULL, Release.REL_19)
    for literal in ('<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0">', "<mcptt-Params>",
                    "<session-type>prearranged</session-type>",
                    '<mcptt-calling-group-id type="Normal"><mcpttURI>sip:grp@x</mcpttURI>',
                    '<emergency-ind type="Normal"><mcpttBoolean>true</mcpttBoolean>',
                    "<broadcast-ind>true</broadcast-ind>"):
        assert literal in text, literal
    assert mcinfo.NAMESPACE == "urn:3gpp:ns:mcpttInfo:1.0"
    assert mcinfo.CONTENT_TYPE == "application/vnd.3gpp.mcptt-info+xml"


def test_round_trip():
    assert mcinfo.parse(mcinfo.render(FULL, Release.REL_19)) == FULL


def test_an_encrypted_field_is_recorded_not_guessed():
    """Clause 4.8 / 6.6.2: the platform holds no key. The field is absent and
    named, so a target that arrives encrypted is refused, not invented."""
    text = ('<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>'
            "<session-type>prearranged</session-type>"
            '<mcptt-request-uri type="Encrypted"><EncryptedData '
            'xmlns="http://www.w3.org/2001/04/xmlenc#"/></mcptt-request-uri>'
            "</mcptt-Params></mcpttinfo>")
    info = mcinfo.parse(text)
    assert info.request_uri is None and info.encrypted == frozenset({"mcptt-request-uri"})


@pytest.mark.parametrize("text", [
    # TS 24.379 V20.0.0 clause 4.8 EXAMPLE 5, as printed. Closed by
    # </mcptt-info>, so not well-formed (its missing namespace and the stray
    # '>' in the URI would only make it invalid).
    "<?xml version=\"1.0\"?>\n<mcpttinfo>\n<mcptt-Params>\n"
    "<session-type>prearranged</session-type>\n<mcptt-request-uri type=\"Normal\">\n"
    "<mcpttURI>sip:group123@mcpttoperator1.com></mcpttURI>\n</mcptt-request-uri>\n"
    "</mcptt-Params>\n</mcptt-info>",
    # well-formed but in no namespace: the schema is elementFormDefault qualified
    "<mcpttinfo><mcptt-Params><session-type>private</session-type></mcptt-Params></mcpttinfo>",
    '<!DOCTYPE mcpttinfo [<!ENTITY a "aaaa">]><mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"/>',
    '<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>'
    '<broadcast-ind>perhaps</broadcast-ind></mcptt-Params></mcpttinfo>',
])
def test_malformed_bodies_are_refused(text):
    with pytest.raises(mcinfo.McInfoError):
        mcinfo.parse(text)


def test_multipart_needs_its_delimiters():
    with pytest.raises(mcinfo.McInfoError):
        mcinfo.split_body("multipart/mixed;boundary=b", "v=0\r\n<mcpttinfo/>")
    with pytest.raises(mcinfo.McInfoError):
        mcinfo.split_body("multipart/mixed", "--b\r\n\r\nx\r\n--b--\r\n")
    ctype, body = mcinfo.build_multipart([mcinfo.Part("application/sdp", "v=0\r\n"),
                                          mcinfo.Part(mcinfo.CONTENT_TYPE, "<x/>")])
    assert [p.content_type for p in mcinfo.split_body(ctype, body)] == [
        "application/sdp", "application/vnd.3gpp.mcptt-info+xml"]
    assert mcinfo.sdp_of("application/sdp", "v=0\r\n") == "v=0\r\n"


def test_reachability_names_what_a_release_cannot_carry():
    from types import SimpleNamespace as NS
    cts = [NS(id="rec", mc_signature=mcinfo.Signature("adhoc", True)),
           NS(id="grp", mc_signature=mcinfo.Signature("prearranged")),
           NS(id="data", mc_signature=None)]
    undeclared, blocked = mcinfo.reachability(cts, Release.REL_17)
    assert undeclared == ("data",) and [b[0] for b in blocked] == ["rec"]
    assert mcinfo.reachability(cts, Release.REL_18)[1] == ()



# ---- found by independent review of the first version --------------------------

@pytest.mark.parametrize("decl", ["bogus", "UTF-7", "ISO-8859-1", "utf-16"])
def test_a_non_utf8_encoding_declaration_is_a_refusal_not_a_crash(decl):
    """"bogus" raised LookupError and "UTF-7" ValueError; both escaped as a
    500 with a traceback, from any unauthenticated INVITE."""
    text = (f'<?xml version="1.0" encoding="{decl}"?>'
            '<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"/>')
    with pytest.raises(mcinfo.McInfoError):
        mcinfo.parse(text)


def test_utf8_declarations_are_accepted():
    for decl in ("UTF-8", "utf-8", "utf8"):
        mcinfo.parse(f'<?xml version="1.0" encoding="{decl}"?>'
                     '<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"/>')


def test_a_multipart_body_without_its_close_delimiter_is_refused():
    """RFC 2046 5.1.1. The last part used to be dropped silently, turning a
    malformed request into a 404 or a 500 depending on part order."""
    body = "--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b\r\n" \
           "Content-Type: application/vnd.3gpp.mcptt-info+xml\r\n\r\n<x/>\r\n"
    with pytest.raises(mcinfo.McInfoError):
        mcinfo.split_body("multipart/mixed;boundary=b", body)


def test_boundary_inside_another_quoted_parameter_is_not_the_boundary():
    ctype = 'multipart/mixed;x="a;boundary=zz";boundary=REAL'
    body = "--REAL\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--REAL--\r\n"
    assert [p.content_type for p in mcinfo.split_body(ctype, body)] == ["application/sdp"]


def test_folded_part_headers_are_unfolded():
    body = "--b\r\nContent-Type:\r\n application/sdp\r\n\r\nv=0\r\n--b--\r\n"
    assert mcinfo.sdp_of("multipart/mixed;boundary=b", body).startswith("v=0")


def test_an_ad_hoc_emergency_is_never_silently_downgraded():
    """A non-conformant client that flags an ad hoc emergency with
    <emergency-ind> instead of <adhoc-emergency-ind> still gets an emergency."""
    text = ('<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>'
            "<session-type>adhoc</session-type>"
            '<emergency-ind type="Normal"><mcpttBoolean>true</mcpttBoolean></emergency-ind>'
            "</mcptt-Params></mcpttinfo>")
    assert mcinfo.parse(text).signature() == mcinfo.Signature("adhoc", emergency=True)


def test_an_encrypted_indication_selects_no_call_type():
    """The platform cannot read it, so it cannot know whether this is an
    emergency; it selects nothing rather than guess either way."""
    text = ('<mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params>'
            "<session-type>prearranged</session-type>"
            '<emergency-ind type="Encrypted"><x xmlns="urn:enc"/></emergency-ind>'
            "</mcptt-Params></mcpttinfo>")
    assert mcinfo.parse(text).signature() is None
