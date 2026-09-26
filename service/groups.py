"""Group documents (PLT-GRP-001, VP1-DOC-001).

Group configuration is deployment data, not service profile data: the core
must not learn any deployment's groups. It is part of the network profile
(`groups` and `users`, service/network.py; SVC-OP-03, decided 2026-09-26), and
counts toward its hash, so every audit record names the group data in force.

Every group member is also a known user, so a private call to one resolves.
Registering over SIP does not make a user known: being registered says where a
user can be reached, the directory says who exists (SIP-OP-05).

CONFORMANCE (PLT-CONF-AUDIT CA-04): the document this renders was checked
against 3GPP TS 24.481 V17.8.0 clause 7.2.2 and the worked example in clause
A.2, and was wrong in four ways: the root element, the namespace, a missing
mandatory element and the media type. All four are corrected here.

SVC-OP-01 stays OPEN, but for a narrower and now precisely stated reason: TS
24.481 clause 7.2.2 defines an MCS group document as the OMA XDM Group
structure "with the MCS specific clarifications specified in this subclause",
and the OMA schema (OMA-TS-XDM_Group-V1_1_1) is not a 3GPP deliverable and is
not in this repository. The 3GPP-specific parts are now pinned; full XSD
validation of the OMA-defined parts needs that document. VP1-DOC-001's
"schema-valid" clause is closed for everything 24.481 specifies and open for
the rest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from xml.etree import ElementTree as ET

# TS 24.481 clause 7.2.2 and the example in clause A.2. The document namespace
# is the OMA one; resource-lists appears only on <entry> child elements that
# the OMA structure imports, which this renderer does not yet emit.
LIST_SERVICE_NS = "urn:oma:xml:poc:list-service"
XDM_EXTENSIONS_NS = "urn:oma:xml:xdm:extensions"
MCPTT_GROUP_INFO_NS = "urn:3gpp:ns:mcpttGroupInfo:1.0"
RESOURCE_LISTS_NS = "urn:ietf:params:xml:ns:resource-lists"

# TS 24.481 clause 7.2.6 defers the media type to OMA XDM Group; the XCAP PUT
# in the clause A.2 example carries it explicitly. It is NOT application/xml,
# which is what this used to declare.
MEDIA_TYPE = "application/vnd.oma.poc.groups+xml"

# The MCPTT ICSI, which clause 7.2.8 requires as the "enabler" attribute of
# the <service> element. Same value as TS 24.379 uses for the feature tag.
MCPTT_ICSI = "urn:urn-7:3gpp-service.ims.icsi.mcptt"


@dataclass(frozen=True)
class Group:
    id: str
    display_name: str
    members: Tuple[str, ...]


def _q(ns: str, tag: str) -> str:
    return f"{{{ns}}}{tag}"


def render(group: Group) -> bytes:
    """An MCPTT group document, per TS 24.481 clause 7.2.2.

    The root is <group> in the OMA list-service namespace with <list-service>
    beneath it -- not <list-service> as the root in the resource-lists
    namespace, which is what this emitted before CA-04.

    <supported-services> is mandatory ("shall include", clause 7.2.2), and
    clause 7.2.8 makes it the thing that makes a group document an MCPTT
    group document at all: without a <service> whose "enabler" attribute is
    the MCPTT ICSI and whose <group-media> contains <mcptt-speech>, a
    conformant group management server does not recognise this as an MCPTT
    group. It was absent entirely.
    """
    ET.register_namespace("", LIST_SERVICE_NS)
    ET.register_namespace("oxe", XDM_EXTENSIONS_NS)
    ET.register_namespace("mcpttgi", MCPTT_GROUP_INFO_NS)
    ET.register_namespace("rl", RESOURCE_LISTS_NS)

    ls = lambda t: _q(LIST_SERVICE_NS, t)        # noqa: E731
    oxe = lambda t: _q(XDM_EXTENSIONS_NS, t)     # noqa: E731
    gi = lambda t: _q(MCPTT_GROUP_INFO_NS, t)    # noqa: E731

    root = ET.Element(ls("group"))
    service = ET.SubElement(root, ls("list-service"), {"uri": group.id})
    ET.SubElement(service, ls("display-name")).text = group.display_name
    lst = ET.SubElement(service, ls("list"))
    for m in group.members:
        ET.SubElement(lst, ls("entry"), {"uri": m})

    supported = ET.SubElement(service, oxe("supported-services"))
    svc = ET.SubElement(supported, oxe("service"), {"enabler": MCPTT_ICSI})
    ET.SubElement(ET.SubElement(svc, oxe("group-media")), gi("mcptt-speech"))

    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def check_rendered(group: Group, document: bytes) -> None:
    """Structural conformance to TS 24.481 clause 7.2.2, plus round-trip.

    This is not full XSD validation: the OMA-defined parts of the structure
    need OMA-TS-XDM_Group-V1_1_1, which is not in this repository (SVC-OP-01).
    Everything 24.481 itself specifies is checked.
    """
    root = ET.fromstring(document)
    ls = lambda t: _q(LIST_SERVICE_NS, t)        # noqa: E731
    oxe = lambda t: _q(XDM_EXTENSIONS_NS, t)     # noqa: E731
    gi = lambda t: _q(MCPTT_GROUP_INFO_NS, t)    # noqa: E731

    assert root.tag == ls("group"), root.tag
    service = root.find(ls("list-service"))
    assert service is not None, "no <list-service> element"
    assert service.get("uri") == group.id

    # OMA-SUP-XSD_poc_listService types <list-service> as an xs:sequence --
    # display-name, list, invite-members, max-participant-count, then a
    # trailing xs:any for ##other namespaces -- with @uri use="required".
    # So an extension element must come AFTER the OMA-defined ones. Walking
    # the tree by name, as this used to, accepts any order (CA-08).
    order = [child.tag for child in service]
    expected = [ls("display-name"), ls("list"), oxe("supported-services")]
    assert order == expected, (order, expected)

    entries = tuple(e.get("uri") for e in service.iter(ls("entry")))
    assert entries == group.members, (entries, group.members)

    # Clause 7.2.8 (Data semantics): all five conditions, or this is not an
    # MCPTT group
    # document as far as a conformant peer is concerned.
    supported = service.find(oxe("supported-services"))
    assert supported is not None, "<supported-services> is mandatory"
    svc = supported.find(oxe("service"))
    assert svc is not None, "<supported-services> needs a <service> child"
    assert svc.get("enabler") == MCPTT_ICSI, svc.get("enabler")
    media = svc.find(oxe("group-media"))
    assert media is not None, "<service> needs a <group-media> child"
    assert media.find(gi("mcptt-speech")) is not None, \
        "<group-media> needs <mcptt-speech>"


class GroupDirectory:
    def __init__(self, groups: Tuple[Group, ...],
                 users: Tuple[str, ...] = ()) -> None:
        self._groups: Dict[str, Group] = {g.id: g for g in groups}
        self._users = tuple(dict.fromkeys(
            list(users) + [m for g in groups for m in g.members]))

    def users(self) -> Tuple[str, ...]:
        return self._users

    def ids(self) -> Tuple[str, ...]:
        return tuple(self._groups)

    def get(self, group_id: str) -> Optional[Group]:
        return self._groups.get(group_id)

    def all(self) -> Tuple[Group, ...]:
        return tuple(self._groups.values())
