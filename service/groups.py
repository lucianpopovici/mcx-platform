"""Group documents (PLT-GRP-001, VP1-DOC-001).

Group configuration is deployment data, not profile data: the profile schema
has no group section, and the core must not learn any deployment's groups.
It is read from the file named by MCX_GROUPS_FILE:

    groups:
      - id: "grp:alpha"
        display_name: "Alpha team"
        members: ["sip:u1@mcptt.example", ...]

OPEN (SVC-OP-01): the TS 24.481 schema is not in this repository and could not
be obtained here. `render` emits an RFC 4826 resource-lists `list-service`
document, which 24.481 builds on, but its namespaces, extension elements and
media type are NOT checked against the specification. `check_rendered` proves
only that the document is well-formed and round-trips to the configuration.
VP1-DOC-001's "schema-valid" clause stays open until the schema is obtained.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

import yaml

from core.errors import StartupRefused

RESOURCE_LISTS_NS = "urn:ietf:params:xml:ns:resource-lists"
MEDIA_TYPE = "application/xml"      # SVC-OP-01: 24.481 media type unconfirmed


@dataclass(frozen=True)
class Group:
    id: str
    display_name: str
    members: Tuple[str, ...]


def load_groups(path: Optional[Path]) -> Tuple[Group, ...]:
    if path is None:
        return ()
    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        raise StartupRefused(f"groups file {path}: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != {"groups"} \
            or not isinstance(raw["groups"], list):
        raise StartupRefused(
            f"groups file {path}: expected a mapping with one key, 'groups'")
    groups: List[Group] = []
    seen = set()
    for i, g in enumerate(raw["groups"]):
        where = f"groups file {path}: groups[{i}]"
        if not isinstance(g, dict) or not set(g) <= {"id", "display_name", "members"}:
            raise StartupRefused(f"{where}: unknown or malformed keys")
        gid = g.get("id")
        members = g.get("members")
        if not isinstance(gid, str) or not gid:
            raise StartupRefused(f"{where}: id must be a non-empty string")
        if gid in seen:
            raise StartupRefused(f"{where}: duplicate group id {gid!r}")
        if not isinstance(members, list) or not members \
                or not all(isinstance(m, str) and m for m in members):
            raise StartupRefused(f"{where}: members must be a non-empty list of ids")
        seen.add(gid)
        # Deduplicate in declaration order, as the resolver does.
        ordered = tuple(dict.fromkeys(members))
        groups.append(Group(gid, str(g.get("display_name") or gid), ordered))
    return tuple(groups)


def render(group: Group) -> bytes:
    ET.register_namespace("", RESOURCE_LISTS_NS)
    q = lambda t: f"{{{RESOURCE_LISTS_NS}}}{t}"  # noqa: E731
    root = ET.Element(q("list-service"), {"uri": group.id})
    ET.SubElement(root, q("display-name")).text = group.display_name
    lst = ET.SubElement(root, q("list"))
    for m in group.members:
        ET.SubElement(lst, q("entry"), {"uri": m})
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def check_rendered(group: Group, document: bytes) -> None:
    """Well-formedness and round-trip only. NOT schema validation (SVC-OP-01)."""
    root = ET.fromstring(document)
    q = lambda t: f"{{{RESOURCE_LISTS_NS}}}{t}"  # noqa: E731
    assert root.tag == q("list-service"), root.tag
    assert root.get("uri") == group.id
    entries = tuple(e.get("uri") for e in root.iter(q("entry")))
    assert entries == group.members, (entries, group.members)


class GroupDirectory:
    def __init__(self, groups: Tuple[Group, ...]) -> None:
        self._groups: Dict[str, Group] = {g.id: g for g in groups}

    def ids(self) -> Tuple[str, ...]:
        return tuple(self._groups)

    def get(self, group_id: str) -> Optional[Group]:
        return self._groups.get(group_id)

    def all(self) -> Tuple[Group, ...]:
        return tuple(self._groups.values())
