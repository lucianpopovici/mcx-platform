"""The deployment's cell map (PLT-ICD-001 2.8; PLT-VP-R1 PRF-OP-03).

A client's location report names its serving cell (TS 24.379 annex F.3). A
profile's functional identities are keyed on location attributes such as
`track_section`. Which cell stands for which attributes depends on the radio
plan of one network, so it is deployment data, like the groups file:

    cells:
      - {cell: "0010100000000000000000000100100011", location: {track_section: S1}}

Checked at startup against the loaded profile, every defect at once.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import Dict, List, Mapping, Set

import yaml

from core import mcinfo
from core.errors import StartupRefused

# MCX_CELLS_FILE=none: the deployment states it has no cell map.
NONE = "none"


def load_cells(path: Path, location_keys: Set[str]) -> Mapping[str, Mapping[str, str]]:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        raise StartupRefused(f"cell map {path}: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != {"cells"} \
            or not isinstance(raw["cells"], list):
        raise StartupRefused(f"cell map {path}: expected one key, 'cells', holding a list")
    defects: List[str] = []
    out: Dict[str, Mapping[str, str]] = {}
    for i, item in enumerate(raw["cells"]):
        where = f"cells[{i}]"
        if not isinstance(item, dict) or set(item) != {"cell", "location"}:
            defects.append(f"{where}: expected exactly 'cell' and 'location'")
            continue
        cell = item["cell"]
        if not isinstance(cell, str) or not (mcinfo.ECGI.fullmatch(cell)
                                             or mcinfo.NCGI.fullmatch(cell)):
            defects.append(f"{where}.cell: expected an ECGI (6 digits + 28 binary "
                           "digits) or an NCGI (6 digits + 36 binary digits), as "
                           "TS 24.379 annex F.3 writes them")
            continue
        if cell in out:
            defects.append(f"{where}.cell: {cell!r} already mapped")
            continue
        loc = item["location"]
        if not isinstance(loc, dict) or not loc:
            defects.append(f"{where}.location: expected a non-empty mapping")
            continue
        attrs: Dict[str, str] = {}
        for k, v in loc.items():
            if k not in location_keys:
                # A key no identity reads could never matter: a typo, most likely.
                defects.append(
                    f"{where}.location.{k}: not a location_key of the profile "
                    f"(known: {', '.join(sorted(location_keys)) or 'none'})")
            elif not isinstance(v, str) or not v:
                defects.append(f"{where}.location.{k}: expected a non-empty string")
            else:
                attrs[k] = v
        out[cell] = MappingProxyType(attrs)
    if defects:
        raise StartupRefused(f"cell map {path}: {len(defects)} defect(s)\n  "
                             + "\n  ".join(defects))
    return MappingProxyType(out)
