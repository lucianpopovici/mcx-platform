"""Network profiles for tests (service/network.py, PLT-ICD-001 2.8)."""

from __future__ import annotations

import json
from pathlib import Path

PLMN = "001010"          # the PLMN of mcpttinfo_fixture's ECGI and NCGI


def network_yaml(directory: Path, *, name="test-net", version="1", plmns=(PLMN,),
                 cells=(), trusted_cores=(), core_ca="none",
                 fname="network.yaml") -> Path:
    """Every key written, as the file requires. JSON is YAML."""
    p = Path(directory) / fname
    p.write_text(json.dumps({"name": name, "version": version,
                             "plmns": list(plmns), "cells": list(cells),
                             "sip": {"trusted_cores": list(trusted_cores),
                                     "core_ca": str(core_ca)}}))
    return p
