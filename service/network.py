"""The network profile (PLT-ICD-001 2.8; NET-OP-01, ICD-OP-10).

Facts about the network one deployment runs in, as opposed to the service
profile's facts about the service: which PLMNs it is, which cell stands for
which location attributes, and which SIP cores are trusted to assert
identities, with the CA that issues their certificates. They change when the
radio plan or the core changes, not when the service does, so they live in
their own file, named by MCX_NETWORK_FILE (required, no default):

    name: rail-ops
    version: "3"
    plmns: ["001010"]                     # MCC + MNC, as tPlmnIdentityFormat
    cells:
      - {cell: "0010100000000000000000000100100011", location: {track_section: S1}}
    sip:
      trusted_cores: [core1.rail.example]  # [] when none is trusted
      core_ca: core-ca.pem                 # "none" when none is trusted

Every key is required; an empty list or "none" is how a deployment says it has
nothing there. The file and the core CA certificate are hashed together, and
the identifier `name/version/hash` joins the service profile and the release
in every audit record, so a record says which network data was in force.

Checked at startup, every defect at once.
"""

from __future__ import annotations

import datetime
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

import yaml
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from core import mcinfo
from core.errors import StartupRefused
from core.loader import content_hash

from .config import is_fqdn

NONE = "none"
KEYS = {"name", "version", "plmns", "cells", "sip"}
SIP_KEYS = {"trusted_cores", "core_ca"}
# "/" and "+" separate the parts of the audit identifier, so neither may occur.
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
PLMN = re.compile(r"[0-9]{6}")                # tPlmnIdentityFormat, \d{3}\d{3}


@dataclass(frozen=True)
class Network:
    name: str
    version: str
    content_hash: str
    plmns: Tuple[str, ...]
    cells: Mapping[str, Mapping[str, str]]
    trusted_cores: Tuple[str, ...]
    # Parsed once, and handed to the TLS context as data: what was checked
    # and hashed is what is trusted, whatever happens to the file later.
    core_ca: Optional[x509.Certificate] = field(default=None, compare=False)

    def identifier(self) -> str:
        return f"{self.name}/{self.version}/{self.content_hash[:16]}"


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(Encoding.DER,
                                          PublicFormat.SubjectPublicKeyInfo)


_PEM_LABEL = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")


def _pem_certificates(path: Path, what: str,
                      defects: List[str]) -> Optional[List[x509.Certificate]]:
    """Every block must be a CERTIFICATE. OpenSSL, reading the same file as
    verify locations, would also take TRUSTED CERTIFICATE blocks as anchors,
    which this parser does not see and so could neither check nor hash
    (review of NET-OP-01)."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        defects.append(f"{what}: {path}: {exc}")
        return None
    others = sorted({m.decode() for m in _PEM_LABEL.findall(data)} - {"CERTIFICATE"})
    if others:
        defects.append(f"{what}: {path}: holds {', '.join(others)} block(s); only "
                       "CERTIFICATE blocks are accepted")
        return None
    try:
        return x509.load_pem_x509_certificates(data)
    except ValueError as exc:
        defects.append(f"{what}: {path}: {exc}")
        return None


def _signs(issuer: x509.Certificate, cert: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def _load_ca(path: Path, anchors: Sequence[x509.Certificate],
             defects: List[str]) -> Optional[x509.Certificate]:
    """The core CA (ICD-OP-10): a root of its own, issuing leaves only.

    - Self-signed. An intermediate under the users' root would also issue
      users, and its leaves carrying a core's name would be cores.
    - pathLenConstraint 0. Then a certificate chains through it only if it
      issued the certificate directly, which is what `issued_by` checks: no
      sub-CA of it can put a peer into the handshake unrecognised.
    - Not a users' anchor, not named like one, and not issuing one.
    """
    certs = _pem_certificates(path, "sip.core_ca", defects)
    if certs is None:
        return None
    if len(certs) != 1:
        defects.append(f"sip.core_ca: {path}: expected exactly one certificate, "
                       f"found {len(certs)}")
        return None
    ca = certs[0]
    where = f"sip.core_ca: {path}"
    try:
        bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        bc = None
    if bc is None or not bc.ca:
        defects.append(f"{where}: not a CA certificate (basicConstraints cA is not true)")
        return None
    if bc.path_length != 0:
        defects.append(f"{where}: basicConstraints pathLenConstraint must be 0, so "
                       "that it issues core certificates directly and nothing else "
                       f"(found {bc.path_length})")
    if not _signs(ca, ca):          # its own issuer name, and its own signature
        defects.append(f"{where}: not self-signed. The core CA must be a root of "
                       "its own; an intermediate under the users' root would issue "
                       "users too")
    try:
        ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.key_cert_sign:
            defects.append(f"{where}: keyUsage lacks keyCertSign")
    except x509.ExtensionNotFound:
        pass
    now = datetime.datetime.now(datetime.timezone.utc)
    if not ca.not_valid_before_utc <= now <= ca.not_valid_after_utc:
        defects.append(f"{where}: not valid now (valid {ca.not_valid_before_utc:%Y-%m-%d} "
                       f"to {ca.not_valid_after_utc:%Y-%m-%d})")
    for a in anchors:
        if _spki(a) == _spki(ca):
            defects.append("sip.core_ca: the same CA (by key) is in MCX_SIP_TLS_CA, "
                           "the users' trust anchor. Cores need a CA of their own "
                           "(ICD-OP-10)")
        elif a.subject == ca.subject:
            # Two anchors with one name: OpenSSL may try the wrong one.
            defects.append(f"sip.core_ca: its subject {ca.subject.rfc4514_string()} "
                           "is also the name of a CA in MCX_SIP_TLS_CA")
        elif _signs(ca, a):
            defects.append(f"sip.core_ca: it issued {a.subject.rfc4514_string()}, a "
                           "CA in MCX_SIP_TLS_CA: users would chain to it")
    return ca                       # with any defect, load_network refuses


def _cells(raw: Any, keys: Set[str], plmns: Set[str],
           defects: List[str]) -> Mapping[str, Mapping[str, str]]:
    if not isinstance(raw, list):
        defects.append("cells: expected a list ([] when there is no cell map)")
        return MappingProxyType({})
    out: Dict[str, Mapping[str, str]] = {}
    for i, item in enumerate(raw):
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
        if cell[:6] not in plmns:
            # A cell of another network: its reports would come from a client
            # roaming there, and the attributes it maps to would be this
            # network's. Most likely a copy from the wrong radio plan.
            defects.append(f"{where}.cell: PLMN {cell[:6]} is not one of this "
                           f"network's plmns ({', '.join(sorted(plmns)) or 'none'})")
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
            if k not in keys:
                # A key no identity reads could never matter: a typo, most likely.
                defects.append(
                    f"{where}.location.{k}: not a location_key of the profile "
                    f"(known: {', '.join(sorted(keys)) or 'none'})")
            elif not isinstance(v, str) or not v:
                defects.append(f"{where}.location.{k}: expected a non-empty string")
            else:
                attrs[k] = v
        out[cell] = MappingProxyType(attrs)
    return MappingProxyType(out)


def load_network(path: Path, location_keys: Set[str],
                 user_ca: Optional[Path] = None) -> Network:
    """`user_ca` is MCX_SIP_TLS_CA when SIP is enabled: the core CA must be
    kept apart from its anchors, or a user certificate could be a core's."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        raise StartupRefused(f"network profile {path}: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != KEYS:
        got = sorted(raw) if isinstance(raw, dict) else type(raw).__name__
        raise StartupRefused(
            f"network profile {path}: expected exactly the keys "
            f"{', '.join(sorted(KEYS))}; found {got}")
    defects: List[str] = []

    ident = {}
    for key in ("name", "version"):
        v = raw[key]
        # A string, quoted if it looks like a number: YAML reads `version: 010`
        # as 8, and the audit record would name a version nobody wrote.
        if not isinstance(v, str) or not _TOKEN.fullmatch(v):
            defects.append(f"{key}: expected a string of letters, digits, '.', '_' "
                           "or '-' (up to 64, no '/' or '+'; quote numbers)")
        ident[key] = v

    plmns: Set[str] = set()
    if not isinstance(raw["plmns"], list) or not raw["plmns"]:
        defects.append("plmns: expected a non-empty list")
    else:
        for i, p in enumerate(raw["plmns"]):
            if not isinstance(p, str) or not PLMN.fullmatch(p):
                defects.append(f"plmns[{i}]: expected six digits, MCC then MNC, "
                               "as the first six digits of the cells' ECGI/NCGI")
            elif p in plmns:
                defects.append(f"plmns[{i}]: {p} listed twice")
            else:
                plmns.add(p)

    cells = _cells(raw["cells"], location_keys, plmns, defects)

    sip = raw["sip"]
    trusted: Tuple[str, ...] = ()
    ca_path: Optional[Path] = None
    ca: Optional[x509.Certificate] = None
    if not isinstance(sip, dict) or set(sip) != SIP_KEYS:
        defects.append("sip: expected exactly 'trusted_cores' and 'core_ca'")
    else:
        cores = sip["trusted_cores"]
        if not isinstance(cores, list) or not all(isinstance(c, str) for c in cores):
            defects.append("sip.trusted_cores: expected a list of DNS names "
                           "([] when no core is trusted)")
        else:
            bad = [c for c in cores if not is_fqdn(c.lower())]
            if bad:
                # Fully qualified names only: a single label such as
                # "localhost" is on many certificates (review of ICD-OP-08).
                defects.append(f"sip.trusted_cores: not fully qualified DNS "
                               f"names: {', '.join(map(repr, bad))}")
            trusted = tuple(sorted({c.lower() for c in cores}))
        raw_ca = sip["core_ca"]
        if not isinstance(raw_ca, str) or not raw_ca.strip():
            defects.append("sip.core_ca: expected a file, or 'none'")
        elif raw_ca.strip().lower() == NONE:
            if trusted:
                defects.append(
                    "sip.core_ca: 'none', but trusted_cores is not empty. A "
                    "trusted core must hold a certificate from a CA of its own: "
                    "on a CA shared with users, any user certificate carrying "
                    "the core's name would be the core (ICD-OP-10)")
        else:
            ca_path = (path.parent / raw_ca.strip()).resolve()
            if cores == []:
                defects.append("sip.core_ca: given, but trusted_cores is empty; "
                               "write 'none'")
            anchors: Sequence[x509.Certificate] = ()
            if user_ca is not None:
                anchors = _pem_certificates(user_ca, "MCX_SIP_TLS_CA", defects) or ()
            ca = _load_ca(ca_path, anchors, defects)

    if defects:
        raise StartupRefused(f"network profile {path}: {len(defects)} defect(s)\n  "
                             + "\n  ".join(defects))
    ca_hash = hashlib.sha256(ca.public_bytes(Encoding.DER)).hexdigest() if ca else None
    return Network(name=ident["name"], version=ident["version"],
                   content_hash=content_hash({"network": raw, "core_ca": ca_hash}),
                   plmns=tuple(sorted(plmns)), cells=cells, trusted_cores=trusted,
                   core_ca=ca)
