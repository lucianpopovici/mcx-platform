"""A throwaway certificate authority for an interoperability run.

Two CAs -- one for the SIP cores, one for everyone else (ICD-OP-10) -- and
one leaf per party, all valid for localhost and 127.0.0.1, written
as PEM into a working directory. RSA rather than EC because the third-party
cores' TLS configuration is simplest to reason about with it; nothing here is
meant to outlive the run.
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn: str, now, path_length=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), True)
            .sign(key, hashes.SHA256()))
    return key, cert


def make(directory: Path, parties: Iterable[str],
         uris: Optional[Mapping[str, Sequence[str]]] = None,
         cores: Iterable[str] = ()) -> Path:
    """One certificate per party. `uris` adds subjectAltName URIs: a user's
    certificate names the sip: identity it may assert to the platform
    (PLT-ICD-001 ICD-OP-08).

    Parties named in `cores` are SIP cores: their certificates come from a CA
    of their own, `core-ca.crt`, which the network profile names (ICD-OP-10).
    Everyone else's come from `ca.crt`. `trust.crt` holds both, for the test
    clients, which talk to cores and to the platform alike."""
    uris = uris or {}
    cores = set(cores)
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, ca = _ca("mcx-interop-ca", now)
    # pathLenConstraint 0: it issues core certificates directly, nothing else.
    core_key, core_ca = _ca("mcx-interop-core-ca", now, path_length=0)
    pem = serialization.Encoding.PEM
    (directory / "ca.crt").write_bytes(ca.public_bytes(pem))
    (directory / "core-ca.crt").write_bytes(core_ca.public_bytes(pem))
    (directory / "trust.crt").write_bytes(ca.public_bytes(pem) + core_ca.public_bytes(pem))

    for cn in parties:
        issuer, issuer_key = (core_ca, core_key) if cn in cores else (ca, ca_key)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder()
                .subject_name(_name(cn)).issuer_name(issuer.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=2))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.DNSName(cn),
                     x509.DNSName(f"{cn}.interop.test"),
                     x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                    + [x509.UniformResourceIdentifier(u) for u in uris.get(cn, ())]), False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                               False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                          x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()).digest),
                                     False)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False, key_agreement=False,
                    key_cert_sign=False, crl_sign=False, encipher_only=False,
                    decipher_only=False), True)
                .add_extension(x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                    False)
                .sign(issuer_key, hashes.SHA256()))
        (directory / f"{cn}.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        (directory / f"{cn}.crt").write_bytes(cert.public_bytes(pem))
    return directory
