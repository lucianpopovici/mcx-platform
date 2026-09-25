"""The network profile (PLT-ICD-001 2.8; NET-OP-01, ICD-OP-10).

The cell map's own checks are in tests/test_location.py, and the trusted-core
decision on the SIP path in tests/test_sip_transport.py.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.errors import StartupRefused  # noqa: E402
from service.config import Config  # noqa: E402
from service.network import load_network  # noqa: E402
from service.runtime import build_runtime  # noqa: E402
from tests.network_fixture import PLMN, network_yaml  # noqa: E402
from tests.test_sip_transport import Clock, pki, sip_env  # noqa: E402,F401  (fixture)

from cryptography import x509  # noqa: E402


def refused(path, keys=frozenset(), user_ca=None):
    with pytest.raises(StartupRefused) as exc:
        load_network(path, set(keys), user_ca)
    return str(exc.value)


def raw_yaml(tmp_path, doc, fname="net.yaml"):
    p = tmp_path / fname
    p.write_text(json.dumps(doc))
    return p


def mkca(directory, cn="other-core-ca", *, issuer=None, path_length=0,
         key_usage=None, days=(-1, 1), key=None, ca=True, fname=None):
    """A CA certificate written as PEM; returns (path, key, cert). `issuer`
    is (key, cert); without it the certificate is self-signed."""
    import datetime
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ikey, icert = issuer if issuer else (key, None)
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(subject)
         .issuer_name(icert.subject if icert else subject)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now + datetime.timedelta(days=days[0]))
         .not_valid_after(now + datetime.timedelta(days=days[1]))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None),
                        True))
    if key_usage is not None:
        b = b.add_extension(key_usage, True)
    cert = b.sign(ikey, hashes.SHA256())
    p = Path(directory) / (fname or f"{cn}.pem")
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return p, key, cert


def user_root(pki):
    from cryptography.hazmat.primitives import serialization
    return (serialization.load_pem_private_key((pki / "ca.key").read_bytes(), None),
            x509.load_pem_x509_certificate((pki / "ca.crt").read_bytes()))


def core_net(tmp_path, core_ca):
    return network_yaml(tmp_path, trusted_cores=["c.example"], core_ca=core_ca)


GOOD = {"name": "rail-ops", "version": "3", "plmns": [PLMN], "cells": [],
        "sip": {"trusted_cores": [], "core_ca": "none"}}


# ============================================================ a well-formed file


def test_a_network_profile_is_read(tmp_path, pki):
    n = load_network(network_yaml(tmp_path, name="rail-ops", version="3",
                                  plmns=["001010", "001001"],
                                  trusted_cores=["Core1.Rail.Example"],
                                  core_ca=pki / "core-ca.crt"), set())
    assert (n.name, n.version) == ("rail-ops", "3")
    assert n.plmns == ("001001", "001010")
    assert n.trusted_cores == ("core1.rail.example",)
    assert n.core_ca == x509.load_pem_x509_certificate((pki / "core-ca.crt").read_bytes())
    assert dict(n.cells) == {}
    assert n.identifier() == f"rail-ops/3/{n.content_hash[:16]}"
    assert len(n.content_hash) == 64


def test_the_core_ca_is_found_beside_the_file(tmp_path, pki):
    shutil.copy(pki / "core-ca.crt", tmp_path / "anchor.pem")
    n = load_network(network_yaml(tmp_path, trusted_cores=["c.example"],
                                  core_ca="anchor.pem"), set())
    assert n.core_ca is not None


def test_the_hash_covers_the_file(tmp_path):
    a = load_network(network_yaml(tmp_path, version="1"), set())
    b = load_network(network_yaml(tmp_path, version="2"), set())
    c = load_network(network_yaml(tmp_path, plmns=[PLMN, "001001"]), set())
    assert len({a.content_hash, b.content_hash, c.content_hash}) == 3
    assert load_network(network_yaml(tmp_path, version="1"), set()).content_hash \
        == a.content_hash


def test_the_hash_covers_the_core_ca_certificate_as_well_as_its_path(tmp_path, pki):
    """Replacing the certificate behind the same path changes the identity."""
    anchor = tmp_path / "anchor.pem"
    net = dict(trusted_cores=["c.example"], core_ca="anchor.pem")
    shutil.copy(pki / "core-ca.crt", anchor)
    before = load_network(network_yaml(tmp_path, **net), set()).content_hash
    shutil.copy(mkca(tmp_path)[0], anchor)
    assert load_network(network_yaml(tmp_path, **net), set()).content_hash != before


# ============================================================ what is refused


def test_a_missing_file_is_refused(tmp_path):
    assert "network profile" in refused(tmp_path / "absent.yaml")


@pytest.mark.parametrize("doc", [
    [], "text", {k: v for k, v in GOOD.items() if k != "cells"},
    {**GOOD, "trusted_peers": []}])
def test_the_keys_are_exactly_these(tmp_path, doc):
    text = refused(raw_yaml(tmp_path, doc))
    assert "expected exactly the keys cells, name, plmns, sip, version" in text


def test_bad_yaml_is_refused(tmp_path):
    p = tmp_path / "n.yaml"
    p.write_text("{{nope")
    assert "network profile" in refused(p)


@pytest.mark.parametrize("key, value", [
    ("name", "a/b"), ("name", "a+b"), ("name", ""), ("name", True),
    ("name", "x" * 65), ("version", None), ("version", "-1"), ("version", 1.5),
    ("version", 3), ("version", 8)])       # `version: 010` is 8 in YAML: quote it
def test_name_and_version_are_plain_tokens(tmp_path, key, value):
    """'/' and '+' separate the parts of the audit identifier."""
    text = refused(raw_yaml(tmp_path, {**GOOD, key: value}))
    assert f"{key}: expected a string of letters, digits" in text


@pytest.mark.parametrize("plmns, says", [
    ([], "plmns: expected a non-empty list"),
    ("001010", "plmns: expected a non-empty list"),
    (["00101"], "plmns[0]: expected six digits"),
    (["0010100"], "plmns[0]: expected six digits"),
    ([1010], "plmns[0]: expected six digits"),
    (["００１０１０"], "plmns[0]: expected six digits"),
    ([PLMN, PLMN], "plmns[1]: 001010 listed twice")])
def test_plmns_are_six_digit_identities(tmp_path, plmns, says):
    assert says in refused(raw_yaml(tmp_path, {**GOOD, "plmns": plmns}))


def test_cells_are_a_list(tmp_path):
    text = refused(raw_yaml(tmp_path, {**GOOD, "cells": {}}))
    assert "cells: expected a list ([] when there is no cell map)" in text


@pytest.mark.parametrize("sip, says", [
    ([], "sip: expected exactly 'trusted_cores' and 'core_ca'"),
    ({"trusted_cores": []}, "sip: expected exactly 'trusted_cores' and 'core_ca'"),
    ({"trusted_cores": [], "core_ca": "none", "trusted_peers": []},
     "sip: expected exactly 'trusted_cores' and 'core_ca'"),
    ({"trusted_cores": "c.example", "core_ca": "none"},
     "sip.trusted_cores: expected a list of DNS names"),
    ({"trusted_cores": [7], "core_ca": "none"},
     "sip.trusted_cores: expected a list of DNS names"),
    ({"trusted_cores": ["localhost", "c.example"], "core_ca": "x.pem"},
     "sip.trusted_cores: not fully qualified DNS names: 'localhost'"),
    ({"trusted_cores": ["*.example"], "core_ca": "x.pem"}, "'*.example'"),
    ({"trusted_cores": [], "core_ca": ""}, "sip.core_ca: expected a file, or 'none'"),
    ({"trusted_cores": [], "core_ca": None}, "sip.core_ca: expected a file, or 'none'"),
])
def test_the_sip_section(tmp_path, sip, says):
    assert says in refused(raw_yaml(tmp_path, {**GOOD, "sip": sip}))


def test_a_trusted_core_needs_a_ca_of_its_own(tmp_path):
    """ICD-OP-10: a name alone is what any certificate from a shared CA could carry."""
    text = refused(network_yaml(tmp_path, trusted_cores=["c.example"], core_ca="NONE"))
    assert "trusted_cores is not empty" in text and "ICD-OP-10" in text


def test_a_core_ca_without_trusted_cores_is_refused(tmp_path, pki):
    text = refused(network_yaml(tmp_path, core_ca=pki / "core-ca.crt"))
    assert "sip.core_ca: given, but trusted_cores is empty; write 'none'" in text


def test_the_core_ca_must_be_readable(tmp_path):
    text = refused(network_yaml(tmp_path, trusted_cores=["c.example"],
                                core_ca="absent.pem"))
    assert "sip.core_ca:" in text and "absent.pem" in text


def test_the_core_ca_is_one_certificate(tmp_path, pki):
    both = tmp_path / "both.pem"
    both.write_bytes((pki / "core-ca.crt").read_bytes() + (pki / "ca.crt").read_bytes())
    text = refused(network_yaml(tmp_path, trusted_cores=["c.example"], core_ca=both))
    assert "expected exactly one certificate, found 2" in text


def test_the_core_ca_is_a_ca(tmp_path, pki):
    text = refused(network_yaml(tmp_path, trusted_cores=["c.example"],
                                core_ca=pki / "client.crt"))
    assert "not a CA certificate" in text


def test_a_certificate_without_basic_constraints_is_not_a_ca(tmp_path):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bare")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    p = tmp_path / "bare.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    text = refused(network_yaml(tmp_path, trusted_cores=["c.example"], core_ca=p))
    assert "not a CA certificate" in text


@pytest.mark.parametrize("bundle", ["same", "in-bundle"])
def test_the_core_ca_is_not_the_users_ca(tmp_path, pki, bundle):
    """ICD-OP-10: the same anchor for both reopens the hole this closes, also
    when it hides in a bundle."""
    user_ca = pki / "ca.crt"
    if bundle == "in-bundle":
        user_ca = tmp_path / "users.pem"
        user_ca.write_bytes((pki / "ca.crt").read_bytes()
                            + (pki / "core-ca.crt").read_bytes())
        core_ca = pki / "core-ca.crt"
    else:
        core_ca = pki / "ca.crt"
    text = refused(network_yaml(tmp_path, trusted_cores=["c.example"], core_ca=core_ca),
                   user_ca=user_ca)
    assert "the same CA (by key) is in MCX_SIP_TLS_CA" in text


def test_a_reissued_certificate_for_the_same_key_is_the_same_ca(tmp_path, pki):
    """Compared by key, not by certificate: a CA re-issued with a new serial
    or validity still signs with the same key."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    key = serialization.load_pem_private_key((pki / "core-ca.key").read_bytes(), None)
    old = x509.load_pem_x509_certificate((pki / "core-ca.crt").read_bytes())
    now = datetime.datetime.now(datetime.timezone.utc)
    again = (x509.CertificateBuilder().subject_name(old.subject).issuer_name(old.subject)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=9))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
             .sign(key, hashes.SHA256()))
    users = tmp_path / "users.pem"
    users.write_bytes((pki / "ca.crt").read_bytes()
                      + again.public_bytes(serialization.Encoding.PEM))
    text = refused(network_yaml(tmp_path, trusted_cores=["c.example"],
                                core_ca=pki / "core-ca.crt"), user_ca=users)
    assert "the same CA (by key) is in MCX_SIP_TLS_CA" in text


# -- the core CA is a root of its own, issuing leaves only (review of NET-OP-01) ----


def test_an_intermediate_under_the_users_root_is_not_a_core_ca(tmp_path, pki):
    """The reviewer's case: users are issued by an intermediate under the root
    in MCX_SIP_TLS_CA. Named as the core CA, it would make a user's
    certificate carrying a core's name a core."""
    p, _, _ = mkca(tmp_path, "users-issuing", issuer=user_root(pki))
    text = refused(core_net(tmp_path, p), user_ca=pki / "ca.crt")
    assert "not self-signed" in text


def test_a_core_ca_named_as_its_own_issuer_must_also_sign_itself(tmp_path, pki):
    """Issuer name equal to subject is not enough: here the users' root signed it."""
    ukey, ucert = user_root(pki)
    p, _, _ = mkca(tmp_path, "test-ca", issuer=(ukey, ucert))   # issuer name == subject
    assert "not self-signed" in refused(core_net(tmp_path, p))


def test_a_core_ca_must_have_path_length_zero(tmp_path):
    for n, pl in enumerate((None, 1)):
        p, _, _ = mkca(tmp_path, path_length=pl, fname=f"pl{n}.pem")
        assert "pathLenConstraint must be 0" in refused(core_net(tmp_path, p))


def test_a_core_ca_that_cannot_sign_certificates_is_refused(tmp_path):
    ku = x509.KeyUsage(digital_signature=True, content_commitment=False,
                       key_encipherment=False, data_encipherment=False,
                       key_agreement=False, key_cert_sign=False, crl_sign=True,
                       encipher_only=False, decipher_only=False)
    p, _, _ = mkca(tmp_path, key_usage=ku)
    assert "keyUsage lacks keyCertSign" in refused(core_net(tmp_path, p))


def test_a_core_ca_with_key_cert_sign_is_accepted(tmp_path):
    ku = x509.KeyUsage(digital_signature=False, content_commitment=False,
                       key_encipherment=False, data_encipherment=False,
                       key_agreement=False, key_cert_sign=True, crl_sign=True,
                       encipher_only=False, decipher_only=False)
    p, _, cert = mkca(tmp_path, key_usage=ku)
    assert load_network(core_net(tmp_path, p), set()).core_ca == cert


@pytest.mark.parametrize("days", [(-9, -1), (1, 9)])
def test_a_core_ca_not_valid_now_is_refused(tmp_path, days):
    p, _, _ = mkca(tmp_path, days=days)
    assert "not valid now" in refused(core_net(tmp_path, p))


def test_a_core_ca_named_like_a_users_ca_is_refused(tmp_path, pki):
    p, _, _ = mkca(tmp_path, "test-ca")          # the users' CA's name, another key
    text = refused(core_net(tmp_path, p), user_ca=pki / "ca.crt")
    assert "is also the name of a CA in MCX_SIP_TLS_CA" in text


def test_a_core_ca_that_issued_a_users_ca_is_refused(tmp_path, pki):
    core_p, core_key, core_cert = mkca(tmp_path, "core-root")
    users_p, _, _ = mkca(tmp_path, "users-sub", issuer=(core_key, core_cert))
    text = refused(core_net(tmp_path, core_p), user_ca=users_p)
    assert "it issued CN=users-sub, a CA in MCX_SIP_TLS_CA" in text


@pytest.mark.parametrize("where", ["core", "users"])
def test_only_certificate_blocks_are_read(tmp_path, pki, where):
    """OpenSSL would take a TRUSTED CERTIFICATE block as an anchor that this
    check never sees and the hash never covers (reviewer's case)."""
    rogue = ("-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n"
             "-----END TRUSTED CERTIFICATE-----\n").encode()
    core_ca, users = pki / "core-ca.crt", pki / "ca.crt"
    if where == "core":
        core_ca = tmp_path / "core.pem"
        core_ca.write_bytes((pki / "core-ca.crt").read_bytes() + rogue)
    else:
        users = tmp_path / "users.pem"
        users.write_bytes((pki / "ca.crt").read_bytes() + rogue)
    text = refused(core_net(tmp_path, core_ca), user_ca=users)
    assert "holds TRUSTED CERTIFICATE block(s); only CERTIFICATE blocks" in text


def test_a_bad_users_ca_is_reported_once(tmp_path, pki):
    users = tmp_path / "users.pem"
    users.write_text("-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n")
    text = refused(core_net(tmp_path, pki / "core-ca.crt"), user_ca=users)
    assert "1 defect(s)" in text and "MCX_SIP_TLS_CA" in text


def test_a_separate_core_ca_is_accepted(tmp_path, pki):
    n = load_network(network_yaml(tmp_path, trusted_cores=["c.example"],
                                  core_ca=pki / "core-ca.crt"), set(), pki / "ca.crt")
    assert n.core_ca is not None


def test_an_unreadable_user_ca_is_reported(tmp_path, pki):
    text = refused(network_yaml(tmp_path, trusted_cores=["c.example"],
                                core_ca=pki / "core-ca.crt"),
                   user_ca=tmp_path / "absent.pem")
    assert "MCX_SIP_TLS_CA" in text


def test_every_defect_is_reported_at_once(tmp_path):
    text = refused(raw_yaml(tmp_path, {**GOOD, "name": "a/b", "plmns": ["1"],
                                       "sip": {"trusted_cores": ["x"], "core_ca": "none"}}))
    assert "4 defect(s)" in text


# ============================================================ configuration


def base_env(tmp_path, pki):
    return sip_env(tmp_path, pki)


def test_the_setting_is_required(tmp_path, pki):
    env = base_env(tmp_path, pki)
    env.pop("MCX_NETWORK_FILE")
    with pytest.raises(StartupRefused) as exc:
        Config.from_env(env)
    assert "MCX_NETWORK_FILE is not set" in str(exc.value)
    with pytest.raises(StartupRefused):
        Config.from_env({**env, "MCX_NETWORK_FILE": "  "})


@pytest.mark.parametrize("moved", ["MCX_CELLS_FILE", "MCX_SIP_TRUSTED_PEERS"])
@pytest.mark.parametrize("value", ["none", ""])
def test_a_setting_that_moved_is_refused_not_ignored(tmp_path, pki, moved, value):
    with pytest.raises(StartupRefused) as exc:
        Config.from_env({**base_env(tmp_path, pki), moved: value})
    assert f"{moved} is no longer read" in str(exc.value)
    assert "MCX_NETWORK_FILE" in str(exc.value)


# ============================================================ in the running process


@pytest.fixture
def rt(tmp_path, pki):
    r = build_runtime(base_env(tmp_path, pki), Clock())
    yield r
    r.close()


def test_every_audit_record_names_the_network(rt):
    """NET-OP-01, with PLT-REL-005: profile, release and network together."""
    net = rt.network.identifier()
    assert net.startswith("test-net/1/")
    record = rt.auditor.emit(__import__("core.audit", fromlist=["RecordType"])
                             .RecordType.SESSION_REFUSED, "c1")
    assert record.profile == \
        f"{rt.loaded.profile.identifier()}+{rt.config.release}+{net}"


def test_the_health_document_names_the_network(rt):
    got = rt.health.snapshot()["network"]
    assert got == {"name": "test-net", "version": "1",
                   "hash": rt.network.content_hash,
                   "identifier": rt.network.identifier()}


def shared_key_ca(tmp_path, pki):
    """A core CA that is fine on its own but shares the users' CA's key."""
    return mkca(tmp_path, "shared-key", key=user_root(pki)[0])[0]


def test_the_runtime_passes_the_users_ca_for_the_separation_check(tmp_path, pki):
    net = network_yaml(tmp_path, trusted_cores=["c.example"],
                       core_ca=shared_key_ca(tmp_path, pki), fname="shared.yaml")
    with pytest.raises(StartupRefused) as exc:
        build_runtime(sip_env(tmp_path, pki, MCX_NETWORK_FILE=str(net)), Clock())
    assert "the same CA (by key) is in MCX_SIP_TLS_CA" in str(exc.value)


def test_without_sip_there_is_no_users_ca_to_compare(tmp_path, pki):
    net = network_yaml(tmp_path, trusted_cores=["c.example"],
                       core_ca=shared_key_ca(tmp_path, pki), fname="shared.yaml")
    env = {k: v for k, v in sip_env(tmp_path, pki, MCX_NETWORK_FILE=str(net)).items()
           if not k.startswith(("MCX_SIP_", "MCX_MEDIA_"))}
    r = build_runtime(env, Clock())
    assert r.network.trusted_cores == ("c.example",)
    r.close()


def test_a_bad_network_refuses_startup_before_the_store_opens(tmp_path, pki):
    env = sip_env(tmp_path, pki, MCX_NETWORK_FILE=str(tmp_path / "absent.yaml"))
    with pytest.raises(StartupRefused):
        build_runtime(env, Clock())
    assert not Path(env["MCX_DATA_DIR"]).exists()


def test_the_example_in_the_repository_loads():
    """CLAUDE.md runs the process with it; it must not rot."""
    n = load_network(ROOT / "examples" / "network.yaml", {"track_section", "yard_id"})
    assert (n.name, n.plmns, n.trusted_cores) == ("example", ("001010",), ())
