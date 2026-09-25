"""VP1-BND-006 / PLT-GEN-001 — per-profile release images.

One codebase; each image carries the shared part and exactly one profile, and
the shared part is byte-identical across images (the core hash). The gate in
tools/check_boundary.py checks the invariants on file lists; these tests check
that a staged image is a working deployment of its own profile and of nothing
else, and that the evidence (MANIFEST.json, the tarball) can be trusted.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import package  # noqa: E402

PROFILES = package.profile_names(ROOT)


@pytest.fixture(scope="module")
def images(tmp_path_factory):
    out = tmp_path_factory.mktemp("dist")
    return {n: package.stage(n, out, ROOT) for n in PROFILES}


def _load_in(image: Path, name: str) -> subprocess.CompletedProcess:
    """Start the loader inside the image, as the image's own interpreter would."""
    code = ("import sys; from pathlib import Path; from core import loader\n"
            f"lp = loader.startup([{name!r}], Path('profiles'), {{}})\n"
            "print(lp.profile.name, lp.profile.content_hash)\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCX_")}
    env["PYTHONPATH"] = str(image)
    return subprocess.run([sys.executable, "-c", code], cwd=image, env=env,
                          capture_output=True, text=True, timeout=60)


def test_there_are_profiles_to_build():
    assert set(PROFILES) == {"mcx", "frmcs", "utility"}


@pytest.mark.parametrize("name", PROFILES)
def test_each_image_carries_exactly_its_own_profile(images, name):
    image = images[name]
    assert package.image_profiles(image) == [name]
    others = [p for p in PROFILES if p != name]
    for other in others:
        assert not (image / "profiles" / other).exists()
    # The framework every profile's hooks import travels with every image.
    assert (image / "profiles" / "common" / "tables.py").is_file()


def test_the_core_hash_is_the_same_in_every_image_and_equals_the_source(images):
    hashes = {json.loads((i / "MANIFEST.json").read_text())["core_hash"] for i in images.values()}
    assert hashes == {package.core_hash(ROOT)}


def test_the_shared_part_is_what_the_manifest_says(images):
    for image in images.values():
        manifest = json.loads((image / "MANIFEST.json").read_text())
        on_disk = sorted(p.relative_to(image).as_posix() for p in image.rglob("*")
                         if p.is_file() and p.name not in ("MANIFEST.json", "Containerfile"))
        assert on_disk == sorted(manifest["shared"] + manifest["profile_files"])


@pytest.mark.parametrize("name", PROFILES)
def test_an_image_loads_its_own_profile(images, name):
    r = _load_in(images[name], name)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split()[0] == name


@pytest.mark.parametrize("name", PROFILES)
def test_an_image_refuses_every_other_profile_as_absent(images, name):
    """VP1-LOAD-003 in image form: the other profiles are not in the delivery at all."""
    for other in (p for p in PROFILES if p != name):
        r = _load_in(images[name], other)
        assert r.returncode != 0
        assert "not found" in r.stderr and repr(other) in r.stderr


def test_verify_catches_a_core_file_changed_after_staging(images, tmp_path):
    victim = package.stage("mcx", tmp_path, ROOT)
    target = victim / "core" / "errors.py"
    target.write_text(target.read_text() + "\n# changed after staging\n")
    problems = package.verify({"mcx": victim, "frmcs": images["frmcs"]})
    assert any("does not match its files" in p for p in problems)
    assert any("core hash differs" in p for p in problems)


def test_verify_catches_an_image_with_a_second_profile(tmp_path):
    image = package.stage("mcx", tmp_path, ROOT)
    for rel in package.profile_files("frmcs", ROOT):
        dst = image / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes((ROOT / rel).read_bytes())
    problems = package.verify({"mcx": image})
    assert any("carries profiles ['frmcs', 'mcx']" in p for p in problems)


def test_the_tarball_is_reproducible(tmp_path):
    a = package.tar(package.stage("utility", tmp_path / "a", ROOT))
    b = package.tar(package.stage("utility", tmp_path / "b", ROOT))
    assert a.read_bytes() == b.read_bytes()


def test_the_containerfile_is_the_same_for_every_image_and_names_no_profile(images):
    texts = {(i / "Containerfile").read_text() for i in images.values()}
    assert len(texts) == 1
    text = texts.pop()
    assert "MCX_PROFILE=" not in text and "ENV MCX_" not in text
    for name in PROFILES:
        assert f"profiles/{name}" not in text
