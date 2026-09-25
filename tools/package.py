#!/usr/bin/env python3
"""Per-profile release images (PLT-GEN-001, VP1-BND-006).

One codebase; each release image carries the shared part and exactly one
profile. The shared part is everything a deployment needs that is not a
profile: `core/`, `service/`, the profile framework (`profiles/__init__.py`,
`profiles/SCHEMA.yaml`, `profiles/common/`) and `requirements.txt`. It is
byte-identical in every image built from one commit, and its hash, the
*core hash*, is what proves it: two images with the same core hash run the
same platform, whatever profile each carries.

What varies between images is data (the profile package), never the build.
There is one Containerfile and it takes no profile argument: the image
still refuses to start until `MCX_PROFILE` names its profile (PLT-GEN-004),
and naming any other profile refuses as absent (VP1-LOAD-003).

    python3 tools/package.py --profile mcx --out dist
    python3 tools/package.py --all --out dist            # every in-tree profile
    python3 tools/package.py --all --out dist --tar      # plus reproducible .tar.gz

Each image directory holds MANIFEST.json: profile name and version, the
core hash, the profile hash and the file list.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Dict, List, Sequence

import yaml

ROOT = Path(__file__).resolve().parents[1]

# The shared part, relative to the repository root.
SHARED_DIRS = ("core", "service", "profiles/common")
SHARED_FILES = ("profiles/__init__.py", "profiles/SCHEMA.yaml", "requirements.txt")
PROFILE_DIR = "profiles"
FRAMEWORK = {"common"}                  # directories under profiles/ that are not profiles
CONTAINERFILE = "tools/release.Containerfile"
SKIP_PARTS = {"__pycache__"}
SKIP_SUFFIXES = {".pyc", ".pyo"}


def profile_names(root: Path = ROOT) -> List[str]:
    """Every profile package: a directory under profiles/ with a profile.yaml."""
    return sorted(p.parent.name for p in (root / PROFILE_DIR).glob("*/profile.yaml")
                  if p.parent.name not in FRAMEWORK)


def _files_under(base: Path, rel: str) -> List[str]:
    top = base / rel
    if top.is_file():
        return [rel]
    out = []
    for p in sorted(top.rglob("*")):
        if not p.is_file() or SKIP_PARTS & set(p.parts) or p.suffix in SKIP_SUFFIXES:
            continue
        out.append(p.relative_to(base).as_posix())
    return out


def shared_files(root: Path = ROOT) -> List[str]:
    files: List[str] = []
    for rel in SHARED_DIRS + SHARED_FILES:
        if not (root / rel).exists():
            raise FileNotFoundError(f"shared part is missing {rel}")
        files += _files_under(root, rel)
    return sorted(files)


def profile_files(name: str, root: Path = ROOT) -> List[str]:
    return _files_under(root, f"{PROFILE_DIR}/{name}")


def tree_hash(root: Path, files: Sequence[str]) -> str:
    """sha256 over (path, content hash) pairs in path order.

    Paths are part of the hash, so moving a file changes it; content is
    hashed per file, so the result does not depend on how files are read.
    """
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(rel.encode("utf-8") + b"\0")
        h.update(hashlib.sha256((root / rel).read_bytes()).digest())
    return h.hexdigest()


def core_hash(root: Path = ROOT) -> str:
    return tree_hash(root, shared_files(root))


def _commit(root: Path) -> str:
    r = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                       capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain",
                            "--untracked-files=no"], capture_output=True, text=True)
    commit = r.stdout.strip() or "unknown"
    return commit + ("-dirty" if dirty.stdout.strip() else "")


def stage(name: str, out: Path, root: Path = ROOT) -> Path:
    """Build one image directory: the shared part plus profile `name`, and nothing else."""
    names = profile_names(root)
    if name not in names:
        raise SystemExit(f"no profile package {name!r} (have: {', '.join(names)})")
    meta = yaml.safe_load((root / PROFILE_DIR / name / "profile.yaml").read_text(encoding="utf-8"))
    ident = meta.get("profile", meta) if isinstance(meta, dict) else {}
    version = str(ident.get("version", "unversioned"))
    dest = out / f"mcx-platform-{name}"
    if dest.exists():
        shutil.rmtree(dest)
    shared = shared_files(root)
    own = profile_files(name, root)
    for rel in shared + own:
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / rel, target)
    shutil.copy2(root / CONTAINERFILE, dest / "Containerfile")
    manifest = {
        "profile": name,
        "profile_version": version,
        "commit": _commit(root),
        "core_hash": tree_hash(dest, shared),
        "profile_hash": tree_hash(dest, own),
        "shared": shared,
        "profile_files": own,
    }
    (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return dest


def image_profiles(image: Path) -> List[str]:
    """The profile packages an image directory actually carries."""
    return profile_names(image)


def tar(image: Path) -> Path:
    """A reproducible .tar.gz: sorted entries, zero mtimes and owners."""
    target = image.with_suffix(".tar.gz")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for p in sorted(image.rglob("*")):
            if not p.is_file():
                continue
            info = tf.gettarinfo(str(p), arcname=f"{image.name}/{p.relative_to(image).as_posix()}")
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            with p.open("rb") as fh:
                tf.addfile(info, fh)
    with target.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz:
        gz.write(buf.getvalue())
    return target


def verify(images: Dict[str, Path]) -> List[str]:
    """The invariants VP1-BND-006 holds a set of images to."""
    problems: List[str] = []
    hashes = {}
    for name, image in images.items():
        manifest = json.loads((image / "MANIFEST.json").read_text(encoding="utf-8"))
        carried = image_profiles(image)
        if carried != [name]:
            problems.append(f"image {image.name}: carries profiles {carried}, expected exactly [{name!r}]")
        recomputed = tree_hash(image, manifest["shared"])
        if recomputed != manifest["core_hash"]:
            problems.append(f"image {image.name}: core hash in MANIFEST.json does not match its files")
        hashes[name] = recomputed
    if len(set(hashes.values())) > 1:
        problems.append("core hash differs between images: "
                        + ", ".join(f"{n}={h[:12]}" for n, h in sorted(hashes.items())))
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    what = ap.add_mutually_exclusive_group(required=True)
    what.add_argument("--profile", action="append", help="profile to build; repeatable")
    what.add_argument("--all", action="store_true", help="every in-tree profile")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--tar", action="store_true", help="also write a reproducible .tar.gz per image")
    a = ap.parse_args(argv)
    names = profile_names() if a.all else a.profile
    a.out.mkdir(parents=True, exist_ok=True)
    images = {n: stage(n, a.out) for n in names}
    problems = verify(images)
    for n, image in images.items():
        m = json.loads((image / "MANIFEST.json").read_text(encoding="utf-8"))
        line = f"{image.name}: profile {n} {m['profile_version']}, core {m['core_hash'][:16]}, profile {m['profile_hash'][:16]}"
        if a.tar:
            line += f", {tar(image).name}"
        print(line)
    for p in problems:
        print("FAIL", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
