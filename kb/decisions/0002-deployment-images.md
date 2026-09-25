---
id: 0002
title: One codebase, one release image per profile, one core in all of them
status: accepted
date: 2026-09-25
closes: []
relates: [VP1-BND-006, VP1-BND-021, OP-03]
source: [owner decision in chat 2026-09-25 (option B), PLT-SRS 0.3 PLT-GEN-001, PLT-VP-R1 0.17 VP1-BND-006, tools/package.py]
---

## Decision (owner, 2026-09-25)
One codebase. Each delivery is a **release image carrying the shared core and exactly one profile**. The
profile is still named at deploy time (`MCX_PROFILE`, no default), and an image refuses any profile it
doesn't carry.

This replaces the earlier rule of "one image carrying every profile" (PLT-GEN-001 as of PLT-SRS 0.2).

## Why
- A delivery contains only what its deployment uses. A public-safety operator doesn't receive railway code.
- The FRMCS safety case (integrity level still open, OP-03) is argued over the core plus one profile, not
  over profiles that are only "never loaded".

## The invariant that makes it safe: the core hash
The shared part (`core/`, `service/`, `profiles/__init__.py`, `profiles/SCHEMA.yaml`, `profiles/common/`,
`requirements.txt`) is hashed per file and path, and it **must be identical in every image built from one
revision**. Without that, per-profile builds are how per-profile drift starts, and decision 0001 (the core
never knows a profile) could no longer be shown to hold for what is actually delivered.

## Enforced by
- `tools/package.py --all --out dist [--tar]` stages one image per profile with a `MANIFEST.json` (core
  hash, profile hash, file list) and one generic Containerfile (`tools/release.Containerfile`: no
  profile argument, no `MCX_*` variable). Tarballs are reproducible.
- **VP1-BND-006** builds every image and fails if: an image carries more than one profile; the core hash
  differs between images; code that ships in every image names a profile package; or a per-profile build
  file exists. All five breakages were mutation-checked.
- `tests/test_packaging.py`: each image loads its own profile inside the image and refuses every other one
  as absent; the manifest and tarball can be trusted.
- CI job `images` builds and uploads all three.

## Rules for agents
- The profile is **data** passed to `tools/package.py`. Never add a per-profile Containerfile, build
  script or build flag.
- Code under `core/`, `service/` or `profiles/common/` must never import or path-join a specific profile.
- Any file under the shared part changes the core hash, including `core/PROFILE_BOUNDARY.md`. That's
  intended: the hash covers what ships, not only code.
- `MCX_TEST_MODE` multi-profile loading exists only in the source tree, for the conformance harness.

## Where the repo changed
Patch `0001-PLT-GEN-001-one-release-image-per-profile-one-core-i.patch` (against d30e3bc): PLT-SRS 0.3
(§1.1, PLT-GEN-001, PLT-VER-001), PLT-VP-R1 0.17 (VP1-BND-006, VP1-BND-021, §1.4, exit criterion 4),
README, CLAUDE.md, core/PROFILE_BOUNDARY.md, CI, tools/package.py, tools/release.Containerfile,
tests/test_packaging.py.
