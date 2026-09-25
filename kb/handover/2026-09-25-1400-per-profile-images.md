---
date: 2026-09-25 14:00
agent: Claude (Opus 5.5), claude.ai project "MCX Solution"
repo_commit_start: d30e3bc
repo_commit_end: d30e3bc + patch 0001 (not applied by the agent; the owner applies it)
ids: [PLT-GEN-001, PLT-VER-001, VP1-BND-006, VP1-BND-021, VP1-LOAD-003, OP-03]
---

## Task
Settle decisions/0002: the owner chose option B, one release image per profile.

## Done
- Patch `0001-PLT-GEN-001-one-release-image-per-profile-one-core-i.patch` against d30e3bc
  (11 files, +482/−33), authored as Lucian with a Claude co-author trailer:
  - `tools/package.py`: stages one image per profile; MANIFEST.json with core hash and profile hash;
    one generic `tools/release.Containerfile`; reproducible `--tar`.
  - VP1-BND-006 rewritten as `check_per_profile_images`. Mutation-checked against five breakages, all red.
  - `tests/test_packaging.py`: 16 tests, including loading inside each staged image and refusing the
    other profiles as absent.
  - CI `images` job. PLT-SRS 0.3, PLT-VP-R1 0.17, README, CLAUDE.md and core/PROFILE_BOUNDARY.md updated.
- Verified on a clean clone with `git am`: 924 passed, 20/20 gates, three images, one core hash.
- decisions/0002 is now `accepted`; overlay and AGENT.md updated.

## Not verified
- No container was built (`podman build` not run here). The Containerfile is untested beyond its
  content checks in test_packaging.
- The CI `images` job has not run on GitHub.
- `requirements.txt` is the repo's single pinned list and includes pytest and its dependencies, so every
  image ships test tools. It was left as is: separating runtime and test requirements is a separate
  decision.

## Open / next
- Apply the patch (`git am`), then `python3 tools/kb.py build`. `git am` creates a new commit hash, so
  the current STATE.md reads as stale until rebuilt.
- Points 2-4 from the bootstrap note are still open (duplicate FC-OP ids, VP1-BND-022/023 missing from
  the plan, stale counts in the prose).

## Do not touch
Nothing half-done.
