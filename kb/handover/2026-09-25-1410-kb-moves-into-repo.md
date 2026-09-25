---
date: 2026-09-25 14:10
agent: Claude (Opus 5.5), claude.ai project "MCX Solution"
repo_commit_start: 8e21342 (d30e3bc + the per-profile images patch)
repo_commit_end: + patch "kb: move the agent memory into the repository"
ids: []
---

## Task
The owner moved the KB into the repository at `kb/`. Make it behave correctly there.

## Done
- `tools/kb.py`:
  - The repository defaults to the KB's parent folder (`config.yaml`: `repo: ..`).
  - `kb/` is excluded from the reference scan, and KB-only commits are excluded from commit scanning.
  - Staleness is judged by a **source fingerprint** (tracked files outside `kb/` plus uncommitted
    changes to them) instead of HEAD. Tested: a KB-only commit leaves STATE current; an uncommitted doc
    edit makes it stale.
- `.gitignore`: `kb/STATE.md` and `kb/registry/` (generated). The hand-written parts are committed.
- CLAUDE.md now tells agents to read `kb/AGENT.md` and build STATE first.
- AGENT.md and README describe the in-repo layout, and ask for KB changes in separate `kb:` commits.
- With `kb/` in the tree: all 924 tests and 20/20 gates still pass. The one repo-wide gate scan
  (VP1-BND-022) covers only core/, service/ and tools/, and `tools/package.py` never stages `kb/`.

## Not verified
- CI has not run with `kb/` present (no workflow reads it; nothing should change).

## Open / next
- Stale claim newly visible after the images patch: CLAUDE.md:14 says 908 tests; there are now 924.
  This is part of point 4 (remove counts from prose).
- Points 2-4 from the bootstrap note are still open.

## Do not touch
Nothing half-done.
