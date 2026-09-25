# AGENT.md — start here

You are about to work on **mcx-platform**, a 3GPP mission-critical platform
(MCPTT / MCData) that serves public-safety MCX and railway FRMCS from one core. This folder is its
memory. It lives in the repository at `kb/`. The hand-written parts (`decisions/`, `handover/`,
`overlay.yaml`, `tools/`) are committed; `STATE.md` and `registry/` are generated and git-ignored, so
a fresh clone has no STATE until you build it.

## Read, in this order (about 10 minutes)

1. **`STATE.md`**: generated. Test and gate health, what is open, what closed recently, and the
   inconsistencies the repo currently contains. If its commit is not the repo's HEAD, rebuild first.
2. **The repo's `CLAUDE.md`**: the one rule, the commands, the conventions. It is authoritative for *how*
   to work. Ignore any count in it that disagrees with `STATE.md`.
3. **`decisions/`**: why things are the way they are. Read every `status: conflicted` record before
   anything else in its area. Those are open owner decisions, and you must not settle them.
4. **The latest note in `handover/`**: what the previous agent left and told you not to touch.
5. For any id you meet: `python3 tools/kb.py show <ID>` shows the registry entry, its decision record,
   and which handovers mention it.

## Which source is authoritative for what

| Question | Authority | Not |
|---|---|---|
| What a requirement, case or finding says | `docs/PLT-*.md` in the repo | this KB |
| Whether an open point is open | the repo docs; `registry/` mirrors them | your memory of a previous session |
| Why a choice was made, and what not to undo | `decisions/` | commit messages alone |
| Numbers (tests, gates) | `STATE.md` after a build | CLAUDE.md / README prose |
| What the last session did | `handover/` | — |

`registry/*.yaml` and `STATE.md` are **generated. Never edit them.** If one is wrong, the extractor is wrong
(`tools/kb.py`) or the repo is inconsistent. `registry/conflicts.yaml` lists the latter.

## Protocol for every session

**Start**
```bash
cd kb                              # from the repository root
python3 tools/kb.py build          # ~30 s: runs pytest and the boundary gates
python3 tools/kb.py check          # must report 0 KB problems (REPO lines are the repo's own inconsistencies)
python3 tools/kb.py handover "<short-slug>"   # creates handover/<date>-<slug>.md; fill it as you go
```

**During**
- Cite ids (PLT-*, VP1-*, *-OP-*, CA-*) in commits, as the repo already does. That is how the KB links
  work to its reasons.
- Meet something the specification doesn't answer? **Record an open point in the repo doc that owns it**
  (usually PLT-VP-R1 §11). Don't guess quietly, and don't record it only here.
- Before adding an id, run `python3 tools/kb.py show <ID>` to make sure it's free. Two ids are
  already duplicated (FC-OP-04, FC-OP-05).

**End**
1. Rebuild: `python3 tools/kb.py build`.
2. Finish your handover note. The *Not verified* section is the most valuable part: say what you did not
   check.
3. If you made or recorded a decision (an open point closed as "decided: …"), add a `decisions/NNNN-*.md`
   with `closes: [ID]`. Choices recorded only in commit messages get re-litigated by the next agent.
4. Run `python3 tools/kb.py check`.
5. Commit your KB changes (handover note, decision records, overlay) **separately** from code changes,
   with a subject starting `kb:`. KB-only commits don't make STATE.md stale and are left out of the
   evidence the registry links to, so keep them KB-only.

## Hard rules, and what goes wrong when they are broken

These are summarised from the repo and from `decisions/`; the sources win if they differ.

- `core/` never learns a profile exists. Never weaken a boundary gate. (0001)
- No defaults. Required settings refuse startup; a refusal is a value, a fault is an exception. (0004)
- Constants and message bodies come from the `.docx` specifications and the extracted schemas, never
  from this repo's code or tests. (0010)
- A green `pytest` run doesn't show that the deployed process works. Run `tools/interop/run.py`. (0004, 0005)
- The FRMCS profile is a stub. It must never be used as safety-case input.
- One release image per profile, identical core hash in every image; the profile is data given to
  `tools/package.py`, never a build file. (0002)

## Layout

```
AGENT.md            this file
STATE.md            GENERATED snapshot
registry/           GENERATED from the repo: open-points, findings (CA), vp-cases, conflicts
overlay.yaml        hand-written: owner / trap / note per id (things the docs don't say)
decisions/          hand-written decision records (front matter: status, closes, relates)
handover/           one note per session, from TEMPLATE.md
tools/kb.py         build | check | show ID | handover SLUG
config.yaml         repo path, `..` by default (overridden by --repo or $MCX_REPO)
```
