# kb — agent memory for mcx-platform

Memory for AI agents (and people) working on this repository. It reads the repository and never
changes anything outside `kb/`.

- Agents: start at **AGENT.md**.
- Current state: **STATE.md**. It is generated and git-ignored; create it with `python3 kb/tools/kb.py build`.

```bash
python3 kb/tools/kb.py build     # re-extract registry/ + STATE.md (runs pytest + the boundary gates, ~30 s)
python3 kb/tools/kb.py check     # drift, conflicts, stale STATE, decision records that disagree with the docs
python3 kb/tools/kb.py show ID   # everything known about one id
```

| Part | Kind | In git |
|---|---|---|
| `decisions/`, `handover/`, `overlay.yaml` | written by hand | yes |
| `tools/kb.py`, `config.yaml`, `AGENT.md`, this file | written by hand | yes |
| `STATE.md`, `registry/` | generated | no (`.gitignore`) |

STATE.md goes stale when a tracked file outside `kb/` changes, not when a commit is made, so
committing a handover note never forces a rebuild. It is not shipped: `tools/package.py` stages
only the shared part and one profile. Needs Python 3 and PyYAML, both already repo dependencies.
