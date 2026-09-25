---
date: {{date}}
agent: <model / tool, e.g. Claude Code (Opus 5.5)>
repo_commit_start: <git rev-parse --short HEAD at start>
repo_commit_end: <at end>
ids: []          # every OP / CA / VP1 id this session touched, e.g. [SIP-OP-17, VP1-SIG-001]
---

## Task
<one or two lines: what was asked>

## Done
<what changed, with commit hashes. Name ids.>

## Not verified
<what you did NOT check, and why. A green pytest run is not evidence of what the
deployed process does: say whether tools/interop/run.py was run.>

## Open / next
<what the next agent should pick up first. New open points go into the repo docs
(VP-R1 §11 or the owning doc's open-points table), not only here.>

## Do not touch
<anything half-done, or a trap you found. Leave empty if none.>
