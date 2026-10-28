"""VP1-ANL-001 re-run: run from a tree with VP1-ANL-001-rerun.patch applied.

Establishes a call of the new call type, and of two shipped ones, through the
core's SessionManager, and prints what the core gave each: the priority from
the new urgency's rule, and the floor policy from the new call type's own
declaration (queue depth 3, T2 2500 ms, values no other call type has).
Nothing under core/ names the new call type.

    python3 docs/analysis/VP1-ANL-001-demo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, ".")
from core import loader  # noqa: E402
from core.audit import Auditor, MemorySink  # noqa: E402
from core.hooks import MediaKind, SessionRequest  # noqa: E402
from core.session import Platform, SessionManager  # noqa: E402

mcx = loader.load(Path("profiles/mcx"))
r = mcx.hooks.identity_resolver
for i in range(4):
    r.register_user(f"sip:u{i}@mcptt.example")
r.register_group("grp:ic", [f"sip:u{i}@mcptt.example" for i in range(4)])
m = SessionManager(mcx, Auditor(MemorySink(), mcx.profile.identifier(), clock=lambda: 0),
                   platform=Platform(), clock=lambda: 0)
for ct in ("incident-command-group", "coordination-group", "prearranged-group"):
    s, _, refusal = m.establish(SessionRequest(
        request_id=ct, initiator="sip:u0@mcptt.example", target="grp:ic", call_type=ct,
        media=(MediaKind.VOICE,)))
    assert refusal is None, refusal
    p = s.floor._policy
    print(f"{ct}: priority {s.priority.label} level {s.priority.level}, "
          f"floor queue depth {p.max_queue_depth}, T2 {p.timers_ms.get('T2')} ms")
print("core files naming it:",
      [str(p) for p in Path("core").rglob("*.py") if "incident-command" in p.read_text()])
