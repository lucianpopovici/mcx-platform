# Task 1 — the service entry point

**Read `CLAUDE.md` first.** It carries the boundary rule, the commands and the
conventions. This brief assumes them.

## Objective

Make the platform run as a process. Today the only `main()` in the repository is
in `tools/check_boundary.py`; nothing opens a socket and nothing consumes the
`Signal`s `SessionManager` emits.

Build the host process: load a profile, wire the six hooks, construct the session
manager, serve HTTP for health and group documents, and shut down cleanly.

**Do not build SIP transport or media here.** Those are tasks 2 and 3. This task
ends at "the process starts, reports its profile, serves documents, and stops".

## Cases this closes

| Case | Pass criterion (verbatim from `docs/PLT-VP-R1.md`) |
|---|---|
| VP1-OAM-002 | Name, version and hash exposed; readiness false until the profile is validated and loaded |
| VP1-OAM-003 | Admission, refusal, establishment and release each produce an audit record; refusals carry their reason code |
| VP1-OAM-005 | Restart an instance mid-run → no committed session record lost; platform returns to service |
| VP1-DOC-001 | Group documents retrievable over HTTP per TS 24.481; schema-valid; content matches the profile's group configuration |
| VP1-SIG-007 | Start with the stub identity provider and a production indicator → refuses to start |

Requirements: PLT-GEN-002, -003, -008, -009; PLT-OAM-001, -002, -005, -007;
PLT-GRP-001; PLT-IDM-007.

## What already exists — do not rebuild it

- `core/loader.py` — `startup(profile_names, profiles_root, env)` already
  enforces the whole startup contract: exactly one profile, refusal when none or
  several, test mode refused under a production indicator, strict validation,
  hook resolution with arity checking, content hashing. **Call it. Do not
  reimplement any part of it.**
- `loader.is_production(env)` and `loader.is_test_mode(env)` define the
  production indicator (`MCX_ENV` in {production, prod}, or `MCX_PRODUCTION`
  truthy). This is a *proposal* pending confirmation — see VP-OP-05 — but it is
  what the tests currently assert.
- `LoadedProfile.profile.identifier()` returns the `name/version/hash16` triple
  the health endpoint and every audit record must carry.
- `core/audit.py` — `Auditor` and `MemorySink` exist. You need a durable sink;
  the interface is `emit(record)` and `Record.to_json()` is already there.
- `core/session.py` — `SessionManager` is complete and tested. Construct it with
  a `Platform` whose callables you supply for real: `recording_available`,
  `reserve_qos`, `active_sessions`.

## Design constraints

1. **Readiness is false until the profile is loaded** (PLT-OAM-007). Do not open
   the listening socket before `startup()` returns. The loader docstring states
   this as the contract; honour it literally.
2. **Log the profile triple once at start** and expose it on health. The same
   value must appear on every audit record — `Auditor` already does that if you
   construct it with `profile.identifier()`.
3. **Fail loudly and exit non-zero** on any startup refusal. Never start
   degraded, never fall back to a default profile.
4. **Injected clock.** The process supplies the real clock (UTC milliseconds) at
   construction; no module below it reads a wall clock.
5. **Configuration comes from the environment**, and the profile name has no
   default. `MCX_PROFILE` is already the convention used by the conformance
   suite — reuse it.
6. **VP1-OAM-005 needs a durable session store.** In-memory is not sufficient:
   the case requires a restart mid-run to lose no committed record. Pick the
   simplest thing that survives a restart (SQLite is fine) and keep the store
   behind a narrow interface so it can be replaced.

## Known traps

- **Do not put HTTP framework types into `core/`.** The document server belongs
  in a new top-level package (suggest `service/`), which may import `core`. The
  boundary gate only guards `core/` against `profiles/`, so nothing will stop you
  polluting `core/` with a web framework — but it makes `core` untestable without
  one. Keep `core/` importable with only `pyyaml` present.
- `VP1-DOC-001` says "schema-valid": the group document must validate against TS
  24.481, not merely be well-formed JSON or XML. If you cannot obtain the schema,
  record an open point rather than asserting conformance you have not checked.
- The `Platform` callables have permissive defaults for testing
  (`recording_available` returns True). A real deployment must not silently
  inherit those — a session requiring recording with no recorder must refuse
  (PLT-OAM-008), and there is already a test for it.

## Definition of done

```bash
python3 -m pytest tests/ -q                  # still 280+ green
python3 tools/check_boundary.py --root .     # still 18/18
```

Plus, demonstrably:

- the process starts with `MCX_PROFILE=mcx`, and refuses with no profile, an
  unknown profile, two profiles, or the stub IdMS under a production indicator;
- `/healthz` (or equivalent) reports name, version and hash, and readiness is
  false until the profile is loaded;
- a group document is retrievable and matches the profile's configuration;
- killing and restarting the process loses no committed session record;
- new tests for each of the five cases above, named `test_vp1_oam_002` etc. so
  the coverage script picks them up.

## Out of scope

SIP transport (task 2), media and RTCP (task 3), the containerised environment,
and anything requiring a second SIP core implementation (`VP1-SIG-001`).
