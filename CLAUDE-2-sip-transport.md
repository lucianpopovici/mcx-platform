# Task 2 — SIP transport

**Read `CLAUDE.md` first.** Task 1 (`CLAUDE-1-service.md`) must be complete: this
attaches to the running process it produces.

## Objective

Put SIP on the wire. `core/sip.py` already renders `Signal`s into message objects
and parses inbound INVITEs; nothing sends or receives them. Build the transport:
TLS sockets, transaction state, retransmission, and the loop connecting inbound
bytes to `SessionManager` and outbound `Signal`s to sent messages.

## Cases this closes

| Case | Pass criterion (verbatim) |
|---|---|
| VP1-SIG-001 | Platform completes registration and session setup against at least two distinct SIP core implementations, with no implementation-specific configuration |
| VP1-SIG-005 | After each final failure response, session store contains no record; verified by direct inspection, not by absence of symptoms |
| VP1-SIG-006 | Plaintext connection attempts refused on every external interface; mutual authentication performed where the peer supports it |
| VP1-CC-001 | Participating and controlling functions deployable and observable as distinct roles; a session names its controlling function in the audit record |
| VP1-CC-004 | Call established without callee action where the session decision sets auto-answer |
| VP1-HOOK-014 | Resolve a group whose backing store is partially unavailable → raises with `resolver-unavailable`; no partial member set returned |

Requirements: PLT-SIG-001..006; PLT-CC-001, -003; PLT-SEC-007; PLT-HOK-015.

## What already exists — do not rebuild it

- `core/sip.py` is a complete message layer with no socket: `Headers` (ordered,
  multi-valued, case-insensitive), `Request`/`Response` with `render()`,
  `Adapter.render(signal, context, request)`, `Adapter.parse_invite(message)`,
  `Adapter.reject(reason_code, context)`, `RegistrationStore` with clock-driven
  expiry, `InboundGuard` for malformed / replayed / unknown-session rejection,
  and `build_offer` / `negotiate` for SDP.
- `REASON_TO_STATUS` maps every reserved reason code to a SIP status, and
  `WARNING_TEXTS` supplies the 3GPP Warning header. Two tests enforce
  completeness, so a new reason code without a mapping fails the build.
- The MC feature tags, `Accept-Contact` with `require;explicit`, `Answer-Mode` /
  `Priv-Answer-Mode` and `P-Asserted-Identity` are already rendered correctly.

**Your job is bytes in and out, transactions, and retransmission. Not protocol
semantics — those are done and tested.**

## Design constraints

1. **TLS only on external interfaces** (PLT-SEC-007). Refuse plaintext. Perform
   mutual authentication where the peer supports it. `VP1-SIG-006` requires the
   refusal to be demonstrable, so make it observable, not merely configured.
2. **Run `InboundGuard.check()` on every inbound request before anything else**,
   and pass it the set of known session ids. It returns a rejection `Response`
   or `None`. Do not duplicate its rules.
3. **`VP1-SIG-005` requires direct inspection.** After a final failure response
   the session store must contain no record, and the test must assert on the
   store's contents — not on the absence of a symptom. Give the store a method
   that makes this checkable.
4. **Transaction state is yours; dialog semantics are shared.** Keep retransmission
   and timers in the transport, and do not let them leak into `SessionManager`,
   which is transport-agnostic on purpose.
5. **No implementation-specific configuration** (`VP1-SIG-001`). If you find
   yourself adding a branch for a particular SIP core, that is the case failing.
   Record it as an open point.
6. **Injected clock** for every timer, as elsewhere. Retransmission intervals
   must be testable without sleeping.

## Known traps

- `VP1-SIG-001` needs **two** independent SIP cores. Which two is `VP-OP-01`, an
  open point — it is not decided. Build against one (Kamailio is the working
  assumption), keep the case open, and do not claim it passed on one core.
- `VP1-CC-001` wants participating and controlling functions **observable as
  distinct roles**, and a session must name its controlling function in the audit
  record. `Session.controlling` exists as a boolean; that is not the same thing.
  Expect to extend the audit detail, and check `PLT-CC-001`/`-002` before
  designing it.
- `VP1-HOOK-014` is not really a transport case: it needs a resolver whose
  backing store can be made partially unavailable. With a real directory behind
  the resolver this becomes testable for the first time. Ensure the failure path
  raises `resolver-unavailable` and returns no partial member set — the contract
  is in `docs/PLT-ICD-001.md` §3.2 POST-5.
- Retransmission plus the replay window in `InboundGuard` can interact: a
  legitimate retransmission must not be rejected as a replay. The guard keys on
  (Call-ID, CSeq); check that against your transaction layer before trusting it.

## Definition of done

```bash
python3 -m pytest tests/ -q
python3 tools/check_boundary.py --root .
```

Plus, demonstrably: registration and a private call completed against a real SIP
core; a packet capture showing the MC feature tags on the wire; plaintext
refused; and a captured final failure response after which the store is
inspected and found empty.

## Out of scope

Media and RTCP (task 3). Codec negotiation beyond what `negotiate()` already
does. `VP1-SIG-001`'s second SIP core, until `VP-OP-01` is decided.
