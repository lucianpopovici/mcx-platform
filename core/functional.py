"""Functional alias management: who holds which functional identity
(PLT-VP-R1 SVC-OP-06, decided 2026-10-23; TS 24.379 clause 9A, Rel-15 on).

A call type that names `initiator_roles` may be started only by a user holding
one of those functional identities (IF-IDR `identities_of`). They are held
because the user activated them, the TS 24.379 9A way: a SIP PUBLISH listing
the functional aliases the user wants (9A.2.1.2), checked by the server that
owns them (9A.2.2.3.3) and bound through the profile's resolver (IF-IDR
`bind` / `unbind`). The service parses the PUBLISH; this module decides.

What the deployment states (the network profile's `functional_aliases`,
PLT-ICD-001 ICD-NET-007): for each functional identity, which users may hold
it, and which of them may take it over from another holder. That is the
platform's form of TS 24.484's per-user `<FunctionalAliasList>` and
`<allow-takeover-functional-alias-other-user>`.

The rules, each from the standard:

* A PUBLISH lists the whole set the user wants: aliases listed and not held
  are activated, aliases held and not listed are deactivated (9A.2.2.2.3
  steps 10-14). Expires 0 deactivates them all.
* Every listed alias must be one the user may hold, or nothing changes and
  the request is refused 403 (steps 4A, 4B; 9A.2.2.3.3 step 4a).
* A single-holder identity already held by someone else is refused 403
  (9A.2.2.3.3 step 5, `<max-simultaneous-activations>` 1), unless the
  request asks to take it over (`<take-over>`) and the user may take over
  (step 6); the holder it is taken from loses it. This settles ICD-OP-02:
  replace only when asked, refuse otherwise.
* A location-dependent identity is held per value of its location key: the
  location the PUBLISH reports, or else the cell the user last reported,
  through the deployment's cell map (owner decision 2026-10-23). With
  neither, it is refused.

Every change and every refusal is an audit record. The holders are returned
to the host as data, so it can keep them across a restart (`restore`).

This module plans and keeps the ledger; the session manager makes the IF-IDR
calls, in place, as it makes every hook call (VP1-BND-003, VP1-BND-014).
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from .audit import Auditor, RecordType
from .errors import (
    FUNCTIONAL_ALIAS_HELD,
    FUNCTIONAL_ALIAS_LOCATION_UNKNOWN,
    FUNCTIONAL_ALIAS_NOT_AUTHORISED,
    FUNCTIONAL_ALIAS_TAKE_OVER_NOT_ALLOWED,
)
from .hooks import LocationContext

SINGLE = "single"
# The slot of an identity that is not location-dependent.
EVERYWHERE = ""


@dataclass(frozen=True)
class AliasPolicy:
    """Deployment data for one functional identity: who may hold it, who of
    them may take it over from another holder, and, for a multi-holder
    identity, how many may hold it at once (None: no limit; TS 24.484
    <max-simultaneous-activations>, FA-OP-01 item 3)."""
    users: FrozenSet[str]
    take_over: FrozenSet[str] = frozenset()
    max_holders: Optional[int] = None


@dataclass(frozen=True)
class Holding:
    """One user holding one identity, at one location value ("" for an
    identity that is not location-dependent)."""
    identity: str
    slot: str
    holder: str


@dataclass(frozen=True)
class AliasOutcome:
    """The answer to one request. `reason_code` is "" when it was accepted;
    `activated`, `deactivated` and `displaced` say what changed."""
    reason_code: str = ""
    detail: str = ""
    activated: Tuple[Holding, ...] = ()
    deactivated: Tuple[Holding, ...] = ()
    displaced: Tuple[Holding, ...] = ()

    @property
    def accepted(self) -> bool:
        return not self.reason_code


class FunctionalAliases:
    """The holders of the profile's functional identities, kept by the core;
    the session manager mirrors them into the profile's resolver."""

    def __init__(self, profile, auditor: Auditor,
                 policy: Mapping[str, AliasPolicy],
                 locate: Callable[[Optional[LocationContext]], Mapping[str, str]]) -> None:
        """`locate` turns a reported location into its location attributes
        (the deployment's cell map)."""
        self._profile = profile
        self._auditor = auditor
        self._policy = dict(policy)
        self._locate = locate
        # (identity, slot) -> holders, in the order they activated.
        self._held: Dict[Tuple[str, str], Tuple[str, ...]] = {}

    # -- observation ------------------------------------------------------

    def holdings(self) -> Tuple[Holding, ...]:
        held = self._held
        return tuple(Holding(i, s, h) for (i, s), hs in sorted(held.items()) for h in hs)

    def held_by(self, user: str) -> Tuple[Holding, ...]:
        return tuple(h for h in self.holdings() if h.holder == user)

    # -- the procedure ------------------------------------------------------

    def plan(self, correlation_id: str, user: str, wanted: Sequence[str],
             take_over: bool, location: Optional[LocationContext]) -> AliasOutcome:
        """What `user` wanting exactly `wanted` changes (9A.2.2.2.3), or the
        refusal, recorded. Nothing is applied until `commit`. All or nothing."""
        wanted = tuple(dict.fromkeys(wanted))
        current = {h.identity: h for h in self.held_by(user)}
        plan: List[Holding] = []
        displaced: List[Holding] = []
        for identity in wanted:
            declared = self._profile.functional_identity(identity)
            policy = self._policy.get(identity)
            if declared is None or declared.resolves_to != "user" or policy is None \
                    or user not in policy.users:
                return self.refuse(correlation_id, user, wanted,
                                   FUNCTIONAL_ALIAS_NOT_AUTHORISED,
                                   f"{user} may not hold {identity!r}")
            slot = EVERYWHERE
            if declared.location_dependent:
                slot = self._locate(location).get(declared.location_key or "", "")
                if not slot:
                    return self.refuse(
                        correlation_id, user, wanted, FUNCTIONAL_ALIAS_LOCATION_UNKNOWN,
                        f"{identity!r} is held per {declared.location_key}, and no "
                        "reported location gives one")
            others = tuple(h for h in self._held.get((identity, slot), ()) if h != user)
            # 9A.2.2.3.3 step 5: <max-simultaneous-activations> reached. One
            # for a single-holder identity; for a multi-holder one, the
            # deployment's max_holders, if it states one (FA-OP-01 item 3).
            # Counting the others only: a holder publishing again is not one
            # more, and holders never exceed the limit (restore caps them).
            limit = 1 if declared.multiplicity == SINGLE else policy.max_holders
            if limit is not None and len(others) >= limit:
                if not take_over:
                    return self.refuse(correlation_id, user, wanted, FUNCTIONAL_ALIAS_HELD,
                                       f"{identity!r} at {slot or 'any location'!r} is "
                                       f"held by {', '.join(others)}"
                                       + (f" (at most {limit})" if limit > 1 else ""))
                if user not in policy.take_over:
                    return self.refuse(correlation_id, user, wanted,
                                       FUNCTIONAL_ALIAS_TAKE_OVER_NOT_ALLOWED,
                                       f"{user} may not take over {identity!r}")
                # Step 6: room is made by the earliest holders, as many as needed.
                displaced += [Holding(identity, slot, o)
                              for o in others[:len(others) - limit + 1]]
            plan.append(Holding(identity, slot, user))
        activated = tuple(h for h in plan if current.get(h.identity) != h)
        deactivated = tuple(h for i, h in sorted(current.items())
                            if i not in wanted or h not in plan)
        return AliasOutcome(activated=activated, deactivated=deactivated,
                            displaced=tuple(displaced))

    def commit(self, correlation_id: str, user: str, outcome: AliasOutcome,
               take_over: bool) -> None:
        """Apply a planned change the resolver has taken, and record it."""
        for h in (*outcome.displaced, *outcome.deactivated):
            self._drop(h)
        for h in outcome.activated:
            self._add(h)
        self._auditor.emit(
            RecordType.BINDING_CHANGED, correlation_id, action="changed", user=user,
            take_over=take_over,
            activated=[dataclasses.asdict(h) for h in outcome.activated],
            deactivated=[dataclasses.asdict(h) for h in outcome.deactivated],
            displaced=[dataclasses.asdict(h) for h in outcome.displaced])

    def restorable(self, h: Holding) -> bool:
        """Whether a holding kept across a restart is still allowed: the
        network profile in force and the profile decide, not the store."""
        declared = self._profile.functional_identity(h.identity)
        policy = self._policy.get(h.identity)
        return declared is not None and declared.resolves_to == "user" and \
            policy is not None and h.holder in policy.users and \
            declared.location_dependent == bool(h.slot)

    def location_key(self, identity: str) -> str:
        declared = self._profile.functional_identity(identity)
        return (declared.location_key or "") if declared is not None else ""

    def single_held(self, h: Holding) -> bool:
        """Whether `h`'s identity has as many holders at `h`'s slot as it may
        (by others: restore takes each holding once): one for a single-holder
        identity, the deployment's max_holders for a multi-holder one."""
        declared = self._profile.functional_identity(h.identity)
        if declared is None:
            return False
        policy = self._policy.get(h.identity)
        limit = 1 if declared.multiplicity == SINGLE else \
            (policy.max_holders if policy is not None else None)
        return limit is not None and len(self._held.get((h.identity, h.slot), ())) >= limit

    def location_for(self, h: Holding, location: Optional[LocationContext]
                     ) -> Optional[LocationContext]:
        """The location to bind `h` with: its slot under its location key."""
        if not h.slot:
            return location
        declared = self._profile.functional_identity(h.identity)
        attrs = {**(location.attributes if location else {}), declared.location_key: h.slot}
        return LocationContext(cell_id=location.cell_id if location else None,
                               attributes=attrs)

    def add(self, h: Holding) -> None:
        self._add(h)

    def drop(self, h: Holding) -> None:
        self._drop(h)

    def refuse(self, correlation_id: str, user: str, wanted: Sequence[str],
               reason_code: str, detail: str) -> AliasOutcome:
        self._auditor.emit(RecordType.BINDING_REFUSED, correlation_id, user=user,
                           wanted=list(wanted), reason_code=reason_code, detail=detail)
        return AliasOutcome(reason_code=reason_code, detail=detail)

    # -- internals ----------------------------------------------------------

    def _add(self, h: Holding) -> None:
        # Copy on write: `holdings()` may be read from another thread (the
        # health document) and iterates whichever mapping it was given.
        key = (h.identity, h.slot)
        if h.holder not in self._held.get(key, ()):
            self._held = {**self._held, key: self._held.get(key, ()) + (h.holder,)}

    def _drop(self, h: Holding) -> None:
        key = (h.identity, h.slot)
        rest = tuple(x for x in self._held.get(key, ()) if x != h.holder)
        held = {k: v for k, v in self._held.items() if k != key}
        if rest:
            held[key] = rest
        self._held = held
