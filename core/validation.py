"""Strict profile validation.

Every rule here traces to a requirement:

  PLT-PRF-003  unknown keys are errors
  PLT-PRF-004  unresolved internal references are errors
  PLT-PRF-005  the priority table must be total over declared call types
  PLT-PRF-006  the bearer table must be total over (call type, media)
  PLT-PRF-008  each defect names the failing element by its path
  PLT-PRF-012  all five hooks are mandatory

Validation collects every defect rather than stopping at the first, so one run
tells the author everything that is wrong with the profile.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from . import mcinfo
from . import model
from . import qos as qos_spec
from .errors import CORE_ORIGINATED, ProfileValidationError

# --------------------------------------------------------------------------
# Closed vocabularies fixed by specification, not by profile.
# --------------------------------------------------------------------------

MEDIA_KINDS = ("voice", "video", "data")
SESSION_MODELS = ("on-demand", "pre-established", "broadcast")
TRANSPORTS = ("udp", "tcp", "sctp")
REDUNDANCY = ("single", "multipath", "multihomed")
BINDINGS = ("static", "dynamic")
MULTIPLICITIES = ("single", "multi")
RESOLVES_TO = ("user", "group")

# On-network floor control SERVER timers, TS 24.380 clause 6.3. A profile may
# override only these.
#
# The off-network PARTICIPANT timers (T201, T203..T207, T230, T233, clause
# 7.2.3) are deliberately NOT accepted: this platform is an on-network server,
# and a profile declaring one of them is making a category error that should
# fail validation rather than be silently honoured. They are added when
# off-network operation arrives (R4).
FLOOR_TIMERS = ("T1", "T2", "T3", "T4", "T7", "T8", "T20")

HOOK_FIELDS = (
    "identity_resolver",
    "priority_policy",
    "session_policy",
    "bearer_selector",
    "interworking_gateway",
    "interconnection_gateway",
)

TRUST_MECHANISMS = ("mutual-tls", "signed-assertion")


@dataclass(frozen=True)
class Defect:
    path: str
    code: str
    message: str


class _Checker:
    """Accumulates defects against paths within the profile package."""

    def __init__(self) -> None:
        self.defects: List[Defect] = []

    def add(self, path: str, code: str, message: str) -> None:
        self.defects.append(Defect(path, code, message))

    # -- structural -----------------------------------------------------

    def keys(self, path: str, node: Any, allowed: Sequence[str],
             required: Sequence[str] = ()) -> bool:
        """Unknown keys are errors (PLT-PRF-003); missing required keys too."""
        if not isinstance(node, dict):
            self.add(path, "bad-type", f"expected a mapping, found {_typename(node)}")
            return False
        for k in node:
            if k not in allowed:
                self.add(f"{path}.{k}", "unknown-key",
                         f"key not defined in the schema (allowed: {', '.join(sorted(allowed))})")
        ok = True
        for k in required:
            if k not in node:
                self.add(f"{path}.{k}", "missing-key", "required key absent")
                ok = False
        return ok

    def typed(self, path: str, node: Mapping, key: str, kind: type,
              default: Any = None, required: bool = True) -> Any:
        if key not in node:
            if required:
                self.add(f"{path}.{key}", "missing-key", "required key absent")
            return default
        v = node[key]
        if kind is int and isinstance(v, bool):
            self.add(f"{path}.{key}", "bad-type", "expected an integer, found a boolean")
            return default
        if not isinstance(v, kind):
            self.add(f"{path}.{key}", "bad-type",
                     f"expected {kind.__name__}, found {_typename(v)}")
            return default
        return v

    def enum(self, path: str, value: Any, allowed: Sequence[str]) -> Optional[str]:
        if value is None:
            return None
        if value not in allowed:
            self.add(path, "bad-value",
                     f"{value!r} is not one of: {', '.join(allowed)}")
            return None
        return value

    def ref(self, path: str, value: Optional[str], universe: Set[str],
            what: str) -> None:
        """Unresolved internal reference (PLT-PRF-004)."""
        if value is None:
            return
        if value not in universe:
            known = ", ".join(sorted(universe)) or "<none declared>"
            self.add(path, "unresolved-reference",
                     f"{what} {value!r} is not declared (declared: {known})")

    def str_map(self, path: str, node: Mapping, key: str) -> Dict[str, str]:
        raw = node.get(key) or {}
        if not isinstance(raw, dict):
            self.add(f"{path}.{key}", "bad-type",
                     f"expected a mapping, found {_typename(raw)}")
            return {}
        out = {}
        for k, v in raw.items():
            if not isinstance(k, str) or not isinstance(v, str):
                self.add(f"{path}.{key}.{k}", "bad-type",
                         "expected string keys and string values")
                continue
            out[k] = v
        return out


def _typename(v: Any) -> str:
    return type(v).__name__


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def build(raw: Mapping[str, Any], content_hash: str) -> model.Profile:
    """Validate `raw` and return a frozen Profile, or raise ProfileValidationError.

    No partial result is ever returned: either the profile is wholly valid or
    nothing is constructed (PLT-PRF-007, PLT-PRF-031 of the verification plan).
    """
    c = _Checker()

    c.keys("<root>", raw, allowed=(
        "$schema", "profile", "urgencies", "preemption_scopes", "applications",
        "call_types", "identity", "priority", "bearer", "interworking",
        "interconnection", "admission", "media",
    ), required=(
        "profile", "urgencies", "preemption_scopes", "call_types", "identity",
        "priority", "bearer", "admission", "media",
    ))
    if not isinstance(raw, dict):
        raise ProfileValidationError(c.defects)

    meta = _profile_meta(c, raw.get("profile"))
    urgencies = _declared(c, raw.get("urgencies"), "urgencies")
    scopes = _declared(c, raw.get("preemption_scopes"), "preemption_scopes")
    applications = _applications(c, raw.get("applications"))
    identity = _identity(c, raw.get("identity"))

    urgency_ids = {u.id for u in urgencies}
    scope_ids = {s.id for s in scopes}
    application_ids = {a.id for a in applications}
    role_ids = {f.id for f in identity.functional} if identity else set()

    call_types = _call_types(c, raw.get("call_types"), urgency_ids,
                             application_ids, role_ids)
    call_type_ids = {ct.id for ct in call_types}

    priority = _priority(c, raw.get("priority"), scope_ids, call_type_ids,
                         application_ids, urgency_ids)
    bearer = _bearer(c, raw.get("bearer"), call_type_ids)
    interworking = _interworking(c, raw.get("interworking"))
    interconnection = _interconnection(c, raw.get("interconnection"), scope_ids,
                                       call_type_ids)
    admission = _admission(c, raw.get("admission"), urgency_ids)
    media = _media(c, raw.get("media"))

    # -- cross-cutting checks -------------------------------------------
    _priority_totality(c, call_types, priority)
    _bearer_totality(c, call_types, bearer)
    _identity_consistency(c, identity)

    if c.defects:
        raise ProfileValidationError(c.defects)

    return model.Profile(
        name=meta["name"],
        version=meta["version"],
        description=meta.get("description", ""),
        hooks=model.HookPaths(**{f: meta["hooks"][f] for f in HOOK_FIELDS}),
        urgencies=urgencies,
        preemption_scopes=scopes,
        applications=applications,
        call_types=call_types,
        identity=identity,
        priority=priority,
        bearer=bearer,
        interworking=interworking,
        interconnection=interconnection,
        admission=admission,
        media=media,
        content_hash=content_hash,
    )


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------


def _profile_meta(c: _Checker, node: Any) -> Dict[str, Any]:
    p = "profile"
    out: Dict[str, Any] = {"name": "", "version": "", "description": "",
                           "hooks": {f: "" for f in HOOK_FIELDS}}
    if not c.keys(p, node, allowed=("name", "version", "description", "hooks"),
                  required=("name", "version", "hooks")):
        return out
    out["name"] = c.typed(p, node, "name", str, "") or ""
    out["version"] = c.typed(p, node, "version", str, "") or ""
    out["description"] = c.typed(p, node, "description", str, "",
                                 required=False) or ""

    hooks = node.get("hooks")
    hp = f"{p}.hooks"
    # All five hooks are mandatory; no default is ever supplied (PLT-PRF-012).
    if c.keys(hp, hooks, allowed=HOOK_FIELDS, required=HOOK_FIELDS):
        for f in HOOK_FIELDS:
            v = c.typed(hp, hooks, f, str, "")
            if v is not None and v != "" and ":" not in v:
                c.add(f"{hp}.{f}", "bad-value",
                      "expected 'module.path:ClassName'")
            out["hooks"][f] = v or ""
    return out


def _declared(c: _Checker, node: Any, section: str) -> Tuple[model.Declared, ...]:
    if not isinstance(node, list):
        c.add(section, "bad-type", f"expected a list, found {_typename(node)}")
        return ()
    out, seen = [], set()
    for i, item in enumerate(node):
        p = f"{section}[{i}]"
        if not c.keys(p, item, allowed=("id", "label"), required=("id", "label")):
            continue
        ident = c.typed(p, item, "id", str, "")
        label = c.typed(p, item, "label", str, "")
        if ident in seen:
            c.add(f"{p}.id", "duplicate", f"{ident!r} already declared")
            continue
        seen.add(ident)
        out.append(model.Declared(id=ident, label=label or ""))
    return tuple(out)


def _applications(c: _Checker, node: Any) -> Tuple[model.Application, ...]:
    if node is None:
        return ()
    if not isinstance(node, list):
        c.add("applications", "bad-type",
              f"expected a list, found {_typename(node)}")
        return ()
    out, seen = [], set()
    for i, item in enumerate(node):
        p = f"applications[{i}]"
        if not c.keys(p, item, allowed=("id", "label", "media", "safety_relevant"),
                      required=("id", "label", "media", "safety_relevant")):
            continue
        ident = c.typed(p, item, "id", str, "")
        if ident in seen:
            c.add(f"{p}.id", "duplicate", f"{ident!r} already declared")
            continue
        seen.add(ident)
        media = _media_list(c, f"{p}.media", item.get("media"))
        out.append(model.Application(
            id=ident,
            label=c.typed(p, item, "label", str, "") or "",
            media=media,
            safety_relevant=bool(c.typed(p, item, "safety_relevant", bool, False)),
        ))
    return tuple(out)


def _media_list(c: _Checker, path: str, node: Any) -> Tuple[str, ...]:
    if not isinstance(node, list) or not node:
        c.add(path, "bad-value", "expected a non-empty list of media kinds")
        return ()
    out = []
    for i, m in enumerate(node):
        v = c.enum(f"{path}[{i}]", m, MEDIA_KINDS)
        if v:
            out.append(v)
    return tuple(out)


def _floor(c: _Checker, path: str, node: Any) -> model.FloorConfig:
    default = model.FloorConfig(False, False, False, 0, model.freeze_map({}))
    if not c.keys(path, node, allowed=(
            "initial_grant_to_initiator", "queueing_enabled", "override_allowed",
            "max_queue_depth", "timers_ms"),
            required=("initial_grant_to_initiator", "queueing_enabled",
                      "override_allowed", "max_queue_depth")):
        return default

    queueing = bool(c.typed(path, node, "queueing_enabled", bool, False))
    depth = c.typed(path, node, "max_queue_depth", int, 0)
    depth = 0 if depth is None else depth

    # PLT-ICD-001 §5.3 POST-1/2: queueing and depth must agree.
    if not queueing and depth != 0:
        c.add(f"{path}.max_queue_depth", "inconsistent",
              "queueing is disabled, so depth must be 0")
    if queueing and depth < 1:
        c.add(f"{path}.max_queue_depth", "inconsistent",
              "queueing is enabled, so depth must be at least 1")

    timers = {}
    raw = node.get("timers_ms") or {}
    tp = f"{path}.timers_ms"
    if not isinstance(raw, dict):
        c.add(tp, "bad-type", f"expected a mapping, found {_typename(raw)}")
    else:
        for name, value in raw.items():
            # PLT-ICD-001 §5.3 POST-3: unknown timer names are contract violations.
            if name not in FLOOR_TIMERS:
                c.add(f"{tp}.{name}", "unknown-key",
                      f"not a TS 24.380 timer (known: {', '.join(FLOOR_TIMERS)})")
                continue
            if isinstance(value, bool) or not isinstance(value, int):
                c.add(f"{tp}.{name}", "bad-type",
                      f"expected an integer in milliseconds, found {_typename(value)}")
                continue
            if value <= 0:
                c.add(f"{tp}.{name}", "bad-value", "must be greater than zero")
                continue
            timers[name] = value

    return model.FloorConfig(
        initial_grant_to_initiator=bool(
            c.typed(path, node, "initial_grant_to_initiator", bool, False)),
        queueing_enabled=queueing,
        override_allowed=bool(c.typed(path, node, "override_allowed", bool, False)),
        max_queue_depth=depth,
        timers_ms=model.freeze_map(timers),
    )


def _call_types(c: _Checker, node: Any, urgencies: Set[str],
                applications: Set[str], roles: Set[str]) -> Tuple[model.CallType, ...]:
    if not isinstance(node, list) or not node:
        c.add("call_types", "bad-value",
              "expected a non-empty list; a profile with no call type cannot serve")
        return ()
    out, seen = [], set()
    for i, item in enumerate(node):
        p = f"call_types[{i}]"
        if not c.keys(p, item, allowed=(
                "id", "label", "media", "session_model", "urgency", "application",
                "auto_answer", "acknowledgement_required", "recording_required",
                "max_participants", "initiator_roles", "floor", "mc_signature",
                "no_answer_s"),
                required=("id", "label", "media", "session_model", "urgency",
                          "auto_answer", "acknowledgement_required",
                          "recording_required", "initiator_roles", "floor",
                          "mc_signature", "no_answer_s")):
            continue
        ident = c.typed(p, item, "id", str, "")
        if ident in seen:
            c.add(f"{p}.id", "duplicate", f"{ident!r} already declared")
            continue
        seen.add(ident)

        urgency = c.typed(p, item, "urgency", str, "")
        c.ref(f"{p}.urgency", urgency, urgencies, "urgency")

        application = item.get("application")
        if application is not None:
            if not isinstance(application, str):
                c.add(f"{p}.application", "bad-type", "expected a string")
                application = None
            else:
                c.ref(f"{p}.application", application, applications, "application")

        raw_roles = item.get("initiator_roles")
        parsed_roles: List[str] = []
        if not isinstance(raw_roles, list):
            c.add(f"{p}.initiator_roles", "bad-type",
                  "expected a list (empty means any authorised user)")
        else:
            for j, r in enumerate(raw_roles):
                if not isinstance(r, str):
                    c.add(f"{p}.initiator_roles[{j}]", "bad-type", "expected a string")
                    continue
                c.ref(f"{p}.initiator_roles[{j}]", r, roles, "functional identity")
                parsed_roles.append(r)

        maxp = item.get("max_participants")
        if maxp is not None:
            if isinstance(maxp, bool) or not isinstance(maxp, int):
                c.add(f"{p}.max_participants", "bad-type", "expected an integer or null")
                maxp = None
            elif maxp < 1:
                c.add(f"{p}.max_participants", "bad-value",
                      "must be at least 1; use null for unlimited")
                maxp = None

        # PLT-ICD-001 2.7: required, a whole number of seconds, at least 1.
        # No upper bound: how long a member may ring is the service's call.
        no_answer = item.get("no_answer_s")
        if isinstance(no_answer, bool) or not isinstance(no_answer, int):
            if "no_answer_s" in item:
                c.add(f"{p}.no_answer_s", "bad-type", "expected an integer (seconds)")
            no_answer = 0
        elif no_answer < 1:
            c.add(f"{p}.no_answer_s", "bad-value", "must be at least 1 second")

        out.append(model.CallType(
            id=ident,
            label=c.typed(p, item, "label", str, "") or "",
            media=_media_list(c, f"{p}.media", item.get("media")),
            session_model=c.enum(f"{p}.session_model", item.get("session_model"),
                                 SESSION_MODELS) or "",
            urgency=urgency or "",
            application=application,
            auto_answer=bool(c.typed(p, item, "auto_answer", bool, False)),
            acknowledgement_required=bool(
                c.typed(p, item, "acknowledgement_required", bool, False)),
            recording_required=bool(
                c.typed(p, item, "recording_required", bool, False)),
            max_participants=maxp,
            initiator_roles=tuple(parsed_roles),
            floor=_floor(c, f"{p}.floor", item.get("floor")),
            mc_signature=_mc_signature(c, f"{p}.mc_signature", item.get("mc_signature")),
            no_answer_s=no_answer,
        ))

    # A signature must name at most one call type, or the core would have to
    # guess which one a client meant -- and must not (PLT-ICD-001 2.6).
    claimed: Dict[mcinfo.Signature, str] = {}
    for ct in out:
        if ct.mc_signature is None:
            continue
        other = claimed.get(ct.mc_signature)
        if other is not None:
            c.add("call_types", "ambiguous-signature",
                  f"{other!r} and {ct.id!r} declare the same mc_signature; TS 24.379 "
                  f"cannot tell them apart, so at most one of them may have it")
        else:
            claimed[ct.mc_signature] = ct.id
    return tuple(out)


def _mc_signature(c: _Checker, p: str, node: Any) -> Optional[mcinfo.Signature]:
    """null, or {session_type, emergency?, imminent_peril?, broadcast?}."""
    if node is None:
        return None
    if not c.keys(p, node, allowed=("session_type", "emergency", "imminent_peril",
                                    "broadcast"), required=("session_type",)):
        return None
    st = c.enum(f"{p}.session_type", node.get("session_type"), mcinfo.SESSION_TYPES)
    flags = {}
    for k in ("emergency", "imminent_peril", "broadcast"):
        val = node.get(k, False)
        if not isinstance(val, bool):
            c.add(f"{p}.{k}", "bad-type", "expected true or false")
            val = False
        flags[k] = val
    return mcinfo.Signature(st, **flags) if st else None


def _identity(c: _Checker, node: Any) -> model.Identity:
    p = "identity"
    if not c.keys(p, node, allowed=("domains", "functional"),
                  required=("domains",)):
        return model.Identity(domains=(), functional=())

    domains = node.get("domains")
    parsed_domains: List[str] = []
    if not isinstance(domains, list) or not domains:
        c.add(f"{p}.domains", "bad-value",
              "expected a non-empty list; a profile must declare its domains")
    else:
        for i, d in enumerate(domains):
            if not isinstance(d, str) or not d:
                c.add(f"{p}.domains[{i}]", "bad-value", "expected a non-empty string")
                continue
            parsed_domains.append(d)

    functional: List[model.FunctionalIdentity] = []
    raw = node.get("functional") or []
    if not isinstance(raw, list):
        c.add(f"{p}.functional", "bad-type",
              f"expected a list, found {_typename(raw)}")
        raw = []
    seen = set()
    for i, item in enumerate(raw):
        fp = f"{p}.functional[{i}]"
        if not c.keys(fp, item, allowed=(
                "id", "label", "binding", "location_dependent", "location_key",
                "multiplicity", "resolves_to"),
                required=("id", "label", "binding", "location_dependent",
                          "multiplicity", "resolves_to")):
            continue
        ident = c.typed(fp, item, "id", str, "")
        if ident in seen:
            c.add(f"{fp}.id", "duplicate", f"{ident!r} already declared")
            continue
        seen.add(ident)
        loc_dep = bool(c.typed(fp, item, "location_dependent", bool, False))
        loc_key = item.get("location_key")
        if loc_key is not None and not isinstance(loc_key, str):
            c.add(f"{fp}.location_key", "bad-type", "expected a string or null")
            loc_key = None
        functional.append(model.FunctionalIdentity(
            id=ident,
            label=c.typed(fp, item, "label", str, "") or "",
            binding=c.enum(f"{fp}.binding", item.get("binding"), BINDINGS) or "",
            location_dependent=loc_dep,
            location_key=loc_key,
            multiplicity=c.enum(f"{fp}.multiplicity", item.get("multiplicity"),
                                MULTIPLICITIES) or "",
            resolves_to=c.enum(f"{fp}.resolves_to", item.get("resolves_to"),
                               RESOLVES_TO) or "",
        ))
    return model.Identity(domains=tuple(parsed_domains), functional=tuple(functional))



def _identity_consistency(c: _Checker, identity: model.Identity) -> None:
    """A location-dependent identity without a location key cannot be resolved."""
    for i, f in enumerate(identity.functional):
        p = f"identity.functional[{i}]"
        if f.location_dependent and not f.location_key:
            c.add(f"{p}.location_key", "inconsistent",
                  "identity is location-dependent, so a location_key is required")
        if not f.location_dependent and f.location_key:
            c.add(f"{p}.location_key", "inconsistent",
                  "location_key is set but the identity is not location-dependent")


def _priority(c: _Checker, node: Any, scopes: Set[str], call_types: Set[str],
              applications: Set[str], urgencies: Set[str]) -> model.Priority:
    p = "priority"
    if not c.keys(p, node, allowed=("default_scope", "rules"),
                  required=("default_scope", "rules")):
        return model.Priority(default_scope="", rules=())

    default_scope = c.typed(p, node, "default_scope", str, "")
    c.ref(f"{p}.default_scope", default_scope, scopes, "pre-emption scope")

    rules: List[model.PriorityRule] = []
    raw = node.get("rules")
    if not isinstance(raw, list) or not raw:
        c.add(f"{p}.rules", "bad-value", "expected a non-empty list of rules")
        raw = []
    for i, item in enumerate(raw):
        rp = f"{p}.rules[{i}]"
        if not c.keys(rp, item, allowed=("match", "decision"),
                      required=("match", "decision")):
            continue
        m = _priority_match(c, f"{rp}.match", item.get("match"), call_types,
                            applications, urgencies)
        d = _priority_decision(c, f"{rp}.decision", item.get("decision"), scopes)
        if m and d:
            rules.append(model.PriorityRule(match=m, decision=d))
    return model.Priority(default_scope=default_scope or "", rules=tuple(rules))


def _priority_match(c: _Checker, path: str, node: Any, call_types: Set[str],
                    applications: Set[str],
                    urgencies: Set[str]) -> Optional[model.PriorityMatch]:
    if not c.keys(path, node, allowed=("call_type", "application", "urgency"),
                  required=("call_type", "urgency")):
        return None
    ct = c.typed(path, node, "call_type", str, "*")
    app = node.get("application", "*")
    urg = c.typed(path, node, "urgency", str, "*")
    if ct != "*":
        c.ref(f"{path}.call_type", ct, call_types, "call type")
    if isinstance(app, str) and app != "*":
        c.ref(f"{path}.application", app, applications, "application")
    elif not isinstance(app, str):
        c.add(f"{path}.application", "bad-type", "expected a string or '*'")
        app = "*"
    if urg != "*":
        c.ref(f"{path}.urgency", urg, urgencies, "urgency")
    return model.PriorityMatch(call_type=ct or "*", application=app or "*",
                               urgency=urg or "*")


def _priority_decision(c: _Checker, path: str, node: Any,
                       scopes: Set[str]) -> Optional[model.PriorityDecisionSpec]:
    if not c.keys(path, node, allowed=(
            "level", "scope", "preemption_capability", "preemption_vulnerability",
            "floor_priority", "label"),
            required=("level", "scope", "preemption_capability",
                      "preemption_vulnerability", "floor_priority", "label")):
        return None
    scope = c.typed(path, node, "scope", str, "")
    c.ref(f"{path}.scope", scope, scopes, "pre-emption scope")
    level = c.typed(path, node, "level", int, 0)
    floor_priority = c.typed(path, node, "floor_priority", int, 0)
    for name, value in (("level", level), ("floor_priority", floor_priority)):
        if value is not None and value < 0:
            c.add(f"{path}.{name}", "bad-value", "must not be negative")
    return model.PriorityDecisionSpec(
        level=level or 0,
        scope=scope or "",
        preemption_capability=bool(
            c.typed(path, node, "preemption_capability", bool, False)),
        preemption_vulnerability=bool(
            c.typed(path, node, "preemption_vulnerability", bool, False)),
        floor_priority=floor_priority or 0,
        label=c.typed(path, node, "label", str, "") or "",
    )


def _priority_totality(c: _Checker, call_types: Tuple[model.CallType, ...],
                       priority: model.Priority) -> None:
    """PLT-PRF-005: every declared call type must reach a decision."""
    for ct in call_types:
        app = ct.application or "*"
        matched = any(
            (r.match.call_type in ("*", ct.id))
            and (r.match.application in ("*", app)
                 or (ct.application is None and r.match.application == "*"))
            and (r.match.urgency in ("*", ct.urgency))
            for r in priority.rules
        )
        if not matched:
            c.add("priority.rules", "not-total",
                  f"no rule matches call type {ct.id!r} "
                  f"(urgency {ct.urgency!r}, application {ct.application!r})")


def _bearer(c: _Checker, node: Any, call_types: Set[str]) -> model.Bearer:
    p = "bearer"
    if not c.keys(p, node, allowed=("rules",), required=("rules",)):
        return model.Bearer(rules=())
    rules: List[model.BearerRule] = []
    raw = node.get("rules")
    if not isinstance(raw, list) or not raw:
        c.add(f"{p}.rules", "bad-value", "expected a non-empty list of rules")
        raw = []
    for i, item in enumerate(raw):
        rp = f"{p}.rules[{i}]"
        if not c.keys(rp, item, allowed=("match", "decision"),
                      required=("match", "decision")):
            continue
        m = _bearer_match(c, f"{rp}.match", item.get("match"), call_types)
        d = _bearer_decision(c, f"{rp}.decision", item.get("decision"))
        if m and d:
            # A mission-critical 5QI is defined for one kind of media
            # (TS 23.501 table 5.7.4-1). Asking for the Mission Critical Video
            # 5QI on a data bearer is not a preference, it is a request the
            # network cannot satisfy as intended, and an in-tree profile was
            # doing exactly that (PLT-CONF-AUDIT CA-15). Non-MC and
            # operator-specific 5QIs carry no such expectation and are left
            # alone.
            expected = qos_spec.media_of(d.qos_identifier)
            if expected is not None and m.media != "*" and m.media != expected:
                c.add(f"{rp}.decision.qos_identifier", "inconsistent",
                      f"5QI {d.qos_identifier} is defined for {expected} "
                      f"(TS 23.501 table 5.7.4-1) but this rule matches "
                      f"media {m.media!r}")
            rules.append(model.BearerRule(match=m, decision=d))
    return model.Bearer(rules=tuple(rules))


def _bearer_match(c: _Checker, path: str, node: Any,
                  call_types: Set[str]) -> Optional[model.BearerMatch]:
    if not c.keys(path, node, allowed=("call_type", "media"),
                  required=("call_type", "media")):
        return None
    ct = c.typed(path, node, "call_type", str, "*")
    media = c.typed(path, node, "media", str, "*")
    if ct != "*":
        c.ref(f"{path}.call_type", ct, call_types, "call type")
    if media != "*":
        c.enum(f"{path}.media", media, MEDIA_KINDS)
    return model.BearerMatch(call_type=ct or "*", media=media or "*")


def _bearer_decision(c: _Checker, path: str,
                     node: Any) -> Optional[model.BearerDecisionSpec]:
    if not c.keys(path, node, allowed=(
            "qos_identifier", "arp_level", "arp_preemption_capability",
            "arp_preemption_vulnerability", "redundancy", "paths"),
            required=("qos_identifier", "arp_level", "arp_preemption_capability",
                      "arp_preemption_vulnerability", "redundancy", "paths")):
        return None

    redundancy = c.enum(f"{path}.redundancy", node.get("redundancy"), REDUNDANCY)
    paths: List[model.PathSpecConfig] = []
    raw = node.get("paths")
    pp = f"{path}.paths"
    if not isinstance(raw, list) or not raw:
        c.add(pp, "bad-value", "expected at least one path")
        raw = []
    seen_ids, primaries = set(), 0
    for i, item in enumerate(raw):
        ip = f"{pp}[{i}]"
        if not c.keys(ip, item, allowed=("id", "transport", "primary", "weight",
                                         "attributes"),
                      required=("id", "transport", "primary")):
            continue
        ident = c.typed(ip, item, "id", str, "")
        if ident in seen_ids:
            c.add(f"{ip}.id", "duplicate", f"path id {ident!r} already used")
            continue
        seen_ids.add(ident)
        primary = bool(c.typed(ip, item, "primary", bool, False))
        if primary:
            primaries += 1
        weight = c.typed(ip, item, "weight", int, 1, required=False)
        if weight is None or weight < 1:
            if item.get("weight") is not None:
                c.add(f"{ip}.weight", "bad-value", "must be at least 1")
            weight = 1
        paths.append(model.PathSpecConfig(
            id=ident or "",
            transport=c.enum(f"{ip}.transport", item.get("transport"),
                             TRANSPORTS) or "",
            primary=primary,
            weight=weight,
            attributes=model.freeze_map(c.str_map(ip, item, "attributes")),
        ))

    # PLT-ICD-001 §6.1 POST-1/3
    if paths and primaries != 1:
        c.add(pp, "inconsistent",
              f"exactly one path must be primary, found {primaries}")
    if redundancy == "single" and len(paths) != 1:
        c.add(pp, "inconsistent",
              f"redundancy 'single' requires exactly one path, found {len(paths)}")
    if redundancy in ("multipath", "multihomed") and len(paths) < 2:
        c.add(pp, "inconsistent",
              f"redundancy {redundancy!r} requires at least two paths, "
              f"found {len(paths)}")

    qos = c.typed(path, node, "qos_identifier", int, 0)
    arp = c.typed(path, node, "arp_level", int, 0)
    # TS 23.501 clause 5.7.2.2, verified against Rel-17 and Rel-19.
    if arp is not None and not (qos_spec.ARP_MIN <= arp <= qos_spec.ARP_MAX):
        c.add(f"{path}.arp_level", "bad-value",
              f"must be between {qos_spec.ARP_MIN} and {qos_spec.ARP_MAX}")

    return model.BearerDecisionSpec(
        qos_identifier=qos or 0,
        arp_level=arp or 0,
        arp_preemption_capability=bool(
            c.typed(path, node, "arp_preemption_capability", bool, False)),
        arp_preemption_vulnerability=bool(
            c.typed(path, node, "arp_preemption_vulnerability", bool, False)),
        redundancy=redundancy or "",
        paths=tuple(paths),
    )


def _bearer_totality(c: _Checker, call_types: Tuple[model.CallType, ...],
                     bearer: model.Bearer) -> None:
    """PLT-PRF-006: every (call type, media) pair must reach a decision."""
    for ct in call_types:
        for media in ct.media:
            matched = any(
                r.match.call_type in ("*", ct.id) and r.match.media in ("*", media)
                for r in bearer.rules
            )
            if not matched:
                c.add("bearer.rules", "not-total",
                      f"no rule matches call type {ct.id!r} with media {media!r}")


def _interworking(c: _Checker, node: Any) -> Optional[model.Interworking]:
    if node is None:
        return None
    p = "interworking"
    if not c.keys(p, node, allowed=("system", "gateway", "routes")):
        return None
    routes: List[model.InterworkingRouteConfig] = []
    raw = node.get("routes") or []
    if not isinstance(raw, list):
        c.add(f"{p}.routes", "bad-type", f"expected a list, found {_typename(raw)}")
        raw = []
    for i, item in enumerate(raw):
        rp = f"{p}.routes[{i}]"
        if not c.keys(rp, item, allowed=("match", "gateway", "attributes"),
                      required=("match", "gateway")):
            continue
        m = item.get("match")
        prefix = ""
        if c.keys(f"{rp}.match", m, allowed=("target_prefix",),
                  required=("target_prefix",)):
            prefix = c.typed(f"{rp}.match", m, "target_prefix", str, "") or ""
        routes.append(model.InterworkingRouteConfig(
            target_prefix=prefix,
            gateway=c.typed(rp, item, "gateway", str, "") or "",
            attributes=model.freeze_map(c.str_map(rp, item, "attributes")),
        ))
    system = node.get("system")
    gateway = node.get("gateway")
    for name, value in (("system", system), ("gateway", gateway)):
        if value is not None and not isinstance(value, str):
            c.add(f"{p}.{name}", "bad-type", "expected a string or null")
    return model.Interworking(
        system=system if isinstance(system, str) else None,
        gateway=gateway if isinstance(gateway, str) else None,
        routes=tuple(routes),
    )


def _interconnection(c: _Checker, node: Any, scopes: Set[str],
                     call_types: Set[str]) -> Optional[model.Interconnection]:
    """Validate partner declarations.

    The rules here are the scope-mapping model made mechanical. Each one exists
    because its absence is a way a partner system could obtain authority in
    this system that its operator never granted.
    """
    if node is None:
        return None
    p = "interconnection"
    if not c.keys(p, node, allowed=("partners",), required=("partners",)):
        return None

    raw = node.get("partners")
    if not isinstance(raw, list) or not raw:
        c.add(f"{p}.partners", "bad-value",
              "expected a non-empty list; omit the whole block for no partners")
        return None

    partners: List[model.PartnerConfig] = []
    seen_ids, seen_prefixes = set(), set()
    for i, item in enumerate(raw):
        pp = f"{p}.partners[{i}]"
        if not c.keys(pp, item, allowed=(
                "id", "domains", "target_prefix", "gateway", "trust",
                "inbound", "outbound"),
                required=("id", "domains", "target_prefix", "gateway", "trust",
                          "inbound")):
            continue
        ident = c.typed(pp, item, "id", str, "")
        if ident in seen_ids:
            c.add(f"{pp}.id", "duplicate", f"partner {ident!r} already declared")
            continue
        seen_ids.add(ident)

        prefix = c.typed(pp, item, "target_prefix", str, "") or ""
        if not prefix:
            c.add(f"{pp}.target_prefix", "bad-value", "must be non-empty")
        elif prefix in seen_prefixes:
            c.add(f"{pp}.target_prefix", "duplicate",
                  f"prefix {prefix!r} already claimed by another partner")
        else:
            seen_prefixes.add(prefix)

        # An unauthenticated partner identity is not an identity.
        c.enum(f"{pp}.trust", item.get("trust"), TRUST_MECHANISMS)

        domains: List[str] = []
        raw_domains = item.get("domains")
        if not isinstance(raw_domains, list) or not raw_domains:
            c.add(f"{pp}.domains", "bad-value",
                  "expected a non-empty list of partner domains")
        else:
            for j, d in enumerate(raw_domains):
                if not isinstance(d, str) or not d:
                    c.add(f"{pp}.domains[{j}]", "bad-value",
                          "expected a non-empty string")
                    continue
                domains.append(d)

        inbound = _partner_inbound(c, f"{pp}.inbound", item.get("inbound"),
                                   scopes, call_types)
        outbound = item.get("outbound") or {}
        assert_label = True
        if outbound:
            if c.keys(f"{pp}.outbound", outbound, allowed=("assert_label",)):
                assert_label = bool(c.typed(f"{pp}.outbound", outbound,
                                            "assert_label", bool, True,
                                            required=False))

        partners.append(model.PartnerConfig(
            id=ident or "", domains=tuple(domains), target_prefix=prefix,
            gateway=c.typed(pp, item, "gateway", str, "") or "",
            trust=item.get("trust") if isinstance(item.get("trust"), str) else "",
            inbound_scope=inbound["scope"],
            inbound_max_level=inbound["max_level"],
            inbound_may_preempt=inbound["may_preempt"],
            inbound_allowed_call_types=inbound["allowed_call_types"],
            inbound_priority_map=inbound["priority_map"],
            outbound_assert_label=assert_label,
        ))
    return model.Interconnection(partners=tuple(partners))


def _partner_inbound(c: _Checker, path: str, node: Any, scopes: Set[str],
                     call_types: Set[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"scope": "", "max_level": 0, "may_preempt": False,
                           "allowed_call_types": (), "priority_map": ()}
    if not c.keys(path, node, allowed=(
            "scope", "max_level", "may_preempt", "allowed_call_types",
            "priority_map"),
            required=("scope", "max_level", "priority_map")):
        return out

    scope = c.typed(path, node, "scope", str, "")
    # A partner session occupies a LOCAL scope, so it is arbitrated by local
    # rules and can never introduce a scope of its own.
    c.ref(f"{path}.scope", scope, scopes, "pre-emption scope")
    out["scope"] = scope or ""

    max_level = c.typed(path, node, "max_level", int, 0)
    if max_level is None or max_level < 0:
        c.add(f"{path}.max_level", "bad-value", "must not be negative")
        max_level = 0
    out["max_level"] = max_level

    # Pre-emption across a system boundary is off unless explicitly granted.
    out["may_preempt"] = bool(c.typed(path, node, "may_preempt", bool, False,
                                      required=False))

    allowed: List[str] = []
    raw_types = node.get("allowed_call_types") or []
    if not isinstance(raw_types, list):
        c.add(f"{path}.allowed_call_types", "bad-type", "expected a list")
    else:
        for j, ct in enumerate(raw_types):
            if not isinstance(ct, str):
                c.add(f"{path}.allowed_call_types[{j}]", "bad-type",
                      "expected a string")
                continue
            c.ref(f"{path}.allowed_call_types[{j}]", ct, call_types, "call type")
            allowed.append(ct)
    out["allowed_call_types"] = tuple(allowed)

    entries: List[model.PriorityMapEntry] = []
    raw_map = node.get("priority_map")
    mp = f"{path}.priority_map"
    if not isinstance(raw_map, list) or not raw_map:
        c.add(mp, "bad-value",
              "expected a non-empty list; a partner with no mapping cannot be "
              "given a local priority")
        raw_map = []
    seen_labels = set()
    for j, entry in enumerate(raw_map):
        ep = f"{mp}[{j}]"
        if not c.keys(ep, entry, allowed=("from_label", "to_level", "to_label"),
                      required=("from_label", "to_level", "to_label")):
            continue
        from_label = c.typed(ep, entry, "from_label", str, "")
        if from_label in seen_labels:
            c.add(f"{ep}.from_label", "duplicate",
                  f"{from_label!r} already mapped")
            continue
        seen_labels.add(from_label)
        to_level = c.typed(ep, entry, "to_level", int, 0)
        if to_level is None or to_level < 0:
            c.add(f"{ep}.to_level", "bad-value", "must not be negative")
            to_level = 0
        # The ceiling is the whole point: no mapping may exceed it, so a
        # partner cannot be granted more authority than the ceiling states.
        if to_level > max_level:
            c.add(f"{ep}.to_level", "inconsistent",
                  f"mapped level {to_level} exceeds the partner ceiling "
                  f"max_level {max_level}")
        entries.append(model.PriorityMapEntry(
            from_label=from_label or "", to_level=to_level,
            to_label=c.typed(ep, entry, "to_label", str, "") or ""))
    out["priority_map"] = tuple(entries)
    return out


def _admission(c: _Checker, node: Any, urgencies: Set[str]) -> model.Admission:
    p = "admission"
    if not c.keys(p, node, allowed=("max_concurrent_sessions",
                                    "reserved_for_urgency", "reject_reason_codes"),
                  required=("max_concurrent_sessions", "reject_reason_codes")):
        return model.Admission(0, model.freeze_map({}), ())

    maxc = c.typed(p, node, "max_concurrent_sessions", int, 0)
    if maxc is not None and maxc < 1:
        c.add(f"{p}.max_concurrent_sessions", "bad-value", "must be at least 1")

    reserved: Dict[str, int] = {}
    raw = node.get("reserved_for_urgency") or {}
    rp = f"{p}.reserved_for_urgency"
    if not isinstance(raw, dict):
        c.add(rp, "bad-type", f"expected a mapping, found {_typename(raw)}")
    else:
        for k, v in raw.items():
            c.ref(f"{rp}.{k}", k, urgencies, "urgency")
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                c.add(f"{rp}.{k}", "bad-value",
                      "expected a non-negative integer session count")
                continue
            reserved[k] = v
    if maxc and sum(reserved.values()) > maxc:
        c.add(rp, "inconsistent",
              f"reserved capacity {sum(reserved.values())} exceeds "
              f"max_concurrent_sessions {maxc}")

    codes: List[str] = []
    raw_codes = node.get("reject_reason_codes")
    cp = f"{p}.reject_reason_codes"
    if not isinstance(raw_codes, list) or not raw_codes:
        c.add(cp, "bad-value", "expected a non-empty list of reason codes")
    else:
        for i, code in enumerate(raw_codes):
            if not isinstance(code, str) or not code:
                c.add(f"{cp}[{i}]", "bad-value", "expected a non-empty string")
                continue
            # A profile may add codes but may not redefine core-originated ones.
            if code in CORE_ORIGINATED:
                c.add(f"{cp}[{i}]", "reserved-code",
                      f"{code!r} is originated by the core and cannot be declared "
                      "by a profile")
                continue
            codes.append(code)

    return model.Admission(
        max_concurrent_sessions=maxc or 0,
        reserved_for_urgency=model.freeze_map(reserved),
        reject_reason_codes=tuple(codes),
    )


def _media(c: _Checker, node: Any) -> model.Media:
    """PLT-MED-001: the codecs the deployment may carry. Static payload types
    (0-95) and dynamic ones (96-127) are both valid; the pair must be unique."""
    p = "media"
    if not c.keys(p, node, allowed=("codecs",), required=("codecs",)):
        return model.Media(())
    raw = node.get("codecs")
    cp = f"{p}.codecs"
    if not isinstance(raw, list) or not raw:
        c.add(cp, "bad-value", "expected a non-empty list of codecs")
        return model.Media(())
    out: List[model.Codec] = []
    seen: Set[int] = set()
    for i, item in enumerate(raw):
        ip = f"{cp}[{i}]"
        if not c.keys(ip, item, allowed=("payload_type", "name"),
                      required=("payload_type", "name")):
            continue
        pt = c.typed(ip, item, "payload_type", int)
        name = c.typed(ip, item, "name", str)
        if pt is None or name is None:
            continue
        if not 0 <= pt <= 127:
            c.add(f"{ip}.payload_type", "bad-value", "must be in 0..127")
            continue
        if not name.strip() or any(ch in name for ch in " \r\n"):
            c.add(f"{ip}.name", "bad-value",
                  "must be a non-empty rtpmap value with no whitespace")
            continue
        if pt in seen:
            c.add(f"{ip}.payload_type", "duplicate", f"payload type {pt} repeated")
            continue
        seen.add(pt)
        out.append(model.Codec(pt, name))
    return model.Media(tuple(out))
