"""Profile loading: read, validate, freeze, hash, resolve hooks.

Startup sequence (PLT-SRS §5.1, PLT-VP-R1 §3):

  1. determine the configured profile(s)          PLT-GEN-002..005
  2. read and canonicalise the package             PLT-PRF-011
  3. validate strictly                             PLT-PRF-002..006
  4. resolve and verify the five hooks             PLT-PRF-012, PLT-PRF-013
  5. freeze                                        PLT-PRF-009
  6. log name, version, content hash               PLT-OAM-001

Any failure at any step prevents start (PLT-PRF-007). Nothing is initialised
and no listening socket is opened before this sequence completes.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import yaml

from . import hooks as hook_ifaces
from . import model, validation
from .errors import ProfileLoadError, ProfileValidationError, StartupRefused

log = logging.getLogger("mcx.loader")

PROFILE_FILENAME = "profile.yaml"

# Hook field -> (Protocol, required method names)
HOOK_INTERFACES: Mapping[str, Tuple[type, Tuple[str, ...]]] = {
    "identity_resolver": (hook_ifaces.IdentityResolver,
                          ("resolve", "bind", "unbind", "identities_of")),
    "priority_policy": (hook_ifaces.PriorityPolicy, ("evaluate", "compare")),
    "session_policy": (hook_ifaces.SessionPolicy,
                       ("admit", "decide", "floor_policy")),
    "bearer_selector": (hook_ifaces.BearerSelector, ("select", "on_path_event")),
    "interworking_gateway": (hook_ifaces.InterworkingGateway,
                             ("route", "map_inbound")),
    "interconnection_gateway": (hook_ifaces.InterconnectionGateway,
                                ("route", "rights", "map_inbound_priority",
                                 "map_outbound")),
}


# --------------------------------------------------------------------------
# Environment predicates
#
# OPEN (VP-OP-05): PLT-GEN-005, PLT-IDM-007 and PLT-SEC-008 all turn on a
# "production indicator" that PLT-SRS does not define. The definition below is
# this implementation's proposal and requires confirmation before baselining.
# --------------------------------------------------------------------------

PRODUCTION_ENV_VALUES = ("production", "prod")


def is_production(env: Optional[Mapping[str, str]] = None) -> bool:
    e = os.environ if env is None else env
    if (e.get("MCX_ENV") or "").strip().lower() in PRODUCTION_ENV_VALUES:
        return True
    return (e.get("MCX_PRODUCTION") or "").strip().lower() in ("1", "true", "yes")


def is_test_mode(env: Optional[Mapping[str, str]] = None) -> bool:
    e = os.environ if env is None else env
    return (e.get("MCX_TEST_MODE") or "").strip().lower() in ("1", "true", "yes")


# --------------------------------------------------------------------------
# Canonicalisation and hashing
# --------------------------------------------------------------------------


def canonicalise(raw: Any) -> str:
    """Stable textual form of a parsed profile, independent of key order,
    whitespace and comments (PLT-PRF-011, VP1-LOAD-041)."""
    return json.dumps(raw, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def content_hash(raw: Any) -> str:
    return hashlib.sha256(canonicalise(raw).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Hook resolution
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LoadedHooks:
    identity_resolver: Any
    priority_policy: Any
    session_policy: Any
    bearer_selector: Any
    interworking_gateway: Any
    interconnection_gateway: Any


def _import_symbol(spec: str) -> Any:
    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        raise ProfileLoadError(
            f"hook specification {spec!r} is not of the form 'module.path:ClassName'")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ProfileLoadError(
            f"hook module {module_name!r} could not be imported: {exc}") from exc
    try:
        return getattr(module, attr)
    except AttributeError as exc:
        raise ProfileLoadError(
            f"hook module {module_name!r} has no attribute {attr!r}") from exc


def _verify_interface(field: str, obj: Any) -> List[str]:
    """PLT-PRF-013: verify the object implements its declared interface.

    `runtime_checkable` only checks method presence, so signatures are checked
    explicitly: a hook with the right method names and the wrong arity fails at
    the first session otherwise.
    """
    proto, required = HOOK_INTERFACES[field]
    problems: List[str] = []
    for name in required:
        member = getattr(obj, name, None)
        if member is None:
            problems.append(f"missing method {name!r}")
            continue
        if not callable(member):
            problems.append(f"attribute {name!r} is not callable")
            continue
        expected = getattr(proto, name, None)
        if expected is None:
            continue
        try:
            got = inspect.signature(member)
            want = inspect.signature(expected)
        except (TypeError, ValueError):
            continue
        want_params = [p for n, p in want.parameters.items() if n != "self"]
        got_params = [p for n, p in got.parameters.items() if n != "self"]
        if len(got_params) != len(want_params):
            problems.append(
                f"method {name!r} takes {len(got_params)} parameter(s), "
                f"expected {len(want_params)}")
    return problems


def resolve_hooks(profile: model.Profile) -> LoadedHooks:
    """Import, instantiate and verify all five hooks. No default is ever
    substituted for a missing or non-conformant hook (PLT-PRF-012)."""
    resolved: Dict[str, Any] = {}
    failures: List[str] = []
    for field in validation.HOOK_FIELDS:
        spec = getattr(profile.hooks, field)
        try:
            symbol = _import_symbol(spec)
        except ProfileLoadError as exc:
            failures.append(f"profile.hooks.{field}: {exc}")
            continue
        try:
            instance = symbol(profile) if inspect.isclass(symbol) else symbol
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            failures.append(
                f"profile.hooks.{field}: {spec} could not be instantiated: {exc}")
            continue
        problems = _verify_interface(field, instance)
        if problems:
            failures.append(
                f"profile.hooks.{field}: {spec} does not implement its interface "
                f"({'; '.join(problems)})")
            continue
        resolved[field] = instance
    if failures:
        raise ProfileLoadError("hook resolution failed:\n  " + "\n  ".join(failures))
    return LoadedHooks(**resolved)


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LoadedProfile:
    profile: model.Profile
    hooks: LoadedHooks
    source: Path


def read_package(directory: Path) -> Any:
    path = directory / PROFILE_FILENAME
    if not path.is_file():
        raise ProfileLoadError(
            f"profile package {str(directory)!r} contains no {PROFILE_FILENAME}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ProfileLoadError(f"{path}: not well-formed YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ProfileLoadError(f"{path}: expected a mapping at the document root")
    return raw


def load(directory: Path, *, resolve: bool = True) -> LoadedProfile:
    """Read, validate, freeze and resolve one profile package."""
    raw = read_package(directory)
    profile = validation.build(raw, content_hash(raw))
    hooks = resolve_hooks(profile) if resolve else LoadedHooks(*(None,) * 6)
    return LoadedProfile(profile=profile, hooks=hooks, source=directory)


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------


def startup(profile_names: Sequence[str], profiles_root: Path,
            env: Optional[Mapping[str, str]] = None) -> LoadedProfile:
    """Enforce the startup rules and return the single loaded profile.

    PLT-GEN-003: no profile, an absent profile, or more than one profile all
    refuse start. PLT-GEN-005: more than one loads only in test mode, which is
    itself refused when a production indicator is set.
    """
    names = [n for n in (s.strip() for s in profile_names) if n]

    if not names:
        raise StartupRefused(
            "no profile configured: exactly one profile must be named at "
            "deployment; the platform provides no default")

    if len(names) > 1:
        if not is_test_mode(env):
            raise StartupRefused(
                f"{len(names)} profiles configured ({', '.join(names)}): exactly "
                "one is permitted outside test mode")
        if is_production(env):
            raise StartupRefused(
                "test mode requested while a production indicator is set; "
                "multi-profile loading is refused")

    loaded = [_load_named(n, profiles_root) for n in names]

    for lp in loaded:
        log.info("profile loaded: name=%s version=%s hash=%s source=%s",
                 lp.profile.name, lp.profile.version,
                 lp.profile.content_hash, lp.source)

    return loaded[0]


def startup_all(profile_names: Sequence[str], profiles_root: Path,
                env: Optional[Mapping[str, str]] = None) -> Tuple[LoadedProfile, ...]:
    """Test-mode variant returning every loaded profile (VP1-LOAD-006).

    Not reachable in a production deployment: `startup` enforces the single
    profile rule, and this function applies the same gate before loading.
    """
    startup(profile_names, profiles_root, env)
    return tuple(_load_named(n, profiles_root) for n in profile_names if n.strip())


def _load_named(name: str, profiles_root: Path) -> LoadedProfile:
    directory = profiles_root / name
    if not directory.is_dir():
        raise StartupRefused(
            f"configured profile {name!r} not found: no package at {directory}")
    try:
        return load(directory)
    except ProfileValidationError as exc:
        raise StartupRefused(f"profile {name!r} is invalid.\n{exc}") from exc
    except ProfileLoadError as exc:
        raise StartupRefused(f"profile {name!r} could not be loaded: {exc}") from exc
