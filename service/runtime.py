"""Wiring: profile -> hooks -> auditor -> session manager -> store.

`build_runtime` is the only place these are assembled. It calls
`loader.startup` first and touches nothing else until that returns, so a
refusal leaves no store opened and no socket bound.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional, Sequence, Tuple

from core import loader
from core.audit import Auditor
from core.errors import StartupRefused
from core.hooks import SessionRequest
from core.loader import LoadedProfile
from core.session import (Platform, Refusal, Session, SessionManager, Signal)

from core import mcinfo

from .config import BEARER_STUB, IDMS_STUB, RECORDER_STUB, Config
from .network import Network, load_network
from .groups import GroupDirectory, load_groups, load_users
from .store import SessionStore, SqliteStore

log = logging.getLogger("mcx.service")

SignalHandler = Callable[[Session, Tuple[Signal, ...]], None]


def fail_closed_platform(recording: bool = False,
                         bearer: bool = False) -> Platform:
    """The platform this process actually has.

    Deliberately NOT `Platform()`, whose permissive defaults exist for tests.
    A QoS reservation is refused because nothing exists yet to grant one.

    `recording` comes from MCX_RECORDER and nowhere else. It defaulted to
    False with no way to change it, and because every call type in every
    in-tree profile sets `recording_required: true`, the shipped process
    refused every call with `recording-unavailable` (PLT-OAM-008 firing on
    every session rather than on a real outage). The suite did not catch it:
    its end-to-end tests pass `platform=Platform()`, so they exercised a
    capability set the process never builds for itself. Found by running
    VP1-SIG-001 against Kamailio.

    MCX_RECORDER=stub says a recorder exists without one existing, which is
    what an interoperability run and an integration environment need. It is
    refused under a production indicator, exactly as the stub IdMS is.
    """
    return Platform(recording_available=lambda: recording,
                    reserve_qos=lambda decision: bearer,
                    active_sessions=lambda: 0)


class Health:
    """Liveness and readiness (PLT-OAM-007). Not ready until told otherwise."""

    def __init__(self) -> None:
        self._ready = False
        self._profile: Optional[str] = None
        self._name = self._version = self._hash = None
        self._release: Optional[str] = None
        self._network: Optional[dict] = None
        self._lock = threading.Lock()
        self._extra: Callable[[], dict] = lambda: {}
        self._call_types: dict = {}

    def set_call_types(self, report: dict) -> None:
        with self._lock:
            self._call_types = report

    def set_extra(self, fn: Callable[[], dict]) -> None:
        self._extra = fn

    def set_profile(self, loaded: LoadedProfile) -> None:
        p = loaded.profile
        with self._lock:
            self._name, self._version = p.name, p.version
            self._hash, self._profile = p.content_hash, p.identifier()

    def set_network(self, network: Network) -> None:
        with self._lock:
            self._network = {"name": network.name, "version": network.version,
                             "hash": network.content_hash,
                             "identifier": network.identifier()}

    def set_release(self, release) -> None:
        """PLT-REL-001. An operator looking at a running instance must be able
        to see which release it speaks without reading its configuration."""
        with self._lock:
            self._release = str(release)

    def set_ready(self, ready: bool) -> None:
        with self._lock:
            self._ready = ready

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._ready and self._profile is not None

    def snapshot(self) -> dict:
        with self._lock:
            return {"live": True,
                    "ready": self._ready and self._profile is not None,
                    "profile": {"name": self._name, "version": self._version,
                                "hash": self._hash,
                                "identifier": self._profile},
                    "release": self._release,
                    "network": self._network,
                    "call_types": self._call_types,
                    **self._extra()}


@dataclass
class Runtime:
    config: Config
    loaded: LoadedProfile
    network: Network
    store: SessionStore
    auditor: Auditor
    manager: SessionManager
    groups: GroupDirectory
    health: Health
    clock: Callable[[], int]
    on_signals: SignalHandler = field(default=lambda session, signals: None)
    recovered: int = 0

    # -- session operations, with persistence -----------------------------

    def establish(self, request: SessionRequest
                  ) -> Tuple[Optional[Session], Tuple[Signal, ...], Optional[Refusal]]:
        session, signals, refusal = self.manager.establish(request)
        if session is not None:
            self._persist(session)
            self.on_signals(session, signals)
        return session, signals, refusal

    def release(self, correlation_id: str, cause: str = "normal"
                ) -> Tuple[Signal, ...]:
        session = self.manager.session(correlation_id)
        signals = self.manager.release(correlation_id, cause)
        if session is not None and signals:
            self.store.mark_released(correlation_id, self.clock())
            self.on_signals(session, signals)
        return signals

    def abandon(self, correlation_id: str, reason: str) -> None:
        """Remove a session that never became live, from memory AND the store
        (PLT-SIG-005). Only the audit record of what happened remains."""
        signals = self.manager.abandon(correlation_id, reason)
        self.store.discard_session(correlation_id)
        if signals:
            log.info("abandoned session %s: %s", correlation_id, reason)

    def _persist(self, s: Session) -> None:
        self.store.save_session(
            s.correlation_id, s.state.value, self.loaded.profile.identifier(),
            self.clock(),
            {"initiator": s.request.initiator, "target": s.request.target,
             "call_type": s.request.call_type, "members": list(s.members),
             "priority": s.priority.label, "scope": s.priority.scope,
             "gateway": s.gateway, "partner_id": s.partner_id})

    def close(self) -> None:
        self.health.set_ready(False)
        self.store.close()


def role_functions(config: Config) -> Mapping[str, str]:
    """Which function hosts which role, for the audit record (VP1-CC-001)."""
    if config.sip is None:
        return {}
    out = {"controlling_function": config.sip.uri}
    if "participating" in config.sip.roles:
        out["participating_function"] = config.sip.uri
    return out


def _network(config: Config, loaded: LoadedProfile) -> Network:
    """NET-OP-01: the network profile, checked against the service profile
    (every cell's attributes must be location keys some identity reads) and,
    when SIP is enabled, against the users' trust anchor (ICD-OP-10)."""
    keys = {f.location_key for f in loaded.profile.identity.functional
            if f.location_key}
    return load_network(config.network, keys,
                        config.sip.ca if config.sip is not None else None)


def build_runtime(env: Mapping[str, str], clock: Callable[[], int],
                  platform: Optional[Platform] = None,
                  store: Optional[SessionStore] = None) -> Runtime:
    config = Config.from_env(env)

    # 1. The whole startup contract lives in the loader. Nothing below runs if
    #    it refuses.
    loaded = loader.startup(config.profile_names, config.profiles_root, env)

    # 2. PLT-IDM-007: the stub identity provider is refused under any
    #    production indicator. (VP-OP-05: the indicator is still a proposal.)
    if config.idms == IDMS_STUB and loader.is_production(env):
        raise StartupRefused(
            "the stub identity provider is refused when a production "
            "indicator is set (PLT-IDM-007)")

    # Same rule, same reason: a stub recorder claims a capability the process
    # does not have, and PLT-OAM-008 exists so that a session which must be
    # recorded is not established when it cannot be.
    if config.recorder == RECORDER_STUB and loader.is_production(env):
        raise StartupRefused(
            "the stub recorder is refused when a production indicator is set "
            "(PLT-OAM-008): it reports recording available with no recorder")

    if config.bearer == BEARER_STUB and loader.is_production(env):
        raise StartupRefused(
            "the stub bearer reservation is refused when a production "
            "indicator is set: it grants a reservation the network never made")

    health = Health()
    health.set_profile(loaded)
    health.set_release(config.release)
    # PLT-REL-005: the release joins the profile in the audit identity. When
    # someone asks months later why this deployment put subtype 14 on the
    # wire, "which release was it speaking" has to be answerable from the
    # record, not from whoever remembers the deployment.
    #
    # NET-OP-01: and so does the network profile. Which cells meant which
    # track section, and which cores could assert any identity, are facts of
    # the day a call was made, not of the day someone asks.
    network = _network(config, loaded)
    health.set_network(network)
    identifier = (f"{loaded.profile.identifier()}+{config.release}"
                  f"+{network.identifier()}")
    log.info("profile loaded: %s (3GPP %s) on network %s",
             loaded.profile.identifier(), config.release, network.identifier())

    store = store or SqliteStore(config.data_dir)
    recovered = sum(1 for s in store.sessions() if s.get("state") == "established")
    auditor = Auditor(store, identifier, clock=clock)
    manager = SessionManager(loaded, auditor,
                             platform=platform or fail_closed_platform(
                                 config.recorder == RECORDER_STUB,
                                 config.bearer == BEARER_STUB),
                             clock=clock, functions=role_functions(config),
                             defer_floor_start=config.sip is not None,
                             adhoc_list_max=config.adhoc_list_max,
                             cells=network.cells)

    groups = GroupDirectory(load_groups(config.groups_file),
                            load_users(config.groups_file))
    # Provision the resolver from the same source the documents are served
    # from, so the two cannot disagree. register_group is not part of IF-IDR;
    # a resolver without it simply has no provisioning surface.
    register = getattr(loaded.hooks.identity_resolver, "register_group", None)
    register_user = getattr(loaded.hooks.identity_resolver, "register_user", None)
    if register is not None and register_user is not None:
        for u in groups.users():
            register_user(u)
        for g in groups.all():
            register(g.id, g.members)
    elif groups.all():
        raise StartupRefused(
            "groups are configured but the profile's identity resolver has no "
            "provisioning surface to receive them")

    # PLT-ICD-001 2.6: say which call types no conformant client can request,
    # and why, rather than leave an operator to discover it from refusals.
    undeclared, blocked = mcinfo.reachability(loaded.profile.call_types,
                                              config.release)
    # REL-OP-02: MCX_STRICT_RELEASE decides whether that is fatal.
    if blocked and config.strict_release:
        raise StartupRefused(
            f"MCX_STRICT_RELEASE=true and profile {loaded.profile.identifier()} "
            f"declares call types {config.release} cannot carry: "
            + "; ".join(f"{cid} ({why})" for cid, why in blocked)
            + ". Raise MCX_RELEASE, or set MCX_STRICT_RELEASE=false to start "
            "without them")
    health.set_call_types({
        "strict_release": config.strict_release,
        "not_requestable_by_mcptt_clients": list(undeclared),
        "unreachable_at_release": {cid: why for cid, why in blocked}})
    for cid, why in blocked:
        log.warning("call type %r cannot be requested by any client at this "
                    "release: %s (MCX_STRICT_RELEASE=false)", cid, why)

    if recovered:
        log.warning("%d session record(s) were established when the previous "
                    "process stopped; their signalling state is not recovered "
                    "(SVC-OP-02)", recovered)
    return Runtime(config=config, loaded=loaded, network=network,
                   store=store, auditor=auditor,
                   manager=manager, groups=groups, health=health, clock=clock,
                   recovered=recovered)
