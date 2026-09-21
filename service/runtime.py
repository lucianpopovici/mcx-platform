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

from .config import IDMS_STUB, Config
from .groups import GroupDirectory, load_groups
from .store import SessionStore, SqliteStore

log = logging.getLogger("mcx.service")

SignalHandler = Callable[[Session, Tuple[Signal, ...]], None]


def fail_closed_platform() -> Platform:
    """The platform a process with no recorder and no network has.

    Deliberately NOT `Platform()`, whose permissive defaults exist for tests.
    A session requiring recording refuses (PLT-OAM-008); a QoS reservation is
    refused because nothing exists yet to grant one (tasks 2 and 3).
    """
    return Platform(recording_available=lambda: False,
                    reserve_qos=lambda decision: False,
                    active_sessions=lambda: 0)


class Health:
    """Liveness and readiness (PLT-OAM-007). Not ready until told otherwise."""

    def __init__(self) -> None:
        self._ready = False
        self._profile: Optional[str] = None
        self._name = self._version = self._hash = None
        self._lock = threading.Lock()

    def set_profile(self, loaded: LoadedProfile) -> None:
        p = loaded.profile
        with self._lock:
            self._name, self._version = p.name, p.version
            self._hash, self._profile = p.content_hash, p.identifier()

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
                                "identifier": self._profile}}


@dataclass
class Runtime:
    config: Config
    loaded: LoadedProfile
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

    health = Health()
    health.set_profile(loaded)
    identifier = loaded.profile.identifier()
    log.info("profile loaded: %s", identifier)

    store = store or SqliteStore(config.data_dir)
    recovered = sum(1 for s in store.sessions() if s.get("state") == "established")
    auditor = Auditor(store, identifier, clock=clock)
    manager = SessionManager(loaded, auditor,
                             platform=platform or fail_closed_platform(),
                             clock=clock)

    groups = GroupDirectory(load_groups(config.groups_file))
    # Provision the resolver from the same source the documents are served
    # from, so the two cannot disagree. register_group is not part of IF-IDR;
    # a resolver without it simply has no provisioning surface.
    register = getattr(loaded.hooks.identity_resolver, "register_group", None)
    if register is not None:
        for g in groups.all():
            register(g.id, g.members)
    elif groups.all():
        raise StartupRefused(
            "groups are configured but the profile's identity resolver has no "
            "provisioning surface to receive them")

    if recovered:
        log.warning("%d session record(s) were established when the previous "
                    "process stopped; their signalling state is not recovered "
                    "(SVC-OP-02)", recovered)
    return Runtime(config=config, loaded=loaded, store=store, auditor=auditor,
                   manager=manager, groups=groups, health=health, clock=clock,
                   recovered=recovered)
