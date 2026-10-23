"""Wiring: profile -> hooks -> auditor -> session manager -> store.

`build_runtime` is the only place these are assembled. It calls
`loader.startup` first and touches nothing else until that returns, so a
refusal leaves no store opened and no socket bound.
"""

from __future__ import annotations

import dataclasses

import logging
import ssl
import threading
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional, Sequence, Tuple

from core import loader
from core.functional import Holding
from core.release import supports_procedure
from core.audit import Auditor, RecordType
from core.errors import StartupRefused
from core.hooks import SessionRequest
from core.loader import LoadedProfile
from core.session import (Platform, Refusal, Session, SessionManager, Signal)

from core import mcinfo

from .config import BEARER_STUB, IDMS_STUB, RECORDER_STUB, Config
from .http_tls import make_context as make_http_context
from .network import Network, load_network
from .groups import GroupDirectory
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
        self._holdings: Callable[[], list] = lambda: []
        self._call_types: dict = {}
        self._settings: dict = {}
        self._deviations: list = []
        self._warnings: list = []
        self._audit: Callable[[], dict] = lambda: {}

    def set_audit(self, fn: Callable[[], dict]) -> None:
        self._audit = fn

    def set_deviations(self, settings: dict, deviations: list) -> None:
        with self._lock:
            self._settings, self._deviations = settings, deviations

    def set_warnings(self, warnings: list) -> None:
        with self._lock:
            self._warnings = warnings

    def set_call_types(self, report: dict) -> None:
        with self._lock:
            self._call_types = report

    def set_extra(self, fn: Callable[[], dict]) -> None:
        self._extra = fn

    def set_holdings(self, fn: Callable[[], list]) -> None:
        """SVC-OP-06: who holds which functional identity, read live."""
        self._holdings = fn

    def set_profile(self, loaded: LoadedProfile) -> None:
        p = loaded.profile
        with self._lock:
            self._name, self._version = p.name, p.version
            self._hash, self._profile = p.content_hash, p.identifier()

    def set_network(self, network: Network) -> None:
        with self._lock:
            self._network = {"name": network.name, "version": network.version,
                             "hash": network.content_hash,
                             "identifier": network.identifier(),
                             "environment": network.environment}

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
                    # VP-OP-05: the production indicator, at a glance.
                    "environment": (self._network or {}).get("environment"),
                    "network": self._network,
                    "call_types": self._call_types,
                    "functional_aliases": self._holdings(),
                    "settings": self._settings,
                    "deviations": self._deviations,
                    "warnings": self._warnings,
                    "audit": self._audit(),
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
    # RES-OP-05: the checked HTTPS context, or None for MCX_HTTP_TLS=off.
    http_context: Optional[ssl.SSLContext] = None

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
            # The BYEs go first: a store that cannot record the release must
            # not keep the other parties' legs up (RES-OP-03 review). A row
            # left 'established' is logged, and is RES-OP-14's to settle.
            self.on_signals(session, signals)
            try:
                self.store.mark_released(correlation_id, self.clock())
            except Exception:                              # noqa: BLE001
                log.exception("session %s: released, but its store row was not "
                              "marked released", correlation_id,
                              extra={"correlation_id": correlation_id})
        return signals

    def abandon(self, correlation_id: str, reason: str) -> None:
        """Remove a session that never became live, from memory AND the store
        (PLT-SIG-005). Only the audit record of what happened remains."""
        signals = self.manager.abandon(correlation_id, reason)
        self.store.discard_session(correlation_id)
        if signals:
            log.info("abandoned session %s: %s", correlation_id, reason,
                     extra={"correlation_id": correlation_id})

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
        # RES-OP-14: a gap still pending reaches the trail before the store
        # closes, or, if the store still fails, the log in full.
        if not self.auditor.try_flush(force=True):
            log.error("audit gap not written before shutdown: %s",
                      self.auditor.pending_gap())
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
                        config.sip.ca if config.sip is not None else None,
                        loaded.profile.call_types, loaded.profile.identity.functional)


STARTUP_CORRELATION_ID = "process-start"


def behaviour_settings(config: Config, loaded: LoadedProfile) -> Tuple[dict, list]:
    """(settings, deviations): every decision that is a setting rather than
    fixed behaviour (owner ruling 2026-10-16), as this deployment states it,
    and each one whose value departs from the standard the original decision
    followed, with that standard. Profile settings are listed where they take
    effect: a pre-emptor's place only where the call type both queues and
    allows override."""
    settings: dict = {"MCX_HTTP_TLS": "off" if config.http_tls is None else "on",
                      "MCX_FLOOR_UNRECORDED": config.floor_unrecorded,
                      "MCX_FOREIGN_INITIATOR": config.foreign_initiator}
    if config.http_tls is not None:
        settings["MCX_HTTP_CLIENT_AUTH"] = config.http_tls.client_auth
    deviations: list = []
    if config.foreign_initiator == "allow":
        deviations.append({
            "setting": "MCX_FOREIGN_INITIATOR", "value": "allow", "ref": "RES-OP-11",
            "departs_from": "PLT-SRS PLT-IDM-008 (no identity outside the declared "
                            "domains); TS 24.379 10.1.1.3.1.1 step 2a (404, warning 141)",
            "consequence": "a caller outside the profile's declared domains, as a "
                           "trusted SIP core may assert, is served, including a "
                           "partner system's users, whose priority is then not capped "
                           "by its interconnection rules (there is no inbound IF-ICX "
                           "path); such a caller still cannot register here"})
    if config.floor_unrecorded == "allow":
        deviations.append({
            "setting": "MCX_FLOOR_UNRECORDED", "value": "allow", "ref": "RES-OP-14",
            "departs_from": "PLT-SRS PLT-FC-011 (every floor transition recorded); "
                            "PLT-ICD-001 ICD-GEN-040/041 (the IF-PRI evaluation of a "
                            "floor request)",
            "consequence": "while the audit store fails the floor runs unrecorded; "
                           "the records lost are counted and written as one "
                           "audit-gap record ahead of the next record the store "
                           "takes, or logged in full at shutdown if it never does"})
    if config.http_tls is None:
        deviations.append({
            "setting": "MCX_HTTP_TLS", "value": "off", "ref": "RES-OP-05",
            "departs_from": "PLT-SRS 3.1 HTTP-1 (HTTPS)",
            "consequence": "health and group documents in clear text, unauthenticated"})
    if config.sip is not None:
        sip = config.sip
        settings.update({"MCX_SERVICE_REFUSAL_STATUS": sip.service_refusal_status,
                         "MCX_DIALOG_TAKEOVER": sip.dialog_takeover,
                         "MCX_LOCATION_REPORTS": sip.location_reports})
        if sip.service_refusal_status != 503:
            deviations.append({
                "setting": "MCX_SERVICE_REFUSAL_STATUS",
                "value": sip.service_refusal_status, "ref": "SIP-OP-10",
                "departs_from": "RFC 3261 21.5.4 (503 for a server that cannot "
                                "take the call)",
                "consequence": "capacity and other service refusals say the callee "
                               "is temporarily unavailable, and a client or proxy "
                               "with another server does not fail over to it, as "
                               "it would on 503 (RFC 3263)"})
        located = sorted(f.id for f in loaded.profile.identity.functional
                         if f.location_dependent)
        if sip.location_reports == "ignore" and located:
            deviations.append({
                "setting": "MCX_LOCATION_REPORTS", "value": "ignore",
                "ref": "ADHOC-OP-03",
                "departs_from": "TS 24.379 17.2.2.1.1 item 14a (the client's "
                                "location report)",
                "consequence": "calls to " + ", ".join(located)
                               + " are refused no-location-binding, and ad hoc "
                               "criteria naming them contribute no one (warning "
                               "187 if nothing else matches)"})
    floor, over = {}, {}
    for ct in loaded.profile.call_types:
        f = ct.floor
        over[ct.id] = ct.group_over_limit
        if f.queueing_enabled and f.override_allowed:
            floor[ct.id] = f.preemption_at_full_queue
            if f.preemption_at_full_queue == "deny":
                deviations.append({
                    "setting": f"call_types[{ct.id}].floor.preemption_at_full_queue",
                    "value": "deny", "ref": "FC-OP-07",
                    "departs_from": "TS 24.380 6.3.4.4.7 item 2e",
                    "consequence": "a pre-emptor meeting a full queue is denied "
                                   "queue-full and the talker keeps the floor"})
        sig = ct.mc_signature
        # Only a group call is truncated or refused by this setting: a private
        # call or an ad hoc call over its limit is refused whatever it says.
        if ct.group_over_limit == "refuse" and not (
                sig is not None and sig.session_type in ("private", "adhoc")):
            deviations.append({
                "setting": f"call_types[{ct.id}].group_over_limit",
                "value": "refuse", "ref": "RES-OP-12",
                "departs_from": "TS 24.379 6.3.5.5 and 10.1.1.4.1",
                "consequence": "a group call over its participant limit is refused "
                               "486 + 122 instead of truncated"})
    settings["preemption_at_full_queue"] = floor
    settings["group_over_limit"] = over
    return settings, deviations


def setting_warnings(config: Config, loaded: LoadedProfile) -> list:
    """A duration stated both in milliseconds and in seconds, with values
    that disagree (PLT-GEN-011 as amended 2026-10-18): the milliseconds are
    used, and the disagreement is reported in the log, the health document
    and the startup audit record."""
    warnings: list = []
    sip = config.sip
    if sip is not None and sip.session_expires_s is not None and \
            sip.session_expires_ms != sip.session_expires_s * 1000:
        warnings.append({
            "setting": "MCX_SESSION_EXPIRES_MS",
            "message": f"MCX_SESSION_EXPIRES={sip.session_expires_s} s "
                       f"({sip.session_expires_s * 1000} ms) and "
                       f"MCX_SESSION_EXPIRES_MS={sip.session_expires_ms} disagree; "
                       f"MCX_SESSION_EXPIRES_MS={sip.session_expires_ms} is used"})
    for ct in loaded.profile.call_types:
        if ct.no_answer_s is not None and ct.no_answer_ms != ct.no_answer_s * 1000:
            warnings.append({
                "setting": f"call_types[{ct.id}].no_answer_ms",
                "message": f"call_types[{ct.id}]: no_answer_s={ct.no_answer_s} s "
                           f"({ct.no_answer_s * 1000} ms) and "
                           f"no_answer_ms={ct.no_answer_ms} disagree; "
                           f"no_answer_ms={ct.no_answer_ms} is used"})
        for name, s in sorted(ct.floor.timers_s.items()):
            ms = ct.floor.timers_ms[name]
            if ms != s * 1000:
                warnings.append({
                    "setting": f"call_types[{ct.id}].floor.timers_ms.{name}",
                    "message": f"call_types[{ct.id}].floor: timers_s.{name}={s} s "
                               f"({s * 1000} ms) and "
                               f"timers_ms.{name}={ms} disagree; timers_ms.{name}={ms} "
                               "is used"})
    return warnings


def build_runtime(env: Mapping[str, str], clock: Callable[[], int],
                  platform: Optional[Platform] = None,
                  store: Optional[SessionStore] = None) -> Runtime:
    config = Config.from_env(env)

    # 1. The whole startup contract lives in the loader. Nothing below runs if
    #    it refuses.
    loaded = loader.startup(config.profile_names, config.profiles_root, env)

    # 2. VP-OP-05 (decided 2026-10-21): the environment is the network
    #    profile's, MCX_ENV must agree with it, and it is the production
    #    indicator for everything below. The network is read here, before
    #    the stubs are judged, so the file decides and not the variable.
    network = _network(config, loaded)
    if network.environment != config.environment:
        raise StartupRefused(
            f"MCX_ENV={config.environment!r} disagrees with the network profile's "
            f"environment {network.environment!r} ({config.network}); the "
            "environment is declared with the network and the variable must "
            "say the same (PLT-VP-R1 VP-OP-05)")
    production = network.environment == loader.PRODUCTION

    # 3. PLT-IDM-007: the stub identity provider is refused under the
    #    production indicator.
    if config.idms == IDMS_STUB and production:
        raise StartupRefused(
            "the stub identity provider is refused when a production "
            "indicator is set (PLT-IDM-007)")

    # Same rule, same reason: a stub recorder claims a capability the process
    # does not have, and PLT-OAM-008 exists so that a session which must be
    # recorded is not established when it cannot be.
    if config.recorder == RECORDER_STUB and production:
        raise StartupRefused(
            "the stub recorder is refused when a production indicator is set "
            "(PLT-OAM-008): it reports recording available with no recorder")

    if config.bearer == BEARER_STUB and production:
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
    # VP-OP-05: and the environment, so a deployment switched out of
    # production shows on every record it writes, not only in its files.
    health.set_network(network)
    identifier = (f"{loaded.profile.identifier()}+{config.release}"
                  f"+{network.identifier()}+{network.environment}")
    log.info("profile loaded: %s (3GPP %s) on network %s, environment %s",
             loaded.profile.identifier(), config.release, network.identifier(),
             network.environment)

    # RES-OP-05: the HTTPS context, built here so that a certificate that
    # cannot be loaded refuses startup before anything is opened, and the
    # listener uses the material that was checked.
    http_context = make_http_context(config.http_tls) if config.http_tls else None

    own_store = store is None
    store = store or SqliteStore(config.data_dir)
    try:
        recovered = sum(1 for s in store.sessions() if s.get("state") == "established")
        auditor = Auditor(store, identifier, clock=clock)
        manager = SessionManager(loaded, auditor,
                                 platform=platform or fail_closed_platform(
                                     config.recorder == RECORDER_STUB,
                                     config.bearer == BEARER_STUB),
                                 clock=clock, functions=role_functions(config),
                                 defer_floor_start=config.sip is not None,
                                 adhoc_list_max=config.adhoc_list_max,
                                 cells=network.cells,
                                 floor_unrecorded=config.floor_unrecorded,
                                 foreign_initiator=config.foreign_initiator,
                                 functional_aliases=network.functional_aliases)

        groups = GroupDirectory(network.groups, network.users)
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

        # SVC-OP-06: the functional identity holders kept across a restart,
        # bound again where the network profile in force still allows them.
        # A release without functional alias activation binds none and
        # leaves the store as it is, so a release set wrongly loses nothing.
        if supports_procedure(config.release, "functional-alias"):
            kept = manager.restore_functional_aliases(
                [Holding(*h) for h in store.holdings()], STARTUP_CORRELATION_ID)
            store.save_holdings([(h.identity, h.slot, h.holder) for h in kept])
        health.set_holdings(lambda: [dataclasses.asdict(h)
                                     for h in manager.functional.holdings()])

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
        # PRF-OP-01: a group-selected call type is reached through the groups
        # that name it; one that no group names is reachable by no client.
        by_group = {cid: [g.id for g in network.groups if g.call_type == cid]
                    for cid in mcinfo.group_selected(loaded.profile.call_types)}
        health.set_call_types({
            "strict_release": config.strict_release,
            "not_requestable_by_mcptt_clients": list(undeclared),
            "unreachable_at_release": {cid: why for cid, why in blocked},
            "selected_by_group": by_group})
        # SVC-OP-06: a functional identity is held once a user the network
        # profile allows activates it (TS 24.379 clause 9A, Rel-15 on). A
        # call type none of whose roles anyone can hold is refused to every
        # caller: said at start, not discovered from refusals.
        activation = supports_procedure(config.release, "functional-alias")
        for ct in loaded.profile.call_types:
            if not ct.initiator_roles:
                continue
            if not activation:
                log.warning("call type %r needs the initiator to hold %s, and %s has no "
                            "functional alias activation (TS 24.379 clause 9A, Rel-15 "
                            "on): every caller is refused not-authorised", ct.id,
                            ", ".join(ct.initiator_roles), config.release)
            elif not set(ct.initiator_roles) & set(network.functional_aliases):
                log.warning("call type %r needs the initiator to hold %s, and the "
                            "network profile lets no user activate one "
                            "(functional_aliases): every caller is refused "
                            "not-authorised", ct.id, ", ".join(ct.initiator_roles))
        for cid, gids in by_group.items():
            if not gids:
                log.warning("call type %r is chosen by its group, and no group in the "
                            "network profile names it: no client can request it", cid)
        for cid, why in blocked:
            log.warning("call type %r cannot be requested by any client at this "
                        "release: %s (MCX_STRICT_RELEASE=false)", cid, why)

        # Owner ruling 2026-10-16: a setting that departs from the standard is
        # allowed, and said so -- in the log, the health document and the audit.
        health.set_audit(manager.floor_audit_state)
        settings, deviations = behaviour_settings(config, loaded)
        warnings = setting_warnings(config, loaded)
        health.set_deviations(settings, deviations)
        health.set_warnings(warnings)
        auditor.emit(RecordType.CONFIGURATION_ACCEPTED, STARTUP_CORRELATION_ID,
                     settings=settings, deviations=deviations, warnings=warnings)
        for w in warnings:
            log.warning("setting: %s", w["message"])
        for d in deviations:
            log.warning("deviation: %s=%s departs from %s (%s): %s", d["setting"],
                        d["value"], d["departs_from"], d["ref"], d["consequence"])
        if config.http_tls is not None and config.http_tls.client_auth != "required":
            # Not a departure from HTTP-1, which asks for HTTPS only; but the
            # handler does not look at a client certificate, so "optional"
            # grants what "none" does (RES-OP-05).
            log.warning("MCX_HTTP_CLIENT_AUTH=%s: health and group documents (every "
                        "group's members) are served to unauthenticated clients",
                        config.http_tls.client_auth)

        if recovered:
            log.warning("%d session record(s) were established when the previous "
                        "process stopped; their signalling state is not recovered "
                        "(SVC-OP-02)", recovered)
    except BaseException:
        # A refusal after the store opened must not leave it open (review of
        # the 2026-10-16 settings); a store the caller passed is the caller's.
        if own_store:
            store.close()
        raise
    return Runtime(config=config, loaded=loaded, network=network,
                   store=store, auditor=auditor,
                   manager=manager, groups=groups, health=health, clock=clock,
                   recovered=recovered, http_context=http_context)
