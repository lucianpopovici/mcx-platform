"""Process configuration, read from the environment only.

Nothing here has a default for a value that selects behaviour: the profile, the
identity provider and the data directory must each be stated. A missing one is
a refusal to start (PLT-GEN-003, PLT-IDM-007), never a fallback.
"""

from __future__ import annotations

import re

from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Optional, Tuple

from core.errors import StartupRefused
from core.release import Release, parse as parse_release
from core.sip import MIN_SE_S

DEFAULT_PROFILES_ROOT = Path(__file__).resolve().parents[1] / "profiles"
IDMS_STUB = "stub"
KNOWN_IDMS = (IDMS_STUB,)   # R1 has only the stub (PLT-IDM-007); R2 adds OIDC

# Every call type in every in-tree profile sets recording_required: true, and
# the process had no way to say a recorder exists, so it refused every call
# with `recording-unavailable`. Found by VP1-SIG-001 against a third-party SIP
# core; the suite had not caught it because its end-to-end tests inject the
# permissive `Platform()` instead of the one the process builds for itself.
# Named explicitly, like MCX_IDMS, with no default: "none" is the fail-closed
# behaviour stated rather than assumed.
RECORDER_NONE = "none"
RECORDER_STUB = "stub"
KNOWN_RECORDERS = (RECORDER_NONE, RECORDER_STUB)

# The same hole, one capability along: `reserve_qos` was hard-coded False too,
# so a process given a recorder still refused every call, with
# `qos-unavailable` instead. Both are capabilities of the network the process
# is deployed into, and neither could be stated. "stub" grants the reservation
# without reserving anything, which is what an integration environment has.
BEARER_NONE = "none"
BEARER_STUB = "stub"
KNOWN_BEARERS = (BEARER_NONE, BEARER_STUB)

# REL-OP-02, decided 2026-09-24: a profile can declare call types the
# configured 3GPP release cannot carry (the FRMCS profile's ad hoc group calls
# before Rel-18). MCX_STRICT_RELEASE=true refuses to start in that case;
# false starts and reports them. Required, like MCX_RELEASE: a default of
# false would let a deployment accept unreachable emergency calls without
# anyone having chosen to.
STRICT_RELEASE_VALUES = {"true": True, "false": False}

# Owner ruling 2026-10-16: the decisions taken as fixed behaviour become
# deployment settings, each required with no default like the ones above. A
# value that departs from the standard the original decision followed starts,
# but is reported: logged at startup, listed in the health document and in the
# startup audit record (service/runtime.py, `deviations`).
#
# SIP-OP-10: the status of a refusal for a service condition (capacity,
# recording, QoS, gateway, partner; not resolver-unavailable, core/sip.py
# KEEP_503). 503 is RFC 3261 21.5.4's; a
# proxy that receives only a 503 sends 500 upstream and drops the Warning
# (16.7 step 6). 480 crosses a proxy intact but says "temporarily
# unavailable" of the callee, which is not what happened.
SERVICE_REFUSAL_STATUSES = (503, 480)
# SIP-OP-18 item 6: may a dialog move to a new connection that proves the same
# party (a reconnecting client keeps its calls), or does it stay on the one it
# was established on.
DIALOG_TAKEOVER_VALUES = ("same-party", "never")
# ADHOC-OP-03: read the client's location report (TS 24.379 annex F.3) or
# ignore it. Ignored, a call to a location-dependent identity is refused
# `no-location-binding`.
LOCATION_REPORT_VALUES = ("read", "ignore")
# RES-OP-05: HTTPS on the HTTP interface (HTTP-1, PLT-SRS 3.1), or plain HTTP.
HTTP_TLS_VALUES = ("on", "off")
# PLT-GEN-011 as amended 2026-10-18: every duration setting may be stated in
# seconds or in milliseconds. Each seconds setting and its millisecond
# setting; at least one is set; with both, the milliseconds apply and a
# disagreement is reported at startup (service/runtime.py).
SECONDS_FORMS = {"MCX_SESSION_EXPIRES": "MCX_SESSION_EXPIRES_MS"}
SIP_ONLY = ("MCX_SERVICE_REFUSAL_STATUS", "MCX_DIALOG_TAKEOVER", "MCX_LOCATION_REPORTS",
            "MCX_SESSION_EXPIRES_MS", "MCX_SESSION_EXPIRES")
HTTP_CLIENT_AUTH_VALUES = ("required", "optional", "none")
# RES-OP-14 (owner ruling 2026-10-16): a floor transition the audit store
# cannot take is undone and not sent ("deny", PLT-FC-011 kept: the floor
# stops while the store fails), or sent unrecorded and counted, the gap
# written to the trail when the store recovers ("allow").
FLOOR_UNRECORDED_VALUES = ("deny", "allow")
# RES-OP-11 (owner ruling 2026-10-17): a caller outside the profile's
# declared domains -- possible when a trusted SIP core asserts it -- is
# refused 404 + 141 ("refuse", PLT-IDM-008) or served ("allow").
FOREIGN_INITIATOR_VALUES = ("refuse", "allow")


def _choice(env: Mapping[str, str], key: str, values, what: str) -> str:
    """A required setting with no default, one of `values`."""
    raw = (env.get(key) or "").strip().lower()
    shown = " or ".join(repr(str(v)) for v in values)
    if not raw:
        raise StartupRefused(f"{key} is not set: {what} ({shown}); there is no default")
    if raw not in {str(v) for v in values}:
        raise StartupRefused(f"{key}={raw!r} must be {shown}")
    return raw


@dataclass(frozen=True)
class HttpTlsConfig:
    cert: Path
    key: Path
    ca: Optional[Path]
    client_auth: str            # "required" | "optional" | "none"

    @staticmethod
    def from_env(env: Mapping[str, str]) -> Optional["HttpTlsConfig"]:
        """None when MCX_HTTP_TLS=off. On, every file must be stated and
        exist, and a CA is required unless client authentication is none."""
        if _choice(env, "MCX_HTTP_TLS", HTTP_TLS_VALUES,
                   "state whether the HTTP interface (health, group documents) "
                   "uses TLS") == "off":
            for key in ("MCX_HTTP_TLS_CERT", "MCX_HTTP_TLS_KEY", "MCX_HTTP_TLS_CA",
                        "MCX_HTTP_CLIENT_AUTH"):
                if (env.get(key) or "").strip():
                    # Refused rather than ignored: whoever set it would believe
                    # the interface is encrypted.
                    raise StartupRefused(f"{key} is set but MCX_HTTP_TLS=off")
            return None
        paths = []
        for key in ("MCX_HTTP_TLS_CERT", "MCX_HTTP_TLS_KEY"):
            raw = (env.get(key) or "").strip()
            if not raw:
                raise StartupRefused(f"{key} is not set: MCX_HTTP_TLS=on requires it")
            if not Path(raw).is_file():
                raise StartupRefused(f"{key}: TLS file {raw} does not exist")
            paths.append(Path(raw))
        auth = _choice(env, "MCX_HTTP_CLIENT_AUTH", HTTP_CLIENT_AUTH_VALUES,
                       "state whether HTTP clients must present a certificate")
        raw_ca = (env.get("MCX_HTTP_TLS_CA") or "").strip()
        if auth == "none":
            if raw_ca:
                raise StartupRefused("MCX_HTTP_TLS_CA is set but MCX_HTTP_CLIENT_AUTH=none")
            return HttpTlsConfig(paths[0], paths[1], None, auth)
        if not raw_ca:
            raise StartupRefused(
                f"MCX_HTTP_TLS_CA is not set: MCX_HTTP_CLIENT_AUTH={auth} cannot "
                "verify a client certificate without a CA")
        if not Path(raw_ca).is_file():
            raise StartupRefused(f"MCX_HTTP_TLS_CA: CA file {raw_ca} does not exist")
        return HttpTlsConfig(paths[0], paths[1], Path(raw_ca), auth)


# Settings whose content moved into the network profile (NET-OP-01).
MOVED_TO_NETWORK = ("MCX_CELLS_FILE", "MCX_SIP_TRUSTED_PEERS", "MCX_GROUPS_FILE")


_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


def is_fqdn(name: str) -> bool:
    """RFC 1035 2.3.4 / RFC 1123 2.1: labels of 1-63 characters, 253 in all,
    and at least two labels -- which also keeps the keyword "none" from ever
    being read as a name in a list."""
    labels = name.split(".")
    return (len(name) <= 253 and len(labels) >= 2
            and all(_LABEL.fullmatch(label) for label in labels))


def _session_interval(env: Mapping[str, str]) -> Tuple[int, Optional[int]]:
    """SIP-OP-17, PLT-GEN-011 as amended 2026-10-18: the RFC 4028 session interval as
    MCX_SESSION_EXPIRES_MS (milliseconds, a whole number of seconds, at
    least 90000) or MCX_SESSION_EXPIRES (seconds, at least 90), or both; at
    least one. Every value set must be valid. Returns (the interval in ms,
    the seconds as stated or None); the milliseconds take priority."""
    raw_ms = (env.get("MCX_SESSION_EXPIRES_MS") or "").strip()
    raw_s = (env.get("MCX_SESSION_EXPIRES") or "").strip()
    if not raw_ms and not raw_s:
        raise StartupRefused(
            "MCX_SESSION_EXPIRES_MS is not set (nor MCX_SESSION_EXPIRES, in "
            "seconds): SIP is enabled and requires the RFC 4028 session "
            "interval; there is no default")
    ms = s = None
    if raw_ms:
        if not (raw_ms.isascii() and raw_ms.isdigit()) or len(raw_ms) > 9 or \
                int(raw_ms) < MIN_SE_S * 1000 or int(raw_ms) % 1000:
            raise StartupRefused(
                f"MCX_SESSION_EXPIRES_MS={raw_ms[:32]!r}: give the RFC 4028 "
                "session interval in milliseconds, a whole number of seconds "
                f"(RFC 4028 counts in seconds), at least {MIN_SE_S * 1000}. It "
                "bounds how long a call whose far end vanished without a BYE "
                "stays up")
        ms = int(raw_ms)
    if raw_s:
        if not (raw_s.isascii() and raw_s.isdigit()) or len(raw_s) > 6 or \
                int(raw_s) < MIN_SE_S:
            raise StartupRefused(
                f"MCX_SESSION_EXPIRES={raw_s[:32]!r}: give the RFC 4028 session "
                f"interval in whole seconds, at least {MIN_SE_S}. It bounds how "
                "long a call whose far end vanished without a BYE stays up")
        s = int(raw_s)
    return (ms if ms is not None else s * 1000), s


@dataclass(frozen=True)
class SipConfig:
    host: str
    port: int
    uri: str
    cert: Path
    key: Path
    ca: Optional[Path]
    client_auth: str            # "required" | "optional"
    roles: Tuple[str, ...]
    # The trusted SIP cores and their CA (ICD-OP-08, ICD-OP-10) are network
    # data: see service/network.py.
    # SIP-OP-17 / CA-20b (decided 2026-09-25): the RFC 4028 session interval
    # the platform asks for and caps a longer request to. It is how long a
    # call whose far end vanished without a BYE can outlive it. Required, no
    # default; in milliseconds (PLT-GEN-011), a whole number of seconds since
    # RFC 4028 counts in seconds, at least 90 s (RFC 4028's smallest Min-SE).
    # PLT-GEN-011 as amended 2026-10-18: MCX_SESSION_EXPIRES_MS, or
    # MCX_SESSION_EXPIRES in seconds, or both, the milliseconds applying.
    session_expires_ms: int = 0
    # MCX_SESSION_EXPIRES as stated, in seconds, or None: checked against
    # session_expires_ms at startup when both are set.
    session_expires_s: Optional[int] = None
    # Owner ruling 2026-10-16 (see SERVICE_REFUSAL_STATUSES and the rest).
    service_refusal_status: int = 503
    dialog_takeover: str = "same-party"
    location_reports: str = "read"

    @staticmethod
    def from_env(env: Mapping[str, str]) -> Optional["SipConfig"]:
        """None when SIP is not enabled (MCX_SIP_LISTEN unset). When it IS
        enabled every security-relevant setting must be stated (PLT-SEC-007):
        there is no plaintext mode to fall back to and no default for
        client authentication."""
        listen = (env.get("MCX_SIP_LISTEN") or "").strip()
        if not listen:
            for key in SIP_ONLY:
                if (env.get(key) or "").strip():
                    # Refused rather than ignored, like a TLS setting with
                    # MCX_HTTP_TLS=off: whoever set it would believe it applies.
                    raise StartupRefused(f"{key} is set but SIP is not enabled "
                                         "(MCX_SIP_LISTEN)")
            return None
        host, _, port_s = listen.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            raise StartupRefused(
                f"MCX_SIP_LISTEN={listen!r} is not host:port") from None
        if not host or not 0 <= port <= 65535:
            raise StartupRefused(f"MCX_SIP_LISTEN={listen!r} is not host:port")

        def need(key: str) -> str:
            v = (env.get(key) or "").strip()
            if not v:
                raise StartupRefused(
                    f"{key} is not set: SIP is enabled and requires it")
            return v

        uri = need("MCX_SIP_URI")
        cert, key = Path(need("MCX_SIP_TLS_CERT")), Path(need("MCX_SIP_TLS_KEY"))
        for p in (cert, key):
            if not p.is_file():
                raise StartupRefused(f"TLS file {p} does not exist")
        ca_s = (env.get("MCX_SIP_TLS_CA") or "").strip()
        ca = Path(ca_s) if ca_s else None
        if ca is not None and not ca.is_file():
            raise StartupRefused(f"TLS CA file {ca} does not exist")
        auth = need("MCX_SIP_CLIENT_AUTH").lower()
        if auth not in ("required", "optional"):
            raise StartupRefused(
                f"MCX_SIP_CLIENT_AUTH={auth!r}: must be 'required' or 'optional'")
        if ca is None:
            raise StartupRefused(
                "MCX_SIP_TLS_CA is not set: client certificates cannot be "
                "verified without a CA (PLT-SEC-007)")

        roles = tuple(sorted({r.strip().lower()
                              for r in need("MCX_SIP_ROLES").split(",")
                              if r.strip()}))
        unknown = set(roles) - {"controlling", "participating"}
        if unknown or not roles:
            raise StartupRefused(
                f"MCX_SIP_ROLES has unknown role(s) {sorted(unknown)}")
        if "controlling" not in roles:
            # SIP-OP-03: a participating-only instance must relay to a
            # controlling function elsewhere (MCPTT-4). Not built.
            raise StartupRefused(
                "MCX_SIP_ROLES=participating alone is not supported: the "
                "controlling function is not reachable remotely (SIP-OP-03)")
        expires_ms, expires_s = _session_interval(env)
        status = _choice(env, "MCX_SERVICE_REFUSAL_STATUS", SERVICE_REFUSAL_STATUSES,
                         "state the SIP status of a refusal for a service condition "
                         "such as capacity (PLT-VP-R1 SIP-OP-10)")
        takeover = _choice(env, "MCX_DIALOG_TAKEOVER", DIALOG_TAKEOVER_VALUES,
                           "state whether a dialog may move to a new connection that "
                           "proves the same party (SIP-OP-18 item 6)")
        location = _choice(env, "MCX_LOCATION_REPORTS", LOCATION_REPORT_VALUES,
                           "state whether the client's location report is read "
                           "(ADHOC-OP-03)")
        return SipConfig(host, port, uri, cert, key, ca, auth, roles,
                         session_expires_ms=expires_ms,
                         session_expires_s=expires_s,
                         service_refusal_status=int(status),
                         dialog_takeover=takeover, location_reports=location)


@dataclass(frozen=True)
class MediaConfig:
    address: str
    ports: Optional[Tuple[int, int]]     # None: OS-assigned (tests only)

    @staticmethod
    def from_env(env: Mapping[str, str]) -> "MediaConfig":
        """Required whenever SIP is enabled: without a media plane in the path
        nothing enforces the floor, and silently forwarding SDP verbatim would
        be exactly that degraded start."""
        addr = (env.get("MCX_MEDIA_ADDRESS") or "").strip()
        if not addr:
            raise StartupRefused(
                "MCX_MEDIA_ADDRESS is not set: SIP is enabled and needs the "
                "address the media relay advertises")
        raw = (env.get("MCX_MEDIA_PORTS") or "").strip()
        if not raw:
            raise StartupRefused(
                "MCX_MEDIA_PORTS is not set: give 'lo-hi', or '0' for "
                "OS-assigned ports")
        if raw == "0":
            return MediaConfig(addr, None)
        lo_s, _, hi_s = raw.partition("-")
        try:
            lo, hi = int(lo_s), int(hi_s)
        except ValueError:
            raise StartupRefused(f"MCX_MEDIA_PORTS={raw!r} is not 'lo-hi'") from None
        if not 1 <= lo <= hi <= 65535:
            raise StartupRefused(f"MCX_MEDIA_PORTS={raw!r} is not a valid range")
        return MediaConfig(addr, (lo, hi))


@dataclass(frozen=True)
class Config:
    profile_names: List[str]
    release: Release
    profiles_root: Path
    data_dir: Path
    idms: str
    recorder: str
    bearer: str
    strict_release: bool
    # ADHOC-OP-04 (decided 2026-09-25): how many entries an ad hoc caller's
    # participant list may hold, whatever the call type -- the deployment's
    # counterpart of the service configuration's <max-no-participants>
    # (TS 24.379 17.4.2.2 step 6, warning 189). Required, no default.
    adhoc_list_max: int
    host: str
    port: int
    # NET-OP-01 (decided 2026-09-25): the network profile -- PLMNs, cell
    # map, trusted SIP cores and their CA, and (SVC-OP-03, decided
    # 2026-09-26) the groups and users. Required, no default.
    network: Path
    # RES-OP-14: "deny" or "allow". Required, no default.
    floor_unrecorded: str = ""
    # RES-OP-11: "refuse" or "allow". Required, no default.
    foreign_initiator: str = ""
    sip: Optional[SipConfig] = None
    media: Optional[MediaConfig] = None
    # RES-OP-05, owner ruling 2026-10-16: None is MCX_HTTP_TLS=off.
    http_tls: Optional[HttpTlsConfig] = None

    @staticmethod
    def from_env(env: Mapping[str, str]) -> "Config":
        raw_profiles = env.get("MCX_PROFILE", "")
        names = [n.strip() for n in raw_profiles.split(",") if n.strip()]

        raw_release = (env.get("MCX_RELEASE") or "").strip()
        if not raw_release:
            raise StartupRefused(
                "MCX_RELEASE is not set: state the 3GPP release this "
                "deployment speaks (PLT-REL-002); there is no default. A "
                "guessed release is silent -- subtype 14 is a valid floor "
                "control message in Rel-17 and in Rel-18 and means a "
                "different one in each")
        release = parse_release(raw_release)

        data_dir = (env.get("MCX_DATA_DIR") or "").strip()
        if not data_dir:
            raise StartupRefused(
                "MCX_DATA_DIR is not set: the durable session store needs an "
                "explicit location (PLT-GEN-009); there is no default")

        idms = (env.get("MCX_IDMS") or "").strip().lower()
        if not idms:
            raise StartupRefused(
                "MCX_IDMS is not set: name the identity provider explicitly "
                f"(known: {', '.join(KNOWN_IDMS)}); there is no default")
        if idms not in KNOWN_IDMS:
            raise StartupRefused(
                f"MCX_IDMS={idms!r} is not a known identity provider "
                f"(known: {', '.join(KNOWN_IDMS)})")

        recorder = (env.get("MCX_RECORDER") or "").strip().lower()
        if not recorder:
            raise StartupRefused(
                "MCX_RECORDER is not set: name the recorder explicitly "
                f"(known: {', '.join(KNOWN_RECORDERS)}); there is no default. "
                "Every call type in every in-tree profile requires recording, "
                "so a process that does not name one refuses every call")
        if recorder not in KNOWN_RECORDERS:
            raise StartupRefused(
                f"MCX_RECORDER={recorder!r} is not a known recorder "
                f"(known: {', '.join(KNOWN_RECORDERS)})")

        bearer = (env.get("MCX_BEARER") or "").strip().lower()
        if not bearer:
            raise StartupRefused(
                "MCX_BEARER is not set: name the bearer reservation source "
                f"explicitly (known: {', '.join(KNOWN_BEARERS)}); there is no "
                "default, and a process that cannot reserve refuses every "
                "session whose decision asks for one")
        if bearer not in KNOWN_BEARERS:
            raise StartupRefused(
                f"MCX_BEARER={bearer!r} is not a known bearer reservation "
                f"source (known: {', '.join(KNOWN_BEARERS)})")

        strict = (env.get("MCX_STRICT_RELEASE") or "").strip().lower()
        if not strict:
            raise StartupRefused(
                "MCX_STRICT_RELEASE is not set: state whether the process may "
                "start when the profile declares call types this release "
                "cannot carry (true = refuse, false = start and warn); there "
                "is no default")
        if strict not in STRICT_RELEASE_VALUES:
            raise StartupRefused(
                f"MCX_STRICT_RELEASE={strict!r} must be 'true' or 'false'")

        raw_max = (env.get("MCX_ADHOC_LIST_MAX") or "").strip()
        if not raw_max:
            raise StartupRefused(
                "MCX_ADHOC_LIST_MAX is not set: state how many entries an ad hoc "
                "caller's participant list may hold (a positive integer); there "
                "is no default, because an unbounded list is unbounded work "
                "before any participant is resolved")
        if not (raw_max.isascii() and raw_max.isdigit()) or int(raw_max) < 1:
            raise StartupRefused(
                f"MCX_ADHOC_LIST_MAX={raw_max!r} must be a whole number of at least 1")

        try:
            port = int(env.get("MCX_HTTP_PORT") or "8080")
        except ValueError as exc:
            raise StartupRefused(f"MCX_HTTP_PORT is not an integer: {exc}") from exc
        if not 0 <= port <= 65535:
            raise StartupRefused(f"MCX_HTTP_PORT {port} is out of range")

        for moved in MOVED_TO_NETWORK:
            if moved in env:
                # Refused rather than ignored: an operator who sets it would
                # otherwise believe it applies.
                raise StartupRefused(
                    f"{moved} is no longer read: its content is part of the "
                    "network profile (MCX_NETWORK_FILE, PLT-ICD-001 2.8)")
        network = (env.get("MCX_NETWORK_FILE") or "").strip()
        if not network:
            raise StartupRefused(
                "MCX_NETWORK_FILE is not set: name the network profile (PLMNs, "
                "cell map, trusted SIP cores and their CA, groups and users); there is no default, "
                "and every audit record names the one in force")

        floor_unrecorded = _choice(
            env, "MCX_FLOOR_UNRECORDED", FLOOR_UNRECORDED_VALUES,
            "state whether the floor may run unrecorded while the audit store is "
            "failing (PLT-VP-R1 RES-OP-14)")
        foreign_initiator = _choice(
            env, "MCX_FOREIGN_INITIATOR", FOREIGN_INITIATOR_VALUES,
            "state whether a caller outside the profile's declared domains is "
            "served (PLT-VP-R1 RES-OP-11)")
        http_tls = HttpTlsConfig.from_env(env)
        sip = SipConfig.from_env(env)
        return Config(
            profile_names=names,
            release=release,
            profiles_root=Path(env.get("MCX_PROFILES_ROOT")
                               or DEFAULT_PROFILES_ROOT),
            data_dir=Path(data_dir),
            idms=idms,
            recorder=recorder,
            bearer=bearer,
            strict_release=STRICT_RELEASE_VALUES[strict],
            adhoc_list_max=int(raw_max),
            host=(env.get("MCX_HTTP_HOST") or "127.0.0.1").strip(),
            port=port,
            network=Path(network),
            floor_unrecorded=floor_unrecorded,
            foreign_initiator=foreign_initiator,
            sip=sip,
            media=MediaConfig.from_env(env) if sip is not None else None,
            http_tls=http_tls,
        )
