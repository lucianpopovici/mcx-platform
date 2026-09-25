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

# Settings whose content moved into the network profile (NET-OP-01).
MOVED_TO_NETWORK = ("MCX_CELLS_FILE", "MCX_SIP_TRUSTED_PEERS")


_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


def is_fqdn(name: str) -> bool:
    """RFC 1035 2.3.4 / RFC 1123 2.1: labels of 1-63 characters, 253 in all,
    and at least two labels -- which also keeps the keyword "none" from ever
    being read as a name in a list."""
    labels = name.split(".")
    return (len(name) <= 253 and len(labels) >= 2
            and all(_LABEL.fullmatch(label) for label in labels))


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
    # the platform asks for and caps a longer request to, in seconds. It is
    # how long a call whose far end vanished without a BYE can outlive it.
    # Required, no default; at least 90 (RFC 4028's smallest Min-SE).
    session_expires: int = 0

    @staticmethod
    def from_env(env: Mapping[str, str]) -> Optional["SipConfig"]:
        """None when SIP is not enabled (MCX_SIP_LISTEN unset). When it IS
        enabled every security-relevant setting must be stated (PLT-SEC-007):
        there is no plaintext mode to fall back to and no default for
        client authentication."""
        listen = (env.get("MCX_SIP_LISTEN") or "").strip()
        if not listen:
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
        raw_se = need("MCX_SESSION_EXPIRES")
        if not raw_se.isdigit() or len(raw_se) > 6 or int(raw_se) < MIN_SE_S:
            raise StartupRefused(
                f"MCX_SESSION_EXPIRES={raw_se!r}: give the RFC 4028 session "
                f"interval in whole seconds, at least {MIN_SE_S}. It bounds how "
                "long a call whose far end vanished without a BYE stays up")
        return SipConfig(host, port, uri, cert, key, ca, auth, roles,
                         session_expires=int(raw_se))


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
    groups_file: Optional[Path]
    # NET-OP-01 (decided 2026-09-25): the network profile -- PLMNs, cell
    # map, trusted SIP cores and their CA. Required, no default.
    network: Path
    sip: Optional[SipConfig] = None
    media: Optional[MediaConfig] = None

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
        if not raw_max.isdigit() or int(raw_max) < 1:
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
                "cell map, trusted SIP cores and their CA); there is no default, "
                "and every audit record names the one in force")

        groups = (env.get("MCX_GROUPS_FILE") or "").strip()
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
            groups_file=Path(groups) if groups else None,
            network=Path(network),
            sip=sip,
            media=MediaConfig.from_env(env) if sip is not None else None,
        )
