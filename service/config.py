"""Process configuration, read from the environment only.

Nothing here has a default for a value that selects behaviour: the profile, the
identity provider and the data directory must each be stated. A missing one is
a refusal to start (PLT-GEN-003, PLT-IDM-007), never a fallback.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Optional, Tuple

from core.errors import StartupRefused

DEFAULT_PROFILES_ROOT = Path(__file__).resolve().parents[1] / "profiles"
IDMS_STUB = "stub"
KNOWN_IDMS = (IDMS_STUB,)   # R1 has only the stub (PLT-IDM-007); R2 adds OIDC


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
        return SipConfig(host, port, uri, cert, key, ca, auth, roles)


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
    profiles_root: Path
    data_dir: Path
    idms: str
    host: str
    port: int
    groups_file: Optional[Path]
    sip: Optional[SipConfig] = None
    media: Optional[MediaConfig] = None

    @staticmethod
    def from_env(env: Mapping[str, str]) -> "Config":
        raw_profiles = env.get("MCX_PROFILE", "")
        names = [n.strip() for n in raw_profiles.split(",") if n.strip()]

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

        try:
            port = int(env.get("MCX_HTTP_PORT") or "8080")
        except ValueError as exc:
            raise StartupRefused(f"MCX_HTTP_PORT is not an integer: {exc}") from exc
        if not 0 <= port <= 65535:
            raise StartupRefused(f"MCX_HTTP_PORT {port} is out of range")

        groups = (env.get("MCX_GROUPS_FILE") or "").strip()
        sip = SipConfig.from_env(env)
        return Config(
            profile_names=names,
            profiles_root=Path(env.get("MCX_PROFILES_ROOT")
                               or DEFAULT_PROFILES_ROOT),
            data_dir=Path(data_dir),
            idms=idms,
            host=(env.get("MCX_HTTP_HOST") or "127.0.0.1").strip(),
            port=port,
            groups_file=Path(groups) if groups else None,
            sip=sip,
            media=MediaConfig.from_env(env) if sip is not None else None,
        )
