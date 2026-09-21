"""Process configuration, read from the environment only.

Nothing here has a default for a value that selects behaviour: the profile, the
identity provider and the data directory must each be stated. A missing one is
a refusal to start (PLT-GEN-003, PLT-IDM-007), never a fallback.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Optional

from core.errors import StartupRefused

DEFAULT_PROFILES_ROOT = Path(__file__).resolve().parents[1] / "profiles"
IDMS_STUB = "stub"
KNOWN_IDMS = (IDMS_STUB,)   # R1 has only the stub (PLT-IDM-007); R2 adds OIDC


@dataclass(frozen=True)
class Config:
    profile_names: List[str]
    profiles_root: Path
    data_dir: Path
    idms: str
    host: str
    port: int
    groups_file: Optional[Path]

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
        return Config(
            profile_names=names,
            profiles_root=Path(env.get("MCX_PROFILES_ROOT")
                               or DEFAULT_PROFILES_ROOT),
            data_dir=Path(data_dir),
            idms=idms,
            host=(env.get("MCX_HTTP_HOST") or "127.0.0.1").strip(),
            port=port,
            groups_file=Path(groups) if groups else None,
        )
