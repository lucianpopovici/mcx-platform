"""Reason codes and platform exceptions.

Reason codes are the closed vocabulary of PLT-ICD-001 §9. Codes originated by
the core are reserved: a profile may add its own but may not redefine these.
"""

from __future__ import annotations

from typing import FrozenSet

# --------------------------------------------------------------------------
# Core-reserved reason codes (PLT-ICD-001 §9)
# --------------------------------------------------------------------------

UNKNOWN_TARGET = "unknown-target"
NO_BINDING = "no-binding"
NO_LOCATION_BINDING = "no-location-binding"
RESOLVER_UNAVAILABLE = "resolver-unavailable"
NOT_AUTHORISED = "not-authorised"
CAPACITY_EXHAUSTED = "capacity-exhausted"
CALL_TYPE_NOT_PERMITTED = "call-type-not-permitted"
RECORDING_UNAVAILABLE = "recording-unavailable"
QOS_UNAVAILABLE = "qos-unavailable"
GATEWAY_UNAVAILABLE = "gateway-unavailable"
PARTNER_UNAVAILABLE = "partner-unavailable"
PARTNER_NOT_PERMITTED = "partner-not-permitted"
HOOK_TIMEOUT = "hook-timeout"
HOOK_ERROR = "hook-error"
HOOK_CONTRACT_VIOLATION = "hook-contract-violation"
# Ad hoc group calls (TS 24.379 clause 17; warning texts 187 and 189).
ADHOC_PARTICIPANTS_UNDETERMINED = "adhoc-participants-undetermined"
ADHOC_TOO_MANY_PARTICIPANTS = "adhoc-too-many-participants"
# The identity a request asserts is not one its connection authenticated
# (PLT-ICD-001 ICD-OP-08; PLT-IDM-004 in its R1 form).
IDENTITY_NOT_AUTHENTICATED = "identity-not-authenticated"

RESERVED_REASON_CODES: FrozenSet[str] = frozenset(
    {
        UNKNOWN_TARGET,
        NO_BINDING,
        NO_LOCATION_BINDING,
        RESOLVER_UNAVAILABLE,
        NOT_AUTHORISED,
        CAPACITY_EXHAUSTED,
        CALL_TYPE_NOT_PERMITTED,
        RECORDING_UNAVAILABLE,
        QOS_UNAVAILABLE,
        GATEWAY_UNAVAILABLE,
        PARTNER_UNAVAILABLE,
        PARTNER_NOT_PERMITTED,
        HOOK_TIMEOUT,
        HOOK_ERROR,
        HOOK_CONTRACT_VIOLATION,
        ADHOC_PARTICIPANTS_UNDETERMINED,
        ADHOC_TOO_MANY_PARTICIPANTS,
        IDENTITY_NOT_AUTHENTICATED,
    }
)

# Codes the core originates itself. A profile declaring one of these in its own
# reject_reason_codes set is redefining core semantics and is rejected.
CORE_ORIGINATED: FrozenSet[str] = frozenset(
    {
        RECORDING_UNAVAILABLE,
        QOS_UNAVAILABLE,
        GATEWAY_UNAVAILABLE,
        PARTNER_UNAVAILABLE,
        PARTNER_NOT_PERMITTED,
        HOOK_TIMEOUT,
        HOOK_ERROR,
        HOOK_CONTRACT_VIOLATION,
        # The limit is the call type's, applied by the core. The other ad hoc
        # code is raised by a resolver, so a profile may declare it.
        ADHOC_TOO_MANY_PARTICIPANTS,
        IDENTITY_NOT_AUTHENTICATED,
    }
)


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class PlatformError(Exception):
    """Base for all platform errors."""


class ProfileValidationError(PlatformError):
    """A profile failed validation. Carries every defect found, not just the first.

    PLT-PRF-008 requires the diagnostic to name the failing element by its path
    within the profile package, so each defect carries that path.
    """

    def __init__(self, defects):
        self.defects = tuple(defects)
        super().__init__(self._render())

    def _render(self) -> str:
        head = f"profile validation failed: {len(self.defects)} defect(s)"
        body = "\n".join(f"  {d.path}: {d.message}" for d in self.defects)
        return f"{head}\n{body}"

    def paths(self):
        return tuple(d.path for d in self.defects)

    def codes(self):
        return tuple(d.code for d in self.defects)


class ProfileLoadError(PlatformError):
    """A profile could not be loaded: missing, unreadable, or hooks unresolvable."""


class StartupRefused(PlatformError):
    """Startup conditions are not satisfiable. The process must not continue.

    PLT-GEN-003, PLT-GEN-005, PLT-PRF-007: the platform never starts degraded.
    """


class HookContractViolation(PlatformError):
    """A hook returned a value failing a POST condition of PLT-ICD-001.

    Distinguished from a hook raising (HOOK_ERROR) because this indicates a
    profile defect and should be alertable, where the other may be environmental.
    """

    reason_code = HOOK_CONTRACT_VIOLATION
