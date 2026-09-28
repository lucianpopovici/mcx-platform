"""The domain of an MC service identity (PLT-IDM-008; PLT-ICD-001 §3.2 POST-3).

An identity counts as within a domain only when it is written plainly:
`sip:` or `sips:`, a user part, one `@`, and a host of DNS characters. The
host is compared without case (RFC 3261 19.1.4). Anything else -- a second
`@`, parameters, headers, a port, brackets, whitespace, another scheme -- is
within no domain, so an identity cannot pass the check by being written in a
way one parser reads differently from another (RES-OP-01 review: a member
`sip:evil@other.example@mcptt.example` read by its last `@` looked local).
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

_IDENTITY = re.compile(r"(?i:sips?):([^@;?<>:\s/]+)@([A-Za-z0-9.-]+)")


def domain_of(identity: str) -> Optional[str]:
    """The identity's host in lower case, or None if it is not written as
    `sip[s]:user@host`."""
    m = _IDENTITY.fullmatch(identity) if isinstance(identity, str) else None
    return m.group(2).lower() if m else None


def outside(identities: Iterable[str], domains: Iterable[str]) -> list:
    """The identities that are not within one of `domains`."""
    declared = {d.lower() for d in domains}
    return [i for i in identities if domain_of(i) not in declared]
