"""Conformant MCPTT INVITE bodies for tests, written WITHOUT core/mcinfo.py.

A fixture built with the renderer under test agrees with it by construction
and proves nothing (PLT-CONF-AUDIT 4.10). Everything here is spelled out from
TS 24.379 annex F.1 as literal text: the namespace, the element names, their
order, the contentType wrapping. The multipart handling is RFC 2046 done by
hand, independently of core.

The call-type table below is the mcx profile's, restated literally so that a
wrong signature in the profile shows up as a test failure instead of being
read back from the profile.
"""

from __future__ import annotations

import re
from typing import Optional

NS = "urn:3gpp:ns:mcpttInfo:1.0"
CT_MCINFO = "application/vnd.3gpp.mcptt-info+xml"
BOUNDARY = "fixture-boundary-7c1e"

# mcx call type -> (<session-type>, emergency, imminent peril)
MCX = {
    "private": ("private", False, False),
    "prearranged-group": ("prearranged", False, False),
    "emergency-group": ("prearranged", True, False),
    "imminent-peril-group": ("prearranged", False, True),
}


def mcinfo_xml(session_type: str, request_uri: Optional[str] = None,
               emergency: bool = False, imminent_peril: bool = False,
               adhoc_emergency: Optional[bool] = None) -> str:
    parts = [f"<session-type>{session_type}</session-type>"]
    if request_uri:
        parts.append(f'<mcptt-request-uri type="Normal"><mcpttURI>{request_uri}'
                     f"</mcpttURI></mcptt-request-uri>")
    if emergency:
        parts.append('<emergency-ind type="Normal"><mcpttBoolean>true'
                     "</mcpttBoolean></emergency-ind>")
    if imminent_peril:
        parts.append('<imminentperil-ind type="Normal"><mcpttBoolean>true'
                     "</mcpttBoolean></imminentperil-ind>")
    if adhoc_emergency is not None:
        parts.append(f"<anyExt><adhoc-emergency-ind>{str(adhoc_emergency).lower()}"
                     f"</adhoc-emergency-ind></anyExt>")
    return (f'<?xml version="1.0" encoding="UTF-8"?>\r\n<mcpttinfo xmlns="{NS}">'
            f"<mcptt-Params>{''.join(parts)}</mcptt-Params></mcpttinfo>")


def multipart(sdp: str, xml: str) -> str:
    sdp = sdp.replace("\r\n", "\n").rstrip("\n").replace("\n", "\r\n")
    return (f"--{BOUNDARY}\r\nContent-Type: application/sdp\r\n\r\n{sdp}\r\n"
            f"--{BOUNDARY}\r\nContent-Type: {CT_MCINFO}\r\n\r\n{xml}\r\n"
            f"--{BOUNDARY}--\r\n")


CONTENT_TYPE = f"multipart/mixed;boundary={BOUNDARY}"


def body_for(call_type: str, target: str, sdp: str) -> str:
    """The body a conformant client sends to request an mcx call type. An
    unknown call type gets session-type "chat", which no mcx call type
    declares, so the platform finds no call type -- the refusal path."""
    session_type, emergency, peril = MCX.get(call_type, ("chat", False, False))
    return multipart(sdp, mcinfo_xml(session_type, target, emergency, peril))


def part(content_type: str, body: str, want: str) -> Optional[str]:
    """One part of a multipart body, by content type; the whole body when it
    is not multipart and is of that type."""
    m = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not m:
        return body if (content_type or "").split(";")[0].strip() == want else None
    for chunk in body.split("--" + m.group(1))[1:]:
        if chunk.startswith("--"):
            break
        head, _, content = chunk.lstrip("\r\n").partition("\r\n\r\n")
        if re.search(rf"(?im)^Content-Type:\s*{re.escape(want)}\s*$", head):
            return content.rstrip("\r\n") + "\r\n"
    return None


def sdp_of(request) -> str:
    """The SDP of a parsed request (anything with .headers.get and .body)."""
    return part(request.headers.get("Content-Type") or "", request.body,
                "application/sdp") or ""


def mcinfo_of(request) -> Optional[str]:
    return part(request.headers.get("Content-Type") or "", request.body, CT_MCINFO)
