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


# -- ad hoc group calls (TS 24.379 17.2.2.1.1 items 10-12), written by hand ----------

CT_RESOURCE_LISTS = "application/resource-lists+xml"


def adhoc_xml(criteria: Optional[str] = None, emergency: Optional[bool] = None,
              request_uri: Optional[str] = None,
              alert_group: Optional[bool] = None) -> str:
    """<session-type>adhoc</session-type>, an optional <mcptt-request-uri>,
    and <anyExt> holding whichever of <adhoc-emergency-ind>,
    <call-participants-criterias> and <adhoc-grp-emg-alert-grp-ind> apply."""
    params = ["<session-type>adhoc</session-type>"]
    if request_uri:
        params.append(f'<mcptt-request-uri type="Normal"><mcpttURI>{request_uri}'
                      f"</mcpttURI></mcptt-request-uri>")
    ext = ""
    if emergency is not None:
        ext += f"<adhoc-emergency-ind>{str(emergency).lower()}</adhoc-emergency-ind>"
    if criteria is not None:
        ext += f"<call-participants-criterias>{criteria}</call-participants-criterias>"
    if alert_group is not None:
        ext += (f"<adhoc-grp-emg-alert-grp-ind>{str(alert_group).lower()}"
                f"</adhoc-grp-emg-alert-grp-ind>")
    if ext:
        params.append(f"<anyExt>{ext}</anyExt>")
    return (f'<?xml version="1.0" encoding="UTF-8"?>\r\n<mcpttinfo xmlns="{NS}">'
            f"<mcptt-Params>{''.join(params)}</mcptt-Params></mcpttinfo>")


def resource_list(uris, nested: bool = False, extra: str = "") -> str:
    """RFC 4826 / RFC 5366: <resource-lists><list><entry uri=.../></list>."""
    entries = "".join(f'<entry uri="{u}"/>' for u in uris)
    if nested:
        entries = f"<list>{entries}</list>"
    return ('<?xml version="1.0" encoding="UTF-8"?>\r\n'
            '<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists">'
            f"<list>{entries}{extra}</list></resource-lists>")


def adhoc_body(sdp: str, xml: str, rl: Optional[str] = None) -> str:
    sdp = sdp.replace("\r\n", "\n").rstrip("\n").replace("\n", "\r\n")
    out = (f"--{BOUNDARY}\r\nContent-Type: application/sdp\r\n\r\n{sdp}\r\n"
           f"--{BOUNDARY}\r\nContent-Type: {CT_MCINFO}\r\n\r\n{xml}\r\n")
    if rl is not None:
        out += f"--{BOUNDARY}\r\nContent-Type: {CT_RESOURCE_LISTS}\r\n\r\n{rl}\r\n"
    return out + f"--{BOUNDARY}--\r\n"


# -- location reports (TS 24.379 annex F.3), written by hand ---------------------------

CT_LOCATION = "application/vnd.3gpp.mcptt-location-info+xml"
NS_LOC = "urn:3gpp:ns:mcpttLocationInfo:1.0"
ECGI = "001010" + "0000000000000000000100100011"               # MCC 001 MNC 010, 28 bits
NCGI = "001010" + "000000000000000000000000000100100011"       # 36 bits


def location_report(ecgi: Optional[str] = None, ncgi: Optional[str] = None,
                    encrypted: bool = False) -> str:
    """<location-info><Report ReportType="NonEmergency"><CurrentLocation>...
    The NCGI goes where Rel-18 puts it: CurrentLocation/anyExt/
    CurrentServingNcgi/anyExt/Ncgi."""
    kind = "Encrypted" if encrypted else "Normal"
    inner = ""
    if ecgi is not None:
        inner += (f'<CurrentServingEcgi type="{kind}"><Ecgi>{ecgi}</Ecgi>'
                  "</CurrentServingEcgi>")
    if ncgi is not None:
        inner += (f'<anyExt><CurrentServingNcgi type="{kind}"><anyExt><Ncgi>{ncgi}</Ncgi>'
                  "</anyExt></CurrentServingNcgi></anyExt>")
    return (f'<?xml version="1.0" encoding="UTF-8"?>\r\n<location-info xmlns="{NS_LOC}">'
            f'<Report ReportType="NonEmergency"><CurrentLocation>{inner}'
            "</CurrentLocation></Report></location-info>")


def with_parts(sdp: str, xml: str, *extra) -> str:
    """SDP, MCPTT info, then (content_type, body) pairs."""
    sdp = sdp.replace("\r\n", "\n").rstrip("\n").replace("\n", "\r\n")
    out = (f"--{BOUNDARY}\r\nContent-Type: application/sdp\r\n\r\n{sdp}\r\n"
           f"--{BOUNDARY}\r\nContent-Type: {CT_MCINFO}\r\n\r\n{xml}\r\n")
    for ctype, body in extra:
        out += f"--{BOUNDARY}\r\nContent-Type: {ctype}\r\n\r\n{body}\r\n"
    return out + f"--{BOUNDARY}--\r\n"
