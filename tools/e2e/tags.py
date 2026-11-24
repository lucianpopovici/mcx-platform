"""VP1-SIG-003: which SIP messages carry the MC service feature tags, and how.

Written from TS 24.379 (and RFC 3840 / RFC 3841 for the syntax), as a table
of message kinds. A message kind TS 24.379 attaches no feature tag to is
listed, with the reason, rather than left out: "every request and response
carries the feature tags of TS 24.379" is read as "every message carries
what TS 24.379 says it carries", and a BYE or an ACK has no Contact for a tag
to be in (RFC 3261 8.1.1.8, 12.2.1.1).

  initial INVITE    Contact: +g.3gpp.mcptt and the MCPTT ICSI; two
                    Accept-Contact header fields, each with require and
                    explicit, one per tag (client: 10.1.1.2.1.1,
                    11.1.1.2.1.1; controlling function towards a callee:
                    6.3.3.1.2 item 1, plus isfocus; PLT-CONF-AUDIT CA-06).
  REGISTER          Contact: both tags (7.2.1).
  18x / 2xx to an   Contact: both tags (terminating client: 10.1.1.2.1.2,
  INVITE, and 2xx   11.1.1.2.2; the platform's to an originator, plus
  to a re-INVITE    isfocus: 6.3.2.1.5.1 item 1, 6.3.3.2.3.1 items 3-4,
  or UPDATE         6.3.3.2.3.2 items 5-6).
  re-INVITE/UPDATE  Contact: both tags (a target refresh, RFC 3261 12.2;
                    the platform's, plus isfocus).
  isfocus           only the platform's (the controlling function is the
                    focus); a client's Contact never carries it.
  service headers   an initial INVITE carries the MCPTT ICSI unescaped: a
                    client's in P-Preferred-Service (10.1.1.2.1.1,
                    11.1.1.2.1.1 item 7), the platform's in P-Asserted-Service
                    (6.3.3.1.2 item 3, which writes "P-Asserted-Service-Id";
                    RFC 6050 names the header P-Asserted-Service). Owner
                    decision 2026-11-24: VP1-SIG-003 covers them.
  none defined      ACK, BYE, CANCEL; 100 Trying; 3xx-6xx; the 2xx to
                    REGISTER, BYE, CANCEL; the 18x/2xx/3xx-6xx to those.

Any other method, or a response to one, is not in the table: it fails
("not in the table") rather than passing unexamined (batch C review H3) --
a SUBSCRIBE, NOTIFY, MESSAGE or PUBLISH on the wire means the table needs a
row for it. Compact header forms (RFC 3261 7.3.3: "m" for Contact) and a
comma-joined Accept-Contact are read as their long forms.
"""

from __future__ import annotations

import re
from typing import List, Tuple

MCPTT = "+g.3gpp.mcptt"
ICSI_PLAIN = "urn:urn-7:3gpp-service.ims.icsi.mcptt"
NONE_REQUESTS = ("ACK", "BYE", "CANCEL")
COMPACT = {"m": "contact", "f": "from", "t": "to", "i": "call-id", "v": "via"}
ICSI = '+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt"'
ACCEPT = {"*;+g.3gpp.mcptt;require;explicit", f"*;{ICSI};require;explicit"}


def _headers(text: str, name: str) -> List[str]:
    out = []
    for line in text.split("\r\n\r\n", 1)[0].split("\r\n")[1:]:
        k, _, v = line.partition(":")
        k = k.strip().lower()
        if COMPACT.get(k, k) == name.lower():
            out.append(v.strip())
    return out


def _split_commas(values: List[str]) -> List[str]:
    """RFC 3261 7.3.1: one header field may carry a comma-separated list. The
    feature-tag values here hold no quoted commas."""
    return [p.strip() for v in values for p in v.split(",") if p.strip()]


def _params(contact: str) -> List[str]:
    """The header parameters after the name-addr (RFC 3261 20.10)."""
    rest = contact.split(">", 1)[1] if ">" in contact else contact.split(";", 1)[-1]
    return [p.strip() for p in rest.split(";") if p.strip()]


def kind(text: str) -> str:
    start = text.split("\r\n", 1)[0]
    cseq = (_headers(text, "CSeq") or ["0 ?"])[0].split()[-1].upper()
    if start.startswith("SIP/2.0 "):
        code = int(start.split()[1])
        if cseq == "INVITE" and (100 < code < 200 or 200 <= code < 300):
            return "dialog-response"
        if cseq == "UPDATE" and 200 <= code < 300:
            return "dialog-response"
        if cseq in ("INVITE", "UPDATE", "REGISTER") + NONE_REQUESTS:
            return "response-none"
        return "unknown"
    method = start.split()[0].upper()
    to = (_headers(text, "To") or [""])[0]
    if method == "INVITE":
        return "re-invite" if re.search(r";\s*tag=", to) else "initial-invite"
    if method == "UPDATE":
        return "re-invite"
    if method == "REGISTER":
        return "register"
    if method in NONE_REQUESTS:
        return "request-none"
    return "unknown"


def check_message(text: str, from_platform: bool) -> Tuple[str, str]:
    """('' if the message conforms, else what is wrong; the rule applied)."""
    k = kind(text)
    if k in ("response-none", "request-none"):
        return "", k
    if k == "unknown":
        return f"{text.split(chr(13), 1)[0]}: not in the table (tools/e2e/tags.py)", k
    contacts = _headers(text, "Contact")
    if len(contacts) != 1:
        return f"{len(contacts)} Contact header fields, expected one", k
    params = _params(contacts[0])
    problems = []
    if MCPTT not in params:
        problems.append("Contact lacks +g.3gpp.mcptt")
    if ICSI not in params:
        problems.append("Contact lacks the MCPTT ICSI")
    if from_platform and k != "register" and "isfocus" not in params:
        problems.append("the platform's Contact lacks isfocus")
    if not from_platform and "isfocus" in params:
        problems.append("a client's Contact carries isfocus")
    if k == "initial-invite":
        accept = {a.replace(" ", "") for a in _split_commas(_headers(text, "Accept-Contact"))}
        for want in sorted(ACCEPT - accept):
            problems.append(f"no Accept-Contact {want}")
        service = "P-Asserted-Service" if from_platform else "P-Preferred-Service"
        if _headers(text, service) != [ICSI_PLAIN]:
            problems.append(f"{service} is {_headers(text, service)}, not the MCPTT ICSI")
    return "; ".join(problems), k
