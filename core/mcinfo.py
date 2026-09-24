"""The MCPTT info body, TS 24.379 annex F.1, and the multipart body carrying it.

    Content-Type: application/vnd.3gpp.mcptt-info+xml

    <mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0">
      <mcptt-Params>
        <session-type>prearranged</session-type>
        <mcptt-request-uri type="Normal"><mcpttURI>sip:grp@...</mcpttURI></mcptt-request-uri>
        ...
      </mcptt-Params>
    </mcpttinfo>

Every element name, the namespace and the element ORDER come from the schema
printed in annex F.1, extracted verbatim to docs/3GPP/schemas/ by
tools/spec/extract_xsd.py. Nothing here was written from recollection.

PLT-CONF-AUDIT CA-20. What this replaced read `<mcptt-call_type>` and
`<mcptt-target>` out of a body with no namespace, appended to the SDP with no
MIME boundaries. Neither element exists in any release of TS 24.379, so no
conformant client could have told the platform what kind of call it wanted.

Not here, deliberately: which of a profile's call types a signature means.
That is profile data (PLT-ICD-001 section 2.6); this module turns a body into
protocol facts and protocol facts into a body, and knows no call type.

The specification's own EXAMPLE 5 (clause 4.8, V20.0.0) is not usable as a
fixture: <mcpttinfo> is closed by </mcptt-info>, which makes it not
well-formed; it also has no namespace, which makes it schema-invalid, and a
stray '>' inside the URI. The schema is the authority. Do not relax the
parser to accept the example.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional, Sequence, Tuple
from xml.etree import ElementTree as ET

from .release import Release, supports_mc_indicator, supports_session_type

NAMESPACE = "urn:3gpp:ns:mcpttInfo:1.0"
CONTENT_TYPE = "application/vnd.3gpp.mcptt-info+xml"
CT_SDP = "application/sdp"
_NS = "{" + NAMESPACE + "}"

# Annex F.1: the <session-type> values the procedures set. When each first
# appears is in core/release.py (SESSION_TYPE_INTRODUCED).
SESSION_TYPES = ("prearranged", "chat", "private", "first-to-answer",
                 "ambient-listening", "adhoc")

# mcptt-ParamsType is an xs:sequence, so order is part of validity. The
# elements this renderer emits, in schema order.
_PARAMS_ORDER = ("session-type", "mcptt-request-uri", "mcptt-calling-user-id",
                 "mcptt-called-party-id", "mcptt-calling-group-id",
                 "emergency-ind", "imminentperil-ind", "broadcast-ind",
                 "mcptt-client-id", "anyExt")


class McInfoError(ValueError):
    """A body that claims to be MCPTT info and is not."""


@dataclass(frozen=True)
class Signature:
    """What TS 24.379 can say about the kind of a call: a session type and
    three indications. A profile maps each signature to at most one of its
    call types (PLT-ICD-001 section 2.6)."""

    session_type: str
    emergency: bool = False
    imminent_peril: bool = False
    broadcast: bool = False


@dataclass(frozen=True)
class McInfo:
    session_type: Optional[str] = None
    request_uri: Optional[str] = None
    calling_user_id: Optional[str] = None
    called_party_id: Optional[str] = None
    calling_group_id: Optional[str] = None
    client_id: Optional[str] = None
    emergency: Optional[bool] = None
    imminent_peril: Optional[bool] = None
    broadcast: Optional[bool] = None
    # Content elements carried with type="Encrypted" (clause 6.6.2). The
    # platform holds no key to read them, so they are recorded, not guessed.
    encrypted: FrozenSet[str] = field(default_factory=frozenset)

    def signature(self) -> Optional[Signature]:
        """None when there is no session type, or when an indication that
        decides the call type arrived encrypted and so cannot be read."""
        if not self.session_type:
            return None
        if self.encrypted & {"emergency-ind", "imminentperil-ind"}:
            return None
        return Signature(self.session_type, bool(self.emergency),
                         bool(self.imminent_peril), bool(self.broadcast))


# -- multipart/mixed (RFC 2046 section 5.1) ------------------------------------

@dataclass(frozen=True)
class Part:
    content_type: str
    body: str


def _param(content_type: str, name: str) -> Optional[str]:
    """A Content-Type parameter, with ';' inside quoted values respected.
    A regex over the whole value found 'boundary=' inside another quoted
    parameter (found by review)."""
    params, cur, quoted = [], "", False
    for ch in content_type.partition(";")[2]:
        if ch == '"':
            quoted = not quoted
        if ch == ";" and not quoted:
            params.append(cur); cur = ""
        else:
            cur += ch
    params.append(cur)
    for item in params:
        k, eq, v = item.partition("=")
        if eq and k.strip().lower() == name.lower():
            v = v.strip()
            return v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v
    return None


def split_body(content_type: str, body: str) -> List[Part]:
    """The parts of a message body. A non-multipart body is one part.

    Raises McInfoError for a multipart body that is not one: no boundary
    parameter, or no delimiter line in the body. The body this replaced was
    declared multipart/mixed and had no delimiters at all.
    """
    ctype = (content_type or "").strip()
    if not ctype.lower().startswith("multipart/"):
        return [Part(ctype.split(";")[0].strip().lower(), body)] if body else []
    boundary = _param(ctype, "boundary")
    if not boundary:
        raise McInfoError("multipart body without a boundary parameter")
    delimiter = "--" + boundary
    text = body.replace("\r\n", "\n")
    lines = text.split("\n")
    starts = [i for i, l in enumerate(lines) if l.rstrip() in (delimiter, delimiter + "--")]
    if not starts:
        raise McInfoError(f"multipart body contains no {delimiter!r} delimiter")
    # RFC 2046 5.1.1: the body ends with a close-delimiter. Without one the
    # last part used to be dropped silently (found by review).
    closing = [i for i in starts if lines[i].rstrip() == delimiter + "--"]
    if not closing:
        raise McInfoError(f"multipart body has no closing {delimiter + '--'!r}")
    starts = [i for i in starts if i <= closing[0]]
    parts: List[Part] = []
    for a, b in zip(starts, starts[1:]):
        chunk = lines[a + 1:b]
        try:
            blank = chunk.index("")
        except ValueError:
            blank = len(chunk)
        headers: List[str] = []
        for h in chunk[:blank]:                    # unfold (RFC 5322 2.2.3)
            if h[:1] in (" ", "\t") and headers:
                headers[-1] += " " + h.strip()
            else:
                headers.append(h)
        content = chunk[blank + 1:]
        part_type = "text/plain"
        for h in headers:
            k, _, v = h.partition(":")
            if k.strip().lower() == "content-type":
                part_type = v.strip()
        parts.append(Part(part_type.split(";")[0].strip().lower(),
                          "\r\n".join(content)))
    return parts


def build_multipart(parts: Sequence[Part]) -> Tuple[str, str]:
    """(Content-Type header value, body) for a multipart/mixed body."""
    boundary = "mcx" + uuid.uuid4().hex[:16]
    out = []
    for p in parts:
        content = p.body.replace("\r\n", "\n").rstrip("\n").replace("\n", "\r\n")
        out.append(f"--{boundary}\r\nContent-Type: {p.content_type}\r\n\r\n{content}\r\n")
    out.append(f"--{boundary}--\r\n")
    return f"multipart/mixed;boundary={boundary}", "".join(out)


def sdp_of(content_type: str, body: str) -> str:
    """The SDP part of a body, or "" when there is none."""
    for p in split_body(content_type, body):
        if p.content_type == CT_SDP:
            return p.body
    return ""


def mcinfo_of(content_type: str, body: str) -> Optional[str]:
    for p in split_body(content_type, body):
        if p.content_type == CONTENT_TYPE:
            return p.body
    return None


# -- the XML ---------------------------------------------------------------------

def _content(el: Optional[ET.Element], name: str, encrypted: set) -> Optional[str]:
    """Value of a contentType element: its mcpttURI, mcpttString or
    mcpttBoolean child. type="Encrypted" is recorded and yields None."""
    if el is None:
        return None
    if (el.get("type") or "").lower() == "encrypted":
        encrypted.add(name)
        return None
    for child in ("mcpttURI", "mcpttString", "mcpttBoolean"):
        c = el.find(_NS + child)
        if c is not None and c.text is not None:
            return c.text.strip()
    return None


def _boolean(text: Optional[str]) -> Optional[bool]:
    if text is None:
        return None
    t = text.strip().lower()
    if t in ("true", "1"):
        return True
    if t in ("false", "0"):
        return False
    raise McInfoError(f"not an xs:boolean: {text!r}")


def parse(text: str) -> McInfo:
    """Protocol facts from an application/vnd.3gpp.mcptt-info+xml body.

    Strict about what the schema makes structural -- the namespace (the
    schema is elementFormDefault="qualified") and the root element -- and
    silent about elements it does not use. A document type declaration is
    refused outright: this body never needs one, and it is the vehicle for
    entity-expansion attacks on anything that parses XML from the network.
    """
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise McInfoError("document type declarations are not accepted")
    # The body is text already; an XML declaration naming another encoding
    # would make the parser re-decode it. "bogus" raised LookupError and
    # "UTF-7" ValueError, both escaping as a 500 with a traceback on any
    # INVITE (found by review). Only UTF-8 is accepted.
    decl = re.match(r'\s*<\?xml[^>]*?encoding\s*=\s*["\']([^"\']+)["\']', text)
    if decl and decl.group(1).strip().lower().replace("_", "-") not in ("utf-8", "utf8"):
        raise McInfoError(f"encoding {decl.group(1)!r} is not accepted; use UTF-8")
    try:
        root = ET.fromstring(text.strip().encode("utf-8"))
    except (ET.ParseError, ValueError, LookupError) as exc:
        raise McInfoError(f"not well-formed: {exc}") from None
    if root.tag != _NS + "mcpttinfo":
        raise McInfoError(f"root element is {root.tag!r}, not "
                          f"{{{NAMESPACE}}}mcpttinfo")
    params = root.find(_NS + "mcptt-Params")
    if params is None:
        return McInfo()
    enc: set = set()

    def content(name: str) -> Optional[str]:
        return _content(params.find(_NS + name), name, enc)

    st = params.find(_NS + "session-type")
    session_type = st.text.strip() if st is not None and st.text else None
    broadcast_el = params.find(_NS + "broadcast-ind")
    broadcast = _boolean(broadcast_el.text) if broadcast_el is not None else None

    emergency_ind = _boolean(content("emergency-ind"))
    if session_type == "adhoc":
        # From Rel-18 an ad hoc group call signals emergency with
        # <adhoc-emergency-ind>, an xs:boolean in the <anyExt> of
        # <mcptt-Params> (6.2.8.1.21). A client that sets <emergency-ind>
        # instead is non-conformant, but silently treating its call as a
        # normal one would be the worst available reading of an emergency,
        # so either indication counts (found by review).
        ext = params.find(_NS + "anyExt")
        flag = ext.find(_NS + "adhoc-emergency-ind") if ext is not None else None
        adhoc_flag = _boolean(flag.text) if flag is not None else None
        emergency = True if (adhoc_flag or emergency_ind) else (
            adhoc_flag if adhoc_flag is not None else emergency_ind)
    else:
        emergency = emergency_ind

    return McInfo(
        session_type=session_type,
        request_uri=content("mcptt-request-uri"),
        calling_user_id=content("mcptt-calling-user-id"),
        called_party_id=content("mcptt-called-party-id"),
        calling_group_id=content("mcptt-calling-group-id"),
        client_id=content("mcptt-client-id"),
        emergency=emergency,
        imminent_peril=_boolean(content("imminentperil-ind")),
        broadcast=broadcast,
        encrypted=frozenset(enc),
    )


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def render(info: McInfo, release: Release) -> str:
    """An mcptt-info body for `info`, valid against the annex F.1 schema of
    `release`. Raises McInfoError for a fact that release cannot express."""
    if info.session_type and info.session_type not in SESSION_TYPES:
        raise McInfoError(f"unknown session-type {info.session_type!r}")
    adhoc = info.session_type == "adhoc"
    if adhoc and info.emergency and not supports_mc_indicator(release, "adhoc-emergency-ind"):
        raise McInfoError(f"{release} has no ad hoc emergency indication")
    el = {}
    if info.session_type:
        el["session-type"] = f"<session-type>{_esc(info.session_type)}</session-type>"

    def uri(name: str, value: Optional[str]) -> None:
        if value:
            el[name] = (f'<{name} type="Normal"><mcpttURI>{_esc(value)}</mcpttURI>'
                        f"</{name}>")

    def flag(name: str, value: Optional[bool]) -> None:
        if value is not None:
            el[name] = (f'<{name} type="Normal"><mcpttBoolean>'
                        f'{"true" if value else "false"}</mcpttBoolean></{name}>')

    uri("mcptt-request-uri", info.request_uri)
    uri("mcptt-calling-user-id", info.calling_user_id)
    uri("mcptt-called-party-id", info.called_party_id)
    uri("mcptt-calling-group-id", info.calling_group_id)
    if not adhoc:
        flag("emergency-ind", info.emergency)
    flag("imminentperil-ind", info.imminent_peril)
    if info.broadcast is not None:
        el["broadcast-ind"] = f"<broadcast-ind>{'true' if info.broadcast else 'false'}</broadcast-ind>"
    uri("mcptt-client-id", info.client_id)
    if adhoc and info.emergency is not None:
        el["anyExt"] = (f"<anyExt><adhoc-emergency-ind>"
                        f"{'true' if info.emergency else 'false'}"
                        f"</adhoc-emergency-ind></anyExt>")
    body = "".join(el[k] for k in _PARAMS_ORDER if k in el)
    return (f'<?xml version="1.0" encoding="UTF-8"?>\r\n'
            f'<mcpttinfo xmlns="{NAMESPACE}"><mcptt-Params>{body}'
            f"</mcptt-Params></mcpttinfo>\r\n")


def reachability(call_types: Sequence[object], release: Release
                 ) -> Tuple[Tuple[str, ...], Tuple[Tuple[str, str], ...]]:
    """(not requestable by declaration, unreachable at this release).

    The first are call types a profile declares with no signature. The second
    have one that `release` cannot carry -- an ad hoc call type at Rel-17 --
    so no conformant client of this deployment can ask for them.
    """
    undeclared, blocked = [], []
    for ct in call_types:
        sig = getattr(ct, "mc_signature", None)
        if sig is None:
            undeclared.append(ct.id)
        elif not supports_session_type(release, sig.session_type):
            blocked.append((ct.id, f"session-type {sig.session_type!r} is not in {release}"))
        elif (sig.session_type == "adhoc" and sig.emergency
              and not supports_mc_indicator(release, "adhoc-emergency-ind")):
            blocked.append((ct.id, f"{release} has no ad hoc emergency indication"))
    return tuple(undeclared), tuple(blocked)
