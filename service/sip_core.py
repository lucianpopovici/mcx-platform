"""SIP endpoint logic: bytes-in-messages, transactions, calls.

No sockets: a `Flow` is anything with `send(text)`. That is what lets the
whole of TS-SIG be driven deterministically with a fake clock and fake flows;
`sip_tls.py` is the only file that opens a socket.

Order of work for an inbound request (PLT-SIG-004, CLAUDE-2 constraint 2):
  1. transaction match  — a retransmission is answered from the stored
     response and goes no further, so it can never be mistaken for a replay
  2. `InboundGuard.check` — before anything else that could act on the request
  3. dispatch by method

Session semantics stay in `SessionManager`; this file only turns its Signals
into messages and messages into requests.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import dataclasses
import threading
import uuid
import weakref

from core.errors import IDENTITY_NOT_AUTHENTICATED, NOT_AUTHORISED
from core.hooks import MediaKind
from core.invoke import Invoker
from core.session import Session, Signal, SignalType
from core.sip import (
    ALLOW, Adapter, DialogContext, Headers, InboundGuard, ReceivedResponse, Request,
    RegistrationStore, Response, SipError, Status, build_sdp, canonical_uri,
    negotiate,
    parse_message, parse_sdp,
    OPTION_TIMER, SUPPORTED_ON_ANSWER, SUPPORTED_ON_PROVISIONAL, allows,
    parse_min_se, uac_session_timer, uas_session_timer,
)

from core import mcinfo
from core.mcinfo import sdp_of

from .media import MediaSession, UdpMediaPlane
from .runtime import Runtime
from .session_timer import DialogTimer
from .sip_txn import (ClientTransactions, ClientTxn, ServerTransactions,
                      ServerTxn, cseq_of, top_branch)

log = logging.getLogger("mcx.sip")

ALLOWED = ALLOW          # core/sip.py: UPDATE added for RFC 4028 refresh
_ECHOED = ("via", "from", "to", "call-id", "cseq")
_STATUS_BY_CODE = {s.code: s for s in Status}
_EXPIRES_PARAM = re.compile(r";\s*expires=(\d+)", re.I)
_DEFAULT_REGISTER_S = 3600     # RFC 3261 §10.2: protocol default, not policy


@dataclass
class Leg:
    uri: str
    call_id: str
    flow: Any
    txn: Optional[ClientTxn] = None
    state: str = "inviting"          # inviting | ringing | confirmed | failed
    to_tag: str = ""
    cseq: int = 1
    invite_cseq: int = 1              # the INVITE's; its ACKs carry it
    # RFC 3261 12.1.2, from the 2xx: where in-dialog requests on this leg go.
    remote_target: str = ""
    route_set: List[str] = field(default_factory=list)
    # The ACK sent for each 2xx dialog on this leg, by To tag, so that a
    # retransmitted 2xx is answered with the same ACK (RFC 3261 13.2.2.4).
    # The leg's own dialog is `to_tag`; any other tag is a fork that was
    # ACKed and then ended with a BYE.
    acks: Dict[str, str] = field(default_factory=dict)
    # RFC 3261 9.1: "" -- not cancelled; "pending" -- owed a CANCEL, which
    # waits for a provisional response; "sent".
    cancel: str = ""
    # RFC 4028 (CA-20b, SIP-OP-17). What the leg's INVITE offered and asked
    # for, the answer it got, and the dialog's session timer once answered.
    sig: Any = None
    offer_sdp: str = ""
    remote_sdp: str = ""
    session_expires: int = 0
    min_se: int = 0
    answer_by: Optional[int] = None
    timer: Optional[DialogTimer] = None
    refresh: Any = None                # a Refresh the platform sent, pending
    remote_cseq: int = 0               # the callee's last in-dialog CSeq
    peer_allows_update: bool = False
    awaiting_answer: bool = False      # our offer (offerless re-INVITE) awaits the ACK
    retired: Any = field(default_factory=weakref.WeakSet)   # connections it left


@dataclass
class Call:
    cid: str
    invite: Request
    sr: Any
    txn: ServerTxn
    flow: Any
    initiator: str
    legs: Dict[str, Leg] = field(default_factory=dict)   # by leg Call-ID
    answered: bool = False
    ended: bool = False
    skip_bye_to: Optional[str] = None
    bye_sent_to_initiator: bool = False
    cseq_out: int = 0
    media: Optional[MediaSession] = None
    payload_type: Optional[int] = None
    media_error: Optional[str] = None
    # RFC 3261 12.1.1, from the INVITE: where requests toward the initiator go.
    remote_target: str = ""
    route_set: List[str] = field(default_factory=list)
    # TS 24.379 clause 4.5: a GRUU (RFC 5627) hosted here, unique to this
    # session, carrying neither MCPTT ID nor group ID. It is the Contact of
    # every dialog of the call (CA-20b).
    session_uri: str = ""
    # RFC 4028: the timer negotiated on the INVITE, and the dialog's timer
    # once the 200 OK is sent; the SDP the platform answered with.
    st: Any = None
    timer: Optional[DialogTimer] = None
    refresh: Any = None
    remote_cseq: int = 0
    peer_allows_update: bool = False
    answer_sdp: str = ""
    awaiting_answer: bool = False
    retired: Any = field(default_factory=weakref.WeakSet)


@dataclass
class Refresh:
    """A session refresh the platform sent on one dialog (RFC 4028 section
    10): the call, the leg (None: the initiator's dialog), and the ACK sent
    for a re-INVITE's 2xx, re-sent for each retransmission of it."""
    call: Call
    leg: Optional[Leg]
    seconds: int
    ack: str = ""
    method: str = "UPDATE"
    txn: Any = None


@dataclass
class AwaitingAnswer:
    """An offerless re-INVITE the platform answered with an offer: the ACK
    carries the peer's answer (RFC 3261 14.2)."""
    call: Call
    leg: Optional[Leg]


def _header_values(values) -> List[str]:
    """Split header field values on the commas that separate them, never on
    commas inside <...> or "..." (RFC 3261 7.3.1). Record-Route may arrive
    as several header lines, one comma-joined line, or both."""
    out: List[str] = []
    for raw in values:
        depth, quoted, escaped, start = 0, False, False, 0
        for i, ch in enumerate(raw):
            if escaped:                      # quoted-pair, RFC 3261 25.1
                escaped = False
            elif quoted and ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = not quoted
            elif not quoted and ch == "<":
                depth += 1
            elif not quoted and ch == ">":
                depth -= 1
            elif ch == "," and not quoted and depth == 0:
                if raw[start:i].strip():
                    out.append(raw[start:i].strip())
                start = i + 1
        if raw[start:].strip():
            out.append(raw[start:].strip())
    return out


def _addr_uri(value: str) -> str:
    """The URI of a name-addr WITH its URI parameters (RFC 3261 20.10).

    `_uri` below strips everything after the first ';', which is right for
    an address-of-record and wrong for a Contact or a Record-Route: the ';lr'
    that says a proxy loose-routes and the ';transport=tls' that says how to
    reach a UE are URI parameters. The first dialog-routing fix used `_uri`
    here, so every route looked strict and every remote target lost its
    transport, and Kamailio delivered neither ACK nor BYE to the callee.
    """
    text = value or ""
    quoted, escaped = False, False
    for i, ch in enumerate(text):        # the first '<' outside a display name
        if escaped:
            escaped = False
        elif quoted and ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif ch == "<" and not quoted:
            end = text.find(">", i)
            if end > i:
                return text[i + 1:end].strip()
    # addr-spec with no <>: parameters after ';' are header parameters.
    return text.split(";")[0].strip()


def _uri_params(uri: str) -> str:
    """The parameter part of a SIP URI: after the host, before any ?headers.
    Searching the whole URI would find ';lr' in a user part (sip:a;lr@h)."""
    uri = uri.split("?", 1)[0]
    hostpart = uri.rsplit("@", 1)[-1]
    return hostpart[hostpart.find(";"):] if ";" in hostpart else ""


def _request_uri_form(uri: str) -> str:
    """RFC 3261 12.2.1.1 / 19.1.1: a route URI used as a Request-URI loses the
    parameters a Request-URI may not carry -- method and any ?headers."""
    uri = uri.split("?", 1)[0]
    return re.sub(r";method=[^;]*", "", uri, flags=re.I)


def dialog_target(remote_target: str, route_set: List[str]) -> Tuple[str, List[str]]:
    """Request-URI and Route header values for a request within a dialog,
    RFC 3261 12.2.1.1.

    Loose routing (first route carries ;lr): the Request-URI is the remote
    target and every route is sent as a Route header. Strict routing: the
    Request-URI is the first route's URI, and the remote target is appended
    as the last Route. With no route set, the Request-URI is the remote target.

    Before this, the platform sent every in-dialog request to the peer's
    address-of-record with no Route at all. That works when nothing sits
    between the platform and the peer, which is true of every test in this
    repository and of no IMS deployment: run against Kamailio (VP1-SIG-001),
    both ACKs of an answered call were dropped by the proxy.
    """
    if not route_set:
        return remote_target, []
    first = _addr_uri(route_set[0])
    if re.search(r";lr(?:[;=]|$)", _uri_params(first), re.I):
        return remote_target, list(route_set)
    return _request_uri_form(first), list(route_set[1:]) + [f"<{remote_target}>"]


def _offer_of(invite: Request) -> str:
    """The SDP part of an INVITE. A conformant MCPTT INVITE's body is
    multipart/mixed (SDP plus the MCPTT info body); treating the whole body
    as SDP worked only for the format this platform invented (CA-20)."""
    try:
        return sdp_of(invite.headers.get("Content-Type") or "", invite.body)
    except ValueError as exc:
        raise SipError(str(exc)) from None


_TAG_KEY = secrets.token_bytes(32)


def _tag(seed: str) -> str:
    """The platform's tag for a dialog it answers. Keyed with a per-process
    secret: a plain hash of the Call-ID could be computed by any callee,
    which learns the caller's Call-ID from its own leg's, and so could forge
    the caller's side of the dialog on a shared (core) connection (review of
    SIP-OP-17)."""
    return "mcx-" + hmac.new(_TAG_KEY, seed.encode(), hashlib.sha256).hexdigest()[:16]


class SipCore:
    def __init__(self, runtime: Runtime, local_uri: str, clock,
                 t1: int = 500, media: Optional[UdpMediaPlane] = None) -> None:
        self.rt = runtime
        # One lock for everything that touches core state: SIP, media and
        # timers all run under it.
        self.lock = threading.RLock()
        media_cfg = runtime.config.media
        if media is None:
            if media_cfg is None:
                raise ValueError("SIP requires a media plane (MCX_MEDIA_*)")
            media = UdpMediaPlane(media_cfg.address, media_cfg.ports, clock,
                                  runtime.config.release, self.lock)
        else:
            media.lock = self.lock
        self.media = media
        self._codecs = {c.payload_type: c.name
                        for c in runtime.loaded.profile.media.codecs}
        # How long an invited member may ring, per call type (SIP-OP-15).
        self._no_answer_s = {ct.id: ct.no_answer_s
                             for ct in runtime.loaded.profile.call_types}
        self.local_uri = local_uri
        self.clock = clock
        self.adapter = Adapter(local_uri, runtime.config.release,
                               runtime.loaded.profile.call_types)
        self.guard = InboundGuard()
        self.registrations = RegistrationStore(clock)
        self.server = ServerTransactions(clock, t1=t1)
        self.client = ClientTransactions(clock, t1=t1)
        self.flows_by_user: Dict[str, Any] = {}
        sip_cfg = runtime.config.sip
        if sip_cfg is None:
            raise ValueError("SIP requires MCX_SIP_* configuration")
        # RFC 4028: the interval asked for, and the cap on a longer one.
        self._session_expires = sip_cfg.session_expires
        # From the network profile (ICD-OP-08, ICD-OP-10).
        self._trusted_cores = set(runtime.network.trusted_cores)
        self.calls: Dict[str, Call] = {}
        self._dialogs: Dict[str, Call] = {}       # any Call-ID -> its call
        self._pending: Dict[str, Call] = {}
        self._branch_seq = 0
        self.counters = {"dropped_malformed": 0, "guard_rejected": 0}
        runtime.on_signals = self._consume

    # -- ingress -----------------------------------------------------------

    def on_bytes(self, data: bytes, flow: Any) -> None:
        """One complete framed message."""
        try:
            message = parse_message(data)
        except SipError as exc:
            # Not parseable at all, so there is nothing to echo a response to.
            self.counters["dropped_malformed"] += 1
            log.warning("dropped unparseable message: %s", exc)
            return
        if isinstance(message, ReceivedResponse):
            try:
                self._on_response(message, flow)
            except Exception:  # noqa: BLE001 - one bad response, not the flow
                # Requests are guarded in _on_request; a fault here would
                # otherwise end the reader of this connection, and with a
                # trusted core that is every user behind it (review of
                # SIP-OP-17).
                log.exception("fault handling a %s response", message.code)
        else:
            self._on_request(message, flow)

    def on_flow_closed(self, flow: Any) -> None:
        for uri in [u for u, f in self.flows_by_user.items() if f is flow]:
            del self.flows_by_user[uri]

    def _on_request(self, req: Request, flow: Any) -> None:
        # 1 — retransmission?
        if req.method == "ACK":
            acked = self.server.absorb_ack(req, flow)
            if acked is None:
                log.info("stray ACK dropped call-id=%s",
                         req.headers.get("Call-ID"))
            elif isinstance(acked.user, AwaitingAnswer):
                waiting = acked.user
                if self._dialog_for(req, flow, acking=True) != (waiting.call, waiting.leg):
                    # absorb_ack matched Call-ID, CSeq and connection, not the
                    # tags; on a shared core connection that is not enough to
                    # let this ACK move anyone's media (review of SIP-OP-17).
                    # Nor to confirm the transaction: the genuine ACK must
                    # still match it (re-review of SIP-OP-17).
                    self.server.unconfirm(acked)
                    log.warning("ACK with foreign tags for call-id=%s ignored",
                                req.headers.get("Call-ID"))
                    return
                acked.user = None
                state = waiting.leg if waiting.leg is not None else waiting.call
                state.awaiting_answer = False
                try:
                    self._apply_answer(waiting.call, waiting.leg, req)
                except Exception:  # noqa: BLE001
                    log.exception("fault applying an ACK answer")
            return
        seen = self.server.match(req)
        if seen is not None:
            if seen.last_response:
                seen.flow.send(seen.last_response)
            return
        txn = self.server.create(req, flow)

        # 2 — the guard, before anything acts on the request
        rejection = self.guard.check(req, known_sessions=tuple(self._dialogs))
        if rejection is not None:
            self.counters["guard_rejected"] += 1
            return self._final(txn, rejection)

        # 3 — dispatch
        handler = {"REGISTER": self._register, "INVITE": self._invite,
                   "BYE": self._bye, "CANCEL": self._cancel,
                   "UPDATE": self._in_dialog,
                   "OPTIONS": self._options}.get(req.method)
        if handler is None:
            resp = Response(Status.NOT_IMPLEMENTED,
                            Headers([("Allow", ALLOWED)]))
            return self._final(txn, resp)
        try:
            handler(req, txn, flow)
        except SipError as exc:
            self._final(txn, Response(Status.BAD_REQUEST,
                                      Headers([("Warning", f'399 mcx "{_quoted(exc)}"')])))
        except Exception:  # noqa: BLE001 - a fault: 500, never a refusal
            log.exception("fault handling %s", req.method)
            self._final(txn, Response(Status.SERVER_ERROR))

    # -- responses to inbound requests ----------------------------------------

    def _echo(self, req: Request, resp: Response) -> str:
        """Address `resp` as a reply to `req` (RFC 3261 §8.2.6.2).

        `Adapter` builds responses with its own Via/From/To; a reply must echo
        the request's, and carry a To tag from the first non-100 response on.
        """
        h = Headers()
        for v in req.headers.get_all("Via"):
            h.add("Via", v)
        for name in ("From", "To", "Call-ID", "CSeq"):
            value = req.headers.get(name) or ""
            if name == "To" and resp.status.code > 100 and "tag=" not in value:
                value += f";tag={_tag(req.headers.get('Call-ID') or '')}"
            h.add(name, value)
        # RFC 3261 12.1.1: a UAS copies every Record-Route value, in order,
        # into each response that can create a dialog. Without it the
        # initiator has no route set, and its ACK and BYE reach the proxy
        # with no Route header -- which Kamailio, correctly, dropped.
        if req.method == "INVITE" and 100 < resp.status.code < 300 \
                and not _tag_of(req.headers.get("To")):
            # A re-INVITE does not change the route set (12.2).
            for v in _header_values(req.headers.get_all("Record-Route")):
                h.add("Record-Route", v)
        for n, v in resp.headers.items():
            if n.lower() not in _ECHOED and n.lower() != "max-forwards":
                h.add(n, v)
        return Response(resp.status, h, resp.body).render()

    def _provisional(self, txn: ServerTxn, resp: Response) -> None:
        text = self._echo(txn.request, resp)
        self.server.respond(txn, text, resp.status.code)
        txn.flow.send(text)

    _final = _provisional      # same path; `respond` arms timers for >= 200

    def _reject(self, txn: ServerTxn, reason_code: str,
                invite: Optional[Request] = None,
                authorisation: bool = False) -> None:
        ctx = DialogContext(call_id=txn.call_id, local_uri=self.local_uri)
        self._final(txn, self.adapter.reject(reason_code, ctx, invite,
                                             authorisation=authorisation))

    # -- REGISTER / OPTIONS ----------------------------------------------------

    def _options(self, req, txn, flow) -> None:
        self._final(txn, Response(Status.OK, Headers([("Allow", ALLOWED)])))

    def _register(self, req: Request, txn: ServerTxn, flow: Any) -> None:
        # Canonical form (scheme and host lower-cased, RFC 3261 19.1.4), so
        # the domain check, the store and call routing agree on one key.
        aor = canonical_uri(_uri(req.headers.get("To") or ""))
        contact = req.headers.get("Contact") or ""
        if not aor:
            raise SipError("REGISTER has no To")
        domain = aor.rpartition("@")[2]
        if domain not in self.rt.loaded.profile.identity.domains:
            return self._reject(txn, NOT_AUTHORISED)       # PLT-IDM-008
        if not self._authenticated_as(flow, aor):
            # Registering someone else's address would route their calls here.
            return self._reject(txn, IDENTITY_NOT_AUTHENTICATED)
        expires_s = req.headers.get("Expires")
        m = _EXPIRES_PARAM.search(contact)
        seconds = int(m.group(1)) if m else (
            int(expires_s) if expires_s and expires_s.isdigit()
            else _DEFAULT_REGISTER_S)
        if seconds == 0:
            self.registrations.deregister(aor)
            self.flows_by_user.pop(aor, None)
        else:
            self.registrations.register(aor, _uri(contact) or aor,
                                        seconds * 1000)
            self.flows_by_user[aor] = flow
        self._final(txn, Response(Status.OK, Headers([("Expires", str(seconds))])))

    # -- INVITE (initiator side) ---------------------------------------------

    def _authenticated_as(self, flow: Any, identity: str) -> bool:
        """ICD-OP-08 (decided 2026-09-25), PLT-IDM-004 in its R1 form.

        A peer whose certificate the network's core CA issued, carrying a
        DNS name the network profile lists in sip.trusted_cores, is a SIP
        core that authenticated its users itself: it may assert any identity
        (RFC 3325 trust domain). Both are needed (ICD-OP-10): the name says
        which core, the issuer says it is one. The core CA vouches for cores
        and nothing else: a certificate it issued asserts no user identity,
        so a core taken off the list asserts nothing at all. Any other peer
        may assert only a sip: URI in its own certificate's subjectAltName. A
        peer without a certificate can assert nothing.
        """
        if getattr(flow, "peer_is_core", False):
            return bool(set(getattr(flow, "peer_dns", ())) & self._trusted_cores)
        return canonical_uri(identity) in getattr(flow, "peer_uris", ())

    def _invite(self, req: Request, txn: ServerTxn, flow: Any) -> None:
        if _tag_of(req.headers.get("To")):
            # A To tag: a request within a dialog, a re-INVITE (SIP-OP-17).
            return self._in_dialog(req, txn, flow)
        sr = self.adapter.parse_invite(req)
        if not self._authenticated_as(flow, sr.initiator):
            # Checked before anything is established or anyone invited: the
            # initiator's identity decides priority, roles and admission.
            return self._reject(txn, IDENTITY_NOT_AUTHENTICATED)
        if sr.request_id in self._dialogs or sr.request_id in self.calls:
            # A new INVITE reusing a live call's Call-ID would replace that
            # call in every table keyed by it: its BYE would then end the
            # newcomer's call, and the original would be orphaned (review of
            # ICD-OP-08). Re-INVITE is not supported, so this is refused.
            return self._final(txn, Response(Status.BAD_REQUEST, Headers(
                [("Warning", '399 mcx "Call-ID of a call in progress"')])))
        if self.adapter.invalid_adhoc_indications(req):
            # TS 24.379 17.4.2.2 step 3A (6.3.3.1.25): an ad hoc call is an
            # emergency or an imminent peril one, never both. Checked on the
            # request alone, before authorisation, as the step order says.
            ctx = DialogContext(call_id=txn.call_id, local_uri=self.local_uri)
            return self._final(txn, self.adapter.reject_invalid_combination(ctx))
        # RFC 4028 section 9, before anything is established: an interval
        # below 90 s is answered 422 with the Min-SE (CA-20b).
        st = uas_session_timer(req.headers, self._session_expires)
        if isinstance(st, int):
            return self._final(txn, Response(Status.SESSION_INTERVAL_TOO_SMALL,
                                             Headers([("Min-SE", str(st))])))
        call = Call(cid=sr.request_id, invite=req, sr=sr, txn=txn, flow=flow,
                    initiator=sr.initiator,
                    remote_target=_addr_uri(req.headers.get("Contact") or "") or sr.initiator,
                    route_set=_header_values(req.headers.get_all("Record-Route")),
                    session_uri=self._session_identity(), st=st,
                    remote_cseq=cseq_of(req.headers)[0],
                    peer_allows_update=allows(req.headers, "UPDATE"))
        self._provisional(txn, Response(Status.TRYING))
        self._pending[call.cid] = call
        try:
            session, signals, refusal = self.rt.establish(sr)
        except Exception:
            self._pending.pop(call.cid, None)
            # Legs invited before the fault must not be left ringing.
            self._cancel_unanswered(call)
            self._undo(call.cid, "establishment fault")
            raise
        finally:
            self._pending.pop(call.cid, None)
        if refusal is not None:
            # Nothing was established: no session, no persisted record, no legs.
            return self._reject(txn, refusal.reason_code, invite=req,
                                authorisation=refusal.step == "authorise")
        # `_consume` (called from establish) has created the legs.
        if call.media_error:
            return self._fail_call(call, Status.NOT_ACCEPTABLE_HERE,
                                   call.media_error)
        if all(l.state == "failed" for l in call.legs.values()):
            self._fail_call(call, Status.TEMPORARILY_UNAVAILABLE,
                            "no invitation could be delivered")

    def _consume(self, session: Session, signals: Tuple[Signal, ...]) -> None:
        """The seam `SessionManager` signals arrive at."""
        call = self._pending.get(session.correlation_id) \
            or self.calls.get(session.correlation_id)
        if call is None:
            return
        if call.cid in self._pending and call.media is None \
                and call.media_error is None:
            self._media_open(call, session)
        for sig in signals:
            if sig.type is SignalType.INVITE and call.cid in self._pending:
                self._invite_leg(call, sig)
            elif sig.type is SignalType.BYE:
                self._bye_leg(call, sig)
        if call.cid in self._pending:
            self.calls[call.cid] = call
            self._dialogs[call.cid] = call

    def _media_open(self, call: Call, session: Session) -> None:
        """Anchor media at the platform (VP1-MED-001/003/004).

        The initiator's offer is checked against the PROFILE's codecs, and one
        payload type is chosen for the whole session: with no transcoding, a
        group only works if every party uses the same one.
        """
        if MediaKind.VOICE not in call.sr.media or session.floor is None:
            return
        try:
            offer = _offer_of(call.invite)
            info = parse_sdp(offer)
        except SipError as exc:
            call.media_error = f"unusable SDP offer: {exc}"
            return
        pt = negotiate(offer, tuple(self._codecs))
        if pt is None:
            call.media_error = "no codec in the offer is declared by the profile"
            return
        ms = self.media.open(call.cid, session.floor, pt,
                             self._priority_of(session))
        ms.add(call.initiator)
        ms.set_remote(call.initiator, (info.address, info.audio_port),
                      (info.address, info.floor_port) if info.floor_port else None)
        call.media, call.payload_type = ms, pt

    def _priority_of(self, session: Session):
        """A participant's floor priority, from IF-PRI (PLT-FC-005)."""
        cache: Dict[str, int] = {}

        def priority(uri: str) -> int:
            if uri not in cache:
                if uri == session.request.initiator:
                    cache[uri] = session.priority.floor_priority
                else:
                    request = dataclasses.replace(session.request, initiator=uri)
                    decision = Invoker(self.rt.auditor, session.correlation_id).call(
                        "IF-PRI", "evaluate",
                        self.rt.loaded.hooks.priority_policy.evaluate,
                        request, session.resolution)
                    cache[uri] = decision.floor_priority
            return cache[uri]
        return priority

    def _relay_sdp(self, call: Call, uri: str) -> str:
        ep = call.media.endpoints[uri]                       # type: ignore[union-attr]
        return build_sdp(self.media.address, ep.rtp_port, ep.floor_port,
                         [(call.payload_type, self._codecs[call.payload_type])])

    def _invite_leg(self, call: Call, sig: Signal) -> None:
        if call.media_error:
            return
        target = sig.target or ""
        flow = self.flows_by_user.get(target)
        # Random, not "<call>.legN": every member would otherwise know the
        # caller's Call-ID and every other leg's, and with them the platform's
        # tag on each ("<Call-ID>-l"). The tags are part of what binds a dialog
        # to its party (review of the reconnect decision, SIP-OP-18 item 6).
        leg = Leg(uri=target, call_id=f"mcx-{secrets.token_hex(12)}", flow=flow)
        if flow is None:
            # Unregistered, or its flow is gone: the leg is dead on arrival.
            leg.state = "failed"
            call.legs[leg.call_id] = leg
            return
        sdp = _offer_of(call.invite)
        if call.media is not None:
            call.media.add(target)
            sdp = self._relay_sdp(call, target)
        secs = self._no_answer_s.get(call.sr.call_type)
        leg.sig, leg.offer_sdp = sig, sdp
        leg.session_expires = self._session_expires
        leg.answer_by = self.clock() + secs * 1000 if secs else None
        call.legs[leg.call_id] = leg
        self._dialogs[leg.call_id] = call
        self._send_leg_invite(call, leg, cseq=1)

    def _send_leg_invite(self, call: Call, leg: Leg, cseq: int) -> None:
        """The leg's INVITE: the focus Contact with the session identity,
        Supported: timer and Session-Expires (6.3.3.1.2 items 1, 6, 7), and
        the Min-SE a 422 imposed on a retry (RFC 4028 7.4)."""
        ctx = DialogContext(call_id=leg.call_id, local_uri=self.local_uri,
                            cseq=cseq, sdp=leg.offer_sdp,
                            session_uri=call.session_uri,
                            session_expires=leg.session_expires,
                            min_se=leg.min_se)
        leg.invite_cseq = leg.cseq = ctx.cseq
        req = self._with_branch(self.adapter.render(leg.sig, ctx, call.sr))
        leg.state = "inviting"
        leg.txn = self.client.start(req, leg.flow, user=leg,
                                    answer_by=leg.answer_by)
        leg.flow.send(req.render())

    def _session_identity(self) -> str:
        """A public GRUU on the server's own address of record, its `gr`
        value an opaque instance identifier (RFC 5627 3.1; TS 24.379 4.5)."""
        return f"{self.local_uri};gr=urn:uuid:{uuid.uuid4()}"

    def _contact(self, call: Call) -> str:
        media = tuple(getattr(call.sr, "media", ()) or ()) or (MediaKind.VOICE,)
        return self.adapter.focus_contact(call.session_uri, media)

    def _with_branch(self, req: Request) -> Request:
        # Unique AND unguessable: responses are matched to transactions by
        # branch, and a guessable one let any peer answer for a callee.
        self._branch_seq += 1
        headers = Headers(req.headers.items())
        via = headers.get("Via") or ""
        branch = f"z9hG4bKmcx{self._branch_seq}.{secrets.token_hex(8)}"
        headers.set("Via", re.sub(r"branch=[^;,\s]+", f"branch={branch}", via))
        return Request(req.method, req.uri, headers, req.body)

    # -- responses from callees --------------------------------------------------

    def _on_response(self, resp: ReceivedResponse, flow: Any) -> None:
        txn = self.client.match(resp)
        if txn is None:
            log.info("response with no transaction dropped code=%s", resp.code)
            return
        if txn.flow is not flow and isinstance(txn.user, Refresh) and \
                flow in (txn.user.leg or txn.user.call).retired:
            # The platform's refresh went out on a connection the dialog has
            # since left, and is answered there (RFC 3261 18.2.2); its 2xx is
            # ACKed there too, and otherwise ignored (review of SIP-OP-18
            # item 6, N4).
            txn.flow = flow
        if txn.flow is not flow or resp.headers.get("Call-ID") != \
                txn.request.headers.get("Call-ID"):
            # A response belongs to the connection its request went out on,
            # and to that request's Call-ID. Otherwise any peer could answer
            # for a callee (review of ICD-OP-08).
            self.counters["foreign_response"] = self.counters.get("foreign_response", 0) + 1
            log.warning("response from another flow or Call-ID dropped code=%s",
                        resp.code)
            return
        if isinstance(txn.user, Refresh):
            return self._refresh_response(txn, resp)
        if txn.user is None:
            # A BYE that ended a stray forked dialog: nothing waits on it.
            if resp.code >= 200:
                self.client.finish(txn)
            return
        leg: Leg = txn.user
        if txn.accepted:
            # RFC 6026 7.2: in 'Accepted' a 2xx is passed up to the UAC core.
            # A 3xx-6xx after a 2xx has no defined use there and is dropped.
            if 200 <= resp.code < 300:
                self._2xx_again(leg, resp)
            return
        if txn.method == "INVITE" and resp.code >= 300:
            # What the UAC owes the callee does not depend on whether the call
            # still exists: a 3xx-6xx is ACKed by the transaction.
            self._ack_non_2xx(txn, resp)
        if txn.method == "INVITE" and resp.code < 200:
            self.client.proceed(txn)
            if leg.cancel == "pending":
                # The call ended before this callee said anything; a CANCEL
                # could not be sent until now (RFC 3261 9.1).
                self._send_cancel(leg)
                return
            if leg.cancel:
                return            # already CANCELled: its ringing changes nothing
        if txn.method == "INVITE" and 200 <= resp.code < 300 and leg.cancel:
            # A 2xx that crossed our CANCEL: the callee answered a call this
            # leg no longer belongs to. ACK it and end it (9.1, 13.2.2.4) --
            # it must not join, even if the call itself goes on.
            self.client.accept(txn)
            self._end_stray_dialog(leg, resp)
            return
        call = self._dialogs.get(leg.call_id)
        if call is None or call.ended:
            if txn.method == "INVITE" and 200 <= resp.code < 300:
                # Answered after the call ended (the initiator hung up while
                # this leg rang): accept the dialog and end it at once.
                self.client.accept(txn)
                self._end_stray_dialog(leg, resp)
            elif resp.code >= 200:
                self.client.finish(txn)
            return
        if txn.method == "BYE":
            if resp.code >= 200:
                self.client.finish(txn)
            return
        if txn.method == "INVITE" and resp.code == 422 \
                and self._retry_leg_422(call, leg, resp):
            return
        if resp.code < 200:
            leg.state = "ringing"
            if resp.code in (180, 183) and not call.answered:
                # 6.3.2.1.5.1 items 1-2, 6.3.3.2.3.1 items 3-4.
                self._provisional(call.txn, Response(Status.RINGING, Headers([
                    ("Contact", self._contact(call)),
                    ("Supported", ", ".join(SUPPORTED_ON_PROVISIONAL))])))
            return
        if resp.code < 300:
            self.client.accept(txn)
            self._leg_answered(call, leg, resp)
        else:
            self.client.finish(txn)
            leg.state = "failed"
            self._maybe_fail(call, resp.code)

    def _leg_answered(self, call: Call, leg: Leg, resp: ReceivedResponse) -> None:
        leg.to_tag, leg.remote_target, leg.route_set = self._dialog_of(leg, resp)
        leg.state = "confirmed"
        self._send_ack(call, leg)
        leg.remote_sdp = resp.body
        leg.peer_allows_update = allows(resp.headers, "UPDATE")
        self._start_leg_timer(leg, resp)
        body = resp.body
        if call.media is not None:
            try:
                info = parse_sdp(resp.body)
                usable = call.payload_type in info.payload_types
            except SipError:
                usable = False
            if not usable:
                # The callee answered with a codec we did not offer (or no
                # media at all). Hang it up rather than relay what we cannot
                # constrain.
                self._bye_leg(call, Signal(SignalType.BYE, target=leg.uri))
                leg.state = "failed"
                self._maybe_fail(call, 488)
                return
            call.media.set_remote(leg.uri, (info.address, info.audio_port),
                                  (info.address, info.floor_port)
                                  if info.floor_port else None)
            body = self._relay_sdp(call, call.initiator)
        if not call.answered:
            call.answered = True
            call.answer_sdp = body
            headers = self._answer_headers(call)
            ctype = "application/sdp" if body else ""
            if call.sr.adhoc:
                ctype, body = self._adhoc_answer(call, body)
            if body:
                headers.add("Content-Type", ctype)
            self._final(call.txn, Response(Status.OK, headers, body))
            if call.st is not None:
                # RFC 4028 section 9: the timer runs from the 2xx.
                call.timer = DialogTimer.start(self.clock(), call.st.seconds,
                                               call.st.refresher == "uas",
                                               own=not call.st.peer_supports)
            if call.media is not None:
                # The floor starts now, when the call is answered, not when it
                # was admitted: its timers must not run while callees ring.
                call.media.apply(self.rt.manager.start_floor(call.cid))

    def _answer_headers(self, call: Call) -> Headers:
        """The 200 OK to the originator: 6.3.3.2.3.2 items 2-3 and 5-10,
        6.3.2.1.5.2 items 1-5 (CA-20b)."""
        h = Headers([("Contact", self._contact(call)),
                     ("Supported", ", ".join(SUPPORTED_ON_ANSWER)),
                     ("Allow", ALLOW)])
        self._timer_headers(h, call.st)
        return h

    @staticmethod
    def _timer_headers(h: Headers, st: Any) -> None:
        """RFC 4028 section 9: Session-Expires with the refresher, and
        Require: timer when the peer supports it (never otherwise)."""
        if st is None:
            return
        h.add("Session-Expires", f"{st.seconds};refresher={st.refresher}")
        if st.peer_supports:
            h.add("Require", OPTION_TIMER)

    def _start_leg_timer(self, leg: Leg, resp: ReceivedResponse) -> None:
        """RFC 4028 section 7.2: the callee's 2xx says who refreshes. No
        Session-Expires: the callee runs no timer, and the dialog has none."""
        try:
            st = uac_session_timer(resp.headers)
        except SipError as exc:
            log.warning("unusable Session-Expires from %s: %s", leg.uri, exc)
            st = None
        if st is None:
            # RFC 4028 7.2: the callee runs no timer. The platform keeps one
            # of its own and refreshes at the deployment's interval, so a
            # callee that vanished is still found out (review of SIP-OP-17).
            leg.timer = DialogTimer.start(self.clock(), self._session_expires,
                                          True, min_se=leg.min_se, own=True)
        else:
            leg.timer = DialogTimer.start(self.clock(), st.seconds,
                                          st.refresher == "uac", min_se=leg.min_se)

    def _retry_leg_422(self, call: Call, leg: Leg, resp: ReceivedResponse) -> bool:
        """RFC 4028 7.4: a 422 asks for at least its Min-SE; the INVITE is
        re-sent once, with that interval and that Min-SE. The 422 was ACKed
        by the transaction already."""
        if call is None or call.ended or leg.cancel or leg.min_se \
                or leg.flow is None:
            return False
        try:
            min_se = parse_min_se(resp.headers.get("Min-SE"))
        except SipError:
            return False
        if not min_se or min_se <= leg.session_expires or min_se > 86_400:
            return False
        leg.session_expires = leg.min_se = min_se
        self._send_leg_invite(call, leg, cseq=leg.cseq + 1)
        return True

    def _adhoc_answer(self, call: Call, sdp: str) -> Tuple[str, str]:
        """TS 24.379 17.4.2.2: the 200 OK to an ad hoc caller carries an MCPTT
        info body with <mcptt-calling-group-id> set to the ad hoc group
        identity the controlling function generated, and the criteria when
        the members were determined by criteria. The caller learns the
        group's identity from nothing else."""
        session = self.rt.manager.session(call.cid)
        info = mcinfo.McInfo(
            calling_group_id=session.resolution.group_id if session else None,
            participant_criteria=call.sr.participant_criteria)
        parts = [mcinfo.Part("application/sdp", sdp)] if sdp else []
        parts.append(mcinfo.Part(mcinfo.CONTENT_TYPE,
                                 mcinfo.render(info, self.rt.config.release)))
        return mcinfo.build_multipart(parts)

    @staticmethod
    def _dialog_of(leg: Leg, resp: ReceivedResponse) -> Tuple[str, str, List[str]]:
        """RFC 3261 12.1.2: the To tag, remote target and route set a 2xx
        establishes (the route set is Record-Route, reversed, at the UAC)."""
        m = re.search(r"tag=([^;>\s]+)", resp.headers.get("To") or "")
        return (m.group(1) if m else "",
                _addr_uri(resp.headers.get("Contact") or "") or leg.uri,
                list(reversed(_header_values(resp.headers.get_all("Record-Route")))))

    def _ack_2xx(self, leg: Leg, to_tag: str, remote_target: str,
                 route_set: List[str]) -> str:
        """The ACK for a 2xx: its own transaction, sent within the dialog
        (RFC 3261 13.2.2.4). Kept, and re-sent unchanged for each
        retransmission of that 2xx."""
        h = Headers([
            ("Via", f"SIP/2.0/TLS {self.local_uri.rpartition('@')[2]};"
                    # Fixed per dialog, so a re-sent ACK is identical; the
                    # '.' keeps (call-id, tag) pairs from running together.
                    f"branch=z9hG4bKmcxack{leg.call_id}.{to_tag}"),
            ("From", f"<{self.local_uri}>;tag={leg.call_id}-l"),
            ("To", f"<{leg.uri}>;tag={to_tag}"),
            ("Call-ID", leg.call_id), ("CSeq", f"{leg.invite_cseq} ACK"),
            ("Max-Forwards", "70")])
        ruri, routes = dialog_target(remote_target or leg.uri, route_set)
        for r in routes:
            h.add("Route", r)
        text = Request("ACK", ruri, h).render()
        leg.acks[to_tag] = text
        if leg.flow is not None:
            leg.flow.send(text)
        return text

    def _send_ack(self, call: Call, leg: Leg) -> None:
        self._ack_2xx(leg, leg.to_tag, leg.remote_target, leg.route_set)

    def _2xx_again(self, leg: Leg, resp: ReceivedResponse) -> None:
        """A 2xx on an INVITE already answered: a retransmission (the ACK was
        lost on the way) gets the same ACK again; a 2xx with a new To tag is
        another fork answering, which is ACKed and ended (13.2.2.4)."""
        to_tag, _, _ = self._dialog_of(leg, resp)
        ack = leg.acks.get(to_tag)
        if ack is not None:
            if leg.flow is not None:
                leg.flow.send(ack)
            return
        self._end_stray_dialog(leg, resp)

    def _end_stray_dialog(self, leg: Leg, resp: ReceivedResponse) -> None:
        """A dialog nobody wants: ACK it, then BYE it (RFC 3261 13.2.2.4 --
        'the UAC core MUST generate an ACK ... and then send a BYE')."""
        to_tag, target, routes_rev = self._dialog_of(leg, resp)
        self._ack_2xx(leg, to_tag, target, routes_rev)
        if leg.flow is None:
            return
        h = Headers([
            ("Via", f"SIP/2.0/TLS {self.local_uri.rpartition('@')[2]};"
                    "branch=z9hG4bK-replaced"),   # _with_branch sets it
            ("From", f"<{self.local_uri}>;tag={leg.call_id}-l"),
            ("To", f"<{leg.uri}>;tag={to_tag}"),
            ("Call-ID", leg.call_id), ("CSeq", f"{leg.invite_cseq + 1} BYE"),
            ("Max-Forwards", "70")])
        ruri, routes = dialog_target(target, routes_rev)
        for r in routes:
            h.add("Route", r)
        req = self._with_branch(Request("BYE", ruri, h))
        self.client.start(req, leg.flow, user=None)
        leg.flow.send(req.render())

    def _ack_non_2xx(self, txn: ClientTxn, resp: ReceivedResponse) -> None:
        """RFC 3261 17.1.1.3: the INVITE client transaction ACKs a 3xx-6xx
        itself -- same Request-URI, Call-ID, From, Route and top Via
        (branch included) as the INVITE, CSeq number unchanged, and the To
        of the response, tag and all. The platform's flows are TLS, so
        Timer D is zero (17.1.1.2) and the transaction ends here."""
        inv: Request = txn.request
        h = Headers([("Via", (inv.headers.get_all("Via") or [""])[0]),
                     ("From", inv.headers.get("From") or ""),
                     ("To", resp.headers.get("To") or ""),
                     ("Call-ID", inv.headers.get("Call-ID") or ""),
                     ("CSeq", f"{cseq_of(inv.headers)[0]} ACK"),
                     ("Max-Forwards", "70")])
        for r in inv.headers.get_all("Route"):
            h.add("Route", r)
        txn.flow.send(Request("ACK", inv.uri, h).render())
        self.client.finish(txn)

    # -- CANCEL --------------------------------------------------------------

    def _cancel_unanswered(self, call: Call) -> None:
        """Every leg still being invited when the call ends is CANCELled
        (RFC 3261 9.1), so no callee is left ringing for a call that is gone.
        A leg that has sent no provisional response yet cannot be CANCELled
        yet; it is marked and CANCELled when one arrives."""
        for leg in call.legs.values():
            txn = leg.txn
            if leg.state not in ("inviting", "ringing") or leg.cancel \
                    or txn is None or txn.done or txn.accepted \
                    or txn.method != "INVITE":
                continue
            if txn.proceeding:
                self._send_cancel(leg)
            else:
                leg.cancel = "pending"

    def _send_cancel(self, leg: Leg) -> None:
        """RFC 3261 9.1: the INVITE's Request-URI, Call-ID, To, From and
        CSeq number; one Via, the INVITE's top Via (so the branch names the
        transaction being cancelled); the INVITE's Route headers. Its own
        non-INVITE client transaction, which nothing waits on."""
        txn = leg.txn
        inv: Request = txn.request                # type: ignore[union-attr]
        h = Headers([("Via", (inv.headers.get_all("Via") or [""])[0]),
                     ("From", inv.headers.get("From") or ""),
                     ("To", inv.headers.get("To") or ""),
                     ("Call-ID", inv.headers.get("Call-ID") or ""),
                     ("CSeq", f"{cseq_of(inv.headers)[0]} CANCEL"),
                     ("Max-Forwards", "70")])
        for r in inv.headers.get_all("Route"):
            h.add("Route", r)
        req = Request("CANCEL", inv.uri, h)
        leg.cancel = "sent"
        self.client.cancelling(txn)               # type: ignore[arg-type]
        self.client.start(req, txn.flow, user=None)   # type: ignore[union-attr]
        txn.flow.send(req.render())               # type: ignore[union-attr]

    def _cancel(self, req: Request, txn: ServerTxn, flow: Any) -> None:
        """The initiator CANCELs its INVITE (RFC 3261 9.2). The CANCEL is
        matched to the INVITE's server transaction by branch and answered
        200; if the INVITE has no final response yet it is answered 487 and
        the call is ended as a failed one, which CANCELs the legs still
        ringing. A CANCEL after the call was answered changes nothing."""
        invite_txn = self.server.find(top_branch(req.headers), "INVITE")
        # 17.2.3: the branch, AND the sent-by of the top Via; and a CANCEL
        # names its INVITE's Call-ID (9.1). A branch alone would let any
        # peer that learnt it cancel someone else's call.
        if invite_txn is None or invite_txn.flow is not flow \
                or _sent_by(req.headers) != _sent_by(invite_txn.request.headers) \
                or req.headers.get("Call-ID") != invite_txn.request.headers.get("Call-ID"):
            return self._final(txn, Response(Status.CALL_DOES_NOT_EXIST))
        self._final(txn, Response(Status.OK))
        call = self.calls.get(invite_txn.call_id)
        if call is None or call.txn is not invite_txn or call.answered \
                or call.ended:
            return
        self._fail_call(call, Status.REQUEST_TERMINATED,
                        "cancelled by the initiator")

    def _maybe_fail(self, call: Call, code: int) -> None:
        if call.answered or any(l.state in ("inviting", "ringing", "confirmed")
                                for l in call.legs.values()):
            return
        # A callee's 408 is about the callee, not the caller's request:
        # relaying it would tell the initiator its own request timed out.
        status = _STATUS_BY_CODE.get(code, Status.TEMPORARILY_UNAVAILABLE)
        if code == 408:
            status = Status.TEMPORARILY_UNAVAILABLE
        self._fail_call(call, status, f"every invited party failed (last {code})")

    def _fail_call(self, call: Call, status: Status, reason: str) -> None:
        """Final failure toward the initiator, then remove every trace of the
        session (PLT-SIG-005). The audit trail keeps the reason."""
        call.ended = True
        self._final(call.txn, Response(status, Headers(
            [("Warning", f'399 mcx "{_quoted(reason)}"')])))
        self._cancel_unanswered(call)
        self._undo(call.cid, reason)

    def _undo(self, cid: str, reason: str) -> None:
        self.rt.abandon(cid, reason)
        call = self.calls.pop(cid, None)
        self.media.close(cid)
        for cid_key in [k for k, c in self._dialogs.items()
                        if c is call or k == cid]:
            del self._dialogs[cid_key]

    # -- BYE ----------------------------------------------------------------------

    def _bye(self, req: Request, txn: ServerTxn, flow: Any) -> None:
        call = self._dialogs.get(req.headers.get("Call-ID") or "")
        if call is None:
            return self._final(txn, Response(Status.CALL_DOES_NOT_EXIST))
        call_id = req.headers.get("Call-ID")
        leg = call.legs.get(call_id or "")
        # A dialog's BYE comes from its remote party, on its connection, with
        # its tag (RFC 3261 12.2.2). Call-ID alone let any invited member --
        # who learns the call's Call-ID from its own leg's -- end the call.
        # ... or on a connection that authenticates the same party, after a
        # reconnect (decided 2026-09-25, SIP-OP-18 item 6).
        if call_id == call.cid and (
                not self._may_act(flow, call.flow, call.initiator, True, call.retired) or
                _tag_of(req.headers.get("From")) !=
                _tag_of(call.invite.headers.get("From")) or
                # From another connection, both tags (review of the reconnect
                # decision): the platform's is keyed, so only the dialog's
                # party knows it.
                (flow is not call.flow and
                 _tag_of(req.headers.get("To")) != _tag(call.cid))):
            return self._final(txn, Response(Status.CALL_DOES_NOT_EXIST))
        if leg is not None and (
                not self._may_act(flow, leg.flow, leg.uri, True, leg.retired) or
                (flow is not leg.flow and
                 _tag_of(req.headers.get("To")) != f"{leg.call_id}-l")):
            return self._final(txn, Response(Status.CALL_DOES_NOT_EXIST))
        if leg is not None:
            # RFC 3261 12.2.2: a request belongs to a dialog by Call-ID AND
            # tags. A leg's Call-ID can carry a second dialog -- a fork that
            # answered and was ACKed and ended (13.2.2.4) -- whose BYE must
            # not end the leg's own. The callee is the remote party, so its
            # tag is in From.
            m = re.search(r"tag=([^;>\s]+)", req.headers.get("From") or "")
            tag = m.group(1) if m else ""
            if tag != leg.to_tag:
                known = tag in leg.acks
                return self._final(txn, Response(
                    Status.OK if known else Status.CALL_DOES_NOT_EXIST))
        self._final(txn, Response(Status.OK))
        if call_id == call.cid:                     # the initiator hung up
            self._end(call, cause="normal", skip=call.initiator)
            return
        if leg is not None:
            leg.state = "failed"
            if not any(l.state == "confirmed" for l in call.legs.values()):
                self._end(call, cause="normal", skip=leg.uri)

    def _end(self, call: Call, cause: str, skip: Optional[str] = None) -> None:
        if call.ended:
            return
        call.ended = True
        call.skip_bye_to = skip
        self._cancel_unanswered(call)
        if call.txn.last_code < 200:
            # The initiator hung up an early dialog: its INVITE is still
            # pending and MUST be answered; 487 is the recommended answer
            # (RFC 3261 15.1.2).
            self._final(call.txn, Response(Status.REQUEST_TERMINATED))
        try:
            self.rt.release(call.cid, cause)
            # A private call's member set is the callee alone, so the
            # initiator gets no BYE from the session layer's signals.
            if skip != call.initiator and not call.bye_sent_to_initiator:
                self._bye_leg(call, Signal(SignalType.BYE, target=call.initiator))
        finally:
            self.media.close(call.cid)
            self.calls.pop(call.cid, None)
            for k in [k for k, c in self._dialogs.items() if c is call]:
                del self._dialogs[k]

    def _bye_leg(self, call: Call, sig: Signal) -> None:
        target = sig.target or ""
        if target == call.skip_bye_to:
            return
        if target == call.initiator:
            call.bye_sent_to_initiator = True
            call.cseq_out += 1
            h = Headers([
                ("Via", f"SIP/2.0/TLS {self.local_uri.rpartition('@')[2]};"
                        f"branch=z9hG4bKmcxbye{call.cid}"),
                ("From", f"<{self.local_uri}>;tag={_tag(call.cid)}"),
                ("To", call.invite.headers.get("From") or f"<{target}>"),
                ("Call-ID", call.cid),
                ("CSeq", f"{call.cseq_out} BYE"), ("Max-Forwards", "70")])
            ruri, routes = dialog_target(call.remote_target or target, call.route_set)
            for r in routes:
                h.add("Route", r)
            call.flow.send(Request("BYE", ruri, h).render())
            return
        for leg in call.legs.values():
            if leg.uri == target and leg.state == "confirmed" and leg.flow:
                leg.cseq += 1
                req = self._with_branch(self.adapter.render(
                    sig, DialogContext(call_id=leg.call_id,
                                       local_uri=self.local_uri,
                                       cseq=leg.cseq)))
                headers = Headers(req.headers.items())
                headers.set("To", f"<{leg.uri}>;tag={leg.to_tag}")
                headers.set("From", f"<{self.local_uri}>;tag={leg.call_id}-l")
                ruri, routes = dialog_target(leg.remote_target or leg.uri,
                                             leg.route_set)
                for r in routes:
                    headers.add("Route", r)
                req = Request(req.method, ruri, headers, req.body)
                leg.txn = self.client.start(req, leg.flow, user=leg)
                leg.flow.send(req.render())

    # -- in-dialog UPDATE and re-INVITE (SIP-OP-17, RFC 4028) ---------------------

    def _dialog_for(self, req: Request, flow: Any, moving: bool = False,
                    acking: bool = False):
        """(call, leg) for a request within one of the call's dialogs, or
        None. RFC 3261 12.2.2: Call-ID AND both tags, and -- as for BYE since
        the ICD-OP-08 review -- the connection the dialog is bound to.
        leg None: the initiator's dialog.

        `moving`: a request may also come on another connection, if that
        connection authenticates the dialog's remote party (its certificate,
        or a trusted core). Decided 2026-09-25 (PLT-VP-R1 SIP-OP-18 item 6):
        a client that reconnects keeps its calls, rather than losing them at
        the next session expiry.

        `acking`: an ACK completes a transaction on the connection the
        request came on, which may be one the dialog has since left."""
        cid = req.headers.get("Call-ID") or ""
        call = self._dialogs.get(cid)
        if call is None or call.ended:
            return None
        remote, local = _tag_of(req.headers.get("From")), _tag_of(req.headers.get("To"))
        if cid == call.cid:
            ok = local == _tag(call.cid) and \
                remote == _tag_of(call.invite.headers.get("From")) and \
                (self._may_act(flow, call.flow, call.initiator, moving, call.retired)
                 or (acking and flow in call.retired))
            return (call, None) if ok else None
        leg = call.legs.get(cid)
        if leg is None or leg.state != "confirmed" \
                or remote != leg.to_tag or local != f"{leg.call_id}-l" \
                or not (self._may_act(flow, leg.flow, leg.uri, moving, leg.retired)
                        or (acking and flow in leg.retired)):
            return None
        return call, leg

    def _may_act(self, flow: Any, bound: Any, party: str, moving: bool,
                 retired: Any = ()) -> bool:
        """The dialog's own connection, or -- when moving is allowed -- a new
        one that proves the same party, and that the dialog has not moved away
        from (a dropped connection stays dropped).

        "Proves the same party" is narrower than `_authenticated_as`: a
        trusted core may assert any identity, but it may not take over a dialog
        from a user's own connection -- that would hand any core the media of
        any directly attached user (review of SIP-OP-18 item 6). So:
          * to a user's connection: its certificate names the party;
          * to a core's connection: only from a connection of the same core
            (both issued by the core CA, sharing a trusted DNS name).
        """
        if flow is bound:
            return True
        if not moving or flow in retired:
            return False
        if getattr(flow, "peer_is_core", False):
            shared = set(getattr(flow, "peer_dns", ())) & \
                set(getattr(bound, "peer_dns", ())) & self._trusted_cores
            return bool(getattr(bound, "peer_is_core", False) and shared)
        return canonical_uri(party) in getattr(flow, "peer_uris", ())

    def _rebind(self, call: Call, leg: Optional[Leg], flow: Any) -> None:
        """Move a dialog to the connection its party now uses. The old
        connection is dropped from it for good: nothing it sends acts on the
        dialog any more, even though it authenticates the same party, and
        nothing the platform sends goes to it. A refresh the platform had
        outstanding on the old connection is abandoned; the request that moved
        the dialog is itself a refresh (decided 2026-09-25, SIP-OP-18)."""
        state = leg if leg is not None else call
        if state.flow is flow:
            return
        log.warning("call %s: %s dialog moves to a new connection (%s)", call.cid,
                    "leg " + leg.uri if leg else "initiator",
                    leg.uri if leg else call.initiator)
        r = state.refresh
        if r is not None:
            if r.txn is not None:
                if r.method == "INVITE":
                    # Its 2xx must still be ACKed, or the peer ends the
                    # session (RFC 3261 13.3.1.4); it now comes on the new
                    # connection. _refresh_response ACKs it and ignores it,
                    # the refresh no longer being the current one.
                    r.txn.flow = flow
                else:
                    self.client.finish(r.txn)
            state.refresh = None
            if state.timer is not None:
                state.timer.pending = False
        state.retired.add(state.flow)
        state.flow = flow

    def _in_dialog(self, req: Request, txn: ServerTxn, flow: Any) -> None:
        """An UPDATE (RFC 3311) or re-INVITE on a dialog of a call: a session
        refresh (RFC 4028), and possibly a new offer.

        The platform does not renegotiate media across the call, so an offer
        is accepted when it keeps the call's codec: the relay then sends to
        the address the offer gives, and answers with the same relay SDP. Any
        other offer is 488, which leaves the session as it was (RFC 3261 14.2).
        """
        found = self._dialog_for(req, flow, moving=True)
        if found is None:
            return self._final(txn, Response(Status.CALL_DOES_NOT_EXIST))
        call, leg = found
        state = leg if leg is not None else call
        if leg is None and not call.answered:
            # Early dialog: the platform has no answer to refresh yet.
            return self._final(txn, Response(Status.REQUEST_PENDING))
        cseq = cseq_of(req.headers)[0]
        if state.remote_cseq and cseq <= state.remote_cseq:
            return self._final(txn, Response(Status.SERVER_ERROR, Headers(
                [("Warning", '399 mcx "CSeq lower than the dialog\'s last"')])))
        state.remote_cseq = cseq
        moving = flow is not state.flow
        offer = self._offer_in(req)
        if state.refresh is not None and not moving and (
                offer or req.method == "INVITE" or state.refresh.method == "INVITE"):
            # (Not when the request moves the dialog: the platform's refresh
            # went to a connection the party has left.)
            # RFC 3261 14.2 / RFC 3311 5.2: an offer crossing ours, or an
            # INVITE crossing our INVITE. Two offerless UPDATEs do not.
            return self._final(txn, Response(Status.REQUEST_PENDING))
        if state.awaiting_answer and (offer or req.method == "INVITE"):
            # Our offer still awaits its answer in an ACK (RFC 3311 5.2).
            return self._final(txn, Response(Status.REQUEST_PENDING))
        st = uas_session_timer(req.headers, self._session_expires)
        if isinstance(st, int):
            return self._final(txn, Response(Status.SESSION_INTERVAL_TOO_SMALL,
                                             Headers([("Min-SE", str(st))])))
        body, ctype = "", ""
        if offer:
            body = self._answer_offer(call, leg, offer)
            if body is None:
                return self._final(txn, Response(Status.NOT_ACCEPTABLE_HERE, Headers(
                    [("Warning", '399 mcx "media change within a call is not supported"')])))
            ctype = "application/sdp"
        elif req.method == "INVITE":
            # Offerless re-INVITE: the 2xx carries our offer, the ACK the
            # answer (RFC 3261 14.2).
            body, ctype = self._our_sdp(call, leg), "application/sdp"
            txn.user = AwaitingAnswer(call, leg)
            state.awaiting_answer = True
        contact = _addr_uri(req.headers.get("Contact") or "")
        if contact:                                  # target refresh (12.2.2)
            state.remote_target = contact
        if req.headers.get_all("Allow"):
            state.peer_allows_update = allows(req.headers, "UPDATE")
        h = Headers([("Contact", self._contact(call)), ("Allow", ALLOW),
                     ("Supported", ", ".join(SUPPORTED_ON_ANSWER) if leg is None
                      else OPTION_TIMER)])
        self._timer_headers(h, st)
        if body:
            h.add("Content-Type", ctype)
        if moving:
            # Everything checked, and the answer is 200: the dialog is on
            # this connection from now on (SIP-OP-18 item 6). A refused
            # request moves nothing (review of the reconnect decision).
            self._rebind(call, leg, flow)
        self._final(txn, Response(Status.OK, h, body or ""))
        old = state.timer
        state.timer = DialogTimer.start(
            self.clock(), st.seconds, st.refresher == "uas",
            min_se=old.min_se if old else 0,
            own=(old.own if old else False) or not st.peer_supports)

    @staticmethod
    def _offer_in(message) -> str:
        if not message.body:
            return ""
        try:
            return sdp_of(message.headers.get("Content-Type") or "", message.body)
        except ValueError:
            return ""

    def _our_sdp(self, call: Call, leg: Optional[Leg]) -> str:
        """The SDP the platform last gave that party: its answer to the
        initiator, or its offer to a callee."""
        if call.media is not None:
            return self._relay_sdp(call, leg.uri if leg else call.initiator)
        return leg.offer_sdp if leg is not None else call.answer_sdp

    def _answer_offer(self, call: Call, leg: Optional[Leg], offer: str) -> Optional[str]:
        """The answer to an in-dialog offer, or None (488)."""
        if call.media is not None:
            if not self._accept_remote(call, leg, offer):
                return None
            return self._our_sdp(call, leg)
        original = leg.remote_sdp if leg is not None else _offer_of(call.invite)
        return self._our_sdp(call, leg) if _same_sdp(offer, original) else None

    def _accept_remote(self, call: Call, leg: Optional[Leg], sdp: str) -> bool:
        """Point the relay at the address `sdp` gives, if it keeps the
        call's codec (there is no transcoding)."""
        try:
            info = parse_sdp(sdp)
        except SipError:
            return False
        if call.payload_type not in info.payload_types:
            return False
        call.media.set_remote(                               # type: ignore[union-attr]
            leg.uri if leg else call.initiator, (info.address, info.audio_port),
            (info.address, info.floor_port) if info.floor_port else None)
        return True

    def _apply_answer(self, call: Call, leg: Optional[Leg], message) -> None:
        """The answer in an ACK, or in the 2xx to a re-INVITE the platform
        sent. One the relay cannot use changes nothing: the session goes on
        as it was, and the refusal is logged."""
        sdp = self._offer_in(message)
        if not sdp or call.ended or call.media is None:
            return
        if not self._accept_remote(call, leg, sdp):
            log.warning("unusable SDP answer on call %s ignored", call.cid)

    def _send_refresh(self, call: Call, leg: Optional[Leg]) -> None:
        """RFC 4028 section 10: the platform refreshes. UPDATE when the peer
        allows it (no offer: nothing about the media changes), else a
        re-INVITE offering the SDP it already has."""
        state = leg if leg is not None else call
        timer = state.timer
        flow = leg.flow if leg is not None else call.flow
        if timer is None or flow is None or getattr(flow, "closed", False):
            return
        method = "UPDATE" if state.peer_allows_update else "INVITE"
        if leg is None:
            call.cseq_out += 1
            n = call.cseq_out
            h = Headers([("Via", f"SIP/2.0/TLS {self.local_uri.rpartition('@')[2]};"
                                 "branch=z9hG4bK-replaced"),
                         ("From", f"<{self.local_uri}>;tag={_tag(call.cid)}"),
                         ("To", call.invite.headers.get("From") or f"<{call.initiator}>"),
                         ("Call-ID", call.cid)])
            target, routes = call.remote_target or call.initiator, call.route_set
        else:
            leg.cseq += 1
            n = leg.cseq
            h = Headers([("Via", f"SIP/2.0/TLS {self.local_uri.rpartition('@')[2]};"
                                 "branch=z9hG4bK-replaced"),
                         ("From", f"<{self.local_uri}>;tag={leg.call_id}-l"),
                         ("To", f"<{leg.uri}>;tag={leg.to_tag}"),
                         ("Call-ID", leg.call_id)])
            target, routes = leg.remote_target or leg.uri, leg.route_set
        h.add("CSeq", f"{n} {method}")
        h.add("Max-Forwards", "70")
        ruri, route_hdrs = dialog_target(target, routes)
        for r in route_hdrs:
            h.add("Route", r)
        h.add("Contact", self._contact(call))
        h.add("Supported", OPTION_TIMER)
        h.add("Allow", ALLOW)
        h.add("Session-Expires", f"{timer.seconds};refresher=uac")
        if timer.min_se:
            h.add("Min-SE", str(timer.min_se))             # RFC 4028 7.4
        body = ""
        if method == "INVITE":
            body = self._our_sdp(call, leg)
            if body:
                h.add("Content-Type", "application/sdp")
        req = self._with_branch(Request(method, ruri, h, body))
        timer.pending = True
        state.refresh = Refresh(call, leg, timer.seconds, method=method)
        state.refresh.txn = self.client.start(req, flow, user=state.refresh)
        flow.send(req.render())

    def _refresh_response(self, txn: ClientTxn, resp: ReceivedResponse) -> None:
        r: Refresh = txn.user
        call, leg = r.call, r.leg
        state = leg if leg is not None else call
        if txn.method == "INVITE" and resp.code >= 300:
            self._ack_non_2xx(txn, resp)
        if resp.code < 200:
            return
        if 200 <= resp.code < 300:
            if txn.method == "INVITE":
                if txn.accepted:
                    if r.ack:                       # 2xx again: the same ACK
                        txn.flow.send(r.ack)
                    return
                self.client.accept(txn)
                contact = _addr_uri(resp.headers.get("Contact") or "")
                if contact and state.refresh is r:
                    # The target refresh first: the ACK goes to it (12.2.1.1).
                    state.remote_target = contact
                r.ack = self._ack_refresh(txn, state, leg is None)
            else:
                self.client.finish(txn)
            if state.refresh is not r or call.ended:
                return
            state.refresh = None
            if txn.method == "INVITE":
                self._apply_answer(call, leg, resp)
            contact = _addr_uri(resp.headers.get("Contact") or "")
            if contact:
                state.remote_target = contact
            try:
                st = uac_session_timer(resp.headers)
            except SipError:
                st = None
            old = state.timer
            if st is None and old is not None and old.own:
                # A peer that runs no timer answers without Session-Expires;
                # the platform's own timer goes on (review of SIP-OP-17).
                state.timer = DialogTimer.start(self.clock(), old.seconds, True,
                                                min_se=old.min_se, own=True)
            elif st is None:
                # RFC 4028 7.2: the peer turned the timer off.
                state.timer = None
            else:
                state.timer = DialogTimer.start(
                    self.clock(), st.seconds, st.refresher == "uac",
                    min_se=old.min_se if old else 0,
                    own=old.own if old else False)
            return
        self.client.finish(txn)
        if state.refresh is not r or call.ended:
            return
        state.refresh = None
        self._refresh_failed(call, leg, resp.code, resp)

    def _refresh_failed(self, call: Call, leg: Optional[Leg], code: int,
                        resp: Optional[ReceivedResponse] = None) -> None:
        state = leg if leg is not None else call
        timer = state.timer
        if timer is None:
            return
        now = self.clock()
        if code in (408, 481):
            # RFC 5057 / RFC 4028 10: the dialog is gone.
            return self._dialog_gone(call, leg, "refresh-failed")
        if timer.own and code not in (422, 491):
            # The platform's own timer only asks whether the peer is still
            # there, and any final response says it is (re-review of
            # SIP-OP-17: a peer that never ran a timer and refuses the
            # refresh method must not lose its call for it).
            state.timer = DialogTimer.start(now, timer.seconds, True,
                                            min_se=timer.min_se, own=True)
            return
        if code == 422 and resp is not None:
            try:
                min_se = parse_min_se(resp.headers.get("Min-SE"))
            except SipError:
                min_se = None
            if min_se and timer.seconds < min_se <= 86_400:
                timer.seconds = timer.min_se = min_se
                timer.pending = False
                return self._send_refresh(call, leg)
        if code == 491:
            # RFC 3261 14.1: glare. The owner of the dialog's Call-ID waits
            # 2.1-4 s, the other side 0-2 s. The initiator chose its dialog's
            # Call-ID; the platform chose each leg's.
            timer.pending = False
            timer.refresh_at = now + (secrets.randbelow(2_000) if leg is None
                                      else 2_100 + secrets.randbelow(1_900))
            return
        timer.retry_later(now)

    def _ack_refresh(self, txn: ClientTxn, state: Any, initiator: bool) -> str:
        """The ACK for the 2xx to a re-INVITE the platform sent: in the
        dialog, its own transaction, CSeq number of the re-INVITE (13.2.2.4),
        addressed to the dialog's remote target as the 2xx left it
        (12.2.1.1; review of SIP-OP-17)."""
        inv: Request = txn.request
        h = Headers([("Via", f"SIP/2.0/TLS {self.local_uri.rpartition('@')[2]};"
                             f"branch=z9hG4bKmcxrack{secrets.token_hex(8)}"),
                     ("From", inv.headers.get("From") or ""),
                     ("To", inv.headers.get("To") or ""),
                     ("Call-ID", inv.headers.get("Call-ID") or ""),
                     ("CSeq", f"{cseq_of(inv.headers)[0]} ACK"),
                     ("Max-Forwards", "70")])
        target = state.remote_target or (state.initiator if initiator else state.uri)
        ruri, routes = dialog_target(target, state.route_set)
        for r in routes:
            h.add("Route", r)
        text = Request("ACK", ruri, h).render()
        txn.flow.send(text)
        return text

    def _dialog_gone(self, call: Call, leg: Optional[Leg], cause: str) -> None:
        """A dialog whose session expired, or whose refresh said it no longer
        exists: the initiator's ends the call; a callee's ends that leg, and
        the call when no callee is left (as a callee's BYE does)."""
        if call.ended:
            return
        if leg is None:
            log.warning("session %s: initiator dialog %s", call.cid, cause)
            return self._end(call, cause=cause)
        log.warning("session %s: leg %s %s", call.cid, leg.uri, cause)
        self._bye_leg(call, Signal(SignalType.BYE, target=leg.uri))
        leg.state, leg.timer, leg.refresh = "failed", None, None
        if not any(l.state == "confirmed" for l in call.legs.values()):
            self._end(call, cause=cause, skip=leg.uri)

    def _force_remove(self, call: Call) -> None:
        """Last resort when ending a call faulted: forget it, so that it is
        not retried on every tick. Each step on its own, so one fault does not
        stop the others."""
        call.ended = True
        try:
            self.rt.release(call.cid, "session-timer-fault")
        except Exception:  # noqa: BLE001
            log.exception("release fault on call %s", call.cid)
            try:
                self.rt.abandon(call.cid, "session-timer fault")
            except Exception:  # noqa: BLE001
                log.exception("abandon fault on call %s", call.cid)
        try:
            self.media.close(call.cid)
        except Exception:  # noqa: BLE001
            log.exception("media close fault on call %s", call.cid)
        self.calls.pop(call.cid, None)
        for k in [k for k, c in self._dialogs.items() if c is call]:
            del self._dialogs[k]

    def _session_timers(self) -> None:
        """What each dialog's RFC 4028 timer says is due now."""
        now = self.clock()
        for call in list(self.calls.values()):
            dialogs = [(call, None)] + [(l, l) for l in list(call.legs.values())
                                        if l.state == "confirmed"]
            for state, leg in dialogs:
                if call.ended:
                    break
                timer = state.timer
                if timer is None:
                    continue
                try:
                    if timer.expired(now):
                        # RFC 4028 section 10: BYE when the session expires.
                        self._dialog_gone(call, leg, "session-expired")
                    elif timer.refresh_due(now):
                        self._send_refresh(call, leg)
                except Exception:  # noqa: BLE001
                    # Contained: the transaction timers in the same tick, and
                    # every other dialog, still run. Nothing is retried in a
                    # loop: a refresh is pushed back, and an expiry that could
                    # not be carried out removes the call's state (review and
                    # re-review of SIP-OP-17).
                    log.exception("session timer fault on call %s", call.cid)
                    timer.pending = False
                    timer.refresh_at = None
                    if timer.expired(now):
                        self._force_remove(call)
                        break

    # -- timers ---------------------------------------------------------------------

    def close(self) -> None:
        self.media.close_all()

    def tick(self) -> None:
        self.media.tick()
        self._session_timers()
        events = self.server.tick()
        for txn, text in events.retransmit:
            txn.flow.send(text)
        for txn in events.unacknowledged:
            if _tag_of(txn.request.headers.get("To")):
                # A re-INVITE's 2xx: the dialog was confirmed long ago, and an
                # ACK lost (or sent on a connection the party then left) is no
                # reason to end the call (review of the reconnect decision).
                if isinstance(txn.user, AwaitingAnswer):
                    w = txn.user
                    (w.leg if w.leg is not None else w.call).awaiting_answer = False
                continue
            call = self.calls.get(txn.call_id)
            if call is not None and not call.ended:
                log.warning("no ACK for 2xx call-id=%s: ending session",
                            call.cid)
                self._end(call, cause="ack-timeout")
        for ctxn in self.client.tick():
            if ctxn.accepted:
                continue          # Timer M: the 2xx window closed, not a failure
            if isinstance(ctxn.user, Refresh):
                r = ctxn.user
                state = r.leg if r.leg is not None else r.call
                if state.refresh is r and not r.call.ended:
                    state.refresh = None
                    self._refresh_failed(r.call, r.leg, 408)
                continue
            leg = ctxn.user
            if leg is not None and ctxn.cancelled and not ctxn.done \
                    and not leg.cancel:
                # Rang past the no-answer limit (SIP-OP-15): the callee is
                # still alerting, so it is CANCELled, not forgotten.
                self._send_cancel(leg)
            call = self._dialogs.get(leg.call_id) if leg else None
            if call is None or call.ended:
                continue
            leg.state = "failed"
            if ctxn.method == "INVITE":
                self._maybe_fail(call, 408)


def _quoted(text: object) -> str:
    """The body of an RFC 3261 quoted-string (25.1: quoted-pair escapes " and
    backslash; no control characters). Refusal detail can carry text the
    caller chose -- an XML namespace, an encoding name -- and a bare quote
    in it used to end the warn-text early (found by review)."""
    clean = "".join(c if c >= " " and c != "\x7f" else " " for c in str(text))
    return clean.replace("\\", "\\\\").replace('"', '\\"')


def _same_sdp(a: str, b: str) -> bool:
    """Two SDP bodies that describe the same session: equal but for the
    origin line (o=, whose version a re-offer may bump) and line endings."""
    def norm(text: str) -> List[str]:
        return [l.strip() for l in text.splitlines()
                if l.strip() and not l.startswith("o=")]
    return norm(a) == norm(b)


def _tag_of(value: Optional[str]) -> str:
    m = re.search(r";\s*tag=([^;>\s,]+)", value or "")
    return m.group(1) if m else ""


def _sent_by(headers) -> str:
    """The sent-by (host[:port]) of the top Via, lower-cased."""
    via = (headers.get_all("Via") or [""])[0]
    m = re.match(r"\s*SIP\s*/\s*2\.0\s*/\s*\S+\s+([^;,\s]+)", via, re.I)
    return m.group(1).lower() if m else ""


def _uri(value: str) -> str:
    m = re.search(r"<([^>]+)>", value)
    return (m.group(1) if m else value.strip()).split(";")[0].strip()
