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
import logging
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import dataclasses
import threading

from core.errors import IDENTITY_NOT_AUTHENTICATED, NOT_AUTHORISED
from core.hooks import MediaKind
from core.invoke import Invoker
from core.session import Session, Signal, SignalType
from core.sip import (
    Adapter, DialogContext, Headers, InboundGuard, ReceivedResponse, Request,
    RegistrationStore, Response, SipError, Status, build_sdp, canonical_uri,
    negotiate,
    parse_message, parse_sdp,
)

from core import mcinfo
from core.mcinfo import sdp_of

from .media import MediaSession, UdpMediaPlane
from .runtime import Runtime
from .sip_txn import (ClientTransactions, ClientTxn, ServerTransactions,
                      ServerTxn, cseq_of, top_branch)

log = logging.getLogger("mcx.sip")

ALLOWED = "INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS"
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


def _tag(seed: str) -> str:
    return "mcx-" + hashlib.sha1(seed.encode()).hexdigest()[:10]


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
        self._trusted_peers = set(sip_cfg.trusted_peers if sip_cfg else ())
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
            self._on_response(message, flow)
        else:
            self._on_request(message, flow)

    def on_flow_closed(self, flow: Any) -> None:
        for uri in [u for u, f in self.flows_by_user.items() if f is flow]:
            del self.flows_by_user[uri]

    def _on_request(self, req: Request, flow: Any) -> None:
        # 1 — retransmission?
        if req.method == "ACK":
            if self.server.absorb_ack(req, flow) is None:
                log.info("stray ACK dropped call-id=%s",
                         req.headers.get("Call-ID"))
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
        if req.method == "INVITE" and 100 < resp.status.code < 300:
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

    def _reject(self, txn: ServerTxn, reason_code: str) -> None:
        ctx = DialogContext(call_id=txn.call_id, local_uri=self.local_uri)
        self._final(txn, self.adapter.reject(reason_code, ctx))

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

        A peer whose certificate carries a DNS name listed in
        MCX_SIP_TRUSTED_PEERS is a SIP core that authenticated its users
        itself: it may assert any identity (RFC 3325 trust domain). Any other
        peer may assert only a sip: URI in its own certificate's
        subjectAltName. A peer without a certificate can assert nothing.
        """
        dns = set(getattr(flow, "peer_dns", ()))
        if dns & self._trusted_peers:
            return True
        return canonical_uri(identity) in getattr(flow, "peer_uris", ())

    def _invite(self, req: Request, txn: ServerTxn, flow: Any) -> None:
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
        call = Call(cid=sr.request_id, invite=req, sr=sr, txn=txn, flow=flow,
                    initiator=sr.initiator,
                    remote_target=_addr_uri(req.headers.get("Contact") or "") or sr.initiator,
                    route_set=_header_values(req.headers.get_all("Record-Route")))
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
            return self._reject(txn, refusal.reason_code)
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
        leg = Leg(uri=target, call_id=f"{call.cid}.leg{len(call.legs) + 1}",
                  flow=flow)
        if flow is None:
            # Unregistered, or its flow is gone: the leg is dead on arrival.
            leg.state = "failed"
            call.legs[leg.call_id] = leg
            return
        sdp = _offer_of(call.invite)
        if call.media is not None:
            call.media.add(target)
            sdp = self._relay_sdp(call, target)
        ctx = DialogContext(call_id=leg.call_id, local_uri=self.local_uri,
                            sdp=sdp)
        leg.invite_cseq = leg.cseq = ctx.cseq
        req = self.adapter.render(sig, ctx, call.sr)
        req = self._with_branch(req)
        secs = self._no_answer_s.get(call.sr.call_type)
        leg.txn = self.client.start(
            req, flow, user=leg,
            answer_by=self.clock() + secs * 1000 if secs else None)
        call.legs[leg.call_id] = leg
        self._dialogs[leg.call_id] = call
        flow.send(req.render())

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
        if txn.flow is not flow or resp.headers.get("Call-ID") != \
                txn.request.headers.get("Call-ID"):
            # A response belongs to the connection its request went out on,
            # and to that request's Call-ID. Otherwise any peer could answer
            # for a callee (review of ICD-OP-08).
            self.counters["foreign_response"] = self.counters.get("foreign_response", 0) + 1
            log.warning("response from another flow or Call-ID dropped code=%s",
                        resp.code)
            return
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
        if resp.code < 200:
            leg.state = "ringing"
            if resp.code in (180, 183) and not call.answered:
                self._provisional(call.txn, Response(Status.RINGING))
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
            headers = Headers([("Contact", f"<{self.local_uri}>")])
            ctype = "application/sdp" if body else ""
            if call.sr.adhoc:
                ctype, body = self._adhoc_answer(call, body)
            if body:
                headers.add("Content-Type", ctype)
            self._final(call.txn, Response(Status.OK, headers, body))
            if call.media is not None:
                # The floor starts now, when the call is answered, not when it
                # was admitted: its timers must not run while callees ring.
                call.media.apply(self.rt.manager.start_floor(call.cid))

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
        if call_id == call.cid and (flow is not call.flow or
                                    _tag_of(req.headers.get("From")) !=
                                    _tag_of(call.invite.headers.get("From"))):
            return self._final(txn, Response(Status.CALL_DOES_NOT_EXIST))
        if leg is not None and flow is not leg.flow:
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

    # -- timers ---------------------------------------------------------------------

    def close(self) -> None:
        self.media.close_all()

    def tick(self) -> None:
        self.media.tick()
        events = self.server.tick()
        for txn, text in events.retransmit:
            txn.flow.send(text)
        for txn in events.unacknowledged:
            call = self.calls.get(txn.call_id)
            if call is not None and not call.ended:
                log.warning("no ACK for 2xx call-id=%s: ending session",
                            call.cid)
                self._end(call, cause="ack-timeout")
        for ctxn in self.client.tick():
            if ctxn.accepted:
                continue          # Timer M: the 2xx window closed, not a failure
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
