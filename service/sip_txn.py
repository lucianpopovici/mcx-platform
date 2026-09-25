"""SIP transaction state (RFC 3261 §17, as amended by RFC 6026 for 2xx).

Pure and clock-driven: nothing here reads a clock, opens a socket or sleeps.
`tick()` is called by whoever owns the timers and returns what is now due.

Transport is TLS, which is reliable, so per RFC 3261 §17.1.1.2 / §17.1.2.2 no
request is retransmitted (Timers A and E do not run). What DOES run:
  * absorbing a peer's retransmission and replaying the stored response, so a
    retransmit never reaches the guard, the session manager or a hook again;
  * 2xx retransmission until ACK (§13.3.1.4, unconditional on transport);
  * Timer B/F: a client transaction with no final response times out (408);
  * linger timers, so a late retransmission is still recognised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.sip import ReceivedResponse, Request

T1_MS = 500
T2_MS = 4000
_BRANCH = re.compile(r"branch=([^;,\s>]+)")
_CSEQ = re.compile(r"^\s*(\d+)\s+([A-Za-z]+)")


def top_branch(headers) -> str:
    via = headers.get("Via") or ""
    m = _BRANCH.search(via)
    return m.group(1) if m else ""


def cseq_of(headers) -> Tuple[int, str]:
    m = _CSEQ.match(headers.get("CSeq") or "")
    return (int(m.group(1)), m.group(2).upper()) if m else (0, "")


# --------------------------------------------------------------------------
# Server transactions
# --------------------------------------------------------------------------

PROCEEDING, COMPLETED, ACCEPTED, CONFIRMED = (
    "proceeding", "completed", "accepted", "confirmed")


@dataclass
class ServerTxn:
    key: Tuple[str, str]
    request: Request
    flow: Any
    call_id: str
    cseq: int
    state: str = PROCEEDING
    last_response: Optional[str] = None
    last_code: int = 0
    expires_at: Optional[int] = None
    retransmit_at: Optional[int] = None
    interval: int = T1_MS
    user: Any = None                    # the owner's handle (e.g. a Call)


@dataclass
class ServerEvents:
    retransmit: List[Tuple[ServerTxn, str]] = field(default_factory=list)
    unacknowledged: List[ServerTxn] = field(default_factory=list)  # 2xx, no ACK


class ServerTransactions:
    def __init__(self, clock: Callable[[], int], t1: int = T1_MS,
                 t2: int = T2_MS) -> None:
        self._now, self._t1, self._t2 = clock, t1, t2
        self._txns: Dict[Tuple[str, str], ServerTxn] = {}

    def __len__(self) -> int:
        return len(self._txns)

    # -- matching --------------------------------------------------------

    def match(self, request: Request) -> Optional[ServerTxn]:
        """The transaction a retransmitted request belongs to, if any."""
        return self._txns.get((top_branch(request.headers), request.method))

    def find(self, branch: str, method: str) -> Optional[ServerTxn]:
        """RFC 3261 9.2: a CANCEL names the INVITE it cancels by that
        INVITE's top Via branch."""
        return self._txns.get((branch, method))

    def create(self, request: Request, flow: Any) -> ServerTxn:
        cseq, _ = cseq_of(request.headers)
        txn = ServerTxn(key=(top_branch(request.headers), request.method),
                        request=request, flow=flow,
                        call_id=request.headers.get("Call-ID") or "", cseq=cseq)
        self._txns[txn.key] = txn
        return txn

    def respond(self, txn: ServerTxn, text: str, code: int) -> None:
        """Record a response as this transaction's latest, and arm timers."""
        txn.last_response, txn.last_code = text, code
        if code < 200:
            return
        now = self._now()
        if txn.request.method == "INVITE" and 200 <= code < 300:
            txn.state = ACCEPTED
            txn.interval = self._t1
            txn.retransmit_at = now + txn.interval
            txn.expires_at = now + 64 * self._t1          # ACK never came
        else:
            txn.state = COMPLETED
            txn.retransmit_at = None
            txn.expires_at = now + 64 * self._t1          # linger (Timer H/J)

    def absorb_ack(self, request: Request, flow: Any = None) -> Optional[ServerTxn]:
        """Match an ACK to its INVITE transaction and stop the timers.

        An ACK to a non-2xx final response carries the INVITE's branch; an ACK
        to a 2xx is its own transaction and is matched on Call-ID and CSeq.
        """
        cseq, _ = cseq_of(request.headers)
        call_id = request.headers.get("Call-ID") or ""
        txn = self._txns.get((top_branch(request.headers), "INVITE"))
        if txn is None:
            for t in self._txns.values():
                if t.request.method == "INVITE" and t.state == ACCEPTED \
                        and t.call_id == call_id and t.cseq == cseq:
                    txn = t
                    break
        if txn is None or txn.state not in (COMPLETED, ACCEPTED):
            return None
        if flow is not None and txn.flow is not flow:
            # An ACK from another connection is not the caller's: it must not
            # stop the missing-ACK timeout of someone else's call (review of
            # ICD-OP-08).
            return None
        txn.state = CONFIRMED
        txn.expires_at = self._now() + 64 * self._t1
        return txn

    def unconfirm(self, txn: ServerTxn) -> None:
        """Undo absorb_ack for an ACK the core refused (foreign tags) on an
        INVITE's 2xx: the 2xx goes on being retransmitted, and the genuine ACK
        still matches."""
        txn.state = ACCEPTED
        txn.expires_at = self._now() + 64 * self._t1

    # -- timers ----------------------------------------------------------

    def tick(self) -> ServerEvents:
        now = self._now()
        events = ServerEvents()
        for key, txn in list(self._txns.items()):
            if txn.state == ACCEPTED and txn.retransmit_at is not None \
                    and now >= txn.retransmit_at:
                if txn.expires_at is not None and now >= txn.expires_at:
                    events.unacknowledged.append(txn)
                    txn.state = COMPLETED
                    txn.retransmit_at = None
                else:
                    events.retransmit.append((txn, txn.last_response or ""))
                    txn.interval = min(txn.interval * 2, self._t2)
                    txn.retransmit_at = now + txn.interval
            elif txn.state in (COMPLETED, CONFIRMED) and txn.expires_at is not None \
                    and now >= txn.expires_at:
                del self._txns[key]
        return events


# --------------------------------------------------------------------------
# Client transactions
# --------------------------------------------------------------------------


@dataclass
class ClientTxn:
    branch: str
    method: str
    request_text: str
    flow: Any
    expires_at: int
    done: bool = False
    user: Any = None
    request: Any = None
    # RFC 6026 7.2 'Accepted': an INVITE that got a 2xx stays matchable for
    # 64*T1 (Timer M), so a retransmitted 2xx, or a 2xx from another fork,
    # reaches the UAC core instead of being dropped as unmatched.
    accepted: bool = False
    # RFC 3261 17.1.1.2: a provisional response moves an INVITE client
    # transaction to 'Proceeding'. A CANCEL may only be sent from there
    # (9.1), and once it is, the transaction waits at most 64*T1 more for
    # the final response it provokes (9.1, last paragraph).
    proceeding: bool = False
    cancelled: bool = False
    # The call type's no-answer limit (profile `no_answer_s`), as an
    # absolute time: the deadline once the INVITE is 'Proceeding', where
    # Timer B no longer runs (17.1.1.2). None: Timer B's deadline stays.
    answer_by: Optional[int] = None


class ClientTransactions:
    def __init__(self, clock: Callable[[], int], t1: int = T1_MS) -> None:
        self._now, self._t1 = clock, t1
        self._txns: Dict[Tuple[str, str], ClientTxn] = {}

    def __len__(self) -> int:
        return len(self._txns)

    def start(self, request: Request, flow: Any, user: Any = None,
              answer_by: Optional[int] = None) -> ClientTxn:
        txn = ClientTxn(branch=top_branch(request.headers), method=request.method,
                        request_text=request.render(), flow=flow,
                        expires_at=self._now() + 64 * self._t1, user=user,
                        request=request, answer_by=answer_by)
        self._txns[(txn.branch, txn.method)] = txn
        return txn

    def match(self, response: ReceivedResponse) -> Optional[ClientTxn]:
        _, method = cseq_of(response.headers)
        return self._txns.get((top_branch(response.headers), method))

    def accept(self, txn: ClientTxn) -> None:
        """INVITE got a 2xx: 'Accepted' until Timer M (64*T1) fires."""
        txn.accepted = True
        txn.expires_at = self._now() + 64 * self._t1

    def proceed(self, txn: ClientTxn) -> None:
        """The first provisional: Timer B stops (17.1.1.2) and the
        no-answer limit, if one was given, becomes the deadline. The limit
        is absolute, so a further provisional changes nothing."""
        txn.proceeding = True
        if txn.answer_by is not None and not txn.cancelled:
            txn.expires_at = txn.answer_by

    def cancelling(self, txn: ClientTxn) -> None:
        """A CANCEL was sent for this INVITE: wait 64*T1 for the 487 (or a
        2xx that crossed the CANCEL), then give up (RFC 3261 9.1)."""
        txn.cancelled = True
        txn.expires_at = self._now() + 64 * self._t1

    def find(self, branch: str, method: str) -> Optional[ClientTxn]:
        return self._txns.get((branch, method))

    def finish(self, txn: ClientTxn) -> None:
        txn.done = True
        self._txns.pop((txn.branch, txn.method), None)

    def tick(self) -> List[ClientTxn]:
        """Transactions whose timer fired: Timer B/F (no final response
        arrived), or Timer M for an accepted INVITE (`accepted` is set; that
        one is not a failure).

        An INVITE that is ringing ('Proceeding') is not ended here. RFC 3261
        17.1.1.2 runs Timer B in 'Calling' only; in 'Proceeding' the deadline
        is the call type's no-answer limit (PLT-VP-R1 SIP-OP-15), and what
        the core owes a ringing callee is a CANCEL, whose 487 -- or a 2xx
        that crossed it -- must still find this transaction to be ACKed. It
        is returned with `cancelled` set and `done` unset, and lives 64*T1
        longer (9.1)."""
        now = self._now()
        expired = [t for t in self._txns.values() if now >= t.expires_at]
        for t in expired:
            if t.method == "INVITE" and t.proceeding and not t.accepted \
                    and not t.cancelled:
                self.cancelling(t)
            else:
                self.finish(t)
        return expired
