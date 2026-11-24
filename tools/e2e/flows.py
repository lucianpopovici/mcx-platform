"""Expected message flows, written from TS 24.379 clause 11.1 (private call,
on-demand, participating and controlling function on one deployment) and
RFC 3261, as the sequence of messages each party sees. A step is a set of
messages whose order among themselves is free (they go on different
connections and nothing in the procedures orders them); the steps are in
order, and the flow is exact: no message missing, none extra, none repeated.

  c1 caller, c2 callee, P the platform.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

Msg = Tuple[str, str]

_RELEASE: List[List[Msg]] = [
    # The caller hangs up (RFC 3261 15.1.1); the platform answers it and
    # ends the callee's dialog (6.3.8.2 item 3: a private call ends when its
    # initiator leaves).
    [("c1>P", "BYE")],
    [("P>c1", "200 BYE"), ("P>c2", "BYE")],
    [("c2>P", "200 BYE")],
]

EXPECTED: Dict[str, List[List[Msg]]] = {
    # Manual commencement (11.1.1.2.1, 11.1.1.3.x; Answer-Mode: Manual): the
    # callee rings, the ringing is passed back, and the caller's 200 OK
    # follows the callee's acceptance.
    "private-manual": [
        [("c1>P", "INVITE")],
        [("P>c1", "100 INVITE"), ("P>c2", "INVITE")],
        [("c2>P", "180 INVITE")],
        [("P>c1", "180 INVITE")],
        [("c2>P", "200 INVITE")],
        [("P>c2", "ACK"), ("P>c1", "200 INVITE")],
        [("c1>P", "ACK")],
    ] + _RELEASE,
    # Automatic commencement (Priv-Answer-Mode: Auto): the callee answers
    # without ringing, so no 18x reaches the caller.
    "private-auto": [
        [("c1>P", "INVITE")],
        [("P>c1", "100 INVITE"), ("P>c2", "INVITE")],
        [("c2>P", "200 INVITE")],
        [("P>c2", "ACK"), ("P>c1", "200 INVITE")],
        [("c1>P", "ACK")],
    ] + _RELEASE,
}


def match_flow(seq: Sequence[Msg], expected: List[List[Msg]]) -> Tuple[bool, Optional[str]]:
    """(True, None) if `seq` is exactly `expected`, else (False, the first
    difference)."""
    i = 0
    for n, step in enumerate(expected):
        want = sorted(step)
        got = sorted(seq[i:i + len(step)])
        if got != want:
            return False, (f"step {n + 1}: expected {want}, captured "
                           f"{list(seq[i:i + len(step)])}")
        i += len(step)
    if i != len(seq):
        return False, f"{len(seq) - i} message(s) beyond the flow: {list(seq[i:])}"
    return True, None
