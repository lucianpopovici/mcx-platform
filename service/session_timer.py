"""RFC 4028 session timer state for one dialog (PLT-CONF-AUDIT CA-20b,
PLT-VP-R1 SIP-OP-17).

Pure and clock-driven, like sip_txn: nothing here reads a clock or sends a
message. `SipCore.tick` asks each dialog's timer what is due.

Two roles, fixed at each negotiation (the initial dialog, then every
successful refresh):

  * the platform refreshes: a refresh is due at half the interval
    (section 10: "half the session expiration interval" is RECOMMENDED);
  * the peer refreshes: the platform only watches, and the session has
    expired when no refresh arrived by the interval minus the lesser of 32 s
    and a third of it (section 10). The platform then sends BYE.

When the platform refreshes and its refreshes keep failing, the session
still expires at the full interval, and the platform sends BYE then.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class DialogTimer:
    seconds: int
    we_refresh: bool
    refresh_at: Optional[int]      # ms; None when the peer refreshes
    expires_at: int                # ms: past this, the dialog is ended
    pending: bool = False          # a refresh the platform sent awaits its answer
    # The Min-SE a 422 imposed on this dialog: sent with every later refresh
    # (RFC 4028 7.4). 0: none.
    min_se: int = 0
    # The platform keeps this timer whatever the peer's 2xx says: the peer
    # runs no session timer of its own (it did not support one, or its 2xx
    # had no Session-Expires), so the platform's refreshes are the only way
    # to learn that it is gone (review of SIP-OP-17).
    own: bool = False

    @staticmethod
    def start(now_ms: int, seconds: int, we_refresh: bool, min_se: int = 0,
              own: bool = False) -> "DialogTimer":
        interval = seconds * 1000
        if we_refresh:
            return DialogTimer(seconds, True, now_ms + interval // 2,
                               now_ms + interval, min_se=min_se, own=own)
        grace = min(32_000, interval // 3)
        return DialogTimer(seconds, False, None, now_ms + interval - grace,
                           min_se=min_se, own=own)

    def refresh_due(self, now_ms: int) -> bool:
        return self.we_refresh and not self.pending and \
            self.refresh_at is not None and now_ms >= self.refresh_at

    def expired(self, now_ms: int) -> bool:
        return now_ms >= self.expires_at

    def retry_later(self, now_ms: int) -> None:
        """A refresh the platform sent failed without ending the dialog:
        try again halfway to expiry, while there is time for it."""
        self.pending = False
        remaining = self.expires_at - now_ms
        self.refresh_at = now_ms + remaining // 2 if remaining > 2_000 else None
