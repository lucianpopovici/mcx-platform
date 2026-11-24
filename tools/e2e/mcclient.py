"""The repository's independent MC client (PLT-VP-R1 ENV-E2E).

The SIP side is tools/interop/ua.py; this adds what an MCPTT client has
beyond it: a voice stream and a floor control stream described in its SDP
(TS 24.380 clause 12 / 14: "m=application <port> udp MCPTT"), the floor
messages and RTP of tools/e2e/floor.py, and the callee's choice between
manual and automatic commencement (TS 24.379 11.1.1.2.2: Priv-Answer-Mode or
Answer-Mode "Auto" is answered 200 without the user's action; otherwise the
client rings first). Nothing here is imported from `core` or `service`.
"""

from __future__ import annotations

import re
import sys
import time
import uuid
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "interop"))
sys.path.insert(0, str(HERE))

from floor import Endpoint  # noqa: E402
from ua import ICSI, MCINFO, UA, body_part, first_line, header  # noqa: E402

# (payload type, rtpmap, fmtp) -- written from RFC 3551 / RFC 4867.
PCMU = (0, "PCMU/8000", "")
AMR_WB = (96, "AMR-WB/16000", "octet-align=1")
OPUS = (111, "opus/48000/2", "")          # declared by no shipped profile


def sdp_ports(sdp: str) -> Tuple[Optional[str], Optional[int], Optional[int], List[int]]:
    """(address, audio port, floor port, audio payload types) of an SDP body."""
    addr = None
    m = re.search(r"(?m)^c=IN IP4 (\S+)", sdp or "")
    if m:
        addr = m.group(1)
    audio = re.search(r"(?m)^m=audio (\d+) RTP/AVP ([\d ]+)", sdp or "")
    floor = re.search(r"(?m)^m=application (\d+) udp MCPTT", sdp or "")
    return (addr, int(audio.group(1)) if audio else None,
            int(floor.group(1)) if floor else None,
            [int(x) for x in audio.group(2).split()] if audio else [])


class MCClient(UA):
    def __init__(self, aor: str, host: str, port: int, pki: str, keylog: str,
                 codecs: Sequence[Tuple[int, str, str]] = (PCMU,), priority: int = 5):
        super().__init__(aor, host, port, pki, keylog=keylog)
        self.media = Endpoint(self.user)
        self.codecs = list(codecs)
        self.priority = priority

    # -- identity ----------------------------------------------------------------
    @property
    def contact(self) -> str:
        """TS 24.379 (e.g. 10.1.1.2.1.1, 11.1.1.2.2): the client's Contact
        carries the MCPTT feature tag and the MCPTT ICSI."""
        return (f"<sip:{self.user}@{self.host}:{self.port};transport=tls>"
                f';+g.3gpp.mcptt;+g.3gpp.icsi-ref="{ICSI}"')

    def register(self, registrar: str = "sip:mcptt.example", expires: int = 3600) -> str:
        cid = f"reg-{self.user}-{uuid.uuid4().hex[:8]}"
        self.send([
            f"REGISTER {registrar} SIP/2.0", self._via(),
            f"From: <{self.aor}>;tag={self.tag}", f"To: <{self.aor}>",
            f"Call-ID: {cid}", "CSeq: 1 REGISTER", "Max-Forwards: 70",
            f"Contact: {self.contact};expires={expires}"])
        return self.wait(r"^SIP/2\.0 [2-6]\d\d", call_id=cid)

    # -- SDP --------------------------------------------------------------------
    def sdp(self, port: int = 0, version: int = 1) -> str:
        """Voice with this client's codecs, and the floor control stream with
        queueing asked for (TS 24.380 14.2: a=fmtp:MCPTT mc_queueing)."""
        lines = [f"v=0", f"o=- {version} {version} IN IP4 {self.host}", "s=-",
                 f"c=IN IP4 {self.host}", "t=0 0",
                 f"m=audio {self.media.rtp_port} RTP/AVP "
                 + " ".join(str(c[0]) for c in self.codecs)]
        for pt, name, fmtp in self.codecs:
            lines.append(f"a=rtpmap:{pt} {name}")
            if fmtp:
                lines.append(f"a=fmtp:{pt} {fmtp}")
        lines += ["a=sendrecv", f"m=application {self.media.floor_port} udp MCPTT",
                  f"a=fmtp:MCPTT mc_queueing;mc_priority={self.priority}"]
        return "\n".join(lines) + "\n"

    def answer_sdp(self, offer: str) -> str:
        """The offer's first payload type this client also has, alone."""
        _, _, _, pts = sdp_ports(offer)
        mine = [c for c in self.codecs if c[0] in pts] or \
            [c for c in self.codecs if c[1].split("/")[0] in offer]
        chosen = mine[:1] or self.codecs[:1]
        saved, self.codecs = self.codecs, chosen
        try:
            return self.sdp()
        finally:
            self.codecs = saved

    def learn(self, sdp: str) -> None:
        """Where the platform's relay receives this client's voice and floor."""
        addr, audio, floor, _ = sdp_ports(sdp)
        if addr and audio:
            self.media.remote_rtp = (addr, audio)
        if addr and floor:
            self.media.remote_floor = (addr, floor)

    # -- calls ------------------------------------------------------------------
    def call(self, target: str, session_type: str, ruri: str) -> dict:
        return self.invite(ruri, session_type, target, self.media.rtp_port)

    def answer_incoming(self, timeout: float = 10.0, ring_first: Optional[bool] = None,
                        ring_s: float = 0.5) -> Tuple[str, str]:
        """Take the platform's INVITE. Manual commencement (TS 24.379
        6.2.3.2.1) rings: a 180 with Require: timer, then, `ring_s` later (the
        user answering), the 200; automatic (6.2.3.1.1: Priv-Answer-Mode or
        Answer-Mode: Auto, 11.1.1.2.1.2 item 9) answers at once. The 200
        carries Require: timer and Session-Expires with refresher=uas (6.2.3.1.1
        items 2 and 5): the INVITE's interval, or RFC 4028's 1800 s without
        one. Both carry the tagged Contact (items 3 and 4). Returns (the
        INVITE, the 200 sent)."""
        inv = self.wait(r"^INVITE ", timeout)
        auto = "auto" in ((header(inv, "Priv-Answer-Mode") or "") + " "
                          + (header(inv, "Answer-Mode") or "")).lower()
        if ring_first if ring_first is not None else not auto:
            self.respond(inv, 180, "Ringing", extra=["Require: timer"])
            time.sleep(ring_s)
        offer = body_part(inv, "application/sdp") or ""
        # "x" is the compact form (RFC 4028 4).
        asked = (header(inv, "Session-Expires") or header(inv, "x") or "").split(";")[0].strip()
        interval = asked if asked.isascii() and asked.isdigit() else "1800"
        ok = self.respond(inv, 200, "OK", self.answer_sdp(offer),
                          extra=["Require: timer", f"Session-Expires: {interval};refresher=uas"])
        self.learn(offer)
        return inv, ok

    def ack(self, invite: dict, final: str) -> str:
        """RFC 3261 13.2.2.4: the ACK for a 2xx is a new transaction in the
        dialog, to the remote target."""
        d = self.dialog_as_uac(invite, final)
        self._dialogs[invite["call_id"]] = d
        return self.in_dialog(d, "ACK", cseq=1)

    def bye(self, call_id: str) -> str:
        d = self._dialogs[call_id]
        self.in_dialog(d, "BYE")
        return self.wait(r"^SIP/2\.0 200", call_id=call_id, method="BYE")

    def ok_bye(self, timeout: float = 10.0) -> str:
        bye = self.wait(r"^BYE ", timeout)
        self.respond(bye, 200, "OK")
        return bye

    @property
    def _dialogs(self) -> dict:
        d = self.__dict__.get("_dlg")
        if d is None:
            d = self.__dict__["_dlg"] = {}
        return d

    def close(self) -> None:
        self.media.close()
        super().close()


__all__ = ["MCClient", "PCMU", "AMR_WB", "OPUS", "MCINFO", "first_line", "sdp_ports"]
