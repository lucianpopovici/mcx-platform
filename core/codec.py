"""Voice codec negotiation for the media relay (PLT-MED-001/002; PLT-VP-R1
VP-OP-03, MED-OP-01).

The platform relays one codec per call, untranscoded (transcoding is R4). So
every party of a call must use the same codec, chosen from the caller's offer
by the profile's preference order, and the relay only maps RTP payload type
NUMBERS between parties -- a dynamic codec (AMR, AMR-WB, EVS) may be 96 to one
client and 97 to another (RFC 3264 6.1 lets each side number its own).

Two things are protocol knowledge and live here, read from the RFCs:

  * RFC 3551 table 4: the static audio payload types used without an rtpmap.
  * Payload format parameters that change the RTP payload itself, and so
    must be identical at both ends of an untranscoded relay:
      - AMR and AMR-WB, RFC 4867 8.3.1: octet-align, crc, robust-sorting and
        interleaving are "declarative and MUST be the same in both the offer
        and the answer", and so is channels (part of the codec's name here).
        The other parameters do not change the payload layout and are carried
        through from the caller's offer. mode-set among them is a limit on
        what the SDP's author wants to receive, and the relay does not
        reconcile it across parties (PLT-VP-R1 MED-OP-05).
      - EVS, TS 26.445 annex A (V12.17.0, V16.4.0 and V19.1.0 agree): hf-only
        (Header-Full format only), evs-mode-switch (AMR-WB IO mode) and cmr
        (-1: no CMR in the payload in primary mode; 1: a CMR in every
        packet), each defaulting to 0 (A.3.1). For each, "when [it] is
        offered ... and the payload type is accepted, the answerer shall not
        modify or remove" it (A.3.3.1), and each decides how the payload is
        framed. An answerer may add one that was not offered; to a relay
        that cannot reframe, that is a mismatch too. dtx, br, bw and the
        AMR-WB IO mode-set limit what is sent, not how, and are carried
        through like mode-set above.
    Absent parameters take their defaults (RFC 4867 8.1: 0 for octet-align,
    crc and robust-sorting; interleaving absent means none).

TS 26.179 (docs/3GPP; V13.2.0 and V19.0.0 read the same): 4.1.1, MCPTT
clients shall support AMR-WB and may support EVS; 4.1.2, the codec preference
order is set by operator policy (here, the profile's order); 4.1.3, the RFC
4867 bandwidth-efficient format shall be supported. So when a caller offers
AMR or AMR-WB in both layouts, the bandwidth-efficient one is chosen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

# RFC 3551 table 4, the audio encodings a deployment of this platform uses
# (G.722's clock rate is 8000 in SDP although it samples at 16 kHz: RFC 3551
# 4.5.2, an error kept for compatibility).
STATIC_PAYLOAD_TYPES: Mapping[int, str] = MappingProxyType({
    0: "PCMU/8000", 8: "PCMA/8000", 9: "G722/8000"})

# Parameters that must match end to end, with their defaults.
MUST_MATCH: Mapping[str, Mapping[str, str]] = MappingProxyType({
    "AMR": MappingProxyType({"octet-align": "0", "crc": "0",
                             "robust-sorting": "0", "interleaving": ""}),
    "AMR-WB": MappingProxyType({"octet-align": "0", "crc": "0",
                                "robust-sorting": "0", "interleaving": ""}),
    "EVS": MappingProxyType({"hf-only": "0", "evs-mode-switch": "0", "cmr": "0"}),
})

# Payload formats that carry no voice and so can never be the call's codec:
# RFC 4733 telephone-event (DTMF), RFC 3389 CN (comfort noise), RFC 2198 red
# and RFC 5109 ulpfec (redundancy, forward error correction).
NOT_VOICE = frozenset({"TELEPHONE-EVENT", "CN", "RED", "ULPFEC"})

# ASCII digits only: \d takes any Unicode digit, which int() may refuse.
_RTPMAP = re.compile(
    r"^a=rtpmap:([0-9]{1,3})\s+([^/\s]+)/([0-9]{1,6})(?:/([0-9]{1,2}))?\s*$", re.I)
_FMTP = re.compile(r"^a=fmtp:([0-9]{1,3})\s+(.*)$", re.I)
NAME = re.compile(r"^[A-Za-z0-9._-]+/\d+(?:/\d+)?$")


def key_of(name: str) -> Tuple[str, int, int]:
    """("AMR-WB", 16000, 1) from "AMR-WB/16000": encoding names compare
    without case (RFC 4855 3), channels default to 1."""
    parts = name.split("/")
    return (parts[0].upper(), int(parts[1]), int(parts[2]) if len(parts) > 2 else 1)


@dataclass(frozen=True)
class Offered:
    """One payload type of an audio m-line."""
    pt: int
    name: str                          # as the SDP wrote it, e.g. "AMR-WB/16000"
    fmtp: str = ""                     # the a=fmtp value, verbatim

    @property
    def key(self) -> Tuple[str, int, int]:
        return key_of(self.name)

    def params(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for item in self.fmtp.split(";"):
            k, _, v = item.strip().partition("=")
            if k:
                out[k.strip().lower()] = v.strip()
        return out

    def layout(self) -> Tuple[Tuple[str, str], ...]:
        """The must-match parameters, defaults filled in."""
        rules = MUST_MATCH.get(self.key[0], {})
        p = self.params()
        return tuple((k, p.get(k, d)) for k, d in sorted(rules.items()))


@dataclass(frozen=True)
class Choice:
    """The call's codec: the profile's name for it, and the caller's payload
    type and parameters, which every other party is offered."""
    name: str
    offered: Offered

    def matches(self, other: Offered) -> bool:
        return other.key == self.offered.key and other.layout() == self.offered.layout()


def payload_type(text: str) -> Optional[int]:
    """An RTP payload type from SDP text, or None: RTP carries 7 bits of it
    (RFC 3550 5.1), so a number outside 0..127 names nothing the relay could
    send or receive."""
    if not (text.isascii() and text.isdigit()) or len(text) > 3:
        return None
    pt = int(text)
    return pt if pt <= 127 else None


def is_audio_line(parts: Sequence[str]) -> bool:
    """The fields of a usable audio m-line: media, a numeric port, proto and
    at least one format. core/sip.py parse_sdp takes the address from the
    same line."""
    return len(parts) >= 4 and parts[0] == "audio" and \
        parts[1].isascii() and parts[1].isdigit()


def audio_payloads(sdp: str) -> List[Offered]:
    """The payload types of the first usable audio m-line, in offer order,
    with their rtpmap (or the static one) and fmtp. A dynamic type without
    an rtpmap names no codec and is left out, and so is a number RTP cannot
    carry."""
    fmt: List[int] = []
    rtpmap: Dict[int, str] = {}
    fmtp: Dict[int, str] = {}
    in_audio = False
    for raw in sdp.splitlines():
        line = raw.strip()
        if line.startswith("m="):
            if in_audio:
                break                                  # only the first audio line
            parts = line[2:].split()
            in_audio = is_audio_line(parts)
            if in_audio:
                fmt = [pt for pt in map(payload_type, parts[3:]) if pt is not None]
            continue
        if not in_audio:
            continue
        m = _RTPMAP.match(line)
        if m:
            name = f"{m.group(2)}/{m.group(3)}" + (f"/{m.group(4)}" if m.group(4) else "")
            rtpmap[int(m.group(1))] = name
            continue
        m = _FMTP.match(line)
        if m:
            fmtp[int(m.group(1))] = m.group(2).strip()
    out: List[Offered] = []
    for pt in fmt:
        # An rtpmap is the SDP's own word for a number, a static one included.
        name = rtpmap.get(pt) or STATIC_PAYLOAD_TYPES.get(pt)
        if name:
            out.append(Offered(pt, name, fmtp.get(pt, "")))
    return out


def choose(offer_sdp: str, preference: Sequence[str]) -> Optional[Choice]:
    """The call's codec: the first codec in the profile's order that the
    offer carries (PLT-MED-002: never one the caller did not offer). Among
    several variants of it, the bandwidth-efficient AMR layout wins (TS 26.179
    4.1.3), else the caller's first. None: 488."""
    offered = audio_payloads(offer_sdp)
    for name in preference:
        k = key_of(name)
        variants = [o for o in offered if o.key == k]
        if not variants:
            continue
        if k[0] in ("AMR", "AMR-WB"):
            efficient = [v for v in variants if v.params().get("octet-align", "0") == "0"]
            variants = efficient or variants
        return Choice(name, variants[0])
    return None


def match(sdp: str, choice: Choice) -> Optional[int]:
    """The payload type `sdp` uses for the call's codec with the same
    payload layout, or None: that party cannot be relayed to untranscoded."""
    for o in audio_payloads(sdp):
        if choice.matches(o):
            return o.pt
    return None
