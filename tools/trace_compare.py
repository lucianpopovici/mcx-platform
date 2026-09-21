#!/usr/bin/env python3
"""Floor-control trace comparator (VP1-FC-002).

Reads a trace of floor control packets and reports every deviation from the
expected encoding and flow. It deliberately does NOT import `core.rtcp`: it
re-reads the bytes with its own table, so a mistake in the encoder cannot hide
behind the same mistake in the checker.

HONEST LIMIT (FC-OP-03, VP-OP-02): the expectations below were written by the
same author from the same recollection of TS 24.380 as the encoder, because
the specification text was not available. Agreement between the two is a
consistency check, NOT evidence of conformance. VP1-FC-002 needs either the
specification checked constant by constant, or golden captures from a
third-party implementation.

Trace file format (JSON lines): {"dir": "in"|"out", "uri": "...", "hex": "..."}
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

NAME = b"MCPT"
TYPES = {0: "request", 1: "granted", 2: "taken", 3: "deny", 4: "release",
         5: "idle", 6: "revoke", 7: "revoke-request",
         8: "queue-position-request", 9: "queue-position-info", 10: "ack",
         11: "unicast-media-flow-control", 14: "queued-floor-requests",
         15: "release-multi-talker"}
FROM_CLIENT = {"request", "release", "queue-position-request", "ack"}
FROM_SERVER = {"granted", "deny", "idle", "taken", "revoke",
               "queue-position-info"}
# id -> (name, exact value length in octets or None if variable).
# TS 24.380 clause 8.2.3.x, read from the prose under each field diagram
# (PLT-CONF-AUDIT CA-03). Read from the specification independently of
# core/rtcp.py, which this tool deliberately does not import -- agreeing with
# the encoder is only evidence if the two were derived separately.
FIELDS = {0: ("priority", 2), 1: ("duration", 2), 2: ("reject-cause", None),
          3: ("queue-info", 2), 4: ("granted-party", None),
          5: ("permission", 2), 6: ("user-id", None), 7: ("queue-size", 2),
          8: ("sequence", 2), 9: ("queued-user-id", None),
          # 8.2.3.12: a 16-bit binary value. Was None here and in the encoder,
          # in both cases unchecked.
          10: ("source", 2),
          11: ("track-info", None), 12: ("acked-type", 2),
          13: ("floor-indicator", 2),
          # 8.2.3.16: 32-bit SSRC plus 16 spare bits. Absent here entirely, so
          # a conformant Floor Taken carrying it was reported as "field id 14".
          14: ("ssrc", 6)}
# message -> (required, permitted-in-addition)
SHAPE = {
    "request": ({"priority"}, {"user-id", "track-info", "sequence"}),
    "release": (set(), {"track-info", "sequence", "user-id"}),
    "queue-position-request": (set(), {"track-info", "sequence", "user-id"}),
    "ack": ({"acked-type"}, {"sequence", "user-id"}),
    "granted": ({"priority", "duration", "sequence"},
                {"queue-info", "granted-party", "track-info", "ssrc",
                 "user-id", "queue-size", "queued-user-id",
                 "floor-indicator"}),
    "deny": ({"reject-cause", "sequence"}, {"track-info"}),
    "idle": ({"sequence"}, {"track-info"}),
    # Table 8.2.9-1 permits nine more fields than were listed here; the
    # comparator reported a conformant Floor Taken carrying any of them as a
    # deviation. Only the ones this platform can encode are added: the rest
    # are CA-13 (see PLT-CONF-AUDIT), because SHAPE has never been verified
    # against the message content tables as a whole.
    "taken": ({"granted-party", "sequence"},
              {"permission", "track-info", "ssrc", "user-id",
               "floor-indicator"}),
    "revoke": ({"reject-cause", "sequence"}, {"track-info"}),
    "queue-position-info": ({"queue-info", "sequence"}, {"track-info"}),
}


@dataclass(frozen=True)
class Deviation:
    index: int
    uri: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"#{self.index} {self.uri}: [{self.code}] {self.message}"


def parse(data: bytes):
    """-> (type name, ssrc, {field name: value bytes}) or raises ValueError."""
    if len(data) < 12 or len(data) % 4:
        raise ValueError("length is not a whole number of words >= 12 octets")
    b0, pt, words = struct.unpack(">BBH", data[:4])
    if b0 >> 6 != 2:
        raise ValueError(f"version {b0 >> 6}")
    if b0 & 0x20:
        raise ValueError("padding bit set")
    if pt != 204:
        raise ValueError(f"packet type {pt}")
    if (words + 1) * 4 != len(data):
        raise ValueError(f"length field {words} does not match {len(data)} octets")
    if data[8:12] != NAME:
        raise ValueError(f"name {data[8:12]!r}")
    name = TYPES.get(b0 & 0x0F)
    if name is None:
        raise ValueError(f"subtype {b0 & 0x0F}")
    fields: Dict[str, bytes] = {}
    i = 12
    while i < len(data):
        if i + 2 > len(data):
            raise ValueError("truncated field header")
        fid, ln = data[i], data[i + 1]
        if fid not in FIELDS:
            raise ValueError(f"field id {fid}")
        fname, fixed = FIELDS[fid]
        if fixed is not None and ln != fixed:
            raise ValueError(f"field {fname} length {ln}, expected {fixed}")
        end = i + 2 + ln
        pad = (-(2 + ln)) % 4
        if end + pad > len(data) or data[end:end + pad] != b"\0" * pad:
            raise ValueError(f"field {fname} padding")
        if fname in fields:
            raise ValueError(f"duplicate field {fname}")
        fields[fname] = data[i + 2:end]
        i = end + pad
    return name, struct.unpack(">I", data[4:8])[0], fields


def compare(trace: Iterable[Tuple[str, str, bytes]]) -> List[Deviation]:
    out: List[Deviation] = []
    last_seq: Dict[str, int] = {}
    holder: Optional[str] = None
    idle_since_grant = True
    pending_requests: Dict[str, int] = {}
    for i, (direction, uri, data) in enumerate(trace):
        def bad(code: str, msg: str) -> None:
            out.append(Deviation(i, uri, code, msg))
        try:
            name, _ssrc, f = parse(data)
        except ValueError as exc:
            bad("encoding", str(exc))
            continue
        allowed = FROM_CLIENT if direction == "in" else FROM_SERVER
        if name not in allowed:
            bad("direction", f"{name} is not sent {'by' if direction == 'in' else 'to'} "
                             "a client")
            continue
        required, extra = SHAPE[name]
        for r in sorted(required - set(f)):
            bad("missing-field", f"{name} lacks {r}")
        for x in sorted(set(f) - required - extra):
            bad("unexpected-field", f"{name} carries {x}")

        if direction == "out":
            seq = struct.unpack(">H", f["sequence"])[0] if "sequence" in f else None
            if seq is not None:
                prev = last_seq.get(uri)
                if prev is not None and seq != (prev + 1) & 0xFFFF:
                    bad("sequence", f"sequence {seq} after {prev}")
                last_seq[uri] = seq
            if name == "granted":
                if holder is not None and not idle_since_grant and holder != uri:
                    bad("flow", f"granted to {uri} while {holder} still holds")
                holder, idle_since_grant = uri, False
            elif name == "idle":
                holder, idle_since_grant = None, True
            elif name == "taken":
                named = f.get("granted-party", b"").decode("utf-8", "replace")
                if holder is not None and named != holder:
                    bad("flow", f"taken names {named}, holder is {holder}")
                if uri == named:
                    bad("flow", "taken sent to the party it names")
                holder, idle_since_grant = named or holder, False
            elif name == "deny":
                if pending_requests.get(uri, 0) < 1:
                    bad("flow", "deny without a request from this party")
                else:
                    pending_requests[uri] -= 1
        else:
            if name == "request":
                pending_requests[uri] = pending_requests.get(uri, 0) + 1
    return out


def load(path: str) -> List[Tuple[str, str, bytes]]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                rows.append((r["dir"], r["uri"], bytes.fromhex(r["hex"])))
    return rows


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("trace")
    args = ap.parse_args(argv)
    deviations = compare(load(args.trace))
    for d in deviations:
        print(d)
    print(f"{len(deviations)} deviation(s)")
    return 1 if deviations else 0


if __name__ == "__main__":
    sys.exit(main())
