"""Decide each ENV-E2E case from the capture.

tshark decrypts SIP with the clients' TLS key log and decodes floor control
with Wireshark's own MCPTT dissector (RTCP APP "MCPT"); RTP is read by its
payload type. Nothing here imports `core` or `service`, and nothing trusts what
the client believed it sent or received: every verdict below is about bytes
that crossed the loopback interface.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import trace_compare  # noqa: E402  (tools/trace_compare.py)
from flows import EXPECTED, match_flow  # noqa: E402
from tags import check_message  # noqa: E402

# Wireshark's names for the floor messages (its RTCP dissector, packet-rtcp.c,
# "MCPTT" APP subtypes), lower-cased. Its table, not the platform's or ours.
FROM_CLIENT = {"floor request", "floor release", "floor queue position request"}
FROM_SERVER = {"floor granted", "floor taken", "floor deny", "floor idle",
               "floor revoke", "floor queue position info"}
FC_001 = {  # VP1-FC-001's eight, as the plan names them -> Wireshark's names
    "request": {"floor request"}, "granted": {"floor granted"},
    "taken": {"floor taken"}, "deny": {"floor deny"}, "release": {"floor release"},
    "idle": {"floor idle"}, "revoke": {"floor revoke"},
    # "queue position" is an exchange: the client's request and the server's
    # info (TS 24.380 8.2.11, 8.2.12); both must be seen.
    "queue position request": {"floor queue position request"},
    "queue position info": {"floor queue position info"},
}


class Report:
    def __init__(self) -> None:
        self.cases: Dict[str, dict] = {}

    def step(self, cases: Sequence[str], name: str, ok: bool, evidence: str = "") -> bool:
        for c in cases:
            r = self.cases.setdefault(c, {"passed": True, "steps": []})
            r["steps"].append({"name": name, "verdict": "PASS" if ok else "FAIL",
                               "evidence": evidence})
            r["passed"] = r["passed"] and ok
        return ok


# -- tshark ------------------------------------------------------------------------

def tshark(work: Path, decode: Iterable[str], display: str, layers: str) -> List[dict]:
    argv = ["tshark", "-r", str(work / "capture.pcap"),
            "-o", f"tls.keylog_file:{work / 'keys.log'}", "-T", "json", "-j", layers,
            "-Y", display]
    for d in decode:
        argv += ["-d", d]
    out = subprocess.run(argv, capture_output=True, text=True, check=True).stdout
    return [p["_source"]["layers"] for p in json.loads(out or "[]")]


def _first(v):
    return v[0] if isinstance(v, list) else v


def sip_messages(work: Path, runs: List[dict]) -> List[dict]:
    """Every SIP message on the wire, decrypted, in capture order."""
    ports = sorted({r["sip_port"] for r in runs})
    decode = [d for p in ports for d in (f"tcp.port=={p},tls", f"tls.port=={p},sip")]
    out: List[dict] = []
    for layers in tshark(work, decode, "sip", "frame tcp sip"):
        frame = int(_first(layers["frame"]["frame.number"]))
        src, dst = int(_first(layers["tcp"]["tcp.srcport"])), int(_first(layers["tcp"]["tcp.dstport"]))
        sips = layers["sip"] if isinstance(layers["sip"], list) else [layers["sip"]]
        for k, s in enumerate(sips):
            start = s.get("sip.Request-Line") or s.get("sip.Status-Line") or ""
            hdr = s.get("sip.msg_hdr", "")
            body = bytes.fromhex(s.get("sip.msg_body", "").replace(":", "")).decode(
                "utf-8", "replace") if s.get("sip.msg_body") else ""
            out.append({"frame": frame, "index": k, "src": src, "dst": dst,
                        "start": start, "text": f"{start}\r\n{hdr}{body}",
                        "from_platform": src in ports, "sip_port": src if src in ports else dst,
                        "peer_port": dst if src in ports else src})
    return out


def _records(tls) -> Iterable[dict]:
    """The TLS records of one frame's tls layer, however tshark nests them."""
    if isinstance(tls, list):
        for t in tls:
            yield from _records(t)
    elif isinstance(tls, dict):
        r = tls.get("tls.record")
        for one in (r if isinstance(r, list) else [r] if r is not None else []):
            if isinstance(one, dict):
                yield one


def tls_records(work: Path, runs: List[dict]) -> dict:
    """Review H2: what "all N messages" rests on. Every encrypted record on
    the SIP ports (TLS 1.3 outer type 23) is either decrypted (tshark gives it
    an inner content type) or listed as not; every frame carrying decrypted
    application data either holds SIP or is reassembled into a later frame
    that does."""
    ports = sorted({r["sip_port"] for r in runs})
    decode = [d for p in ports for d in (f"tcp.port=={p},tls", f"tls.port=={p},sip")]
    argv = ["tshark", "-r", str(work / "capture.pcap"),
            "-o", f"tls.keylog_file:{work / 'keys.log'}", "-T", "json",
            "-J", "frame tcp tls sip", "-Y", "tls"]
    for d in decode:
        argv += ["-d", d]
    out = subprocess.run(argv, capture_output=True, text=True, check=True).stdout
    encrypted, undecrypted, app_frames, not_sip = 0, [], 0, []
    peers: Dict[int, int] = {}      # undecrypted frame -> the port not a SIP port
    for p in json.loads(out or "[]"):
        layers = p["_source"]["layers"]
        frame = int(_first(layers["frame"]["frame.number"]))
        tcp = layers.get("tcp", {})
        src, dst = int(_first(tcp.get("tcp.srcport", 0))), int(_first(tcp.get("tcp.dstport", 0)))
        app = False
        for r in _records(layers.get("tls")):
            if r.get("tls.record.opaque_type") != "23":
                continue
            encrypted += 1
            inner = r.get("tls.record.content_type")
            if inner is None:
                undecrypted.append(frame)
                peers[frame] = dst if src in ports else src
            app = app or inner == "23"
        if app:
            app_frames += 1
            if "sip" not in layers and "reassembled_in" not in json.dumps(layers):
                not_sip.append(frame)
    return {"encrypted": encrypted, "undecrypted": sorted(set(undecrypted)),
            "undecrypted_peers": sorted(set(peers.values())),
            "application_frames": app_frames, "not_sip": not_sip}


def header(text: str, name: str) -> List[str]:
    out = []
    for line in text.split("\r\n\r\n", 1)[0].split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if k.strip().lower() == name.lower():
            out.append(v.strip())
    return out


def body_sdp(text: str) -> str:
    body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
    m = re.search(r"(?s)(v=0\r?\n.*?)(?:\r?\n--|\Z)", body)
    return m.group(1) if m else ""


def audio_formats(sdp: str) -> Tuple[List[int], Dict[int, str]]:
    m = re.search(r"(?m)^m=audio \d+ RTP/AVP ([\d ]+)", sdp)
    pts = [int(x) for x in m.group(1).split()] if m else []
    maps = {int(a): b.strip() for a, b in re.findall(r"(?m)^a=rtpmap:(\d+) (\S+)", sdp)}
    return pts, maps


def label(msg: dict, clients: Dict[int, str]) -> Tuple[str, str]:
    """(direction like 'c1>P' or 'P>c2', kind like 'INVITE' or '200 INVITE')."""
    who = clients.get(msg["peer_port"], f"port{msg['peer_port']}")
    direction = f"P>{who}" if msg["from_platform"] else f"{who}>P"
    start = msg["start"]
    if start.startswith("SIP/2.0 "):
        code = start.split()[1]
        method = (header(msg["text"], "CSeq") or [" ?"])[0].split()[-1]
        kind = f"{code} {method}"
    else:
        kind = start.split()[0]
    return direction, kind


# -- the checks ----------------------------------------------------------------------

def check_tags(rep: Report, messages: List[dict], records: dict) -> None:
    """VP1-SIG-003: every SIP message of every scenario, by the table in
    tools/e2e/tags.py (TS 24.379) -- and "every" is shown, not assumed: no
    encrypted record on the SIP ports is left undecrypted, and all decrypted
    application data is SIP (review H2)."""
    whole = not records["undecrypted"] and not records["not_sip"] and \
        records["application_frames"] > 0
    rep.step(["VP1-SIG-003"], f"all {records['encrypted']} encrypted TLS records on the SIP "
             f"ports decrypted, and the application data in all "
             f"{records['application_frames']} frames that carry it is SIP", whole,
             f"undecrypted in frames {records['undecrypted'][:8]}; "
             f"not SIP in frames {records['not_sip'][:8]}")
    bad, counted = [], {}
    for m in messages:
        verdict, rule = check_message(m["text"], m["from_platform"])
        counted[rule] = counted.get(rule, 0) + 1
        if verdict:
            bad.append(f"frame {m['frame']} {m['start']}: {verdict}")
    rep.step(["VP1-SIG-003"], f"feature tags on all {len(messages)} SIP messages "
             f"(decrypted from the capture with the clients' TLS keys)",
             not bad and len(messages) > 0,
             "; ".join(bad[:8]) or json.dumps(counted, sort_keys=True))


def check_private(rep: Report, run: dict, messages: List[dict], case: str) -> None:
    ids = {run["call_id"], run["callee_call_id"]}
    clients = {c["sip_port"]: f"c{i + 1}" for i, c in enumerate(run["clients"])}
    mine = [m for m in messages if (header(m["text"], "Call-ID") or [""])[0] in ids]
    seq = [label(m, clients) for m in mine]
    ok, why = match_flow(seq, EXPECTED[run["scenario"]])
    # The flow is ordered: the caller's 200 OK comes only after the callee's,
    # so the call is established only once the callee accepted.
    rep.step([case], f"{run['scenario']}: the captured messages are the expected flow, "
             f"the caller's 200 OK only after the callee's ({len(seq)} messages)",
             ok, why or " ".join(f"{d}:{k}" for d, k in seq))
    to_callee = [m for m in mine if label(m, clients) == ("P>c2", "INVITE")]
    if to_callee:
        t = to_callee[0]["text"]
        priv, plain = header(t, "Priv-Answer-Mode"), header(t, "Answer-Mode")
        if case == "VP1-CC-003":
            rep.step([case], "manual commencement: Answer-Mode: Manual, no Priv-Answer-Mode",
                     plain == ["Manual"] and not priv, f"Answer-Mode={plain} Priv={priv}")
        else:
            rep.step([case], "automatic commencement: Priv-Answer-Mode: Auto, no Answer-Mode",
                     priv == ["Auto"] and not plain, f"Answer-Mode={plain} Priv={priv}")
    else:
        rep.step([case], "the platform invited the callee", False, "no INVITE to c2")
    # The harness's own fidelity, read from the wire (review H6): the callee
    # answered as TS 24.379 6.2.3.1.1 and 6.2.3.2.1 have a client answer.
    answers = [m for m in mine if label(m, clients)[0] == "c2>P"
               and label(m, clients)[1] in ("180 INVITE", "200 INVITE")]
    faults = []
    for m in answers:
        kind = label(m, clients)[1]
        if "timer" not in [t.strip().lower() for v in header(m["text"], "Require")
                           for t in v.split(",")]:
            faults.append(f"{kind}: no Require: timer")
        if kind == "200 INVITE":
            se = header(m["text"], "Session-Expires") or header(m["text"], "x")
            if len(se) != 1 or not re.search(r"(?i);\s*refresher\s*=\s*uas\b", se[0]):
                faults.append(f"200 INVITE: Session-Expires is {se}, not refresher=uas")
    rep.step([case], "the callee's 180/200 carry Require: timer, its 200 Session-Expires "
             "with refresher=uas (TS 24.379 6.2.3.1.1, 6.2.3.2.1: the client is conformant)",
             bool(answers) and not faults, "; ".join(faults) or "no answer from c2")


def rtp_packets(work: Path, runs: List[dict]) -> List[dict]:
    ports = sorted({p for r in runs for c in r["clients"]
                    for p in (c["rtp"], c["relay_rtp"]) if p})
    out = []
    for layers in tshark(work, [f"udp.port=={p},rtp" for p in ports], "rtp", "frame udp rtp"):
        out.append({"frame": int(_first(layers["frame"]["frame.number"])),
                    "src": int(_first(layers["udp"]["udp.srcport"])),
                    "dst": int(_first(layers["udp"]["udp.dstport"])),
                    "pt": int(_first(layers["rtp"]["rtp.p_type"]))})
    return out


def check_media(rep: Report, runs: Dict[str, dict], messages: List[dict],
                rtp: List[dict]) -> None:
    g = runs["group-floor"]
    clients = {c["sip_port"]: f"c{i + 1}" for i, c in enumerate(g["clients"])}
    ids = {g["call_id"], g["callee_call_id"]}
    mine = [m for m in messages if (header(m["text"], "Call-ID") or [""])[0] in ids]
    by = {label(m, clients): m for m in mine}
    offer = body_sdp(by.get(("c1>P", "INVITE"), {}).get("text", ""))
    answer = body_sdp(by.get(("P>c1", "200 INVITE"), {}).get("text", ""))
    to_callee = body_sdp(by.get(("P>c2", "INVITE"), {}).get("text", ""))
    o_pts, o_map = audio_formats(offer)
    a_pts, a_map = audio_formats(answer)
    c_pts, c_map = audio_formats(to_callee)
    names = lambda pts, m: [m.get(p, str(p)) for p in pts]  # noqa: E731
    rep.step(["VP1-MED-001", "VP1-MED-002"],
             "the caller offered an undeclared codec first, then two declared ones",
             names(o_pts, o_map)[:1] == ["opus/48000/2"] and len(o_pts) == 3,
             f"offer: {names(o_pts, o_map)}")
    rep.step(["VP1-MED-001", "VP1-MED-002"],
             "the answer to the caller carries the profile's first offered codec alone "
             "(AMR-WB, mcx's order: EVS, AMR-WB, ...)",
             names(a_pts, a_map) == ["AMR-WB/16000"], f"answer: {names(a_pts, a_map)}")
    rep.step(["VP1-MED-001"], "the callee is offered that codec alone",
             names(c_pts, c_map) == ["AMR-WB/16000"], f"offer to c2: {names(c_pts, c_map)}")
    c1, c2 = g["clients"]
    sent = sorted({p["pt"] for p in rtp if p["src"] == c1["rtp"]})
    to_c2 = sorted({p["pt"] for p in rtp if p["dst"] == c2["rtp"]})
    to_c1 = sorted({p["pt"] for p in rtp if p["dst"] == c1["rtp"]})
    count_c2 = sum(1 for p in rtp if p["dst"] == c2["rtp"])
    rep.step(["VP1-MED-001"], "the caller sent RTP in the undeclared and the unchosen "
             "codecs as well as AMR-WB", sent == [0, 96, 111], f"sent: {sent}")
    rep.step(["VP1-MED-001"], "the relay forwarded only AMR-WB, to both clients",
             to_c2 == [96] and to_c1 == [96] and count_c2 > 50,
             f"to c2: {to_c2} ({count_c2} packets), to c1: {to_c1}")
    p = runs["private-manual"]
    pc2 = p["clients"][1]
    rep.step(["VP1-MED-001"], "private call: PCMU, the one codec offered, end to end",
             sorted({x["pt"] for x in rtp if x["dst"] == pc2["rtp"]}) == [0],
             str(sorted({x["pt"] for x in rtp if x["dst"] == pc2["rtp"]})))
    r = runs["codec-refused"]
    rc = {c["sip_port"]: f"c{i + 1}" for i, c in enumerate(r["clients"])}
    refused = [label(m, rc) for m in messages if (header(m["text"], "Call-ID") or [""])[0]
               == r["call_id"]]
    rep.step(["VP1-MED-002"], "an offer with no declared codec (opus alone) is refused 488",
             ("P>c1", "488 INVITE") in refused and ("P>c1", "200 INVITE") not in refused,
             " ".join(f"{d}:{k}" for d, k in refused))
    callee_port = r["clients"][1]["sip_port"]
    first = min((m["frame"] for m in messages
                 if (header(m["text"], "Call-ID") or [""])[0] == r["call_id"]), default=0)
    invited = [m for m in messages if m["frame"] >= first and m["peer_port"] == callee_port
               and m["from_platform"] and m["start"].startswith("INVITE")]
    rep.step(["VP1-MED-002"], "nobody is invited for the refused offer", first > 0 and
             not invited, f"{len(invited)} INVITE(s) to c2")


def _floor_display(ports: Sequence[int]) -> str:
    """The group call's floor packets only: the private calls have floor
    streams of their own, which Wireshark also names MCPT, and a packet of
    theirs must not stand in for one of the group call's."""
    return f'rtcp.app.name == "MCPT" && udp.port in {{{", ".join(map(str, ports))}}}'


def floor_packets(work: Path, run: dict) -> List[dict]:
    ports = sorted({p for c in run["clients"] for p in (c["floor"], c["relay_floor"]) if p})
    out = []
    layers_all = tshark(work, [f"udp.port=={p},rtcp" for p in ports],
                        _floor_display(ports), "frame udp rtcp _ws.malformed")
    for layers in layers_all:
        info = json.dumps(layers.get("rtcp", {}))
        sub = re.findall(r'"rtcp\.app\.subtype":\s*"(\d+)"', info)
        out.append({"frame": int(_first(layers["frame"]["frame.number"])),
                    "src": int(_first(layers["udp"]["udp.srcport"])),
                    "dst": int(_first(layers["udp"]["udp.dstport"])),
                    "payload": bytes.fromhex(_first(layers["udp"].get("udp.payload", ""))
                                             .replace(":", "")),
                    "subtype": int(sub[0]) if sub else None,
                    "malformed": "_ws.malformed" in layers})
    return out


def wireshark_names(work: Path, run: dict) -> Dict[int, str]:
    """frame -> the message name in Wireshark's Info column."""
    ports = sorted({p for c in run["clients"] for p in (c["floor"], c["relay_floor"]) if p})
    argv = ["tshark", "-r", str(work / "capture.pcap"), "-Y", _floor_display(ports),
            "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Info"]
    for p in ports:
        argv += ["-d", f"udp.port=={p},rtcp"]
    out = subprocess.run(argv, capture_output=True, text=True, check=True).stdout
    names = {}
    for line in out.splitlines():
        frame, _, info = line.partition("\t")
        # "(MCPT) Floor Deny - Other reason": the name, before any cause.
        m = re.search(r"(Floor [A-Za-z ]+?)(?:\s*[-(,]|$)", info)
        names[int(frame)] = (m.group(1) if m else info).strip().lower()
    return names


# TS 24.380 8.2.4-8.2.12, the mandatory fields of each message, as Wireshark
# names them (its fields, not ours): message -> fields that must be decoded.
MANDATORY = {
    "floor request": ["rtcp.app_data.mcptt.priority"],
    "floor granted": ["rtcp.app_data.mcptt.duration", "rtcp.app_data.mcptt.priority"],
    "floor taken": ["rtcp.mcptt.granted_partys_id", "rtcp.app_data.mcptt.msg_seq_num"],
    "floor deny": ["rtcp.app_data.mcptt.rej_cause.floor_deny"],
    "floor revoke": ["rtcp.app_data.mcptt.rej_cause.floor_revoke"],
    "floor idle": ["rtcp.app_data.mcptt.msg_seq_num"],
    "floor queue position info": ["rtcp.app_data.mcptt.queue_pos_inf"],
}


def wireshark_fields(work: Path, run: dict) -> Dict[int, Dict[str, str]]:
    ports = sorted({p for c in run["clients"] for p in (c["floor"], c["relay_floor"]) if p})
    names = sorted({f for v in MANDATORY.values() for f in v})
    argv = ["tshark", "-r", str(work / "capture.pcap"), "-Y", _floor_display(ports),
            "-T", "fields", "-E", "occurrence=f", "-e", "frame.number"]
    for f in names:
        argv += ["-e", f]
    for p in ports:
        argv += ["-d", f"udp.port=={p},rtcp"]
    out = subprocess.run(argv, capture_output=True, text=True, check=True).stdout
    rows = {}
    for line in out.splitlines():
        cols = line.split("\t")
        rows[int(cols[0])] = {n: v for n, v in zip(names, cols[1:]) if v != ""}
    return rows


def check_floor(rep: Report, run: dict, pkts: List[dict], names: Dict[int, str],
                fields: Dict[int, Dict[str, str]]) -> List[dict]:
    floor_of = {c["floor"]: c["aor"] for c in run["clients"]}
    seen: Dict[str, set] = {"in": set(), "out": set()}
    wrong, trace = [], []
    for p in pkts:
        name = names.get(p["frame"], "?")
        if p["src"] in floor_of:
            d, uri = "in", floor_of[p["src"]]
        elif p["dst"] in floor_of:
            d, uri = "out", floor_of[p["dst"]]
        else:
            continue
        seen[d].add(name)
        if (d == "in") != (name in FROM_CLIENT) or p["malformed"]:
            wrong.append(f"frame {p['frame']} {d} {name}{' (malformed)' if p['malformed'] else ''}")
        trace.append({"dir": d, "uri": uri, "hex": p["payload"].hex(), "frame": p["frame"],
                      "wireshark": name})
    missing = [k for k, v in FC_001.items() if not v & (seen["in"] | seen["out"])]
    # The eight of the plan, the queue position exchange counted once.
    rep.step(["VP1-FC-001"], "each of the eight messages crossed the wire, named by "
             "Wireshark's MCPTT dissector", not missing and len(trace) > 0,
             f"missing: {missing}; client->server: {sorted(seen['in'])}; "
             f"server->client: {sorted(seen['out'])}")
    rep.step(["VP1-FC-001"], "each in its direction (request, release, queue position "
             "request from a client; the rest from the server), none malformed",
             not wrong and len(trace) > 0, "; ".join(wrong[:6]) or f"{len(trace)} messages")
    unparsed, revoke_causes, taken_named = [], set(), set()
    for t in trace:
        got = fields.get(t["frame"], {})
        for f in MANDATORY.get(t["wireshark"], []):
            if f not in got:
                unparsed.append(f"frame {t['frame']} {t['wireshark']}: no {f}")
        if t["wireshark"] == "floor revoke":
            revoke_causes.add(got.get("rtcp.app_data.mcptt.rej_cause.floor_revoke"))
        if t["wireshark"] == "floor taken":
            taken_named.add(got.get("rtcp.mcptt.granted_partys_id"))
    aors = {c["aor"] for c in run["clients"]}
    rep.step(["VP1-FC-001"], "Wireshark decodes each message's mandatory fields "
             "(TS 24.380 8.2.4-8.2.12); the revoke after T2 says #2 'media burst too "
             "long'; Floor Taken names a party of the call",
             not unparsed and revoke_causes == {"2"} and bool(taken_named)
             and taken_named <= aors,
             "; ".join(unparsed[:6]) or f"revoke causes {sorted(revoke_causes)}, "
             f"taken names {sorted(taken_named)}")
    rows = [(t["dir"], t["uri"], bytes.fromhex(t["hex"])) for t in trace]
    deviations = trace_compare.compare(rows)
    rep.step(["VP1-FC-001"], "the floor trace from the capture passes tools/trace_compare.py",
             not deviations and len(rows) > 0,
             "; ".join(str(d) for d in deviations[:6]) or f"{len(rows)} packets, 0 deviations")
    return trace


def decode(work: Path, runs: List[dict]) -> dict:
    """Everything the verdicts need, read from the capture by tshark, as plain
    data (JSON-able: floor payloads as hex)."""
    group = next(r for r in runs if r["scenario"] == "group-floor")
    pkts = floor_packets(work, group)
    return {"messages": sip_messages(work, runs), "tls": tls_records(work, runs),
            "rtp": rtp_packets(work, runs),
            "floor": [dict(p, payload=p["payload"].hex()) for p in pkts],
            "names": {str(k): v for k, v in wireshark_names(work, group).items()},
            "fields": {str(k): v for k, v in wireshark_fields(work, group).items()}}


def judge(decoded: dict, runs: List[dict]) -> dict:
    """Each case's verdict from the decoded capture alone."""
    rep = Report()
    by = {r["scenario"]: r for r in runs}
    messages, rtp = decoded["messages"], decoded["rtp"]
    pkts = [dict(p, payload=bytes.fromhex(p["payload"])) for p in decoded["floor"]]
    names = {int(k): v for k, v in decoded["names"].items()}
    fields = {int(k): v for k, v in decoded["fields"].items()}
    check_tags(rep, messages, decoded["tls"])
    check_private(rep, by["private-manual"], messages, "VP1-CC-003")
    check_private(rep, by["private-auto"], messages, "VP1-CC-004")
    check_media(rep, by, messages, rtp)
    trace = check_floor(rep, by["group-floor"], pkts, names, fields)
    # R1 exit criterion 6 (PLT-VP-R1 §10): not a case of its own.
    g = by["group-floor"]
    granted_to = {t["uri"] for t in trace if t["dir"] == "out"
                  and t["wireshark"] == "floor granted"}
    exit6 = {
        "two clients in one prearranged group call": len(g["clients"]) == 2,
        "floor arbitrated: granted to each client in turn": len(granted_to) == 2,
        "captured, and the floor trace matched by the trace comparator":
            rep.cases["VP1-FC-001"]["steps"][-1]["verdict"] == "PASS",
    }
    return {"passed": all(r["passed"] for r in rep.cases.values()) and all(exit6.values()),
            "cases": rep.cases, "exit_criterion_6": exit6, "trace": trace,
            "sip_messages": len(messages), "floor_packets": len(trace),
            "rtp_packets": len(rtp)}


def analyse(work: Path, runs: List[dict]) -> dict:
    decoded = decode(work, runs)
    (work / "decoded.json").write_text(json.dumps(decoded, indent=1))
    (work / "sip-decrypted.txt").write_text("\n\n".join(
        f"=== frame {m['frame']} {'platform ->' if m['from_platform'] else '-> platform'} "
        f"port {m['peer_port']}\n{m['text']}" for m in decoded["messages"]))
    result = judge(decoded, runs)
    with open(work / "floor-trace.jsonl", "w") as fh:
        for t in result.pop("trace"):
            fh.write(json.dumps(t) + "\n")
    return result
