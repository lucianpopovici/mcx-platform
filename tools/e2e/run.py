#!/usr/bin/env python3
"""ENV-E2E (PLT-VP-R1 §2): the real process, the repository's independent MC
client, and a packet capture with the TLS keys to read it.

    python3 tools/e2e/run.py [--workdir DIR] [--results RUN.json]

Starts `python -m service` over TLS on loopback, captures the loopback
interface with tcpdump while the client runs the scenarios below, then hands
the capture, the TLS key log and what each scenario did to tools/e2e/analyse.py,
which decides each case from the WIRE -- tshark decrypts SIP with the key log
and decodes floor control with its own MCPTT dissector -- not from what the
client believed. Needs tcpdump (and the right to capture), tshark, and the
`cryptography` package (for the test PKI).

Scenarios, and the cases they serve:
  private-manual   VP1-CC-003 (and SIG-003): a private call the callee accepts
  private-auto     VP1-CC-004: the same with a session decision setting
                   auto-answer -- a copy of the mcx profile whose private call
                   type sets `auto_answer: true`, as no shipped profile does
  group-floor      VP1-FC-001, VP1-MED-001, R1 exit criterion 6: a prearranged
                   group call between two clients with floor arbitration
  codec-refused    VP1-MED-002: an offer with no codec the profile declares

Exit status 0 only if every case passed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "interop"))

import analyse  # noqa: E402
import pki  # noqa: E402
from mcclient import AMR_WB, OPUS, PCMU, MCClient, sdp_ports  # noqa: E402
from ua import body_part, header  # noqa: E402

DOMAIN = "mcptt.example"
AS_URI = f"sip:mcptt@{DOMAIN}"
U1, U2 = f"sip:u1@{DOMAIN}", f"sip:u2@{DOMAIN}"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class PlatformExited(RuntimeError):
    """The platform stopped before it answered: for one, its port was taken
    between free_port() and its bind (review H8)."""


def wait_tls(port: int, ca: Path, keylog: Path, timeout: float = 20.0,
             proc: Optional["Proc"] = None) -> None:
    """Until the platform answers TLS. The probe logs its keys like every
    client, so no record in the capture is left undecryptable (review H2)."""
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.check_hostname = False
    ctx.keylog_filename = str(keylog)
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.p.poll() is not None:
            raise PlatformExited(f"{proc.name} exited ({proc.p.returncode}); see {proc.log}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as raw:
                with ctx.wrap_socket(raw):
                    return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"nothing answering TLS on 127.0.0.1:{port}")


class Proc:
    def __init__(self, name: str, argv: List[str], log: Path,
                 env: Optional[Dict[str, str]] = None, cwd: Optional[Path] = None):
        self.name, self.log = name, log
        self.fh = open(log, "w")
        self.p = subprocess.Popen(argv, stdout=self.fh, stderr=subprocess.STDOUT,
                                  env=env, cwd=cwd, start_new_session=True)

    def stop(self, sig: int = signal.SIGTERM) -> None:
        if self.p.poll() is None:
            try:
                os.killpg(self.p.pid, sig)
                self.p.wait(timeout=10)
            except Exception:
                os.killpg(self.p.pid, signal.SIGKILL)
        self.fh.close()


def auto_answer_profiles(work: Path) -> Path:
    """A copy of the shipped profiles in which mcx's private call type sets
    auto_answer -- profile data only, the code is the same."""
    root = work / "profiles"
    if root.exists():
        shutil.rmtree(root)
    shutil.copytree(ROOT / "profiles", root)
    path = root / "mcx" / "profile.yaml"
    text = path.read_text()
    i = text.index("  - id: private\n")
    j = text.index("auto_answer: false", i)
    path.write_text(text[:j] + "auto_answer: true" + text[j + len("auto_answer: false"):])
    return root


def start_platform(work: Path, name: str,
                   profiles_root: Optional[Path] = None, attempts: int = 3) -> Tuple[Proc, int]:
    """The platform on a free port; another port if the one chosen was taken
    before the platform bound it (review H8). Returns (process, port)."""
    for n in range(attempts):
        port = free_port()
        proc = _start_platform(work, name, port, profiles_root)
        try:
            wait_tls(port, work / "pki/ca.crt", work / f"keys-00-{name}.log", proc=proc)
            return proc, port
        except PlatformExited:
            proc.stop()
            if n == attempts - 1:
                raise
    raise AssertionError("unreachable")


def _start_platform(work: Path, name: str, port: int,
                    profiles_root: Optional[Path] = None) -> Proc:
    data = work / f"data-{name}"
    data.mkdir(exist_ok=True)
    network = work / f"network-{name}.yaml"
    network.write_text(json.dumps({
        "name": "e2e", "version": "1", "environment": "test", "plmns": ["001010"],
        "cells": [], "sip": {"trusted_cores": [], "core_ca": "none"},
        "groups": [{"id": "grp:alpha", "display_name": "Alpha", "members": [U1, U2]}],
        "users": [U1, U2], "functional_aliases": []}))
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCX_")}
    env.update({
        "MCX_PROFILE": "mcx", "MCX_RELEASE": "19", "MCX_IDMS": "stub",
        "MCX_RECORDER": "stub", "MCX_BEARER": "stub", "MCX_STRICT_RELEASE": "true",
        "MCX_ADHOC_LIST_MAX": "100", "MCX_DATA_DIR": str(data),
        "MCX_HTTP_PORT": str(free_port()), "MCX_HTTP_TLS": "off",
        "MCX_SIP_LISTEN": f"127.0.0.1:{port}", "MCX_SIP_URI": AS_URI,
        "MCX_SIP_TLS_CERT": str(work / "pki/platform.crt"),
        "MCX_SIP_TLS_KEY": str(work / "pki/platform.key"),
        "MCX_SIP_TLS_CA": str(work / "pki/ca.crt"),
        "MCX_SIP_CLIENT_AUTH": "required", "MCX_SIP_ROLES": "participating,controlling",
        "MCX_SESSION_EXPIRES_MS": "1800000",
        "MCX_FLOOR_UNRECORDED": "deny", "MCX_FOREIGN_INITIATOR": "refuse",
        "MCX_GROUP_INITIATOR_LEAVES": "release", "MCX_ARP_VULNERABILITY_CHECK": "true",
        "MCX_ENV": "test", "MCX_SERVICE_REFUSAL_STATUS": "503",
        "MCX_DIALOG_TAKEOVER": "same-party", "MCX_LOCATION_REPORTS": "read",
        "MCX_NETWORK_FILE": str(network),
        "MCX_MEDIA_ADDRESS": "127.0.0.1", "MCX_MEDIA_PORTS": "0",
    })
    if profiles_root is not None:
        env["MCX_PROFILES_ROOT"] = str(profiles_root)
    return Proc(name, [sys.executable, "-m", "service"], work / f"platform-{name}.log",
                env=env, cwd=ROOT)


def wait_capture(capture: Proc, timeout: float = 10.0) -> str:
    """"" once tcpdump says it is listening; else why not (review H8: it
    waited a fixed second, and a capture without rights failed later, as a
    missing pcap)."""
    end = time.time() + timeout
    while time.time() < end:
        text = capture.log.read_text(errors="replace") if capture.log.exists() else ""
        if "listening on" in text:
            return ""
        if capture.p.poll() is not None:
            return text.strip() or f"tcpdump exited {capture.p.returncode}"
        time.sleep(0.05)
    return f"tcpdump said nothing in {timeout:.0f} s"


_KEYLOGS = [0]


def client(work: Path, aor: str, port: int, **kw) -> MCClient:
    # One key log per client: two TLS contexts appending to one file clobber
    # each other's lines (a damaged line left a direction undecryptable).
    # merge_keylogs() joins them for tshark.
    _KEYLOGS[0] += 1
    keylog = work / f"keys-{_KEYLOGS[0]:02d}.log"
    c = MCClient(aor, "127.0.0.1", port, str(work / "pki"), keylog=str(keylog), **kw)
    final = c.register()
    if not final.startswith("SIP/2.0 200"):
        raise RuntimeError(f"{aor}: REGISTER answered {final.splitlines()[0]}")
    return c


def merge_keylogs(work: Path) -> None:
    lines = []
    for f in sorted(work.glob("keys-*.log")):
        for line in f.read_text(errors="strict").splitlines():
            if line and not line.startswith("#"):
                if len(line.split()) != 3:
                    raise RuntimeError(f"{f.name}: damaged key log line {line[:40]!r}")
                lines.append(line)
    (work / "keys.log").write_text("\n".join(lines) + "\n")


def endpoints(c: MCClient) -> dict:
    return {"aor": c.aor, "sip_port": c.port, "rtp": c.media.rtp_port,
            "floor": c.media.floor_port,
            "relay_rtp": c.media.remote_rtp[1] if c.media.remote_rtp else None,
            "relay_floor": c.media.remote_floor[1] if c.media.remote_floor else None}


# -- scenarios -------------------------------------------------------------------

def private_call(work: Path, port: int, name: str) -> dict:
    """u1 calls u2; u2 answers as its client decides (manual: 180 first)."""
    u1, u2 = client(work, U1, port), client(work, U2, port)
    try:
        inv = u1.call(U2, "private", AS_URI)
        got, _ = u2.answer_incoming()
        ok = u1.wait(r"^SIP/2\.0 200", call_id=inv["call_id"], method="INVITE", timeout=15)
        u1.learn(body_part(ok, "application/sdp") or "")
        u1.ack(inv, ok)
        u1.media.talk(0, 0.4)
        time.sleep(0.3)
        u1.bye(inv["call_id"])
        u2.ok_bye()
        time.sleep(0.3)
        return {"scenario": name, "sip_port": port, "call_id": inv["call_id"],
                "callee_call_id": header(got, "Call-ID"),
                "clients": [endpoints(u1), endpoints(u2)],
                "callee_rtp_payload_types": sorted(set(u2.media.rtp_rx))}
    finally:
        u1.close()
        u2.close()


def group_floor(work: Path, port: int) -> dict:
    """A prearranged group call between u1 and u2 with floor arbitration, set
    to put every message of VP1-FC-001 on the wire. u1 offers an undeclared
    codec first (opus), then AMR-WB and PCMU: the profile prefers AMR-WB."""
    u1 = client(work, U1, port, codecs=(OPUS, AMR_WB, PCMU))
    u2 = client(work, U2, port, codecs=(AMR_WB, PCMU))
    steps: List[str] = []
    try:
        inv = u1.call("grp:alpha", "prearranged", AS_URI)
        got, _ = u2.answer_incoming()
        ok = u1.wait(r"^SIP/2\.0 200", call_id=inv["call_id"], method="INVITE", timeout=15)
        u1.learn(body_part(ok, "application/sdp") or "")
        u1.ack(inv, ok)
        # The initiator's implicit request (initial grant): Granted to u1,
        # Taken to u2.
        u1.media.wait_floor("granted")
        u2.media.wait_floor("taken")
        steps.append("u1 granted at setup, u2 told taken")
        # u2 asks while u1 talks: queued (Queue Position Info), then asks
        # where it stands.
        m = u2.media.mark()
        u2.media.send_floor(__import__("floor").floor_request(u2.media.ssrc, 5))
        u2.media.wait_floor("queue-position-info", after=m)
        m = u2.media.mark()
        u2.media.send_floor(__import__("floor").queue_position_request(u2.media.ssrc))
        u2.media.wait_floor("queue-position-info", after=m)
        steps.append("u2 queued; queue position asked and told")
        # u1 sends one packet each in the codec it offered but was not chosen
        # and in the undeclared one, then talks AMR-WB past T2 (4 s):
        # Floor Revoke.
        u1.media.talk(PCMU[0], 0.06)
        u1.media.talk(OPUS[0], 0.06)
        m = u1.media.mark()
        u1.media.talk(AMR_WB[0], 4.6)
        u1.media.wait_floor("revoke", after=m)
        steps.append("u1 revoked after talking past T2")
        # Asking again while being revoked: Floor Deny.
        m = u1.media.mark()
        u1.media.send_floor(__import__("floor").floor_request(u1.media.ssrc, 5))
        u1.media.wait_floor("deny", after=m)
        steps.append("u1 denied while revoked")
        # u1 releases: the queued u2 is granted, u1 told taken.
        m1, m2 = u1.media.mark(), u2.media.mark()
        u1.media.send_floor(__import__("floor").floor_release(u1.media.ssrc))
        u2.media.wait_floor("granted", after=m2)
        u1.media.wait_floor("taken", after=m1)
        steps.append("u1 released; u2 granted, u1 told taken")
        u2.media.talk(AMR_WB[0], 0.5)
        m1, m2 = u1.media.mark(), u2.media.mark()
        u2.media.send_floor(__import__("floor").floor_release(u2.media.ssrc))
        u1.media.wait_floor("idle", after=m1)
        u2.media.wait_floor("idle", after=m2)
        steps.append("u2 released; both told idle")
        time.sleep(0.3)
        u1.bye(inv["call_id"])
        u2.ok_bye()
        time.sleep(0.3)
        return {"scenario": "group-floor", "sip_port": port, "call_id": inv["call_id"],
                "callee_call_id": header(got, "Call-ID"),
                "clients": [endpoints(u1), endpoints(u2)], "steps": steps,
                "client_floor_rx": {u1.aor: [x["type"] for x in u1.media.floor_rx],
                                    u2.aor: [x["type"] for x in u2.media.floor_rx]},
                "callee_rtp_payload_types": sorted(set(u2.media.rtp_rx)),
                "caller_rtp_payload_types": sorted(set(u1.media.rtp_rx))}
    finally:
        u1.close()
        u2.close()


def codec_refused(work: Path, port: int) -> dict:
    """u1 offers opus only, which no shipped profile declares: refused, and
    nobody is invited."""
    u1 = client(work, U1, port, codecs=(OPUS,))
    u2 = client(work, U2, port)
    try:
        inv = u1.call(U2, "private", AS_URI)
        final = u1.wait(r"^SIP/2\.0 [3-6]\d\d", call_id=inv["call_id"], timeout=15)
        u1.ack_failure(inv, final)
        time.sleep(1.5)
        invited = [m for m in u2.rx if m.startswith("INVITE ")]
        return {"scenario": "codec-refused", "sip_port": port, "call_id": inv["call_id"],
                "clients": [endpoints(u1), endpoints(u2)],
                "final": final.split("\r\n", 1)[0], "callee_invites": len(invited)}
    finally:
        u1.close()
        u2.close()


# -- the run -----------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--workdir", type=Path)
    ap.add_argument("--results", type=Path, help="write the per-case results here")
    args = ap.parse_args(argv)
    for tool in ("tcpdump", "tshark"):
        if not shutil.which(tool):
            print(f"{tool} is not installed", file=sys.stderr)
            return 2
    work = args.workdir or Path(tempfile.mkdtemp(prefix="mcx-e2e-"))
    if work.exists():
        for f in ["capture.pcap", "keys.log"] + [p.name for p in work.glob("keys-*.log")]:
            (work / f).unlink(missing_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    pki.make(work / "pki", ["platform", "u1", "u2"], uris={"u1": [U1], "u2": [U2]})
    if not (work / "pki" / "trust.crt").exists():
        (work / "pki" / "trust.crt").write_bytes((work / "pki" / "ca.crt").read_bytes())
    capture = Proc("tcpdump", ["tcpdump", "-i", "lo", "-U", "-s", "0", "-w",
                               str(work / "capture.pcap"), "host", "127.0.0.1"],
                   work / "tcpdump.log")
    why = wait_capture(capture)
    if why:
        capture.stop()
        print(f"cannot capture on lo: {why}\n(run as root, or give tcpdump "
              f"CAP_NET_RAW and CAP_NET_ADMIN)", file=sys.stderr)
        return 2
    runs: List[dict] = []
    procs: List[Proc] = []
    try:
        proc, port = start_platform(work, "mcx")
        procs.append(proc)
        runs.append(private_call(work, port, "private-manual"))
        runs.append(group_floor(work, port))
        runs.append(codec_refused(work, port))
        procs.pop().stop()
        proc, port = start_platform(work, "mcx-auto", auto_answer_profiles(work))
        procs.append(proc)
        runs.append(private_call(work, port, "private-auto"))
    finally:
        for p in procs:
            p.stop()
        time.sleep(0.5)
        capture.stop(signal.SIGINT)
    merge_keylogs(work)
    (work / "scenarios.json").write_text(json.dumps(runs, indent=1))
    commit = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=ROOT,
                            capture_output=True, text=True).stdout.strip()
    # Review H7: a run of uncommitted code is not evidence for the commit it
    # names; say so in the results (tools/vp_results.py refuses it).
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                           cwd=ROOT, capture_output=True, text=True).stdout.strip()
    result = analyse.analyse(work, runs)
    result["commit"] = commit
    result["dirty"] = bool(dirty)
    text = json.dumps(result, indent=1)
    (work / "results.json").write_text(text)
    if args.results:
        args.results.write_text(text)
    for case, r in sorted(result["cases"].items()):
        print(f"{'PASS' if r['passed'] else 'FAIL'}  {case}")
        for s in r["steps"]:
            print(f"    {s['verdict']:4}  {s['name']}")
            if s["verdict"] != "PASS" and s.get("evidence"):
                print(f"          {s['evidence'][:300]}")
    print(f"\nworkdir: {work}\n{'PASSED' if result['passed'] else 'FAILED'}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
