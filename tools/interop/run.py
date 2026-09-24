"""VP1-SIG-001 — run the platform against a third-party SIP core.

    python3 tools/interop/run.py --core kamailio [--workdir DIR] [--keep]

Starts the core and the platform as real processes over TLS on loopback,
drives two independent user agents (tools/interop/ua.py) through the core,
and reports each step as PASS, FAIL or OBSERVED:

  PASS / FAIL  steps the VP1-SIG-001 pass criterion depends on --
               registration and session setup
  OBSERVED     behaviour worth recording that the criterion does not judge
               (teardown, refusals as they arrive through the core)

The platform is started from its environment alone, with no `platform=`
injection and no configuration specific to the core under test: the same
environment is used for every core. Every message each UA sent and received
is written to <workdir>/transcript.txt.

Exit status is 0 only if every PASS/FAIL step passed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import pki  # noqa: E402
from ua import MCINFO, UA, body_part, first_line, header, headers  # noqa: E402

DOMAIN = "mcptt.example"
U1, U2 = f"sip:u1@{DOMAIN}", f"sip:u2@{DOMAIN}"

# Neither core is required to be on the host PATH. When it is not, and
# podman is, the same binary runs inside this image instead -- built from
# Ubuntu 24.04, which carries the exact versions PLT-VP-R1 §7.1.1 already
# records (Kamailio 5.7.4, Asterisk 20.6.0). --network host puts the
# container on the same loopback as the platform process, so every port
# and path below is unchanged either way; see tools/interop/containers/.
CONTAINER_IMAGE = "localhost/mcx-interop-cores:ubuntu24.04"


def _core_argv(binary: str, work: Path, argv: List[str]) -> List[str]:
    if shutil.which(binary):
        return argv
    if not shutil.which("podman"):
        raise RuntimeError(f"{binary} is not installed and podman is not available")
    # :z (shared), not :Z (exclusive) -- multiple containers touch the same
    # work directory concurrently here (the running daemon, plus each
    # asterisk_cli() call), and :Z's private relabel on the later one
    # revokes the earlier container's access under SELinux enforcing.
    return ["podman", "run", "--rm", "--network", "host",
            "-v", f"{work}:{work}:z", CONTAINER_IMAGE] + argv


def _dir_exists(path: str, binary: str) -> bool:
    if shutil.which(binary):
        return Path(path).is_dir()
    if not shutil.which("podman"):
        return False
    r = subprocess.run(["podman", "run", "--rm", CONTAINER_IMAGE, "test", "-d", path])
    return r.returncode == 0
AS_URI = f"sip:mcptt@{DOMAIN}"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_tls(port: int, ca: Path, timeout: float = 15.0) -> None:
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.check_hostname = False
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as raw:
                with ctx.wrap_socket(raw):
                    return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"nothing answering TLS on 127.0.0.1:{port}")


# -- the processes -------------------------------------------------------------

class Proc:
    def __init__(self, name: str, argv: List[str], log: Path,
                 env: Optional[Dict[str, str]] = None, cwd: Optional[Path] = None):
        self.name, self.log = name, log
        self.fh = open(log, "w")
        self.p = subprocess.Popen(argv, stdout=self.fh, stderr=subprocess.STDOUT,
                                  env=env, cwd=cwd, start_new_session=True)

    def stop(self) -> None:
        if self.p.poll() is None:
            try:
                os.killpg(self.p.pid, signal.SIGTERM)
                self.p.wait(timeout=10)
            except Exception:
                os.killpg(self.p.pid, signal.SIGKILL)
        self.fh.close()


def start_platform(work: Path, port: int, recorder: str = "stub") -> Proc:
    groups = work / "groups.yaml"
    groups.write_text(
        "groups:\n"
        "  - id: \"grp:alpha\"\n"
        "    display_name: \"Alpha\"\n"
        f"    members: [\"{U1}\", \"{U2}\"]\n"
        f"users: [\"{U1}\", \"{U2}\"]\n")
    data = work / f"data-{recorder}"
    data.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCX_")}
    env.update({
        "MCX_PROFILE": "mcx", "MCX_RELEASE": "19", "MCX_IDMS": "stub",
        "MCX_RECORDER": recorder, "MCX_BEARER": "stub", "MCX_STRICT_RELEASE": "true",
        "MCX_DATA_DIR": str(data), "MCX_GROUPS_FILE": str(groups),
        "MCX_HTTP_PORT": str(free_port()),
        "MCX_SIP_LISTEN": f"127.0.0.1:{port}", "MCX_SIP_URI": AS_URI,
        "MCX_SIP_TLS_CERT": str(work / "pki/platform.crt"),
        "MCX_SIP_TLS_KEY": str(work / "pki/platform.key"),
        "MCX_SIP_TLS_CA": str(work / "pki/ca.crt"),
        "MCX_SIP_CLIENT_AUTH": "optional",
        "MCX_SIP_ROLES": "participating,controlling",
        "MCX_MEDIA_ADDRESS": "127.0.0.1", "MCX_MEDIA_PORTS": "0",
    })
    proc = Proc("platform", [sys.executable, "-m", "service"],
                work / f"platform-{recorder}.log", env=env, cwd=ROOT)
    wait_tls(port, work / "pki/ca.crt")
    return proc


def start_kamailio(work: Path, core_port: int, platform_port: int) -> Proc:
    if not shutil.which("kamailio") and not shutil.which("podman"):
        raise RuntimeError("kamailio is not installed and podman is not available")
    modules = next((p for p in ("/usr/lib/x86_64-linux-gnu/kamailio/modules",
                                "/usr/lib/kamailio/modules",
                                "/usr/local/lib64/kamailio/modules")
                    if _dir_exists(p, "kamailio")), None)
    if modules is None:
        raise RuntimeError("kamailio module directory not found")
    tls_cfg = work / "kamailio-tls.cfg"
    tls_cfg.write_text(
        "[server:default]\nmethod = TLSv1.2+\nverify_certificate = no\n"
        "require_certificate = no\n"
        f"private_key = {work}/pki/kamailio.key\ncertificate = {work}/pki/kamailio.crt\n"
        f"ca_list = {work}/pki/ca.crt\n\n"
        "[client:default]\nmethod = TLSv1.2+\nverify_certificate = yes\n"
        "require_certificate = yes\n"
        f"private_key = {work}/pki/kamailio.key\ncertificate = {work}/pki/kamailio.crt\n"
        f"ca_list = {work}/pki/ca.crt\n")
    cfg = work / "kamailio.cfg"
    cfg.write_text((HERE / "kamailio.cfg.in").read_text()
                   .replace("@@DEBUG@@", "2")
                   .replace("@@CORE_PORT@@", str(core_port))
                   .replace("@@PLATFORM_PORT@@", str(platform_port))
                   .replace("@@AS_DOMAIN@@", DOMAIN)
                   .replace("@@MODULES@@", modules + "/")
                   .replace("@@TLS_CFG@@", str(tls_cfg)))
    check = subprocess.run(_core_argv("kamailio", work, ["kamailio", "-c", "-f", str(cfg)]),
                           capture_output=True, text=True)
    if "config file ok" not in (check.stdout + check.stderr):
        raise RuntimeError("kamailio rejected its configuration:\n" + check.stderr)
    proc = Proc("kamailio", _core_argv("kamailio", work,
                             ["kamailio", "-f", str(cfg), "-DD", "-E",
                              "-w", str(work), "-P", str(work / "kamailio.pid")]),
                work / "kamailio.log")
    wait_tls(core_port, work / "pki/ca.crt")
    return proc


def _asterisk_conf(work: Path) -> Path:
    return work / "asterisk-etc" / "asterisk.conf"


def asterisk_cli(work: Path, command: str) -> str:
    r = subprocess.run(_core_argv("asterisk", work,
                        ["asterisk", "-C", str(_asterisk_conf(work)), "-rx", command]),
                       capture_output=True, text=True, timeout=15)
    return r.stdout + r.stderr


def start_asterisk(work: Path, core_port: int, platform_port: int) -> Proc:
    if not shutil.which("asterisk") and not shutil.which("podman"):
        raise RuntimeError("asterisk is not installed and podman is not available")
    modules = next((p for p in ("/usr/lib/x86_64-linux-gnu/asterisk/modules",
                                "/usr/lib/asterisk/modules")
                    if _dir_exists(p, "asterisk")), None)
    if modules is None:
        raise RuntimeError("asterisk module directory not found")
    for d in ("asterisk-etc", "asterisk-var", "asterisk-spool", "asterisk-run",
              "asterisk-log"):
        (work / d).mkdir(exist_ok=True)
    subs = {"@@WORK@@": str(work), "@@MODULES@@": modules,
            "@@CORE_PORT@@": str(core_port), "@@PLATFORM_PORT@@": str(platform_port),
            "@@AS_DOMAIN@@": DOMAIN}
    for name in ("asterisk.conf", "modules.conf", "pjsip.conf", "extensions.conf"):
        text = (HERE / "asterisk" / f"{name}.in").read_text()
        for k, v in subs.items():
            text = text.replace(k, v)
        (work / "asterisk-etc" / name).write_text(text)
    (work / "asterisk-etc" / "logger.conf").write_text(
        "[general]\n[logfiles]\nconsole => notice,warning,error,verbose\n")
    proc = Proc("asterisk", _core_argv("asterisk", work,
                             ["asterisk", "-C", str(_asterisk_conf(work)), "-f", "-n", "-vvv"]),
                work / "asterisk.log")
    wait_tls(core_port, work / "pki/ca.crt", timeout=30)
    asterisk_cli(work, "pjsip set logger on")
    return proc


CORES: Dict[str, Callable[[Path, int, int], Proc]] = {
    "kamailio": start_kamailio, "asterisk": start_asterisk}
# A proxy forwards the platform's own messages; a B2BUA terminates each call
# and originates a new one. They need different scenarios, and the result of
# one says nothing about the other.
TOPOLOGY = {"kamailio": "proxy", "asterisk": "b2bua"}


# -- the scenario --------------------------------------------------------------

class Report:
    def __init__(self) -> None:
        self.steps: List[Tuple[str, str, str]] = []

    def check(self, name: str, ok: bool, evidence: str) -> bool:
        self.steps.append(("PASS" if ok else "FAIL", name, evidence))
        return ok

    def observe(self, name: str, evidence: str) -> None:
        self.steps.append(("OBSERVED", name, evidence))

    @property
    def passed(self) -> bool:
        return all(v != "FAIL" for v, _, _ in self.steps)


def drain(ua: UA, pattern: str, seconds: float, call_id: Optional[str]) -> List[str]:
    """Everything matching `pattern` on `call_id` that arrives within `seconds`."""
    got, end = [], time.time() + seconds
    while time.time() < end:
        try:
            got.append(ua.wait(pattern, timeout=max(0.05, end - time.time()),
                               call_id=call_id))
        except TimeoutError:
            break
    return got


def scenario(core: str, work: Path, core_port: int, platform_port: int,
             report: Report, uas: List[UA]) -> None:
    ca = str(work / "pki")
    u1 = UA(U1, "127.0.0.1", core_port, ca); uas.append(u1)
    u2 = UA(U2, "127.0.0.1", core_port, ca); uas.append(u2)

    # 1. Registration through the core, with the platform as registrar of record.
    for ua in (u1, u2):
        r = ua.register()
        to = header(r, "To") or ""
        report.check(f"REGISTER {ua.user} completes through {core}",
                     first_line(r).startswith("SIP/2.0 200"), first_line(r))
        report.check(f"REGISTER {ua.user} answered by the platform, not the core",
                     "tag=mcx-" in to, f"To: {to}")

    # 2. Group call: u1 originates, the platform invites u2 through the core.
    inv = u1.invite(AS_URI, "prearranged", "grp:alpha", media_port=41000)
    try:
        incoming = u2.wait(r"^INVITE ", timeout=10)
    except TimeoutError as exc:
        report.check("platform's INVITE reaches the callee through the core", False, str(exc))
        return
    report.check("platform's INVITE reaches the callee through the core", True,
                 first_line(incoming))
    accept = headers(incoming, "Accept-Contact")
    report.check("INVITE to callee carries both TS 24.379 Accept-Contact fields",
                 any("+g.3gpp.mcptt" in a and "icsi-ref" not in a for a in accept)
                 and any("icsi-ref" in a and "3gpp-service.ims.icsi.mcptt" in a
                         for a in accept),
                 " | ".join(accept) or "(none)")
    xml = body_part(incoming, MCINFO) or ""
    report.check("INVITE to callee carries the MCPTT info body (TS 24.379 6.3.2.2.3 item 8)",
                 "<session-type>prearranged</session-type>" in xml
                 and "<mcpttURI>grp:alpha</mcpttURI>" in xml
                 and f"<mcpttURI>{U1}</mcpttURI>" in xml,
                 "session-type, calling group and calling user present" if xml else
                 f"no {MCINFO} part; Content-Type {header(incoming, 'Content-Type')}")
    report.observe("INVITE to callee: Record-Route as received",
                   " | ".join(headers(incoming, "Record-Route")) or "(none)")
    report.observe("INVITE to callee: Contact", header(incoming, "Contact") or "(none)")

    u2.respond(incoming, 180, "Ringing")
    u2.respond(incoming, 200, "OK", body=u2.sdp(41002, 2))
    try:
        final = u1.wait(r"^SIP/2\.0 [2-6]\d\d", timeout=10,
                        call_id=inv["call_id"], method="INVITE")
    except TimeoutError as exc:
        report.check("originator receives a final response", False, str(exc))
        return
    report.check("originator receives 200 OK through the core",
                 first_line(final).startswith("SIP/2.0 200"), first_line(final))
    report.observe("200 OK to originator: Record-Route",
                   " | ".join(headers(final, "Record-Route")) or
                   "(none -- RFC 3261 12.1.1 requires the UAS to copy it)")
    report.observe("200 OK to originator: Contact", header(final, "Contact") or "(none)")

    # The originator ACKs at once, as a UA does, built the RFC 3261 section 12
    # way from what it received. Only 200s arriving AFTER this ACK count as
    # retransmissions: the first version of this harness waited on the callee
    # first and then counted the platform's legitimate earlier retransmissions.
    d1 = u1.dialog_as_uac(inv, final)
    u1.in_dialog(d1, "ACK", cseq=1)
    time.sleep(0.3)
    drain(u1, r"^SIP/2\.0 200", 0.05, call_id=inv["call_id"])   # in flight before the ACK

    try:
        ack = u2.wait(r"^ACK ", timeout=5, call_id=header(incoming, "Call-ID"))
        report.check("platform's ACK reaches the callee through the core", True,
                     first_line(ack))
    except TimeoutError:
        report.check("platform's ACK reaches the callee through the core", False,
                     "no ACK within 5 s")

    retrans = drain(u1, r"^SIP/2\.0 200", 4.5, call_id=inv["call_id"])
    report.check("originator's ACK reaches the platform (no 2xx retransmission after it)",
                 not retrans,
                 f"remote target {d1.remote_target}, route set {d1.route_set or '[]'}; "
                 f"{len(retrans)} 200 OK after the ACK")

    # 3. Teardown -- observed, not judged by VP1-SIG-001.
    u1.in_dialog(d1, "BYE")
    try:
        bye_resp = u1.wait(r"^SIP/2\.0 [2-6]\d\d", timeout=5,
                           call_id=inv["call_id"], method="BYE")
        report.observe("originator's BYE through the core", first_line(bye_resp))
    except TimeoutError:
        report.observe("originator's BYE through the core", "no response within 5 s")
    try:
        bye2 = u2.wait(r"^BYE ", timeout=5, call_id=header(incoming, "Call-ID"))
        report.observe("callee receives the platform's BYE", first_line(bye2))
        u2.respond(bye2, 200, "OK")
    except TimeoutError:
        report.observe("callee receives the platform's BYE", "none within 5 s")

    # 4. SIP-OP-14: the originator CANCELs while the callee rings.
    cancelled_call(core, u1, u2, report,
                   f"hop by hop, by {core} -- the 487 is the platform's")

    # 5. A refusal, as it arrives through the core.
    bad = u1.invite(AS_URI, "prearranged", "grp:nobody", media_port=41004)
    try:
        r = u1.wait(r"^SIP/2\.0 [3-6]\d\d", timeout=10, call_id=bad["call_id"])
        report.observe("unknown group, through the core",
                       f"{first_line(r)} / Warning: {header(r, 'Warning') or '(none)'}")
    except TimeoutError:
        report.observe("unknown group, through the core", "no final response in 10 s")


def cancelled_call(core: str, caller: UA, callee: UA, report: Report,
                   caller_path: str) -> None:
    """SIP-OP-14. The caller's CANCEL must be answered 200, its INVITE 487
    (RFC 3261 9.2), and the callee -- still ringing -- must be CANCELled in
    turn (9.1) and have its 487 ACKed (17.1.1.3). Every hop is the core's to
    carry: a proxy relays CANCEL statefully; a B2BUA mirrors it per leg."""
    drain(callee, r"^INVITE ", 0.3, call_id=None)      # nothing stale may answer
    inv = caller.invite(AS_URI, "private", callee.aor, media_port=41006)
    try:
        incoming = callee.wait(r"^INVITE ", timeout=10)
    except TimeoutError as exc:
        report.check("SIP-OP-14: the private call reaches the callee", False, str(exc))
        return
    callee.respond(incoming, 180, "Ringing")
    try:
        caller.wait(r"^SIP/2\.0 1\d\d", timeout=5, call_id=inv["call_id"], method="INVITE")
    except TimeoutError:
        # 9.1: a CANCEL MUST NOT be sent before a provisional response.
        report.check("SIP-OP-14: the originator sees a provisional response", False,
                     "none within 5 s; no CANCEL may be sent")
        return
    caller.cancel(inv)
    try:
        ok = caller.wait(r"^SIP/2\.0 \d\d\d", timeout=5, call_id=inv["call_id"],
                         method="CANCEL")
        report.check(f"SIP-OP-14: the originator's CANCEL is answered ({caller_path})",
                     first_line(ok).startswith("SIP/2.0 200"), first_line(ok))
    except TimeoutError:
        report.check(f"SIP-OP-14: the originator's CANCEL is answered ({caller_path})",
                     False, "no response within 5 s")
    try:
        final = caller.wait(r"^SIP/2\.0 [2-6]\d\d", timeout=10, call_id=inv["call_id"],
                            method="INVITE")
        report.check("SIP-OP-14: the cancelled INVITE ends with 487",
                     first_line(final).startswith("SIP/2.0 487"), first_line(final))
        if first_line(final).startswith("SIP/2.0 2"):
            # a 2xx that crossed the CANCEL: accept it and hang up (9.1)
            d = caller.dialog_as_uac(inv, final)
            caller.in_dialog(d, "ACK", cseq=1)
            caller.in_dialog(d, "BYE")
        else:
            caller.ack_failure(inv, final)
    except TimeoutError:
        report.check("SIP-OP-14: the cancelled INVITE ends with 487", False,
                     "no final response within 10 s")
    leg = header(incoming, "Call-ID")
    try:
        cancel = callee.wait(r"^CANCEL ", timeout=10, call_id=leg)
        report.check("SIP-OP-14: the ringing callee receives a CANCEL", True,
                     first_line(cancel))
    except TimeoutError:
        report.check("SIP-OP-14: the ringing callee receives a CANCEL", False,
                     "none within 10 s -- the callee is left ringing")
        return
    callee.respond(cancel, 200, "OK")
    callee.respond(incoming, 487, "Request Terminated")
    try:
        ack = callee.wait(r"^ACK ", timeout=5, call_id=leg)
        report.check("SIP-OP-14: the callee's 487 is ACKed", True, first_line(ack))
    except TimeoutError:
        report.check("SIP-OP-14: the callee's 487 is ACKed", False, "no ACK within 5 s")
    late = drain(callee, r"^(BYE|INVITE|CANCEL) ", 1.0, call_id=leg)
    report.check("SIP-OP-14: nothing further reaches the cancelled callee", not late,
                 ", ".join(first_line(m) for m in late) or "nothing")


def scenario_b2bua(core: str, work: Path, core_port: int, platform_port: int,
                   report: Report, uas: List[UA]) -> None:
    """A back-to-back user agent between the UEs and the platform.

    Registration has two hops here: each UE registers with the B2BUA, which
    answers it itself, and the B2BUA registers each user onward to the
    platform (the B2BUA form of IMS third-party registration). The two call
    directions are tested separately so that one cannot mask the other:

      terminating  the originator attaches to the platform DIRECTLY; the
                   platform reaches the callee only through the B2BUA
      originating  the originator's INVITE goes through the B2BUA
    """
    ca = str(work / "pki")
    u1 = UA(U1, "127.0.0.1", core_port, ca); uas.append(u1)
    u2 = UA(U2, "127.0.0.1", core_port, ca); uas.append(u2)
    for ua in (u1, u2):
        r = ua.register()
        report.check(f"REGISTER {ua.user} with {core}",
                     first_line(r).startswith("SIP/2.0 200"), first_line(r))

    # The onward registrations, as the B2BUA itself reports them.
    end, regs = time.time() + 20, ""
    while time.time() < end:
        regs = asterisk_cli(work, "pjsip show registrations")
        if regs.count("Registered") >= 2:
            break
        time.sleep(0.5)
    for user in ("u1", "u2"):
        line = next((l.strip() for l in regs.splitlines() if f"reg-{user}/" in l), "")
        report.check(f"{core} registers {user} onward to the platform",
                     "Registered" in line, line or "(no such registration)")

    # -- terminating: platform -> B2BUA -> callee ---------------------------
    direct = UA(U1, "127.0.0.1", platform_port, ca); uas.append(direct)
    r = direct.register()          # u1's flow is now this direct connection
    inv = direct.invite(AS_URI, "prearranged", "grp:alpha", media_port=41020)
    try:
        incoming = u2.wait(r"^INVITE ", timeout=10)
    except TimeoutError as exc:
        report.check("terminating: the callee receives an INVITE through the B2BUA",
                     False, str(exc))
        incoming = None
    if incoming:
        report.check("terminating: the callee receives an INVITE through the B2BUA",
                     True, first_line(incoming))
        report.observe("terminating: MCPTT info body after the B2BUA",
                       "present" if body_part(incoming, MCINFO) else
                       f"absent -- Content-Type {header(incoming, 'Content-Type')}")
        report.observe("terminating: INVITE as the B2BUA re-originated it",
                       f"Accept-Contact: {' | '.join(headers(incoming, 'Accept-Contact')) or '(none)'}; "
                       f"Contact: {header(incoming, 'Contact')}; "
                       f"Content-Type: {header(incoming, 'Content-Type')}")
        u2.respond(incoming, 180, "Ringing")
        u2.respond(incoming, 200, "OK", body=u2.sdp(41022, 2))
        try:
            final = direct.wait(r"^SIP/2\.0 [2-6]\d\d", timeout=10,
                                call_id=inv["call_id"], method="INVITE")
            report.check("terminating: the originator receives 200 OK",
                         first_line(final).startswith("SIP/2.0 200"), first_line(final))
        except TimeoutError as exc:
            report.check("terminating: the originator receives 200 OK", False, str(exc))
            final = None
        try:
            u2.wait(r"^ACK ", timeout=5, call_id=header(incoming, "Call-ID"))
            report.check("terminating: the callee receives the ACK", True, "ACK")
        except TimeoutError:
            report.check("terminating: the callee receives the ACK", False,
                         "no ACK within 5 s")
        if final and first_line(final).startswith("SIP/2.0 200"):
            d = direct.dialog_as_uac(inv, final)
            direct.in_dialog(d, "ACK", cseq=1)
            time.sleep(0.3)
            drain(direct, r"^SIP/2\.0 200", 0.05, call_id=inv["call_id"])
            retrans = drain(direct, r"^SIP/2\.0 200", 4.0, call_id=inv["call_id"])
            report.check("terminating: the platform absorbs the originator's ACK",
                         not retrans, f"{len(retrans)} 200 OK after the ACK")
            direct.in_dialog(d, "BYE")
            try:
                b = u2.wait(r"^BYE ", timeout=6, call_id=header(incoming, "Call-ID"))
                u2.respond(b, 200, "OK")
                report.observe("terminating: teardown reaches the callee", first_line(b))
            except TimeoutError:
                report.observe("terminating: teardown reaches the callee", "no BYE in 6 s")
    # SIP-OP-14 through the B2BUA: here the originator is attached to the
    # platform directly, so the 200 to its CANCEL is the platform's own
    # (through a proxy it is the proxy's hop-by-hop answer).
    cancelled_call(core, direct, u2, report, "by the platform, originator attached directly")
    direct.close()
    # Put u1's platform registration back on the B2BUA's flow.
    asterisk_cli(work, "pjsip send register reg-u1")
    time.sleep(1.5)

    # -- originating: UE -> B2BUA -> platform --------------------------------
    orig = u1.invite(AS_URI, "prearranged", "grp:alpha", media_port=41030)
    try:
        r = u1.wait(r"^SIP/2\.0 [2-6]\d\d", timeout=15, call_id=orig["call_id"],
                    method="INVITE")
        report.observe("originating: the UE's call through the B2BUA",
                       f"{first_line(r)} / Warning: {header(r, 'Warning') or '(none)'}")
        if first_line(r).startswith("SIP/2.0 2"):
            u1.in_dialog(u1.dialog_as_uac(orig, r), "ACK", cseq=1)
    except TimeoutError:
        report.observe("originating: the UE's call through the B2BUA",
                       "no final response in 15 s")
    try:
        leaked = u2.wait(r"^INVITE ", timeout=3)
        report.observe("originating: did the platform invite the callee?", first_line(leaked))
        u2.respond(leaked, 486, "Busy Here")
    except TimeoutError:
        report.observe("originating: did the platform invite the callee?", "no")


def refusal_comparison(core: str, work: Path, core_port: int, platform_port: int,
                       report: Report, uas: List[UA]) -> None:
    """The same 503 refusal, directly and through the core (SIP-OP-10: the proxy
    turns it into a 500 without its Warning; accepted, and PLT-PRI-008 is unaffected).

    Runs a fail-closed platform (MCX_RECORDER=none) on the port the core
    already routes to, so the core's configuration is untouched.
    """
    platform = start_platform(work, platform_port, recorder="none")
    try:
        results = {}
        for label, target_port in (("direct", platform_port), (core, core_port)):
            a = UA(U1, "127.0.0.1", target_port, str(work / "pki")); uas.append(a)
            b = UA(U2, "127.0.0.1", target_port, str(work / "pki")); uas.append(b)
            a.register(); b.register()
            i = a.invite(AS_URI, "prearranged", "grp:alpha", media_port=41010)
            r = a.wait(r"^SIP/2\.0 [3-6]\d\d", timeout=10, call_id=i["call_id"])
            results[label] = f"{first_line(r)} / Warning: {header(r, 'Warning') or '(none)'}"
        for label, text in results.items():
            report.observe(f"recording-unavailable refusal, {label}", text)
    finally:
        platform.stop()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--core", choices=sorted(CORES), required=True)
    ap.add_argument("--workdir")
    ap.add_argument("--keep", action="store_true",
                    help="keep the working directory (always kept with --workdir)")
    args = ap.parse_args()

    work = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="mcx-interop-"))
    work.mkdir(parents=True, exist_ok=True)
    pki.make(work / "pki", ("platform", "ua", "kamailio", "asterisk"))

    report, uas, procs = Report(), [], []
    platform_port, core_port = free_port(), free_port()
    try:
        platform = start_platform(work, platform_port)
        procs.append(CORES[args.core](work, core_port, platform_port))
        run = scenario if TOPOLOGY[args.core] == "proxy" else scenario_b2bua
        try:
            run(args.core, work, core_port, platform_port, report, uas)
        finally:
            platform.stop()
        if TOPOLOGY[args.core] == "proxy":
            refusal_comparison(args.core, work, core_port, platform_port, report, uas)
    finally:
        for ua in uas:
            ua.close()
        for p in reversed(procs):
            p.stop()

    with open(work / "transcript.txt", "w") as t:
        for ua in uas:
            for direction, line, text in ua.log:
                t.write(f"===== {ua.user} {direction} {line}\n{text}\n")

    width = max(len(n) for _, n, _ in report.steps)
    print(f"\nVP1-SIG-001 against {args.core}  (work: {work})\n")
    for verdict, name, evidence in report.steps:
        print(f"  {verdict:<8} {name:<{width}}  {evidence}")
    print(f"\n  {'PASSED' if report.passed else 'FAILED'}")
    if not (args.keep or args.workdir):
        shutil.rmtree(work, ignore_errors=True)
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
