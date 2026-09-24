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
from ua import UA, first_line, header, headers  # noqa: E402

DOMAIN = "mcptt.example"
U1, U2 = f"sip:u1@{DOMAIN}", f"sip:u2@{DOMAIN}"
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
        "MCX_RECORDER": recorder, "MCX_BEARER": "stub",
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
    if not shutil.which("kamailio"):
        raise RuntimeError("kamailio is not installed")
    modules = next((p for p in ("/usr/lib/x86_64-linux-gnu/kamailio/modules",
                                "/usr/lib/kamailio/modules",
                                "/usr/local/lib64/kamailio/modules")
                    if Path(p).is_dir()), None)
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
    check = subprocess.run(["kamailio", "-c", "-f", str(cfg)],
                           capture_output=True, text=True)
    if "config file ok" not in (check.stdout + check.stderr):
        raise RuntimeError("kamailio rejected its configuration:\n" + check.stderr)
    proc = Proc("kamailio", ["kamailio", "-f", str(cfg), "-DD", "-E",
                             "-w", str(work), "-P", str(work / "kamailio.pid")],
                work / "kamailio.log")
    wait_tls(core_port, work / "pki/ca.crt")
    return proc


def _asterisk_conf(work: Path) -> Path:
    return work / "asterisk-etc" / "asterisk.conf"


def asterisk_cli(work: Path, command: str) -> str:
    r = subprocess.run(["asterisk", "-C", str(_asterisk_conf(work)), "-rx", command],
                       capture_output=True, text=True, timeout=15)
    return r.stdout + r.stderr


def start_asterisk(work: Path, core_port: int, platform_port: int) -> Proc:
    if not shutil.which("asterisk"):
        raise RuntimeError("asterisk is not installed")
    modules = next((p for p in ("/usr/lib/x86_64-linux-gnu/asterisk/modules",
                                "/usr/lib/asterisk/modules")
                    if Path(p).is_dir()), None)
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
    proc = Proc("asterisk", ["asterisk", "-C", str(_asterisk_conf(work)), "-f", "-n", "-vvv"],
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


def drain(ua: UA, pattern: str, seconds: float, call_id: str) -> List[str]:
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
    inv = u1.invite(AS_URI, "prearranged-group", "grp:alpha", media_port=41000)
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

    # 4. A refusal, as it arrives through the core.
    bad = u1.invite(AS_URI, "prearranged-group", "grp:nobody", media_port=41004)
    try:
        r = u1.wait(r"^SIP/2\.0 [3-6]\d\d", timeout=10, call_id=bad["call_id"])
        report.observe("unknown group, through the core",
                       f"{first_line(r)} / Warning: {header(r, 'Warning') or '(none)'}")
    except TimeoutError:
        report.observe("unknown group, through the core", "no final response in 10 s")


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
    inv = direct.invite(AS_URI, "prearranged-group", "grp:alpha", media_port=41020)
    try:
        incoming = u2.wait(r"^INVITE ", timeout=10)
    except TimeoutError as exc:
        report.check("terminating: the callee receives an INVITE through the B2BUA",
                     False, str(exc))
        incoming = None
    if incoming:
        report.check("terminating: the callee receives an INVITE through the B2BUA",
                     True, first_line(incoming))
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
    direct.close()
    # Put u1's platform registration back on the B2BUA's flow.
    asterisk_cli(work, "pjsip send register reg-u1")
    time.sleep(1.5)

    # -- originating: UE -> B2BUA -> platform --------------------------------
    orig = u1.invite(AS_URI, "prearranged-group", "grp:alpha", media_port=41030)
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
    """The same 503 refusal, directly and through the core (PLT-PRI-008).

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
            i = a.invite(AS_URI, "prearranged-group", "grp:alpha", media_port=41010)
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
