"""A SIP user agent for VP1-SIG-001.

It shares NOTHING with the platform: no import from `core` or `service`, no
reuse of the platform's renderer or parser. Messages are built by string
formatting and read by splitting on CRLF. If this agent and the platform
agree, they agree because both follow RFC 3261 and TS 24.379, not because
they run the same code -- which is the whole value of the exercise.

It always sends to the SIP core it was connected to, as a UE sends to its
P-CSCF, and never to the platform directly. Dialog state is kept the RFC 3261
§12 way: the route set is the reversed Record-Route of the response (UAC) or
the Record-Route of the request (UAS), and the remote target is the peer's
Contact.
"""

from __future__ import annotations

import re
import socket
import ssl
import threading
import time
import uuid
from typing import List, Optional

ICSI = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt"


def header(msg: str, name: str) -> Optional[str]:
    for line in msg.split("\r\n")[1:]:
        if not line:
            break
        k, _, v = line.partition(":")
        if k.strip().lower() == name.lower():
            return v.strip()
    return None


def headers(msg: str, name: str) -> List[str]:
    out = []
    for line in msg.split("\r\n")[1:]:
        if not line:
            break
        k, _, v = line.partition(":")
        if k.strip().lower() == name.lower():
            out.extend(p.strip() for p in v.split(",") if p.strip())
    return out


def first_line(msg: str) -> str:
    return msg.split("\r\n", 1)[0]


def uri_of(value: str) -> str:
    m = re.search(r"<([^>]+)>", value or "")
    return m.group(1) if m else (value or "").split(";")[0].strip()


class Dialog:
    def __init__(self, call_id, local_tag, remote_tag, local_uri, remote_uri,
                 remote_target, route_set, cseq):
        self.call_id, self.local_tag, self.remote_tag = call_id, local_tag, remote_tag
        self.local_uri, self.remote_uri = local_uri, remote_uri
        self.remote_target, self.route_set, self.cseq = remote_target, route_set, cseq


class UA:
    def __init__(self, aor: str, host: str, port: int, pki: str, name: str = "ua"):
        self.aor = aor
        self.user = aor.split(":", 1)[1].split("@")[0]
        self.rx: List[str] = []
        self.log: List[tuple] = []          # (direction, first line, full text)
        self.lock = threading.Lock()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(f"{pki}/ca.crt")
        ctx.load_cert_chain(f"{pki}/{name}.crt", f"{pki}/{name}.key")
        ctx.check_hostname = False
        self.sock = ctx.wrap_socket(socket.create_connection((host, port), timeout=10))
        self.sock.settimeout(None)
        self.host, self.port = self.sock.getsockname()[:2]
        self.tag = uuid.uuid4().hex[:8]
        self.closed = False
        threading.Thread(target=self._reader, daemon=True).start()

    # -- transport -------------------------------------------------------------
    def _reader(self) -> None:
        buf = b""
        while not self.closed:
            try:
                chunk = self.sock.recv(65535)
            except Exception:
                return
            if not chunk:
                return
            buf += chunk
            while True:
                i = buf.find(b"\r\n\r\n")
                if i < 0:
                    break
                head = buf[:i].decode("utf8", "replace")
                m = re.search(r"(?im)^Content-Length:\s*(\d+)", head)
                n = int(m.group(1)) if m else 0
                if len(buf) < i + 4 + n:
                    break
                text = buf[:i + 4 + n].decode("utf8", "replace")
                buf = buf[i + 4 + n:]
                with self.lock:
                    self.rx.append(text)
                    self.log.append(("<<", first_line(text), text))

    def send(self, lines: List[str], body: str = "") -> str:
        """Lines and body use bare newlines. CRLF conversion and Content-Length
        both happen here, once, so the two cannot disagree. (The first version
        of this agent converted twice, sent \\r\\r\\n with a length computed
        before the conversion, and the platform rightly refused it.)"""
        body = body.replace("\r\n", "\n").replace("\n", "\r\n")
        head = "\r\n".join(l.replace("\r", "").replace("\n", "") for l in lines)
        text = head + f"\r\nContent-Length: {len(body.encode())}\r\n\r\n" + body
        self.sock.sendall(text.encode())
        with self.lock:
            self.log.append((">>", first_line(text), text))
        return text

    def wait(self, pattern: str, timeout: float = 10.0, call_id: Optional[str] = None,
             method: Optional[str] = None) -> str:
        """First queued message whose first line matches `pattern` and, when
        given, whose Call-ID and CSeq method match. Matching on the status
        line alone let a stale 100 Trying answer a later BYE in the first
        version of this harness, which misattributed two observations."""
        rx = re.compile(pattern, re.I | re.M)
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                for k, m in enumerate(self.rx):
                    if not rx.search(first_line(m)):
                        continue
                    if call_id and header(m, "Call-ID") != call_id:
                        continue
                    if method and (header(m, "CSeq") or "").split()[-1:] != [method]:
                        continue
                    return self.rx.pop(k)
            time.sleep(0.02)
        with self.lock:
            seen = [first_line(m) for m in self.rx]
        raise TimeoutError(f"{self.user}: nothing matching {pattern!r}; queued: {seen}")

    def close(self) -> None:
        self.closed = True
        try:
            self.sock.close()
        except Exception:
            pass

    # -- building blocks -------------------------------------------------------
    @property
    def contact(self) -> str:
        return f"<sip:{self.user}@{self.host}:{self.port};transport=tls>"

    def _via(self) -> str:
        return (f"Via: SIP/2.0/TLS {self.host}:{self.port};"
                f"branch=z9hG4bK{uuid.uuid4().hex[:12]};rport")

    def sdp(self, port: int, version: int = 1) -> str:
        return (f"v=0\no=- {version} {version} IN IP4 {self.host}\ns=-\n"
                f"c=IN IP4 {self.host}\nt=0 0\n"
                f"m=audio {port} RTP/AVP 0\na=rtpmap:0 PCMU/8000\na=sendrecv\n")

    # -- requests out of dialog ------------------------------------------------
    def register(self, registrar: str = "sip:mcptt.example", expires: int = 3600) -> str:
        cid = f"reg-{self.user}-{uuid.uuid4().hex[:8]}"
        self.send([
            f"REGISTER {registrar} SIP/2.0", self._via(),
            f"From: <{self.aor}>;tag={self.tag}", f"To: <{self.aor}>",
            f"Call-ID: {cid}", "CSeq: 1 REGISTER",
            "Max-Forwards: 70",
            f'Contact: {self.contact};expires={expires};'
            f'+g.3gpp.icsi-ref="{ICSI}";+g.3gpp.mcptt',
        ])
        return self.wait(r"^SIP/2\.0 [2-6]\d\d", call_id=cid)

    def invite(self, ruri: str, call_type: str, target: Optional[str],
               media_port: int) -> dict:
        cid = f"call-{uuid.uuid4().hex[:10]}"
        mc = f"<mcptt-call_type>{call_type}</mcptt-call_type>"
        if target:
            mc += f"<mcptt-target>{target}</mcptt-target>"
        sent = self.send([
            f"INVITE {ruri} SIP/2.0", self._via(),
            f"From: <{self.aor}>;tag={self.tag}", f"To: <{ruri}>",
            f"Call-ID: {cid}", "CSeq: 1 INVITE", "Max-Forwards: 70",
            f"Contact: {self.contact}", f"P-Asserted-Identity: <{self.aor}>",
            "Accept-Contact: *;+g.3gpp.mcptt;require;explicit",
            f'Accept-Contact: *;+g.3gpp.icsi-ref="{ICSI}";require;explicit',
            "Content-Type: multipart/mixed;boundary=b",
        ], self.sdp(media_port) + mc)
        return {"call_id": cid, "ruri": ruri, "request": sent}

    # -- dialogs ------------------------------------------------------------------
    def dialog_as_uac(self, invite: dict, final: str) -> Dialog:
        """RFC 3261 §12.1.2."""
        rr = headers(final, "Record-Route")
        to = header(final, "To") or ""
        m = re.search(r"tag=([^;>\s]+)", to)
        return Dialog(invite["call_id"], self.tag, m.group(1) if m else "",
                      self.aor, invite["ruri"],
                      uri_of(header(final, "Contact") or invite["ruri"]),
                      list(reversed(rr)), 1)

    def dialog_as_uas(self, request: str) -> Dialog:
        """RFC 3261 §12.1.1."""
        frm = header(request, "From") or ""
        m = re.search(r"tag=([^;>\s]+)", frm)
        return Dialog(header(request, "Call-ID"), self.tag, m.group(1) if m else "",
                      self.aor, uri_of(frm),
                      uri_of(header(request, "Contact") or ""),
                      headers(request, "Record-Route"),
                      int((header(request, "CSeq") or "0").split()[0]))

    def in_dialog(self, d: Dialog, method: str, cseq: Optional[int] = None) -> str:
        """RFC 3261 §12.2.1.1: Request-URI is the remote target, Route is the
        route set. Loose routing only (every route entry here carries ;lr)."""
        if cseq is None:
            d.cseq += 1
            cseq = d.cseq
        lines = [f"{method} {d.remote_target} SIP/2.0", self._via()]
        for r in d.route_set:
            lines.append(f"Route: {r}")
        lines += [f"From: <{d.local_uri}>;tag={d.local_tag}",
                  f"To: <{d.remote_uri}>;tag={d.remote_tag}",
                  f"Call-ID: {d.call_id}", f"CSeq: {cseq} {method}",
                  "Max-Forwards: 70"]
        return self.send(lines)

    def respond(self, request: str, code: int, phrase: str, body: str = "") -> str:
        lines = [f"SIP/2.0 {code} {phrase}"]
        for ln in request.split("\r\n")[1:]:
            if not ln:
                break
            k = ln.split(":", 1)[0].strip().lower()
            if k in ("via", "from", "call-id", "cseq", "record-route"):
                lines.append(ln)
            elif k == "to":
                lines.append(ln if "tag=" in ln else f"{ln};tag={self.tag}")
        if code >= 180 and code < 300:
            lines.append(f"Contact: {self.contact}")
        if body:
            lines.append("Content-Type: application/sdp")
        return self.send(lines, body)
