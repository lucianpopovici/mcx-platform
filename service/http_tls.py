"""TLS for the HTTP interface (PLT-SRS 3.1 HTTP-1; PLT-VP-R1 RES-OP-05).

Owner ruling 2026-10-16: HTTPS is a deployment setting, `MCX_HTTP_TLS`, with
no default. Off is the recorded deviation of 2026-09-29 and is reported as
one (service/runtime.py). On, the server's certificate and key are required,
and `MCX_HTTP_CLIENT_AUTH` says whether a client must present a certificate
from `MCX_HTTP_TLS_CA`: "required", "optional" (verified when offered), or
"none" (no CA; anyone who can reach the port can read the group documents).
The handler does not look at the client's certificate, so "optional" grants
the same access as "none". The material is read once, at startup: a renewed
certificate takes effect at the next restart.
"""

from __future__ import annotations

import ssl

from core.errors import StartupRefused

from .config import HttpTlsConfig

# PLT-PRF-032: this module implements the HTTP-1 reference point (PLT-SRS §3.1).
REFERENCE_POINT = "HTTP-1"

HANDSHAKE_TIMEOUT_S = 10
# After the handshake, how long a connection may sit without completing a
# request before it is closed; and how many may be open at once. Each holds a
# thread (ThreadingHTTPServer), so neither may be unbounded.
IDLE_TIMEOUT_S = 30
MAX_CONNECTIONS = 64
# The idle timeout bounds each read, not a request a client trickles in a
# byte at a time: every connection is also cut REQUEST_DEADLINE_S after it
# was accepted, handshake and response included (a request here is one GET
# of a small document). And one client address may hold only
# MAX_PER_CLIENT of the slots, so a single host cannot take them all and
# fail the readiness probe (review of the 2026-10-16 settings). Many hosts
# still can: the interface belongs on a network the deployment controls.
REQUEST_DEADLINE_S = 15
MAX_PER_CLIENT = 8

_VERIFY = {"required": ssl.CERT_REQUIRED, "optional": ssl.CERT_OPTIONAL,
           "none": ssl.CERT_NONE}


def make_context(cfg: HttpTlsConfig) -> ssl.SSLContext:
    """The server context, or StartupRefused naming the file that failed."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Client-initiated TLS 1.2 renegotiation costs the server a handshake per
    # request of it, and nothing here needs it.
    ctx.options |= ssl.OP_NO_RENEGOTIATION
    try:
        ctx.load_cert_chain(str(cfg.cert), str(cfg.key))
    except (ssl.SSLError, OSError) as exc:
        raise StartupRefused(
            f"MCX_HTTP_TLS_CERT/MCX_HTTP_TLS_KEY ({cfg.cert}, {cfg.key}) cannot "
            f"be loaded: {exc}") from exc
    if cfg.ca is not None:
        try:
            ctx.load_verify_locations(str(cfg.ca))
        except (ssl.SSLError, OSError) as exc:
            raise StartupRefused(
                f"MCX_HTTP_TLS_CA ({cfg.ca}) cannot be loaded: {exc}") from exc
    ctx.verify_mode = _VERIFY[cfg.client_auth]
    return ctx
