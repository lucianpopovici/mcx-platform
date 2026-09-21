"""Entry point: `python -m service`.

Order matters and is the contract of `core/loader.py`: profile first, then the
store and groups, then the socket, and only then readiness. Any refusal logs
the reason and exits non-zero; there is no degraded start.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from typing import Mapping, Optional, Sequence

from core.errors import PlatformError, StartupRefused

from . import logs
from .clock import utc_ms
from .http import Server
from .runtime import build_runtime

log = logging.getLogger("mcx.service")

EXIT_REFUSED = 2
EXIT_FAULT = 1


def main(argv: Optional[Sequence[str]] = None,
         env: Optional[Mapping[str, str]] = None) -> int:
    logs.configure()
    env = os.environ if env is None else env
    try:
        runtime = build_runtime(env, utc_ms)
    except (StartupRefused, PlatformError) as exc:
        log.error("startup refused: %s", exc)
        return EXIT_REFUSED
    except Exception:  # noqa: BLE001 - a fault, reported with its traceback
        log.exception("startup failed")
        return EXIT_FAULT

    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    try:
        server = Server(runtime, runtime.config.host, runtime.config.port)
    except OSError as exc:
        log.error("cannot listen on %s:%s: %s", runtime.config.host,
                  runtime.config.port, exc)
        runtime.close()
        return EXIT_FAULT

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    runtime.health.set_ready(True)
    log.info("ready: profile=%s listening=%s:%s",
             runtime.loaded.profile.identifier(), runtime.config.host,
             server.bound_port)

    stop.wait()
    log.info("shutting down")
    runtime.health.set_ready(False)
    server.shutdown()
    server.server_close()
    runtime.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
