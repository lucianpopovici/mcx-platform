"""The one place the wall clock is read. Injected everywhere below."""

import time


def utc_ms() -> int:
    """UTC milliseconds since the epoch."""
    return int(time.time() * 1000)
