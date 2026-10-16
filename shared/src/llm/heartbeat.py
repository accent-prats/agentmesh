"""A background heartbeat logger for a single long-running blocking call
(an `httpx.post()` with a multi-minute read timeout) that would otherwise
log nothing between its "starting" line and its eventual success/failure.

Found 2026-10-17 from a real production run: the service log showed
"calling ..." once, then nothing at all for the full ~10 minutes
`httpx.post()` sat blocked waiting on a slow custom gateway, then the
timeout failure. From the outside that is indistinguishable from the
app itself being hung rather than just waiting on a slow network call.
This logs a fixed-interval "still waiting" line for as long as the
wrapped call is in flight, and stops the instant it returns - either way
- without changing what the call itself does or how long it waits.
"""
from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from typing import Iterator


@contextmanager
def log_heartbeat(logger: logging.Logger, label: str, *, interval: float = 30.0) -> Iterator[None]:
    started = time.monotonic()
    stop = threading.Event()

    def _beat() -> None:
        while not stop.wait(interval):
            logger.info("%s - still waiting after %.0fs", label, time.monotonic() - started)

    thread = threading.Thread(target=_beat, daemon=True, name="heartbeat-log")
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1.0)
