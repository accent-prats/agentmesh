"""Pins a real, empirically-found gap (review, 2026-10-16): with no
logging configured anywhere in the real app, every logger's effective
level fell back to the root logger's default (WARNING) - uvicorn's own
startup only configures its own uvicorn/uvicorn.error/uvicorn.access
loggers, never the root logger. Every `log.info(...)` call anywhere in
this app (e.g. pipeline/discovery.py's "falling back to vmId parsing"
recovery notice - the exact signal an operator needs to triage a
degraded-but-recovered machine) was silently swallowed in every real
deployment; only WARNING+ ever reached stderr. Fixed via a module-level
`logging.basicConfig(level=logging.INFO)` in api/main.py."""
from __future__ import annotations

import logging
import subprocess
import sys


def test_importing_the_app_makes_info_logs_visible_on_a_culprit_logger():
    """Runs in a fresh subprocess - importing culprit.api.main in-process
    here would inherit whatever logging config pytest itself (or an
    earlier test module) already set up, masking the exact bug this
    pins (the real deployed process's logging config, not pytest's)."""
    script = (
        "import logging, culprit.api.main\n"
        "logger = logging.getLogger('culprit.pipeline.discovery')\n"
        "print(logger.isEnabledFor(logging.INFO))\n"
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"
