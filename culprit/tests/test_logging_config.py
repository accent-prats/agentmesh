"""Pins two real, empirically-found logging gaps in culprit/api/main.py:

1. (2026-10-16) With no logging configured anywhere in the real app,
   every logger's effective level fell back to the root logger's default
   (WARNING) - uvicorn's own startup only configures its own
   uvicorn/uvicorn.error/uvicorn.access loggers, never the root logger.
   Every `log.info(...)` call anywhere in this app (e.g.
   pipeline/discovery.py's "falling back to vmId parsing" recovery
   notice - the exact signal an operator needs to triage a
   degraded-but-recovered machine) was silently swallowed in every real
   deployment; only WARNING+ ever reached stderr.

2. (2026-10-16, second pass - seen directly in a real deployment's logs)
   The first fix's blanket `logging.basicConfig(level=logging.INFO)`
   also turned on every third-party library's own INFO logging - most
   visibly azure-core's `http_logging_policy`, which dumps full
   request/response headers for every single Azure API call. That
   flooded real logs with HTTP noise, burying the diagnostic lines the
   first fix exists to surface. Fixed by leaving the root logger at its
   normal default (WARNING) and only bumping this app's own "culprit"
   logger node (and therefore every culprit.* child, since all of this
   codebase's loggers nest under it) to INFO.

3. (2026-10-16, found in review of fix #2) demo/run_demo.py is a
   separate, real entrypoint (`python -m culprit.demo.run_demo`) that
   never imports api/main.py - it independently set its own blanket
   `logging.basicConfig(level=logging.INFO)`, reintroducing exactly the
   same noise pattern fix #2 eliminated for the main app the moment this
   script's scope grows (it already posts to Slack/Teams webhooks via
   httpx when configured). Scoped the same way as api/main.py."""
from __future__ import annotations

import logging
import subprocess
import sys


def test_importing_the_app_makes_info_logs_visible_on_a_culprit_logger():
    """Runs in a fresh subprocess, not in-process: once anything imports
    culprit.api.main in this same interpreter, Python's own sys.modules
    cache makes a later import a no-op, so an in-process version of this
    test could pass without the module body's logging setup ever
    actually re-running (the way a real deployed process starts fresh)."""
    script = (
        "import logging, culprit.api.main\n"
        "logger = logging.getLogger('culprit.pipeline.discovery')\n"
        "print(logger.isEnabledFor(logging.INFO))\n"
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"


def test_importing_the_app_does_not_turn_on_third_party_http_logging_noise():
    """Found directly in a real deployment's logs: azure-core's own
    http_logging_policy logger (INFO-level by default when enabled)
    flooded output with full request/response headers for every Azure
    API call once the root logger was blanket-set to INFO. A third-party
    logger with no explicit level of its own must stay at the root's
    WARNING default."""
    script = (
        "import logging, culprit.api.main\n"
        "logger = logging.getLogger('azure.core.pipeline.policies.http_logging_policy')\n"
        "print(logger.isEnabledFor(logging.INFO))\n"
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_demo_entrypoint_has_the_same_scoped_logging_as_the_main_app():
    """demo/run_demo.py is a separate real entrypoint that never imports
    api/main.py, so fix #2 above doesn't automatically cover it - it
    needs (and now has) the identical scoping applied independently."""
    script = (
        "import logging, culprit.demo.run_demo\n"
        "culprit_logger = logging.getLogger('culprit.demo')\n"
        "noisy_logger = logging.getLogger('azure.core.pipeline.policies.http_logging_policy')\n"
        "print(culprit_logger.isEnabledFor(logging.INFO), noisy_logger.isEnabledFor(logging.INFO))\n"
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True False"
