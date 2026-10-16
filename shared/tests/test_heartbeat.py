"""shared/src/llm/heartbeat.py - found 2026-10-17 from a real production
run where a slow custom LLM gateway sat silent for the entire ~10-minute
read timeout before failing: nothing logged anything in that window, so
from the outside a slow-but-alive call and a genuinely hung process were
indistinguishable. log_heartbeat() closes that gap for any single
long-running blocking call."""
from __future__ import annotations

import logging
import time

from shared.src.llm.heartbeat import log_heartbeat


def test_logs_nothing_for_a_call_that_finishes_before_the_first_interval(caplog):
    with caplog.at_level("INFO"):
        with log_heartbeat(logging.getLogger("test.heartbeat"), "quick call", interval=5.0):
            pass  # finishes immediately - well under the 5s interval
    assert not any("still waiting" in r.message for r in caplog.records)


def test_logs_a_heartbeat_for_each_interval_elapsed_while_still_in_flight(caplog):
    with caplog.at_level("INFO"):
        with log_heartbeat(logging.getLogger("test.heartbeat"), "slow call", interval=0.05):
            time.sleep(0.23)  # long enough for ~4 heartbeats at 0.05s each

    heartbeats = [r.message for r in caplog.records if "still waiting" in r.message]
    assert len(heartbeats) >= 3
    assert all("slow call" in m for m in heartbeats)


def test_stops_logging_the_instant_the_block_exits(caplog):
    with log_heartbeat(logging.getLogger("test.heartbeat"), "slow call", interval=0.05):
        time.sleep(0.1)

    caplog.clear()
    with caplog.at_level("INFO"):
        time.sleep(0.2)  # if the background thread were still running, it would log here
    assert not any("still waiting" in r.message for r in caplog.records)


def test_still_logs_heartbeats_when_the_wrapped_call_raises(caplog):
    with caplog.at_level("INFO"):
        try:
            with log_heartbeat(logging.getLogger("test.heartbeat"), "failing call", interval=0.05):
                time.sleep(0.12)
                raise RuntimeError("boom")
        except RuntimeError:
            pass

    heartbeats = [r.message for r in caplog.records if "still waiting" in r.message]
    assert len(heartbeats) >= 1
