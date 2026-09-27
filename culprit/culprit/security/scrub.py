"""Secret/PII scrubbing applied to every TimelineEvent's `summary` and
`detail` before it is ever included in an RCA agent prompt (proposal
Section 12: "Scrubbing before reasoning").

This runs on collector output, not on the model's output - the point is
that a secret never enters the prompt in the first place, not that it gets
redacted after the fact.
"""
from __future__ import annotations

import re

from culprit.models.evidence import TimelineEvent

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("azure_sas_token", re.compile(r"(?:sig|sv)=[A-Za-z0-9%._-]{20,}")),
    ("bearer_token", re.compile(r"[Bb]earer\s+[A-Za-z0-9\-_.]{20,}")),
    ("basic_auth_url", re.compile(r"://[^/\s:]+:[^/\s@]+@")),
    ("generic_secret_kv", re.compile(r"(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*\S+")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
]


def scrub_text(text: str, redact_network_and_pii: bool = False) -> str:
    """Always strips credential-shaped content. `redact_network_and_pii`
    additionally strips IPs/emails - off by default because those are
    often legitimate, useful evidence (e.g. the host in a log line); turn
    it on for a stricter compliance posture."""
    out = text
    for name, pattern in _PATTERNS:
        if name in ("ipv4", "email") and not redact_network_and_pii:
            continue
        out = pattern.sub(f"[REDACTED:{name}]", out)
    return out


def scrub_event(event: TimelineEvent, redact_network_and_pii: bool = False) -> TimelineEvent:
    scrubbed_detail = {
        k: (scrub_text(v, redact_network_and_pii) if isinstance(v, str) else v)
        for k, v in event.detail.items()
    }
    return event.model_copy(
        update={
            "summary": scrub_text(event.summary, redact_network_and_pii),
            "detail": scrubbed_detail,
        }
    )


def scrub_events(events: list[TimelineEvent], redact_network_and_pii: bool = False) -> list[TimelineEvent]:
    return [scrub_event(e, redact_network_and_pii) for e in events]
