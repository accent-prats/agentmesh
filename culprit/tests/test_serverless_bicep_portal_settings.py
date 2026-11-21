"""culprit/infra/main.bicep - a static text check, not a deployment (no
`az`/bicep CLI in this test environment - see main.bicep's own comments
for what has and hasn't been validated against a real subscription).

Found 2026-11-22: a real deployment made from this template can never
reach Portal's AI Providers API at all (culprit/api/deps.py::
get_rca_agent() -> _fetch_active_ai_provider_from_portal()), since
CULPRIT_PORTAL_INTERNAL_URL/CULPRIT_PORTAL_JWT_SECRET were never wired
into this template's appSettings - it silently falls back to the
ANTHROPIC_API_KEY-only env path, and from there to the scripted demo RCA
agent if that's unset too. Same class of gap as the earlier missing
CULPRIT_SCHEDULER_ENABLED wiring in docker-compose.yml.
"""
from __future__ import annotations

from pathlib import Path

_BICEP = Path(__file__).resolve().parent.parent / "infra" / "main.bicep"


def _bicep_text() -> str:
    assert _BICEP.is_file(), f"expected main.bicep at {_BICEP}"
    return _BICEP.read_text(encoding="utf-8")


def test_portal_internal_url_is_a_parameter_and_an_app_setting():
    text = _bicep_text()
    assert "param portalInternalUrl string" in text
    assert "name: 'CULPRIT_PORTAL_INTERNAL_URL'" in text
    assert "value: portalInternalUrl" in text


def test_portal_jwt_secret_is_a_secure_parameter_stored_in_key_vault_and_wired_as_an_app_setting():
    text = _bicep_text()
    assert "param portalJwtSecret string" in text
    # It must actually be marked @secure() immediately above its own
    # param line, not just exist as a plain string somewhere else.
    secure_param_block = "@secure()\nparam portalJwtSecret string"
    assert secure_param_block in text, (
        "portalJwtSecret must be @secure() - it's a shared secret, same "
        "treatment as postgresAdminPassword/anthropicApiKey/culpritEncryptionKey"
    )
    assert "name: 'portal-jwt-secret'" in text
    assert "name: 'CULPRIT_PORTAL_JWT_SECRET'" in text
    assert "portalJwtSecretSecret.properties.secretUri" in text
