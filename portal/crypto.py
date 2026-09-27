"""Symmetric encryption for AI provider secrets stored in the Portal's
database (portal/db.py::AIProviderSetting).

Fernet, with its own env var (`PORTAL_ENCRYPTION_KEY`) rather than reusing
`SECRET_KEY` (which signs JWTs, a different trust boundary) or Culprit's
own `CULPRIT_ENCRYPTION_KEY` - each app's encrypted-at-rest secrets are
decryptable only with that app's own key. The dev-only fallback key means
the demo works with zero configuration; set `PORTAL_ENCRYPTION_KEY` in any
real deployment. Mirrors culprit/culprit/security/crypto.py exactly.
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet

_DEV_ONLY_DEFAULT_KEY = "portal-dev-only-insecure-default-key-do-not-use-in-production"


def _fernet() -> Fernet:
    raw = os.environ.get("PORTAL_ENCRYPTION_KEY") or _DEV_ONLY_DEFAULT_KEY
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
    return Fernet(key)


def encrypt(plain: str) -> str:
    if not plain:
        return ""
    return _fernet().encrypt(plain.encode()).decode()


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    return _fernet().decrypt(ciphertext.encode()).decode()
