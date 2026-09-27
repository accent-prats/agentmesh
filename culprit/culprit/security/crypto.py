"""Symmetric encryption for connection settings stored in the database
(Azure client secret, Datadog API/app keys).

Fernet, with a key derived from an env var, and its own env var
(`CULPRIT_ENCRYPTION_KEY`) rather than reusing the Portal's - so
Culprit's DB and the Portal's DB aren't decryptable with each other's
key. The dev-only fallback key means the demo and test suite work with
zero configuration; set `CULPRIT_ENCRYPTION_KEY` in any real deployment.
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet

_DEV_ONLY_DEFAULT_KEY = "culprit-dev-only-insecure-default-key-do-not-use-in-production"


def _fernet() -> Fernet:
    raw = os.environ.get("CULPRIT_ENCRYPTION_KEY") or _DEV_ONLY_DEFAULT_KEY
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
    return Fernet(key)


def encrypt(plain: str) -> str:
    """Encrypt a plain-text string. Empty in, empty out - a blank secret
    field should never round-trip through Fernet only to decrypt back to
    an empty string in a roundabout way."""
    if not plain:
        return ""
    return _fernet().encrypt(plain.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a ciphertext produced by `encrypt()`. Raises
    cryptography.fernet.InvalidToken if the ciphertext was tampered with
    or encrypted under a different key (e.g. CULPRIT_ENCRYPTION_KEY
    rotated without re-saving settings)."""
    if not ciphertext:
        return ""
    return _fernet().decrypt(ciphertext.encode()).decode()
