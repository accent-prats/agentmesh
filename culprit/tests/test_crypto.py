from __future__ import annotations

import pytest
from cryptography.fernet import InvalidToken

from culprit.security.crypto import decrypt, encrypt


def test_roundtrip():
    ciphertext = encrypt("s3cr3t-value")
    assert ciphertext != "s3cr3t-value"
    assert decrypt(ciphertext) == "s3cr3t-value"


def test_blank_in_blank_out():
    assert encrypt("") == ""
    assert decrypt("") == ""


def test_tampered_ciphertext_is_rejected():
    ciphertext = encrypt("s3cr3t-value")
    tampered = ciphertext[:-4] + "abcd"
    with pytest.raises(InvalidToken):
        decrypt(tampered)


def test_different_plaintexts_produce_different_ciphertexts():
    assert encrypt("a") != encrypt("b")
