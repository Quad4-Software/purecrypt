# SPDX-License-Identifier: 0BSD
"""Reticulum Token wire-format validation.

A Reticulum token uses a 64-byte token key split into a 32-byte
signing key and a 32-byte encryption key. On the wire the token is

    iv(16) || AES-256-CBC(PKCS7(data), enc, iv) || HMAC-SHA256(signing, iv || ct)

These tests build and parse tokens in exactly that layout and cover
the identity flow: X25519 key agreement feeding HKDF-SHA256 to derive
the 64-byte token key. The construction is also cross-checked against
the cryptography package where the APIs overlap.
"""

import secrets

import pytest

from purecrypt import aes, hashes, kdf
from purecrypt.exceptions import InvalidCiphertext, InvalidTag
from purecrypt.x25519 import X25519PrivateKey

TOKEN_OVERHEAD = 48  # iv 16 plus hmac 32


def _token_encrypt(token_key: bytes, data: bytes, iv: bytes | None = None) -> bytes:
    signing_key, enc_key = token_key[:32], token_key[32:]
    if iv is None:
        iv = secrets.token_bytes(16)
    ct = aes.cbc_encrypt(enc_key, iv, aes.pkcs7_pad(data))
    mac = hashes.HMAC(signing_key, iv + ct)
    return iv + ct + mac


def _token_decrypt(token_key: bytes, token: bytes) -> bytes:
    if len(token) <= TOKEN_OVERHEAD:
        raise InvalidCiphertext("token too short")
    signing_key, enc_key = token_key[:32], token_key[32:]
    iv, ct, mac = token[:16], token[16:-32], token[-32:]
    expected = hashes.HMAC(signing_key, iv + ct)
    if not _ct_eq(mac, expected):
        raise InvalidTag("token HMAC mismatch")
    return aes.pkcs7_unpad(aes.cbc_decrypt(enc_key, iv, ct))


def _ct_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b, strict=True):
        diff |= x ^ y
    return diff == 0


def _identity_token_key() -> tuple[bytes, bytes, bytes]:
    """Simulate two Reticulum identities agreeing on a token key."""
    alice = X25519PrivateKey.generate()
    bob = X25519PrivateKey.generate()
    shared_a = alice.exchange(bob.public_key())
    shared_b = bob.exchange(alice.public_key())
    key_a = kdf.hkdf("sha256", shared_a, None, b"", 64)
    key_b = kdf.hkdf("sha256", shared_b, None, b"", 64)
    return shared_a, key_a, key_b


def test_token_roundtrip() -> None:
    key = secrets.token_bytes(64)
    data = b"reticulum packet payload"
    token = _token_encrypt(key, data)
    assert len(token) == 16 + 16 * ((len(data) + 16) // 16) + 32
    assert _token_decrypt(key, token) == data


def test_token_roundtrip_empty_and_aligned() -> None:
    key = secrets.token_bytes(64)
    for size in (0, 15, 16, 17, 64):
        data = secrets.token_bytes(size)
        token = _token_encrypt(key, data)
        assert _token_decrypt(key, token) == data


def test_token_wrong_key_fails_hmac() -> None:
    key = secrets.token_bytes(64)
    token = _token_encrypt(key, b"payload")
    wrong = bytearray(key)
    wrong[0] ^= 1  # flip a signing-key bit
    with pytest.raises(InvalidTag):
        _token_decrypt(bytes(wrong), token)
    # flipping an encryption-key bit leaves the HMAC valid but the
    # plaintext either fails unpadding or comes back wrong
    wrong = bytearray(key)
    wrong[63] ^= 1
    try:
        out = _token_decrypt(bytes(wrong), token)
    except (InvalidCiphertext, InvalidTag):
        pass
    else:
        assert out != b"payload"


def test_token_truncated_fails() -> None:
    key = secrets.token_bytes(64)
    token = _token_encrypt(key, b"payload")
    for cut in (0, 16, 32, TOKEN_OVERHEAD, len(token) - 1):
        with pytest.raises((InvalidCiphertext, InvalidTag)):
            _token_decrypt(key, token[:cut])


def test_token_bit_flip_fails() -> None:
    key = secrets.token_bytes(64)
    token = _token_encrypt(key, b"payload")
    for pos in (0, 20, len(token) - 33, len(token) - 1):
        bad = bytearray(token)
        bad[pos] ^= 0x40
        with pytest.raises(InvalidTag):
            _token_decrypt(key, bytes(bad))


def test_identity_flow() -> None:
    shared, key_a, key_b = _identity_token_key()
    assert len(shared) == 32
    assert key_a == key_b
    token = _token_encrypt(key_a, b"hello from alice")
    assert _token_decrypt(key_b, token) == b"hello from alice"


def test_wire_layout_explicit() -> None:
    """Field offsets are exactly iv | ct | hmac with no extra header."""
    key = bytes(range(64))
    data = b"x" * 10
    iv = bytes(range(16))
    token = _token_encrypt(key, data, iv=iv)
    assert token[:16] == iv
    ct = aes.cbc_encrypt(key[32:], iv, aes.pkcs7_pad(data))
    assert token[16:-32] == ct
    assert token[-32:] == hashes.HMAC(key[:32], iv + ct)


def test_oracle_cryptography_package() -> None:
    """Cross-validate the token format against the cryptography package."""
    crypto = pytest.importorskip("cryptography.hazmat.primitives.ciphers")
    from cryptography.hazmat.primitives import hashes as ch
    from cryptography.hazmat.primitives import hmac as chmac
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    key = secrets.token_bytes(64)
    data = secrets.token_bytes(37)
    iv = secrets.token_bytes(16)

    # our encrypt -> their verify/decrypt
    token = _token_encrypt(key, data, iv=iv)
    h = chmac.HMAC(key[:32], ch.SHA256())
    h.update(token[:-32])
    h.verify(token[-32:])
    cipher = crypto.Cipher(crypto.algorithms.AES(key[32:]), crypto.modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(token[16:-32]) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    assert unpadder.update(padded) + unpadder.finalize() == data

    # their encrypt -> our verify/decrypt
    padder = padding.PKCS7(128).padder()
    padded2 = padder.update(data) + padder.finalize()
    cipher = crypto.Cipher(crypto.algorithms.AES(key[32:]), crypto.modes.CBC(iv))
    enc = cipher.encryptor()
    ct2 = enc.update(padded2) + enc.finalize()
    h2 = chmac.HMAC(key[:32], ch.SHA256())
    h2.update(iv + ct2)
    token2 = iv + ct2 + h2.finalize()
    assert _token_decrypt(key, token2) == data

    # HKDF agreement on the identity-style derivation
    shared = secrets.token_bytes(32)
    ours = kdf.hkdf("sha256", shared, None, b"", 64)
    theirs = HKDF(algorithm=ch.SHA256(), length=64, salt=None, info=b"").derive(shared)
    assert ours == theirs
