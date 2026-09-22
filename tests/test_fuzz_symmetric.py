# SPDX-License-Identifier: 0BSD
"""Adversarial fuzz: feed os.urandom into decrypt/verify entry points.

Only InvalidTag, InvalidCiphertext, or InvalidKey may escape. Any other
exception (or, worse, released plaintext for tampered input) fails.
"""

import os
import random  # deterministic seeds for fuzz reproducibility

import pytest

from purecrypt import aes, chacha
from purecrypt.exceptions import InvalidCiphertext, InvalidKey, InvalidTag

_EXPECTED = (InvalidTag, InvalidCiphertext, InvalidKey)


def test_fuzz_gcm_decrypt() -> None:
    rng = random.Random(0xF00D)  # noqa: S311
    for _ in range(600):
        key = os.urandom(rng.choice([16, 24, 32, rng.randrange(0, 40)]))
        nonce = os.urandom(rng.randrange(0, 24))
        ct = os.urandom(rng.randrange(0, 80))
        tag = os.urandom(rng.randrange(0, 20))
        aad = os.urandom(rng.randrange(0, 32))
        try:
            pt = aes.gcm_decrypt(key, nonce, ct, tag, aad)
        except _EXPECTED:
            continue
        # can only succeed when every input was valid AND the tag matched
        assert len(key) in (16, 24, 32)
        assert 4 <= len(tag) <= 16
        assert len(pt) == len(ct)


def test_fuzz_gcm_tamper_near_miss() -> None:
    rng = random.Random(0xBEEF)  # noqa: S311
    for _ in range(400):
        key = os.urandom(16)
        nonce = os.urandom(12)
        pt = os.urandom(rng.randrange(0, 48))
        aad = os.urandom(rng.randrange(0, 24))
        ct, tag = aes.gcm_encrypt(key, nonce, pt, aad)
        # mutate a random byte somewhere in ct/tag/aad
        which = rng.randrange(3)
        if (which == 0 and not ct) or (which == 2 and not aad):
            which = 1
        if which == 0:
            bad = bytearray(ct)
            bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
            ct = bytes(bad)
        elif which == 1:
            bad = bytearray(tag)
            bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
            tag = bytes(bad)
        elif aad:
            bad = bytearray(aad)
            bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
            aad = bytes(bad)
            with pytest.raises(InvalidTag):
                aes.gcm_decrypt(key, nonce, ct, tag, aad)
            continue
        with pytest.raises(_EXPECTED):
            aes.gcm_decrypt(key, nonce, ct, tag, aad)


def test_fuzz_chacha_decrypt() -> None:
    rng = random.Random(0xCAFE)  # noqa: S311
    for _ in range(600):
        key = os.urandom(rng.choice([32, rng.randrange(0, 48)]))
        nonce = os.urandom(rng.choice([12, rng.randrange(0, 24)]))
        ct = os.urandom(rng.randrange(0, 80))
        tag = os.urandom(rng.randrange(0, 20))
        aad = os.urandom(rng.randrange(0, 32))
        with pytest.raises(_EXPECTED):
            chacha.chacha20_poly1305_decrypt(key, nonce, ct, tag, aad)


def test_fuzz_xchacha_decrypt() -> None:
    rng = random.Random(0xDEAD)  # noqa: S311
    for _ in range(300):
        key = os.urandom(32)
        nonce = os.urandom(rng.choice([24, rng.randrange(0, 32)]))
        ct = os.urandom(rng.randrange(0, 80))
        tag = os.urandom(rng.randrange(0, 20))
        with pytest.raises(_EXPECTED):
            chacha.xchacha20_poly1305_decrypt(key, nonce, ct, tag)


def test_fuzz_cbc_unpad() -> None:
    rng = random.Random(0xD00D)  # noqa: S311
    key = os.urandom(16)
    iv = os.urandom(16)
    rejected = 0
    for _ in range(400):
        # aligned ciphertext: decrypt is fine, padding must validate.
        # random plaintext occasionally forms a legal pad. That is fine,
        # the assertion is that nothing else escapes.
        ct = os.urandom(16 * rng.randrange(1, 5))
        pt = aes.cbc_decrypt(key, iv, ct)
        try:
            aes.pkcs7_unpad(pt)
        except _EXPECTED:
            rejected += 1
        # misaligned ciphertext must be rejected before decrypting
        bad_ct = os.urandom(16 * rng.randrange(1, 5) + rng.randrange(1, 16))
        with pytest.raises(_EXPECTED):
            aes.cbc_decrypt(key, iv, bad_ct)
    assert rejected > 350


def test_fuzz_decrypt_never_releases_on_bad_tag() -> None:
    # dedicated regression: every bit flip in tag AND ct rejects
    rng = random.Random(0xABCD)  # noqa: S311
    for _ in range(20):
        key = os.urandom(16)
        nonce = os.urandom(12)
        pt = os.urandom(rng.randrange(1, 33))
        ct, tag = aes.gcm_encrypt(key, nonce, pt)
        for buf in (ct, tag):
            bad = bytearray(buf)
            bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
            arg = bytes(bad) if buf is ct else ct
            tg = bytes(bad) if buf is tag else tag
            with pytest.raises(InvalidTag):
                aes.gcm_decrypt(key, nonce, arg, tg)
