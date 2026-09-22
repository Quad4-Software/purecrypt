# SPDX-License-Identifier: 0BSD
"""ChaCha20, Poly1305, and the ChaCha20-Poly1305 / XChaCha20-Poly1305 AEADs.

Implements RFC 8439 (block function, keystream XOR, Poly1305 one-time
MAC, AEAD construction) plus HChaCha20 and XChaCha20-Poly1305 from
draft-irtf-cfrg-xchacha.

WARNING: pure Python cannot provide constant-time guarantees. Every
primitive in this module leaks timing information and must not be
used in production. Nonce reuse with the same key is catastrophic:
it leaks the keystream and forges the Poly1305 key. Nonce management
is the caller's responsibility; nothing here tracks reuse.
"""

from __future__ import annotations

import struct

from ._utils import ct_equal
from .exceptions import InvalidCiphertext, InvalidKey, InvalidTag

_MASK32 = (1 << 32) - 1
_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_POLY_P = (1 << 130) - 5


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & _MASK32


def _quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & _MASK32
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK32
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotl32(s[b] ^ s[c], 7)


def _rounds(state: list[int]) -> list[int]:
    s = state[:]
    for _ in range(10):
        _quarter_round(s, 0, 4, 8, 12)
        _quarter_round(s, 1, 5, 9, 13)
        _quarter_round(s, 2, 6, 10, 14)
        _quarter_round(s, 3, 7, 11, 15)
        _quarter_round(s, 0, 5, 10, 15)
        _quarter_round(s, 1, 6, 11, 12)
        _quarter_round(s, 2, 7, 8, 13)
        _quarter_round(s, 3, 4, 9, 14)
    return s


def _check_key(key: bytes) -> list[int]:
    if len(key) != 32:
        raise InvalidKey("ChaCha20 key must be exactly 32 bytes")
    return list(struct.unpack("<8I", key))


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """RFC 8439 section 2.3 block function: 64 bytes of keystream."""
    kw = _check_key(key)
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be exactly 12 bytes")
    if not 0 <= counter <= _MASK32:
        raise ValueError("ChaCha20 counter must fit in 32 bits")
    state = [*_SIGMA, *kw, counter & _MASK32, *struct.unpack("<3I", nonce)]
    working = _rounds(state)
    out = [(a + b) & _MASK32 for a, b in zip(working, state, strict=True)]
    return struct.pack("<16I", *out)


def hchacha20(key: bytes, nonce: bytes) -> bytes:
    """HChaCha20: derives an XChaCha20 subkey from a 16-byte nonce."""
    kw = _check_key(key)
    if len(nonce) != 16:
        raise ValueError("HChaCha20 nonce must be exactly 16 bytes")
    state = [*_SIGMA, *kw, *struct.unpack("<4I", nonce)]
    s = _rounds(state)
    return struct.pack("<8I", s[0], s[1], s[2], s[3], s[12], s[13], s[14], s[15])


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    """XOR data with the ChaCha20 keystream. Encrypt and decrypt are identical."""
    _check_key(key)
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be exactly 12 bytes")
    out = bytearray(len(data))
    pos = 0
    while pos < len(data):
        ks = chacha20_block(key, counter, nonce)
        chunk = data[pos : pos + 64]
        xored = bytes(x ^ y for x, y in zip(chunk, ks, strict=False))
        out[pos : pos + len(chunk)] = xored
        pos += len(chunk)
        counter = (counter + 1) & _MASK32
    return bytes(out)


def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """RFC 8439 section 2.5 Poly1305 one-time authenticator."""
    if len(key) != 32:
        raise InvalidKey("Poly1305 key must be exactly 32 bytes")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i : i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        acc = ((acc + n) * r) % _POLY_P
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return data if rem == 0 else data + bytes(16 - rem)


def _aead_mac(poly_key: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    mac_data = (
        _pad16(aad) + _pad16(ciphertext) + struct.pack("<QQ", len(aad), len(ciphertext))
    )
    return poly1305_mac(poly_key, mac_data)


def chacha20_poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    """RFC 8439 section 2.8 AEAD. Returns (ciphertext, 16-byte tag).

    NOT constant-time. The 12-byte nonce MUST be unique per key.
    """
    _check_key(key)
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be exactly 12 bytes")
    poly_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20_xor(key, nonce, plaintext, counter=1)
    return ciphertext, _aead_mac(poly_key, aad, ciphertext)


def chacha20_poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """RFC 8439 section 2.8 AEAD decryption.

    Verifies the tag before releasing plaintext. Raises InvalidTag on
    authentication failure.
    """
    _check_key(key)
    if len(nonce) != 12:
        raise InvalidCiphertext("ChaCha20-Poly1305 nonce must be exactly 12 bytes")
    if len(tag) != 16:
        raise InvalidCiphertext("ChaCha20-Poly1305 tag must be exactly 16 bytes")
    poly_key = chacha20_block(key, 0, nonce)[:32]
    expected = _aead_mac(poly_key, aad, ciphertext)
    if not ct_equal(expected, bytes(tag)):
        raise InvalidTag("ChaCha20-Poly1305 authentication tag mismatch")
    return chacha20_xor(key, nonce, ciphertext, counter=1)


def _xcheck_nonce(nonce: bytes, exc: type[Exception] = ValueError) -> None:
    if len(nonce) != 24:
        raise exc("XChaCha20-Poly1305 nonce must be exactly 24 bytes")


def xchacha20_poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    """XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha).

    Same security contract as ChaCha20-Poly1305 with a 24-byte nonce
    that is safe to choose randomly. NOT constant-time.
    """
    _check_key(key)
    _xcheck_nonce(nonce)
    subkey = hchacha20(key, nonce[:16])
    return chacha20_poly1305_encrypt(subkey, bytes(4) + nonce[16:], plaintext, aad)


def xchacha20_poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """XChaCha20-Poly1305 AEAD decryption. Raises InvalidTag on failure."""
    _check_key(key)
    _xcheck_nonce(nonce, InvalidCiphertext)
    subkey = hchacha20(key, nonce[:16])
    inner_nonce = bytes(4) + nonce[16:]
    return chacha20_poly1305_decrypt(subkey, inner_nonce, ciphertext, tag, aad)


__all__ = [
    "chacha20_block",
    "chacha20_poly1305_decrypt",
    "chacha20_poly1305_encrypt",
    "chacha20_xor",
    "hchacha20",
    "poly1305_mac",
    "xchacha20_poly1305_decrypt",
    "xchacha20_poly1305_encrypt",
]
