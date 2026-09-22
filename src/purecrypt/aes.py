# SPDX-License-Identifier: 0BSD
"""AES-128/192/256 (FIPS-197) plus ECB, CBC, CTR, and GCM modes.

WARNING: pure Python cannot provide constant-time guarantees. Every
primitive in this module leaks timing information and must not be
used in production. This module exists for education, testing, and
interop where native crypto is unavailable.

AEAD notes: GCM nonces MUST be unique per key. Reusing a nonce with
the same key destroys both confidentiality and authenticity (it leaks
the GHASH key and the keystream). Nonce management is the caller's
problem. This library deliberately does not track or detect reuse.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Iterator

from ._utils import ct_equal, xor_bytes
from .exceptions import InvalidCiphertext, InvalidKey, InvalidTag

BLOCK_SIZE = 16

_GCM_R = 0xE1000000000000000000000000000000


def _gf_mul(a: int, b: int) -> int:
    """Multiply in the AES field GF(2^8) modulo x^8+x^4+x^3+x+1."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_pow(a: int, n: int) -> int:
    result = 1
    while n:
        if n & 1:
            result = _gf_mul(result, a)
        a = _gf_mul(a, a)
        n >>= 1
    return result


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox() -> tuple[list[int], list[int]]:
    sbox = [0] * 256
    inv = [0] * 256
    for x in range(256):
        i = 0 if x == 0 else _gf_pow(x, 254)
        s = i ^ _rotl8(i, 1) ^ _rotl8(i, 2) ^ _rotl8(i, 3) ^ _rotl8(i, 4) ^ 0x63
        sbox[x] = s
        inv[s] = x
    return sbox, inv


_SBOX, _INV_SBOX = _build_sbox()
_MUL2 = [_gf_mul(x, 2) for x in range(256)]
_MUL3 = [_gf_mul(x, 3) for x in range(256)]
_MUL9 = [_gf_mul(x, 9) for x in range(256)]
_MUL11 = [_gf_mul(x, 11) for x in range(256)]
_MUL13 = [_gf_mul(x, 13) for x in range(256)]
_MUL14 = [_gf_mul(x, 14) for x in range(256)]


def _check_key(key: bytes) -> int:
    """Validate an AES key and return its length in 32-bit words."""
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise InvalidKey("AES key must be 16, 24, or 32 bytes")
    return nk


def _expand_key(key: bytes) -> tuple[list[list[int]], int]:
    """FIPS-197 section 5.2 key expansion. Returns round words, Nr."""
    nk = _check_key(key)
    nr = nk + 6
    words: list[list[int]] = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = words[i - 1][:]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _gf_mul(rcon, 2)
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp, strict=True)])
    return words, nr


def _add_round_key(state: list[int], words: list[list[int]], rnd: int) -> None:
    for c in range(4):
        w = words[4 * rnd + c]
        for r in range(4):
            state[4 * c + r] ^= w[r]


def _sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _inv_sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = _INV_SBOX[state[i]]


def _shift_rows(state: list[int]) -> None:
    old = state[:]
    for r in range(4):
        for c in range(4):
            state[4 * c + r] = old[4 * ((c + r) % 4) + r]


def _inv_shift_rows(state: list[int]) -> None:
    old = state[:]
    for r in range(4):
        for c in range(4):
            state[4 * c + r] = old[4 * ((c - r) % 4) + r]


def _mix_columns(state: list[int]) -> None:
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c : 4 * c + 4]
        state[4 * c] = _MUL2[a0] ^ _MUL3[a1] ^ a2 ^ a3
        state[4 * c + 1] = a0 ^ _MUL2[a1] ^ _MUL3[a2] ^ a3
        state[4 * c + 2] = a0 ^ a1 ^ _MUL2[a2] ^ _MUL3[a3]
        state[4 * c + 3] = _MUL3[a0] ^ a1 ^ a2 ^ _MUL2[a3]


def _inv_mix_columns(state: list[int]) -> None:
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c : 4 * c + 4]
        state[4 * c] = _MUL14[a0] ^ _MUL11[a1] ^ _MUL13[a2] ^ _MUL9[a3]
        state[4 * c + 1] = _MUL9[a0] ^ _MUL14[a1] ^ _MUL11[a2] ^ _MUL13[a3]
        state[4 * c + 2] = _MUL13[a0] ^ _MUL9[a1] ^ _MUL14[a2] ^ _MUL11[a3]
        state[4 * c + 3] = _MUL11[a0] ^ _MUL13[a1] ^ _MUL9[a2] ^ _MUL14[a3]


class AES:
    """AES block cipher context holding an expanded key.

    NOT constant-time. See module docstring.
    """

    __slots__ = ("_nr", "_words")

    def __init__(self, key: bytes) -> None:
        words, nr = _expand_key(bytes(key))
        self._words = words
        self._nr = nr

    @property
    def block_size(self) -> int:
        return BLOCK_SIZE

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("AES block must be exactly 16 bytes")
        state = list(block)
        _add_round_key(state, self._words, 0)
        for rnd in range(1, self._nr):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, self._words, rnd)
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, self._words, self._nr)
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("AES block must be exactly 16 bytes")
        state = list(block)
        _add_round_key(state, self._words, self._nr)
        for rnd in range(self._nr - 1, 0, -1):
            _inv_shift_rows(state)
            _inv_sub_bytes(state)
            _add_round_key(state, self._words, rnd)
            _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, self._words, 0)
        return bytes(state)


def encrypt_block(key: bytes, block: bytes) -> bytes:
    return AES(key).encrypt_block(block)


def decrypt_block(key: bytes, block: bytes) -> bytes:
    return AES(key).decrypt_block(block)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """PKCS#7 padding. Always adds a full block for aligned input."""
    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be in [1, 255]")
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Remove and fully validate PKCS#7 padding.

    Raises InvalidCiphertext on any malformed padding. The final block
    is scanned in full and pad-byte mismatches accumulate into a flag
    rather than exiting early, so no position information leaks through
    an early return. Still variable-time at the Python level.
    """
    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be in [1, 255]")
    if len(data) == 0 or len(data) % block_size != 0:
        raise InvalidCiphertext("padded input is empty or misaligned")
    n = data[-1]
    bad = int(not 1 <= n <= block_size)
    last = data[len(data) - block_size :]
    for i in range(block_size):
        # Positions i >= block_size - n carry pad bytes equal to n.
        in_pad = int(i >= block_size - n)
        bad |= in_pad & int(last[i] != n)
    if bad:
        raise InvalidCiphertext("invalid PKCS#7 padding")
    return data[:-n]


def _require_aligned(
    data: bytes, what: str, exc: type[Exception] = InvalidCiphertext
) -> None:
    if len(data) % BLOCK_SIZE != 0:
        raise exc(f"{what} length must be a multiple of 16")


def _map_blocks(fn: Callable[[bytes], bytes], data: bytes) -> bytes:
    return b"".join(fn(data[i : i + 16]) for i in range(0, len(data), 16))


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    _require_aligned(data, "ECB plaintext", ValueError)
    cipher = AES(key)
    return _map_blocks(cipher.encrypt_block, data)


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    _require_aligned(data, "ECB ciphertext")
    cipher = AES(key)
    return _map_blocks(cipher.decrypt_block, data)


def cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CBC encrypt. Input must be block-aligned. Pad with pkcs7_pad."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be exactly 16 bytes")
    _require_aligned(data, "CBC plaintext", ValueError)
    cipher = AES(key)
    prev = bytes(iv)
    out = []
    for i in range(0, len(data), 16):
        prev = cipher.encrypt_block(xor_bytes(data[i : i + 16], prev))
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CBC decrypt. Returns raw plaintext. Strip padding via pkcs7_unpad."""
    if len(iv) != BLOCK_SIZE:
        raise InvalidCiphertext("CBC IV must be exactly 16 bytes")
    _require_aligned(data, "CBC ciphertext")
    cipher = AES(key)
    prev = bytes(iv)
    out = []
    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        out.append(xor_bytes(cipher.decrypt_block(block), prev))
        prev = block
    return b"".join(out)


def _ctr_keystream(cipher: AES, initial: int) -> Iterator[bytes]:
    counter = initial
    while True:
        yield cipher.encrypt_block(counter.to_bytes(16, "big"))
        counter = (counter + 1) % (1 << 128)


def ctr_encrypt(key: bytes, counter_block: bytes, data: bytes) -> bytes:
    """AES-CTR stream cipher.

    counter_block is the full 16-byte initial counter block (nonce
    concatenated with the starting counter value, SP 800-38A style).
    The counter is incremented as a 128-bit big-endian integer. CTR is
    symmetric, so this function also decrypts.
    """
    if len(counter_block) != BLOCK_SIZE:
        raise ValueError("CTR counter block must be exactly 16 bytes")
    cipher = AES(key)
    stream = _ctr_keystream(cipher, int.from_bytes(counter_block, "big"))
    out = bytearray(len(data))
    pos = 0
    while pos < len(data):
        block = next(stream)
        chunk = data[pos : pos + 16]
        out[pos : pos + len(chunk)] = xor_bytes(chunk, block[: len(chunk)])
        pos += len(chunk)
    return bytes(out)


ctr_decrypt = ctr_encrypt


def _gcm_mul(x: int, y: int) -> int:
    """GF(2^128) multiply per NIST SP 800-38D (reflected bit order)."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ _GCM_R if v & 1 else v >> 1
    return z


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return data if rem == 0 else data + bytes(16 - rem)


def _ghash(h: int, data: bytes) -> int:
    """GHASH over 16-byte-aligned data. h is the integer hash subkey."""
    y = 0
    for i in range(0, len(data), 16):
        y = _gcm_mul(y ^ int.from_bytes(data[i : i + 16], "big"), h)
    return y


def _gcm_j0(h: int, nonce: bytes) -> int:
    """J0 per NIST SP 800-38D: direct for 96-bit nonces, GHASH otherwise."""
    if len(nonce) == 12:
        return int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
    padded = _pad16(nonce) + struct.pack(">Q", 8 * len(nonce))
    return _ghash(h, padded)


def _gctr(cipher: AES, icb: int, data: bytes) -> bytes:
    """GCTR: XOR data with keystream from counter icb (inc32 stepping)."""
    out = bytearray(len(data))
    counter = icb
    pos = 0
    while pos < len(data):
        ks = cipher.encrypt_block(counter.to_bytes(16, "big"))
        chunk = data[pos : pos + 16]
        out[pos : pos + len(chunk)] = xor_bytes(chunk, ks[: len(chunk)])
        pos += len(chunk)
        counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
    return bytes(out)


def _inc32(counter: int) -> int:
    return (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)


def _gcm_auth_tag(cipher: AES, h: int, j0: int, aad: bytes, ciphertext: bytes) -> int:
    lens = struct.pack(">QQ", 8 * len(aad), 8 * len(ciphertext))
    s = _ghash(h, _pad16(aad) + _pad16(ciphertext) + lens)
    return int.from_bytes(_gctr(cipher, j0, s.to_bytes(16, "big")), "big")


def _gcm_check_nonce(nonce: bytes, exc: type[Exception] = ValueError) -> None:
    if len(nonce) == 0 or len(nonce) > (1 << 32) - 1:
        raise exc("GCM nonce must be between 1 and 2^32-1 bytes")


def gcm_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
    tag_length: int = 16,
) -> tuple[bytes, bytes]:
    """AES-GCM AEAD encryption (NIST SP 800-38D). Returns (ciphertext, tag).

    NOT constant-time. The nonce MUST be unique per key. Reuse is
    catastrophic and is the caller's responsibility to prevent.
    """
    _check_key(key)
    _gcm_check_nonce(nonce)
    if not 4 <= tag_length <= 16:
        raise ValueError("GCM tag_length must be between 4 and 16 bytes")
    cipher = AES(key)
    h = int.from_bytes(cipher.encrypt_block(bytes(16)), "big")
    j0 = _gcm_j0(h, nonce)
    ciphertext = _gctr(cipher, _inc32(j0), plaintext)
    tag = _gcm_auth_tag(cipher, h, j0, aad, ciphertext)
    return ciphertext, tag.to_bytes(16, "big")[:tag_length]


def gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """AES-GCM AEAD decryption. Verifies the tag before releasing plaintext.

    Raises InvalidTag on authentication failure. Plaintext is never
    released for unauthenticated input.
    """
    _check_key(key)
    _gcm_check_nonce(nonce, InvalidCiphertext)
    if len(tag) < 4 or len(tag) > 16:
        raise InvalidCiphertext("GCM tag must be between 4 and 16 bytes")
    cipher = AES(key)
    h = int.from_bytes(cipher.encrypt_block(bytes(16)), "big")
    j0 = _gcm_j0(h, nonce)
    expected = _gcm_auth_tag(cipher, h, j0, aad, ciphertext)
    if not ct_equal(expected.to_bytes(16, "big")[: len(tag)], bytes(tag)):
        raise InvalidTag("GCM authentication tag mismatch")
    return _gctr(cipher, _inc32(j0), ciphertext)


__all__ = [
    "AES",
    "BLOCK_SIZE",
    "cbc_decrypt",
    "cbc_encrypt",
    "ctr_decrypt",
    "ctr_encrypt",
    "decrypt_block",
    "ecb_decrypt",
    "ecb_encrypt",
    "encrypt_block",
    "gcm_decrypt",
    "gcm_encrypt",
    "pkcs7_pad",
    "pkcs7_unpad",
]
