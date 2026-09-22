# SPDX-License-Identifier: 0BSD
"""Key derivation functions: HKDF, PBKDF2, scrypt, and Argon2.

HKDF follows RFC 5869 and is generic over hashlib digests. PBKDF2 is
implemented directly over HMAC per RFC 8018 (validated against
hashlib.pbkdf2_hmac in tests). scrypt wraps hashlib.scrypt (RFC 7914).
Argon2d/i/id is implemented from scratch over hashlib.blake2b per
RFC 9106, including the data-independent addressing mode.

WARNING: pure Python cannot provide constant-time guarantees. These
functions are fine for offline key derivation but must not be used in
production. Prefer audited native implementations.
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Iterator
from typing import Any

from ._utils import ct_equal
from .exceptions import InvalidTag
from .hashes import DigestSpec, _factory, _hmac_digest

# ---------------------------------------------------------------- HKDF


def hkdf_extract(digest: DigestSpec, salt: bytes | None, ikm: bytes) -> bytes:
    """RFC 5869 section 2.2 extract step. Returns the PRK."""
    factory = _factory(digest)
    hlen = factory(b"").digest_size
    key = bytes(hlen) if salt is None else bytes(salt)
    return _hmac_digest(factory, key, ikm)


def hkdf_expand(digest: DigestSpec, prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 section 2.3 expand step."""
    factory = _factory(digest)
    hlen = factory(b"").digest_size
    if length < 0 or length > 255 * hlen:
        raise ValueError("HKDF length must be in [0, 255 * hash digest size]")
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = _hmac_digest(factory, prk, t + info + bytes([counter]))
        out += t
        counter += 1
    return bytes(out[:length])


def hkdf(
    digest: DigestSpec,
    ikm: bytes,
    salt: bytes | None = None,
    info: bytes = b"",
    length: int = 32,
) -> bytes:
    """RFC 5869 HKDF: extract then expand. Returns length bytes."""
    return hkdf_expand(digest, hkdf_extract(digest, salt, ikm), info, length)


# -------------------------------------------------------------- PBKDF2


def pbkdf2(
    password: bytes,
    salt: bytes,
    iterations: int,
    dklen: int,
    digest: DigestSpec = "sha256",
) -> bytes:
    """PBKDF2 (RFC 8018) implemented directly over HMAC.

    Equivalent to hashlib.pbkdf2_hmac; implemented over pure-Python
    HMAC so no OpenSSL PBKDF2 support is required.
    """
    factory = _factory(digest)
    hlen = factory(b"").digest_size
    if iterations < 1:
        raise ValueError("PBKDF2 iterations must be >= 1")
    if dklen < 1:
        raise ValueError("PBKDF2 dklen must be >= 1")
    blocks = math.ceil(dklen / hlen)
    out = bytearray()
    for i in range(1, blocks + 1):
        u = _hmac_digest(factory, password, salt + struct.pack(">I", i))
        t = u
        for _ in range(iterations - 1):
            u = _hmac_digest(factory, password, u)
            t = bytes(a ^ b for a, b in zip(t, u, strict=True))
        out += t
    return bytes(out[:dklen])


# -------------------------------------------------------------- scrypt


def scrypt(
    password: bytes,
    salt: bytes,
    n: int = 16384,
    r: int = 8,
    p: int = 1,
    dklen: int = 64,
    maxmem: int = 64 * 1024 * 1024,
) -> bytes:
    """scrypt (RFC 7914) via hashlib.scrypt with parameter validation.

    n must be a power of two greater than 1. maxmem defaults to 64 MiB;
    raise it for larger parameter sets.
    """
    if n < 2 or (n & (n - 1)) != 0:
        raise ValueError("scrypt n must be a power of two greater than 1")
    if r < 1 or p < 1:
        raise ValueError("scrypt r and p must be >= 1")
    if dklen < 1:
        raise ValueError("scrypt dklen must be >= 1")
    if (n - 1) * p >= (1 << 63) // (128 * r):
        raise ValueError("scrypt parameters exceed RFC 7914 bounds")
    return hashlib.scrypt(
        password, salt=salt, n=n, r=r, p=p, maxmem=maxmem, dklen=dklen
    )


# -------------------------------------------------------------- Argon2

ARGON2D = 0
ARGON2I = 1
ARGON2ID = 2
ARGON2_VERSION = 0x13
_ARGON2_SLICES = 4
_ARGON2_BLOCK_WORDS = 128
_MASK32 = (1 << 32) - 1
_MASK64 = (1 << 64) - 1
_ZERO_BLOCK = [0] * _ARGON2_BLOCK_WORDS


def _rotr64(v: int, n: int) -> int:
    return ((v >> n) | (v << (64 - n))) & _MASK64


def _gb(v: list[int], a: int, b: int, c: int, d: int) -> None:
    """RFC 9106 section 3.6 GB: BLAKE2b G with multiplication."""
    v[a] = (v[a] + v[b] + 2 * (v[a] & _MASK32) * (v[b] & _MASK32)) & _MASK64
    v[d] = _rotr64(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d] + 2 * (v[c] & _MASK32) * (v[d] & _MASK32)) & _MASK64
    v[b] = _rotr64(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + 2 * (v[a] & _MASK32) * (v[b] & _MASK32)) & _MASK64
    v[d] = _rotr64(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d] + 2 * (v[c] & _MASK32) * (v[d] & _MASK32)) & _MASK64
    v[b] = _rotr64(v[b] ^ v[c], 63)


def _permute(v: list[int]) -> None:
    """RFC 9106 permutation P on 16 64-bit words."""
    _gb(v, 0, 4, 8, 12)
    _gb(v, 1, 5, 9, 13)
    _gb(v, 2, 6, 10, 14)
    _gb(v, 3, 7, 11, 15)
    _gb(v, 0, 5, 10, 15)
    _gb(v, 1, 6, 11, 12)
    _gb(v, 2, 7, 8, 13)
    _gb(v, 3, 4, 9, 14)


def _g_compress(x: list[int], y: list[int]) -> list[int]:
    """RFC 9106 section 3.5 compression function G. Returns Z XOR R."""
    r = [a ^ b for a, b in zip(x, y, strict=True)]
    z = r[:]
    for i in range(8):
        row = z[16 * i : 16 * i + 16]
        _permute(row)
        z[16 * i : 16 * i + 16] = row
    for i in range(8):
        idx = [2 * i + 16 * j + k for j in range(8) for k in range(2)]
        col = [z[m] for m in idx]
        _permute(col)
        for m, w in zip(idx, col, strict=True):
            z[m] = w
    return [a ^ b for a, b in zip(z, r, strict=True)]


def _h_prime(data: bytes, outlen: int) -> bytes:
    """RFC 9106 section 3.3 variable-length hash H'."""
    prefix = struct.pack("<I", outlen) + data
    if outlen <= 64:
        return hashlib.blake2b(prefix, digest_size=outlen).digest()
    r = math.ceil(outlen / 32) - 2
    v = hashlib.blake2b(prefix, digest_size=64).digest()
    out = bytearray(v[:32])
    for _ in range(r - 1):
        v = hashlib.blake2b(v, digest_size=64).digest()
        out += v[:32]
    out += hashlib.blake2b(v, digest_size=outlen - 32 * r).digest()
    return bytes(out)


def _words(block: bytes) -> list[int]:
    return list(struct.unpack("<128Q", block))


def _block(words: list[int]) -> bytes:
    return struct.pack("<128Q", *words)


def _address_stream(
    pass_: int, lane: int, slice_: int, mprime: int, passes: int, variant: int
) -> Iterator[tuple[int, int]]:
    """Lazy J1/J2 pairs for Argon2i-style data-independent indexing."""
    inp = [pass_, lane, slice_, mprime, passes, variant, 0] + [0] * 121
    counter = 0
    while True:
        counter += 1
        inp[6] = counter
        a = _g_compress(_ZERO_BLOCK, inp)
        a = _g_compress(_ZERO_BLOCK, a)
        for w in a:
            yield w & _MASK32, w >> 32


def _index_alpha(
    pass_: int,
    slice_: int,
    index: int,
    lane_length: int,
    segment_length: int,
    j1: int,
    same_lane: bool,
) -> int:
    """RFC 9106 section 3.4.2: map J1 into the reference window W."""
    if pass_ == 0:
        if slice_ == 0:
            ref_area = index - 1
        elif same_lane:
            ref_area = slice_ * segment_length + index - 1
        else:
            ref_area = slice_ * segment_length + (-1 if index == 0 else 0)
    elif same_lane:
        ref_area = lane_length - segment_length + index - 1
    else:
        ref_area = lane_length - segment_length + (-1 if index == 0 else 0)
    rel = (j1 * j1) >> 32
    rel = ref_area - 1 - ((ref_area * rel) >> 32)
    if pass_ == 0 or slice_ == _ARGON2_SLICES - 1:
        start = 0
    else:
        start = (slice_ + 1) * segment_length
    return (start + rel) % lane_length


def _fill_segment(
    mem: list[list[int]],
    *,
    lane_length: int,
    segment_length: int,
    pass_: int,
    slice_: int,
    lane: int,
    lanes: int,
    passes: int,
    mprime: int,
    variant: int,
    version: int,
) -> None:
    data_indep = variant == ARGON2I or (
        variant == ARGON2ID and pass_ == 0 and slice_ < _ARGON2_SLICES // 2
    )
    stream: Iterator[tuple[int, int]] | None = None
    start = 2 if (pass_ == 0 and slice_ == 0) else 0
    if data_indep:
        stream = _address_stream(pass_, lane, slice_, mprime, passes, variant)
        for _ in range(start):
            next(stream)
    for i in range(start, segment_length):
        cur = slice_ * segment_length + i
        prev = cur - 1 if cur > 0 else lane_length - 1
        base = lane * lane_length
        if stream is not None:
            j1, j2 = next(stream)
        else:
            w0 = mem[base + prev][0]
            j1, j2 = w0 & _MASK32, w0 >> 32
        ref_lane = lane if (pass_ == 0 and slice_ == 0) else j2 % lanes
        ref_index = _index_alpha(
            pass_, slice_, i, lane_length, segment_length, j1, ref_lane == lane
        )
        new = _g_compress(mem[base + prev], mem[ref_lane * lane_length + ref_index])
        if pass_ != 0 and version != 0x10:
            new = [a ^ b for a, b in zip(new, mem[base + cur], strict=True)]
        mem[base + cur] = new


def _argon2_validate(
    variant: int,
    parallelism: int,
    tag_length: int,
    memory_cost: int,
    time_cost: int,
    version: int,
) -> None:
    if variant not in (ARGON2D, ARGON2I, ARGON2ID):
        raise ValueError("variant must be ARGON2D, ARGON2I, or ARGON2ID")
    if not 1 <= parallelism <= (1 << 24) - 1:
        raise ValueError("Argon2 parallelism must be in [1, 2^24 - 1]")
    if not 4 <= tag_length <= (1 << 32) - 1:
        raise ValueError("Argon2 tag_length must be >= 4 bytes")
    if memory_cost < 8 * parallelism or memory_cost > (1 << 32) - 1:
        raise ValueError("Argon2 memory_cost must be in [8*p, 2^32 - 1] KiB")
    if time_cost < 1:
        raise ValueError("Argon2 time_cost must be >= 1")
    if version not in (0x10, 0x13):
        raise ValueError("Argon2 version must be 0x10 or 0x13")


def argon2(
    password: bytes,
    salt: bytes,
    *,
    time_cost: int = 3,
    memory_cost: int = 32,
    parallelism: int = 4,
    tag_length: int = 32,
    variant: int = ARGON2ID,
    version: int = ARGON2_VERSION,
    secret: bytes = b"",
    associated_data: bytes = b"",
) -> bytes:
    """Argon2 per RFC 9106. memory_cost is in kibibytes.

    variant is ARGON2D (0), ARGON2I (1), or ARGON2ID (2). secret and
    associated_data feed the optional K and X inputs. Single-threaded:
    lanes are computed sequentially in the spec-mandated slice order,
    which yields identical output to parallel execution.
    """
    _argon2_validate(variant, parallelism, tag_length, memory_cost, time_cost, version)

    mprime = 4 * parallelism * (memory_cost // (4 * parallelism))
    lane_length = mprime // parallelism
    segment_length = lane_length // _ARGON2_SLICES

    header = struct.pack(
        "<IIIIII", parallelism, tag_length, memory_cost, time_cost, version, variant
    )
    h0 = hashlib.blake2b(
        header
        + struct.pack("<I", len(password))
        + password
        + struct.pack("<I", len(salt))
        + salt
        + struct.pack("<I", len(secret))
        + secret
        + struct.pack("<I", len(associated_data))
        + associated_data,
        digest_size=64,
    ).digest()

    mem: list[list[int]] = [_ZERO_BLOCK[:] for _ in range(mprime)]
    for lane in range(parallelism):
        mem[lane * lane_length] = _words(
            _h_prime(h0 + struct.pack("<II", 0, lane), 1024)
        )
        mem[lane * lane_length + 1] = _words(
            _h_prime(h0 + struct.pack("<II", 1, lane), 1024)
        )

    for pass_ in range(time_cost):
        for slice_ in range(_ARGON2_SLICES):
            for lane in range(parallelism):
                _fill_segment(
                    mem,
                    lane_length=lane_length,
                    segment_length=segment_length,
                    pass_=pass_,
                    slice_=slice_,
                    lane=lane,
                    lanes=parallelism,
                    passes=time_cost,
                    mprime=mprime,
                    variant=variant,
                    version=version,
                )

    final = mem[lane_length - 1][:]
    for lane in range(1, parallelism):
        last = mem[lane * lane_length + lane_length - 1]
        final = [a ^ b for a, b in zip(final, last, strict=True)]
    return _h_prime(_block(final), tag_length)


def argon2id(
    password: bytes,
    salt: bytes,
    *,
    time_cost: int = 3,
    memory_cost: int = 65536,
    parallelism: int = 4,
    tag_length: int = 32,
) -> bytes:
    """Argon2id with RFC 9106 second-recommendation defaults.

    Default memory_cost is 64 MiB which is slow in pure Python; pass a
    smaller value for tests. Salt should be at least 16 random bytes.
    """
    return argon2(
        password,
        salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        tag_length=tag_length,
        variant=ARGON2ID,
    )


def verify_argon2(
    password: bytes,
    expected_tag: bytes,
    salt: bytes,
    **kwargs: Any,
) -> None:
    """Re-derive an Argon2 tag and compare via ct_equal.

    Raises InvalidTag on mismatch. kwargs are passed through to
    argon2 (time_cost, memory_cost, parallelism, variant, and friends).
    """
    candidate = argon2(password, salt, tag_length=len(expected_tag), **kwargs)
    if not ct_equal(candidate, expected_tag):
        raise InvalidTag("Argon2 tag verification failed")


__all__ = [
    "ARGON2D",
    "ARGON2I",
    "ARGON2ID",
    "ARGON2_VERSION",
    "argon2",
    "argon2id",
    "hkdf",
    "hkdf_expand",
    "hkdf_extract",
    "pbkdf2",
    "scrypt",
    "verify_argon2",
]
