# SPDX-License-Identifier: 0BSD
"""Shared internals: integer/byte conversion, xor, secret hygiene.

Nothing here is public API.
"""

from __future__ import annotations

import hmac


def i2osp(value: int, length: int) -> bytes:
    """Integer-to-octet-string primitive (RFC 8017)."""
    if value < 0 or value >= 1 << (8 * length):
        raise ValueError("integer too large for requested length")
    return value.to_bytes(length, "big")


def os2ip(data: bytes) -> int:
    """Octet-string-to-integer primitive (RFC 8017)."""
    return int.from_bytes(data, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("xor operands differ in length")
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def ct_equal(a: bytes, b: bytes) -> bool:
    """Constant-time-ish byte comparison via hmac.compare_digest.

    Pure Python cannot guarantee constant time; this is the best the
    language offers and avoids the obvious early-exit pitfalls.
    """
    return hmac.compare_digest(a, b)


def wipe(buf: bytearray) -> None:
    """Best-effort overwrite of mutable secret material.

    CPython may keep other copies of the data alive elsewhere; this is
    hygiene, not a guarantee.
    """
    for i in range(len(buf)):
        buf[i] = 0


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)
