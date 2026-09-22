# SPDX-License-Identifier: 0BSD
"""Thin typed facade over hashlib plus an HMAC helper.

Convenience layer only: the real work is done by CPython's hashlib
and hmac bindings. md5 and sha1 are exposed for legacy and protocol
compatibility only; they are broken and must not be used for new
designs or anything security-relevant.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
from collections.abc import Callable
from typing import Protocol, TypeAlias


class HashLike(Protocol):
    """Structural type for hashlib hash objects."""

    @property
    def digest_size(self) -> int:
        pass

    @property
    def block_size(self) -> int:
        pass

    def update(self, data: bytes, /) -> None:
        pass

    def digest(self) -> bytes:
        pass

    def copy(self) -> HashLike:
        pass


HashFactory: TypeAlias = Callable[[bytes], HashLike]
DigestSpec: TypeAlias = str | HashFactory


def _factory(digest: DigestSpec) -> HashFactory:
    """Resolve a digest name or hashlib-style constructor to a factory."""
    if isinstance(digest, str):
        name = digest

        def make(data: bytes = b"") -> HashLike:
            return hashlib.new(name, data)

        return make
    return digest


def digest_size(digest: DigestSpec) -> int:
    """Output size in bytes of the named or given digest."""
    return _factory(digest)(b"").digest_size


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def sha1(data: bytes) -> bytes:
    """LEGACY ONLY: SHA-1 is broken. Present for protocol interop."""
    return hashlib.sha1(data).digest()  # noqa: S324  # nosec B324: legacy interop only, documented


def md5(data: bytes) -> bytes:
    """LEGACY ONLY: MD5 is broken. Present for protocol interop."""
    return hashlib.md5(data).digest()  # noqa: S324  # nosec B324: legacy interop only, documented


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def shake128(data: bytes, length: int) -> bytes:
    return hashlib.shake_128(data).digest(length)


def shake256(data: bytes, length: int) -> bytes:
    return hashlib.shake_256(data).digest(length)


def blake2b(data: bytes, digest_size: int = 64) -> bytes:
    return hashlib.blake2b(data, digest_size=digest_size).digest()


def blake2s(data: bytes, digest_size: int = 32) -> bytes:
    return hashlib.blake2s(data, digest_size=digest_size).digest()


def _hmac_digest(factory: HashFactory, key: bytes, msg: bytes) -> bytes:
    """RFC 2104 HMAC over an arbitrary hashlib-style factory.

    Implemented directly (rather than via hmac.HMAC) so that any
    factory returning a HashLike works, including closures that carry
    preset parameters such as blake2b digest sizes. Not valid for
    XOF digests such as SHAKE, which need a length argument.
    """
    probe = factory(b"")
    block_size = probe.block_size
    if len(key) > block_size:
        key = factory(key).digest()
    key = key.ljust(block_size, b"\x00")
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = factory(ipad)
    inner.update(msg)
    outer = factory(opad)
    outer.update(inner.digest())
    return outer.digest()


def HMAC(key: bytes, msg: bytes, digest: DigestSpec = "sha256") -> bytes:  # noqa: N802
    """HMAC(key, msg) under the named digest or hashlib-style factory."""
    if isinstance(digest, str):
        return _hmac.digest(key, msg, digest)
    return _hmac_digest(digest, key, msg)


__all__ = [
    "HMAC",
    "DigestSpec",
    "HashFactory",
    "HashLike",
    "blake2b",
    "blake2s",
    "digest_size",
    "md5",
    "sha1",
    "sha3_256",
    "sha3_512",
    "sha256",
    "sha384",
    "sha512",
    "shake128",
    "shake256",
]
