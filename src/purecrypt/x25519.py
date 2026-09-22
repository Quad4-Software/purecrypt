# SPDX-License-Identifier: 0BSD
"""X25519 and X448 Diffie-Hellman per RFC 7748.

NOT READY FOR PRODUCTION. Pure Python cannot provide constant-time
guarantees: the Montgomery ladder below uses Python conditional swaps,
which are data-dependent branches and leak the scalar through timing.
This package exists for education, testing, and environments where
native crypto is unavailable and the threat model tolerates it. Prefer
OpenSSL via the cryptography package for real deployments.

Both functions clamp the scalar per RFC 7748, accept non-canonical
u-coordinates (the top bit is masked for X25519), and reject an all-zero
shared-secret output, which indicates a low-order peer point
(contributed-key attack surface) and raises InvalidKey.
"""

import secrets
from dataclasses import dataclass

from .exceptions import InvalidKey

_P25519 = 2**255 - 19
_P448 = 2**448 - 2**224 - 1


def _ladder(k: int, u: int, p: int, a24: int, bits: int) -> int:
    """RFC 7748 Montgomery ladder. Variable-time Python swaps."""
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in range(bits - 1, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        aa = (x2 + z2) ** 2 % p
        bb = (x2 - z2) ** 2 % p
        e = (aa - bb) % p
        da = ((x3 - z3) * (x2 + z2)) % p
        cb = ((x3 + z3) * (x2 - z2)) % p
        x3 = (da + cb) ** 2 % p
        z3 = x1 * ((da - cb) ** 2) % p
        x2 = aa * bb % p
        z2 = e * (aa + a24 * e) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return x2 * pow(z2, p - 2, p) % p


def _x25519(scalar: bytes, u_bytes: bytes) -> bytes:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    out = _ladder(int.from_bytes(k, "little"), u, _P25519, 121665, 255)
    return out.to_bytes(32, "little")


def _x448(scalar: bytes, u_bytes: bytes) -> bytes:
    k = bytearray(scalar)
    k[0] &= 252
    k[55] |= 128
    u = int.from_bytes(u_bytes, "little")
    out = _ladder(int.from_bytes(k, "little"), u, _P448, 39081, 448)
    return out.to_bytes(56, "little")


def _check_shared(shared: bytes) -> bytes:
    """Reject all-zero outputs (low-order peer point, RFC 7748 6.1/6.2)."""
    if not any(shared):
        raise InvalidKey("low-order peer point: all-zero shared secret")
    return shared


@dataclass(frozen=True)
class X25519PublicKey:
    _enc: bytes

    def __post_init__(self) -> None:
        if len(self._enc) != 32:
            raise InvalidKey("X25519 public keys are 32 bytes")

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "X25519PublicKey":
        return cls(_enc=bytes(data))

    def public_bytes(self) -> bytes:
        return self._enc


@dataclass(frozen=True)
class X25519PrivateKey:
    _scalar: bytes

    def __post_init__(self) -> None:
        if len(self._scalar) != 32:
            raise InvalidKey("X25519 private keys are 32 bytes")

    @classmethod
    def generate(cls) -> "X25519PrivateKey":
        return cls(_scalar=secrets.token_bytes(32))

    @classmethod
    def from_private_bytes(
        cls, data: bytes | bytearray | memoryview
    ) -> "X25519PrivateKey":
        return cls(_scalar=bytes(data))

    def private_bytes(self) -> bytes:
        return self._scalar

    def public_key(self) -> X25519PublicKey:
        return X25519PublicKey(_enc=_x25519(self._scalar, b"\x09" + b"\x00" * 31))

    def exchange(self, peer: X25519PublicKey | bytes) -> bytes:
        """Return the 32-byte shared secret. Raises InvalidKey on low order."""
        enc = peer.public_bytes() if isinstance(peer, X25519PublicKey) else bytes(peer)
        if len(enc) != 32:
            raise InvalidKey("X25519 peer public keys are 32 bytes")
        return _check_shared(_x25519(self._scalar, enc))


@dataclass(frozen=True)
class X448PublicKey:
    _enc: bytes

    def __post_init__(self) -> None:
        if len(self._enc) != 56:
            raise InvalidKey("X448 public keys are 56 bytes")

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "X448PublicKey":
        return cls(_enc=bytes(data))

    def public_bytes(self) -> bytes:
        return self._enc


@dataclass(frozen=True)
class X448PrivateKey:
    _scalar: bytes

    def __post_init__(self) -> None:
        if len(self._scalar) != 56:
            raise InvalidKey("X448 private keys are 56 bytes")

    @classmethod
    def generate(cls) -> "X448PrivateKey":
        return cls(_scalar=secrets.token_bytes(56))

    @classmethod
    def from_private_bytes(
        cls, data: bytes | bytearray | memoryview
    ) -> "X448PrivateKey":
        return cls(_scalar=bytes(data))

    def private_bytes(self) -> bytes:
        return self._scalar

    def public_key(self) -> X448PublicKey:
        return X448PublicKey(_enc=_x448(self._scalar, b"\x05" + b"\x00" * 55))

    def exchange(self, peer: X448PublicKey | bytes) -> bytes:
        """Return the 56-byte shared secret. Raises InvalidKey on low order."""
        enc = peer.public_bytes() if isinstance(peer, X448PublicKey) else bytes(peer)
        if len(enc) != 56:
            raise InvalidKey("X448 peer public keys are 56 bytes")
        return _check_shared(_x448(self._scalar, enc))
