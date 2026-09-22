# SPDX-License-Identifier: 0BSD
"""Ed25519 signatures per RFC 8032, plus the Ed25519ph prehash variant.

NOT READY FOR PRODUCTION. Pure Python cannot provide constant-time
guarantees. Scalar multiplication here runs a fixed-iteration
double-and-add-always ladder in extended coordinates with a
mask-selected conditional add, which removes the obvious
secret-dependent branches. Residual leaks remain: Python big-int
arithmetic is variable-time, so secrets still leak through timing.
This package exists for education, testing, and environments where
native crypto is unavailable and the threat model tolerates it.
Prefer libsodium via PyNaCl or OpenSSL via cryptography for real
deployments.

Verification policy (RFC 8032 section 5.1.7 with deliberate strictness):

* The cofactored equation [8][S]B = [8]R + [8][k]A' is checked, the
  conservative choice that remains correct under the cofactor.
* S must be canonical: S >= l is rejected before any curve work.
* Point decoding is strict: non-canonical y >= p, missing square roots,
  and x = 0 with the sign bit set are all rejected.
* Small-order public keys are rejected outright ([8]A == identity).
  The cofactored equation alone does not require this, but accepting
  small-order A enables forgery-adjacent edge cases, so this
  implementation is stricter than the RFC minimum.
"""

import hashlib
import secrets
from dataclasses import dataclass

from ._utils import ct_equal
from .exceptions import InvalidKey, InvalidSignature

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)  # sqrt(-1) mod p

_IDENTITY = (0, 1)
_DOM2_PREFIX = b"SigEd25519 no Ed25519 collisions"


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if x % 2 != 0:
        x = _P - x
    return x


_B_Y = 4 * pow(5, _P - 2, _P) % _P
_B = (_xrecover(_B_Y), _B_Y)


def _point_add(p1: tuple[int, int], p2: tuple[int, int]) -> tuple[int, int]:
    """Complete twisted-Edwards addition for a = -1."""
    x1, y1 = p1
    x2, y2 = p2
    xxyy = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + y1 * x2) * pow(1 + xxyy, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - xxyy, _P - 2, _P) % _P
    return (x3, y3)


# Extended twisted-Edwards point (X, Y, T, Z) with x = X/Z, y = Y/Z and
# T = XY/Z. The addition law below is complete for ed25519 (d is a
# non-square), so it handles doubling, the identity and inverses with
# no exceptional cases.
_EXT_IDENTITY = (0, 1, 0, 1)

# Widest scalar used here is 8 * S with S < l, which stays under 2^256.
_SCALAR_BITS = 256


def _ext_add(
    p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    """Extended twisted-Edwards addition, a = -1 (RFC 8032 point add)."""
    x1, y1, t1, z1 = p1
    x2, y2, t2, z2 = p2
    a = x1 * x2 % _P
    b = y1 * y2 % _P
    c = _D * t1 * t2 % _P
    d = z1 * z2 % _P
    e = ((x1 + y1) * (x2 + y2) - a - b) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return (e * f % _P, g * h % _P, e * h % _P, f * g % _P)


def _scalarmult(k: int, point: tuple[int, int]) -> tuple[int, int]:
    """Fixed-iteration double-and-add-always over _SCALAR_BITS bits.

    Every iteration computes both the doubling and the conditional add
    and selects via integer mask arithmetic rather than branching on a
    secret bit. Still not constant-time: Python int arithmetic leaks.
    Scalars must fit in _SCALAR_BITS bits, which every in-tree caller
    upholds.
    """
    px, py = point
    pt = (px, py, px * py % _P, 1)
    acc = _EXT_IDENTITY
    for i in range(_SCALAR_BITS - 1, -1, -1):
        acc = _ext_add(acc, acc)
        cand = _ext_add(acc, pt)
        mask = -((k >> i) & 1)
        acc = (
            acc[0] ^ (mask & (acc[0] ^ cand[0])),
            acc[1] ^ (mask & (acc[1] ^ cand[1])),
            acc[2] ^ (mask & (acc[2] ^ cand[2])),
            acc[3] ^ (mask & (acc[3] ^ cand[3])),
        )
    zinv = pow(acc[3], _P - 2, _P)
    return (acc[0] * zinv % _P, acc[1] * zinv % _P)


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point_strict(data: bytes) -> tuple[int, int] | None:
    """RFC 8032 decode plus canonical-y rejection. None on failure."""
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = data[31] >> 7
    if y >= _P:
        return None  # non-canonical encoding
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
        if (x * x - xx) % _P != 0:
            return None
    if x == 0 and sign:
        return None
    if x % 2 != sign:
        x = _P - x
    return (x, y)


def _hint(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % _L


def _clamp(h_first_half: bytes) -> int:
    a = int.from_bytes(h_first_half, "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


@dataclass(frozen=True)
class Ed25519PublicKey:
    """Ed25519 public key (32 raw bytes, validated lazily on verify)."""

    _enc: bytes

    def __post_init__(self) -> None:
        if len(self._enc) != 32:
            raise InvalidKey("Ed25519 public keys are 32 bytes")

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "Ed25519PublicKey":
        return cls(_enc=bytes(data))

    def public_bytes(self) -> bytes:
        return self._enc

    def verify(self, signature: bytes, message: bytes) -> None:
        """PureEdDSA verification. Raises InvalidSignature on failure."""
        _verify(self._enc, signature, message, ph=False)

    def verify_ph(self, signature: bytes, message: bytes) -> None:
        """Ed25519ph verification (dom2, prehashed message)."""
        _verify(self._enc, signature, message, ph=True)


@dataclass(frozen=True)
class Ed25519PrivateKey:
    """Ed25519 private key held as its 32-byte seed."""

    _seed: bytes

    def __post_init__(self) -> None:
        if len(self._seed) != 32:
            raise InvalidKey("Ed25519 seeds are 32 bytes")

    @classmethod
    def generate(cls) -> "Ed25519PrivateKey":
        return cls(_seed=secrets.token_bytes(32))

    @classmethod
    def from_seed(cls, seed: bytes | bytearray | memoryview) -> "Ed25519PrivateKey":
        return cls(_seed=bytes(seed))

    def private_bytes(self) -> bytes:
        """Return the 32-byte seed (the private scalar is derived)."""
        return self._seed

    def public_key(self) -> Ed25519PublicKey:
        h = _sha512(self._seed)
        a = _clamp(h[:32])
        return Ed25519PublicKey(_enc=_encode_point(_scalarmult(a, _B)))

    def sign(self, message: bytes) -> bytes:
        """PureEdDSA signature over message."""
        return _sign(self._seed, message, ph=False)

    def sign_ph(self, message: bytes) -> bytes:
        """Ed25519ph signature over message (dom2, prehashed)."""
        return _sign(self._seed, message, ph=True)


def _dom2(ph: bool) -> bytes:
    if not ph:
        return b""
    # phflag = 1, empty context (len byte 0)
    return _DOM2_PREFIX + b"\x01\x00"


def _sign(seed: bytes, message: bytes, ph: bool) -> bytes:
    h = _sha512(seed)
    a = _clamp(h[:32])
    prefix = h[32:]
    a_enc = _encode_point(_scalarmult(a, _B))
    dom2 = _dom2(ph)
    body = _sha512(message) if ph else message
    r = _hint(dom2 + prefix + body)
    r_enc = _encode_point(_scalarmult(r, _B))
    k = _hint(dom2 + r_enc + a_enc + body)
    s = (r + k * a) % _L
    return r_enc + s.to_bytes(32, "little")


def _verify(a_enc: bytes, signature: bytes, message: bytes, ph: bool) -> None:
    if len(signature) != 64:
        raise InvalidSignature("Ed25519 signatures are 64 bytes")
    r_enc = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        raise InvalidSignature("non-canonical S >= l")
    a_pt = _decode_point_strict(a_enc)
    if a_pt is None:
        raise InvalidSignature("public key fails strict point decoding")
    if ct_equal(_encode_point(_scalarmult(8, a_pt)), _encode_point(_IDENTITY)):
        raise InvalidSignature("small-order public key rejected")
    r_pt = _decode_point_strict(r_enc)
    if r_pt is None:
        raise InvalidSignature("R fails strict point decoding")
    dom2 = _dom2(ph)
    body = _sha512(message) if ph else message
    k = _hint(dom2 + r_enc + a_enc + body)
    # Cofactored check: [8][S]B == [8](R + [k]A)
    lhs = _scalarmult(8 * s, _B)
    rhs = _scalarmult(8, _point_add(r_pt, _scalarmult(k, a_pt)))
    if not ct_equal(_encode_point(lhs), _encode_point(rhs)):
        raise InvalidSignature("Ed25519 verification failed")
