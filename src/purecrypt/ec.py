# SPDX-License-Identifier: 0BSD
"""Short-Weierstrass elliptic-curve cryptography: ECDH and ECDSA.

NOT READY FOR PRODUCTION. Pure Python cannot provide constant-time
guarantees: scalar multiplication here is a textbook double-and-add in
affine coordinates with a modular inversion per step, which is
maximally variable-time and leaks the scalar through timing. This
package exists for education, testing, and environments where native
crypto is unavailable and the threat model tolerates it. Prefer OpenSSL
via the cryptography package for real deployments.

Implements:

* Curves: P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1) and
  secp256k1. All have cofactor h = 1.
* ECDH with mandatory peer-point validation: on-curve and in-subgroup
  (n * P == infinity). This is the invalid-curve-attack surface. The
  checks are not optional.
* ECDSA sign/verify with RFC 6979 deterministic nonces. Signatures are
  produced and consumed in DER form. Signing normalizes to low-s
  (BIP-62 style): verification still accepts the mathematically
  equivalent (r, n - s) form because ECDSA is inherently malleable. The
  low-s policy only pins the canonical encoder output.
* SEC1 uncompressed (and compressed, on parse) point format, SEC1
  ECPrivateKey PEM, PKCS#8 private and SubjectPublicKeyInfo public
  serialization.
"""

import hashlib
import hmac
import secrets
from collections.abc import Iterator
from dataclasses import dataclass

from . import asn1
from ._utils import i2osp, os2ip
from .exceptions import (
    InvalidKey,
    InvalidSerialization,
    InvalidSignature,
    UnsupportedAlgorithm,
)
from .pem import decode_pem, encode_pem

_OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"

_PEM_EC_PRIVATE = "EC PRIVATE KEY"
_PEM_PRIVATE = "PRIVATE KEY"
_PEM_PUBLIC = "PUBLIC KEY"

_KNOWN_HASHES = frozenset(
    {"sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_384", "sha3_512"}
)


def _hash(name: str, data: bytes) -> bytes:
    if name not in _KNOWN_HASHES:
        raise UnsupportedAlgorithm(f"unsupported hash {name!r}")
    return hashlib.new(name, data).digest()


# --- curve parameters --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Curve:
    """Short-Weierstrass curve y^2 = x^3 + a x + b over F_p."""

    name: str
    oid: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int
    h: int
    size: int  # coordinate size in octets

    @property
    def base_point(self) -> tuple[int, int]:
        return (self.gx, self.gy)


P256 = Curve(
    name="P-256",
    oid="1.2.840.10045.3.1.7",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    h=1,
    size=32,
)

P384 = Curve(
    name="P-384",
    oid="1.3.132.0.34",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
    b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    h=1,
    size=48,
)

P521 = Curve(
    name="P-521",
    oid="1.3.132.0.35",
    p=(1 << 521) - 1,
    a=(1 << 521) - 4,  # p - 3
    b=0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
    gx=0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
    gy=0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
    n=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
    h=1,
    size=66,
)

SECP256K1 = Curve(
    name="secp256k1",
    oid="1.3.132.0.10",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    h=1,
    size=32,
)

CURVES: tuple[Curve, ...] = (P256, P384, P521, SECP256K1)

_NAME_ALIASES: dict[str, Curve] = {}
for _c in CURVES:
    _NAME_ALIASES[_c.name.lower()] = _c
    _NAME_ALIASES[_c.oid] = _c
_NAME_ALIASES.update(
    {
        "secp256r1": P256,
        "prime256v1": P256,
        "nistp256": P256,
        "secp384r1": P384,
        "nistp384": P384,
        "secp521r1": P521,
        "nistp521": P521,
    }
)


def curve_by_name(name: str) -> Curve:
    try:
        return _NAME_ALIASES[name.lower()]
    except KeyError as exc:
        raise UnsupportedAlgorithm(f"unknown curve {name!r}") from exc


def curve_by_oid(oid: str) -> Curve:
    for c in CURVES:
        if c.oid == oid:
            return c
    raise UnsupportedAlgorithm(f"unknown curve OID {oid!r}")


# --- point arithmetic (affine) ------------------------------------------------

Point = tuple[int, int] | None  # None encodes the point at infinity


def _point_add(curve: Curve, p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % curve.p == 0:
            return None
        lam = ((3 * x1 * x1 + curve.a) * pow(2 * y1, -1, curve.p)) % curve.p
    else:
        lam = ((y2 - y1) * pow((x2 - x1) % curve.p, -1, curve.p)) % curve.p
    x3 = (lam * lam - x1 - x2) % curve.p
    y3 = (lam * (x1 - x3) - y1) % curve.p
    return (x3, y3)


def _scalar_mult(curve: Curve, k: int, point: tuple[int, int]) -> Point:
    """Plain LSB-first double-and-add. Deliberately variable-time."""
    result: Point = None
    addend: Point = point
    while k:
        if k & 1:
            result = _point_add(curve, result, addend)
        addend = _point_add(curve, addend, addend)
        k >>= 1
    return result


def on_curve(curve: Curve, x: int, y: int) -> bool:
    """Range and curve-equation check for a candidate point."""
    if not (0 <= x < curve.p and 0 <= y < curve.p):
        return False
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0


def validate_public_point(curve: Curve, x: int, y: int) -> None:
    """Full public-point validation: on-curve and in-subgroup.

    Raises InvalidKey otherwise. All bundled curves have cofactor 1, so
    on-curve implies prime-order subgroup, but the n * P == infinity
    check is performed anyway because this is the invalid-curve-attack
    surface and an explicit check is cheap insurance against parameter
    mistakes.
    """
    if not on_curve(curve, x, y):
        raise InvalidKey("point is not on the curve")
    if _scalar_mult(curve, curve.n, (x, y)) is not None:
        raise InvalidKey("point is not in the prime-order subgroup")


# --- SEC1 point encodings ------------------------------------------------------


def encode_point(
    curve: Curve, point: tuple[int, int], compressed: bool = False
) -> bytes:
    x, y = point
    if compressed:
        return bytes([0x02 | (y & 1)]) + i2osp(x, curve.size)
    return b"\x04" + i2osp(x, curve.size) + i2osp(y, curve.size)


def decode_point(curve: Curve, data: bytes) -> tuple[int, int]:
    """Parse a SEC1 point. Validates membership via validate_public_point.

    Malformed encodings raise InvalidSerialization. Well-formed
    encodings of points that fail validation (off-curve or wrong
    subgroup) raise InvalidKey.
    """
    if not data:
        raise InvalidSerialization("empty point encoding")
    if data[0] == 0x04:
        if len(data) != 1 + 2 * curve.size:
            raise InvalidSerialization("bad uncompressed point length")
        x = os2ip(data[1 : 1 + curve.size])
        y = os2ip(data[1 + curve.size :])
    elif data[0] in (0x02, 0x03):
        if len(data) != 1 + curve.size:
            raise InvalidSerialization("bad compressed point length")
        x = os2ip(data[1:])
        y = _recover_y(curve, x, data[0] & 1)
    else:
        raise InvalidSerialization("unknown point format byte")
    validate_public_point(curve, x, y)
    return (x, y)


def _recover_y(curve: Curve, x: int, odd: int) -> int:
    """Square root for p % 4 == 3 (true for every bundled curve)."""
    if curve.p % 4 != 3:
        raise UnsupportedAlgorithm("compressed points need p % 4 == 3")
    if not 0 <= x < curve.p:
        raise InvalidSerialization("x out of range")
    alpha = (x * x * x + curve.a * x + curve.b) % curve.p
    beta = pow(alpha, (curve.p + 1) // 4, curve.p)
    if beta * beta % curve.p != alpha:
        raise InvalidSerialization("compressed point x yields no y")
    return beta if (beta & 1) == odd else curve.p - beta


# --- RFC 6979 deterministic k ---------------------------------------------------


def _bits2int(data: bytes, qlen: int) -> int:
    v = int.from_bytes(data, "big")
    excess = len(data) * 8 - qlen
    if excess > 0:
        v >>= excess
    return v


def _bits2octets(data: bytes, n: int, rolen: int, qlen: int) -> bytes:
    z1 = _bits2int(data, qlen)
    z2 = z1 - n
    if z2 < 0:
        z2 = z1
    return i2osp(z2, rolen)


def _rfc6979_k(
    d: int, digest: bytes, n: int, hash_name: str, rolen: int, qlen: int
) -> Iterator[int]:
    """RFC 6979 HMAC-DRBG candidate nonce generator (section 3.2)."""
    hlen = hashlib.new(hash_name).digest_size
    bx = i2osp(d, rolen) + _bits2octets(digest, n, rolen, qlen)
    v = b"\x01" * hlen
    k = b"\x00" * hlen
    k = hmac.new(k, v + b"\x00" + bx, hash_name).digest()
    v = hmac.new(k, v, hash_name).digest()
    k = hmac.new(k, v + b"\x01" + bx, hash_name).digest()
    v = hmac.new(k, v, hash_name).digest()
    while True:
        t = b""
        while len(t) * 8 < qlen:
            v = hmac.new(k, v, hash_name).digest()
            t += v
        candidate = _bits2int(t, qlen)
        if 1 <= candidate < n:
            yield candidate
        k = hmac.new(k, v + b"\x00", hash_name).digest()
        v = hmac.new(k, v, hash_name).digest()


def _encode_dss(r: int, s: int) -> bytes:
    return asn1.encode_sequence(asn1.encode_integer(r), asn1.encode_integer(s))


def _decode_dss(sig: bytes, n: int) -> tuple[int, int]:
    """Strict DER parse of SEQUENCE { r INTEGER, s INTEGER }."""
    node = asn1.decode(sig)  # raises InvalidSerialization on bad DER
    kids = asn1.sequence_value(node)
    if len(kids) != 2:
        raise InvalidSerialization("ECDSA signature must have r and s")
    r = asn1.signed_int_value(kids[0])
    s = asn1.signed_int_value(kids[1])
    if not 1 <= r < n or not 1 <= s < n:
        raise InvalidSignature("ECDSA r or s out of range")
    return r, s


# --- key objects ----------------------------------------------------------------


@dataclass(frozen=True)
class ECPublicKey:
    """Elliptic-curve public key: a validated curve point."""

    curve: Curve
    x: int
    y: int

    def __post_init__(self) -> None:
        validate_public_point(self.curve, self.x, self.y)

    @property
    def point(self) -> tuple[int, int]:
        return (self.x, self.y)

    # -- signatures ---------------------------------------------------------

    def verify_ecdsa(
        self, signature: bytes, message: bytes, hash_name: str = "sha256"
    ) -> None:
        """Verify a DER ECDSA signature. Raises InvalidSignature."""
        curve = self.curve
        n = curve.n
        r, s = _decode_dss(signature, n)
        digest = _hash(hash_name, message)
        z = _bits2int(digest, n.bit_length())
        w = pow(s, -1, n)
        u1 = z * w % n
        u2 = r * w % n
        point = _point_add(
            curve,
            _scalar_mult(curve, u1, curve.base_point),
            _scalar_mult(curve, u2, self.point),
        )
        if point is None or point[0] % n != r:
            raise InvalidSignature("ECDSA verification failed")

    # -- serialization ---------------------------------------------------------

    def to_sec1_bytes(self, compressed: bool = False) -> bytes:
        return encode_point(self.curve, self.point, compressed)

    @classmethod
    def from_sec1_bytes(cls, data: bytes, curve: Curve) -> "ECPublicKey":
        x, y = decode_point(curve, data)
        return cls(curve=curve, x=x, y=y)

    def to_spki_der(self) -> bytes:
        alg = asn1.encode_sequence(
            asn1.encode_oid(_OID_EC_PUBLIC_KEY),
            asn1.encode_oid(self.curve.oid),
        )
        return asn1.encode_sequence(alg, asn1.encode_bit_string(self.to_sec1_bytes()))

    def to_spki_pem(self) -> str:
        return encode_pem(_PEM_PUBLIC, self.to_spki_der())

    @classmethod
    def from_der(cls, data: bytes) -> "ECPublicKey":
        node = asn1.decode(data)
        kids = asn1.sequence_value(node)
        if len(kids) != 2:
            raise InvalidSerialization("malformed SubjectPublicKeyInfo")
        alg_kids = asn1.sequence_value(kids[0])
        if len(alg_kids) != 2:
            raise InvalidSerialization("malformed AlgorithmIdentifier")
        if asn1.oid_value(alg_kids[0]) != _OID_EC_PUBLIC_KEY:
            raise InvalidSerialization("SPKI algorithm is not id-ecPublicKey")
        curve = curve_by_oid(asn1.oid_value(alg_kids[1]))
        return cls.from_sec1_bytes(asn1.bit_string_value(kids[1]), curve)

    @classmethod
    def from_pem(cls, text: str | bytes) -> "ECPublicKey":
        label, der = decode_pem(text)
        if label != _PEM_PUBLIC:
            raise InvalidSerialization(f"unexpected PEM label {label!r}")
        return cls.from_der(der)


def _check_private_scalar(curve: Curve, d: int) -> None:
    if not 1 <= d < curve.n:
        raise InvalidKey("private scalar out of range")


@dataclass(frozen=True)
class ECPrivateKey:
    """Elliptic-curve private key: scalar d on a named curve."""

    curve: Curve
    d: int

    def __post_init__(self) -> None:
        _check_private_scalar(self.curve, self.d)

    @classmethod
    def generate(cls, curve: Curve) -> "ECPrivateKey":
        d = secrets.randbelow(curve.n - 1) + 1
        return cls(curve=curve, d=d)

    def public_key(self) -> ECPublicKey:
        point = _scalar_mult(self.curve, self.d, self.curve.base_point)
        if point is None:
            raise InvalidKey("invalid private scalar")  # pragma: no cover
        return ECPublicKey(curve=self.curve, x=point[0], y=point[1])

    def private_bytes(self) -> bytes:
        return i2osp(self.d, self.curve.size)

    @classmethod
    def from_private_bytes(cls, data: bytes, curve: Curve) -> "ECPrivateKey":
        if len(data) != curve.size:
            raise InvalidKey("private scalar length mismatch")
        return cls(curve=curve, d=os2ip(data))

    # -- ECDH --------------------------------------------------------------------

    def ecdh(self, peer: "ECPublicKey | bytes") -> bytes:
        """X-coordinate shared secret. Peer point is fully validated."""
        if isinstance(peer, bytes):
            peer_key = ECPublicKey.from_sec1_bytes(peer, self.curve)
        else:
            peer_key = peer
            if peer_key.curve != self.curve:
                raise InvalidKey("peer key is on a different curve")
            validate_public_point(self.curve, peer_key.x, peer_key.y)
        shared = _scalar_mult(self.curve, self.d, peer_key.point)
        if shared is None:
            raise InvalidKey("ECDH produced the point at infinity")
        return i2osp(shared[0], self.curve.size)

    # -- ECDSA -------------------------------------------------------------------

    def sign_ecdsa(self, message: bytes, hash_name: str = "sha256") -> bytes:
        """Deterministic RFC 6979 ECDSA signature in DER form.

        Normalizes to low-s (s > n/2 is replaced by n - s) as a canonical
        output policy. ECDSA remains mathematically malleable: (r, n - s)
        always verifies. See the module docstring.
        """
        curve = self.curve
        n = curve.n
        qlen = n.bit_length()
        digest = _hash(hash_name, message)
        z = _bits2int(digest, qlen)
        for k in _rfc6979_k(self.d, digest, n, hash_name, curve.size, qlen):
            point = _scalar_mult(curve, k, curve.base_point)
            if point is None:
                continue  # pragma: no cover
            r = point[0] % n
            if r == 0:
                continue  # pragma: no cover
            s = pow(k, -1, n) * ((z + r * self.d) % n) % n
            if s == 0:
                continue  # pragma: no cover
            if s > n // 2:
                s = n - s
            return _encode_dss(r, s)
        raise InvalidSignature("RFC 6979 produced no usable nonce")

    # -- serialization ------------------------------------------------------------

    def to_sec1_der(self) -> bytes:
        """SEC1 ECPrivateKey with both optional fields populated."""
        return asn1.encode_sequence(
            asn1.encode_integer(1),
            asn1.encode_octet_string(self.private_bytes()),
            asn1.encode_context(0, asn1.encode_oid(self.curve.oid)),
            asn1.encode_context(
                1, asn1.encode_bit_string(self.public_key().to_sec1_bytes())
            ),
        )

    def to_sec1_pem(self) -> str:
        return encode_pem(_PEM_EC_PRIVATE, self.to_sec1_der())

    def to_pkcs8_der(self) -> bytes:
        inner = asn1.encode_sequence(
            asn1.encode_integer(1),
            asn1.encode_octet_string(self.private_bytes()),
        )
        alg = asn1.encode_sequence(
            asn1.encode_oid(_OID_EC_PUBLIC_KEY),
            asn1.encode_oid(self.curve.oid),
        )
        return asn1.encode_sequence(
            asn1.encode_integer(0), alg, asn1.encode_octet_string(inner)
        )

    def to_pkcs8_pem(self) -> str:
        return encode_pem(_PEM_PRIVATE, self.to_pkcs8_der())

    @classmethod
    def from_der(cls, data: bytes, curve: Curve | None = None) -> "ECPrivateKey":
        """Parse SEC1 ECPrivateKey or PKCS#8 PrivateKeyInfo DER.

        For SEC1 input missing its [0] parameters field, the curve
        argument is required.
        """
        node = asn1.decode(data)
        kids = asn1.sequence_value(node)
        if len(kids) == 3 and kids[1].tag == asn1.TAG_SEQUENCE:
            return cls._from_pkcs8(kids)
        return cls._from_sec1(kids, curve)

    @classmethod
    def _from_pkcs8(cls, kids: tuple[asn1.DerNode, ...]) -> "ECPrivateKey":
        if asn1.int_value(kids[0]) != 0:
            raise InvalidSerialization("unsupported PrivateKeyInfo version")
        alg_kids = asn1.sequence_value(kids[1])
        if len(alg_kids) != 2:
            raise InvalidSerialization("malformed AlgorithmIdentifier")
        if asn1.oid_value(alg_kids[0]) != _OID_EC_PUBLIC_KEY:
            raise InvalidSerialization("PKCS#8 algorithm is not id-ecPublicKey")
        curve = curve_by_oid(asn1.oid_value(alg_kids[1]))
        inner = asn1.decode(asn1.octet_string_value(kids[2]))
        return cls._from_sec1(asn1.sequence_value(inner), curve)

    @classmethod
    def _from_sec1(
        cls, kids: tuple[asn1.DerNode, ...], curve: Curve | None
    ) -> "ECPrivateKey":
        if not 2 <= len(kids) <= 4:
            raise InvalidSerialization("malformed SEC1 ECPrivateKey")
        if asn1.int_value(kids[0]) != 1:
            raise InvalidSerialization("unsupported ECPrivateKey version")
        d_bytes = asn1.octet_string_value(kids[1])
        curve = _sec1_curve(kids, curve)
        if len(d_bytes) != curve.size:
            raise InvalidSerialization("private scalar length mismatch")
        key = cls(curve=curve, d=os2ip(d_bytes))
        _sec1_check_public(key, kids)
        return key

    @classmethod
    def from_pem(cls, text: str | bytes, curve: Curve | None = None) -> "ECPrivateKey":
        label, der = decode_pem(text)
        if label not in (_PEM_EC_PRIVATE, _PEM_PRIVATE):
            raise InvalidSerialization(f"unexpected PEM label {label!r}")
        return cls.from_der(der, curve)


def _sec1_curve(kids: tuple[asn1.DerNode, ...], fallback: Curve | None) -> Curve:
    """Resolve the curve from the optional [0] parameters field."""
    for kid in kids[2:]:
        if kid.tag == 0xA0:
            params = asn1.context_value(kid, 0)
            if len(params) != 1:
                raise InvalidSerialization("bad EC parameters")
            return curve_by_oid(asn1.oid_value(params[0]))
    if fallback is None:
        raise InvalidSerialization("SEC1 key without curve parameters")
    return fallback


def _sec1_check_public(key: ECPrivateKey, kids: tuple[asn1.DerNode, ...]) -> None:
    """If [1] publicKey is present it must match the private scalar."""
    for kid in kids[2:]:
        if kid.tag == 0xA1:
            params = asn1.context_value(kid, 1)
            if len(params) != 1:
                raise InvalidSerialization("bad SEC1 publicKey field")
            embedded = asn1.bit_string_value(params[0])
            if embedded != key.public_key().to_sec1_bytes():
                raise InvalidKey("SEC1 public key does not match private key")
