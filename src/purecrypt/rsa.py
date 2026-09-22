# SPDX-License-Identifier: 0BSD
"""RSA per RFC 8017 (PKCS#1 v2.2): key generation, signatures, encryption.

NOT READY FOR PRODUCTION. Pure Python cannot provide constant-time
guarantees: private-key operations here are demonstrably variable-time
and are vulnerable to timing and potentially other side-channel
analysis. This package exists for education, testing, and environments
where native crypto is unavailable and the threat model tolerates it.
Prefer OpenSSL via the cryptography package for real deployments.

Implements:

* Probable-prime key generation (trial division + Miller-Rabin), CRT
  components dmp1/dmq1/iqmp, default e = 65537, minimum 1024 bits.
* RSASSA-PKCS1-v1_5 sign/verify with DigestInfo for sha1/sha224/sha256/
  sha384/sha512.
* RSASSA-PSS sign/verify with MGF1 and configurable salt length.
* RSAES-PKCS1-v1_5 encrypt/decrypt. NOTE: v1.5 decryption is
  fundamentally exposed to Bleichenbacher-style padding-oracle attacks.
  All padding failures collapse to a single InvalidKey("decryption
  failed") error with no distinguishable sub-case, but in pure Python
  the padding scan is unavoidably variable-time, so a determined oracle
  attacker may still extract signal. Do not use v1.5 decryption on
  attacker-supplied ciphertext. Prefer OAEP.
* RSAES-OAEP encrypt/decrypt with MGF1 and configurable hash/label.
  Decrypt likewise returns the single uniform InvalidKey error for every
  failure mode (bad length, bad lHash, bad separator).
* Serialization: PKCS#1 RSAPublicKey/RSAPrivateKey, PKCS#8
  PrivateKeyInfo, and SubjectPublicKeyInfo, in DER and PEM.
"""

import hashlib
import math
import secrets
from dataclasses import dataclass

from . import asn1
from ._utils import ct_equal, i2osp, os2ip, xor_bytes
from .exceptions import (
    InvalidKey,
    InvalidSerialization,
    InvalidSignature,
    UnsupportedAlgorithm,
)
from .pem import decode_pem, encode_pem

MIN_KEY_BITS = 1024
DEFAULT_E = 65537
_MR_ROUNDS = 16

_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"

_PEM_RSA_PUBLIC = "RSA PUBLIC KEY"
_PEM_RSA_PRIVATE = "RSA PRIVATE KEY"
_PEM_PUBLIC = "PUBLIC KEY"
_PEM_PRIVATE = "PRIVATE KEY"

# DigestInfo prefixes (RFC 8017 section 9.2 note) for EMSA-PKCS1-v1_5.
_DIGEST_INFO_PREFIX: dict[str, bytes] = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha224": bytes.fromhex("302d300d06096086480165030402040500041c"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

# Hashes permitted for PSS and OAEP (v1.5 is restricted to the
# DigestInfo table above).
_KNOWN_HASHES = frozenset(
    {
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3_256",
        "sha3_384",
        "sha3_512",
    }
)


def _check_hash(name: str) -> None:
    if name not in _KNOWN_HASHES:
        raise UnsupportedAlgorithm(f"unsupported hash {name!r}")


def _hash_size(name: str) -> int:
    _check_hash(name)
    return hashlib.new(name).digest_size


def _hash(name: str, data: bytes) -> bytes:
    _check_hash(name)
    return hashlib.new(name, data).digest()


def mgf1(seed: bytes, length: int, hash_name: str = "sha256") -> bytes:
    """Mask generation function (RFC 8017 B.2.1)."""
    hlen = _hash_size(hash_name)
    out = bytearray()
    for counter in range(math.ceil(length / hlen)):
        out += _hash(hash_name, seed + counter.to_bytes(4, "big"))
    return bytes(out[:length])


# --- primality -------------------------------------------------------------

_SMALL_PRIMES: tuple[int, ...] = ()


def _build_small_primes() -> tuple[int, ...]:
    sieve = bytearray(b"\x01") * 2048
    sieve[0] = sieve[1] = 0
    for i in range(2, int(2048**0.5) + 1):
        if sieve[i]:
            sieve[i * i :: i] = b"\x00" * len(sieve[i * i :: i])
    return tuple(i for i in range(2048) if sieve[i])


_SMALL_PRIMES = _build_small_primes()


def _miller_rabin(n: int, rounds: int) -> bool:
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _is_probable_prime(n: int, rounds: int = _MR_ROUNDS) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    return _miller_rabin(n, rounds)


def _generate_prime(bits: int, e: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if math.gcd(candidate - 1, e) != 1:
            continue
        if _is_probable_prime(candidate):
            return candidate


def generate_private_key(bits: int = 2048, e: int = DEFAULT_E) -> "RSAPrivateKey":
    """Generate a probable-prime RSA key. bits must be >= 1024.

    Pure-Python generation is slow: roughly a second for 1024 bits and
    tens of seconds for 4096 bits, depending on luck.
    """
    if bits < MIN_KEY_BITS:
        raise InvalidKey(f"RSA keys smaller than {MIN_KEY_BITS} bits rejected")
    if e < 3 or e % 2 == 0 or e.bit_length() > 32:
        raise InvalidKey("public exponent must be an odd int >= 3")
    p_bits = bits // 2
    q_bits = bits - p_bits
    while True:
        p = _generate_prime(p_bits, e)
        q = _generate_prime(q_bits, e)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        if n.bit_length() != bits:
            continue
        break
    d = pow(e, -1, math.lcm(p - 1, q - 1))
    return RSAPrivateKey(
        n=n,
        e=e,
        d=d,
        p=p,
        q=q,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
    )


# --- key objects -----------------------------------------------------------


def _check_public_numbers(n: int, e: int) -> None:
    if n.bit_length() < MIN_KEY_BITS:
        raise InvalidKey(f"RSA modulus smaller than {MIN_KEY_BITS} bits")
    if n % 2 == 0:
        raise InvalidKey("even RSA modulus is invalid")
    if e < 3 or e % 2 == 0:
        raise InvalidKey("public exponent must be odd and >= 3")
    if e >= n:
        raise InvalidKey("public exponent out of range")


@dataclass(frozen=True)
class RSAPublicKey:
    """RSA public key (n, e)."""

    n: int
    e: int

    def __post_init__(self) -> None:
        _check_public_numbers(self.n, self.e)

    @property
    def key_size_bits(self) -> int:
        return self.n.bit_length()

    @property
    def key_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    # -- primitives ---------------------------------------------------------

    def _rsaep(self, m: int) -> int:
        return pow(m, self.e, self.n)

    # -- signatures ---------------------------------------------------------

    def verify_v15(
        self, signature: bytes, message: bytes, hash_name: str = "sha256"
    ) -> None:
        """Verify RSASSA-PKCS1-v1_5. Raises InvalidSignature on failure."""
        k = self.key_bytes
        if len(signature) != k:
            raise InvalidSignature("signature length mismatch")
        if hash_name not in _DIGEST_INFO_PREFIX:
            raise UnsupportedAlgorithm(f"v1.5 unsupported hash {hash_name!r}")
        m = self._rsaep(os2ip(signature))
        em = i2osp(m, k)
        expected = _emsa_v15_encode(hash_name, _hash(hash_name, message), k)
        if not ct_equal(em, expected):
            raise InvalidSignature("signature verification failed")

    def verify_pss(
        self,
        signature: bytes,
        message: bytes,
        hash_name: str = "sha256",
        salt_len: int | None = None,
    ) -> None:
        """Verify RSASSA-PSS.

        salt_len=None recovers the salt length from the padding (like
        pyca's PSS.AUTO). An int requires that exact length.
        """
        k = self.key_bytes
        if len(signature) != k:
            raise InvalidSignature("signature length mismatch")
        hlen = _hash_size(hash_name)
        em_bits = self.n.bit_length() - 1
        em_len = (em_bits + 7) // 8
        if em_len < hlen + 2:
            raise InvalidSignature("key too small for PSS")
        m = self._rsaep(os2ip(signature))
        if m >= 1 << em_bits:
            raise InvalidSignature("signature representative out of range")
        em = i2osp(m, em_len)
        if not _emsa_pss_verify(
            em, _hash(hash_name, message), hash_name, salt_len, em_bits
        ):
            raise InvalidSignature("signature verification failed")

    # -- encryption ----------------------------------------------------------

    def encrypt_v15(self, message: bytes) -> bytes:
        """RSAES-PKCS1-v1_5 encryption."""
        k = self.key_bytes
        if len(message) > k - 11:
            raise InvalidKey("message too long for v1.5 encryption")
        ps = _nonzero_random(k - len(message) - 3)
        em = b"\x00\x02" + ps + b"\x00" + message
        return i2osp(self._rsaep(os2ip(em)), k)

    def encrypt_oaep(
        self,
        message: bytes,
        hash_name: str = "sha256",
        label: bytes = b"",
    ) -> bytes:
        """RSAES-OAEP encryption (MGF1 with the same hash)."""
        k = self.key_bytes
        hlen = _hash_size(hash_name)
        if len(message) > k - 2 * hlen - 2:
            raise InvalidKey("message too long for OAEP")
        em = _eme_oaep_encode(message, k, hash_name, label)
        return i2osp(self._rsaep(os2ip(em)), k)

    # -- serialization --------------------------------------------------------

    def to_pkcs1_der(self) -> bytes:
        """PKCS#1 RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }."""
        return asn1.encode_sequence(
            asn1.encode_integer(self.n), asn1.encode_integer(self.e)
        )

    def to_pkcs1_pem(self) -> str:
        return encode_pem(_PEM_RSA_PUBLIC, self.to_pkcs1_der())

    def to_spki_der(self) -> bytes:
        """SubjectPublicKeyInfo wrapping the PKCS#1 public key."""
        alg = asn1.encode_sequence(
            asn1.encode_oid(_OID_RSA_ENCRYPTION), asn1.encode_null()
        )
        return asn1.encode_sequence(alg, asn1.encode_bit_string(self.to_pkcs1_der()))

    def to_spki_pem(self) -> str:
        return encode_pem(_PEM_PUBLIC, self.to_spki_der())

    @classmethod
    def from_der(cls, data: bytes) -> "RSAPublicKey":
        """Parse PKCS#1 RSAPublicKey or SubjectPublicKeyInfo DER."""
        node = asn1.decode(data)
        children = asn1.sequence_value(node)
        if len(children) == 2 and children[0].tag == asn1.TAG_INTEGER:
            return cls(n=asn1.int_value(children[0]), e=asn1.int_value(children[1]))
        return cls._from_spki_node(children)

    @classmethod
    def _from_spki_node(cls, children: tuple[asn1.DerNode, ...]) -> "RSAPublicKey":
        if len(children) != 2:
            raise InvalidSerialization("malformed SubjectPublicKeyInfo")
        oid, _params = _parse_algorithm(children[0])
        if oid != _OID_RSA_ENCRYPTION:
            raise InvalidSerialization(f"SPKI algorithm {oid} is not RSA")
        pkcs1 = asn1.decode(asn1.bit_string_value(children[1]))
        kids = asn1.sequence_value(pkcs1)
        if len(kids) != 2:
            raise InvalidSerialization("malformed PKCS#1 public key")
        return cls(n=asn1.int_value(kids[0]), e=asn1.int_value(kids[1]))

    @classmethod
    def from_pem(cls, text: str | bytes) -> "RSAPublicKey":
        label, der = decode_pem(text)
        if label == _PEM_RSA_PUBLIC:
            node = asn1.decode(der)
            kids = asn1.sequence_value(node)
            if len(kids) != 2:
                raise InvalidSerialization("malformed PKCS#1 public key")
            return cls(n=asn1.int_value(kids[0]), e=asn1.int_value(kids[1]))
        if label == _PEM_PUBLIC:
            return cls.from_der(der)
        raise InvalidSerialization(f"unexpected PEM label {label!r}")


def _nonzero_random(length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        chunk = secrets.token_bytes(length - len(out))
        out += chunk.replace(b"\x00", b"")
    return bytes(out[:length])


def _check_private_numbers(
    n: int,
    e: int,
    d: int,
    p: int,
    q: int,
    dmp1: int,
    dmq1: int,
    iqmp: int,
) -> None:
    _check_public_numbers(n, e)
    if p * q != n:
        raise InvalidKey("p * q does not equal modulus")
    if dmp1 != d % (p - 1) or dmq1 != d % (q - 1):
        raise InvalidKey("CRT exponents inconsistent with d")
    if (iqmp * q) % p != 1:
        raise InvalidKey("iqmp is not the inverse of q mod p")
    if (e * d) % math.lcm(p - 1, q - 1) != 1:
        raise InvalidKey("e * d is not 1 mod lcm(p-1, q-1)")


@dataclass(frozen=True)
class RSAPrivateKey:
    """RSA private key with CRT components."""

    n: int
    e: int
    d: int
    p: int
    q: int
    dmp1: int
    dmq1: int
    iqmp: int

    def __post_init__(self) -> None:
        _check_private_numbers(
            self.n,
            self.e,
            self.d,
            self.p,
            self.q,
            self.dmp1,
            self.dmq1,
            self.iqmp,
        )

    @property
    def key_size_bits(self) -> int:
        return self.n.bit_length()

    @property
    def key_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(n=self.n, e=self.e)

    # -- primitives ----------------------------------------------------------

    def _rsadp(self, c: int) -> int:
        """Private-key operation via the Chinese Remainder Theorem."""
        m1 = pow(c % self.p, self.dmp1, self.p)
        m2 = pow(c % self.q, self.dmq1, self.q)
        h = (self.iqmp * (m1 - m2)) % self.p
        return m2 + h * self.q

    # -- signatures -----------------------------------------------------------

    def sign_v15(self, message: bytes, hash_name: str = "sha256") -> bytes:
        """RSASSA-PKCS1-v1_5 signature over message."""
        if hash_name not in _DIGEST_INFO_PREFIX:
            raise UnsupportedAlgorithm(f"v1.5 unsupported hash {hash_name!r}")
        k = self.key_bytes
        em = _emsa_v15_encode(hash_name, _hash(hash_name, message), k)
        return i2osp(self._rsadp(os2ip(em)), k)

    def sign_pss(
        self,
        message: bytes,
        hash_name: str = "sha256",
        salt_len: int | None = None,
    ) -> bytes:
        """RSASSA-PSS signature. salt_len defaults to the digest size."""
        k = self.key_bytes
        hlen = _hash_size(hash_name)
        em_bits = self.n.bit_length() - 1
        slen = hlen if salt_len is None else salt_len
        em = _emsa_pss_encode(_hash(hash_name, message), em_bits, hash_name, slen)
        m = self._rsadp(os2ip(em))
        return i2osp(m, k)

    # -- decryption ------------------------------------------------------------

    def decrypt_v15(self, ciphertext: bytes) -> bytes:
        """RSAES-PKCS1-v1_5 decryption.

        Every failure mode (length, type byte, missing or short padding
        string) raises the identical InvalidKey("decryption failed").
        See the module docstring for the Bleichenbacher side-channel
        caveat: the scan itself is not constant-time in pure Python.
        """
        k = self.key_bytes
        ok = len(ciphertext) == k
        em = b""
        if ok:
            c = os2ip(ciphertext)
            ok = c < self.n
            if ok:
                em = i2osp(self._rsadp(c), k)
        pad_ok, msg = _split_v15_padding(em) if ok else (False, b"")
        if not pad_ok:
            raise InvalidKey("decryption failed")
        return msg

    def decrypt_oaep(
        self,
        ciphertext: bytes,
        hash_name: str = "sha256",
        label: bytes = b"",
    ) -> bytes:
        """RSAES-OAEP decryption. Single uniform error on any failure."""
        k = self.key_bytes
        hlen = _hash_size(hash_name)
        msg: bytes | None = None
        if len(ciphertext) == k and k >= 2 * hlen + 2:
            c = os2ip(ciphertext)
            if c < self.n:
                em = i2osp(self._rsadp(c), k)
                msg = _eme_oaep_decode(em, hash_name, label)
        if msg is None:
            raise InvalidKey("decryption failed")
        return msg

    # -- serialization ---------------------------------------------------------

    def to_pkcs1_der(self) -> bytes:
        """PKCS#1 RSAPrivateKey (version 0, n, e, d, p, q, dp, dq, qinv)."""
        return asn1.encode_sequence(
            asn1.encode_integer(0),
            asn1.encode_integer(self.n),
            asn1.encode_integer(self.e),
            asn1.encode_integer(self.d),
            asn1.encode_integer(self.p),
            asn1.encode_integer(self.q),
            asn1.encode_integer(self.dmp1),
            asn1.encode_integer(self.dmq1),
            asn1.encode_integer(self.iqmp),
        )

    def to_pkcs1_pem(self) -> str:
        return encode_pem(_PEM_RSA_PRIVATE, self.to_pkcs1_der())

    def to_pkcs8_der(self) -> bytes:
        """PKCS#8 PrivateKeyInfo wrapping the PKCS#1 private key."""
        alg = asn1.encode_sequence(
            asn1.encode_oid(_OID_RSA_ENCRYPTION), asn1.encode_null()
        )
        return asn1.encode_sequence(
            asn1.encode_integer(0),
            alg,
            asn1.encode_octet_string(self.to_pkcs1_der()),
        )

    def to_pkcs8_pem(self) -> str:
        return encode_pem(_PEM_PRIVATE, self.to_pkcs8_der())

    @classmethod
    def from_der(cls, data: bytes) -> "RSAPrivateKey":
        """Parse PKCS#1 RSAPrivateKey or PKCS#8 PrivateKeyInfo DER."""
        node = asn1.decode(data)
        children = asn1.sequence_value(node)
        if len(children) == 9:
            return cls._from_pkcs1_children(children)
        return cls._from_pkcs8_children(children)

    @classmethod
    def _from_pkcs1_children(cls, kids: tuple[asn1.DerNode, ...]) -> "RSAPrivateKey":
        vals = [asn1.int_value(k) for k in kids]
        if vals[0] != 0:
            raise InvalidSerialization("unsupported RSAPrivateKey version")
        return cls(
            n=vals[1],
            e=vals[2],
            d=vals[3],
            p=vals[4],
            q=vals[5],
            dmp1=vals[6],
            dmq1=vals[7],
            iqmp=vals[8],
        )

    @classmethod
    def _from_pkcs8_children(cls, kids: tuple[asn1.DerNode, ...]) -> "RSAPrivateKey":
        if len(kids) != 3:
            raise InvalidSerialization("malformed PrivateKeyInfo")
        if asn1.int_value(kids[0]) != 0:
            raise InvalidSerialization("unsupported PrivateKeyInfo version")
        oid, params = _parse_algorithm(kids[1])
        if oid != _OID_RSA_ENCRYPTION:
            raise InvalidSerialization(f"PKCS#8 algorithm {oid} is not RSA")
        if params is not None:
            asn1.null_value(params)
        inner = asn1.decode(asn1.octet_string_value(kids[2]))
        inner_kids = asn1.sequence_value(inner)
        if len(inner_kids) != 9:
            raise InvalidSerialization("malformed PKCS#1 private key")
        return cls._from_pkcs1_children(inner_kids)

    @classmethod
    def from_pem(cls, text: str | bytes) -> "RSAPrivateKey":
        label, der = decode_pem(text)
        if label not in (_PEM_RSA_PRIVATE, _PEM_PRIVATE):
            raise InvalidSerialization(f"unexpected PEM label {label!r}")
        return cls.from_der(der)


# --- encoding primitives -----------------------------------------------------


def _parse_algorithm(node: asn1.DerNode) -> tuple[str, asn1.DerNode | None]:
    """Parse AlgorithmIdentifier. Returns (oid, params_node_or_None)."""
    kids = asn1.sequence_value(node)
    if not 1 <= len(kids) <= 2:
        raise InvalidSerialization("malformed AlgorithmIdentifier")
    oid = asn1.oid_value(kids[0])
    return oid, kids[1] if len(kids) == 2 else None


def _emsa_v15_encode(hash_name: str, digest: bytes, em_len: int) -> bytes:
    t = _DIGEST_INFO_PREFIX[hash_name] + digest
    if em_len < len(t) + 11:
        raise InvalidKey("key too small for DigestInfo encoding")
    return b"\x00\x01" + b"\xff" * (em_len - len(t) - 3) + b"\x00" + t


def _emsa_pss_encode(
    m_hash: bytes, em_bits: int, hash_name: str, salt_len: int
) -> bytes:
    """EMSA-PSS-ENCODE (RFC 8017 9.1.1)."""
    hlen = _hash_size(hash_name)
    em_len = (em_bits + 7) // 8
    if salt_len < 0:
        raise InvalidKey("negative salt length")
    if em_len < hlen + salt_len + 2:
        raise InvalidKey("key too small for PSS with this salt length")
    salt = secrets.token_bytes(salt_len)
    h = _hash(hash_name, b"\x00" * 8 + m_hash + salt)
    ps = b"\x00" * (em_len - salt_len - hlen - 2)
    db = ps + b"\x01" + salt
    masked = bytearray(xor_bytes(db, mgf1(h, em_len - hlen - 1, hash_name)))
    masked[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked) + h + b"\xbc"


def _emsa_pss_verify(
    em: bytes,
    m_hash: bytes,
    hash_name: str,
    salt_len: int | None,
    em_bits: int,
) -> bool:
    """EMSA-PSS-VERIFY. Returns bool so callers collapse error paths."""
    hlen = _hash_size(hash_name)
    em_len = len(em)
    if em_len < hlen + 2 or em[-1] != 0xBC:
        return False
    unused = 8 * em_len - em_bits  # in 0..7 given em_len from the caller
    masked_db = em[: em_len - hlen - 1]
    h = em[em_len - hlen - 1 : -1]
    # The leftmost (8*emLen - emBits) bits of maskedDB must be zero.
    if masked_db[0] & ((0xFF << (8 - unused)) & 0xFF):
        return False
    db = bytearray(xor_bytes(masked_db, mgf1(h, em_len - hlen - 1, hash_name)))
    db[0] &= 0xFF >> unused
    # Locate the 0x01 separator scanning the whole buffer. Salt follows.
    sep = -1
    for i, byte in enumerate(db):
        if byte != 0 and sep < 0:
            sep = i
    if sep < 0 or db[sep] != 0x01:
        return False
    salt = bytes(db[sep + 1 :])
    if salt_len is not None and len(salt) != salt_len:
        return False
    expected = _hash(hash_name, b"\x00" * 8 + m_hash + salt)
    return ct_equal(h, expected)


def _split_v15_padding(em: bytes) -> tuple[bool, bytes]:
    """Split EM = 0x00 0x02 PS(>=8) 0x00 M without early return."""
    ok = len(em) >= 11 and em[0] == 0 and em[1] == 2
    sep = -1
    for i in range(2, len(em)):
        if em[i] == 0 and sep < 0:
            sep = i
    if sep < 0 or sep - 2 < 8:
        return False, b""
    return ok, em[sep + 1 :]


def _eme_oaep_encode(message: bytes, k: int, hash_name: str, label: bytes) -> bytes:
    hlen = _hash_size(hash_name)
    l_hash = _hash(hash_name, label)
    ps = b"\x00" * (k - len(message) - 2 * hlen - 2)
    db = l_hash + ps + b"\x01" + message
    seed = secrets.token_bytes(hlen)
    masked_db = xor_bytes(db, mgf1(seed, k - hlen - 1, hash_name))
    masked_seed = xor_bytes(seed, mgf1(masked_db, hlen, hash_name))
    return b"\x00" + masked_seed + masked_db


def _eme_oaep_decode(em: bytes, hash_name: str, label: bytes) -> bytes | None:
    """EME-OAEP-DECODE. Returns None on any failure (uniform upstream)."""
    hlen = _hash_size(hash_name)
    masked_seed = em[1 : 1 + hlen]
    masked_db = em[1 + hlen :]
    seed = xor_bytes(masked_seed, mgf1(masked_db, hlen, hash_name))
    db = xor_bytes(masked_db, mgf1(seed, len(em) - hlen - 1, hash_name))
    ok = em[0] == 0 and ct_equal(db[:hlen], _hash(hash_name, label))
    sep = -1
    for i in range(hlen, len(db)):
        if db[i] != 0 and sep < 0:
            sep = i
    if sep < 0 or db[sep] != 0x01 or not ok:
        return None
    return bytes(db[sep + 1 :])
