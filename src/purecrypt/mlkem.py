# SPDX-License-Identifier: 0BSD
"""ML-KEM key encapsulation mechanism (FIPS 203), pure Python.

Implements all three parameter sets: ML-KEM-512, ML-KEM-768 and
ML-KEM-1024. The underlying K-PKE uses the number theoretic transform
over the ring R_q = Z_3329[X]/(X^256 + 1) with zeta = 17 as the
primitive 256-th root of unity. Decapsulation uses the FIPS 203
implicit rejection path: on any ciphertext mismatch the shared key is
replaced by J(z || c).
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Final, NamedTuple, Protocol

from .exceptions import InvalidCiphertext, InvalidKey

_Q: Final = 3329
_N: Final = 256
_ZETA: Final = 17
_INV128: Final = 3303  # 128^-1 mod 3329
_SEED_LEN: Final = 32
_SHARED_KEY_LEN: Final = 32


def _bitrev7(i: int) -> int:
    r = 0
    for _ in range(7):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


_ZETAS: Final = [pow(_ZETA, _bitrev7(i), _Q) for i in range(128)]
_GAMMAS: Final = [pow(_ZETA, 2 * _bitrev7(i) + 1, _Q) for i in range(128)]


class _Params(NamedTuple):
    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int

    @property
    def ek_size(self) -> int:
        return 384 * self.k + 32

    @property
    def dk_size(self) -> int:
        return 768 * self.k + 96

    @property
    def ct_size(self) -> int:
        return 32 * (self.du * self.k + self.dv)


_MLKEM_512 = _Params("ML-KEM-512", 2, 3, 2, 10, 4)
_MLKEM_768 = _Params("ML-KEM-768", 3, 2, 2, 10, 4)
_MLKEM_1024 = _Params("ML-KEM-1024", 4, 2, 2, 11, 5)

_PARAM_SETS: Final = {p.name: p for p in (_MLKEM_512, _MLKEM_768, _MLKEM_1024)}
_BY_EK_SIZE: Final = {p.ek_size: p for p in _PARAM_SETS.values()}
_BY_DK_SIZE: Final = {p.dk_size: p for p in _PARAM_SETS.values()}


# ------------------------------------------------------------ hash usage


def _h(data: bytes) -> bytes:
    """H(x) = SHA3-256(x)."""
    return hashlib.sha3_256(data).digest()


def _j(data: bytes) -> bytes:
    """J(x) = SHAKE256(x, 32)."""
    return hashlib.shake_256(data).digest(32)


def _g(data: bytes) -> bytes:
    """G(x) = SHA3-512(x), split as two 32-byte halves."""
    return hashlib.sha3_512(data).digest()


def _prf(eta: int, s: bytes, b: int) -> bytes:
    """PRF_eta(s, b) = SHAKE256(s || b, 64*eta)."""
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


class _ShakeLike(Protocol):
    def digest(self, length: int, /) -> bytes:
        pass


class _XofReader:
    """Incremental reader over a SHAKE object.

    hashlib SHAKE digests always return the stream prefix, so the
    reader grows the requested prefix as needed.
    """

    __slots__ = ("_buf", "_off", "_xof")

    def __init__(self, xof: _ShakeLike) -> None:
        self._xof = xof
        self._buf = b""
        self._off = 0

    def read(self, n: int) -> bytes:
        while len(self._buf) - self._off < n:
            self._buf = self._xof.digest(len(self._buf) + 512)
        out = self._buf[self._off : self._off + n]
        self._off += n
        return out


# ------------------------------------------------- encode and compress


def _byte_encode(d: int, coeffs: list[int]) -> bytes:
    """FIPS 203 Algorithm 6: little-endian packing of d-bit values."""
    out = bytearray(len(coeffs) * d // 8)
    acc = 0
    nacc = 0
    pos = 0
    for x in coeffs:
        acc |= x << nacc
        nacc += d
        while nacc >= 8:
            out[pos] = acc & 0xFF
            acc >>= 8
            nacc -= 8
            pos += 1
    return bytes(out)


def _byte_decode(d: int, data: bytes) -> list[int]:
    """FIPS 203 Algorithm 7: unpack d-bit values from bytes."""
    mask = (1 << d) - 1
    coeffs = []
    acc = 0
    nacc = 0
    pos = 0
    for _ in range(_N):
        while nacc < d:
            acc |= data[pos] << nacc
            nacc += 8
            pos += 1
        coeffs.append(acc & mask)
        acc >>= d
        nacc -= d
    return coeffs


def _compress(d: int, x: int) -> int:
    """FIPS 203 Algorithm 5: round(2^d / q * x) mod 2^d."""
    return ((x << (d + 1)) + _Q) // (2 * _Q) & ((1 << d) - 1)


def _decompress(d: int, y: int) -> int:
    """FIPS 203 Algorithm 5: round(q / 2^d * y)."""
    return (y * _Q + (1 << (d - 1))) >> d


# ------------------------------------------------------------- sampling


def _sample_ntt(rho: bytes, j: int, i: int) -> list[int]:
    """FIPS 203 Algorithm 8: rejection-sample a uniform poly in NTT form."""
    reader = _XofReader(hashlib.shake_128(rho + bytes([j, i])))
    coeffs: list[int] = []
    while len(coeffs) < _N:
        b0, b1, b2 = reader.read(3)
        d1 = b0 + 256 * (b1 & 0x0F)
        d2 = (b1 >> 4) + 16 * b2
        if d1 < _Q:
            coeffs.append(d1)
        if d2 < _Q and len(coeffs) < _N:
            coeffs.append(d2)
    return coeffs


def _sample_cbd(eta: int, data: bytes) -> list[int]:
    """FIPS 203 Algorithm 9: centered binomial sample from 64*eta bytes."""
    bits = int.from_bytes(data, "little")
    coeffs = []
    for i in range(_N):
        x = sum((bits >> (2 * i * eta + j)) & 1 for j in range(eta))
        y = sum((bits >> (2 * i * eta + eta + j)) & 1 for j in range(eta))
        coeffs.append((x - y) % _Q)
    return coeffs


# ----------------------------------------------------------------- NTT


def _ntt(f: list[int]) -> list[int]:
    """FIPS 203 Algorithm 10."""
    f = list(f)
    idx = 1
    length = 128
    while length >= 2:
        for start in range(0, _N, 2 * length):
            z = _ZETAS[idx]
            idx += 1
            for j in range(start, start + length):
                t = (z * f[j + length]) % _Q
                f[j + length] = (f[j] - t) % _Q
                f[j] = (f[j] + t) % _Q
        length >>= 1
    return f


def _ntt_inv(f: list[int]) -> list[int]:
    """FIPS 203 Algorithm 11."""
    f = list(f)
    idx = 127
    length = 2
    while length <= 128:
        for start in range(0, _N, 2 * length):
            z = _ZETAS[idx]
            idx -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % _Q
                f[j + length] = (z * (f[j + length] - t)) % _Q
        length <<= 1
    return [(x * _INV128) % _Q for x in f]


def _multiply_ntts(f: list[int], g: list[int]) -> list[int]:
    """FIPS 203 Algorithm 12: degree-1 basemul per coefficient pair."""
    h = [0] * _N
    for i in range(128):
        gamma = _GAMMAS[i]
        a0, a1 = f[2 * i], f[2 * i + 1]
        b0, b1 = g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * gamma) % _Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % _Q
    return h


def _poly_add(f: list[int], g: list[int]) -> list[int]:
    return [(a + b) % _Q for a, b in zip(f, g, strict=True)]


def _poly_sub(f: list[int], g: list[int]) -> list[int]:
    return [(a - b) % _Q for a, b in zip(f, g, strict=True)]


def _poly_dot_ntt(a_vec: list[list[int]], b_vec: list[list[int]]) -> list[int]:
    acc = [0] * _N
    for a, b in zip(a_vec, b_vec, strict=True):
        acc = _poly_add(acc, _multiply_ntts(a, b))
    return acc


# ---------------------------------------------------------------- K-PKE


def _kpke_keygen(params: _Params, d: bytes) -> tuple[bytes, bytes]:
    """FIPS 203 Algorithm 13."""
    k = params.k
    g_out = _g(d + bytes([k]))
    rho, sigma = g_out[:32], g_out[32:]
    a_hat = [[_sample_ntt(rho, j, i) for j in range(k)] for i in range(k)]
    ctr = 0
    s = []
    for _ in range(k):
        s.append(_sample_cbd(params.eta1, _prf(params.eta1, sigma, ctr)))
        ctr += 1
    e = []
    for _ in range(k):
        e.append(_sample_cbd(params.eta1, _prf(params.eta1, sigma, ctr)))
        ctr += 1
    s_hat = [_ntt(p) for p in s]
    e_hat = [_ntt(p) for p in e]
    t_hat = [_poly_add(_poly_dot_ntt(a_hat[i], s_hat), e_hat[i]) for i in range(k)]
    ek = b"".join(_byte_encode(12, p) for p in t_hat) + rho
    dk_pke = b"".join(_byte_encode(12, p) for p in s_hat)
    return ek, dk_pke


def _kpke_encrypt(params: _Params, ek: bytes, m: bytes, r: bytes) -> bytes:
    """FIPS 203 Algorithm 14."""
    k = params.k
    t_hat = [_byte_decode(12, ek[384 * i : 384 * (i + 1)]) for i in range(k)]
    rho = ek[384 * k : 384 * k + 32]
    a_hat = [[_sample_ntt(rho, j, i) for j in range(k)] for i in range(k)]
    ctr = 0
    y = []
    for _ in range(k):
        y.append(_sample_cbd(params.eta1, _prf(params.eta1, r, ctr)))
        ctr += 1
    e1 = []
    for _ in range(k):
        e1.append(_sample_cbd(params.eta2, _prf(params.eta2, r, ctr)))
        ctr += 1
    e2 = _sample_cbd(params.eta2, _prf(params.eta2, r, ctr))
    y_hat = [_ntt(p) for p in y]
    u = [
        _poly_add(
            _ntt_inv(_poly_dot_ntt([a_hat[j][i] for j in range(k)], y_hat)), e1[i]
        )
        for i in range(k)
    ]
    mu = [_decompress(1, x) for x in _byte_decode(1, m)]
    v = _poly_add(
        _poly_add(_ntt_inv(_poly_dot_ntt(t_hat, y_hat)), e2),
        mu,
    )
    c1 = b"".join(
        _byte_encode(params.du, [_compress(params.du, x) for x in p]) for p in u
    )
    c2 = _byte_encode(params.dv, [_compress(params.dv, x) for x in v])
    return c1 + c2


def _kpke_decrypt(params: _Params, dk_pke: bytes, c: bytes) -> bytes:
    """FIPS 203 Algorithm 15."""
    k = params.k
    c1_len = 32 * params.du * k
    block = 32 * params.du
    u = [
        [_decompress(params.du, x) for x in _byte_decode(params.du, c1)]
        for c1 in (c[block * i : block * (i + 1)] for i in range(k))
    ]
    v = [_decompress(params.dv, x) for x in _byte_decode(params.dv, c[c1_len:])]
    s_hat = [_byte_decode(12, dk_pke[384 * i : 384 * (i + 1)]) for i in range(k)]
    u_hat = [_ntt(p) for p in u]
    w = _poly_sub(v, _ntt_inv(_poly_dot_ntt(s_hat, u_hat)))
    return _byte_encode(1, [_compress(1, x) for x in w])


# --------------------------------------------------------------- ML-KEM


def _keygen_internal(params: _Params, d: bytes, z: bytes) -> tuple[bytes, bytes]:
    """FIPS 203 Algorithm 16."""
    ek, dk_pke = _kpke_keygen(params, d)
    dk = dk_pke + ek + _h(ek) + z
    return ek, dk


def _encaps_internal(params: _Params, ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """FIPS 203 Algorithm 17."""
    g_out = _g(m + _h(ek))
    k_shared, r = g_out[:32], g_out[32:]
    c = _kpke_encrypt(params, ek, m, r)
    return k_shared, c


def _decaps_internal(params: _Params, dk: bytes, c: bytes) -> bytes:
    """FIPS 203 Algorithm 18 with implicit rejection."""
    k = params.k
    dk_pke = dk[: 384 * k]
    ek = dk[384 * k : 768 * k + 32]
    h = dk[768 * k + 32 : 768 * k + 64]
    z = dk[768 * k + 64 : 768 * k + 96]
    m2 = _kpke_decrypt(params, dk_pke, c)
    g_out = _g(m2 + h)
    k2, r2 = g_out[:32], g_out[32:]
    k_bar = _j(z + c)
    c2 = _kpke_encrypt(params, ek, m2, r2)
    if _ct_equal(c, c2):
        return k2
    return k_bar


def _ct_equal(a: bytes, b: bytes) -> bool:
    """Length-insensitive equality check in the spirit of hmac.compare_digest."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b, strict=True):
        diff |= x ^ y
    return diff == 0


def _resolve_name(parameter_set: str) -> _Params:
    try:
        return _PARAM_SETS[parameter_set]
    except KeyError:
        raise ValueError(f"unknown ML-KEM parameter set: {parameter_set!r}") from None


def _resolve_ek(ek: bytes) -> _Params:
    params = _BY_EK_SIZE.get(len(ek))
    if params is None:
        raise InvalidKey(f"invalid ML-KEM encapsulation key length: {len(ek)} bytes")
    return params


def _resolve_dk(dk: bytes) -> _Params:
    params = _BY_DK_SIZE.get(len(dk))
    if params is None:
        raise InvalidKey(f"invalid ML-KEM decapsulation key length: {len(dk)} bytes")
    return params


def check_encaps_key(ek: bytes) -> None:
    """FIPS 203 section 7.2 encapsulation key check.

    Verifies length and that every ByteDecode12 coefficient is a
    canonical residue modulo q (the type check plus modulus check).
    """
    params = _resolve_ek(ek)
    for i in range(params.k):
        coeffs = _byte_decode(12, ek[384 * i : 384 * (i + 1)])
        if any(x >= _Q for x in coeffs):
            raise InvalidKey("ML-KEM encapsulation key has non-canonical coefficients")


def check_decaps_key(dk: bytes) -> None:
    """FIPS 203 section 7.3 decapsulation key check.

    Verifies length and that the embedded hash of the encapsulation
    key is consistent with the embedded copy of the key.
    """
    params = _resolve_dk(dk)
    k = params.k
    ek = dk[384 * k : 768 * k + 32]
    h = dk[768 * k + 32 : 768 * k + 64]
    if not _ct_equal(_h(ek), h):
        raise InvalidKey("ML-KEM decapsulation key hash check failed")


def keygen(parameter_set: str = "ML-KEM-768") -> tuple[bytes, bytes]:
    """Generate an ML-KEM key pair. Returns (encaps_key, decaps_key)."""
    params = _resolve_name(parameter_set)
    d = secrets.token_bytes(_SEED_LEN)
    z = secrets.token_bytes(_SEED_LEN)
    return _keygen_internal(params, d, z)


def encaps(ek: bytes) -> tuple[bytes, bytes]:
    """Encapsulate. Returns (shared_key, ciphertext)."""
    params = _resolve_ek(ek)
    m = secrets.token_bytes(32)
    return _encaps_internal(params, ek, m)


def decaps(dk: bytes, c: bytes) -> bytes:
    """Decapsulate a ciphertext. Implicit rejection on bad input."""
    params = _resolve_dk(dk)
    if len(c) != params.ct_size:
        raise InvalidCiphertext(f"invalid ML-KEM ciphertext length: {len(c)} bytes")
    return _decaps_internal(params, dk, c)


__all__ = [
    "check_decaps_key",
    "check_encaps_key",
    "decaps",
    "encaps",
    "keygen",
]
