# SPDX-License-Identifier: 0BSD
"""ML-DSA digital signatures (FIPS 204), pure Python.

Implements all three parameter sets: ML-DSA-44, ML-DSA-65 and
ML-DSA-87, both the pure variant and HashML-DSA. Ring arithmetic
uses the number theoretic transform over R_q = Z_8380417[X]/(X^256+1)
with zeta = 1753 as the primitive 512-th root of unity.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Final, NamedTuple, Protocol

from .exceptions import InvalidKey

_Q: Final = 8380417
_N: Final = 256
_D: Final = 13
_ZETA: Final = 1753
_SEED_LEN: Final = 32


def _bitrev8(i: int) -> int:
    r = 0
    for _ in range(8):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


_ZETAS: Final = [pow(_ZETA, _bitrev8(i), _Q) for i in range(256)]
_INV256: Final = pow(256, -1, _Q)


class _Params(NamedTuple):
    name: str
    k: int
    ell: int
    eta: int
    tau: int
    beta: int
    gamma1: int
    gamma2: int
    omega: int
    ctilde: int

    @property
    def w1_bits(self) -> int:
        m = (_Q - 1) // (2 * self.gamma2)
        return (m - 1).bit_length()

    @property
    def z_bits(self) -> int:
        return (2 * self.gamma1 - 1).bit_length()

    @property
    def s_bits(self) -> int:
        return (2 * self.eta).bit_length()

    @property
    def pk_size(self) -> int:
        return 32 + 320 * self.k

    @property
    def sk_size(self) -> int:
        s_bytes = 32 * self.s_bits
        return 128 + (self.ell + self.k) * s_bytes + 416 * self.k

    @property
    def sig_size(self) -> int:
        return self.ctilde + 32 * self.z_bits * self.ell + self.omega + self.k


_MLDSA_44 = _Params("ML-DSA-44", 4, 4, 2, 39, 78, 1 << 17, (_Q - 1) // 88, 80, 32)
_MLDSA_65 = _Params("ML-DSA-65", 6, 5, 4, 49, 196, 1 << 19, (_Q - 1) // 32, 55, 48)
_MLDSA_87 = _Params("ML-DSA-87", 8, 7, 2, 60, 120, 1 << 19, (_Q - 1) // 32, 75, 64)

_PARAM_SETS: Final = {p.name: p for p in (_MLDSA_44, _MLDSA_65, _MLDSA_87)}
_BY_PK_SIZE: Final = {p.pk_size: p for p in _PARAM_SETS.values()}
_BY_SK_SIZE: Final = {p.sk_size: p for p in _PARAM_SETS.values()}

# DER-encoded OIDs for HashML-DSA prehash algorithms (FIPS 204).
_HASH_INFO: Final = {
    "SHA2-224": (bytes.fromhex("0609608648016503040204"), "sha224", None),
    "SHA2-256": (bytes.fromhex("0609608648016503040201"), "sha256", None),
    "SHA2-384": (bytes.fromhex("0609608648016503040202"), "sha384", None),
    "SHA2-512": (bytes.fromhex("0609608648016503040203"), "sha512", None),
    "SHA2-512/224": (bytes.fromhex("0609608648016503040205"), "sha512_224", None),
    "SHA2-512/256": (bytes.fromhex("0609608648016503040206"), "sha512_256", None),
    "SHA3-224": (bytes.fromhex("0609608648016503040207"), "sha3_224", None),
    "SHA3-256": (bytes.fromhex("0609608648016503040208"), "sha3_256", None),
    "SHA3-384": (bytes.fromhex("0609608648016503040209"), "sha3_384", None),
    "SHA3-512": (bytes.fromhex("060960864801650304020a"), "sha3_512", None),
    "SHAKE-128": (bytes.fromhex("060960864801650304020b"), "shake_128", 32),
    "SHAKE-256": (bytes.fromhex("060960864801650304020c"), "shake_256", 64),
}


class _ShakeLike(Protocol):
    def digest(self, length: int, /) -> bytes:
        pass


class _XofReader:
    """Incremental reader over a SHAKE object."""

    __slots__ = ("_buf", "_off", "_xof")

    def __init__(self, xof: _ShakeLike) -> None:
        self._xof = xof
        self._buf = b""
        self._off = 0

    def read(self, n: int) -> bytes:
        while len(self._buf) - self._off < n:
            self._buf = self._xof.digest(len(self._buf) + 840)
        out = self._buf[self._off : self._off + n]
        self._off += n
        return out


def _h(data: bytes, length: int) -> bytes:
    """FIPS 204 H function: SHAKE256 with variable output length."""
    return hashlib.shake_256(data).digest(length)


# ------------------------------------------------------------- NTT


def _ntt(f: list[int]) -> list[int]:
    """FIPS 204 Algorithm 41."""
    f = list(f)
    k = 0
    length = 128
    while length >= 1:
        for start in range(0, _N, 2 * length):
            k += 1
            z = _ZETAS[k]
            for j in range(start, start + length):
                t = (z * f[j + length]) % _Q
                f[j + length] = (f[j] - t) % _Q
                f[j] = (f[j] + t) % _Q
        length >>= 1
    return f


def _ntt_inv(f: list[int]) -> list[int]:
    """FIPS 204 Algorithm 42."""
    f = list(f)
    k = 256
    length = 1
    while length <= 128:
        for start in range(0, _N, 2 * length):
            k -= 1
            z = _ZETAS[k]
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % _Q
                f[j + length] = (z * (f[j + length] - t)) % _Q
        length <<= 1
    return [(x * _INV256) % _Q for x in f]


def _poly_mul_ntt(f: list[int], g: list[int]) -> list[int]:
    return [(a * b) % _Q for a, b in zip(f, g, strict=True)]


def _poly_add(f: list[int], g: list[int]) -> list[int]:
    return [(a + b) % _Q for a, b in zip(f, g, strict=True)]


def _poly_sub(f: list[int], g: list[int]) -> list[int]:
    return [(a - b) % _Q for a, b in zip(f, g, strict=True)]


def _mat_vec_ntt(
    a_hat: list[list[list[int]]], v_hat: list[list[int]]
) -> list[list[int]]:
    out = []
    for row in a_hat:
        acc = [0] * _N
        for a, v in zip(row, v_hat, strict=True):
            acc = _poly_add(acc, _poly_mul_ntt(a, v))
        out.append(acc)
    return out


# -------------------------------------------------- rounding helpers


def _mod_pm(x: int) -> int:
    """Centered residue in (-q/2, q/2]."""
    x %= _Q
    if x > (_Q - 1) // 2:
        x -= _Q
    return x


def _mod_pm_range(x: int, m: int) -> int:
    """Centered residue in (-m/2, m/2]."""
    x %= m
    if x > m // 2:
        x -= m
    return x


def _power2round(r: int) -> tuple[int, int]:
    """FIPS 204 Algorithm 35."""
    r_plus = r % _Q
    r0 = _mod_pm_range(r_plus, 1 << _D)
    return (r_plus - r0) >> _D, r0


def _decompose(r: int, gamma2: int) -> tuple[int, int]:
    """FIPS 204 Algorithm 36."""
    r_plus = r % _Q
    r0 = _mod_pm_range(r_plus, 2 * gamma2)
    if r_plus - r0 == _Q - 1:
        return 0, r0 - 1
    return (r_plus - r0) // (2 * gamma2), r0


def _high_bits(r: int, gamma2: int) -> int:
    return _decompose(r, gamma2)[0]


def _make_hint(z: int, r: int, gamma2: int) -> int:
    """FIPS 204 Algorithm 39."""
    return int(_high_bits(r, gamma2) != _high_bits(r + z, gamma2))


def _use_hint(h: int, r: int, gamma2: int) -> int:
    """FIPS 204 Algorithm 40."""
    m = (_Q - 1) // (2 * gamma2)
    r1, r0 = _decompose(r, gamma2)
    if h == 1:
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m
    return r1


def _norm_ok(vec: list[int], bound: int) -> bool:
    """True iff every coefficient has |x mod^{+-} q| < bound."""
    for x in vec:
        t = x % _Q
        if t > (_Q - 1) // 2:
            t -= _Q
        if t < 0:
            t = -t
        if t >= bound:
            return False
    return True


# ------------------------------------------------------------- sampling


def _rej_ntt_poly(seed: bytes) -> list[int]:
    """FIPS 204 Algorithm 30: uniform poly in NTT domain."""
    reader = _XofReader(hashlib.shake_128(seed))
    coeffs: list[int] = []
    while len(coeffs) < _N:
        b0, b1, b2 = reader.read(3)
        t = (b0 | (b1 << 8) | (b2 << 16)) & 0x7FFFFF
        if t < _Q:
            coeffs.append(t)
    return coeffs


def _expand_a(params: _Params, rho: bytes) -> list[list[list[int]]]:
    return [
        [_rej_ntt_poly(rho + bytes([j, i])) for j in range(params.ell)]
        for i in range(params.k)
    ]


def _rej_bounded_poly(seed: bytes, eta: int) -> list[int]:
    """FIPS 204 Algorithm 31: poly with coefficients in [-eta, eta]."""
    reader = _XofReader(hashlib.shake_256(seed))
    coeffs: list[int] = []
    while len(coeffs) < _N:
        for t in reader.read(1):
            for cand in (t & 0x0F, t >> 4):
                if eta == 2:
                    if cand < 15:
                        coeffs.append(2 - (cand - (205 * cand >> 10) * 5))
                elif cand < 9:
                    coeffs.append(4 - cand)
                if len(coeffs) == _N:
                    break
    return coeffs


def _expand_s(params: _Params, rho2: bytes) -> tuple[list[list[int]], list[list[int]]]:
    s1 = [
        _rej_bounded_poly(rho2 + i.to_bytes(2, "little"), params.eta)
        for i in range(params.ell)
    ]
    s2 = [
        _rej_bounded_poly(rho2 + (params.ell + i).to_bytes(2, "little"), params.eta)
        for i in range(params.k)
    ]
    return s1, s2


def _expand_mask(params: _Params, rho_pp: bytes, kappa: int) -> list[list[int]]:
    """FIPS 204 Algorithm 34: y coefficients in (-gamma1, gamma1]."""
    bits = params.z_bits
    count = _N * bits // 8
    out = []
    for i in range(params.ell):
        stream = hashlib.shake_256(rho_pp + (kappa + i).to_bytes(2, "little")).digest(
            count
        )
        t = _unpack_bits(stream, bits)
        out.append([(params.gamma1 - x) % _Q for x in t])
    return out


def _sample_in_ball(seed: bytes, tau: int) -> list[int]:
    """FIPS 204 Algorithm 29: challenge poly with tau coefficients +-1."""
    reader = _XofReader(hashlib.shake_256(seed))
    signs = int.from_bytes(reader.read(8), "little")
    c = [0] * _N
    for i in range(_N - tau, _N):
        j = reader.read(1)[0]
        while j > i:
            j = reader.read(1)[0]
        c[i] = c[j]
        c[j] = 1 if signs & 1 == 0 else _Q - 1
        signs >>= 1
    return c


# ------------------------------------------------------- bit packing


def _pack_bits(values: list[int], bits: int) -> bytes:
    out = bytearray(len(values) * bits // 8)
    acc = 0
    nacc = 0
    pos = 0
    for v in values:
        acc |= v << nacc
        nacc += bits
        while nacc >= 8:
            out[pos] = acc & 0xFF
            acc >>= 8
            nacc -= 8
            pos += 1
    return bytes(out)


def _unpack_bits(data: bytes, bits: int) -> list[int]:
    mask = (1 << bits) - 1
    values = []
    acc = 0
    nacc = 0
    pos = 0
    total = len(data) * 8 // bits
    for _ in range(total):
        while nacc < bits:
            acc |= data[pos] << nacc
            nacc += 8
            pos += 1
        values.append(acc & mask)
        acc >>= bits
        nacc -= bits
    return values


def _pack_poly_offset(values: list[int], offset: int, bits: int) -> bytes:
    return _pack_bits([offset - _mod_pm(x) for x in values], bits)


def _unpack_poly_offset(data: bytes, offset: int, bits: int) -> list[int]:
    return [(offset - x) % _Q for x in _unpack_bits(data, bits)]


# --------------------------------------------------- encodings


def _pk_encode(rho: bytes, t1: list[list[int]]) -> bytes:
    return rho + b"".join(_pack_bits(p, 10) for p in t1)


def _pk_decode(params: _Params, pk: bytes) -> tuple[bytes, list[list[int]]]:
    rho = pk[:32]
    t1 = [
        _unpack_bits(pk[32 + 320 * i : 32 + 320 * (i + 1)], 10) for i in range(params.k)
    ]
    return rho, t1


def _sk_encode(
    params: _Params,
    rho: bytes,
    key: bytes,
    tr: bytes,
    s1: list[list[int]],
    s2: list[list[int]],
    t0: list[list[int]],
) -> bytes:
    out = rho + key + tr
    out += b"".join(_pack_poly_offset(p, params.eta, params.s_bits) for p in s1)
    out += b"".join(_pack_poly_offset(p, params.eta, params.s_bits) for p in s2)
    out += b"".join(_pack_poly_offset(p, 1 << (_D - 1), _D) for p in t0)
    return out


def _sk_decode(
    params: _Params, sk: bytes
) -> tuple[bytes, bytes, bytes, list[list[int]], list[list[int]], list[list[int]]]:
    rho, key, tr = sk[:32], sk[32:64], sk[64:128]
    s_size = 32 * params.s_bits
    pos = 128
    s1 = [
        _unpack_poly_offset(
            sk[pos + s_size * i : pos + s_size * (i + 1)], params.eta, params.s_bits
        )
        for i in range(params.ell)
    ]
    pos += s_size * params.ell
    s2 = [
        _unpack_poly_offset(
            sk[pos + s_size * i : pos + s_size * (i + 1)], params.eta, params.s_bits
        )
        for i in range(params.k)
    ]
    pos += s_size * params.k
    t0 = [
        _unpack_poly_offset(sk[pos + 416 * i : pos + 416 * (i + 1)], 1 << (_D - 1), _D)
        for i in range(params.k)
    ]
    return rho, key, tr, s1, s2, t0


def _w1_encode(params: _Params, w1: list[list[int]]) -> bytes:
    return b"".join(_pack_bits(p, params.w1_bits) for p in w1)


def _sig_encode(
    params: _Params, ctilde: bytes, z: list[list[int]], h: list[list[int]]
) -> bytes:
    out = bytearray(ctilde)
    for p in z:
        out += _pack_bits([params.gamma1 - _mod_pm(x) for x in p], params.z_bits)
    positions = []
    counts = []
    for p in h:
        idx = [i for i, x in enumerate(p) if x % _Q != 0]
        positions.extend(idx)
        counts.append(len(idx))
    positions.extend([0] * (params.omega - len(positions)))
    out += bytes(positions)
    acc = 0
    tail = []
    for count in counts:
        acc += count
        tail.append(acc)
    out += bytes(tail)
    return bytes(out)


def _sig_decode(
    params: _Params, sig: bytes
) -> tuple[bytes, list[list[int]], list[list[int]]] | None:
    ctilde = sig[: params.ctilde]
    z_size = 32 * params.z_bits
    pos = params.ctilde
    z = []
    for i in range(params.ell):
        chunk = sig[pos + z_size * i : pos + z_size * (i + 1)]
        z.append([(params.gamma1 - x) % _Q for x in _unpack_bits(chunk, params.z_bits)])
    pos += z_size * params.ell
    h = [[0] * _N for _ in range(params.k)]
    tail = sig[pos : pos + params.omega + params.k]
    if len(tail) != params.omega + params.k:
        return None
    last = 0
    for i in range(params.k):
        end = tail[params.omega + i]
        if end < last or end > params.omega:
            return None
        seen = -1
        for j in range(last, end):
            idx = tail[j]
            if idx <= seen:
                return None
            seen = idx
            h[i][idx] = 1
        last = end
    for j in range(last, params.omega):
        if tail[j] != 0:
            return None
    return ctilde, z, h


# ----------------------------------------------------------- internals


def _keygen_internal(params: _Params, seed: bytes) -> tuple[bytes, bytes]:
    """FIPS 204 Algorithm 6."""
    g = _h(seed + bytes([params.k, params.ell]), 128)
    rho, rho2, key = g[:32], g[32:96], g[96:]
    a_hat = _expand_a(params, rho)
    s1, s2 = _expand_s(params, rho2)
    s1_hat = [_ntt(p) for p in s1]
    t = [
        _poly_add(_ntt_inv(row), s2[i])
        for i, row in enumerate(_mat_vec_ntt(a_hat, s1_hat))
    ]
    t1 = []
    t0 = []
    for p in t:
        hi, lo = zip(*(_power2round(x) for x in p), strict=True)
        t1.append(list(hi))
        t0.append(list(lo))
    pk = _pk_encode(rho, t1)
    tr = _h(pk, 64)
    sk = _sk_encode(params, rho, key, tr, s1, s2, t0)
    return pk, sk


def _sign_internal(params: _Params, sk: bytes, m_prime: bytes, rnd: bytes) -> bytes:
    """FIPS 204 Algorithm 7."""
    _rho, _key, tr, _s1, _s2, _t0 = _sk_decode(params, sk)
    return _sign_mu(params, sk, _h(tr + m_prime, 64), rnd)


def _sign_mu(params: _Params, sk: bytes, mu: bytes, rnd: bytes) -> bytes:
    """Algorithm 7 starting from a precomputed message representative mu."""
    rho, key, _tr, s1, s2, t0 = _sk_decode(params, sk)
    rho_pp = _h(key + rnd + mu, 64)
    a_hat = _expand_a(params, rho)
    s1_hat = [_ntt(p) for p in s1]
    s2_hat = [_ntt(p) for p in s2]
    t0_hat = [_ntt(p) for p in t0]
    kappa = 0
    while True:
        y = _expand_mask(params, rho_pp, kappa)
        kappa += params.ell
        y_hat = [_ntt(p) for p in y]
        w = [_ntt_inv(row) for row in _mat_vec_ntt(a_hat, y_hat)]
        w1 = [[_high_bits(x, params.gamma2) for x in p] for p in w]
        ctilde = _h(mu + _w1_encode(params, w1), params.ctilde)
        c_hat = _ntt(_sample_in_ball(ctilde, params.tau))
        z = [
            _poly_add(y[i], _ntt_inv(_poly_mul_ntt(c_hat, s1_hat[i])))
            for i in range(params.ell)
        ]
        if not all(_norm_ok(p, params.gamma1 - params.beta) for p in z):
            continue
        cs2 = [_ntt_inv(_poly_mul_ntt(c_hat, s2_hat[i])) for i in range(params.k)]
        r = [_poly_sub(w[i], cs2[i]) for i in range(params.k)]
        r0 = [[_decompose(x, params.gamma2)[1] for x in p] for p in r]
        if not all(_norm_ok(p, params.gamma2 - params.beta) for p in r0):
            continue
        ct0 = [_ntt_inv(_poly_mul_ntt(c_hat, t0_hat[i])) for i in range(params.k)]
        if not all(_norm_ok(p, params.gamma2) for p in ct0):
            continue
        h = [
            [
                _make_hint(-ct0[i][j], r[i][j] + ct0[i][j], params.gamma2)
                for j in range(_N)
            ]
            for i in range(params.k)
        ]
        if sum(sum(1 for x in p if x) for p in h) > params.omega:
            continue
        return _sig_encode(params, ctilde, [[_mod_pm(x) for x in p] for p in z], h)


def _verify_internal(params: _Params, pk: bytes, sig: bytes, m_prime: bytes) -> bool:
    """FIPS 204 Algorithm 8."""
    if len(sig) != params.sig_size:
        return False
    rho, t1 = _pk_decode(params, pk)
    mu = _h(_h(pk, 64) + m_prime, 64)
    return _verify_mu(params, rho, t1, mu, sig)


def _verify_mu(
    params: _Params, rho: bytes, t1: list[list[int]], mu: bytes, sig: bytes
) -> bool:
    decoded = _sig_decode(params, sig)
    if decoded is None:
        return False
    ctilde, z, h = decoded
    if not all(_norm_ok(p, params.gamma1 - params.beta) for p in z):
        return False
    c_hat = _ntt(_sample_in_ball(ctilde, params.tau))
    a_hat = _expand_a(params, rho)
    z_hat = [_ntt(p) for p in z]
    az = _mat_vec_ntt(a_hat, z_hat)
    scale = 1 << _D
    w_prime = []
    for i in range(params.k):
        ct1 = [(c_hat[j] * x * scale) % _Q for j, x in enumerate(_ntt(t1[i]))]
        w_prime.append(_ntt_inv(_poly_sub(az[i], ct1)))
    w1 = [
        [_use_hint(h[i][j], w_prime[i][j], params.gamma2) for j in range(_N)]
        for i in range(params.k)
    ]
    return _h(mu + _w1_encode(params, w1), params.ctilde) == ctilde


def _m_prime(message: bytes, context: bytes, hash_alg: str | None) -> bytes:
    if len(context) > 255:
        raise ValueError("context must be at most 255 bytes")
    if hash_alg is None:
        return b"\x00" + bytes([len(context)]) + context + message
    oid, hash_name, xof_len = _HASH_INFO[hash_alg]
    if xof_len is None:
        ph = hashlib.new(hash_name, message).digest()
    else:
        ph = getattr(hashlib, hash_name)(message).digest(xof_len)
    return b"\x01" + bytes([len(context)]) + context + oid + ph


def _resolve_name(parameter_set: str) -> _Params:
    try:
        return _PARAM_SETS[parameter_set]
    except KeyError:
        raise ValueError(f"unknown ML-DSA parameter set: {parameter_set!r}") from None


def _resolve_sk(sk: bytes) -> _Params:
    params = _BY_SK_SIZE.get(len(sk))
    if params is None:
        raise InvalidKey(f"invalid ML-DSA secret key length: {len(sk)} bytes")
    return params


def _resolve_pk(pk: bytes) -> _Params:
    params = _BY_PK_SIZE.get(len(pk))
    if params is None:
        raise InvalidKey(f"invalid ML-DSA public key length: {len(pk)} bytes")
    return params


# -------------------------------------------------------------- public


def keygen(parameter_set: str = "ML-DSA-44") -> tuple[bytes, bytes]:
    """Generate an ML-DSA key pair. Returns (public_key, secret_key)."""
    params = _resolve_name(parameter_set)
    return _keygen_internal(params, secrets.token_bytes(_SEED_LEN))


def sign(
    sk: bytes,
    message: bytes,
    context: bytes = b"",
    hash_alg: str | None = None,
) -> bytes:
    """Sign message. context is at most 255 bytes. hash_alg selects
    HashML-DSA prehash mode with one of the FIPS 204 named hashes."""
    params = _resolve_sk(sk)
    rnd = secrets.token_bytes(32)
    return _sign_internal(params, sk, _m_prime(message, context, hash_alg), rnd)


def verify(
    pk: bytes,
    signature: bytes,
    message: bytes,
    context: bytes = b"",
    hash_alg: str | None = None,
) -> bool:
    """Verify an ML-DSA signature. Returns False on any failure."""
    params = _resolve_pk(pk)
    if len(signature) != params.sig_size:
        return False
    m_prime = _m_prime(message, context, hash_alg)
    return _verify_internal(params, pk, signature, m_prime)


def sign_deterministic(
    sk: bytes,
    message: bytes,
    context: bytes = b"",
    hash_alg: str | None = None,
) -> bytes:
    """Sign with the all-zero rnd (the deterministic variant)."""
    params = _resolve_sk(sk)
    return _sign_internal(params, sk, _m_prime(message, context, hash_alg), bytes(32))


__all__ = [
    "keygen",
    "sign",
    "sign_deterministic",
    "verify",
]
