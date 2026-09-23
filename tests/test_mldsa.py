# SPDX-License-Identifier: 0BSD
"""ML-DSA (FIPS 204) tests: NIST ACVP vectors plus property checks.

Vectors are a compacted subset of the NIST ACVP-Server
internalProjection files for ML-DSA-keyGen-FIPS204,
ML-DSA-sigGen-FIPS204 and ML-DSA-sigVer-FIPS204, covering all three
parameter sets, pure and prehashed (HashML-DSA) modes, deterministic
and hedged signing, and mu-level internal cases.
"""

import json
import secrets
from pathlib import Path
from typing import Any

import pytest

from purecrypt import mldsa
from purecrypt.exceptions import InvalidKey

VECTOR_PATH = Path(__file__).parent / "data" / "mldsa_vectors.json"
VECTORS = json.loads(VECTOR_PATH.read_text())

PARAM_NAMES = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


def _param(name: str) -> Any:
    return mldsa._PARAM_SETS[name]


def _m_prime_of(rec: dict[str, Any]) -> bytes:
    hash_alg = rec.get("hashAlg")
    if hash_alg == "none":
        hash_alg = None
    return mldsa._m_prime(
        bytes.fromhex(rec.get("message", "")),
        bytes.fromhex(rec.get("context", "")),
        hash_alg,
    )


@pytest.mark.parametrize("case", VECTORS["keygen"], ids=lambda c: c["parameterSet"])
def test_acvp_keygen(case: dict[str, Any]) -> None:
    pk, sk = mldsa._keygen_internal(
        _param(case["parameterSet"]), bytes.fromhex(case["seed"])
    )
    assert pk == bytes.fromhex(case["pk"])
    assert sk == bytes.fromhex(case["sk"])


@pytest.mark.parametrize(
    "case", VECTORS["sign"], ids=lambda c: f"{c['parameterSet']}-{c['interface']}"
)
def test_acvp_siggen(case: dict[str, Any]) -> None:
    params = _param(case["parameterSet"])
    sk = bytes.fromhex(case["sk"])
    rnd = bytes.fromhex(case["rnd"]) if "rnd" in case else bytes(32)
    if case["interface"] == "internal" and "mu" in case:
        sig = mldsa._sign_mu(params, sk, bytes.fromhex(case["mu"]), rnd)
    elif case["interface"] == "internal":
        sig = mldsa._sign_internal(params, sk, bytes.fromhex(case["message"]), rnd)
    else:
        sig = mldsa._sign_internal(params, sk, _m_prime_of(case), rnd)
    assert sig == bytes.fromhex(case["signature"])


@pytest.mark.parametrize(
    "case", VECTORS["verify"], ids=lambda c: f"{c['parameterSet']}-{c['interface']}"
)
def test_acvp_sigver(case: dict[str, Any]) -> None:
    params = _param(case["parameterSet"])
    pk = bytes.fromhex(case["pk"])
    sig = bytes.fromhex(case["signature"])
    if case["interface"] == "internal" and "mu" in case:
        rho, t1 = mldsa._pk_decode(params, pk)
        got = mldsa._verify_mu(params, rho, t1, bytes.fromhex(case["mu"]), sig)
    elif case["interface"] == "internal":
        got = mldsa._verify_internal(params, pk, sig, bytes.fromhex(case["message"]))
    else:
        got = mldsa._verify_internal(params, pk, sig, _m_prime_of(case))
    assert got == case["testPassed"]


@pytest.mark.parametrize("name", PARAM_NAMES)
def test_roundtrip(name: str) -> None:
    pk, sk = mldsa.keygen(name)
    msg = secrets.token_bytes(64)
    sig = mldsa.sign(sk, msg)
    assert mldsa.verify(pk, sig, msg)


def test_deterministic_signing_is_deterministic() -> None:
    pk, sk = mldsa.keygen("ML-DSA-44")
    msg = b"deterministic"
    sig1 = mldsa.sign_deterministic(sk, msg)
    sig2 = mldsa.sign_deterministic(sk, msg)
    assert sig1 == sig2
    assert mldsa.verify(pk, sig1, msg)


def test_context_and_prehash() -> None:
    pk, sk = mldsa.keygen("ML-DSA-44")
    msg = b"with context"
    sig = mldsa.sign(sk, msg, context=b"ctx")
    assert mldsa.verify(pk, sig, msg, context=b"ctx")
    assert not mldsa.verify(pk, sig, msg, context=b"other")
    sig2 = mldsa.sign(sk, msg, hash_alg="SHA2-256")
    assert mldsa.verify(pk, sig2, msg, hash_alg="SHA2-256")
    assert not mldsa.verify(pk, sig2, msg)


def test_tampered_signature_rejected() -> None:
    pk, sk = mldsa.keygen("ML-DSA-44")
    sig = bytearray(mldsa.sign(sk, b"m"))
    for pos in (0, 100, len(sig) - 1):
        bad = bytearray(sig)
        bad[pos] ^= 1
        assert not mldsa.verify(pk, bytes(bad), b"m")


def test_wrong_message_rejected() -> None:
    pk, sk = mldsa.keygen("ML-DSA-44")
    sig = mldsa.sign(sk, b"right")
    assert not mldsa.verify(pk, sig, b"wrong")


def test_bad_lengths() -> None:
    with pytest.raises(InvalidKey, match="secret key length"):
        mldsa.sign(b"\x00" * 10, b"m")
    pk, _sk = mldsa.keygen("ML-DSA-44")
    assert not mldsa.verify(pk, b"\x00" * 10, b"m")
    with pytest.raises(InvalidKey, match="public key length"):
        mldsa.verify(b"\x00" * 10, b"\x00" * 2420, b"m")
    with pytest.raises(ValueError, match="parameter set"):
        mldsa.keygen("ML-DSA-99")


def test_context_length_limit() -> None:
    pk, sk = mldsa.keygen("ML-DSA-44")
    with pytest.raises(ValueError, match="255"):
        mldsa.sign(sk, b"m", context=b"x" * 256)
    sig = mldsa.sign(sk, b"m", context=b"x" * 255)
    assert mldsa.verify(pk, sig, b"m", context=b"x" * 255)
