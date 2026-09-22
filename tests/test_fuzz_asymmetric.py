# SPDX-License-Identifier: 0BSD
"""Shared adversarial/property tests for the asymmetric half of purecrypt.

Two regimes:

* Fuzzing: os.urandom and mutated valid inputs are pushed through every
  decoder and verification entry point. Only purecrypt's typed
  exceptions (PureCryptError subclasses) may escape; IndexError,
  struct.error, RecursionError and friends are test failures.
* Metamorphic/property checks that span modules: ECDH symmetry,
  ECDSA determinism, PEM/DER round-trips for every key type.
"""

import contextlib
import os
import secrets

import pytest

from purecrypt import asn1, ec, pem
from purecrypt.eddsa import Ed25519PrivateKey, Ed25519PublicKey
from purecrypt.exceptions import PureCryptError
from purecrypt.rsa import RSAPrivateKey, RSAPublicKey, generate_private_key
from purecrypt.x25519 import X25519PrivateKey

_FUZZ_ITERS = 300  # per entry point; ~2000+ total across the file


def _random_bytes(max_len: int = 160) -> bytes:
    return os.urandom(secrets.randbelow(max_len + 1))


@pytest.fixture(scope="module")
def rsa_der() -> bytes:
    return generate_private_key(1024).public_key().to_pkcs1_der()


@pytest.fixture(scope="module")
def rsa_pem() -> str:
    return generate_private_key(1024).to_pkcs1_pem()


@pytest.fixture(scope="module")
def ec_pub() -> ec.ECPublicKey:
    return ec.ECPrivateKey.generate(ec.P256).public_key()


@pytest.fixture(scope="module")
def ec_sig() -> tuple[ec.ECPublicKey, bytes]:
    key = ec.ECPrivateKey.generate(ec.P256)
    return key.public_key(), key.sign_ecdsa(b"target")


@pytest.fixture(scope="module")
def ed_pub() -> Ed25519PublicKey:
    return Ed25519PrivateKey.generate().public_key()


class TestDecoderFuzz:
    def test_asn1_random(self) -> None:
        for _ in range(_FUZZ_ITERS):
            with contextlib.suppress(PureCryptError):
                asn1.decode(_random_bytes())

    def test_asn1_mutated_valid(self, rsa_der: bytes) -> None:
        for _ in range(_FUZZ_ITERS):
            buf = bytearray(rsa_der)
            for _ in range(secrets.randbelow(4)):
                pos = secrets.randbelow(len(buf))
                buf[pos] = secrets.randbelow(256)
            if secrets.randbelow(3) == 0:
                buf = buf[: secrets.randbelow(len(buf))]
            with contextlib.suppress(PureCryptError):
                asn1.decode(bytes(buf))

    def test_pem_random(self) -> None:
        for _ in range(_FUZZ_ITERS):
            with contextlib.suppress(PureCryptError):
                pem.decode_pem(_random_bytes(400))

    def test_pem_mutated_valid(self, rsa_pem: str) -> None:
        for _ in range(_FUZZ_ITERS):
            text = list(rsa_pem)
            pos = secrets.randbelow(len(text))
            text[pos] = chr(secrets.randbelow(128))
            with contextlib.suppress(PureCryptError):
                pem.decode_pem("".join(text))

    def test_rsa_from_der_random(self) -> None:
        for _ in range(_FUZZ_ITERS):
            blob = _random_bytes(200)
            with contextlib.suppress(PureCryptError):
                RSAPublicKey.from_der(blob)
            with contextlib.suppress(PureCryptError):
                RSAPrivateKey.from_der(blob)

    def test_rsa_from_pem_random(self) -> None:
        for _ in range(_FUZZ_ITERS // 3):
            blob = _random_bytes(300)
            with contextlib.suppress(PureCryptError):
                RSAPublicKey.from_pem(blob)
            with contextlib.suppress(PureCryptError):
                RSAPrivateKey.from_pem(blob)

    def test_ec_from_der_random(self) -> None:
        for _ in range(_FUZZ_ITERS):
            blob = _random_bytes(160)
            with contextlib.suppress(PureCryptError):
                ec.ECPublicKey.from_der(blob)
            with contextlib.suppress(PureCryptError):
                ec.ECPrivateKey.from_der(blob)

    def test_ec_point_random(self) -> None:
        for _ in range(_FUZZ_ITERS):
            with contextlib.suppress(PureCryptError):
                ec.ECPublicKey.from_sec1_bytes(_random_bytes(80), ec.P256)


class TestVerifyFuzz:
    def test_ecdsa_verify_random_sigs(self, ec_pub: ec.ECPublicKey) -> None:
        for _ in range(_FUZZ_ITERS):
            with contextlib.suppress(PureCryptError):
                ec_pub.verify_ecdsa(_random_bytes(90), _random_bytes(64))

    def test_ecdsa_mutated_valid_sig(
        self, ec_sig: tuple[ec.ECPublicKey, bytes]
    ) -> None:
        pub, sig = ec_sig
        for _ in range(_FUZZ_ITERS):
            buf = bytearray(sig)
            pos = secrets.randbelow(len(buf))
            buf[pos] = secrets.randbelow(256)
            with contextlib.suppress(PureCryptError):
                pub.verify_ecdsa(bytes(buf), b"target")

    def test_ed25519_verify_random(self, ed_pub: Ed25519PublicKey) -> None:
        for _ in range(_FUZZ_ITERS):
            with contextlib.suppress(PureCryptError):
                ed_pub.verify(_random_bytes(70), _random_bytes(64))

    def test_ed25519_random_pub(self) -> None:
        sig = Ed25519PrivateKey.generate().sign(b"m")
        for _ in range(_FUZZ_ITERS):
            with contextlib.suppress(PureCryptError):
                Ed25519PublicKey.from_public_bytes(_random_bytes(40)).verify(sig, b"m")


class TestMetamorphic:
    @pytest.mark.parametrize("curve", ec.CURVES, ids=lambda c: c.name)
    def test_ecdh_both_directions(self, curve: ec.Curve) -> None:
        a = ec.ECPrivateKey.generate(curve)
        b = ec.ECPrivateKey.generate(curve)
        assert a.ecdh(b.public_key()) == b.ecdh(a.public_key())

    @pytest.mark.parametrize("curve", ec.CURVES, ids=lambda c: c.name)
    def test_ecdsa_deterministic(self, curve: ec.Curve) -> None:
        key = ec.ECPrivateKey.generate(curve)
        assert key.sign_ecdsa(b"fixed") == key.sign_ecdsa(b"fixed")

    def test_x25519_exchange_symmetry(self) -> None:
        for _ in range(8):
            a = X25519PrivateKey.generate()
            b = X25519PrivateKey.generate()
            assert a.exchange(b.public_key()) == b.exchange(a.public_key())

    def test_all_key_pem_round_trips(self) -> None:
        # every key type: DER -> PEM -> parse -> identical object
        rk = generate_private_key(1024)
        pub = rk.public_key()
        assert RSAPrivateKey.from_pem(rk.to_pkcs1_pem()) == rk
        assert RSAPrivateKey.from_pem(rk.to_pkcs8_pem()) == rk
        assert RSAPublicKey.from_pem(pub.to_pkcs1_pem()) == pub
        assert RSAPublicKey.from_pem(pub.to_spki_pem()) == pub
        for curve in ec.CURVES:
            k = ec.ECPrivateKey.generate(curve)
            assert ec.ECPrivateKey.from_pem(k.to_sec1_pem()) == k
            assert ec.ECPrivateKey.from_pem(k.to_pkcs8_pem()) == k
            assert (
                ec.ECPublicKey.from_pem(k.public_key().to_spki_pem()) == k.public_key()
            )
