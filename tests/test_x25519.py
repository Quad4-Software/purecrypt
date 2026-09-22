# SPDX-License-Identifier: 0BSD
"""Tests for purecrypt.x25519 (RFC 7748 X25519 and X448).

Vectors: RFC 7748 section 5.2 single-step, iterated, and Alice/Bob DH.
"""

import pytest

from purecrypt.exceptions import InvalidKey
from purecrypt.x25519 import (
    X448PrivateKey,
    X448PublicKey,
    X25519PrivateKey,
    X25519PublicKey,
    _x448,
    _x25519,
)
from tests.vectors import (
    X448_VECTORS,
    X25519_DH,
    X25519_ITER_1,
    X25519_ITER_1000,
    X25519_VECTORS,
)


class TestX25519Vectors:
    @pytest.mark.parametrize(
        ("scalar", "u", "expected"),
        [tuple(bytes.fromhex(p) for p in v) for v in X25519_VECTORS],
    )
    def test_single_step(self, scalar: bytes, u: bytes, expected: bytes) -> None:
        assert _x25519(scalar, u) == expected
        key = X25519PrivateKey.from_private_bytes(scalar)
        assert key.exchange(u) == expected

    def test_alice_bob(self) -> None:
        a_priv, a_pub, b_priv, b_pub, shared = (bytes.fromhex(x) for x in X25519_DH)
        ka = X25519PrivateKey.from_private_bytes(a_priv)
        kb = X25519PrivateKey.from_private_bytes(b_priv)
        assert ka.public_key().public_bytes() == a_pub
        assert kb.public_key().public_bytes() == b_pub
        assert ka.exchange(kb.public_key()) == shared
        assert kb.exchange(ka.public_key()) == shared

    def test_iterated(self) -> None:
        k = u = b"\x09" + b"\x00" * 31
        for i in range(1000):
            out = _x25519(k, u)
            u, k = k, out
            if i == 0:
                assert k == bytes.fromhex(X25519_ITER_1)
        assert k == bytes.fromhex(X25519_ITER_1000)


class TestX448Vectors:
    @pytest.mark.parametrize(
        ("scalar", "u", "expected"),
        [tuple(bytes.fromhex(p) for p in v) for v in X448_VECTORS],
    )
    def test_single_step(self, scalar: bytes, u: bytes, expected: bytes) -> None:
        assert _x448(scalar, u) == expected


class TestAdversarial:
    @pytest.mark.parametrize("peer", [b"\x00" * 32, b"\x01" + b"\x00" * 31])
    def test_low_order_x25519(self, peer: bytes) -> None:
        key = X25519PrivateKey.generate()
        with pytest.raises(InvalidKey):
            key.exchange(peer)

    def test_low_order_x448(self) -> None:
        key = X448PrivateKey.generate()
        with pytest.raises(InvalidKey):
            key.exchange(b"\x00" * 56)

    def test_bad_lengths(self) -> None:
        with pytest.raises(InvalidKey):
            X25519PrivateKey.from_private_bytes(b"\x00" * 31)
        with pytest.raises(InvalidKey):
            X25519PublicKey.from_public_bytes(b"\x00" * 31)
        with pytest.raises(InvalidKey):
            X448PrivateKey.from_private_bytes(b"\x00" * 55)
        with pytest.raises(InvalidKey):
            X448PublicKey.from_public_bytes(b"\x00" * 55)
        with pytest.raises(InvalidKey):
            X25519PrivateKey.generate().exchange(b"\x00" * 31)
        with pytest.raises(InvalidKey):
            X448PrivateKey.generate().exchange(b"\x00" * 55)


class TestRoundTrips:
    def test_x25519_dh(self) -> None:
        a = X25519PrivateKey.generate()
        b = X25519PrivateKey.generate()
        s1 = a.exchange(b.public_key())
        s2 = b.exchange(a.public_key())
        assert s1 == s2
        assert len(s1) == 32
        assert s1 != b"\x00" * 32

    def test_x448_dh(self) -> None:
        a = X448PrivateKey.generate()
        b = X448PrivateKey.generate()
        s1 = a.exchange(b.public_key())
        s2 = b.exchange(a.public_key())
        assert s1 == s2
        assert len(s1) == 56

    def test_key_bytes_round_trip(self) -> None:
        k = X25519PrivateKey.generate()
        k2 = X25519PrivateKey.from_private_bytes(k.private_bytes())
        assert k2.public_key().public_bytes() == k.public_key().public_bytes()
        k448 = X448PrivateKey.generate()
        k448b = X448PrivateKey.from_private_bytes(k448.private_bytes())
        assert k448b.public_key().public_bytes() == k448.public_key().public_bytes()
