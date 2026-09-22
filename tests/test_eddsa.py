# SPDX-License-Identifier: 0BSD
"""Tests for purecrypt.eddsa (Ed25519 per RFC 8032).

Vectors: RFC 8032 section 7.1 (TEST 1-3, the 1023-byte test, SHA(abc))
and section 7.3 (Ed25519ph TEST abc).
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from purecrypt.eddsa import (
    _L,
    _P,
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from purecrypt.exceptions import InvalidKey, InvalidSignature
from tests.vectors import (
    ED25519_1023,
    ED25519_SHA_ABC,
    ED25519_VECTORS,
    ED25519PH_ABC,
)


def _unhex(v: tuple[str, ...]) -> tuple[bytes, ...]:
    return tuple(bytes.fromhex(x) for x in v)


class TestRfc8032Vectors:
    @pytest.mark.parametrize(
        "vec", [_unhex(v) for v in ED25519_VECTORS], ids=["TEST1", "TEST2", "TEST3"]
    )
    def test_sign_verify(self, vec: tuple[bytes, ...]) -> None:
        seed, pub_b, msg, sig = vec
        key = Ed25519PrivateKey.from_seed(seed)
        assert key.public_key().public_bytes() == pub_b
        assert key.sign(msg) == sig
        Ed25519PublicKey.from_public_bytes(pub_b).verify(sig, msg)

    def test_1023_byte_message(self) -> None:
        seed, pub_b, msg, sig = _unhex(ED25519_1023)
        key = Ed25519PrivateKey.from_seed(seed)
        assert len(msg) == 1023
        assert key.sign(msg) == sig
        Ed25519PublicKey.from_public_bytes(pub_b).verify(sig, msg)

    def test_sha_abc_plain(self) -> None:
        seed, pub_b, msg, sig = _unhex(ED25519_SHA_ABC)
        key = Ed25519PrivateKey.from_seed(seed)
        assert key.sign(msg) == sig
        Ed25519PublicKey.from_public_bytes(pub_b).verify(sig, msg)

    def test_ph_abc(self) -> None:
        seed, pub_b, msg, sig = _unhex(ED25519PH_ABC)
        key = Ed25519PrivateKey.from_seed(seed)
        assert key.public_key().public_bytes() == pub_b
        assert key.sign_ph(msg) == sig
        Ed25519PublicKey.from_public_bytes(pub_b).verify_ph(sig, msg)


@pytest.fixture(scope="module")
def ed_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


class TestAdversarial:
    @pytest.fixture
    def key(self, ed_key: Ed25519PrivateKey) -> Ed25519PrivateKey:
        return ed_key

    def test_tampered_signature(self, key: Ed25519PrivateKey) -> None:
        pub = key.public_key()
        sig = key.sign(b"message")
        for i in (0, 17, 40, 63):
            bad = bytearray(sig)
            bad[i] ^= 0x01
            with pytest.raises(InvalidSignature):
                pub.verify(bytes(bad), b"message")

    def test_tampered_message(self, key: Ed25519PrivateKey) -> None:
        sig = key.sign(b"message")
        with pytest.raises(InvalidSignature):
            key.public_key().verify(sig, b"messsge")

    def test_wrong_key(self, key: Ed25519PrivateKey) -> None:
        sig = key.sign(b"message")
        with pytest.raises(InvalidSignature):
            Ed25519PrivateKey.generate().public_key().verify(sig, b"message")

    def test_noncanonical_s(self, key: Ed25519PrivateKey) -> None:
        pub = key.public_key()
        sig = key.sign(b"m")
        bad = sig[:32] + _L.to_bytes(32, "little")  # s == l
        with pytest.raises(InvalidSignature):
            pub.verify(bad, b"m")
        bad = sig[:32] + (_L + 5).to_bytes(32, "little")
        with pytest.raises(InvalidSignature):
            pub.verify(bad, b"m")

    def test_noncanonical_public_key(self, key: Ed25519PrivateKey) -> None:
        sig = key.sign(b"m")
        # y >= p is a non-canonical field encoding
        bad_pub = Ed25519PublicKey.from_public_bytes(_P.to_bytes(32, "little"))
        with pytest.raises(InvalidSignature):
            bad_pub.verify(sig, b"m")

    def test_small_order_public_key(self, key: Ed25519PrivateKey) -> None:
        sig = key.sign(b"m")
        # The identity point encodes as 01 followed by zeros.
        identity = Ed25519PublicKey.from_public_bytes(b"\x01" + b"\x00" * 31)
        with pytest.raises(InvalidSignature):
            identity.verify(sig, b"m")

    def test_noncanonical_r(self, key: Ed25519PrivateKey) -> None:
        pub = key.public_key()
        sig = key.sign(b"m")
        bad = _P.to_bytes(32, "little") + sig[32:]
        with pytest.raises(InvalidSignature):
            pub.verify(bad, b"m")

    def test_bad_lengths(self, key: Ed25519PrivateKey) -> None:
        with pytest.raises(InvalidSignature):
            key.public_key().verify(b"\x00" * 63, b"m")
        with pytest.raises(InvalidKey):
            Ed25519PrivateKey.from_seed(b"\x00" * 31)
        with pytest.raises(InvalidKey):
            Ed25519PublicKey.from_public_bytes(b"\x00" * 33)

    def test_deterministic(self, key: Ed25519PrivateKey) -> None:
        assert key.sign(b"m") == key.sign(b"m")

    def test_seed_round_trip(self, key: Ed25519PrivateKey) -> None:
        clone = Ed25519PrivateKey.from_seed(key.private_bytes())
        assert clone.public_key().public_bytes() == key.public_key().public_bytes()

    def test_ph_round_trip(self, key: Ed25519PrivateKey) -> None:
        sig = key.sign_ph(b"data")
        key.public_key().verify_ph(sig, b"data")
        with pytest.raises(InvalidSignature):
            key.public_key().verify_ph(sig, b"other")
        # a ph signature must not pass the pure verifier
        with pytest.raises(InvalidSignature):
            key.public_key().verify(sig, b"data")


class TestProperties:
    @given(st.binary(min_size=0, max_size=256))
    @settings(max_examples=10, deadline=None)
    def test_sign_verify_property(self, message: bytes) -> None:
        key = Ed25519PrivateKey.generate()
        sig = key.sign(message)
        key.public_key().verify(sig, message)
