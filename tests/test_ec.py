# SPDX-License-Identifier: 0BSD
"""Tests for purecrypt.ec: ECDSA (RFC 6979), ECDH, serialization.

Vector sources: RFC 6979 appendix A.2.5.1 (P-256/SHA-256) and RFC 5903
sections 8.1/8.2 (P-256 and P-384 ECDH shared secrets).
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from purecrypt import asn1, ec
from purecrypt.ec import (
    CURVES,
    P256,
    P384,
    SECP256K1,
    ECPrivateKey,
    ECPublicKey,
)
from purecrypt.exceptions import (
    InvalidKey,
    InvalidSerialization,
    InvalidSignature,
    UnsupportedAlgorithm,
)
from tests.vectors import ECDH_P256, ECDH_P384, RFC6979_P256


def _dss(sig: bytes) -> tuple[int, int]:
    kids = asn1.sequence_value(asn1.decode(sig))
    return asn1.int_value(kids[0]), asn1.int_value(kids[1])


def _dss_der(r: int, s: int) -> bytes:
    return asn1.encode_sequence(asn1.encode_integer(r), asn1.encode_integer(s))


class TestRfc6979:
    def test_key_and_public(self) -> None:
        key = ECPrivateKey(curve=P256, d=RFC6979_P256["x"])
        pub = key.public_key()
        assert pub.x == RFC6979_P256["ux"]
        assert pub.y == RFC6979_P256["uy"]

    @pytest.mark.parametrize(
        ("message", "r_key", "s_key"),
        [
            (b"sample", "sample_r", "sample_s"),
            (b"test", "test_r", "test_s"),
        ],
    )
    def test_deterministic_signature(
        self, message: bytes, r_key: str, s_key: str
    ) -> None:
        key = ECPrivateKey(curve=P256, d=RFC6979_P256["x"])
        r, s = _dss(key.sign_ecdsa(message, hash_name="sha256"))
        assert r == RFC6979_P256[r_key]
        # sign normalizes to low-s; the RFC value may be the high-s form
        s_rfc = RFC6979_P256[s_key]
        assert s in (s_rfc, P256.n - s_rfc)

    def test_determinism(self) -> None:
        key = ECPrivateKey.generate(P256)
        assert key.sign_ecdsa(b"m") == key.sign_ecdsa(b"m")


class TestEcdhVectors:
    def test_p256_rfc5903(self) -> None:
        ki = ECPrivateKey(curve=P256, d=ECDH_P256["i"])
        assert ki.public_key().x == ECDH_P256["gix"]
        assert ki.public_key().y == ECDH_P256["giy"]
        kr = ECPrivateKey(curve=P256, d=ECDH_P256["r"])
        shared = ki.ecdh(kr.public_key())
        assert shared == ECDH_P256["girx"].to_bytes(32, "big")
        assert kr.ecdh(ki.public_key()) == shared

    def test_p384_rfc5903(self) -> None:
        ki = ECPrivateKey(curve=P384, d=ECDH_P384["i"])
        assert ki.public_key().x == ECDH_P384["gix"]
        kr = ECPrivateKey(curve=P384, d=ECDH_P384["r"])
        shared = ki.ecdh(kr.public_key())
        assert shared == ECDH_P384["girx"].to_bytes(48, "big")
        assert kr.ecdh(ki.public_key()) == shared


class TestRoundTrips:
    @pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
    def test_sign_verify(self, curve: ec.Curve) -> None:
        key = ECPrivateKey.generate(curve)
        sig = key.sign_ecdsa(b"hello")
        key.public_key().verify_ecdsa(sig, b"hello")

    @pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
    def test_ecdh_symmetric(self, curve: ec.Curve) -> None:
        a = ECPrivateKey.generate(curve)
        b = ECPrivateKey.generate(curve)
        assert a.ecdh(b.public_key()) == b.ecdh(a.public_key())

    @pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
    def test_ecdh_raw_point(self, curve: ec.Curve) -> None:
        a = ECPrivateKey.generate(curve)
        b = ECPrivateKey.generate(curve)
        peer = b.public_key().to_sec1_bytes()
        assert a.ecdh(peer) == b.ecdh(a.public_key())

    @pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
    def test_sec1_private_round_trip(self, curve: ec.Curve) -> None:
        key = ECPrivateKey.generate(curve)
        assert ECPrivateKey.from_der(key.to_sec1_der()) == key
        text = key.to_sec1_pem()
        assert "EC PRIVATE KEY" in text
        assert ECPrivateKey.from_pem(text) == key

    @pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
    def test_pkcs8_round_trip(self, curve: ec.Curve) -> None:
        key = ECPrivateKey.generate(curve)
        assert ECPrivateKey.from_der(key.to_pkcs8_der()) == key
        assert ECPrivateKey.from_pem(key.to_pkcs8_pem()) == key

    @pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
    def test_spki_round_trip(self, curve: ec.Curve) -> None:
        pub = ECPrivateKey.generate(curve).public_key()
        assert ECPublicKey.from_der(pub.to_spki_der()) == pub
        assert ECPublicKey.from_pem(pub.to_spki_pem()) == pub

    @pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
    def test_sec1_point_formats(self, curve: ec.Curve) -> None:
        pub = ECPrivateKey.generate(curve).public_key()
        for compressed in (False, True):
            enc = pub.to_sec1_bytes(compressed=compressed)
            assert ECPublicKey.from_sec1_bytes(enc, curve) == pub


class TestInvalidCurveAndPoints:
    def test_off_curve_peer_rejected(self) -> None:
        a = ECPrivateKey.generate(P256)
        off = (
            b"\x04"
            + P256.gx.to_bytes(32, "big")
            + ((P256.gy + 1) % P256.p).to_bytes(32, "big")
        )
        with pytest.raises(InvalidKey):
            a.ecdh(off)
        with pytest.raises(InvalidKey):
            ECPublicKey.from_sec1_bytes(off, P256)

    def test_foreign_curve_point_rejected(self) -> None:
        a = ECPrivateKey.generate(P256)
        # secp256k1 base point encoded as a P-256 point: on neither
        # curve equation nor subgroup
        foreign = (
            b"\x04"
            + SECP256K1.gx.to_bytes(32, "big")
            + (SECP256K1.gy.to_bytes(32, "big"))
        )
        with pytest.raises(InvalidKey):
            a.ecdh(foreign)

    def test_validate_public_point(self) -> None:
        with pytest.raises(InvalidKey):
            ec.validate_public_point(P256, P256.gx, (P256.gy + 5) % P256.p)
        with pytest.raises(InvalidKey):
            ec.validate_public_point(P256, P256.p + 1, 0)  # out of range
        ec.validate_public_point(P256, P256.gx, P256.gy)  # ok

    def test_different_curve_peer(self) -> None:
        a = ECPrivateKey.generate(P256)
        b = ECPrivateKey.generate(P384)
        with pytest.raises(InvalidKey):
            a.ecdh(b.public_key())

    def test_bad_point_encodings(self) -> None:
        for raw in (
            b"",
            b"\x05" + b"\x00" * 64,
            b"\x04" + b"\x00" * 10,
            b"\x02" + b"\x00" * 33,
        ):
            with pytest.raises(InvalidSerialization):
                ECPublicKey.from_sec1_bytes(raw, P256)
        with pytest.raises(InvalidSerialization):
            ECPublicKey.from_sec1_bytes(b"\x02" + P256.p.to_bytes(32, "big"), P256)


@pytest.fixture(scope="module")
def p256_key() -> ECPrivateKey:
    return ECPrivateKey.generate(P256)


class TestSignatureValidation:
    @pytest.fixture
    def key(self, p256_key: ECPrivateKey) -> ECPrivateKey:
        return p256_key

    def test_malformed_der(self, key: ECPrivateKey) -> None:
        pub = key.public_key()
        for bad in (
            b"",
            b"\x30\x03\x02\x01",
            b"not der at all",
            _dss_der(1, 1) + b"\x00",
        ):
            with pytest.raises(InvalidSerialization):
                pub.verify_ecdsa(bad, b"m")

    @pytest.mark.parametrize("r", [0, -5, P256.n, P256.n + 7])
    def test_r_out_of_range(self, key: ECPrivateKey, r: int) -> None:
        s = 1
        if r < 0:
            # encode a negative r via raw INTEGER content
            sig = asn1.encode_sequence(
                asn1.encode_tlv(asn1.TAG_INTEGER, b"\x80"),
                asn1.encode_integer(s),
            )
        else:
            sig = _dss_der(r, s)
        with pytest.raises(InvalidSignature):
            key.public_key().verify_ecdsa(sig, b"m")

    @pytest.mark.parametrize("s", [0, -5, P256.n])
    def test_s_out_of_range(self, key: ECPrivateKey, s: int) -> None:
        if s < 0:
            sig = asn1.encode_sequence(
                asn1.encode_integer(1),
                asn1.encode_tlv(asn1.TAG_INTEGER, b"\x80"),
            )
        else:
            sig = _dss_der(1, s)
        with pytest.raises(InvalidSignature):
            key.public_key().verify_ecdsa(sig, b"m")

    def test_malleability_both_s_forms_verify(self, key: ECPrivateKey) -> None:
        sig = key.sign_ecdsa(b"m")
        r, s = _dss(sig)
        pub = key.public_key()
        pub.verify_ecdsa(sig, b"m")
        # ECDSA is malleable: (r, n - s) is also mathematically valid.
        # Signing normalizes to low-s, but verification must accept the
        # alternative encoding of the same signature.
        pub.verify_ecdsa(_dss_der(r, P256.n - s), b"m")

    def test_tampered_signature(self, key: ECPrivateKey) -> None:
        sig = bytearray(key.sign_ecdsa(b"m"))
        sig[-1] ^= 1
        with pytest.raises((InvalidSignature, InvalidSerialization)):
            key.public_key().verify_ecdsa(bytes(sig), b"m")

    def test_wrong_message(self, key: ECPrivateKey) -> None:
        sig = key.sign_ecdsa(b"m")
        with pytest.raises(InvalidSignature):
            key.public_key().verify_ecdsa(sig, b"other")


class TestSerializationEdgeCases:
    def test_sec1_without_curve_params(self) -> None:
        key = ECPrivateKey.generate(P256)
        minimal = asn1.encode_sequence(
            asn1.encode_integer(1),
            asn1.encode_octet_string(key.private_bytes()),
        )
        with pytest.raises(InvalidSerialization):
            ECPrivateKey.from_der(minimal)
        assert ECPrivateKey.from_der(minimal, curve=P256) == key

    def test_sec1_public_mismatch(self) -> None:
        key = ECPrivateKey.generate(P256)
        other = ECPrivateKey.generate(P256)
        bad = asn1.encode_sequence(
            asn1.encode_integer(1),
            asn1.encode_octet_string(key.private_bytes()),
            asn1.encode_context(0, asn1.encode_oid(P256.oid)),
            asn1.encode_context(
                1, asn1.encode_bit_string(other.public_key().to_sec1_bytes())
            ),
        )
        with pytest.raises(InvalidKey):
            ECPrivateKey.from_der(bad)

    def test_curve_names(self) -> None:
        assert ec.curve_by_name("P-256") is P256
        assert ec.curve_by_name("secp256r1") is P256
        assert ec.curve_by_name("prime256v1") is P256
        assert ec.curve_by_name("secp256k1") is SECP256K1
        with pytest.raises(UnsupportedAlgorithm):
            ec.curve_by_name("curve25519")
        with pytest.raises(UnsupportedAlgorithm):
            ec.curve_by_oid("1.2.3.4")

    def test_private_scalar_bounds(self) -> None:
        with pytest.raises(InvalidKey):
            ECPrivateKey(curve=P256, d=0)
        with pytest.raises(InvalidKey):
            ECPrivateKey(curve=P256, d=P256.n)
        with pytest.raises(InvalidKey):
            ECPrivateKey.from_private_bytes(b"\x01" * 32, P384)

    def test_spki_wrong_algorithm(self) -> None:
        pub = ECPrivateKey.generate(P256).public_key()
        bad = asn1.encode_sequence(
            asn1.encode_sequence(
                asn1.encode_oid("1.2.840.113549.1.1.1"),
                asn1.encode_oid(P256.oid),
            ),
            asn1.encode_bit_string(pub.to_sec1_bytes()),
        )
        with pytest.raises(InvalidSerialization):
            ECPublicKey.from_der(bad)

    def test_pem_label_enforcement(self) -> None:
        key = ECPrivateKey.generate(P256)
        with pytest.raises(InvalidSerialization):
            ECPrivateKey.from_pem(
                key.to_sec1_pem().replace("EC PRIVATE KEY", "PRIVATE KEY2")
            )


class TestHypothesisProperties:
    @pytest.mark.parametrize("curve", CURVES, ids=lambda c: c.name)
    @given(st.binary(min_size=0, max_size=128))
    @settings(max_examples=8, deadline=None)
    def test_sign_verify_property(self, curve: ec.Curve, message: bytes) -> None:
        key = ECPrivateKey.generate(curve)
        sig = key.sign_ecdsa(message)
        key.public_key().verify_ecdsa(sig, message)


class TestMoreEdgeCases:
    def test_unsupported_hash(self) -> None:
        key = ECPrivateKey.generate(P256)
        with pytest.raises(UnsupportedAlgorithm):
            key.sign_ecdsa(b"m", hash_name="md5")
        sig = key.sign_ecdsa(b"m")
        with pytest.raises(UnsupportedAlgorithm):
            key.public_key().verify_ecdsa(sig, b"m", hash_name="md5")

    def test_dss_wrong_element_count(self) -> None:
        pub = ECPrivateKey.generate(P256).public_key()
        sig = asn1.encode_sequence(asn1.encode_integer(1))
        with pytest.raises(InvalidSerialization):
            pub.verify_ecdsa(sig, b"m")

    def test_spki_malformed(self) -> None:
        bad = asn1.encode_sequence(asn1.encode_integer(1))
        with pytest.raises(InvalidSerialization):
            ECPublicKey.from_der(bad)
        bad_alg = asn1.encode_sequence(
            asn1.encode_sequence(asn1.encode_oid("1.2.840.10045.2.1")),
            asn1.encode_bit_string(b"\x04"),
        )
        with pytest.raises(InvalidSerialization):
            ECPublicKey.from_der(bad_alg)

    def test_compressed_point_no_y(self) -> None:
        # find an x whose quadratic residue is non-residue on P-256
        p, a, b = P256.p, P256.a, P256.b
        for x in range(50):
            alpha = (x * x * x + a * x + b) % p
            if pow(alpha, (p - 1) // 2, p) == p - 1:
                enc = b"\x02" + x.to_bytes(32, "big")
                with pytest.raises(InvalidSerialization):
                    ECPublicKey.from_sec1_bytes(enc, P256)
                break
        else:
            pytest.fail("no non-residue x found in first 50 candidates")

    def test_from_private_bytes_success(self) -> None:
        key = ECPrivateKey.generate(P256)
        assert ECPrivateKey.from_private_bytes(key.private_bytes(), P256) == key

    def test_pkcs8_errors(self, p256_key: ECPrivateKey) -> None:
        der = p256_key.to_pkcs8_der()
        kids = list(asn1.sequence_value(asn1.decode(der)))

        def re(node: asn1.DerNode) -> bytes:
            return asn1.encode_tlv(node.tag, node.content)

        # a nonzero version must be rejected
        bad = asn1.encode_sequence(asn1.encode_integer(1), re(kids[1]), re(kids[2]))
        with pytest.raises(InvalidSerialization):
            ECPrivateKey.from_der(bad)
        # a non-EC algorithm oid must be rejected
        bad_alg = asn1.encode_sequence(
            asn1.encode_oid("1.2.840.113549.1.1.1"),
            asn1.encode_oid(P256.oid),
        )
        bad = asn1.encode_sequence(asn1.encode_integer(0), bad_alg, re(kids[2]))
        with pytest.raises(InvalidSerialization):
            ECPrivateKey.from_der(bad)
        # an empty algorithm sequence must be rejected
        bad = asn1.encode_sequence(
            asn1.encode_integer(0), asn1.encode_sequence(), re(kids[2])
        )
        with pytest.raises(InvalidSerialization):
            ECPrivateKey.from_der(bad)

    def test_sec1_errors(self, p256_key: ECPrivateKey) -> None:
        # a version other than 1 must be rejected
        bad = asn1.encode_sequence(
            asn1.encode_integer(2),
            asn1.encode_octet_string(p256_key.private_bytes()),
        )
        with pytest.raises(InvalidSerialization):
            ECPrivateKey.from_der(bad)
        # a scalar of the wrong length must be rejected
        bad = asn1.encode_sequence(
            asn1.encode_integer(1),
            asn1.encode_octet_string(b"\x01"),
            asn1.encode_context(0, asn1.encode_oid(P256.oid)),
        )
        with pytest.raises(InvalidSerialization):
            ECPrivateKey.from_der(bad)
        # a truncated sequence must be rejected
        bad = asn1.encode_sequence(asn1.encode_integer(1))
        with pytest.raises(InvalidSerialization):
            ECPrivateKey.from_der(bad)
        # a [0] parameters field with two elements must be rejected
        bad = asn1.encode_sequence(
            asn1.encode_integer(1),
            asn1.encode_octet_string(p256_key.private_bytes()),
            asn1.encode_context(
                0, asn1.encode_oid(P256.oid), asn1.encode_oid(P256.oid)
            ),
        )
        with pytest.raises(InvalidSerialization):
            ECPrivateKey.from_der(bad)
        # a [1] publicKey field with two elements must be rejected
        bad = asn1.encode_sequence(
            asn1.encode_integer(1),
            asn1.encode_octet_string(p256_key.private_bytes()),
            asn1.encode_context(
                1,
                asn1.encode_bit_string(b"\x04"),
                asn1.encode_bit_string(b"\x04"),
            ),
        )
        with pytest.raises(InvalidSerialization):
            ECPrivateKey.from_der(bad)
