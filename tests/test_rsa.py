# SPDX-License-Identifier: 0BSD
"""Tests for purecrypt.rsa against published vectors and adversarial cases.

Vector sources: RSA Laboratories pkcs-1v2-1-vec.zip (oaep-vect.txt,
pss-vect.txt, pkcs1v15sign-vectors.txt, pkcs1v15crypt-vectors.txt), as
mirrored in the pyca cryptography_vectors repository.
"""

import secrets

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import purecrypt.rsa as rsa
from purecrypt import asn1
from purecrypt.exceptions import (
    InvalidKey,
    InvalidSerialization,
    InvalidSignature,
    PureCryptError,
    UnsupportedAlgorithm,
)
from tests.vectors import (
    OAEP_EXAMPLES,
    OAEP_KEY,
    PSS_EXAMPLES,
    PSS_KEY,
    V15CRYPT_EXAMPLES,
    V15CRYPT_KEY,
    V15SIGN_EXAMPLES,
    V15SIGN_KEY,
)


def _key(d: dict[str, int]) -> rsa.RSAPrivateKey:
    return rsa.RSAPrivateKey(
        n=d["n"],
        e=d["e"],
        d=d["d"],
        p=d["p"],
        q=d["q"],
        dmp1=d["dmp1"],
        dmq1=d["dmq1"],
        iqmp=d["iqmp"],
    )


@pytest.fixture(scope="module")
def fresh_key() -> rsa.RSAPrivateKey:
    # 1024 bits is TEST-ONLY: the smallest accepted size, fast to
    # generate in pure Python. Never ship keys this small.
    return rsa.generate_private_key(1024)  # nosec B311 - test-only size


class TestPublishedVectors:
    def test_oaep_decrypt(self) -> None:
        key = _key(OAEP_KEY)
        for msg_hex, _seed, ct_hex in OAEP_EXAMPLES:
            out = key.decrypt_oaep(bytes.fromhex(ct_hex), hash_name="sha1")
            assert out == bytes.fromhex(msg_hex)

    def test_oaep_encrypt_with_vector_seed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        key = _key(OAEP_KEY).public_key()
        for msg_hex, seed_hex, ct_hex in OAEP_EXAMPLES:
            monkeypatch.setattr(
                secrets, "token_bytes", lambda n, s=seed_hex: bytes.fromhex(s)
            )
            ct = key.encrypt_oaep(bytes.fromhex(msg_hex), hash_name="sha1")
            assert ct == bytes.fromhex(ct_hex)
            monkeypatch.undo()

    def test_pss_verify(self) -> None:
        pub = _key(PSS_KEY).public_key()
        for msg_hex, _salt, sig_hex in PSS_EXAMPLES:
            pub.verify_pss(
                bytes.fromhex(sig_hex),
                bytes.fromhex(msg_hex),
                hash_name="sha1",
                salt_len=20,
            )
            # auto salt-length recovery must accept too
            pub.verify_pss(
                bytes.fromhex(sig_hex),
                bytes.fromhex(msg_hex),
                hash_name="sha1",
            )

    def test_pss_sign_with_vector_salt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        key = _key(PSS_KEY)
        for msg_hex, salt_hex, sig_hex in PSS_EXAMPLES:
            monkeypatch.setattr(
                secrets, "token_bytes", lambda n, s=salt_hex: bytes.fromhex(s)
            )
            sig = key.sign_pss(bytes.fromhex(msg_hex), hash_name="sha1", salt_len=20)
            assert sig == bytes.fromhex(sig_hex)
            monkeypatch.undo()

    def test_v15_sign(self) -> None:
        key = _key(V15SIGN_KEY)
        pub = key.public_key()
        for msg_hex, sig_hex in V15SIGN_EXAMPLES:
            msg, sig = bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)
            pub.verify_v15(sig, msg, hash_name="sha1")
            assert key.sign_v15(msg, hash_name="sha1") == sig

    def test_v15_decrypt(self) -> None:
        key = _key(V15CRYPT_KEY)
        for msg_hex, _pad, ct_hex in V15CRYPT_EXAMPLES:
            out = key.decrypt_v15(bytes.fromhex(ct_hex))
            assert out == bytes.fromhex(msg_hex)

    def test_v15_encrypt_with_vector_padding(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        key = _key(V15CRYPT_KEY).public_key()
        for msg_hex, pad_hex, ct_hex in V15CRYPT_EXAMPLES:
            monkeypatch.setattr(
                rsa, "_nonzero_random", lambda n, s=pad_hex: bytes.fromhex(s)
            )
            ct = key.encrypt_v15(bytes.fromhex(msg_hex))
            assert ct == bytes.fromhex(ct_hex)
            monkeypatch.undo()


class TestRoundTrips:
    @pytest.mark.parametrize(
        "hash_name", ["sha1", "sha224", "sha256", "sha384", "sha512"]
    )
    def test_v15_sign_hashes(
        self, fresh_key: rsa.RSAPrivateKey, hash_name: str
    ) -> None:
        sig = fresh_key.sign_v15(b"msg", hash_name=hash_name)
        fresh_key.public_key().verify_v15(sig, b"msg", hash_name=hash_name)

    @pytest.mark.parametrize("salt_len", [None, 0, 20, 32])
    def test_pss_round_trip(
        self, fresh_key: rsa.RSAPrivateKey, salt_len: int | None
    ) -> None:
        sig = fresh_key.sign_pss(b"msg", salt_len=salt_len)
        fresh_key.public_key().verify_pss(sig, b"msg", salt_len=salt_len)
        fresh_key.public_key().verify_pss(sig, b"msg")  # auto salt len

    # sha512 needs 2*64+2=130 bytes, more than a 1024-bit (TEST-ONLY)
    # modulus provides, so it is intentionally absent here.
    @pytest.mark.parametrize("hash_name", ["sha256", "sha384", "sha3_256"])
    def test_oaep_round_trip(
        self, fresh_key: rsa.RSAPrivateKey, hash_name: str
    ) -> None:
        ct = fresh_key.public_key().encrypt_oaep(
            b"payload", hash_name=hash_name, label=b"lbl"
        )
        out = fresh_key.decrypt_oaep(ct, hash_name=hash_name, label=b"lbl")
        assert out == b"payload"

    def test_v15_round_trip(self, fresh_key: rsa.RSAPrivateKey) -> None:
        ct = fresh_key.public_key().encrypt_v15(b"payload")
        assert fresh_key.decrypt_v15(ct) == b"payload"

    def test_oaep_empty_message(self, fresh_key: rsa.RSAPrivateKey) -> None:
        ct = fresh_key.public_key().encrypt_oaep(b"")
        assert fresh_key.decrypt_oaep(ct) == b""

    def test_pss_differs_across_signs(self, fresh_key: rsa.RSAPrivateKey) -> None:
        s1 = fresh_key.sign_pss(b"same")
        s2 = fresh_key.sign_pss(b"same")
        assert s1 != s2  # random salt
        fresh_key.public_key().verify_pss(s1, b"same")
        fresh_key.public_key().verify_pss(s2, b"same")

    def test_v15_deterministic(self, fresh_key: rsa.RSAPrivateKey) -> None:
        assert fresh_key.sign_v15(b"same") == fresh_key.sign_v15(b"same")


class TestSerialization:
    def test_pkcs1_private_round_trip(self, fresh_key: rsa.RSAPrivateKey) -> None:
        der = fresh_key.to_pkcs1_der()
        assert rsa.RSAPrivateKey.from_der(der) == fresh_key
        text = fresh_key.to_pkcs1_pem()
        assert "RSA PRIVATE KEY" in text
        assert rsa.RSAPrivateKey.from_pem(text) == fresh_key
        assert rsa.RSAPrivateKey.from_pem(text.encode()) == fresh_key

    def test_pkcs8_round_trip(self, fresh_key: rsa.RSAPrivateKey) -> None:
        der = fresh_key.to_pkcs8_der()
        assert rsa.RSAPrivateKey.from_der(der) == fresh_key
        text = fresh_key.to_pkcs8_pem()
        assert "PRIVATE KEY" in text
        assert rsa.RSAPrivateKey.from_pem(text) == fresh_key

    def test_pkcs1_public_round_trip(self, fresh_key: rsa.RSAPrivateKey) -> None:
        pub = fresh_key.public_key()
        assert rsa.RSAPublicKey.from_der(pub.to_pkcs1_der()) == pub
        assert rsa.RSAPublicKey.from_pem(pub.to_pkcs1_pem()) == pub

    def test_spki_round_trip(self, fresh_key: rsa.RSAPrivateKey) -> None:
        pub = fresh_key.public_key()
        assert rsa.RSAPublicKey.from_der(pub.to_spki_der()) == pub
        text = pub.to_spki_pem()
        assert "PUBLIC KEY" in text
        assert rsa.RSAPublicKey.from_pem(text) == pub

    def test_spki_from_der_dispatch(self, fresh_key: rsa.RSAPrivateKey) -> None:
        pub = fresh_key.public_key()
        # from_der accepts both PKCS1 and SPKI forms
        assert rsa.RSAPublicKey.from_der(pub.to_pkcs1_der()) == pub
        assert rsa.RSAPublicKey.from_der(pub.to_spki_der()) == pub

    def test_wrong_label_rejected(self, fresh_key: rsa.RSAPrivateKey) -> None:
        with pytest.raises(InvalidSerialization):
            rsa.RSAPrivateKey.from_pem(
                fresh_key.to_pkcs1_pem().replace("RSA PRIVATE KEY", "RSA PUBLIC KEY")
            )
        with pytest.raises(InvalidSerialization):
            rsa.RSAPublicKey.from_pem(fresh_key.to_pkcs1_pem())


class TestAdversarial:
    def test_mutated_signature(self, fresh_key: rsa.RSAPrivateKey) -> None:
        pub = fresh_key.public_key()
        for sig in (fresh_key.sign_v15(b"m"), fresh_key.sign_pss(b"m")):
            bad = bytearray(sig)
            bad[10] ^= 0x01
            with pytest.raises(InvalidSignature):
                pub.verify_v15(bytes(bad), b"m")
            with pytest.raises(InvalidSignature):
                pub.verify_pss(bytes(bad), b"m")

    def test_wrong_message(self, fresh_key: rsa.RSAPrivateKey) -> None:
        sig = fresh_key.sign_v15(b"m")
        with pytest.raises(InvalidSignature):
            fresh_key.public_key().verify_v15(sig, b"other")

    def test_bad_signature_length(self, fresh_key: rsa.RSAPrivateKey) -> None:
        with pytest.raises(InvalidSignature):
            fresh_key.public_key().verify_v15(b"short", b"m")
        with pytest.raises(InvalidSignature):
            fresh_key.public_key().verify_pss(b"short", b"m")

    def test_oaep_wrong_label(self, fresh_key: rsa.RSAPrivateKey) -> None:
        ct = fresh_key.public_key().encrypt_oaep(b"m", label=b"good")
        with pytest.raises(InvalidKey):
            fresh_key.decrypt_oaep(ct, label=b"evil")

    def test_oaep_corrupted(self, fresh_key: rsa.RSAPrivateKey) -> None:
        ct = bytearray(fresh_key.public_key().encrypt_oaep(b"m"))
        ct[40] ^= 0x40
        with pytest.raises(InvalidKey):
            fresh_key.decrypt_oaep(bytes(ct))

    def test_oaep_truncated(self, fresh_key: rsa.RSAPrivateKey) -> None:
        ct = fresh_key.public_key().encrypt_oaep(b"m")
        with pytest.raises(InvalidKey):
            fresh_key.decrypt_oaep(ct[:-1])

    def test_v15_malformed_padding(self, fresh_key: rsa.RSAPrivateKey) -> None:
        ct = bytearray(fresh_key.public_key().encrypt_v15(b"m"))
        ct[5] = 0  # punch a hole in the padding string
        with pytest.raises(InvalidKey):
            fresh_key.decrypt_v15(bytes(ct))

    def test_v15_wrong_block_type(self, fresh_key: rsa.RSAPrivateKey) -> None:
        # decrypt an OAEP blob as v1.5: uniform failure either way
        ct = fresh_key.public_key().encrypt_oaep(b"m")
        with pytest.raises(InvalidKey):
            fresh_key.decrypt_v15(ct)

    def test_message_too_long(self, fresh_key: rsa.RSAPrivateKey) -> None:
        pub = fresh_key.public_key()
        with pytest.raises(InvalidKey):
            pub.encrypt_v15(b"x" * 200)
        with pytest.raises(InvalidKey):
            pub.encrypt_oaep(b"x" * 200)

    def test_unsupported_hash(self, fresh_key: rsa.RSAPrivateKey) -> None:
        pub = fresh_key.public_key()
        with pytest.raises(UnsupportedAlgorithm):
            fresh_key.sign_v15(b"m", hash_name="md5")
        with pytest.raises(UnsupportedAlgorithm):
            fresh_key.sign_pss(b"m", hash_name="md5")
        with pytest.raises(UnsupportedAlgorithm):
            pub.encrypt_oaep(b"m", hash_name="md5")

    def test_key_size_floor(self) -> None:
        with pytest.raises(InvalidKey):
            rsa.generate_private_key(512)
        with pytest.raises(InvalidKey):
            rsa.generate_private_key(1024, e=4)

    def test_invalid_public_numbers(self) -> None:
        with pytest.raises(InvalidKey):
            rsa.RSAPublicKey(n=1 << 1024, e=65537)  # even modulus
        with pytest.raises(InvalidKey):
            rsa.RSAPublicKey(n=(1 << 1023) + 1, e=2)  # even e
        with pytest.raises(InvalidKey):
            rsa.RSAPublicKey(n=(1 << 1023) + 1, e=1)  # e too small
        with pytest.raises(InvalidKey):
            rsa.RSAPublicKey(n=(1 << 511) + 1, e=3)  # modulus too small

    def test_inconsistent_private_numbers(self) -> None:
        d = dict(OAEP_KEY)
        d["dmp1"] = d["dmp1"] + 2
        with pytest.raises(InvalidKey):
            _key(d)
        d = dict(OAEP_KEY)
        d["iqmp"] = d["iqmp"] + 2
        with pytest.raises(InvalidKey):
            _key(d)

    def test_from_der_garbage(self) -> None:
        with pytest.raises(InvalidSerialization):
            rsa.RSAPublicKey.from_der(b"\x30\x03\x02\x01")  # truncated
        with pytest.raises(InvalidSerialization):
            rsa.RSAPublicKey.from_der(b"\x05\x00")
        with pytest.raises(InvalidSerialization):
            rsa.RSAPrivateKey.from_der(b"\x05\x00")


class TestProperties:
    @given(st.binary(min_size=0, max_size=200))
    @settings(max_examples=15, deadline=None)
    def test_v15_sign_verify_property(
        self, fresh_key: rsa.RSAPrivateKey, message: bytes
    ) -> None:
        sig = fresh_key.sign_v15(message)
        fresh_key.public_key().verify_v15(sig, message)

    @given(st.binary(min_size=0, max_size=50))
    @settings(max_examples=10, deadline=None)
    def test_oaep_round_trip_property(
        self, fresh_key: rsa.RSAPrivateKey, message: bytes
    ) -> None:
        ct = fresh_key.public_key().encrypt_oaep(message)
        assert fresh_key.decrypt_oaep(ct) == message


class TestEdgeCases:
    def test_key_size_properties(self, fresh_key: rsa.RSAPrivateKey) -> None:
        assert fresh_key.key_size_bits == 1024
        assert fresh_key.key_bytes == 128
        assert fresh_key.public_key().key_size_bits == 1024

    def test_exponent_out_of_range(self) -> None:
        n = (1 << 1023) + 7  # odd, large enough
        with pytest.raises(InvalidKey):
            rsa.RSAPublicKey(n=n, e=n + 2)

    def test_inconsistent_d(self) -> None:
        d = dict(OAEP_KEY)
        d["d"] = d["d"] + 2
        with pytest.raises(InvalidKey):
            _key(d)
        d = dict(OAEP_KEY)
        d["q"] = d["q"] + 2
        with pytest.raises(InvalidKey):
            _key(d)

    def test_pss_salt_bounds(self, fresh_key: rsa.RSAPrivateKey) -> None:
        with pytest.raises(InvalidKey):
            fresh_key.sign_pss(b"m", salt_len=-1)
        with pytest.raises(InvalidKey):
            fresh_key.sign_pss(b"m", salt_len=500)

    def test_pss_corrupt_trailer(self, fresh_key: rsa.RSAPrivateKey) -> None:
        pub = fresh_key.public_key()
        sig = bytearray(fresh_key.sign_pss(b"m"))
        sig[-1] ^= 0xFF  # destroy the 0xbc trailer
        with pytest.raises(InvalidSignature):
            pub.verify_pss(bytes(sig), b"m")

    def test_pss_corrupt_hash_region(self, fresh_key: rsa.RSAPrivateKey) -> None:
        pub = fresh_key.public_key()
        sig = bytearray(fresh_key.sign_pss(b"m"))
        sig[-2] ^= 0xFF  # inside H / trailer boundary
        with pytest.raises(InvalidSignature):
            pub.verify_pss(bytes(sig), b"m")

    def test_spki_wrong_algorithm(self, fresh_key: rsa.RSAPrivateKey) -> None:
        pub = fresh_key.public_key()
        bad = asn1.encode_sequence(
            asn1.encode_sequence(
                asn1.encode_oid("1.2.840.10045.2.1"), asn1.encode_null()
            ),
            asn1.encode_bit_string(pub.to_pkcs1_der()),
        )
        with pytest.raises(InvalidSerialization):
            rsa.RSAPublicKey.from_der(bad)

    def test_spki_malformed(self) -> None:
        bad = asn1.encode_sequence(asn1.encode_integer(1))
        with pytest.raises(InvalidSerialization):
            rsa.RSAPublicKey.from_der(bad)
        inner = asn1.encode_sequence(
            asn1.encode_sequence(
                asn1.encode_oid("1.2.840.113549.1.1.1"), asn1.encode_null()
            ),
            asn1.encode_bit_string(asn1.encode_integer(3)),
        )
        with pytest.raises(InvalidSerialization):
            rsa.RSAPublicKey.from_der(inner)

    def test_pkcs8_errors(self, fresh_key: rsa.RSAPrivateKey) -> None:
        der = fresh_key.to_pkcs8_der()
        kids = list(asn1.sequence_value(asn1.decode(der)))
        # a nonzero version must be rejected
        bad = asn1.encode_sequence(
            asn1.encode_integer(1), _reenc(kids[1]), _reenc(kids[2])
        )
        with pytest.raises(InvalidSerialization):
            rsa.RSAPrivateKey.from_der(bad)
        # a non-RSA algorithm oid must be rejected
        bad_alg = asn1.encode_sequence(
            asn1.encode_oid("1.2.840.10045.2.1"), asn1.encode_null()
        )
        bad = asn1.encode_sequence(asn1.encode_integer(0), bad_alg, _reenc(kids[2]))
        with pytest.raises(InvalidSerialization):
            rsa.RSAPrivateKey.from_der(bad)
        # an empty algorithm sequence must be rejected
        bad = asn1.encode_sequence(
            asn1.encode_integer(0),
            asn1.encode_sequence(),
            _reenc(kids[2]),
        )
        with pytest.raises(InvalidSerialization):
            rsa.RSAPrivateKey.from_der(bad)

    def test_pkcs1_version_error(self, fresh_key: rsa.RSAPrivateKey) -> None:
        kids = asn1.sequence_value(asn1.decode(fresh_key.to_pkcs1_der()))
        bad = asn1.encode_sequence(
            asn1.encode_integer(1), *[_reenc(k) for k in kids[1:]]
        )
        with pytest.raises(InvalidSerialization):
            rsa.RSAPrivateKey.from_der(bad)

    def test_mgf1(self) -> None:
        out = rsa.mgf1(b"seed", 100, "sha256")
        assert len(out) == 100
        assert rsa.mgf1(b"seed", 32, "sha1") == rsa.mgf1(b"seed", 32, "sha1")
        with pytest.raises(ValueError, match="non-negative"):
            rsa.mgf1(b"seed", -1)


class TestBlindingAndFaultCheck:
    def test_blinded_private_op_matches_plain(
        self, fresh_key: rsa.RSAPrivateKey
    ) -> None:
        # The blinded CRT path must agree with the plain schoolbook
        # private exponentiation on arbitrary inputs.
        for _ in range(10):
            c = secrets.randbelow(fresh_key.n)
            assert fresh_key._rsadp(c) == pow(c, fresh_key.d, fresh_key.n)

    def test_blinding_factor_actually_used(
        self, fresh_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[int] = []
        real = secrets.randbelow

        def spy(bound: int) -> int:
            calls.append(bound)
            return real(bound)

        monkeypatch.setattr(secrets, "randbelow", spy)
        fresh_key.sign_v15(b"m")
        assert calls == [fresh_key.n - 2]

    def test_blinding_gcd_retry(
        self, fresh_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A factor of n must be rejected and re-drawn.
        draws = iter([fresh_key.p, 17])
        monkeypatch.setattr(secrets, "randbelow", lambda _n: next(draws))
        assert fresh_key._rsadp(12345) == pow(12345, fresh_key.d, fresh_key.n)

    def test_crt_fault_detected(self, fresh_key: rsa.RSAPrivateKey) -> None:
        # A corrupted CRT coefficient must be caught by the public-key
        # verification step instead of releasing a bad result.
        original = fresh_key.iqmp
        object.__setattr__(fresh_key, "iqmp", (original + 1) % fresh_key.p)
        try:
            with pytest.raises(PureCryptError):
                fresh_key._rsadp(12345)
        finally:
            object.__setattr__(fresh_key, "iqmp", original)


class TestMrRoundsTable:
    @pytest.mark.parametrize(
        ("bits", "rounds"),
        [(512, 40), (767, 40), (768, 56), (1023, 56), (1024, 64), (2048, 64)],
    )
    def test_table(self, bits: int, rounds: int) -> None:
        assert rsa._mr_rounds(bits) == rounds

    def test_small_prime_defensive_default(self) -> None:
        assert rsa._mr_rounds(256) == 64


def _reenc(node: asn1.DerNode) -> bytes:
    return asn1.encode_tlv(node.tag, node.content)
