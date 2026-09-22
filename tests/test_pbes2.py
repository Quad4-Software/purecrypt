# SPDX-License-Identifier: 0BSD
"""Tests for purecrypt._pbes2 and password-aware key serialization.

Fixtures under tests/fixtures were generated once by generate.sh with
the openssl CLI (see that file for the exact commands). The password
for every *_enc.pem fixture is PASSWORD below.
"""

import contextlib
import os
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest

from purecrypt import _pbes2, aes, asn1, ec, kdf, pem, rsa
from purecrypt.exceptions import (
    InvalidKey,
    InvalidSerialization,
    PureCryptError,
    UnsupportedAlgorithm,
)

FIXTURES = Path(__file__).parent / "fixtures"
PASSWORD = b"correct horse battery staple"
ITER = 2048  # keep test-time PBKDF2 cheap while the default runs once

OPENSSL = shutil.which("openssl")


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _fixture_der(name: str) -> bytes:
    return pem.decode_pem(_fixture(name))[1]


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.RSAPrivateKey.from_pem(_fixture("rsa_pkcs8.pem"))


@pytest.fixture(scope="module")
def ec_key() -> ec.ECPrivateKey:
    return ec.ECPrivateKey.from_pem(_fixture("ec_pkcs8.pem"))


class TestEncryptStructure:
    def test_emits_pbes2_shape(self, rsa_key: rsa.RSAPrivateKey) -> None:
        der = rsa_key.to_pkcs8_der(password=PASSWORD, iterations=ITER)
        kids = asn1.sequence_value(asn1.decode(der))
        assert len(kids) == 2
        alg = asn1.sequence_value(kids[0])
        assert asn1.oid_value(alg[0]) == "1.2.840.113549.1.5.13"  # PBES2
        assert kids[1].tag == asn1.TAG_OCTET_STRING
        params = asn1.sequence_value(alg[1])
        kdf = asn1.sequence_value(params[0])
        assert asn1.oid_value(kdf[0]) == "1.2.840.113549.1.5.12"  # PBKDF2
        kdf_params = asn1.sequence_value(kdf[1])
        assert asn1.int_value(kdf_params[1]) == ITER
        assert asn1.int_value(kdf_params[2]) == 32  # keyLength
        prf = asn1.sequence_value(kdf_params[3])
        assert asn1.oid_value(prf[0]) == "1.2.840.113549.2.9"  # hmacSHA256
        enc = asn1.sequence_value(params[1])
        assert asn1.oid_value(enc[0]) == "2.16.840.1.101.3.4.1.42"  # aes256
        assert len(asn1.octet_string_value(kdf_params[0])) == 16  # salt
        assert len(asn1.octet_string_value(enc[1])) == 16  # IV

    def test_encrypt_validation(self, rsa_key: rsa.RSAPrivateKey) -> None:
        der = rsa_key.to_pkcs8_der()
        with pytest.raises(ValueError, match="iterations"):
            _pbes2.pbes2_encrypt(der, PASSWORD, iterations=0)
        with pytest.raises(ValueError, match="iterations"):
            _pbes2.pbes2_encrypt(der, PASSWORD, iterations=20_000_000)
        with pytest.raises(UnsupportedAlgorithm):
            _pbes2.pbes2_encrypt(der, PASSWORD, hash_name="sha1")
        with pytest.raises(UnsupportedAlgorithm):
            _pbes2.pbes2_encrypt(der, PASSWORD, hash_name="md5")

    def test_salt_and_iv_randomized(self, rsa_key: rsa.RSAPrivateKey) -> None:
        a = rsa_key.to_pkcs8_der(password=PASSWORD, iterations=ITER)
        b = rsa_key.to_pkcs8_der(password=PASSWORD, iterations=ITER)
        assert a != b


class TestRoundTrip:
    def test_rsa_der(self, rsa_key: rsa.RSAPrivateKey) -> None:
        der = rsa_key.to_pkcs8_der(password=PASSWORD, iterations=ITER)
        assert rsa.RSAPrivateKey.from_der(der, password=PASSWORD) == rsa_key

    def test_rsa_pem(self, rsa_key: rsa.RSAPrivateKey) -> None:
        text = rsa_key.to_pkcs8_pem(password=PASSWORD, iterations=ITER)
        assert "ENCRYPTED PRIVATE KEY" in text
        assert rsa.RSAPrivateKey.from_pem(text, password=PASSWORD) == rsa_key

    def test_rsa_str_password(self, rsa_key: rsa.RSAPrivateKey) -> None:
        pw = "hunter2"
        text = rsa_key.to_pkcs8_pem(password=pw, iterations=ITER)
        assert rsa.RSAPrivateKey.from_pem(text, password=pw) == rsa_key
        assert rsa.RSAPrivateKey.from_pem(text, password=pw.encode()) == rsa_key

    def test_ec_der_and_pem(self, ec_key: ec.ECPrivateKey) -> None:
        der = ec_key.to_pkcs8_der(password=PASSWORD, iterations=ITER)
        assert ec.ECPrivateKey.from_der(der, password=PASSWORD) == ec_key
        text = ec_key.to_pkcs8_pem(password=PASSWORD, iterations=ITER)
        assert "ENCRYPTED PRIVATE KEY" in text
        assert ec.ECPrivateKey.from_pem(text, password=PASSWORD) == ec_key

    def test_unencrypted_unchanged(self, rsa_key: rsa.RSAPrivateKey) -> None:
        # password=None keeps the byte-identical historical output
        assert rsa_key.to_pkcs8_der(password=None) == rsa_key.to_pkcs8_der()
        assert rsa_key.to_pkcs8_pem(password=None) == rsa_key.to_pkcs8_pem()

    def test_default_iterations_once(self, ec_key: ec.ECPrivateKey) -> None:
        # Exercise the 600k-iteration default path once, end to end.
        der = ec_key.to_pkcs8_der(password=PASSWORD)
        assert ec.ECPrivateKey.from_der(der, password=PASSWORD) == ec_key


class TestOpenSSLFixtures:
    def test_rsa_encrypted_pem(self, rsa_key: rsa.RSAPrivateKey) -> None:
        loaded = rsa.RSAPrivateKey.from_pem(_fixture("rsa_enc.pem"), password=PASSWORD)
        assert loaded == rsa_key

    def test_rsa_aes128_sha512(self, rsa_key: rsa.RSAPrivateKey) -> None:
        loaded = rsa.RSAPrivateKey.from_pem(
            _fixture("rsa_enc_aes128_sha512.pem"), password=PASSWORD
        )
        assert loaded == rsa_key

    def test_ec_encrypted_pem(self, ec_key: ec.ECPrivateKey) -> None:
        loaded = ec.ECPrivateKey.from_pem(_fixture("ec_enc.pem"), password=PASSWORD)
        assert loaded == ec_key

    def test_ec_aes192_sha224(self, ec_key: ec.ECPrivateKey) -> None:
        loaded = ec.ECPrivateKey.from_pem(
            _fixture("ec_enc_aes192_sha224.pem"), password=PASSWORD
        )
        assert loaded == ec_key

    def test_ec_default_prf(self, ec_key: ec.ECPrivateKey) -> None:
        loaded = ec.ECPrivateKey.from_pem(
            _fixture("ec_enc_default_prf.pem"), password=PASSWORD
        )
        assert loaded == ec_key

    def test_raw_decrypt_matches_pki(self) -> None:
        inner = _pbes2.pbes2_decrypt(_fixture_der("ec_enc.pem"), PASSWORD)
        assert inner == _fixture_der("ec_pkcs8.pem")


@pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")
class TestOpenSSLCrossCheck:
    def test_openssl_decrypts_our_rsa(self, rsa_key: rsa.RSAPrivateKey) -> None:
        assert OPENSSL is not None
        enc = rsa_key.to_pkcs8_pem(password=PASSWORD, iterations=ITER)
        proc = subprocess.run(
            [OPENSSL, "pkcs8", "-passin", f"pass:{PASSWORD.decode()}"],
            input=enc.encode(),
            capture_output=True,
        )
        assert proc.returncode == 0
        assert rsa.RSAPrivateKey.from_pem(proc.stdout) == rsa_key

    def test_openssl_decrypts_our_ec(self, ec_key: ec.ECPrivateKey) -> None:
        assert OPENSSL is not None
        enc = ec_key.to_pkcs8_pem(password=PASSWORD, iterations=ITER)
        proc = subprocess.run(
            [OPENSSL, "pkcs8", "-passin", f"pass:{PASSWORD.decode()}"],
            input=enc.encode(),
            capture_output=True,
        )
        assert proc.returncode == 0
        assert ec.ECPrivateKey.from_pem(proc.stdout) == ec_key


class TestUniformFailure:
    def test_wrong_password(self, rsa_key: rsa.RSAPrivateKey) -> None:
        enc = rsa_key.to_pkcs8_pem(password=PASSWORD, iterations=ITER)
        with pytest.raises(InvalidKey, match="decryption failed"):
            rsa.RSAPrivateKey.from_pem(enc, password=b"wrong")
        with pytest.raises(InvalidKey, match="decryption failed"):
            _pbes2.pbes2_decrypt(_fixture_der("rsa_enc.pem"), b"wrong")

    def test_no_password(self, rsa_key: rsa.RSAPrivateKey) -> None:
        enc = rsa_key.to_pkcs8_pem(password=PASSWORD, iterations=ITER)
        with pytest.raises(InvalidKey, match="requires a password"):
            rsa.RSAPrivateKey.from_pem(enc)
        with pytest.raises(InvalidKey, match="requires a password"):
            rsa.RSAPrivateKey.from_der(pem.decode_pem(enc)[1])
        with pytest.raises(InvalidKey, match="requires a password"):
            ec.ECPrivateKey.from_pem(_fixture("ec_enc.pem"))

    def test_bad_params_uniform_error(self, rsa_key: rsa.RSAPrivateKey) -> None:
        der = rsa_key.to_pkcs8_der(password=PASSWORD, iterations=ITER)
        kids = asn1.sequence_value(asn1.decode(der))
        alg = asn1.sequence_value(kids[0])
        params = asn1.sequence_value(alg[1])
        ct = asn1.encode_tlv(kids[1].tag, kids[1].content)

        def bake(alg_seq: bytes) -> bytes:
            return asn1.encode_sequence(
                asn1.encode_sequence(asn1.encode_oid("1.2.840.113549.1.5.13"), alg_seq),
                ct,
            )

        kdf_enc = asn1.encode_tlv(params[0].tag, params[0].content)
        enc_enc = asn1.encode_tlv(params[1].tag, params[1].content)

        # unknown PRF oid
        bad_prf = asn1.encode_sequence(
            asn1.encode_octet_string(b"s" * 16),
            asn1.encode_integer(1000),
            asn1.encode_sequence(asn1.encode_oid("1.2.3.4"), asn1.encode_null()),
        )
        bad_kdf = asn1.encode_sequence(
            asn1.encode_oid("1.2.840.113549.1.5.12"), bad_prf
        )
        with pytest.raises(InvalidKey, match="decryption failed"):
            _pbes2.pbes2_decrypt(bake(asn1.encode_sequence(bad_kdf, enc_enc)), PASSWORD)

        # unknown cipher oid (des-EDE3-CBC)
        bad_enc = asn1.encode_sequence(
            asn1.encode_oid("1.2.840.113549.3.7"),
            asn1.encode_octet_string(b"\x00" * 16),
        )
        with pytest.raises(InvalidKey, match="decryption failed"):
            _pbes2.pbes2_decrypt(bake(asn1.encode_sequence(kdf_enc, bad_enc)), PASSWORD)

        # absurd iteration count is rejected before doing the work
        huge = asn1.encode_sequence(
            asn1.encode_octet_string(b"s" * 16),
            asn1.encode_integer(2**40),
        )
        bad_kdf = asn1.encode_sequence(asn1.encode_oid("1.2.840.113549.1.5.12"), huge)
        with pytest.raises(InvalidKey, match="decryption failed"):
            _pbes2.pbes2_decrypt(bake(asn1.encode_sequence(bad_kdf, enc_enc)), PASSWORD)

        # not even EncryptedPrivateKeyInfo shape
        with pytest.raises(InvalidKey, match="decryption failed"):
            _pbes2.pbes2_decrypt(rsa_key.to_pkcs8_der(), PASSWORD)
        with pytest.raises(InvalidKey, match="decryption failed"):
            _pbes2.pbes2_decrypt(b"\x30\x00", PASSWORD)

    def _pbes2_blob(self, kdf_alg: bytes, enc_alg: bytes, ct: bytes) -> bytes:
        return asn1.encode_sequence(
            asn1.encode_sequence(
                asn1.encode_oid("1.2.840.113549.1.5.13"),
                asn1.encode_sequence(kdf_alg, enc_alg),
            ),
            asn1.encode_octet_string(ct),
        )

    def _kdf_alg(self, *params: bytes) -> bytes:
        return asn1.encode_sequence(
            asn1.encode_oid("1.2.840.113549.1.5.12"), asn1.encode_sequence(*params)
        )

    def _enc_alg(
        self, oid: str = "2.16.840.1.101.3.4.1.42", iv: bytes = b"i" * 16
    ) -> bytes:
        return asn1.encode_sequence(asn1.encode_oid(oid), asn1.encode_octet_string(iv))

    def test_param_variants_uniform_error(self) -> None:
        salt = asn1.encode_octet_string(b"s" * 16)
        iters = asn1.encode_integer(1000)
        keylen = asn1.encode_integer(32)
        prf = asn1.encode_sequence(
            asn1.encode_oid("1.2.840.113549.2.9"), asn1.encode_null()
        )
        good_kdf = self._kdf_alg(salt, iters, keylen, prf)
        good_enc = self._enc_alg()
        ct = os.urandom(64)

        cases = [
            # keyDerivationFunc is not PBKDF2
            self._pbes2_blob(
                asn1.encode_sequence(asn1.encode_oid("1.2.3.4")), good_enc, ct
            ),
            # PBKDF2 params with too few or too many elements
            self._pbes2_blob(self._kdf_alg(salt), good_enc, ct),
            self._pbes2_blob(
                self._kdf_alg(salt, iters, keylen, prf, prf), good_enc, ct
            ),
            # salt carried as otherSource (a SEQUENCE) is unsupported
            self._pbes2_blob(
                self._kdf_alg(asn1.encode_sequence(), iters), good_enc, ct
            ),
            # keyLength inconsistent with the cipher
            self._pbes2_blob(
                self._kdf_alg(salt, iters, asn1.encode_integer(16), prf),
                good_enc,
                ct,
            ),
            # keyLength zero
            self._pbes2_blob(
                self._kdf_alg(salt, iters, asn1.encode_integer(0), prf),
                good_enc,
                ct,
            ),
            # prf params must be NULL when present
            self._pbes2_blob(
                self._kdf_alg(
                    salt,
                    iters,
                    keylen,
                    asn1.encode_sequence(
                        asn1.encode_oid("1.2.840.113549.2.9"),
                        asn1.encode_octet_string(b"x"),
                    ),
                ),
                good_enc,
                ct,
            ),
            # prf AlgorithmIdentifier with no oid
            self._pbes2_blob(
                self._kdf_alg(salt, iters, keylen, asn1.encode_sequence()),
                good_enc,
                ct,
            ),
            # a stray non-INTEGER non-SEQUENCE field in PBKDF2-params
            self._pbes2_blob(
                self._kdf_alg(salt, iters, asn1.encode_null()), good_enc, ct
            ),
            # encryptionScheme with missing or extra children
            self._pbes2_blob(
                good_kdf,
                asn1.encode_sequence(asn1.encode_oid("2.16.840.1.101.3.4.1.42")),
                ct,
            ),
            # IV of the wrong length
            self._pbes2_blob(good_kdf, self._enc_alg(iv=b"short"), ct),
            # empty and misaligned ciphertexts
            self._pbes2_blob(good_kdf, good_enc, b""),
            self._pbes2_blob(good_kdf, good_enc, os.urandom(17)),
            # PBES2 params must hold exactly two AlgorithmIdentifiers
            asn1.encode_sequence(
                asn1.encode_sequence(
                    asn1.encode_oid("1.2.840.113549.1.5.13"),
                    asn1.encode_sequence(good_kdf),
                ),
                asn1.encode_octet_string(ct),
            ),
            # outer algorithm oid is not PBES2
            asn1.encode_sequence(
                asn1.encode_sequence(
                    asn1.encode_oid("1.2.3.4"),
                    asn1.encode_sequence(good_kdf, good_enc),
                ),
                asn1.encode_octet_string(ct),
            ),
        ]
        for blob in cases:
            with pytest.raises(InvalidKey, match="decryption failed"):
                _pbes2.pbes2_decrypt(blob, PASSWORD)

    def test_absent_prf_defaults_to_sha1(self) -> None:
        # Craft a PBKDF2-params without the optional prf field, meaning
        # hmacWithSHA1, and confirm the key derivation honors it.
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = kdf.pbkdf2(PASSWORD, salt, 100, 32, "sha1")
        pki = ec.ECPrivateKey.generate(ec.P256).to_pkcs8_der()
        ct = aes.cbc_encrypt(key, iv, aes.pkcs7_pad(pki))
        blob = self._pbes2_blob(
            self._kdf_alg(
                asn1.encode_octet_string(salt),
                asn1.encode_integer(100),
                asn1.encode_integer(32),
            ),
            self._enc_alg(iv=iv),
            ct,
        )
        assert _pbes2.pbes2_decrypt(blob, PASSWORD) == pki

    def test_plaintext_sanity_check(self) -> None:
        # PBES2 has no MAC: a syntactically valid blob whose plaintext is
        # not a PrivateKeyInfo must still fail with the uniform error.
        blob = _pbes2.pbes2_encrypt(b"\x30" * 48, PASSWORD, iterations=100)
        with pytest.raises(InvalidKey, match="decryption failed"):
            _pbes2.pbes2_decrypt(blob, PASSWORD)

    def test_random_ciphertext_uniform(self, rsa_key: rsa.RSAPrivateKey) -> None:
        # Well-formed params over a random ciphertext: padding or the
        # PrivateKeyInfo sanity check catches it, always the same error.
        kids = asn1.sequence_value(
            asn1.decode(rsa_key.to_pkcs8_der(password=PASSWORD, iterations=ITER))
        )
        alg = asn1.encode_tlv(kids[0].tag, kids[0].content)
        for _ in range(20):
            size = 16 * (1 + secrets.randbelow(8))
            blob = asn1.encode_sequence(alg, asn1.encode_octet_string(os.urandom(size)))
            with pytest.raises(InvalidKey, match="decryption failed"):
                _pbes2.pbes2_decrypt(blob, PASSWORD)


class TestFuzz:
    """Malformed input only ever yields purecrypt typed exceptions."""

    def test_random_garbage(self) -> None:
        for _ in range(100):
            blob = os.urandom(secrets.randbelow(400))
            with contextlib.suppress(PureCryptError):
                _pbes2.pbes2_decrypt(blob, PASSWORD)

    def test_mutated_valid(self) -> None:
        blob = bytearray(_fixture_der("rsa_enc.pem"))
        # Mutate only the tail (the ciphertext region): fields parsed
        # before it include the iteration count, which an attacker could
        # otherwise inflate to pin the CPU in PBKDF2.
        for _ in range(150):
            buf = bytearray(blob)
            pos = len(buf) // 2 + secrets.randbelow(len(buf) - len(buf) // 2)
            buf[pos] = secrets.randbelow(256)
            with contextlib.suppress(PureCryptError):
                _pbes2.pbes2_decrypt(bytes(buf), PASSWORD)
            with contextlib.suppress(PureCryptError):
                rsa.RSAPrivateKey.from_der(bytes(buf), password=PASSWORD)

    def test_truncations(self) -> None:
        blob = _fixture_der("rsa_enc.pem")
        for cut in range(0, len(blob), 37):
            with contextlib.suppress(PureCryptError):
                _pbes2.pbes2_decrypt(blob[:cut], PASSWORD)

    def test_from_pem_garbage_labels(self) -> None:
        for _ in range(50):
            blob = os.urandom(secrets.randbelow(300))
            text = pem.encode_pem("ENCRYPTED PRIVATE KEY", blob)
            with contextlib.suppress(PureCryptError):
                rsa.RSAPrivateKey.from_pem(text, password=PASSWORD)
            with contextlib.suppress(PureCryptError):
                ec.ECPrivateKey.from_pem(text, password=PASSWORD)

    def test_label_enforcement_unchanged(self) -> None:
        # A PUBLIC KEY block still cannot be loaded as a private key.
        with pytest.raises(InvalidSerialization):
            rsa.RSAPrivateKey.from_pem(
                pem.encode_pem("PUBLIC KEY", _fixture_der("rsa_pkcs8.pem"))
            )
        with pytest.raises(InvalidSerialization):
            ec.ECPrivateKey.from_pem(
                pem.encode_pem("RSA PRIVATE KEY", _fixture_der("ec_pkcs8.pem"))
            )
