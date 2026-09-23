# SPDX-License-Identifier: 0BSD
"""Differential oracle tests against the cryptography package (pyca).

Every primitive where purecrypt and cryptography overlap is exercised
in both directions: ours encrypts or signs, theirs decrypts or
verifies, and vice versa. Skipped entirely if cryptography is not
installed.
"""

import secrets
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography.exceptions import InvalidSignature as TheirInvalidSignature
from cryptography.hazmat.primitives import hashes as ch
from cryptography.hazmat.primitives import hmac as chmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec as chec
from cryptography.hazmat.primitives.asymmetric import ed25519 as ched
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.asymmetric import rsa as chrsa
from cryptography.hazmat.primitives.asymmetric import x25519 as chx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from purecrypt import aes, chacha, ec, hashes, kdf, rsa
from purecrypt.eddsa import Ed25519PrivateKey
from purecrypt.exceptions import InvalidKey, InvalidSignature, InvalidTag
from purecrypt.x25519 import X25519PrivateKey

DATA = Path(__file__).parent / "data"
RSA_KEY_PEM = (DATA / "rsa_root_key.pem").read_bytes()


def _their_rsa_private() -> chrsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(RSA_KEY_PEM, password=None)
    assert isinstance(key, chrsa.RSAPrivateKey)
    return key


def _our_rsa_private() -> rsa.RSAPrivateKey:
    return rsa.RSAPrivateKey.from_pem(RSA_KEY_PEM)


# ------------------------------------------------------------------- AES


@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_aes_block_both_ways(key_size: int) -> None:
    key = secrets.token_bytes(key_size)
    block = secrets.token_bytes(16)
    ours = aes.encrypt_block(key, block)
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # noqa: S305
    theirs = cipher.encryptor().update(block)
    assert ours == theirs
    assert aes.decrypt_block(key, ours) == block


def test_aes_cbc_both_ways() -> None:
    key, iv = secrets.token_bytes(32), secrets.token_bytes(16)
    data = secrets.token_bytes(48)
    ours = aes.cbc_encrypt(key, iv, data)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    assert ours == enc.update(data) + enc.finalize()
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    assert dec.update(ours) + dec.finalize() == data


def test_aes_ctr_both_ways() -> None:
    key, ctr = secrets.token_bytes(16), secrets.token_bytes(16)
    data = secrets.token_bytes(200)
    ours = aes.ctr_encrypt(key, ctr, data)
    enc = Cipher(algorithms.AES(key), modes.CTR(ctr)).encryptor()
    assert ours == enc.update(data) + enc.finalize()
    dec = Cipher(algorithms.AES(key), modes.CTR(ctr)).decryptor()
    assert dec.update(ours) + dec.finalize() == data


def test_aes_gcm_both_ways() -> None:
    key, nonce, aad = secrets.token_bytes(32), secrets.token_bytes(12), b"hdr"
    data = secrets.token_bytes(100)
    ct, tag = aes.gcm_encrypt(key, nonce, data, aad)
    assert AESGCM(key).decrypt(nonce, ct + tag, aad) == data
    theirs = AESGCM(key).encrypt(nonce, data, aad)
    assert aes.gcm_decrypt(key, nonce, theirs[:-16], theirs[-16:], aad) == data


# ---------------------------------------------------------------- ChaCha


def test_chacha20_poly1305_both_ways() -> None:
    key, nonce, aad = secrets.token_bytes(32), secrets.token_bytes(12), b"aad"
    data = secrets.token_bytes(80)
    ct, tag = chacha.chacha20_poly1305_encrypt(key, nonce, data, aad)
    assert ChaCha20Poly1305(key).decrypt(nonce, ct + tag, aad) == data
    theirs = ChaCha20Poly1305(key).encrypt(nonce, data, aad)
    assert (
        chacha.chacha20_poly1305_decrypt(key, nonce, theirs[:-16], theirs[-16:], aad)
        == data
    )


# ----------------------------------------------------------------- EdDSA


def test_ed25519_cross_verify() -> None:
    seed = secrets.token_bytes(32)
    msg = secrets.token_bytes(64)
    ours = Ed25519PrivateKey.from_seed(seed)
    theirs = ched.Ed25519PrivateKey.from_private_bytes(seed)
    assert ours.public_key().public_bytes() == theirs.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    sig_ours = ours.sign(msg)
    theirs.public_key().verify(sig_ours, msg)

    sig_theirs = theirs.sign(msg)
    ours.public_key().verify(sig_theirs, msg)


def test_ed25519_rejects_bad_signature_both() -> None:
    seed = secrets.token_bytes(32)
    ours = Ed25519PrivateKey.from_seed(seed)
    theirs = ched.Ed25519PrivateKey.from_private_bytes(seed)
    sig = bytearray(ours.sign(b"m"))
    sig[10] ^= 1
    with pytest.raises(InvalidSignature):
        ours.public_key().verify(bytes(sig), b"m")
    with pytest.raises(TheirInvalidSignature):
        theirs.public_key().verify(bytes(sig), b"m")


# ----------------------------------------------------------------- X25519


def test_x25519_cross_exchange() -> None:
    ours_a = X25519PrivateKey.generate()
    ours_b = X25519PrivateKey.generate()
    theirs_a = chx.X25519PrivateKey.from_private_bytes(ours_a.private_bytes())
    theirs_b = chx.X25519PrivateKey.from_private_bytes(ours_b.private_bytes())

    ours_ab = ours_a.exchange(ours_b.public_key())
    theirs_ab = theirs_a.exchange(
        chx.X25519PublicKey.from_public_bytes(ours_b.public_key().public_bytes())
    )
    assert ours_ab == theirs_ab
    theirs_ba = theirs_b.exchange(
        chx.X25519PublicKey.from_public_bytes(ours_a.public_key().public_bytes())
    )
    assert theirs_ba == ours_ab
    assert ours_b.exchange(ours_a.public_key()) == ours_ab


# ------------------------------------------------------------------- KDF


def test_hkdf_matches() -> None:
    ikm, salt, info = secrets.token_bytes(40), secrets.token_bytes(16), b"i"
    for ours_name, theirs_alg in (
        ("sha256", ch.SHA256()),
        ("sha384", ch.SHA384()),
        ("sha512", ch.SHA512()),
    ):
        ours = kdf.hkdf(ours_name, ikm, salt, info, 64)
        theirs = HKDF(algorithm=theirs_alg, length=64, salt=salt, info=info).derive(ikm)
        assert ours == theirs


def test_pbkdf2_matches() -> None:
    password, salt = b"password", secrets.token_bytes(16)
    ours = kdf.pbkdf2(password, salt, 1000, 32, "sha256")
    theirs = PBKDF2HMAC(ch.SHA256(), 32, salt, 1000).derive(password)
    assert ours == theirs


def test_scrypt_matches() -> None:
    password, salt = b"password", secrets.token_bytes(16)
    ours = kdf.scrypt(password, salt, n=16384, r=8, p=1, dklen=64)
    theirs = Scrypt(salt=salt, length=64, n=16384, r=8, p=1).derive(password)
    assert ours == theirs


# ---------------------------------------------------------------- hashes


def test_hashes_match_hashlib_oracle() -> None:
    data = secrets.token_bytes(128)
    for ours_name, theirs_alg in (
        ("sha256", ch.SHA256()),
        ("sha384", ch.SHA384()),
        ("sha512", ch.SHA512()),
        ("sha3_256", ch.SHA3_256()),
        ("sha3_512", ch.SHA3_512()),
    ):
        ours = getattr(hashes, ours_name)(data)
        h = ch.Hash(theirs_alg)
        h.update(data)
        assert ours == h.finalize()


def test_hmac_matches() -> None:
    key, msg = secrets.token_bytes(40), secrets.token_bytes(90)
    ours = hashes.HMAC(key, msg, "sha256")
    h = chmac.HMAC(key, ch.SHA256())
    h.update(msg)
    assert ours == h.finalize()


# ------------------------------------------------------------------- RSA


def test_rsa_pss_both_ways() -> None:
    ours = _our_rsa_private()
    theirs = _their_rsa_private()
    msg = secrets.token_bytes(50)

    sig = ours.sign_pss(msg, "sha256")
    theirs.public_key().verify(
        sig,
        msg,
        asympadding.PSS(
            mgf=asympadding.MGF1(ch.SHA256()), salt_length=ch.SHA256.digest_size
        ),
        ch.SHA256(),
    )

    sig2 = theirs.sign(
        msg,
        asympadding.PSS(
            mgf=asympadding.MGF1(ch.SHA256()), salt_length=ch.SHA256.digest_size
        ),
        ch.SHA256(),
    )
    ours.public_key().verify_pss(sig2, msg, "sha256")


def test_rsa_v15_both_ways() -> None:
    ours = _our_rsa_private()
    theirs = _their_rsa_private()
    msg = secrets.token_bytes(50)

    sig = ours.sign_v15(msg, "sha256")
    theirs.public_key().verify(sig, msg, asympadding.PKCS1v15(), ch.SHA256())

    sig2 = theirs.sign(msg, asympadding.PKCS1v15(), ch.SHA256())
    ours.public_key().verify_v15(sig2, msg, "sha256")


def test_rsa_oaep_both_ways() -> None:
    ours = _our_rsa_private()
    theirs = _their_rsa_private()
    msg = secrets.token_bytes(30)

    ct = ours.public_key().encrypt_oaep(msg, "sha256")
    pad = asympadding.OAEP(
        mgf=asympadding.MGF1(ch.SHA256()), algorithm=ch.SHA256(), label=None
    )
    assert theirs.decrypt(ct, pad) == msg

    ct2 = theirs.public_key().encrypt(msg, pad)
    assert ours.decrypt_oaep(ct2, "sha256") == msg


def test_rsa_v15_encryption_both_ways() -> None:
    ours = _our_rsa_private()
    theirs = _their_rsa_private()
    msg = secrets.token_bytes(20)

    ct = ours.public_key().encrypt_v15(msg)
    assert theirs.decrypt(ct, asympadding.PKCS1v15()) == msg

    ct2 = theirs.public_key().encrypt(msg, asympadding.PKCS1v15())
    assert ours.decrypt_v15(ct2) == msg


# ------------------------------------------------------------------ ECDSA


def test_ecdsa_p256_cross_verify() -> None:
    ours = ec.ECPrivateKey.generate(ec.P256)
    msg = secrets.token_bytes(40)

    # our private bytes -> their key, so both sides share one key pair
    our_priv_int = int.from_bytes(ours.private_bytes(), "big")
    theirs_same = chec.derive_private_key(our_priv_int, chec.SECP256R1())
    assert ours.public_key().to_sec1_bytes() == theirs_same.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    sig_ours = ours.sign_ecdsa(msg, "sha256")
    theirs_same.public_key().verify(sig_ours, msg, chec.ECDSA(ch.SHA256()))

    sig_theirs = theirs_same.sign(msg, chec.ECDSA(ch.SHA256()))
    ours.public_key().verify_ecdsa(sig_theirs, msg, "sha256")


def test_ecdh_p256_matches() -> None:
    ours_a = ec.ECPrivateKey.generate(ec.P256)
    theirs_b = chec.generate_private_key(chec.SECP256R1())
    our_shared = ours_a.ecdh(
        theirs_b.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    their_shared = theirs_b.exchange(
        chec.ECDH(),
        chec.EllipticCurvePublicKey.from_encoded_point(
            chec.SECP256R1(), ours_a.public_key().to_sec1_bytes()
        ),
    )
    assert our_shared == their_shared


# ------------------------------------------------------ negative behavior


def test_invalid_signature_raises_ours() -> None:
    ours = _our_rsa_private()
    msg = b"message"
    sig = bytearray(ours.sign_v15(msg))
    sig[-1] ^= 1
    with pytest.raises(InvalidSignature):
        ours.public_key().verify_v15(bytes(sig), msg)


def test_gcm_tag_mismatch_raises_ours() -> None:
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    ct, tag = aes.gcm_encrypt(key, nonce, b"data")
    bad = bytearray(tag)
    bad[0] ^= 1
    with pytest.raises(InvalidTag):
        aes.gcm_decrypt(key, nonce, ct, bytes(bad))


def test_oaep_wrong_label_raises_ours() -> None:
    ours = _our_rsa_private()
    ct = ours.public_key().encrypt_oaep(b"m", "sha256", label=b"L1")
    with pytest.raises(InvalidKey):
        ours.decrypt_oaep(ct, "sha256", label=b"L2")
