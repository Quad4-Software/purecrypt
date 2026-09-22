# SPDX-License-Identifier: 0BSD
"""ChaCha20/Poly1305 tests: RFC 8439 vectors, draft-xchacha, tamper, properties.

The XChaCha20-Poly1305 expected output was generated with libsodium
(PyNaCl crypto_aead_xchacha20poly1305_ietf_encrypt).
"""

import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from purecrypt import chacha
from purecrypt.exceptions import InvalidCiphertext, InvalidKey, InvalidTag

KEY32 = bytes(range(32))
NONCE12 = bytes.fromhex("000000000000004a00000000")
PT_RFC = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you "
    b"only one tip for the future, sunscreen would be it."
)


def test_chacha20_block_rfc8439_242() -> None:
    block = chacha.chacha20_block(KEY32, 1, bytes.fromhex("000000090000004a00000000"))
    assert block == bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )


def test_chacha20_encrypt_rfc8439_243() -> None:
    nonce = bytes.fromhex("000000000000004a00000000")
    ct = chacha.chacha20_xor(KEY32, nonce, PT_RFC, counter=1)
    assert ct == bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )
    assert chacha.chacha20_xor(KEY32, nonce, ct, counter=1) == PT_RFC


def test_poly1305_rfc8439_252() -> None:
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    )
    tag = chacha.poly1305_mac(key, b"Cryptographic Forum Research Group")
    assert tag == bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")


def test_poly1305_zero_key_msg() -> None:
    assert chacha.poly1305_mac(bytes(32), b"") == bytes(16)


def test_aead_rfc8439_282() -> None:
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    ct, tag = chacha.chacha20_poly1305_encrypt(key, nonce, PT_RFC, aad)
    assert ct == bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    )
    assert tag == bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
    assert chacha.chacha20_poly1305_decrypt(key, nonce, ct, tag, aad) == PT_RFC


def test_hchacha20_draft_vector() -> None:
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    assert chacha.hchacha20(KEY32, nonce) == bytes.fromhex(
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    )


def test_xchacha_libsodium_vector() -> None:
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555658")
    pt = b'The dhole (pronounced "dole") is also known as the Asiatic wild dog'
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    ct, tag = chacha.xchacha20_poly1305_encrypt(key, nonce, pt, aad)
    assert ct == bytes.fromhex(
        "7d0a2e6b7f7c65a236542630294e063b"
        "7ab9b555a5d5149aa21e4ae1e4fbce87"
        "ecc8e08a8b5e350abe622b2ffa617b20"
        "2cfad72032a3037e76ffdcdc4376ee05"
        "3a190d"
    )
    assert tag == bytes.fromhex("f1785106f20e3ec7157d4bf460891718")
    assert chacha.xchacha20_poly1305_decrypt(key, nonce, ct, tag, aad) == pt


def test_tamper_every_bit() -> None:
    key, nonce, aad = os.urandom(32), os.urandom(12), os.urandom(20)
    pt = os.urandom(33)
    ct, tag = chacha.chacha20_poly1305_encrypt(key, nonce, pt, aad)
    for i in range(len(tag) * 8):
        bad = bytearray(tag)
        bad[i // 8] ^= 1 << (i % 8)
        with pytest.raises(InvalidTag):
            chacha.chacha20_poly1305_decrypt(key, nonce, ct, bytes(bad), aad)
    for i in range(len(ct) * 8):
        bad = bytearray(ct)
        bad[i // 8] ^= 1 << (i % 8)
        with pytest.raises(InvalidTag):
            chacha.chacha20_poly1305_decrypt(key, nonce, bytes(bad), tag, aad)


def test_xchacha_tamper() -> None:
    key, nonce = os.urandom(32), os.urandom(24)
    ct, tag = chacha.xchacha20_poly1305_encrypt(key, nonce, b"secret", b"aad")
    bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
    with pytest.raises(InvalidTag):
        chacha.xchacha20_poly1305_decrypt(key, nonce, ct, bad_tag, b"aad")
    with pytest.raises(InvalidTag):
        chacha.xchacha20_poly1305_decrypt(key, nonce, ct, tag, b"different")


def test_aad_changes_tag() -> None:
    key, nonce = KEY32, os.urandom(12)
    _, t1 = chacha.chacha20_poly1305_encrypt(key, nonce, b"msg", b"aad1")
    _, t2 = chacha.chacha20_poly1305_encrypt(key, nonce, b"msg", b"aad2")
    assert t1 != t2


def test_empty_plaintext_roundtrip() -> None:
    nonce = os.urandom(12)
    ct, tag = chacha.chacha20_poly1305_encrypt(KEY32, nonce, b"")
    assert ct == b""
    assert chacha.chacha20_poly1305_decrypt(KEY32, nonce, ct, tag) == b""


def test_bad_key_and_nonce_lengths() -> None:
    with pytest.raises(InvalidKey):
        chacha.chacha20_xor(b"short", NONCE12, b"")
    with pytest.raises(InvalidKey):
        chacha.chacha20_poly1305_encrypt(b"short", NONCE12, b"")
    with pytest.raises(InvalidKey):
        chacha.poly1305_mac(b"short", b"")
    with pytest.raises(ValueError, match="12 bytes"):
        chacha.chacha20_xor(KEY32, b"bad nonce", b"")
    with pytest.raises(ValueError, match="12 bytes"):
        chacha.chacha20_poly1305_encrypt(KEY32, b"bad nonce", b"")
    with pytest.raises(InvalidCiphertext):
        chacha.chacha20_poly1305_decrypt(KEY32, b"bad nonce", b"", bytes(16))
    with pytest.raises(InvalidCiphertext):
        chacha.chacha20_poly1305_decrypt(KEY32, NONCE12, b"", b"short tag")
    with pytest.raises(ValueError, match="24 bytes"):
        chacha.xchacha20_poly1305_encrypt(KEY32, b"bad nonce", b"")
    with pytest.raises(InvalidCiphertext):
        chacha.xchacha20_poly1305_decrypt(KEY32, b"bad nonce", b"", bytes(16))
    with pytest.raises(ValueError, match="16 bytes"):
        chacha.hchacha20(KEY32, b"short")
    with pytest.raises(ValueError, match="32 bits"):
        chacha.chacha20_block(KEY32, 1 << 32, NONCE12)
    with pytest.raises(ValueError, match="12 bytes"):
        chacha.chacha20_block(KEY32, 1, b"bad nonce")


@settings(max_examples=40, deadline=None)
@given(
    key=st.binary(min_size=32, max_size=32),
    nonce=st.binary(min_size=12, max_size=12),
    data=st.binary(max_size=200),
    counter=st.integers(min_value=0, max_value=(1 << 32) - 8),
)
def test_prop_xor_self_inverse(
    key: bytes, nonce: bytes, data: bytes, counter: int
) -> None:
    ct = chacha.chacha20_xor(key, nonce, data, counter)
    assert chacha.chacha20_xor(key, nonce, ct, counter) == data


@settings(max_examples=40, deadline=None)
@given(
    key=st.binary(min_size=32, max_size=32),
    nonce=st.binary(min_size=12, max_size=12),
    aad=st.binary(max_size=64),
    pt=st.binary(max_size=128),
)
def test_prop_aead_roundtrip(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> None:
    ct, tag = chacha.chacha20_poly1305_encrypt(key, nonce, pt, aad)
    assert len(ct) == len(pt)
    assert chacha.chacha20_poly1305_decrypt(key, nonce, ct, tag, aad) == pt


@settings(max_examples=40, deadline=None)
@given(
    key=st.binary(min_size=32, max_size=32),
    nonce=st.binary(min_size=24, max_size=24),
    aad=st.binary(max_size=64),
    pt=st.binary(max_size=128),
)
def test_prop_xaead_roundtrip(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> None:
    ct, tag = chacha.xchacha20_poly1305_encrypt(key, nonce, pt, aad)
    assert chacha.xchacha20_poly1305_decrypt(key, nonce, ct, tag, aad) == pt


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 63, 64, 65, 128])
def test_boundary_lengths(n: int) -> None:
    nonce = os.urandom(12)
    pt = os.urandom(n)
    ct, tag = chacha.chacha20_poly1305_encrypt(KEY32, nonce, pt)
    assert chacha.chacha20_poly1305_decrypt(KEY32, nonce, ct, tag) == pt
