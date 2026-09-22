# SPDX-License-Identifier: 0BSD
"""AES tests: FIPS-197 and SP 800-38A vectors, GCM AEAD, tamper, properties.

GCM inputs are the McGrew & Viega test-case inputs; expected outputs
were cross-verified against pyca/cryptography's AESGCM.
"""

import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from purecrypt import aes
from purecrypt.exceptions import InvalidCiphertext, InvalidKey, InvalidTag

PT1 = bytes.fromhex("00112233445566778899aabbccddeeff")
PT4 = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
KEY128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
KEY192 = bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
KEY256 = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
)
IV38A = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        pytest.param(
            "000102030405060708090a0b0c0d0e0f",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            id="aes128",
        ),
        pytest.param(
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
            id="aes192",
        ),
        pytest.param(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
            id="aes256",
        ),
    ],
)
def test_fips197_block(key: str, expected: str) -> None:
    k = bytes.fromhex(key)
    ct = aes.encrypt_block(k, PT1)
    assert ct == bytes.fromhex(expected)
    assert aes.decrypt_block(k, ct) == PT1


def test_block_roundtrip_all_key_sizes() -> None:
    for k in (bytes(16), bytes(range(16)), KEY128, KEY192, KEY256):
        assert aes.decrypt_block(k, aes.encrypt_block(k, PT1)) == PT1


def test_bad_key_lengths() -> None:
    for bad in (b"", b"\x00" * 15, b"\x00" * 17, b"\x00" * 33, b"\x00" * 64):
        with pytest.raises(InvalidKey):
            aes.encrypt_block(bad, PT1)
    with pytest.raises(InvalidKey):
        aes.AES(b"short")


def test_bad_block_size() -> None:
    cipher = aes.AES(KEY128)
    assert cipher.block_size == 16
    with pytest.raises(ValueError, match="16 bytes"):
        cipher.encrypt_block(b"too short")
    with pytest.raises(ValueError, match="16 bytes"):
        cipher.decrypt_block(b"too short")


def test_ecb() -> None:
    ct = aes.ecb_encrypt(KEY128, PT4)
    assert ct[:16] == bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    assert aes.ecb_decrypt(KEY128, ct) == PT4
    with pytest.raises(ValueError, match="multiple of 16"):
        aes.ecb_encrypt(KEY128, b"not aligned")
    with pytest.raises(InvalidCiphertext):
        aes.ecb_decrypt(KEY128, b"not aligned")


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        pytest.param(
            KEY128,
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7",
            id="cbc-128",
        ),
        pytest.param(
            KEY192,
            "4f021db243bc633d7178183a9fa071e8"
            "b4d9ada9ad7dedf4e5e738763f69145a"
            "571b242012fb7ae07fa9baac3df102e0"
            "08b0e27988598881d920a9e64f5615cd",
            id="cbc-192",
        ),
        pytest.param(
            KEY256,
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
            "9cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461"
            "b2eb05e2c39be9fcda6c19078c6a9d1b",
            id="cbc-256",
        ),
    ],
)
def test_cbc_sp80038a(key: bytes, expected: str) -> None:
    ct = aes.cbc_encrypt(key, IV38A, PT4)
    assert ct == bytes.fromhex(expected)
    assert aes.cbc_decrypt(key, IV38A, ct) == PT4


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        pytest.param(
            KEY128,
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee",
            id="ctr-128",
        ),
        pytest.param(
            KEY192,
            "1abc932417521ca24f2b0459fe7e6e0b"
            "090339ec0aa6faefd5ccc2c6f4ce8e94"
            "1e36b26bd1ebc670d1bd1d665620abf7"
            "4f78a7f6d29809585a97daec58c6b050",
            id="ctr-192",
        ),
        pytest.param(
            KEY256,
            "601ec313775789a5b7a7f504bbf3d228"
            "f443e3ca4d62b59aca84e990cacaf5c5"
            "2b0930daa23de94ce87017ba2d84988d"
            "dfc9c58db67aada613c2dd08457941a6",
            id="ctr-256",
        ),
    ],
)
def test_ctr_sp80038a(key: bytes, expected: str) -> None:
    icb = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ct = aes.ctr_encrypt(key, icb, PT4)
    assert ct == bytes.fromhex(expected)
    assert aes.ctr_decrypt(key, icb, ct) == PT4


def test_ctr_nonzero_initial_counter() -> None:
    icb = (1 << 120).to_bytes(16, "big")
    pt = os.urandom(48)
    ct = aes.ctr_encrypt(KEY128, icb, pt)
    assert aes.ctr_decrypt(KEY128, icb, ct) == pt


def test_ctr_bad_counter_size() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        aes.ctr_encrypt(KEY128, b"short", b"data")


def test_cbc_bad_iv() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        aes.cbc_encrypt(KEY128, b"short", PT4)
    with pytest.raises(InvalidCiphertext):
        aes.cbc_decrypt(KEY128, b"short", PT4)


def test_pkcs7_block_size_bounds() -> None:
    with pytest.raises(ValueError, match="block_size"):
        aes.pkcs7_pad(b"x", block_size=0)
    with pytest.raises(ValueError, match="block_size"):
        aes.pkcs7_pad(b"x", block_size=256)
    with pytest.raises(ValueError, match="block_size"):
        aes.pkcs7_unpad(bytes(16), block_size=0)
    with pytest.raises(ValueError, match="block_size"):
        aes.pkcs7_unpad(bytes(16), block_size=256)


def test_pkcs7_roundtrip() -> None:
    for n in (0, 1, 15, 16, 17, 32, 255):
        data = bytes(range(n)) if n <= 256 else bytes(n)
        padded = aes.pkcs7_pad(data)
        assert len(padded) % 16 == 0
        assert aes.pkcs7_unpad(padded) == data


def test_pkcs7_pad_full_block() -> None:
    padded = aes.pkcs7_pad(bytes(16))
    assert padded == bytes(16) + bytes([16]) * 16


def test_pkcs7_unpad_rejects_all_corruptions() -> None:
    padded = aes.pkcs7_pad(b"hello world")
    pad_len = padded[-1]
    # corrupt each byte inside the padding region only; data bytes are
    # unauthenticated by definition and are covered by AEAD tests
    for i in range(len(padded) - pad_len, len(padded)):
        for flip in (0x01, 0x80, 0xFF):
            bad = bytearray(padded)
            bad[i] ^= flip
            with pytest.raises(InvalidCiphertext):
                aes.pkcs7_unpad(bytes(bad))
    for bad_input in (b"", b"\x00" * 16, bytes([32]) * 16, b"short"):
        with pytest.raises(InvalidCiphertext):
            aes.pkcs7_unpad(bad_input)


def test_pkcs7_unpad_single_exception_type() -> None:
    # uniform failure surface: any malformed pad raises the same type
    padded = bytearray(aes.pkcs7_pad(b"data"))
    padded[-1] ^= 1
    with pytest.raises(InvalidCiphertext) as excinfo:
        aes.pkcs7_unpad(bytes(padded))
    assert type(excinfo.value) is InvalidCiphertext


# ------------------------------------------------------------ GCM KATs
# Inputs: McGrew & Viega GCM test cases. Outputs cross-verified against
# pyca/cryptography AESGCM (which embeds the published vectors).

_GCM_KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
_GCM_P = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9538534f7da1e4c303d2a318a72"
    "8c3c0c95156809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b391aafd255"
)
_GCM_A = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")


def test_gcm_case1_empty() -> None:
    ct, tag = aes.gcm_encrypt(bytes(16), bytes(12), b"")
    assert ct == b""
    assert tag == bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")
    assert aes.gcm_decrypt(bytes(16), bytes(12), ct, tag) == b""


def test_gcm_case2_zero_block() -> None:
    ct, tag = aes.gcm_encrypt(bytes(16), bytes(12), bytes(16))
    assert ct == bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
    assert tag == bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf")


def test_gcm_case3_no_aad() -> None:
    iv = bytes.fromhex("cafebabefacedbaddecaf888")
    ct, tag = aes.gcm_encrypt(_GCM_KEY, iv, _GCM_P)
    assert ct == bytes.fromhex(
        "42831ec2217774244b7221b784d0d49c"
        "e3aa212fbc02a4e005c17e2389aca12e"
        "b1d514b2d466931c7d8f6a5aac84aa05"
        "1ba30b396a0aac973d58e091473f5985"
    )
    assert tag == bytes.fromhex("95e6266797b5addefceda5b5fc9fec81")


def test_gcm_case4_with_aad() -> None:
    ct, tag = aes.gcm_encrypt(
        _GCM_KEY, bytes.fromhex("cafebabefacedbaddecaf888"), _GCM_P, _GCM_A
    )
    assert ct == bytes.fromhex(
        "42831ec2217774244b7221b784d0d49c"
        "e3aa212fbc02a4e005c17e2389aca12e"
        "b1d514b2d466931c7d8f6a5aac84aa05"
        "1ba30b396a0aac973d58e091473f5985"
    )
    assert tag == bytes.fromhex("023ac217bc85695572bce7a9a3765a43")
    assert (
        aes.gcm_decrypt(
            _GCM_KEY, bytes.fromhex("cafebabefacedbaddecaf888"), ct, tag, _GCM_A
        )
        == _GCM_P
    )


def test_gcm_case5_short_iv() -> None:
    # 64-bit nonce exercises the GHASH-based J0 path of SP 800-38D
    ct, tag = aes.gcm_encrypt(
        _GCM_KEY, bytes.fromhex("cafebabefacedbad"), _GCM_P, _GCM_A
    )
    assert ct == bytes.fromhex(
        "61353b4c2806934a777ff51fa22a47"
        "55699b2a71dfcdc6f80766e5f9db6c"
        "7423e3806900649f24b22b097544d4"
        "896b424989b5e1ebac0f07c23f4598"
        "59a3bdf3"
    )
    assert tag == bytes.fromhex("d5b42a6ce196dddb857920ea59b5c6ab")


def test_gcm_case6_long_iv() -> None:
    # 60-byte nonce also goes through GHASH J0
    iv = bytes.fromhex(
        "9313225df88406e555909c5aff5269"
        "aa6a7a9538534f7da1e4c303d2a318"
        "a728c3c0c95156809539fcf0e2429a"
        "6b525416aedbf5a0de6a57a637b39b"
    )
    ct, tag = aes.gcm_encrypt(_GCM_KEY, iv, _GCM_P, _GCM_A)
    assert ct == bytes.fromhex(
        "8ce24998625615b603a033aca13fb8"
        "94be9112a553a211a88a262a3c6a7e"
        "2ca791e4a9a47ba43c90ccdcb281d4"
        "8c7c6fd62875d2aca417034c34aee5"
        "8e18948e"
    )
    assert tag == bytes.fromhex("b5300c38ee834a7806646a1c1b5646e0")


def test_gcm_tamper_every_bit() -> None:
    key, nonce, aad = KEY128, os.urandom(12), os.urandom(20)
    pt = os.urandom(33)
    ct, tag = aes.gcm_encrypt(key, nonce, pt, aad)
    for i in range(len(tag) * 8):
        bad = bytearray(tag)
        bad[i // 8] ^= 1 << (i % 8)
        with pytest.raises(InvalidTag):
            aes.gcm_decrypt(key, nonce, ct, bytes(bad), aad)
    for i in range(len(ct) * 8):
        bad = bytearray(ct)
        bad[i // 8] ^= 1 << (i % 8)
        with pytest.raises(InvalidTag):
            aes.gcm_decrypt(key, nonce, bytes(bad), tag, aad)


def test_gcm_aad_tamper() -> None:
    key, nonce = KEY128, os.urandom(12)
    ct, tag = aes.gcm_encrypt(key, nonce, b"msg", b"aad1")
    with pytest.raises(InvalidTag):
        aes.gcm_decrypt(key, nonce, ct, tag, b"aad2")


def test_gcm_tag_truncation() -> None:
    key, nonce = KEY128, os.urandom(12)
    ct, tag = aes.gcm_encrypt(key, nonce, b"data", tag_length=8)
    assert len(tag) == 8
    assert aes.gcm_decrypt(key, nonce, ct, tag) == b"data"


def test_gcm_tag_length_bounds() -> None:
    with pytest.raises(ValueError, match="tag_length"):
        aes.gcm_encrypt(KEY128, bytes(12), b"", tag_length=3)
    with pytest.raises(ValueError, match="tag_length"):
        aes.gcm_encrypt(KEY128, bytes(12), b"", tag_length=17)
    with pytest.raises(InvalidCiphertext):
        aes.gcm_decrypt(KEY128, bytes(12), b"", b"\x00" * 3)


def test_gcm_nonce_bounds() -> None:
    with pytest.raises(ValueError, match="nonce"):
        aes.gcm_encrypt(KEY128, b"", b"")
    with pytest.raises(InvalidCiphertext):
        aes.gcm_decrypt(KEY128, b"", b"", bytes(16))
    # odd-but-legal nonce lengths take the GHASH J0 path
    for n in (1, 11, 13, 32):
        nonce = os.urandom(n)
        ct, tag = aes.gcm_encrypt(KEY128, nonce, b"pt")
        assert aes.gcm_decrypt(KEY128, nonce, ct, tag) == b"pt"


def test_gcm_wrong_key() -> None:
    with pytest.raises(InvalidKey):
        aes.gcm_encrypt(b"bad key", bytes(12), b"")
    with pytest.raises(InvalidKey):
        aes.gcm_decrypt(b"bad key", bytes(12), b"", bytes(16))


# ------------------------------------------------------- property tests


@settings(max_examples=40, deadline=None)
@given(
    key=st.binary(min_size=16, max_size=16)
    | st.binary(min_size=24, max_size=24)
    | st.binary(min_size=32, max_size=32),
    data=st.binary(min_size=0, max_size=128),
)
def test_prop_ecb_cbc_roundtrip(key: bytes, data: bytes) -> None:
    padded = aes.pkcs7_pad(data)
    assert aes.ecb_decrypt(key, aes.ecb_encrypt(key, padded)) == padded
    iv = bytes(16)
    ct = aes.cbc_encrypt(key, iv, padded)
    assert aes.pkcs7_unpad(aes.cbc_decrypt(key, iv, ct)) == data


@settings(max_examples=40, deadline=None)
@given(
    key=st.binary(min_size=16, max_size=16),
    ctr=st.integers(min_value=0, max_value=(1 << 128) - 256),
    data=st.binary(min_size=0, max_size=200),
)
def test_prop_ctr_roundtrip(key: bytes, ctr: int, data: bytes) -> None:
    icb = ctr.to_bytes(16, "big")
    ct = aes.ctr_encrypt(key, icb, data)
    assert aes.ctr_encrypt(key, icb, ct) == data


@settings(max_examples=30, deadline=None)
@given(
    key=st.binary(min_size=16, max_size=16),
    ctr=st.integers(min_value=0, max_value=(1 << 128) - 256),
    a=st.binary(min_size=0, max_size=64),
    b=st.binary(min_size=0, max_size=64),
)
def test_prop_ctr_keystream_consistency(
    key: bytes, ctr: int, a: bytes, b: bytes
) -> None:
    n = max(len(a), len(b))
    a, b = a.ljust(n, b"\x00"), b.ljust(n, b"\x00")
    icb = ctr.to_bytes(16, "big")
    xa = aes.ctr_encrypt(key, icb, a)
    xb = aes.ctr_encrypt(key, icb, b)
    # CTR(m) XOR CTR(m') == m XOR m': the keystream cancels out
    assert bytes(x ^ y for x, y in zip(xa, xb, strict=True)) == bytes(
        x ^ y for x, y in zip(a, b, strict=True)
    )


@settings(max_examples=40, deadline=None)
@given(
    key=st.binary(min_size=16, max_size=16)
    | st.binary(min_size=24, max_size=24)
    | st.binary(min_size=32, max_size=32),
    nonce=st.binary(min_size=1, max_size=20),
    aad=st.binary(max_size=64),
    pt=st.binary(max_size=128),
)
def test_prop_gcm_roundtrip(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> None:
    ct, tag = aes.gcm_encrypt(key, nonce, pt, aad)
    assert len(ct) == len(pt)
    assert aes.gcm_decrypt(key, nonce, ct, tag, aad) == pt


@settings(max_examples=25, deadline=None)
@given(
    key=st.binary(min_size=16, max_size=16),
    nonce=st.binary(min_size=12, max_size=12),
    aad1=st.binary(min_size=1, max_size=32),
    aad2=st.binary(min_size=1, max_size=32),
)
def test_prop_gcm_tag_depends_on_aad(
    key: bytes, nonce: bytes, aad1: bytes, aad2: bytes
) -> None:
    if aad1 == aad2:
        return
    _, t1 = aes.gcm_encrypt(key, nonce, b"same plaintext", aad1)
    _, t2 = aes.gcm_encrypt(key, nonce, b"same plaintext", aad2)
    assert t1 != t2


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 31, 32, 33, 64])
def test_boundary_lengths(n: int) -> None:
    key, nonce = KEY128, os.urandom(12)
    pt = os.urandom(n)
    ct, tag = aes.gcm_encrypt(key, nonce, pt)
    assert aes.gcm_decrypt(key, nonce, ct, tag) == pt
    assert aes.ctr_decrypt(key, bytes(16), aes.ctr_encrypt(key, bytes(16), pt)) == pt
