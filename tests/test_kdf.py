# SPDX-License-Identifier: 0BSD
"""KDF tests: RFC 5869 (HKDF), RFC 6070/8018 (PBKDF2), RFC 7914 (scrypt),
RFC 9106 (Argon2), plus cross-checks against hashlib and argon2-cffi-
generated digests.
"""

import hashlib
import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from purecrypt import kdf
from purecrypt.exceptions import InvalidTag


def _b(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr)


# ------------------------------------------------------------------ HKDF


def test_hkdf_rfc5869_case1() -> None:
    prk = kdf.hkdf_extract("sha256", _b("000102030405060708090a0b0c"), _b("0b" * 22))
    assert prk == _b("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    okm = kdf.hkdf_expand("sha256", prk, _b("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm == _b(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_hkdf_rfc5869_case2() -> None:
    ikm = bytes(range(0x50))
    salt = bytes(range(0x60, 0xB0))
    info = bytes(range(0xB0, 0x100))
    okm = kdf.hkdf("sha256", ikm, salt, info, 82)
    assert okm == _b(
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87"
    )


def test_hkdf_rfc5869_case3() -> None:
    # zero-length salt and info. Passing salt=None is equivalent per RFC
    okm = kdf.hkdf("sha256", _b("0b" * 22), b"", b"", 42)
    assert okm == _b(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )
    assert okm == kdf.hkdf("sha256", _b("0b" * 22), None, b"", 42)


def test_hkdf_rfc5869_case7() -> None:
    # SHA-1, salt not provided (HashLen zeros), empty info
    okm = kdf.hkdf("sha1", _b("0c" * 22), None, b"", 42)
    assert okm == _b(
        "2c91117204d745f3500d636a62f64f0a"
        "b3bae548aa53d423b0d1f27ebba6f5e5"
        "673a081d70cce7acfc48"
    )


def test_hkdf_callable_digest_and_length_bounds() -> None:
    out = kdf.hkdf(hashlib.sha512, b"ikm", b"salt", b"info", 100)
    assert len(out) == 100
    with pytest.raises(ValueError, match="255"):
        kdf.hkdf_expand("sha256", bytes(32), b"", 255 * 32 + 1)
    assert kdf.hkdf_expand("sha256", bytes(32), b"", 0) == b""


# ---------------------------------------------------------------- PBKDF2


@pytest.mark.parametrize(
    ("iterations", "expected"),
    [
        pytest.param(1, "0c60c80f961f0e71f3a9b524af6012062fe037a6", id="c1"),
        pytest.param(2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", id="c2"),
        pytest.param(4096, "4b007901b765489abead49d926f721d065a429c1", id="c4096"),
    ],
)
def test_pbkdf2_rfc6070(iterations: int, expected: str) -> None:
    assert kdf.pbkdf2(b"password", b"salt", iterations, 20, "sha1") == _b(expected)


def test_pbkdf2_long_block() -> None:
    # dklen > hash length exercises multiple blocks (RFC 6070 case 5)
    out = kdf.pbkdf2(
        b"passwordPASSWORDpassword",
        b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
        4096,
        25,
        "sha1",
    )
    assert out == _b("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")


@settings(max_examples=30, deadline=None)
@given(
    pw=st.binary(max_size=64),
    salt=st.binary(max_size=64),
    iterations=st.integers(min_value=1, max_value=300),
    dklen=st.integers(min_value=1, max_value=100),
    digest=st.sampled_from(["sha1", "sha256", "sha384", "sha512"]),
)
def test_prop_pbkdf2_matches_hashlib(
    pw: bytes, salt: bytes, iterations: int, dklen: int, digest: str
) -> None:
    assert kdf.pbkdf2(pw, salt, iterations, dklen, digest) == hashlib.pbkdf2_hmac(
        digest, pw, salt, iterations, dklen
    )


def test_pbkdf2_validation() -> None:
    with pytest.raises(ValueError, match="iterations"):
        kdf.pbkdf2(b"pw", b"salt", 0, 32)
    with pytest.raises(ValueError, match="dklen"):
        kdf.pbkdf2(b"pw", b"salt", 1, 0)


# ---------------------------------------------------------------- scrypt


def test_scrypt_rfc7914_empty() -> None:
    out = kdf.scrypt(b"", b"", n=16, r=1, p=1, dklen=64)
    assert out == _b(
        "77d6576238657b203b19ca42c18a0497"
        "f16b4844e3074ae8dfdffa3fede21442"
        "fcd0069ded0948f8326a753a0fc81f17"
        "e8d3e0fb2e0d3628cf35e20c38d18906"
    )


def test_scrypt_rfc7914_password() -> None:
    out = kdf.scrypt(b"password", b"NaCl", n=1024, r=8, p=16, dklen=64)
    assert out == _b(
        "fdbabe1c9d3472007856e7190d01e9fe"
        "7c6ad7cbc8237830e77376634b373162"
        "2eaf30d92e22a3886ff109279d9830da"
        "c727afb94a83ee6d8360cbdfa2cc0640"
    )


def test_scrypt_rfc7914_pleaseletmein() -> None:
    out = kdf.scrypt(b"pleaseletmein", b"SodiumChloride", n=16384, r=8, p=1, dklen=64)
    assert out == _b(
        "7023bdcb3afd7348461c06cd81fd38eb"
        "fda8fbba904f8e3ea9b543f6545da1f2"
        "d5432955613f0fcf62d49705242a9af9"
        "e61e85dc0d651e40dfcf017b45575887"
    )


def test_scrypt_validation() -> None:
    with pytest.raises(ValueError, match="power of two"):
        kdf.scrypt(b"p", b"s", n=15)
    with pytest.raises(ValueError, match="power of two"):
        kdf.scrypt(b"p", b"s", n=1)
    with pytest.raises(ValueError, match=">= 1"):
        kdf.scrypt(b"p", b"s", n=16, r=0)
    with pytest.raises(ValueError, match=">= 1"):
        kdf.scrypt(b"p", b"s", n=16, p=0)
    with pytest.raises(ValueError, match="dklen"):
        kdf.scrypt(b"p", b"s", n=16, dklen=0)
    with pytest.raises(ValueError, match="bounds"):
        kdf.scrypt(b"p", b"s", n=1 << 30, r=1, p=1 << 27)


# ---------------------------------------------------------------- Argon2

_PW = b"\x01" * 32
_SALT = b"\x02" * 16
_SECRET = b"\x03" * 8
_AD = b"\x04" * 12


@pytest.mark.parametrize(
    ("variant", "expected"),
    [
        pytest.param(
            kdf.ARGON2D,
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
            id="argon2d",
        ),
        pytest.param(
            kdf.ARGON2I,
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
            id="argon2i",
        ),
        pytest.param(
            kdf.ARGON2ID,
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            id="argon2id",
        ),
    ],
)
def test_argon2_rfc9106(variant: int, expected: str) -> None:
    # RFC 9106 section 5 vectors: m=32 KiB, t=3, p=4, T=32, v=0x13
    tag = kdf.argon2(
        _PW,
        _SALT,
        time_cost=3,
        memory_cost=32,
        parallelism=4,
        tag_length=32,
        variant=variant,
        secret=_SECRET,
        associated_data=_AD,
    )
    assert tag == _b(expected)


def test_argon2id_reference_vector() -> None:
    # cross-verified against argon2-cffi (libsodium ref impl)
    tag = kdf.argon2id(
        b"password", b"somesalt", time_cost=2, memory_cost=1024, parallelism=2
    )
    assert tag == _b("9047cd41b3ef93a43b868916e89aef9f53236fd91d4ff23b3975432acbe26b39")


def test_argon2_long_tag() -> None:
    # tag_length 100 exercises the H' iterated path (RFC 9106 3.3).
    # cross-verified against argon2-cffi
    tag = kdf.argon2(
        b"password",
        b"0123456789abcdef",
        time_cost=2,
        memory_cost=256,
        parallelism=2,
        tag_length=100,
        variant=kdf.ARGON2ID,
    )
    assert tag == _b(
        "c3d7fa4f86b984117c925549e4806cd1"
        "438c4c24d57c577629e205429919997a"
        "d3cf7d0a229193fef44212f108a827ac"
        "390680eee6b7a1a767f9b3bd232a3317"
        "caa1ef7b1551af1573076e3e75e67992"
        "b6045fd4dd4e8422804ba1f892cc9849"
        "531c76a1"
    )


def test_argon2_single_lane() -> None:
    tag = kdf.argon2id(b"pw", b"salt", time_cost=1, memory_cost=64, parallelism=1)
    assert len(tag) == 32
    kdf.verify_argon2(
        b"pw",
        tag,
        b"salt",
        time_cost=1,
        memory_cost=64,
        parallelism=1,
        variant=kdf.ARGON2ID,
    )
    with pytest.raises(InvalidTag):
        kdf.verify_argon2(
            b"wrong",
            tag,
            b"salt",
            time_cost=1,
            memory_cost=64,
            parallelism=1,
            variant=kdf.ARGON2ID,
        )


def test_argon2_validation() -> None:
    with pytest.raises(ValueError, match="parallelism"):
        kdf.argon2(b"p", b"s", parallelism=0)
    with pytest.raises(ValueError, match="tag_length"):
        kdf.argon2(b"p", b"s", tag_length=3)
    with pytest.raises(ValueError, match="memory_cost"):
        kdf.argon2(b"p", b"s", memory_cost=8, parallelism=4)
    with pytest.raises(ValueError, match="time_cost"):
        kdf.argon2(b"p", b"s", time_cost=0)
    with pytest.raises(ValueError, match="variant"):
        kdf.argon2(b"p", b"s", variant=7)
    with pytest.raises(ValueError, match="version"):
        kdf.argon2(b"p", b"s", version=0x11)


@settings(max_examples=10, deadline=None)
@given(
    pw=st.binary(max_size=32),
    salt=st.binary(min_size=8, max_size=24),
)
def test_prop_argon2_deterministic(pw: bytes, salt: bytes) -> None:
    t1 = kdf.argon2id(pw, salt, time_cost=1, memory_cost=32, parallelism=1)
    t2 = kdf.argon2id(pw, salt, time_cost=1, memory_cost=32, parallelism=1)
    assert t1 == t2


def test_argon2_salt_changes_output() -> None:
    t1 = kdf.argon2id(b"pw", os.urandom(16), time_cost=1, memory_cost=32, parallelism=1)
    t2 = kdf.argon2id(b"pw", os.urandom(16), time_cost=1, memory_cost=32, parallelism=1)
    assert t1 != t2


def test_argon2i_long_segment_addressing() -> None:
    # segment_length 129 forces a second pass through the Argon2i
    # address-block generator (each block yields 128 J1/J2 pairs)
    tag = kdf.argon2(
        b"pw",
        b"salt",
        time_cost=1,
        memory_cost=516,
        parallelism=1,
        variant=kdf.ARGON2I,
    )
    assert len(tag) == 32
