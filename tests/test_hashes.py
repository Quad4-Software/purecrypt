# SPDX-License-Identifier: 0BSD
"""Known-answer tests for the hashlib facade."""

import hashlib
import hmac as stdlib_hmac

from purecrypt import hashes


def test_sha256() -> None:
    assert (
        hashes.sha256(b"abc").hex()
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert hashes.sha256(b"") == hashlib.sha256(b"").digest()


def test_sha384() -> None:
    assert (
        hashes.sha384(b"abc").hex()
        == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
        "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    )


def test_sha512() -> None:
    assert (
        hashes.sha512(b"abc").hex()
        == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2"
        "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f"
    )


def test_sha1_legacy() -> None:
    assert hashes.sha1(b"abc").hex() == "a9993e364706816aba3e25717850c26c9cd0d89d"


def test_md5_legacy() -> None:
    assert hashes.md5(b"abc").hex() == "900150983cd24fb0d6963f7d28e17f72"


def test_sha3() -> None:
    assert (
        hashes.sha3_256(b"abc").hex()
        == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    )
    assert (
        hashes.sha3_512(b"abc").hex()
        == "b751850b1a57168a5693cd924b6b096e08f621827444f70d"
        "884f5d0240d2712e10e116e9192af3c91a7ec57647e39340"
        "57340b4cf408d5a56592f8274eec53f0"
    )


def test_shake() -> None:
    assert (
        hashes.shake128(b"abc", 32).hex()
        == "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
    )
    assert (
        hashes.shake256(b"abc", 32).hex()
        == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
    )
    # different lengths of the same input share a prefix
    assert hashes.shake128(b"x", 16) == hashes.shake128(b"x", 32)[:16]


def test_blake2() -> None:
    assert (
        hashes.blake2b(b"abc").hex()
        == "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b7"
        "4b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc95"
        "18d38aa8dbf1925ab92386edd4009923"
    )
    assert (
        hashes.blake2s(b"abc").hex()
        == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a29"
        "4d999b4c86675982"
    )
    assert len(hashes.blake2b(b"x", digest_size=32)) == 32
    assert len(hashes.blake2s(b"x", digest_size=16)) == 16


def test_hmac_rfc4231_case2() -> None:
    # RFC 4231 test case 2: key = "Jefe", data = "what do ya want for nothing?"
    out = hashes.HMAC(b"Jefe", b"what do ya want for nothing?", "sha256")
    assert (
        out.hex() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


def test_hmac_rfc4231_case6() -> None:
    # RFC 4231 test case 6: key = 131 x 0xaa, ASCII message, sha256
    out = hashes.HMAC(
        bytes([0xAA]) * 131,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "sha256",
    )
    assert (
        out.hex() == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    )


def test_hmac_matches_stdlib() -> None:
    for name in ("sha1", "sha256", "sha384", "sha512", "md5"):
        assert hashes.HMAC(b"key", b"message", name) == stdlib_hmac.digest(
            b"key", b"message", name
        )


def test_hmac_callable_digest() -> None:
    # a hashlib-style constructor works as the digest spec too
    assert hashes.HMAC(b"key", b"msg", hashlib.sha512) == stdlib_hmac.digest(
        b"key", b"msg", hashlib.sha512
    )


def test_digest_size() -> None:
    assert hashes.digest_size("sha256") == 32
    assert hashes.digest_size("sha512") == 64
    assert hashes.digest_size(hashlib.sha384) == 48
