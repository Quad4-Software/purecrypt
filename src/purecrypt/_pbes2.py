# SPDX-License-Identifier: 0BSD
"""PBES2 password-encrypted PKCS#8 private keys (RFC 8018, RFC 5958).

Wraps PrivateKeyInfo DER into EncryptedPrivateKeyInfo using PBES2 with
PBKDF2 key derivation and AES-CBC with PKCS#7 padding. Encryption
always emits PBKDF2-HMAC-SHA256 at 600000 iterations (the OWASP
recommendation for that PRF) and AES-256-CBC, with 16-byte salt and IV
drawn from os.urandom. Decryption additionally accepts the SHA-1,
SHA-224, SHA-384 and SHA-512 PRFs and AES-128/192-CBC for interop with
other encoders.

WARNING: pure Python cannot provide constant-time guarantees. PBES2
over AES-CBC carries no integrity MAC, so a wrong password can yield
well-formed garbage and the only wrong-password signals are PKCS#7
padding plus a structural sanity check that the plaintext parses as
PrivateKeyInfo. Every failure mode collapses into the identical
InvalidKey("decryption failed") so no stage is distinguishable to the
caller. Do not use for production key storage.
"""

from __future__ import annotations

import os

from . import aes, asn1
from .exceptions import InvalidKey, PureCryptError, UnsupportedAlgorithm
from .kdf import pbkdf2

PEM_LABEL = "ENCRYPTED PRIVATE KEY"
DEFAULT_ITERATIONS = 600_000
_SALT_LEN = 16
_KEY_LEN = 32  # AES-256

# A ceiling on the declared PBKDF2 count bounds the work a hostile
# EncryptedPrivateKeyInfo can force during decryption.
_MAX_ITERATIONS = 10_000_000

_OID_PBKDF2 = "1.2.840.113549.1.5.12"
_OID_PBES2 = "1.2.840.113549.1.5.13"
_OID_AES256_CBC = "2.16.840.1.101.3.4.1.42"

_PRF_TO_OID = {
    "sha1": "1.2.840.113549.2.7",
    "sha224": "1.2.840.113549.2.8",
    "sha256": "1.2.840.113549.2.9",
    "sha384": "1.2.840.113549.2.10",
    "sha512": "1.2.840.113549.2.11",
}
_OID_TO_PRF = {oid: name for name, oid in _PRF_TO_OID.items()}

_ENCRYPT_PRFS = frozenset({"sha256", "sha384", "sha512"})

# AES-CBC cipher OIDs mapped to their key length in bytes.
_OID_TO_KEYLEN = {
    "2.16.840.1.101.3.4.1.2": 16,
    "2.16.840.1.101.3.4.1.22": 24,
    "2.16.840.1.101.3.4.1.42": 32,
}


def looks_encrypted(kids: tuple[asn1.DerNode, ...]) -> bool:
    """True when SEQUENCE children have EncryptedPrivateKeyInfo shape."""
    return (
        len(kids) == 2
        and kids[0].tag == asn1.TAG_SEQUENCE
        and kids[1].tag == asn1.TAG_OCTET_STRING
    )


def _password_bytes(password: bytes | str) -> bytes:
    if isinstance(password, str):
        return password.encode("utf-8")
    return bytes(password)


def pbes2_encrypt(
    private_key_info_der: bytes,
    password: bytes | str,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    hash_name: str = "sha256",
) -> bytes:
    """Wrap PrivateKeyInfo DER in a PBES2 EncryptedPrivateKeyInfo.

    Emits PBKDF2-HMAC with hash_name (sha256, sha384 or sha512) and
    AES-256-CBC. The default iteration count follows the OWASP
    recommendation for PBKDF2-HMAC-SHA256.
    """
    if hash_name not in _ENCRYPT_PRFS:
        raise UnsupportedAlgorithm(
            f"PBES2 encryption supports {sorted(_ENCRYPT_PRFS)}, not {hash_name!r}"
        )
    if not 1 <= iterations <= _MAX_ITERATIONS:
        raise ValueError("PBES2 iterations out of supported range")
    salt = os.urandom(_SALT_LEN)
    iv = os.urandom(aes.BLOCK_SIZE)
    key = pbkdf2(_password_bytes(password), salt, iterations, _KEY_LEN, hash_name)
    ct = aes.cbc_encrypt(key, iv, aes.pkcs7_pad(private_key_info_der))
    kdf_alg = asn1.encode_sequence(
        asn1.encode_oid(_OID_PBKDF2),
        asn1.encode_sequence(
            asn1.encode_octet_string(salt),
            asn1.encode_integer(iterations),
            asn1.encode_integer(_KEY_LEN),
            asn1.encode_sequence(
                asn1.encode_oid(_PRF_TO_OID[hash_name]), asn1.encode_null()
            ),
        ),
    )
    enc_alg = asn1.encode_sequence(
        asn1.encode_oid(_OID_AES256_CBC), asn1.encode_octet_string(iv)
    )
    return asn1.encode_sequence(
        asn1.encode_sequence(
            asn1.encode_oid(_OID_PBES2), asn1.encode_sequence(kdf_alg, enc_alg)
        ),
        asn1.encode_octet_string(ct),
    )


def _parse_kdf(node: asn1.DerNode) -> tuple[str, bytes, int, int | None]:
    """Parse the PBES2 keyDerivationFunc. Returns (hash, salt, iters, keylen)."""
    kids = asn1.sequence_value(node)
    if len(kids) != 2 or asn1.oid_value(kids[0]) != _OID_PBKDF2:
        raise InvalidKey("decryption failed")
    params = asn1.sequence_value(kids[1])
    if not 2 <= len(params) <= 4:
        raise InvalidKey("decryption failed")
    # salt CHOICE: only the specified OCTET STRING form is supported.
    salt = asn1.octet_string_value(params[0])
    iterations = asn1.int_value(params[1])
    if not 1 <= iterations <= _MAX_ITERATIONS:
        raise InvalidKey("decryption failed")
    keylen: int | None = None
    hash_name = "sha1"  # prf is DEFAULT hmacWithSHA1 when absent
    for extra in params[2:]:
        if extra.tag == asn1.TAG_INTEGER:
            keylen = asn1.int_value(extra)
        elif extra.tag == asn1.TAG_SEQUENCE:
            prf = asn1.sequence_value(extra)
            if not 1 <= len(prf) <= 2:
                raise InvalidKey("decryption failed")
            oid = asn1.oid_value(prf[0])
            if oid not in _OID_TO_PRF:
                raise InvalidKey("decryption failed")
            hash_name = _OID_TO_PRF[oid]
            if len(prf) == 2:
                asn1.null_value(prf[1])
        else:
            raise InvalidKey("decryption failed")
    return hash_name, salt, iterations, keylen


def _parse_cipher(node: asn1.DerNode) -> tuple[int, bytes]:
    """Parse the PBES2 encryptionScheme. Returns (key length, IV)."""
    kids = asn1.sequence_value(node)
    if len(kids) != 2:
        raise InvalidKey("decryption failed")
    oid = asn1.oid_value(kids[0])
    if oid not in _OID_TO_KEYLEN:
        raise InvalidKey("decryption failed")
    iv = asn1.octet_string_value(kids[1])
    if len(iv) != aes.BLOCK_SIZE:
        raise InvalidKey("decryption failed")
    return _OID_TO_KEYLEN[oid], iv


def _check_private_key_info(der: bytes) -> None:
    """Require the plaintext to parse as a PrivateKeyInfo skeleton.

    PBES2 over AES-CBC has no MAC, so this shape check is the second
    wrong-password signal after PKCS#7 padding. It is a sanity gate,
    not authentication. Version v1(0) and v2(1) are both accepted.
    """
    kids = asn1.sequence_value(asn1.decode(der))
    if len(kids) < 3:
        raise InvalidKey("decryption failed")
    if asn1.int_value(kids[0]) not in (0, 1):
        raise InvalidKey("decryption failed")
    asn1.expect(kids[1], asn1.TAG_SEQUENCE)
    asn1.expect(kids[2], asn1.TAG_OCTET_STRING)


def pbes2_decrypt(
    encrypted_private_key_info_der: bytes, password: bytes | str
) -> bytes:
    """Unwrap an EncryptedPrivateKeyInfo into PrivateKeyInfo DER.

    Every failure mode (malformed DER, unsupported parameters, wrong
    password, bad padding, implausible plaintext) raises the identical
    InvalidKey("decryption failed").
    """
    try:
        kids = asn1.sequence_value(asn1.decode(encrypted_private_key_info_der))
        if not looks_encrypted(kids):
            raise InvalidKey("decryption failed")
        alg_kids = asn1.sequence_value(kids[0])
        if len(alg_kids) != 2 or asn1.oid_value(alg_kids[0]) != _OID_PBES2:
            raise InvalidKey("decryption failed")
        params = asn1.sequence_value(alg_kids[1])
        if len(params) != 2:
            raise InvalidKey("decryption failed")
        hash_name, salt, iterations, keylen = _parse_kdf(params[0])
        key_size, iv = _parse_cipher(params[1])
        if keylen is not None and keylen != key_size:
            raise InvalidKey("decryption failed")
        ct = asn1.octet_string_value(kids[1])
        if len(ct) == 0 or len(ct) % aes.BLOCK_SIZE != 0:
            raise InvalidKey("decryption failed")
        key = pbkdf2(_password_bytes(password), salt, iterations, key_size, hash_name)
        plain = aes.pkcs7_unpad(aes.cbc_decrypt(key, iv, ct))
        _check_private_key_info(plain)
    except (PureCryptError, ValueError):
        raise InvalidKey("decryption failed") from None
    return plain
