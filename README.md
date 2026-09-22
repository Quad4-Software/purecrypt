# purecrypt

[![CI](https://github.com/Quad4-Software/purecrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/purecrypt/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Quad4-Software/purecrypt/actions/workflows/codeql.yml/badge.svg)](https://github.com/Quad4-Software/purecrypt/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/purecrypt/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/purecrypt)
[![PyPI](https://img.shields.io/pypi/v/purecrypt.svg)](https://pypi.org/project/purecrypt/)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

> **WARNING: NOT READY FOR PRODUCTION.**
>
> Pure Python cannot provide constant-time execution. Every operation
> in this library is potentially vulnerable to timing and other
> side-channel analysis, and secret material may be copied by the
> garbage collector. This package exists for education, testing, and
> environments where native crypto is unavailable and the threat model
> tolerates it. For real deployments use audited native
> implementations such as `cryptography` (OpenSSL) or `PyNaCl`
> (libsodium).

Pure-Python cryptographic primitives for Python 3.10+. No
dependencies, no Rust, no C extensions: only `hashlib`, `hmac` and
`secrets` from the standard library.

## Install

    pip install purecrypt

## Contents

- AES-128/192/256 with ECB, CBC, CTR and GCM (AEAD)
- ChaCha20, Poly1305, ChaCha20-Poly1305 and XChaCha20-Poly1305
- Ed25519 signatures and X25519 key exchange
- ECDSA and ECDH over P-256, P-384, P-521 and secp256k1 (RFC 6979
  deterministic signatures)
- RSA: key generation, PSS and PKCS#1 v1.5 signatures, OAEP and
  PKCS#1 v1.5 encryption, PKCS#1/PKCS#8/SPKI serialization
- HKDF, PBKDF2, scrypt and Argon2id
- Minimal DER/PEM handling for key serialization
- SHA-2, SHA-3, SHAKE, BLAKE2 and HMAC facades over hashlib

## Example

```python
from purecrypt.aes import gcm_decrypt, gcm_encrypt
from purecrypt.eddsa import Ed25519PrivateKey

key, nonce = b"k" * 32, b"n" * 12
ct, tag = gcm_encrypt(key, nonce, b"secret", aad=b"hdr")
assert gcm_decrypt(key, nonce, ct, tag, aad=b"hdr") == b"secret"

priv = Ed25519PrivateKey.generate()
sig = priv.sign(b"message")
priv.public_key().verify(sig, b"message")
```

## Known limitations

- No constant-time guarantees. Python semantics preclude them.
- Secret zeroization is best-effort (mutable buffers are wiped where
  practical, but interpreter copies are out of scope).
- RSA PKCS#1 v1.5 decryption is inherently Bleichenbacher-prone. Use
  OAEP.
- No X.509/TLS. That is a different and much larger problem.

## Development

    uv sync --group dev
    make check

License: 0BSD. Quad4 Software, https://quad4.io
