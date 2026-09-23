# purecrypt

[![CI](https://github.com/Quad4-Software/purecrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/purecrypt/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Quad4-Software/purecrypt/actions/workflows/codeql.yml/badge.svg)](https://github.com/Quad4-Software/purecrypt/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/purecrypt/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/purecrypt)
[![PyPI](https://img.shields.io/pypi/v/purecrypt.svg)](https://pypi.org/project/purecrypt/)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

> **Security notice.** Pure Python cannot provide constant-time
> execution. Secret-key operations (signing, decryption, key exchange)
> are hardened against the obvious leaks: RSA blinding, fixed-iteration
> scalar multiplication with mask-selected adds, uniform error paths,
> and constant-time-style comparisons. Residual timing variance in the
> interpreter remains, so do not run secret-key operations where a
> co-located attacker can measure timing. Public-data operations such
> as certificate validation and signature verification are unaffected.
> For high-assurance deployments use audited native implementations
> such as `cryptography` (OpenSSL) or `PyNaCl` (libsodium).

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
  PKCS#1 v1.5 encryption, PKCS#1/PKCS#8/SPKI serialization, encrypted
  PKCS#8 (PBES2/AES-CBC)
- X.509 certificate parsing, signature verification, RFC 5280 chain
  validation and RFC 6125 hostname matching
- HKDF, PBKDF2, scrypt and Argon2id
- ML-KEM-512/768/1024 key encapsulation (FIPS 203)
- ML-DSA-44/65/87 signatures including HashML-DSA (FIPS 204)
- Minimal DER/PEM handling for key serialization
- SHA-2, SHA-3, SHAKE, BLAKE2 and HMAC facades over hashlib
- BLAKE3 hashing, keyed hashing, key derivation and XOF output

## Example

```python
from purecrypt.aes import gcm_decrypt, gcm_encrypt
from purecrypt.eddsa import Ed25519PrivateKey
from purecrypt.x509 import Certificate, validate_chain, verify_hostname

key, nonce = b"k" * 32, b"n" * 12
ct, tag = gcm_encrypt(key, nonce, b"secret", aad=b"hdr")
assert gcm_decrypt(key, nonce, ct, tag, aad=b"hdr") == b"secret"

priv = Ed25519PrivateKey.generate()
sig = priv.sign(b"message")
priv.public_key().verify(sig, b"message")

leaf = Certificate.from_pem(pem_text)
validate_chain(leaf, intermediates, trust_roots)
verify_hostname(leaf, "example.com")
```

## Known limitations

- No constant-time guarantees. Python semantics preclude them.
- Secret material cannot be reliably zeroized. Interpreter copies are
  out of scope, so no wiping is attempted.
- RSA PKCS#1 v1.5 decryption is inherently Bleichenbacher-prone. Use
  OAEP.
- X.509 validation covers RFC 5280 path rules and RFC 6125 hostnames,
  but there is no revocation checking (no CRL or OCSP) and no name or
  policy constraint enforcement. A critical extension whose semantics
  are not enforced fails validation.
- No TLS. That is a different and much larger problem.

## Development

    uv sync --group dev
    make check

License: 0BSD. Quad4 Software, https://quad4.io
