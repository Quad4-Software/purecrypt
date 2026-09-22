# Changelog

## [0.1.0] - Unreleased

Initial release. Pure-Python primitives with no dependencies and no
Rust. NOT READY FOR PRODUCTION: see the README warning about
constant-time and side-channel limitations.

- AES-128/192/256 block cipher with ECB, CBC, CTR and GCM (AEAD)
- ChaCha20, Poly1305, ChaCha20-Poly1305 and XChaCha20-Poly1305
- Ed25519 signatures (RFC 8032) and X25519 key exchange (RFC 7748)
- ECDSA and ECDH over P-256, P-384, P-521 and secp256k1 with RFC 6979
  deterministic k
- RSA key generation, PSS and PKCS#1 v1.5 signatures, OAEP and
  PKCS#1 v1.5 encryption, PKCS#1/PKCS#8/SPKI/SEC1 serialization
- HKDF, PBKDF2, scrypt and Argon2id
- Minimal strict DER and PEM codecs for key serialization
- Hash and HMAC facades over hashlib
