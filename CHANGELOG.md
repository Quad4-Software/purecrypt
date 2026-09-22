# Changelog

## [0.1.0] - Unreleased

Initial release. Pure-Python primitives with no dependencies and no
Rust. See the README security notice: pure Python cannot provide
constant-time execution, so secret-key operations must not run where a
co-located attacker can measure timing.

- AES-128/192/256 block cipher with ECB, CBC, CTR and GCM (AEAD)
- ChaCha20, Poly1305, ChaCha20-Poly1305 and XChaCha20-Poly1305
- Ed25519 signatures (RFC 8032) and X25519/X448 key exchange (RFC 7748)
- ECDSA and ECDH over P-256, P-384, P-521 and secp256k1 with RFC 6979
  deterministic k
- RSA key generation, PSS and PKCS#1 v1.5 signatures, OAEP and
  PKCS#1 v1.5 encryption, PKCS#1/PKCS#8/SPKI/SEC1 serialization
- Encrypted PKCS#8 (RFC 5958) via PBES2 with PBKDF2-HMAC and AES-CBC
- X.509 certificate parsing and validation (RFC 5280): chain building,
  signature verification for RSA/ECDSA/Ed25519, critical-extension
  policy, and RFC 6125 hostname matching
- HKDF, PBKDF2, scrypt and Argon2id
- Minimal strict DER and PEM codecs for keys and certificates
- Hash and HMAC facades over hashlib

Side-channel hardening: RSA private operations blinded with a random
factor and verified against the public exponent before release, fixed
iteration scalar multiplication with mask-selected adds on all curves,
mask-arithmetic Montgomery cswap, uniform full-buffer padding scans,
and constant-time-style comparisons on all secret-derived values.
