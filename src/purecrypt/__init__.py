# SPDX-License-Identifier: 0BSD
"""Pure-Python cryptographic primitives. No dependencies, no Rust.

.. warning::
   Pure Python cannot provide constant-time execution. Secret-key
   operations (signing, decryption, key exchange) are hardened against
   the obvious leaks - RSA blinding, fixed-iteration scalar
   multiplication, uniform error paths, constant-time-style compares -
   but residual timing variance remains, so they must not run where a
   co-located attacker can measure timing. Public-data operations
   (certificate validation, signature verification) are unaffected.
   For high-assurance deployments prefer audited native
   implementations (OpenSSL via cryptography, libsodium via PyNaCl).
"""

__version__ = "0.1.1"

from . import blake3, mlkem
from .exceptions import (
    InvalidCertificate,
    InvalidCiphertext,
    InvalidKey,
    InvalidSerialization,
    InvalidSignature,
    InvalidTag,
    PureCryptError,
    UnsupportedAlgorithm,
)

__all__ = [
    "InvalidCertificate",
    "InvalidCiphertext",
    "InvalidKey",
    "InvalidSerialization",
    "InvalidSignature",
    "InvalidTag",
    "PureCryptError",
    "UnsupportedAlgorithm",
    "__version__",
    "blake3",
    "mlkem",
]
