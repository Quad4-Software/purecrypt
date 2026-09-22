# SPDX-License-Identifier: 0BSD
"""Pure-Python cryptographic primitives. No dependencies, no Rust.

.. warning::
   NOT READY FOR PRODUCTION. Pure Python cannot provide constant-time
   guarantees: all operations here are potentially vulnerable to timing
   and other side-channel analysis. This package exists for education,
   testing, and environments where native crypto is unavailable and the
   threat model tolerates it. Prefer audited native implementations
   (OpenSSL via ``cryptography``, libsodium via ``PyNaCl``) for real
   deployments.
"""

__version__ = "0.1.0"

from .exceptions import (
    InvalidCiphertext,
    InvalidKey,
    InvalidSerialization,
    InvalidSignature,
    InvalidTag,
    PureCryptError,
    UnsupportedAlgorithm,
)

__all__ = [
    "InvalidCiphertext",
    "InvalidKey",
    "InvalidSerialization",
    "InvalidSignature",
    "InvalidTag",
    "PureCryptError",
    "UnsupportedAlgorithm",
    "__version__",
]
