# SPDX-License-Identifier: 0BSD
"""Exception hierarchy for purecrypt."""


class PureCryptError(Exception):
    """Base class for all purecrypt errors."""


class InvalidKey(PureCryptError, ValueError):
    """A key is malformed, out of range, or unsuitable for the operation."""


class InvalidSignature(PureCryptError):
    """Signature verification failed."""


class InvalidTag(PureCryptError):
    """AEAD authentication tag verification failed.

    Raised instead of releasing plaintext: callers must never get
    unauthenticated data out of a decrypt call.
    """


class InvalidCiphertext(PureCryptError):
    """Ciphertext is malformed before authentication could even be tried."""


class UnsupportedAlgorithm(PureCryptError):
    """The named algorithm, curve, or key type is not implemented."""


class InvalidSerialization(PureCryptError, ValueError):
    """DER/PEM/ASN.1 input is malformed or has trailing garbage."""


class InvalidCertificate(PureCryptError):
    """An X.509 certificate or certification path failed validation."""
