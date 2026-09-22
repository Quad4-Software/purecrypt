# SPDX-License-Identifier: 0BSD
"""X.509 certificate parsing, path validation, and hostname matching.

NOT READY FOR PRODUCTION. Pure Python cannot provide constant-time
guarantees: nothing in this module runs in constant time, so it must
not be used on adversarial input where timing leaks matter. This
package exists for education, testing, and environments where native
crypto is unavailable and the threat model tolerates it.

Implements the RFC 5280 certificate profile needed to build and verify
certification paths against an explicit trust store, plus RFC 6125
hostname verification.

Deliberate strictness beyond the RFC minimum:

* Unknown critical extensions always fail validation. This includes
  nameConstraints and the policy extensions: they are parsed far
  enough to detect presence but their semantics are never enforced,
  so a critical marking is a hard error.
* md5 and sha1 signature algorithms are rejected unless the caller
  passes allow_weak=True. md2 is never accepted.
* Issuer and subject matching during path building uses exact DER
  equality of the two Name encodings rather than RFC 5280 string
  preparation rules.
* A non-CA leaf carrying keyUsage must contain digitalSignature.
* TeletexString and GeneralString values in names are decoded as
  latin-1. T.61 is not latin-1, but no production encoder emits
  TeletexString anymore and latin-1 never fails on byte input.
"""

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TypeAlias

from . import asn1
from ._utils import ct_equal
from .ec import ECPublicKey, curve_by_oid
from .eddsa import Ed25519PublicKey
from .exceptions import (
    InvalidCertificate,
    InvalidKey,
    InvalidSerialization,
    InvalidSignature,
    PureCryptError,
    UnsupportedAlgorithm,
)
from .pem import decode_pem, decode_pem_expect
from .rsa import RSAPublicKey, _parse_algorithm

PublicKey: TypeAlias = RSAPublicKey | ECPublicKey | Ed25519PublicKey
IPAddress: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address

PEM_CERTIFICATE = "CERTIFICATE"

_MAX_PATH_DEPTH = 8
_TAG_BOOLEAN = 0x01
_TAG_UTC_TIME = 0x17
_TAG_GENERALIZED_TIME = 0x18
_TAG_UTF8_STRING = 0x0C
_TAG_TELETEX_STRING = 0x14
_TAG_PRINTABLE_STRING = 0x13
_TAG_UNIVERSAL_STRING = 0x1C
_TAG_BMP_STRING = 0x1E
_TAG_IA5_STRING = 0x16
_TAG_VISIBLE_STRING = 0x1A
_TAG_GENERAL_STRING = 0x1B
_TAG_NUMERIC_STRING = 0x12

_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
_OID_ED25519 = "1.3.101.112"
_OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
_OID_MGF1 = "1.2.840.113549.1.1.8"
_OID_MD2_RSA = "1.2.840.113549.1.1.2"

_OID_BASIC_CONSTRAINTS = "2.5.29.19"
_OID_KEY_USAGE = "2.5.29.15"
_OID_EXT_KEY_USAGE = "2.5.29.37"
_OID_SUBJECT_ALT_NAME = "2.5.29.17"
_OID_ISSUER_ALT_NAME = "2.5.29.18"
_OID_SUBJECT_KEY_ID = "2.5.29.14"
_OID_AUTHORITY_KEY_ID = "2.5.29.35"
_OID_NAME_CONSTRAINTS = "2.5.29.30"
_OID_CERT_POLICIES = "2.5.29.32"
_OID_POLICY_CONSTRAINTS = "2.5.29.36"
_OID_POLICY_MAPPINGS = "2.5.29.33"

# Critical extensions whose semantics this module enforces. Any other
# critical extension fails validation, per the RFC 5280 requirement
# that unrecognized critical extensions must abort path processing,
# applied here more strictly than required.
_ENFORCED_CRITICAL = frozenset(
    {_OID_BASIC_CONSTRAINTS, _OID_KEY_USAGE, _OID_SUBJECT_ALT_NAME}
)

_PRESENCE_ONLY_EXTENSIONS = frozenset(
    {
        _OID_NAME_CONSTRAINTS,
        _OID_CERT_POLICIES,
        _OID_POLICY_CONSTRAINTS,
        _OID_POLICY_MAPPINGS,
    }
)

_RSA_V15_HASHES = {
    "1.2.840.113549.1.1.4": "md5",
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.113549.1.1.14": "sha224",
}

_ECDSA_HASHES = {
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}

_SIG_ALG_NAMES = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
}

_HASH_OIDS = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

_WEAK_HASHES = frozenset({"md5", "sha1"})

_KEY_TYPE_MSG = "issuer key type does not match signature algorithm"

_ATTR_SHORT_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.5": "SERIALNUMBER",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "0.9.2342.19200300.100.1.25": "DC",
    "1.2.840.113549.1.9.1": "emailAddress",
}

_NAME_LOOKUP = {name.lower(): oid for oid, name in _ATTR_SHORT_NAMES.items()}

_KEY_USAGE_BITS = (
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
)

_RFC4514_ESCAPED = frozenset(',+"\\<>;')
_UTC_RE = re.compile(rb"^(\d{12})(Z|[+-]\d{4})$")
_GENERALIZED_RE = re.compile(rb"^(\d{14})(Z|[+-]\d{4})$")

_STRING_DECODERS = {
    _TAG_UTF8_STRING: "utf-8",
    _TAG_NUMERIC_STRING: "ascii",
    _TAG_PRINTABLE_STRING: "ascii",
    _TAG_IA5_STRING: "ascii",
    _TAG_VISIBLE_STRING: "ascii",
    _TAG_TELETEX_STRING: "latin-1",
    _TAG_GENERAL_STRING: "latin-1",
    _TAG_BMP_STRING: "utf-16-be",
    _TAG_UNIVERSAL_STRING: "utf-32-be",
}


# --- distinguished names ---------------------------------------------------


def _decode_directory_string(node: asn1.DerNode) -> str:
    codec = _STRING_DECODERS.get(node.tag)
    if codec is None:
        raise InvalidCertificate(f"unsupported name string tag 0x{node.tag:02x}")
    try:
        return node.content.decode(codec)
    except UnicodeDecodeError as exc:
        raise InvalidCertificate("invalid encoding in name attribute") from exc


def _escape_rfc4514(value: str) -> str:
    if not value:
        return value
    out: list[str] = []
    last = len(value) - 1
    for i, ch in enumerate(value):
        code = ord(ch)
        if (
            ch in _RFC4514_ESCAPED
            or (i == 0 and ch in ("#", " "))
            or (i == last and ch == " ")
        ):
            out.append("\\" + ch)
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\{code:02X}")
        else:
            out.append(ch)
    return "".join(out)


@dataclass(frozen=True, slots=True)
class Name:
    """An X.501 distinguished name.

    rdns holds the encoded order of the RDNSequence. Each RDN is a
    tuple of (attribute_oid, value) pairs and may be multi-valued.
    Equality compares the exact DER encoding, which is stricter than
    RFC 5280 name matching.
    """

    rdns: tuple[tuple[tuple[str, str], ...], ...]
    der: bytes

    def rfc4514(self) -> str:
        """RFC 4514 string form, most specific RDN last in DER order."""
        rdns = []
        for rdn in reversed(self.rdns):
            parts = [
                f"{_ATTR_SHORT_NAMES.get(oid, oid)}={_escape_rfc4514(value)}"
                for oid, value in rdn
            ]
            rdns.append("+".join(parts))
        return ",".join(rdns)

    def get(self, attribute: str) -> str | None:
        """First value for attribute, an OID or short name like CN."""
        values = self.get_all(attribute)
        return values[0] if values else None

    def get_all(self, attribute: str) -> tuple[str, ...]:
        oid = _NAME_LOOKUP.get(attribute.lower(), attribute)
        return tuple(value for rdn in self.rdns for o, value in rdn if o == oid)


def _parse_name(node: asn1.DerNode) -> Name:
    rdns: list[tuple[tuple[str, str], ...]] = []
    for rdn_node in asn1.sequence_value(node):
        atvs = asn1.expect(rdn_node, asn1.TAG_SET).children
        if not atvs:
            raise InvalidCertificate("empty RDN")
        pairs: list[tuple[str, str]] = []
        for atv in atvs:
            fields = asn1.sequence_value(atv)
            if len(fields) != 2:
                raise InvalidCertificate("malformed AttributeTypeAndValue")
            pairs.append(
                (asn1.oid_value(fields[0]), _decode_directory_string(fields[1]))
            )
        rdns.append(tuple(pairs))
    return Name(rdns=tuple(rdns), der=asn1.encode_tlv(node.tag, node.content))


# --- times ------------------------------------------------------------------


def _parse_time(node: asn1.DerNode) -> datetime:
    """Parse a Time CHOICE. Returns an aware datetime in UTC."""
    if node.tag == _TAG_UTC_TIME:
        m = _UTC_RE.match(node.content)
        if m is None:
            raise InvalidCertificate("malformed UTCTime")
        yy = int(m.group(1)[:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        fields = m.group(1)[2:]
    elif node.tag == _TAG_GENERALIZED_TIME:
        m = _GENERALIZED_RE.match(node.content)
        if m is None:
            raise InvalidCertificate("malformed GeneralizedTime")
        year = int(m.group(1)[:4])
        fields = m.group(1)[4:]
    else:
        raise InvalidCertificate(f"expected time, got tag 0x{node.tag:02x}")
    month, day, hour, minute, second = (int(fields[i : i + 2]) for i in range(0, 10, 2))
    tzs = m.group(2)
    if tzs == b"Z":
        tz = timezone.utc
    else:
        off_h, off_m = int(tzs[1:3]), int(tzs[3:5])
        if off_h > 23 or off_m > 59:
            raise InvalidCertificate("time offset out of range")
        sign = 1 if tzs[:1] == b"+" else -1
        tz = timezone(sign * timedelta(hours=off_h, minutes=off_m))
    try:
        dt = datetime(year, month, day, hour, minute, second, tzinfo=tz)
    except ValueError as exc:
        raise InvalidCertificate(f"invalid time value: {exc}") from exc
    return dt.astimezone(timezone.utc)


# --- extensions -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Extension:
    """One extension: OID, critical flag, and raw inner DER value."""

    oid: str
    critical: bool
    value: bytes


@dataclass(frozen=True, slots=True)
class BasicConstraints:
    ca: bool
    path_length: int | None


@dataclass(frozen=True, slots=True)
class GeneralName:
    """One GeneralName. kind is dns, ip, email, uri, dir, oid, other."""

    kind: str
    value: str | bytes | Name | IPAddress


def _ext_inner(value: bytes) -> asn1.DerNode:
    try:
        return asn1.decode(value)
    except InvalidSerialization as exc:
        raise InvalidCertificate(f"malformed extension value: {exc}") from exc


def _check_boolean(node: asn1.DerNode) -> bool:
    asn1.expect(node, _TAG_BOOLEAN)
    if node.content not in (b"\x00", b"\xff"):
        raise InvalidCertificate("non-canonical BOOLEAN")
    return node.content == b"\xff"


def _parse_basic_constraints(value: bytes) -> BasicConstraints:
    kids = asn1.sequence_value(_ext_inner(value))
    if len(kids) > 2:
        raise InvalidCertificate("malformed basicConstraints")
    ca = False
    path_length = None
    pos = 0
    if pos < len(kids) and kids[pos].tag == _TAG_BOOLEAN:
        ca = _check_boolean(kids[pos])
        pos += 1
    if pos < len(kids) and kids[pos].tag == asn1.TAG_INTEGER:
        path_length = asn1.int_value(kids[pos])
        pos += 1
    if pos != len(kids):
        raise InvalidCertificate("malformed basicConstraints")
    return BasicConstraints(ca=ca, path_length=path_length)


def _parse_key_usage(value: bytes) -> frozenset[str]:
    unused, payload = asn1.bit_string_parts(_ext_inner(value))
    total = len(payload) * 8 - unused
    return frozenset(
        _KEY_USAGE_BITS[i] if i < len(_KEY_USAGE_BITS) else f"bit{i}"
        for i in range(total)
        if payload[i // 8] & (0x80 >> (i % 8))
    )


def _parse_ext_key_usage(value: bytes) -> tuple[str, ...]:
    return tuple(
        asn1.oid_value(node) for node in asn1.sequence_value(_ext_inner(value))
    )


def _ia5(content: bytes) -> str:
    try:
        return content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise InvalidCertificate("non-ASCII IA5String") from exc


def _parse_general_name(node: asn1.DerNode) -> GeneralName:
    tag = node.tag
    if tag == 0x81:
        return GeneralName("email", _ia5(node.content))
    if tag == 0x82:
        return GeneralName("dns", _ia5(node.content))
    if tag == 0x86:
        return GeneralName("uri", _ia5(node.content))
    if tag == 0x87:
        try:
            ip = ipaddress.ip_address(node.content)
        except ValueError as exc:
            raise InvalidCertificate("malformed iPAddress") from exc
        return GeneralName("ip", ip)
    if tag == 0xA4:
        if len(node.children) != 1:
            raise InvalidCertificate("malformed directoryName")
        return GeneralName("dir", _parse_name(node.children[0]))
    if tag == 0x88:
        oid_node = asn1.DerNode(tag=asn1.TAG_OID, content=node.content)
        return GeneralName("oid", asn1.oid_value(oid_node))
    if node.tag_class == 2:
        return GeneralName("other", bytes(node.content))
    raise InvalidCertificate("non-context tag in GeneralName")


def _parse_general_names(value: bytes) -> tuple[GeneralName, ...]:
    node = _ext_inner(value)
    return tuple(_parse_general_name(gn) for gn in asn1.sequence_value(node))


def _parse_subject_key_id(value: bytes) -> bytes:
    return asn1.octet_string_value(_ext_inner(value))


def _parse_authority_key_id(value: bytes) -> bytes | None:
    key_id = None
    for child in asn1.sequence_value(_ext_inner(value)):
        if child.tag == 0x80:
            if key_id is not None:
                raise InvalidCertificate("duplicate keyIdentifier")
            key_id = bytes(child.content)
        elif child.tag not in (0xA1, 0x82):
            raise InvalidCertificate("malformed authorityKeyIdentifier")
    return key_id


def _parse_extensions(node: asn1.DerNode) -> tuple[Extension, ...]:
    extensions: list[Extension] = []
    seen: set[str] = set()
    for ext_node in asn1.sequence_value(node):
        kids = asn1.sequence_value(ext_node)
        if not 2 <= len(kids) <= 3:
            raise InvalidCertificate("malformed extension")
        oid = asn1.oid_value(kids[0])
        if oid in seen:
            raise InvalidCertificate(f"duplicate extension {oid}")
        seen.add(oid)
        critical = False
        value_node = kids[1]
        if len(kids) == 3:
            critical = _check_boolean(kids[1])
            value_node = kids[2]
        extensions.append(
            Extension(
                oid=oid,
                critical=critical,
                value=asn1.octet_string_value(value_node),
            )
        )
    return tuple(extensions)


# --- public keys -------------------------------------------------------------


def _parse_spki(node: asn1.DerNode) -> PublicKey:
    kids = asn1.sequence_value(node)
    if len(kids) != 2:
        raise InvalidCertificate("malformed subjectPublicKeyInfo")
    oid, params = _parse_algorithm(kids[0])
    try:
        payload = asn1.bit_string_value(kids[1])
        if oid == _OID_RSA_ENCRYPTION:
            if params is not None:
                asn1.null_value(params)
            inner = asn1.decode(payload)
            pkcs1 = asn1.sequence_value(inner)
            if len(pkcs1) != 2:
                raise InvalidCertificate("malformed RSA public key")
            return RSAPublicKey(n=asn1.int_value(pkcs1[0]), e=asn1.int_value(pkcs1[1]))
        if oid == _OID_EC_PUBLIC_KEY:
            if params is None:
                raise InvalidCertificate("missing EC curve OID")
            curve = curve_by_oid(asn1.oid_value(params))
            return ECPublicKey.from_sec1_bytes(payload, curve)
        if oid == _OID_ED25519:
            if params is not None:
                raise InvalidCertificate("Ed25519 params must be absent")
            return Ed25519PublicKey.from_public_bytes(payload)
    except (InvalidSerialization, InvalidKey, UnsupportedAlgorithm) as exc:
        raise InvalidCertificate(f"invalid subjectPublicKeyInfo: {exc}") from exc
    raise InvalidCertificate(f"unsupported public key algorithm {oid}")


# --- signature algorithms -----------------------------------------------------


def _hash_from_alg(node: asn1.DerNode) -> str:
    oid, params = _parse_algorithm(node)
    if params is not None:
        try:
            asn1.null_value(params)
        except InvalidSerialization as exc:
            raise InvalidCertificate("hash params must be NULL") from exc
    try:
        return _HASH_OIDS[oid]
    except KeyError as exc:
        raise InvalidCertificate(f"unsupported hash algorithm {oid}") from exc


def _mgf_hash_from_alg(node: asn1.DerNode) -> str:
    oid, params = _parse_algorithm(node)
    if oid != _OID_MGF1 or params is None:
        raise InvalidCertificate("maskGenAlgorithm must be MGF1")
    return _hash_from_alg(params)


def _parse_pss_params(node: asn1.DerNode) -> tuple[str, int]:
    """Parse RSASSA-PSS-params. Returns (hash_name, salt_length)."""
    hash_name = "sha1"
    mgf_hash = "sha1"
    salt_len = 20
    trailer = 1
    seen: set[int] = set()
    for field in asn1.sequence_value(node):
        number = field.tag_number
        if (
            field.tag_class != 2
            or not field.constructed
            or number > 3
            or number in seen
            or len(field.children) != 1
        ):
            raise InvalidCertificate("malformed RSASSA-PSS params")
        seen.add(number)
        inner = field.children[0]
        if number == 0:
            hash_name = _hash_from_alg(inner)
        elif number == 1:
            mgf_hash = _mgf_hash_from_alg(inner)
        elif number == 2:
            salt_len = asn1.int_value(inner)
        else:
            trailer = asn1.int_value(inner)
    if trailer != 1:
        raise InvalidCertificate("unsupported PSS trailerField")
    if mgf_hash != hash_name:
        raise InvalidCertificate("MGF hash differs from signature hash")
    return hash_name, salt_len


def _check_sig_params(oid: str, params: asn1.DerNode | None) -> None:
    rsa_family = oid in _RSA_V15_HASHES or oid == _OID_MD2_RSA
    if rsa_family and params is not None:
        try:
            asn1.null_value(params)
        except InvalidSerialization as exc:
            raise InvalidCertificate("RSA signature params must be NULL") from exc
    if (oid in _ECDSA_HASHES or oid == _OID_ED25519) and params is not None:
        raise InvalidCertificate("signature params must be absent")
    if oid == _OID_RSASSA_PSS and params is None:
        raise InvalidCertificate("RSASSA-PSS params are required")


# --- certificate ---------------------------------------------------------------


def _first_tlv(content: bytes) -> bytes:
    """Return the raw encoding of the first TLV inside content."""
    if len(content) < 2:
        raise InvalidCertificate("missing tbsCertificate")
    first = content[1]
    if first < 0x80:
        total = 2 + first
    else:
        count = first & 0x7F
        if count == 0 or count > 8 or 2 + count > len(content):
            raise InvalidCertificate("bad tbsCertificate length")
        total = 2 + count + int.from_bytes(content[2 : 2 + count], "big")
    if total > len(content):
        raise InvalidCertificate("tbsCertificate exceeds certificate")
    return content[:total]


@dataclass(frozen=True, slots=True)
class Certificate:
    """A parsed X.509 certificate.

    Construct with from_der or from_pem only. Equality compares every
    parsed field, which is equivalent to DER equality.
    """

    _der: bytes
    _tbs_der: bytes
    _signature: bytes
    _signature_oid: str
    _pss: tuple[str, int] | None
    version: int
    serial_number: int
    issuer: Name
    subject: Name
    not_valid_before: datetime
    not_valid_after: datetime
    public_key: PublicKey
    extensions: tuple[Extension, ...]
    _basic_constraints: BasicConstraints | None
    _key_usage: frozenset[str] | None
    _extended_key_usage: tuple[str, ...] | None
    _subject_alt_names: tuple[GeneralName, ...] | None
    _issuer_alt_names: tuple[GeneralName, ...] | None
    _subject_key_id: bytes | None
    _authority_key_id: bytes | None
    _unenforced_critical: frozenset[str]

    @classmethod
    def from_der(cls, data: bytes | bytearray | memoryview) -> "Certificate":
        """Parse one DER-encoded certificate. Rejects trailing data."""
        try:
            return _parse_certificate(bytes(data))
        except PureCryptError:
            raise
        except (
            ValueError,
            TypeError,
            IndexError,
            KeyError,
            AttributeError,
            OverflowError,
        ) as exc:
            raise InvalidCertificate("malformed certificate") from exc

    @classmethod
    def from_pem(cls, text: str | bytes) -> "Certificate":
        """Parse a single CERTIFICATE PEM block.

        Strictly single-certificate: input containing a second PEM
        block is rejected. Use load_pem_bundle for bundles.
        """
        if isinstance(text, str):
            many = text.count("-----BEGIN") > 1
        else:
            many = bytes(text).count(b"-----BEGIN") > 1
        if many:
            raise InvalidSerialization(
                "from_pem expects one certificate, use load_pem_bundle"
            )
        return cls.from_der(decode_pem_expect(text, PEM_CERTIFICATE))

    @property
    def der(self) -> bytes:
        return self._der

    @property
    def tbs_der(self) -> bytes:
        return self._tbs_der

    @property
    def signature(self) -> bytes:
        return self._signature

    @property
    def signature_algorithm(self) -> str:
        return _SIG_ALG_NAMES.get(self._signature_oid, self._signature_oid)

    def fingerprint(self, hash_name: str = "sha256") -> bytes:
        """Digest of the full DER encoding."""
        try:
            h = hashlib.new(hash_name)
        except ValueError as exc:
            raise UnsupportedAlgorithm(f"unsupported hash {hash_name!r}") from exc
        h.update(self._der)
        return h.digest()

    @property
    def is_ca(self) -> bool:
        bc = self._basic_constraints
        return bc.ca if bc is not None else False

    @property
    def is_self_signed(self) -> bool:
        return self.issuer == self.subject

    @property
    def basic_constraints(self) -> BasicConstraints | None:
        return self._basic_constraints

    @property
    def key_usage(self) -> frozenset[str] | None:
        return self._key_usage

    @property
    def extended_key_usage(self) -> tuple[str, ...] | None:
        return self._extended_key_usage

    @property
    def subject_alt_names(self) -> tuple[GeneralName, ...] | None:
        return self._subject_alt_names

    @property
    def issuer_alt_names(self) -> tuple[GeneralName, ...] | None:
        return self._issuer_alt_names

    @property
    def subject_key_identifier(self) -> bytes | None:
        return self._subject_key_id

    @property
    def authority_key_identifier(self) -> bytes | None:
        return self._authority_key_id

    @property
    def san_dns_names(self) -> tuple[str, ...]:
        if self._subject_alt_names is None:
            return ()
        return tuple(
            gn.value
            for gn in self._subject_alt_names
            if gn.kind == "dns" and isinstance(gn.value, str)
        )

    @property
    def san_ip_addresses(self) -> tuple[IPAddress, ...]:
        if self._subject_alt_names is None:
            return ()
        return tuple(
            gn.value
            for gn in self._subject_alt_names
            if gn.kind == "ip"
            and isinstance(gn.value, (ipaddress.IPv4Address, ipaddress.IPv6Address))
        )

    def extension(self, oid: str) -> Extension | None:
        for ext in self.extensions:
            if ext.oid == oid:
                return ext
        return None

    def verify_issuer_signature(
        self, issuer_public_key: PublicKey, *, allow_weak: bool = False
    ) -> None:
        """Verify this certificate was signed by issuer_public_key.

        Raises InvalidSignature on a bad signature and
        InvalidCertificate on algorithm or key-type problems.
        """
        oid = self._signature_oid
        if oid == _OID_MD2_RSA:
            raise InvalidCertificate("md2WithRSAEncryption is never accepted")
        if oid in _RSA_V15_HASHES:
            hash_name = _RSA_V15_HASHES[oid]
            self._check_hash_allowed(hash_name, allow_weak)
            if not isinstance(issuer_public_key, RSAPublicKey):
                raise InvalidCertificate(_KEY_TYPE_MSG)
            issuer_public_key.verify_v15(self._signature, self._tbs_der, hash_name)
        elif oid == _OID_RSASSA_PSS:
            hash_name, salt_len = self._require_pss()
            self._check_hash_allowed(hash_name, allow_weak)
            if not isinstance(issuer_public_key, RSAPublicKey):
                raise InvalidCertificate(_KEY_TYPE_MSG)
            issuer_public_key.verify_pss(
                self._signature, self._tbs_der, hash_name, salt_len
            )
        elif oid in _ECDSA_HASHES:
            hash_name = _ECDSA_HASHES[oid]
            self._check_hash_allowed(hash_name, allow_weak)
            if not isinstance(issuer_public_key, ECPublicKey):
                raise InvalidCertificate(_KEY_TYPE_MSG)
            issuer_public_key.verify_ecdsa(self._signature, self._tbs_der, hash_name)
        elif oid == _OID_ED25519:
            if not isinstance(issuer_public_key, Ed25519PublicKey):
                raise InvalidCertificate(_KEY_TYPE_MSG)
            issuer_public_key.verify(self._signature, self._tbs_der)
        else:
            raise InvalidCertificate(f"unsupported signature algorithm {oid}")

    @staticmethod
    def _check_hash_allowed(hash_name: str, allow_weak: bool) -> None:
        if hash_name in _WEAK_HASHES and not allow_weak:
            raise InvalidCertificate(f"weak signature hash {hash_name} rejected")

    def _require_pss(self) -> tuple[str, int]:
        if self._pss is None:
            raise InvalidCertificate("malformed RSASSA-PSS params")
        return self._pss


def _parse_certificate(data: bytes) -> Certificate:
    node = asn1.decode(data)
    kids = asn1.sequence_value(node)
    if len(kids) != 3:
        raise InvalidCertificate("Certificate must have three fields")
    tbs_node, sig_alg_node, sig_node = kids
    tbs_der = _first_tlv(node.content)
    signature = asn1.bit_string_value(sig_node)
    outer_oid, outer_params = _parse_algorithm(sig_alg_node)
    (
        version,
        serial,
        tbs_sig_oid,
        tbs_sig_params,
        issuer,
        not_before,
        not_after,
        subject,
        public_key,
        extensions,
    ) = _parse_tbs(tbs_node)
    if outer_oid != tbs_sig_oid or outer_params != tbs_sig_params:
        raise InvalidCertificate("signature algorithm fields differ")
    _check_sig_params(tbs_sig_oid, tbs_sig_params)
    pss = (
        _parse_pss_params(tbs_sig_params)
        if tbs_sig_oid == _OID_RSASSA_PSS and tbs_sig_params is not None
        else None
    )
    known = _parse_known_extensions(extensions)
    return Certificate(
        _der=data,
        _tbs_der=tbs_der,
        _signature=signature,
        _signature_oid=tbs_sig_oid,
        _pss=pss,
        version=version,
        serial_number=serial,
        issuer=issuer,
        subject=subject,
        not_valid_before=not_before,
        not_valid_after=not_after,
        public_key=public_key,
        extensions=extensions,
        _basic_constraints=known[0],
        _key_usage=known[1],
        _extended_key_usage=known[2],
        _subject_alt_names=known[3],
        _issuer_alt_names=known[4],
        _subject_key_id=known[5],
        _authority_key_id=known[6],
        _unenforced_critical=known[7],
    )


def _parse_tbs(
    tbs_node: asn1.DerNode,
) -> tuple[
    int,
    int,
    str,
    asn1.DerNode | None,
    Name,
    datetime,
    datetime,
    Name,
    PublicKey,
    tuple[Extension, ...],
]:
    kids = asn1.sequence_value(tbs_node)
    pos = 0
    version = 1
    if kids and kids[0].tag == 0xA0:
        inner = asn1.context_value(kids[0], 0)
        if len(inner) != 1:
            raise InvalidCertificate("malformed version field")
        v = asn1.int_value(inner[0])
        if v > 2:
            raise InvalidCertificate(f"unsupported certificate version {v + 1}")
        version = v + 1
        pos = 1
    if len(kids) < pos + 6:
        raise InvalidCertificate("tbsCertificate too short")
    serial = asn1.int_value(kids[pos])
    if serial <= 0:
        raise InvalidCertificate("serial number must be positive")
    sig_oid, sig_params = _parse_algorithm(kids[pos + 1])
    issuer = _parse_name(kids[pos + 2])
    validity = asn1.sequence_value(kids[pos + 3])
    if len(validity) != 2:
        raise InvalidCertificate("malformed validity")
    not_before = _parse_time(validity[0])
    not_after = _parse_time(validity[1])
    subject = _parse_name(kids[pos + 4])
    public_key = _parse_spki(kids[pos + 5])
    extensions = _parse_optional_tail(kids[pos + 6 :])
    return (
        version,
        serial,
        sig_oid,
        sig_params,
        issuer,
        not_before,
        not_after,
        subject,
        public_key,
        extensions,
    )


def _parse_optional_tail(
    tail: tuple[asn1.DerNode, ...],
) -> tuple[Extension, ...]:
    """Parse unique IDs and the extensions field after the SPKI."""
    extensions: tuple[Extension, ...] = ()
    last_tag = 0
    for node in tail:
        if node.tag not in (0x81, 0x82, 0xA3) or node.tag <= last_tag:
            raise InvalidCertificate("unexpected tbsCertificate field")
        last_tag = node.tag
        if node.tag == 0xA3:
            wrapper = asn1.context_value(node, 3)
            if len(wrapper) != 1:
                raise InvalidCertificate("malformed extensions")
            extensions = _parse_extensions(wrapper[0])
    return extensions


def _parse_known_extensions(
    extensions: tuple[Extension, ...],
) -> tuple[
    BasicConstraints | None,
    frozenset[str] | None,
    tuple[str, ...] | None,
    tuple[GeneralName, ...] | None,
    tuple[GeneralName, ...] | None,
    bytes | None,
    bytes | None,
    frozenset[str],
]:
    bc = None
    ku = None
    eku = None
    san = None
    ian = None
    skid = None
    akid = None
    for ext in extensions:
        if ext.oid == _OID_BASIC_CONSTRAINTS:
            bc = _parse_basic_constraints(ext.value)
        elif ext.oid == _OID_KEY_USAGE:
            ku = _parse_key_usage(ext.value)
        elif ext.oid == _OID_EXT_KEY_USAGE:
            eku = _parse_ext_key_usage(ext.value)
        elif ext.oid == _OID_SUBJECT_ALT_NAME:
            san = _parse_general_names(ext.value)
        elif ext.oid == _OID_ISSUER_ALT_NAME:
            ian = _parse_general_names(ext.value)
        elif ext.oid == _OID_SUBJECT_KEY_ID:
            skid = _parse_subject_key_id(ext.value)
        elif ext.oid == _OID_AUTHORITY_KEY_ID:
            akid = _parse_authority_key_id(ext.value)
        elif ext.oid in _PRESENCE_ONLY_EXTENSIONS:
            asn1.sequence_value(_ext_inner(ext.value))
    unenforced = frozenset(
        ext.oid
        for ext in extensions
        if ext.critical and ext.oid not in _ENFORCED_CRITICAL
    )
    return bc, ku, eku, san, ian, skid, akid, unenforced


# --- path building and validation ---------------------------------------------


def _same_entity(a: Certificate, b: Certificate) -> bool:
    return a._der == b._der or (a.subject == b.subject and a.public_key == b.public_key)


def _issues(issuer: Certificate, child: Certificate, allow_weak: bool) -> bool:
    if child.issuer != issuer.subject:
        return False
    akid = child.authority_key_identifier
    skid = issuer.subject_key_identifier
    if akid is not None and skid is not None and not ct_equal(akid, skid):
        return False
    try:
        child.verify_issuer_signature(issuer.public_key, allow_weak=allow_weak)
    except InvalidSignature:
        return False
    return True


def _extend_path(
    chain: list[Certificate],
    intermediates: list[Certificate],
    roots: list[Certificate],
    allow_weak: bool,
) -> list[Certificate] | None:
    current = chain[-1]
    if len(chain) > _MAX_PATH_DEPTH + 1:
        return None
    for root in roots:
        if _issues(root, current, allow_weak):
            return [*chain, root]
    for root in roots:
        if _same_entity(current, root):
            return chain
    for cand in intermediates:
        if cand in chain or not _issues(cand, current, allow_weak):
            continue
        result = _extend_path([*chain, cand], intermediates, roots, allow_weak)
        if result is not None:
            return result
    return None


def build_chain(
    leaf: Certificate,
    intermediates: list[Certificate] | tuple[Certificate, ...],
    trust_roots: list[Certificate] | tuple[Certificate, ...],
    *,
    allow_weak: bool = False,
) -> list[Certificate]:
    """Build a path from leaf to a trust root.

    Candidate issuers are matched by subject/issuer Name equality plus
    authorityKeyIdentifier/subjectKeyIdentifier when both are present,
    and confirmed by verifying the signature. Depth is capped at eight
    links. Raises InvalidCertificate when no path exists.
    """
    inter = list(intermediates)
    roots = list(trust_roots)
    for root in roots:
        if _same_entity(leaf, root):
            return [leaf]
    chain = _extend_path([leaf], inter, roots, allow_weak)
    if chain is None:
        raise InvalidCertificate("no path from leaf to a trust anchor")
    return chain


build_path = build_chain


def _check_validity(cert: Certificate, moment: datetime) -> None:
    if moment < cert.not_valid_before:
        raise InvalidCertificate("certificate is not yet valid")
    if moment > cert.not_valid_after:
        raise InvalidCertificate("certificate is expired")


def _check_critical(cert: Certificate) -> None:
    if cert._unenforced_critical:
        raise InvalidCertificate(
            f"unsupported critical extension {min(cert._unenforced_critical)}"
        )


def _check_ca(
    cert: Certificate, index: int, chain: list[Certificate], anchor: bool = False
) -> None:
    bc = cert.basic_constraints
    if bc is None:
        # Intermediates must carry cA=TRUE. A trust anchor that asserts
        # nothing (v1 or extensionless) is trusted by fiat, matching
        # openssl; an anchor that does carry basicConstraints or
        # keyUsage must still satisfy them.
        if not anchor:
            raise InvalidCertificate("issuer lacks basicConstraints cA=TRUE")
    elif not bc.ca:
        raise InvalidCertificate("issuer lacks basicConstraints cA=TRUE")
    # pathLenConstraint bounds the intermediate CA certs between this
    # CA and the leaf. The leaf itself never counts, even if is_ca.
    cas_below = sum(1 for c in chain[1:index] if c.is_ca)
    if bc is not None and bc.path_length is not None and bc.path_length < cas_below:
        raise InvalidCertificate("pathLenConstraint exceeded")
    if cert.key_usage is not None and "keyCertSign" not in cert.key_usage:
        raise InvalidCertificate("issuer keyUsage lacks keyCertSign")


def validate_chain(
    leaf: Certificate,
    intermediates: list[Certificate] | tuple[Certificate, ...],
    trust_roots: list[Certificate] | tuple[Certificate, ...],
    moment: datetime | None = None,
    *,
    allow_weak: bool = False,
) -> list[Certificate]:
    """Validate a path from leaf to a trust root, return the chain.

    Checks, per certificate: validity window at moment (default now),
    the critical-extension policy, CA requirements on every non-leaf
    (basicConstraints cA=TRUE, keyCertSign when keyUsage is present,
    pathLenConstraint), and digitalSignature in the leaf keyUsage when
    the leaf is not itself a CA. A self-signed trust anchor gets a
    self-signature sanity check; its trust still comes from the store.
    """
    chain = build_chain(leaf, intermediates, trust_roots, allow_weak=allow_weak)
    if moment is None:
        moment = datetime.now(timezone.utc)
    elif moment.tzinfo is None:
        raise InvalidCertificate("moment must be timezone-aware")
    moment = moment.astimezone(timezone.utc)
    for i, cert in enumerate(chain):
        _check_validity(cert, moment)
        _check_critical(cert)
        if i == 0:
            if (
                not cert.is_ca
                and cert.key_usage is not None
                and "digitalSignature" not in cert.key_usage
            ):
                raise InvalidCertificate("leaf keyUsage lacks digitalSignature")
        else:
            _check_ca(cert, i, chain, anchor=i == len(chain) - 1)
    anchor = chain[-1]
    if anchor.is_self_signed:
        try:
            anchor.verify_issuer_signature(anchor.public_key, allow_weak=allow_weak)
        except InvalidSignature as exc:
            raise InvalidCertificate("trust anchor self-signature invalid") from exc
    return chain


# --- PEM bundles ---------------------------------------------------------------


def load_pem_bundle(text: str | bytes) -> list[Certificate]:
    """Load every CERTIFICATE block from a multi-cert PEM bundle.

    Blocks with other labels are ignored. Raises InvalidSerialization
    when no certificate is found.
    """
    if isinstance(text, str):
        try:
            raw = text.encode("ascii")
        except UnicodeEncodeError as exc:
            raise InvalidSerialization("PEM is not ASCII") from exc
    else:
        raw = bytes(text)
    certs: list[Certificate] = []
    pos = 0
    while True:
        start = raw.find(b"-----BEGIN ", pos)
        if start < 0:
            break
        end = raw.find(b"-----END ", start)
        if end < 0:
            raise InvalidSerialization("unterminated PEM block")
        newline = raw.find(b"\n", end)
        block_end = len(raw) if newline < 0 else newline + 1
        label, der = decode_pem(raw[start:block_end])
        if label == PEM_CERTIFICATE:
            certs.append(Certificate.from_der(der))
        pos = block_end
    if not certs:
        raise InvalidSerialization("no certificates found in bundle")
    return certs


# --- hostname verification ------------------------------------------------------


def _dns_name_match(pattern: str, hostname: str) -> bool:
    pattern = pattern.lower()
    hostname = hostname.lower()
    if "*" not in pattern:
        return pattern == hostname
    if not pattern.startswith("*."):
        return False  # partial wildcards never match
    suffix = pattern[2:]
    if not hostname.endswith("." + suffix):
        return False
    leftmost = hostname[: len(hostname) - len(suffix) - 1]
    return leftmost != "" and "." not in leftmost


def verify_hostname(cert: Certificate, hostname: str) -> bool:
    """RFC 6125 hostname verification.

    IP addresses match only iPAddress SANs. DNS names match dNSName
    SANs when a SAN extension is present; only when the certificate
    has no SAN extension at all does the subject CN apply, which real
    world certificates still rely on. Wildcards are limited to a
    complete leftmost label.
    """
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    if ip is not None:
        return ip in cert.san_ip_addresses
    try:
        a_label = hostname.rstrip(".").encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return False
    if not a_label:
        return False
    san = cert.subject_alt_names
    if san is not None:
        patterns = [
            gn.value for gn in san if gn.kind == "dns" and isinstance(gn.value, str)
        ]
    else:
        patterns = list(cert.subject.get_all("CN"))
    return any(_dns_name_match(p, a_label) for p in patterns)
