# SPDX-License-Identifier: 0BSD
"""Minimal strict DER encoder/decoder for asymmetric key serialization.

NOT READY FOR PRODUCTION. Pure Python cannot provide constant-time
guarantees: nothing in this module runs in constant time, so it must not
be used on adversarial input where timing leaks matter. This package
exists for education, testing, and environments where native crypto is
unavailable and the threat model tolerates it.

Implements the subset of X.690 DER needed for PKCS#1, PKCS#8, SEC1 and
SubjectPublicKeyInfo structures: SEQUENCE, SET, INTEGER, BIT STRING,
OCTET STRING, NULL, OBJECT IDENTIFIER, and context-specific tagged
values.

The decoder is strict DER, not BER. It rejects indefinite lengths,
non-minimal length fields, non-minimal INTEGER padding, malformed BIT
STRING trailing bits, non-minimal OID arcs, multi-byte (high-tag-number)
tags, primitive SEQUENCE/SET encodings, constructed encodings of
universal primitive types, standalone EOC markers, nesting beyond a
bounded depth, and trailing garbage after the top-level element.

One deliberate deviation: DER also requires SET OF elements to be sorted
by encoding. That ordering check is not enforced. Key structures use
SEQUENCE everywhere, so this does not affect the intended consumers.
"""

from dataclasses import dataclass

from .exceptions import InvalidSerialization

TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

_CLASS_UNIVERSAL = 0

_MAX_NESTING = 64
_MAX_LEN_OCTETS = 8

_PRIMITIVE_SEQUENCE = 0x10
_PRIMITIVE_SET = 0x11
_EOC = 0x00


@dataclass(frozen=True, slots=True)
class DerNode:
    """One decoded TLV.

    content holds the raw content octets. children holds the
    decoded sub-elements when the constructed bit was set. It is empty
    for primitive encodings.
    """

    tag: int
    content: bytes
    children: tuple["DerNode", ...] = ()

    @property
    def tag_class(self) -> int:
        return self.tag >> 6

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def tag_number(self) -> int:
        return self.tag & 0x1F


# --- decoder -------------------------------------------------------------


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    """Read a DER length field. Returns (length, next_pos)."""
    if pos >= len(data):
        raise InvalidSerialization("truncated DER: missing length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0:
        raise InvalidSerialization("indefinite length is not DER")
    if count > _MAX_LEN_OCTETS:
        raise InvalidSerialization("DER length field too large")
    if pos + count > len(data):
        raise InvalidSerialization("truncated DER length field")
    if data[pos] == 0:
        raise InvalidSerialization("non-minimal DER length encoding")
    length = int.from_bytes(data[pos : pos + count], "big")
    pos += count
    if length < 0x80:
        raise InvalidSerialization("long-form length used for short value")
    return length, pos


def _validate_integer(content: bytes) -> None:
    if not content:
        raise InvalidSerialization("empty INTEGER content")
    if len(content) > 1:
        if content[0] == 0x00 and content[1] < 0x80:
            raise InvalidSerialization("non-minimal positive INTEGER")
        if content[0] == 0xFF and content[1] >= 0x80:
            raise InvalidSerialization("non-minimal negative INTEGER")


def _validate_bit_string(content: bytes) -> None:
    if not content:
        raise InvalidSerialization("empty BIT STRING content")
    unused = content[0]
    if unused > 7:
        raise InvalidSerialization("BIT STRING unused-bit count > 7")
    if len(content) == 1 and unused != 0:
        raise InvalidSerialization("empty BIT STRING claims unused bits")
    if unused and (content[-1] & ((1 << unused) - 1)):
        raise InvalidSerialization("BIT STRING has nonzero trailing bits")


def _parse_base128(content: bytes) -> list[int]:
    """Strict base-128 subidentifier parse used for OIDs."""
    arcs: list[int] = []
    i = 0
    while i < len(content):
        value = 0
        while True:
            if i >= len(content):
                raise InvalidSerialization("truncated OID arc")
            octet = content[i]
            i += 1
            if value == 0 and octet == 0x80:
                raise InvalidSerialization("non-minimal OID arc")
            value = (value << 7) | (octet & 0x7F)
            if not octet & 0x80:
                break
        arcs.append(value)
    return arcs


def _check_universal_tag(tag: int) -> None:
    """Enforce DER primitive/constructed rules for universal tags."""
    if tag == _EOC:
        raise InvalidSerialization("unexpected EOC marker")
    if tag & 0x20:
        if tag not in (TAG_SEQUENCE, TAG_SET):
            raise InvalidSerialization(
                "constructed encoding of universal primitive type"
            )
    elif tag in (_PRIMITIVE_SEQUENCE, _PRIMITIVE_SET):
        raise InvalidSerialization("primitive encoding of SEQUENCE/SET")


def _validate_content(tag: int, content: bytes) -> None:
    """Per-tag DER content rules checked at decode time."""
    if tag == TAG_INTEGER:
        _validate_integer(content)
    elif tag == TAG_BIT_STRING:
        _validate_bit_string(content)
    elif tag == TAG_OID:
        if not content:
            raise InvalidSerialization("empty OID content")
        _parse_base128(content)


def _read_children(content: bytes, depth: int) -> tuple[DerNode, ...]:
    if depth >= _MAX_NESTING:
        raise InvalidSerialization("DER nesting too deep")
    kids: list[DerNode] = []
    pos = 0
    while pos < len(content):
        child, pos = _read_tlv(content, pos, depth + 1)
        kids.append(child)
    return tuple(kids)


def _read_tlv(data: bytes, pos: int, depth: int) -> tuple[DerNode, int]:
    if pos >= len(data):
        raise InvalidSerialization("truncated DER: missing tag")
    tag = data[pos]
    pos += 1
    if tag & 0x1F == 0x1F:
        raise InvalidSerialization("multi-byte tags are not supported")
    if tag >> 6 == _CLASS_UNIVERSAL:
        _check_universal_tag(tag)
    length, pos = _read_length(data, pos)
    end = pos + length
    if end > len(data):
        raise InvalidSerialization("DER length exceeds available input")
    content = data[pos:end]
    _validate_content(tag, content)
    children: tuple[DerNode, ...] = ()
    if tag & 0x20:
        children = _read_children(content, depth)
    return DerNode(tag=tag, content=content, children=children), end


def decode(data: bytes | bytearray | memoryview) -> DerNode:
    """Decode exactly one top-level DER element.

    Raises InvalidSerialization on any malformation, including trailing
    bytes after the first complete element.
    """
    raw = bytes(data)
    node, end = _read_tlv(raw, 0, 0)
    if end != len(raw):
        raise InvalidSerialization("trailing data after DER element")
    return node


def decode_all(data: bytes | bytearray | memoryview) -> tuple[DerNode, ...]:
    """Decode a concatenation of DER elements (must consume all input)."""
    raw = bytes(data)
    nodes: list[DerNode] = []
    pos = 0
    while pos < len(raw):
        node, pos = _read_tlv(raw, pos, 0)
        nodes.append(node)
    return tuple(nodes)


# --- typed accessors -------------------------------------------------------


def expect(node: DerNode, tag: int) -> DerNode:
    """Require node to carry exactly the given full tag byte."""
    if node.tag != tag:
        raise InvalidSerialization(f"expected tag 0x{tag:02x}, got 0x{node.tag:02x}")
    return node


def sequence_value(node: DerNode) -> tuple[DerNode, ...]:
    return expect(node, TAG_SEQUENCE).children


def int_value(node: DerNode) -> int:
    """Non-negative INTEGER value. Negative encodings are rejected."""
    expect(node, TAG_INTEGER)
    if node.content[0] & 0x80:
        raise InvalidSerialization("negative INTEGER where unsigned expected")
    return int.from_bytes(node.content, "big")


def signed_int_value(node: DerNode) -> int:
    expect(node, TAG_INTEGER)
    return int.from_bytes(node.content, "big", signed=True)


def octet_string_value(node: DerNode) -> bytes:
    return expect(node, TAG_OCTET_STRING).content


def bit_string_parts(node: DerNode) -> tuple[int, bytes]:
    """Return (unused_bit_count, payload) of a BIT STRING."""
    expect(node, TAG_BIT_STRING)
    return node.content[0], node.content[1:]


def bit_string_value(node: DerNode) -> bytes:
    """BIT STRING payload, requiring zero unused bits (key material case)."""
    unused, payload = bit_string_parts(node)
    if unused:
        raise InvalidSerialization("BIT STRING with unused bits")
    return payload


def null_value(node: DerNode) -> None:
    expect(node, TAG_NULL)
    if node.content:
        raise InvalidSerialization("NULL with non-empty content")


def oid_value(node: DerNode) -> str:
    expect(node, TAG_OID)
    arcs = _parse_base128(node.content)
    if not arcs:
        raise InvalidSerialization("empty OID content")
    first = arcs[0]
    arc0 = min(first // 40, 2)
    arc1 = first - arc0 * 40
    return ".".join(str(a) for a in (arc0, arc1, *arcs[1:]))


def context_value(node: DerNode, number: int) -> tuple[DerNode, ...]:
    """Children of a constructed context-specific tag [n]."""
    expected = 0xA0 | number
    expect(node, expected)
    return node.children


def context_primitive(node: DerNode, number: int) -> bytes:
    """Content octets of a primitive context-specific tag [n]."""
    expected = 0x80 | number
    return expect(node, expected).content


# --- encoder ---------------------------------------------------------------


def encode_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("negative length")
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def encode_tlv(tag: int, content: bytes | bytearray | memoryview) -> bytes:
    if tag & 0x1F == 0x1F:
        raise ValueError("multi-byte tags are not supported")
    body = bytes(content)
    return bytes([tag]) + encode_length(len(body)) + body


def encode_integer(value: int) -> bytes:
    """Minimal two's-complement DER INTEGER. Non-negative values only."""
    if value < 0:
        raise ValueError("encode_integer supports non-negative values only")
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return encode_tlv(TAG_INTEGER, raw)


def encode_sequence(*items: bytes) -> bytes:
    return encode_tlv(TAG_SEQUENCE, b"".join(items))


def encode_set(*items: bytes) -> bytes:
    return encode_tlv(TAG_SET, b"".join(items))


def encode_octet_string(data: bytes | bytearray | memoryview) -> bytes:
    return encode_tlv(TAG_OCTET_STRING, data)


def encode_bit_string(
    data: bytes | bytearray | memoryview, unused_bits: int = 0
) -> bytes:
    body = bytes(data)
    if not 0 <= unused_bits <= 7:
        raise ValueError("unused_bits must be 0..7")
    if not body and unused_bits:
        raise ValueError("empty bit string cannot claim unused bits")
    if unused_bits and (body[-1] & ((1 << unused_bits) - 1)):
        raise ValueError("unused low bits of last octet are nonzero")
    return encode_tlv(TAG_BIT_STRING, bytes([unused_bits]) + body)


def encode_null() -> bytes:
    return encode_tlv(TAG_NULL, b"")


def _base128(value: int) -> bytes:
    out = bytearray()
    while True:
        out.insert(0, value & 0x7F)
        value >>= 7
        if not value:
            break
    for i in range(len(out) - 1):
        out[i] |= 0x80
    return bytes(out)


def encode_oid(dotted: str) -> bytes:
    """Encode an OBJECT IDENTIFIER from dotted-decimal form."""
    parts = dotted.split(".")
    if len(parts) < 2:
        raise ValueError("OID needs at least two arcs")
    try:
        arcs = [int(p, 10) for p in parts]
    except ValueError as exc:
        raise ValueError(f"invalid OID arc in {dotted!r}") from exc
    if arcs[0] not in (0, 1, 2):
        raise ValueError("first OID arc must be 0, 1 or 2")
    if arcs[0] < 2 and not 0 <= arcs[1] <= 39:
        raise ValueError("second OID arc must be 0..39 when first is 0 or 1")
    if any(a < 0 for a in arcs):
        raise ValueError("negative OID arc")
    content = _base128(40 * arcs[0] + arcs[1])
    for arc in arcs[2:]:
        content += _base128(arc)
    return encode_tlv(TAG_OID, content)


def encode_context(number: int, *inner_tlvs: bytes) -> bytes:
    """Constructed context tag [n] wrapping complete inner encodings."""
    if not 0 <= number <= 30:
        raise ValueError("context tag number out of range")
    return encode_tlv(0xA0 | number, b"".join(inner_tlvs))


def encode_context_primitive(
    number: int, content: bytes | bytearray | memoryview
) -> bytes:
    """Primitive context tag [n] wrapping raw content octets."""
    if not 0 <= number <= 30:
        raise ValueError("context tag number out of range")
    return encode_tlv(0x80 | number, content)
