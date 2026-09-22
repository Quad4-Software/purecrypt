# SPDX-License-Identifier: 0BSD
"""Tests for purecrypt.asn1 strict DER encoding/decoding."""

import pytest

from purecrypt import asn1
from purecrypt.exceptions import InvalidSerialization


class TestIntegerEncoding:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0, bytes.fromhex("020100")),
            (1, bytes.fromhex("020101")),
            (127, bytes.fromhex("02017f")),
            (128, bytes.fromhex("02020080")),
            (255, bytes.fromhex("020200ff")),
            (256, bytes.fromhex("02020100")),
            (65537, bytes.fromhex("0203010001")),
            (2**64, bytes.fromhex("020901") + b"\x00" * 8),
        ],
    )
    def test_minimal_encoding(self, value: int, expected: bytes) -> None:
        assert asn1.encode_integer(value) == expected

    def test_negative_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            asn1.encode_integer(-1)

    @pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 65537, 2**200])
    def test_round_trip(self, value: int) -> None:
        node = asn1.decode(asn1.encode_integer(value))
        assert asn1.int_value(node) == value


class TestBasicTypes:
    def test_sequence_known_encoding(self) -> None:
        der = asn1.encode_sequence(asn1.encode_integer(1), asn1.encode_null())
        assert der == bytes.fromhex("30050201010500")

    def test_nested_sequence_round_trip(self) -> None:
        inner = asn1.encode_sequence(
            asn1.encode_oid("1.2.840.113549.1.1.1"), asn1.encode_null()
        )
        der = asn1.encode_sequence(inner, asn1.encode_bit_string(b"\xde\xad"))
        node = asn1.decode(der)
        kids = asn1.sequence_value(node)
        assert len(kids) == 2
        alg = asn1.sequence_value(kids[0])
        assert asn1.oid_value(alg[0]) == "1.2.840.113549.1.1.1"
        asn1.null_value(alg[1])
        assert asn1.bit_string_value(kids[1]) == b"\xde\xad"

    def test_octet_string(self) -> None:
        der = asn1.encode_octet_string(b"\x01\x02")
        assert der == bytes.fromhex("04020102")
        node = asn1.decode(der)
        assert asn1.octet_string_value(node) == b"\x01\x02"

    def test_bit_string_unused_bits(self) -> None:
        der = asn1.encode_bit_string(b"\xf0", unused_bits=4)
        assert der == bytes.fromhex("030204f0")
        node = asn1.decode(der)
        unused, payload = asn1.bit_string_parts(node)
        assert unused == 4
        assert payload == b"\xf0"

    def test_bit_string_value_rejects_unused(self) -> None:
        node = asn1.decode(bytes.fromhex("030204f0"))
        with pytest.raises(InvalidSerialization):
            asn1.bit_string_value(node)

    def test_bit_string_bad_args(self) -> None:
        with pytest.raises(ValueError, match="empty bit string"):
            asn1.encode_bit_string(b"", unused_bits=1)
        with pytest.raises(ValueError, match=r"must be 0\.\.7"):
            asn1.encode_bit_string(b"\xff", unused_bits=8)
        with pytest.raises(ValueError, match="unused low bits"):
            asn1.encode_bit_string(b"\x01", unused_bits=1)  # low bit set

    def test_null(self) -> None:
        assert asn1.encode_null() == bytes.fromhex("0500")
        asn1.null_value(asn1.decode(b"\x05\x00"))
        with pytest.raises(InvalidSerialization):
            asn1.null_value(asn1.decode(bytes.fromhex("0501ff")))


class TestOid:
    @pytest.mark.parametrize(
        ("dotted", "expected"),
        [
            ("1.2.840.113549.1.1.1", "06092a864886f70d010101"),
            ("1.2.840.10045.2.1", "06072a8648ce3d0201"),
            ("1.2.840.10045.3.1.7", "06082a8648ce3d030107"),
            ("1.3.132.0.34", "06052b81040022"),
            ("2.16.840.1.101.3.4.2.1", "0609608648016503040201"),
            ("1.3.101.112", "06032b6570"),
        ],
    )
    def test_known_encodings(self, dotted: str, expected: str) -> None:
        assert asn1.encode_oid(dotted) == bytes.fromhex(expected)

    @pytest.mark.parametrize(
        "dotted",
        [
            "1.2.840.113549.1.1.1",
            "2.999.3",
            "0.0",
            "2.16.840.1.101.3.4.2.1",
        ],
    )
    def test_round_trip(self, dotted: str) -> None:
        node = asn1.decode(asn1.encode_oid(dotted))
        assert asn1.oid_value(node) == dotted

    @pytest.mark.parametrize(
        "dotted",
        ["3.1", "1.40", "1", "1.-2.3", "a.b", "1..2", ""],
    )
    def test_encode_rejects_bad_oids(self, dotted: str) -> None:
        with pytest.raises(ValueError, match="OID"):
            asn1.encode_oid(dotted)


class TestContextTags:
    def test_constructed_context(self) -> None:
        der = asn1.encode_context(0, asn1.encode_oid("1.3.132.0.34"))
        assert der[0] == 0xA0
        node = asn1.decode(der)
        kids = asn1.context_value(node, 0)
        assert asn1.oid_value(kids[0]) == "1.3.132.0.34"

    def test_primitive_context(self) -> None:
        der = asn1.encode_context_primitive(1, b"\x99")
        assert der == bytes.fromhex("810199")
        node = asn1.decode(der)
        assert asn1.context_primitive(node, 1) == b"\x99"

    def test_context_range(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            asn1.encode_context(31, b"")
        with pytest.raises(ValueError, match="out of range"):
            asn1.encode_context_primitive(-1, b"")


class TestLengthEncoding:
    @pytest.mark.parametrize(
        ("length", "expected"),
        [
            (0, b"\x00"),
            (127, b"\x7f"),
            (128, b"\x81\x80"),
            (255, b"\x81\xff"),
            (256, b"\x82\x01\x00"),
            (65536, b"\x83\x01\x00\x00"),
        ],
    )
    def test_lengths(self, length: int, expected: bytes) -> None:
        assert asn1.encode_length(length) == expected

    def test_negative_length(self) -> None:
        with pytest.raises(ValueError, match="negative"):
            asn1.encode_length(-1)

    def test_multibyte_tag_rejected(self) -> None:
        with pytest.raises(ValueError, match="multi-byte"):
            asn1.encode_tlv(0x1F, b"")


class TestStrictDecode:
    @pytest.mark.parametrize(
        "hex_input",
        [
            "",  # empty
            "3080",  # indefinite length
            "3081050500",  # long form used for short length
            "3082000505000500050005",  # non-minimal length (leading 0)
            "30ff0500",  # length-of-length too large
            "30050201",  # content truncated
            "0500ff",  # trailing garbage
            "0200",  # empty INTEGER
            "0202007f",  # non-minimal positive INTEGER
            "0202ff80",  # non-minimal negative INTEGER
            "0300",  # BIT STRING missing unused-bits octet
            "03020800",  # unused bits > 7
            "030101",  # empty BIT STRING claims unused bits
            "03020101",  # nonzero trailing bits
            "1000",  # primitive SEQUENCE
            "1100",  # primitive SET
            "220105",  # constructed INTEGER
            "0000",  # stray EOC
            "1f0100",  # high-tag-number form
            "0600",  # empty OID content
            "060180",  # truncated OID arc
            "0602800" + "1",  # non-minimal OID arc
            "30",  # tag without length
            "3085",  # length field truncated
        ],
    )
    def test_rejects_malformed(self, hex_input: str) -> None:
        with pytest.raises(InvalidSerialization):
            asn1.decode(bytes.fromhex(hex_input))

    def test_nesting_bound(self) -> None:
        inner = b"\x05\x00"
        for _ in range(70):
            inner = asn1.encode_sequence(inner)
        with pytest.raises(InvalidSerialization):
            asn1.decode(inner)

    def test_nesting_at_bound_ok(self) -> None:
        inner = b"\x05\x00"
        for _ in range(60):
            inner = asn1.encode_sequence(inner)
        node = asn1.decode(inner)
        assert node.tag == asn1.TAG_SEQUENCE

    def test_decode_all(self) -> None:
        blob = asn1.encode_integer(7) + asn1.encode_null()
        nodes = asn1.decode_all(blob)
        assert len(nodes) == 2
        assert asn1.int_value(nodes[0]) == 7
        with pytest.raises(InvalidSerialization):
            asn1.decode_all(blob + b"\xff")

    def test_int_value_rejects_negative(self) -> None:
        node = asn1.decode(bytes.fromhex("020180"))
        with pytest.raises(InvalidSerialization):
            asn1.int_value(node)
        assert asn1.signed_int_value(node) == -128

    def test_expect_wrong_tag(self) -> None:
        node = asn1.decode(asn1.encode_null())
        with pytest.raises(InvalidSerialization):
            asn1.expect(node, asn1.TAG_INTEGER)

    def test_node_properties(self) -> None:
        node = asn1.decode(asn1.encode_sequence(b""))
        assert node.tag_class == 0
        assert node.constructed
        assert node.tag_number == 16

    def test_der_round_trip_big_structure(self) -> None:
        der = asn1.encode_sequence(
            asn1.encode_integer(0),
            asn1.encode_sequence(
                asn1.encode_oid("1.2.840.113549.1.1.1"), asn1.encode_null()
            ),
            asn1.encode_octet_string(b"\xaa" * 200),
        )
        node = asn1.decode(der)
        kids = asn1.sequence_value(node)
        assert asn1.int_value(kids[0]) == 0
        assert asn1.octet_string_value(kids[2]) == b"\xaa" * 200

    def test_bytearray_and_memoryview_input(self) -> None:
        der = asn1.encode_integer(5)
        assert asn1.int_value(asn1.decode(bytearray(der))) == 5
        assert asn1.int_value(asn1.decode(memoryview(der))) == 5
