# SPDX-License-Identifier: 0BSD
"""Tests for purecrypt.x509 against openssl-generated fixtures.

Fixtures live in tests/data and are produced by tests/data/generate.sh
with the openssl CLI. All keys are throwaway test material.
"""

import contextlib
import hashlib
import ipaddress
import random
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from purecrypt import asn1, x509
from purecrypt.exceptions import (
    InvalidCertificate,
    InvalidSerialization,
    InvalidSignature,
    PureCryptError,
    UnsupportedAlgorithm,
)
from purecrypt.rsa import RSAPublicKey
from purecrypt.x509 import (
    Certificate,
    build_chain,
    load_pem_bundle,
    validate_chain,
    verify_hostname,
)

DATA = Path(__file__).resolve().parent / "data"

Chain = tuple[Certificate, Certificate, Certificate]

CERT_FILES = sorted(
    p.stem
    for p in DATA.glob("*.pem")
    if "_key" not in p.name and p.stem not in ("bundle", "zero_serial")
)


def load(name: str) -> Certificate:
    return Certificate.from_pem((DATA / f"{name}.pem").read_bytes())


def _time_node(tag: int, content: bytes) -> asn1.DerNode:
    return asn1.decode(asn1.encode_tlv(tag, content))


def _utc(content: bytes) -> asn1.DerNode:
    return _time_node(0x17, content)


def _name_der(rdns: list[list[tuple[str, int, bytes]]]) -> bytes:
    return asn1.encode_sequence(
        *(
            asn1.encode_set(
                *(
                    asn1.encode_sequence(
                        asn1.encode_oid(oid), asn1.encode_tlv(tag, raw)
                    )
                    for oid, tag, raw in rdn
                )
            )
            for rdn in rdns
        )
    )


@pytest.fixture(scope="module", name="rsa_chain")
def _rsa_chain() -> Chain:
    return load("rsa_leaf"), load("rsa_inter"), load("rsa_root")


class TestParsing:
    @pytest.mark.parametrize("name", CERT_FILES)
    def test_parses_every_fixture(self, name: str) -> None:
        cert = load(name)
        expected = 1 if name == "v1_root" else 3
        assert cert.version == expected
        assert cert.serial_number > 0
        assert cert.not_valid_before.tzinfo is not None
        assert cert.not_valid_after.tzinfo is not None
        assert cert.tbs_der
        assert cert.der

    def test_from_der_matches_pem(self) -> None:
        cert = Certificate.from_der((DATA / "rsa_leaf.der").read_bytes())
        assert cert.der == (DATA / "rsa_leaf.der").read_bytes()
        assert cert.serial_number == 3001

    def test_der_round_trip_of_tbs(self, rsa_chain: Chain) -> None:
        leaf = rsa_chain[0]
        node = asn1.decode(leaf.tbs_der)
        assert node.tag == asn1.TAG_SEQUENCE

    def test_subject_and_issuer(self, rsa_chain: Chain) -> None:
        leaf, inter, root = rsa_chain
        assert leaf.issuer == inter.subject
        assert inter.issuer == root.subject
        assert root.is_self_signed
        assert not leaf.is_self_signed
        assert leaf.subject.get("CN") == "cn-fallback.invalid"
        assert leaf.subject.get("2.5.4.6") == "US"
        assert leaf.subject.get("nonsense") is None

    def test_rfc4514(self, rsa_chain: Chain) -> None:
        assert (
            rsa_chain[2].subject.rfc4514() == "CN=PureCrypt Test RSA Root,O=Quad4,C=US"
        )

    def test_rfc4514_escapes_control_chars(self) -> None:
        der = _name_der([[("2.5.4.3", 0x0C, b"a\x01b")]])
        name = x509._parse_name(asn1.decode(der))
        assert name.rfc4514() == "CN=a\\01b"
        empty = x509._parse_name(asn1.decode(_name_der([[("2.5.4.3", 0x0C, b"")]])))
        assert empty.rfc4514() == "CN="

    def test_name_parse_errors(self) -> None:
        empty_rdn = asn1.decode(asn1.encode_sequence(asn1.encode_set()))
        with pytest.raises(InvalidCertificate, match="empty RDN"):
            x509._parse_name(empty_rdn)
        bad_atv = asn1.decode(
            asn1.encode_sequence(
                asn1.encode_set(asn1.encode_sequence(asn1.encode_oid("2.5.4.3")))
            )
        )
        with pytest.raises(InvalidCertificate):
            x509._parse_name(bad_atv)
        bad_str = asn1.decode(_name_der([[("2.5.4.3", 0x09, b"weird")]]))
        with pytest.raises(InvalidCertificate, match="string tag"):
            x509._parse_name(bad_str)

    def test_rfc4514_escaping_and_multivalued(self) -> None:
        der = _name_der(
            [
                [("2.5.4.3", 0x0C, b"a,b")],
                [
                    ("2.5.4.10", 0x0C, b"x"),
                    ("2.5.4.11", 0x0C, b"y"),
                ],
            ]
        )
        name = x509._parse_name(asn1.decode(der))
        assert name.rfc4514() == "O=x+OU=y,CN=a\\,b"
        assert name.get("CN") == "a,b"
        assert name.get_all("OU") == ("y",)

    def test_name_string_types(self) -> None:
        der = _name_der(
            [
                [("2.5.4.3", 0x1E, "bmp".encode("utf-16-be"))],
                [("2.5.4.10", 0x1C, "uni".encode("utf-32-be"))],
                [("2.5.4.11", 0x14, b"\xe9")],  # Teletex as latin-1
            ]
        )
        name = x509._parse_name(asn1.decode(der))
        assert name.get("CN") == "bmp"
        assert name.get("O") == "uni"
        assert name.get("OU") == "é"

    def test_fingerprint(self, rsa_chain: Chain) -> None:
        leaf = rsa_chain[0]
        assert leaf.fingerprint() == hashlib.sha256(leaf.der).digest()
        assert leaf.fingerprint("sha512") == hashlib.sha512(leaf.der).digest()
        with pytest.raises(UnsupportedAlgorithm):
            leaf.fingerprint("blake9")
        assert leaf.signature == leaf.der[-256:]

    def test_signature_algorithm_names(self) -> None:
        assert load("rsa_leaf").signature_algorithm == "sha256WithRSAEncryption"
        assert load("ec_leaf").signature_algorithm == "ecdsa-with-SHA256"
        assert load("ed25519_leaf").signature_algorithm == "Ed25519"
        assert load("pss_leaf").signature_algorithm == "RSASSA-PSS"
        assert load("sha1_leaf").signature_algorithm == "sha1WithRSAEncryption"

    def test_extensions_view(self, rsa_chain: Chain) -> None:
        leaf, inter, _root = rsa_chain
        bc = leaf.basic_constraints
        assert bc is not None
        assert not bc.ca
        assert inter.basic_constraints is not None
        assert inter.basic_constraints.ca
        assert inter.basic_constraints.path_length == 1
        assert leaf.key_usage == frozenset({"digitalSignature", "keyEncipherment"})
        assert "1.3.6.1.5.5.7.3.1" in (leaf.extended_key_usage or ())
        ext = leaf.extension("2.5.29.17")
        assert ext is not None
        assert not ext.critical
        assert leaf.extension("1.2.3.4") is None
        assert inter.authority_key_identifier is not None
        assert inter.authority_key_identifier == rsa_chain[2].subject_key_identifier
        kinds = {gn.kind for gn in (leaf.subject_alt_names or ())}
        assert {"dns", "ip", "email", "uri", "oid"} <= kinds
        ian = rsa_chain[2].issuer_alt_names
        assert ian is not None
        assert ian[0].value == "ca.example.com"

    def test_san_properties(self, rsa_chain: Chain) -> None:
        leaf = rsa_chain[0]
        assert set(leaf.san_dns_names) == {
            "www.example.com",
            "*.example.com",
            "example.org",
        }
        assert ipaddress.ip_address("127.0.0.1") in leaf.san_ip_addresses
        assert ipaddress.ip_address("::1") in leaf.san_ip_addresses
        nosan = load("rsa_leaf_nosan")
        assert nosan.san_dns_names == ()
        assert nosan.subject_alt_names is None

    def test_from_pem_rejects_bundle(self) -> None:
        bundle = (DATA / "bundle.pem").read_text()
        with pytest.raises(InvalidSerialization):
            Certificate.from_pem(bundle)

    def test_from_pem_rejects_other_label(self) -> None:
        key_pem = (DATA / "rsa_root_key.pem").read_text()
        with pytest.raises(InvalidSerialization):
            Certificate.from_pem(key_pem)

    def test_from_der_rejects_garbage(self) -> None:
        with pytest.raises(PureCryptError):
            Certificate.from_der(b"\x30\x03\x01\x01\xff")
        with pytest.raises(PureCryptError):
            Certificate.from_der(load("rsa_leaf").der + b"\x00")

    def test_zero_serial_rejected(self) -> None:
        # openssl will issue serial 0 even though RFC 5280 forbids it.
        with pytest.raises(InvalidCertificate, match="serial"):
            load("zero_serial")

    def test_extension_parse_errors(self) -> None:
        short = asn1.encode_sequence(asn1.encode_oid("1.2.3.4"))
        node = asn1.decode(asn1.encode_sequence(short))
        with pytest.raises(InvalidCertificate, match="malformed extension"):
            x509._parse_extensions(node)
        ext = asn1.encode_sequence(
            asn1.encode_oid("1.2.3.4"),
            asn1.encode_octet_string(asn1.encode_null()),
        )
        dup = asn1.decode(asn1.encode_sequence(ext + ext))
        with pytest.raises(InvalidCertificate, match="duplicate"):
            x509._parse_extensions(dup)
        bad_flag = asn1.encode_sequence(
            asn1.encode_oid("1.2.3.4"),
            asn1.encode_tlv(0x01, b"\x01"),  # non-canonical TRUE
            asn1.encode_octet_string(asn1.encode_null()),
        )
        node = asn1.decode(asn1.encode_sequence(bad_flag))
        with pytest.raises(InvalidCertificate, match="BOOLEAN"):
            x509._parse_extensions(node)

    def test_basic_constraints_edge(self) -> None:
        bc = x509._parse_basic_constraints(asn1.encode_sequence())
        assert not bc.ca
        assert bc.path_length is None
        bc = x509._parse_basic_constraints(
            asn1.encode_sequence(asn1.encode_tlv(0x01, b"\xff"), asn1.encode_integer(2))
        )
        assert bc.ca
        assert bc.path_length == 2
        with pytest.raises(InvalidCertificate):
            x509._parse_basic_constraints(
                asn1.encode_sequence(
                    asn1.encode_tlv(0x01, b"\xff"),
                    asn1.encode_integer(0),
                    asn1.encode_null(),
                )
            )

    def test_general_name_other(self) -> None:
        names = x509._parse_general_names(
            asn1.encode_sequence(asn1.encode_tlv(0xA0, b"\x30\x00"))
        )
        assert names[0].kind == "other"
        bad_ip = asn1.encode_sequence(asn1.encode_tlv(0x87, b"\x01\x02"))
        with pytest.raises(InvalidCertificate, match="iPAddress"):
            x509._parse_general_names(bad_ip)
        bad_dir = asn1.encode_sequence(
            asn1.encode_tlv(0xA4, asn1.encode_sequence() + asn1.encode_sequence())
        )
        with pytest.raises(InvalidCertificate, match="directoryName"):
            x509._parse_general_names(bad_dir)


def _alg_id(oid: str, params: bytes = b"\x05\x00") -> bytes:
    return asn1.encode_sequence(asn1.encode_oid(oid), params)


_SHA256_ALG = _alg_id("2.16.840.1.101.3.4.2.1")
_SHA384_ALG = _alg_id("2.16.840.1.101.3.4.2.2")
_MGF1_SHA256 = _alg_id("1.2.840.113549.1.1.8", _SHA256_ALG)
_MGF1_SHA384 = _alg_id("1.2.840.113549.1.1.8", _SHA384_ALG)


class TestPssParams:
    def _params(self, *fields: bytes) -> asn1.DerNode:
        return asn1.decode(asn1.encode_sequence(*fields))

    def test_empty_is_defaults(self) -> None:
        assert x509._parse_pss_params(self._params()) == ("sha1", 20)

    def test_full_params(self) -> None:
        node = self._params(
            asn1.encode_context(0, _SHA256_ALG),
            asn1.encode_context(1, _MGF1_SHA256),
            asn1.encode_context(2, asn1.encode_integer(32)),
            asn1.encode_context(3, asn1.encode_integer(1)),
        )
        assert x509._parse_pss_params(node) == ("sha256", 32)

    def test_mgf_must_be_mgf1(self) -> None:
        node = self._params(asn1.encode_context(1, _SHA256_ALG))
        with pytest.raises(InvalidCertificate, match="MGF1"):
            x509._parse_pss_params(node)

    def test_trailer_must_be_one(self) -> None:
        node = self._params(asn1.encode_context(3, asn1.encode_integer(2)))
        with pytest.raises(InvalidCertificate, match="trailerField"):
            x509._parse_pss_params(node)

    def test_mgf_hash_mismatch(self) -> None:
        node = self._params(
            asn1.encode_context(0, _SHA256_ALG),
            asn1.encode_context(1, _MGF1_SHA384),
        )
        with pytest.raises(InvalidCertificate, match="MGF hash"):
            x509._parse_pss_params(node)

    def test_malformed_fields(self) -> None:
        with pytest.raises(InvalidCertificate, match="PSS params"):
            x509._parse_pss_params(
                self._params(asn1.encode_context(4, asn1.encode_integer(1)))
            )
        with pytest.raises(InvalidCertificate, match="PSS params"):
            x509._parse_pss_params(self._params(asn1.encode_context_primitive(0, b"")))
        with pytest.raises(InvalidCertificate, match="PSS params"):
            x509._parse_pss_params(
                self._params(
                    asn1.encode_context(0, _SHA256_ALG),
                    asn1.encode_context(0, _SHA256_ALG),
                )
            )

    def test_hash_alg_problems(self) -> None:
        bad_params = self._params(
            asn1.encode_context(
                0, _alg_id("2.16.840.1.101.3.4.2.1", asn1.encode_integer(1))
            )
        )
        with pytest.raises(InvalidCertificate, match="NULL"):
            x509._parse_pss_params(bad_params)
        unknown = self._params(asn1.encode_context(0, _alg_id("1.2.3.4")))
        with pytest.raises(InvalidCertificate, match="unsupported hash"):
            x509._parse_pss_params(unknown)

    def test_sig_params_rules(self) -> None:
        not_null = asn1.decode(asn1.encode_octet_string(b"x"))
        with pytest.raises(InvalidCertificate, match="NULL"):
            x509._check_sig_params("1.2.840.113549.1.1.11", not_null)
        with pytest.raises(InvalidCertificate, match="absent"):
            x509._check_sig_params(
                "1.2.840.10045.4.3.2", asn1.decode(asn1.encode_null())
            )
        with pytest.raises(InvalidCertificate, match="required"):
            x509._check_sig_params("1.2.840.113549.1.1.10", None)


def _rsa_root_spki() -> bytes:
    key = load("rsa_root").public_key
    assert isinstance(key, RSAPublicKey)
    return key.to_spki_der()


def _minimal_tbs(*extra: bytes) -> asn1.DerNode:
    fields = [
        asn1.encode_integer(1),
        _alg_id("1.2.840.113549.1.1.11"),
        asn1.encode_sequence(),
        asn1.encode_sequence(
            asn1.encode_tlv(0x17, b"300101000000Z"),
            asn1.encode_tlv(0x18, b"20310101000000Z"),
        ),
        asn1.encode_sequence(),
        _rsa_root_spki(),
        *extra,
    ]
    return asn1.decode(asn1.encode_sequence(*fields))


class TestTbsEdges:
    def test_version_too_new(self) -> None:
        node = asn1.decode(
            asn1.encode_sequence(asn1.encode_context(0, asn1.encode_integer(3)))
        )
        with pytest.raises(InvalidCertificate, match="version"):
            x509._parse_tbs(node)

    def test_version_malformed(self) -> None:
        node = asn1.decode(
            asn1.encode_sequence(
                asn1.encode_context(0, asn1.encode_integer(2) + asn1.encode_integer(2))
            )
        )
        with pytest.raises(InvalidCertificate, match="version"):
            x509._parse_tbs(node)

    def test_too_short(self) -> None:
        node = asn1.decode(asn1.encode_sequence(asn1.encode_integer(1)))
        with pytest.raises(InvalidCertificate, match="too short"):
            x509._parse_tbs(node)

    def test_bad_validity(self) -> None:
        node = asn1.decode(
            asn1.encode_sequence(
                asn1.encode_integer(1),
                _alg_id("1.2.840.113549.1.1.11"),
                asn1.encode_sequence(),
                asn1.encode_sequence(asn1.encode_tlv(0x17, b"300101000000Z")),
                asn1.encode_sequence(),
                _rsa_root_spki(),
            )
        )
        with pytest.raises(InvalidCertificate, match="validity"):
            x509._parse_tbs(node)

    def test_minimal_parses(self) -> None:
        parsed = x509._parse_tbs(_minimal_tbs())
        assert parsed[0] == 1  # v1 default

    def test_tail_ordering(self) -> None:
        bad = _minimal_tbs(
            asn1.encode_context(3, asn1.encode_sequence()),
            asn1.encode_context_primitive(1, b"\x00\x80"),
        )
        with pytest.raises(InvalidCertificate, match="unexpected"):
            x509._parse_tbs(bad)
        ok = _minimal_tbs(
            asn1.encode_context_primitive(1, b"\x00\x80"),
            asn1.encode_context_primitive(2, b"\x00\x40"),
            asn1.encode_context(3, asn1.encode_sequence()),
        )
        x509._parse_tbs(ok)

    def test_bad_extensions_wrapper(self) -> None:
        node = _minimal_tbs(
            asn1.encode_context(3, asn1.encode_sequence() + asn1.encode_sequence())
        )
        with pytest.raises(InvalidCertificate, match="extensions"):
            x509._parse_tbs(node)

    def test_unknown_tail_field(self) -> None:
        node = _minimal_tbs(asn1.encode_context(4))
        with pytest.raises(InvalidCertificate, match="unexpected"):
            x509._parse_tbs(node)

    def test_first_tlv_bounds(self) -> None:
        with pytest.raises(InvalidCertificate):
            x509._first_tlv(b"\x30")
        with pytest.raises(InvalidCertificate):
            x509._first_tlv(b"\x30\x80")
        with pytest.raises(InvalidCertificate):
            x509._first_tlv(b"\x30\x89" + b"\x01" * 9)
        with pytest.raises(InvalidCertificate):
            x509._first_tlv(b"\x30\x02\xff")


class TestTimes:
    @pytest.mark.parametrize(
        ("content", "year"),
        [
            (b"491231235959Z", 2049),
            (b"500101000000Z", 1950),
            (b"990101000000Z", 1999),
            (b"260101120000+0530", 2026),
        ],
    )
    def test_utc_time(self, content: bytes, year: int) -> None:
        dt = x509._parse_time(_utc(content))
        assert dt.tzinfo == timezone.utc
        assert dt.year == year

    def test_utc_offset_normalizes(self) -> None:
        dt = x509._parse_time(_utc(b"260101120000+0530"))
        assert (dt.hour, dt.minute) == (6, 30)

    def test_generalized_time(self) -> None:
        dt = x509._parse_time(_time_node(0x18, b"20500101000000Z"))
        assert dt.year == 2050

    @pytest.mark.parametrize(
        ("tag", "content"),
        [
            (0x17, b"491231235959"),  # missing zone
            (0x17, b"49123123595Z"),  # short
            (0x17, b"4912312359595Z"),  # long
            (0x17, b"491331235959Z"),  # month 13
            (0x17, b"491231246059Z"),  # hour 24
            (0x17, b"491231235959+2460"),  # bad offset
            (0x18, b"2050010100000Z"),  # short generalized
            (0x18, b"20500101000000.5Z"),  # fractional
            (0x04, b"491231235959Z"),  # wrong tag
        ],
    )
    def test_rejects_malformed(self, tag: int, content: bytes) -> None:
        with pytest.raises(InvalidCertificate):
            x509._parse_time(_time_node(tag, content))


class TestSignatures:
    def test_rsa_chain_signatures(self, rsa_chain: Chain) -> None:
        leaf, inter, root = rsa_chain
        leaf.verify_issuer_signature(inter.public_key)
        inter.verify_issuer_signature(root.public_key)
        root.verify_issuer_signature(root.public_key)

    def test_ec_and_ed25519(self) -> None:
        ec_leaf = load("ec_leaf")
        ec_leaf.verify_issuer_signature(load("ec_root").public_key)
        ed_leaf = load("ed25519_leaf")
        ed_leaf.verify_issuer_signature(load("ed25519_root").public_key)

    def test_pss(self) -> None:
        load("pss_leaf").verify_issuer_signature(load("rsa_root").public_key)

    def test_tampered_signature(self, rsa_chain: Chain) -> None:
        leaf, inter, _root = rsa_chain
        der = bytearray(leaf.der)
        der[-1] ^= 0x01
        tampered = Certificate.from_der(bytes(der))
        with pytest.raises(InvalidSignature):
            tampered.verify_issuer_signature(inter.public_key)

    def test_wrong_key_type(self, rsa_chain: Chain) -> None:
        leaf = rsa_chain[0]
        with pytest.raises(InvalidCertificate):
            leaf.verify_issuer_signature(load("ec_root").public_key)
        with pytest.raises(InvalidCertificate):
            load("ec_leaf").verify_issuer_signature(load("rsa_root").public_key)
        with pytest.raises(InvalidCertificate):
            load("ed25519_leaf").verify_issuer_signature(load("rsa_root").public_key)

    def test_wrong_key_same_type(self, rsa_chain: Chain) -> None:
        leaf = rsa_chain[0]
        with pytest.raises(InvalidSignature):
            leaf.verify_issuer_signature(load("untrusted_root").public_key)

    def test_weak_sha1_rejected_by_default(self) -> None:
        sha1 = load("sha1_leaf")
        with pytest.raises(InvalidCertificate, match="weak"):
            sha1.verify_issuer_signature(load("rsa_root").public_key)
        sha1.verify_issuer_signature(load("rsa_root").public_key, allow_weak=True)

    def _swap_sig_oid(self, cert: Certificate, last_byte: int) -> Certificate:
        # Rewrite both AlgorithmIdentifier OID copies (tbs and outer).
        oid = bytes.fromhex("06092a864886f70d010105")
        der = cert.der
        assert der.count(oid) == 2
        return Certificate.from_der(der.replace(oid, oid[:-1] + bytes([last_byte])))

    def test_md2_never_accepted(self) -> None:
        cert = self._swap_sig_oid(load("sha1_leaf"), 0x02)
        assert cert.signature_algorithm == "md2WithRSAEncryption"
        with pytest.raises(InvalidCertificate, match="never accepted"):
            cert.verify_issuer_signature(load("rsa_root").public_key, allow_weak=True)

    def test_unknown_signature_oid(self) -> None:
        cert = self._swap_sig_oid(load("sha1_leaf"), 0x63)
        with pytest.raises(InvalidCertificate, match="unsupported signature"):
            cert.verify_issuer_signature(load("rsa_root").public_key)

    def test_pss_wrong_key_type(self) -> None:
        with pytest.raises(InvalidCertificate):
            load("pss_leaf").verify_issuer_signature(load("ec_root").public_key)


class TestChains:
    def test_rsa_three_level(self, rsa_chain: Chain) -> None:
        leaf, inter, root = rsa_chain
        chain = validate_chain(leaf, [inter], [root])
        assert [c.subject.get("CN") for c in chain] == [
            "cn-fallback.invalid",
            "PureCrypt Test RSA Intermediate",
            "PureCrypt Test RSA Root",
        ]

    def test_intermediate_order_irrelevant(self, rsa_chain: Chain) -> None:
        leaf, inter, root = rsa_chain
        chain = validate_chain(leaf, [root, inter], [root])
        assert len(chain) == 3

    def test_ec_chain(self) -> None:
        chain = validate_chain(load("ec_leaf"), [], [load("ec_root")])
        assert len(chain) == 2

    def test_ed25519_chain(self) -> None:
        chain = validate_chain(load("ed25519_leaf"), [], [load("ed25519_root")])
        assert len(chain) == 2

    def test_pss_leaf(self) -> None:
        assert len(validate_chain(load("pss_leaf"), [], [load("rsa_root")])) == 2

    def test_nosan_leaf(self, rsa_chain: Chain) -> None:
        chain = validate_chain(load("rsa_leaf_nosan"), [rsa_chain[1]], [rsa_chain[2]])
        assert len(chain) == 3

    def test_leaf_as_trust_anchor(self, rsa_chain: Chain) -> None:
        assert validate_chain(rsa_chain[2], [], [rsa_chain[2]]) == [rsa_chain[2]]

    def test_untrusted_root_rejected(self) -> None:
        with pytest.raises(InvalidCertificate, match="no path"):
            validate_chain(load("untrusted_leaf"), [], [load("rsa_root")])

    def test_wrong_intermediate(self) -> None:
        with pytest.raises(InvalidCertificate):
            validate_chain(load("rsa_leaf"), [load("rsa_inter_p0")], [load("rsa_root")])

    def test_expired_rejected(self) -> None:
        with pytest.raises(InvalidCertificate, match="expired"):
            validate_chain(load("expired_leaf"), [], [load("expired_root")])

    def test_expired_valid_at_past_moment(self) -> None:
        moment = datetime(2020, 6, 1, tzinfo=timezone.utc)
        chain = validate_chain(
            load("expired_leaf"), [], [load("expired_root")], moment=moment
        )
        assert len(chain) == 2

    def test_not_yet_valid(self) -> None:
        moment = datetime(2019, 6, 1, tzinfo=timezone.utc)
        with pytest.raises(InvalidCertificate, match="not yet valid"):
            validate_chain(
                load("expired_leaf"),
                [],
                [load("expired_root")],
                moment=moment,
            )

    def test_naive_moment_rejected(self) -> None:
        with pytest.raises(InvalidCertificate, match="timezone-aware"):
            validate_chain(
                load("expired_leaf"),
                [],
                [load("expired_root")],
                moment=datetime(2020, 6, 1, tzinfo=timezone.utc).replace(tzinfo=None),
            )

    def test_tampered_leaf_fails_chain(self, rsa_chain: Chain) -> None:
        leaf, inter, root = rsa_chain
        der = bytearray(leaf.der)
        der[-1] ^= 0x01
        tampered = Certificate.from_der(bytes(der))
        with pytest.raises(InvalidCertificate):
            validate_chain(tampered, [inter], [root])

    def test_critical_unknown_extension(self) -> None:
        with pytest.raises(InvalidCertificate, match="critical extension"):
            validate_chain(load("critext_leaf"), [], [load("rsa_root")])

    def test_path_len_constraint(self) -> None:
        # rsa_inter_p0 has pathlen:0 but rsa_subca sits below it as a CA.
        with pytest.raises(InvalidCertificate, match="pathLenConstraint"):
            validate_chain(
                load("rsa_subleaf"),
                [load("rsa_subca"), load("rsa_inter_p0")],
                [load("rsa_root")],
            )
        # The CA cert itself validates fine as a leaf: the leaf never
        # counts toward pathLenConstraint.
        assert (
            len(
                validate_chain(
                    load("rsa_subca"),
                    [load("rsa_inter_p0")],
                    [load("rsa_root")],
                )
            )
            == 3
        )

    def test_issuer_without_ca_flag(self) -> None:
        # plain_root has no basicConstraints but asserts a keyUsage
        # without keyCertSign. openssl rejects it the same way.
        with pytest.raises(InvalidCertificate, match="keyCertSign"):
            validate_chain(load("plain_leaf"), [], [load("plain_root")])

    def test_issuer_without_keycertsign(self) -> None:
        with pytest.raises(InvalidCertificate, match="keyCertSign"):
            validate_chain(load("ku_leaf"), [], [load("ku_root")])

    def test_leaf_without_digital_signature(self, rsa_chain: Chain) -> None:
        # openssl accepts this. The strict leaf rule is documented.
        with pytest.raises(InvalidCertificate, match="digitalSignature"):
            validate_chain(load("rsa_leaf_nods"), [rsa_chain[1]], [rsa_chain[2]])

    def test_anchor_self_signature_sanity(self, rsa_chain: Chain) -> None:
        der = bytearray(rsa_chain[2].der)
        der[-1] ^= 0x01
        tampered_root = Certificate.from_der(bytes(der))
        with pytest.raises(InvalidCertificate, match="self-signature"):
            validate_chain(tampered_root, [], [rsa_chain[2]])

    def test_sha1_chain_rejected(self) -> None:
        with pytest.raises(InvalidCertificate, match="weak"):
            validate_chain(load("sha1_leaf"), [], [load("rsa_root")])
        assert (
            len(
                validate_chain(
                    load("sha1_leaf"),
                    [],
                    [load("rsa_root")],
                    allow_weak=True,
                )
            )
            == 2
        )

    def test_missing_intermediate(self, rsa_chain: Chain) -> None:
        leaf, _inter, root = rsa_chain
        with pytest.raises(InvalidCertificate, match="no path"):
            build_chain(leaf, [], [root])

    def test_critical_san_accepted(self) -> None:
        # SAN is parsed and fed to hostname matching, so a critical
        # marking is supported rather than failing validation.
        leaf = load("critsan_leaf")
        assert len(validate_chain(leaf, [], [load("rsa_root")])) == 2
        assert verify_hostname(leaf, "critsan.example.com")

    def test_v1_trust_anchor(self) -> None:
        # A version-1 anchor carries no extensions. Its CA status comes
        # from the trust store, not basicConstraints.
        chain = validate_chain(load("v1_leaf"), [], [load("v1_root")])
        assert len(chain) == 2

    def test_negative_version_rejected(self) -> None:
        der = bytearray(load("rsa_leaf").der)
        idx = der.find(b"\xa0\x03\x02\x01\x02")
        assert idx >= 0
        der[idx + 4] = 0xFF  # version INTEGER -1
        with pytest.raises(PureCryptError):
            Certificate.from_der(bytes(der))


class TestHostname:
    @pytest.mark.parametrize(
        ("hostname", "expected"),
        [
            ("www.example.com", True),
            ("WWW.EXAMPLE.COM", True),
            ("www.example.com.", True),
            ("example.org", True),
            ("foo.example.com", True),  # wildcard
            ("a.b.example.com", False),  # wildcard is one label
            ("example.com", False),  # wildcard does not match apex
            ("wwwexample.com", False),
            ("other.org", False),
            ("cn-fallback.invalid", False),  # SAN present, CN ignored
            ("127.0.0.1", True),
            ("::1", True),
            ("10.0.0.1", False),
            ("", False),
        ],
    )
    def test_san_matrix(self, hostname: str, expected: bool) -> None:
        assert verify_hostname(load("rsa_leaf"), hostname) is expected

    def test_cn_fallback_without_san(self) -> None:
        nosan = load("rsa_leaf_nosan")
        assert verify_hostname(nosan, "legacy.example.com")
        assert not verify_hostname(nosan, "other.example.com")
        assert not verify_hostname(nosan, "127.0.0.1")

    def test_partial_wildcard_never_matches(self) -> None:
        assert not x509._dns_name_match("w*.example.com", "www.example.com")
        assert not x509._dns_name_match("*", "anything.example.com")
        assert not x509._dns_name_match("*.example.com", "example.com")
        assert not x509._dns_name_match("*.example.com", ".example.com")


class TestBundles:
    def test_bundle(self) -> None:
        certs = load_pem_bundle((DATA / "bundle.pem").read_text())
        assert len(certs) == 3
        assert certs[0].subject.get("CN") == "cn-fallback.invalid"
        assert len(load_pem_bundle((DATA / "bundle.pem").read_bytes())) == 3

    def test_bundle_skips_other_labels(self) -> None:
        text = (DATA / "rsa_leaf_key.pem").read_text() + (
            DATA / "rsa_leaf.pem"
        ).read_text()
        assert len(load_pem_bundle(text)) == 1

    def test_bundle_requires_cert(self) -> None:
        with pytest.raises(InvalidSerialization):
            load_pem_bundle("no pem here")

    def test_bundle_rejects_unterminated(self) -> None:
        with pytest.raises(InvalidSerialization):
            load_pem_bundle("-----BEGIN CERTIFICATE-----\nAAAA\n")

    def test_bundle_rejects_non_ascii(self) -> None:
        with pytest.raises(InvalidSerialization):
            load_pem_bundle("-----BEGIN CERTIFICATE-----\néééé\n")

    def test_hostname_rejects_bad_idna(self) -> None:
        assert not verify_hostname(load("rsa_leaf"), "\ud800")


OPENSSL = shutil.which("openssl")


def _openssl_verify(leaf: str, inters: list[str], root: str) -> bool:
    assert OPENSSL is not None
    cmd = [OPENSSL, "verify", "-CAfile", str(DATA / f"{root}.pem")]
    for inter in inters:
        cmd += ["-untrusted", str(DATA / f"{inter}.pem")]
    cmd.append(str(DATA / f"{leaf}.pem"))
    proc = subprocess.run(cmd, capture_output=True, check=False)
    return proc.returncode == 0


@pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")
class TestOpenSSLAgreement:
    @pytest.mark.parametrize(
        ("leaf", "inters", "root", "ours"),
        [
            ("rsa_leaf", ["rsa_inter"], "rsa_root", True),
            ("rsa_leaf_nosan", ["rsa_inter"], "rsa_root", True),
            ("ec_leaf", [], "ec_root", True),
            ("ed25519_leaf", [], "ed25519_root", True),
            ("pss_leaf", [], "rsa_root", True),
            ("untrusted_leaf", [], "rsa_root", False),
            ("rsa_leaf", ["rsa_inter"], "untrusted_root", False),
            ("expired_leaf", [], "expired_root", False),
            ("critext_leaf", [], "rsa_root", False),
            ("plain_leaf", [], "plain_root", False),
            ("ku_leaf", [], "ku_root", False),
            ("rsa_subca", ["rsa_inter_p0"], "rsa_root", True),
            (
                "rsa_subleaf",
                ["rsa_subca", "rsa_inter_p0"],
                "rsa_root",
                False,
            ),
        ],
    )
    def test_verify_agrees(
        self, leaf: str, inters: list[str], root: str, ours: bool
    ) -> None:
        openssl_ok = _openssl_verify(leaf, inters, root)
        try:
            validate_chain(
                load(leaf),
                [load(i) for i in inters],
                [load(root)],
            )
            ours_ok = True
        except InvalidCertificate:
            ours_ok = False
        assert ours_ok == ours
        assert openssl_ok == ours_ok

    def test_sha1_divergence_is_deliberate(self) -> None:
        # openssl accepts sha1WithRSAEncryption at its default verify
        # security level. We reject it as weak on purpose.
        assert _openssl_verify("sha1_leaf", [], "rsa_root")
        with pytest.raises(InvalidCertificate):
            validate_chain(load("sha1_leaf"), [], [load("rsa_root")])


class TestFuzz:
    def test_random_and_mutated_inputs(self) -> None:
        rng = random.Random(20260922)  # noqa: S311  # fuzzing, not crypto
        base = load("rsa_leaf").der
        for _ in range(150):
            blob = bytes(rng.getrandbits(8) for _ in range(rng.randrange(65)))
            with contextlib.suppress(PureCryptError):
                Certificate.from_der(blob)
        for _ in range(150):
            mut = bytearray(base)
            for _ in range(rng.randrange(1, 8)):
                mut[rng.randrange(len(mut))] = rng.getrandbits(8)
            if rng.random() < 0.2:
                mut = mut[: rng.randrange(1, len(mut))]
            with contextlib.suppress(PureCryptError):
                Certificate.from_der(bytes(mut))
