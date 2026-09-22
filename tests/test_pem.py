# SPDX-License-Identifier: 0BSD
"""Tests for purecrypt.pem armor handling."""

import pytest

from purecrypt import pem
from purecrypt.exceptions import InvalidSerialization

DER = bytes(range(64))


class TestEncode:
    def test_format(self) -> None:
        text = pem.encode_pem("TEST KEY", DER)
        lines = text.splitlines()
        assert lines[0] == "-----BEGIN TEST KEY-----"
        assert lines[-1] == "-----END TEST KEY-----"
        assert all(len(line) <= 64 for line in lines[1:-1])

    def test_line_wrapping(self) -> None:
        text = pem.encode_pem("X", bytes(200))
        lines = text.splitlines()[1:-1]
        assert all(len(line) == 64 for line in lines[:-1])
        assert len(lines[-1]) <= 64

    @pytest.mark.parametrize("label", ["lowercase", "HAS-DASH", "has(paren)", "", "  "])
    def test_bad_labels(self, label: str) -> None:
        with pytest.raises(ValueError, match="PEM label"):
            pem.encode_pem(label, DER)


class TestDecode:
    def test_round_trip(self) -> None:
        text = pem.encode_pem("RSA PUBLIC KEY", DER)
        label, der = pem.decode_pem(text)
        assert label == "RSA PUBLIC KEY"
        assert der == DER

    def test_decode_bytes_input(self) -> None:
        text = pem.encode_pem("K", DER)
        assert pem.decode_pem(text.encode("ascii"))[1] == DER

    def test_crlf(self) -> None:
        text = pem.encode_pem("K", DER).replace("\n", "\r\n")
        assert pem.decode_pem(text)[1] == DER

    def test_surrounding_text_ignored(self) -> None:
        text = "preamble\n" + pem.encode_pem("K", DER) + "trailer\n"
        assert pem.decode_pem(text)[1] == DER

    def test_blank_lines_inside(self) -> None:
        text = pem.encode_pem("K", DER).replace("\n", "\n\n", 1)
        assert pem.decode_pem(text)[1] == DER

    def test_decode_expect(self) -> None:
        text = pem.encode_pem("K", DER)
        assert pem.decode_pem_expect(text, "K") == DER
        with pytest.raises(InvalidSerialization):
            pem.decode_pem_expect(text, "OTHER")

    @pytest.mark.parametrize(
        "text",
        [
            "-----BEGIN K-----\nQUJD\n-----END OTHER-----\n",  # label mismatch
            "-----BEGIN K-----\nQUJD\n",  # missing END
            "-----BEGIN K-----\n",  # missing everything
            "-----BEGIN K-----\n@@@\n-----END K-----\n",  # non-base64
            "-----BEGIN K-----\nProc-Type: 4,ENCRYPTED\nQUJD\n-----END K-----\n",
            "-----BEGIN K-----\n-----END K-----\n",  # empty body
            "no pem here",
            "-----BEGIN bad-label-----\nQUJD\n-----END bad-label-----\n",
            "-----BEGIN -----\nQUJD\n-----END -----\n",
            "-----BEGIN K-----x\nQUJD\n-----END K-----\n",  # suffix garbage
        ],
    )
    def test_rejects_malformed(self, text: str) -> None:
        with pytest.raises(InvalidSerialization):
            pem.decode_pem(text)

    def test_non_ascii_input(self) -> None:
        with pytest.raises(InvalidSerialization):
            pem.decode_pem(b"\xff\xfe\x00")

    def test_bad_base64_padding(self) -> None:
        text = "-----BEGIN K-----\nQQ==QQ==\n-----END K-----\n"
        with pytest.raises(InvalidSerialization):
            pem.decode_pem(text)
