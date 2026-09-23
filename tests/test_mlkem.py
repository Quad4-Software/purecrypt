# SPDX-License-Identifier: 0BSD
"""ML-KEM (FIPS 203) tests: NIST ACVP vectors plus property checks.

Vectors are the official NIST ACVP-Server internalProjection files
for ML-KEM-keyGen-FIPS203 and ML-KEM-encapDecap-FIPS203, covering
deterministic key generation, encapsulation, decapsulation, and the
key-consistency checks.
"""

import json
import secrets
from pathlib import Path
from typing import Any

import pytest

from purecrypt import mlkem
from purecrypt.exceptions import InvalidCiphertext, InvalidKey

_DATA = Path(__file__).parent / "data"
KEYGEN_VECTORS = json.loads((_DATA / "mlkem_keygen.json").read_text())
ENCDEC_VECTORS = json.loads((_DATA / "mlkem_encdecap.json").read_text())

PARAM_NAMES = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]


def _param(name: str) -> Any:
    return mlkem._PARAM_SETS[name]


def _kg_id(group: dict[str, Any]) -> str:
    return str(group["parameterSet"])


def _ed_id(group: dict[str, Any]) -> str:
    return f"{group['parameterSet']}-{group.get('function')}"


@pytest.mark.parametrize("group", KEYGEN_VECTORS["testGroups"], ids=_kg_id)
def test_acvp_keygen(group: dict[str, Any]) -> None:
    params = _param(group["parameterSet"])
    for tc in group["tests"]:
        ek, dk = mlkem._keygen_internal(
            params, bytes.fromhex(tc["d"]), bytes.fromhex(tc["z"])
        )
        assert ek == bytes.fromhex(tc["ek"]), tc["tcId"]
        assert dk == bytes.fromhex(tc["dk"]), tc["tcId"]


@pytest.mark.parametrize("group", ENCDEC_VECTORS["testGroups"], ids=_ed_id)
def test_acvp_encapdecap(group: dict[str, Any]) -> None:
    params = _param(group["parameterSet"])
    function = group.get("function")
    if function == "encapsulation":
        for tc in group["tests"]:
            k, c = mlkem._encaps_internal(
                params, bytes.fromhex(tc["ek"]), bytes.fromhex(tc["m"])
            )
            assert c == bytes.fromhex(tc["c"]), tc["tcId"]
            assert k == bytes.fromhex(tc["k"]), tc["tcId"]
    elif function == "decapsulation":
        for tc in group["tests"]:
            k = mlkem._decaps_internal(
                params, bytes.fromhex(tc["dk"]), bytes.fromhex(tc["c"])
            )
            assert k == bytes.fromhex(tc["k"]), tc["tcId"]


@pytest.mark.parametrize("group", ENCDEC_VECTORS["testGroups"], ids=_ed_id)
def test_acvp_key_checks(group: dict[str, Any]) -> None:
    function = group.get("function")
    if function == "encapsulationKeyCheck":
        for tc in group["tests"]:
            try:
                mlkem.check_encaps_key(bytes.fromhex(tc["ek"]))
                passed = True
            except InvalidKey:
                passed = False
            assert passed == tc["testPassed"], tc["tcId"]
    elif function == "decapsulationKeyCheck":
        for tc in group["tests"]:
            try:
                mlkem.check_decaps_key(bytes.fromhex(tc["dk"]))
                passed = True
            except InvalidKey:
                passed = False
            assert passed == tc["testPassed"], tc["tcId"]


@pytest.mark.parametrize("name", PARAM_NAMES)
def test_roundtrip_random(name: str) -> None:
    ek, dk = mlkem.keygen(name)
    shared1, c = mlkem.encaps(ek)
    shared2 = mlkem.decaps(dk, c)
    assert shared1 == shared2
    assert len(shared1) == 32


@pytest.mark.parametrize("name", PARAM_NAMES)
def test_implicit_rejection_bad_ciphertext(name: str) -> None:
    ek, dk = mlkem.keygen(name)
    shared1, c = mlkem.encaps(ek)
    bad = bytearray(c)
    bad[secrets.randbelow(len(bad))] ^= 1
    shared2 = mlkem.decaps(dk, bytes(bad))
    assert shared2 != shared1
    assert len(shared2) == 32


def test_decaps_wrong_key() -> None:
    ek, _dk = mlkem.keygen("ML-KEM-512")
    _ek2, dk2 = mlkem.keygen("ML-KEM-512")
    shared1, c = mlkem.encaps(ek)
    assert mlkem.decaps(dk2, c) != shared1


def test_keygen_sizes() -> None:
    sizes = {
        "ML-KEM-512": (800, 1632, 768),
        "ML-KEM-768": (1184, 2400, 1088),
        "ML-KEM-1024": (1568, 3168, 1568),
    }
    for name, (ek_len, dk_len, ct_len) in sizes.items():
        ek, dk = mlkem.keygen(name)
        assert len(ek) == ek_len
        assert len(dk) == dk_len
        _k, c = mlkem.encaps(ek)
        assert len(c) == ct_len


def test_bad_parameter_set() -> None:
    with pytest.raises(ValueError, match="parameter set"):
        mlkem.keygen("ML-KEM-999")


def test_bad_key_lengths() -> None:
    with pytest.raises(InvalidKey, match="encapsulation key length"):
        mlkem.encaps(b"\x00" * 100)
    _ek, dk = mlkem.keygen("ML-KEM-512")
    with pytest.raises(InvalidKey, match="decapsulation key length"):
        mlkem.decaps(dk[:-1], b"\x00" * 768)
    with pytest.raises(InvalidCiphertext, match="ciphertext length"):
        mlkem.decaps(dk, b"\x00" * 100)


def test_encaps_accepts_ek_from_any_set() -> None:
    for name in PARAM_NAMES:
        ek, dk = mlkem.keygen(name)
        _k, c = mlkem.encaps(ek)
        assert mlkem.decaps(dk, c) == _k
