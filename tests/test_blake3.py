# SPDX-License-Identifier: 0BSD
"""BLAKE3 tests: official test_vectors.json, incremental splits, XOF seek.

Vectors are the official BLAKE3 repository test vectors
(test_vectors/test_vectors.json), which include 131 bytes of output
per case so the XOF stream beyond 32 bytes is covered.
"""

import json
import secrets
from pathlib import Path
from typing import Any

import pytest

from purecrypt import blake3

VECTOR_PATH = Path(__file__).parent / "data" / "blake3_vectors.json"
VECTORS = json.loads(VECTOR_PATH.read_text())
KEY = VECTORS["key"].encode("ascii")
CONTEXT = VECTORS["context_string"]


def _pattern_input(length: int) -> bytes:
    return bytes(i % 251 for i in range(length))


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: f"len{c['input_len']}")
def test_official_vectors_hash(case: dict[str, Any]) -> None:
    data = _pattern_input(case["input_len"])
    assert blake3.hash(data, 131).hex() == case["hash"]
    assert blake3.hash(data).hex() == case["hash"][:64]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: f"len{c['input_len']}")
def test_official_vectors_keyed_hash(case: dict[str, Any]) -> None:
    data = _pattern_input(case["input_len"])
    assert blake3.keyed_hash(KEY, data, 131).hex() == case["keyed_hash"]
    assert blake3.keyed_hash(KEY, data).hex() == case["keyed_hash"][:64]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: f"len{c['input_len']}")
def test_official_vectors_derive_key(case: dict[str, Any]) -> None:
    data = _pattern_input(case["input_len"])
    assert blake3.derive_key(CONTEXT, data, 131).hex() == case["derive_key"]
    assert blake3.derive_key(CONTEXT, data).hex() == case["derive_key"][:64]


@pytest.mark.parametrize("length", [0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3072])
def test_incremental_matches_one_shot(length: int) -> None:
    data = secrets.token_bytes(length)
    expected = blake3.hash(data, 100)
    for _ in range(8):
        h = blake3.new()
        pos = 0
        while pos < length:
            step = secrets.randbelow(97) + 1
            h.update(data[pos : pos + step])
            pos += step
        assert h.digest(100) == expected


@pytest.mark.parametrize("split", [0, 1, 63, 64, 65, 1023, 1024, 1025])
def test_incremental_split_points(split: int) -> None:
    data = _pattern_input(2048)
    h = blake3.new()
    h.update(data[:split])
    h.update(data[split:])
    assert h.digest(64) == blake3.hash(data, 64)


def test_xof_seek_matches_stream_prefix() -> None:
    data = _pattern_input(1025)
    h = blake3.new(data)
    full = h.digest(512)
    for offset in (0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 300):
        assert h.digest(64, seek=offset) == full[offset : offset + 64]


def test_xof_zero_length() -> None:
    assert blake3.new(b"x").digest(0) == b""


def test_digest_is_repeatable() -> None:
    h = blake3.new(b"abc")
    assert h.digest(40) == h.digest(40)
    h.update(b"def")
    assert h.digest() == blake3.hash(b"abcdef")


def test_copy_isolates_state() -> None:
    h1 = blake3.new(b"abc")
    h2 = h1.copy()
    h1.update(b"one")
    h2.update(b"two")
    assert h1.digest() == blake3.hash(b"abcone")
    assert h2.digest() == blake3.hash(b"abctwo")


def test_reset() -> None:
    h = blake3.new(b"junk")
    h.reset()
    h.update(b"real")
    assert h.digest() == blake3.hash(b"real")


def test_keyed_hash_requires_32_byte_key() -> None:
    with pytest.raises(ValueError, match="32-byte key"):
        blake3.keyed_hash(b"short", b"data")
    with pytest.raises(ValueError, match="32-byte key"):
        blake3.new_keyed(b"x" * 33)


def test_derive_key_accepts_str_or_bytes_context() -> None:
    ctx = "example.com 2024-01-01 test context"
    assert blake3.derive_key(ctx, b"material") == blake3.derive_key(
        ctx.encode(), b"material"
    )
    h = blake3.new_derive_key(ctx)
    h.update(b"material")
    assert h.digest() == blake3.derive_key(ctx, b"material")


def test_keyed_modes_differ() -> None:
    data = b"same input"
    key = secrets.token_bytes(32)
    out_hash = blake3.hash(data)
    assert blake3.keyed_hash(key, data) != out_hash
    assert blake3.derive_key("ctx", data) != out_hash


def test_negative_args_rejected() -> None:
    h = blake3.new(b"x")
    with pytest.raises(ValueError, match=">= 0"):
        h.digest(-1)
    with pytest.raises(ValueError, match=">= 0"):
        h.digest(8, seek=-1)


def test_update_accepts_buffer_types() -> None:
    h = blake3.new()
    h.update(b"ab")
    h.update(bytearray(b"cd"))
    h.update(memoryview(b"ef"))
    assert h.digest() == blake3.hash(b"abcdef")


def test_random_key() -> None:
    k1 = blake3.random_key()
    assert len(k1) == 32
    assert blake3.keyed_hash(k1, b"m") == blake3.new_keyed(k1, b"m").digest()
