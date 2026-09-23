# SPDX-License-Identifier: 0BSD
"""BLAKE3 cryptographic hash and PRF (official spec, portable form).

Implements the full BLAKE3 tree mode: one-shot and incremental
hashing, keyed hashing, key derivation, and extendable output (XOF)
via a seekable output stream. A 64-byte compress output block is
produced per output counter, so seek costs are proportional to the
distance from the current position.
"""

from __future__ import annotations

import secrets
from typing import Final

OUT_LEN: Final = 32
KEY_LEN: Final = 32
BLOCK_LEN: Final = 64
CHUNK_LEN: Final = 1024

CHUNK_START: Final = 1 << 0
CHUNK_END: Final = 1 << 1
PARENT: Final = 1 << 2
ROOT: Final = 1 << 3
KEYED_HASH: Final = 1 << 4
DERIVE_KEY_CONTEXT: Final = 1 << 5
DERIVE_KEY_MATERIAL: Final = 1 << 6

_IV: Final = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

_MSG_PERMUTATION: Final = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)

_MASK: Final = 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK


def _g(state: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = (state[a] + state[b] + mx) & _MASK
    state[d] = _rotr32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotr32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & _MASK
    state[d] = _rotr32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotr32(state[b] ^ state[c], 7)


def _round(state: list[int], m: list[int]) -> None:
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def _compress(
    cv: list[int],
    block_words: list[int],
    counter: int,
    block_len: int,
    flags: int,
) -> list[int]:
    state = [
        *cv,
        _IV[0],
        _IV[1],
        _IV[2],
        _IV[3],
        counter & _MASK,
        (counter >> 32) & _MASK,
        block_len,
        flags,
    ]
    m = list(block_words)
    for r in range(7):
        _round(state, m)
        if r != 6:
            m = [m[p] for p in _MSG_PERMUTATION]
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= cv[i]
    return state


def _words_from_block(block: bytes) -> list[int]:
    padded = block.ljust(BLOCK_LEN, b"\x00")
    return [int.from_bytes(padded[4 * i : 4 * i + 4], "little") for i in range(16)]


def _words_to_bytes(words: list[int]) -> bytes:
    return b"".join(w.to_bytes(4, "little") for w in words)


class _Output:
    """One compression input that can be finalised in several modes."""

    __slots__ = ("block_len", "block_words", "counter", "flags", "input_cv")

    def __init__(
        self,
        input_cv: list[int],
        block_words: list[int],
        counter: int,
        block_len: int,
        flags: int,
    ) -> None:
        self.input_cv = input_cv
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self) -> list[int]:
        return _compress(
            self.input_cv,
            self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        )[:8]

    def root_output_bytes(self, seek: int, length: int) -> bytes:
        if seek < 0:
            raise ValueError("seek position must be >= 0")
        if length < 0:
            raise ValueError("output length must be >= 0")
        out = bytearray()
        counter = seek // BLOCK_LEN
        offset = seek % BLOCK_LEN
        while len(out) < length + offset:
            words = _compress(
                self.input_cv,
                self.block_words,
                counter,
                self.block_len,
                self.flags | ROOT,
            )
            out += _words_to_bytes(words)
            counter += 1
        return bytes(out[offset : offset + length])


def _parent_output(
    left_cv: list[int],
    right_cv: list[int],
    key_words: list[int],
    flags: int,
) -> _Output:
    return _Output(
        key_words,
        list(left_cv) + list(right_cv),
        0,
        BLOCK_LEN,
        flags | PARENT,
    )


def _parent_cv(
    left_cv: list[int],
    right_cv: list[int],
    key_words: list[int],
    flags: int,
) -> list[int]:
    return _parent_output(left_cv, right_cv, key_words, flags).chaining_value()


class _ChunkState:
    __slots__ = ("blocks_compressed", "buf", "chunk_counter", "cv", "flags")

    def __init__(self, key_words: list[int], chunk_counter: int, flags: int) -> None:
        self.cv = list(key_words)
        self.chunk_counter = chunk_counter
        self.buf = bytearray()
        self.blocks_compressed = 0
        self.flags = flags

    def length(self) -> int:
        return BLOCK_LEN * self.blocks_compressed + len(self.buf)

    def _start_flag(self) -> int:
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data: bytes) -> None:
        view = memoryview(data)
        pos = 0
        while pos < len(view):
            if len(self.buf) == BLOCK_LEN:
                block_words = _words_from_block(bytes(self.buf))
                self.cv = _compress(
                    self.cv,
                    block_words,
                    self.chunk_counter,
                    BLOCK_LEN,
                    self.flags | self._start_flag(),
                )[:8]
                self.blocks_compressed += 1
                self.buf = bytearray()
            want = BLOCK_LEN - len(self.buf)
            take = min(want, len(view) - pos)
            self.buf += view[pos : pos + take]
            pos += take

    def output(self) -> _Output:
        return _Output(
            self.cv,
            _words_from_block(bytes(self.buf)),
            self.chunk_counter,
            len(self.buf),
            self.flags | self._start_flag() | CHUNK_END,
        )


class Hasher:
    """Incremental BLAKE3 context for hash, keyed hash, or derive key."""

    __slots__ = ("_chunk_state", "_cv_stack", "_flags", "_key_words")

    def __init__(self, key_words: list[int], flags: int) -> None:
        self._key_words = list(key_words)
        self._flags = flags
        self._chunk_state = _ChunkState(self._key_words, 0, flags)
        self._cv_stack: list[list[int]] = []

    def _push_cv(self, new_cv: list[int], total_chunks: int) -> None:
        cv = new_cv
        while total_chunks & 1 == 0:
            cv = _parent_cv(self._cv_stack.pop(), cv, self._key_words, self._flags)
            total_chunks >>= 1
        self._cv_stack.append(cv)

    def update(self, data: bytes | bytearray | memoryview) -> Hasher:
        view = memoryview(data)
        pos = 0
        while pos < len(view):
            if self._chunk_state.length() == CHUNK_LEN:
                chunk_cv = self._chunk_state.output().chaining_value()
                total_chunks = self._chunk_state.chunk_counter + 1
                self._push_cv(chunk_cv, total_chunks)
                self._chunk_state = _ChunkState(
                    self._key_words, total_chunks, self._flags
                )
            want = CHUNK_LEN - self._chunk_state.length()
            take = min(want, len(view) - pos)
            self._chunk_state.update(bytes(view[pos : pos + take]))
            pos += take
        return self

    def copy(self) -> Hasher:
        clone = Hasher(self._key_words, self._flags)
        clone._chunk_state.cv = list(self._chunk_state.cv)
        clone._chunk_state.chunk_counter = self._chunk_state.chunk_counter
        clone._chunk_state.buf = bytearray(self._chunk_state.buf)
        clone._chunk_state.blocks_compressed = self._chunk_state.blocks_compressed
        clone._cv_stack = [list(cv) for cv in self._cv_stack]
        return clone

    def _final_output(self) -> _Output:
        output = self._chunk_state.output()
        for i in range(len(self._cv_stack) - 1, -1, -1):
            output = _parent_output(
                self._cv_stack[i],
                output.chaining_value(),
                self._key_words,
                self._flags,
            )
        return output

    def digest(self, length: int = OUT_LEN, *, seek: int = 0) -> bytes:
        """Return length bytes of output starting at stream offset seek."""
        return self._final_output().root_output_bytes(seek, length)

    def hexdigest(self, length: int = OUT_LEN, *, seek: int = 0) -> str:
        return self.digest(length, seek=seek).hex()

    def reset(self) -> None:
        self._chunk_state = _ChunkState(self._key_words, 0, self._flags)
        self._cv_stack = []


def new(data: bytes = b"") -> Hasher:
    """Return a Hasher for the plain hashing mode, primed with data."""
    h = Hasher(list(_IV), 0)
    if data:
        h.update(data)
    return h


def new_keyed(key: bytes, data: bytes = b"") -> Hasher:
    """Return a Hasher for the keyed hashing mode. key must be 32 bytes."""
    if len(key) != KEY_LEN:
        raise ValueError("BLAKE3 keyed hash requires a 32-byte key")
    key_words = [int.from_bytes(key[4 * i : 4 * i + 4], "little") for i in range(8)]
    h = Hasher(key_words, KEYED_HASH)
    if data:
        h.update(data)
    return h


def new_derive_key(context: str | bytes, key_material: bytes = b"") -> Hasher:
    """Return a Hasher that derives a key from key_material.

    context is a globally unique application-specific string, hashed
    once under the DERIVE_KEY_CONTEXT flag. key_material is then
    hashed under the DERIVE_KEY_MATERIAL flag.
    """
    ctx_bytes = context.encode("utf-8") if isinstance(context, str) else bytes(context)
    ctx_hasher = Hasher(list(_IV), DERIVE_KEY_CONTEXT)
    ctx_hasher.update(ctx_bytes)
    context_key = ctx_hasher.digest(OUT_LEN)
    key_words = [
        int.from_bytes(context_key[4 * i : 4 * i + 4], "little") for i in range(8)
    ]
    h = Hasher(key_words, DERIVE_KEY_MATERIAL)
    if key_material:
        h.update(key_material)
    return h


def hash(data: bytes, length: int = OUT_LEN) -> bytes:  # noqa: A001
    """One-shot BLAKE3 hash. length may exceed 32 for XOF output."""
    return new(data).digest(length)


def keyed_hash(key: bytes, data: bytes, length: int = OUT_LEN) -> bytes:
    """One-shot BLAKE3 keyed hash. key must be 32 bytes."""
    return new_keyed(key, data).digest(length)


def derive_key(
    context: str | bytes,
    key_material: bytes,
    length: int = OUT_LEN,
) -> bytes:
    """One-shot BLAKE3 key derivation (context string plus material)."""
    return new_derive_key(context, key_material).digest(length)


def random_key() -> bytes:
    """Return a fresh 32-byte key suitable for keyed_hash."""
    return secrets.token_bytes(KEY_LEN)


__all__ = [
    "BLOCK_LEN",
    "CHUNK_LEN",
    "KEY_LEN",
    "OUT_LEN",
    "Hasher",
    "derive_key",
    "hash",
    "keyed_hash",
    "new",
    "new_derive_key",
    "new_keyed",
    "random_key",
]
