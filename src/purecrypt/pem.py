# SPDX-License-Identifier: 0BSD
"""PEM armor encode/decode (RFC 7468 style, strict subset).

NOT READY FOR PRODUCTION. Pure Python cannot provide constant-time
guarantees: nothing in this module runs in constant time. This package
exists for education, testing, and environments where native crypto is
unavailable and the threat model tolerates it.

Accepted form:

    -----BEGIN LABEL-----
    <base64 lines>
    -----END LABEL-----

The BEGIN and END labels must match exactly. Only base64 characters may
appear inside the armor: legacy headers (Proc-Type, DEK-Info, ...) are
rejected. Free text before the BEGIN line or after the END line is
ignored, matching common PEM practice. Only the first block is decoded.
"""

import base64
import binascii
import re

from .exceptions import InvalidSerialization

_LABEL_RE = re.compile(r"^[A-Z0-9][A-Z0-9 ]{0,62}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
_BEGIN_PREFIX = "-----BEGIN "
_END_PREFIX = "-----END "
_MARKER_SUFFIX = "-----"


def encode_pem(label: str, der: bytes | bytearray | memoryview) -> str:
    """Return the PEM armor for der under the given label."""
    if not _LABEL_RE.match(label):
        raise ValueError(f"invalid PEM label {label!r}")
    b64 = base64.b64encode(bytes(der)).decode("ascii")
    lines = [f"{_BEGIN_PREFIX}{label}{_MARKER_SUFFIX}"]
    lines.extend(b64[i : i + 64] for i in range(0, len(b64), 64))
    lines.append(f"{_END_PREFIX}{label}{_MARKER_SUFFIX}")
    return "\n".join(lines) + "\n"


def _strip_marker(line: str, prefix: str) -> str | None:
    """Extract the label from a marker line, or None if not a marker."""
    if not line.startswith(prefix) or not line.endswith(_MARKER_SUFFIX):
        return None
    label = line[len(prefix) : -len(_MARKER_SUFFIX)]
    if not _LABEL_RE.match(label):
        raise InvalidSerialization(f"malformed PEM label {label!r}")
    return label


def decode_pem(data: str | bytes | bytearray | memoryview) -> tuple[str, bytes]:
    """Decode the first PEM block. Returns (label, der_bytes).

    Raises InvalidSerialization on missing markers, mismatched labels,
    or non-base64 content inside the armor.
    """
    if isinstance(data, str):
        text = data
    else:
        try:
            text = bytes(data).decode("ascii")
        except UnicodeDecodeError as exc:
            raise InvalidSerialization("PEM is not ASCII") from exc
    label: str | None = None
    body: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if label is None:
            found = _strip_marker(line, _BEGIN_PREFIX)
            if found is not None:
                label = found
            continue
        end_label = _strip_marker(line, _END_PREFIX)
        if end_label is not None:
            if end_label != label:
                raise InvalidSerialization(
                    f"PEM label mismatch: BEGIN {label!r} vs END {end_label!r}"
                )
            return label, _decode_body(body)
        if not line:
            continue  # tolerate blank lines inside the armor
        if not _B64_RE.match(line):
            raise InvalidSerialization("non-base64 content inside PEM armor")
        body.append(line)
    raise InvalidSerialization("unterminated or missing PEM block")


def _decode_body(lines: list[str]) -> bytes:
    if not lines:
        raise InvalidSerialization("empty PEM body")
    joined = "".join(lines)
    try:
        return base64.b64decode(joined, validate=True)
    except binascii.Error as exc:
        raise InvalidSerialization("invalid PEM base64") from exc


def decode_pem_expect(data: str | bytes | bytearray | memoryview, label: str) -> bytes:
    """Decode a PEM block requiring a specific label."""
    found, der = decode_pem(data)
    if found != label:
        raise InvalidSerialization(f"expected PEM label {label!r}, got {found!r}")
    return der
