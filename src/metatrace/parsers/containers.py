"""Container traversal helpers: JPEG segments, PNG chunks, WebP chunks.

Shared by the v0.3 metadata parsers (XMP, IPTC, ICC) so each format's
container walk lives in exactly one place. All iterators are defensive:
truncated or malformed containers yield what was safely readable and
then stop — they never raise on untrusted input.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator

# Never walk more than this many container elements (DoS bound).
_MAX_ELEMENTS = 4096

# JPEG markers without a length field.
_STANDALONE_MARKERS = frozenset([0xD8, 0xD9, 0x01] + list(range(0xD0, 0xD8)))


def iter_jpeg_segments(data: bytes, bound: int) -> Iterator[tuple[int, bytes]]:
    """Yield ``(marker, payload)`` for each JPEG segment carrying a length.

    *payload* excludes the 2-byte length field. Standalone markers
    (SOI/EOI/RSTn/TEM) are skipped. Iteration stops at SOS (0xDA),
    EOI (0xD9), on truncation, or at *bound* bytes — APPn metadata
    always lives before the compressed scan data.
    """
    if len(data) < 4 or data[0:2] != b"\xff\xd8":
        return
    pos = 2
    size = min(len(data), bound)
    seen = 0
    while pos + 2 <= size and seen < _MAX_ELEMENTS:
        if data[pos] != 0xFF:
            # Byte-stuffed resync: not a marker boundary, advance.
            pos += 1
            continue
        # Skip fill bytes (0xFF 0xFF ...).
        while pos + 1 < size and data[pos + 1] == 0xFF:
            pos += 1
        if pos + 1 >= size:
            break
        marker = data[pos + 1]
        if marker in _STANDALONE_MARKERS:
            if marker == 0xD9:  # EOI
                break
            pos += 2
            continue
        if marker == 0xDA:  # SOS: entropy-coded data follows
            break
        if pos + 4 > size:
            break
        length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        if length < 2 or pos + 2 + length > size:
            break
        yield marker, data[pos + 4 : pos + 2 + length]
        seen += 1
        pos += 2 + length


def iter_png_chunks(data: bytes) -> Iterator[tuple[bytes, bytes]]:
    """Yield ``(chunk_type, chunk_data)`` for PNG chunks after the signature.

    Stops at IEND or on truncation. CRCs are not validated — MetaTrace
    observes metadata, it does not validate the image.
    """
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return
    pos = 8
    size = len(data)
    seen = 0
    while pos + 8 <= size and seen < _MAX_ELEMENTS:
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        ctype = data[pos + 4 : pos + 8]
        if pos + 12 + length > size:
            break
        yield ctype, data[pos + 8 : pos + 8 + length]
        seen += 1
        if ctype == b"IEND":
            break
        pos += 12 + length


def iter_webp_chunks(data: bytes) -> Iterator[tuple[bytes, bytes]]:
    """Yield ``(fourcc, chunk_data)`` for chunks of a WebP RIFF container."""
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return
    pos = 12
    size = len(data)
    seen = 0
    while pos + 8 <= size and seen < _MAX_ELEMENTS:
        fourcc = data[pos : pos + 4]
        length = struct.unpack("<I", data[pos + 4 : pos + 8])[0]
        if pos + 8 + length > size:
            break
        yield fourcc, data[pos + 8 : pos + 8 + length]
        seen += 1
        pos += 8 + length + (length & 1)  # chunks are word-aligned
