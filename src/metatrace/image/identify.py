"""File identification: magic-byte format detection and dimensions.

Pure stdlib (``struct``) — no Pillow. Only the file header is read
(bounded by config ``identify_header_bytes``); the source file is
opened read-only and never modified.

Supported in v0.1: JPEG, PNG, GIF, BMP, WebP, TIFF. Anything else is
reported as ``UNKNOWN`` with empty dimensions rather than an error —
identification is observation, not validation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from metatrace.core.models import FileIdentity


@dataclass
class HeaderRead:
    data: bytes
    bytes_read: int


def read_header(path: str, max_bytes: int) -> HeaderRead:
    """Read up to *max_bytes* from the start of *path* (read-only)."""
    with open(path, "rb") as fh:
        data = fh.read(max_bytes)
    return HeaderRead(data=data, bytes_read=len(data))


# ---------------------------------------------------------------------------
# Dimension parsers (each returns (width, height) or (None, None))
# ---------------------------------------------------------------------------


def _png_dimensions(data: bytes) -> tuple[int | None, int | None, str]:
    # 8-byte signature + 4-byte length + 4-byte "IHDR" + 13-byte IHDR data.
    if len(data) < 33 or data[12:16] != b"IHDR":
        return None, None, "PNG (header truncated)"
    width, height, bit_depth, color_type = struct.unpack(">IIBB", data[16:26])
    if width == 0 or height == 0 or width > 1_000_000 or height > 1_000_000:
        return None, None, "PNG (implausible dimensions)"
    return width, height, f"PNG (color type {color_type}, bit depth {bit_depth})"


def _gif_dimensions(data: bytes) -> tuple[int | None, int | None, str]:
    if len(data) < 10:
        return None, None, "GIF (header truncated)"
    width, height = struct.unpack("<HH", data[6:10])
    if width == 0 or height == 0:
        return None, None, "GIF (implausible dimensions)"
    version = data[3:6].decode("ascii", errors="replace")
    return width, height, f"GIF ({version})"


def _bmp_dimensions(data: bytes) -> tuple[int | None, int | None, str]:
    # BITMAPFILEHEADER (14) + DIB header; width/height at offset 18.
    if len(data) < 26:
        return None, None, "BMP (header truncated)"
    width, height = struct.unpack("<ii", data[18:26])
    if width <= 0 or width > 1_000_000 or abs(height) > 1_000_000 or height == 0:
        return None, None, "BMP (implausible dimensions)"
    return width, abs(height), "BMP (DIB)"


def _jpeg_dimensions(data: bytes) -> tuple[int | None, int | None, str]:
    # Scan markers for a Start-Of-Frame segment (baseline/progressive DCT).
    pos = 2  # skip SOI
    progressive = False
    size = len(data)
    while pos + 4 <= size:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        # Standalone markers without length.
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            pos += 2
            continue
        if pos + 4 > size:
            break
        length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        if length < 2:
            break
        if marker in (0xC0, 0xC1, 0xC2, 0xC3):
            # SOF: precision(1) + height(2) + width(2) + components...
            if pos + 9 > size:
                break
            height, width = struct.unpack(">HH", data[pos + 5 : pos + 9])
            if width == 0 or height == 0:
                break
            if marker == 0xC2:
                progressive = True
            kind = "progressive DCT" if progressive else "baseline DCT"
            return width, height, f"JPEG ({kind})"
        if marker == 0xDA:  # SOS: image data follows; no SOF will appear later
            break
        pos += 2 + length
        if pos > 1_000_000:  # never scan past 1 MiB of markers
            break
    return None, None, "JPEG (dimensions not found in header)"


def _webp_dimensions(data: bytes) -> tuple[int | None, int | None, str]:
    # RIFF....WEBP then VP8X / VP8_ / VP8L chunk.
    if len(data) < 21 or data[8:12] != b"WEBP":
        return None, None, "WebP (header truncated)"
    chunk = data[12:16]
    if chunk == b"VP8X":
        # Chunk data (10 bytes): flags(1), reserved(3),
        # canvas width-1 (3, LE), canvas height-1 (3, LE).
        if len(data) < 30:
            return None, None, "WebP (VP8X truncated)"
        width = int.from_bytes(data[24:27], "little") + 1
        height = int.from_bytes(data[27:30], "little") + 1
        return width, height, "WebP (VP8X, extended)"
    if chunk == b"VP8L":
        # Chunk data: signature 0x2F (1 byte at offset 20), then 14-bit
        # width-1, 14-bit height-1, 1-bit alpha hint, 3-bit version.
        if len(data) < 25:
            return None, None, "WebP (VP8L truncated)"
        if data[20] != 0x2F:  # signature byte
            return None, None, "WebP (VP8L bad signature)"
        field = int.from_bytes(data[21:25], "little")
        width = (field & 0x3FFF) + 1
        height = ((field >> 14) & 0x3FFF) + 1
        if width > 16384 or height > 16384:
            return None, None, "WebP (VP8L implausible dimensions)"
        return width, height, "WebP (VP8L, lossless)"
    if chunk == b"VP8 ":
        if len(data) < 30:
            return None, None, "WebP (VP8 truncated)"
        if data[23:26] != b"\x9d\x01\x2a":  # start code
            return None, None, "WebP (VP8 bad start code)"
        width = struct.unpack("<H", data[26:28])[0] & 0x3FFF
        height = struct.unpack("<H", data[28:30])[0] & 0x3FFF
        if width == 0 or height == 0:
            return None, None, "WebP (VP8 implausible dimensions)"
        return width, height, "WebP (VP8, lossy)"
    return None, None, "WebP (unknown chunk)"


def _tiff_dimensions(data: bytes) -> tuple[int | None, int | None, str]:
    # Minimal IFD walk for tags 256 (width) / 257 (height).
    if len(data) < 8:
        return None, None, "TIFF (header truncated)"
    endian = "<" if data[:2] == b"II" else ">"
    if struct.unpack(endian + "H", data[2:4])[0] != 42:
        return None, None, "TIFF (bad magic)"
    ifd_offset = struct.unpack(endian + "I", data[4:8])[0]
    if ifd_offset + 2 > len(data) or ifd_offset > 1_000_000:
        return None, None, "TIFF (bad IFD offset)"
    count = struct.unpack(endian + "H", data[ifd_offset : ifd_offset + 2])[0]
    if count > 256:
        return None, None, "TIFF (implausible tag count)"
    width = height = None
    for i in range(count):
        off = ifd_offset + 2 + i * 12
        if off + 12 > len(data):
            break
        tag, typ = struct.unpack(endian + "HH", data[off : off + 4])
        n = struct.unpack(endian + "I", data[off + 4 : off + 8])[0]
        if n != 1 or typ not in (3, 4):  # SHORT or LONG, single value
            continue
        raw = data[off + 8 : off + 12]
        value = (
            struct.unpack(endian + "H", raw[:2])[0]
            if typ == 3
            else struct.unpack(endian + "I", raw[:4])[0]
        )
        if tag == 256:
            width = value
        elif tag == 257:
            height = value
    if width and height:
        return width, height, "TIFF"
    return None, None, "TIFF (dimensions not found)"


# ---------------------------------------------------------------------------
# Top-level identification
# ---------------------------------------------------------------------------

_FORMATS: tuple[tuple[str, str, bytes], ...] = (
    ("JPEG", "image/jpeg", b"\xff\xd8\xff"),
    ("PNG", "image/png", b"\x89PNG\r\n\x1a\n"),
    ("GIF", "image/gif", b"GIF87a"),
    ("GIF", "image/gif", b"GIF89a"),
    ("BMP", "image/bmp", b"BM"),
    ("WEBP", "image/webp", b"RIFF"),
    ("TIFF", "image/tiff", b"II*\x00"),
    ("TIFF", "image/tiff", b"MM\x00*"),
)

_DIMENSION_PARSERS = {
    "JPEG": _jpeg_dimensions,
    "PNG": _png_dimensions,
    "GIF": _gif_dimensions,
    "BMP": _bmp_dimensions,
    "WEBP": _webp_dimensions,
    "TIFF": _tiff_dimensions,
}


def detect_format(header: bytes) -> tuple[str, str]:
    """Return (format, mime) from magic bytes; ("UNKNOWN", "") if unrecognized."""
    for fmt, mime, magic in _FORMATS:
        if header.startswith(magic):
            if fmt == "WEBP" and not header[8:12] == b"WEBP":
                continue
            return fmt, mime
    return "UNKNOWN", ""


def identify(path: str, header_bytes: int = 65536) -> FileIdentity:
    """Identify a file from its header bytes (read-only)."""
    from pathlib import Path as _Path  # local import: keep module import-light

    p = _Path(path)
    header = read_header(path, header_bytes)
    data = header.data
    fmt, mime = detect_format(data)
    width: int | None = None
    height: int | None = None
    encoding = ""
    if fmt in _DIMENSION_PARSERS:
        try:
            width, height, encoding = _DIMENSION_PARSERS[fmt](data)
        except (struct.error, IndexError, ValueError):
            # Defensive: a broken header must not crash identification.
            width, height, encoding = None, None, f"{fmt} (header parse failed)"
    return FileIdentity(
        path=path,
        filename=p.name,
        size_bytes=p.stat().st_size,
        format=fmt,
        mime=mime,
        width=width,
        height=height,
        encoding=encoding,
        header_bytes_read=header.bytes_read,
    )
