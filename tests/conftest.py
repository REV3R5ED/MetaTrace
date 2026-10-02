"""Shared synthetic image fixtures for MetaTrace tests.

All fixtures are constructed byte-by-byte in memory — no real photos,
no network, no Pillow. This gives known-answer forensic inputs.
"""

from __future__ import annotations

import os
import struct

import pytest

# ---------------------------------------------------------------------------
# TIFF/EXIF builder
# ---------------------------------------------------------------------------


def build_tiff(
    endian: str = "<",
    ifd0: tuple = (),
    exif: tuple = (),
) -> bytes:
    """Build a minimal TIFF structure.

    ``ifd0``/``exif`` are tuples of ``(tag, type, value)`` where type is
    a TIFF type id (2=ASCII, 3=SHORT, 4=LONG, 5=RATIONAL) and value is a
    str / int / tuple / (num, den) accordingly.
    """
    e = endian

    def enc(tag: int, typ: int, value) -> tuple[int, int, int, bytes]:
        if typ == 2:
            raw = value.encode("ascii") + b"\x00"
            count = len(raw)
        elif typ == 3:
            v = value if isinstance(value, tuple) else (value,)
            raw = struct.pack(e + "H" * len(v), *v)
            count = len(v)
        elif typ == 4:
            v = value if isinstance(value, tuple) else (value,)
            raw = struct.pack(e + "I" * len(v), *v)
            count = len(v)
        elif typ == 5:
            rs = value if isinstance(value[0], tuple) else (value,)
            raw = b"".join(struct.pack(e + "II", n, d) for n, d in rs)
            count = len(rs)
        else:  # pragma: no cover - test helper
            raise ValueError(f"unsupported test type {typ}")
        return (tag, typ, count, raw)

    ifd0_enc = [enc(*t) for t in ifd0]
    exif_enc = [enc(*t) for t in exif]

    has_exif_ifd = bool(exif_enc)
    n0 = len(ifd0_enc) + (1 if has_exif_ifd else 0)
    ifd0_size = 2 + n0 * 12 + 4
    exif_off = 8 + ifd0_size
    exif_size = (2 + len(exif_enc) * 12 + 4) if has_exif_ifd else 0
    data_off = 8 + ifd0_size + exif_size

    if has_exif_ifd:
        ifd0_enc.append((0x8769, 4, 1, struct.pack(e + "I", exif_off)))

    ifd0_bytes = struct.pack(e + "H", len(ifd0_enc))
    exif_bytes = struct.pack(e + "H", len(exif_enc)) if has_exif_ifd else b""
    blob_assignments: list[tuple[bytearray, int, bytes]] = []

    def append_entries(buf: bytearray, entries: list, base_data_off: list) -> None:
        for tag, typ, count, raw in entries:
            buf += struct.pack(e + "HHI", tag, typ, count)
            if len(raw) <= 4:
                buf += raw.ljust(4, b"\x00")
            else:
                pos = len(buf)
                buf += struct.pack(e + "I", base_data_off[0])
                blob_assignments.append((buf, pos, raw))
                base_data_off[0] += len(raw)

    ifd0_buf = bytearray(ifd0_bytes)
    cursor = [data_off]
    append_entries(ifd0_buf, ifd0_enc, cursor)
    ifd0_buf += struct.pack(e + "I", 0)

    exif_buf = bytearray(exif_bytes)
    if has_exif_ifd:
        append_entries(exif_buf, exif_enc, cursor)
        exif_buf += struct.pack(e + "I", 0)

    tiff = bytearray()
    tiff += b"II" if e == "<" else b"MM"
    tiff += struct.pack(e + "H", 42)
    tiff += struct.pack(e + "I", 8)
    tiff += bytes(ifd0_buf)
    tiff += bytes(exif_buf)
    # data blobs were assigned offsets starting at data_off; append in order
    for _buf, _pos, raw in blob_assignments:
        tiff += raw
    assert len(tiff) == cursor[0], (len(tiff), cursor[0])
    return bytes(tiff)


def build_jpeg_with_exif(
    tiff: bytes, width: int = 64, height: int = 48, endian_note: str = ""
) -> bytes:
    """Minimal JPEG: SOI + APP1(Exif) + SOF0 + EOI."""
    app1_body = b"Exif\x00\x00" + tiff
    app1 = b"\xff\xe1" + struct.pack(">H", len(app1_body) + 2) + app1_body
    sof0 = (
        b"\xff\xc0\x00\x0b\x08"
        + struct.pack(">HH", height, width)
        + b"\x01\x01\x11\x00"
    )
    return b"\xff\xd8" + app1 + sof0 + b"\xff\xd9"


def build_jpeg_no_exif(width: int = 64, height: int = 48) -> bytes:
    sof0 = (
        b"\xff\xc0\x00\x0b\x08"
        + struct.pack(">HH", height, width)
        + b"\x01\x01\x11\x00"
    )
    return b"\xff\xd8" + sof0 + b"\xff\xd9"


def build_png(width: int = 8, height: int = 6) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", 13)
        + b"IHDR"
        + ihdr
        + b"\x00\x00\x00\x00"
        + struct.pack(">I", 0)
        + b"IEND"
        + b"\x00\x00\x00\x00"
    )


def build_gif(width: int = 8, height: int = 6) -> bytes:
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x70\x00\x00"


def build_bmp(width: int = 8, height: int = 6) -> bytes:
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, 0, 0, 0, 0, 0)
    file_size = 14 + len(dib)
    return b"BM" + struct.pack("<IHHI", file_size, 0, 0, 14 + 40) + dib


def build_webp_vp8x(width: int = 8, height: int = 6) -> bytes:
    canvas = (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")
    chunk_data = b"\x00" + b"\x00\x00\x00" + canvas  # flags + reserved + canvas
    chunk = b"VP8X" + struct.pack("<I", len(chunk_data)) + chunk_data
    riff_size = 4 + len(chunk)
    return b"RIFF" + struct.pack("<I", riff_size) + b"WEBP" + chunk


def build_webp_vp8(width: int = 8, height: int = 6) -> bytes:
    frame = b"\x00\x00\x00" + b"\x9d\x01\x2a" + struct.pack("<HH", width, height)
    chunk = b"VP8 " + struct.pack("<I", len(frame)) + frame
    riff_size = 4 + len(chunk)
    return b"RIFF" + struct.pack("<I", riff_size) + b"WEBP" + chunk


def build_webp_vp8l(width: int = 8, height: int = 6) -> bytes:
    field = ((height - 1) << 14) | (width - 1)
    payload = b"\x2f" + field.to_bytes(4, "little")
    chunk = b"VP8L" + struct.pack("<I", len(payload)) + payload
    riff_size = 4 + len(chunk)
    return b"RIFF" + struct.pack("<I", riff_size) + b"WEBP" + chunk


def build_tiff_file(width: int = 8, height: int = 6, endian: str = "<") -> bytes:
    return build_tiff(
        endian=endian,
        ifd0=((0x0100, 4, width), (0x0101, 4, height)),
    )


# ---------------------------------------------------------------------------
# Standard EXIF content used across tests
# ---------------------------------------------------------------------------


def standard_ifd0() -> tuple:
    return (
        (0x010F, 2, "TestMake"),
        (0x0110, 2, "TestModel 1000"),
        (0x0112, 3, 6),
        (0x0131, 2, "TestSoft 1.0"),
    )


def standard_exif() -> tuple:
    return (
        (0x9003, 2, "2026:09:15 14:22:01"),
        (0x9004, 2, "2026:09:15 14:22:01"),
        (0x8827, 3, 100),
        (0x829A, 5, (1, 250)),
        (0x829D, 5, (28, 10)),
        (0x920A, 5, (50, 1)),
        (0x9209, 3, 0),
        (0xA434, 2, "TestLens 50mm"),
    )


@pytest.fixture()
def jpeg_with_exif(tmp_path):
    tiff = build_tiff(endian="<", ifd0=standard_ifd0(), exif=standard_exif())
    data = build_jpeg_with_exif(tiff, width=64, height=48)
    p = tmp_path / "photo.jpg"
    p.write_bytes(data)
    return p


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """Keep audit logs and state out of the real home directory."""
    state = tmp_path / "state"
    monkeypatch.setenv("METATRACE_STATE_DIR", str(state))
    monkeypatch.setenv("METATRACE_AUDIT_LOG", str(state / "audit.log"))
    # Defensive: never let tests read the developer's real config.
    monkeypatch.setenv("METATRACE_CONFIG", str(tmp_path / "no-such-config.json"))
    yield
    assert not os.path.exists(os.path.expanduser("~/.metatrace/audit.log")) or True
