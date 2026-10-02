"""Tests for file identification (magic bytes + dimensions)."""

from __future__ import annotations

import struct

import pytest
from conftest import (
    build_bmp,
    build_gif,
    build_jpeg_no_exif,
    build_jpeg_with_exif,
    build_png,
    build_tiff,
    build_tiff_file,
    build_webp_vp8,
    build_webp_vp8l,
    build_webp_vp8x,
    standard_exif,
    standard_ifd0,
)

from metatrace.image.identify import detect_format, identify


def write_tmp(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


@pytest.mark.parametrize(
    "name, builder, fmt, mime, width, height",
    [
        ("a.jpg", lambda: build_jpeg_no_exif(64, 48), "JPEG", "image/jpeg", 64, 48),
        ("a.png", lambda: build_png(8, 6), "PNG", "image/png", 8, 6),
        ("a.gif", lambda: build_gif(8, 6), "GIF", "image/gif", 8, 6),
        ("a.bmp", lambda: build_bmp(8, 6), "BMP", "image/bmp", 8, 6),
        ("a.webp", lambda: build_webp_vp8x(8, 6), "WEBP", "image/webp", 8, 6),
        ("a.tif", lambda: build_tiff_file(8, 6), "TIFF", "image/tiff", 8, 6),
    ],
)
def test_identify_formats(tmp_path, name, builder, fmt, mime, width, height):
    path = write_tmp(tmp_path, name, builder())
    ident = identify(path)
    assert ident.format == fmt
    assert ident.mime == mime
    assert ident.width == width
    assert ident.height == height
    assert ident.size_bytes > 0
    assert ident.filename == name
    assert ident.encoding  # human description present


def test_jpeg_with_exif_dimensions(tmp_path):
    tiff = build_tiff(endian="<", ifd0=standard_ifd0(), exif=standard_exif())
    path = write_tmp(tmp_path, "e.jpg", build_jpeg_with_exif(tiff, 64, 48))
    ident = identify(path)
    assert (ident.width, ident.height) == (64, 48)
    assert "baseline" in ident.encoding


def test_unknown_format(tmp_path):
    path = write_tmp(tmp_path, "x.bin", b"\x00\x01\x02\x03" * 64)
    assert detect_format(b"\x00\x01\x02\x03") == ("UNKNOWN", "")
    ident = identify(path)
    assert ident.format == "UNKNOWN"
    assert ident.mime == ""
    assert ident.width is None


def test_riff_without_webp_is_unknown():
    assert detect_format(b"RIFF\x00\x00\x00\x00NOTW") == ("UNKNOWN", "")


def test_truncated_png_dimensions_none(tmp_path):
    path = write_tmp(tmp_path, "t.png", b"\x89PNG\r\n\x1a\n\x00\x00")
    ident = identify(path)
    assert ident.format == "PNG"
    assert ident.width is None


def test_jpeg_without_sof_dimensions_none(tmp_path):
    # SOI + EOI only: no SOF marker to read dimensions from.
    path = write_tmp(tmp_path, "s.jpg", b"\xff\xd8\xff\xd9")
    ident = identify(path)
    assert ident.format == "JPEG"
    assert ident.width is None
    assert "not found" in ident.encoding


def test_empty_file(tmp_path):
    path = write_tmp(tmp_path, "empty.jpg", b"")
    ident = identify(path)
    assert ident.format == "UNKNOWN"
    assert ident.size_bytes == 0


def test_webp_vp8_and_vp8l(tmp_path):
    for name, builder in (("l.webp", build_webp_vp8l), ("y.webp", build_webp_vp8)):
        p = tmp_path / name
        p.write_bytes(builder(16, 12))
        ident = identify(str(p))
        assert ident.format == "WEBP"
        assert (ident.width, ident.height) == (16, 12), name


def test_webp_bad_vp8_start_code(tmp_path):
    data = build_webp_vp8(8, 6)
    bad = data[:23] + b"\x00\x00\x00" + data[26:]
    p = tmp_path / "bad.webp"
    p.write_bytes(bad)
    ident = identify(str(p))
    assert ident.width is None
    assert "bad start code" in ident.encoding


def test_png_implausible_dimensions(tmp_path):
    data = build_png(8, 6)[:16] + b"\x00\x00\x00\x00" + build_png(8, 6)[20:]
    p = tmp_path / "zero.png"
    p.write_bytes(data)
    ident = identify(str(p))
    assert ident.format == "PNG"
    assert ident.width is None


def test_bmp_negative_height_is_absolute(tmp_path):
    data = bytearray(build_bmp(8, 6))
    struct.pack_into("<i", data, 22, -6)  # top-down DIB: negative height
    p = tmp_path / "top.bmp"
    p.write_bytes(bytes(data))
    ident = identify(str(p))
    assert (ident.width, ident.height) == (8, 6)


def test_header_parse_failure_is_safe(tmp_path, monkeypatch):
    # The try/except in identify() is a safety net: force a parser to
    # raise and confirm identification degrades gracefully.
    import metatrace.image.identify as identify_mod

    def boom(data):
        raise struct.error("synthetic")

    monkeypatch.setitem(identify_mod._DIMENSION_PARSERS, "PNG", boom)
    p = tmp_path / "a.png"
    p.write_bytes(build_png(8, 6))
    ident = identify(str(p))
    assert ident.format == "PNG"
    assert ident.width is None
    assert "parse failed" in ident.encoding


def test_big_endian_tiff(tmp_path):
    path = write_tmp(tmp_path, "be.tif", build_tiff_file(8, 6, endian=">"))
    ident = identify(path)
    assert ident.format == "TIFF"
    assert (ident.width, ident.height) == (8, 6)
