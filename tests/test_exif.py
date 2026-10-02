"""Tests for the defensive TIFF/EXIF parser."""

from __future__ import annotations

import struct

import pytest
from conftest import (
    build_jpeg_no_exif,
    build_jpeg_with_exif,
    build_tiff,
    standard_exif,
    standard_ifd0,
)

from metatrace.parsers.exif import (
    _TiffParser,
    extract_exif,
    find_exif_in_jpeg,
    format_rational,
    normalize_exif_datetime,
)


def write_tmp(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# ---------------------------------------------------------------------------
# Full extraction: known-answer fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("endian", ["<", ">"])
def test_full_exif_little_and_big_endian(tmp_path, endian):
    tiff = build_tiff(endian=endian, ifd0=standard_ifd0(), exif=standard_exif())
    jpeg = build_jpeg_with_exif(tiff)
    path = write_tmp(tmp_path, "photo.jpg", jpeg)

    ex = extract_exif(path, "JPEG")

    assert ex.present is True
    assert ex.warnings == []
    assert ex.make == "TestMake"
    assert ex.model == "TestModel 1000"
    assert ex.software == "TestSoft 1.0"
    assert ex.lens_model == "TestLens 50mm"
    assert ex.orientation == 6
    assert ex.orientation_name == "Rotate 90 CW"
    assert ex.datetime_original == "2026-09-15T14:22:01"
    assert ex.datetime_original_raw == "2026:09:15 14:22:01"
    assert ex.datetime_digitized == "2026-09-15T14:22:01"
    assert ex.timezone_known is False
    assert ex.iso == 100
    assert ex.exposure_time == "1/250"
    assert ex.exposure_seconds == pytest.approx(0.004)
    assert ex.f_number == pytest.approx(2.8)
    assert ex.focal_length_mm == pytest.approx(50.0)
    assert ex.flash == 0
    assert ex.flash_fired is False
    assert ex.has_gps_ifd is False
    # Raw observed values are preserved verbatim.
    assert ex.raw_tags[0x010F] == "TestMake"
    assert ex.raw_tags[0x829A] == [1, 250]
    assert ex.raw_tag_names[0x010F] == "Make"


def test_standalone_tiff(tmp_path):
    tiff = build_tiff(endian="<", ifd0=standard_ifd0(), exif=standard_exif())
    path = write_tmp(tmp_path, "photo.tif", tiff)
    ex = extract_exif(path, "TIFF")
    assert ex.present is True
    assert ex.make == "TestMake"
    assert ex.iso == 100


def test_jpeg_without_exif(tmp_path):
    path = write_tmp(tmp_path, "noexif.jpg", build_jpeg_no_exif())
    ex = extract_exif(path, "JPEG")
    assert ex.present is False
    assert ex.warnings == []


def test_non_exif_format_returns_empty(tmp_path):
    p = tmp_path / "a.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    ex = extract_exif(str(p), "PNG")
    assert ex.present is False


def test_gps_ifd_presence_recorded_not_decoded(tmp_path):
    # GPS pointer present; v0.1 records presence only.
    tiff = build_tiff(
        endian="<",
        ifd0=standard_ifd0() + ((0x8825, 4, 200),),
        exif=standard_exif(),
    )
    path = write_tmp(tmp_path, "gps.jpg", build_jpeg_with_exif(tiff))
    ex = extract_exif(path, "JPEG")
    assert ex.present is True
    assert ex.has_gps_ifd is True


def test_unreadable_file_records_warning(tmp_path):
    ex = extract_exif(str(tmp_path / "missing.jpg"), "JPEG")
    assert ex.present is False
    assert any("cannot read" in w for w in ex.warnings)


# ---------------------------------------------------------------------------
# Defensive parsing: malformed input must not crash
# ---------------------------------------------------------------------------


def test_truncated_app1_is_safe(tmp_path):
    tiff = build_tiff(endian="<", ifd0=standard_ifd0(), exif=standard_exif())
    jpeg = build_jpeg_with_exif(tiff)
    path = write_tmp(tmp_path, "trunc.jpg", jpeg[:40])  # cut inside APP1
    ex = extract_exif(path, "JPEG")
    assert ex.present is False  # no crash; nothing usable


def test_bad_tiff_magic_records_warning(tmp_path):
    path = write_tmp(tmp_path, "bad.tif", b"II\x00\x00" + b"\x00" * 100)
    ex = extract_exif(path, "TIFF")
    assert ex.present is False
    assert any("magic 42" in w for w in ex.warnings)


def test_not_a_tiff_header(tmp_path):
    path = write_tmp(tmp_path, "bad2.tif", b"ZZZZ" + b"\x00" * 100)
    ex = extract_exif(path, "TIFF")
    assert ex.present is False
    assert any("byte-order" in w for w in ex.warnings)


def test_huge_tag_count_truncated(tmp_path):
    # IFD claims 5000 tags; parser truncates to the configured bound.
    data = b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", 5000)
    path = write_tmp(tmp_path, "many.tif", data)
    ex = extract_exif(path, "TIFF", max_tags=16)
    assert ex.present is True
    assert any("truncated" in w for w in ex.warnings)


def test_out_of_bounds_value_offset_skipped(tmp_path):
    # One entry points its value far past the end of the buffer.
    e = "<"
    header = b"II" + struct.pack(e + "H", 42) + struct.pack(e + "I", 8)
    entry = struct.pack(e + "HHI", 0x010F, 2, 600) + struct.pack(e + "I", 999999)
    ifd = struct.pack(e + "H", 1) + entry + struct.pack(e + "I", 0)
    path = write_tmp(tmp_path, "oob.tif", header + ifd)
    ex = extract_exif(path, "TIFF")
    assert ex.present is True
    assert ex.make is None
    assert any("out of bounds" in w for w in ex.warnings)


def test_oversized_value_skipped(tmp_path):
    tiff = build_tiff(
        endian="<",
        ifd0=((0x010F, 2, "X" * 5000),),
    )
    path = write_tmp(tmp_path, "big.tif", tiff)
    ex = extract_exif(path, "TIFF", max_value_bytes=64)
    assert ex.present is True
    assert ex.make is None
    assert any("exceeds limit" in w for w in ex.warnings)


def test_unparseable_datetime_warns(tmp_path):
    tiff = build_tiff(
        endian="<",
        ifd0=standard_ifd0(),
        exif=((0x9003, 2, "not-a-date"),) + standard_exif()[1:],
    )
    path = write_tmp(tmp_path, "baddt.jpg", build_jpeg_with_exif(tiff))
    ex = extract_exif(path, "JPEG")
    assert ex.present is True
    assert ex.datetime_original is None
    assert ex.datetime_original_raw == "not-a-date"
    assert any("unparseable datetime" in w for w in ex.warnings)


def test_zero_denominator_rational(tmp_path):
    tiff = build_tiff(
        endian="<",
        ifd0=standard_ifd0(),
        exif=((0x829A, 5, (1, 0)),),
    )
    path = write_tmp(tmp_path, "zr.jpg", build_jpeg_with_exif(tiff))
    ex = extract_exif(path, "JPEG")
    assert ex.exposure_time is None
    assert ex.exposure_seconds is None


def test_unknown_field_type_warns():
    # Direct parser test: type 99 is unknown.
    e = "<"
    header = b"II" + struct.pack(e + "H", 42) + struct.pack(e + "I", 8)
    entry = struct.pack(e + "HHI", 0x010F, 99, 1) + b"\x00" * 4
    ifd = struct.pack(e + "H", 1) + entry + struct.pack(e + "I", 0)
    parser = _TiffParser(header + ifd, 512, 1024 * 1024)
    raw, _, _ = parser.parse()
    assert 0x010F not in raw
    assert any("unknown TIFF field type" in w for w in parser.warnings)


def test_find_exif_in_jpeg_edge_cases():
    assert find_exif_in_jpeg(b"") is None
    assert find_exif_in_jpeg(b"not a jpeg") is None
    # APP1 present but not EXIF (e.g. XMP) -> None
    xmp_app1 = (
        b"\xff\xd8\xff\xe1"
        + struct.pack(">H", 29 + 2)
        + b"http://ns.adobe.com/xap/1.0/\x00"
        + b"\xff\xd9"
    )
    assert find_exif_in_jpeg(xmp_app1) is None


# ---------------------------------------------------------------------------
# Normalization unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2026:09:15 14:22:01", "2026-09-15T14:22:01"),
        ("2000:01:01 00:00:00", "2000-01-01T00:00:00"),
        ("2026-09-15 14:22:01", None),  # wrong separators
        ("not a date", None),
        ("", None),
        (None, None),
        ("2026:13:45 99:99:99", None),  # impossible values
    ],
)
def test_normalize_exif_datetime(raw, expected):
    assert normalize_exif_datetime(raw) == expected


@pytest.mark.parametrize(
    "value, text, seconds",
    [
        ((1, 250), "1/250", 0.004),
        ((28, 10), "14/5", 2.8),
        ((50, 1), "50", 50.0),
        ((0, 5), "0", 0.0),
        ((1, 0), None, None),  # zero denominator
        ("nope", None, None),
        (None, None, None),
    ],
)
def test_format_rational(value, text, seconds):
    t, s = format_rational(value)
    assert t == text
    assert (s == pytest.approx(seconds)) if seconds is not None else s is None
