"""Tests for ICC profile extraction and header parsing (v0.3)."""

from __future__ import annotations

import struct

from metatrace.parsers import icc as icc_mod
from metatrace.parsers.icc import (
    find_icc_in_jpeg,
    find_icc_in_png,
    find_icc_in_tiff,
    parse_icc_header,
)
from tests.conftest import (
    build_icc_app2,
    build_icc_profile,
    build_iccp_chunk,
    build_jpeg_no_exif,
    build_jpeg_with_segments,
    build_png_with_chunks,
    build_tiff,
    build_tiff_file,
)

# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------


def test_icc_found_in_jpeg_app2_single_chunk():
    profile = build_icc_profile()
    data = build_jpeg_with_segments(build_icc_app2(profile, chunk_size=1 << 20))
    found, warnings = find_icc_in_jpeg(data)
    assert found == profile
    assert warnings == []


def test_icc_reassembled_out_of_order():
    profile = build_icc_profile()
    chunks = build_icc_app2(profile, chunk_size=64)  # several chunks
    assert len(chunks) > 2
    reversed_chunks = list(reversed(chunks))
    data = build_jpeg_with_segments(reversed_chunks)
    found, warnings = find_icc_in_jpeg(data)
    assert found == profile
    assert warnings == []


def test_icc_missing_chunk_warns_and_drops():
    profile = build_icc_profile()
    chunks = build_icc_app2(profile, chunk_size=64)
    data = build_jpeg_with_segments(chunks[:-1])  # drop the last chunk
    found, warnings = find_icc_in_jpeg(data)
    assert found is None
    assert any("missing chunk" in w for w in warnings)


def test_icc_absent_in_plain_jpeg():
    found, _ = find_icc_in_jpeg(build_jpeg_no_exif())
    assert found is None


def test_icc_found_in_png_iccp():
    profile = build_icc_profile()
    data = build_png_with_chunks([build_iccp_chunk(profile)])
    found, warnings = find_icc_in_png(data, 4 * 1024 * 1024)
    assert found == profile
    assert warnings == []


def test_icc_png_bad_compression_method_skipped():
    chunk = (b"iCCP", b"name\x00\x01" + b"junk")
    found, warnings = find_icc_in_png(build_png_with_chunks([chunk]), 4 * 1024 * 1024)
    assert found is None
    assert any("compression method" in w for w in warnings)


def test_icc_found_in_tiff_tag_34675():
    profile = build_icc_profile()
    tiff = build_tiff(ifd0=((34675, 7, profile),))
    found, warnings = find_icc_in_tiff(tiff, 512)
    assert found == profile


def test_icc_absent_in_tiff_without_tag():
    found, _ = find_icc_in_tiff(build_tiff_file(), 512)
    assert found is None


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


def test_parse_icc_header_fields():
    header, tags, warnings = parse_icc_header(build_icc_profile())
    assert warnings == []
    assert header["signature_valid"] is True
    assert header["device_class"] == "mntr"
    assert header["device_class_name"] == "display device"
    assert header["color_space"] == "RGB"
    assert header["pcs"] == "XYZ"
    assert header["version"] == "2.1.0"
    assert header["created"] == "2026-09-14T18:42:07"
    assert header["rendering_intent"] == 1
    assert header["rendering_intent_name"] == "relative colorimetric"
    assert header["device_manufacturer"] == "ACME"
    assert len(tags) == 1
    assert tags[0]["signature"] == "desc"
    assert tags[0]["readable"] is True


def test_parse_icc_header_bad_magic():
    header, _, warnings = parse_icc_header(build_icc_profile(magic=b"XXXX"))
    assert header["signature_valid"] is False
    assert any("acsp" in w for w in warnings)


def test_parse_icc_header_size_mismatch():
    profile = build_icc_profile(size_override=999999)
    header, _, warnings = parse_icc_header(profile)
    assert header["signature_valid"] is True  # magic still checked
    assert any("claims size" in w for w in warnings)


def test_parse_icc_header_truncated():
    header, tags, warnings = parse_icc_header(b"\x00" * 40)
    assert header == {}
    assert tags == []
    assert any("shorter than" in w for w in warnings)


def test_parse_icc_header_tag_out_of_bounds():
    profile = bytearray(build_icc_profile(tag_sigs=(b"desc",)))
    # Point the tag past the end of the profile.
    struct.pack_into(">I", profile, 132 + 4, len(profile) + 100)
    header, tags, warnings = parse_icc_header(bytes(profile))
    assert tags[0]["readable"] is False
    assert any("past the buffer" in w for w in warnings)


def test_parse_icc_header_version_format():
    header, _, _ = parse_icc_header(build_icc_profile(version=(4, 3, 0)))
    assert header["version"] == "4.3.0"


# ---------------------------------------------------------------------------
# extract_icc
# ---------------------------------------------------------------------------


def test_extract_icc_jpeg_end_to_end(tmp_path):
    profile = build_icc_profile()
    p = tmp_path / "c.jpg"
    p.write_bytes(build_jpeg_with_segments(build_icc_app2(profile)))
    icc = icc_mod.extract_icc(str(p), "JPEG")
    assert icc.present
    assert icc.signature_valid
    assert icc.header["device_class_name"] == "display device"
    assert len(icc.tags) == 1
    assert icc.warnings == []


def test_extract_icc_bad_signature_flagged(tmp_path):
    profile = build_icc_profile(magic=b"XXXX")
    p = tmp_path / "c.jpg"
    p.write_bytes(build_jpeg_with_segments(build_icc_app2(profile)))
    icc = icc_mod.extract_icc(str(p), "JPEG")
    assert icc.present  # observed even though invalid
    assert not icc.signature_valid
    assert any("acsp" in w for w in icc.warnings)


def test_extract_icc_png_end_to_end(tmp_path):
    profile = build_icc_profile()
    p = tmp_path / "c.png"
    p.write_bytes(build_png_with_chunks([build_iccp_chunk(profile)]))
    icc = icc_mod.extract_icc(str(p), "PNG")
    assert icc.present
    assert icc.signature_valid


def test_extract_icc_tiff_end_to_end(tmp_path):
    profile = build_icc_profile()
    p = tmp_path / "c.tiff"
    p.write_bytes(build_tiff(ifd0=((34675, 7, profile),)))
    icc = icc_mod.extract_icc(str(p), "TIFF")
    assert icc.present
    assert icc.header["version"] == "2.1.0"


def test_extract_icc_oversize_profile_skipped(tmp_path):
    profile = build_icc_profile()
    p = tmp_path / "c.jpg"
    p.write_bytes(build_jpeg_with_segments(build_icc_app2(profile)))
    icc = icc_mod.extract_icc(str(p), "JPEG", max_profile_bytes=16)
    assert not icc.present
    assert any("limit" in w for w in icc.warnings)


def test_extract_icc_unsupported_format(tmp_path):
    p = tmp_path / "c.gif"
    p.write_bytes(b"GIF89a\x08\x00\x06\x00\x70\x00\x00")
    assert not icc_mod.extract_icc(str(p), "GIF").present


def test_extract_icc_missing_file():
    got = icc_mod.extract_icc("/nonexistent/c.jpg", "JPEG")
    assert not got.present
    assert got.warnings


def test_extract_icc_json_serializable(tmp_path):
    import json

    profile = build_icc_profile()
    p = tmp_path / "c.jpg"
    p.write_bytes(build_jpeg_with_segments(build_icc_app2(profile)))
    json.dumps(icc_mod.extract_icc(str(p), "JPEG").to_dict())
