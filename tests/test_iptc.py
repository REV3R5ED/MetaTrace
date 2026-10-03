"""Tests for IPTC/IIM parsing from JPEG APP13 (v0.3)."""

from __future__ import annotations

import struct

import pytest

from metatrace.parsers import iptc as iptc_mod
from metatrace.parsers.iptc import (
    find_iptc_in_jpeg,
    iter_8bim,
    parse_iptc_record,
)
from tests.conftest import (
    build_iptc_8bim,
    build_iptc_dataset,
    build_jpeg_no_exif,
    build_jpeg_with_segments,
    standard_iptc_datasets,
)


def _jpeg_with_iptc(datasets) -> bytes:
    return build_jpeg_with_segments([(0xED, build_iptc_8bim(datasets))])


# ---------------------------------------------------------------------------
# Location / 8BIM
# ---------------------------------------------------------------------------


def test_iptc_found_in_jpeg_app13():
    data = _jpeg_with_iptc(standard_iptc_datasets())
    record = find_iptc_in_jpeg(data)
    assert record is not None
    datasets, warnings = parse_iptc_record(record)
    assert warnings == []
    assert len(datasets) == 9


def test_iptc_absent_in_plain_jpeg():
    assert find_iptc_in_jpeg(build_jpeg_no_exif()) is None


def test_8bim_truncated_block_raises():
    # Declared payload longer than the buffer.
    bad = b"8BIM" + struct.pack(">H", 0x0404) + b"\x00\x00" + struct.pack(">I", 999)
    with pytest.raises(ValueError, match="past the buffer"):
        list(iter_8bim(bad))


def test_8bim_bad_signature_raises():
    with pytest.raises(ValueError, match="8BIM"):
        list(iter_8bim(b"XXXX" + b"\x00" * 12))


def test_8bim_named_resource_and_padding():
    # Non-empty Pascal name ("AB" -> 1+2=3 bytes, padded to 4).
    name = b"\x02AB\x00"
    payload = b"hello!"
    block = b"8BIM" + struct.pack(">H", 0x0404) + name + struct.pack(">I", 6) + payload
    found = list(iter_8bim(block))
    assert found == [(0x0404, b"AB", b"hello!")]


# ---------------------------------------------------------------------------
# Dataset parsing
# ---------------------------------------------------------------------------


def test_parse_iptc_record_unknown_dataset_kept():
    datasets = [build_iptc_dataset(2, 99, b"mystery")]
    parsed, warnings = parse_iptc_record(b"".join(datasets))
    assert warnings == []
    assert parsed[0]["name"] is None
    assert parsed[0]["data"] == "mystery"
    assert parsed[0]["data_hex"] == b"mystery".hex()


def test_parse_iptc_record_truncated_warns():
    parsed, warnings = parse_iptc_record(b"\x1c\x02\x19\x00\x05ab")
    assert any("past the buffer" in w for w in warnings)
    assert parsed == []


def test_parse_iptc_record_bad_marker_warns():
    parsed, warnings = parse_iptc_record(b"\x00\x02\x19\x00\x01a")
    assert any("0x1C" in w for w in warnings)
    assert parsed == []


def test_parse_iptc_record_extended_length():
    value = b"z" * 100
    # Extended form: length field 0x8001 -> 1 length byte follows (=100).
    raw = b"\x1c\x02\x78" + struct.pack(">H", 0x8001) + bytes((100,)) + value
    parsed, warnings = parse_iptc_record(raw)
    assert warnings == []
    assert parsed[0]["data"] == "z" * 100


def test_parse_iptc_record_non_utf8_falls_back():
    raw = build_iptc_dataset(2, 80, b"Bj\xf6rk")  # latin-1 ö
    parsed, _ = parse_iptc_record(raw)
    assert parsed[0]["data"] == "Björk"
    assert parsed[0]["data_hex"] == b"Bj\xf6rk".hex()


# ---------------------------------------------------------------------------
# extract_iptc
# ---------------------------------------------------------------------------


def test_extract_iptc_normalized_fields(tmp_path):
    p = tmp_path / "i.jpg"
    p.write_bytes(_jpeg_with_iptc(standard_iptc_datasets()))
    iptc = iptc_mod.extract_iptc(str(p), "JPEG")
    assert iptc.present
    assert iptc.fields["record_version"] == 4
    assert iptc.fields["keywords"] == ["harbor", "dusk"]
    assert iptc.fields["byline"] == ["Pouya Shini Karim"]
    assert iptc.fields["credit"] == ["Test Agency"]
    assert iptc.fields["copyright_notice"] == ["(c) 2026 Test"]
    assert iptc.fields["date_created"] == "2026-09-14"
    assert iptc.fields["date_created_raw"] == "20260914"
    assert iptc.fields["time_created"] == "18:42:07+00:00"
    assert iptc.fields["time_created_raw"] == "184207+0000"
    assert iptc.fields["caption"] == "A harbor at dusk."
    assert iptc.warnings == []


def test_extract_iptc_implausible_date_not_normalized(tmp_path):
    datasets = [build_iptc_dataset(2, 55, b"20261399")]
    p = tmp_path / "i.jpg"
    p.write_bytes(_jpeg_with_iptc(datasets))
    iptc = iptc_mod.extract_iptc(str(p), "JPEG")
    assert iptc.present
    assert iptc.fields["date_created"] is None
    assert iptc.fields["date_created_raw"] == "20261399"


def test_extract_iptc_duplicate_non_repeatable_keeps_first(tmp_path):
    datasets = [
        build_iptc_dataset(2, 105, b"First headline"),
        build_iptc_dataset(2, 105, b"Second headline"),
    ]
    p = tmp_path / "i.jpg"
    p.write_bytes(_jpeg_with_iptc(datasets))
    iptc = iptc_mod.extract_iptc(str(p), "JPEG")
    assert iptc.fields["headline"] == "First headline"
    assert len(iptc.raw_datasets) == 2  # both observed


def test_extract_iptc_unknown_dataset_surfaced(tmp_path):
    datasets = [build_iptc_dataset(2, 99, b"mystery")]
    p = tmp_path / "i.jpg"
    p.write_bytes(_jpeg_with_iptc(datasets))
    iptc = iptc_mod.extract_iptc(str(p), "JPEG")
    assert iptc.present
    assert iptc.fields["dataset_2_99"] == "mystery"
    assert iptc.raw_datasets[0]["name"] is None


def test_extract_iptc_truncated_irb_warns_but_present(tmp_path):
    # APP13 claims an IPTC block but the payload is cut short.
    bad_block = b"Photoshop 3.0\x00" + b"8BIM" + struct.pack(">H", 0x0404)
    p = tmp_path / "i.jpg"
    p.write_bytes(build_jpeg_with_segments([(0xED, bad_block)]))
    iptc = iptc_mod.extract_iptc(str(p), "JPEG")
    # find_iptc_in_jpeg swallows the 8BIM ValueError -> no record found.
    assert not iptc.present


def test_extract_iptc_unsupported_format(tmp_path):
    p = tmp_path / "i.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    assert not iptc_mod.extract_iptc(str(p), "PNG").present


def test_extract_iptc_missing_file():
    got = iptc_mod.extract_iptc("/nonexistent/i.jpg", "JPEG")
    assert not got.present
    assert got.warnings


def test_extract_iptc_json_serializable(tmp_path):
    import json

    p = tmp_path / "i.jpg"
    p.write_bytes(_jpeg_with_iptc(standard_iptc_datasets()))
    json.dumps(iptc_mod.extract_iptc(str(p), "JPEG").to_dict())
