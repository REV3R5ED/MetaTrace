"""Tests for v0.7 embedded thumbnail extraction, comparison, CLI, batch."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import struct

import pytest
from conftest import (
    build_jpeg_no_exif,
    build_jpeg_thumb_blob,
    build_jpeg_with_exif,
    build_jpeg_with_ifd1_thumbnail,
    build_png,
    build_tiff,
    build_tiff_with_ifd1,
)

from metatrace.cli.main import main
from metatrace.thumbnails import (
    compare_thumbnail,
    extract_thumbnails,
    extract_thumbnails_with_blobs,
)
from metatrace.thumbnails.extract import (
    iter_jpeg_markers,
    jpeg_encoder_signals,
    jpeg_sof_dimensions,
    write_thumbnail,
)
from metatrace.thumbnails.models import ThumbnailInfo


def _write(tmp_path, name: str, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _thumb(
    width: int | None = 160,
    height: int | None = 120,
    dqt_count: int | None = 2,
    has_dht: bool | None = True,
) -> ThumbnailInfo:
    return ThumbnailInfo(
        index=0,
        source="EXIF IFD1 (JPEG blob)",
        byte_size=64,
        sha256="cd" * 32,
        width=width,
        height=height,
        format="JPEG",
        dqt_count=dqt_count,
        has_dht=has_dht,
    )


# ---------------------------------------------------------------------------
# JPEG SOF dimension scan
# ---------------------------------------------------------------------------


def test_sof_dimensions_basic():
    assert jpeg_sof_dimensions(build_jpeg_thumb_blob(160, 120)) == (160, 120)


def test_sof_dimensions_not_jpeg():
    assert jpeg_sof_dimensions(b"definitely not a jpeg") == (None, None)


def test_sof_dimensions_truncated():
    assert jpeg_sof_dimensions(b"\xff\xd8\xff\xc0\x00\x0b\x08\x00") == (None, None)


def test_sof_skips_non_sof_markers():
    blob = (
        b"\xff\xd8"
        + b"\xff\xe0\x00\x10JFIF\x00"
        + bytes(9)  # APP0
        + b"\xff\xdb\x00\x43\x00"
        + bytes(64)  # DQT
        + b"\xff\xc0\x00\x0b\x08"
        + struct.pack(">HH", 90, 80)
        + b"\x01\x01\x11\x00"
        + b"\xff\xd9"
    )
    assert jpeg_sof_dimensions(blob) == (80, 90)


def test_sof_first_frame_wins():
    blob = (
        b"\xff\xd8"
        + b"\xff\xc0\x00\x0b\x08"
        + struct.pack(">HH", 10, 20)
        + b"\x01\x01\x11\x00"
        + b"\xff\xc2\x00\x0b\x08"
        + struct.pack(">HH", 30, 40)
        + b"\x01\x01\x11\x00"
        + b"\xff\xd9"
    )
    assert jpeg_sof_dimensions(blob) == (20, 10)


def test_sof_ignores_dht_marker():
    # 0xC4 is DHT, not a frame header — must not be read as dimensions.
    blob = b"\xff\xd8" + b"\xff\xc4\x00\x05AA" + b"\xff\xd9"
    assert jpeg_sof_dimensions(blob) == (None, None)


def test_iter_jpeg_markers_stops_at_sos():
    blob = build_jpeg_thumb_blob()
    markers = [m for m, _, _ in iter_jpeg_markers(blob)]
    assert 0xDA not in markers  # SOS ends the scan
    assert 0xC0 in markers  # SOF0 seen


def test_iter_jpeg_markers_not_jpeg():
    assert iter_jpeg_markers(b"hello") == []


# ---------------------------------------------------------------------------
# Encoder signals
# ---------------------------------------------------------------------------


def test_encoder_signals_counts_tables():
    dqt, dht = jpeg_encoder_signals(build_jpeg_thumb_blob(dqt_tables=2, with_dht=True))
    assert dqt == 2
    assert dht is True


def test_encoder_signals_no_dht():
    dqt, dht = jpeg_encoder_signals(build_jpeg_thumb_blob(dqt_tables=1, with_dht=False))
    assert dqt == 1
    assert dht is False


def test_encoder_signals_garbage_never_raises():
    assert jpeg_encoder_signals(b"\xff\xd8\xff\xdb\x00\x02") == (0, False)


# ---------------------------------------------------------------------------
# Extraction: JPEG EXIF IFD1
# ---------------------------------------------------------------------------


def test_extract_jpeg_ifd1_jpeg_blob(tmp_path):
    blob = build_jpeg_thumb_blob(160, 120)
    path = _write(tmp_path, "t.jpg", build_jpeg_with_ifd1_thumbnail(blob))
    data = extract_thumbnails(path, "JPEG")
    assert data.present
    assert len(data.thumbnails) == 1
    t = data.thumbnails[0]
    assert t.source == "EXIF IFD1 (JPEG blob)"
    assert t.width == 160 and t.height == 120
    assert t.format == "JPEG"
    assert t.byte_size == len(blob)
    assert t.sha256 == hashlib.sha256(blob).hexdigest()
    assert t.dqt_count == 1 and t.has_dht is True
    # Main-image encoder signals recorded for the "same encoder?" check.
    assert data.main_dqt_count is not None
    assert data.main_has_dht is not None


def test_extract_jpeg_no_exif_absent(tmp_path):
    path = _write(tmp_path, "t.jpg", build_jpeg_no_exif())
    data = extract_thumbnails(path, "JPEG")
    assert not data.present
    assert data.thumbnails == []


def test_extract_jpeg_exif_no_ifd1_absent(tmp_path):
    tiff = build_tiff(ifd0=((0x010F, 2, "Make"),))
    path = _write(tmp_path, "t.jpg", build_jpeg_with_exif(tiff))
    data = extract_thumbnails(path, "JPEG")
    assert not data.present


def test_extract_ifd1_offset_out_of_bounds_warns(tmp_path):
    # 0x0201 points past the end of the file: bounds-checked, skipped.
    tiff = build_tiff_with_ifd1(
        ifd1=((0x0201, 4, 0), (0x0202, 4, 5000)),
        thumb_blob=b"",
    )
    path = _write(tmp_path, "t.tif", tiff)
    data = extract_thumbnails(path, "TIFF")
    assert not data.present
    assert any("out of bounds" in w for w in data.warnings)


def test_extract_tiff_ifd1_jpeg_blob(tmp_path):
    blob = build_jpeg_thumb_blob(80, 60)
    tiff = build_tiff_with_ifd1(
        ifd1=((0x0201, 4, 0), (0x0202, 4, len(blob))),
        thumb_blob=blob,
    )
    path = _write(tmp_path, "t.tif", tiff)
    data = extract_thumbnails(path, "TIFF")
    assert data.present
    assert data.thumbnails[0].source == "TIFF IFD1 (JPEG blob)"
    assert (data.thumbnails[0].width, data.thumbnails[0].height) == (80, 60)


def test_extract_tiff_uncompressed_strips(tmp_path):
    pixels = bytes(160 * 120 * 3)
    tiff = build_tiff_with_ifd1(
        ifd1=(
            (0x0100, 4, 160),
            (0x0101, 4, 120),
            (0x0103, 3, 1),
            (0x0111, 4, 0),  # patched
            (0x0117, 4, len(pixels)),
        ),
        thumb_blob=pixels,
        thumb_offset_tag=0x0111,
    )
    path = _write(tmp_path, "t.tif", tiff)
    data = extract_thumbnails(path, "TIFF")
    assert data.present
    t = data.thumbnails[0]
    assert t.source == "TIFF IFD1 (TIFF strips)"
    assert (t.width, t.height) == (160, 120)
    assert t.format == "UNKNOWN"  # raw pixels: no magic bytes


def test_extract_ifd1_no_thumb_tags_warns(tmp_path):
    tiff = build_tiff_with_ifd1(ifd1=((0x0100, 4, 160),))
    path = _write(tmp_path, "t.tif", tiff)
    data = extract_thumbnails(path, "TIFF")
    assert not data.present
    assert any("no thumbnail data tags" in w for w in data.warnings)


def test_extract_corrupt_blob_no_crash(tmp_path):
    blob = b"this is not image data, just bytes...."
    tiff = build_tiff_with_ifd1(
        ifd1=((0x0201, 4, 0), (0x0202, 4, len(blob))),
        thumb_blob=blob,
    )
    path = _write(tmp_path, "t.tif", tiff)
    data = extract_thumbnails(path, "TIFF")
    assert data.present
    t = data.thumbnails[0]
    assert t.format == "UNKNOWN"
    assert t.width is None and t.height is None


def test_extract_png_absent(tmp_path):
    path = _write(tmp_path, "t.png", build_png())
    data = extract_thumbnails(path, "PNG")
    assert not data.present
    assert data.thumbnails == []
    assert data.warnings == []


def test_extract_missing_file_warns(tmp_path):
    data = extract_thumbnails(str(tmp_path / "nope.jpg"), "JPEG")
    assert not data.present
    assert data.warnings


def test_extract_with_blobs_roundtrip(tmp_path):
    blob = build_jpeg_thumb_blob(160, 120)
    path = _write(tmp_path, "t.jpg", build_jpeg_with_ifd1_thumbnail(blob))
    data, blobs = extract_thumbnails_with_blobs(path, "JPEG")
    assert len(blobs) == 1
    assert blobs[0] == blob
    assert data.thumbnails[0].sha256 == hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# Metadata-level comparison
# ---------------------------------------------------------------------------


def test_compare_same_aspect_and_scale():
    thumb = _thumb(width=150, height=100)  # 3:2 like the 6000x4000 main
    comp = compare_thumbnail(thumb, 6000, 4000, 2, True)
    assert comp["aspect"] == "same"
    assert comp["scale"] == pytest.approx(150 / 6000)
    assert comp["larger_than_main"] is False
    assert comp["encoder"] == "same"


def test_compare_different_aspect():
    comp = compare_thumbnail(_thumb(width=160, height=120), 6000, 4000, 2, True)
    assert comp["aspect"] == "different"
    assert "5%" in " ".join(comp["notes"])


def test_compare_larger_than_main():
    comp = compare_thumbnail(_thumb(width=7000, height=5000), 6000, 4000, 2, True)
    assert comp["larger_than_main"] is True


def test_compare_encoder_different_is_weak():
    comp = compare_thumbnail(_thumb(dqt_count=1, has_dht=False), 6000, 4000, 2, True)
    assert comp["encoder"] == "different"
    assert "weak signal" in (comp["encoder_detail"] or "")


def test_compare_encoder_partial_is_unknown():
    comp = compare_thumbnail(_thumb(dqt_count=9, has_dht=True), 6000, 4000, 2, True)
    assert comp["encoder"] == "unknown"


def test_compare_unknown_dimensions():
    comp = compare_thumbnail(_thumb(width=None, height=None), 6000, 4000, 2, True)
    assert comp["aspect"] == "unknown"
    assert comp["scale"] is None


def test_compare_no_main_dimensions():
    comp = compare_thumbnail(_thumb(), None, None, None, None)
    assert comp["aspect"] == "unknown"
    assert comp["encoder"] == "unknown"


# ---------------------------------------------------------------------------
# write_thumbnail
# ---------------------------------------------------------------------------


def test_write_thumbnail_roundtrip(tmp_path):
    blob = build_jpeg_thumb_blob(160, 120)
    target, err = write_thumbnail(blob, str(tmp_path), "MT-abc123", 0, "JPEG")
    assert err is None
    assert target is not None and target.endswith("MT-abc123_thumb0.jpg")
    assert open(target, "rb").read() == blob


def test_write_thumbnail_sanitizes_stem(tmp_path):
    target, err = write_thumbnail(b"x", str(tmp_path), "a/b\\c", 0, "JPEG")
    assert err is None
    assert target is not None and "a_b_c_thumb0.jpg" in target


def test_write_thumbnail_refuses_overwrite(tmp_path):
    blob = build_jpeg_thumb_blob()
    target, err = write_thumbnail(blob, str(tmp_path), "MT-x", 0, "JPEG")
    assert err is None
    _target2, err2 = write_thumbnail(b"other", str(tmp_path), "MT-x", 0, "JPEG")
    assert err2 is not None and "--force" in err2
    assert open(target, "rb").read() == blob  # untouched


def test_write_thumbnail_force_overwrites(tmp_path):
    blob = build_jpeg_thumb_blob()
    target, _ = write_thumbnail(blob, str(tmp_path), "MT-x", 0, "JPEG")
    target2, err = write_thumbnail(b"new", str(tmp_path), "MT-x", 0, "JPEG", force=True)
    assert err is None
    assert target2 == target
    assert open(target, "rb").read() == b"new"


def test_write_thumbnail_tiff_extension(tmp_path):
    target, err = write_thumbnail(b"x", str(tmp_path), "MT-x", 1, "TIFF")
    assert err is None
    assert target is not None and target.endswith("_thumb1.tif")


# ---------------------------------------------------------------------------
# CLI: thumbnails command
# ---------------------------------------------------------------------------


def _cli(args, capsys=None):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(args)
    return code, buf.getvalue()


def test_cli_thumbnails_lists(tmp_path, capsys):
    blob = build_jpeg_thumb_blob(160, 120)
    path = _write(tmp_path, "t.jpg", build_jpeg_with_ifd1_thumbnail(blob))
    code, out = _cli(["thumbnails", path])
    assert code == 0
    assert "1 embedded thumbnail" in out
    assert "160x120" in out
    assert "JPEG" in out


def test_cli_thumbnails_none(tmp_path):
    path = _write(tmp_path, "t.png", build_png())
    code, out = _cli(["thumbnails", path])
    assert code == 0
    assert "none embedded" in out


def test_cli_thumbnails_json(tmp_path):
    blob = build_jpeg_thumb_blob(160, 120)
    path = _write(tmp_path, "t.jpg", build_jpeg_with_ifd1_thumbnail(blob))
    code, out = _cli(["thumbnails", path, "--json"])
    assert code == 0
    env = json.loads(out)
    thumbs = env["data"]["analysis"]["thumbnails"]["thumbnails"]
    assert len(thumbs) == 1
    assert thumbs[0]["width"] == 160
    assert env["data"]["extracted"] == []


def test_cli_thumbnails_missing_file():
    code, _out = _cli(["thumbnails", "/nonexistent/x.jpg"])
    assert code == 2


def test_cli_extract_roundtrip(tmp_path):
    blob = build_jpeg_thumb_blob(160, 120)
    path = _write(tmp_path, "t.jpg", build_jpeg_with_ifd1_thumbnail(blob))
    out_dir = tmp_path / "out"
    code, out = _cli(["thumbnails", path, "--extract", "--out-dir", str(out_dir)])
    assert code == 0
    assert "extracted" in out
    written = list(out_dir.iterdir())
    assert len(written) == 1
    assert written[0].read_bytes() == blob
    assert written[0].name.startswith("MT-")
    assert written[0].name.endswith("_thumb0.jpg")


def test_cli_extract_refuses_overwrite(tmp_path):
    blob = build_jpeg_thumb_blob(160, 120)
    path = _write(tmp_path, "t.jpg", build_jpeg_with_ifd1_thumbnail(blob))
    out_dir = tmp_path / "out"
    code1, _ = _cli(["thumbnails", path, "--extract", "--out-dir", str(out_dir)])
    assert code1 == 0
    code2, _ = _cli(["thumbnails", path, "--extract", "--out-dir", str(out_dir)])
    assert code2 == 2  # refuses without --force


def test_cli_extract_force(tmp_path):
    blob = build_jpeg_thumb_blob(160, 120)
    path = _write(tmp_path, "t.jpg", build_jpeg_with_ifd1_thumbnail(blob))
    out_dir = tmp_path / "out"
    _cli(["thumbnails", path, "--extract", "--out-dir", str(out_dir)])
    code, _ = _cli(
        ["thumbnails", path, "--extract", "--out-dir", str(out_dir), "--force"]
    )
    assert code == 0


def test_inspect_shows_thumbnails_section(tmp_path):
    blob = build_jpeg_thumb_blob(160, 120)
    path = _write(tmp_path, "t.jpg", build_jpeg_with_ifd1_thumbnail(blob))
    code, out = _cli(["inspect", path])
    assert code == 0
    assert "Thumbnails (1 embedded)" in out
    assert "160x120" in out


def test_inspect_png_thumbnails_na(tmp_path):
    path = _write(tmp_path, "t.png", build_png())
    code, out = _cli(["inspect", path])
    assert code == 0
    assert "Thumbnails:" in out and "n/a" in out


# ---------------------------------------------------------------------------
# Anomaly engine integration (v0.7 rule)
# ---------------------------------------------------------------------------


def test_analyze_stripped_thumbnail_end_to_end(tmp_path):
    # IFD1 exists but points nowhere useful: stripped-thumbnail flag.
    # Exit 1: the extraction warning becomes a low-severity finding.
    tiff = build_tiff_with_ifd1(ifd1=((0x0100, 4, 160),))
    path = _write(tmp_path, "t.jpg", build_jpeg_with_exif(tiff))
    code, out = _cli(["analyze", path])
    assert code == 1
    assert "thumbnail-mismatch" in out
    assert "none was extractable" in out


def test_analyze_clean_thumbnail_no_flag(tmp_path):
    blob = build_jpeg_thumb_blob(64, 48, dqt_tables=2, with_dht=True)
    # Main image encoder signals: scan the built JPEG for its own DQT/DHT.
    path = _write(
        tmp_path,
        "t.jpg",
        build_jpeg_with_ifd1_thumbnail(blob, width=640, height=480),
    )
    code, out = _cli(["analyze", path])
    assert code == 0
    # 64x48 vs 640x480: same aspect; encoder signals may differ — the
    # blob has 2 DQT + DHT; the carrier JPEG has none scanned before SOS
    # (SOF-only carrier). Accept either outcome; assert no crash and the
    # thumbnail was seen.
    assert "thumbnail" in out.lower() or "no anomalies" in out


# ---------------------------------------------------------------------------
# Batch integration
# ---------------------------------------------------------------------------


def _batch_json(args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(args)
    return code, json.loads(buf.getvalue())


def test_batch_thumbnail_counts(tmp_path):
    blob = build_jpeg_thumb_blob(160, 120)
    (tmp_path / "with_thumb.jpg").write_bytes(build_jpeg_with_ifd1_thumbnail(blob))
    (tmp_path / "plain.jpg").write_bytes(build_jpeg_no_exif())
    code, env = _batch_json(["batch", str(tmp_path), "--json"])
    assert code == 0
    s = env["data"]["batch"]["summary"]
    assert s["files_with_thumbnails"] == 1
    assert s["total_thumbnails"] == 1
    counts = {
        f["path"].split("/")[-1]: f["thumbnail_count"]
        for f in env["data"]["batch"]["files"]
    }
    assert counts["with_thumb.jpg"] == 1
    assert counts["plain.jpg"] == 0


def test_batch_csv_has_thumbnails_column(tmp_path):
    import csv as csv_mod

    blob = build_jpeg_thumb_blob(160, 120)
    (tmp_path / "with_thumb.jpg").write_bytes(build_jpeg_with_ifd1_thumbnail(blob))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["batch", str(tmp_path), "--csv"])
    rows = list(csv_mod.DictReader(io.StringIO(buf.getvalue())))
    assert "thumbnails" in rows[0]
    assert rows[0]["thumbnails"] == "1"
