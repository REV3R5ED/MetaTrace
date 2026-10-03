"""Tests for the MetaTrace CLI."""

from __future__ import annotations

import json

import pytest
from conftest import (
    build_icc_app2,
    build_icc_profile,
    build_iptc_8bim,
    build_jpeg_with_exif,
    build_jpeg_with_segments,
    build_png,
    build_tiff,
    build_xmp_packet,
    standard_exif,
    standard_ifd0,
    standard_iptc_datasets,
)

from metatrace.cli.main import build_parser, main


def write_tmp(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_inspect_jpeg_with_exif_human(tmp_path, capsys, jpeg_with_exif):
    code = main(["inspect", str(jpeg_with_exif)])
    assert code == 0
    out = capsys.readouterr().out
    assert "TestMake" in out
    assert "TestModel 1000" in out
    assert "1/250" in out
    assert "evidence_id:  MT-" in out
    assert "sha256:" in out


def test_inspect_json_envelope(tmp_path, capsys, jpeg_with_exif):
    code = main(["inspect", str(jpeg_with_exif), "--json"])
    assert code == 0
    out = capsys.readouterr().out
    env = json.loads(out)
    assert env["tool"] == "metatrace"
    assert env["command"] == "inspect"
    assert env["status"] == "ok"
    analysis = env["data"]["analysis"]
    assert analysis["evidence_id"].startswith("MT-")
    assert analysis["exif"]["make"] == "TestMake"
    assert analysis["exif"]["raw_tags"]["271"] == "TestMake"  # 0x010F
    assert analysis["tool_version"] == env["version"]


def test_inspect_json_flag_before_subcommand(tmp_path, capsys, jpeg_with_exif):
    code = main(["--json", "inspect", str(jpeg_with_exif)])
    assert code == 0
    env = json.loads(capsys.readouterr().out)
    assert env["status"] == "ok"


def test_inspect_sha512_flag(tmp_path, capsys, jpeg_with_exif):
    code = main(["inspect", str(jpeg_with_exif), "--sha512", "--json"])
    assert code == 0
    env = json.loads(capsys.readouterr().out)
    assert "sha512" in env["data"]["analysis"]["hashes"]


def test_inspect_png_no_exif(tmp_path, capsys):
    path = write_tmp(tmp_path, "a.png", build_png(8, 6))
    code = main(["inspect", path])
    assert code == 0
    out = capsys.readouterr().out
    assert "PNG" in out
    assert "EXIF:         not present" in out


def test_inspect_v03_sections_and_dates_side_by_side(tmp_path, capsys):
    """v0.3 sections render; v0.4 compares the same logical date across
    sources descriptively — agree/differ, never merged, never judged."""
    tiff = build_tiff(ifd0=standard_ifd0(), exif=standard_exif())
    exif_seg = (0xE1, b"Exif\x00\x00" + tiff)
    xmp_seg = (0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + build_xmp_packet())
    iptc_seg = (0xED, build_iptc_8bim(standard_iptc_datasets()))
    icc_segs = build_icc_app2(build_icc_profile())
    data = build_jpeg_with_segments([exif_seg, xmp_seg, iptc_seg, *icc_segs])
    path = write_tmp(tmp_path, "full.jpg", data)

    code = main(["inspect", path])
    assert code == 0
    out = capsys.readouterr().out
    assert "XMP (normalized" in out
    assert "Harbor at dusk" in out
    assert "IPTC/IIM (normalized" in out
    assert "A harbor at dusk." in out
    assert "ICC profile (header" in out
    assert "display device" in out
    # v0.4 descriptive comparison: all three claims visible, none merged.
    assert "Cross-source comparison (descriptive" in out
    assert "EXIF DateTimeOriginal" in out
    assert "2026-09-15T14:22:01" in out  # EXIF claim
    assert "XMP xmp:CreateDate" in out
    assert "2026-09-14T18:42:07Z" in out  # XMP claim
    assert "IPTC DateCreated" in out
    assert "2026-09-14" in out  # IPTC claim
    assert "not a verdict" in out
    # EXIF (2026-09-15 naive) vs XMP/IPTC (2026-09-14 UTC): differ, recorded.
    assert "capture_time: DIFFER" in out

    code = main(["inspect", path, "--json"])
    env = json.loads(capsys.readouterr().out)
    analysis = env["data"]["analysis"]
    assert analysis["xmp"]["present"]
    assert analysis["iptc"]["present"]
    assert analysis["icc"]["present"]
    assert analysis["xmp"]["dublin_core"]["title"] == "Harbor at dusk"
    assert analysis["iptc"]["fields"]["keywords"] == ["harbor", "dusk"]
    assert analysis["icc"]["signature_valid"] is True


def test_inspect_v03_absent_sections(tmp_path, capsys):
    path = write_tmp(tmp_path, "plain.png", build_png(8, 6))
    code = main(["inspect", path])
    assert code == 0
    out = capsys.readouterr().out
    assert "XMP:          not present" in out
    assert "IPTC:         not present" in out
    assert "ICC:          not present" in out
    # No dates section when no source claims a date.
    assert "side by side" not in out


def test_inspect_v03_bad_icc_signature_finding(tmp_path, capsys):
    profile = build_icc_profile(magic=b"XXXX")
    data = build_jpeg_with_segments(build_icc_app2(profile))
    path = write_tmp(tmp_path, "badicc.jpg", data)
    code = main(["inspect", path, "--json"])
    assert code == 1  # medium finding
    env = json.loads(capsys.readouterr().out)
    assert any(f["title"] == "ICC profile signature invalid" for f in env["findings"])
    assert env["data"]["analysis"]["icc"]["signature_valid"] is False


def test_inspect_unknown_format_warns(tmp_path, capsys):
    path = write_tmp(tmp_path, "x.bin", b"\x00\x01\x02" * 100)
    code = main(["inspect", path, "--json"])
    assert code == 1  # findings -> warning
    env = json.loads(capsys.readouterr().out)
    assert env["status"] == "warning"
    assert any("unrecognized" in f["title"] for f in env["findings"])


def test_inspect_missing_file(capsys):
    code = main(["inspect", "/no/such/file.jpg"])
    assert code == 2
    assert "no such file" in capsys.readouterr().err


def test_inspect_directory(tmp_path, capsys):
    code = main(["inspect", str(tmp_path)])
    assert code == 2


def test_inspect_over_size_limit(tmp_path, capsys, jpeg_with_exif, monkeypatch):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"max_file_size_bytes": 10}))
    code = main(["--config", str(cfg), "inspect", str(jpeg_with_exif)])
    assert code == 2
    assert "over the" in capsys.readouterr().err


def test_inspect_malformed_exif_warns_not_crashes(tmp_path, capsys):
    # Truncated inside APP1: identification ok, EXIF absent, no crash.
    tiff = build_tiff(endian="<", ifd0=standard_ifd0(), exif=standard_exif())
    jpeg = build_jpeg_with_exif(tiff)[:40]
    path = write_tmp(tmp_path, "trunc.jpg", jpeg)
    code = main(["inspect", path, "--json"])
    assert code in (0, 1)
    env = json.loads(capsys.readouterr().out)
    assert env["data"]["analysis"]["exif"]["present"] is False


def test_config_show(tmp_path, capsys):
    code = main(["config", "show"])
    assert code == 0
    assert "profile 'default'" in capsys.readouterr().out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.8.0" in capsys.readouterr().out


def test_help_flag():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_bad_config_file_exits_2(tmp_path, capsys):
    cfg = tmp_path / "bad.json"
    cfg.write_text("{nope")
    code = main(["--config", str(cfg), "inspect", "x.jpg"])
    assert code == 2


def test_audit_log_written(tmp_path, monkeypatch, jpeg_with_exif, capsys):
    log_file = tmp_path / "audit.log"
    monkeypatch.setenv("METATRACE_AUDIT_LOG", str(log_file))
    assert main(["inspect", str(jpeg_with_exif)]) == 0
    entry = json.loads(log_file.read_text().strip())
    assert entry["command"] == "inspect"
    assert entry["exit_code"] == 0


def test_parser_builds():
    parser = build_parser()
    assert parser.prog == "metatrace"
