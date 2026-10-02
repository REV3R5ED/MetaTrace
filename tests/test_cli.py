"""Tests for the MetaTrace CLI."""

from __future__ import annotations

import json

import pytest
from conftest import (
    build_jpeg_with_exif,
    build_png,
    build_tiff,
    standard_exif,
    standard_ifd0,
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
    assert "0.2.0" in capsys.readouterr().out


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
