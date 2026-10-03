"""Tests for batch analysis: parallel scans, duplicates, grouping (v0.5)."""

from __future__ import annotations

import csv
import io
import json

import pytest
from conftest import (
    build_jpeg_with_exif,
    build_jpeg_with_segments,
    build_png,
    build_tiff,
    build_xmp_packet,
    standard_exif,
    standard_gps,
    standard_ifd0,
)

from metatrace.batch.grouping import (
    capture_day,
    device_key_and_display,
    find_duplicates,
    group_by_capture_day,
    group_by_device,
    group_by_location,
)
from metatrace.batch.models import BatchFileResult
from metatrace.batch.runner import default_jobs, run_batch
from metatrace.batch.scan import is_supported_image, iter_candidate_files
from metatrace.cli.main import main
from metatrace.core import config as config_mod


def _write(path, data):
    path.write_bytes(data)
    return str(path)


def _exif_jpeg_bytes(
    make="TestMake", model="TestModel 1000", dto="2026:09:15 14:22:01"
):
    ifd0 = tuple(e for e in standard_ifd0() if e[0] not in (0x010F, 0x0110))
    ifd0 = ifd0 + ((0x010F, 2, make), (0x0110, 2, model))
    exif = tuple(e for e in standard_exif() if e[0] not in (0x9003, 0x9004))
    exif = exif + ((0x9003, 2, dto), (0x9004, 2, dto))
    return build_jpeg_with_exif(build_tiff(ifd0=ifd0, exif=exif))


def _gps_jpeg_bytes(lat_dms=((49, 1), (20, 1), (152, 10))):
    gps = tuple(e for e in standard_gps() if e[0] != 0x0002)
    gps = gps + ((0x0002, 5, lat_dms),)
    tiff = build_tiff(ifd0=standard_ifd0(), exif=standard_exif(), gps=gps)
    return build_jpeg_with_exif(tiff)


def _conflict_jpeg_bytes():
    """EXIF says 2026-09-14 (naive), XMP says 2026-09-15T09:00:00Z."""
    exif = tuple(e for e in standard_exif() if e[0] not in (0x9003, 0x9004))
    exif = exif + (
        (0x9003, 2, "2026:09:14 18:42:07"),
        (0x9004, 2, "2026:09:14 18:42:07"),
    )
    tiff = build_tiff(ifd0=standard_ifd0(), exif=exif)
    app1 = b"Exif\x00\x00" + tiff
    xmp = b"http://ns.adobe.com/xap/1.0/\x00" + build_xmp_packet(
        create_date="2026-09-15T09:00:00Z"
    )
    return build_jpeg_with_segments([(0xE1, app1), (0xE1, xmp)])


@pytest.fixture()
def photo_dir(tmp_path):
    """Mixed directory: images, a duplicate, a non-image, a subdir image."""
    d = tmp_path / "photos"
    d.mkdir()
    _write(d / "a.jpg", _exif_jpeg_bytes())
    _write(d / "b.jpg", _exif_jpeg_bytes())  # byte-identical duplicate of a.jpg
    _write(d / "c.jpg", _exif_jpeg_bytes(make="Canon", model="EOS R5"))
    _write(d / "d.png", build_png())
    _write(d / "notes.txt", b"not an image")
    sub = d / "sub"
    sub.mkdir()
    _write(sub / "e.jpg", _exif_jpeg_bytes())
    return d


def test_scan_lists_files_sorted_not_recursive(photo_dir):
    paths = iter_candidate_files(str(photo_dir), recursive=False)
    names = [p.rsplit("/", 1)[-1] for p in paths]
    assert names == sorted(names)
    assert "e.jpg" not in names
    assert len(paths) == 5


def test_scan_recursive(photo_dir):
    paths = iter_candidate_files(str(photo_dir), recursive=True)
    names = [p.rsplit("/", 1)[-1] for p in paths]
    assert "e.jpg" in names
    assert len(paths) == 6


def test_scan_bad_inputs(tmp_path):
    with pytest.raises(FileNotFoundError):
        iter_candidate_files(str(tmp_path / "nope"), recursive=False)
    with pytest.raises(NotADirectoryError):
        p = tmp_path / "f.txt"
        p.write_text("x")
        iter_candidate_files(str(p), recursive=False)


def test_is_supported_image(tmp_path):
    img = tmp_path / "a.jpg"
    img.write_bytes(_exif_jpeg_bytes())
    txt = tmp_path / "b.txt"
    txt.write_text("hello")
    assert is_supported_image(str(img), 65536)
    assert not is_supported_image(str(txt), 65536)
    assert not is_supported_image(str(tmp_path / "missing.jpg"), 65536)


def test_run_batch_skips_non_images(photo_dir):
    cfg = config_mod.load_config()
    paths = iter_candidate_files(str(photo_dir), recursive=True)
    results = run_batch(paths, cfg, jobs=2, progress=None)
    assert [r.path for r in results] == sorted(r.path for r in results)
    by_status = {}
    for r in results:
        by_status.setdefault(r.status, []).append(r.path)
    assert len(by_status["ok"]) == 5
    assert len(by_status["skipped"]) == 1
    assert by_status["skipped"][0].endswith("notes.txt")


def test_run_batch_error_recorded_not_raised(tmp_path, monkeypatch):
    import metatrace.cli.main as cli_main

    d = tmp_path / "photos"
    d.mkdir()
    _write(d / "good.jpg", _exif_jpeg_bytes())
    bad = _write(d / "bad.jpg", _exif_jpeg_bytes())

    real_analyze = cli_main.analyze_image

    def flaky(path, cfg):
        if path.endswith("bad.jpg"):
            raise OSError("simulated read failure")
        return real_analyze(path, cfg)

    monkeypatch.setattr(cli_main, "analyze_image", flaky)
    cfg = config_mod.load_config()
    results = run_batch(iter_candidate_files(str(d), False), cfg, 2, None)
    assert len(results) == 2
    bad_result = next(r for r in results if r.path == bad)
    assert bad_result.status == "error"
    assert "simulated read failure" in bad_result.error
    assert next(r for r in results if r.path.endswith("good.jpg")).status == "ok"


def test_find_duplicates(photo_dir):
    cfg = config_mod.load_config()
    results = run_batch(
        iter_candidate_files(str(photo_dir), True), cfg, 2, progress=None
    )
    groups = find_duplicates(results)
    # a.jpg, b.jpg and sub/e.jpg are byte-identical (deterministic fixtures).
    assert len(groups) == 1
    assert len(groups[0].files) == 3
    names = {p.rsplit("/", 1)[-1] for p in groups[0].files}
    assert names == {"a.jpg", "b.jpg", "e.jpg"}


def test_group_by_device(photo_dir):
    cfg = config_mod.load_config()
    results = run_batch(
        iter_candidate_files(str(photo_dir), True), cfg, 2, progress=None
    )
    buckets = {b.display: len(b.files) for b in group_by_device(results)}
    assert buckets["TestMake TestModel 1000"] == 3  # a, b, sub/e
    assert buckets["Canon EOS R5"] == 1
    assert buckets["unknown device"] == 1  # d.png


def test_group_by_capture_day(photo_dir):
    cfg = config_mod.load_config()
    results = run_batch(
        iter_candidate_files(str(photo_dir), True), cfg, 2, progress=None
    )
    buckets = {b.display: len(b.files) for b in group_by_capture_day(results)}
    assert buckets["2026-09-15 (timezone unknown)"] == 4
    assert buckets["unknown date"] == 1  # d.png has no timestamps


def test_group_by_location(tmp_path):
    d = tmp_path / "gps"
    d.mkdir()
    _write(d / "g1.jpg", _gps_jpeg_bytes())
    _write(d / "g2.jpg", _gps_jpeg_bytes())  # same cell
    # ~1.7 km north: lands in a different 2-decimal cell.
    _write(d / "g3.jpg", _gps_jpeg_bytes(lat_dms=((49, 1), (21, 1), (152, 10))))
    _write(d / "plain.jpg", _exif_jpeg_bytes())
    cfg = config_mod.load_config()
    results = run_batch(iter_candidate_files(str(d), False), cfg, 2, None)
    buckets = group_by_location(results)
    assert len(buckets) == 2
    counts = sorted(len(b.files) for b in buckets)
    assert counts == [1, 2]
    assert all("approx. 1 km cell" in b.display for b in buckets)


def test_capture_day_and_device_helpers():
    analysis = {
        "timestamps": [
            {
                "label": "capture",
                "value_utc": "2026-09-15T09:00:00Z",
                "wall": None,
                "parseable": True,
            }
        ],
        "device": {
            "claims": [
                {
                    "source": "EXIF",
                    "make_norm": "Canon",
                    "model_norm": "Canon EOS R5",
                    "make_key": "canon",
                    "model_key": "canoneosr5",
                }
            ]
        },
    }
    assert capture_day(analysis) == ("2026-09-15", "2026-09-15")
    key, display = device_key_and_display(analysis)
    assert display == "Canon EOS R5"
    assert key == "canon/canoneosr5"
    assert capture_day({}) == ("unknown", "unknown date")
    assert device_key_and_display({}) == ("unknown", "unknown device")


def test_batch_human_summary(photo_dir, capsys):
    code = main(["batch", str(photo_dir), "--recursive", "--jobs", "1"])
    assert code == 1  # skips -> warning status
    out = capsys.readouterr().out
    assert "5 analyzed" in out
    assert "1 skipped" in out
    assert "JPEG" in out and "PNG" in out
    assert "TestMake TestModel 1000" in out
    assert "Duplicates (1 group(s)" in out
    assert "a.jpg" in out


def test_batch_clean_dir_exit_zero(tmp_path, capsys):
    d = tmp_path / "clean"
    d.mkdir()
    _write(d / "a.jpg", _exif_jpeg_bytes())
    code = main(["batch", str(d)])
    assert code == 0
    assert "1 analyzed, 0 skipped, 0 errors" in capsys.readouterr().out


def test_batch_empty_dir(tmp_path, capsys):
    d = tmp_path / "empty"
    d.mkdir()
    code = main(["batch", str(d)])
    assert code == 0
    out = capsys.readouterr().out
    assert "0 analyzed" in out


def test_batch_bad_directory(tmp_path, capsys):
    code = main(["batch", str(tmp_path / "missing")])
    assert code == 2
    f = tmp_path / "f.txt"
    f.write_text("x")
    code = main(["batch", str(f)])
    assert code == 2
    assert "error" in capsys.readouterr().err


def test_batch_jobs_invalid(photo_dir, capsys):
    assert main(["batch", str(photo_dir), "--jobs", "0"]) == 2
    assert main(["batch", str(photo_dir), "--jobs", "-3"]) == 2


def _batch_json(tmp_path, argv):
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(argv)
    return code, json.loads(buf.getvalue())


def _scrub_volatile(env):
    env = json.loads(json.dumps(env))
    env.pop("timestamp", None)
    env["data"]["batch"].pop("jobs", None)
    for f in env["data"]["batch"]["files"]:
        if f["analysis"]:
            f["analysis"].pop("analyzed_at", None)
    return env


def test_batch_json_envelope(photo_dir):
    code, env = _batch_json(None, ["batch", str(photo_dir), "--recursive", "--json"])
    assert code == 1
    assert env["tool"] == "metatrace"
    assert env["command"] == "batch"
    assert env["status"] == "warning"
    batch = env["data"]["batch"]
    assert batch["summary"]["analyzed"] == 5
    assert batch["summary"]["skipped"] == 1
    assert batch["summary"]["by_format"]["JPEG"] == 4
    assert len(batch["duplicates"]) == 1
    assert set(batch["groups"]) == {"by_device", "by_capture_day", "by_location"}
    analyzed = [f for f in batch["files"] if f["status"] == "ok"]
    assert all(f["analysis"]["evidence_id"].startswith("MT-") for f in analyzed)


def test_batch_json_deterministic(photo_dir):
    _, env1 = _batch_json(None, ["batch", str(photo_dir), "--recursive", "--json"])
    _, env2 = _batch_json(None, ["batch", str(photo_dir), "--recursive", "--json"])
    assert _scrub_volatile(env1) == _scrub_volatile(env2)


def test_batch_jobs_1_vs_4_same_results(photo_dir):
    base = ["batch", str(photo_dir), "--recursive", "--json"]
    _, env1 = _batch_json(None, [*base, "--jobs", "1"])
    _, env4 = _batch_json(None, [*base, "--jobs", "4"])
    assert _scrub_volatile(env1) == _scrub_volatile(env4)


def test_batch_csv(photo_dir):
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(["batch", str(photo_dir), "--recursive", "--csv"])
    assert code == 1
    rows = list(csv.DictReader(io.StringIO(buf.getvalue())))
    assert len(rows) == 6
    assert rows[0].keys() == {
        "path",
        "filename",
        "status",
        "format",
        "width",
        "height",
        "size_bytes",
        "sha256",
        "make",
        "model",
        "software",
        "capture_day",
        "gps_latitude",
        "gps_longitude",
        "duplicate_group",
        "warnings",
        "error",
    }
    by_name = {r["filename"]: r for r in rows}
    assert by_name["a.jpg"]["status"] == "ok"
    assert by_name["a.jpg"]["format"] == "JPEG"
    assert by_name["a.jpg"]["duplicate_group"] == by_name["b.jpg"]["duplicate_group"]
    assert by_name["a.jpg"]["duplicate_group"] != ""
    assert by_name["d.png"]["duplicate_group"] == ""
    assert by_name["notes.txt"]["status"] == "skipped"
    assert by_name["notes.txt"]["error"] != ""


def test_batch_progress_stderr_human_but_not_json(photo_dir, capfd):
    main(["batch", str(photo_dir), "--recursive", "--jobs", "1"])
    captured = capfd.readouterr()
    assert "metatrace: batch" in captured.err
    assert "6/6" in captured.err

    main(["batch", str(photo_dir), "--recursive", "--json"])
    captured = capfd.readouterr()
    assert captured.err == ""


def test_batch_timeline_orders_chronologically(tmp_path, capsys):
    d = tmp_path / "tl"
    d.mkdir()
    _write(d / "old.jpg", _exif_jpeg_bytes(dto="2026:09:01 10:00:00"))
    _write(d / "new.jpg", _exif_jpeg_bytes(dto="2026:09:20 10:00:00"))
    code = main(["batch", str(d), "--timeline"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Cross-image timeline" in out
    timeline_section = out.split("Cross-image timeline", 1)[1]
    capture_lines = [ln for ln in timeline_section.splitlines() if "(capture)" in ln]
    assert capture_lines, "expected capture entries in the timeline"
    first_old = next(i for i, ln in enumerate(capture_lines) if "old.jpg" in ln)
    first_new = next(i for i, ln in enumerate(capture_lines) if "new.jpg" in ln)
    assert first_old < first_new


def test_batch_conflicts_counted(tmp_path, capsys):
    d = tmp_path / "conf"
    d.mkdir()
    _write(d / "conflict.jpg", _conflict_jpeg_bytes())
    _write(d / "plain.jpg", _exif_jpeg_bytes())
    code, env = _batch_json(None, ["batch", str(d), "--json"])
    # Conflicts surface as an info-level finding -> warning status -> exit 1.
    assert code == 1
    assert env["status"] == "warning"
    assert env["data"]["batch"]["summary"]["files_with_conflicts"] == 1
    code = main(["batch", str(d)])
    out = capsys.readouterr().out
    assert "Conflicting timestamp claims" in out
    assert "conflict.jpg" in out


def test_batch_location_disclaimer_shown(tmp_path, capsys):
    d = tmp_path / "gpsd"
    d.mkdir()
    _write(d / "g.jpg", _gps_jpeg_bytes())
    main(["batch", str(d)])
    out = capsys.readouterr().out
    assert "they do not prove where the photograph was taken" in out
    assert "approx. 1 km cell" in out


def test_batch_gps_count_in_summary(tmp_path):
    d = tmp_path / "gpsd"
    d.mkdir()
    _write(d / "g.jpg", _gps_jpeg_bytes())
    _write(d / "p.jpg", _exif_jpeg_bytes())
    code, env = _batch_json(None, ["batch", str(d), "--json"])
    assert code == 0
    assert env["data"]["batch"]["summary"]["files_with_gps"] == 1


def test_batch_config_jobs_respected(tmp_path, monkeypatch):
    d = tmp_path / "photos"
    d.mkdir()
    _write(d / "a.jpg", _exif_jpeg_bytes())
    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({"batch_jobs": 3}))
    monkeypatch.setenv("METATRACE_CONFIG", str(cfg_file))
    code, env = _batch_json(None, ["batch", str(d), "--json"])
    assert code == 0
    assert env["data"]["batch"]["jobs"] == 3


def test_default_jobs_sane():
    assert default_jobs() >= 1
    assert default_jobs() <= 4


def test_batch_result_model_roundtrip():
    r = BatchFileResult(path="/x/a.jpg", status="ok", analysis={"a": 1})
    d = r.to_dict()
    assert d["path"] == "/x/a.jpg"
    assert d["analysis"] == {"a": 1}
    assert d["error"] is None
