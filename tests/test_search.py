"""Tests for v0.9 metadata search: index, filters, geo, timeline (v0.9)."""

from __future__ import annotations

import json

import pytest
from conftest import (
    build_jpeg_with_exif,
    build_tiff,
    standard_exif,
    standard_gps,
    standard_ifd0,
)

from metatrace.batch.models import BatchFileResult
from metatrace.batch.runner import run_batch
from metatrace.cli.main import main
from metatrace.core import config as config_mod
from metatrace.search.filters import (
    SearchFilters,
    apply_filters,
    matches,
    parse_date,
    parse_date_range,
    parse_hash,
    parse_near,
)
from metatrace.search.geo import cluster_locations, haversine_km
from metatrace.search.index import (
    INDEX_VERSION,
    IndexError,
    build_index,
    read_index,
    write_index,
)
from metatrace.search.models import IndexRecord
from metatrace.search.timeline import build_search_timeline


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


def _gps_bytes(lat_dms, lon_dms):
    """GPS IFD with custom lat/lon (rational DMS tuples)."""
    gps = tuple(e for e in standard_gps() if e[0] not in (0x0002, 0x0004))
    gps = gps + ((0x0002, 5, lat_dms), (0x0004, 5, lon_dms))
    return gps


def _gps_jpeg_bytes(make="Canon", model="EOS R5", lat=None, lon=None):
    ifd0 = tuple(e for e in standard_ifd0() if e[0] not in (0x010F, 0x0110))
    ifd0 = ifd0 + ((0x010F, 2, make), (0x0110, 2, model))
    gps = standard_gps() if lat is None else _gps_bytes(lat, lon)
    tiff = build_tiff(ifd0=ifd0, exif=standard_exif(), gps=gps)
    return build_jpeg_with_exif(tiff)


def _write_files(tmp_path, files):
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)


def _run_batch_results(tmp_path, files):
    """Write *files* {name: bytes} and run the batch pipeline on them."""
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    cfg = config_mod.load_config()
    return run_batch([str(tmp_path / n) for n in files], cfg, jobs=1)


def _index_from_files(tmp_path, files):
    results = _run_batch_results(tmp_path, files)
    return build_index(results, root=str(tmp_path))


# ---------------------------------------------------------------------------
# Index building
# ---------------------------------------------------------------------------


def test_build_index_record_fields(tmp_path):
    files = {"canon.jpg": _gps_jpeg_bytes()}
    index = _index_from_files(tmp_path, files)
    assert len(index.records) == 1
    r = index.records[0]
    assert r.format == "JPEG"
    assert len(r.sha256) == 64
    assert "Canon" in r.device_display
    assert r.capture_day == "2026-09-15"
    assert r.has_gps
    assert r.gps_lat == pytest.approx(49.33754, abs=0.001)
    assert r.gps_lon == pytest.approx(-123.16244, abs=0.001)
    assert r.timestamps  # normalized claims kept for timeline search
    assert isinstance(r.anomaly_rule_ids, list)


def test_build_index_skips_non_ok(tmp_path):
    (tmp_path / "note.txt").write_text("not an image")
    index = _index_from_files(tmp_path, {"note.txt": b"not an image"})
    assert index.records == []
    assert index.version == INDEX_VERSION


def test_build_index_deterministic(tmp_path):
    files = {
        "b.jpg": _exif_jpeg_bytes(make="Canon"),
        "a.jpg": _exif_jpeg_bytes(make="NIKON"),
    }
    i1 = _index_from_files(tmp_path, files)
    i2 = _index_from_files(tmp_path, files)
    paths1 = [r.path for r in i1.records]
    paths2 = [r.path for r in i2.records]
    assert paths1 == paths2 == sorted(paths1)


def test_index_roundtrip(tmp_path):
    files = {"canon.jpg": _gps_jpeg_bytes()}
    index = _index_from_files(tmp_path, files)
    p = tmp_path / "idx.json"
    write_index(str(p), index)
    back = read_index(str(p))
    assert len(back.records) == 1
    assert back.records[0].sha256 == index.records[0].sha256
    assert back.records[0].gps_lat == pytest.approx(49.33754, abs=0.001)


def test_index_version_mismatch(tmp_path):
    p = tmp_path / "idx.json"
    p.write_text(json.dumps({"version": 999, "records": []}))
    with pytest.raises(IndexError, match="rebuild"):
        read_index(str(p))


def test_index_missing_file(tmp_path):
    with pytest.raises(IndexError, match="no such index"):
        read_index(str(tmp_path / "nope.json"))


def test_index_corrupt_file(tmp_path):
    p = tmp_path / "idx.json"
    p.write_text("{not json")
    with pytest.raises(IndexError, match="cannot read"):
        read_index(str(p))


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def _canon_record() -> IndexRecord:
    return IndexRecord(
        path="/x/canon.jpg",
        filename="canon.jpg",
        sha256="a" * 64,
        format="JPEG",
        device_make="Canon",
        device_model="EOS R5",
        device_display="Canon EOS R5",
        capture_day="2026-09-15",
        gps_lat=49.34,
        gps_lon=-123.16,
        has_gps=True,
        gps_valid=True,
        anomaly_rule_ids=["timestamp-conflict"],
        caption="sunset over water",
        keywords=["vacation", "beach"],
        software="Adobe Photoshop",
    )


def test_filter_device_substring():
    assert matches(_canon_record(), SearchFilters(device="canon"))
    assert matches(_canon_record(), SearchFilters(device="EOS"))
    assert not matches(_canon_record(), SearchFilters(device="nikon"))


def test_filter_date_and_range():
    r = _canon_record()
    assert matches(r, SearchFilters(date="2026-09-15"))
    assert not matches(r, SearchFilters(date="2026-09-16"))
    assert matches(r, SearchFilters(date_range=("2026-09-01", "2026-09-30")))
    assert not matches(r, SearchFilters(date_range=("2026-10-01", "2026-10-31")))
    unknown = IndexRecord(
        path="/x/u.jpg", filename="u.jpg", sha256="b" * 64, format="JPEG"
    )
    assert not matches(unknown, SearchFilters(date_range=("2026-01-01", "2026-12-31")))


def test_parse_date_range_rejects():
    with pytest.raises(ValueError, match="must look like"):
        parse_date_range("2026-09-01")
    with pytest.raises(ValueError, match="not a YYYY-MM-DD"):
        parse_date_range("yesterday..2026-09-30")
    with pytest.raises(ValueError, match="after end"):
        parse_date_range("2026-09-30..2026-09-01")
    assert parse_date("2026-09-15") == "2026-09-15"
    with pytest.raises(ValueError, match="real calendar"):
        parse_date("2026-13-99")


def test_filter_gps_and_anomaly_and_hash():
    r = _canon_record()
    assert matches(r, SearchFilters(gps_only=True))
    assert not matches(
        IndexRecord(path="/x/u.jpg", filename="u.jpg", sha256="b" * 64, format="JPEG"),
        SearchFilters(gps_only=True),
    )
    assert matches(r, SearchFilters(anomaly="timestamp-conflict"))
    assert not matches(r, SearchFilters(anomaly="device-identity-mismatch"))
    assert matches(r, SearchFilters(hash="a" * 8))
    assert matches(r, SearchFilters(hash="A" * 64))  # case-insensitive
    assert not matches(r, SearchFilters(hash="b" * 8))
    with pytest.raises(ValueError, match="at least 8 hex"):
        parse_hash("abc")
    with pytest.raises(ValueError, match="at least 8 hex"):
        parse_hash("zzzzzzzz")


def test_filter_text_literal():
    r = _canon_record()
    assert matches(r, SearchFilters(text="sunset"))
    assert matches(r, SearchFilters(text="VACATION"))  # case-insensitive
    assert matches(r, SearchFilters(text="Photoshop"))
    # Regex metacharacters are literal: "Canon." must not match "CanonX".
    assert not matches(r, SearchFilters(text="Canon."))
    assert matches(r, SearchFilters(text="Canon EOS"))
    assert not matches(r, SearchFilters(text="nikon"))


def test_filters_compose_and():
    r = _canon_record()
    f = SearchFilters(device="canon", date="2026-09-15", gps_only=True)
    assert matches(r, f)
    f2 = SearchFilters(device="canon", date="2026-09-16")
    assert not matches(r, f2)
    recs = [r]
    assert apply_filters(recs, f) == [r]
    assert apply_filters(recs, f2) == []


# ---------------------------------------------------------------------------
# Geo: haversine + --near + clustering
# ---------------------------------------------------------------------------


def test_haversine_known_distances():
    # One degree of latitude ~= 111.19 km.
    assert haversine_km(0.0, 0.0, 1.0, 0.0) == pytest.approx(111.19, abs=0.5)
    # Same point is zero.
    assert haversine_km(49.34, -123.16, 49.34, -123.16) == pytest.approx(0.0)
    # New York to London ~= 5570 km.
    assert haversine_km(40.7128, -74.0060, 51.5074, -0.1278) == pytest.approx(
        5570, abs=30
    )


def test_parse_near_rejects():
    with pytest.raises(ValueError, match="must look like"):
        parse_near("49.34,-123.16")
    with pytest.raises(ValueError, match="must be numbers"):
        parse_near("a,b,c")
    with pytest.raises(ValueError, match="out of range"):
        parse_near("91,0,10")
    with pytest.raises(ValueError, match="out of range"):
        parse_near("0,181,10")
    with pytest.raises(ValueError, match="must be positive"):
        parse_near("0,0,0")
    with pytest.raises(ValueError, match="exceeds the 1000 km cap"):
        parse_near("0,0,1001")
    assert parse_near("49.34,-123.16,10") == (49.34, -123.16, 10.0)


def test_near_filter(tmp_path):
    files = {"canon.jpg": _gps_jpeg_bytes(), "nikon.jpg": _exif_jpeg_bytes()}
    index = _index_from_files(tmp_path, files)
    near = parse_near("49.34,-123.16,10")
    matched = apply_filters(index.records, SearchFilters(near=near))
    assert [r.filename for r in matched] == ["canon.jpg"]
    far = parse_near("0,0,10")
    assert apply_filters(index.records, SearchFilters(near=far)) == []


def test_cluster_locations_merge_and_separate():
    def rec(path, lat, lon):
        return IndexRecord(
            path=path,
            filename=path.rsplit("/", 1)[-1],
            sha256="a" * 64,
            format="JPEG",
            gps_lat=lat,
            gps_lon=lon,
            has_gps=True,
            gps_valid=True,
            capture_day="2026-09-15",
        )

    # Two points ~500 m apart merge; one 50 km away stays separate.
    records = [
        rec("/x/a.jpg", 49.3400, -123.1600),
        rec("/x/b.jpg", 49.3440, -123.1600),
        rec("/x/c.jpg", 49.8000, -123.1600),
    ]
    clusters = cluster_locations(records)
    assert len(clusters) == 2
    big = next(c for c in clusters if c.count == 2)
    assert big.files == ["/x/a.jpg", "/x/b.jpg"]
    assert big.radius_km < 1.0
    assert big.time_span == ("2026-09-15", "2026-09-15")
    solo = next(c for c in clusters if c.count == 1)
    assert solo.files == ["/x/c.jpg"]


def test_cluster_locations_deterministic_and_empty():
    assert cluster_locations([]) == []
    no_gps = IndexRecord(
        path="/x/u.jpg", filename="u.jpg", sha256="b" * 64, format="JPEG"
    )
    assert cluster_locations([no_gps]) == []


# ---------------------------------------------------------------------------
# Timeline search
# ---------------------------------------------------------------------------


def test_search_timeline_ordering(tmp_path):
    files = {"canon.jpg": _gps_jpeg_bytes()}
    index = _index_from_files(tmp_path, files)
    timeline = build_search_timeline(index.records)
    assert timeline
    # v0.4 rule: UTC-known claims before timezone-naive ones.
    seen_naive = False
    for entry in timeline:
        ts = entry["timestamp"]
        if ts.get("value_utc"):
            assert not seen_naive, "UTC claim after a naive claim"
        elif ts.get("wall"):
            seen_naive = True
    assert any(e["timestamp"].get("value_utc") for e in timeline)
    assert any(e["timestamp"].get("wall") for e in timeline)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_search_filters(tmp_path, capsys):
    files = {
        "canon.jpg": _gps_jpeg_bytes(),
        "nikon.jpg": _exif_jpeg_bytes(make="NIKON", model="D850"),
    }
    _write_files(tmp_path, files)
    idx = tmp_path / "idx.json"
    code = main(["search", "--build-index", str(tmp_path), "--index", str(idx)])
    assert code == 0
    assert "2 record(s)" in capsys.readouterr().out

    code = main(["search", "--index", str(idx), "--device", "nikon"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Nikon D850" in out
    assert "Canon" not in out

    code = main(["search", "--index", str(idx), "--gps"])
    assert code == 0
    out = capsys.readouterr().out
    assert "1 of 2" in out

    # Empty results are a valid outcome, exit 0 with a message.
    code = main(["search", "--index", str(idx), "--device", "leica"])
    assert code == 0
    assert "No records match" in capsys.readouterr().out


def test_cli_search_bad_index(tmp_path, capsys):
    code = main(["search", "--index", str(tmp_path / "missing.json")])
    assert code == 2
    code = main(
        ["search", "--index", str(tmp_path / "missing.json"), "--near", "0,0,9999"]
    )
    assert code == 2  # bad filter also exits 2


def test_cli_search_clusters_and_timeline(tmp_path, capsys):
    _write_files(tmp_path, {"canon.jpg": _gps_jpeg_bytes()})
    idx = tmp_path / "idx.json"
    assert main(["search", "--build-index", str(tmp_path), "--index", str(idx)]) == 0
    capsys.readouterr()

    code = main(["search", "--index", str(idx), "clusters"])
    assert code == 0
    out = capsys.readouterr().out
    assert "1 cluster(s)" in out
    assert "do not prove" in out  # claimed-location disclaimer kept

    code = main(["search", "--index", str(idx), "timeline"])
    assert code == 0
    assert "canon.jpg" in capsys.readouterr().out

    code = main(["search", "--index", str(idx), "timeline", "--format", "csv"])
    assert code == 0
    out = capsys.readouterr().out
    assert out.startswith("path,filename,timestamp")


def test_cli_search_json(tmp_path, capsys):
    _write_files(tmp_path, {"canon.jpg": _gps_jpeg_bytes()})
    idx = tmp_path / "idx.json"
    assert main(["search", "--build-index", str(tmp_path), "--index", str(idx)]) == 0
    capsys.readouterr()
    code = main(["search", "--index", str(idx), "--json"])
    assert code == 0
    import json as json_mod

    data = json_mod.loads(capsys.readouterr().out)
    assert data["command"] == "search"
    assert len(data["data"]["matches"]) == 1


def test_cli_batch_index_flag(tmp_path, capsys):
    (tmp_path / "a.jpg").write_bytes(_exif_jpeg_bytes())
    idx = tmp_path / "from-batch.json"
    code = main(["batch", str(tmp_path), "--index", str(idx)])
    assert code == 0
    out = capsys.readouterr().out
    assert "Search index: 1 record(s)" in out
    assert "from-batch.json" in out
    back = read_index(str(idx))
    assert len(back.records) == 1


def test_cli_search_anomaly_filter(tmp_path, capsys):
    # Build a record carrying a rule id directly.
    r = BatchFileResult(
        path="/x/a.jpg",
        status="ok",
        analysis={
            "identity": {"filename": "a.jpg", "format": "JPEG"},
            "hashes": {"sha256": "c" * 64},
            "device": {"claims": []},
            "timestamps": [],
            "exif": {"gps": {"present": False}, "software": ""},
            "iptc": {"caption": "", "keywords": []},
            "xmp": {"dublin_core": {"title": ""}},
        },
        anomaly_count=1,
        anomaly_rule_ids=["timestamp-conflict"],
    )
    index = build_index([r])
    p = tmp_path / "idx.json"
    write_index(str(p), index)
    code = main(["search", "--index", str(p), "--anomaly", "timestamp-conflict"])
    assert code == 0
    assert "a.jpg" in capsys.readouterr().out
    code = main(["search", "--index", str(p), "--anomaly", "device-identity-mismatch"])
    assert code == 0
    assert "No records match" in capsys.readouterr().out
