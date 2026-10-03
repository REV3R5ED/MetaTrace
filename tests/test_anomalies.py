"""Tests for the v0.6 anomaly engine: rules, CLI, batch integration."""

from __future__ import annotations

import json
import struct

from conftest import (
    build_jpeg_with_segments,
    build_tiff,
    build_xmp_packet,
    standard_exif,
    standard_ifd0,
)

from metatrace.anomalies import detect_anomalies
from metatrace.anomalies.rules import (
    _product_name,
    rule_device_mismatch,
    rule_gps_timezone,
    rule_serial_conflict,
    rule_software_chain,
    rule_thumbnail_aspect,
    rule_timestamp_conflict,
)
from metatrace.batch.summary import build_report
from metatrace.cli.main import main
from metatrace.core.models import (
    Analysis,
    ComparedValue,
    ComparisonFact,
    DeviceClaim,
    DeviceIdentity,
    ExifData,
    FileIdentity,
    GeoData,
    NormalizedTimestamp,
    XmpData,
)
from metatrace.normalize.timestamps import (
    normalize_exif_timestamp,
    normalize_xmp_timestamp,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _analysis(**kwargs) -> Analysis:
    a = Analysis(evidence_id="MT-test")
    for key, value in kwargs.items():
        setattr(a, key, value)
    return a


def _exif_ts(raw: str, offset: str | None = None) -> NormalizedTimestamp:
    ts = normalize_exif_timestamp(
        raw, offset, label="capture", source="EXIF DateTimeOriginal"
    )
    assert ts is not None
    return ts


def _xmp_ts(raw: str) -> NormalizedTimestamp:
    ts = normalize_xmp_timestamp(raw, label="capture", source="XMP xmp:CreateDate")
    assert ts is not None
    return ts


def _gps_analysis(lon: float, lat: float = 49.34) -> Analysis:
    gps = GeoData(present=True, valid=True, latitude=lat, longitude=lon)
    return _analysis(exif=ExifData(present=True, gps=gps))


def _compare_fact(
    fact: str, status: str, pairs: list[tuple[str, str]]
) -> ComparisonFact:
    return ComparisonFact(
        fact=fact,
        status=status,
        values=[
            ComparedValue(source=s, raw=r, normalized=r, key=r.lower())
            for s, r in pairs
        ],
    )


# ---------------------------------------------------------------------------
# Rule 1: timestamp conflict
# ---------------------------------------------------------------------------


def test_timestamp_conflict_under_tolerance():
    a = _analysis(
        timestamps=[
            _exif_ts("2026:09:14 18:42:07"),
            _xmp_ts("2026-09-14T18:42:30Z"),  # 23s apart, naive wall vs aware wall
        ]
    )
    assert rule_timestamp_conflict(a) == []


def test_timestamp_conflict_just_over_tolerance():
    a = _analysis(
        timestamps=[
            _exif_ts("2026:09:14 18:42:07"),
            _xmp_ts("2026-09-14T18:44:00Z"),  # 113s apart
        ]
    )
    flags = rule_timestamp_conflict(a)
    assert len(flags) == 1
    assert flags[0].rule_id == "timestamp-conflict"
    assert flags[0].severity == "low"
    assert flags[0].confidence == 50


def test_timestamp_conflict_days_apart_is_high():
    a = _analysis(
        timestamps=[
            _exif_ts("2026:09:14 18:42:07", "+00:00"),
            _xmp_ts("2026-09-17T18:42:07Z"),  # 3 days apart, both aware
        ]
    )
    flags = rule_timestamp_conflict(a)
    assert len(flags) == 1
    assert flags[0].severity == "high"
    assert flags[0].confidence == 85


def test_timestamp_conflict_naive_caps_confidence():
    a = _analysis(
        timestamps=[
            _exif_ts("2026:09:14 18:42:07"),  # naive
            _xmp_ts("2026-09-16T18:42:07Z"),  # 2 days apart by wall clock
        ]
    )
    flags = rule_timestamp_conflict(a)
    assert len(flags) == 1
    assert flags[0].confidence <= 60
    assert "timezone-naive" in flags[0].explanation


def test_timestamp_conflict_single_source_no_flag():
    a = _analysis(timestamps=[_exif_ts("2026:09:14 18:42:07")])
    assert rule_timestamp_conflict(a) == []


def test_timestamp_conflict_custom_tolerance():
    a = _analysis(
        timestamps=[
            _exif_ts("2026:09:14 18:42:07"),
            _xmp_ts("2026-09-14T18:44:00Z"),  # 113s apart
        ]
    )
    assert rule_timestamp_conflict(a, tolerance_s=120.0) == []
    assert len(rule_timestamp_conflict(a, tolerance_s=60.0)) == 1


# ---------------------------------------------------------------------------
# Rule 2: GPS vs timezone
# ---------------------------------------------------------------------------


def test_gps_timezone_plausible_no_flag():
    # Lon -123.16 -> implied UTC-8.2; claimed -08:00 is within tolerance.
    a = _gps_analysis(-123.16)
    a.timestamps = [_exif_ts("2026:09:14 18:42:07", "-08:00")]
    flags, notes = rule_gps_timezone(a)
    assert flags == [] and notes == []


def test_gps_timezone_implausible_flags():
    a = _gps_analysis(-123.16)
    a.timestamps = [_exif_ts("2026:09:14 18:42:07", "+05:00")]
    flags, notes = rule_gps_timezone(a)
    assert len(flags) == 1
    assert flags[0].rule_id == "gps-timezone-implausible"
    assert flags[0].severity == "medium"
    assert flags[0].confidence == 55
    assert notes == []


def test_gps_timezone_naive_is_note_not_flag():
    a = _gps_analysis(-123.16)
    a.timestamps = [_exif_ts("2026:09:14 18:42:07")]  # naive
    flags, notes = rule_gps_timezone(a)
    assert flags == []
    assert len(notes) == 1
    assert "cannot be assessed" in notes[0]


def test_gps_timezone_no_gps_no_output():
    a = _analysis(timestamps=[_exif_ts("2026:09:14 18:42:07", "-08:00")])
    flags, notes = rule_gps_timezone(a)
    assert flags == [] and notes == []


# ---------------------------------------------------------------------------
# Rule 3: device + serial
# ---------------------------------------------------------------------------


def test_device_mismatch_flags():
    a = _analysis(
        comparison=[
            _compare_fact(
                "device_make",
                "differ",
                [("EXIF", "Canon"), ("XMP tiff:Make/tiff:Model", "NIKON")],
            ),
            _compare_fact(
                "device_model",
                "agree",
                [
                    ("EXIF", "Canon EOS R5"),
                    ("XMP tiff:Make/tiff:Model", "Canon EOS R5"),
                ],
            ),
        ]
    )
    flags = rule_device_mismatch(a)
    assert len(flags) == 1
    assert flags[0].rule_id == "device-identity-mismatch"
    assert flags[0].severity == "medium"
    assert flags[0].confidence == 65


def test_device_agree_no_flag():
    a = _analysis(
        comparison=[
            _compare_fact("device_make", "agree", [("EXIF", "Canon"), ("XMP", "Canon")])
        ]
    )
    assert rule_device_mismatch(a) == []


def test_serial_conflict_flags_high():
    device = DeviceIdentity(body_serial="ABC123")
    xmp = XmpData(
        present=True,
        exif_in_xmp={"http://ns.adobe.com/exif/1.0/aux/#SerialNumber": "XYZ789"},
    )
    flags = rule_serial_conflict(_analysis(device=device, xmp=xmp))
    assert len(flags) == 1
    assert flags[0].rule_id == "serial-number-conflict"
    assert flags[0].severity == "high"
    assert flags[0].confidence == 80


def test_serial_same_or_missing_no_flag():
    device = DeviceIdentity(body_serial="ABC123")
    same = XmpData(
        exif_in_xmp={"http://ns.adobe.com/exif/1.0/aux/#SerialNumber": "ABC123"}
    )
    assert rule_serial_conflict(_analysis(device=device, xmp=same)) == []
    assert rule_serial_conflict(_analysis(device=device, xmp=XmpData())) == []
    assert rule_serial_conflict(_analysis(device=DeviceIdentity(), xmp=same)) == []


# ---------------------------------------------------------------------------
# Rule 4: software chain
# ---------------------------------------------------------------------------


def _device_with_software(exif_sw: str | None, xmp_sw: str | None) -> DeviceIdentity:
    claims = []
    if exif_sw is not None:
        claims.append(DeviceClaim(source="EXIF", software_raw=exif_sw))
    if xmp_sw is not None:
        claims.append(
            DeviceClaim(source="XMP tiff:Make/tiff:Model", software_raw=xmp_sw)
        )
    return DeviceIdentity(claims=claims)


def test_software_different_products_flags():
    a = _analysis(device=_device_with_software("Adobe Photoshop 25.0", "GIMP 2.10"))
    flags = rule_software_chain(a)
    assert len(flags) == 1
    assert flags[0].rule_id == "software-chain-resave"
    assert flags[0].severity == "low"
    assert "Adobe Photoshop" in flags[0].title


def test_software_same_product_versions_agree():
    a = _analysis(
        device=_device_with_software("Adobe Photoshop 25.0", "Adobe Photoshop")
    )
    assert rule_software_chain(a) == []


def test_software_single_source_no_flag():
    a = _analysis(device=_device_with_software("Adobe Photoshop 25.0", None))
    assert rule_software_chain(a) == []


def test_product_name_strips_versions():
    assert _product_name("Adobe Photoshop 25.0") == "Adobe Photoshop"
    assert _product_name("GIMP 2.10") == "GIMP"
    assert _product_name("Adobe Photoshop") == "Adobe Photoshop"


# ---------------------------------------------------------------------------
# Rule 5: thumbnail aspect
# ---------------------------------------------------------------------------


def _thumb_analysis(mw: int, mh: int, tw: int | None, th: int | None) -> Analysis:
    ident = FileIdentity(
        path="x.jpg",
        filename="x.jpg",
        size_bytes=10,
        format="JPEG",
        mime="image/jpeg",
        width=mw,
        height=mh,
    )
    exif = ExifData(
        present=True,
        has_thumbnail_ifd=tw is not None,
        thumbnail_width=tw,
        thumbnail_height=th,
    )
    return _analysis(identity=ident, exif=exif)


def test_thumbnail_aspect_mismatch_flags():
    flags = rule_thumbnail_aspect(_thumb_analysis(6000, 4000, 160, 120))
    assert len(flags) == 1
    assert flags[0].rule_id == "thumbnail-aspect-mismatch"
    assert flags[0].severity == "low"
    assert flags[0].confidence == 45


def test_thumbnail_aspect_match_no_flag():
    assert rule_thumbnail_aspect(_thumb_analysis(6000, 4000, 600, 400)) == []


def test_thumbnail_absent_skips_silently():
    assert rule_thumbnail_aspect(_thumb_analysis(6000, 4000, None, None)) == []


# ---------------------------------------------------------------------------
# Engine guarantees
# ---------------------------------------------------------------------------


def test_detect_anomalies_never_raises_on_empty_analysis():
    flags, notes = detect_anomalies(_analysis())
    assert flags == [] and notes == []


def test_every_flag_ends_with_does_not_prove():
    a = _analysis(
        timestamps=[
            _exif_ts("2026:09:14 18:42:07"),
            _xmp_ts("2026-09-17T18:42:07Z"),
        ],
        comparison=[
            _compare_fact(
                "device_make",
                "differ",
                [("EXIF", "Canon"), ("XMP", "NIKON")],
            )
        ],
        device=_device_with_software("Adobe Photoshop 25.0", "GIMP 2.10"),
        identity=FileIdentity(
            path="x",
            filename="x",
            size_bytes=1,
            format="JPEG",
            mime="image/jpeg",
            width=6000,
            height=4000,
        ),
        exif=ExifData(
            present=True,
            thumbnail_width=160,
            thumbnail_height=120,
            body_serial="AAA",
        ),
        xmp=XmpData(
            exif_in_xmp={"http://ns.adobe.com/exif/1.0/aux/#SerialNumber": "BBB"}
        ),
    )
    a.exif.gps = GeoData(present=True, valid=True, latitude=49.3, longitude=-123.16)
    flags, _notes = detect_anomalies(a)
    assert len(flags) >= 5  # timestamp, device, serial, software, thumbnail
    for flag in flags:
        assert "does NOT prove" in flag.explanation
        assert flag.explanation.rstrip().endswith(flag.does_not_prove)
        assert flag.does_not_prove
        assert 0 <= flag.confidence <= 100
        assert flag.rule_id and flag.sources and flag.values


# ---------------------------------------------------------------------------
# Parser extensions (v0.6 needs)
# ---------------------------------------------------------------------------


def _tiff_with_ifd1() -> bytes:
    """Minimal little-endian TIFF: IFD0 (1 entry) -> IFD1 (width/height)."""
    header = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    # IFD0 at 8: 1 entry (ImageWidth=64), next-IFD at 8+2+12=22 -> IFD1 at 26.
    ifd0 = struct.pack("<H", 1)
    ifd0 += struct.pack("<HHI", 0x0100, 3, 1) + struct.pack("<H", 64) + b"\x00\x00"
    ifd0 += struct.pack("<I", 26)
    # IFD1 at 26: ImageWidth=160 (SHORT), ImageLength=120 (LONG), next=0.
    ifd1 = struct.pack("<H", 2)
    ifd1 += struct.pack("<HHI", 0x0100, 3, 1) + struct.pack("<H", 160) + b"\x00\x00"
    ifd1 += struct.pack("<HHI", 0x0101, 4, 1) + struct.pack("<I", 120)
    ifd1 += struct.pack("<I", 0)
    return header + ifd0 + ifd1


def test_ifd1_dimensions_parsed():
    from metatrace.parsers.exif import _TiffParser

    parser = _TiffParser(_tiff_with_ifd1(), max_tags=64, max_value_bytes=4096)
    raw, _gps, _has_gps, has_thumb, tw, th = parser.parse()
    assert has_thumb is True
    assert (tw, th) == (160, 120)


def test_ifd1_absent_gives_no_dimensions():
    from metatrace.parsers.exif import _TiffParser

    tiff = build_tiff(ifd0=standard_ifd0(), exif=standard_exif())
    parser = _TiffParser(tiff, max_tags=64, max_value_bytes=4096)
    _raw, _gps, _has_gps, has_thumb, tw, th = parser.parse()
    assert has_thumb is False
    assert (tw, th) == (None, None)


def test_aux_serial_captured_in_xmp(tmp_path):
    packet = build_xmp_packet()
    text = (
        packet.decode()
        .replace(
            'xmlns:tiff="http://ns.adobe.com/tiff/1.0/"',
            'xmlns:tiff="http://ns.adobe.com/tiff/1.0/"\n'
            '    xmlns:aux="http://ns.adobe.com/exif/1.0/aux/"',
        )
        .replace(
            'tiff:Make="TestMake">',
            'tiff:Make="TestMake"\n    aux:SerialNumber="SN-001">',
        )
    )
    data = build_jpeg_with_segments(
        [(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + text.encode())]
    )
    path = tmp_path / "aux.jpg"
    path.write_bytes(data)
    from metatrace.parsers import xmp as xmp_mod

    parsed = xmp_mod.extract_xmp(str(path), "JPEG")
    assert (
        parsed.exif_in_xmp["http://ns.adobe.com/exif/1.0/aux/#SerialNumber"] == "SN-001"
    )


# ---------------------------------------------------------------------------
# CLI: analyze
# ---------------------------------------------------------------------------


def _conflict_jpeg(path, dto="2026:09:14 18:42:07", xmp_date="2026-09-15T09:00:00Z"):
    exif = tuple(e for e in standard_exif() if e[0] != 0x9003) + ((0x9003, 2, dto),)
    tiff = build_tiff(ifd0=standard_ifd0(), exif=exif)
    packet = b"http://ns.adobe.com/xap/1.0/\x00" + build_xmp_packet(
        create_date=xmp_date
    )
    data = build_jpeg_with_segments([(0xE1, b"Exif\x00\x00" + tiff), (0xE1, packet)])
    path.write_bytes(data)
    return str(path)


def test_analyze_cli_flags_conflict(tmp_path):
    img = _conflict_jpeg(tmp_path / "c.jpg")
    assert main(["analyze", img]) == 0  # medium/low flags only -> exit 0
    # JSON envelope carries anomalies + notes + tolerance.
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["analyze", img, "--json"])
    assert code == 0
    payload = json.loads(buf.getvalue())
    assert payload["command"] == "analyze"
    data = payload["data"]
    assert data["tolerance_s"] == 60.0
    assert any(f["rule_id"] == "timestamp-conflict" for f in data["anomalies"])
    assert isinstance(data["notes"], list)


def test_analyze_cli_no_flags_wording(tmp_path, capsys):
    img = _conflict_jpeg(
        tmp_path / "ok.jpg",
        dto="2026:09:14 18:42:07",
        xmp_date="2026-09-14T18:42:07Z",
    )
    assert main(["analyze", img]) == 0
    out = capsys.readouterr().out
    assert "no anomalies detected by the v0.6 rule set" in out
    assert "authentic" not in out.lower()


def test_analyze_cli_high_flag_becomes_finding(tmp_path, capsys):
    # 3-day timestamp conflict -> high severity -> core finding -> exit 1.
    img = _conflict_jpeg(
        tmp_path / "bad.jpg",
        dto="2026:09:14 18:42:07",
        xmp_date="2026-09-17T18:42:07Z",
    )
    assert main(["analyze", img]) == 1
    out = capsys.readouterr().out
    assert "[high] anomaly:" in out


def test_analyze_cli_bad_tolerance(tmp_path):
    img = _conflict_jpeg(tmp_path / "c.jpg")
    assert main(["analyze", img, "--tolerance", "-5"]) == 2


def test_analyze_cli_missing_file():
    assert main(["analyze", "/tmp/does-not-exist-mt.jpg"]) == 2


# ---------------------------------------------------------------------------
# Batch integration
# ---------------------------------------------------------------------------


def test_batch_summary_anomaly_counts(tmp_path):
    from metatrace.batch.runner import run_batch
    from metatrace.core import config as config_mod

    _conflict_jpeg(tmp_path / "conflict.jpg")  # flags expected
    _conflict_jpeg(
        tmp_path / "clean.jpg",
        dto="2026:09:14 18:42:07",
        xmp_date="2026-09-14T18:42:07Z",
    )  # no flags
    cfg = config_mod.load_config()
    results = run_batch(
        [str(tmp_path / "conflict.jpg"), str(tmp_path / "clean.jpg")],
        cfg,
        jobs=1,
        progress=None,
    )
    report = build_report(root=str(tmp_path), recursive=False, jobs=1, results=results)
    s = report.summary
    assert s.files_with_anomalies == 1
    assert s.total_anomaly_flags >= 1
    counts = {r.path: r.anomaly_count for r in report.files}
    assert counts[str(tmp_path / "conflict.jpg")] >= 1
    assert counts[str(tmp_path / "clean.jpg")] == 0
    # JSON-serializable.
    json.dumps(report.to_dict())
