"""Tests for v0.4: timestamp/device normalization, comparison, timelines."""

from __future__ import annotations

import json

from conftest import (
    build_icc_app2,
    build_icc_profile,
    build_iptc_8bim,
    build_iptc_dataset,
    build_jpeg_with_segments,
    build_tiff,
    build_xmp_packet,
)

from metatrace.cli.main import analyze_image
from metatrace.core.config import load_config
from metatrace.core.models import Analysis
from metatrace.normalize import (
    build_timeline,
    compare_sources,
    normalize_device,
)
from metatrace.normalize.devices import (
    normalize_make,
    normalize_model,
    normalize_software,
)
from metatrace.normalize.timestamps import (
    normalize_exif_timestamp,
    normalize_filesystem_timestamp,
    normalize_gps_timestamp,
    normalize_icc_timestamp,
    normalize_iptc_timestamp,
    normalize_xmp_timestamp,
)


def _cfg():
    return load_config()


def _conflict_jpeg_bytes() -> bytes:
    """EXIF naive 2026-09-15, XMP UTC 2026-09-14, IPTC 20260914+0000.

    Device variants on purpose: EXIF "canon"/"canon eos r5" vs XMP
    "Canon "/"EOS R5".
    """
    tiff = build_tiff(
        endian="<",
        ifd0=(
            (0x010F, 2, "canon"),
            (0x0110, 2, "canon eos r5"),
            (0x0131, 2, "TestSoft 1.0"),
        ),
        exif=(
            (0x9003, 2, "2026:09:15 14:22:01"),
            (0xA431, 2, "SN-12345"),
        ),
    )
    xmp = build_xmp_packet(
        create_date="2026-09-14T18:42:07Z",
        tiff_make="Canon ",
        tiff_model="EOS R5",
    )
    iptc = build_iptc_8bim(
        [
            build_iptc_dataset(2, 55, b"20260914"),
            build_iptc_dataset(2, 60, b"184207+0000"),
        ]
    )
    icc = build_icc_profile()
    segs = [
        (0xE1, b"Exif\x00\x00" + tiff),
        (0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp),
        (0xED, iptc),
    ] + build_icc_app2(icc)
    return build_jpeg_with_segments(segs)


def _analyzed_conflict(tmp_path):
    p = tmp_path / "conflict.jpg"
    p.write_bytes(_conflict_jpeg_bytes())
    analysis, findings = analyze_image(str(p), _cfg())
    return analysis, findings


# ---------------------------------------------------------------------------
# EXIF timestamps
# ---------------------------------------------------------------------------


def test_exif_naive():
    ts = normalize_exif_timestamp(
        "2026:09:15 14:22:01", None, label="capture", source="EXIF DateTimeOriginal"
    )
    assert ts is not None
    assert ts.parseable
    assert ts.timezone_status == "naive"
    assert ts.value_utc is None
    assert ts.wall == "2026-09-15T14:22:01"
    assert ts.precision == "second"


def test_exif_explicit_offset_converts_to_utc():
    ts = normalize_exif_timestamp(
        "2026:09:15 14:22:01",
        "+02:00",
        label="capture",
        source="EXIF DateTimeOriginal",
    )
    assert ts is not None and ts.parseable
    assert ts.timezone_status == "explicit"
    assert ts.value_utc == "2026-09-15T12:22:01Z"


def test_exif_garbage_offset_falls_back_to_naive():
    ts = normalize_exif_timestamp(
        "2026:09:15 14:22:01", "bogus", label="capture", source="EXIF DateTimeOriginal"
    )
    assert ts is not None and ts.parseable
    assert ts.timezone_status == "naive"
    assert "bogus" in (ts.raw or "")


def test_exif_unparseable_kept_verbatim():
    ts = normalize_exif_timestamp(
        "not a date", None, label="capture", source="EXIF DateTimeOriginal"
    )
    assert ts is not None
    assert not ts.parseable
    assert ts.raw == "not a date"


def test_exif_absent_returns_none():
    assert normalize_exif_timestamp(None, None, label="capture", source="X") is None


# ---------------------------------------------------------------------------
# XMP timestamps
# ---------------------------------------------------------------------------


def test_xmp_zulu():
    ts = normalize_xmp_timestamp(
        "2026-09-14T18:42:07Z", label="capture", source="XMP xmp:CreateDate"
    )
    assert ts is not None and ts.parseable
    assert ts.timezone_status == "explicit"
    assert ts.value_utc == "2026-09-14T18:42:07Z"


def test_xmp_numeric_offset_converts_to_utc():
    ts = normalize_xmp_timestamp(
        "2026-09-14T18:42:07+02:00", label="capture", source="XMP xmp:CreateDate"
    )
    assert ts is not None and ts.parseable
    assert ts.value_utc == "2026-09-14T16:42:07Z"


def test_xmp_naive():
    ts = normalize_xmp_timestamp(
        "2026-09-14T18:42:07", label="capture", source="XMP xmp:CreateDate"
    )
    assert ts is not None and ts.parseable
    assert ts.timezone_status == "naive"
    assert ts.value_utc is None


def test_xmp_date_only_is_day_precision():
    ts = normalize_xmp_timestamp("2026-09-14", label="capture", source="XMP")
    assert ts is not None and ts.parseable
    assert ts.precision == "day"
    assert ts.timezone_status == "naive"


def test_xmp_minute_precision():
    ts = normalize_xmp_timestamp("2026-09-14T18:42", label="capture", source="XMP")
    assert ts is not None and ts.parseable
    assert ts.precision == "minute"


def test_xmp_garbage():
    ts = normalize_xmp_timestamp("yesterday-ish", label="capture", source="XMP")
    assert ts is not None and not ts.parseable


# ---------------------------------------------------------------------------
# IPTC / GPS / ICC / filesystem
# ---------------------------------------------------------------------------


def test_iptc_date_time_with_zone():
    ts = normalize_iptc_timestamp("20260914", "184207+0000", source="IPTC")
    assert ts is not None and ts.parseable
    assert ts.timezone_status == "explicit"
    assert ts.value_utc == "2026-09-14T18:42:07Z"


def test_iptc_date_only_is_day_naive():
    ts = normalize_iptc_timestamp("20260914", None, source="IPTC")
    assert ts is not None and ts.parseable
    assert ts.precision == "day"
    assert ts.timezone_status == "naive"
    assert ts.wall == "2026-09-14"


def test_iptc_time_without_date_unparseable():
    ts = normalize_iptc_timestamp(None, "184207+0000", source="IPTC")
    assert ts is not None and not ts.parseable


def test_iptc_garbage_date():
    ts = normalize_iptc_timestamp("99999999", None, source="IPTC")
    assert ts is not None and not ts.parseable


def test_gps_is_utc():
    ts = normalize_gps_timestamp("2026-09-14T18:42:07Z")
    assert ts is not None and ts.parseable
    assert ts.timezone_status == "utc"
    assert ts.value_utc == "2026-09-14T18:42:07Z"


def test_icc_is_utc():
    ts = normalize_icc_timestamp("2026-09-14T18:42:07")
    assert ts is not None and ts.parseable
    assert ts.timezone_status == "utc"
    assert ts.value_utc == "2026-09-14T18:42:07Z"


def test_filesystem_labeled_not_image():
    ts = normalize_filesystem_timestamp(1726000000.0)
    assert ts.timezone_status == "utc"
    assert ts.label == "filesystem"
    assert "not image metadata" in ts.source
    assert ts.value_utc == "2024-09-10T20:26:40Z"


# ---------------------------------------------------------------------------
# Device normalization
# ---------------------------------------------------------------------------


def test_make_variants_normalize_equal():
    norms = {normalize_make(v)[0] for v in ("canon", "Canon ", "CANON INC.")}
    keys = {normalize_make(v)[1] for v in ("canon", "Canon ", "CANON INC.")}
    assert norms == {"Canon"}
    assert keys == {"canon"}


def test_unknown_make_kept_verbatim():
    norm, key = normalize_make("TestMake")
    assert norm == "TestMake"
    assert key == "testmake"


def test_model_variants_share_key():
    _, k1 = normalize_model("canon eos r5", "Canon", "canon")
    _, k2 = normalize_model("Canon EOS R5", "Canon", "canon")
    assert k1 == k2 == "canoneosr5"


def test_model_key_includes_canonical_make():
    # "EOS R5" with make "Canon" canonicalizes to "Canon EOS R5",
    # so it agrees with an EXIF model that already names the maker.
    _, k1 = normalize_model("EOS R5", "Canon", "canon")
    _, k2 = normalize_model("canon eos r5", "Canon", "canon")
    assert k1 == k2


def test_model_gets_canonical_make_prefix():
    norm, _ = normalize_model("EOS R5", "Canon", "canon")
    assert norm == "Canon EOS R5"


def test_software_key_insensitive():
    _, k1 = normalize_software("TestSoft 1.0")
    _, k2 = normalize_software("testsoft  1.0")
    assert k1 == k2


def test_device_claims_and_verbatim_serials(tmp_path):
    analysis, _ = _analyzed_conflict(tmp_path)
    device = normalize_device(analysis)
    assert len(device.claims) == 2
    exif_claim = device.claims[0]
    assert exif_claim.source == "EXIF"
    assert exif_claim.make_norm == "Canon"
    xmp_claim = device.claims[1]
    assert xmp_claim.make_key == exif_claim.make_key == "canon"
    # Serials are identifiers: verbatim, never normalized.
    assert device.body_serial == "SN-12345"


# ---------------------------------------------------------------------------
# Cross-source comparison (descriptive only)
# ---------------------------------------------------------------------------


def test_conflicting_capture_times_differ(tmp_path):
    analysis, _ = _analyzed_conflict(tmp_path)
    facts = {f.fact: f for f in analysis.comparison}
    fact = facts["capture_time"]
    assert fact.status == "differ"
    assert len(fact.values) == 3
    # No verdicts, no scores anywhere in the comparison.
    assert "not a verdict" in fact.note
    for value in fact.values:
        assert "fake" not in value.normalized.lower()


def test_agreeing_naive_capture_times_agree(tmp_path):
    tiff = build_tiff(
        endian="<",
        ifd0=((0x010F, 2, "TestMake"),),
        exif=((0x9003, 2, "2026:09:14 18:42:07"),),
    )
    xmp = build_xmp_packet(create_date="2026-09-14T18:42:07")
    data = build_jpeg_with_segments(
        [
            (0xE1, b"Exif\x00\x00" + tiff),
            (0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp),
        ]
    )
    p = tmp_path / "agree.jpg"
    p.write_bytes(data)
    analysis, _ = analyze_image(str(p), _cfg())
    facts = {f.fact: f for f in analysis.comparison}
    assert facts["capture_time"].status == "agree"


def test_single_source_capture_time(tmp_path):
    tiff = build_tiff(
        endian="<",
        ifd0=((0x010F, 2, "TestMake"),),
        exif=((0x9003, 2, "2026:09:14 18:42:07"),),
    )
    data = build_jpeg_with_segments([(0xE1, b"Exif\x00\x00" + tiff)])
    p = tmp_path / "single.jpg"
    p.write_bytes(data)
    analysis, _ = analyze_image(str(p), _cfg())
    facts = {f.fact: f for f in analysis.comparison}
    assert facts["capture_time"].status == "only-in-one-source"


def test_no_timestamps_no_data():
    analysis = Analysis(evidence_id="MT-test")
    facts = {f.fact: f for f in compare_sources([], normalize_device(analysis))}
    assert facts["capture_time"].status == "no-data"


def test_device_make_agrees_across_variant_spellings(tmp_path):
    analysis, _ = _analyzed_conflict(tmp_path)
    facts = {f.fact: f for f in analysis.comparison}
    assert facts["device_make"].status == "agree"


def test_software_chain_differs_on_version(tmp_path):
    analysis, _ = _analyzed_conflict(tmp_path)
    facts = {f.fact: f for f in analysis.comparison}
    # EXIF "TestSoft 1.0" vs XMP "TestSoft 2.0": recorded as differ,
    # never auto-resolved, never judged.
    assert facts["software"].status == "differ"


def test_comparison_never_auto_resolves(tmp_path):
    """Conflicts stay visible: raw values of every source are present."""
    analysis, _ = _analyzed_conflict(tmp_path)
    facts = {f.fact: f for f in analysis.comparison}
    raws = [v.raw for v in facts["capture_time"].values]
    assert "2026:09:15 14:22:01" in raws
    assert "2026-09-14T18:42:07Z" in raws


# ---------------------------------------------------------------------------
# Timelines
# ---------------------------------------------------------------------------


def test_timeline_orders_utc_before_naive(tmp_path):
    analysis, _ = _analyzed_conflict(tmp_path)
    timeline = analysis.timeline
    kinds = ["utc" if t.value_utc else ("naive" if t.wall else "bad") for t in timeline]
    # All UTC-known claims come before all naive ones.
    first_naive = kinds.index("naive")
    assert all(k == "utc" for k in kinds[:first_naive])
    assert all(k == "naive" for k in kinds[first_naive:])
    # UTC claims are chronological.
    utc_vals = [t.value_utc for t in timeline if t.value_utc]
    assert utc_vals == sorted(utc_vals)


def test_timeline_unparseable_sorts_last():
    ts_ok = normalize_xmp_timestamp("2026-09-14T18:42:07Z", label="c", source="X")
    ts_bad = normalize_xmp_timestamp("garbage", label="c", source="X")
    ts_naive = normalize_exif_timestamp(
        "2026:09:15 14:22:01", None, label="c", source="Y"
    )
    assert ts_ok is not None and ts_bad is not None and ts_naive is not None
    ordered = build_timeline([ts_bad, ts_naive, ts_ok])
    assert ordered[0] is ts_ok
    assert ordered[1] is ts_naive
    assert ordered[2] is ts_bad


def test_filesystem_mtime_in_timeline_labeled(tmp_path):
    analysis, _ = _analyzed_conflict(tmp_path)
    fs = [t for t in analysis.timeline if t.label == "filesystem"]
    assert len(fs) == 1
    assert "not image metadata" in fs[0].source


# ---------------------------------------------------------------------------
# Findings: unparseable timestamps
# ---------------------------------------------------------------------------


def test_unparseable_xmp_date_is_low_finding(tmp_path):
    tiff = build_tiff(
        endian="<",
        ifd0=((0x010F, 2, "TestMake"),),
        exif=((0x9003, 2, "2026:09:14 18:42:07"),),
    )
    xmp = build_xmp_packet(create_date="not-a-date")
    data = build_jpeg_with_segments(
        [
            (0xE1, b"Exif\x00\x00" + tiff),
            (0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp),
        ]
    )
    p = tmp_path / "baddate.jpg"
    p.write_bytes(data)
    _, findings = analyze_image(str(p), _cfg())
    ts_findings = [f for f in findings if f.title == "unparseable timestamp"]
    assert len(ts_findings) == 1
    assert ts_findings[0].severity == "low"
    assert "not-a-date" in ts_findings[0].reason


def test_unparseable_iptc_date_is_low_finding(tmp_path):
    tiff = build_tiff(
        endian="<",
        ifd0=((0x010F, 2, "TestMake"),),
        exif=((0x9003, 2, "2026:09:14 18:42:07"),),
    )
    iptc = build_iptc_8bim([build_iptc_dataset(2, 55, b"nodate")])
    data = build_jpeg_with_segments([(0xE1, b"Exif\x00\x00" + tiff), (0xED, iptc)])
    p = tmp_path / "badiptc.jpg"
    p.write_bytes(data)
    _, findings = analyze_image(str(p), _cfg())
    ts_findings = [f for f in findings if f.title == "unparseable timestamp"]
    assert len(ts_findings) == 1
    assert ts_findings[0].severity == "low"


# ---------------------------------------------------------------------------
# EXIF serial extraction
# ---------------------------------------------------------------------------


def test_exif_serial_tags_extracted(tmp_path):
    analysis, _ = _analyzed_conflict(tmp_path)
    assert analysis.exif.body_serial == "SN-12345"
    assert analysis.device is not None
    assert analysis.device.body_serial == "SN-12345"


# ---------------------------------------------------------------------------
# CLI: inspect --json envelope + timeline command
# ---------------------------------------------------------------------------


def test_inspect_json_envelope_keys(tmp_path, capsys):
    from metatrace.cli.main import main

    p = tmp_path / "conflict.jpg"
    p.write_bytes(_conflict_jpeg_bytes())
    main(["inspect", str(p), "--json"])
    payload = json.loads(capsys.readouterr().out)
    analysis = payload["data"]["analysis"]
    assert analysis["timestamps"], "timestamps missing from envelope"
    assert analysis["device"] is not None
    assert len(analysis["comparison"]) == 4
    assert analysis["timeline"], "timeline missing from envelope"
    assert analysis["timestamps"][0]["timezone_status"] in (
        "explicit",
        "naive",
        "utc",
    )


def test_timeline_command_human(tmp_path, capsys):
    from metatrace.cli.main import main

    p = tmp_path / "conflict.jpg"
    p.write_bytes(_conflict_jpeg_bytes())
    code = main(["timeline", str(p)])
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "timeline for conflict.jpg" in out
    assert "EXIF DateTimeOriginal" in out
    assert "filesystem mtime (not image metadata)" in out


def test_timeline_command_json(tmp_path, capsys):
    from metatrace.cli.main import main

    p = tmp_path / "conflict.jpg"
    p.write_bytes(_conflict_jpeg_bytes())
    code = main(["timeline", str(p), "--json"])
    assert code in (0, 1)
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "timeline"
    assert payload["data"]["timeline"]
    assert payload["data"]["evidence_id"].startswith("MT-")


def test_timeline_missing_file_is_error(capsys):
    from metatrace.cli.main import main

    assert main(["timeline", "/nonexistent/photo.jpg"]) == 2


def test_collect_timestamps_source_grouped_order(tmp_path):
    analysis, _ = _analyzed_conflict(tmp_path)
    sources = [t.source for t in analysis.timestamps]
    assert sources[0] == "EXIF DateTimeOriginal"
    assert "XMP xmp:CreateDate" in sources
    assert "IPTC DateCreated/TimeCreated" in sources
    assert "GPS GPSDateStamp/GPSTimeStamp" not in sources  # no GPS in fixture
    assert sources[-1] == "filesystem mtime (not image metadata)"


def test_normalize_plugin_registered():
    from metatrace.core.plugins import get_registry

    assert "normalize" in get_registry().names()
