"""Tests for GPS IFD decoding and coordinate normalization (v0.2).

All fixtures are synthetic TIFF/GPS structures built byte-by-byte in
conftest — no real photos, no network.
"""

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

from metatrace.cli.main import main
from metatrace.geo import LOCATION_DISCLAIMER, normalize_gps, osm_link
from metatrace.geo.coords import dms_to_decimal
from metatrace.parsers.exif import extract_exif


def write_tmp(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def dms(deg, minutes, sec_num, sec_den=1):
    return ((deg, 1), (minutes, 1), (sec_num, sec_den))


# ---------------------------------------------------------------------------
# dms_to_decimal unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ref,expected",
    [("N", 49.5), ("n", 49.5), ("S", -49.5), ("s", -49.5)],
)
def test_dms_latitude_refs(ref, expected):
    dec, issues = dms_to_decimal(dms(49, 30, 0), ref, "N", "S", "Latitude")
    assert dec == pytest.approx(expected)
    assert issues == []


@pytest.mark.parametrize(
    "ref,expected",
    [("E", 123.25), ("W", -123.25)],
)
def test_dms_longitude_refs(ref, expected):
    dec, issues = dms_to_decimal(dms(123, 15, 0), ref, "E", "W", "Longitude")
    assert dec == pytest.approx(expected)
    assert issues == []


def test_dms_seconds_fraction():
    dec, issues = dms_to_decimal(dms(49, 20, 152, 10), "N", "N", "S", "Latitude")
    assert dec == pytest.approx(49 + 20 / 60 + 15.2 / 3600)
    assert issues == []


def test_dms_missing_ref():
    dec, issues = dms_to_decimal(dms(49, 0, 0), None, "N", "S", "Latitude")
    assert dec is None
    assert any("GPSLatitudeRef" in i for i in issues)


def test_dms_bad_ref():
    dec, issues = dms_to_decimal(dms(49, 0, 0), "X", "N", "S", "Latitude")
    assert dec is None
    assert any("not 'N'/'S'" in i for i in issues)


def test_dms_malformed_value():
    dec, issues = dms_to_decimal("not-dms", "N", "N", "S", "Latitude")
    assert dec is None
    assert any("malformed" in i for i in issues)


def test_dms_zero_denominator():
    dec, issues = dms_to_decimal(((49, 1), (30, 0), (0, 1)), "N", "N", "S", "Latitude")
    assert dec is None
    assert any("malformed" in i for i in issues)


def test_dms_minutes_out_of_range_flagged_not_dropped():
    dec, issues = dms_to_decimal(dms(49, 75, 0), "N", "N", "S", "Latitude")
    assert dec == pytest.approx(49 + 75 / 60)
    assert any("minutes out of range" in i for i in issues)


def test_dms_seconds_out_of_range_flagged():
    dec, issues = dms_to_decimal(dms(49, 20, 90), "N", "N", "S", "Latitude")
    assert dec is not None
    assert any("seconds out of range" in i for i in issues)


# ---------------------------------------------------------------------------
# normalize_gps unit tests (raw-tag level, no TIFF involved)
# ---------------------------------------------------------------------------


def full_gps_raw():
    return {
        0x0001: "N",
        0x0002: dms(49, 20, 152, 10),
        0x0003: "W",
        0x0004: dms(123, 9, 448, 10),
        0x0005: b"\x00",
        0x0006: (42, 1),
        0x0007: ((18, 1), (42, 1), (7, 1)),
        0x000B: (25, 10),
        0x000C: "T",
        0x000D: (90, 1),
        0x001B: b"GPS\x00",
        0x001D: "2026:09:14",
    }


def test_normalize_gps_full():
    geo = normalize_gps(full_gps_raw())
    assert geo.present
    assert geo.valid
    assert geo.latitude == pytest.approx(49.3375556)
    assert geo.longitude == pytest.approx(-123.1624444)
    assert geo.altitude_m == pytest.approx(42.0)
    assert geo.bearing_deg == pytest.approx(90.0)
    assert geo.bearing_ref == "true"
    assert geo.gps_datetime_utc == "2026-09-14T18:42:07Z"
    assert geo.dop == pytest.approx(2.5)
    assert geo.processing_method == "GPS"
    assert geo.validity_issues == []
    # raw tags preserved verbatim in their own namespace
    assert geo.raw_tags[2] == [[49, 1], [20, 1], [152, 10]]
    assert geo.raw_tag_names[2] == "GPSLatitude"


def test_normalize_gps_empty():
    geo = normalize_gps({})
    assert not geo.present
    assert geo.latitude is None


@pytest.mark.parametrize(
    "lat_ref,lon_ref,lat_sign,lon_sign",
    [("N", "E", 1, 1), ("N", "W", 1, -1), ("S", "E", -1, 1), ("S", "W", -1, -1)],
)
def test_normalize_gps_all_hemispheres(lat_ref, lon_ref, lat_sign, lon_sign):
    raw = full_gps_raw()
    raw[0x0001] = lat_ref
    raw[0x0003] = lon_ref
    geo = normalize_gps(raw)
    assert geo.valid
    assert geo.latitude == pytest.approx(lat_sign * 49.3375556)
    assert geo.longitude == pytest.approx(lon_sign * 123.1624444)


def test_normalize_gps_below_sea_level():
    raw = full_gps_raw()
    raw[0x0005] = b"\x01"
    raw[0x0006] = (430, 10)
    geo = normalize_gps(raw)
    assert geo.valid
    assert geo.altitude_m == pytest.approx(-43.0)


def test_normalize_gps_altitude_ref_invalid():
    raw = full_gps_raw()
    raw[0x0005] = b"\x02"
    geo = normalize_gps(raw)
    assert not geo.valid
    assert geo.altitude_m == pytest.approx(42.0)  # kept positive, flagged
    assert any("GPSAltitudeRef" in i for i in geo.validity_issues)


def test_normalize_gps_latitude_out_of_range():
    raw = full_gps_raw()
    raw[0x0002] = dms(95, 0, 0)
    geo = normalize_gps(raw)
    assert not geo.valid
    assert geo.latitude is None  # rejected value not used
    assert geo.longitude == pytest.approx(-123.1624444)  # good value kept
    assert any("latitude 95.0 out of range" in i for i in geo.validity_issues)


def test_normalize_gps_longitude_out_of_range():
    raw = full_gps_raw()
    raw[0x0004] = dms(200, 0, 0)
    raw[0x0003] = "E"
    geo = normalize_gps(raw)
    assert not geo.valid
    assert geo.longitude is None
    assert any("longitude 200.0 out of range" in i for i in geo.validity_issues)


def test_normalize_gps_altitude_out_of_bounds():
    raw = full_gps_raw()
    raw[0x0006] = (99999, 1)
    geo = normalize_gps(raw)
    assert not geo.valid
    assert geo.altitude_m is None
    assert any("sane bounds" in i for i in geo.validity_issues)


def test_normalize_gps_bearing_magnetic():
    raw = full_gps_raw()
    raw[0x000C] = "M"
    raw[0x000D] = (270, 1)
    geo = normalize_gps(raw)
    assert geo.bearing_deg == pytest.approx(270.0)
    assert geo.bearing_ref == "magnetic"


def test_normalize_gps_bearing_wraps():
    raw = full_gps_raw()
    raw[0x000D] = (370, 1)
    geo = normalize_gps(raw)
    assert geo.bearing_deg == pytest.approx(10.0)


def test_normalize_gps_bearing_bad_ref():
    raw = full_gps_raw()
    raw[0x000C] = "Q"
    geo = normalize_gps(raw)
    assert geo.bearing_deg == pytest.approx(90.0)
    assert geo.bearing_ref is None
    assert any("GPSImgDirectionRef" in w for w in geo.warnings)


def test_normalize_gps_partial_timestamp_date_only():
    raw = full_gps_raw()
    raw[0x0007] = None
    geo = normalize_gps(raw)
    assert geo.gps_datetime_utc is None
    assert any("partial GPS timestamp" in w for w in geo.warnings)


def test_normalize_gps_partial_timestamp_time_only():
    raw = full_gps_raw()
    raw[0x001D] = None
    geo = normalize_gps(raw)
    assert geo.gps_datetime_utc is None
    assert any("partial GPS timestamp" in w for w in geo.warnings)


def test_normalize_gps_malformed_date():
    raw = full_gps_raw()
    raw[0x001D] = "yesterday"
    geo = normalize_gps(raw)
    assert geo.gps_datetime_utc is None
    assert any("GPSDateStamp malformed" in i for i in geo.validity_issues)


def test_normalize_gps_bad_time():
    raw = full_gps_raw()
    raw[0x0007] = ((99, 1), (0, 1), (0, 1))
    geo = normalize_gps(raw)
    assert geo.gps_datetime_utc is None
    assert any("GPSTimeStamp out of range" in i for i in geo.validity_issues)


def test_normalize_gps_empty_ifd():
    geo = normalize_gps({0x0000: b"\x02\x03\x00\x00"})
    assert geo.present
    assert any("no usable GPS values" in w for w in geo.warnings)


def test_normalize_gps_missing_refs():
    geo = normalize_gps({0x0002: dms(49, 0, 0), 0x0004: dms(123, 0, 0)})
    assert not geo.valid
    assert geo.latitude is None and geo.longitude is None
    assert len(geo.validity_issues) == 2


def test_normalize_gps_timestamp_not_tuple():
    raw = full_gps_raw()
    raw[0x0007] = "18:42:07"
    geo = normalize_gps(raw)
    assert geo.gps_datetime_utc is None
    assert any("GPSTimeStamp malformed" in i for i in geo.validity_issues)


def test_normalize_gps_timestamp_bad_component():
    raw = full_gps_raw()
    raw[0x0007] = ((18, 1), "xx", (7, 1))
    geo = normalize_gps(raw)
    assert geo.gps_datetime_utc is None
    assert any("GPSTimeStamp malformed" in i for i in geo.validity_issues)


def test_normalize_gps_date_out_of_range():
    raw = full_gps_raw()
    raw[0x001D] = "2026:13:40"
    geo = normalize_gps(raw)
    assert geo.gps_datetime_utc is None
    assert any("GPSDateStamp out of range" in i for i in geo.validity_issues)


def test_normalize_gps_negative_degrees():
    raw = full_gps_raw()
    raw[0x0002] = ((-49, 1), (20, 1), (0, 1))
    geo = normalize_gps(raw)
    assert geo.latitude == pytest.approx(49 + 20 / 60)
    assert any("degrees negative" in i for i in geo.validity_issues)


def test_normalize_gps_bearing_without_ref():
    raw = full_gps_raw()
    del raw[0x000C]
    geo = normalize_gps(raw)
    assert geo.bearing_deg == pytest.approx(90.0)
    assert geo.bearing_ref is None
    assert geo.valid  # no warning for simply-absent ref


def test_normalize_gps_altitude_ref_as_single_int():
    raw = full_gps_raw()
    raw[0x0005] = 1
    raw[0x0006] = (430, 10)
    geo = normalize_gps(raw)
    assert geo.altitude_m == pytest.approx(-43.0)


def test_normalize_gps_unknown_tag_kept_raw():
    raw = full_gps_raw()
    raw[0x9999] = "vendor blob"
    geo = normalize_gps(raw)
    assert geo.raw_tags[0x9999] == "vendor blob"
    assert 0x9999 not in geo.raw_tag_names
    assert geo.valid


def test_normalize_gps_list_values_json_safe():
    raw = full_gps_raw()
    raw[0x0002] = [[49, 1], [20, 1], [152, 10]]
    geo = normalize_gps(raw)
    assert geo.latitude == pytest.approx(49.3375556)
    assert geo.raw_tags[2] == [[49, 1], [20, 1], [152, 10]]


def test_osm_link():
    url = osm_link(49.337556, -123.162444)
    assert url == (
        "https://www.openstreetmap.org/?mlat=49.337556&mlon=-123.162444"
        "#map=15/49.337556/-123.162444"
    )


# ---------------------------------------------------------------------------
# End-to-end: synthetic TIFF/JPEG -> extract_exif -> GeoData
# ---------------------------------------------------------------------------


def test_extract_exif_gps_little_endian(tmp_path):
    tiff = build_tiff(
        endian="<", ifd0=standard_ifd0(), exif=standard_exif(), gps=standard_gps()
    )
    path = write_tmp(tmp_path, "gps.jpg", build_jpeg_with_exif(tiff))
    exif = extract_exif(path, "JPEG")
    assert exif.present
    assert exif.has_gps_ifd
    assert exif.gps.present and exif.gps.valid
    assert exif.gps.latitude == pytest.approx(49.3375556)
    assert exif.gps.longitude == pytest.approx(-123.1624444)
    assert exif.gps.altitude_m == pytest.approx(42.0)
    assert exif.gps.gps_datetime_utc == "2026-09-14T18:42:07Z"


def test_extract_exif_gps_big_endian(tmp_path):
    tiff = build_tiff(
        endian=">", ifd0=standard_ifd0(), exif=standard_exif(), gps=standard_gps()
    )
    path = write_tmp(tmp_path, "gps-be.jpg", build_jpeg_with_exif(tiff))
    exif = extract_exif(path, "JPEG")
    assert exif.gps.present and exif.gps.valid
    assert exif.gps.latitude == pytest.approx(49.3375556)
    assert exif.gps.longitude == pytest.approx(-123.1624444)
    assert exif.gps.bearing_ref == "true"


def test_extract_exif_no_gps(tmp_path, jpeg_with_exif):
    exif = extract_exif(str(jpeg_with_exif), "JPEG")
    assert exif.present
    assert not exif.has_gps_ifd
    assert not exif.gps.present
    assert exif.gps.latitude is None


def test_extract_exif_gps_pointer_out_of_bounds(tmp_path):
    tiff = build_tiff(endian="<", ifd0=((0x8825, 4, 999999),))
    path = write_tmp(tmp_path, "bad.jpg", build_jpeg_with_exif(tiff))
    exif = extract_exif(path, "JPEG")
    assert exif.has_gps_ifd  # pointer exists...
    assert not exif.gps.present  # ...but nothing decodable
    assert any("GPS IFD offset" in w for w in exif.warnings)


def test_extract_exif_invalid_gps_survives(tmp_path):
    bad_gps = (
        (0x0001, 2, "N"),
        (0x0002, 5, ((95, 1), (0, 1), (0, 1))),
        (0x0003, 2, "E"),
        (0x0004, 5, ((10, 1), (0, 1), (0, 1))),
    )
    tiff = build_tiff(endian="<", ifd0=standard_ifd0(), gps=bad_gps)
    path = write_tmp(tmp_path, "badgps.jpg", build_jpeg_with_exif(tiff))
    exif = extract_exif(path, "JPEG")
    assert exif.gps.present
    assert not exif.gps.valid
    assert exif.gps.latitude is None
    assert exif.gps.longitude == pytest.approx(10.0)


def test_extract_exif_standalone_tiff_with_gps(tmp_path):
    tiff = build_tiff(endian="<", ifd0=standard_ifd0(), gps=standard_gps())
    path = write_tmp(tmp_path, "gps.tiff", tiff)
    exif = extract_exif(path, "TIFF")
    assert exif.gps.present and exif.gps.valid
    assert exif.gps.altitude_m == pytest.approx(42.0)


# ---------------------------------------------------------------------------
# CLI rendering
# ---------------------------------------------------------------------------


def test_cli_gps_section_human(tmp_path, capsys, jpeg_with_gps):
    code = main(["inspect", str(jpeg_with_gps)])
    assert code == 0
    out = capsys.readouterr().out
    assert "GPS:" in out
    assert "coordinates  49.337556, -123.162444" in out
    assert "altitude     42.0 m" in out
    assert "bearing      90.0° (true north)" in out
    assert "gps_time     2026-09-14T18:42:07Z" in out
    assert "map          https" not in out  # only with --map-link
    # forensic discipline: metadata indicates, never proves
    assert LOCATION_DISCLAIMER in out


def test_cli_gps_absent(tmp_path, capsys, jpeg_with_exif):
    code = main(["inspect", str(jpeg_with_exif)])
    assert code == 0
    out = capsys.readouterr().out
    assert "GPS:          not present" in out


def test_cli_map_link(tmp_path, capsys, jpeg_with_gps):
    code = main(["inspect", str(jpeg_with_gps), "--map-link"])
    assert code == 0
    out = capsys.readouterr().out
    assert (
        "map          https://www.openstreetmap.org/?mlat=49.337556"
        "&mlon=-123.162444#map=15/49.337556/-123.162444" in out
    )


def test_cli_map_link_no_gps(tmp_path, capsys, jpeg_with_exif):
    code = main(["inspect", str(jpeg_with_exif), "--map-link"])
    assert code == 0
    assert "openstreetmap" not in capsys.readouterr().out


def test_cli_invalid_gps_becomes_finding(tmp_path, capsys):
    bad_gps = (
        (0x0001, 2, "N"),
        (0x0002, 5, ((95, 1), (0, 1), (0, 1))),
        (0x0003, 2, "E"),
        (0x0004, 5, ((10, 1), (0, 1), (0, 1))),
    )
    tiff = build_tiff(endian="<", ifd0=standard_ifd0(), gps=bad_gps)
    path = write_tmp(tmp_path, "badgps.jpg", build_jpeg_with_exif(tiff))
    code = main(["inspect", path])
    assert code == 1  # findings present
    out = capsys.readouterr().out
    assert "GPS metadata validity issue" in out
    assert "latitude 95.0 out of range" in out
    assert "coordinates  not decodable" in out


def test_cli_gps_json(tmp_path, capsys, jpeg_with_gps):
    code = main(["inspect", str(jpeg_with_gps), "--json"])
    assert code == 0
    env = json.loads(capsys.readouterr().out)
    gps = env["data"]["analysis"]["exif"]["gps"]
    assert gps["present"] is True
    assert gps["valid"] is True
    assert gps["latitude"] == pytest.approx(49.3375556)
    assert gps["longitude"] == pytest.approx(-123.1624444)
    assert gps["altitude_m"] == pytest.approx(42.0)
    assert gps["gps_datetime_utc"] == "2026-09-14T18:42:07Z"
    assert gps["raw_tags"]["2"] == [[49, 1], [20, 1], [152, 10]]
    assert gps["raw_tag_names"]["2"] == "GPSLatitude"
    assert gps["validity_issues"] == []


def test_cli_gps_exif_datetime_kept_separate(tmp_path, capsys, jpeg_with_gps):
    """EXIF DateTimeOriginal is kept as-is; GPS time recorded alongside."""
    code = main(["inspect", str(jpeg_with_gps), "--json"])
    assert code == 0
    env = json.loads(capsys.readouterr().out)
    exif = env["data"]["analysis"]["exif"]
    assert exif["datetime_original"] == "2026-09-15T14:22:01"
    assert exif["gps"]["gps_datetime_utc"] == "2026-09-14T18:42:07Z"
