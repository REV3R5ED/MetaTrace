"""GPS IFD decoding and coordinate normalization (v0.2).

Takes the raw decoded GPS IFD tags (as produced by the TIFF parser)
and produces a :class:`GeoData` model with:

- decimal-degree latitude/longitude (DMS rationals + N/S/E/W refs)
- signed altitude in meters (above/below sea level via GPSAltitudeRef)
- bearing in degrees (GPSImgDirection, true or magnetic)
- UTC ISO-8601 timestamp from GPSDateStamp + GPSTimeStamp
- validity checks with explained issues — never silent drops

Every value is defensive: malformed rationals, out-of-range components,
and missing refs produce recorded issues, never exceptions.
"""

from __future__ import annotations

import re
from typing import Any

from metatrace.core.models import GeoData

# Forensic discipline, stated once and reused in CLI output and docs:
# metadata describes the file; it does not prove real-world facts.
LOCATION_DISCLAIMER = (
    "GPS coordinates record the location stored in the file's metadata; "
    "they do not prove where the photograph was taken."
)

# GPS IFD tag ids -> human names.
GPS_TAG_NAMES: dict[int, str] = {
    0x0000: "GPSVersionID",
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x000B: "GPSDOP",
    0x000C: "GPSImgDirectionRef",
    0x000D: "GPSImgDirection",
    0x001B: "GPSProcessingMethod",
    0x001D: "GPSDateStamp",
}

_GPS_DATE_RE = re.compile(r"^(\d{4}):(\d{2}):(\d{2})$")

# Bounds for sanity checks. Altitude range is deliberately generous:
# the Dead Sea shore (-430 m) and airliners (~12 km) are both real.
_LAT_RANGE = (-90.0, 90.0)
_LON_RANGE = (-180.0, 180.0)
_ALT_RANGE = (-1000.0, 12000.0)


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def _rational_to_float(value: Any) -> float | None:
    """(num, den) -> float. None when unusable (never raises)."""
    if (
        not isinstance(value, (tuple, list))
        or len(value) != 2
        or not all(isinstance(v, int) and not isinstance(v, bool) for v in value)
    ):
        return None
    num, den = int(value[0]), int(value[1])
    if den == 0:
        return None
    return num / den


def _as_str(value: Any) -> str | None:
    if isinstance(value, bytes):
        try:
            text = value.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        except Exception:  # pragma: no cover - decode(errors=replace) is safe
            return None
        text = text.strip()
        return text or None
    if isinstance(value, str):
        text = value.strip().strip("\x00").strip()
        return text or None
    return None


def _byte_to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)) and len(value) == 1:
        return value[0]
    if isinstance(value, (tuple, list)) and len(value) == 1:
        return _byte_to_int(value[0])
    return None


def dms_to_decimal(
    dms: Any, ref: str | None, positive: str, negative: str, label: str
) -> tuple[float | None, list[str]]:
    """Convert DMS rationals + hemisphere ref to signed decimal degrees.

    Returns (decimal_or_None, issues). ``dms`` is expected to be three
    rationals (deg, min, sec); anything else yields an issue, not an
    exception. Minutes/seconds >= 60 are flagged but still computed —
    recorded, never silently dropped.
    """
    issues: list[str] = []
    if ref is None:
        issues.append(
            f"GPS{label}Ref missing or invalid; {label.lower()}itude not normalized"
        )
        return None, issues
    ref = ref.strip().upper()
    if ref == positive:
        sign = 1.0
    elif ref == negative:
        sign = -1.0
    else:
        issues.append(
            f"GPS{label}Ref {ref!r} not {positive!r}/{negative!r}; "
            f"{label.lower()}itude not normalized"
        )
        return None, issues

    parts: list[float] | None = None
    if isinstance(dms, (tuple, list)) and len(dms) == 3:
        converted: list[float] = []
        for component in dms:
            component_f = _rational_to_float(component)
            if component_f is None:
                break
            converted.append(component_f)
        if len(converted) == 3:
            parts = converted
    if parts is None:
        issues.append(
            f"GPS{label} DMS value malformed; {label.lower()}itude not normalized"
        )
        return None, issues

    deg, minutes, seconds = parts
    if deg < 0:
        issues.append(f"GPS{label} degrees negative ({deg}); using absolute value")
        deg = abs(deg)
    if not 0 <= minutes < 60:
        issues.append(f"GPS{label} minutes out of range [0, 60): {minutes}")
    if not 0 <= seconds < 60:
        issues.append(f"GPS{label} seconds out of range [0, 60): {seconds}")
    return sign * (deg + minutes / 60.0 + seconds / 3600.0), issues


def _normalize_gps_datetime(
    date_raw: Any, time_raw: Any
) -> tuple[str | None, list[str], list[str]]:
    """GPSDateStamp + GPSTimeStamp -> 'YYYY-MM-DDTHH:MM:SSZ'.

    Returns (iso_or_None, issues, warnings). A partial timestamp (date
    without time or vice versa) is reported, not silently merged.
    """
    issues: list[str] = []
    warnings: list[str] = []
    date_s = _as_str(date_raw)
    date_m = _GPS_DATE_RE.match(date_s) if date_s else None
    if date_s is not None and date_m is None:
        issues.append(f"GPSDateStamp malformed: {date_s!r}")
    time_parts: list[float] | None = None
    if time_raw is not None:
        if isinstance(time_raw, (tuple, list)) and len(time_raw) == 3:
            converted: list[float] = []
            for component in time_raw:
                component_f = _rational_to_float(component)
                if component_f is None:
                    break
                converted.append(component_f)
            if len(converted) == 3:
                time_parts = converted
        if time_parts is None:
            issues.append("GPSTimeStamp malformed; GPS time not normalized")

    if date_m is None and time_parts is None:
        return None, issues, warnings
    if date_m is None or time_parts is None:
        warnings.append(
            "partial GPS timestamp (date without time or vice versa); "
            "no combined UTC datetime produced"
        )
        return None, issues, warnings

    year, mon, day = (int(g) for g in date_m.groups())
    hour, minute, second = time_parts
    if not (1 <= mon <= 12 and 1 <= day <= 31):
        issues.append(f"GPSDateStamp out of range: {date_s!r}")
        return None, issues, warnings
    if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 61):
        issues.append(f"GPSTimeStamp out of range: {time_parts}")
        return None, issues, warnings
    sec_int = int(second)
    iso = (
        f"{year:04d}-{mon:02d}-{day:02d}"
        f"T{int(hour):02d}:{int(minute):02d}:{sec_int:02d}Z"
    )
    return iso, issues, warnings


def osm_link(latitude: float, longitude: float, zoom: int = 15) -> str:
    """Build an OpenStreetMap URL for coordinates. No network call."""
    lat_s = f"{latitude:.6f}"
    lon_s = f"{longitude:.6f}"
    return (
        f"https://www.openstreetmap.org/?mlat={lat_s}&mlon={lon_s}"
        f"#map={zoom}/{lat_s}/{lon_s}"
    )


def normalize_gps(gps_raw: dict[int, Any]) -> GeoData:
    """Normalize raw GPS IFD tags into a GeoData model.

    Never raises on malformed input. Coordinates are derived only from
    complete, well-formed values; everything questionable is recorded
    in ``validity_issues`` / ``warnings``.
    """
    geo = GeoData()
    if not gps_raw:
        return geo
    geo.present = True
    for tag, value in gps_raw.items():
        geo.raw_tags[tag] = _json_safe(value)
        if tag in GPS_TAG_NAMES:
            geo.raw_tag_names[tag] = GPS_TAG_NAMES[tag]

    # --- latitude / longitude ---
    lat, lat_issues = dms_to_decimal(
        gps_raw.get(0x0002), _as_str(gps_raw.get(0x0001)), "N", "S", "Latitude"
    )
    lon, lon_issues = dms_to_decimal(
        gps_raw.get(0x0004), _as_str(gps_raw.get(0x0003)), "E", "W", "Longitude"
    )
    geo.validity_issues.extend(lat_issues)
    geo.validity_issues.extend(lon_issues)

    if lat is not None and not _LAT_RANGE[0] <= lat <= _LAT_RANGE[1]:
        geo.validity_issues.append(
            f"latitude {lat} out of range {_LAT_RANGE[0]}..{_LAT_RANGE[1]}"
        )
        lat = None
    if lon is not None and not _LON_RANGE[0] <= lon <= _LON_RANGE[1]:
        geo.validity_issues.append(
            f"longitude {lon} out of range {_LON_RANGE[0]}..{_LON_RANGE[1]}"
        )
        lon = None
    geo.latitude = lat
    geo.longitude = lon

    # --- altitude ---
    alt_ref = _byte_to_int(gps_raw.get(0x0005))
    alt = _rational_to_float(gps_raw.get(0x0006))
    if alt is not None:
        if alt_ref == 1:
            alt = -alt
        elif alt_ref not in (0, None):
            geo.validity_issues.append(
                f"GPSAltitudeRef {alt_ref} not 0 (above) or 1 (below); "
                "altitude sign unknown, kept positive"
            )
        if not _ALT_RANGE[0] <= alt <= _ALT_RANGE[1]:
            geo.validity_issues.append(
                f"altitude {alt} m outside sane bounds "
                f"{_ALT_RANGE[0]}..{_ALT_RANGE[1]} m"
            )
        else:
            geo.altitude_m = alt

    # --- bearing ---
    bearing = _rational_to_float(gps_raw.get(0x000D))
    if bearing is not None:
        ref = _as_str(gps_raw.get(0x000C))
        if ref is not None:
            ref_u = ref.strip().upper()
            if ref_u == "T":
                geo.bearing_ref = "true"
            elif ref_u == "M":
                geo.bearing_ref = "magnetic"
            else:
                geo.warnings.append(
                    f"GPSImgDirectionRef {ref!r} not 'T'/'M'; bearing reference unknown"
                )
        geo.bearing_deg = bearing % 360.0

    # --- timestamp ---
    iso, dt_issues, dt_warnings = _normalize_gps_datetime(
        gps_raw.get(0x001D), gps_raw.get(0x0007)
    )
    geo.gps_datetime_utc = iso
    geo.validity_issues.extend(dt_issues)
    geo.warnings.extend(dt_warnings)

    # --- misc ---
    geo.dop = _rational_to_float(gps_raw.get(0x000B))
    geo.processing_method = _as_str(gps_raw.get(0x001B))

    if not any(
        v is not None
        for v in (
            geo.latitude,
            geo.longitude,
            geo.altitude_m,
            geo.bearing_deg,
            geo.gps_datetime_utc,
            geo.dop,
            geo.processing_method,
        )
    ):
        geo.warnings.append("GPS IFD present but no usable GPS values decoded")

    geo.valid = not geo.validity_issues
    return geo
