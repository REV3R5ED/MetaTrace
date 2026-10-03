"""Timestamp normalization: every flavor MetaTrace has seen, one model.

Flavors handled:

- EXIF ``YYYY:MM:DD HH:MM:SS`` (+ optional ``OffsetTime*`` ``±HH:MM``)
- XMP ISO-8601 (``Z`` / numeric offsets / naive / date-only)
- IPTC ``DateCreated`` (``YYYYMMDD``) + ``TimeCreated`` (``HHMMSS±HHMM``)
- GPS ``GPSDateStamp`` + ``GPSTimeStamp`` (inherently UTC)
- ICC profile creation time (``YYYY-MM-DDTHH:MM:SS``, UTC per ICC spec)
- Filesystem mtime (labeled as filesystem, never image metadata)

A timezone is never invented: naive claims keep ``value_utc=None``.
Unparseable values are kept verbatim with ``parseable=False``.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from metatrace.core.models import Analysis, NormalizedTimestamp

_EXIF_RE = re.compile(r"^(\d{4}):(\d{2}):(\d{2})[ ](\d{2}):(\d{2}):(\d{2})$")
_OFFSET_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
_XMP_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?"
    r"(Z|[+-]\d{2}:?\d{2})?)?$"
)
_IPTC_DATE_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})$")
_IPTC_TIME_RE = re.compile(r"^(\d{2})(\d{2})(\d{2})([+-]\d{4})?$")


def _plausible(
    year: int, mon: int, day: int, hh: int = 0, mm: int = 0, ss: int = 0
) -> bool:
    """Range checks matching the rest of MetaTrace (no calendar math)."""
    return (
        1 <= mon <= 12
        and 1 <= day <= 31
        and hh <= 23
        and mm <= 59
        and ss <= 61
        and year >= 1
    )


def _parse_offset(text: str) -> timedelta | None:
    """'+HH:MM' / '-HHMM' / 'Z' -> timedelta. None when not an offset."""
    text = text.strip()
    if text == "Z":
        return timedelta(0)
    m = _OFFSET_RE.match(text)
    if not m:
        return None
    sign, hh, mm = m.group(1), int(m.group(2)), int(m.group(3))
    if hh > 23 or mm > 59:
        return None
    delta = timedelta(hours=hh, minutes=mm)
    return delta if sign == "+" else -delta


def _utc_iso(dt: datetime) -> str:
    """An aware datetime -> 'YYYY-MM-DDTHH:MM:SSZ' (sub-second dropped)."""
    return (
        dt.astimezone(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _iso_wall(y: int, mo: int, d: int, h: int = 0, mi: int = 0, s: int = 0) -> str:
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}"


def normalize_exif_timestamp(
    raw: str | None,
    offset_raw: str | None,
    *,
    label: str,
    source: str,
) -> NormalizedTimestamp | None:
    """EXIF 'YYYY:MM:DD HH:MM:SS' + optional OffsetTime* -> NormalizedTimestamp."""
    if not raw:
        return None
    raw = raw.strip()
    m = _EXIF_RE.match(raw)
    if not m:
        return NormalizedTimestamp(label=label, source=source, raw=raw, parseable=False)
    y, mo, d, h, mi, s = (int(g) for g in m.groups())
    if not _plausible(y, mo, d, h, mi, s):
        return NormalizedTimestamp(label=label, source=source, raw=raw, parseable=False)
    wall = _iso_wall(y, mo, d, h, mi, s)
    offset = _parse_offset(offset_raw) if offset_raw else None
    if offset_raw and offset is None:
        # An OffsetTime* tag exists but is garbage: the claim is still
        # usable as naive, and the raw offset stays in the EXIF model.
        return NormalizedTimestamp(
            label=label,
            source=source,
            raw=f"{raw} (offset tag {offset_raw!r} unparseable)",
            wall=wall,
            precision="second",
            timezone_status="naive",
        )
    if offset is not None:
        aware = datetime(y, mo, d, h, mi, s, tzinfo=timezone(offset))
        return NormalizedTimestamp(
            label=label,
            source=source,
            raw=raw,
            value_utc=_utc_iso(aware),
            wall=wall,
            precision="second",
            timezone_status="explicit",
        )
    return NormalizedTimestamp(
        label=label,
        source=source,
        raw=raw,
        wall=wall,
        precision="second",
        timezone_status="naive",
    )


def normalize_xmp_timestamp(
    raw: str | None, *, label: str, source: str
) -> NormalizedTimestamp | None:
    """XMP ISO-8601 date -> NormalizedTimestamp (offsets converted to UTC)."""
    if not raw:
        return None
    raw = raw.strip()
    m = _XMP_RE.match(raw)
    if not m:
        return NormalizedTimestamp(label=label, source=source, raw=raw, parseable=False)
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hh_s, mm_s, ss_s, tz_s = m.group(4), m.group(5), m.group(6), m.group(7)
    if not _plausible(y, mo, d):
        return NormalizedTimestamp(label=label, source=source, raw=raw, parseable=False)
    if hh_s is None:
        return NormalizedTimestamp(
            label=label,
            source=source,
            raw=raw,
            wall=f"{y:04d}-{mo:02d}-{d:02d}",
            precision="day",
            timezone_status="naive",
        )
    hh, mm, ss = int(hh_s), int(mm_s), int(ss_s or 0)
    if not _plausible(y, mo, d, hh, mm, ss):
        return NormalizedTimestamp(label=label, source=source, raw=raw, parseable=False)
    wall = _iso_wall(y, mo, d, hh, mm, ss)
    precision = "second" if ss_s is not None else "minute"
    if tz_s is None:
        return NormalizedTimestamp(
            label=label,
            source=source,
            raw=raw,
            wall=wall,
            precision=precision,
            timezone_status="naive",
        )
    offset = _parse_offset(tz_s)
    if offset is None:  # pragma: no cover - regex already constrains this
        return NormalizedTimestamp(label=label, source=source, raw=raw, parseable=False)
    aware = datetime(y, mo, d, hh, mm, ss, tzinfo=timezone(offset))
    return NormalizedTimestamp(
        label=label,
        source=source,
        raw=raw,
        value_utc=_utc_iso(aware),
        wall=wall,
        precision=precision,
        timezone_status="explicit",
    )


def normalize_iptc_timestamp(
    date_raw: str | None, time_raw: str | None, *, source: str
) -> NormalizedTimestamp | None:
    """IPTC DateCreated 'YYYYMMDD' + TimeCreated 'HHMMSS±HHMM'."""
    if not date_raw and not time_raw:
        return None
    raw = " ".join(p for p in (date_raw, time_raw) if p)
    if not date_raw:
        # A time without a date cannot be anchored to an instant.
        return NormalizedTimestamp(
            label="capture", source=source, raw=raw, parseable=False
        )
    m = _IPTC_DATE_RE.match(date_raw.strip())
    if not m or not _plausible(int(m.group(1)), int(m.group(2)), int(m.group(3))):
        return NormalizedTimestamp(
            label="capture", source=source, raw=raw, parseable=False
        )
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if not time_raw:
        return NormalizedTimestamp(
            label="capture",
            source=source,
            raw=raw,
            wall=f"{y:04d}-{mo:02d}-{d:02d}",
            precision="day",
            timezone_status="naive",
        )
    tm = _IPTC_TIME_RE.match(time_raw.strip())
    if not tm or not _plausible(y, mo, d, int(tm.group(1)), int(tm.group(2))):
        return NormalizedTimestamp(
            label="capture", source=source, raw=raw, parseable=False
        )
    hh, mm, ss = int(tm.group(1)), int(tm.group(2)), int(tm.group(3))
    wall = _iso_wall(y, mo, d, hh, mm, ss)
    zone = tm.group(4)
    if zone is None:
        return NormalizedTimestamp(
            label="capture",
            source=source,
            raw=raw,
            wall=wall,
            precision="second",
            timezone_status="naive",
        )
    offset = _parse_offset(zone)
    if offset is None:  # pragma: no cover - regex already constrains this
        return NormalizedTimestamp(
            label="capture", source=source, raw=raw, parseable=False
        )
    aware = datetime(y, mo, d, hh, mm, ss, tzinfo=timezone(offset))
    return NormalizedTimestamp(
        label="capture",
        source=source,
        raw=raw,
        value_utc=_utc_iso(aware),
        wall=wall,
        precision="second",
        timezone_status="explicit",
    )


def normalize_gps_timestamp(iso_utc: str | None) -> NormalizedTimestamp | None:
    """GPS 'YYYY-MM-DDTHH:MM:SSZ' (inherently UTC) -> NormalizedTimestamp."""
    if not iso_utc:
        return None
    return NormalizedTimestamp(
        label="gps",
        source="GPS GPSDateStamp/GPSTimeStamp",
        raw=iso_utc,
        value_utc=iso_utc,
        wall=iso_utc[:-1],
        precision="second",
        timezone_status="utc",
    )


def normalize_icc_timestamp(created: str | None) -> NormalizedTimestamp | None:
    """ICC 'YYYY-MM-DDTHH:MM:SS' (UTC per ICC spec) -> NormalizedTimestamp."""
    if not created:
        return None
    return NormalizedTimestamp(
        label="icc-created",
        source="ICC profile creation",
        raw=created,
        value_utc=created + "Z",
        wall=created,
        precision="second",
        timezone_status="utc",
    )


def normalize_filesystem_timestamp(mtime: float) -> NormalizedTimestamp:
    """Filesystem mtime — labeled as filesystem, never image metadata."""
    dt = datetime.fromtimestamp(mtime, tz=timezone.utc).replace(microsecond=0)
    iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return NormalizedTimestamp(
        label="filesystem",
        source="filesystem mtime (not image metadata)",
        raw=repr(mtime),
        value_utc=iso,
        wall=iso[:-1],
        precision="second",
        timezone_status="utc",
    )


def collect_timestamps(
    analysis: Analysis, fs_mtime: float
) -> list[NormalizedTimestamp]:
    """Gather every timestamp claim from *analysis* into one list.

    Order is source-grouped (EXIF, XMP, IPTC, GPS, ICC, filesystem);
    chronological ordering is the timeline builder's job.
    """
    out: list[NormalizedTimestamp] = []
    exif = analysis.exif

    for raw, offset, label, source in (
        (
            exif.datetime_original_raw,
            exif.offset_time_original,
            "capture",
            "EXIF DateTimeOriginal",
        ),
        (
            exif.datetime_digitized_raw,
            exif.offset_time_digitized,
            "digitized",
            "EXIF DateTimeDigitized",
        ),
        (exif.datetime_file_raw, exif.offset_time, "file", "EXIF DateTime"),
    ):
        ts = normalize_exif_timestamp(raw, offset, label=label, source=source)
        if ts is not None:
            out.append(ts)

    xmp_basic: dict[str, Any] = analysis.xmp.xmp_basic
    for key, xmp_name, label in (
        ("create_date", "CreateDate", "capture"),
        ("modify_date", "ModifyDate", "modified"),
    ):
        ts = normalize_xmp_timestamp(
            xmp_basic.get(key), label=label, source=f"XMP xmp:{xmp_name}"
        )
        if ts is not None:
            out.append(ts)

    fields: dict[str, Any] = analysis.iptc.fields
    ts = normalize_iptc_timestamp(
        fields.get("date_created_raw"),
        fields.get("time_created_raw"),
        source="IPTC DateCreated/TimeCreated",
    )
    if ts is not None:
        out.append(ts)

    if exif.gps.present:
        ts = normalize_gps_timestamp(exif.gps.gps_datetime_utc)
        if ts is not None:
            out.append(ts)

    ts = normalize_icc_timestamp(analysis.icc.header.get("created"))
    if ts is not None:
        out.append(ts)

    out.append(normalize_filesystem_timestamp(fs_mtime))
    return out
