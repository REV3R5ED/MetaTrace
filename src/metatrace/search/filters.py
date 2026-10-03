"""Composable metadata filters for v0.9 search.

All filters AND together. Every filter is optional; a record matches
when every *set* filter matches. Parsing helpers raise ValueError
with a human message — the CLI turns these into exit-2 usage errors.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from metatrace.search.geo import haversine_km
from metatrace.search.models import IndexRecord

#: --near radii above this are rejected as absurd.
MAX_NEAR_RADIUS_KM = 1000.0

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass
class SearchFilters:
    device: str | None = None  # substring of the device display label
    date: str | None = None  # exact capture day "YYYY-MM-DD"
    date_range: tuple[str, str] | None = None  # inclusive (start, end)
    gps_only: bool = False  # has decodable GPS coordinates
    near: tuple[float, float, float] | None = None  # (lat, lon, radius_km)
    anomaly: str | None = None  # anomaly rule id, e.g. "timestamp-conflict"
    text: str | None = None  # literal substring over text fields
    hash: str | None = None  # sha256 prefix (>= 8 hex chars) or full hash

    def is_empty(self) -> bool:
        return not any(
            [
                self.device,
                self.date,
                self.date_range,
                self.gps_only,
                self.near,
                self.anomaly,
                self.text,
                self.hash,
            ]
        )

    def describe(self) -> dict[str, Any]:
        """Stable description for --json output."""
        d: dict[str, Any] = {}
        if self.device:
            d["device"] = self.device
        if self.date:
            d["date"] = self.date
        if self.date_range:
            d["date_range"] = list(self.date_range)
        if self.gps_only:
            d["gps"] = True
        if self.near:
            d["near"] = {
                "lat": self.near[0],
                "lon": self.near[1],
                "radius_km": self.near[2],
            }
        if self.anomaly:
            d["anomaly"] = self.anomaly
        if self.text:
            d["text"] = self.text
        if self.hash:
            d["hash"] = self.hash
        return d


def parse_date(value: str) -> str:
    """Validate a YYYY-MM-DD date; returns it unchanged."""
    if not _DATE_RE.match(value):
        raise ValueError(f"not a YYYY-MM-DD date: {value!r}")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"not a real calendar date: {value!r}") from None
    return value


def parse_date_range(value: str) -> tuple[str, str]:
    """Parse 'START..END' (inclusive); raises ValueError on misuse."""
    parts = value.split("..")
    if len(parts) != 2:
        raise ValueError(
            f"date range must look like 2026-09-01..2026-09-30, got {value!r}"
        )
    start, end = parse_date(parts[0].strip()), parse_date(parts[1].strip())
    if start > end:
        raise ValueError(f"date range start {start} is after end {end}")
    return start, end


def parse_near(value: str) -> tuple[float, float, float]:
    """Parse 'LAT,LON,RADIUS_KM'; raises ValueError on misuse."""
    parts = [p.strip() for p in value.split(",")]
    if len(parts) != 3:
        raise ValueError(f"--near must look like LAT,LON,RADIUS_KM, got {value!r}")
    try:
        lat, lon, radius = float(parts[0]), float(parts[1]), float(parts[2])
    except ValueError:
        raise ValueError(f"--near values must be numbers, got {value!r}") from None
    for name, v in (("latitude", lat), ("longitude", lon), ("radius", radius)):
        if not math.isfinite(v):
            raise ValueError(f"--near {name} must be finite, got {value!r}")
    if not -90.0 <= lat <= 90.0:
        raise ValueError(f"latitude {lat} out of range [-90, 90]")
    if not -180.0 <= lon <= 180.0:
        raise ValueError(f"longitude {lon} out of range [-180, 180]")
    if radius <= 0:
        raise ValueError(f"--near radius must be positive, got {radius}")
    if radius > MAX_NEAR_RADIUS_KM:
        raise ValueError(
            f"--near radius {radius} km exceeds the {MAX_NEAR_RADIUS_KM:g} km cap"
        )
    return lat, lon, radius


def parse_hash(value: str) -> str:
    """Validate a sha256 prefix (>= 8 hex chars); returns lowercase."""
    cleaned = value.strip().lower()
    if len(cleaned) < 8 or not re.fullmatch(r"[0-9a-f]+", cleaned):
        raise ValueError(f"--hash needs at least 8 hex characters, got {value!r}")
    return cleaned


def matches(record: IndexRecord, filters: SearchFilters) -> bool:
    """True when *record* satisfies every set filter (AND)."""
    if filters.device:
        if filters.device.lower() not in record.device_display.lower():
            return False
    if filters.date:
        if record.capture_day != filters.date:
            return False
    if filters.date_range:
        start, end = filters.date_range
        if record.capture_day == "unknown":
            return False
        if not (start <= record.capture_day <= end):
            return False
    if filters.gps_only and not record.has_gps:
        return False
    if filters.near:
        lat, lon, radius = filters.near
        if not record.has_gps or record.gps_lat is None or record.gps_lon is None:
            return False
        if haversine_km(lat, lon, record.gps_lat, record.gps_lon) > radius:
            return False
    if filters.anomaly:
        if filters.anomaly not in record.anomaly_rule_ids:
            return False
    if filters.text:
        # Literal substring — regex metacharacters are never special.
        needle = filters.text.lower()
        if not any(needle in (f or "").lower() for f in record.text_fields()):
            return False
    if filters.hash:
        if not record.sha256.lower().startswith(filters.hash.lower()):
            return False
    return True


def apply_filters(
    records: list[IndexRecord], filters: SearchFilters
) -> list[IndexRecord]:
    """Return matching records, preserving index order (sorted by path)."""
    return [r for r in records if matches(r, filters)]
