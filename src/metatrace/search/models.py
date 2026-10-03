"""Search index data models (v0.9).

The index is a flat JSON list of per-file records — metadata only,
never pixel data. It is built from batch results (``metatrace batch
--index``) or directly from a directory (``metatrace search
--build-index``) and queried fully offline afterwards.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class IndexRecord:
    """One analyzed image, reduced to searchable metadata."""

    path: str
    filename: str
    sha256: str
    format: str  # identity.format, e.g. "JPEG"
    device_make: str = ""  # normalized make claim ("" when unknown)
    device_model: str = ""  # normalized model claim ("" when unknown)
    device_display: str = "unknown device"  # human label, e.g. "Canon EOS R5"
    capture_day: str = "unknown"  # "YYYY-MM-DD" claim, or "unknown"
    capture_day_display: str = "unknown date"
    gps_lat: float | None = None
    gps_lon: float | None = None
    has_gps: bool = False  # present + decodable coordinates
    gps_valid: bool = False  # passed the GPS validity checks
    timestamps: list[dict[str, Any]] = field(default_factory=list)
    thumbnail_count: int = 0
    anomaly_rule_ids: list[str] = field(default_factory=list)
    caption: str = ""  # IPTC caption
    keywords: list[str] = field(default_factory=list)  # IPTC keywords
    software: str = ""  # EXIF Software
    title: str = ""  # XMP dc:title

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def text_fields(self) -> list[str]:
        """Fields searched by --text (substring, case-insensitive)."""
        return [
            self.device_make,
            self.device_model,
            self.device_display,
            self.software,
            self.caption,
            self.title,
            *self.keywords,
        ]


@dataclass
class SearchIndex:
    """A versioned, deterministic search index."""

    version: int
    tool_version: str
    built_at: str  # UTC ISO-8601
    root: str  # directory the index was built from ("" when from batch)
    records: list[IndexRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["records"] = [r.to_dict() for r in self.records]
        return d


@dataclass
class LocationCluster:
    """Geotagged images grouped into one ~1km-merged cluster (v0.9).

    Coordinates are GPS metadata *claims* — clustering never asserts
    where photographs were actually taken.
    """

    center_lat: float
    center_lon: float
    radius_km: float  # max haversine distance from center to a member
    count: int
    files: list[str] = field(default_factory=list)  # sorted paths
    time_span: tuple[str, str] | None = None  # (min_day, max_day) or None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["time_span"] = list(self.time_span) if self.time_span else None
        return d
