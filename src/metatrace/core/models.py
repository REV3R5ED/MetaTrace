"""Normalized forensic data models.

Design principle carried through every phase: **observed** values are
kept verbatim (``raw`` fields) while **normalized** values are derived
alongside them. An analyst can always verify a normalized field
against the raw bytes it came from. Nothing here makes authenticity
claims — these models record what was observed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FileIdentity:
    """What the file *is*, independent of its metadata."""

    path: str  # as given on the command line
    filename: str
    size_bytes: int
    format: str  # "JPEG", "PNG", "GIF", "BMP", "WEBP", "TIFF", or "UNKNOWN"
    mime: str  # e.g. "image/jpeg", "" when unknown
    width: int | None = None
    height: int | None = None
    encoding: str = ""  # e.g. "PNG (color type 2, bit depth 8)"
    header_bytes_read: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GeoData:
    """GPS normalization result: raw observed tags + normalized fields.

    Coordinates record what the file's metadata *claims*. They never
    prove where a photograph was taken — that distinction is enforced
    in rendering and docs, not just here. ``validity_issues`` explains
    every rejected or questionable value; nothing is silently dropped.
    """

    present: bool = False  # a GPS IFD was found and decoded
    # Normalized, analyst-friendly fields (None when absent/unusable).
    latitude: float | None = None  # decimal degrees, -90..90
    longitude: float | None = None  # decimal degrees, -180..180
    altitude_m: float | None = None  # signed meters (negative = below sea level)
    bearing_deg: float | None = None  # 0..360
    bearing_ref: str | None = None  # "true" | "magnetic"
    gps_datetime_utc: str | None = None  # ISO-8601 UTC from GPSDateStamp+GPSTimeStamp
    processing_method: str | None = None
    dop: float | None = None  # dilution of precision
    valid: bool = True
    validity_issues: list[str] = field(default_factory=list)
    # Raw observed GPS tag values: {tag_id: value} (bytes hex-encoded).
    raw_tags: dict[int, Any] = field(default_factory=dict)
    raw_tag_names: dict[int, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["raw_tags"] = {str(k): v for k, v in self.raw_tags.items()}
        d["raw_tag_names"] = {str(k): v for k, v in self.raw_tag_names.items()}
        return d


@dataclass
class ExifData:
    """EXIF extraction result: raw observed tags + normalized fields.

    ``raw_tags`` maps tag id (int) to the observed value — the forensic
    record. ``normalized`` carries analyst-friendly derivations. The two
    are never merged: normalization must stay verifiable.
    """

    present: bool = False  # an EXIF segment was found at all
    has_gps_ifd: bool = False  # GPS IFD exists (decoded into ``gps`` in v0.2+)
    has_thumbnail_ifd: bool = False  # IFD1 exists
    # GPS normalization (v0.2). Empty (present=False) when no GPS IFD.
    gps: GeoData = field(default_factory=GeoData)
    # Normalized, analyst-friendly fields (None when absent/unparseable).
    make: str | None = None
    model: str | None = None
    software: str | None = None
    lens_model: str | None = None
    orientation: int | None = None
    orientation_name: str | None = None
    datetime_original: str | None = None  # ISO-8601, naive unless offset known
    datetime_original_raw: str | None = None
    datetime_digitized: str | None = None
    datetime_digitized_raw: str | None = None
    datetime_file: str | None = None  # IFD0 DateTime
    datetime_file_raw: str | None = None
    timezone_known: bool = False
    iso: int | None = None
    exposure_time: str | None = None  # e.g. "1/250"
    exposure_seconds: float | None = None
    f_number: float | None = None
    focal_length_mm: float | None = None
    flash: int | None = None
    flash_fired: bool | None = None
    # Raw observed tag values: {tag_id: value}. Values are JSON-safe
    # (bytes are hex-encoded by the parser).
    raw_tags: dict[int, Any] = field(default_factory=dict)
    raw_tag_names: dict[int, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # JSON keys must be strings; keep raw tag ids readable.
        d["raw_tags"] = {str(k): v for k, v in self.raw_tags.items()}
        d["raw_tag_names"] = {str(k): v for k, v in self.raw_tag_names.items()}
        # Nested GeoData carries its own raw tags; serialize with str keys.
        d["gps"] = self.gps.to_dict()
        return d


@dataclass
class Analysis:
    """Complete v0.1 analysis of one image file."""

    evidence_id: str  # "MT-" + sha256[:16]; deterministic, content-bound
    tool: str = "metatrace"
    tool_version: str = ""
    analyzed_at: str = ""  # UTC ISO-8601
    identity: FileIdentity | None = None
    hashes: dict[str, str] = field(default_factory=dict)
    exif: ExifData = field(default_factory=ExifData)
    parser_warnings: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["identity"] = self.identity.to_dict() if self.identity else None
        d["exif"] = self.exif.to_dict()
        return d
