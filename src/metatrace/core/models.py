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
    body_serial: str | None = None  # EXIF BodySerialNumber (0xA431), verbatim
    lens_serial: str | None = None  # EXIF LensSerialNumber (0xA433), verbatim
    camera_owner: str | None = None  # EXIF CameraOwnerName (0xA430), verbatim
    offset_time: str | None = None  # OffsetTime (0x9010), e.g. "+02:00"
    offset_time_original: str | None = None  # OffsetTimeOriginal (0x9011)
    offset_time_digitized: str | None = None  # OffsetTimeDigitized (0x9012)
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
class XmpData:
    """XMP packet extraction: observed packet + normalized views.

    The same logical field may exist in EXIF, XMP and IPTC. Those
    values are reported per source, side by side — never merged or
    silently preferred. Cross-source comparison is the v0.6 anomaly
    engine's job.
    """

    present: bool = False  # an XMP packet was observed
    raw_packet: str = ""  # decoded packet text (bounded; may be truncated)
    packet_truncated: bool = False
    namespaces: list[str] = field(default_factory=list)  # URIs seen
    # Normalized views (None / empty when absent or unparseable).
    dublin_core: dict[str, Any] = field(default_factory=dict)
    xmp_basic: dict[str, Any] = field(default_factory=dict)
    photoshop: dict[str, Any] = field(default_factory=dict)
    exif_in_xmp: dict[str, Any] = field(default_factory=dict)
    # Full flattening: {namespace URI: {local name: value}}.
    raw_properties: dict[str, dict[str, Any]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IptcData:
    """IPTC/IIM extraction: normalized datasets + verbatim record."""

    present: bool = False  # an IPTC-NAA record was observed
    # Normalized known datasets (None / [] when absent).
    fields: dict[str, Any] = field(default_factory=dict)
    # Every observed dataset, including unknown ones:
    # [{record, dataset, name|None, data, data_hex}].
    raw_datasets: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IccData:
    """Embedded ICC profile: header + tag directory (no color math)."""

    present: bool = False  # a complete profile was observed
    signature_valid: bool = False  # 'acsp' magic check
    header: dict[str, Any] = field(default_factory=dict)
    # Tag directory entries: [{signature, offset, size, readable}].
    tags: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NormalizedTimestamp:
    """One timestamp claim, normalized into a common model (v0.4).

    ``value_utc`` is the instant in UTC ISO-8601 (``...Z``) when the
    source pins the timezone down; it is None for timezone-naive
    claims — MetaTrace never invents a timezone. ``wall`` is the
    wall-clock reading (ISO-8601, no offset) for display and for
    comparing naive claims against each other. ``timezone_status``
    is one of ``"explicit"`` (offset given, incl. ``Z``), ``"naive"``
    (no timezone information), or ``"utc"`` (inherently UTC:
    GPS, ICC, filesystem mtime). ``precision`` is ``"second"``,
    ``"minute"``, ``"day"``, or ``"unknown"``.
    """

    label: str  # "capture" | "digitized" | "file" | "modified" | "gps" | ...
    source: str  # e.g. "EXIF DateTimeOriginal", "XMP xmp:CreateDate"
    raw: str | None  # verbatim observed value
    value_utc: str | None = None
    wall: str | None = None
    precision: str = "unknown"
    timezone_status: str = "naive"  # "explicit" | "naive" | "utc"
    parseable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DeviceClaim:
    """Device identity as claimed by one metadata source (v0.4).

    ``*_norm`` are display-friendly canonical forms; ``*_key`` are
    comparison keys (lowercase alphanumeric) so "canon eos r5" and
    "Canon EOS R5" compare equal. Raw values stay verbatim in the
    parser models — nothing here overwrites them.
    """

    source: str  # e.g. "EXIF", "XMP tiff:Make/tiff:Model"
    make_raw: str | None = None
    model_raw: str | None = None
    software_raw: str | None = None
    make_norm: str | None = None
    model_norm: str | None = None
    software_norm: str | None = None
    make_key: str | None = None
    model_key: str | None = None
    software_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DeviceIdentity:
    """Normalized device identity across sources (v0.4).

    Serial numbers are kept verbatim — they are identifiers, and
    normalizing them would destroy information.
    """

    claims: list[DeviceClaim] = field(default_factory=list)
    body_serial: str | None = None  # EXIF BodySerialNumber, verbatim
    lens_serial: str | None = None  # EXIF LensSerialNumber, verbatim
    camera_owner: str | None = None  # EXIF CameraOwnerName, verbatim

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["claims"] = [c.to_dict() for c in self.claims]
        return d


@dataclass
class ComparedValue:
    """One source's value inside a cross-field comparison (v0.4)."""

    source: str
    raw: str | None
    normalized: str | None  # display form (UTC instant, wall clock, or norm string)
    key: str  # comparison key; equal keys mean "agree"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComparisonFact:
    """One logical fact compared across metadata sources (v0.4).

    ``status`` is ``"agree"``, ``"differ"``, ``"only-in-one-source"``,
    or ``"no-data"``. This is descriptive bookkeeping — it records
    whether sources say the same thing, never a verdict on
    authenticity. Judging conflicts is the v0.6 anomaly engine's job.
    """

    fact: str  # "capture_time" | "device_make" | "device_model" | "software"
    status: str
    values: list[ComparedValue] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["values"] = [v.to_dict() for v in self.values]
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
    xmp: XmpData = field(default_factory=XmpData)  # v0.3
    iptc: IptcData = field(default_factory=IptcData)  # v0.3
    icc: IccData = field(default_factory=IccData)  # v0.3
    timestamps: list[NormalizedTimestamp] = field(default_factory=list)  # v0.4
    device: DeviceIdentity | None = None  # v0.4
    comparison: list[ComparisonFact] = field(default_factory=list)  # v0.4
    timeline: list[NormalizedTimestamp] = field(default_factory=list)  # v0.4
    parser_warnings: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["identity"] = self.identity.to_dict() if self.identity else None
        d["exif"] = self.exif.to_dict()
        d["timestamps"] = [t.to_dict() for t in self.timestamps]
        d["device"] = self.device.to_dict() if self.device else None
        d["comparison"] = [c.to_dict() for c in self.comparison]
        d["timeline"] = [t.to_dict() for t in self.timeline]
        return d
