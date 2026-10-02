"""TIFF/EXIF parser in pure stdlib.

Parses EXIF from JPEG APP1 segments and standalone TIFF files.
Defensive by design — image input is untrusted:

- every offset is validated against the buffer before use
- tag counts and value sizes are bounded (configurable)
- both endiannesses supported
- malformed or truncated input produces recorded warnings, never
  an uncaught exception

What is extracted (v0.1, "basic EXIF"):
  IFD0: Make, Model, Orientation, Software, DateTime, ExifIFD/GPS pointers
  EXIF IFD: DateTimeOriginal, DateTimeDigitized, OffsetTime*, ISO,
            ExposureTime, FNumber, FocalLength, Flash, LensModel
GPS values are NOT decoded in v0.1 (v0.2); only presence is recorded.
XMP/IPTC/ICC are v0.3. Thumbnails are v0.7.

Raw observed tag values are preserved verbatim (bytes as hex) in
``ExifData.raw_tags``; normalized analyst-friendly fields are derived
alongside them and never merged.
"""

from __future__ import annotations

import math
import re
import struct
from typing import Any

from metatrace.core.models import ExifData

# TIFF field types: id -> size in bytes.
_TYPE_SIZES = {
    1: 1,  # BYTE
    2: 1,  # ASCII
    3: 2,  # SHORT
    4: 4,  # LONG
    5: 8,  # RATIONAL (two LONGs)
    7: 1,  # UNDEFINED
    9: 4,  # SLONG
    10: 8,  # SRATIONAL (two SLONGs)
}

# tag id -> human name (only tags MetaTrace v0.1 knows about).
TAG_NAMES: dict[int, str] = {
    0x0100: "ImageWidth",
    0x0101: "ImageHeight",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x0131: "Software",
    0x0132: "DateTime",
    0x8769: "ExifIFDPointer",
    0x8825: "GPSIFDPointer",
    0xA005: "InteropIFDPointer",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime",
    0x9011: "OffsetTimeOriginal",
    0x9012: "OffsetTimeDigitized",
    0x8827: "ISOSpeedRatings",
    0x829A: "ExposureTime",
    0x829D: "FNumber",
    0x920A: "FocalLength",
    0x9209: "Flash",
    0xA434: "LensModel",
}

_ORIENTATION_NAMES = {
    1: "Horizontal (normal)",
    2: "Mirror horizontal",
    3: "Rotate 180",
    4: "Mirror vertical",
    5: "Mirror horizontal and rotate 270 CW",
    6: "Rotate 90 CW",
    7: "Mirror horizontal and rotate 90 CW",
    8: "Rotate 270 CW",
}

_EXIF_DATETIME_RE = re.compile(r"^(\d{4}):(\d{2}):(\d{2})[ ](\d{2}):(\d{2}):(\d{2})$")

# Never scan more than this for EXIF data (APP1 segments are <= 64 KiB
# by the JPEG spec; TIFF IFDs live near the start of the file).
_SCAN_BOUND = 4 * 1024 * 1024


class ExifError(Exception):
    """Raised for unrecoverable EXIF problems (converted to warnings by callers)."""


def _decode_ascii(raw: bytes) -> str:
    text = raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return text.strip()


def _json_safe(value: Any) -> Any:
    """Convert a decoded tag value to something JSON-serializable."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    return value


class _TiffParser:
    """Defensive TIFF/IFD parser over one byte buffer."""

    def __init__(self, data: bytes, max_tags: int, max_value_bytes: int) -> None:
        self.data = data
        self.max_tags = max_tags
        self.max_value_bytes = max_value_bytes
        self.warnings: list[str] = []
        self.endian: str = "<"  # set by parse()

    # -- low-level helpers -------------------------------------------------

    def _u16(self, offset: int) -> int:
        return int(struct.unpack(self.endian + "H", self.data[offset : offset + 2])[0])

    def _u32(self, offset: int) -> int:
        return int(struct.unpack(self.endian + "I", self.data[offset : offset + 4])[0])

    def _in_bounds(self, offset: int, size: int) -> bool:
        return 0 <= offset and 0 <= size and offset + size <= len(self.data)

    # -- value decoding ----------------------------------------------------

    def _decode_value(self, typ: int, count: int, inline: bytes) -> Any:
        """Decode one IFD entry's value given its 4-byte inline field."""
        if typ not in _TYPE_SIZES:
            self.warnings.append(f"unknown TIFF field type {typ}; value skipped")
            return None
        total = _TYPE_SIZES[typ] * count
        if total <= 4:
            buf = inline[:total]
            base = 0
        else:
            if total > self.max_value_bytes:
                self.warnings.append(
                    f"value of {total} bytes exceeds limit "
                    f"({self.max_value_bytes}); skipped"
                )
                return None
            offset = struct.unpack(self.endian + "I", inline)[0]
            if not self._in_bounds(offset, total):
                self.warnings.append(
                    f"value offset {offset} (+{total}) out of bounds; skipped"
                )
                return None
            buf = self.data[offset : offset + total]
            base = offset
        try:
            if typ == 2:  # ASCII
                return _decode_ascii(buf)
            if typ in (1, 7):  # BYTE / UNDEFINED
                return bytes(buf)
            if typ == 3:  # SHORT
                vals = struct.unpack(self.endian + "H" * count, buf)
            elif typ == 4:  # LONG
                vals = struct.unpack(self.endian + "I" * count, buf)
            elif typ == 9:  # SLONG
                vals = struct.unpack(self.endian + "i" * count, buf)
            elif typ in (5, 10):  # RATIONAL / SRATIONAL
                fmt = self.endian + ("II" if typ == 5 else "ii")
                rationals = [
                    struct.unpack(fmt, buf[i * 8 : (i + 1) * 8]) for i in range(count)
                ]
                vals_t = [tuple(v) for v in rationals]
                return vals_t[0] if count == 1 else tuple(vals_t)
            else:  # pragma: no cover - guarded above
                return None
        except struct.error as exc:
            self.warnings.append(f"value decode failed at offset {base}: {exc}")
            return None
        if count == 1:
            return vals[0]
        return tuple(vals)

    # -- IFD parsing -------------------------------------------------------

    def parse_ifd(self, offset: int) -> dict[int, Any]:
        """Parse one IFD; returns {tag_id: decoded value}."""
        tags: dict[int, Any] = {}
        if not self._in_bounds(offset, 2):
            self.warnings.append(f"IFD offset {offset} out of bounds")
            return tags
        count = self._u16(offset)
        if count > self.max_tags:
            self.warnings.append(
                f"IFD at {offset} claims {count} tags (limit {self.max_tags}); "
                "truncated"
            )
            count = self.max_tags
        for i in range(count):
            entry = offset + 2 + i * 12
            if not self._in_bounds(entry, 12):
                self.warnings.append(f"IFD entry {i} at {entry} out of bounds")
                break
            tag = self._u16(entry)
            typ = self._u16(entry + 2)
            n = self._u32(entry + 4)
            if n > self.max_tags * 64:
                self.warnings.append(f"tag {tag:#x} count {n} implausible; skipped")
                continue
            inline = self.data[entry + 8 : entry + 12]
            value = self._decode_value(typ, n, inline)
            if value is not None and tag not in tags:
                tags[tag] = value
        return tags

    def next_ifd_offset(self, offset: int, count: int) -> int | None:
        nxt = offset + 2 + count * 12
        if not self._in_bounds(nxt, 4):
            return None
        return self._u32(nxt)

    # -- top-level TIFF parse ----------------------------------------------

    def parse(self) -> tuple[dict[int, Any], bool, bool]:
        """Parse TIFF data.

        Returns (raw_tags, has_gps_ifd, has_thumbnail_ifd).
        """
        data = self.data
        if len(data) < 8:
            raise ExifError("TIFF data shorter than 8-byte header")
        byte_order = data[0:2]
        if byte_order == b"II":
            self.endian = "<"
        elif byte_order == b"MM":
            self.endian = ">"
        else:
            raise ExifError("not a TIFF header (bad byte-order mark)")
        if self._u16(2) != 42:
            raise ExifError("not a TIFF header (bad magic 42)")
        ifd0_off = self._u32(4)
        if not self._in_bounds(ifd0_off, 2):
            raise ExifError(f"IFD0 offset {ifd0_off} out of bounds")

        raw = self.parse_ifd(ifd0_off)

        # EXIF sub-IFD.
        exif_ptr = raw.get(0x8769)
        if isinstance(exif_ptr, int) and self._in_bounds(exif_ptr, 2):
            for tag, value in self.parse_ifd(exif_ptr).items():
                raw.setdefault(tag, value)
        elif isinstance(exif_ptr, int):
            self.warnings.append(f"EXIF IFD offset {exif_ptr} out of bounds")

        has_gps = isinstance(raw.get(0x8825), int)
        # IFD1 (thumbnail) presence: nonzero next-IFD offset after IFD0.
        count = self._u16(ifd0_off)
        count = min(count, self.max_tags)
        nxt = self.next_ifd_offset(ifd0_off, count)
        has_thumbnail = bool(nxt)
        return raw, has_gps, has_thumbnail


# ---------------------------------------------------------------------------
# JPEG APP1 discovery
# ---------------------------------------------------------------------------


def find_exif_in_jpeg(data: bytes) -> bytes | None:
    """Return the TIFF payload of the first EXIF APP1 segment, or None.

    Scans JPEG markers up to ``_SCAN_BOUND`` bytes; stops at SOS.
    """
    if len(data) < 4 or data[0:2] != b"\xff\xd8":
        return None
    pos = 2
    size = min(len(data), _SCAN_BOUND)
    while pos + 4 <= size:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            pos += 2
            continue
        if pos + 4 > size:
            break
        length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        if length < 2 or pos + 2 + length > size:
            break
        if marker == 0xE1 and data[pos + 4 : pos + 10] == b"Exif\x00\x00":
            return data[pos + 10 : pos + 2 + length]
        if marker == 0xDA:  # SOS: compressed data follows
            break
        pos += 2 + length
    return None


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def normalize_exif_datetime(raw: str | None) -> str | None:
    """'YYYY:MM:DD HH:MM:SS' -> 'YYYY-MM-DDTHH:MM:SS'; None if unparseable."""
    if not raw:
        return None
    m = _EXIF_DATETIME_RE.match(raw.strip())
    if not m:
        return None
    year, mon, day, hh, mm, ss = (int(g) for g in m.groups())
    try:
        if not (
            1 <= mon <= 12 and 1 <= day <= 31 and hh <= 23 and mm <= 59 and ss <= 61
        ):
            return None
    except ValueError:
        return None
    return f"{year:04d}-{mon:02d}-{day:02d}T{hh:02d}:{mm:02d}:{ss:02d}"


def format_rational(value: Any) -> tuple[str | None, float | None]:
    """(num, den) -> ('1/250', 0.004). Returns (None, None) when unusable."""
    if (
        not isinstance(value, (tuple, list))
        or len(value) != 2
        or not all(isinstance(v, int) for v in value)
    ):
        return None, None
    num, den = int(value[0]), int(value[1])
    if den == 0:
        return None, None
    seconds = num / den
    if num == 0:
        return "0", 0.0
    g = math.gcd(num, den)
    num, den = num // g, den // g
    if den == 1:
        text = str(num)
    elif num == 1:
        text = f"1/{den}"
    else:
        text = f"{num}/{den}"
    return text, seconds


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, (tuple, list)) and value and isinstance(value[0], int):
        return int(value[0])
    return None


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, (tuple, list)) and len(value) == 2:
        _, seconds = format_rational(value)
        return seconds
    return None


def _as_str(value: Any) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def extract_exif(
    path: str,
    fmt: str,
    max_tags: int = 512,
    max_value_bytes: int = 1024 * 1024,
) -> ExifData:
    """Extract basic EXIF from *path* (JPEG APP1 or standalone TIFF).

    Never raises on malformed input: problems are recorded in
    ``ExifData.warnings`` and ``present`` stays False when nothing
    usable was found.
    """
    exif = ExifData()
    if fmt not in ("JPEG", "TIFF"):
        return exif  # no EXIF container for other formats in v0.1

    try:
        with open(path, "rb") as fh:
            data = fh.read(_SCAN_BOUND)
    except OSError as exc:
        exif.warnings.append(f"cannot read file for EXIF extraction: {exc}")
        return exif

    try:
        if fmt == "JPEG":
            tiff_data = find_exif_in_jpeg(data)
            if tiff_data is None:
                return exif
        else:
            tiff_data = data
        parser = _TiffParser(tiff_data, max_tags, max_value_bytes)
        raw, has_gps, has_thumbnail = parser.parse()
    except ExifError as exc:
        exif.warnings.append(str(exc))
        return exif
    except (struct.error, IndexError, ValueError, MemoryError) as exc:
        # Truly defensive: no malformed file may crash the tool.
        exif.warnings.append(f"EXIF parse failed defensively: {exc}")
        return exif

    exif.present = True
    exif.has_gps_ifd = has_gps
    exif.has_thumbnail_ifd = has_thumbnail
    exif.warnings.extend(parser.warnings)
    for tag, value in raw.items():
        exif.raw_tags[tag] = _json_safe(value)
        if tag in TAG_NAMES:
            exif.raw_tag_names[tag] = TAG_NAMES[tag]

    # --- normalized fields (each independently optional) ---
    exif.make = _as_str(raw.get(0x010F))
    exif.model = _as_str(raw.get(0x0110))
    exif.software = _as_str(raw.get(0x0131))
    exif.lens_model = _as_str(raw.get(0xA434))

    orientation = _as_int(raw.get(0x0112))
    exif.orientation = orientation
    if orientation is not None:
        exif.orientation_name = _ORIENTATION_NAMES.get(orientation)

    for tag, raw_attr, norm_attr in (
        (0x9003, "datetime_original_raw", "datetime_original"),
        (0x9004, "datetime_digitized_raw", "datetime_digitized"),
        (0x0132, "datetime_file_raw", "datetime_file"),
    ):
        raw_dt = _as_str(raw.get(tag))
        setattr(exif, raw_attr, raw_dt)
        normalized = normalize_exif_datetime(raw_dt)
        setattr(exif, norm_attr, normalized)
        if raw_dt and normalized is None:
            exif.warnings.append(
                f"unparseable datetime in {TAG_NAMES.get(tag, hex(tag))}: {raw_dt!r}"
            )

    exif.timezone_known = any(_as_str(raw.get(t)) for t in (0x9010, 0x9011, 0x9012))
    exif.iso = _as_int(raw.get(0x8827))

    exp_text, exp_sec = format_rational(raw.get(0x829A))
    exif.exposure_time = exp_text
    exif.exposure_seconds = exp_sec
    exif.f_number = _as_float(raw.get(0x829D))
    exif.focal_length_mm = _as_float(raw.get(0x920A))

    flash = _as_int(raw.get(0x9209))
    exif.flash = flash
    exif.flash_fired = bool(flash & 1) if flash is not None else None

    return exif
