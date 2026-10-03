"""ICC color-profile extraction: header + tag directory.

ICC profiles travel embedded in the image container:

- JPEG: one or more APP2 segments starting with ``ICC_PROFILE\\x00``
  (sequence byte + total-chunks byte + payload; reassembled in order)
- PNG: ``iCCP`` chunk (name NUL + compression method 0 + zlib profile)
- TIFF: tag 34675 (0x8773), type UNDEFINED

v0.3 parses the 128-byte header (size, CMM, version, device class,
color space, PCS, creation time, ``acsp`` signature, rendering
intent, manufacturer/model) and lists the tag directory (signature +
offset + size per tag). Full tag-table color math is out of scope —
the directory tells an analyst exactly what the profile claims to
carry, which is what forensics needs first.

Defensive: size/signature mismatches, truncated directories and bad
chunks become warnings; a profile that fails the ``acsp`` magic is
reported with ``signature_valid=False`` rather than trusted.
"""

from __future__ import annotations

import struct
import zlib
from typing import Any

from metatrace.core.models import IccData
from metatrace.parsers.containers import (
    iter_jpeg_segments,
    iter_png_chunks,
)

_SCAN_BOUND = 4 * 1024 * 1024
_ICC_JPEG_HEADER = b"ICC_PROFILE\x00"
_ICC_TIFF_TAG = 34675
_MAX_TAGS = 256  # DoS bound on the tag-directory walk

_DEVICE_CLASSES = {
    "scnr": "input device",
    "mntr": "display device",
    "prtr": "output device",
    "link": "device link",
    "spac": "color space",
    "abst": "abstract",
    "nmcl": "named color",
}

_RENDERING_INTENTS = {
    0: "perceptual",
    1: "relative colorimetric",
    2: "saturation",
    3: "absolute colorimetric",
}


def _sig(raw: bytes) -> str:
    return raw.decode("ascii", errors="replace").strip("\x00 ").strip() or "?"


def find_icc_in_jpeg(data: bytes) -> tuple[bytes | None, list[str]]:
    """Reassemble a chunked ICC profile from JPEG APP2 segments.

    Returns (profile_bytes, warnings). ``(None, warnings)`` when no
    complete profile could be assembled.
    """
    warnings: list[str] = []
    chunks: dict[int, bytes] = {}
    expected: int | None = None
    for marker, payload in iter_jpeg_segments(data, _SCAN_BOUND):
        if marker != 0xE2 or not payload.startswith(_ICC_JPEG_HEADER):
            continue
        body = payload[len(_ICC_JPEG_HEADER) :]
        if len(body) < 2:
            warnings.append("truncated ICC APP2 chunk header; chunk skipped")
            continue
        seq, total = body[0], body[1]
        if seq == 0 or total == 0 or seq > total or total > 255:
            warnings.append(
                f"implausible ICC chunk numbering seq={seq} total={total}; "
                "chunk skipped"
            )
            continue
        if expected is None:
            expected = total
        elif expected != total:
            warnings.append(
                "inconsistent ICC chunk totals across APP2 segments; using first seen"
            )
        if seq in chunks:
            warnings.append(f"duplicate ICC chunk seq={seq}; keeping first")
            continue
        chunks[seq] = body[2:]
    if not chunks:
        return None, warnings
    assert expected is not None
    missing = [s for s in range(1, expected + 1) if s not in chunks]
    if missing:
        warnings.append(
            f"ICC profile incomplete: missing chunk(s) "
            f"{', '.join(map(str, missing))} of {expected}"
        )
        return None, warnings
    return b"".join(chunks[s] for s in range(1, expected + 1)), warnings


def find_icc_in_png(
    data: bytes, max_profile_bytes: int
) -> tuple[bytes | None, list[str]]:
    """Extract and decompress the ICC profile from a PNG iCCP chunk."""
    warnings: list[str] = []
    for ctype, cdata in iter_png_chunks(data):
        if ctype != b"iCCP":
            continue
        try:
            nul = cdata.index(b"\x00")
        except ValueError:
            warnings.append("iCCP chunk has no profile-name terminator; skipped")
            continue
        rest = cdata[nul + 1 :]
        if len(rest) < 1:
            warnings.append("truncated iCCP chunk; skipped")
            continue
        if rest[0] != 0:
            warnings.append(f"unknown iCCP compression method {rest[0]}; skipped")
            continue
        comp = rest[1:]
        # Incremental decompression with a hard output cap
        # (decompression-bomb defense).
        try:
            decomp = zlib.decompressobj()
            out = bytearray()
            for off in range(0, len(comp), 65536):
                out += decomp.decompress(comp[off : off + 65536])
                if len(out) > max_profile_bytes:
                    break
            out += decomp.flush()
        except zlib.error as exc:
            warnings.append(f"iCCP zlib decompression failed: {exc}")
            continue
        if len(out) > max_profile_bytes:
            warnings.append(
                f"decompressed ICC profile is {len(out)} bytes "
                f"(limit {max_profile_bytes}); skipped"
            )
            continue
        return bytes(out), warnings
    return None, warnings


def find_icc_in_tiff(tiff_data: bytes, max_tags: int) -> tuple[bytes | None, list[str]]:
    """Return the ICC profile from TIFF tag 34675, if present."""
    from metatrace.parsers.exif import _TiffParser

    try:
        parser = _TiffParser(tiff_data, max_tags, 8 * 1024 * 1024)
        raw, _, _, _ = parser.parse()
    except Exception as exc:  # ExifError and friends: not our problem here
        return None, [f"TIFF parse for ICC tag failed: {exc}"]
    value = raw.get(_ICC_TIFF_TAG)
    if isinstance(value, bytes):
        return value, list(parser.warnings)
    return None, list(parser.warnings)


def parse_icc_header(
    data: bytes,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """Parse the ICC header + tag directory.

    Returns (header, tags, warnings). ``header["signature_valid"]``
    reports the ``acsp`` magic check.
    """
    warnings: list[str] = []
    header: dict[str, Any] = {}
    tags: list[dict[str, Any]] = []
    if len(data) < 128:
        warnings.append(
            f"ICC profile is {len(data)} bytes, shorter than the "
            "128-byte header; cannot parse"
        )
        return header, tags, warnings

    claimed_size = struct.unpack(">I", data[0:4])[0]
    if claimed_size != len(data):
        warnings.append(
            f"ICC header claims size {claimed_size} but profile is {len(data)} bytes"
        )
    header["size_bytes"] = len(data)
    header["size_claimed"] = claimed_size
    header["preferred_cmm"] = _sig(data[4:8])
    major, minor_bf = data[8], data[9]
    header["version"] = f"{major}.{(minor_bf >> 4) & 0xF}.{minor_bf & 0xF}"
    dev_class = _sig(data[12:16])
    header["device_class"] = dev_class
    header["device_class_name"] = _DEVICE_CLASSES.get(dev_class, "unknown")
    header["color_space"] = _sig(data[16:20])
    header["pcs"] = _sig(data[20:24])
    year, mon, day, hh, mm, ss = struct.unpack(">6H", data[24:36])
    try:
        if 1 <= mon <= 12 and 1 <= day <= 31 and hh <= 23 and mm <= 59 and ss <= 61:
            created = f"{year:04d}-{mon:02d}-{day:02d}T{hh:02d}:{mm:02d}:{ss:02d}"
        else:
            created = None
            warnings.append("ICC creation timestamp has implausible fields")
    except (struct.error, ValueError):
        created = None
    header["created"] = created
    magic = data[36:40]
    header["signature_valid"] = magic == b"acsp"
    if not header["signature_valid"]:
        warnings.append(
            f"ICC magic is {magic!r}, not b'acsp'; profile is not a valid ICC profile"
        )
    header["platform"] = _sig(data[40:44])
    header["device_manufacturer"] = _sig(data[48:52])
    header["device_model"] = _sig(data[52:56])
    intent = struct.unpack(">I", data[64:68])[0]
    header["rendering_intent"] = intent
    header["rendering_intent_name"] = _RENDERING_INTENTS.get(intent, "unknown")
    header["creator"] = _sig(data[80:84])

    if len(data) < 132:
        warnings.append("ICC profile has no tag-directory count; stopping")
        return header, tags, warnings
    count = struct.unpack(">I", data[128:132])[0]
    if count > _MAX_TAGS:
        warnings.append(
            f"ICC tag directory claims {count} tags (limit {_MAX_TAGS}); truncated"
        )
        count = _MAX_TAGS
    for i in range(count):
        off = 132 + i * 12
        if off + 12 > len(data):
            warnings.append(f"ICC tag entry {i} runs past the buffer; stopping")
            break
        sig = _sig(data[off : off + 4])
        tag_off = struct.unpack(">I", data[off + 4 : off + 8])[0]
        tag_size = struct.unpack(">I", data[off + 8 : off + 12])[0]
        entry: dict[str, Any] = {
            "signature": sig,
            "offset": tag_off,
            "size": tag_size,
        }
        if tag_off + tag_size > len(data):
            warnings.append(
                f"ICC tag {sig!r} (offset {tag_off}, size {tag_size}) "
                "runs past the buffer; entry kept, data unread"
            )
            entry["readable"] = False
        else:
            entry["readable"] = True
        tags.append(entry)
    header["tag_count"] = len(tags)
    return header, tags, warnings


def extract_icc(
    path: str,
    fmt: str,
    max_tags: int = 512,
    max_profile_bytes: int = 4 * 1024 * 1024,
) -> IccData:
    """Locate and parse the embedded ICC profile in *path*.

    Never raises on malformed input: problems land in
    ``IccData.warnings`` and ``present`` reflects an observed profile
    even when the header failed validation.
    """
    icc = IccData()
    if fmt not in ("JPEG", "PNG", "TIFF"):
        return icc

    try:
        with open(path, "rb") as fh:
            data = fh.read(_SCAN_BOUND)
    except OSError as exc:
        icc.warnings.append(f"cannot read file for ICC extraction: {exc}")
        return icc

    profile: bytes | None = None
    try:
        if fmt == "JPEG":
            profile, w = find_icc_in_jpeg(data)
            icc.warnings.extend(w)
        elif fmt == "PNG":
            profile, w = find_icc_in_png(data, max_profile_bytes)
            icc.warnings.extend(w)
        else:  # TIFF
            profile, w = find_icc_in_tiff(data, max_tags)
            icc.warnings.extend(w)
    except (struct.error, IndexError, ValueError, MemoryError) as exc:
        icc.warnings.append(f"ICC location failed defensively: {exc}")
        return icc

    if profile is None:
        return icc
    if len(profile) > max_profile_bytes:
        icc.warnings.append(
            f"ICC profile is {len(profile)} bytes (limit {max_profile_bytes}); skipped"
        )
        return icc
    icc.present = True
    header, tags, warnings = parse_icc_header(profile)
    icc.header = header
    icc.tags = tags
    icc.signature_valid = bool(header.get("signature_valid", False))
    icc.warnings.extend(warnings)
    return icc
