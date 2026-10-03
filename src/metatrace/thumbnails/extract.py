"""Embedded thumbnail extraction (v0.7).

Sources handled:
- JPEG EXIF IFD1: JPEG-compressed blob via JPEGInterchangeFormat
  (0x0201) / JPEGInterchangeFormatLength (0x0202), or uncompressed
  TIFF strips via StripOffsets (0x0111) / StripByteCounts (0x0117).
- Standalone TIFF IFD1: same two layouts.
- PNG / WebP / GIF / BMP: no embedded-thumbnail mechanism in the
  metadata MetaTrace parses — reported absent, never an error.

No pixel decoding anywhere (stdlib has no JPEG decoder): thumbnail
dimensions come from a JPEG SOF marker scan of the blob, or from
TIFF tags directly. Everything is bounds-checked; corrupt blobs
become warnings, never exceptions.
"""

from __future__ import annotations

import hashlib
import struct

from metatrace.parsers.exif import find_exif_in_jpeg
from metatrace.thumbnails.models import ThumbnailInfo, ThumbnailsData

# Never read more than this for thumbnail hunting (thumbnails live
# near the start of the file; blobs themselves are bounded below).
_SCAN_BOUND = 4 * 1024 * 1024
# A single embedded thumbnail bigger than this is not parsed as one
# (still reported via its tags when sane).
_MAX_THUMB_BYTES = 16 * 1024 * 1024

# JPEG SOF markers (start-of-frame, carry dimensions). Excludes DHT
# (0xC4), JPGn (0xC8), DAC (0xCC) which are not frame headers.
_SOF_MARKERS = frozenset(
    {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
)

# IFD1 tags MetaTrace reads for thumbnails.
_T_JPEG_IF_OFFSET = 0x0201
_T_JPEG_IF_LENGTH = 0x0202
_T_IMAGE_WIDTH = 0x0100
_T_IMAGE_LENGTH = 0x0101
_T_COMPRESSION = 0x0103
_T_STRIP_OFFSETS = 0x0111
_T_STRIP_BYTE_COUNTS = 0x0117


def _in_bounds(buf: bytes, offset: int, size: int) -> bool:
    return 0 <= offset and 0 <= size and offset + size <= len(buf)


def iter_jpeg_markers(
    data: bytes, bound: int = _SCAN_BOUND
) -> list[tuple[int, int, int]]:
    """Yield (marker, payload_offset, payload_len) scanning JPEG markers.

    Stops at SOS (0xDA) or EOI, or when the scan leaves *bound*.
    Defensive: malformed lengths end the scan instead of raising.
    """
    out: list[tuple[int, int, int]] = []
    if len(data) < 2 or data[0:2] != b"\xff\xd8":
        return out
    pos = 2
    limit = min(len(data), bound)
    while pos + 2 <= limit:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker == 0xD9:  # EOI
            break
        if marker == 0xDA:  # SOS: entropy-coded data follows
            break
        if marker == 0xD8 or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            pos += 2
            continue
        if pos + 4 > limit:
            break
        seg_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        if seg_len < 2 or pos + 2 + seg_len > limit:
            break
        out.append((marker, pos + 4, seg_len - 2))
        pos += 2 + seg_len
    return out


def jpeg_sof_dimensions(blob: bytes) -> tuple[int | None, int | None]:
    """Dimensions from the first SOF marker in a JPEG blob.

    Returns (width, height) or (None, None) when no parseable SOF is
    found (truncated blob, progressive edge cases, non-JPEG data).
    Never raises.
    """
    try:
        for marker, payload_off, payload_len in iter_jpeg_markers(blob):
            if marker not in _SOF_MARKERS:
                continue
            if payload_len < 7:
                return None, None
            # SOF payload: precision(1) height(2) width(2) components(1)...
            height = struct.unpack(">H", blob[payload_off + 1 : payload_off + 3])[0]
            width = struct.unpack(">H", blob[payload_off + 3 : payload_off + 5])[0]
            if width > 0 and height > 0 and width <= 65500 and height <= 65500:
                return width, height
            return None, None
        return None, None
    except (struct.error, IndexError):
        return None, None


def jpeg_encoder_signals(data: bytes, bound: int = _SCAN_BOUND) -> tuple[int, bool]:
    """Coarse JPEG encoder signals: (DQT table count, DHT seen).

    Counts quantization tables across DQT segments (each 8-bit table
    is 65 bytes: 1 info + 64 coefficients; 16-bit tables are 129) and
    notes whether any DHT segment exists. Scanned over marker
    segments only — never the entropy-coded payload. Defensive:
    malformed segments are skipped, never fatal.
    """
    dqt = 0
    dht = False
    try:
        for marker, payload_off, payload_len in iter_jpeg_markers(data, bound):
            if marker == 0xDB:  # DQT
                pos = payload_off
                end = payload_off + payload_len
                while pos + 65 <= end:
                    info = data[pos]
                    step = 129 if (info >> 4) else 65
                    if pos + step > end:
                        break
                    dqt += 1
                    pos += step
            elif marker == 0xC4:  # DHT
                dht = True
    except (struct.error, IndexError):
        pass
    return dqt, dht


def _tiff_header(data: bytes) -> tuple[str, int] | None:
    """(endian, IFD0 offset) or None for non-TIFF data."""
    if len(data) < 8:
        return None
    mark = data[0:2]
    if mark == b"II":
        endian = "<"
    elif mark == b"MM":
        endian = ">"
    else:
        return None
    try:
        if struct.unpack(endian + "H", data[2:4])[0] != 42:
            return None
        return endian, struct.unpack(endian + "I", data[4:8])[0]
    except struct.error:
        return None


def _read_ifd_values(
    tiff: bytes, endian: str, entry_off: int, max_tags: int
) -> list[int] | None:
    """Read one IFD entry's value as a list of ints (SHORT/LONG only).

    Returns None when the entry is malformed or an unsupported type —
    callers treat that as "tag unusable", never an error.
    """
    try:
        if not _in_bounds(tiff, entry_off, 12):
            return None
        typ = struct.unpack(endian + "H", tiff[entry_off + 2 : entry_off + 4])[0]
        count = struct.unpack(endian + "I", tiff[entry_off + 4 : entry_off + 8])[0]
        if typ not in (3, 4) or count == 0 or count > 4096:
            return None
        size = (2 if typ == 3 else 4) * count
        inline = tiff[entry_off + 8 : entry_off + 12]
        if size <= 4:
            buf = inline[:size]
        else:
            offset = struct.unpack(endian + "I", inline)[0]
            if not _in_bounds(tiff, offset, size):
                return None
            buf = tiff[offset : offset + size]
        fmt = endian + ("H" if typ == 3 else "I") * count
        return [int(v) for v in struct.unpack(fmt, buf)]
    except struct.error:
        return None


def _parse_ifd1_tags(
    tiff: bytes, endian: str, ifd1_off: int, max_tags: int
) -> dict[int, list[int]]:
    """Read IFD1 entries of interest; {tag_id: [values]}."""
    tags: dict[int, list[int]] = {}
    try:
        if not _in_bounds(tiff, ifd1_off, 2):
            return tags
        count = struct.unpack(endian + "H", tiff[ifd1_off : ifd1_off + 2])[0]
        count = min(count, max_tags)
        for i in range(count):
            entry = ifd1_off + 2 + i * 12
            if not _in_bounds(tiff, entry, 12):
                break
            tag = struct.unpack(endian + "H", tiff[entry : entry + 2])[0]
            if tag not in (
                _T_JPEG_IF_OFFSET,
                _T_JPEG_IF_LENGTH,
                _T_IMAGE_WIDTH,
                _T_IMAGE_LENGTH,
                _T_COMPRESSION,
                _T_STRIP_OFFSETS,
                _T_STRIP_BYTE_COUNTS,
            ):
                continue
            values = _read_ifd_values(tiff, endian, entry, max_tags)
            if values and tag not in tags:
                tags[tag] = values
    except struct.error:
        pass
    return tags


def _ifd1_offset(tiff: bytes, endian: str, ifd0_off: int, max_tags: int) -> int | None:
    """Next-IFD offset after IFD0 (IFD1), or None."""
    try:
        if not _in_bounds(tiff, ifd0_off, 2):
            return None
        count = min(
            struct.unpack(endian + "H", tiff[ifd0_off : ifd0_off + 2])[0], max_tags
        )
        nxt = ifd0_off + 2 + count * 12
        if not _in_bounds(tiff, nxt, 4):
            return None
        off = struct.unpack(endian + "I", tiff[nxt : nxt + 4])[0]
        return off if off else None
    except struct.error:
        return None


def _identify_blob(blob: bytes) -> str:
    if blob[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if blob[:4] in (b"II*\x00", b"MM\x00*"):
        return "TIFF"
    return "UNKNOWN"


def _finish_thumbnail(
    index: int,
    source: str,
    blob: bytes,
    width: int | None,
    height: int | None,
    warnings: list[str],
) -> ThumbnailInfo:
    fmt = _identify_blob(blob)
    tw, th = width, height
    dqt: int | None = None
    dht: bool | None = None
    if fmt == "JPEG":
        sw, sh = jpeg_sof_dimensions(blob)
        tw, th = sw if tw is None else tw, sh if th is None else th
        dqt, dht = jpeg_encoder_signals(blob)
    return ThumbnailInfo(
        index=index,
        source=source,
        byte_size=len(blob),
        sha256=hashlib.sha256(blob).hexdigest(),
        width=tw,
        height=th,
        format=fmt,
        dqt_count=dqt,
        has_dht=dht,
        warnings=warnings,
    )


def _thumbnails_from_tiff(
    tiff: bytes,
    endian: str,
    ifd0_off: int,
    source_label: str,
    max_tags: int,
    warnings: list[str],
) -> list[tuple[ThumbnailInfo, bytes]]:
    """Extract thumbnails from one TIFF payload's IFD1.

    Returns (ThumbnailInfo, blob bytes) pairs; callers drop the bytes
    when they are not needed.
    """
    found: list[tuple[ThumbnailInfo, bytes]] = []
    ifd1_off = _ifd1_offset(tiff, endian, ifd0_off, max_tags)
    if ifd1_off is None:
        return found
    tags = _parse_ifd1_tags(tiff, endian, ifd1_off, max_tags)

    # Layout 1: JPEG-compressed thumbnail blob.
    if _T_JPEG_IF_OFFSET in tags and _T_JPEG_IF_LENGTH in tags:
        off = tags[_T_JPEG_IF_OFFSET][0]
        length = tags[_T_JPEG_IF_LENGTH][0]
        if length <= 0 or length > _MAX_THUMB_BYTES:
            warnings.append(f"IFD1 JPEG thumbnail length {length} implausible; skipped")
        elif not _in_bounds(tiff, off, length):
            warnings.append(
                f"IFD1 JPEG thumbnail at offset {off} (+{length}) out of "
                "bounds; skipped"
            )
        else:
            blob = tiff[off : off + length]
            info = _finish_thumbnail(
                len(found), f"{source_label} (JPEG blob)", blob, None, None, []
            )
            found.append((info, blob))
        return found

    # Layout 2: uncompressed TIFF strips.
    if _T_STRIP_OFFSETS in tags and _T_STRIP_BYTE_COUNTS in tags:
        compression = (tags.get(_T_COMPRESSION) or [1])[0]
        if compression != 1:
            warnings.append(
                f"IFD1 thumbnail uses compression {compression} "
                "(only uncompressed strips supported); skipped"
            )
            return found
        offsets = tags[_T_STRIP_OFFSETS]
        counts = tags[_T_STRIP_BYTE_COUNTS]
        if len(counts) == 1 and len(offsets) > 1:
            counts = counts * len(offsets)
        if len(offsets) != len(counts):
            warnings.append("IFD1 strip offsets/counts mismatch; skipped")
            return found
        total = sum(counts)
        if total <= 0 or total > _MAX_THUMB_BYTES:
            warnings.append(f"IFD1 strip total {total} bytes implausible; skipped")
            return found
        strips = bytearray()
        ok = True
        for off, ln in zip(offsets, counts, strict=True):
            if not _in_bounds(tiff, off, ln):
                warnings.append(
                    f"IFD1 strip at offset {off} (+{ln}) out of bounds; skipped"
                )
                ok = False
                break
            strips += tiff[off : off + ln]
        if ok:
            w_vals = tags.get(_T_IMAGE_WIDTH)
            h_vals = tags.get(_T_IMAGE_LENGTH)
            width = w_vals[0] if w_vals else None
            height = h_vals[0] if h_vals else None
            info = _finish_thumbnail(
                len(found),
                f"{source_label} (TIFF strips)",
                bytes(strips),
                width,
                height,
                [],
            )
            found.append((info, bytes(strips)))
        return found

    warnings.append(
        "IFD1 exists but carries no thumbnail data tags "
        "(no JPEGInterchangeFormat or StripOffsets); nothing extractable"
    )
    return found


def extract_thumbnails_with_blobs(
    path: str,
    fmt: str,
    max_tags: int = 512,
) -> tuple[ThumbnailsData, list[bytes]]:
    """Like :func:`extract_thumbnails` but also returns the raw blobs.

    Used by ``metatrace thumbnails --extract``. The analysis pipeline
    uses :func:`extract_thumbnails` and never retains blob bytes.
    """
    result = ThumbnailsData()
    blobs: list[bytes] = []
    if fmt not in ("JPEG", "TIFF"):
        return result, blobs  # no thumbnail mechanism; absent, not an error
    try:
        with open(path, "rb") as fh:
            data = fh.read(_SCAN_BOUND)
    except OSError as exc:
        result.warnings.append(f"cannot read file for thumbnail extraction: {exc}")
        return result, blobs

    try:
        if fmt == "JPEG":
            # Main-image encoder signals for the "same encoder?" comparison.
            result.main_dqt_count, result.main_has_dht = jpeg_encoder_signals(data)
            tiff = find_exif_in_jpeg(data)
            if tiff is None:
                return result, blobs  # no EXIF at all: no IFD1 possible
            source_label = "EXIF IFD1"
        else:
            tiff = data
            source_label = "TIFF IFD1"
        header = _tiff_header(tiff)
        if header is None:
            result.warnings.append("EXIF/TIFF payload is not a TIFF header")
            return result, blobs
        endian, ifd0_off = header
        pairs = _thumbnails_from_tiff(
            tiff, endian, ifd0_off, source_label, max_tags, result.warnings
        )
    except (struct.error, IndexError, ValueError, MemoryError) as exc:
        result.warnings.append(f"thumbnail extraction failed defensively: {exc}")
        return result, blobs
    for info, blob in pairs:
        info.index = len(result.thumbnails)
        result.thumbnails.append(info)
        blobs.append(blob)
    result.present = bool(result.thumbnails)
    return result, blobs


def extract_thumbnails(
    path: str,
    fmt: str,
    max_tags: int = 512,
) -> ThumbnailsData:
    """Extract embedded thumbnails from *path* (read-only).

    JPEG: EXIF IFD1 inside the APP1 segment. TIFF: IFD1 of the file.
    Other formats have no embedded-thumbnail mechanism in the
    metadata MetaTrace parses — reported absent. Blob bytes are not
    retained (see :func:`extract_thumbnails_with_blobs`). Never
    raises: problems become warnings.
    """
    result, _blobs = extract_thumbnails_with_blobs(path, fmt, max_tags)
    return result


def write_thumbnail(
    blob: bytes, out_dir: str, stem: str, index: int, fmt: str, force: bool = False
) -> tuple[str | None, str | None]:
    """Write one thumbnail blob; (path, error).

    Filename: ``<stem>_thumb<N>.<ext>`` sanitized to
    ``[A-Za-z0-9_.-]``. Refuses to overwrite without *force*.
    """
    import os
    import re as _re

    ext = {"JPEG": "jpg", "TIFF": "tif"}.get(fmt, "bin")
    safe_stem = _re.sub(r"[^A-Za-z0-9_.-]", "_", stem) or "thumbnail"
    name = f"{safe_stem}_thumb{index}.{ext}"
    target = os.path.join(out_dir, name)
    if os.path.exists(target) and not force:
        return None, (
            f"refusing to overwrite existing file {target} (pass --force to overwrite)"
        )
    try:
        os.makedirs(out_dir, exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(blob)
    except OSError as exc:
        return None, f"cannot write {target}: {exc}"
    return target, None
