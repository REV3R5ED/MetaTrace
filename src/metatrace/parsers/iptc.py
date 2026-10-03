"""IPTC/IIM metadata parsing (Photoshop IRB 8BIM blocks in JPEG APP13).

Layout: APP13 starts with ``Photoshop 3.0\\x00``, followed by 8BIM
resource blocks (``8BIM`` + id + Pascal name + u32 size + data).
Resource id 0x0404 carries the IPTC-NAA record: a sequence of datasets
(``0x1C`` + record + dataset + u16 length [+ extended length] + value).

Defensive throughout: every length is bounds-checked, truncated IRBs
produce warnings with partial results, unknown datasets are skipped
*by name* but kept verbatim in ``raw_datasets`` — nothing observed is
silently dropped.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import Any

from metatrace.core.models import IptcData
from metatrace.parsers.containers import iter_jpeg_segments

_SCAN_BOUND = 4 * 1024 * 1024
_PHOTOSHOP_HEADER = b"Photoshop 3.0\x00"
_IPTC_RESOURCE_ID = 0x0404

# (record, dataset) -> human name (IIM datasets MetaTrace v0.3 knows).
DATASET_NAMES: dict[tuple[int, int], str] = {
    (2, 0): "RecordVersion",
    (2, 5): "ObjectName",
    (2, 15): "Category",
    (2, 20): "SupplementalCategory",
    (2, 25): "Keywords",
    (2, 40): "SpecialInstructions",
    (2, 55): "DateCreated",
    (2, 60): "TimeCreated",
    (2, 80): "Byline",
    (2, 85): "BylineTitle",
    (2, 90): "City",
    (2, 92): "Sublocation",
    (2, 95): "ProvinceState",
    (2, 100): "CountryCode",
    (2, 101): "Country",
    (2, 105): "Headline",
    (2, 110): "Credit",
    (2, 115): "Source",
    (2, 116): "CopyrightNotice",
    (2, 120): "Caption",
    (2, 122): "CaptionWriter",
}

# Datasets that repeat (collected into lists, in encounter order).
_REPEATABLE = frozenset(
    {
        (2, 20),
        (2, 25),
        (2, 80),
        (2, 85),
        (2, 110),
        (2, 116),
    }
)


def _decode_text(raw: bytes) -> str:
    """IPTC text: try UTF-8, fall back to latin-1 (both common in the wild)."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _norm_date(raw: str) -> str | None:
    """'YYYYMMDD' -> 'YYYY-MM-DD'; None when not a plausible date."""
    if len(raw) != 8 or not raw.isdigit():
        return None
    y, m, d = int(raw[:4]), int(raw[4:6]), int(raw[6:8])
    if not (1 <= m <= 12 and 1 <= d <= 31):
        return None
    return f"{y:04d}-{m:02d}-{d:02d}"


def _norm_time(raw: str) -> str | None:
    """'HHMMSS[±HHMM]' -> 'HH:MM:SS[±HH:MM]'; None when implausible."""
    core = raw[:6]
    if len(core) != 6 or not core.isdigit():
        return None
    hh, mm, ss = int(core[:2]), int(core[2:4]), int(core[4:6])
    if hh > 23 or mm > 59 or ss > 61:
        return None
    out = f"{hh:02d}:{mm:02d}:{ss:02d}"
    zone = raw[6:]
    if len(zone) == 5 and zone[0] in "+-" and zone[1:].isdigit():
        out += f"{zone[0]}{zone[1:3]}:{zone[3:5]}"
    return out


def iter_8bim(data: bytes) -> Iterator[tuple[int, bytes, bytes]]:
    """Yield ``(resource_id, name, payload)`` for 8BIM blocks.

    Stops (with a raised ``ValueError`` describing the truncation) when
    a block header or payload runs past the buffer — callers convert
    that into a recorded warning and keep partial results.
    """
    pos = 0
    size = len(data)
    while pos + 12 <= size:
        if data[pos : pos + 4] != b"8BIM":
            raise ValueError(f"expected 8BIM signature at offset {pos}")
        rid = struct.unpack(">H", data[pos + 4 : pos + 6])[0]
        name_len = data[pos + 6]
        name_end = pos + 7 + name_len
        # Pascal string padded to even size (length byte included).
        name_end += (name_end - pos) & 1
        if name_end + 4 > size:
            raise ValueError("8BIM name runs past buffer")
        name = data[pos + 7 : pos + 7 + name_len]
        payload_len = struct.unpack(">I", data[name_end : name_end + 4])[0]
        payload_off = name_end + 4
        if payload_off + payload_len > size:
            raise ValueError(
                f"8BIM resource {rid:#06x} claims {payload_len} payload bytes "
                "past the buffer"
            )
        payload = data[payload_off : payload_off + payload_len]
        yield rid, bytes(name), payload
        # Payloads are padded to even size.
        pos = payload_off + payload_len + (payload_len & 1)


def parse_iptc_record(data: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse one IPTC-NAA record into dataset dicts + warnings.

    Each dataset dict: ``record``, ``dataset``, ``name`` (or None),
    ``data`` (decoded text), ``data_hex`` (verbatim bytes).
    """
    datasets: list[dict[str, Any]] = []
    warnings: list[str] = []
    pos = 0
    size = len(data)
    while pos < size:
        if data[pos] != 0x1C:
            warnings.append(
                f"IPTC tag marker 0x1C expected at offset {pos}, "
                f"found {data[pos]:#04x}; stopping"
            )
            break
        if pos + 5 > size:
            warnings.append("truncated IPTC dataset header; stopping")
            break
        record, ds = data[pos + 1], data[pos + 2]
        length = struct.unpack(">H", data[pos + 3 : pos + 5])[0]
        pos += 5
        if length & 0x8000:
            # Extended length: low 15 bits = number of length bytes.
            nbytes = length & 0x7FFF
            if nbytes == 0 or nbytes > 4 or pos + nbytes > size:
                warnings.append("bad IPTC extended length; stopping")
                break
            length = int.from_bytes(data[pos : pos + nbytes], "big")
            pos += nbytes
        if pos + length > size:
            warnings.append(
                f"IPTC dataset {record}:{ds} claims {length} bytes past "
                "the buffer; stopping"
            )
            break
        raw = data[pos : pos + length]
        pos += length
        key = (record, ds)
        datasets.append(
            {
                "record": record,
                "dataset": ds,
                "name": DATASET_NAMES.get(key),
                "data": _decode_text(raw),
                "data_hex": raw.hex(),
            }
        )
    return datasets, warnings


def find_iptc_in_jpeg(data: bytes) -> bytes | None:
    """Return the IPTC-NAA payload (8BIM 0x0404) from JPEG APP13."""
    for marker, payload in iter_jpeg_segments(data, _SCAN_BOUND):
        if marker != 0xED or not payload.startswith(_PHOTOSHOP_HEADER):
            continue
        body = payload[len(_PHOTOSHOP_HEADER) :]
        try:
            for rid, _name, block in iter_8bim(body):
                if rid == _IPTC_RESOURCE_ID:
                    return block
        except ValueError:
            # Malformed IRB: no usable IPTC here; the public entry
            # point records the warning with partial context.
            return None
    return None


def extract_iptc(path: str, fmt: str) -> IptcData:
    """Extract IPTC/IIM metadata from *path* (JPEG APP13 in v0.3).

    Never raises on malformed input: problems land in
    ``IptcData.warnings``; ``present`` reflects an observed IPTC record
    even when individual datasets failed.
    """
    iptc = IptcData()
    if fmt != "JPEG":
        return iptc  # IPTC lives in JPEG APP13 for v0.3's scope

    try:
        with open(path, "rb") as fh:
            data = fh.read(_SCAN_BOUND)
    except OSError as exc:
        iptc.warnings.append(f"cannot read file for IPTC extraction: {exc}")
        return iptc

    try:
        record = find_iptc_in_jpeg(data)
    except (struct.error, IndexError, ValueError, MemoryError) as exc:
        iptc.warnings.append(f"IPTC location failed defensively: {exc}")
        return iptc
    if record is None:
        return iptc

    datasets, warnings = parse_iptc_record(record)
    iptc.warnings.extend(warnings)
    if not datasets and not warnings:
        return iptc
    iptc.present = True
    iptc.raw_datasets = datasets

    fields: dict[tuple[int, int], Any] = {}
    for ds in datasets:
        key = (int(ds["record"]), int(ds["dataset"]))
        text = ds["data"]
        if key in _REPEATABLE:
            fields.setdefault(key, []).append(text)
        elif key not in fields:
            fields[key] = text
        # duplicate non-repeatable: keep first, raw keeps all

    def pop(key: tuple[int, int]) -> Any:
        return fields.pop(key, None)

    pop((2, 0))  # RecordVersion handled separately below (binary field)
    rv: int | None = None
    for ds in datasets:
        if (ds["record"], ds["dataset"]) == (2, 0):
            raw_rv = bytes.fromhex(ds["data_hex"])
            if len(raw_rv) == 2:
                rv = struct.unpack(">H", raw_rv)[0]
            elif raw_rv:
                iptc.warnings.append(
                    f"IPTC RecordVersion has unexpected length {len(raw_rv)}"
                )
            break
    date_raw = pop((2, 55))
    time_raw = pop((2, 60))
    iptc.fields = {
        "record_version": rv,
        "object_name": pop((2, 5)),
        "category": pop((2, 15)),
        "supplemental_categories": pop((2, 20)) or [],
        "keywords": pop((2, 25)) or [],
        "special_instructions": pop((2, 40)),
        "date_created": _norm_date(date_raw) if date_raw else None,
        "date_created_raw": date_raw,
        "time_created": _norm_time(time_raw) if time_raw else None,
        "time_created_raw": time_raw,
        "byline": pop((2, 80)) or [],
        "byline_title": pop((2, 85)) or [],
        "city": pop((2, 90)),
        "sublocation": pop((2, 92)),
        "province_state": pop((2, 95)),
        "country_code": pop((2, 100)),
        "country": pop((2, 101)),
        "headline": pop((2, 105)),
        "credit": pop((2, 110)) or [],
        "source": pop((2, 115)),
        "copyright_notice": pop((2, 116)) or [],
        "caption": pop((2, 120)),
        "caption_writer": pop((2, 122)),
    }
    # Any known dataset not explicitly mapped above stays reachable via
    # its numeric key — nothing observed is dropped from the model.
    for key, value in fields.items():
        iptc.fields[f"dataset_{key[0]}_{key[1]}"] = value
    return iptc
