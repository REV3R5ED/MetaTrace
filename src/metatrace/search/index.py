"""Build and persist the v0.9 search index.

The index is built from :class:`BatchFileResult` records — the same
objects a batch run produces — so ``metatrace batch --index`` and
``metatrace search --build-index`` share one code path. Records are
sorted by path, making index builds deterministic.
"""

from __future__ import annotations

import json
from typing import Any

from metatrace import __version__
from metatrace.batch.grouping import capture_day, device_key_and_display
from metatrace.batch.models import BatchFileResult
from metatrace.core.logging import utc_now_iso
from metatrace.search.models import IndexRecord, SearchIndex

#: Index schema version. Bumped whenever IndexRecord gains or loses
#: a field; readers reject anything else with a rebuild hint.
INDEX_VERSION = 1


class IndexError(Exception):
    """The index file is missing, corrupt, or the wrong version."""


def _device_norms(analysis: dict[str, Any]) -> tuple[str, str]:
    """(make_norm, model_norm) from the preferred device claim."""
    claims: list[dict[str, Any]] = (analysis.get("device") or {}).get("claims") or []
    claim: dict[str, Any] | None = None
    for c in claims:
        if c.get("source") == "EXIF":
            claim = c
            break
    if claim is None and claims:
        claim = claims[0]
    if not claim:
        return "", ""
    return str(claim.get("make_norm") or ""), str(claim.get("model_norm") or "")


def build_index_record(result: BatchFileResult) -> IndexRecord | None:
    """Reduce one batch result to an IndexRecord; None when not analyzed."""
    analysis = result.analysis
    if result.status != "ok" or not analysis:
        return None
    identity = analysis.get("identity") or {}
    exif = analysis.get("exif") or {}
    gps = exif.get("gps") or {}
    iptc = analysis.get("iptc") or {}
    xmp = analysis.get("xmp") or {}
    dc = xmp.get("dublin_core") or {}

    _key, display = device_key_and_display(analysis)
    make_norm, model_norm = _device_norms(analysis)
    day, day_display = capture_day(analysis)
    lat = gps.get("latitude")
    lon = gps.get("longitude")
    has_gps = bool(gps.get("present") and lat is not None and lon is not None)

    keywords = iptc.get("keywords") or []
    if isinstance(keywords, str):
        keywords = [keywords]

    return IndexRecord(
        path=result.path,
        filename=identity.get("filename") or result.path,
        sha256=(analysis.get("hashes") or {}).get("sha256", ""),
        format=identity.get("format") or "UNKNOWN",
        device_make=make_norm,
        device_model=model_norm,
        device_display=display,
        capture_day=day,
        capture_day_display=day_display,
        gps_lat=lat,
        gps_lon=lon,
        has_gps=has_gps,
        gps_valid=bool(has_gps and gps.get("valid", True)),
        timestamps=list(analysis.get("timestamps") or []),
        thumbnail_count=result.thumbnail_count,
        anomaly_rule_ids=list(result.anomaly_rule_ids),
        caption=str(iptc.get("caption") or ""),
        keywords=[str(k) for k in keywords],
        software=str(exif.get("software") or ""),
        title=str(dc.get("title") or ""),
    )


def build_index(results: list[BatchFileResult], root: str = "") -> SearchIndex:
    """Build a deterministic SearchIndex from batch results."""
    records = []
    for result in sorted(results, key=lambda r: r.path):
        record = build_index_record(result)
        if record is not None:
            records.append(record)
    return SearchIndex(
        version=INDEX_VERSION,
        tool_version=__version__,
        built_at=utc_now_iso(),
        root=root,
        records=records,
    )


def write_index(path: str, index: SearchIndex) -> None:
    """Write the index as pretty JSON (deterministic key order)."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(index.to_dict(), fh, indent=2, sort_keys=True)
        fh.write("\n")


def read_index(path: str) -> SearchIndex:
    """Read and validate an index file.

    Raises IndexError with a rebuild hint on any problem — the
    search commands surface this as a clean exit-2 error.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise IndexError(f"no such index file: {path}") from None
    except (OSError, ValueError) as exc:
        raise IndexError(f"cannot read index {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("version") != INDEX_VERSION:
        found = data.get("version") if isinstance(data, dict) else "?"
        raise IndexError(
            f"index {path} has version {found!r}, expected {INDEX_VERSION}; "
            "rebuild it with 'metatrace batch --index' or "
            "'metatrace search --build-index'"
        )
    records = [IndexRecord(**r) for r in data.get("records") or []]
    return SearchIndex(
        version=data["version"],
        tool_version=str(data.get("tool_version", "")),
        built_at=str(data.get("built_at", "")),
        root=str(data.get("root", "")),
        records=records,
    )
