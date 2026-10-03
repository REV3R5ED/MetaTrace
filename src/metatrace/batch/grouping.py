"""Grouping and duplicate detection across a batch (v0.5).

Grouping is descriptive: files are bucketed by what their metadata
*claims* — device (normalized make+model key), capture day, and a
~1km location grid from GPS claims. Buckets never judge; near-
duplicate (perceptual) grouping is out of scope for v0.5 (v0.7).
Exact duplicates group by SHA-256 of file content.
"""

from __future__ import annotations

from typing import Any

from metatrace.batch.models import BatchFileResult, DuplicateGroup, GroupBucket

UNKNOWN_DEVICE = "unknown device"
UNKNOWN_DATE = "unknown date"
UNKNOWN_LOCATION = "unknown location"

# ~1.1 km at the equator (1 degree of latitude ~= 111 km).
_LOCATION_GRID_DECIMALS = 2

LOCATION_GRID_NOTE = (
    "Location cells are ~1 km grid squares (coordinates rounded to "
    "2 decimals) over GPS metadata claims. Claims are not proof of "
    "where a photograph was taken."
)


def _analysis_of(result: BatchFileResult) -> dict[str, Any] | None:
    return result.analysis if result.status == "ok" else None


def _device_claim(analysis: dict[str, Any]) -> dict[str, Any] | None:
    """Preferred device claim: EXIF first, else the first claim."""
    claims: list[dict[str, Any]] = (analysis.get("device") or {}).get("claims") or []
    for claim in claims:
        if claim.get("source") == "EXIF":
            return claim
    return claims[0] if claims else None


def device_key_and_display(
    analysis: dict[str, Any],
) -> tuple[str, str]:
    """(group key, display label) for one file's device claim."""
    claim = _device_claim(analysis)
    if not claim:
        return "unknown", UNKNOWN_DEVICE
    make_key = claim.get("make_key")
    model_key = claim.get("model_key")
    make_norm = claim.get("make_norm")
    model_norm = claim.get("model_norm")
    if not make_key and not model_key:
        return "unknown", UNKNOWN_DEVICE
    key = f"{make_key or '?'}/{model_key or '?'}"
    # model_norm already reads "Make Model" when the maker is known
    # (normalize_model prepends it); only fall back to the make alone
    # when there is no model claim at all.
    if model_norm:
        display = model_norm
    elif make_norm:
        display = f"{make_norm} (model unknown)"
    else:  # pragma: no cover - defensive; key exists so one norm is set
        display = UNKNOWN_DEVICE
    return key, display


def capture_day(analysis: dict[str, Any]) -> tuple[str, str]:
    """(group key, display) for the capture day claim.

    Prefers the first ``capture``-labeled timestamp: UTC instant when
    the timezone is known, wall-clock day when naive. Naive claims
    are labeled as such — never silently treated as UTC.
    """
    for ts in analysis.get("timestamps") or []:
        if ts.get("label") != "capture" or not ts.get("parseable", True):
            continue
        if ts.get("value_utc"):
            day = ts["value_utc"][:10]
            return day, day
        if ts.get("wall"):
            day = ts["wall"][:10]
            return day, f"{day} (timezone unknown)"
    return "unknown", UNKNOWN_DATE


def location_cell(analysis: dict[str, Any]) -> tuple[str, str] | None:
    """(group key, display) for the ~1km GPS grid cell, or None.

    Coordinates are metadata claims, never proof of where a photo was
    taken — callers must repeat the disclaimer with any location
    output.
    """
    gps = (analysis.get("exif") or {}).get("gps") or {}
    if not gps.get("present"):
        return None
    lat = gps.get("latitude")
    lon = gps.get("longitude")
    if lat is None or lon is None:
        return None
    if not gps.get("valid", True):
        return None
    cell_lat = round(lat, _LOCATION_GRID_DECIMALS)
    cell_lon = round(lon, _LOCATION_GRID_DECIMALS)
    key = f"{cell_lat:.2f},{cell_lon:.2f}"
    display = f"~{cell_lat:.2f}, {cell_lon:.2f} (approx. 1 km cell)"
    return key, display


def has_conflicts(analysis: dict[str, Any]) -> bool:
    """True when any cross-source comparison fact is DIFFER.

    Descriptive count only — a difference is not a verdict (v0.6).
    """
    return any(
        fact.get("status") == "differ" for fact in analysis.get("comparison") or []
    )


def has_gps(analysis: dict[str, Any]) -> bool:
    gps = (analysis.get("exif") or {}).get("gps") or {}
    return bool(
        gps.get("present")
        and gps.get("latitude") is not None
        and gps.get("longitude") is not None
    )


def find_duplicates(results: list[BatchFileResult]) -> list[DuplicateGroup]:
    """Group analyzed files by SHA-256; only groups of 2+ are returned."""
    by_hash: dict[str, list[str]] = {}
    for result in results:
        analysis = _analysis_of(result)
        if not analysis:
            continue
        sha256 = (analysis.get("hashes") or {}).get("sha256")
        if sha256:
            by_hash.setdefault(sha256, []).append(result.path)
    groups = [
        DuplicateGroup(sha256=sha, files=sorted(paths))
        for sha, paths in by_hash.items()
        if len(paths) > 1
    ]
    groups.sort(key=lambda g: g.sha256)
    return groups


def _bucketize(
    results: list[BatchFileResult],
    key_fn: Any,
) -> list[GroupBucket]:
    buckets: dict[str, GroupBucket] = {}
    for result in results:
        analysis = _analysis_of(result)
        if not analysis:
            continue
        key, display = key_fn(analysis)
        bucket = buckets.get(key)
        if bucket is None:
            bucket = buckets[key] = GroupBucket(key=key, display=display)
        bucket.files.append(result.path)
    ordered = sorted(buckets.values(), key=lambda b: b.key)
    for bucket in ordered:
        bucket.files.sort()
    return ordered


def group_by_device(results: list[BatchFileResult]) -> list[GroupBucket]:
    """Bucket analyzed files by normalized (make, model) claim."""
    return _bucketize(results, device_key_and_display)


def group_by_capture_day(results: list[BatchFileResult]) -> list[GroupBucket]:
    """Bucket analyzed files by claimed capture day."""
    return _bucketize(results, capture_day)


def group_by_location(results: list[BatchFileResult]) -> list[GroupBucket]:
    """Bucket analyzed files by ~1km GPS grid cell (claims only)."""
    buckets: dict[str, GroupBucket] = {}
    for result in results:
        analysis = _analysis_of(result)
        if not analysis:
            continue
        cell = location_cell(analysis)
        if cell is None:
            continue
        key, display = cell
        bucket = buckets.get(key)
        if bucket is None:
            bucket = buckets[key] = GroupBucket(key=key, display=display)
        bucket.files.append(result.path)
    ordered = sorted(buckets.values(), key=lambda b: b.key)
    for bucket in ordered:
        bucket.files.sort()
    return ordered
