"""Batch summary aggregation (v0.5)."""

from __future__ import annotations

from metatrace.batch.grouping import (
    find_duplicates,
    group_by_capture_day,
    group_by_device,
    group_by_location,
    has_conflicts,
    has_gps,
)
from metatrace.batch.models import (
    BatchFileResult,
    BatchReport,
    BatchSummary,
    CrossImageTimestamp,
    DuplicateGroup,
    GroupBucket,
)
from metatrace.batch.timeline import build_cross_image_timeline


def build_summary(
    results: list[BatchFileResult],
    duplicates: list[DuplicateGroup],
    groups: dict[str, list[GroupBucket]],
) -> BatchSummary:
    summary = BatchSummary(total_files=len(results))
    for result in results:
        if result.status == "skipped":
            summary.skipped += 1
            continue
        if result.status == "error":
            summary.errors += 1
            continue
        summary.analyzed += 1
        analysis = result.analysis or {}
        fmt = (analysis.get("identity") or {}).get("format") or "UNKNOWN"
        summary.by_format[fmt] = summary.by_format.get(fmt, 0) + 1
        if has_gps(analysis):
            summary.files_with_gps += 1
        if has_conflicts(analysis):
            summary.files_with_conflicts += 1
    for bucket in groups.get("by_device", []):
        summary.by_device[bucket.display] = len(bucket.files)
    for bucket in groups.get("by_capture_day", []):
        summary.by_capture_day[bucket.display] = len(bucket.files)
    for bucket in groups.get("by_location", []):
        summary.by_location[bucket.display] = len(bucket.files)
    summary.duplicate_groups = len(duplicates)
    summary.duplicate_files = sum(len(g.files) for g in duplicates)
    return summary


def build_report(
    root: str,
    recursive: bool,
    jobs: int,
    results: list[BatchFileResult],
    include_timeline: bool = False,
) -> BatchReport:
    """Assemble the full deterministic batch report."""
    duplicates = find_duplicates(results)
    groups = {
        "by_device": group_by_device(results),
        "by_capture_day": group_by_capture_day(results),
        "by_location": group_by_location(results),
    }
    summary = build_summary(results, duplicates, groups)
    timeline: list[CrossImageTimestamp] = (
        build_cross_image_timeline(results) if include_timeline else []
    )
    return BatchReport(
        root=root,
        recursive=recursive,
        jobs=jobs,
        files=results,
        summary=summary,
        groups=groups,
        duplicates=duplicates,
        timeline=timeline,
    )
