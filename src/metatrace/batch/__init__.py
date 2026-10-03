"""Batch analysis: parallel directory scans, grouping, duplicates (v0.5).

``metatrace batch <dir>`` runs the full single-image pipeline over
every recognized image in a directory: per-file results plus a batch
summary (formats, devices, capture days, locations, duplicates, GPS
and conflict counts). Non-images are skipped with a recorded reason;
per-file failures become error records — the batch never crashes.
"""

from metatrace.batch.grouping import (
    LOCATION_GRID_NOTE,
    capture_day,
    device_key_and_display,
    find_duplicates,
    group_by_capture_day,
    group_by_device,
    group_by_location,
    has_conflicts,
    has_gps,
    location_cell,
)
from metatrace.batch.models import (
    BatchFileResult,
    BatchReport,
    BatchSummary,
    CrossImageTimestamp,
    DuplicateGroup,
    GroupBucket,
)
from metatrace.batch.runner import default_jobs, run_batch, stderr_progress
from metatrace.batch.scan import IMAGE_FORMATS, is_supported_image, iter_candidate_files
from metatrace.batch.summary import build_report, build_summary
from metatrace.batch.timeline import build_cross_image_timeline
from metatrace.core.plugins import ModuleInfo, register

__all__ = [
    "BatchFileResult",
    "BatchReport",
    "BatchSummary",
    "CrossImageTimestamp",
    "DuplicateGroup",
    "GroupBucket",
    "IMAGE_FORMATS",
    "LOCATION_GRID_NOTE",
    "build_cross_image_timeline",
    "build_report",
    "build_summary",
    "capture_day",
    "default_jobs",
    "device_key_and_display",
    "find_duplicates",
    "group_by_capture_day",
    "group_by_device",
    "group_by_location",
    "has_conflicts",
    "has_gps",
    "is_supported_image",
    "iter_candidate_files",
    "location_cell",
    "run_batch",
    "stderr_progress",
]

register(
    ModuleInfo(
        name="batch",
        description="Batch analysis: parallel directory scans, duplicate "
        "detection, grouping by device/date/location (v0.5)",
        version="0.5.0",
        commands=["batch"],
    )
)
