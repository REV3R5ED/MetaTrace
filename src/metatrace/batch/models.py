"""Batch data models (v0.5).

Per-file results carry either a full single-image analysis, a skip
record (not a recognized image), or an error record (unreadable /
un analyzable file). The summary aggregates counts and groups across
the whole batch. Everything serializes with ``to_dict()`` so the
``--json`` envelope is stable and deterministic.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class BatchFileResult:
    """Outcome for one file in a batch run."""

    path: str  # as scanned (absolute or as-given)
    status: str  # "ok" | "skipped" | "error"
    analysis: dict[str, Any] | None = None  # Analysis.to_dict() when ok
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None  # human reason when status == "error"
    skipped_reason: str | None = None  # human reason when status == "skipped"
    anomaly_count: int = 0  # v0.6 engine flag count (0 when skipped/error)
    anomaly_rule_ids: list[str] = field(  # v0.9: rule ids for search index
        default_factory=list
    )
    thumbnail_count: int = 0  # v0.7 embedded thumbnails (0 when skipped/error)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DuplicateGroup:
    """Files sharing identical content (SHA-256)."""

    sha256: str
    files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GroupBucket:
    """One bucket of a grouping: files sharing a key."""

    key: str  # machine key (stable, sortable)
    display: str  # human label
    files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BatchSummary:
    """Aggregate counts for a batch run."""

    total_files: int = 0  # every regular file seen by the scan
    analyzed: int = 0  # status == "ok"
    skipped: int = 0  # not a recognized image format
    errors: int = 0  # unreadable / un-analyzable
    by_format: dict[str, int] = field(default_factory=dict)
    by_device: dict[str, int] = field(default_factory=dict)  # display -> count
    by_capture_day: dict[str, int] = field(default_factory=dict)
    by_location: dict[str, int] = field(default_factory=dict)
    duplicate_groups: int = 0
    duplicate_files: int = 0  # files sitting in any duplicate group
    files_with_gps: int = 0
    files_with_conflicts: int = 0  # >=1 DIFFER comparison fact (descriptive)
    files_with_anomalies: int = 0  # >=1 v0.6 anomaly flag
    total_anomaly_flags: int = 0  # v0.6 flags across the batch
    files_with_thumbnails: int = 0  # >=1 embedded thumbnail (v0.7)
    total_thumbnails: int = 0  # embedded thumbnails across the batch (v0.7)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CrossImageTimestamp:
    """One normalized timestamp claim attributed to its file (v0.5)."""

    path: str
    filename: str
    timestamp: dict[str, Any] = field(default_factory=dict)  # NormalizedTimestamp

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BatchReport:
    """Everything a `batch` run produces."""

    root: str
    recursive: bool
    jobs: int
    files: list[BatchFileResult] = field(default_factory=list)
    summary: BatchSummary = field(default_factory=BatchSummary)
    groups: dict[str, list[GroupBucket]] = field(default_factory=dict)
    duplicates: list[DuplicateGroup] = field(default_factory=list)
    timeline: list[CrossImageTimestamp] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["files"] = [f.to_dict() for f in self.files]
        d["summary"] = self.summary.to_dict()
        d["groups"] = {k: [b.to_dict() for b in v] for k, v in self.groups.items()}
        d["duplicates"] = [g.to_dict() for g in self.duplicates]
        d["timeline"] = [t.to_dict() for t in self.timeline]
        return d
