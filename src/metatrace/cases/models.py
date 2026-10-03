"""Data models for MetaTrace case management (v0.8).

Cases organize images under investigation with a chain of custody,
evidence manifests, analyst flag reviews and reproducible reports.

Forensic rule: the image file itself is NEVER copied into the case —
evidence records store the file's SHA-256, its path at add time, and a
full analysis snapshot (the JSON of the v0.7 ``analyze`` pipeline).
The hash lets ``case verify`` detect later modification; the snapshot
preserves exactly what the tool observed at add time.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Case lifecycle states.
CASE_STATUSES = ("open", "in-progress", "closed")

# Analyst verdicts on anomaly flags. Append-only: a review never deletes
# or rewrites the flag itself.
REVIEW_VERDICTS = ("confirmed", "dismissed", "unsure")


@dataclass
class CaseRecord:
    """One investigation case."""

    id: str  # e.g. "MT-CASE-2026-001"
    title: str
    description: str = ""
    created_utc: str = ""
    status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceRecord:
    """One image registered as evidence in a case.

    ``sha256`` is the file's hash at add time. ``snapshot`` is the full
    ``analyze`` result dict (analysis + anomalies + notes) serialized to
    JSON — what the tool observed, frozen at add time.
    """

    id: str  # e.g. "MT-CASE-2026-001-E01"
    case_id: str
    path: str  # path as given at add time (evidence is not copied)
    sha256: str
    added_utc: str
    note: str = ""
    snapshot_json: str = "{}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CustodyEvent:
    """One link in the chain of custody.

    Every case mutation (create, add, note, review, status, manifest,
    report) appends an event. ``actor`` is always the literal string
    ``"analyst"``: MetaTrace has no authentication, so the record states
    it was the local user of the machine, nothing stronger.
    """

    id: int = 0
    case_id: str = ""
    ts_utc: str = ""
    actor: str = "analyst"
    action: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalystNote:
    """Append-only analyst note on a case."""

    id: int = 0
    case_id: str = ""
    ts_utc: str = ""
    actor: str = "analyst"
    text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FlagReview:
    """Analyst review of one anomaly flag on one evidence item.

    ``flag_id`` is ``"<evidence-id>:<rule-id>"`` — deterministic, so the
    same flag reviewed twice keeps a visible history instead of one row
    being overwritten.
    """

    id: int = 0
    case_id: str = ""
    evidence_id: str = ""
    flag_id: str = ""
    rule_id: str = ""
    verdict: str = ""  # one of REVIEW_VERDICTS
    ts_utc: str = ""
    actor: str = "analyst"
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaseManifest:
    """Evidence manifest for a case.

    ``sha256`` is the SHA-256 of the canonical JSON encoding of the
    manifest body (sorted keys, no whitespace) — tamper evidence for the
    manifest itself, not a legal claim.
    """

    case_id: str
    generated_utc: str
    tool_version: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    custody_event_count: int = 0
    sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
