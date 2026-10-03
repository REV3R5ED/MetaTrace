"""Evidence manifests and verification (v0.8).

A manifest freezes what a case contains: every evidence item's path,
SHA-256 at add time, and the SHA-256 of its analysis snapshot, plus
the custody-event count. The manifest's own SHA-256 (over the canonical
JSON encoding) is stored inside the manifest — tamper evidence for the
manifest, not a legal claim.

``verify_case`` re-hashes the image files on disk and compares against
the recorded hashes: ``changed`` / ``missing`` / ``ok`` per item.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from metatrace import __version__
from metatrace.cases.models import CaseManifest, EvidenceRecord
from metatrace.cases.store import CaseStore
from metatrace.core.hashing import HashingError, hash_file
from metatrace.core.logging import utc_now_iso


def _canonical_sha256(body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_manifest(store: CaseStore, case_id: str) -> CaseManifest:
    """Build the evidence manifest for a case (read-only)."""
    case = store.get_case(case_id)
    evidence = store.list_evidence(case_id)
    custody = store.list_custody(case_id)

    items: list[dict[str, Any]] = []
    for ev in evidence:
        items.append(
            {
                "evidence_id": ev.id,
                "path": ev.path,
                "sha256": ev.sha256,
                "added_utc": ev.added_utc,
                "note": ev.note,
                "snapshot_sha256": hashlib.sha256(
                    ev.snapshot_json.encode("utf-8")
                ).hexdigest(),
            }
        )

    manifest = CaseManifest(
        case_id=case.id,
        generated_utc=utc_now_iso(),
        tool_version=__version__,
        evidence=items,
        custody_event_count=len(custody),
    )
    body = manifest.to_dict()
    body.pop("sha256", None)
    manifest.sha256 = _canonical_sha256(body)
    return manifest


def verify_case(store: CaseStore, case_id: str) -> list[dict[str, Any]]:
    """Re-hash every evidence file on disk; report ok/changed/missing.

    Read-only with respect to the case DB (no custody event is logged —
    verification is an observation, not a mutation).
    """
    store.get_case(case_id)
    results: list[dict[str, Any]] = []
    for ev in store.list_evidence(case_id):
        entry: dict[str, Any] = {
            "evidence_id": ev.id,
            "path": ev.path,
            "expected_sha256": ev.sha256,
            "status": "ok",
            "actual_sha256": None,
        }
        p = Path(ev.path)
        if not p.is_file():
            entry["status"] = "missing"
        else:
            try:
                actual = hash_file(str(p), ["sha256"])["sha256"]
            except HashingError as exc:
                entry["status"] = "unreadable"
                entry["detail"] = str(exc)
            else:
                entry["actual_sha256"] = actual
                if actual != ev.sha256:
                    entry["status"] = "changed"
        results.append(entry)
    return results


def snapshot_flags(evidence: EvidenceRecord) -> list[dict[str, Any]]:
    """Anomaly flags stored in an evidence snapshot (may be empty)."""
    try:
        snapshot = json.loads(evidence.snapshot_json or "{}")
    except json.JSONDecodeError:
        return []
    flags = snapshot.get("anomalies") or []
    return [f for f in flags if isinstance(f, dict)]


def flag_id_for(evidence_id: str, rule_id: str) -> str:
    """Deterministic flag id: ``<evidence-id>:<rule-id>``."""
    return f"{evidence_id}:{rule_id}"
