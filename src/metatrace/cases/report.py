"""Reproducible case report bundles (v0.8).

``build_report`` writes, into an output directory:
  case.json            — case metadata + counts
  evidence.json        — the evidence manifest (with its own SHA-256)
  custody.json         — the full chain-of-custody event list
  flags.json           — anomaly flags per evidence item, with reviews
  notes.txt            — analyst notes, chronological
  report-manifest.json — per-artifact SHA-256 digests

The report itself is a case mutation (it freezes a view of the case),
so the caller logs a custody event after a successful build.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from metatrace.cases.manifest import (
    build_manifest,
    flag_id_for,
    snapshot_flags,
)
from metatrace.cases.store import CaseError, CaseStore


def _write_json(path: Path, payload: Any) -> str:
    text = json.dumps(payload, indent=2, sort_keys=True)
    path.write_text(text + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_report(
    store: CaseStore, case_id: str, output_dir: str | Path, force: bool = False
) -> dict[str, Any]:
    """Write the report bundle. Returns the report manifest dict."""
    case = store.get_case(case_id)
    out = Path(output_dir)
    if out.exists() and any(out.iterdir()) and not force:
        raise CaseError(
            f"report output {out} already exists and is not empty "
            "(pass --force to overwrite)"
        )
    out.mkdir(parents=True, exist_ok=True)

    stats = store.stats(case_id)
    manifest = build_manifest(store, case_id)
    custody = [e.to_dict() for e in store.list_custody(case_id)]
    notes = [n.to_dict() for n in store.list_notes(case_id)]
    reviews = [r.to_dict() for r in store.list_reviews(case_id)]

    evidence = store.list_evidence(case_id)
    flags: list[dict[str, Any]] = []
    for ev in evidence:
        for f in snapshot_flags(ev):
            flags.append(
                {
                    "flag_id": flag_id_for(ev.id, f.get("rule_id", "")),
                    "evidence_id": ev.id,
                    **f,
                }
            )

    artifacts: dict[str, str] = {}
    artifacts["case.json"] = _write_json(
        out / "case.json", {**case.to_dict(), "counts": stats}
    )
    artifacts["evidence.json"] = _write_json(out / "evidence.json", manifest.to_dict())
    artifacts["custody.json"] = _write_json(out / "custody.json", custody)
    artifacts["flags.json"] = _write_json(
        out / "flags.json", {"flags": flags, "reviews": reviews}
    )
    notes_text = "\n\n".join(
        f"[{n['ts_utc']}] {n['actor']}: {n['text']}" for n in notes
    )
    notes_path = out / "notes.txt"
    notes_path.write_text(notes_text + ("\n" if notes_text else ""), encoding="utf-8")
    artifacts["notes.txt"] = hashlib.sha256(notes_path.read_bytes()).hexdigest()

    report_manifest = {
        "case_id": case.id,
        "artifacts": artifacts,
    }
    _write_json(out / "report-manifest.json", report_manifest)
    return {
        "output_dir": str(out),
        "artifacts": artifacts,
        "evidence_count": len(evidence),
        "flag_count": len(flags),
    }
