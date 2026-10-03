"""MetaTrace case management (v0.8).

Case management, chain of custody, evidence manifests and the SQLite
case database. Registered in the plugin registry as the ``cases``
module.
"""

from __future__ import annotations

from metatrace.cases.manifest import build_manifest, verify_case
from metatrace.cases.models import (
    CASE_STATUSES,
    REVIEW_VERDICTS,
    AnalystNote,
    CaseManifest,
    CaseRecord,
    CustodyEvent,
    EvidenceRecord,
    FlagReview,
)
from metatrace.cases.report import build_report
from metatrace.cases.store import CaseError, CaseStore, default_db_path
from metatrace.core.plugins import ModuleInfo, register

register(
    ModuleInfo(
        name="cases",
        description="Case management, chain of custody, evidence "
        "manifests, SQLite case DB (v0.8)",
        version="0.8.0",
        commands=["case"],
    )
)

__all__ = [
    "CASE_STATUSES",
    "REVIEW_VERDICTS",
    "AnalystNote",
    "CaseError",
    "CaseManifest",
    "CaseRecord",
    "CaseStore",
    "CustodyEvent",
    "EvidenceRecord",
    "FlagReview",
    "build_manifest",
    "build_report",
    "default_db_path",
    "verify_case",
]
