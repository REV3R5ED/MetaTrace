"""SQLite case database (v0.8).

The database lives at ``<state_dir>/cases.db`` (``state_dir()`` honors
``METATRACE_STATE_DIR``). Tables: cases, evidence, custody, notes,
flag_reviews, plus a per-year case-ID sequence.

Schema versioning: ``PRAGMA user_version`` carries the schema version
(currently 1). Migrations are out of scope — a database whose version
does not match fails cleanly with ``CaseError`` instead of being
silently misread.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from metatrace.cases.models import (
    AnalystNote,
    CaseRecord,
    CustodyEvent,
    EvidenceRecord,
    FlagReview,
)
from metatrace.core.logging import state_dir, utc_now_iso

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_utc TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id),
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    added_utc TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    snapshot_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE TABLE IF NOT EXISTS custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    ts_utc TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'analyst',
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_custody_case ON custody(case_id);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    ts_utc TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'analyst',
    text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_case ON notes(case_id);
CREATE TABLE IF NOT EXISTS flag_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    evidence_id TEXT NOT NULL,
    flag_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    ts_utc TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'analyst',
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_reviews_case ON flag_reviews(case_id);
CREATE TABLE IF NOT EXISTS case_seq (
    year INTEGER PRIMARY KEY,
    next_n INTEGER NOT NULL
);
"""


class CaseError(Exception):
    """Operational case error (unknown case, bad status, schema mismatch...)."""


def default_db_path() -> Path:
    return state_dir() / "cases.db"


class CaseStore:
    """SQLite-backed case storage. One instance per CLI invocation."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    # -- schema ------------------------------------------------------

    def _ensure_schema(self) -> None:
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._conn.commit()
        elif version != SCHEMA_VERSION:
            raise CaseError(
                f"cases database schema version {version} is not supported "
                f"(this build of metatrace expects {SCHEMA_VERSION}); "
                "migrations are not implemented — back up and remove the "
                f"database at {self.path} to start fresh"
            )

    def close(self) -> None:
        self._conn.close()

    # -- cases -------------------------------------------------------

    def next_case_id(self) -> str:
        year = datetime.now().year
        row = self._conn.execute(
            "SELECT next_n FROM case_seq WHERE year = ?", (year,)
        ).fetchone()
        n = row["next_n"] if row else 1
        if row:
            self._conn.execute(
                "UPDATE case_seq SET next_n = next_n + 1 WHERE year = ?",
                (year,),
            )
        else:
            self._conn.execute(
                "INSERT INTO case_seq (year, next_n) VALUES (?, ?)", (year, 2)
            )
        self._conn.commit()
        return f"MT-CASE-{year}-{n:03d}"

    def create_case(
        self, case_id: str, title: str, description: str, created_utc: str
    ) -> None:
        try:
            self._conn.execute(
                "INSERT INTO cases (id, title, description, created_utc, status)"
                " VALUES (?, ?, ?, ?, 'open')",
                (case_id, title, description, created_utc),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            raise CaseError(f"case {case_id} already exists") from exc

    def get_case(self, case_id: str) -> CaseRecord:
        row = self._conn.execute(
            "SELECT * FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        if row is None:
            raise CaseError(f"unknown case: {case_id}")
        return CaseRecord(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            created_utc=row["created_utc"],
            status=row["status"],
        )

    def list_cases(self) -> list[CaseRecord]:
        rows = self._conn.execute(
            "SELECT * FROM cases ORDER BY created_utc, id"
        ).fetchall()
        return [
            CaseRecord(
                id=r["id"],
                title=r["title"],
                description=r["description"],
                created_utc=r["created_utc"],
                status=r["status"],
            )
            for r in rows
        ]

    def set_status(self, case_id: str, status: str) -> None:
        self.get_case(case_id)  # raises if unknown
        self._conn.execute(
            "UPDATE cases SET status = ? WHERE id = ?", (status, case_id)
        )
        self._conn.commit()

    # -- evidence ----------------------------------------------------

    def next_evidence_id(self, case_id: str) -> str:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM evidence WHERE case_id = ?", (case_id,)
        ).fetchone()
        return f"{case_id}-E{row['n'] + 1:02d}"

    def add_evidence(self, record: EvidenceRecord) -> None:
        self._conn.execute(
            "INSERT INTO evidence (id, case_id, path, sha256, added_utc,"
            " note, snapshot_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                record.id,
                record.case_id,
                record.path,
                record.sha256,
                record.added_utc,
                record.note,
                record.snapshot_json,
            ),
        )
        self._conn.commit()

    def list_evidence(self, case_id: str) -> list[EvidenceRecord]:
        self.get_case(case_id)
        rows = self._conn.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY id", (case_id,)
        ).fetchall()
        return [
            EvidenceRecord(
                id=r["id"],
                case_id=r["case_id"],
                path=r["path"],
                sha256=r["sha256"],
                added_utc=r["added_utc"],
                note=r["note"],
                snapshot_json=r["snapshot_json"],
            )
            for r in rows
        ]

    def get_evidence(self, case_id: str, evidence_id: str) -> EvidenceRecord:
        row = self._conn.execute(
            "SELECT * FROM evidence WHERE case_id = ? AND id = ?",
            (case_id, evidence_id),
        ).fetchone()
        if row is None:
            raise CaseError(f"unknown evidence {evidence_id} in {case_id}")
        return EvidenceRecord(
            id=row["id"],
            case_id=row["case_id"],
            path=row["path"],
            sha256=row["sha256"],
            added_utc=row["added_utc"],
            note=row["note"],
            snapshot_json=row["snapshot_json"],
        )

    # -- custody -----------------------------------------------------

    def log_custody(self, case_id: str, action: str, detail: str = "") -> None:
        self._conn.execute(
            "INSERT INTO custody (case_id, ts_utc, actor, action, detail)"
            " VALUES (?, ?, 'analyst', ?, ?)",
            (case_id, utc_now_iso(), action, detail),
        )
        self._conn.commit()

    def list_custody(self, case_id: str) -> list[CustodyEvent]:
        self.get_case(case_id)
        rows = self._conn.execute(
            "SELECT * FROM custody WHERE case_id = ? ORDER BY id", (case_id,)
        ).fetchall()
        return [
            CustodyEvent(
                id=r["id"],
                case_id=r["case_id"],
                ts_utc=r["ts_utc"],
                actor=r["actor"],
                action=r["action"],
                detail=r["detail"],
            )
            for r in rows
        ]

    # -- notes -------------------------------------------------------

    def add_note(self, case_id: str, text: str) -> None:
        self.get_case(case_id)
        self._conn.execute(
            "INSERT INTO notes (case_id, ts_utc, actor, text)"
            " VALUES (?, ?, 'analyst', ?)",
            (case_id, utc_now_iso(), text),
        )
        self._conn.commit()

    def list_notes(self, case_id: str) -> list[AnalystNote]:
        self.get_case(case_id)
        rows = self._conn.execute(
            "SELECT * FROM notes WHERE case_id = ? ORDER BY id", (case_id,)
        ).fetchall()
        return [
            AnalystNote(
                id=r["id"],
                case_id=r["case_id"],
                ts_utc=r["ts_utc"],
                actor=r["actor"],
                text=r["text"],
            )
            for r in rows
        ]

    # -- flag reviews ------------------------------------------------

    def add_review(self, review: FlagReview) -> None:
        self._conn.execute(
            "INSERT INTO flag_reviews (case_id, evidence_id, flag_id,"
            " rule_id, verdict, ts_utc, actor, note)"
            " VALUES (?, ?, ?, ?, ?, ?, 'analyst', ?)",
            (
                review.case_id,
                review.evidence_id,
                review.flag_id,
                review.rule_id,
                review.verdict,
                utc_now_iso(),
                review.note,
            ),
        )
        self._conn.commit()

    def list_reviews(self, case_id: str) -> list[FlagReview]:
        self.get_case(case_id)
        rows = self._conn.execute(
            "SELECT * FROM flag_reviews WHERE case_id = ? ORDER BY id",
            (case_id,),
        ).fetchall()
        return [
            FlagReview(
                id=r["id"],
                case_id=r["case_id"],
                evidence_id=r["evidence_id"],
                flag_id=r["flag_id"],
                rule_id=r["rule_id"],
                verdict=r["verdict"],
                ts_utc=r["ts_utc"],
                actor=r["actor"],
                note=r["note"],
            )
            for r in rows
        ]

    # -- misc --------------------------------------------------------

    def stats(self, case_id: str) -> dict[str, Any]:
        """Counts for the case overview."""
        self.get_case(case_id)
        q = lambda t: self._conn.execute(  # noqa: E731
            f"SELECT COUNT(*) AS n FROM {t} WHERE case_id = ?", (case_id,)
        ).fetchone()["n"]
        return {
            "evidence": q("evidence"),
            "custody_events": q("custody"),
            "notes": q("notes"),
            "reviews": q("flag_reviews"),
        }
