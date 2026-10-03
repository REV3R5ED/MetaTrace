"""Tests for MetaTrace v0.8 case management (SQLite case DB, chain of
custody, evidence manifests, flag reviews, reports)."""

from __future__ import annotations

import json
import sqlite3

import pytest

from metatrace import __version__
from metatrace.cases import (
    REVIEW_VERDICTS,
    CaseError,
    CaseStore,
    build_manifest,
    verify_case,
)
from metatrace.cases.manifest import flag_id_for, snapshot_flags
from metatrace.cli.main import main
from metatrace.core.plugins import get_registry


@pytest.fixture()
def state_dir(tmp_path, monkeypatch):
    """Isolated METATRACE_STATE_DIR for each test."""
    d = tmp_path / "state"
    monkeypatch.setenv("METATRACE_STATE_DIR", str(d))
    return d


@pytest.fixture()
def jpeg_evidence(tmp_path):
    from conftest import (
        build_jpeg_with_exif,
        build_tiff,
        standard_exif,
        standard_ifd0,
    )

    tiff = build_tiff(ifd0=standard_ifd0(), exif=standard_exif())
    p = tmp_path / "ev.jpg"
    p.write_bytes(build_jpeg_with_exif(tiff))
    return p


@pytest.fixture()
def store(state_dir):
    s = CaseStore()
    yield s
    s.close()


def _make_case(store: CaseStore, title: str = "t") -> str:
    case_id = store.next_case_id()
    store.create_case(case_id, title, "", "2026-10-03T00:00:00Z")
    return case_id


# ---------------------------------------------------------------------------
# Store basics
# ---------------------------------------------------------------------------


def test_case_id_sequencing(store):
    a = _make_case(store, "first")
    b = _make_case(store, "second")
    assert a != b
    assert a.startswith("MT-CASE-")
    assert a.endswith("-001")
    assert b.endswith("-002")


def test_create_and_get_case(store):
    case_id = _make_case(store, "hello")
    case = store.get_case(case_id)
    assert case.title == "hello"
    assert case.status == "open"
    assert store.list_cases()[0].id == case_id


def test_unknown_case_raises(store):
    with pytest.raises(CaseError, match="unknown case"):
        store.get_case("MT-CASE-2099-999")


def test_schema_version_mismatch_fails_cleanly(state_dir):
    db = state_dir / "cases.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA user_version = 99")
    conn.commit()
    conn.close()
    with pytest.raises(CaseError, match="schema version 99"):
        CaseStore()


def test_plugin_registered():
    info = get_registry().get("cases")
    assert info.version == "0.8.0"
    assert "case" in info.commands


# ---------------------------------------------------------------------------
# CLI lifecycle
# ---------------------------------------------------------------------------


def test_full_lifecycle(state_dir, jpeg_evidence, tmp_path, capsys):
    assert main(["case", "create", "--title", "lc", "--description", "d"]) == 0
    out = capsys.readouterr().out
    case_id = [w for w in out.split() if w.startswith("MT-CASE-")][0]

    assert main(["case", "add", case_id, str(jpeg_evidence), "--note", "n1"]) == 0
    ev_id = f"{case_id}-E01"
    assert main(["case", "note", case_id, "analyst note"]) == 0
    assert main(["case", "flags", case_id]) == 0
    assert main(["case", "manifest", case_id]) == 0
    assert main(["case", "verify", case_id]) == 0
    report_dir = tmp_path / "report"
    assert main(["case", "report", case_id, "--output", str(report_dir)]) == 0
    assert (report_dir / "report-manifest.json").exists()
    assert main(["case", "status", case_id, "closed", "--note", "resolved"]) == 0

    store = CaseStore()
    try:
        case = store.get_case(case_id)
        assert case.status == "closed"
        ev = store.get_evidence(case_id, ev_id)
        assert ev.sha256  # hash recorded
        snapshot = json.loads(ev.snapshot_json)
        assert "analysis" in snapshot  # full analyze snapshot frozen
        assert "anomalies" in snapshot
        # custody chain: create, add, note, manifest, report, status
        actions = [e.action for e in store.list_custody(case_id)]
        for expected in (
            "create",
            "add-evidence",
            "note",
            "manifest",
            "report",
            "status",
        ):
            assert expected in actions, actions
        # actor is always the local-user label
        assert {e.actor for e in store.list_custody(case_id)} == {"analyst"}
    finally:
        store.close()


def test_close_requires_note(state_dir, capsys):
    main(["case", "create", "--title", "c"])
    case_id = "MT-CASE-2026-001"
    assert main(["case", "status", case_id, "closed"]) == 2
    assert "requires --note" in capsys.readouterr().err
    store = CaseStore()
    try:
        assert store.get_case(case_id).status == "open"
    finally:
        store.close()


def test_verify_detects_changed_and_missing(state_dir, jpeg_evidence, tmp_path):
    main(["case", "create", "--title", "v"])
    case_id = "MT-CASE-2026-001"
    main(["case", "add", case_id, str(jpeg_evidence)])
    other = tmp_path / "other.jpg"
    other.write_bytes(jpeg_evidence.read_bytes())
    main(["case", "add", case_id, str(other)])

    # tamper with the first file, delete the second
    jpeg_evidence.write_bytes(b"\xff\xd8tampered")
    other.unlink()

    code = main(["case", "verify", case_id, "--json"])
    assert code == 1  # findings -> exit 1
    store = CaseStore()
    try:
        checks = verify_case(store, case_id)
    finally:
        store.close()
    by_id = {c["evidence_id"]: c["status"] for c in checks}
    assert by_id[f"{case_id}-E01"] == "changed"
    assert by_id[f"{case_id}-E02"] == "missing"


def test_review_append_only(state_dir, tmp_path):
    from conftest import (
        build_tiff,
        standard_exif,
        standard_ifd0,
    )

    # EXIF DateTimeOriginal vs XMP CreateDate conflict -> guaranteed flag.
    exif = tuple(e for e in standard_exif() if e[0] != 0x9003) + (
        (0x9003, 2, "2026:09:14 18:42:07"),
    )
    tiff = build_tiff(ifd0=standard_ifd0(), exif=exif)
    xmp = (
        b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta xmlns:x='adobe:ns:meta/'>"
        b"<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>"
        b"<rdf:Description rdf:about='' "
        b"xmlns:xmp='http://ns.adobe.com/xap/1.0/' "
        b"xmp:CreateDate='2026-09-15T09:00:00Z'/>"
        b"</rdf:RDF></x:xmpmeta>"
    )
    app1 = b"Exif\x00\x00" + tiff
    seg1 = b"\xff\xe1" + len(app1 + b"\x00\x00").to_bytes(2, "big") + app1
    seg2 = b"\xff\xe1" + (len(xmp) + 2).to_bytes(2, "big") + xmp
    sof0 = b"\xff\xc0\x00\x0b\x08\x00\x30\x00\x40\x01\x01\x11\x00"
    img = tmp_path / "conflict.jpg"
    img.write_bytes(b"\xff\xd8" + seg1 + seg2 + sof0 + b"\xff\xd9")

    main(["case", "create", "--title", "r"])
    case_id = "MT-CASE-2026-001"
    assert main(["case", "add", case_id, str(img)]) == 0
    store = CaseStore()
    try:
        ev = store.get_evidence(case_id, f"{case_id}-E01")
        flags = snapshot_flags(ev)
    finally:
        store.close()
    assert flags, "conflicting fixture must produce at least one flag"
    flag_id = flag_id_for(f"{case_id}-E01", flags[0]["rule_id"])
    assert (
        main(
            [
                "case",
                "review",
                case_id,
                "--flag",
                flag_id,
                "--verdict",
                "confirmed",
                "--note",
                "first look",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "case",
                "review",
                case_id,
                "--flag",
                flag_id,
                "--verdict",
                "dismissed",
                "--note",
                "second look",
            ]
        )
        == 0
    )
    store = CaseStore()
    try:
        reviews = store.list_reviews(case_id)
        assert len(reviews) == 2  # both kept, nothing overwritten
        assert [r.verdict for r in reviews] == ["confirmed", "dismissed"]
    finally:
        store.close()


def test_review_rejects_bad_flag_and_verdict(state_dir, jpeg_evidence, capsys):
    main(["case", "create", "--title", "r"])
    case_id = "MT-CASE-2026-001"
    main(["case", "add", case_id, str(jpeg_evidence)])
    ev_id = f"{case_id}-E01"
    assert (
        main(
            [
                "case",
                "review",
                case_id,
                "--flag",
                f"{ev_id}:nope",
                "--verdict",
                "confirmed",
            ]
        )
        == 2
    )
    assert "no flag" in capsys.readouterr().err
    assert (
        main(
            [
                "case",
                "review",
                case_id,
                "--flag",
                "badformat",
                "--verdict",
                "confirmed",
            ]
        )
        == 2
    )


def test_review_verdicts_are_valid_choices():
    assert set(REVIEW_VERDICTS) == {"confirmed", "dismissed", "unsure"}


def test_report_refuses_nonempty_without_force(state_dir, tmp_path, capsys):
    main(["case", "create", "--title", "r"])
    case_id = "MT-CASE-2026-001"
    out = tmp_path / "rep"
    out.mkdir()
    (out / "existing.txt").write_text("x")
    assert main(["case", "report", case_id, "--output", str(out)]) == 2
    assert "--force" in capsys.readouterr().err
    assert main(["case", "report", case_id, "--output", str(out), "--force"]) == 0


def test_manifest_sha256_is_canonical(state_dir, jpeg_evidence):
    import hashlib

    main(["case", "create", "--title", "m"])
    case_id = "MT-CASE-2026-001"
    main(["case", "add", case_id, str(jpeg_evidence)])
    store = CaseStore()
    try:
        manifest = build_manifest(store, case_id)
    finally:
        store.close()
    body = manifest.to_dict()
    digest = body.pop("sha256")
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    assert digest == hashlib.sha256(canonical.encode()).hexdigest()
    assert len(digest) == 64
    assert manifest.tool_version == __version__
    assert manifest.evidence[0]["snapshot_sha256"]  # snapshot hashed too


def test_report_manifest_hashes_match_artifacts(state_dir, tmp_path):
    import hashlib

    main(["case", "create", "--title", "r"])
    case_id = "MT-CASE-2026-001"
    out = tmp_path / "rep"
    main(["case", "report", case_id, "--output", str(out)])
    manifest = json.loads((out / "report-manifest.json").read_text())
    for name, digest in manifest["artifacts"].items():
        actual = hashlib.sha256((out / name).read_bytes()).hexdigest()
        assert actual == digest, name


def test_unknown_case_cli_errors(state_dir, capsys):
    assert main(["case", "show", "MT-CASE-2099-999"]) == 2
    assert "unknown case" in capsys.readouterr().err
    assert main(["case", "add", "MT-CASE-2099-999", "/tmp/x.jpg"]) == 2


def test_add_missing_file_errors(state_dir, capsys):
    main(["case", "create", "--title", "a"])
    assert main(["case", "add", "MT-CASE-2026-001", "/tmp/does-not-exist.jpg"]) == 2


def test_case_json_envelope(state_dir, jpeg_evidence, capsys):
    main(["case", "create", "--title", "j"])
    capsys.readouterr()  # drain the create output
    main(["case", "add", "MT-CASE-2026-001", str(jpeg_evidence), "--json"])
    out = capsys.readouterr().out
    envelope = json.loads(out)
    assert envelope["command"] == "case"
    assert envelope["data"]["case_action"] == "add"
    assert envelope["data"]["evidence"]["id"] == "MT-CASE-2026-001-E01"
