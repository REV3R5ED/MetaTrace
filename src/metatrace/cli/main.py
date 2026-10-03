"""MetaTrace CLI: ``metatrace inspect <image>`` / ``batch <dir>`` (v0.5).

Every command returns a shared result envelope, renders human-readable
text by default (``--json`` for automation, ``--csv`` for batch
tabular output), uses structured exit codes (0 ok / 1 findings /
2 error), and writes an audit record. Diagnostics go to stderr;
stdout carries only the requested output.

Forensic posture: the source file is only ever opened read-only,
hashes are computed before any parsing, and parser failures are
recorded as warnings — never silent, never fatal.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from metatrace import __version__
from metatrace.batch.grouping import LOCATION_GRID_NOTE, device_key_and_display
from metatrace.batch.runner import default_jobs, run_batch, stderr_progress
from metatrace.batch.scan import iter_candidate_files
from metatrace.batch.summary import build_report
from metatrace.core import config as config_mod
from metatrace.core.config import AppConfig, ConfigError
from metatrace.core.hashing import HashingError, hash_file
from metatrace.core.logging import audit_log, configure_logging, get_logger, utc_now_iso
from metatrace.core.models import Analysis
from metatrace.core.results import EXIT_ERROR, Finding, Result, exit_code_for
from metatrace.geo import LOCATION_DISCLAIMER, osm_link
from metatrace.image import identify as identify_mod
from metatrace.normalize import build_normalization
from metatrace.parsers import exif as exif_mod
from metatrace.parsers import icc as icc_mod
from metatrace.parsers import iptc as iptc_mod
from metatrace.parsers import xmp as xmp_mod

log = get_logger()


# ---------------------------------------------------------------------------
# Analysis pipeline
# ---------------------------------------------------------------------------


def analyze_image(path: str, cfg: AppConfig) -> tuple[Analysis, list[Finding]]:
    """Run the v0.4 pipeline: hash -> identify -> EXIF -> XMP/IPTC/ICC -> normalize.

    Read-only. Each parser is defensive: failures become warnings and
    findings, never exceptions.
    """
    findings: list[Finding] = []
    max_size = int(cfg["max_file_size_bytes"])
    header_bytes = int(cfg["identify_header_bytes"])

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"no such file: {path}")
    if p.is_dir():
        raise IsADirectoryError(f"not a regular file: {path}")
    if not p.is_file():
        raise ValueError(f"not a regular file: {path}")
    st = p.stat()
    size = st.st_size
    fs_mtime = st.st_mtime
    if max_size and size > max_size:
        raise ValueError(
            f"file is {size} bytes, over the {max_size}-byte limit "
            "(raise 'max_file_size_bytes' to override)"
        )

    # 1. Hash BEFORE analysis (forensic ordering).
    algos = list(cfg["hash_algorithms"])
    if "sha256" not in algos:
        algos = ["sha256", *algos]
    try:
        hashes = hash_file(path, algos)
    except HashingError as exc:
        raise OSError(str(exc)) from exc

    # 2. Identify format/dimensions from the header.
    identity = identify_mod.identify(path, header_bytes=header_bytes)
    if identity.format == "UNKNOWN":
        findings.append(
            Finding(
                title="unrecognized file format",
                severity="info",
                reason="magic bytes match no known image format; "
                "treated as opaque evidence",
                evidence=[f"first bytes: {identity.header_bytes_read} read"],
            )
        )

    # 3. EXIF (JPEG/TIFF containers only in v0.1).
    exif = exif_mod.extract_exif(
        path,
        identity.format,
        max_tags=int(cfg["exif_max_tags"]),
        max_value_bytes=int(cfg["exif_max_value_bytes"]),
    )
    for warning in exif.warnings:
        findings.append(
            Finding(
                title="EXIF parser warning",
                severity="low",
                reason=warning,
                evidence=["parser continued; partial results kept"],
            )
        )
    for issue in exif.gps.validity_issues:
        findings.append(
            Finding(
                title="GPS metadata validity issue",
                severity="low",
                reason=issue,
                evidence=[
                    "value kept in raw GPS tags (--json); "
                    "not used for normalized coordinates"
                ],
            )
        )

    # 4. XMP / IPTC / ICC (v0.3). Each extract() is defensive and never
    # raises; warnings become findings so nothing is silent.
    xmp = xmp_mod.extract_xmp(
        path,
        identity.format,
        max_tags=int(cfg["exif_max_tags"]),
        max_packet_bytes=int(cfg["xmp_max_packet_bytes"]),
    )
    iptc = iptc_mod.extract_iptc(path, identity.format)
    icc = icc_mod.extract_icc(
        path,
        identity.format,
        max_tags=int(cfg["exif_max_tags"]),
        max_profile_bytes=int(cfg["icc_max_profile_bytes"]),
    )
    for label, parsed in (("XMP", xmp), ("IPTC", iptc), ("ICC", icc)):
        for warning in parsed.warnings:
            findings.append(
                Finding(
                    title=f"{label} parser warning",
                    severity="low",
                    reason=warning,
                    evidence=["parser continued; partial results kept"],
                )
            )
    if icc.present and not icc.signature_valid:
        findings.append(
            Finding(
                title="ICC profile signature invalid",
                severity="medium",
                reason="embedded ICC profile fails the 'acsp' magic check; "
                "its color claims are not trustworthy",
                evidence=["header and tag directory still reported in --json"],
            )
        )

    analysis = Analysis(
        evidence_id="MT-" + hashes["sha256"][:16],
        tool_version=__version__,
        analyzed_at=utc_now_iso(),
        identity=identity,
        hashes=hashes,
        exif=exif,
        xmp=xmp,
        iptc=iptc,
        icc=icc,
        parser_warnings=list(exif.warnings)
        + list(xmp.warnings)
        + list(iptc.warnings)
        + list(icc.warnings),
    )

    # 5. v0.4 normalization: timestamps, device identity, descriptive
    # cross-source comparison, single-image timeline.
    findings.extend(build_normalization(analysis, fs_mtime))
    return analysis, findings


def cmd_inspect(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="inspect", target=args.image)
    if args.sha512 and "sha512" not in cfg["hash_algorithms"]:
        cfg = AppConfig(
            values={**cfg.values, "hash_algorithms": ["sha256", "sha512"]},
            profile=cfg.profile,
            source=cfg.source,
        )
    try:
        analysis, findings = analyze_image(args.image, cfg)
    except (FileNotFoundError, IsADirectoryError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    result.data = {"analysis": analysis.to_dict()}
    for finding in findings:
        result.add_finding(finding)
    ident = analysis.identity
    assert ident is not None
    dims = (
        f"{ident.width}x{ident.height}"
        if ident.width and ident.height
        else "dimensions unknown"
    )
    exif_note = (
        "EXIF present"
        if analysis.exif.present
        else ("no EXIF data" if ident.format in ("JPEG", "TIFF") else "EXIF n/a")
    )
    extra_kinds = [
        name
        for name, flag in (
            ("XMP", analysis.xmp.present),
            ("IPTC", analysis.iptc.present),
            ("ICC", analysis.icc.present),
        )
        if flag
    ]
    meta_note = exif_note + (" + " + " + ".join(extra_kinds) if extra_kinds else "")
    result.summary = (
        f"{ident.filename}: {ident.format} {dims}, "
        f"{ident.size_bytes} bytes, {meta_note}"
    )
    return result


def cmd_timeline(args: argparse.Namespace, cfg: AppConfig) -> Result:
    """v0.4: chronological list of every normalized timestamp claim."""
    result = Result(command="timeline", target=args.image)
    try:
        analysis, findings = analyze_image(args.image, cfg)
    except (FileNotFoundError, IsADirectoryError, ValueError, OSError) as exc:
        result.fail(str(exc))
        return result
    result.data = {
        "timeline": [t.to_dict() for t in analysis.timeline],
        "evidence_id": analysis.evidence_id,
    }
    for finding in findings:
        result.add_finding(finding)
    assert analysis.identity is not None
    result.summary = (
        f"timeline for {analysis.identity.filename}: "
        f"{len(analysis.timeline)} timestamp(s)"
    )
    return result


def cmd_config_show(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="config show")
    result.data = cfg.to_dict()
    result.summary = f"profile {cfg.profile!r} from {cfg.source}"
    return result


def _resolve_jobs(args: argparse.Namespace, cfg: AppConfig) -> int:
    if getattr(args, "jobs", None) is not None:
        jobs = int(args.jobs)
        if jobs < 1:
            raise ValueError("--jobs must be >= 1")
        return jobs
    configured = int(cfg["batch_jobs"])
    if configured > 0:
        return configured
    return default_jobs()


def cmd_batch(args: argparse.Namespace, cfg: AppConfig) -> Result:
    """v0.5: analyze every recognized image in a directory, in parallel."""
    result = Result(command="batch", target=args.directory)
    try:
        paths = iter_candidate_files(args.directory, recursive=args.recursive)
        jobs = _resolve_jobs(args, cfg)
    except (FileNotFoundError, NotADirectoryError, OSError, ValueError) as exc:
        result.fail(str(exc))
        return result

    quiet = bool(getattr(args, "json", False) or getattr(args, "csv", False))
    results = run_batch(
        paths,
        cfg,
        jobs,
        progress=None if quiet else stderr_progress,
    )
    report = build_report(
        root=args.directory,
        recursive=args.recursive,
        jobs=jobs,
        results=results,
        include_timeline=bool(getattr(args, "timeline", False)),
    )
    result.data = {"batch": report.to_dict()}

    summary = report.summary
    dup_note = (
        f", {summary.duplicate_groups} duplicate group(s)"
        if summary.duplicate_groups
        else ""
    )
    result.summary = (
        f"batch {args.directory}: {summary.analyzed} analyzed, "
        f"{summary.skipped} skipped, {summary.errors} errors{dup_note}"
    )

    # Envelope findings: skips and per-file errors are always worth
    # flagging; duplicates and conflicts are informational counts
    # (descriptive, never verdicts — v0.6 judges).
    for fr in report.files:
        if fr.status == "skipped":
            result.add_finding(
                Finding(
                    title="file skipped",
                    severity="info",
                    reason=f"{fr.path}: {fr.skipped_reason}",
                    evidence=["skipped files are listed in the batch report"],
                )
            )
        elif fr.status == "error":
            result.add_finding(
                Finding(
                    title="file failed analysis",
                    severity="medium",
                    reason=f"{fr.path}: {fr.error}",
                    evidence=["batch continued with the remaining files"],
                )
            )
    if report.duplicates:
        result.add_finding(
            Finding(
                title="duplicate files detected",
                severity="info",
                reason=f"{summary.duplicate_groups} group(s), "
                f"{summary.duplicate_files} file(s) share identical content "
                "(SHA-256); groups listed in the batch report",
                evidence=["exact content match only — no perceptual comparison"],
            )
        )
    if summary.files_with_conflicts:
        result.add_finding(
            Finding(
                title="files with conflicting timestamp claims",
                severity="info",
                reason=f"{summary.files_with_conflicts} file(s) have metadata "
                "sources that disagree on capture time (comparison status "
                "DIFFER); recorded descriptively, not judged",
                evidence=["per-file comparison facts in the batch report"],
            )
        )
    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _fmt_exif_value(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _render_gps_section(gps: dict[str, Any], args: argparse.Namespace) -> list[str]:
    """Render the GPS section. Coordinates are metadata claims, not proof."""
    lines = [""]
    if not gps["present"]:
        lines.append("GPS:          not present")
        return lines
    lines.append("GPS:")
    lines.append(f"  note         {LOCATION_DISCLAIMER}")
    lat, lon = gps["latitude"], gps["longitude"]
    if lat is not None and lon is not None:
        lines.append(f"  coordinates  {lat:.6f}, {lon:.6f}")
    else:
        lines.append("  coordinates  not decodable from GPS tags")
    if gps["altitude_m"] is not None:
        lines.append(f"  altitude     {gps['altitude_m']:.1f} m")
    if gps["bearing_deg"] is not None:
        ref = f" ({gps['bearing_ref']} north)" if gps["bearing_ref"] else ""
        lines.append(f"  bearing      {gps['bearing_deg']:.1f}\u00b0{ref}")
    if gps["gps_datetime_utc"] is not None:
        lines.append(f"  gps_time     {gps['gps_datetime_utc']}")
    if gps["processing_method"] is not None:
        lines.append(f"  method       {gps['processing_method']}")
    if gps["dop"] is not None:
        lines.append(f"  dop          {gps['dop']:.1f}")
    if not gps["valid"]:
        lines.append("  validity     INVALID:")
        for issue in gps["validity_issues"]:
            lines.append(f"    - {issue}")
    if (
        getattr(args, "map_link", False)
        and lat is not None
        and lon is not None
        and gps["valid"]
    ):
        lines.append(f"  map          {osm_link(lat, lon)}")
    lines.append(f"  raw tags:    {len(gps['raw_tags'])} captured")
    return lines


def _render_xmp_section(xmp: dict[str, Any]) -> list[str]:
    lines = [""]
    if not xmp["present"]:
        lines.append("XMP:          not present")
        return lines
    lines.append("XMP (normalized | raw packet + properties kept in --json):")
    dc = xmp["dublin_core"]
    basic = xmp["xmp_basic"]
    ps = xmp["photoshop"]
    for label, value in (
        ("dc:title", dc.get("title")),
        ("dc:creator", dc.get("creator")),
        ("dc:rights", dc.get("rights")),
        ("xmp:CreateDate", basic.get("create_date")),
        ("xmp:ModifyDate", basic.get("modify_date")),
        ("xmp:CreatorTool", basic.get("creator_tool")),
        ("xmp:Rating", basic.get("rating")),
        ("photoshop:Credit", ps.get("credit")),
        ("photoshop:Source", ps.get("source")),
    ):
        if value is not None:
            lines.append(f"  {label:<18} {_fmt_exif_value(value)}")
    lines.append(f"  namespaces:    {len(xmp['namespaces'])} seen")
    raw_props = sum(len(v) for v in xmp["raw_properties"].values())
    lines.append(f"  raw props:     {raw_props} captured")
    size_note = f"{len(xmp['raw_packet'])} chars"
    if xmp["packet_truncated"]:
        size_note += " (truncated)"
    lines.append(f"  raw packet:    {size_note}")
    return lines


def _render_iptc_section(iptc: dict[str, Any]) -> list[str]:
    lines = [""]
    if not iptc["present"]:
        lines.append("IPTC:         not present")
        return lines
    lines.append("IPTC/IIM (normalized | raw datasets kept in --json):")
    fields = iptc["fields"]
    for label, key in (
        ("object_name", "object_name"),
        ("headline", "headline"),
        ("caption", "caption"),
        ("keywords", "keywords"),
        ("byline", "byline"),
        ("credit", "credit"),
        ("source", "source"),
        ("copyright", "copyright_notice"),
        ("city", "city"),
        ("country", "country"),
        ("date_created", "date_created"),
        ("time_created", "time_created"),
    ):
        value = fields.get(key)
        if value is not None and value != []:
            lines.append(f"  {label:<18} {_fmt_exif_value(value)}")
    lines.append(f"  raw datasets:  {len(iptc['raw_datasets'])} captured")
    return lines


def _render_icc_section(icc: dict[str, Any]) -> list[str]:
    lines = [""]
    if not icc["present"]:
        lines.append("ICC:          not present")
        return lines
    lines.append("ICC profile (header + tag directory; no color math):")
    header = icc["header"]
    sig = "valid" if icc["signature_valid"] else "INVALID"
    for label, value in (
        ("signature", f"'acsp' check: {sig}"),
        ("device_class", header.get("device_class_name")),
        ("color_space", header.get("color_space")),
        ("pcs", header.get("pcs")),
        ("version", header.get("version")),
        ("created", header.get("created")),
        ("rendering_intent", header.get("rendering_intent_name")),
        ("manufacturer", header.get("device_manufacturer")),
        ("model", header.get("device_model")),
    ):
        if value is not None:
            lines.append(f"  {label:<18} {_fmt_exif_value(value)}")
    lines.append(f"  tags:          {len(icc['tags'])} in directory")
    return lines


def _render_comparison_section(analysis_data: dict[str, Any]) -> list[str]:
    """Descriptive cross-source comparison (v0.4).

    Records whether sources state the same thing — agree / differ /
    only-in-one-source — without resolving conflicts or judging them.
    Judging conflicts is the v0.6 anomaly engine's job.
    """
    facts = analysis_data.get("comparison") or []
    if not facts:
        return []
    lines = [""]
    lines.append("Cross-source comparison (descriptive — not a verdict):")
    for fact in facts:
        status = fact["status"].replace("-", " ")
        lines.append(f"  {fact['fact']}: {status.upper()}")
        for value in fact["values"]:
            lines.append(
                f"    {value['source']}: {_fmt_exif_value(value['normalized'])}"
            )
            if value["raw"] and str(value["raw"]) != str(value["normalized"]):
                lines.append(f"      raw: {value['raw']!r}")
        if not fact["values"]:
            lines.append("    (no parseable claims)")
    lines.append(
        "  note: timezone-aware claims compare by UTC instant; "
        "timezone-naive claims compare by wall-clock as written. "
        "Agreement or difference here is not an authenticity verdict."
    )
    return lines


def _render_timeline_section(timeline: list[dict[str, Any]]) -> list[str]:
    """Chronological list of timestamp claims (v0.4 `timeline` command)."""
    lines = [""]
    if not timeline:
        lines.append("No timestamp claims found.")
        return lines
    lines.append(
        "UTC-known claims first (chronological), then timezone-naive "
        "claims by wall-clock, then unparseable:"
    )
    for ts in timeline:
        if ts["value_utc"]:
            when = ts["value_utc"]
            tz = "utc" if ts["timezone_status"] == "utc" else "explicit->utc"
        elif ts["wall"]:
            when = f"{ts['wall']} (timezone unknown)"
            tz = "naive"
        else:
            when = f"unparseable: {ts['raw']!r}"
            tz = "n/a"
        lines.append(f"  {when:<38} {ts['source']} ({ts['label']}) [{tz}]")
    return lines


def _batch_file_brief(f: dict[str, Any]) -> str:
    """One compact line per file for human batch output."""
    name = Path(f["path"]).name
    if f["status"] == "skipped":
        return f"  {name:<32} skipped: {f['skipped_reason']}"
    if f["status"] == "error":
        return f"  {name:<32} ERROR: {f['error']}"
    a = f["analysis"]
    ident = a["identity"]
    _key, device = device_key_and_display(a)
    day = "date unknown"
    for ts in a.get("timestamps") or []:
        if ts.get("label") == "capture" and ts.get("parseable", True):
            day = (ts.get("value_utc") or ts.get("wall") or "?")[:10]
            break
    warns = len(a.get("parser_warnings") or [])
    warn_note = f" ({warns} warning{'s' if warns != 1 else ''})" if warns else ""
    return f"  {name:<32} {ident['format']:<6} {device:<24} {day}{warn_note}"


def _render_batch_timeline_section(
    entries: list[dict[str, Any]],
) -> list[str]:
    lines = [""]
    lines.append("Cross-image timeline (v0.4 ordering rule):")
    for entry in entries:
        ts = entry["timestamp"]
        if ts["value_utc"]:
            when = ts["value_utc"]
        elif ts["wall"]:
            when = f"{ts['wall']} (tz unknown)"
        else:
            when = f"unparseable: {ts['raw']!r}"
        lines.append(
            f"  {when:<34} {entry['filename']:<24} {ts['source']} ({ts['label']})"
        )
    return lines


def _render_batch_human(batch: dict[str, Any]) -> list[str]:
    """Human-readable batch report: summary tables + per-file lines."""
    lines: list[str] = []
    s = batch["summary"]
    lines.append("")
    lines.append(
        f"Files: {s['total_files']} total — {s['analyzed']} analyzed, "
        f"{s['skipped']} skipped, {s['errors']} errors"
    )

    def _table(title: str, counts: dict[str, int]) -> None:
        if not counts:
            return
        lines.append("")
        lines.append(f"{title}:")
        for key in sorted(counts):
            lines.append(f"  {key:<42} {counts[key]}")

    _table("Formats", s["by_format"])
    _table("Devices (normalized make + model claims)", s["by_device"])
    _table("Capture days (claimed)", s["by_capture_day"])

    if s["by_location"]:
        lines.append("")
        lines.append("Locations (GPS metadata claims):")
        lines.append(f"  note  {LOCATION_DISCLAIMER}")
        lines.append(f"  note  {LOCATION_GRID_NOTE}")
        for key in sorted(s["by_location"]):
            lines.append(f"  {key:<42} {s['by_location'][key]}")

    if batch["duplicates"]:
        lines.append("")
        lines.append(
            f"Duplicates ({len(batch['duplicates'])} group(s), "
            "exact SHA-256 content match):"
        )
        for group in batch["duplicates"]:
            lines.append(
                f"  sha256 {group['sha256'][:16]}… ({len(group['files'])} files):"
            )
            for path in group["files"]:
                lines.append(f"    {Path(path).name}")

    conflicted = [
        f["path"]
        for f in batch["files"]
        if f["status"] == "ok"
        and any(
            fact.get("status") == "differ"
            for fact in (f["analysis"].get("comparison") or [])
        )
    ]
    if conflicted:
        lines.append("")
        lines.append("Conflicting timestamp claims (descriptive — not a verdict):")
        for path in conflicted:
            lines.append(f"  {Path(path).name}")

    lines.append("")
    lines.append("Per-file results:")
    for f in batch["files"]:
        lines.append(_batch_file_brief(f))

    skipped = [f for f in batch["files"] if f["status"] == "skipped"]
    if skipped:
        lines.append("")
        lines.append("Skipped (not recognized images):")
        for f in skipped:
            lines.append(f"  {Path(f['path']).name}: {f['skipped_reason']}")
    errors = [f for f in batch["files"] if f["status"] == "error"]
    if errors:
        lines.append("")
        lines.append("Errors:")
        for f in errors:
            lines.append(f"  {Path(f['path']).name}: {f['error']}")

    if batch["timeline"]:
        lines.extend(_render_batch_timeline_section(batch["timeline"]))
    return lines


def _render_batch_csv(batch: dict[str, Any]) -> str:
    """One row per file: stable column order, QUOTE_MINIMAL."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "path",
            "filename",
            "status",
            "format",
            "width",
            "height",
            "size_bytes",
            "sha256",
            "make",
            "model",
            "software",
            "capture_day",
            "gps_latitude",
            "gps_longitude",
            "duplicate_group",
            "warnings",
            "error",
        ]
    )
    dup_of: dict[str, str] = {}
    for group in batch["duplicates"]:
        for path in group["files"]:
            dup_of[path] = group["sha256"][:16]
    for f in batch["files"]:
        if f["status"] != "ok" or not f["analysis"]:
            writer.writerow(
                [
                    f["path"],
                    Path(f["path"]).name,
                    f["status"],
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    dup_of.get(f["path"], ""),
                    "",
                    f.get("error") or f.get("skipped_reason") or "",
                ]
            )
            continue
        a = f["analysis"]
        ident = a["identity"]
        claims = (a.get("device") or {}).get("claims") or []
        exif_claim = next((c for c in claims if c.get("source") == "EXIF"), None)
        claim = exif_claim or (claims[0] if claims else {})
        day = ""
        for ts in a.get("timestamps") or []:
            if ts.get("label") == "capture" and ts.get("parseable", True):
                day = (ts.get("value_utc") or ts.get("wall") or "")[:10]
                break
        gps = (a.get("exif") or {}).get("gps") or {}
        writer.writerow(
            [
                f["path"],
                ident["filename"],
                "ok",
                ident["format"],
                ident["width"] if ident["width"] is not None else "",
                ident["height"] if ident["height"] is not None else "",
                ident["size_bytes"],
                (a.get("hashes") or {}).get("sha256", ""),
                claim.get("make_norm") or "",
                claim.get("model_norm") or "",
                claim.get("software_norm") or "",
                day,
                gps.get("latitude") if gps.get("latitude") is not None else "",
                gps.get("longitude") if gps.get("longitude") is not None else "",
                dup_of.get(f["path"], ""),
                len(a.get("parser_warnings") or []),
                "",
            ]
        )
    return buf.getvalue().rstrip("\n")


def render_human(result: Result, args: argparse.Namespace) -> str:
    lines: list[str] = []
    if result.summary:
        lines.append(result.summary)
    if result.status == "error":
        return "\n".join(lines) if lines else "error"

    if result.command == "batch":
        batch = result.data.get("batch")
        if batch:
            lines.extend(_render_batch_human(batch))
        if result.findings:
            lines.append("")
            lines.append("Findings:")
            for f in result.findings:
                lines.append(f"  [{f.severity}] {f.title}")
                if f.reason:
                    lines.append(f"    {f.reason}")
        return "\n".join(lines)

    if result.command == "timeline":
        timeline = result.data.get("timeline") or []
        lines.extend(_render_timeline_section(timeline))
        if result.findings:
            lines.append("")
            lines.append("Findings:")
            for f in result.findings:
                lines.append(f"  [{f.severity}] {f.title}")
                if f.reason:
                    lines.append(f"    {f.reason}")
        return "\n".join(lines)

    analysis_data = result.data.get("analysis")
    if not analysis_data:
        if result.data:
            lines.append("")
            lines.append(json.dumps(result.data, indent=2))
        return "\n".join(lines)

    ident = analysis_data["identity"]
    lines.append(f"evidence_id:  {analysis_data['evidence_id']}")
    lines.append(f"file:         {ident['path']} ({ident['size_bytes']} bytes)")
    dims = (
        f"{ident['width']}x{ident['height']}"
        if ident["width"] and ident["height"]
        else "unknown"
    )
    lines.append(
        f"format:       {ident['format']} ({ident['mime'] or 'unknown mime'}), {dims}"
    )
    if ident["encoding"]:
        lines.append(f"encoding:     {ident['encoding']}")
    for algo, digest in analysis_data["hashes"].items():
        lines.append(f"{algo}:      {digest}")
    lines.append(f"analyzed_at:  {analysis_data['analyzed_at']} (UTC)")
    lines.append(f"tool:         metatrace {analysis_data['tool_version']}")

    exif_d: dict[str, Any] = analysis_data["exif"]
    lines.append("")
    if not exif_d["present"]:
        lines.append("EXIF:         not present")
    else:
        lines.append("EXIF (normalized | raw kept in --json):")
        rows = [
            ("make", exif_d["make"]),
            ("model", exif_d["model"]),
            ("software", exif_d["software"]),
            ("lens", exif_d["lens_model"]),
            ("body_serial", exif_d.get("body_serial")),
            ("lens_serial", exif_d.get("lens_serial")),
            ("camera_owner", exif_d.get("camera_owner")),
            (
                "orientation",
                f"{exif_d['orientation']} ({exif_d['orientation_name']})"
                if exif_d["orientation"] is not None
                else None,
            ),
            (
                "datetime_original",
                _fmt_exif_value(exif_d["datetime_original"])
                + (
                    " (timezone unknown)"
                    if exif_d["datetime_original"] and not exif_d["timezone_known"]
                    else ""
                )
                if exif_d["datetime_original"] or exif_d["datetime_original_raw"]
                else None,
            ),
            ("datetime_digitized", exif_d["datetime_digitized"]),
            ("iso", exif_d["iso"]),
            (
                "exposure",
                f"{exif_d['exposure_time']} ({exif_d['exposure_seconds']:.6f}s)"
                if exif_d["exposure_time"]
                else None,
            ),
            ("f_number", f"f/{exif_d['f_number']}" if exif_d["f_number"] else None),
            (
                "focal_length",
                f"{exif_d['focal_length_mm']}mm" if exif_d["focal_length_mm"] else None,
            ),
            (
                "flash",
                "fired"
                if exif_d["flash_fired"]
                else "did not fire"
                if exif_d["flash"] is not None
                else None,
            ),
            (
                "thumbnail_ifd",
                "present" if exif_d["has_thumbnail_ifd"] else "absent",
            ),
        ]
        for label, value in rows:
            if value is not None:
                lines.append(f"  {label:<18} {_fmt_exif_value(value)}")
        lines.append(f"  raw tags:      {len(exif_d['raw_tags'])} captured")

    lines.extend(_render_gps_section(analysis_data["exif"]["gps"], args))
    lines.extend(_render_xmp_section(analysis_data["xmp"]))
    lines.extend(_render_iptc_section(analysis_data["iptc"]))
    lines.extend(_render_icc_section(analysis_data["icc"]))
    lines.extend(_render_comparison_section(analysis_data))

    if analysis_data["parser_warnings"]:
        lines.append("")
        lines.append("Parser warnings:")
        for w in analysis_data["parser_warnings"]:
            lines.append(f"  - {w}")

    if result.findings:
        lines.append("")
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity}] {f.title}")
            if f.reason:
                lines.append(f"    {f.reason}")
    return "\n".join(lines)


def render(result: Result, args: argparse.Namespace) -> str:
    if args.json:
        return json.dumps(result.to_dict(), indent=2)
    if getattr(args, "csv", False) and result.command == "batch":
        batch = result.data.get("batch")
        if batch:
            return _render_batch_csv(batch)
    return render_human(result, args)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="metatrace",
        description="MetaTrace — image forensics and metadata analysis "
        "(v0.5: core + file identification + full EXIF/GPS + XMP/IPTC/ICC + "
        "timestamp/device normalization + cross-source comparison + timelines + "
        "batch analysis). "
        "Trace the story behind the image. MIT licensed.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="debug diagnostics on stderr"
    )
    parser.add_argument("--config", default=None, help="path to JSON config file")
    parser.add_argument("--profile", default="default", help="config profile name")
    parser.add_argument(
        "--json", action="store_true", help="emit result envelope as JSON"
    )

    # --json must also work after the subcommand. The parent's default is
    # SUPPRESS so it never clobbers a --json given before the subcommand.
    output_parent = argparse.ArgumentParser(add_help=False)
    output_parent.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="emit result envelope as JSON",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser(
        "inspect",
        help="identify a file, hash it, extract EXIF + GPS + XMP/IPTC/ICC, "
        "normalize timestamps/devices, compare across sources",
        parents=[output_parent],
    )
    p_inspect.add_argument("image", help="path to the image file (read-only)")
    p_inspect.add_argument(
        "--sha512",
        action="store_true",
        help="also compute SHA-512 (SHA-256 is always computed)",
    )
    p_inspect.add_argument(
        "--map-link",
        action="store_true",
        help="print an OpenStreetMap URL for decoded GPS coordinates "
        "(URL only, no network request)",
    )
    p_inspect.set_defaults(func=cmd_inspect)

    p_timeline = sub.add_parser(
        "timeline",
        help="chronological list of every normalized timestamp claim",
        parents=[output_parent],
    )
    p_timeline.add_argument("image", help="path to the image file (read-only)")
    p_timeline.set_defaults(func=cmd_timeline)

    p_batch = sub.add_parser(
        "batch",
        help="analyze every recognized image in a directory (parallel), "
        "with duplicate detection and grouping",
        parents=[output_parent],
    )
    p_batch.add_argument(
        "directory", help="directory to scan (read-only; files are never modified)"
    )
    p_batch.add_argument(
        "--recursive",
        action="store_true",
        help="descend into subdirectories (symlinked directories are not followed)",
    )
    p_batch.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="parallel worker threads (default: config 'batch_jobs', "
        "or min(4, CPU count) when 0/unset)",
    )
    p_batch.add_argument(
        "--timeline",
        action="store_true",
        help="include a cross-image timeline of every timestamp claim",
    )
    p_batch.add_argument(
        "--csv",
        action="store_true",
        help="emit one CSV row per file instead of human-readable output",
    )
    p_batch.set_defaults(func=cmd_batch)

    p_config = sub.add_parser("config", help="configuration")
    config_sub = p_config.add_subparsers(dest="config_command", required=True)
    p_show = config_sub.add_parser(
        "show", help="show effective configuration", parents=[output_parent]
    )
    p_show.set_defaults(func=cmd_config_show)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    try:
        cfg = config_mod.load_config(path=args.config, profile=args.profile)
    except ConfigError as exc:
        print(f"metatrace: error: {exc}", file=sys.stderr)
        audit_log(
            {
                "command": "config-load",
                "argv": list(argv or []),
                "exit_code": EXIT_ERROR,
            }
        )
        return EXIT_ERROR

    try:
        result: Result = args.func(args, cfg)
    except KeyboardInterrupt:
        print("metatrace: interrupted", file=sys.stderr)
        return EXIT_ERROR

    output = render(result, args)
    if output:
        print(output)
    code = exit_code_for(result)
    if result.status == "error" and result.summary:
        print(f"metatrace: error: {result.summary}", file=sys.stderr)
    audit_log(
        {
            "command": result.command,
            "target": result.target,
            "status": result.status,
            "exit_code": code,
        }
    )
    return code
