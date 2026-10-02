"""MetaTrace CLI: ``metatrace inspect <image>`` (v0.1).

Every command returns a shared result envelope, renders human-readable
text by default (``--json`` for automation), uses structured exit
codes (0 ok / 1 findings / 2 error), and writes an audit record.
Diagnostics go to stderr; stdout carries only the requested output.

Forensic posture: the source file is only ever opened read-only,
hashes are computed before any parsing, and parser failures are
recorded as warnings — never silent, never fatal.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from metatrace import __version__
from metatrace.core import config as config_mod
from metatrace.core.config import AppConfig, ConfigError
from metatrace.core.hashing import HashingError, hash_file
from metatrace.core.logging import audit_log, configure_logging, get_logger, utc_now_iso
from metatrace.core.models import Analysis
from metatrace.core.results import EXIT_ERROR, Finding, Result, exit_code_for
from metatrace.image import identify as identify_mod
from metatrace.parsers import exif as exif_mod

log = get_logger()


# ---------------------------------------------------------------------------
# Analysis pipeline
# ---------------------------------------------------------------------------


def analyze_image(path: str, cfg: AppConfig) -> tuple[Analysis, list[Finding]]:
    """Run the v0.1 pipeline: hash -> identify -> EXIF. Read-only."""
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
    size = p.stat().st_size
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

    analysis = Analysis(
        evidence_id="MT-" + hashes["sha256"][:16],
        tool_version=__version__,
        analyzed_at=utc_now_iso(),
        identity=identity,
        hashes=hashes,
        exif=exif,
        parser_warnings=list(exif.warnings),
    )
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
    result.summary = (
        f"{ident.filename}: {ident.format} {dims}, "
        f"{ident.size_bytes} bytes, {exif_note}"
    )
    return result


def cmd_config_show(args: argparse.Namespace, cfg: AppConfig) -> Result:
    result = Result(command="config show")
    result.data = cfg.to_dict()
    result.summary = f"profile {cfg.profile!r} from {cfg.source}"
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


def render_human(result: Result) -> str:
    lines: list[str] = []
    if result.summary:
        lines.append(result.summary)
    if result.status == "error":
        return "\n".join(lines) if lines else "error"

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
                "gps_ifd",
                "present (decoded in v0.2)" if exif_d["has_gps_ifd"] else "absent",
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
    return render_human(result)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="metatrace",
        description="MetaTrace — image forensics and metadata analysis "
        "(v0.1: core + file identification + basic EXIF). "
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
        help="identify a file, hash it, extract basic EXIF",
        parents=[output_parent],
    )
    p_inspect.add_argument("image", help="path to the image file (read-only)")
    p_inspect.add_argument(
        "--sha512",
        action="store_true",
        help="also compute SHA-512 (SHA-256 is always computed)",
    )
    p_inspect.set_defaults(func=cmd_inspect)

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
