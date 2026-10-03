"""Parallel per-file analysis for batch runs (v0.5).

Each file goes through the full single-image pipeline
(:func:`metatrace.cli.main.analyze_image`): hash -> identify ->
EXIF -> XMP/IPTC/ICC -> normalize. Parsing is I/O-bound, so a
thread pool is the right tool; output ordering is by path regardless
of completion order, making runs deterministic.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from metatrace.batch.models import BatchFileResult
from metatrace.batch.scan import is_supported_image
from metatrace.core.config import AppConfig


def default_jobs() -> int:
    """Worker count when the user (and config) ask for 'auto'."""
    return max(1, min(4, os.cpu_count() or 1))


def _analyze_one(path: str, cfg: AppConfig, header_bytes: int) -> BatchFileResult:
    # Local import: keeps this module importable without pulling in
    # the CLI (and avoids a cli -> batch -> cli import cycle).
    from metatrace.cli.main import analyze_image

    if not is_supported_image(path, header_bytes):
        return BatchFileResult(
            path=path,
            status="skipped",
            skipped_reason="not a recognized image format (magic bytes)",
        )
    try:
        analysis, findings = analyze_image(path, cfg)
    except Exception as exc:  # per-file failure: record, never crash the batch
        return BatchFileResult(
            path=path, status="error", error=f"{type(exc).__name__}: {exc}"
        )
    assert analysis.identity is not None
    return BatchFileResult(
        path=path,
        status="ok",
        analysis=analysis.to_dict(),
        findings=[f.to_dict() for f in findings],
    )


def run_batch(
    paths: list[str],
    cfg: AppConfig,
    jobs: int,
    progress: Callable[[int, int], None] | None = None,
) -> list[BatchFileResult]:
    """Analyze *paths* in parallel; results sorted by path.

    *progress(done, total)* is called on the main thread after each
    file completes (pass None for silence).
    """
    header_bytes = int(cfg["identify_header_bytes"])
    total = len(paths)
    results: list[BatchFileResult] = []
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = {
            pool.submit(_analyze_one, path, cfg, header_bytes): path for path in paths
        }
        for future in as_completed(futures):
            results.append(future.result())
            done += 1
            if progress is not None:
                progress(done, total)
    results.sort(key=lambda r: r.path)
    return results


def stderr_progress(done: int, total: int) -> None:
    """Default human-run progress line (stderr only)."""
    print(f"metatrace: batch {done}/{total} files", file=sys.stderr)
