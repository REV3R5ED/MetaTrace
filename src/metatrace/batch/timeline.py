"""Cross-image timeline for batch runs (v0.5).

Every normalized timestamp claim from every analyzed file, ordered
by the v0.4 rule (:func:`timeline_sort_key`): UTC-known claims first
chronologically, then timezone-naive claims by wall-clock, then
unparseable. Ties break by filename, then path — fully deterministic.
"""

from __future__ import annotations

from metatrace.batch.models import BatchFileResult, CrossImageTimestamp
from metatrace.core.models import NormalizedTimestamp
from metatrace.normalize.timeline import timeline_sort_key


def build_cross_image_timeline(
    results: list[BatchFileResult],
) -> list[CrossImageTimestamp]:
    """Collect and order timestamp claims across all analyzed files."""
    entries: list[tuple[NormalizedTimestamp, str, str]] = []
    for result in results:
        if result.status != "ok" or not result.analysis:
            continue
        filename = (result.analysis.get("identity") or {}).get("filename")
        filename = filename or result.path
        for ts_dict in result.analysis.get("timestamps") or []:
            ts = NormalizedTimestamp(
                label=ts_dict.get("label", ""),
                source=ts_dict.get("source", ""),
                raw=ts_dict.get("raw"),
                value_utc=ts_dict.get("value_utc"),
                wall=ts_dict.get("wall"),
                precision=ts_dict.get("precision", "unknown"),
                timezone_status=ts_dict.get("timezone_status", "naive"),
                parseable=ts_dict.get("parseable", True),
            )
            entries.append((ts, filename, result.path))
    entries.sort(key=lambda e: (timeline_sort_key(e[0]), e[1], e[2]))
    return [
        CrossImageTimestamp(path=path, filename=filename, timestamp=ts.to_dict())
        for ts, filename, path in entries
    ]
