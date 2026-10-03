"""Filtered cross-image timeline for v0.9 search.

Reuses the v0.4 ordering rule (:func:`timeline_sort_key`): UTC-known
claims first chronologically, then timezone-naive claims by
wall-clock, then unparseable. Ties break by filename, then path —
fully deterministic.
"""

from __future__ import annotations

from typing import Any

from metatrace.core.models import NormalizedTimestamp
from metatrace.normalize.timeline import timeline_sort_key
from metatrace.search.models import IndexRecord


def _to_timestamp(ts_dict: dict[str, Any]) -> NormalizedTimestamp:
    return NormalizedTimestamp(
        label=ts_dict.get("label", ""),
        source=ts_dict.get("source", ""),
        raw=ts_dict.get("raw"),
        value_utc=ts_dict.get("value_utc"),
        wall=ts_dict.get("wall"),
        precision=ts_dict.get("precision", "unknown"),
        timezone_status=ts_dict.get("timezone_status", "naive"),
        parseable=ts_dict.get("parseable", True),
    )


def build_search_timeline(records: list[IndexRecord]) -> list[dict[str, Any]]:
    """Every timestamp claim from *records*, ordered by the v0.4 rule."""
    entries: list[tuple[NormalizedTimestamp, str, str]] = []
    for record in records:
        for ts_dict in record.timestamps:
            entries.append((_to_timestamp(ts_dict), record.filename, record.path))
    entries.sort(key=lambda e: (timeline_sort_key(e[0]), e[1], e[2]))
    return [
        {"path": path, "filename": filename, "timestamp": ts.to_dict()}
        for ts, filename, path in entries
    ]
