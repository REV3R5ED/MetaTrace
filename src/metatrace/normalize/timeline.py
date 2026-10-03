"""Timelines: chronological ordering of normalized timestamps (v0.4).

v0.4 timelines cover a single image (multi-image timelines arrive
with batch processing in v0.5). Ordering rule, stated on the output:
timestamps with a known instant (UTC) sort first, chronologically;
timezone-naive claims sort after them by wall-clock, clearly labeled;
unparseable values sort last. Naive claims are never placed on the
UTC line — the timeline shows what is known, not what is guessed.
"""

from __future__ import annotations

from metatrace.core.models import NormalizedTimestamp


def _sort_key(ts: NormalizedTimestamp) -> tuple[int, str]:
    if ts.value_utc is not None:
        return (0, ts.value_utc)
    if ts.wall is not None:
        return (1, ts.wall)
    return (2, ts.raw or "")


def build_timeline(
    timestamps: list[NormalizedTimestamp],
) -> list[NormalizedTimestamp]:
    """Return *timestamps* in chronological order (stable)."""
    return sorted(timestamps, key=_sort_key)
