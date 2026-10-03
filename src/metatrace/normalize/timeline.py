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


def timeline_sort_key(ts: NormalizedTimestamp) -> tuple[int, str]:
    """Sort key implementing the v0.4 ordering rule.

    Public so batch (v0.5) cross-image timelines order identically to
    single-image timelines: UTC-known claims first chronologically,
    then timezone-naive claims by wall-clock, then unparseable.
    """
    if ts.value_utc is not None:
        return (0, ts.value_utc)
    if ts.wall is not None:
        return (1, ts.wall)
    return (2, ts.raw or "")


def build_timeline(
    timestamps: list[NormalizedTimestamp],
) -> list[NormalizedTimestamp]:
    """Return *timestamps* in chronological order (stable)."""
    return sorted(timestamps, key=timeline_sort_key)
