"""Timestamp & device normalization, cross-field comparison, timelines.

v0.4. Every timestamp flavor MetaTrace has seen so far is parsed into
one common model (:class:`NormalizedTimestamp`): EXIF datetimes
(optionally with OffsetTime*), XMP ISO-8601 dates, IPTC
DateCreated+TimeCreated, GPS UTC stamps, ICC creation time, and the
filesystem mtime (labeled as filesystem, never confused with image
metadata).

Forensic rule: a timezone is never invented. Timezone-naive claims
keep ``value_utc=None``; they compare by wall-clock only, and the
comparison output says so. Unparseable values are kept verbatim with
``parseable=False`` — never silently dropped.
"""

from metatrace.core.models import Analysis
from metatrace.core.results import Finding
from metatrace.normalize.compare import ComparisonFact, compare_sources
from metatrace.normalize.devices import DeviceIdentity, normalize_device
from metatrace.normalize.timeline import build_timeline
from metatrace.normalize.timestamps import (
    NormalizedTimestamp,
    collect_timestamps,
)

__all__ = [
    "NormalizedTimestamp",
    "DeviceIdentity",
    "ComparisonFact",
    "build_normalization",
    "build_timeline",
    "collect_timestamps",
    "compare_sources",
    "normalize_device",
]


def build_normalization(analysis: Analysis, fs_mtime: float) -> list[Finding]:
    """Fill the v0.4 fields of *analysis* in place.

    Collects normalized timestamps (including the filesystem mtime),
    normalizes device identity, builds the descriptive cross-source
    comparison and the chronological timeline. Returns findings —
    currently only low-severity "unparseable timestamp" notes for
    sources whose failures the parsers did not already report.
    """
    timestamps = collect_timestamps(analysis, fs_mtime)
    analysis.timestamps = timestamps
    analysis.device = normalize_device(analysis)
    analysis.comparison = compare_sources(timestamps, analysis.device)
    analysis.timeline = build_timeline(timestamps)

    findings: list[Finding] = []
    for ts in timestamps:
        if ts.parseable or ts.raw is None:
            continue
        # EXIF/GPS/ICC parse failures already surface as parser
        # warnings or validity findings; only XMP/IPTC need a new note.
        if ts.source.startswith(("XMP", "IPTC")):
            findings.append(
                Finding(
                    title="unparseable timestamp",
                    severity="low",
                    reason=f"{ts.source} carries a timestamp MetaTrace "
                    f"could not parse: {ts.raw!r}; kept verbatim",
                    evidence=["raw value preserved in --json output"],
                )
            )
    return findings
