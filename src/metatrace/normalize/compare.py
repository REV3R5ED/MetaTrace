"""Cross-field comparison across metadata sources (v0.4).

This module is descriptive bookkeeping, not analysis: for each
logical fact (capture time, device make/model, software chain) it
places each source's claim side by side and records whether the
claims agree, differ, or exist in only one source. It never resolves
a conflict, never scores it, never calls anything suspicious — that
judgment is the v0.6 anomaly engine's job. Every fact carries a
``note`` explaining the comparison rule that was applied, so an
analyst can see exactly what "agree" meant here.

Timezone-naive timestamps compare by wall-clock; a naive claim and a
timezone-aware claim are compared as written (their keys differ by
construction) with the note saying so.
"""

from __future__ import annotations

from metatrace.core.models import (
    ComparedValue,
    ComparisonFact,
    DeviceIdentity,
    NormalizedTimestamp,
)

_DESCRIPTIVE_NOTE = (
    "This comparison is descriptive: it records whether sources state "
    "the same thing. Agreement or difference is not a verdict on "
    "authenticity — judging conflicts is the v0.6 anomaly engine's job."
)


def _status_for(values: list[ComparedValue]) -> str:
    if not values:
        return "no-data"
    if len(values) == 1:
        return "only-in-one-source"
    keys = {v.key for v in values}
    return "agree" if len(keys) == 1 else "differ"


def _compare_capture_time(
    timestamps: list[NormalizedTimestamp],
) -> ComparisonFact:
    """The capture-time claim per source: EXIF, XMP, IPTC."""
    wanted = {
        "EXIF DateTimeOriginal",
        "XMP xmp:CreateDate",
        "IPTC DateCreated/TimeCreated",
    }
    values: list[ComparedValue] = []
    for ts in timestamps:
        if ts.source not in wanted or not ts.parseable:
            continue
        if ts.value_utc is not None:
            key = f"utc:{ts.value_utc}"
            shown = ts.value_utc
        elif ts.wall is not None:
            key = f"naive:{ts.wall}"
            shown = f"{ts.wall} (timezone unknown)"
        else:  # pragma: no cover - defensive
            continue
        values.append(
            ComparedValue(source=ts.source, raw=ts.raw, normalized=shown, key=key)
        )
    status = _status_for(values)
    note = (
        "Timezone-aware claims compare by UTC instant; timezone-naive "
        "claims (no offset recorded) compare by wall-clock as written. "
        "A naive claim never silently converts to UTC. " + _DESCRIPTIVE_NOTE
    )
    return ComparisonFact(fact="capture_time", status=status, values=values, note=note)


def _compare_device_field(
    device: DeviceIdentity, fact: str, attr: str
) -> ComparisonFact:
    """One device field (make/model/software) across source claims."""
    values: list[ComparedValue] = []
    for claim in device.claims:
        norm = getattr(claim, f"{attr}_norm")
        key = getattr(claim, f"{attr}_key")
        raw = getattr(claim, f"{attr}_raw")
        if norm is None or key is None:
            continue
        values.append(
            ComparedValue(source=claim.source, raw=raw, normalized=norm, key=key)
        )
    status = _status_for(values)
    labels = {
        "device_make": "device maker",
        "device_model": "device model",
        "software": "software/creator tool",
    }
    note = (
        f"Claims of {labels[fact]} compare by normalized key "
        "(case/whitespace/punctuation-insensitive); raw values are shown "
        "verbatim. " + _DESCRIPTIVE_NOTE
    )
    return ComparisonFact(fact=fact, status=status, values=values, note=note)


def compare_sources(
    timestamps: list[NormalizedTimestamp], device: DeviceIdentity
) -> list[ComparisonFact]:
    """Build the four descriptive comparison facts for v0.4."""
    return [
        _compare_capture_time(timestamps),
        _compare_device_field(device, "device_make", "make"),
        _compare_device_field(device, "device_model", "model"),
        _compare_device_field(device, "software", "software"),
    ]
