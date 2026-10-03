"""Anomaly engine orchestration (v0.6).

:func:`detect_anomalies` runs every deterministic rule against one
finished :class:`Analysis` and returns ``(flags, notes)``. Flags are
:class:`AnomalyFlag` judgments with confidence and explanations;
notes are informational (e.g. "cannot assess") and never flags.
"""

from __future__ import annotations

from metatrace.anomalies.rules import (
    rule_device_mismatch,
    rule_gps_timezone,
    rule_serial_conflict,
    rule_software_chain,
    rule_thumbnail_mismatch,
    rule_timestamp_conflict,
)
from metatrace.core.models import Analysis, AnomalyFlag


def detect_anomalies(
    analysis: Analysis, tolerance_s: float = 60.0
) -> tuple[list[AnomalyFlag], list[str]]:
    """Run the v0.7 rule set against *analysis*.

    *tolerance_s* is the timestamp-conflict tolerance in seconds.
    Never raises on partial analyses — missing pieces simply yield
    no flags from the rules that need them.
    """
    flags: list[AnomalyFlag] = []
    notes: list[str] = []
    flags.extend(rule_timestamp_conflict(analysis, tolerance_s))
    gps_flags, gps_notes = rule_gps_timezone(analysis)
    flags.extend(gps_flags)
    notes.extend(gps_notes)
    flags.extend(rule_device_mismatch(analysis))
    flags.extend(rule_serial_conflict(analysis))
    flags.extend(rule_software_chain(analysis))
    flags.extend(rule_thumbnail_mismatch(analysis))
    return flags, notes
