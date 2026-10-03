"""Consistency/anomaly engine (v0.6).

Rule-based detectors over a finished :class:`Analysis`: timestamp
conflicts, GPS/timezone plausibility, device-identity and serial
mismatches, software-chain re-saves, and thumbnail aspect checks.
Every flag carries a rule id, severity, an honestly calibrated
confidence (certainty about the *observation*, never about intent),
a human explanation ending with what the observation does NOT prove,
the exact values compared, and the sources involved.
"""

from metatrace.anomalies.engine import detect_anomalies
from metatrace.core.models import AnomalyFlag

__all__ = ["AnomalyFlag", "detect_anomalies"]
