"""Deterministic consistency rules (v0.6).

Each rule inspects one finished :class:`Analysis` and returns
``AnomalyFlag``s. No machine learning, no network, no learned
thresholds — every rule is a documented comparison with an honest
confidence number.

Confidence discipline: confidence measures certainty about the
*observation* (how far apart two timestamps are, how cleanly two
serials differ), never about *intent*. A high-confidence flag means
"the metadata really does disagree this much", not "this image was
manipulated". Every flag's explanation ends with a "what this does
NOT prove" line.
"""

from __future__ import annotations

import re
from datetime import datetime

from metatrace.core.models import Analysis, AnomalyFlag, NormalizedTimestamp

DOES_NOT_PROVE_MARKER = "What this does NOT prove:"

# Sources compared by the timestamp-conflict rule, in priority order.
_CAPTURE_SOURCES = (
    "EXIF DateTimeOriginal",
    "XMP xmp:CreateDate",
    "IPTC DateCreated/TimeCreated",
)

# XMP auxiliary namespace carrying exif:SerialNumber.
_AUX_SERIAL_KEY = "http://ns.adobe.com/exif/1.0/aux/#SerialNumber"

# Trailing version tokens stripped to get an editor's product name:
# "Adobe Photoshop 25.0" -> "Adobe Photoshop", "GIMP 2.10" -> "GIMP".
_VERSION_TAIL_RE = re.compile(r"[\s\-_]*v?\d+(\.\d+)*(\s+[A-Za-z]+)?\s*$")


def _flag(
    rule_id: str,
    severity: str,
    confidence: int,
    title: str,
    body: str,
    values: dict,
    sources: list[str],
    does_not_prove: str,
) -> AnomalyFlag:
    """Build a flag whose explanation ends with the does-not-prove line."""
    return AnomalyFlag(
        rule_id=rule_id,
        severity=severity,
        confidence=max(0, min(100, confidence)),
        title=title,
        explanation=f"{body}\n\n{DOES_NOT_PROVE_MARKER} {does_not_prove}",
        values=values,
        sources=sources,
        does_not_prove=does_not_prove,
    )


def _parse_dt(value: str | None) -> datetime | None:
    """Parse an ISO-8601 datetime or date; None when unparseable."""
    if not value:
        return None
    text = value.strip()
    try:
        if text.endswith(("Z", "z")):
            return datetime.fromisoformat(text[:-1] + "+00:00")
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _fmt_duration(seconds: float) -> str:
    s = int(round(seconds))
    if s < 120:
        return f"{s}s"
    minutes = s // 60
    if minutes < 120:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h{minutes % 60}m" if minutes % 60 else f"{hours}h"
    days = hours // 24
    return f"{days}d{hours % 24}h" if hours % 24 else f"{days}d"


def _fmt_offset(hours: float) -> str:
    sign = "+" if hours >= 0 else "-"
    total = abs(hours)
    hh = int(total)
    mm = int(round((total - hh) * 60))
    return f"UTC{sign}{hh:02d}:{mm:02d}"


def _capture_claims(analysis: Analysis) -> list[NormalizedTimestamp]:
    """Parseable capture-time claims from EXIF / XMP / IPTC."""
    return [
        t
        for t in analysis.timestamps
        if t.source in _CAPTURE_SOURCES and t.parseable and (t.value_utc or t.wall)
    ]


def _claim_instant(
    claim: NormalizedTimestamp,
) -> tuple[datetime | None, datetime | None]:
    """(UTC instant or None, wall-clock reading or None) for a claim."""
    return _parse_dt(claim.value_utc), _parse_dt(claim.wall)


def rule_timestamp_conflict(
    analysis: Analysis, tolerance_s: float = 60.0
) -> list[AnomalyFlag]:
    """Flag capture-time claims that disagree beyond *tolerance_s*.

    Timezone-aware claims compare by UTC instant; any pair involving
    a timezone-naive claim compares by wall-clock as written (the v0.4
    rule) and caps confidence at 60, because the disagreement may be a
    timezone offset rather than a real time difference. Day-precision
    claims (e.g. IPTC date-only) compare by calendar date.
    """
    claims = _capture_claims(analysis)
    if len(claims) < 2:
        return []

    best: tuple[float, NormalizedTimestamp, NormalizedTimestamp, bool] | None = None
    for i in range(len(claims)):
        for j in range(i + 1, len(claims)):
            a, b = claims[i], claims[j]
            a_utc, a_wall = _claim_instant(a)
            b_utc, b_wall = _claim_instant(b)
            naive = a.timezone_status == "naive" or b.timezone_status == "naive"
            if a.precision == "day" or b.precision == "day":
                if not a_wall or not b_wall:
                    continue
                diff = abs((a_wall.date() - b_wall.date()).days) * 86400.0
            elif a_utc is not None and b_utc is not None and not naive:
                diff = abs((a_utc - b_utc).total_seconds())
            elif a_wall is not None and b_wall is not None:
                diff = abs((a_wall - b_wall).total_seconds())
            else:
                continue
            if best is None or diff > best[0]:
                best = (diff, a, b, naive)

    if best is None:
        return []
    diff, _a, _b, naive = best
    if diff <= tolerance_s:
        return []

    if diff > 86400:
        severity, confidence = "high", 85
    elif diff > 3600:
        severity, confidence = "medium", 70
    else:
        severity, confidence = "low", 50
    naive_note = ""
    if naive:
        confidence = min(confidence, 60)
        naive_note = (
            " At least one compared claim is timezone-naive, so the "
            "comparison used wall-clock readings as written; part or all "
            "of the disagreement may be a timezone offset rather than a "
            "real time difference."
        )
    parts = "; ".join(
        f"{c.source} claims {c.raw!r}"
        + (" (timezone unknown)" if c.timezone_status == "naive" else "")
        for c in claims
    )
    body = (
        f"Capture-time claims disagree: {parts} — "
        f"{_fmt_duration(diff)} apart at most, beyond the "
        f"{tolerance_s:g}s tolerance.{naive_note}"
    )
    return [
        _flag(
            rule_id="timestamp-conflict",
            severity=severity,
            confidence=confidence,
            title=f"capture timestamps disagree by {_fmt_duration(diff)}",
            body=body,
            values={c.source: c.raw for c in claims},
            sources=[c.source for c in claims],
            does_not_prove=(
                "a timestamp conflict does not prove manipulation — camera "
                "clocks drift, timezone settings are often wrong, and "
                "editors routinely rewrite metadata timestamps."
            ),
        )
    ]


def rule_gps_timezone(
    analysis: Analysis,
) -> tuple[list[AnomalyFlag], list[str]]:
    """Check the capture timestamp's UTC offset against GPS longitude.

    Longitude implies a zone at 15° per hour; a ±2h tolerance covers
    borders and daylight saving. GPS + timezone-naive timestamps
    yields an informational note, never a flag — there is nothing to
    compare against.
    """
    gps = analysis.exif.gps
    if not (
        gps.present
        and gps.valid
        and gps.latitude is not None
        and gps.longitude is not None
    ):
        return [], []

    claim: NormalizedTimestamp | None = None
    for source in _CAPTURE_SOURCES:
        for t in analysis.timestamps:
            if (
                t.source == source
                and t.parseable
                and t.timezone_status == "explicit"
                and t.value_utc
                and t.wall
            ):
                claim = t
                break
        if claim is not None:
            break

    if claim is None:
        if any(
            t.source in _CAPTURE_SOURCES and t.parseable for t in analysis.timestamps
        ):
            return [], [
                "GPS coordinates are present but no capture timestamp carries "
                "timezone information, so UTC-offset plausibility cannot be "
                "assessed."
            ]
        return [], []

    utc = _parse_dt(claim.value_utc)
    wall = _parse_dt(claim.wall)
    if utc is None or wall is None:  # pragma: no cover - parseable claims parse
        return [], []
    actual_h = (
        wall.replace(tzinfo=None) - utc.replace(tzinfo=None)
    ).total_seconds() / 3600
    expected_h = gps.longitude / 15.0
    gap = abs(actual_h - expected_h)
    if gap <= 2:
        return [], []

    lon = gps.longitude
    body = (
        f"GPS claims longitude {lon:.2f}° (implied zone ≈ {_fmt_offset(expected_h)}) "
        f"but {claim.source} carries offset {_fmt_offset(actual_h)} "
        f"({claim.raw}); {gap:.1f}h from the longitude-implied zone, beyond "
        "the ±2h tolerance for borders and daylight saving."
    )
    return [
        _flag(
            rule_id="gps-timezone-implausible",
            severity="medium",
            confidence=55,
            title="capture timezone implausible for GPS longitude",
            body=body,
            values={
                "GPS longitude": f"{lon:.6f}",
                "implied zone": _fmt_offset(expected_h),
                claim.source: claim.raw,
                "claimed offset": _fmt_offset(actual_h),
            },
            sources=["EXIF GPS", claim.source],
            does_not_prove=(
                "an implausible offset does not prove the location is wrong — "
                "the camera's clock or timezone setting may be wrong, or the "
                "photo may have been taken while traveling."
            ),
        )
    ], []


def rule_device_mismatch(analysis: Analysis) -> list[AnomalyFlag]:
    """Flag EXIF vs XMP device-identity disagreements (post-normalization)."""
    facts = {c.fact: c for c in analysis.comparison}
    differing = [
        facts[f]
        for f in ("device_make", "device_model")
        if facts.get(f) and facts[f].status == "differ"
    ]
    if not differing:
        return []
    values: dict[str, str | None] = {}
    sources: list[str] = []
    bits: list[str] = []
    for fact in differing:
        for v in fact.values:
            values[f"{v.source} [{fact.fact}]"] = v.raw
            if v.source not in sources:
                sources.append(v.source)
        claims = "; ".join(f"{v.source} claims {v.raw!r}" for v in fact.values)
        bits.append(f"{fact.fact}: {claims}")
    body = (
        "Device identity differs across sources (compared after "
        "case/whitespace-insensitive normalization): " + "; ".join(bits) + "."
    )
    return [
        _flag(
            rule_id="device-identity-mismatch",
            severity="medium",
            confidence=65,
            title="device make/model differs across metadata sources",
            body=body,
            values=values,
            sources=sources,
            does_not_prove=(
                "a device mismatch does not prove forgery — metadata is often "
                "rewritten when images pass through editors, converters, or "
                "stock-photo pipelines."
            ),
        )
    ]


def rule_serial_conflict(analysis: Analysis) -> list[AnomalyFlag]:
    """Flag when EXIF and XMP carry different camera serial numbers."""
    device = analysis.device
    exif_serial = (device.body_serial if device else None) or None
    if exif_serial is not None:
        exif_serial = exif_serial.strip() or None
    aux = analysis.xmp.exif_in_xmp.get(_AUX_SERIAL_KEY)
    aux_serial = aux.strip() if isinstance(aux, str) and aux.strip() else None
    if not exif_serial or not aux_serial or exif_serial == aux_serial:
        return []
    return [
        _flag(
            rule_id="serial-number-conflict",
            severity="high",
            confidence=80,
            title="camera serial number differs across metadata sources",
            body=(
                f"EXIF BodySerialNumber is {exif_serial!r} but XMP "
                f"aux:SerialNumber is {aux_serial!r} — two sources name "
                "different cameras."
            ),
            values={
                "EXIF BodySerialNumber": exif_serial,
                "XMP aux:SerialNumber": aux_serial,
            },
            sources=["EXIF", "XMP aux:SerialNumber"],
            does_not_prove=(
                "a serial-number conflict does not prove the image is fake — "
                "serials are sometimes stripped, replaced, or miswritten by "
                "editing software; treat it as a lead, not a verdict."
            ),
        )
    ]


def _product_name(raw: str) -> str:
    """Editor product name with version tokens stripped."""
    return _VERSION_TAIL_RE.sub("", raw.strip()).strip() or raw.strip()


def rule_software_chain(analysis: Analysis) -> list[AnomalyFlag]:
    """Flag when EXIF Software and XMP CreatorTool name different editors.

    Same product at different versions ("Adobe Photoshop 25.0" vs
    "Adobe Photoshop") agrees — only genuinely different products flag.
    """
    device = analysis.device
    claims = {c.source: c for c in (device.claims if device else [])}
    exif_c = claims.get("EXIF")
    xmp_c = claims.get("XMP tiff:Make/tiff:Model")
    s1 = exif_c.software_raw if exif_c else None
    s2 = xmp_c.software_raw if xmp_c else None
    if not s1 or not s2:
        return []
    p1, p2 = _product_name(s1), _product_name(s2)
    if p1.lower() == p2.lower():
        return []
    return [
        _flag(
            rule_id="software-chain-resave",
            severity="low",
            confidence=60,
            title=f"different editors in metadata chain ({p1} vs {p2})",
            body=(
                f"EXIF Software claims {s1!r} but XMP xmp:CreatorTool claims "
                f"{s2!r} — the file passed through different editors (a "
                "re-save in the chain, not necessarily an edit of image "
                "content)."
            ),
            values={"EXIF Software": s1, "XMP xmp:CreatorTool": s2},
            sources=["EXIF", "XMP xmp:CreatorTool"],
            does_not_prove=(
                "different software tags do not prove forgery — many "
                "legitimate workflows pass images through multiple editors."
            ),
        )
    ]


def rule_thumbnail_mismatch(analysis: Analysis) -> list[AnomalyFlag]:
    """Flag thumbnail/main-image inconsistencies (v0.7, fuller comparison).

    Replaces the v0.6 aspect-only check. Three sub-checks, all
    metadata-level (no pixel decoding):
    - IFD1 claims a thumbnail but none was extractable -> medium
      ("stripped or unreadable thumbnail").
    - A thumbnail larger than the main image, or with an aspect
      differing beyond 5% -> medium / low respectively.
    - JPEG encoder signals (DQT count + DHT presence) differ on both
      axes between thumbnail and main image -> low, explicitly weak.
    Silent when the format has no thumbnail mechanism or no IFD1.
    """
    from metatrace.thumbnails.compare import compare_thumbnail

    flags: list[AnomalyFlag] = []
    ident = analysis.identity
    thumbs = analysis.thumbnails
    if not (ident and ident.width and ident.height):
        return []

    if analysis.exif.has_thumbnail_ifd and not thumbs.present:
        detail = "; ".join(thumbs.warnings) if thumbs.warnings else "no details"
        flags.append(
            _flag(
                rule_id="thumbnail-mismatch",
                severity="medium",
                confidence=60,
                title="IFD1 claims a thumbnail but none was extractable",
                body=(
                    "EXIF IFD1 exists, yet no thumbnail bytes could be "
                    f"extracted ({detail}) — the thumbnail may have been "
                    "stripped, or its offsets/lengths are corrupt."
                ),
                values={"has_thumbnail_ifd": True, "thumbnails_extracted": 0},
                sources=["EXIF IFD1"],
                does_not_prove=(
                    "a missing thumbnail does not prove manipulation — "
                    "many editors and converters drop embedded previews "
                    "when re-saving."
                ),
            )
        )
        return flags

    for thumb in thumbs.thumbnails:
        comp = compare_thumbnail(
            thumb,
            ident.width,
            ident.height,
            thumbs.main_dqt_count,
            thumbs.main_has_dht,
        )
        dims = (
            f"{thumb.width}x{thumb.height}"
            if thumb.width and thumb.height
            else "dimensions unknown"
        )
        if comp["larger_than_main"]:
            flags.append(
                _flag(
                    rule_id="thumbnail-mismatch",
                    severity="medium",
                    confidence=60,
                    title="embedded thumbnail larger than the main image",
                    body=(
                        f"thumbnail #{thumb.index} ({thumb.source}) is {dims} "
                        f"but the main image is {ident.width}x{ident.height} "
                        "— a preview larger than its image is unusual."
                    ),
                    values={
                        "main dimensions": f"{ident.width}x{ident.height}",
                        f"thumbnail #{thumb.index} dimensions": dims,
                        "thumbnail sha256": thumb.sha256[:16],
                    },
                    sources=["image header", thumb.source],
                    does_not_prove=(
                        "an oversized thumbnail does not prove manipulation — "
                        "it can result from container reuse or sloppy "
                        "metadata handling."
                    ),
                )
            )
        elif comp["aspect"] == "different":
            flags.append(
                _flag(
                    rule_id="thumbnail-mismatch",
                    severity="low",
                    confidence=45,
                    title="embedded thumbnail aspect differs from main image",
                    body=(
                        f"thumbnail #{thumb.index} ({thumb.source}): "
                        f"{comp['aspect_detail']}."
                    ),
                    values={
                        "main dimensions": f"{ident.width}x{ident.height}",
                        f"thumbnail #{thumb.index} dimensions": dims,
                    },
                    sources=["image header", thumb.source],
                    does_not_prove=(
                        "an aspect mismatch does not prove manipulation — "
                        "cameras and editors often generate thumbnails with "
                        "different cropping than the main image."
                    ),
                )
            )
        if comp["encoder"] == "different":
            flags.append(
                _flag(
                    rule_id="thumbnail-mismatch",
                    severity="low",
                    confidence=50,
                    title="thumbnail encoder signals differ from main image",
                    body=(
                        f"thumbnail #{thumb.index} ({thumb.source}): "
                        f"{comp['encoder_detail']}."
                    ),
                    values={
                        "main DQT tables": thumbs.main_dqt_count,
                        "main DHT present": thumbs.main_has_dht,
                        f"thumbnail #{thumb.index} DQT tables": thumb.dqt_count,
                        f"thumbnail #{thumb.index} DHT present": thumb.has_dht,
                    },
                    sources=["image header", thumb.source],
                    does_not_prove=(
                        "differing encoder signals do not prove the thumbnail "
                        "came from another image — encoders vary DQT/DHT "
                        "layout freely; this is a weak signal, not a verdict."
                    ),
                )
            )
    return flags
