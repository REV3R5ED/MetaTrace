"""Device normalization: maker/model/software across sources (v0.4).

Raw strings are never rewritten — each source's claim keeps its
verbatim form in the parser models. Normalization produces two
things per claim: a display-friendly canonical form (``*_norm``) and
a comparison key (``*_key``: lowercase alphanumeric) so that
"canon", "Canon " and "CANON INC." compare equal without mangling
the observed values.

Serial numbers are identifiers, not descriptions: they are kept
verbatim and never normalized.
"""

from __future__ import annotations

import re
from typing import Any

from metatrace.core.models import Analysis, DeviceClaim, DeviceIdentity

# Corporate suffixes stripped before make lookup ("Canon Inc." -> "Canon").
_CORP_SUFFIX_RE = re.compile(
    r"\s+(inc\.?|incorporated|corp\.?|corporation|co\.?,?\s*ltd\.?|ltd\.?|gmbh|s\.?a\.?|pty\.?|limited)$",
    re.IGNORECASE,
)

# Case-insensitive lookup -> canonical display form.
_KNOWN_MAKES = {
    "CANON": "Canon",
    "NIKON": "Nikon",
    "SONY": "Sony",
    "FUJIFILM": "Fujifilm",
    "FUJI": "Fujifilm",
    "PANASONIC": "Panasonic",
    "OLYMPUS": "Olympus",
    "OMSYSTEM": "OM System",
    "LEICA": "Leica",
    "APPLE": "Apple",
    "SAMSUNG": "Samsung",
    "GOOGLE": "Google",
    "HUAWEI": "Huawei",
    "XIAOMI": "Xiaomi",
    "HASSELBLAD": "Hasselblad",
    "PENTAX": "Pentax",
    "RICOH": "Ricoh",
    "DJI": "DJI",
    "GOPRO": "GoPro",
    "KODAK": "Kodak",
    "SIGMA": "Sigma",
    "TAMRON": "Tamron",
    "ONEPLUS": "OnePlus",
    "MOTOROLA": "Motorola",
    "LG": "LG",
    "SONYERICSSON": "Sony Ericsson",
}


def _collapse(text: str) -> str:
    """Strip, drop NULs, collapse internal whitespace."""
    return re.sub(r"\s+", " ", text.replace("\x00", "").strip())


def _key(text: str | None) -> str | None:
    """Comparison key: lowercase alphanumeric only."""
    if not text:
        return None
    key = re.sub(r"[^a-z0-9]", "", text.lower())
    return key or None


def normalize_make(raw: str | None) -> tuple[str | None, str | None]:
    """(display form, comparison key) for a maker string."""
    if not raw:
        return None, None
    clean = _collapse(raw)
    if not clean:
        return None, None
    base = _CORP_SUFFIX_RE.sub("", clean).strip()
    canonical = _KNOWN_MAKES.get(base.upper().replace(" ", "").replace("-", ""))
    if canonical is None:
        # Unknown maker: keep the observed form, collapsed. Do not
        # invent a canonical spelling for something unrecognized.
        canonical = base
    return canonical, _key(base)


def normalize_model(
    raw: str | None, make_norm: str | None, make_key: str | None
) -> tuple[str | None, str | None]:
    """(display form, comparison key) for a model string.

    When the maker is known and the model does not already name it,
    the canonical form is "Make Model" (e.g. "Canon EOS R5"). The key
    is derived from the canonical form, so "canon eos r5" and "EOS R5"
    (both with make "Canon") compare equal.
    """
    if not raw:
        return None, None
    clean = _collapse(raw)
    if not clean:
        return None, None
    display = clean
    model_key = _key(clean)
    if make_norm and make_key and model_key and not model_key.startswith(make_key):
        display = f"{make_norm} {clean}"
    return display, _key(display)


def normalize_software(raw: str | None) -> tuple[str | None, str | None]:
    """(display form, comparison key) for a software/creator-tool string."""
    if not raw:
        return None, None
    clean = _collapse(raw)
    if not clean:
        return None, None
    return clean, _key(clean)


def _claim_from_parts(
    source: str,
    make_raw: str | None,
    model_raw: str | None,
    software_raw: str | None,
) -> DeviceClaim | None:
    if not any((make_raw, model_raw, software_raw)):
        return None
    make_norm, make_key = normalize_make(make_raw)
    model_norm, model_key = normalize_model(model_raw, make_norm, make_key)
    software_norm, software_key = normalize_software(software_raw)
    return DeviceClaim(
        source=source,
        make_raw=make_raw,
        model_raw=model_raw,
        software_raw=software_raw,
        make_norm=make_norm,
        model_norm=model_norm,
        software_norm=software_norm,
        make_key=make_key,
        model_key=model_key,
        software_key=software_key,
    )


_TIFF_NS = "http://ns.adobe.com/tiff/1.0/"


def normalize_device(analysis: Analysis) -> DeviceIdentity:
    """Build the normalized device identity from all sources (v0.4).

    Sources: EXIF (make/model/software + serials) and XMP
    (tiff:Make/tiff:Model via exif_in_xmp, xmp:CreatorTool). IPTC
    carries no device fields.
    """
    identity = DeviceIdentity()
    exif = analysis.exif

    claim = _claim_from_parts("EXIF", exif.make, exif.model, exif.software)
    if claim is not None:
        identity.claims.append(claim)

    xmp_make: Any = analysis.xmp.exif_in_xmp.get(f"{_TIFF_NS}#Make")
    xmp_model: Any = analysis.xmp.exif_in_xmp.get(f"{_TIFF_NS}#Model")
    xmp_tool: Any = analysis.xmp.xmp_basic.get("creator_tool")
    claim = _claim_from_parts(
        "XMP tiff:Make/tiff:Model",
        xmp_make if isinstance(xmp_make, str) else None,
        xmp_model if isinstance(xmp_model, str) else None,
        xmp_tool if isinstance(xmp_tool, str) else None,
    )
    if claim is not None:
        identity.claims.append(claim)

    # Serials stay verbatim.
    identity.body_serial = exif.body_serial.strip() if exif.body_serial else None
    identity.lens_serial = exif.lens_serial.strip() if exif.lens_serial else None
    identity.camera_owner = exif.camera_owner.strip() if exif.camera_owner else None
    return identity
