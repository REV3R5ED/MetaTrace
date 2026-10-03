"""Metadata-level thumbnail vs main-image comparison (v0.7).

No pixel decoding: compares what the headers say — dimensions
(aspect ratio + scale factor), and coarse JPEG encoder signals
(DQT table count, DHT presence) as a *weak* "same encoder?" hint.
Every result states its own limits: these are observations about
container metadata, never verdicts about image content.
"""

from __future__ import annotations

from typing import Any

from metatrace.thumbnails.models import ThumbnailInfo

# Aspect relative difference above this counts as "different".
_ASPECT_TOLERANCE = 0.05


def compare_thumbnail(
    thumb: ThumbnailInfo,
    main_width: int | None,
    main_height: int | None,
    main_dqt_count: int | None,
    main_has_dht: bool | None,
) -> dict[str, Any]:
    """Describe how one thumbnail relates to the main image.

    Returns a dict with ``aspect`` ("same"/"different"/"unknown"),
    ``scale`` (thumbnail-to-main linear scale or None),
    ``larger_than_main`` (bool), ``encoder`` ("same"/"different"/
    "unknown" — explicitly weak), and human ``notes``. Pure
    function; never raises.
    """
    out: dict[str, Any] = {
        "thumbnail_index": thumb.index,
        "aspect": "unknown",
        "aspect_detail": None,
        "scale": None,
        "larger_than_main": False,
        "encoder": "unknown",
        "encoder_detail": None,
        "notes": [],
    }
    try:
        if (
            main_width
            and main_height
            and thumb.width
            and thumb.height
            and main_width > 0
            and main_height > 0
        ):
            a_main = main_width / main_height
            a_thumb = thumb.width / thumb.height
            rel = abs(a_main - a_thumb) / a_main
            out["aspect"] = "same" if rel <= _ASPECT_TOLERANCE else "different"
            out["aspect_detail"] = (
                f"main {main_width}x{main_height} (aspect {a_main:.3f}) vs "
                f"thumbnail {thumb.width}x{thumb.height} (aspect "
                f"{a_thumb:.3f}): {rel:.1%} relative difference"
            )
            out["scale"] = round(thumb.width / main_width, 4)
            out["larger_than_main"] = (
                thumb.width > main_width or thumb.height > main_height
            )
            if out["larger_than_main"]:
                out["notes"].append(
                    "thumbnail is larger than the image it previews — unusual"
                )
            elif out["aspect"] == "different":
                out["notes"].append(
                    "aspect differs beyond the 5% tolerance used for same-crop previews"
                )
        else:
            out["notes"].append("dimensions unknown on one side; no comparison")

        # Encoder signals: weak by design. Both DQT count AND DHT
        # presence must differ to say "different"; anything less is
        # "unknown" because encoders vary these freely.
        if (
            thumb.dqt_count is not None
            and thumb.has_dht is not None
            and main_dqt_count is not None
            and main_has_dht is not None
        ):
            dqt_same = thumb.dqt_count == main_dqt_count
            dht_same = thumb.has_dht == main_has_dht
            if dqt_same and dht_same:
                out["encoder"] = "same"
                out["encoder_detail"] = (
                    f"both carry {thumb.dqt_count} DQT table(s) and "
                    f"{'have' if thumb.has_dht else 'lack'} DHT — consistent "
                    "with one encoder (weak signal)"
                )
            elif not dqt_same and not dht_same:
                out["encoder"] = "different"
                out["encoder_detail"] = (
                    f"main image: {main_dqt_count} DQT table(s), DHT "
                    f"{'present' if main_has_dht else 'absent'}; thumbnail: "
                    f"{thumb.dqt_count} DQT table(s), DHT "
                    f"{'present' if thumb.has_dht else 'absent'} — encoder "
                    "signatures differ (weak signal: encoders vary these)"
                )
            else:
                out["encoder_detail"] = (
                    "partial encoder-signal agreement — inconclusive (weak signal)"
                )
            out["notes"].append(
                "encoder comparison is a weak signal: DQT/DHT layout varies "
                "between encoders and settings; it is not a verdict"
            )
        else:
            out["notes"].append("encoder signals unavailable; no comparison")
    except (ZeroDivisionError, TypeError, ValueError):
        out["notes"].append("comparison failed defensively")
    return out
