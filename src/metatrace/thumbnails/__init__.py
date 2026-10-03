"""Embedded thumbnail/content analysis (v0.7).

Extracts embedded preview thumbnails — JPEG EXIF IFD1 blobs
(JPEGInterchangeFormat), uncompressed TIFF IFD1 strips, standalone
TIFF IFD1 — and describes them without pixel decoding (stdlib has no
JPEG decoder): byte size, SHA-256, dimensions from JPEG SOF marker
scans or TIFF tags, format by magic bytes, and coarse encoder
signals (DQT table count / DHT presence) for "same encoder?" hints.

Every comparison is metadata-level and explicitly weak: a thumbnail
that disagrees with the main image is an observation, never a
verdict. Judging disagreements is the anomaly engine's job.
"""

from metatrace.thumbnails.compare import compare_thumbnail
from metatrace.thumbnails.extract import (
    extract_thumbnails,
    extract_thumbnails_with_blobs,
    write_thumbnail,
)
from metatrace.thumbnails.models import ThumbnailInfo, ThumbnailsData

__all__ = [
    "ThumbnailInfo",
    "ThumbnailsData",
    "compare_thumbnail",
    "extract_thumbnails",
    "extract_thumbnails_with_blobs",
    "write_thumbnail",
]
