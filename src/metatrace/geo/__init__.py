"""Geographic normalization for MetaTrace (v0.2).

Converts EXIF GPS IFD values into analyst-friendly decimal coordinates
and UTC timestamps. Forensic posture: coordinates record what the
file's metadata *claims* — they never prove where a photograph was
taken. See :data:`LOCATION_DISCLAIMER`.
"""

from metatrace.geo.coords import (
    LOCATION_DISCLAIMER,
    normalize_gps,
    osm_link,
)

__all__ = ["LOCATION_DISCLAIMER", "normalize_gps", "osm_link"]
