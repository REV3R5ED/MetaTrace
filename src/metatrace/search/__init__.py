"""Metadata search over analyzed images (v0.9).

``metatrace search`` queries a saved JSON index (built by
``metatrace batch --index`` or ``metatrace search --build-index``)
fully offline: filter by device, capture date, GPS presence /
proximity, anomaly rule, free text, or hash; cluster geotagged
images; or pull a filtered cross-image timeline.
"""

from metatrace.core.plugins import ModuleInfo, register
from metatrace.search.filters import (
    MAX_NEAR_RADIUS_KM,
    SearchFilters,
    apply_filters,
    matches,
    parse_date,
    parse_date_range,
    parse_hash,
    parse_near,
)
from metatrace.search.geo import cluster_locations, haversine_km
from metatrace.search.index import (
    INDEX_VERSION,
    IndexError,
    build_index,
    build_index_record,
    read_index,
    write_index,
)
from metatrace.search.models import IndexRecord, LocationCluster, SearchIndex
from metatrace.search.timeline import build_search_timeline

__all__ = [
    "INDEX_VERSION",
    "IndexError",
    "IndexRecord",
    "LocationCluster",
    "MAX_NEAR_RADIUS_KM",
    "SearchFilters",
    "SearchIndex",
    "apply_filters",
    "build_index",
    "build_index_record",
    "build_search_timeline",
    "cluster_locations",
    "haversine_km",
    "matches",
    "parse_date",
    "parse_date_range",
    "parse_hash",
    "parse_near",
    "read_index",
    "write_index",
]

register(
    ModuleInfo(
        name="search",
        description="Metadata search over analyzed images: filters, "
        "geographic clustering, filtered timelines (v0.9)",
        version="0.9.0",
        commands=["search", "batch"],
    )
)
