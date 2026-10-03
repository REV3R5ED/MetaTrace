"""Geographic math for v0.9 search: haversine distance and clustering.

Coordinates are GPS metadata *claims*. Distance and clustering are
computed over the claims as written; nothing here asserts where a
photograph was actually taken.
"""

from __future__ import annotations

import math

from metatrace.search.models import IndexRecord, LocationCluster

EARTH_RADIUS_KM = 6371.0

#: Grid cell size in degrees (~1.11 km of latitude at the equator).
_GRID_CELL_DEG = 0.01


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres (stdlib math only)."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (
        math.sin(dphi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    )
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def _cell_of(lat: float, lon: float) -> tuple[int, int]:
    return (math.floor(lat / _GRID_CELL_DEG), math.floor(lon / _GRID_CELL_DEG))


def cluster_locations(
    records: list[IndexRecord], cell_deg: float = _GRID_CELL_DEG
) -> list[LocationCluster]:
    """Group geotagged records into location clusters.

    Records land in ~1km grid cells; adjacent cells (8-neighbourhood)
    merge via union-find. Deterministic: clusters sort by
    (center_lat, center_lon), files sort by path.
    """
    cells: dict[tuple[int, int], list[IndexRecord]] = {}
    for record in records:
        if not record.has_gps or record.gps_lat is None or record.gps_lon is None:
            continue
        key = (
            math.floor(record.gps_lat / cell_deg),
            math.floor(record.gps_lon / cell_deg),
        )
        cells.setdefault(key, []).append(record)
    if not cells:
        return []

    # Union-find over cells; neighbours merge (8-neighbourhood).
    parent = {key: key for key in cells}

    def find(key: tuple[int, int]) -> tuple[int, int]:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(a: tuple[int, int], b: tuple[int, int]) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for key in cells:
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                neighbour = (key[0] + dx, key[1] + dy)
                if neighbour in cells:
                    union(key, neighbour)

    groups: dict[tuple[int, int], list[IndexRecord]] = {}
    for key, members in cells.items():
        groups.setdefault(find(key), []).extend(members)

    clusters = []
    for members in groups.values():
        coords = [
            (m.gps_lat, m.gps_lon)
            for m in members
            if m.gps_lat is not None and m.gps_lon is not None
        ]
        lats = [lat for lat, _ in coords]
        lons = [lon for _, lon in coords]
        center_lat = sum(lats) / len(lats)
        center_lon = sum(lons) / len(lons)
        radius = max(
            haversine_km(center_lat, center_lon, lat, lon) for lat, lon in coords
        )
        days = sorted({m.capture_day for m in members if m.capture_day != "unknown"})
        time_span = (days[0], days[-1]) if days else None
        clusters.append(
            LocationCluster(
                center_lat=center_lat,
                center_lon=center_lon,
                radius_km=radius,
                count=len(members),
                files=sorted(m.path for m in members),
                time_span=time_span,
            )
        )
    clusters.sort(key=lambda c: (c.center_lat, c.center_lon))
    return clusters
