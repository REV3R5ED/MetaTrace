"""XMP (Extensible Metadata Platform) packet location and parsing.

XMP travels as an RDF/XML packet embedded in the image container:

- JPEG: APP1 segment starting with ``http://ns.adobe.com/xap/1.0/\\x00``
- PNG: ``iTXt`` chunk with keyword ``XML:com.adobe.xmp``
- WebP: ``XMP `` chunk in the RIFF container
- TIFF: tag 700 (0x02BC), type UNDEFINED

Parsing is stdlib ``xml.etree`` with defensive guards: entity
definitions are refused outright (billion-laughs class), malformed
XML becomes a recorded warning — never a crash. A packet that fails
to parse still counts as *observed* (``present=True``); only the
normalized views stay empty.

Forensic discipline: XMP properties are reported per source. When the
same logical field exists in EXIF, XMP and IPTC, the values are shown
side by side — merging or preferring one source is the v0.6 anomaly
engine's job, not this parser's.
"""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from typing import Any

from metatrace.core.models import XmpData
from metatrace.parsers.containers import (
    iter_jpeg_segments,
    iter_png_chunks,
    iter_webp_chunks,
)

# Never read more than this looking for embedded XMP (packets live at
# the start of the file; APP1 segments are <= 64 KiB by spec).
_SCAN_BOUND = 4 * 1024 * 1024

_XMP_JPEG_HEADER = b"http://ns.adobe.com/xap/1.0/\x00"
_XMP_PNG_KEYWORD = b"XML:com.adobe.xmp"
_XMP_TIFF_TAG = 700

_RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
_DC_NS = "http://purl.org/dc/elements/1.1/"
_XMP_NS = "http://ns.adobe.com/xap/1.0/"
_PHOTOSHOP_NS = "http://ns.adobe.com/photoshop/1.0/"
_TIFF_NS = "http://ns.adobe.com/tiff/1.0/"
_EXIF_NS = "http://ns.adobe.com/exif/1.0/"
_AUX_NS = "http://ns.adobe.com/exif/1.0/aux/"
_XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"


# ---------------------------------------------------------------------------
# Packet location
# ---------------------------------------------------------------------------


def find_xmp_in_jpeg(data: bytes) -> bytes | None:
    """Return the first standard XMP packet in JPEG APP1 segments."""
    for marker, payload in iter_jpeg_segments(data, _SCAN_BOUND):
        if marker == 0xE1 and payload.startswith(_XMP_JPEG_HEADER):
            return payload[len(_XMP_JPEG_HEADER) :]
    return None


def _parse_itxt_payload(payload: bytes) -> tuple[bytes, bytes] | None:
    """Split an iTXt chunk into (keyword, text); handles compression."""
    # keyword NUL, compression flag (1), method (1), language NUL,
    # translated keyword NUL, text.
    try:
        kw_end = payload.index(b"\x00")
    except ValueError:
        return None
    keyword = payload[:kw_end]
    rest = payload[kw_end + 1 :]
    if len(rest) < 2:
        return None
    compressed, method = rest[0], rest[1]
    rest = rest[2:]
    # Skip language tag and translated keyword (both NUL-terminated).
    for _ in range(2):
        try:
            nul = rest.index(b"\x00")
        except ValueError:
            return None
        rest = rest[nul + 1 :]
    if compressed:
        if method != 0:
            return None  # only zlib (method 0) is defined
        import zlib

        try:
            rest = zlib.decompress(rest)
        except zlib.error:
            return None
    return keyword, rest


def find_xmp_in_png(data: bytes) -> bytes | None:
    """Return the XMP packet from a PNG iTXt chunk, if present."""
    for ctype, cdata in iter_png_chunks(data):
        if ctype != b"iTXt":
            continue
        parsed = _parse_itxt_payload(cdata)
        if parsed and parsed[0] == _XMP_PNG_KEYWORD:
            return parsed[1]
    return None


def find_xmp_in_webp(data: bytes) -> bytes | None:
    """Return the XMP packet from a WebP ``XMP `` chunk, if present."""
    for fourcc, cdata in iter_webp_chunks(data):
        if fourcc == b"XMP ":
            return cdata
    return None


def find_xmp_in_tiff(tiff_data: bytes, max_tags: int) -> bytes | None:
    """Return the XMP packet from TIFF tag 700, if present."""
    from metatrace.parsers.exif import _TiffParser

    try:
        parser = _TiffParser(tiff_data, max_tags, 4 * 1024 * 1024)
        raw, *_ = parser.parse()
    except Exception:
        return None
    value = raw.get(_XMP_TIFF_TAG)
    if isinstance(value, bytes):
        return value
    return None


# ---------------------------------------------------------------------------
# RDF/XML parsing
# ---------------------------------------------------------------------------


def _split_tag(tag: str) -> tuple[str, str]:
    """'{namespace}local' -> (namespace, local)."""
    if tag.startswith("{") and "}" in tag:
        ns, _, local = tag[1:].partition("}")
        return ns, local
    return "", tag


def _li_texts(container: ET.Element) -> list[str]:
    return [
        (li.text or "").strip() for li in container if _split_tag(li.tag)[1] == "li"
    ]


def _alt_text(container: ET.Element) -> str | None:
    """rdf:Alt -> preferred x-default text, else first non-empty."""
    default = None
    first = None
    for li in container:
        if _split_tag(li.tag)[1] != "li":
            continue
        text = (li.text or "").strip()
        if not text:
            continue
        if first is None:
            first = text
        if li.get(_XML_LANG) == "x-default":
            default = text
    return default if default is not None else first


def _element_value(elem: ET.Element) -> Any:
    """Extract a scalar/list/dict from one RDF property element."""
    children = list(elem)
    if not children:
        text = (elem.text or "").strip()
        return text or None
    # rdf:Alt / rdf:Bag / rdf:Seq containers.
    if len(children) == 1:
        ns, local = _split_tag(children[0].tag)
        if ns == _RDF_NS and local == "Alt":
            return _alt_text(children[0])
        if ns == _RDF_NS and local in ("Bag", "Seq"):
            items = [t for t in _li_texts(children[0]) if t]
            return items or None
    # Nested resource (rdf:parseType="Resource" or rdf:Description).
    nested: dict[str, Any] = {}
    for child in children:
        ns, local = _split_tag(child.tag)
        if ns == _RDF_NS:
            continue
        nested.setdefault(local, _element_value(child))
    if nested:
        return nested
    text = (elem.text or "").strip()
    return text or None


def parse_rdf(packet: str) -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
    """Parse an XMP RDF packet.

    Returns (properties, namespaces, warnings) where properties maps
    namespace URI -> {local name: value}. Raises nothing.
    """
    warnings: list[str] = []
    properties: dict[str, dict[str, Any]] = {}
    namespaces: list[str] = []
    if "<!ENTITY" in packet or "<!DOCTYPE" in packet:
        warnings.append(
            "XMP packet contains ENTITY/DOCTYPE declarations; "
            "refused to parse (entity-expansion risk)"
        )
        return properties, namespaces, warnings
    try:
        root = ET.fromstring(packet)
    except ET.ParseError as exc:
        warnings.append(f"XMP XML is malformed: {exc}")
        return properties, namespaces, warnings
    except (ValueError, MemoryError, RecursionError) as exc:
        warnings.append(f"XMP XML parse failed defensively: {exc}")
        return properties, namespaces, warnings

    def descriptions(node: ET.Element) -> Any:
        for child in node:
            ns, local = _split_tag(child.tag)
            if ns == _RDF_NS and local in ("RDF", "Description"):
                if local == "Description":
                    yield child
                yield from descriptions(child)

    seen_ns: set[str] = set()
    for desc in descriptions(root):
        # Attributes on rdf:Description are properties too.
        for attr, value in desc.attrib.items():
            ns, local = _split_tag(attr)
            if ns in (_RDF_NS, "") or local == "about":
                continue
            seen_ns.add(ns)
            properties.setdefault(ns, {})[local] = value
        for prop in desc:
            ns, local = _split_tag(prop.tag)
            if ns in (_RDF_NS, ""):
                continue
            seen_ns.add(ns)
            properties.setdefault(ns, {}).setdefault(local, _element_value(prop))
    namespaces = sorted(seen_ns)
    return properties, namespaces, warnings


def _first_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value or None
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item:
                return item
        return None
    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def extract_xmp(
    path: str,
    fmt: str,
    max_tags: int = 512,
    max_packet_bytes: int = 4 * 1024 * 1024,
) -> XmpData:
    """Locate and parse the XMP packet in *path*.

    Never raises on malformed input: problems land in
    ``XmpData.warnings`` and ``present`` reflects whether a packet was
    *observed*, even if it could not be parsed.
    """
    xmp = XmpData()
    if fmt not in ("JPEG", "PNG", "WEBP", "TIFF"):
        return xmp

    try:
        with open(path, "rb") as fh:
            data = fh.read(_SCAN_BOUND)
    except OSError as exc:
        xmp.warnings.append(f"cannot read file for XMP extraction: {exc}")
        return xmp

    packet: bytes | None = None
    try:
        if fmt == "JPEG":
            packet = find_xmp_in_jpeg(data)
        elif fmt == "PNG":
            packet = find_xmp_in_png(data)
        elif fmt == "WEBP":
            packet = find_xmp_in_webp(data)
        else:  # TIFF
            packet = find_xmp_in_tiff(data, max_tags)
    except (struct.error, IndexError, ValueError, MemoryError) as exc:
        xmp.warnings.append(f"XMP location failed defensively: {exc}")
        return xmp

    if packet is None:
        return xmp
    xmp.present = True
    if len(packet) > max_packet_bytes:
        xmp.warnings.append(
            f"XMP packet is {len(packet)} bytes (limit {max_packet_bytes}); "
            "truncated for analysis"
        )
        packet = packet[:max_packet_bytes]
        xmp.packet_truncated = True
    # XMP is UTF-8 by spec; decode defensively and strip the packet
    # wrapper processing instructions for the raw record.
    xmp.raw_packet = packet.decode("utf-8", errors="replace")

    props, namespaces, warnings = parse_rdf(xmp.raw_packet)
    xmp.warnings.extend(warnings)
    xmp.namespaces = namespaces
    xmp.raw_properties = props

    dc = props.get(_DC_NS, {})
    xmp.dublin_core = {
        "title": _first_text(dc.get("title")),
        "creator": dc.get("creator"),
        "description": _first_text(dc.get("description")),
        "rights": _first_text(dc.get("rights")),
        "subject": dc.get("subject"),
    }
    basic = props.get(_XMP_NS, {})
    rating = basic.get("Rating")
    try:
        rating_n: int | None = int(str(rating)) if rating is not None else None
    except (TypeError, ValueError):
        rating_n = None
    xmp.xmp_basic = {
        "create_date": _first_text(basic.get("CreateDate")),
        "modify_date": _first_text(basic.get("ModifyDate")),
        "creator_tool": _first_text(basic.get("CreatorTool")),
        "rating": rating_n,
    }
    ps = props.get(_PHOTOSHOP_NS, {})
    xmp.photoshop = {
        "authors_position": _first_text(ps.get("AuthorsPosition")),
        "credit": _first_text(ps.get("Credit")),
        "source": _first_text(ps.get("Source")),
        "date_created": _first_text(ps.get("DateCreated")),
    }
    exif_in_xmp: dict[str, Any] = {}
    for ns in (_TIFF_NS, _EXIF_NS, _AUX_NS):
        for local, value in props.get(ns, {}).items():
            exif_in_xmp[f"{ns}#{local}"] = value
    xmp.exif_in_xmp = exif_in_xmp
    return xmp
