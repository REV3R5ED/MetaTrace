"""Tests for XMP packet location and RDF parsing (v0.3)."""

from __future__ import annotations

from metatrace.parsers import xmp as xmp_mod
from metatrace.parsers.xmp import (
    find_xmp_in_jpeg,
    find_xmp_in_png,
    find_xmp_in_tiff,
    find_xmp_in_webp,
    parse_rdf,
)
from tests.conftest import (
    build_itxt_chunk,
    build_jpeg_no_exif,
    build_jpeg_with_exif,
    build_jpeg_with_segments,
    build_png_with_chunks,
    build_tiff,
    build_tiff_file,
    build_webp_with_xmp,
    build_xmp_packet,
    standard_exif,
    standard_ifd0,
)

XMP_HEADER = b"http://ns.adobe.com/xap/1.0/\x00"


def _jpeg_with_xmp(packet: bytes):
    return build_jpeg_with_segments([(0xE1, XMP_HEADER + packet)])


# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------


def test_xmp_found_in_jpeg_app1():
    packet = build_xmp_packet()
    found = find_xmp_in_jpeg(_jpeg_with_xmp(packet))
    assert found == packet


def test_xmp_absent_in_plain_jpeg():
    assert find_xmp_in_jpeg(build_jpeg_no_exif()) is None


def test_xmp_found_in_png_itxt():
    packet = build_xmp_packet()
    chunk = build_itxt_chunk(b"XML:com.adobe.xmp", packet)
    assert find_xmp_in_png(build_png_with_chunks([chunk])) == packet


def test_xmp_found_in_png_itxt_compressed():
    packet = build_xmp_packet()
    chunk = build_itxt_chunk(b"XML:com.adobe.xmp", packet, compressed=True)
    assert find_xmp_in_png(build_png_with_chunks([chunk])) == packet


def test_xmp_found_in_webp_xmp_chunk():
    packet = build_xmp_packet()
    assert find_xmp_in_webp(build_webp_with_xmp(packet)) == packet


def test_xmp_found_in_tiff_tag_700():
    packet = build_xmp_packet()
    tiff = build_tiff(ifd0=((700, 7, packet),))
    assert find_xmp_in_tiff(tiff, 512) == packet


def test_xmp_absent_in_tiff_without_tag_700():
    assert find_xmp_in_tiff(build_tiff_file(), 512) is None


def test_xmp_ignores_non_xmp_app1():
    # EXIF APP1 must not be mistaken for XMP.
    tiff = build_tiff(ifd0=standard_ifd0(), exif=standard_exif())
    assert find_xmp_in_jpeg(build_jpeg_with_exif(tiff)) is None


# ---------------------------------------------------------------------------
# RDF parsing
# ---------------------------------------------------------------------------


def test_parse_rdf_extracts_known_namespaces():
    props, namespaces, warnings = parse_rdf(build_xmp_packet().decode("utf-8"))
    assert warnings == []
    assert "http://purl.org/dc/elements/1.1/" in namespaces
    assert "http://ns.adobe.com/xap/1.0/" in namespaces
    assert props["http://purl.org/dc/elements/1.1/"]["title"] == "Harbor at dusk"
    assert props["http://ns.adobe.com/xap/1.0/"]["CreatorTool"] == "TestSoft 2.0"
    assert props["http://ns.adobe.com/photoshop/1.0/"]["Credit"] == "Test Agency"
    assert props["http://ns.adobe.com/tiff/1.0/"]["Make"] == "TestMake"


def test_parse_rdf_malformed_xml_warns():
    props, namespaces, warnings = parse_rdf("<rdf:RDF><unclosed>")
    assert props == {}
    assert any("malformed" in w for w in warnings)


def test_parse_rdf_refuses_entities():
    evil = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz [<!ENTITY lol "lollollol">]>'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        "<rdf:Description>&lol;</rdf:Description></rdf:RDF>"
    )
    props, _, warnings = parse_rdf(evil)
    assert props == {}
    assert any("ENTITY" in w for w in warnings)


def test_parse_rdf_alt_prefers_x_default():
    packet = """<x:xmpmeta xmlns:x="adobe:ns:meta/">
     <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
      <rdf:Description rdf:about=""
        xmlns:dc="http://purl.org/dc/elements/1.1/">
       <dc:title><rdf:Alt>
        <rdf:li xml:lang="fr-FR">Titre</rdf:li>
        <rdf:li xml:lang="x-default">Default title</rdf:li>
       </rdf:Alt></dc:title>
      </rdf:Description>
     </rdf:RDF></x:xmpmeta>"""
    props, _, _ = parse_rdf(packet)
    dc = "http://purl.org/dc/elements/1.1/"
    assert props[dc]["title"] == "Default title"


# ---------------------------------------------------------------------------
# extract_xmp
# ---------------------------------------------------------------------------


def test_extract_xmp_jpeg_normalized(tmp_path):
    p = tmp_path / "x.jpg"
    p.write_bytes(_jpeg_with_xmp(build_xmp_packet()))
    x = xmp_mod.extract_xmp(str(p), "JPEG")
    assert x.present
    assert x.dublin_core["title"] == "Harbor at dusk"
    assert x.dublin_core["creator"] == ["Pouya Shini Karim"]
    assert x.dublin_core["rights"] == "All rights reserved"
    assert x.xmp_basic["create_date"] == "2026-09-14T18:42:07Z"
    assert x.xmp_basic["creator_tool"] == "TestSoft 2.0"
    assert x.xmp_basic["rating"] == 4
    assert x.photoshop["credit"] == "Test Agency"
    assert x.exif_in_xmp["http://ns.adobe.com/tiff/1.0/#Make"] == "TestMake"
    assert x.raw_packet  # observed packet kept verbatim
    assert not x.packet_truncated
    assert x.warnings == []


def test_extract_xmp_rating_non_numeric_kept_raw(tmp_path):
    packet = build_xmp_packet(rating="high")
    p = tmp_path / "x.jpg"
    p.write_bytes(_jpeg_with_xmp(packet))
    x = xmp_mod.extract_xmp(str(p), "JPEG")
    assert x.present
    assert x.xmp_basic["rating"] is None
    # ...but the observed value survives in raw_properties.
    assert x.raw_properties["http://ns.adobe.com/xap/1.0/"]["Rating"] == "high"


def test_extract_xmp_malformed_packet_still_present(tmp_path):
    p = tmp_path / "x.jpg"
    p.write_bytes(_jpeg_with_xmp(b"<not xml at all"))
    x = xmp_mod.extract_xmp(str(p), "JPEG")
    assert x.present  # the packet was observed...
    assert x.dublin_core["title"] is None  # ...but nothing normalized
    assert any("malformed" in w for w in x.warnings)


def test_extract_xmp_truncation_bound(tmp_path):
    packet = build_xmp_packet()
    p = tmp_path / "x.jpg"
    p.write_bytes(_jpeg_with_xmp(packet))
    x = xmp_mod.extract_xmp(str(p), "JPEG", max_packet_bytes=64)
    assert x.present
    assert x.packet_truncated
    assert len(x.raw_packet.encode("utf-8")) <= 64
    assert len(x.raw_packet) < len(packet.decode("utf-8"))
    assert any("truncated" in w for w in x.warnings)


def test_extract_xmp_unsupported_format(tmp_path):
    p = tmp_path / "x.gif"
    p.write_bytes(b"GIF89a\x08\x00\x06\x00\x70\x00\x00")
    x = xmp_mod.extract_xmp(str(p), "GIF")
    assert not x.present


def test_extract_xmp_missing_file():
    x = xmp_mod.extract_xmp("/nonexistent/x.jpg", "JPEG")
    assert not x.present
    assert x.warnings


def test_extract_xmp_png_and_webp_and_tiff(tmp_path):
    packet = build_xmp_packet()
    png = tmp_path / "x.png"
    png.write_bytes(
        build_png_with_chunks([build_itxt_chunk(b"XML:com.adobe.xmp", packet)])
    )
    assert xmp_mod.extract_xmp(str(png), "PNG").present

    webp = tmp_path / "x.webp"
    webp.write_bytes(build_webp_with_xmp(packet))
    assert xmp_mod.extract_xmp(str(webp), "WEBP").present

    tiff = tmp_path / "x.tiff"
    tiff.write_bytes(build_tiff(ifd0=((700, 7, packet),)))
    got = xmp_mod.extract_xmp(str(tiff), "TIFF")
    assert got.present
    assert got.dublin_core["title"] == "Harbor at dusk"


def test_extract_xmp_json_serializable(tmp_path):
    import json

    p = tmp_path / "x.jpg"
    p.write_bytes(_jpeg_with_xmp(build_xmp_packet()))
    x = xmp_mod.extract_xmp(str(p), "JPEG")
    json.dumps(x.to_dict())  # must not raise
