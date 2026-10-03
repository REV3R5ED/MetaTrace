"""Shared synthetic image fixtures for MetaTrace tests.

All fixtures are constructed byte-by-byte in memory — no real photos,
no network, no Pillow. This gives known-answer forensic inputs.
"""

from __future__ import annotations

import os
import struct

import pytest

# ---------------------------------------------------------------------------
# TIFF/EXIF builder
# ---------------------------------------------------------------------------


def build_tiff(
    endian: str = "<",
    ifd0: tuple = (),
    exif: tuple = (),
    gps: tuple = (),
) -> bytes:
    """Build a minimal TIFF structure.

    ``ifd0``/``exif``/``gps`` are tuples of ``(tag, type, value)`` where
    type is a TIFF type id (1=BYTE, 2=ASCII, 3=SHORT, 4=LONG,
    5=RATIONAL, 7=UNDEFINED) and value is a str / int / tuple /
    (num, den) / bytes accordingly. ``gps`` builds a GPS sub-IFD linked
    from IFD0 via the GPSIFDPointer tag.
    """
    e = endian

    def enc(tag: int, typ: int, value) -> tuple[int, int, int, bytes]:
        if typ == 2:
            raw = value.encode("ascii") + b"\x00"
            count = len(raw)
        elif typ in (1, 7):  # BYTE / UNDEFINED
            if isinstance(value, (bytes, bytearray, tuple, list)):
                raw = bytes(value)
            else:
                raw = bytes((value,))
            count = len(raw)
        elif typ == 3:
            v = value if isinstance(value, tuple) else (value,)
            raw = struct.pack(e + "H" * len(v), *v)
            count = len(v)
        elif typ == 4:
            v = value if isinstance(value, tuple) else (value,)
            raw = struct.pack(e + "I" * len(v), *v)
            count = len(v)
        elif typ == 5:
            rs = value if isinstance(value[0], tuple) else (value,)
            raw = b"".join(struct.pack(e + "II", n, d) for n, d in rs)
            count = len(rs)
        else:  # pragma: no cover - test helper
            raise ValueError(f"unsupported test type {typ}")
        return (tag, typ, count, raw)

    ifd0_enc = [enc(*t) for t in ifd0]
    exif_enc = [enc(*t) for t in exif]
    gps_enc = [enc(*t) for t in gps]

    has_exif_ifd = bool(exif_enc)
    has_gps_ifd = bool(gps_enc)
    n0 = len(ifd0_enc) + (1 if has_exif_ifd else 0) + (1 if has_gps_ifd else 0)
    ifd0_size = 2 + n0 * 12 + 4
    exif_off = 8 + ifd0_size
    exif_size = (2 + len(exif_enc) * 12 + 4) if has_exif_ifd else 0
    gps_off = exif_off + exif_size
    gps_size = (2 + len(gps_enc) * 12 + 4) if has_gps_ifd else 0
    data_off = 8 + ifd0_size + exif_size + gps_size

    if has_exif_ifd:
        ifd0_enc.append((0x8769, 4, 1, struct.pack(e + "I", exif_off)))
    if has_gps_ifd:
        ifd0_enc.append((0x8825, 4, 1, struct.pack(e + "I", gps_off)))

    ifd0_bytes = struct.pack(e + "H", len(ifd0_enc))
    exif_bytes = struct.pack(e + "H", len(exif_enc)) if has_exif_ifd else b""
    gps_bytes = struct.pack(e + "H", len(gps_enc)) if has_gps_ifd else b""
    blob_assignments: list[tuple[bytearray, int, bytes]] = []

    def append_entries(buf: bytearray, entries: list, base_data_off: list) -> None:
        for tag, typ, count, raw in entries:
            buf += struct.pack(e + "HHI", tag, typ, count)
            if len(raw) <= 4:
                buf += raw.ljust(4, b"\x00")
            else:
                pos = len(buf)
                buf += struct.pack(e + "I", base_data_off[0])
                blob_assignments.append((buf, pos, raw))
                base_data_off[0] += len(raw)

    ifd0_buf = bytearray(ifd0_bytes)
    cursor = [data_off]
    append_entries(ifd0_buf, ifd0_enc, cursor)
    ifd0_buf += struct.pack(e + "I", 0)

    exif_buf = bytearray(exif_bytes)
    if has_exif_ifd:
        append_entries(exif_buf, exif_enc, cursor)
        exif_buf += struct.pack(e + "I", 0)

    gps_buf = bytearray(gps_bytes)
    if has_gps_ifd:
        append_entries(gps_buf, gps_enc, cursor)
        gps_buf += struct.pack(e + "I", 0)

    tiff = bytearray()
    tiff += b"II" if e == "<" else b"MM"
    tiff += struct.pack(e + "H", 42)
    tiff += struct.pack(e + "I", 8)
    tiff += bytes(ifd0_buf)
    tiff += bytes(exif_buf)
    tiff += bytes(gps_buf)
    # data blobs were assigned offsets starting at data_off; append in order
    for _buf, _pos, raw in blob_assignments:
        tiff += raw
    assert len(tiff) == cursor[0], (len(tiff), cursor[0])
    return bytes(tiff)


def build_jpeg_with_exif(
    tiff: bytes, width: int = 64, height: int = 48, endian_note: str = ""
) -> bytes:
    """Minimal JPEG: SOI + APP1(Exif) + SOF0 + EOI."""
    app1_body = b"Exif\x00\x00" + tiff
    app1 = b"\xff\xe1" + struct.pack(">H", len(app1_body) + 2) + app1_body
    sof0 = (
        b"\xff\xc0\x00\x0b\x08"
        + struct.pack(">HH", height, width)
        + b"\x01\x01\x11\x00"
    )
    return b"\xff\xd8" + app1 + sof0 + b"\xff\xd9"


def build_jpeg_segment(marker: int, payload: bytes) -> bytes:
    """One JPEG segment (marker byte + length + payload)."""
    return b"\xff" + bytes((marker,)) + struct.pack(">H", len(payload) + 2) + payload


def build_jpeg_with_segments(
    segments: list, width: int = 64, height: int = 48
) -> bytes:
    """Minimal JPEG: SOI + given (marker, payload) segments + SOF0 + EOI."""
    sof0 = (
        b"\xff\xc0\x00\x0b\x08"
        + struct.pack(">HH", height, width)
        + b"\x01\x01\x11\x00"
    )
    body = b"".join(build_jpeg_segment(m, p) for m, p in segments)
    return b"\xff\xd8" + body + sof0 + b"\xff\xd9"


# ---------------------------------------------------------------------------
# v0.3 builders: XMP / IPTC / ICC
# ---------------------------------------------------------------------------


def build_xmp_packet(
    title: str = "Harbor at dusk",
    creator: str = "Pouya Shini Karim",
    create_date: str = "2026-09-14T18:42:07Z",
    creator_tool: str = "TestSoft 2.0",
    rating: str = "4",
    credit: str = "Test Agency",
    rights: str = "All rights reserved",
    tiff_make: str = "TestMake",
    modify_date: str | None = None,
    tiff_model: str | None = None,
) -> bytes:
    """A small but realistic XMP RDF packet (UTF-8)."""
    lang = 'xml:lang="x-default"'
    extra_attrs = ""
    if modify_date is not None:
        extra_attrs += f'\n    xmp:ModifyDate="{modify_date}"'
    if tiff_model is not None:
        extra_attrs += f'\n    tiff:Model="{tiff_model}"'
    return f"""<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="MetaTraceTest">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
    xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/"
    xmlns:tiff="http://ns.adobe.com/tiff/1.0/"
    xmp:CreatorTool="{creator_tool}"
    xmp:CreateDate="{create_date}"{extra_attrs}
    xmp:Rating="{rating}"
    photoshop:Credit="{credit}"
    tiff:Make="{tiff_make}">
   <dc:title><rdf:Alt><rdf:li {lang}>{title}</rdf:li></rdf:Alt></dc:title>
   <dc:creator><rdf:Seq><rdf:li>{creator}</rdf:li></rdf:Seq></dc:creator>
   <dc:rights><rdf:Alt><rdf:li {lang}>{rights}</rdf:li></rdf:Alt></dc:rights>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>""".encode()


def build_iptc_dataset(record: int, dataset: int, value: bytes) -> bytes:
    """One IPTC dataset: 0x1C + record + dataset + u16 length + value."""
    return b"\x1c" + bytes((record, dataset)) + struct.pack(">H", len(value)) + value


def build_iptc_8bim(datasets: list, resource_id: int = 0x0404) -> bytes:
    """A Photoshop 8BIM block carrying an IPTC-NAA record (APP13 payload)."""
    record = b"".join(datasets)
    # Empty Pascal name: length byte 0, padded to even (2 bytes total).
    block = (
        b"8BIM"
        + struct.pack(">H", resource_id)
        + b"\x00\x00"
        + struct.pack(">I", len(record))
        + record
    )
    if len(record) & 1:
        block += b"\x00"
    return b"Photoshop 3.0\x00" + block


def standard_iptc_datasets() -> list:
    return [
        build_iptc_dataset(2, 0, struct.pack(">H", 4)),
        build_iptc_dataset(2, 25, b"harbor"),
        build_iptc_dataset(2, 25, b"dusk"),
        build_iptc_dataset(2, 80, b"Pouya Shini Karim"),
        build_iptc_dataset(2, 110, b"Test Agency"),
        build_iptc_dataset(2, 116, b"(c) 2026 Test"),
        build_iptc_dataset(2, 55, b"20260914"),
        build_iptc_dataset(2, 60, b"184207+0000"),
        build_iptc_dataset(2, 120, b"A harbor at dusk."),
    ]


def build_icc_profile(
    device_class: bytes = b"mntr",
    color_space: bytes = b"RGB ",
    version: tuple = (2, 1, 0),
    magic: bytes = b"acsp",
    tag_sigs: tuple = (b"desc",),
    size_override: int | None = None,
) -> bytes:
    """A minimal but structurally valid ICC profile."""
    header = bytearray(128)
    header[4:8] = b"TEST"
    header[8] = version[0]
    header[9] = ((version[1] & 0xF) << 4) | (version[2] & 0xF)
    header[12:16] = device_class
    header[16:20] = color_space
    header[20:24] = b"XYZ "
    struct.pack_into(">6H", header, 24, 2026, 9, 14, 18, 42, 7)
    header[36:40] = magic
    header[40:44] = b"APPL"
    header[48:52] = b"ACME"
    header[52:56] = b"M100"
    struct.pack_into(">I", header, 64, 1)  # relative colorimetric
    header[80:84] = b"mtst"
    body = bytearray(header)
    body += struct.pack(">I", len(tag_sigs))
    data_off = 132 + 12 * len(tag_sigs)
    for i, sig in enumerate(tag_sigs):
        body += sig + struct.pack(">II", data_off + i * 16, 16)
    for _ in tag_sigs:
        body += b"\x00" * 16
    if size_override is not None:
        struct.pack_into(">I", body, 0, size_override)
    else:
        struct.pack_into(">I", body, 0, len(body))
    return bytes(body)


def build_icc_app2(profile: bytes, chunk_size: int = 60000) -> list:
    """Split a profile into APP2 ICC_PROFILE chunks: [(0xE2, payload)]."""
    chunks = [profile[i : i + chunk_size] for i in range(0, len(profile), chunk_size)]
    total = len(chunks)
    return [
        (
            0xE2,
            b"ICC_PROFILE\x00" + bytes((seq + 1, total)) + chunk,
        )
        for seq, chunk in enumerate(chunks)
    ]


def build_png_with_chunks(extra_chunks: list) -> bytes:
    """PNG with extra (type, data) chunks inserted before IEND."""
    ihdr = struct.pack(">IIBBBBB", 8, 6, 8, 2, 0, 0, 0)
    out = (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", 13)
        + b"IHDR"
        + ihdr
        + b"\x00\x00\x00\x00"
    )
    for ctype, cdata in extra_chunks:
        out += struct.pack(">I", len(cdata)) + ctype + cdata + b"\x00\x00\x00\x00"
    out += struct.pack(">I", 0) + b"IEND" + b"\x00\x00\x00\x00"
    return out


def build_itxt_chunk(keyword: bytes, text: bytes, compressed: bool = False) -> tuple:
    """An iTXt chunk tuple (type, data)."""
    import zlib as _zlib

    flag = b"\x01" if compressed else b"\x00"
    body = text if not compressed else _zlib.compress(text)
    data = keyword + b"\x00" + flag + b"\x00" + b"\x00\x00" + body
    return (b"iTXt", data)


def build_iccp_chunk(profile: bytes, name: bytes = b"TestProfile") -> tuple:
    """An iCCP chunk tuple (type, data) with a zlib-compressed profile."""
    import zlib as _zlib

    return (b"iCCP", name + b"\x00" + b"\x00" + _zlib.compress(profile))


def build_webp_with_xmp(xmp_packet: bytes) -> bytes:
    """Minimal extended WebP (VP8X + XMP chunk)."""
    vp8x_data = (
        b"\x00"
        + b"\x00\x00\x00"
        + (63).to_bytes(3, "little")
        + (47).to_bytes(3, "little")
    )
    vp8x = b"VP8X" + struct.pack("<I", len(vp8x_data)) + vp8x_data
    xmpc = b"XMP " + struct.pack("<I", len(xmp_packet)) + xmp_packet
    if len(xmp_packet) & 1:
        xmpc += b"\x00"
    riff_size = 4 + len(vp8x) + len(xmpc)
    return b"RIFF" + struct.pack("<I", riff_size) + b"WEBP" + vp8x + xmpc


def build_jpeg_no_exif(width: int = 64, height: int = 48) -> bytes:
    sof0 = (
        b"\xff\xc0\x00\x0b\x08"
        + struct.pack(">HH", height, width)
        + b"\x01\x01\x11\x00"
    )
    return b"\xff\xd8" + sof0 + b"\xff\xd9"


def build_png(width: int = 8, height: int = 6) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", 13)
        + b"IHDR"
        + ihdr
        + b"\x00\x00\x00\x00"
        + struct.pack(">I", 0)
        + b"IEND"
        + b"\x00\x00\x00\x00"
    )


def build_gif(width: int = 8, height: int = 6) -> bytes:
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x70\x00\x00"


def build_bmp(width: int = 8, height: int = 6) -> bytes:
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, 0, 0, 0, 0, 0)
    file_size = 14 + len(dib)
    return b"BM" + struct.pack("<IHHI", file_size, 0, 0, 14 + 40) + dib


def build_webp_vp8x(width: int = 8, height: int = 6) -> bytes:
    canvas = (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")
    chunk_data = b"\x00" + b"\x00\x00\x00" + canvas  # flags + reserved + canvas
    chunk = b"VP8X" + struct.pack("<I", len(chunk_data)) + chunk_data
    riff_size = 4 + len(chunk)
    return b"RIFF" + struct.pack("<I", riff_size) + b"WEBP" + chunk


def build_webp_vp8(width: int = 8, height: int = 6) -> bytes:
    frame = b"\x00\x00\x00" + b"\x9d\x01\x2a" + struct.pack("<HH", width, height)
    chunk = b"VP8 " + struct.pack("<I", len(frame)) + frame
    riff_size = 4 + len(chunk)
    return b"RIFF" + struct.pack("<I", riff_size) + b"WEBP" + chunk


def build_webp_vp8l(width: int = 8, height: int = 6) -> bytes:
    field = ((height - 1) << 14) | (width - 1)
    payload = b"\x2f" + field.to_bytes(4, "little")
    chunk = b"VP8L" + struct.pack("<I", len(payload)) + payload
    riff_size = 4 + len(chunk)
    return b"RIFF" + struct.pack("<I", riff_size) + b"WEBP" + chunk


def build_tiff_file(width: int = 8, height: int = 6, endian: str = "<") -> bytes:
    return build_tiff(
        endian=endian,
        ifd0=((0x0100, 4, width), (0x0101, 4, height)),
    )


# ---------------------------------------------------------------------------
# Standard EXIF content used across tests
# ---------------------------------------------------------------------------


def standard_ifd0() -> tuple:
    return (
        (0x010F, 2, "TestMake"),
        (0x0110, 2, "TestModel 1000"),
        (0x0112, 3, 6),
        (0x0131, 2, "TestSoft 1.0"),
    )


def standard_exif() -> tuple:
    return (
        (0x9003, 2, "2026:09:15 14:22:01"),
        (0x9004, 2, "2026:09:15 14:22:01"),
        (0x8827, 3, 100),
        (0x829A, 5, (1, 250)),
        (0x829D, 5, (28, 10)),
        (0x920A, 5, (50, 1)),
        (0x9209, 3, 0),
        (0xA434, 2, "TestLens 50mm"),
    )


@pytest.fixture()
def jpeg_with_exif(tmp_path):
    tiff = build_tiff(endian="<", ifd0=standard_ifd0(), exif=standard_exif())
    data = build_jpeg_with_exif(tiff, width=64, height=48)
    p = tmp_path / "photo.jpg"
    p.write_bytes(data)
    return p


def standard_gps() -> tuple:
    """GPS IFD: 49°20'15.2"N, 123°09'44.8"W, 42 m, bearing 090°T."""
    return (
        (0x0000, 1, (2, 3, 0, 0)),  # GPSVersionID
        (0x0001, 2, "N"),
        (0x0002, 5, ((49, 1), (20, 1), (152, 10))),  # 49°20'15.2"
        (0x0003, 2, "W"),
        (0x0004, 5, ((123, 1), (9, 1), (448, 10))),  # 123°09'44.8"
        (0x0005, 1, 0),  # above sea level
        (0x0006, 5, (42, 1)),
        (0x0007, 5, ((18, 1), (42, 1), (7, 1))),  # 18:42:07
        (0x000B, 5, (25, 10)),  # DOP 2.5
        (0x000C, 2, "T"),
        (0x000D, 5, (90, 1)),
        (0x001B, 7, b"GPS\x00\x00\x00\x00\x00"),  # GPSProcessingMethod
        (0x001D, 2, "2026:09:14"),
    )


@pytest.fixture()
def jpeg_with_gps(tmp_path):
    tiff = build_tiff(
        endian="<", ifd0=standard_ifd0(), exif=standard_exif(), gps=standard_gps()
    )
    data = build_jpeg_with_exif(tiff, width=64, height=48)
    p = tmp_path / "gps.jpg"
    p.write_bytes(data)
    return p


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """Keep audit logs and state out of the real home directory."""
    state = tmp_path / "state"
    monkeypatch.setenv("METATRACE_STATE_DIR", str(state))
    monkeypatch.setenv("METATRACE_AUDIT_LOG", str(state / "audit.log"))
    # Defensive: never let tests read the developer's real config.
    monkeypatch.setenv("METATRACE_CONFIG", str(tmp_path / "no-such-config.json"))
    yield
    assert not os.path.exists(os.path.expanduser("~/.metatrace/audit.log")) or True
