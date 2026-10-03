# MetaTrace

**Trace the story behind the image.**

MetaTrace is a Python image-forensics and metadata-analysis platform. It starts as a reliable metadata extractor — file identification, cryptographic hashes, EXIF parsing — and grows into a full investigation platform: GPS normalization, XMP/IPTC/ICC, anomaly detection, case management, and defensible reporting.

The core forensic rule: **observed metadata is kept verbatim; normalized fields are derived alongside it, never merged.** MetaTrace records what an image *technically contains* and never labels an image "fake" from metadata alone.

## License

MIT — see [LICENSE](LICENSE). Free for personal and commercial use.

## v0.4 — what works today

- **File identification**: magic-byte format detection (JPEG, PNG, GIF, BMP, WebP, TIFF) and dimension parsing — pure stdlib, no Pillow
- **Evidence hashing**: SHA-256 (always) and optional SHA-512, streamed, computed *before* any parsing
- **Full EXIF + GPS normalization**: TIFF/EXIF parser in pure stdlib (both endiannesses) — make/model, timestamps, orientation, ISO, exposure, aperture, focal length, flash, lens, software; GPS IFD decoded to decimal coordinates, altitude, bearing, UTC timestamp with validity checks; raw tag values preserved verbatim
- **XMP / IPTC / ICC extraction**: XMP RDF packets (JPEG APP1, PNG iTXt, WebP XMP chunk, TIFF tag 700) with Dublin Core / XMP Basic / Photoshop properties; IPTC/IIM datasets from JPEG APP13 Photoshop IRBs (caption, keywords, byline, credit, copyright, dates); embedded ICC profiles (JPEG APP2, PNG iCCP, TIFF tag 34675) with header + tag directory and `acsp` signature check — full color math out of scope
- **Timestamp normalization**: every timestamp flavor parsed into one model — EXIF datetimes (+ `OffsetTime*` → UTC), XMP ISO-8601 (offsets converted), IPTC DateCreated+TimeCreated, GPS (UTC), ICC creation (UTC), filesystem mtime (labeled as filesystem, never image metadata). Timezone-naive claims keep `value_utc: null` — a timezone is never invented; unparseable values are kept verbatim with a low-severity finding
- **Device normalization**: maker/model/software strings normalized per source (case/whitespace/punctuation-insensitive keys, canonical display like "Canon EOS R5"); EXIF serial numbers extracted verbatim
- **Descriptive cross-source comparison**: capture time, device make/model and software chain compared across EXIF/XMP/IPTC as agree / differ / only-in-one-source, with raw values shown — descriptive bookkeeping, never a verdict (judging conflicts is the v0.6 anomaly engine's job)
- **Timelines**: `metatrace timeline <image>` lists every timestamp claim chronologically — UTC-known first, then timezone-naive by wall-clock, then unparseable — human + `--json`
- **Defensive parsing**: truncated or malicious files produce recorded warnings, never crashes; file-size and value-size bounds; invalid GPS values and bad ICC signatures become explained findings, never silent drops
- **CLI**: `metatrace inspect <image>` with human-readable output and `--json`; `--map-link` prints an OpenStreetMap URL for GPS coordinates (no network request); structured exit codes (0 ok / 1 findings / 2 error); audit logging of every invocation
- **Framework for the roadmap**: parser/plugin registry, normalized evidence models, JSON config profiles

## Install

Requires Python 3.10+. Zero dependencies.

```bash
git clone https://github.com/REV3R5ED/MetaTrace.git
cd MetaTrace
pip install -e .
```

## Quickstart

```bash
$ metatrace inspect photo.jpg
photo.jpg: JPEG 64x48, 1718 bytes, EXIF present + XMP + IPTC
evidence_id:  MT-20e7d60a98f61355
file:         /tmp/mt-docs/photo.jpg (1718 bytes)
format:       JPEG (image/jpeg), 64x48
encoding:     JPEG (baseline DCT)
sha256:      20e7d60a98f61355cc244fc1c68fadb894f726c6623352f9b7dd1618daddf74a
analyzed_at:  2026-10-03T00:32:28.151780Z (UTC)
tool:         metatrace 0.4.0

EXIF (normalized | raw kept in --json):
  make               TestMake
  model              TestModel 1000
  software           TestSoft 1.0
  lens               TestLens 50mm
  orientation        6 (Rotate 90 CW)
  datetime_original  2026-09-15T14:22:01 (timezone unknown)
  datetime_digitized 2026-09-15T14:22:01
  iso                100
  exposure           1/250 (0.004000s)
  f_number           f/2.8
  focal_length       50.0mm
  flash              did not fire
  thumbnail_ifd      absent
  raw tags:      14 captured

GPS:
  note         GPS coordinates record the location stored in the file's metadata; they do not prove where the photograph was taken.
  coordinates  49.337556, -123.162444
  altitude     42.0 m
  bearing      90.0° (true north)
  gps_time     2026-09-14T18:42:07Z
  method       GPS
  dop          2.5
  raw tags:    13 captured

XMP (normalized | raw packet + properties kept in --json):
  dc:title           Harbor at dusk
  dc:creator         ['Pouya Shini Karim']
  dc:rights          All rights reserved
  xmp:CreateDate     2026-09-14T18:42:07Z
  xmp:CreatorTool    TestSoft 2.0
  xmp:Rating         4
  photoshop:Credit   Test Agency
  namespaces:    4 seen
  raw props:     8 captured
  raw packet:    912 chars

IPTC/IIM (normalized | raw datasets kept in --json):
  caption            A harbor at dusk.
  keywords           ['harbor', 'dusk']
  byline             ['Pouya Shini Karim']
  credit             ['Test Agency']
  copyright          ['(c) 2026 Test']
  date_created       2026-09-14
  time_created       18:42:07+00:00
  raw datasets:  9 captured

ICC:          not present

Cross-source comparison (descriptive — not a verdict):
  capture_time: DIFFER
    EXIF DateTimeOriginal: 2026-09-15T14:22:01 (timezone unknown)
      raw: '2026:09:15 14:22:01'
    XMP xmp:CreateDate: 2026-09-14T18:42:07Z
    IPTC DateCreated/TimeCreated: 2026-09-14T18:42:07Z
      raw: '20260914 184207+0000'
  device_make: AGREE
    EXIF: TestMake
    XMP tiff:Make/tiff:Model: TestMake
  device_model: ONLY IN ONE SOURCE
    EXIF: TestMake TestModel 1000
      raw: 'TestModel 1000'
  software: DIFFER
    EXIF: TestSoft 1.0
    XMP tiff:Make/tiff:Model: TestSoft 2.0
  note: timezone-aware claims compare by UTC instant; timezone-naive claims compare by wall-clock as written. Agreement or difference here is not an authenticity verdict.
```

*(Output above is from a synthetic test file; dimensions, hashes, and
timestamps will differ for real photos.)*

Machine-readable output for pipelines:

```bash
metatrace inspect photo.jpg --json | jq '.data.analysis.exif.gps.latitude'
metatrace inspect photo.jpg --map-link  # OpenStreetMap URL for GPS coords
metatrace inspect photo.jpg --sha512    # also compute SHA-512
metatrace timeline photo.jpg            # chronological timestamp claims
metatrace config show                   # effective configuration
```

See [docs/USAGE.md](docs/USAGE.md) for a scenario walkthrough with
screenshots: a photo arrives as evidence — trace its story step by step.

## Roadmap

Per the master plan, each release is independently useful:

- **v0.1** — Core framework, file identification, hashes, basic EXIF ✅
- **v0.2** — Full EXIF + GPS normalization (DMS→decimal, validity checks) ✅
- **v0.3** — XMP/IPTC/ICC extraction + conflicting-field comparison ✅
- **v0.4** — Timestamp and device normalization, cross-field comparison ✅
- **v0.5** — Batch analysis, parallel processing, duplicate detection
- **v0.6** — Consistency/anomaly engine (confidence + explanation per flag)
- **v0.7** — Embedded thumbnail/content analysis
- **v0.8** — Case management, chain of custody, evidence manifests
- **v0.9** — Search, timeline, geographic correlation
- **v1.0** — Stable CLI/API, professional reporting (JSON/CSV/HTML/PDF)

## Forensic reliability

- Source files are only ever opened **read-only**; MetaTrace never writes to evidence
- **Hash before analysis**: digests are computed before any parsing
- Every result records the exact tool version and UTC analysis timestamp
- Raw observed values are preserved alongside normalized derivations
- Parser failures are recorded as warnings — partial results are kept, never hidden
- Input size and value-size bounds guard against decompression bombs

## Development

```bash
pip install -e '.[dev]'
pytest -q        # 90 tests, coverage gate 80%
ruff check . && ruff format --check .
mypy src
```

See [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), and [CHANGELOG](CHANGELOG.md).
