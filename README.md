# MetaTrace

**Trace the story behind the image.**

MetaTrace is a Python image-forensics and metadata-analysis platform. It starts as a reliable metadata extractor — file identification, cryptographic hashes, EXIF parsing — and grows into a full investigation platform: GPS normalization, XMP/IPTC/ICC, anomaly detection, case management, and defensible reporting.

The core forensic rule: **observed metadata is kept verbatim; normalized fields are derived alongside it, never merged.** MetaTrace records what an image *technically contains* and never labels an image "fake" from metadata alone.

## License

MIT — see [LICENSE](LICENSE). Free for personal and commercial use.

## v0.9 — what works today

- **Search index**: `metatrace batch --index photos.json` or `metatrace search --build-index DIR --index photos.json` writes a deterministic JSON index (one record per analyzed file: path, SHA-256, format, device claims, normalized timestamps, GPS, thumbnail count, anomaly rule IDs, caption/keywords). The index stores no pixel data and is queried fully offline — no re-analysis. An `index_version` field guards the format: an index from a newer/older MetaTrace fails with a clean error telling you to rebuild
- **Composable filters (AND)**: `metatrace search --index photos.json --device "Canon" --date 2026-09-15 --date-range 2026-09-01..2026-09-30 --gps --near 49.34,-123.16,10 --anomaly timestamp-conflict --text "sunset" --hash a1b2c3d4`. `--near` uses haversine distance (stdlib math) and the radius is capped at 1000 km; `--text` is a literal substring over maker/model/software/caption/keywords/title (regex characters are never special); `--hash` takes a SHA-256 prefix (≥ 8 hex chars) or full hash
- **Location clusters**: `metatrace search --index photos.json clusters [--same filters]` groups geotagged images with ~1km grid clustering plus adjacent-cell merging (deterministic ordering). Each cluster reports center, radius, image count, and capture-day time span — every geographic output keeps the claimed-location warning: GPS metadata is a claim, not proof
- **Filtered timelines**: `metatrace search --index photos.json timeline [--same filters] [--format csv]` lists timestamp claims across images using the v0.4 ordering rule (UTC-known first, then timezone-naive by wall-clock, then unparseable), exportable as CSV
- **CLI**: `metatrace search ...` with human-readable output and `--json`; structured exit codes (0 ok / 1 findings / 2 error); empty result sets are a valid outcome (exit 0, "No records match the given filters"); bad filters or an unreadable/stale index exit 2; audit logging of every invocation

## v0.8 — what works today

- **Case management**: `metatrace case create --title "..."` opens a case (`MT-CASE-2026-001` style IDs); `case list` / `case show` for overviews; `case status` moves open → in-progress → closed (closing requires `--note`)
- **Evidence without copying**: `case add CASE-ID image.jpg --note "..."` registers an image as evidence — the file is hashed and a full `analyze` snapshot (analysis + anomaly flags) is frozen into the SQLite case DB (`~/.metatrace/cases.db`, `METATRACE_STATE_DIR` override). The image itself is never copied; the hash + snapshot is the evidence record
- **Chain of custody**: every mutation (create, add, note, flag review, status, manifest, report) appends a custody event (UTC timestamp, action, `actor: analyst` — MetaTrace has no auth, so the record states the local user, nothing stronger). `case custody CASE-ID` lists the full chain
- **Evidence manifests**: `case manifest CASE-ID` builds a JSON manifest (paths, SHA-256s, snapshot hashes, custody count) with a top-level SHA-256 over the canonical encoding; `case verify CASE-ID` re-hashes files on disk and reports ok / changed / missing
- **Flag reviews**: anomaly flags are stored per evidence item; `case flags` lists them; `case review CASE-ID --flag <evidence-id>:<rule-id> --verdict confirmed|dismissed|unsure --note "..."` records an append-only review — flags are never deleted or rewritten
- **Reproducible reports**: `case report CASE-ID --output DIR` writes case.json, evidence.json, custody.json, flags.json, notes.txt, and a report-manifest.json with per-artifact SHA-256 digests; refuses a non-empty output dir without `--force`
- **CLI**: `metatrace case ...` (12 subcommands) with human-readable output and `--json`; structured exit codes (0 ok / 1 findings / 2 error); audit logging of every invocation

## v0.7 — what works today

- **Embedded thumbnails**: `metatrace thumbnails <image>` lists embedded previews — JPEG EXIF IFD1 blobs (`JPEGInterchangeFormat`), uncompressed TIFF IFD1 strips, standalone TIFF IFD1 — with byte size, SHA-256, dimensions (JPEG SOF marker scan or TIFF tags — no pixel decoding, stdlib has no JPEG decoder), format by magic bytes, and coarse encoder signals (DQT table count / DHT presence). PNG/WebP report "no thumbnail mechanism", never an error
- **`--extract`**: writes each thumbnail to `<evidence-id>_thumb<N>.<ext>` (sanitized); refuses to overwrite without `--force`; the one write operation — everything else is read-only
- **Metadata-level comparison**: thumbnail vs main image on aspect ratio, scale factor, and encoder signals — each labeled with its limits ("weak signal", never a verdict)
- **Anomaly engine upgrade**: the v0.6 aspect-only check is now the fuller `thumbnail-mismatch` rule — stripped/unreadable thumbnails (IFD1 claims one, none extractable) → medium; thumbnail larger than the main image → medium; aspect differs → low; encoder signals differ on both axes → low (explicitly weak). Every flag keeps the "what this does NOT prove" discipline
- **Batch integration**: per-file thumbnail counts, `files_with_thumbnails` / `total_thumbnails` in the summary, `thumbnails` CSV column
- **CLI**: `metatrace thumbnails <image> [--extract] [--out-dir DIR] [--force]` with human-readable output and `--json`; structured exit codes (0 ok / 1 findings / 2 error); audit logging of every invocation and extraction

## v0.6 — what works today

- **Anomaly engine**: `metatrace analyze <image>` runs five deterministic, rule-based consistency checks — capture-timestamp conflicts across EXIF/XMP/IPTC (with `--tolerance`, default 60s), GPS-longitude vs capture-timezone plausibility (±2h tolerance for borders/DST), device make/model mismatches after normalization, EXIF-vs-XMP camera serial conflicts, software-chain re-saves (product names compared, versions ignored), and IFD1 thumbnail aspect-ratio checks (dimensions only — pixel comparison is v0.7's job)
- **Confidence + explanation per flag**: every flag carries severity (low/medium/high), a 0–100 confidence, the exact values compared, the sources involved, and a human explanation that always ends with what the observation does *not* prove. Confidence measures certainty about the *observation* (how far apart two timestamps are), never about *intent* — a high-confidence flag means "the metadata really disagrees this much", not "this image was manipulated"
- **Honest edge handling**: timezone-naive timestamps cap timestamp-conflict confidence at 60 (the gap may be a timezone offset); GPS with naive timestamps yields an informational note ("cannot assess"), never a flag; no flags prints "no anomalies detected by the v0.7 rule set" — never "image is authentic"
- **Batch integration**: `metatrace batch` runs the engine per file and reports anomaly counts in the summary (per-file counts in `--json`); high-severity flags become core findings
- **CLI**: `metatrace analyze <image> [--tolerance SECONDS]` with human-readable output and `--json`; structured exit codes (0 ok / 1 findings / 2 error); audit logging of every invocation

## v0.5 — what works today

- **Batch analysis**: `metatrace batch <dir>` scans a directory (opt-in `--recursive`) and runs the full pipeline on every recognized image — per-file results plus a batch summary. Files are identified by magic bytes, never extensions; non-images are skipped with a recorded reason, per-file failures become error records, the batch never crashes
- **Parallel processing**: `ThreadPoolExecutor` with `--jobs N` (default: config `batch_jobs`, or min(4, CPU count) when unset); output ordering is by path regardless of completion order, so runs are deterministic; a stderr progress line (`N/M files`) shows progress on human runs, silent with `--json`/`--csv`
- **Duplicate detection**: exact content duplicates grouped by SHA-256 (near-duplicate/perceptual grouping is v0.7's job)
- **Grouping**: by normalized device (make + model claim), by claimed capture day, and by ~1km GPS grid cell — every location output repeats that coordinates are metadata claims, not proof of where a photo was taken
- **Cross-image timeline**: `metatrace batch --timeline` lines up every timestamp claim from every file under the v0.4 ordering rule
- **Batch summary**: counts by format/device/capture-day/location, duplicate groups, files-with-GPS count, files-with-conflicting-timestamps count (descriptive DIFFER counts, never verdicts); `--json` (per-file results + summary + groups) and `--csv` (one row per file); exit codes 0 ok / 1 findings / 2 error

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
- **v0.5** — Batch analysis, parallel processing, duplicate detection ✅
- **v0.6** — Consistency/anomaly engine (confidence + explanation per flag) ✅
- **v0.7** — Embedded thumbnail extraction + metadata-level comparison ✅
- **v0.8** — Case management, chain of custody, evidence manifests ✅
- **v0.9** — Search, timeline, geographic correlation ✅
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
