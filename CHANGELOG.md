# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.5.0] - 2026-10-03

### Added

- Batch analysis (plan Phase 7): new `batch/` package, pure stdlib.
- `metatrace batch <dir>`: full pipeline over every recognized image
  in a directory (`--recursive` opt-in). Files are identified by
  magic bytes, never extensions; non-images are skipped with a
  recorded reason; per-file failures become error records — the batch
  never crashes.
- Parallel processing via `ThreadPoolExecutor` (`--jobs N`; default
  is config `batch_jobs`, or min(4, CPU count) when unset).
  Deterministic output ordering (by path); stderr progress line on
  human runs, silent with `--json`/`--csv`.
- Duplicate detection by SHA-256 (exact content match; perceptual
  grouping is v0.7's job).
- Grouping by normalized device (make + model claim), by claimed
  capture day, and by ~1km GPS grid cell. Every location output
  repeats the claimed-location disclaimer.
- `metatrace batch --timeline`: cross-image timeline of every
  timestamp claim, ordered by the v0.4 rule.
- Batch summary: counts by format/device/capture-day/location,
  duplicate groups, files-with-GPS, files-with-conflicting-timestamps
  (descriptive DIFFER counts, never verdicts).
- `--json` (per-file results + summary + groups) and `--csv` (one
  row per file); exit codes 0 ok / 1 findings / 2 error.
- New config knob `batch_jobs` (0 = automatic).

## [0.4.0] - 2026-10-02

### Added

- Timestamp & device normalization, cross-field comparison, timelines
  (plan Phase 6): new `normalize/` package, pure stdlib.
- `normalize/timestamps.py`: every timestamp flavor parsed into one
  `NormalizedTimestamp` model — EXIF `DateTimeOriginal`/`CreateDate`/
  `ModifyDate` (+ `OffsetTime*` offsets converted to UTC, naive claims
  keep `value_utc: null`), XMP ISO-8601 (numeric offsets converted,
  date-only → day precision), IPTC `DateCreated`+`TimeCreated`,
  GPS (UTC), ICC creation time (UTC per ICC spec), filesystem mtime
  (labeled as filesystem, never image metadata). A timezone is never
  invented; unparseable values are kept verbatim with `parseable:
  false` and surface a low-severity "unparseable timestamp" finding
  for XMP/IPTC.
- `normalize/devices.py`: maker/model/software normalized per source —
  case/whitespace/punctuation-insensitive comparison keys plus
  canonical display forms ("canon"/"Canon "/"CANON INC." → "Canon";
  model prefixed to "Make Model" form when the maker is known).
  EXIF serial numbers (`BodySerialNumber`, `LensSerialNumber`,
  `CameraOwnerName`) extracted verbatim — identifiers are never
  normalized.
- `normalize/compare.py`: descriptive cross-field comparison of
  capture time, device make/model and software chain across
  EXIF/XMP/IPTC — agree / differ / only-in-one-source / no-data with
  raw values shown. No verdicts, no scores, no auto-resolution;
  every fact states the comparison rule and that agreement is not an
  authenticity verdict (judging conflicts is the v0.6 anomaly
  engine's job).
- `normalize/timeline.py` + `metatrace timeline <image>`: chronological
  list of every timestamp claim — UTC-known first, then
  timezone-naive by wall-clock, then unparseable — human + `--json`.
- `metatrace inspect` renders the EXIF serial fields and a new
  "Cross-source comparison" section (replacing the v0.3 side-by-side
  date display whose note is now outdated).

## [0.3.0] - 2026-10-02

### Added

- Extended metadata extraction (plan Phase 5): XMP, IPTC/IIM, and ICC
  profiles, all in pure stdlib.
- New `parsers/containers.py`: shared defensive traversal for JPEG
  segments, PNG chunks, and WebP RIFF chunks (one walk per container,
  reused by all three v0.3 parsers).
- XMP (`parsers/xmp.py`): packet location in JPEG APP1
  (`http://ns.adobe.com/xap/1.0/`), PNG iTXt (`XML:com.adobe.xmp`,
  plain or zlib), WebP `XMP ` chunk, TIFF tag 700. RDF/XML parsed with
  stdlib `xml.etree`; entity/DOCTYPE declarations refused outright,
  malformed XML becomes a warning — an unparseable packet still counts
  as observed. Normalized views: Dublin Core (title/creator/
  description/rights), XMP Basic (CreateDate, ModifyDate, CreatorTool,
  Rating), Photoshop (AuthorsPosition, Credit, Source), EXIF-in-XMP
  (`tiff:*`/`exif:*`); full property flattening kept raw.
- IPTC/IIM (`parsers/iptc.py`): Photoshop 8BIM parsing of JPEG APP13,
  IPTC-NAA record decoding with bounds-checked standard and extended
  dataset lengths. Normalized: object name, keywords, byline, credit,
  copyright, caption, date/time created (`YYYYMMDD` → ISO); unknown
  datasets kept verbatim in raw; truncated records keep partial results.
- ICC (`parsers/icc.py`): profile location in JPEG APP2 (multi-chunk
  reassembly in sequence order, missing chunks → warning), PNG iCCP
  (zlib with decompression-bomb cap), TIFF tag 34675. Header parse:
  size, CMM, version, device class, color space, PCS, creation time,
  `acsp` signature check, rendering intent, manufacturer/model; tag
  directory listing (signature + offset + size). No color math — header
  + directory is the v0.3 scope. A failed `acsp` check surfaces a
  medium-severity "ICC profile signature invalid" finding.
- `metatrace inspect` renders XMP / IPTC / ICC sections (human + JSON).
  New "Capture dates claimed per source" section shows EXIF
  DateTimeOriginal, XMP CreateDate/ModifyDate, and IPTC DateCreated
  side by side — never merged; cross-source comparison stays the v0.6
  anomaly engine's job.
- New models `XmpData`, `IptcData`, `IccData` in `core/models.py`
  (observed-vs-normalized separation preserved); new config bounds
  `xmp_max_packet_bytes` and `icc_max_profile_bytes`.
- Docs: `docs/USAGE.md` gains a v0.3 scenario step with a real terminal
  screenshot (`docs/images/04-xmp-iptc-icc.png`); README "what works"
  and roadmap updated to v0.3.
- 63 new tests (all four XMP containers, malformed/entity XML,
  truncated IRB, out-of-order ICC chunks, bad ICC signature, iCCP
  round-trip, multi-source date display); 208 total, coverage 87%.

## [0.2.0] - 2026-10-02

### Added

- Full EXIF + GPS normalization (plan Phase 4). The TIFF parser now
  decodes the GPS sub-IFD (kept in its own tag namespace, never merged
  with IFD0/EXIF tags); new `geo/coords.py` package converts DMS
  rationals + N/S/E/W refs to decimal degrees, altitude (+/− sea level
  via GPSAltitudeRef), bearing (true/magnetic, 0–360°), GPSDateStamp +
  GPSTimeStamp to UTC ISO-8601, DOP, and processing method.
- New `GeoData` model in `core/models.py` (`ExifData.gps`): normalized
  fields alongside verbatim raw GPS tags; observed-vs-normalized
  separation preserved. Validity checks (lat −90..90, lon −180..180,
  sane altitude bounds) produce explained `validity_issues` — invalid
  values are flagged and rejected from normalized output, never
  silently dropped; they surface as "GPS metadata validity issue"
  findings.
- `metatrace inspect` GPS section: coordinates, altitude, bearing,
  GPS time, method, DOP; `gps: not present` when absent. Every run
  states the forensic rule: coordinates record the location stored in
  the file's metadata; they do not prove where the photograph was
  taken. EXIF `DateTimeOriginal` is kept as-is ("timezone unknown");
  GPS time is recorded alongside it, never merged.
- Optional `--map-link` flag: prints an OpenStreetMap URL for decoded
  coordinates (URL construction only — no network request).
- Docs: `docs/USAGE.md` gains a GPS scenario step with real output and
  screenshot (`docs/images/03-gps-location.png`); README roadmap v0.2
  checked off.
- 55 new tests (all four hemispheres, ref variants, above/below sea
  level, invalid coordinates, missing GPS IFD, big-endian TIFF,
  `--map-link`); coverage 89%.

## [0.1.0] - 2026-10-02

### Added

- Core framework: JSON config profiles (`core/config.py`), normalized
  forensic models with observed-vs-normalized separation (`core/models.py`),
  streaming SHA-256/SHA-512 hashing (`core/hashing.py`), centralized
  logging and audit log (`core/logging.py`), shared result envelope and
  exit codes 0/1/2 (`core/results.py`), parser/module registry with
  entry-point discovery stub (`core/plugins.py`).
- File identification (`image/identify.py`): magic-byte detection and
  dimension parsing for JPEG, PNG, GIF, BMP, WebP (VP8/VP8L/VP8X), TIFF —
  pure stdlib, header-only reads, read-only.
- Basic EXIF parser (`parsers/exif.py`): defensive TIFF/IFD parser in pure
  stdlib (both endiannesses, bounded tag counts and value sizes); extracts
  make/model/software/lens, orientation, DateTimeOriginal/Digitized,
  ISO, exposure time, F-number, focal length, flash; records GPS IFD and
  thumbnail IFD presence (decoding in later phases); raw tag values kept
  verbatim, malformed input yields warnings never crashes.
- CLI: `metatrace inspect <image>` (+ `--sha512`), `metatrace config show`;
  human-readable default output, `--json` mode (accepted before or after
  the subcommand); structured exit codes; `--version`, `--verbose`,
  `--config`, `--profile`; audit logging of every invocation.
- MIT license (see LICENSE).
- Docs: README (with real sample output), CHANGELOG, SECURITY,
  CONTRIBUTING.
- Packaging: `pyproject.toml` (stdlib-only, Python 3.10–3.13), console
  script + `python -m metatrace`, ruff/mypy/coverage/pytest tooling.
- CI: ruff, mypy, pytest across 3.10–3.13 on ubuntu, a Windows smoke job
  (builds a PNG byte-by-byte and inspects it), build + twine check,
  Dependabot.
- 90 pytest tests with byte-level synthetic fixtures (no real photos, no
  network); coverage gate 80%.
