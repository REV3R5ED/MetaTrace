# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
