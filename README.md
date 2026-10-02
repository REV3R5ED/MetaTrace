# MetaTrace

**Trace the story behind the image.**

MetaTrace is a Python image-forensics and metadata-analysis platform. It starts as a reliable metadata extractor — file identification, cryptographic hashes, EXIF parsing — and grows into a full investigation platform: GPS normalization, XMP/IPTC/ICC, anomaly detection, case management, and defensible reporting.

The core forensic rule: **observed metadata is kept verbatim; normalized fields are derived alongside it, never merged.** MetaTrace records what an image *technically contains* and never labels an image "fake" from metadata alone.

## License

MIT — see [LICENSE](LICENSE). Free for personal and commercial use.

## v0.1 — what works today

- **File identification**: magic-byte format detection (JPEG, PNG, GIF, BMP, WebP, TIFF) and dimension parsing — pure stdlib, no Pillow
- **Evidence hashing**: SHA-256 (always) and optional SHA-512, streamed, computed *before* any parsing
- **Basic EXIF**: TIFF/EXIF parser in pure stdlib (both endiannesses) — make/model, timestamps, orientation, ISO, exposure, aperture, focal length, flash, lens, software; raw tag values preserved verbatim
- **Defensive parsing**: truncated or malicious files produce recorded warnings, never crashes; file-size and value-size bounds
- **CLI**: `metatrace inspect <image>` with human-readable output and `--json`; structured exit codes (0 ok / 1 findings / 2 error); audit logging of every invocation
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
sample-photo.jpg: JPEG 4032x3024, 318 bytes, EXIF present
evidence_id:  MT-bc4cd04ace573156
file:         /tmp/sample-photo.jpg (318 bytes)
format:       JPEG (image/jpeg), 4032x3024
encoding:     JPEG (baseline DCT)
sha256:      bc4cd04ace573156a24b34ac77aa3a174d8935ece710575f70b62ce78f77bf01
analyzed_at:  2026-10-02T23:16:11.037638Z (UTC)
tool:         metatrace 0.1.0

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
  gps_ifd            absent
  thumbnail_ifd      absent
  raw tags:      13 captured
```

Machine-readable output for pipelines:

```bash
metatrace inspect photo.jpg --json | jq '.data.analysis.exif.make'
metatrace inspect photo.jpg --sha512   # also compute SHA-512
metatrace config show                  # effective configuration
```

See [docs/USAGE.md](docs/USAGE.md) for a scenario walkthrough with
screenshots: a photo arrives as evidence — trace its story step by step.

## Roadmap

Per the master plan, each release is independently useful:

- **v0.1** — Core framework, file identification, hashes, basic EXIF ✅
- **v0.2** — Full EXIF + GPS normalization (DMS→decimal, validity checks)
- **v0.3** — XMP/IPTC/ICC extraction + conflicting-field comparison
- **v0.4** — Timestamp and device normalization, cross-field comparison
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
