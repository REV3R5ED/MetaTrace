# MetaTrace in action — scenario walkthrough

> **Scenario:** a photo arrives as evidence. Someone claims it was taken
> on a specific camera, on a specific date. Your job: extract everything
> the file can technically tell you — and separate what you *observe*
> from what you *conclude*.
>
> Every command below is real output from MetaTrace v0.4.0
> (screenshots 01–02 were captured under v0.1.0, 03 under v0.2.0,
> 04 under v0.3.0; step 7 is new in v0.4.0).

## Step 1 — Identify and hash the evidence

Before anything else, identify the file and record its integrity. The
source file is never modified; the hash is captured first.

```
$ metatrace inspect evidence-photo.jpg
```

![The evidence — file identification and EXIF](images/01-the-evidence.png)

You immediately have: format and dimensions, a SHA-256 fingerprint, an
evidence ID, and the tool version — everything needed to reference this
file defensibly later.

## Step 2 — Read what the camera wrote

The EXIF block is the camera's own testimony: make and model, lens,
capture timestamp, exposure settings. MetaTrace shows normalized fields
for quick reading and keeps every raw tag value in `--json` for
verification.

Observations from this file:

- **Device:** Canon EOS R5 with an RF 24-70mm lens
- **Captured:** 2026-09-14T18:42:07 (timezone not recorded — noted, not assumed)
- **Settings:** ISO 400, 1/250s, f/2.8 — consistent with a real exposure
- **Software tag:** Adobe Lightroom 7.2 — the file passed through editing software

That last line is exactly where MetaTrace's discipline matters: the
software tag is an *observation*. It means the file went through
Lightroom, not that the image is fake. Metadata can be rewritten, copied,
or stripped — the tool reports, you interpret.

## Step 3 — Handle the file with no story

Not every image carries metadata. A screenshot, for example, has no EXIF
at all — and that absence is itself a finding, reported cleanly instead
of erroring out:

```
$ metatrace inspect screenshot.png
screenshot.png: PNG 1920x1080, 45 bytes, EXIF n/a
...
EXIF:         not present
```

![No metadata — graceful handling](images/02-no-metadata.png)

## Step 4 — Read the location claim (v0.2: GPS normalization)

When the file carries a GPS IFD, MetaTrace decodes it into decimal
coordinates, altitude, bearing, and a UTC timestamp — and validates
everything. Degrees/minutes/seconds rationals become signed decimals;
out-of-range values (latitude 95°, a 20000 m altitude) become explained
findings, never silent drops:

```
$ metatrace inspect gps-photo.jpg --map-link
```

![GPS location decoded from metadata](images/03-gps-location.png)

Observations from this file:

- **Coordinates:** 49.337556, -123.162444 (from 49°20'15.2"N 123°09'44.8"W)
- **Altitude:** 42.0 m above sea level · **Bearing:** 090° true north
- **GPS time:** 2026-09-14T18:42:07Z — recorded alongside, not merged
  with, the camera's `DateTimeOriginal` (2026-09-15T14:22:01, timezone
  unknown). Two clocks, two claims; the cross-check is yours to make.
- `--map-link` prints an OpenStreetMap URL for the coordinates. It only
  *builds* the URL — no network request is made, ever.

And the discipline, stated on every run: GPS coordinates record the
location **stored in the file's metadata**; they do not prove where the
photograph was taken. Metadata says; it never testifies.

## Step 5 — Read the publisher's labels (v0.3: XMP/IPTC/ICC)

A photo that has been through an editor, a newsroom, or a stock agency
often carries more than the camera's EXIF. MetaTrace now reads the
three other metadata standards that travel inside image files:

- **XMP** — Adobe's RDF/XML packet (JPEG APP1, PNG iTXt, WebP XMP
  chunk, TIFF tag 700): Dublin Core title/creator/rights, XMP Basic
  dates and rating, Photoshop credit/source.
- **IPTC/IIM** — the newsroom standard (JPEG APP13 Photoshop IRB):
  caption, keywords, byline, credit, copyright, creation date/time.
- **ICC** — the embedded color profile (JPEG APP2, PNG iCCP, TIFF tag
  34675): header fields (device class, color space, version, creation
  time, `acsp` signature check) plus the tag directory. No color math —
  the directory says what the profile claims to carry, which is what
  forensics needs first.

```
$ metatrace inspect published-photo.jpg
```

![XMP, IPTC and ICC sections with per-source dates](images/04-xmp-iptc-icc.png)

Observations from this file:

- **XMP:** title "Harbor at dusk", creator "Pouya Shini Karim",
  `xmp:CreateDate` 2026-09-14T18:42:07Z, rating 4, credit "Test Agency".
  The raw packet (912 chars) is kept verbatim in `--json`.
- **IPTC:** caption "A harbor at dusk.", keywords harbor/dusk, byline
  "Pouya Shini Karim", `DateCreated` 2026-09-14. All 9 datasets kept
  raw, including ones MetaTrace doesn't normalize by name.
- **ICC:** valid `acsp` signature, display-device profile, RGB → XYZ,
  version 2.1.0, one tag in the directory.
- **Three dates, three claims:** EXIF says 2026-09-15T14:22:01, XMP says
  2026-09-14T18:42:07Z, IPTC says 2026-09-14. MetaTrace shows them side
  by side and **never merges them** — deciding whether they agree is
  the v0.6 anomaly engine's job, not this parser's.

Defensive as ever: malformed XMP XML becomes a warning (the packet
still counts as observed), truncated IPTC records keep partial
results, and an ICC profile that fails the `acsp` check is reported
with `signature_valid: false` plus a medium-severity finding.

## Step 6 — Feed the machines

Every inspection also emits a stable JSON envelope for case files,
pipelines, and later correlation:

```
$ metatrace inspect evidence-photo.jpg --json
{
  "tool": "metatrace",
  "version": "0.3.0",
  "command": "inspect",
  "timestamp": "2026-10-02T23:17:17Z",
  "status": "ok",
  "data": { "identity": {...}, "exif": {...}, "xmp": {...}, "iptc": {...}, "icc": {...},
            "timestamps": [...], "device": {...}, "comparison": [...], "timeline": [...] },
  ...
}
```

Exit codes: `0` = ok, `1` = findings/warnings, `2` = error.

## Step 7 — Normalize, compare, and line up time (v0.4)

A photo can carry the same fact in three different standards — and
the three don't always agree. v0.4 parses every timestamp flavor
into one model, normalizes device identity per source, and compares
the claims **descriptively**: agree / differ / only-in-one-source,
with raw values shown. No verdicts, no scores, no auto-resolution —
judging a conflict is the v0.6 anomaly engine's job.

```
$ metatrace inspect conflict-photo.jpg
$ metatrace timeline conflict-photo.jpg
```

![Cross-source comparison and timeline](images/05-compare-timeline.png)

Observations from this file:

- **Timestamps, one model:** EXIF `DateTimeOriginal` is timezone-naive
  (`value_utc: null` — MetaTrace never invents a timezone), XMP
  `xmp:CreateDate` carries `Z`, IPTC `DateCreated`+`TimeCreated`
  carries `+0000`; all three normalize to comparable instants.
- **capture_time: DIFFER** — the camera claims 2026-09-15T14:22:01
  (naive), the publisher's XMP/IPTC claims 2026-09-14T18:42:07Z.
  MetaTrace records the difference and shows both raws; it does not
  pick a winner.
- **device_make / device_model: AGREE** — EXIF says `canon` /
  `canon eos r5`, XMP says `Canon ` / `EOS R5`. Different spellings,
  same device: normalization sees through the variants while the raw
  strings stay verbatim in `--json`.
- **software: DIFFER** — EXIF `TestSoft 1.0` vs XMP `TestSoft 2.0`.
  Recorded, not judged.
- **Timeline:** `metatrace timeline` lines every claim up
  chronologically — UTC-known first, then the naive EXIF claim by
  wall-clock, each labeled with its source. The filesystem mtime is
  listed too, explicitly marked *not image metadata*.

Unparseable timestamps (a garbage XMP date, an IPTC date that isn't
a date) are kept verbatim with `parseable: false` and surface a
low-severity finding — never a silent drop, never a crash.

## Step 8 — Triage a whole directory (v0.5: batch analysis)

A case rarely arrives as one file. Point MetaTrace at a directory and
it runs the full pipeline — identify, hash, EXIF/XMP/IPTC/ICC,
normalize, compare — on every recognized image, in parallel:

```
$ metatrace batch /tmp/batchdemo --jobs 2
```

![Batch summary: formats, devices, capture days, locations, duplicates](images/06-batch.png)

Observations from this run:

- **Magic bytes, not extensions:** `README.txt` is skipped with a
  recorded reason instead of crashing the batch. Seven files in,
  six analyzed, one skipped, zero errors.
- **Duplicates:** `harbor-01.jpg` and `harbor-01-copy.jpg` are
  byte-identical (SHA-256) — one duplicate group. Exact content
  match only; perceptual near-duplicate grouping is v0.7's job.
- **Devices:** the normalized claims sort the set into Canon EOS R5
  ×2, Nikon Z 8, Apple iPhone 16, and one file whose device is
  unknown — no manual sorting.
- **Locations:** the iPhone shot's GPS claim lands in the
  `~49.34, -123.16` grid cell, and the output repeats the
  disclaimer twice: coordinates are metadata claims, never proof of
  where a photo was taken.
- **Conflicts counted, not judged:** `agency-04.jpg` has EXIF and
  XMP disagreeing on capture time, so the summary counts one file
  with conflicting timestamp claims — descriptive, exactly like the
  single-image comparison in Step 7.
- **Machine formats:** `--json` emits per-file analyses plus the
  summary and groups (stable, deterministic ordering — same input
  twice gives byte-identical output modulo timestamps); `--csv`
  emits one row per file for spreadsheets. `--timeline` adds the
  cross-image timeline.

A progress line (`N/M files`) goes to stderr on human runs and stays
silent under `--json`/`--csv`, so pipelines never see it.

## Step 9 — Judge the disagreements (v0.6: anomaly engine)

Steps 1–8 record what the metadata *says*. The anomaly engine is the
first part of MetaTrace that *judges* what it says — with rules you
can read, confidence you can interpret, and an explicit statement of
what each finding does not prove:

```
$ metatrace analyze case-1147.jpg
```

![Anomaly flags: timestamp conflict and device mismatch with confidence and disclaimers](images/07-anomalies.png)

Observations from this run:

- **Four flags, five rules:** the image trips `timestamp-conflict`
  (EXIF says Sep 14, XMP says Sep 15), `device-identity-mismatch`
  (Canon vs NIKON), `serial-number-conflict` (two sources name
  different cameras — the only high-severity flag, so it becomes a
  core finding), and `software-chain-resave` (Photoshop vs GIMP).
  The thumbnail aspect check passes silently.
- **Honest confidence:** the timestamp conflict scores 60, not 85 —
  the EXIF claim is timezone-naive, so the engine says the gap may
  be a timezone offset rather than a real time difference. A
  three-day gap between two timezone-aware claims would score 85.
- **Every flag ends with what it does NOT prove:** "a timestamp
  conflict does not prove manipulation — camera clocks drift…".
  Confidence measures certainty about the *observation*, never
  about intent.
- **No flags is a statement too:** a clean image prints "no
  anomalies detected by the v0.6 rule set" — never "image is
  authentic".
- **Tunable strictness:** `--tolerance 300` widens the
  timestamp-conflict window to five minutes; `--json` emits the
  flags, notes, and tolerance for pipelines. `metatrace batch`
  runs the engine per file and adds anomaly counts to the summary.

## Step 10 — Open the embedded previews (v0.7: thumbnails)

Many JPEGs carry a smaller copy of themselves inside the EXIF data —
a preview thumbnail written by the camera. MetaTrace extracts it
without decoding any pixels (the standard library has no JPEG
decoder, and v0.7 adds no dependencies):

```
$ metatrace thumbnails demo_thumb.jpg
```

![Embedded thumbnail listing and the thumbnail-mismatch anomaly flag](images/08-thumbnails.png)

Observations from this run:

- **Listed, not decoded:** one embedded thumbnail — `EXIF IFD1
  (JPEG blob)`, 320x240, SHA-256 recorded so the bytes can be
  re-found. Dimensions come from a JPEG SOF marker scan of the
  blob; TIFF thumbnails report dimensions from their tags
  directly. PNG and WebP have no thumbnail mechanism and say so —
  never an error.
- **`--extract` is the one write operation:** `metatrace
  thumbnails demo_thumb.jpg --extract` writes
  `<evidence-id>_thumb0.jpg` (sanitized name) and refuses to
  overwrite an existing file without `--force`. Everything else
  MetaTrace does is read-only.
- **Metadata-level comparison only:** the anomaly engine's
  `thumbnail-mismatch` rule now replaces the v0.6 aspect-only
  check. Here it fires low-confidence: the 320x240 (4:3) thumbnail
  vs the 6000x4000 (3:2) main image differ by 11.1% in aspect. A
  thumbnail *larger* than its main image, or an IFD1 that claims a
  thumbnail with no extractable bytes ("stripped"), scores medium.
  Encoder signals (DQT table count, DHT presence) are compared as
  an explicitly *weak* signal — never a verdict.
- **Batch counts them:** `metatrace batch` reports per-file
  thumbnail counts plus `files_with_thumbnails` /
  `total_thumbnails` in the summary and a `thumbnails` CSV column.

## Step 11 — Put the evidence in a case (v0.8: case management)

Single-image analysis answers "what does this file contain". A case
answers "what do we know, who touched it, and what did we decide".
MetaTrace cases live in a SQLite database
(`~/.metatrace/cases.db`, `METATRACE_STATE_DIR` override) with a
versioned schema — a database from a newer schema fails cleanly
instead of being silently misread:

```
$ metatrace case create --title "Gallery dispute" --description "two photos, one story"
$ metatrace case add MT-CASE-2026-001 /tmp/shot_a.jpg --note "exhibit A"
$ metatrace case add MT-CASE-2026-001 /tmp/shot_b.jpg --note "exhibit B"
$ metatrace case flags MT-CASE-2026-001
$ metatrace case custody MT-CASE-2026-001
```

![Case creation, evidence registration, flag listing and chain of custody](images/09-case-management.png)

Observations from this run:

- **Evidence is hashed, never copied:** `case add` records the
  image's SHA-256, its path, and a frozen JSON snapshot of the full
  `analyze` output (analysis + anomaly flags). The image file itself
  stays where it is — copying multi-gigabyte evidence into a case
  database would be wasteful, and the hash plus snapshot is what
  `case verify` needs to detect later modification.
- **Flags travel with the evidence:** exhibit B's EXIF/XMP timestamp
  conflict was caught by the anomaly engine at add time and stored
  in the snapshot. `case flags` shows it as `unreviewed` until an
  analyst records a verdict with `case review --flag
  <evidence-id>:<rule-id> --verdict confirmed|dismissed|unsure`.
  Reviews are append-only — a second review doesn't erase the first,
  and flags are never deleted.
- **Chain of custody is automatic:** every mutation — create, add,
  note, review, status change, manifest, report — appends a UTC event
  with `actor: analyst`. MetaTrace has no authentication, so the
  record says "the local user of this machine", nothing stronger.
- **Manifests and reports are reproducible:** `case manifest`
  freezes paths, hashes, snapshot hashes and the custody count behind
  a top-level SHA-256; `case verify` re-hashes the files on disk and
  reports ok / changed / missing (changed files become high-severity
  findings); `case report --output DIR` bundles case.json,
  evidence.json, custody.json, flags.json, notes.txt and a
  report-manifest.json with per-artifact digests. A non-empty output
  dir is refused without `--force`.
- **Closing needs a reason:** `case status CASE-ID closed` without
  `--note` exits 2 — a case can't be closed silently.

## What's next

v0.8 covers identification, hashing, full EXIF, GPS normalization,
XMP/IPTC/ICC extraction, timestamp and device normalization,
descriptive cross-source comparison, single-image timelines, batch
analysis with duplicate detection and grouping, the rule-based
anomaly engine, embedded thumbnail extraction with metadata-level
comparison, and case management with chain of custody, evidence
manifests, flag reviews and reproducible reports. The
roadmap adds search, timelines, and geographic correlation — each on
the same evidence-first foundation.
