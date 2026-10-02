# MetaTrace in action — scenario walkthrough

> **Scenario:** a photo arrives as evidence. Someone claims it was taken
> on a specific camera, on a specific date. Your job: extract everything
> the file can technically tell you — and separate what you *observe*
> from what you *conclude*.
>
> Every command below is real output from MetaTrace v0.2.0
> (screenshots 01–02 were captured under v0.1.0; the GPS step is new
> in v0.2.0).

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

## Step 5 — Feed the machines

Every inspection also emits a stable JSON envelope for case files,
pipelines, and later correlation:

```
$ metatrace inspect evidence-photo.jpg --json
{
  "tool": "metatrace",
  "version": "0.2.0",
  "command": "inspect",
  "timestamp": "2026-10-02T23:17:17Z",
  "status": "ok",
  "data": { "identity": {...}, "exif": {"normalized": {...}, "raw": {...}} },
  ...
}
```

Exit codes: `0` = ok, `1` = findings/warnings, `2` = error.

## What's next

v0.2 covers identification, hashing, full EXIF, and GPS normalization.
The roadmap adds XMP/IPTC/ICC parsing, timestamp analysis, batch
processing, the anomaly engine, thumbnail inspection, case management,
and full reporting — each on the same evidence-first foundation.
