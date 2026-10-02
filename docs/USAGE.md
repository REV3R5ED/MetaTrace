# MetaTrace in action — scenario walkthrough

> **Scenario:** a photo arrives as evidence. Someone claims it was taken
> on a specific camera, on a specific date. Your job: extract everything
> the file can technically tell you — and separate what you *observe*
> from what you *conclude*.
>
> Every command below is real output from MetaTrace v0.1.0.

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

## Step 4 — Feed the machines

Every inspection also emits a stable JSON envelope for case files,
pipelines, and later correlation:

```
$ metatrace inspect evidence-photo.jpg --json
{
  "tool": "metatrace",
  "version": "0.1.0",
  "command": "inspect",
  "timestamp": "2026-10-02T23:17:17Z",
  "status": "ok",
  "data": { "identity": {...}, "exif": {"normalized": {...}, "raw": {...}} },
  ...
}
```

Exit codes: `0` = ok, `1` = findings/warnings, `2` = error.

## What's next

v0.1 covers identification, hashing, and basic EXIF. The roadmap adds
GPS normalization, XMP/IPTC/ICC parsing, timestamp analysis, batch
processing, the anomaly engine, thumbnail inspection, case management,
and full reporting — each on the same evidence-first foundation.
