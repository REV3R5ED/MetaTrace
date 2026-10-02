# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

MetaTrace processes potentially untrusted image files, so parser safety
is a first-class concern. If you find a security issue, please report it
privately rather than opening a public issue:

- Email the author directly (see GitHub profile REV3R5ED) with a
  description, reproduction steps, and the version affected.
- Allow a reasonable time for a fix before any public disclosure.

## Security-relevant design (v0.1)

- **Read-only evidence handling**: source files are only opened for
  reading; MetaTrace never writes to the analyzed file.
- **Hash before analysis**: SHA-256 is computed before any parsing.
- **Untrusted input**: every TIFF offset is bounds-checked; tag counts
  and value sizes are bounded by configuration; truncated or malformed
  files produce warnings, never uncaught exceptions.
- **Bounded reads**: format identification reads only the file header
  (default 64 KiB); EXIF scanning is capped at 4 MiB.
- **No subprocess, no shell**: v0.1 performs no subprocess calls at all.
- **No network access**: nothing in MetaTrace opens a network connection.
- **Stdlib-only**: zero third-party dependencies, no supply-chain surface.
- **Audit trail**: every CLI invocation appends a JSON record to the
  local audit log (best effort; logging never breaks a run).
