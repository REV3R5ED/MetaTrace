# Contributing to MetaTrace

## Ground rules

- **Stdlib-only.** MetaTrace has zero dependencies by design (forensic
  tools minimize supply-chain surface). Do not add third-party packages
  without discussion.
- **Python 3.10–3.13.** No `tomllib`, no `match` on 3.10-incompatible
  constructs — CI runs the full matrix.
- **Observed vs normalized.** Raw metadata values are kept verbatim;
  normalized derivations sit alongside them. Never merge the two, and
  never let the tool make authenticity claims — flag observations with
  evidence and confidence, nothing more.
- **Defensive parsing.** Image input is untrusted. Bound everything,
  validate every offset, and turn malformed input into recorded
  warnings, not crashes.

## Workflow

1. Fork and create a feature branch.
2. Add tests first for parser/behavior changes. Test fixtures are
   byte-level synthetic images built in `tests/conftest.py` — no real
   photos, no network.
3. Run the gates locally before pushing:

```bash
pip install -e '.[dev]'
pytest -q
ruff check . && ruff format --check .
mypy src
```

4. Update `CHANGELOG.md` under `[Unreleased]`.
5. Open a PR with a clear description and sample output for CLI changes.

## Project layout

```
src/metatrace/
├── core/      # config, models, hashing, logging, results, plugins
├── image/     # identify.py (v0.1)
├── parsers/   # exif.py (v0.1); xmp/iptc/icc land in v0.3
├── cli/       # argument parsing, rendering
└── ...        # geo/timeline/anomaly/cases/reporting arrive per roadmap
tests/         # byte-level synthetic fixtures, no network
```

Later roadmap phases plug into `core/plugins.py` and the models in
`core/models.py` — keep those seams stable.
