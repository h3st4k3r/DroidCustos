# Contributing to DroidCustos

Author: h3st4k3r

## Principles

- Preserve explicit attribution to h3st4k3r.
- Keep findings evidence-based and conservative.
- Never equate a heuristic with a confirmed IOC.
- Never intentionally modify original evidence after sealing.
- Do not add exploitation, lock bypass, covert acquisition or persistence features.
- Keep canonical source code, interface text and documentation in English.
- Add tests for parsing, acquisition-state, verdict and report changes.

## Development setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e . pytest
.venv/bin/python -m pytest
```

## Pull requests

Include:

- Problem statement.
- Security and privacy impact.
- Tests.
- Example output using synthetic or redacted data.
- Documentation changes.
- Compatibility impact.

Do not submit real case data, private indicators, personal identifiers or copyrighted vendor files.

## OEM collectors

Use the declarative plugin format under `droidcustos/plugin_data/`. A collector must specify manufacturer matching, SDK constraints, required capabilities, privilege, sensitivity, timeout and output path.

## Release requirements

- Test suite passes.
- Source compiles.
- Version is updated consistently.
- Changelog is updated.
- Archive excludes virtual environments, caches, build output, case data and secrets.
- Checksums are generated after final packaging.
