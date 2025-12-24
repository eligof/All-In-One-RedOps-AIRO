# AIRO Developer Guide

## Development Setup
```bash
python airo-splitter.py
```

## Tests
```bash
python -m pytest -q
```

## Adding a Module
1) Add `create_module_<name>()` in `airo-splitter.py`.
2) Export functions as `airo_<command>`.
3) Update `airo_lazy_load` map in `airo-core.sh` template (inside `airo-splitter.py`).
4) Regenerate with `python airo-splitter.py`.

## Style Notes
- Use `set -euo pipefail` in modules.
- Guard external tools with `command -v`.
- Use `|| true` when a non‑zero exit is acceptable.
- Keep usage messages accurate.

## Releases
- Update version in `airo-core.sh` template.
- Update docs and CHANGELOG (when added).
- Tag and push.
