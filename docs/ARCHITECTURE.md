# AIRO Architecture

## High‑Level Flow
1) `airo-splitter.py` generates a package directory:
   - `airo-core.sh` (loader)
   - `modules/*.sh` (feature modules)
   - `config/*` (defaults + user templates)
   - `docs/*` (README + DOCS + additional docs)
   - `vendors/tools.json` (hashes/versions)
2) `install.sh` copies the package into XDG locations.
3) `airo-core.sh` lazy‑loads modules on demand.

## Core Loader
`airo-core.sh` provides:
- Config loading (defaults + overrides + INI + env)
- Runtime flags (`--fast`, `--dry-run`, `--proxy`, etc.)
- Lazy module loading and aliases
- Logging: errors + optional JSON command logs

## Modules
Each module exports functions named `airo_<command>` and is lazily loaded:
```
modules/
  network.sh
  web.sh
  system.sh
  privesc.sh
  cloud.sh
  ad.sh
  wireless.sh
  mobile.sh
  osint.sh
  automation.sh
  utilities.sh
```

## Config
Files are loaded in order:
1) `defaults.conf`
2) `main.conf`
3) `user.conf`
4) `config.ini` (optional)
5) Env overrides (`AIRO_*`)

## Vendors
`vendors/tools.json` stores pinned versions and hashes for downloads (e.g., PEAS).

## Extending
Add a new `create_module_<name>` in `airo-splitter.py` and update the command map in `airo_lazy_load`.
