# AIRO Plugin Guide

AIRO supports extensions by adding new modules or scripts alongside the generated framework.

## Option 1: New Module
Create a new module file under `modules/` with exported functions:
```bash
#!/usr/bin/env bash
set -euo pipefail

airo_mytool() {
  echo "hello"
}

export -f airo_mytool
```

## Option 2: Wrapper Script
Add a script in `plugins/` and call it from a module function:
```bash
plugins/mytool.sh
modules/custom.sh
```

## Registering Commands
Add your command name to the lazy-load map in the core loader template in `airo-splitter.py`:
```
case "$cmd" in
  mytool) module="custom" ;;
esac
```

## Packaging
Re-run:
```bash
python airo-splitter.py
```
