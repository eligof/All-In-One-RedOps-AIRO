#!/usr/bin/env bash
set -euo pipefail

# Build a standalone airo-splitter binary.
python -m pip install --user pyinstaller
pyinstaller --onefile airo-splitter.py --name airo-splitter
