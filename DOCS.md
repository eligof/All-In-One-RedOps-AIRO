# AIRO Documentation Index

This repository contains user and developer documentation for the AIRO toolkit. The generator (`airo-splitter.py`) copies these files into the packaged `docs/` folder.

## Start Here
- New users: begin with `docs/OPERATOR_GUIDE.md` for end-to-end workflow.
- Configuration and flags: `docs/USER_GUIDE.md`.
- Quick command reference: `docs/COMMANDS.md`.

## User Documentation
- `docs/USER_GUIDE.md` – installation, configuration, runtime flags, examples.
- `docs/OPERATOR_GUIDE.md` – end-to-end operator workflow and checklists.
- `docs/COMMANDS.md` – command index by module with concise descriptions.
- `docs/TROUBLESHOOTING.md` – common issues and fixes.
- `docs/man/airo.1` – man page for the `airo` command.

## Developer Documentation
- `docs/ARCHITECTURE.md` – how the splitter and generated toolkit are structured.
- `docs/DEVELOPER_GUIDE.md` – coding conventions, tests, release notes.
- `docs/PLUGIN_GUIDE.md` – extension points and plugin patterns.

## Quick Start (Docs)
1) Generate package:
```
python airo-splitter.py
```
2) Read user guide:
```
docs/USER_GUIDE.md
```

## Packaging Note
`DOCS.md` is copied into the generated toolkit as `docs/DOCS.md`.
