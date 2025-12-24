# AIRO Troubleshooting

## Installer prompts fail in non‑interactive shells
Set `AIRO_YES=1`:
```bash
AIRO_YES=1 ./install.sh
```

## Launcher not created
Non‑TTY sudo will skip the launcher. Create it manually:
```bash
sudo ln -sf ~/.local/share/airo/airo-core.sh /usr/local/bin/airo
```

## Command not found
- Reload your shell: `source ~/.bashrc` or `source ~/.zshrc`
- Verify install: `ls ~/.local/share/airo/airo-core.sh`

## Missing tools
Use the dependency helper or install the missing tool:
```bash
./install_airo_dependencies.sh
```

## Wordlist not found
Clone SecLists or update `WORDLIST_*` in config:
```bash
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
```

## No permission for scans
Some scans (raw sockets) require sudo. Try:
```bash
sudo airo portscan <target>
```

## JSON log file missing
Logs are written to:
```
~/.cache/airo/logs/commands.jsonl
```
Make sure the cache directory exists or re‑run `install.sh`.
