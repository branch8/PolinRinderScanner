# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **PolinRider** threat intelligence repository maintained by the [OpenSourceMalware](https://opensourcemalware.com) team. It tracks a DPRK (Lazarus group) supply chain attack campaign that implants obfuscated JavaScript payloads into GitHub repositories via compromised npm packages, VS Code extensions, and config file injection. As of April 2026, 1,951+ repos / 1,047+ owners are confirmed compromised.

The repo contains:
- `polinrider-scanner.sh` — a ~1200-line Bash scanner (v2.0) for detecting PolinRider/TasksJacker malware on macOS
- `README.md` — the full threat intelligence writeup (campaign analysis, IOCs, YARA rules, methodology)
- `polinrider-windows-incident-response.md` — Windows-specific IR guide for Stage 4 credential stealer
- CSV data files tracking compromised repos and affected users
- `archive/` — historical CSV snapshots

## Scanner Architecture

`polinrider-scanner.sh` is a pure Bash script (no external dependencies beyond standard macOS tools). It has three scan modes:

| Mode | Flag | What it does |
|------|------|-------------|
| Repo scan | *(default)* | Scans git repos under a directory for infection markers |
| Quick scan | `--quick` | Processes + network connections only |
| Full system | `--full-system` | All 9 scan modules + repo scan |

The 9 scan modules (functions) for full-system mode:
1. `scan_processes` — running node processes with payload markers
2. `scan_network` — active connections to C2 domains via `lsof` + DNS log
3. `scan_persistence_plists` — LaunchAgents/LaunchDaemons
4. `scan_crontab` — scheduled tasks
5. `scan_shell_profiles` — .zshrc, .bashrc, etc.
6. `scan_vscode_extensions` — VS Code/Cursor extension dirs + workspace tasks.json
7. `scan_npm_global` — global npm packages (known malicious + suspicious tailwind-*)
8. `scan_temp_dirs` — /tmp artifacts
9. `scan_browser_extensions` — Chrome/Brave/Edge extension dirs

The core repo scanner (`scan_repo`) checks:
- Known config files (postcss, tailwind, eslint, next, babel, etc.) for variant signatures
- `.woff2` fake font files for embedded payloads
- `temp_auto_push.bat` / `config.bat` propagation scripts
- `.vscode/tasks.json` for TasksJacker curl|bash vectors
- `package.json` for malicious npm dependencies
- `git grep` across all branches (with 15s timeout)

## Malware Variants

Two obfuscator variants are tracked, each with distinct signature constants defined at the top of the scanner:

- **Variant 1** (original): marker `rmcej%otb%`, seed `2857687`, decoder `_$_1e42`, global `global['!']`
- **Variant 2** (rotated): marker `Cot%3t=shtP`, seed `1111436`, decoder `MDy`, global `global['_V']`

When adding detection for new variants, follow the existing pattern: define signature constants at top, add checks in `check_file_for_signatures()`, and update the `.woff2` scan in `scan_repo()`.

## Running the Scanner

```bash
./polinrider-scanner.sh                              # Scan current directory
./polinrider-scanner.sh --full-system                # Full macOS scan
./polinrider-scanner.sh --quick                      # Quick process/network check
./polinrider-scanner.sh --verbose /path/to/projects  # Verbose repo scan
./polinrider-scanner.sh --js-all ~/projects          # Deep scan all JS files
```

Exit codes: 0 = clean, 1 = infections found, 2 = error.

## Testing Changes to the Scanner

There is no test suite. To validate changes:
1. Run `bash -n polinrider-scanner.sh` to syntax-check
2. Run with `--verbose` against a known-clean directory to verify no false positives
3. Test against the repo itself (it contains signature strings as constants, but `grep -qF` on those should not trigger since they're in variable assignments, not config files)
4. Use `shellcheck polinrider-scanner.sh` if available

## CSV Data Format

`polinrider-master-*.csv` columns: `#,repository,owner,owner_type,stars,forks,description,repo_url,infected_files,file_paths,marker_family,severity,in_osm,osm_threat_id,submission_round,needs_recheck,repo_status`

`polinrider-users-*.csv` tracks unique affected GitHub users/orgs.

## Key Conventions

- The scanner uses `set -u` (undefined variable errors) but not `set -e` — individual command failures are handled explicitly
- Color output is auto-disabled when stdout is not a terminal
- IFS manipulation is used extensively for space-separated list iteration — always save/restore `old_ifs`
- The known-legitimate tailwind packages allowlist appears in two places (`scan_repo` for package.json and `scan_npm_global`) — keep them in sync when updating
- C2 domains and malicious npm package lists are defined as space-separated strings at the top of the script
