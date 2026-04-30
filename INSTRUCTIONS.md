# PolinRider Scanner v2.2 — Usage Guide

## Prerequisites

- **macOS** (the scanner uses macOS-specific tools like `lsof`, `launchctl`, etc.)
- **bash** (ships with macOS)
- **gh CLI** (only required for `--github` scanning) — install from https://cli.github.com
- **SSH key configured** (only required for `--github` scanning)

### Setting up gh CLI

```bash
# Install
brew install gh

# Authenticate
gh auth login
```

### Setting up SSH for GitHub

Ensure your SSH key is configured in `~/.ssh/config`. The scanner clones repos using the SSH host defined by `--ssh-host` (default: `git@github.com`).

Example `~/.ssh/config` entry for a custom alias:

```
Host github.com-myalias
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_mykey
```

Then use: `--ssh-host git@github.com-myalias`

## Making the Script Executable

```bash
chmod +x polinrider-scanner.sh
```

## Scan Modes

### 1. Local Repository Scan (default)

Scans all git repositories under a directory for PolinRider infection markers.

```bash
# Scan repos in the current directory
./polinrider-scanner.sh

# Scan repos under a specific directory
./polinrider-scanner.sh /path/to/projects

# Verbose output (shows each file being checked)
./polinrider-scanner.sh --verbose /path/to/projects

# Deep scan all JS files (not just known config files)
./polinrider-scanner.sh --js-all ~/projects
```

### 2. Quick Scan

Checks running processes and network connections only. No repo scanning.

```bash
./polinrider-scanner.sh --quick
```

### 3. Full System Scan

Runs all 9 scan modules (processes, network, persistence, crontab, shell profiles, VS Code extensions, npm globals, temp dirs, browser extensions) plus a repo scan.

```bash
# Full system scan (scans repos under $HOME by default)
./polinrider-scanner.sh --full-system

# Full system scan with verbose output
./polinrider-scanner.sh --full-system --verbose

# Full system scan + scan repos under a specific directory
./polinrider-scanner.sh --full-system /path/to/projects
```

### 4. GitHub Remote Scan

Scans all repositories of a GitHub user or organization. Clones each repo, scans priority branches (`main`, `master`, `production`, `staging`, `uat`), then deletes the clone.

```bash
# Scan all repos of a GitHub org
./polinrider-scanner.sh --github myorg

# Scan multiple orgs/users
./polinrider-scanner.sh --github myorg --github myuser

# With verbose output
./polinrider-scanner.sh --github myorg --verbose

# Use a custom SSH host alias
./polinrider-scanner.sh --github myorg --ssh-host git@github.com-myalias

# Combine with full system scan
./polinrider-scanner.sh --full-system --github myorg
```

**How it works:**
- Lists all repos using `gh repo list`
- Clones 3 repos in parallel with a 2-second delay between clones (to avoid GitHub rate limiting)
- Scans each priority branch that exists
- Deletes each clone immediately after scanning
- Generates a summary report

**Cannot combine with:** `--quick` (quick scan is process/network only)

## Output

### Terminal Output

The scanner prints findings in real-time with color-coded output:
- **Red** — confirmed infection
- **Yellow** — suspicious, verify manually
- **Green** — clean

### Log Files

Every run creates a log file in the `logs/` directory (created automatically):

```
logs/scan-repo-2026-04-30_14-23-01.log          # local repo scan
logs/scan-quick-2026-04-30_14-23-01.log          # quick scan
logs/scan-full-system-2026-04-30_14-23-01.log    # full system scan
logs/scan-github-2026-04-30_14-23-01.log         # GitHub scan
logs/scan-full-system-github-2026-04-30_14-23-01.log  # combined
```

Log files contain the same output as the terminal but with ANSI color codes stripped.

### Infected Repo Details

When using `--github`, a per-repo log file is created for each **infected** repository in the `infected-repos/` directory:

```
infected-repos/2026-04-30_22-19-27/repo-name.log
```

Each `.log` file contains the repo name, infected branches, and finding details. These files are **not** cleaned up after the scan — they persist for review and sharing.

If no infections are found, the timestamped folder will be empty.

### GitHub Scan Report

When using `--github`, a summary report is also generated for each owner:

```
logs/report-github-myorg-2026-04-30_14-30-00.txt
```

This report is formatted for sharing and includes:
- Total repos scanned, infected count, clean count
- List of each infected repo with branch and finding details

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No infections found |
| 1 | Infections found |
| 2 | Error (invalid arguments, missing dependencies, etc.) |

## All Options

```
--full-system       Scan entire Mac (processes, persistence, repos, etc.)
--quick             Quick scan (running processes + network only)
--verbose           Show detailed output for each check
--js-all            Scan all .js/.mjs/.cjs files (not just known configs)
--github <owner>    Scan all GitHub repos of a user/org (repeatable)
--ssh-host <host>   SSH host alias for cloning (default: git@github.com)
--help              Show help message
```

## Examples

```bash
# Daily quick check
./polinrider-scanner.sh --quick

# Scan your local projects
./polinrider-scanner.sh ~/Work

# Full system audit
./polinrider-scanner.sh --full-system --verbose

# Scan a GitHub org and get a report for your team
./polinrider-scanner.sh --github myorg --verbose

# Scan everything — local system + multiple GitHub orgs
./polinrider-scanner.sh --full-system --github org1 --github org2 --verbose
```
