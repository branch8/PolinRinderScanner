# GitHub Remote Scanning & Run Logging — Design Spec

## Problem

The scanner only works on local repositories. The user also has repositories on GitHub under various orgs/users that need scanning. Additionally, there is no persistent log of scan runs.

## Solution

Add a `--github <owner>` flag (repeatable) that lists all repos for a GitHub user/org, clones them via SSH, scans priority branches, and cleans up. Add logging for every scan run.

## CLI Interface

New flags:

```
--github <owner>    Scan all repos of a GitHub user/org (repeatable)
--ssh-host <host>   SSH host alias for cloning (default: github.com-nhatitsforce)
```

Examples:

```bash
./polinrider-scanner.sh --github myorg
./polinrider-scanner.sh --github myorg --github myuser --verbose
./polinrider-scanner.sh --github myorg --full-system
./polinrider-scanner.sh --github myorg --ssh-host github.com-custom
```

`--github` can combine with `--full-system` and `--verbose`/`--js-all`. Cannot combine with `--quick` — if both are specified, print an error and exit 2. The `--quick` + `--github` conflict is validated after the argument parsing loop completes (post-parse check), before any scanning begins.

`--ssh-host` without `--github` is silently ignored (no-op).

`--github` and a positional `SCAN_DIR` can coexist — the positional dir is used for local repo scanning, and `--github` runs its own GitHub scan section independently.

`print_usage()` must be updated to document `--github` and `--ssh-host`.

## GitHub Scanning Flow

### Prerequisites

Before starting GitHub scanning:

1. Check `gh` is installed: `command -v gh`. If not, print error and exit 2.
2. Check `gh` is authenticated: `gh auth status`. If not, print the error from `gh` and exit 2.

### Per-Owner Flow

For each `--github <owner>`:

1. List repos via `gh repo list <owner> --limit 1000 --json nameWithOwner`.
   - If `gh repo list` returns no repos: log warning, continue to next owner.
2. Create temp dir `.polinrider-tmp-<timestamp>/` in the current working directory.
3. For each repo:
   - Clone via SSH: `git clone git@<SSH_HOST>:<owner>/<repo>.git`
   - If clone fails (auth error, 404, network), log the error and continue to the next repo.
   - Remote-tracking refs are available post-clone (`origin/*`). No explicit `git fetch` needed.
   - Set `SKIP_GIT_GREP=0` before scanning branches for this repo.
   - For each priority branch (`main`, `master`, `production`, `staging`, `uat`):
     - Check if branch exists as a remote-tracking ref (`git branch -r | grep origin/<branch>`)
     - If exists: `git checkout <branch>`, run `scan_repo()`.
     - After the first `scan_repo()` call, set `SKIP_GIT_GREP=1`.
   - Delete the cloned repo immediately after scanning.
4. Remove `.polinrider-tmp-<timestamp>/` when all repos for that owner are done.

### Git Grep Deduplication

`scan_repo()` runs `git grep` across all branches/refs internally. Since `scan_repo()` is called once per priority branch checkout, the git grep section would run redundantly (it searches all refs regardless of HEAD). To prevent duplicate findings:

- A global variable `SKIP_GIT_GREP` is added (default `0`).
- `scan_repo()` checks `SKIP_GIT_GREP` before the git grep section. If `1`, it skips git grep entirely.
- `scan_github_owner()` sets `SKIP_GIT_GREP=0` before the first branch, then sets it to `1` after the first `scan_repo()` call completes.
- For local (non-GitHub) scanning, `SKIP_GIT_GREP` stays at `0` — no behavior change.

This is the only modification to `scan_repo()` internals: a single `if` guard around the git grep block.

### SSH Clone Host

Default: `github.com-nhatitsforce`. Configurable via `--ssh-host <host>`.

Clone URL format: `git@<SSH_HOST>:<owner>/<repo>.git`

### Priority Branches

Scanned in order: `main`, `master`, `production`, `staging`, `uat`. Only branches that exist on the remote are scanned.

### Progress Output

```
[GitHub] Listing repos for myorg...
[GitHub] Found 42 repositories
[GitHub] [1/42] Cloning myorg/repo-name...
[GitHub] Scanning branch: main
[GitHub] Scanning branch: production
[GitHub] [1/42] Done — 2 finding(s)
[GitHub] [1/42] Cleaned up local clone
```

## Logging

A log file is created for every scanner run (all modes, not just GitHub).

### Log Location

- Directory: `<current_dir>/logs/` (created if it doesn't exist)
- Filename: `scan-<mode>-<YYYY-MM-DD_HH-MM-SS>.log`

### Filename Construction

Mode components are joined with `-` in this order:
1. `full-system` (if `--full-system`)
2. `quick` (if `--quick`)
3. `github` (if `--github`)
4. `repo` (if none of the above — default local repo scan)

Examples:
```
logs/scan-github-2026-04-30_14-23-01.log
logs/scan-full-system-2026-04-30_14-23-01.log
logs/scan-quick-2026-04-30_14-23-01.log
logs/scan-repo-2026-04-30_14-23-01.log
logs/scan-full-system-github-2026-04-30_14-23-01.log
```

### Log Contents

- Timestamp and scanner version at start
- Scan mode
- For GitHub mode: which owners, how many repos found
- Each repo scanned and which branches were checked
- All findings (same as terminal output, without color codes)
- Summary totals at the end
- Duration of the scan

### Logging Architecture

After argument parsing and banner, `init_log()` creates the log file. Then `exec > >(tee -a "$LOG_FILE") 2>&1` is used to mirror all stdout and stderr to the log file. A `sed` filter in the `tee` pipeline strips ANSI color codes before writing to the log file:

```bash
exec > >(while IFS= read -r line; do
    printf '%s\n' "$line"
    printf '%s\n' "$line" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
done) 2>&1
```

This approach requires zero changes to `scan_repo()` or any existing `printf` calls — all terminal output is automatically captured and logged.

### Log Format

```
[2026-04-30 14:23:01] PolinRider Scanner v2.2 started
[2026-04-30 14:23:01] Mode: GitHub scan
[2026-04-30 14:23:01] GitHub owners: myorg, myuser
[2026-04-30 14:23:03] [myorg] Found 42 repositories
[2026-04-30 14:23:05] [myorg] [1/42] Cloning myorg/repo-name...
[2026-04-30 14:23:10] [myorg] [1/42] Scanning branch: main
[2026-04-30 14:23:12] [myorg] [1/42] FINDING: postcss.config.mjs: variant 1 (rmcej%otb%)
[2026-04-30 14:23:14] [myorg] [1/42] Done — 1 finding(s)
...
[2026-04-30 14:30:45] Scan complete. Duration: 7m44s
[2026-04-30 14:30:45] Total repos: 42, Infected: 3, System findings: 0
```

### Trap and Exit Code

An EXIT trap handles temp directory cleanup. The trap preserves `$?` so the original exit code (0, 1, or 2) is returned:

```bash
cleanup() {
    local exit_code=$?
    # remove temp dirs if they exist
    ...
    exit $exit_code
}
trap cleanup EXIT
```

## Code Changes

### New Global Variables

```bash
GITHUB_OWNERS=""        # space-separated list of owners
LOG_FILE=""             # path to the log file
PRIORITY_BRANCHES="main master production staging uat"
SSH_HOST="github.com-nhatitsforce"
SCAN_START_TIME=""      # epoch seconds for duration calc
SKIP_GIT_GREP=0         # set to 1 to skip git grep in scan_repo (used for multi-branch GitHub scanning)
```

### New Functions

- `log_msg()` — writes a timestamped `[YYYY-MM-DD HH:MM:SS] message` line to stdout (which is mirrored to the log via the `tee` exec)
- `scan_github_owner()` — lists repos for an owner, clones each, iterates priority branches, calls `scan_repo()`, cleans up
- `init_log()` — creates the `logs/` directory, sets `LOG_FILE` path, writes the header, sets up the `exec > >(tee ...)` redirect
- `cleanup()` — EXIT trap function that removes temp directories and preserves exit code

### Modified Areas

- **Argument parser** — add `--github` and `--ssh-host` cases
- **Post-parse validation** — check `--quick` + `--github` conflict (exit 2)
- **`print_usage()`** — document `--github` and `--ssh-host` flags
- **Main execution block** — add GitHub scanning section after existing repo scan logic
- **After `print_banner()`** — call `init_log()` (all mode flags are already parsed at this point)
- **`scan_repo()` git grep section** — wrap in `if [ "$SKIP_GIT_GREP" -eq 0 ]` guard

### Unchanged

- `scan_repo()` working-tree checks — unmodified
- All existing scan modules — unchanged
- Exit codes — same semantics (0=clean, 1=infected, 2=error)
- Existing counters (`INFECTED_REPOS`, `TOTAL_REPOS`, etc.) — GitHub repos feed into the same counters

### Version

Bump `VERSION` to `"2.2"`.

## Dependencies

- `gh` CLI — must be installed and authenticated (`gh auth login`). Pre-checked before scanning.
- SSH config — host alias must be configured (default `github.com-nhatitsforce`, configurable via `--ssh-host`)

## Temp Directory

- Location: `.polinrider-tmp-<timestamp>/` in the current working directory
- Created per GitHub owner scan
- Each repo clone is deleted immediately after scanning
- Temp directory is deleted after all repos for that owner are scanned
- Cleanup guaranteed via EXIT trap (runs on normal exit, errors, and signals)
- The trap preserves the original exit code
