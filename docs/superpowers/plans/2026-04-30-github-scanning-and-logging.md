# GitHub Remote Scanning & Run Logging — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--github <owner>` remote repo scanning and per-run log files to `polinrider-scanner.sh`.

**Architecture:** Clone GitHub repos via SSH to a temp directory, scan priority branches using the existing `scan_repo()` function, clean up. Mirror all terminal output to a log file via `exec > >(tee ...)`. Single file modified: `polinrider-scanner.sh`.

**Tech Stack:** Bash, `gh` CLI, `git`, standard macOS tools (`sed`, `mktemp`, `date`).

**Spec:** `docs/superpowers/specs/2026-04-30-github-scanning-and-logging-design.md`

---

## File Map

- Modify: `polinrider-scanner.sh` (all changes in this single file)
  - Line 24: bump VERSION
  - Lines 25-29: add new global variables
  - Lines 124-143: update `print_usage()`
  - After line 143: add `log_msg()`, `init_log()`, `cleanup()` functions
  - After line 693 (end of `scan_repo`): add `scan_github_owner()` function
  - Line 578-669: wrap git grep block in `SKIP_GIT_GREP` guard
  - Lines 1229-1266: extend argument parser
  - After line 1266: add post-parse validation
  - Line 1271: add `init_log()` call after `print_banner`
  - After line 1359 (end of repo scan): add GitHub scanning section

No new files created. No test suite exists (validated via `bash -n` syntax check and manual runs per CLAUDE.md).

---

## Chunk 1: Global Variables, Usage, and Logging Infrastructure

### Task 1: Add new global variables and bump version

**Files:**
- Modify: `polinrider-scanner.sh:24-29`

- [ ] **Step 1: Bump VERSION to 2.2 and add new globals**

At line 24, change:
```bash
VERSION="2.1"
```
to:
```bash
VERSION="2.2"
```

After line 29 (`SCAN_DIR=""`), add:
```bash
GITHUB_OWNERS=""
PRIORITY_BRANCHES="main master production staging uat"
SSH_HOST="github.com-nhatitsforce"
LOG_FILE=""
SCAN_START_TIME=""
SKIP_GIT_GREP=0
GITHUB_TMP_DIRS=""
```

- [ ] **Step 2: Syntax check**

Run: `bash -n polinrider-scanner.sh`
Expected: no output (clean parse)

- [ ] **Step 3: Commit**

```bash
git add polinrider-scanner.sh
git commit -m "feat: add global variables for GitHub scanning and logging"
```

---

### Task 2: Update print_usage()

**Files:**
- Modify: `polinrider-scanner.sh:124-143`

- [ ] **Step 1: Add --github and --ssh-host to usage output**

After the line `printf "  --js-all       Scan all .js/.mjs/.cjs files (not just known configs)\n"` (line 133), add:
```bash
    printf "  --github <owner>  Scan all GitHub repos of a user/org (repeatable)\n"
    printf "  --ssh-host <host> SSH host alias for cloning (default: github.com-nhatitsforce)\n"
```

After the line `printf "  %s --js-all ~/projects          # Deep scan all JS files\n" "$0"` (line 142), add:
```bash
    printf "  %s --github myorg              # Scan all repos of a GitHub org\n" "$0"
    printf "  %s --github org1 --github org2 # Scan repos of multiple orgs\n" "$0"
```

- [ ] **Step 2: Syntax check**

Run: `bash -n polinrider-scanner.sh`
Expected: no output

- [ ] **Step 3: Verify usage output**

Run: `./polinrider-scanner.sh --help 2>&1 | head -20`
Expected: `--github` and `--ssh-host` appear in the options list

- [ ] **Step 4: Commit**

```bash
git add polinrider-scanner.sh
git commit -m "feat: add --github and --ssh-host to usage help"
```

---

### Task 3: Add log_msg(), init_log(), and cleanup() functions

**Files:**
- Modify: `polinrider-scanner.sh` — insert after `log_verbose()` function (after line 149)

- [ ] **Step 1: Add the three new functions**

Insert after the closing `}` of `log_verbose()` (after line 149):

```bash

log_msg() {
    local msg="$1"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    printf "[%s] %s\n" "$timestamp" "$msg"
}

init_log() {
    local mode_parts=""
    if [ "$FULL_SYSTEM" -eq 1 ]; then
        mode_parts="full-system"
    fi
    if [ "$QUICK_SCAN" -eq 1 ]; then
        mode_parts="${mode_parts:+${mode_parts}-}quick"
    fi
    if [ -n "$GITHUB_OWNERS" ]; then
        mode_parts="${mode_parts:+${mode_parts}-}github"
    fi
    if [ -z "$mode_parts" ]; then
        mode_parts="repo"
    fi

    local timestamp
    timestamp="$(date '+%Y-%m-%d_%H-%M-%S')"
    mkdir -p logs
    LOG_FILE="logs/scan-${mode_parts}-${timestamp}.log"
    : > "$LOG_FILE"

    SCAN_START_TIME="$(date '+%s')"

    exec > >(while IFS= read -r line; do
        printf '%s\n' "$line"
        printf '%s\n' "$line" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    done) 2>&1

    log_msg "PolinRider Scanner v${VERSION} started"
}

cleanup() {
    local exit_code=$?
    if [ -n "$GITHUB_TMP_DIRS" ]; then
        local old_ifs="$IFS"
        IFS=' '
        for tmp_dir in $GITHUB_TMP_DIRS; do
            if [ -d "$tmp_dir" ]; then
                rm -rf "$tmp_dir"
            fi
        done
        IFS="$old_ifs"
    fi
    wait 2>/dev/null
    exit $exit_code
}
trap cleanup EXIT
```

- [ ] **Step 2: Syntax check**

Run: `bash -n polinrider-scanner.sh`
Expected: no output

- [ ] **Step 3: Commit**

```bash
git add polinrider-scanner.sh
git commit -m "feat: add logging infrastructure and cleanup trap"
```

---

### Task 4: Wire init_log() into main execution

**Files:**
- Modify: `polinrider-scanner.sh` — at the MAIN EXECUTION section

- [ ] **Step 1: Add init_log() call after print_banner**

After the line `print_banner` (line 1271), add:
```bash
init_log
```

- [ ] **Step 2: Add a log_duration helper function**

Add this function after the `cleanup()` function (still inside the functions section):
```bash
log_scan_complete() {
    local end_time
    end_time="$(date '+%s')"
    local duration=$((end_time - SCAN_START_TIME))
    local mins=$((duration / 60))
    local secs=$((duration % 60))
    log_msg "Scan complete. Duration: ${mins}m${secs}s"
    log_msg "Total repos: ${TOTAL_REPOS}, Infected: ${INFECTED_REPOS}, System findings: ${SYSTEM_FINDINGS}"
}
```

- [ ] **Step 3: Add duration log before ALL exit points**

There are 4 exit points in the scanner. Add `log_scan_complete` before each:

1. **Quick scan — findings found** (around line 1286): before `exit 1` in the quick scan block
2. **Quick scan — clean** (around line 1290): before `exit 0` in the quick scan block
3. **Summary — findings found** (around line 1388): before `exit 1` in the summary block
4. **Summary — clean** (around line 1392): before `exit 0` in the summary block

Insert `log_scan_complete` on the line before each `exit` call.

- [ ] **Step 3: Syntax check**

Run: `bash -n polinrider-scanner.sh`
Expected: no output

- [ ] **Step 4: Test logging works**

Run: `./polinrider-scanner.sh --verbose . 2>&1 | tail -5`
Then check: `ls logs/scan-repo-*.log`
Expected: a log file exists with stripped-color content

- [ ] **Step 5: Commit**

```bash
git add polinrider-scanner.sh
git commit -m "feat: wire up per-run logging for all scan modes"
```

---

## Chunk 2: Argument Parsing and SKIP_GIT_GREP Guard

### Task 5: Extend argument parser with --github and --ssh-host

**Files:**
- Modify: `polinrider-scanner.sh` — argument parsing section (lines 1229-1266)

- [ ] **Step 1: Add --github and --ssh-host cases**

In the `case "$1" in` block, before the `--help|-h)` case, add:
```bash
        --github)
            if [ $# -lt 2 ]; then
                printf "Error: --github requires an owner argument\n" >&2
                print_usage >&2
                exit 2
            fi
            GITHUB_OWNERS="${GITHUB_OWNERS:+${GITHUB_OWNERS} }$2"
            shift 2
            ;;
        --ssh-host)
            if [ $# -lt 2 ]; then
                printf "Error: --ssh-host requires a host argument\n" >&2
                print_usage >&2
                exit 2
            fi
            SSH_HOST="$2"
            shift 2
            ;;
```

- [ ] **Step 2: Add post-parse validation**

After the `done` that closes the argument parsing `while` loop (line 1266), add:
```bash

if [ "$QUICK_SCAN" -eq 1 ] && [ -n "$GITHUB_OWNERS" ]; then
    printf "Error: --quick and --github cannot be used together\n" >&2
    print_usage >&2
    exit 2
fi
```

- [ ] **Step 3: Syntax check**

Run: `bash -n polinrider-scanner.sh`
Expected: no output

- [ ] **Step 4: Test argument parsing**

Run: `./polinrider-scanner.sh --help 2>&1 | grep github`
Expected: shows --github in usage

Run: `./polinrider-scanner.sh --quick --github testorg 2>&1`
Expected: error message about --quick and --github conflict, exit code 2

Run: `./polinrider-scanner.sh --github 2>&1`
Expected: error message about missing owner argument

- [ ] **Step 5: Commit**

```bash
git add polinrider-scanner.sh
git commit -m "feat: add --github and --ssh-host argument parsing"
```

---

### Task 6: Add SKIP_GIT_GREP guard to scan_repo()

**Files:**
- Modify: `polinrider-scanner.sh:578-669` (git grep block inside `scan_repo()`)

- [ ] **Step 1: Wrap git grep block in SKIP_GIT_GREP check**

At line 578, change:
```bash
    # --- git grep across all branches for signatures ---
    # For each signature, run git grep -lF against all branches.
    # Each hit already knows which signature matched — no second-pass needed.
    if [ -d "${repo_dir}/.git" ]; then
```

to:
```bash
    # --- git grep across all branches for signatures ---
    # For each signature, run git grep -lF against all branches.
    # Each hit already knows which signature matched — no second-pass needed.
    if [ -d "${repo_dir}/.git" ] && [ "$SKIP_GIT_GREP" -eq 0 ]; then
```

This is a single-line change — adding `&& [ "$SKIP_GIT_GREP" -eq 0 ]` to the existing `if` condition.

- [ ] **Step 2: Syntax check**

Run: `bash -n polinrider-scanner.sh`
Expected: no output

- [ ] **Step 3: Verify local scanning still works**

Run: `./polinrider-scanner.sh --verbose .`
Expected: still scans repos normally, git grep still runs (SKIP_GIT_GREP defaults to 0)

- [ ] **Step 4: Commit**

```bash
git add polinrider-scanner.sh
git commit -m "feat: add SKIP_GIT_GREP guard for multi-branch GitHub scanning"
```

---

## Chunk 3: GitHub Scanning Function and Main Integration

### Task 7: Add scan_github_owner() function

**Files:**
- Modify: `polinrider-scanner.sh` — insert after `scan_repo()` (after line 693, before the FULL-SYSTEM SCAN FUNCTIONS section)

- [ ] **Step 1: Add the scan_github_owner function**

Insert after the closing `}` of `scan_repo()` (line 693):

```bash

# ---------------------------------------------------------------------------
# scan_github_owner — clone and scan all repos for a GitHub user/org
# ---------------------------------------------------------------------------
scan_github_owner() {
    local owner="$1"

    log_msg "[${owner}] Listing repositories..."

    local repo_json
    repo_json="$(gh repo list "$owner" --limit 1000 --json nameWithOwner -q '.[].nameWithOwner' 2>&1)"
    local gh_exit=$?
    if [ "$gh_exit" -ne 0 ]; then
        log_msg "[${owner}] ERROR: gh repo list failed: ${repo_json}"
        return 1
    fi

    if [ -z "$repo_json" ]; then
        log_msg "[${owner}] WARNING: No repositories found"
        return 0
    fi

    local repo_count=0
    local repo_list=""
    while IFS= read -r repo_name; do
        if [ -n "$repo_name" ]; then
            repo_list="${repo_list}${repo_name}
"
            repo_count=$((repo_count + 1))
        fi
    done <<< "$repo_json"
    repo_list="${repo_list%
}"

    log_msg "[${owner}] Found ${repo_count} repositories"

    local tmp_dir=".polinrider-tmp-$(date '+%s')"
    mkdir -p "$tmp_dir"
    GITHUB_TMP_DIRS="${GITHUB_TMP_DIRS:+${GITHUB_TMP_DIRS} }${tmp_dir}"

    local repo_idx=0
    while IFS= read -r full_name; do
        if [ -z "$full_name" ]; then continue; fi
        repo_idx=$((repo_idx + 1))
        local repo_short="${full_name#*/}"

        log_msg "[${owner}] [${repo_idx}/${repo_count}] Cloning ${full_name}..."

        local clone_dir="${tmp_dir}/${repo_short}"
        if ! git clone "git@${SSH_HOST}:${full_name}.git" "$clone_dir" 2>&1; then
            log_msg "[${owner}] [${repo_idx}/${repo_count}] ERROR: Clone failed, skipping"
            rm -rf "$clone_dir" 2>/dev/null
            continue
        fi

        SKIP_GIT_GREP=0
        local repo_finding_count=0
        local old_ifs="$IFS"
        IFS=' '
        for branch in $PRIORITY_BRANCHES; do
            if git -C "$clone_dir" branch -r 2>/dev/null | grep -qw "origin/${branch}"; then
                log_msg "[${owner}] [${repo_idx}/${repo_count}] Scanning branch: ${branch}"
                git -C "$clone_dir" checkout "$branch" 2>/dev/null

                local before_infected="$INFECTED_REPOS"
                TOTAL_REPOS=$((TOTAL_REPOS + 1))
                scan_repo "$clone_dir"
                if [ "$INFECTED_REPOS" -gt "$before_infected" ]; then
                    repo_finding_count=$((repo_finding_count + 1))
                fi

                SKIP_GIT_GREP=1
            fi
        done
        IFS="$old_ifs"

        log_msg "[${owner}] [${repo_idx}/${repo_count}] Done — ${repo_finding_count} finding(s)"

        rm -rf "$clone_dir"
        log_msg "[${owner}] [${repo_idx}/${repo_count}] Cleaned up local clone"
    done <<GHREPOEOF
$repo_list
GHREPOEOF

    rm -rf "$tmp_dir"
    GITHUB_TMP_DIRS="${GITHUB_TMP_DIRS% ${tmp_dir}}"
    GITHUB_TMP_DIRS="${GITHUB_TMP_DIRS#${tmp_dir} }"
    GITHUB_TMP_DIRS="${GITHUB_TMP_DIRS#${tmp_dir}}"
}
```

- [ ] **Step 2: Syntax check**

Run: `bash -n polinrider-scanner.sh`
Expected: no output

- [ ] **Step 3: Commit**

```bash
git add polinrider-scanner.sh
git commit -m "feat: add scan_github_owner function"
```

---

### Task 8: Add GitHub scanning to main execution block

**Files:**
- Modify: `polinrider-scanner.sh` — MAIN EXECUTION section, after the repo scan loop

- [ ] **Step 1: Add gh prerequisite checks and GitHub scan loop**

After the repo scan `fi` block (the `fi` that closes `if [ "$TOTAL_REPOS" -eq 0 ]` around line 1359), and before the SUMMARY section, add:

```bash

# --- GitHub remote scan mode ---
if [ -n "$GITHUB_OWNERS" ]; then
    if ! command -v gh >/dev/null 2>&1; then
        printf "Error: 'gh' CLI is required for --github scanning. Install: https://cli.github.com\n" >&2
        exit 2
    fi
    if ! gh auth status >/dev/null 2>&1; then
        printf "Error: 'gh' is not authenticated. Run: gh auth login\n" >&2
        exit 2
    fi

    print_section "GITHUB" "Scanning GitHub repositories..."

    old_ifs="$IFS"
    IFS=' '
    owner_list=""
    for owner in $GITHUB_OWNERS; do
        owner_list="${owner_list:+${owner_list}, }${owner}"
    done
    IFS="$old_ifs"
    log_msg "GitHub owners: ${owner_list}"

    old_ifs="$IFS"
    IFS=' '
    for owner in $GITHUB_OWNERS; do
        scan_github_owner "$owner"
    done
    IFS="$old_ifs"
fi
```

Note: This is in the main body (not a function), so `local` is not used. `old_ifs` and `owner_list` are plain variables.

- [ ] **Step 2: Syntax check**

Run: `bash -n polinrider-scanner.sh`
Expected: no output

- [ ] **Step 3: Test with a real GitHub org (dry run)**

Run: `./polinrider-scanner.sh --github <a-small-test-org-with-1-2-repos> --verbose`
Expected: Lists repos, clones them, scans priority branches, reports findings, cleans up temp dir, creates log file in `logs/`

- [ ] **Step 4: Verify log file**

Run: `cat logs/scan-github-*.log | head -20`
Expected: timestamped lines without ANSI color codes

- [ ] **Step 5: Verify temp directory is cleaned up**

Run: `ls -la .polinrider-tmp-* 2>&1`
Expected: "No such file or directory" — temp dir was removed

- [ ] **Step 6: Verify combined mode**

Run: `./polinrider-scanner.sh --full-system --github <test-org> --verbose`
Expected: runs system scans first, then GitHub scans, log file named `scan-full-system-github-*.log`

- [ ] **Step 7: Commit**

```bash
git add polinrider-scanner.sh
git commit -m "feat: integrate GitHub scanning into main execution flow"
```

---

## Chunk 4: Final Validation

### Task 9: End-to-end validation and version finalization

- [ ] **Step 1: Syntax check**

Run: `bash -n polinrider-scanner.sh`
Expected: no output

- [ ] **Step 2: ShellCheck (if available)**

Run: `shellcheck polinrider-scanner.sh 2>&1 | head -30`
Expected: no new errors (existing warnings are acceptable)

- [ ] **Step 3: Local repo scan still works (no regression)**

Run: `./polinrider-scanner.sh --verbose .`
Expected: scans local repos as before, creates `logs/scan-repo-*.log`

- [ ] **Step 4: Quick scan still works**

Run: `./polinrider-scanner.sh --quick`
Expected: runs process/network scan, creates `logs/scan-quick-*.log`

- [ ] **Step 5: Error cases work**

Run: `./polinrider-scanner.sh --quick --github testorg 2>&1; echo "exit: $?"`
Expected: error message, exit code 2

Run: `./polinrider-scanner.sh --github 2>&1; echo "exit: $?"`
Expected: error about missing owner, exit code 2

- [ ] **Step 6: Verify --help is complete**

Run: `./polinrider-scanner.sh --help`
Expected: shows all flags including `--github` and `--ssh-host` with examples

- [ ] **Step 7: Final commit (if any remaining changes)**

```bash
git add polinrider-scanner.sh
git commit -m "chore: finalize v2.2 with GitHub scanning and logging"
```
