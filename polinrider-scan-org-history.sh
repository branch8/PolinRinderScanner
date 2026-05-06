#!/bin/bash
#
# PolinRider Org History Scanner v3.1 — Branch8 Edition
# Customized by Glenn Cheng
# https://github.com/branch8/PolinRiderScanner
#
# Deep audit scanner for GitHub org/user repos.
# Scans all branch heads via git grep AND scans git commit history
# to detect payloads that existed in past commits but have since been removed.
# Use this for incident response and one-time audits.
#
# Results are categorised:
#   INFECTED      — payload currently present in at least one branch
#   HISTORY       — payload found in commit history but no longer in any branch
#
# Usage:
#   ./polinrider-scan-org-history.sh --github <owner>
#   ./polinrider-scan-org-history.sh --github org1 --github org2
#   ./polinrider-scan-org-history.sh --parallel 10 --github myorg
#   ./polinrider-scan-org-history.sh --log-json --github myorg
#
# Exit codes:
#   0 - No infections or history hits found
#   1 - Infections or history hits found
#   2 - Error (invalid path, missing tools, etc.)
#
# Changelog:
#   v3.1 (2026-05-06)  — Branch8 Edition
#     - Braille spinner (⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏) cycling through 4 colors
#     - Progress bar uses █/─ with green fill, dark-gray empty
#     - Bar header now shows [org: <owner>] for clarity
#     - done:/workers: counts colorized; infected: only shown when >0 (red)
#     - Sticky bar expanded to 3 lines: bar + scanning repos + status line
#     - Scanning line: each active repo name cycles through 4 colors
#     - Status line: latest worker event always visible as 3rd sticky line
#     - Verbose: separator + 2 blank lines above bar; log lines colorized
#       (red=infected, yellow=history-only, green=clean, cyan=complete, dim=in-progress)
#     - Continuous animation: wait loops poll every 0.3s so spinner never stalls
#     - Banner updated: Branch8 Edition, Glenn Cheng
#
#   v3.0
#     - Branch8 fork: bare-clone + git-grep + commit-history audit with
#       INFECTED/HISTORY classification, multi-org support, persistent
#       resume/restart state, parallel workers, sticky progress bar

set -u

ORIG_ARGS=("$@")

VERSION="3.1"
VERBOSE=0
VERBOSE_DETAIL=0
GITHUB_OWNERS=""
SSH_HOST="git@github.com"
USE_HTTPS=0
RESTART=0
RESUME_MODE=0
LOG_FILE=""
SCAN_START_TIME=""
GITHUB_TMP_DIRS=""
MAX_PARALLEL=6
CLONE_DELAY=0.5
REPORT_FILE=""
GITHUB_RESULTS_DIR=""
LOG_JSON=0
JSON_FILE=""
GIT_GREP_TIMEOUT=30
KEEP_REPO=0

# ---------------------------------------------------------------------------
# Variant 1 signatures (original — rmcej%otb%)
# ---------------------------------------------------------------------------
V1_PRIMARY='("rmcej%otb%",2857687)'
V1_SECONDARY="global['!']='8-270-2';var _\$_1e42="
V1_MARKER="rmcej%otb%"
V1_SEED="2857687"
V1_SEED2="2667686"
V1_DECODER="_\$_1e42"
V1_GLOBAL="global['!']"

# ---------------------------------------------------------------------------
# Variant 2 signatures (rotated — Cot%3t=shtP)
# ---------------------------------------------------------------------------
V2_MARKER="Cot%3t=shtP"
V2_SEED="1111436"
V2_SEED2="3896884"
V2_DECODER="MDy"
V2_GLOBAL="global['_V']"

# Common across variants
COMMON_GLOBAL_R="global['r'] = require"
COMMON_GLOBAL_M="global['m'] = module"

# ---------------------------------------------------------------------------
# Known malicious npm packages
# ---------------------------------------------------------------------------
MALICIOUS_NPM_PKGS="tailwindcss-style-animate tailwind-mainanimation tailwind-autoanimation tailwind-animationbased tailwindcss-typography-style tailwindcss-style-modify tailwindcss-animate-style"

# ---------------------------------------------------------------------------
# C2 infrastructure domains
# ---------------------------------------------------------------------------
C2_DOMAINS="260120.vercel.app default-configuration.vercel.app vscode-settings-bootstrap.vercel.app vscode-settings-config.vercel.app vscode-bootstrapper.vercel.app vscode-load-config.vercel.app"

# Blockchain C2 endpoints
BLOCKCHAIN_HOSTS="api.trongrid.io fullnode.mainnet.aptoslabs.com bsc-dataseed.binance.org bsc-rpc.publicnode.com"
TRON_ADDR_1="TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP"
TRON_ADDR_2="TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG"
APTOS_HASH_1="0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e"
APTOS_HASH_2="0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3"

# Weaponized template identifiers
STAKING_UUID="e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9"

# IDE/agent config directories
IDE_CONFIG_DIRS=".vscode .cursor .claude"

# ---------------------------------------------------------------------------
# Colors (disabled if not a terminal)
# ---------------------------------------------------------------------------
RED="" GREEN="" YELLOW="" CYAN="" MAGENTA="" BOLD="" DIM="" RESET=""
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    DIM='\033[0;90m'
    RESET='\033[0m'
fi

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
TOTAL_REPOS=0
INFECTED_REPOS=0
PROGRESS_UI=0
PROGRESS_LINES=0
LAST_QUEUE_LINE=0
SPINNER_IDX=0

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------
print_banner() {
    printf "\n"
    printf "${BOLD}================================================${RESET}\n"
    printf "${BOLD}  PolinRider Org History Scanner v%s — Branch8 Edition${RESET}\n" "$VERSION"
    printf "${BOLD}  Customized by Glenn Cheng${RESET}\n"
    printf "${BOLD}  https://github.com/branch8/PolinRiderScanner${RESET}\n"
    printf "${BOLD}  Bare-clone + git-grep + commit history audit${RESET}\n"
    printf "${BOLD}================================================${RESET}\n"
    printf "\n"
}

print_usage() {
    printf "Usage: %s [OPTIONS]\n" "$0"
    printf "\n"
    printf "Fast GitHub scanner using bare clone + git grep (no checkout).\n"
    printf "Scans ALL branches, not just priority ones.\n"
    printf "\n"
    printf "Options:\n"
    printf "  --github <owner>    Scan all repos of a user/org (repeatable)\n"
    printf "  --ssh-host <host>   SSH host alias for cloning (default: git@github.com)
  --https             Clone via HTTPS instead of SSH (use if SSH key not set up)\n"
    printf "  --restart           Clear previous scan state and rescan all repos\n"
    printf "  --parallel <n>      Max parallel clone workers (default: 6)\n"
    printf "  --clone-delay <s>   Seconds between clone starts (default: 0.5)\n"
    printf "  --log-json          Output a single JSON log with all repo results\n"
    printf "  --verbose           Show scan results in scrolling log above progress bar\n"
    printf "  --verbose-detail    Show all events (clone, scan, result) in scrolling log\n"
    printf "  --help              Show this help message\n"
    printf "\n"
    printf "Examples:\n"
    printf "  %s --github myorg                          # Scan org (6 workers)\n" "$0"
    printf "  %s --github myorg --parallel 10            # 10 parallel workers\n" "$0"
    printf "  %s --github myorg --log-json               # With JSON report\n" "$0"
    printf "  %s --github org1 --github org2 --log-json  # Multiple orgs\n" "$0"
}

log_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        printf "  ${CYAN}[verbose]${RESET} %s\n" "$1"
    fi
}

log_msg() {
    local msg="$1"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    printf "[%s] %s\n" "$timestamp" "$msg"
    if [ -n "$LOG_FILE" ]; then
        printf "[%s] %s\n" "$timestamp" "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    fi
}

init_log() {
    local timestamp
    timestamp="$(date '+%Y-%m-%d_%H-%M-%S')"
    mkdir -p scan-logs/org-history
    LOG_FILE="scan-logs/org-history/scan-${timestamp}.log"
    : > "$LOG_FILE"
    SCAN_START_TIME="$(date '+%s')"
    log_msg "PolinRider Fast Scanner v${VERSION} started"
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

log_scan_complete() {
    local end_time
    end_time="$(date '+%s')"
    local duration=$((end_time - SCAN_START_TIME))
    local mins=$((duration / 60))
    local secs=$((duration % 60))
    log_msg "Scan complete. Duration: ${mins}m${secs}s"
    log_msg "Total repos: ${TOTAL_REPOS}, Infected: ${INFECTED_REPOS}"
}

init_progress_ui() {
    if [ -t 1 ]; then
        PROGRESS_UI=1
    else
        PROGRESS_UI=0
    fi
}

prompt_keep_repos() {
    if [ ! -t 0 ]; then
        return  # non-interactive, default: delete after scan
    fi
    printf "Keep cloned repos after scan? (stored in repos/, skipped on re-run) [y/N]: "
    local answer
    read -r answer </dev/tty
    case "$answer" in
        [yY]*) KEEP_REPO=1 ;;
    esac
}

ui_emit_event() {
    local status_dir="$1"
    local msg="$2"
    printf "%s\n" "$msg" > "${status_dir}/latest-event"
    if [ "$VERBOSE_DETAIL" -eq 1 ]; then
        local _ts
        _ts="$(date '+%Y-%m-%d %H:%M:%S')"
        printf "[%s] %s\n" "$_ts" "$msg" >> "${status_dir}/event-log"
    fi
}

ui_log_result() {
    local status_dir="$1"
    local msg="$2"
    printf "%s\n" "$msg" > "${status_dir}/latest-event"
    if [ "$VERBOSE" -eq 1 ] || [ "$VERBOSE_DETAIL" -eq 1 ]; then
        local _ts
        _ts="$(date '+%Y-%m-%d %H:%M:%S')"
        printf "[%s] %s\n" "$_ts" "$msg" >> "${status_dir}/event-log"
    fi
}

_colorize_log_line() {
    local _line="$1"
    case "$_line" in
        *"CONFIRMED"*|*" INFECTED"*|*"[INFECTED]"*|*"[V1"*|*"[V2"*)
            printf "${RED}%s${RESET}\n" "$_line" ;;
        *"HISTORY"*)
            printf "${YELLOW}%s${RESET}\n" "$_line" ;;
        *" — clean"*|*": clean"*)
            printf "${GREEN}%s${RESET}\n" "$_line" ;;
        *"Complete:"*|*"complete:"*)
            printf "${CYAN}%s${RESET}\n" "$_line" ;;
        *"Starting"*|*"Cloning"*|*"Fetching"*|*"Scanning"*)
            printf "${DIM}%s${RESET}\n" "$_line" ;;
        *)
            printf "%s\n" "$_line" ;;
    esac
}

ui_mark_state() {
    local status_dir="$1"
    local repo_short="$2"
    local state="$3"
    : > "${status_dir}/${repo_short}.${state}"
}

# ---------------------------------------------------------------------------
# Persistent resume state helpers
# State dir: scan-bare-clones/<owner>/.scan-state/
#   last-run-time     — timestamp of last run
#   last-results-dir  — path to last run's infected-repos dir
#   <repo_short>      — per-repo result: "infected N" | "history N" | "clean" | "error"
# ---------------------------------------------------------------------------
_state_dir() { printf "scan-bare-clones/%s/.scan-state" "$1"; }

check_previous_run() {
    local owner="$1"
    local sd
    sd="$(_state_dir "$owner")"
    RESUME_MODE=0

    if [ ! -d "$sd" ] || [ -z "$(ls -A "$sd" 2>/dev/null)" ]; then
        return
    fi

    local last_ts done_count infected_count
    last_ts=$(cat "${sd}/last-run-time" 2>/dev/null || printf "unknown")
    done_count=$(find "$sd" -maxdepth 1 -type f \
        ! -name 'last-run-time' ! -name 'last-results-dir' 2>/dev/null | wc -l | tr -d ' ')
    infected_count=$(grep -rl '^infected' "$sd" 2>/dev/null | wc -l | tr -d ' ')

    printf "\n${BOLD}[%s] Previous scan found:${RESET}\n" "$owner"
    printf "  Time:      %s\n" "$last_ts"
    printf "  Completed: %d repo(s)   infected: %d\n" "$done_count" "$infected_count"

    if [ "$RESTART" -eq 1 ]; then
        printf "  -> Restart mode (--restart), clearing previous state...\n\n"
        rm -rf "$sd"
        return
    fi

    [ ! -t 0 ] && return

    printf "\n  [Y] Resume  — skip already-done %d repo(s)\n" "$done_count"
    printf "  [r] Restart — rescan everything\n"
    printf "  [n] Cancel\n"
    printf "> " >/dev/tty
    local answer
    read -r answer </dev/tty
    printf "\n"
    case "$answer" in
        [rR]*) rm -rf "$sd" ;;
        [nN]*) printf "Cancelled.\n"; exit 0 ;;
        *) RESUME_MODE=1 ;;
    esac
}

persist_repo_result() {
    local owner="$1" repo_short="$2" result="$3"
    local sd
    sd="$(_state_dir "$owner")"
    mkdir -p "$sd"
    printf "%s\n" "$result" > "${sd}/${repo_short}"
    date '+%Y-%m-%d %H:%M:%S' > "${sd}/last-run-time"
}

repo_already_done() {
    [ -f "$(_state_dir "$1")/$2" ]
}

render_progress_bar() {
    local owner="$1"
    local total="$2"
    local running="$3"
    local status_dir="$4"

    if [ "$PROGRESS_UI" -ne 1 ] || [ "$total" -le 0 ]; then
        return
    fi

    local _verbose_mode=0
    { [ "$VERBOSE" -eq 1 ] || [ "$VERBOSE_DETAIL" -eq 1 ]; } && _verbose_mode=1

    # Erase current sticky area then flush new log lines (colorized)
    if [ "$PROGRESS_LINES" -gt 0 ]; then
        printf "\033[%sA\033[J" "$PROGRESS_LINES"
    fi
    if [ "$_verbose_mode" -eq 1 ]; then
        local queue_file="${status_dir}/event-log"
        if [ -f "$queue_file" ]; then
            local current_lines
            current_lines=$(wc -l < "$queue_file" 2>/dev/null | tr -d ' ')
            if [ "$current_lines" -gt "$LAST_QUEUE_LINE" ]; then
                while IFS= read -r _line; do
                    _colorize_log_line "$_line"
                done < <(tail -n +"$((LAST_QUEUE_LINE + 1))" "$queue_file")
                LAST_QUEUE_LINE=$current_lines
            fi
        fi
    fi

    # Braille spinner with 4-color cycling
    local spinner
    case $((SPINNER_IDX % 10)) in
        0) spinner="⠋" ;; 1) spinner="⠙" ;; 2) spinner="⠹" ;; 3) spinner="⠸" ;;
        4) spinner="⠼" ;; 5) spinner="⠴" ;; 6) spinner="⠦" ;; 7) spinner="⠧" ;;
        8) spinner="⠇" ;; *) spinner="⠏" ;;
    esac
    local _sc
    case $((SPINNER_IDX % 4)) in
        0) _sc="$CYAN" ;; 1) _sc="$GREEN" ;; 2) _sc="$YELLOW" ;; *) _sc="$MAGENTA" ;;
    esac
    SPINNER_IDX=$((SPINNER_IDX + 1))

    # Collect stats
    local infected done latest_event active_repos
    infected=$(find "$status_dir" -type f -name '*.infected' 2>/dev/null | wc -l | tr -d ' ')
    done=$(find "$status_dir" -type f -name '*.done' 2>/dev/null | wc -l | tr -d ' ')
    latest_event="$(cat "${status_dir}/latest-event" 2>/dev/null || true)"
    [ -z "$latest_event" ] && latest_event="Waiting for workers..."
    active_repos=$(find "$status_dir" -type f -name 'active-*' 2>/dev/null \
        | xargs -I{} cat {} 2>/dev/null | tr '\n' ' ' | sed 's/ $//')

    # Bar: green fill █, dark-gray empty ─
    local percent=$((done * 100 / total))
    local width=30
    local fill=$((done * width / total))
    local empty=$((width - fill))
    local bar_fill bar_empty
    bar_fill="$(printf "%${fill}s" "" | tr ' ' '█')"
    bar_empty="$(printf "%${empty}s" "" | tr ' ' '─')"

    # Verbose separator above sticky area
    local _plines=3
    if [ "$_verbose_mode" -eq 1 ]; then
        printf "\033[2K${DIM}──────────────────── scan log ───────────────────────${RESET}\n"
        printf "\033[2K\n"
        printf "\033[2K\n"
        _plines=6
    fi

    # Line 1: spinner + [org: owner] + bar + stats
    if [ "$infected" -gt 0 ]; then
        printf "\033[2K${_sc}%s${RESET} ${BOLD}${CYAN}[org: %s]${RESET} [${GREEN}%s${RESET}${DIM}%s${RESET}] %3d%%  ${CYAN}done: %d/%d${RESET}  ${RED}infected: %d${RESET}  ${YELLOW}workers: %d${RESET}\n" \
            "$spinner" "$owner" "$bar_fill" "$bar_empty" "$percent" "$done" "$total" "$infected" "$running"
    else
        printf "\033[2K${_sc}%s${RESET} ${BOLD}${CYAN}[org: %s]${RESET} [${GREEN}%s${RESET}${DIM}%s${RESET}] %3d%%  ${CYAN}done: %d/%d${RESET}  ${YELLOW}workers: %d${RESET}\n" \
            "$spinner" "$owner" "$bar_fill" "$bar_empty" "$percent" "$done" "$total" "$running"
    fi

    # Line 2: active repos with per-repo color cycling
    local _colored="" _ri=0 _rc
    for _repo in $active_repos; do
        case $((_ri % 4)) in
            0) _rc="$CYAN" ;; 1) _rc="$GREEN" ;; 2) _rc="$YELLOW" ;; *) _rc="$MAGENTA" ;;
        esac
        _colored="${_colored}${_rc}${_repo}${RESET}  "
        _ri=$((_ri + 1))
    done
    [ "$_ri" -eq 0 ] && _colored="(idle)"
    printf "\033[2K  ${DIM}scanning:${RESET} %b\n" "$_colored"

    # Line 3: latest pipeline status
    printf "\033[2K  ${DIM}status:${RESET}   %s\n" "$latest_event"

    PROGRESS_LINES=$_plines
}

clear_progress_line() {
    if [ "$PROGRESS_UI" -eq 1 ]; then
        PROGRESS_LINES=0
        printf "\n"
    fi
}

# ---------------------------------------------------------------------------
# scan_bare_repo — scans a bare git clone using git grep + git show
# No checkout needed. Scans ALL branches.
#
# Writes structured results to a file:
#   FINDING\tbranch\tfile\tdescription
# ---------------------------------------------------------------------------
scan_bare_repo() {
    local bare_dir="$1"
    local results_file="$2"
    local _sd="${3:-}"
    local _wp="${4:-}"
    local _rn="${5:-}"
    _ep() { [ -n "$_sd" ] && ui_emit_event "$_sd" "${_wp} ${_rn} — ${1}"; }

    : > "$results_file"

    # Get all branch refs
    local all_refs=""
    local ref_count=0
    while IFS= read -r ref_line; do
        if [ -n "$ref_line" ]; then
            all_refs="${all_refs} ${ref_line}"
            ref_count=$((ref_count + 1))
        fi
    done <<REFSEOF
$(git -C "$bare_dir" for-each-ref --format='%(refname)' refs/heads/ 2>/dev/null)
REFSEOF

    if [ "$ref_count" -eq 0 ]; then
        log_verbose "No branches found"
        return 0
    fi

    log_verbose "Scanning ${ref_count} branch(es) via git grep"
    _ep "${ref_count} branches — signatures..."

    # --- Pass 1: Primary signatures (high-confidence, single-pattern) ---
    # These alone confirm infection.
    local primary_sigs=""
    primary_sigs="[V1] Obfuscated payload detected — decoder marker \"rmcej%otb%\" found|$V1_MARKER
[V2] Obfuscated payload detected — decoder marker \"Cot%3t=shtP\" found|$V2_MARKER
[V1] Payload decoder function detected: \"_\$_1e42\"|$V1_DECODER
[V1] Runtime global hook detected: \"global['!']\"|$V1_GLOBAL
[V2] Runtime global hook detected: \"global['_V']\"|$V2_GLOBAL
[SUSPICIOUS] Malware runtime require hook: global['r']=require|$COMMON_GLOBAL_R"

    while IFS= read -r sig_entry; do
        if [ -z "$sig_entry" ]; then continue; fi
        local sig_label="${sig_entry%%|*}"
        local sig_val="${sig_entry#*|}"

        local grep_out
        grep_out=$(mktemp)

        # Run git grep with timeout
        # shellcheck disable=SC2086
        git -C "$bare_dir" grep -lF "$sig_val" $all_refs -- \
            ':(glob)**/*.config.mjs' ':(glob)**/*.config.js' ':(glob)**/*.config.cjs' ':(glob)**/*.config.ts' \
            ':(glob)**/App.js' ':(glob)**/app.js' ':(glob)**/index.js' \
            ':(glob)**/babel.config.js' ':(glob)**/jest.config.js' ':(glob)**/truffle.js' \
            ':(glob)**/*.woff' ':(glob)**/*.woff2' \
            ':(glob)**/temp_auto_push.bat' ':(glob)**/config.bat' \
            ':(glob)**/.vscode/*' ':(glob)**/.cursor/*' ':(glob)**/.claude/*' \
            ':(glob)**/package.json' \
            > "$grep_out" 2>/dev/null &
        local grep_pid=$!
        local waited=0
        while kill -0 "$grep_pid" 2>/dev/null; do
            sleep 1
            waited=$((waited + 1))
            if [ "$waited" -ge "$GIT_GREP_TIMEOUT" ]; then
                kill "$grep_pid" 2>/dev/null
                wait "$grep_pid" 2>/dev/null
                break
            fi
        done
        wait "$grep_pid" 2>/dev/null

        if [ ! -s "$grep_out" ]; then
            rm -f "$grep_out"
            continue
        fi

        while IFS= read -r hit_line; do
            if [ -z "$hit_line" ]; then continue; fi
            local ref="${hit_line%%:*}"
            local filepath="${hit_line#*:}"
            if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi

            local branch="${ref#refs/heads/}"

            # Skip origin/ duplicates
            case "$branch" in
                origin/*|*/HEAD) continue ;;
            esac

            printf 'FINDING\t%s\t%s\t%s\n' "$branch" "$filepath" "$sig_label" >> "$results_file"
        done < "$grep_out"

        rm -f "$grep_out"
    done <<SIGSEOF
$primary_sigs
SIGSEOF

    # --- Pass 2: Compound checks via git show on files already flagged ---
    # For files that matched V1_GLOBAL, verify V1_SEED co-exists
    # For files that matched COMMON_GLOBAL_R, verify COMMON_GLOBAL_M co-exists
    local compound_file
    compound_file=$(mktemp)
    grep 'V1 global' "$results_file" 2>/dev/null | while IFS='	' read -r _type branch filepath _desc; do
        local content
        content="$(git -C "$bare_dir" show "refs/heads/${branch}:${filepath}" 2>/dev/null)" || continue
        if printf '%s' "$content" | grep -qF "$V1_SEED" || \
           printf '%s' "$content" | grep -qF "$V1_SEED2"; then
            printf 'FINDING\t%s\t%s\t[V1 CONFIRMED] Active payload — global hook + seed both present\n' "$branch" "$filepath" >> "$compound_file"
        fi
    done
    grep 'V2 global' "$results_file" 2>/dev/null | while IFS='	' read -r _type branch filepath _desc; do
        local content
        content="$(git -C "$bare_dir" show "refs/heads/${branch}:${filepath}" 2>/dev/null)" || continue
        if printf '%s' "$content" | grep -qF "$V2_SEED" || \
           printf '%s' "$content" | grep -qF "$V2_SEED2" || \
           printf '%s' "$content" | grep -qF "$V2_DECODER"; then
            printf 'FINDING\t%s\t%s\t[V2 CONFIRMED] Active payload — global hook + seed/decoder both present\n' "$branch" "$filepath" >> "$compound_file"
        fi
    done
    grep 'global r marker' "$results_file" 2>/dev/null | while IFS='	' read -r _type branch filepath _desc; do
        local content
        content="$(git -C "$bare_dir" show "refs/heads/${branch}:${filepath}" 2>/dev/null)" || continue
        if printf '%s' "$content" | grep -qF "$COMMON_GLOBAL_M"; then
            if printf '%s' "$content" | grep -qF "$V1_SEED" || \
               printf '%s' "$content" | grep -qF "$V2_SEED"; then
                printf 'FINDING\t%s\t%s\t[SUSPICIOUS] Require/module hooks + known seed — likely infected\n' "$branch" "$filepath" >> "$compound_file"
            fi
        fi
    done

    if [ -s "$compound_file" ]; then
        cat "$compound_file" >> "$results_file"
    fi
    rm -f "$compound_file"

    # --- Pass 3: Malicious npm packages (git grep for each) ---
    _ep "npm packages..."
    local old_ifs="$IFS"
    IFS=' '
    for mal_pkg in $MALICIOUS_NPM_PKGS; do
        local pkg_out
        pkg_out=$(mktemp)
        # shellcheck disable=SC2086
        git -C "$bare_dir" grep -lF "\"${mal_pkg}\"" $all_refs -- ':(glob)**/package.json' > "$pkg_out" 2>/dev/null || true

        if [ -s "$pkg_out" ]; then
            while IFS= read -r hit_line; do
                if [ -z "$hit_line" ]; then continue; fi
                local ref="${hit_line%%:*}"
                local filepath="${hit_line#*:}"
                if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi
                local branch="${ref#refs/heads/}"
                case "$branch" in origin/*|*/HEAD) continue ;; esac
                printf 'FINDING\t%s\t%s\t[SUPPLY CHAIN] Malicious npm package in dependencies: %s\n' "$branch" "$filepath" "$mal_pkg" >> "$results_file"
            done < "$pkg_out"
        fi
        rm -f "$pkg_out"
    done
    IFS="$old_ifs"

    # --- Pass 4: C2 domains in IDE configs ---
    _ep "C2 domains..."
    old_ifs="$IFS"
    IFS=' '
    for domain in $C2_DOMAINS; do
        local c2_out
        c2_out=$(mktemp)
        # shellcheck disable=SC2086
        git -C "$bare_dir" grep -lF "$domain" $all_refs -- \
            ':(glob)**/.vscode/*' ':(glob)**/.cursor/*' ':(glob)**/.claude/*' \
            ':(glob)**/*.config.js' ':(glob)**/*.config.mjs' \
            > "$c2_out" 2>/dev/null || true

        if [ -s "$c2_out" ]; then
            while IFS= read -r hit_line; do
                if [ -z "$hit_line" ]; then continue; fi
                local ref="${hit_line%%:*}"
                local filepath="${hit_line#*:}"
                if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi
                local branch="${ref#refs/heads/}"
                case "$branch" in origin/*|*/HEAD) continue ;; esac
                printf 'FINDING\t%s\t%s\t[C2] Command & control domain in config: %s\n' "$branch" "$filepath" "$domain" >> "$results_file"
            done < "$c2_out"
        fi
        rm -f "$c2_out"
    done
    IFS="$old_ifs"

    # --- Pass 5: Blockchain C2 addresses ---
    for addr in "$TRON_ADDR_1" "$TRON_ADDR_2" "$APTOS_HASH_1" "$APTOS_HASH_2"; do
        local addr_out
        addr_out=$(mktemp)
        # shellcheck disable=SC2086
        git -C "$bare_dir" grep -lF "$addr" $all_refs > "$addr_out" 2>/dev/null || true

        if [ -s "$addr_out" ]; then
            while IFS= read -r hit_line; do
                if [ -z "$hit_line" ]; then continue; fi
                local ref="${hit_line%%:*}"
                local filepath="${hit_line#*:}"
                if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi
                local branch="${ref#refs/heads/}"
                case "$branch" in origin/*|*/HEAD) continue ;; esac
                printf 'FINDING\t%s\t%s\t[C2] Blockchain exfiltration address: %s\n' "$branch" "$filepath" "$addr" >> "$results_file"
            done < "$addr_out"
        fi
        rm -f "$addr_out"
    done

    # --- Pass 6: StakingGame UUID ---
    local uuid_out
    uuid_out=$(mktemp)
    # shellcheck disable=SC2086
    git -C "$bare_dir" grep -lF "$STAKING_UUID" $all_refs > "$uuid_out" 2>/dev/null || true
    if [ -s "$uuid_out" ]; then
        while IFS= read -r hit_line; do
            if [ -z "$hit_line" ]; then continue; fi
            local ref="${hit_line%%:*}"
            local filepath="${hit_line#*:}"
            if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi
            local branch="${ref#refs/heads/}"
            case "$branch" in origin/*|*/HEAD) continue ;; esac
            printf 'FINDING\t%s\t%s\t[IOC] StakingGame UUID found — confirms PolinRider infection origin\n' "$branch" "$filepath" >> "$results_file"
        done < "$uuid_out"
    fi
    rm -f "$uuid_out"

    # --- Pass 7: Propagation scripts (temp_auto_push.bat, config.bat) ---
    local prop_out
    prop_out=$(mktemp)
    # shellcheck disable=SC2086
    git -C "$bare_dir" grep -lF "LAST_COMMIT_DATE" $all_refs -- \
        ':(glob)**/temp_auto_push.bat' ':(glob)**/config.bat' \
        > "$prop_out" 2>/dev/null || true
    if [ -s "$prop_out" ]; then
        while IFS= read -r hit_line; do
            if [ -z "$hit_line" ]; then continue; fi
            local ref="${hit_line%%:*}"
            local filepath="${hit_line#*:}"
            if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi
            local branch="${ref#refs/heads/}"
            case "$branch" in origin/*|*/HEAD) continue ;; esac
            printf 'FINDING\t%s\t%s\t[PROPAGATION] Auto-push script detected — spreads infection to other repos via git\n' "$branch" "$filepath" >> "$results_file"
        done < "$prop_out"
    fi
    rm -f "$prop_out"

    # --- Pass 8: IDE config compound checks (curl|bash + folderOpen) ---
    _ep "IDE configs..."
    local curl_out
    curl_out=$(mktemp)
    # shellcheck disable=SC2086
    git -C "$bare_dir" grep -lE '(curl|wget).*\|.*(bash|sh)' $all_refs -- \
        ':(glob)**/.vscode/*' ':(glob)**/.cursor/*' ':(glob)**/.claude/*' \
        > "$curl_out" 2>/dev/null || true
    if [ -s "$curl_out" ]; then
        while IFS= read -r hit_line; do
            if [ -z "$hit_line" ]; then continue; fi
            local ref="${hit_line%%:*}"
            local filepath="${hit_line#*:}"
            if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi
            local branch="${ref#refs/heads/}"
            case "$branch" in origin/*|*/HEAD) continue ;; esac

            local content
            content="$(git -C "$bare_dir" show "refs/heads/${branch}:${filepath}" 2>/dev/null)" || continue
            if printf '%s' "$content" | grep -qF "folderOpen"; then
                printf 'FINDING\t%s\t%s\t[RCE] curl|bash auto-executes on folder open — TasksJacker attack vector\n' "$branch" "$filepath" >> "$results_file"
            else
                printf 'FINDING\t%s\t%s\t[SUSPICIOUS] curl|bash command in IDE task config\n' "$branch" "$filepath" >> "$results_file"
            fi
        done < "$curl_out"
    fi
    rm -f "$curl_out"

    # --- Pass 9: child_process + detached in config files ---
    local cp_out
    cp_out=$(mktemp)
    # shellcheck disable=SC2086
    git -C "$bare_dir" grep -lF "child_process" $all_refs -- \
        ':(glob)**/*.config.mjs' ':(glob)**/*.config.js' ':(glob)**/*.config.cjs' ':(glob)**/*.config.ts' \
        > "$cp_out" 2>/dev/null || true
    if [ -s "$cp_out" ]; then
        while IFS= read -r hit_line; do
            if [ -z "$hit_line" ]; then continue; fi
            local ref="${hit_line%%:*}"
            local filepath="${hit_line#*:}"
            if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi
            local branch="${ref#refs/heads/}"
            case "$branch" in origin/*|*/HEAD) continue ;; esac

            local content
            content="$(git -C "$bare_dir" show "refs/heads/${branch}:${filepath}" 2>/dev/null)" || continue
            if printf '%s' "$content" | grep -qF "detached" || \
               printf '%s' "$content" | grep -qF "windowsHide"; then
                printf 'FINDING\t%s\t%s\t[SUSPICIOUS] Hidden background process spawned from config file\n' "$branch" "$filepath" >> "$results_file"
            fi
        done < "$cp_out"
    fi
    rm -f "$cp_out"

    # --- Pass 10: Prompt injection in .claude/.cursor configs ---
    local pi_out
    pi_out=$(mktemp)
    # shellcheck disable=SC2086
    git -C "$bare_dir" grep -liE '(ignore previous|ignore above|disregard|forget all|new instructions|you are now|act as|pretend)' $all_refs -- \
        ':(glob)**/.claude/*' ':(glob)**/.cursor/*' \
        > "$pi_out" 2>/dev/null || true
    if [ -s "$pi_out" ]; then
        while IFS= read -r hit_line; do
            if [ -z "$hit_line" ]; then continue; fi
            local ref="${hit_line%%:*}"
            local filepath="${hit_line#*:}"
            if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi
            local branch="${ref#refs/heads/}"
            case "$branch" in origin/*|*/HEAD) continue ;; esac
            printf 'FINDING\t%s\t%s\t[PROMPT INJECTION] AI agent config contains instruction override pattern\n' "$branch" "$filepath" >> "$results_file"
        done < "$pi_out"
    fi
    rm -f "$pi_out"

    # --- Pass 11: Credential exfiltration in agent configs ---
    local cred_out
    cred_out=$(mktemp)
    # shellcheck disable=SC2086
    git -C "$bare_dir" grep -liE '(ssh_key|private_key|api_key|secret|token|password|credential)' $all_refs -- \
        ':(glob)**/.claude/*' ':(glob)**/.cursor/*' \
        > "$cred_out" 2>/dev/null || true
    if [ -s "$cred_out" ]; then
        while IFS= read -r hit_line; do
            if [ -z "$hit_line" ]; then continue; fi
            local ref="${hit_line%%:*}"
            local filepath="${hit_line#*:}"
            if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi
            local branch="${ref#refs/heads/}"
            case "$branch" in origin/*|*/HEAD) continue ;; esac
            # Skip Claude Code's own local config — legitimately contains token/credential terms
            case "$filepath" in */.claude/settings.local.json) continue ;; esac

            local content
            content="$(git -C "$bare_dir" show "refs/heads/${branch}:${filepath}" 2>/dev/null)" || continue
            if printf '%s' "$content" | grep -qiE '(read|cat|send|upload|post|exfil|steal|extract)'; then
                printf 'FINDING\t%s\t%s\t[EXFILTRATION] Agent config reads credentials and appears to exfiltrate them\n' "$branch" "$filepath" >> "$results_file"
            fi
        done < "$cred_out"
    fi
    rm -f "$cred_out"

    # --- Pass 12: External URLs in agent configs ---
    local url_out
    url_out=$(mktemp)
    # shellcheck disable=SC2086
    git -C "$bare_dir" grep -liE '(curl|wget|fetch|http|https)://' $all_refs -- \
        ':(glob)**/.claude/*' ':(glob)**/.cursor/*' \
        > "$url_out" 2>/dev/null || true
    if [ -s "$url_out" ]; then
        while IFS= read -r hit_line; do
            if [ -z "$hit_line" ]; then continue; fi
            local ref="${hit_line%%:*}"
            local filepath="${hit_line#*:}"
            if [ "$ref" = "$hit_line" ] || [ -z "$filepath" ]; then continue; fi
            local branch="${ref#refs/heads/}"
            case "$branch" in origin/*|*/HEAD) continue ;; esac
            # Skip known-legitimate paths: Claude Code local config and Cursor team workflow files
            case "$filepath" in
                */.claude/settings.local.json) continue ;;
                */.cursor/rules/*|*/.cursor/commands/*|*/.cursor/skills/*) continue ;;
            esac
            printf 'FINDING\t%s\t%s\t[SUSPICIOUS] External URL in agent config — possible data exfiltration\n' "$branch" "$filepath" >> "$results_file"
        done < "$url_out"
    fi
    rm -f "$url_out"

    # Deduplicate results
    if [ -s "$results_file" ]; then
        local deduped
        deduped=$(mktemp)
        sort -u "$results_file" > "$deduped"
        mv "$deduped" "$results_file"
    fi

    # Return: 0 = clean, 1 = infected
    if [ -s "$results_file" ]; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# scan_commit_history — scan git commit history for payload signatures
# Uses `git log --all -S` to find ALL commits where V1/V2 markers were added or removed.
# Writes HISTORY\t<hash>\t<date>\t<message>\t<description> lines to results_file.
# Returns 0 = no history hits, 1 = history hits found.
# ---------------------------------------------------------------------------
scan_commit_history() {
    local bare_dir="$1"
    local results_file="$2"
    local _sd="${3:-}"
    local _wp="${4:-}"
    local _rn="${5:-}"
    _ep() { [ -n "$_sd" ] && ui_emit_event "$_sd" "${_wp} ${_rn} — ${1}"; }

    : > "$results_file"

    local history_v1=""
    local history_v2=""

    # --format="%h|%ai|%an|%ae|%s": short hash | ISO date | author name | author email | subject
    # -S searches commits where the string count changed (i.e. was added or removed).
    _ep "commit history (V1)..."
    history_v1=$(git -C "$bare_dir" log --all \
        -S "$V1_MARKER" --format="%h|%ai|%an|%ae|%s" 2>/dev/null) || true

    _ep "commit history (V2)..."
    history_v2=$(git -C "$bare_dir" log --all \
        -S "$V2_MARKER" --format="%h|%ai|%an|%ae|%s" 2>/dev/null) || true

    if [ -n "$history_v1" ]; then
        while IFS= read -r commit_line; do
            [ -z "$commit_line" ] && continue
            local commit_hash="${commit_line%%|*}"
            local rest="${commit_line#*|}"
            local commit_date="${rest%%|*}"
            rest="${rest#*|}"
            local commit_author="${rest%%|*}"
            rest="${rest#*|}"
            local commit_email="${rest%%|*}"
            local commit_msg="${rest#*|}"
            printf 'HISTORY\t%s\t%s\t%s\t%s\t%s\tVariant 1 (rmcej%%otb%%) injected\n' \
                "$commit_hash" "$commit_date" "$commit_author" "$commit_email" "$commit_msg" >> "$results_file"
        done <<< "$history_v1"
    fi

    if [ -n "$history_v2" ]; then
        while IFS= read -r commit_line; do
            [ -z "$commit_line" ] && continue
            local commit_hash="${commit_line%%|*}"
            local rest="${commit_line#*|}"
            local commit_date="${rest%%|*}"
            rest="${rest#*|}"
            local commit_author="${rest%%|*}"
            rest="${rest#*|}"
            local commit_email="${rest%%|*}"
            local commit_msg="${rest#*|}"
            printf 'HISTORY\t%s\t%s\t%s\t%s\t%s\tVariant 2 (Cot%%3t=shtP) injected\n' \
                "$commit_hash" "$commit_date" "$commit_author" "$commit_email" "$commit_msg" >> "$results_file"
        done <<< "$history_v2"
    fi

    if [ -s "$results_file" ]; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# scan_single_repo_worker — worker: bare clone + scan + write results
# ---------------------------------------------------------------------------
scan_single_repo_worker() {
    local owner="$1"
    local full_name="$2"
    local repo_idx="$3"
    local repo_count="$4"
    local tmp_dir="$5"
    local results_dir="$6"
    local status_dir="$7"

    local repo_short="${full_name#*/}"
    local bare_dir
    if [ "$KEEP_REPO" -eq 1 ]; then
        mkdir -p "scan-bare-clones/${owner}"
        bare_dir="scan-bare-clones/${owner}/${repo_short}.git"
    else
        bare_dir="${tmp_dir}/${repo_short}.git"
    fi
    local worker_prefix="[${owner}] #${repo_idx}"

    # Resume mode: skip repos already completed in a previous run
    if [ "$RESUME_MODE" -eq 1 ] && repo_already_done "$owner" "$repo_short"; then
        local _prev_result _old_results_dir
        _prev_result=$(cat "$(_state_dir "$owner")/${repo_short}" 2>/dev/null || true)
        _old_results_dir=$(cat "$(_state_dir "$owner")/last-results-dir" 2>/dev/null || true)
        case "$_prev_result" in
            infected*)
                if [ -n "$_old_results_dir" ] && [ -f "${_old_results_dir}/${repo_short}.log" ]; then
                    cp "${_old_results_dir}/${repo_short}.log" "${results_dir}/${repo_short}.log" 2>/dev/null || true
                fi
                ;;
            history*)
                if [ -n "$_old_results_dir" ] && [ -f "${_old_results_dir}/${repo_short}.history" ]; then
                    cp "${_old_results_dir}/${repo_short}.history" "${results_dir}/${repo_short}.history" 2>/dev/null || true
                fi
                ;;
        esac
        ui_mark_state "$status_dir" "$repo_short" "done"
        return 0
    fi

    printf "%s\n" "$full_name" > "${status_dir}/active-${repo_short}"
    ui_emit_event "$status_dir" "${worker_prefix} Cloning ${full_name}..."
    log_msg "${worker_prefix} ${full_name} — cloning..."

    local clone_url
    if [ "$USE_HTTPS" -eq 1 ]; then
        clone_url="https://github.com/${full_name}.git"
    else
        clone_url="${SSH_HOST}:${full_name}.git"
    fi
    if ! git clone --bare --quiet "$clone_url" "$bare_dir" 2>&1; then
        rm -f "${status_dir}/active-${repo_short}"
        log_msg "${worker_prefix} ${full_name} — ERROR: clone failed, skipping"
        ui_log_result "$status_dir" "${worker_prefix} ERROR: Clone failed for ${full_name}"
        ui_mark_state "$status_dir" "$repo_short" "done"
        rm -rf "$bare_dir" 2>/dev/null
        return 1
    fi
    ui_mark_state "$status_dir" "$repo_short" "cloned"
    ui_emit_event "$status_dir" "${worker_prefix} Scanning ${full_name}..."

    local scan_results
    scan_results=$(mktemp)
    local history_results
    history_results=$(mktemp)

    scan_bare_repo "$bare_dir" "$scan_results" "$status_dir" "$worker_prefix" "$full_name"
    local scan_exit=$?
    ui_mark_state "$status_dir" "$repo_short" "scanned"

    scan_commit_history "$bare_dir" "$history_results" "$status_dir" "$worker_prefix" "$full_name"
    local history_exit=$?

    local is_infected=0
    local has_history=0
    [ "$scan_exit" -ne 0 ] && [ -s "$scan_results" ] && is_infected=1
    [ "$history_exit" -ne 0 ] && [ -s "$history_results" ] && has_history=1

    if [ "$is_infected" -eq 1 ]; then
        local result_file="${results_dir}/${repo_short}.log"
        {
            printf "repo=%s\n" "$full_name"
            cat "$scan_results"
            [ "$has_history" -eq 1 ] && cat "$history_results"
        } > "$result_file"

        local finding_count
        finding_count=$(wc -l < "$scan_results" | tr -d ' ')
        log_msg "${worker_prefix} ${full_name} — INFECTED (${finding_count} findings)"
        ui_log_result "$status_dir" "${worker_prefix} INFECTED ${full_name} (${finding_count} findings)"
        ui_mark_state "$status_dir" "$repo_short" "infected"
        persist_repo_result "$owner" "$repo_short" "infected ${finding_count}"

    elif [ "$has_history" -eq 1 ]; then
        local result_file="${results_dir}/${repo_short}.history"
        {
            printf "repo=%s\n" "$full_name"
            cat "$history_results"
        } > "$result_file"

        local history_count
        history_count=$(wc -l < "$history_results" | tr -d ' ')
        log_msg "${worker_prefix} ${full_name} — HISTORY (${history_count} past commit(s) — payload cleaned)"
        ui_log_result "$status_dir" "${worker_prefix} HISTORY ${full_name} (${history_count} past commits — cleaned)"
        ui_mark_state "$status_dir" "$repo_short" "infected"
        persist_repo_result "$owner" "$repo_short" "history ${history_count}"

    else
        local result_file="${results_dir}/${repo_short}.clean"
        printf "repo=%s\n" "$full_name" > "$result_file"
        log_msg "${worker_prefix} ${full_name} — clean"
        ui_log_result "$status_dir" "${worker_prefix} CLEAN ${full_name}"
        ui_mark_state "$status_dir" "$repo_short" "clean"
        persist_repo_result "$owner" "$repo_short" "clean"
    fi

    rm -f "${status_dir}/active-${repo_short}"
    ui_mark_state "$status_dir" "$repo_short" "done"
    rm -f "$scan_results" "$history_results"
    if [ "$KEEP_REPO" -ne 1 ]; then
        rm -rf "$bare_dir"
    fi
}

# ---------------------------------------------------------------------------
# scan_github_owner — list and scan all repos for a GitHub user/org
# ---------------------------------------------------------------------------
scan_github_owner() {
    local owner="$1"

    check_previous_run "$owner"
    LAST_QUEUE_LINE=0

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
    log_msg "[${owner}] Scanning with ${MAX_PARALLEL} parallel workers, ${CLONE_DELAY}s delay"

    local tmp_dir=".polinrider-fast-tmp-$(date '+%s')"
    mkdir -p "$tmp_dir"
    GITHUB_TMP_DIRS="${GITHUB_TMP_DIRS:+${GITHUB_TMP_DIRS} }${tmp_dir}"

    local scan_timestamp
    scan_timestamp="$(date '+%Y-%m-%d_%H-%M-%S')"
    GITHUB_RESULTS_DIR="infected-repos/${scan_timestamp}"
    mkdir -p "$GITHUB_RESULTS_DIR"

    local _sd
    _sd="$(_state_dir "$owner")"
    mkdir -p "$_sd"
    printf "%s\n" "$GITHUB_RESULTS_DIR" > "${_sd}/last-results-dir"

    local repo_idx=0
    local running_jobs=0
    local pids=""
    local status_dir="${tmp_dir}/.status"
    mkdir -p "$status_dir"

    if [ "$PROGRESS_UI" -eq 1 ]; then
        ui_emit_event "$status_dir" "[${owner}] Starting scan..."
        render_progress_bar "$owner" "$repo_count" 0 "$status_dir"
    fi

    while IFS= read -r full_name; do
        if [ -z "$full_name" ]; then continue; fi
        repo_idx=$((repo_idx + 1))

        while [ "$running_jobs" -ge "$MAX_PARALLEL" ]; do
            sleep 0.3
            _np="" _nc=0
            for _p in $pids; do
                if kill -0 "$_p" 2>/dev/null; then
                    _np="${_np} $_p"; _nc=$((_nc + 1))
                else
                    wait "$_p" 2>/dev/null || true
                fi
            done
            pids="$_np"; running_jobs=$_nc
            if [ "$PROGRESS_UI" -eq 1 ]; then
                render_progress_bar "$owner" "$repo_count" "$running_jobs" "$status_dir"
            fi
        done

        if [ "$PROGRESS_UI" -eq 1 ]; then
            scan_single_repo_worker "$owner" "$full_name" "$repo_idx" "$repo_count" "$tmp_dir" "$GITHUB_RESULTS_DIR" "$status_dir" >/dev/null &
        else
            scan_single_repo_worker "$owner" "$full_name" "$repo_idx" "$repo_count" "$tmp_dir" "$GITHUB_RESULTS_DIR" "$status_dir" &
        fi
        pids="${pids} $!"
        running_jobs=$((running_jobs + 1))

        if [ "$PROGRESS_UI" -eq 1 ]; then
            render_progress_bar "$owner" "$repo_count" "$running_jobs" "$status_dir"
        fi

        sleep "$CLONE_DELAY"
    done <<GHREPOEOF
$repo_list
GHREPOEOF

    while [ "$running_jobs" -gt 0 ]; do
        sleep 0.3
        _np="" _nc=0
        for _p in $pids; do
            if kill -0 "$_p" 2>/dev/null; then
                _np="${_np} $_p"; _nc=$((_nc + 1))
            else
                wait "$_p" 2>/dev/null || true
            fi
        done
        pids="$_np"; running_jobs=$_nc
        if [ "$PROGRESS_UI" -eq 1 ]; then
            render_progress_bar "$owner" "$repo_count" "$running_jobs" "$status_dir"
        fi
    done

    # Aggregate results
    local gh_infected=0
    local gh_history=0
    for result_file in "${GITHUB_RESULTS_DIR}"/*.log; do
        [ -f "$result_file" ] || continue
        gh_infected=$((gh_infected + 1))
    done
    for result_file in "${GITHUB_RESULTS_DIR}"/*.history; do
        [ -f "$result_file" ] || continue
        gh_history=$((gh_history + 1))
    done
    local gh_clean=$((repo_count - gh_infected - gh_history))

    TOTAL_REPOS=$((TOTAL_REPOS + repo_count))
    INFECTED_REPOS=$((INFECTED_REPOS + gh_infected))

    if [ "$PROGRESS_UI" -eq 1 ]; then
        render_progress_bar "$owner" "$repo_count" 0 "$status_dir"
        clear_progress_line
    fi

    log_msg "[${owner}] Complete: ${repo_count} repos, ${gh_infected} infected, ${gh_history} history-only, ${gh_clean} clean"

    # Generate reports
    generate_text_report "$owner" "$repo_count" "$GITHUB_RESULTS_DIR"

    if [ "$LOG_JSON" -eq 1 ]; then
        generate_json_report "$owner" "$repo_count" "$GITHUB_RESULTS_DIR"
    fi

    # Clean up .clean files and tmp
    rm -f "${GITHUB_RESULTS_DIR}"/*.clean 2>/dev/null
    rm -rf "$tmp_dir"
    GITHUB_TMP_DIRS="${GITHUB_TMP_DIRS% ${tmp_dir}}"
    GITHUB_TMP_DIRS="${GITHUB_TMP_DIRS#${tmp_dir} }"
    GITHUB_TMP_DIRS="${GITHUB_TMP_DIRS#${tmp_dir}}"
}

# ---------------------------------------------------------------------------
# generate_text_report
# ---------------------------------------------------------------------------
generate_text_report() {
    local owner="$1"
    local repo_count="$2"
    local results_dir="$3"

    local timestamp
    timestamp="$(date '+%Y-%m-%d_%H-%M-%S')"
    mkdir -p scan-logs/org-history
    REPORT_FILE="scan-logs/org-history/report-${owner}-${timestamp}.txt"

    local infected_count=0
    local infected_details=""
    local history_count=0
    local history_details=""

    for log_file in "${results_dir}"/*.log; do
        [ -f "$log_file" ] || continue
        infected_count=$((infected_count + 1))
        local repo_name
        repo_name="$(grep '^repo=' "$log_file" | head -1)"
        repo_name="${repo_name#repo=}"
        infected_details="${infected_details}${infected_count}. ${repo_name}\n"

        # Group FINDING lines by branch
        local branches
        branches="$(grep '^FINDING' "$log_file" | cut -f2 | sort -u)"
        local findings_tmp
        findings_tmp=$(mktemp)
        grep '^FINDING' "$log_file" > "$findings_tmp" 2>/dev/null || true
        while IFS= read -r branch; do
            if [ -z "$branch" ]; then continue; fi
            infected_details="${infected_details}   [${branch}]\n"
            while IFS='	' read -r _type _br filepath desc; do
                if [ "$_br" = "$branch" ]; then
                    infected_details="${infected_details}     - ${filepath}: ${desc}\n"
                fi
            done < "$findings_tmp"
        done <<BRDETAILEOF
$branches
BRDETAILEOF
        rm -f "$findings_tmp"

        # Also show HISTORY lines if any (repo was infected + has history)
        if grep -q '^HISTORY' "$log_file" 2>/dev/null; then
            infected_details="${infected_details}   [commit history]\n"
            while IFS='	' read -r _type commit_hash commit_date commit_author commit_email commit_msg desc; do
                infected_details="${infected_details}     - ${commit_hash}  ${commit_date}  ${commit_author} <${commit_email}>  \"${commit_msg}\": ${desc}\n"
            done < <(grep '^HISTORY' "$log_file")
        fi

        infected_details="${infected_details}\n"
    done

    # History-only repos (payload was cleaned but appears in past commits)
    for hist_file in "${results_dir}"/*.history; do
        [ -f "$hist_file" ] || continue
        history_count=$((history_count + 1))
        local repo_name
        repo_name="$(grep '^repo=' "$hist_file" | head -1)"
        repo_name="${repo_name#repo=}"
        history_details="${history_details}${history_count}. ${repo_name}\n"
        while IFS='	' read -r _type commit_hash commit_date commit_author commit_email commit_msg desc; do
            history_details="${history_details}   - ${commit_hash}  ${commit_date}  ${commit_author} <${commit_email}>  \"${commit_msg}\": ${desc}\n"
        done < <(grep '^HISTORY' "$hist_file")
        history_details="${history_details}\n"
    done

    local clean_count=$((repo_count - infected_count - history_count))

    {
        printf "PolinRider Scan Report (with Commit History)\n"
        printf "Generated: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf "Scanner: v%s (bare-clone, all branches + commit history)\n" "$VERSION"
        printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        printf "\n"
        printf "Owner:             %s\n" "$owner"
        printf "Total repos:       %d\n" "$repo_count"
        printf "Infected:          %d\n" "$infected_count"
        printf "History only:      %d\n" "$history_count"
        printf "Clean:             %d\n" "$clean_count"
        printf "\n"

        if [ "$infected_count" -gt 0 ]; then
            printf "INFECTED REPOSITORIES (payload still present):\n"
            printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            printf '%b' "$infected_details"
        fi

        if [ "$history_count" -gt 0 ]; then
            printf "PREVIOUSLY INFECTED (payload in history, now cleaned):\n"
            printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            printf '%b' "$history_details"
        fi

        if [ "$infected_count" -eq 0 ] && [ "$history_count" -eq 0 ]; then
            printf "No infections or history hits found.\n"
        fi

        printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        printf "Report: %s\n" "$REPORT_FILE"
        printf "Full log: %s\n" "$LOG_FILE"
    } > "$REPORT_FILE"

    log_msg "[${owner}] Report saved to ${REPORT_FILE}"
    printf "\n"
    cat "$REPORT_FILE"
    printf "\n"
}

# ---------------------------------------------------------------------------
# json_escape — POSIX-compatible JSON string escaping
# ---------------------------------------------------------------------------
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g' | tr -d '\n\r'
}

# ---------------------------------------------------------------------------
# generate_json_report — single JSON file with all repo results
# ---------------------------------------------------------------------------
generate_json_report() {
    local owner="$1"
    local repo_count="$2"
    local results_dir="$3"

    mkdir -p scan-logs/org-history
    JSON_FILE="scan-logs/org-history/result.json"

    local first_repo=1
    printf '[\n' > "$JSON_FILE"

    # Infected repos
    for log_file in "${results_dir}"/*.log; do
        [ -f "$log_file" ] || continue

        local repo_name
        repo_name="$(grep '^repo=' "$log_file" | head -1)"
        repo_name="${repo_name#repo=}"

        if [ "$first_repo" -eq 0 ]; then
            printf ',\n' >> "$JSON_FILE"
        fi
        first_repo=0

        printf '  {\n' >> "$JSON_FILE"
        printf '    "repository": "%s",\n' "$(json_escape "$repo_name")" >> "$JSON_FILE"
        printf '    "infected": true,\n' >> "$JSON_FILE"

        # Build infected_files (unique file -> merged descriptions)
        local findings_only
        findings_only=$(mktemp)
        grep '^FINDING' "$log_file" > "$findings_only" 2>/dev/null || true

        printf '    "infected_files": {' >> "$JSON_FILE"
        if [ -s "$findings_only" ]; then
            local all_files
            all_files="$(cut -f3 "$findings_only" | sort -u)"
            local file_first=1
            while IFS= read -r filepath; do
                if [ -z "$filepath" ]; then continue; fi
                local combined_desc="" seen_descs=""
                while IFS='	' read -r _type _br _f _d; do
                    if [ "$_f" = "$filepath" ]; then
                        case "$seen_descs" in *"|${_d}|"*) continue ;; esac
                        seen_descs="${seen_descs}|${_d}|"
                        if [ -n "$combined_desc" ]; then
                            combined_desc="${combined_desc} | ${_d}"
                        else
                            combined_desc="$_d"
                        fi
                    fi
                done < "$findings_only"
                if [ "$file_first" -eq 0 ]; then printf ',' >> "$JSON_FILE"; fi
                file_first=0
                printf '\n      "%s": "%s"' "$(json_escape "$filepath")" "$(json_escape "$combined_desc")" >> "$JSON_FILE"
            done <<FILESEOF
$all_files
FILESEOF
            printf '\n    },\n' >> "$JSON_FILE"
        else
            printf '},\n' >> "$JSON_FILE"
        fi

        # Build infected_branches
        printf '    "infected_branches": {' >> "$JSON_FILE"
        if [ -s "$findings_only" ]; then
            local all_branches
            all_branches="$(cut -f2 "$findings_only" | sort -u)"
            local br_first=1
            while IFS= read -r br_name; do
                if [ -z "$br_name" ]; then continue; fi
                if [ "$br_first" -eq 0 ]; then printf ',' >> "$JSON_FILE"; fi
                br_first=0
                printf '\n      "%s": {' "$(json_escape "$br_name")" >> "$JSON_FILE"

                local br_files
                br_files="$(awk -F'\t' -v br="$br_name" '$2 == br {print $3}' "$findings_only" | sort -u)"
                local bf_first=1
                while IFS= read -r br_file; do
                    if [ -z "$br_file" ]; then continue; fi
                    local combined_desc="" seen_descs=""
                    while IFS='	' read -r _type _br _f _d; do
                        if [ "$_br" = "$br_name" ] && [ "$_f" = "$br_file" ]; then
                            case "$seen_descs" in *"|${_d}|"*) continue ;; esac
                            seen_descs="${seen_descs}|${_d}|"
                            if [ -n "$combined_desc" ]; then
                                combined_desc="${combined_desc} | ${_d}"
                            else
                                combined_desc="$_d"
                            fi
                        fi
                    done < "$findings_only"
                    if [ "$bf_first" -eq 0 ]; then printf ',' >> "$JSON_FILE"; fi
                    bf_first=0
                    printf '\n        "%s": "%s"' "$(json_escape "$br_file")" "$(json_escape "$combined_desc")" >> "$JSON_FILE"
                done <<BRFEOF
$br_files
BRFEOF
                printf '\n      }' >> "$JSON_FILE"
            done <<BREOF
$all_branches
BREOF
            printf '\n    }\n' >> "$JSON_FILE"
        else
            printf '}\n' >> "$JSON_FILE"
        fi

        rm -f "$findings_only"
        printf '  }' >> "$JSON_FILE"
    done

    # Clean repos
    for clean_file in "${results_dir}"/*.clean; do
        [ -f "$clean_file" ] || continue

        local repo_name
        repo_name="$(grep '^repo=' "$clean_file" | head -1)"
        repo_name="${repo_name#repo=}"

        if [ "$first_repo" -eq 0 ]; then
            printf ',\n' >> "$JSON_FILE"
        fi
        first_repo=0

        printf '  {\n' >> "$JSON_FILE"
        printf '    "repository": "%s",\n' "$(json_escape "$repo_name")" >> "$JSON_FILE"
        printf '    "infected": false,\n' >> "$JSON_FILE"
        printf '    "infected_files": {},\n' >> "$JSON_FILE"
        printf '    "infected_branches": {}\n' >> "$JSON_FILE"
        printf '  }' >> "$JSON_FILE"
    done

    printf '\n]\n' >> "$JSON_FILE"

    log_msg "[${owner}] JSON report saved to ${JSON_FILE}"
    printf "  JSON report: ${BOLD}%s${RESET}\n" "$JSON_FILE"
}

# ===================================================================
#  ARGUMENT PARSING
# ===================================================================
while [ $# -gt 0 ]; do
    case "$1" in
        --verbose)
            VERBOSE=1
            shift
            ;;
        --verbose-detail)
            VERBOSE=1
            VERBOSE_DETAIL=1
            shift
            ;;
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
        --https)
            USE_HTTPS=1
            shift
            ;;
        --restart)
            RESTART=1
            shift
            ;;
        --parallel)
            if [ $# -lt 2 ]; then
                printf "Error: --parallel requires a number\n" >&2
                print_usage >&2
                exit 2
            fi
            MAX_PARALLEL="$2"
            shift 2
            ;;
        --clone-delay)
            if [ $# -lt 2 ]; then
                printf "Error: --clone-delay requires a number\n" >&2
                print_usage >&2
                exit 2
            fi
            CLONE_DELAY="$2"
            shift 2
            ;;
        --log-json)
            LOG_JSON=1
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        -*)
            printf "Error: Unknown option '%s'\n" "$1" >&2
            print_usage >&2
            exit 2
            ;;
        *)
            printf "Error: This scanner only supports --github mode\n" >&2
            print_usage >&2
            exit 2
            ;;
    esac
done

if [ -z "$GITHUB_OWNERS" ]; then
    printf "Error: --github <owner> is required\n" >&2
    print_usage >&2
    exit 2
fi

# ===================================================================
#  MAIN EXECUTION
# ===================================================================
print_banner
init_progress_ui
prompt_keep_repos
init_log

if ! command -v gh >/dev/null 2>&1; then
    printf "Error: 'gh' CLI required. Install: https://cli.github.com\n" >&2
    exit 2
fi
if ! gh auth status >/dev/null 2>&1; then
    printf "Error: 'gh' not authenticated. Run: gh auth login\n" >&2
    exit 2
fi

log_msg "GitHub owners: ${GITHUB_OWNERS}"
log_msg "Workers: ${MAX_PARALLEL}, Clone delay: ${CLONE_DELAY}s"

old_ifs="$IFS"
IFS=' '
for owner in $GITHUB_OWNERS; do
    scan_github_owner "$owner"
done
IFS="$old_ifs"

# ===================================================================
#  SUMMARY
# ===================================================================
local_clean=$((TOTAL_REPOS - INFECTED_REPOS))

printf "\n${BOLD}================================================${RESET}\n"
if [ "$INFECTED_REPOS" -gt 0 ]; then
    printf "  ${RED}${BOLD}INFECTED: %d repo(s)${RESET}\n" "$INFECTED_REPOS"
    if [ "$local_clean" -gt 0 ]; then
        printf "  ${GREEN}${BOLD}CLEAN:    %d repo(s)${RESET}\n" "$local_clean"
    fi
    printf "${BOLD}================================================${RESET}\n"
    log_scan_complete
    exit 1
else
    printf "  ${GREEN}${BOLD}ALL CLEAN: %d repo(s) scanned${RESET}\n" "$TOTAL_REPOS"
    printf "${BOLD}================================================${RESET}\n\n"
    log_scan_complete
    exit 0
fi
