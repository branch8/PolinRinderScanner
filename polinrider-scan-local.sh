#!/bin/bash
#
# PolinRider Local Scanner v2.2
# https://opensourcemalware.com
#
# Scans local macOS/Linux machine for PolinRider / TasksJacker malware.
# Detects both obfuscator variants (rmcej%otb% and Cot%3t=shtP),
# malicious npm packages, weaponized .vscode/tasks.json, fake font
# payloads, persistence mechanisms (macOS: LaunchAgents), and active C2 connections.
# For GitHub org scanning use: polinrider-scan-org.sh / polinrider-scan-org-history.sh
#
# Usage:
#   ./polinrider-scan-local.sh                              # Scan current directory (repos only)
#   ./polinrider-scan-local.sh --full-system                # Full macOS/Linux device scan
#   ./polinrider-scan-local.sh --quick                      # Quick scan (processes + signatures)
#   ./polinrider-scan-local.sh --verbose /path/to/projects  # Verbose repo scan
#
# Exit codes:
#   0 - No infections found
#   1 - Infections found
#   2 - Error (invalid path, etc.)
#
# Changelog:
#   v2.2 (2026-05-06)
#     - Spinner animation written to /dev/tty (bypasses logging re-exec pipe,
#       visible even when stdout is piped to the log formatter)
#     - --full-system: each module wrapped with [N/9] label and spinner so
#       the user knows which module is running and that it hasn't stalled
#     - Repo scan: per-repo progress bar printed after each repo completes
#       ([=====>   ] pct%  done:X/Y  infected:N  clean/INFECTED)
#
#   v2.1
#     - Branch8 fork: extended config file list, IDE config dir scanning
#       (.vscode, .cursor, .claude), expanded C2 domain and npm package lists
#     - Auto-cleanup prompt for bat propagation scripts and node_modules
#     - Linux persistence (systemd units) alongside macOS LaunchAgents

set -u

ORIG_ARGS=("$@")

VERSION="2.2"
VERBOSE=0
JS_ALL=0
FULL_SYSTEM=0
QUICK_SCAN=0
SCAN_DIR=""
LOG_FILE=""
SCAN_START_TIME=""
SKIP_GIT_GREP=0

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
# Expanded config files targeted by PolinRider (Apr 2026 corpus)
# ---------------------------------------------------------------------------
CONFIG_FILES="postcss.config.mjs postcss.config.js postcss.config.cjs tailwind.config.js tailwind.config.mjs eslint.config.mjs next.config.mjs next.config.js next.config.ts babel.config.js jest.config.js vite.config.js vite.config.mjs webpack.config.js gridsome.config.js vue.config.js truffle.js astro.config.mjs App.js app.js index.js"

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
SHOEVISTA_NAMES="ShoeVista shoevista shoe-vista Test-west-shoe"

# XOR keys used in payload decryption
XOR_KEY_1='2[gWfGj;<:-93Z^C'
XOR_KEY_2='m6:tTh^D)cBz?NM]'

# IDE/agent config directories to scan inside each repo
IDE_CONFIG_DIRS=".vscode .cursor .claude"

# ---------------------------------------------------------------------------
# Colors (disabled if not a terminal)
# ---------------------------------------------------------------------------
RED="" GREEN="" YELLOW="" CYAN="" MAGENTA="" BOLD="" RESET=""
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    RESET='\033[0m'
fi

# Enable spinner when /dev/tty is writable (works even through the logging re-exec pipe)
{ [ -w /dev/tty ] && PROGRESS_UI=1; } 2>/dev/null || true

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
TOTAL_REPOS=0
INFECTED_REPOS=0
INFECTED_REPO_PATHS=""
SYSTEM_FINDINGS=0
SYSTEM_FINDINGS_DETAIL=""

# Progress UI
PROGRESS_UI=0
SPINNER_PID=0
REPO_DONE=0

# Auto-cleanup tracking (populated during local repo scan only)
CLEANUP_BAT_FILES=()
CLEANUP_GITIGNORE_REPOS=()
CLEANUP_NODE_MODULES=()

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------
print_banner() {
    printf "\n"
    printf "${BOLD}================================================${RESET}\n"
    printf "${BOLD}  PolinRider Local Scanner v%s (macOS/Linux)${RESET}\n" "$VERSION"
    printf "${BOLD}  https://opensourcemalware.com${RESET}\n"
    printf "${BOLD}  Detects variants: rmcej%%otb%% + Cot%%3t=shtP${RESET}\n"
    printf "${BOLD}================================================${RESET}\n"
    printf "\n"
}

print_usage() {
    printf "Usage: %s [OPTIONS] [directory]\n" "$0"
    printf "\n"
    printf "Scans local machine for PolinRider / TasksJacker malware (macOS/Linux).\n"
    printf "For GitHub org scanning use: polinrider-scan-org.sh\n"
    printf "\n"
    printf "Options:\n"
    printf "  --full-system  Full local scan (processes, persistence, repos, browser, npm)\n"
    printf "  --quick        Quick scan (running processes + network only)\n"
    printf "  --verbose      Show detailed output for each check\n"
    printf "  --js-all       Scan all .js/.mjs/.cjs files (not just known configs)\n"
    printf "  --help         Show this help message\n"
    printf "\n"
    printf "Examples:\n"
    printf "  %s                              # Scan current directory repos\n" "$0"
    printf "  %s --full-system                # Full macOS/Linux device scan\n" "$0"
    printf "  %s --full-system --verbose      # Full scan with details\n" "$0"
    printf "  %s --quick                      # Quick process/network check\n" "$0"
    printf "  %s /path/to/projects            # Scan specific directory repos\n" "$0"
    printf "  %s --js-all ~/projects          # Deep scan all JS files\n" "$0"
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
}

init_log() {
    local mode_parts=""
    if [ "$FULL_SYSTEM" -eq 1 ]; then
        mode_parts="full-system"
    fi
    if [ "$QUICK_SCAN" -eq 1 ]; then
        mode_parts="${mode_parts:+${mode_parts}-}quick"
    fi
    if [ -z "$mode_parts" ]; then
        mode_parts="repo"
    fi

    SCAN_START_TIME="$(date '+%s')"

    local timestamp
    timestamp="$(date '+%Y-%m-%d_%H-%M-%S')"
    mkdir -p scan-logs/local
    LOG_FILE="scan-logs/local/scan-${mode_parts}-${timestamp}.log"
    : > "$LOG_FILE"

    if [ "${_POLINRIDER_LOGGING:-0}" = "1" ]; then
        log_msg "PolinRider Scanner v${VERSION} started"
    fi
}

cleanup() {
    local exit_code=$?
    _spinner_stop 2>/dev/null
    wait 2>/dev/null
    exit $exit_code
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Spinner helpers — write to /dev/tty so they bypass the logging re-exec pipe
# ---------------------------------------------------------------------------
_spinner_start() {
    [ "$PROGRESS_UI" -eq 1 ] || return 0
    local msg="$1"
    ( local _sp='|/-\'
      local _i=0
      while true; do
          printf "\r  %s  %s   " "${_sp:$((_i % 4)):1}" "$msg" >/dev/tty 2>/dev/null
          _i=$((_i + 1))
          sleep 0.3 2>/dev/null || sleep 1
      done ) &
    SPINNER_PID=$!
}

_spinner_stop() {
    if [ "${SPINNER_PID:-0}" -ne 0 ]; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null || true
        printf "\r\033[2K" >/dev/tty 2>/dev/null
        SPINNER_PID=0
    fi
}

log_scan_complete() {
    local end_time
    end_time="$(date '+%s')"
    local duration=$((end_time - SCAN_START_TIME))
    local mins=$((duration / 60))
    local secs=$((duration % 60))
    log_msg "Scan complete. Duration: ${mins}m${secs}s"
    log_msg "Total repos: ${TOTAL_REPOS}, Infected: ${INFECTED_REPOS}, System findings: ${SYSTEM_FINDINGS}"
}

add_system_finding() {
    local category="$1"
    local detail="$2"
    SYSTEM_FINDINGS=$((SYSTEM_FINDINGS + 1))
    SYSTEM_FINDINGS_DETAIL="${SYSTEM_FINDINGS_DETAIL}  ${RED}-${RESET} ${BOLD}[${category}]${RESET} ${detail}\n"
}

print_section() {
    printf "\n${MAGENTA}${BOLD}[%s]${RESET} %s\n" "$1" "$2"
}

# Portable timeout: uses `timeout` if available, falls back to background+kill
run_with_timeout() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@" 2>/dev/null || true
    else
        "$@" 2>/dev/null &
        local pid=$!
        local waited=0
        while kill -0 "$pid" 2>/dev/null; do
            sleep 1
            waited=$((waited + 1))
            if [ "$waited" -ge "$secs" ]; then
                kill "$pid" 2>/dev/null
                wait "$pid" 2>/dev/null
                return
            fi
        done
        wait "$pid" 2>/dev/null
    fi
}

# ---------------------------------------------------------------------------
# check_file_for_signatures — scans a single file for both variants
# Returns 0 if clean, 1 if infected. Appends to $findings variable in caller.
# ---------------------------------------------------------------------------
check_file_for_signatures() {
    local filepath="$1"
    local label="$2"
    local found=0

    # Variant 1 checks — each indicator reported independently
    if grep -qF "$V1_MARKER" "$filepath" 2>/dev/null; then
        findings="${findings}  ${RED}-${RESET} ${BOLD}${label}${RESET}: Variant 1 payload (rmcej%%otb%%) detected\n"
        found=$((found + 1))
    fi
    if grep -qF "$V1_DECODER" "$filepath" 2>/dev/null; then
        findings="${findings}  ${RED}-${RESET} ${BOLD}${label}${RESET}: Variant 1 decoder (_\$_1e42) detected\n"
        found=$((found + 1))
    fi
    if grep -qF "$V1_GLOBAL" "$filepath" 2>/dev/null; then
        if grep -qF "$V1_SEED" "$filepath" 2>/dev/null || grep -qF "$V1_SEED2" "$filepath" 2>/dev/null; then
            findings="${findings}  ${RED}-${RESET} ${BOLD}${label}${RESET}: Variant 1 markers (global['!'] + seed) detected\n"
            found=$((found + 1))
        else
            findings="${findings}  ${RED}-${RESET} ${BOLD}${label}${RESET}: PolinRider global['!'] assignment (variant 1 marker)\n"
            found=$((found + 1))
        fi
    fi

    # Variant 2 checks — each indicator reported independently
    if grep -qF "$V2_MARKER" "$filepath" 2>/dev/null; then
        findings="${findings}  ${RED}-${RESET} ${BOLD}${label}${RESET}: Variant 2 payload (Cot%%3t=shtP) detected\n"
        found=$((found + 1))
    fi
    if grep -qF "$V2_GLOBAL" "$filepath" 2>/dev/null; then
        if grep -qF "$V2_SEED" "$filepath" 2>/dev/null || grep -qF "$V2_SEED2" "$filepath" 2>/dev/null || grep -qF "$V2_DECODER" "$filepath" 2>/dev/null; then
            findings="${findings}  ${RED}-${RESET} ${BOLD}${label}${RESET}: Variant 2 markers (global['_V'] + seed/decoder) detected\n"
            found=$((found + 1))
        else
            findings="${findings}  ${RED}-${RESET} ${BOLD}${label}${RESET}: PolinRider global['_V'] assignment (variant 2 marker)\n"
            found=$((found + 1))
        fi
    fi

    # Common cross-variant markers
    if grep -qF "$COMMON_GLOBAL_R" "$filepath" 2>/dev/null && grep -qF "$COMMON_GLOBAL_M" "$filepath" 2>/dev/null; then
        if grep -qF "$V1_SEED" "$filepath" 2>/dev/null || grep -qF "$V1_SEED2" "$filepath" 2>/dev/null || \
           grep -qF "$V2_SEED" "$filepath" 2>/dev/null || grep -qF "$V2_SEED2" "$filepath" 2>/dev/null; then
            findings="${findings}  ${YELLOW}-${RESET} ${BOLD}${label}${RESET}: Suspicious global['r']/global['m'] with known seed\n"
            found=$((found + 1))
        fi
    fi

    # eval() combined with global markers (partially cleaned infection)
    if grep -qE 'eval\(' "$filepath" 2>/dev/null; then
        if grep -qF "$COMMON_GLOBAL_R" "$filepath" 2>/dev/null || \
           grep -qF "$V1_GLOBAL" "$filepath" 2>/dev/null || \
           grep -qF "$V2_GLOBAL" "$filepath" 2>/dev/null; then
            findings="${findings}  ${YELLOW}-${RESET} ${BOLD}${label}${RESET}: eval() with PolinRider global markers — possible partially cleaned infection\n"
            found=$((found + 1))
        fi
    fi

    return $found
}

# ---------------------------------------------------------------------------
# scan_repo — scans a single git repository (enhanced)
# ---------------------------------------------------------------------------
scan_repo() {
    local repo_dir="$1"
    local findings=""
    local branch_findings=""
    local finding_count=0
    local branch_finding_count=0

    log_verbose "Scanning repo: $repo_dir"

    # --- Config files for payload signatures (both variants) ---
    local old_ifs="$IFS"
    IFS=' '
    for config_file in $CONFIG_FILES; do
        # Check root and common nested paths
        local search_paths="${repo_dir}/${config_file}"
        for nested in client server frontend backend web apps src packages/ui packages/dashboard; do
            if [ -d "${repo_dir}/${nested}" ]; then
                search_paths="${search_paths} ${repo_dir}/${nested}/${config_file}"
            fi
        done
        # Scan all packages/* subdirs for monorepo layouts
        if [ -d "${repo_dir}/packages" ]; then
            while IFS= read -r pkg_subdir; do
                if [ -d "$pkg_subdir" ] && [ -f "${pkg_subdir}/${config_file}" ]; then
                    search_paths="${search_paths} ${pkg_subdir}/${config_file}"
                fi
            done <<PKGDIREOF
$(find "${repo_dir}/packages" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
PKGDIREOF
        fi

        for filepath in $search_paths; do
            if [ -f "$filepath" ]; then
                local relpath="${filepath#${repo_dir}/}"
                log_verbose "Checking $relpath"
                check_file_for_signatures "$filepath" "$relpath"
                local ret=$?
                if [ "$ret" -gt 0 ]; then
                    finding_count=$((finding_count + ret))
                fi
            fi
        done
    done
    IFS="$old_ifs"

    # --- Scan for .woff2 fake font payloads ---
    # Binary font files need stricter matching to avoid false positives.
    # Short strings like "MDy" (3 chars) appear randomly in binary data,
    # so we require a high-confidence marker (the full obfuscator signature
    # or the multi-token global['r']/global['m'] pair) rather than a
    # single short decoder name.
    while IFS= read -r woff_file; do
        if [ -f "$woff_file" ]; then
            local relpath="${woff_file#${repo_dir}/}"
            local woff_hit=0

            if grep -qF "$V1_MARKER" "$woff_file" 2>/dev/null; then
                findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: Fake font file with variant 1 payload (rmcej%%otb%%)\n"
                woff_hit=1
            fi
            if grep -qF "$V2_MARKER" "$woff_file" 2>/dev/null; then
                findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: Fake font file with variant 2 payload (Cot%%3t=shtP)\n"
                woff_hit=1
            fi
            # For short decoder names, require a second corroborating marker
            if [ "$woff_hit" -eq 0 ]; then
                if grep -qF "$V1_DECODER" "$woff_file" 2>/dev/null && \
                   grep -qF "$V1_GLOBAL" "$woff_file" 2>/dev/null; then
                    findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: Fake font file with variant 1 markers\n"
                    woff_hit=1
                fi
                if grep -qF "$COMMON_GLOBAL_R" "$woff_file" 2>/dev/null && \
                   grep -qF "$COMMON_GLOBAL_M" "$woff_file" 2>/dev/null; then
                    findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: Fake font file with PolinRider global markers\n"
                    woff_hit=1
                fi
            fi

            if [ "$woff_hit" -gt 0 ]; then
                finding_count=$((finding_count + 1))
            fi
        fi
    done <<WOFFEOF
$(find "$repo_dir" \( -name "*.woff2" -o -name "*.woff" \) -type f -not -path "*/.git/*" 2>/dev/null)
WOFFEOF

    # --- Deep JS scan (--js-all) ---
    if [ "$JS_ALL" -eq 1 ]; then
        while IFS= read -r jsfile; do
            if [ -f "$jsfile" ]; then
                local relpath="${jsfile#${repo_dir}/}"
                case "$relpath" in
                    node_modules/*|.git/*) continue ;;
                esac
                log_verbose "Checking $relpath"
                check_file_for_signatures "$jsfile" "$relpath"
                local ret=$?
                if [ "$ret" -gt 0 ]; then
                    finding_count=$((finding_count + ret))
                fi
            fi
        done <<JSEOF
$(find "$repo_dir" \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" \) -type f -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)
JSEOF
    fi

    # --- Propagation scripts (existence + content verification) ---
    if [ -f "${repo_dir}/temp_auto_push.bat" ]; then
        if grep -qF "LAST_COMMIT_DATE" "${repo_dir}/temp_auto_push.bat" 2>/dev/null || \
           grep -qF "--no-verify" "${repo_dir}/temp_auto_push.bat" 2>/dev/null || \
           grep -qF "git push -uf" "${repo_dir}/temp_auto_push.bat" 2>/dev/null; then
            findings="${findings}  ${RED}-${RESET} ${BOLD}temp_auto_push.bat${RESET}: PolinRider propagation script (confirmed by content)\n"
            CLEANUP_BAT_FILES+=("${repo_dir}/temp_auto_push.bat")
        else
            findings="${findings}  ${YELLOW}-${RESET} ${BOLD}temp_auto_push.bat${RESET}: Propagation script found (verify manually)\n"
        fi
        finding_count=$((finding_count + 1))
    fi
    if [ -f "${repo_dir}/config.bat" ]; then
        if grep -qF "LAST_COMMIT_DATE" "${repo_dir}/config.bat" 2>/dev/null || \
           grep -qF "--no-verify" "${repo_dir}/config.bat" 2>/dev/null || \
           grep -qF "git push -uf" "${repo_dir}/config.bat" 2>/dev/null || \
           grep -qF "temp_auto_push" "${repo_dir}/config.bat" 2>/dev/null; then
            findings="${findings}  ${RED}-${RESET} ${BOLD}config.bat${RESET}: PolinRider hidden orchestrator (confirmed by content)\n"
            CLEANUP_BAT_FILES+=("${repo_dir}/config.bat")
        else
            findings="${findings}  ${YELLOW}-${RESET} ${BOLD}config.bat${RESET}: Hidden orchestrator found (verify manually)\n"
        fi
        finding_count=$((finding_count + 1))
    fi

    # --- .gitignore injection ---
    if [ -f "${repo_dir}/.gitignore" ]; then
        local gi_hit=0
        if grep -qxF "config.bat" "${repo_dir}/.gitignore" 2>/dev/null; then
            findings="${findings}  ${RED}-${RESET} ${BOLD}.gitignore${RESET}: config.bat entry injected\n"
            finding_count=$((finding_count + 1))
            gi_hit=1
        fi
        if grep -qxF "temp_auto_push.bat" "${repo_dir}/.gitignore" 2>/dev/null; then
            findings="${findings}  ${RED}-${RESET} ${BOLD}.gitignore${RESET}: temp_auto_push.bat entry injected\n"
            finding_count=$((finding_count + 1))
            gi_hit=1
        fi
        if [ "$gi_hit" -eq 1 ]; then
            CLEANUP_GITIGNORE_REPOS+=("$repo_dir")
        fi
    fi

    # --- child_process.spawn persistence pattern in config files ---
    local old_ifs_cp="$IFS"
    IFS=' '
    for config_file in $CONFIG_FILES; do
        local filepath="${repo_dir}/${config_file}"
        if [ -f "$filepath" ]; then
            if grep -qF "child_process" "$filepath" 2>/dev/null; then
                if grep -qF "detached" "$filepath" 2>/dev/null || \
                   grep -qF "windowsHide" "$filepath" 2>/dev/null; then
                    local relpath="${filepath#${repo_dir}/}"
                    findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: child_process.spawn with detached/hidden execution\n"
                    finding_count=$((finding_count + 1))
                fi
            fi
        fi
    done
    IFS="$old_ifs_cp"

    # --- IDE/agent config directories (.vscode, .cursor, .claude) ---
    for ide_dir_name in $IDE_CONFIG_DIRS; do
        local ide_dir="${repo_dir}/${ide_dir_name}"
        if [ ! -d "$ide_dir" ]; then continue; fi

        # Scan all files in the IDE config directory
        while IFS= read -r ide_file; do
            if [ ! -f "$ide_file" ]; then continue; fi
            local relpath="${ide_file#${repo_dir}/}"
            local ide_hit=0

            # Payload signature checks (all dirs)
            check_file_for_signatures "$ide_file" "$relpath"
            local ret=$?
            if [ "$ret" -gt 0 ]; then
                finding_count=$((finding_count + ret))
            fi

            # StakingGame UUID
            if grep -qF "$STAKING_UUID" "$ide_file" 2>/dev/null; then
                findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: StakingGame weaponized template UUID found\n"
                ide_hit=1
            fi

            # C2 domains
            old_ifs="$IFS"
            IFS=' '
            for domain in $C2_DOMAINS; do
                if grep -qF "$domain" "$ide_file" 2>/dev/null; then
                    findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: C2 domain reference (${domain})\n"
                    ide_hit=1
                fi
            done
            IFS="$old_ifs"

            # Blockchain C2 addresses
            for addr in "$TRON_ADDR_1" "$TRON_ADDR_2" "$APTOS_HASH_1" "$APTOS_HASH_2"; do
                if grep -qF "$addr" "$ide_file" 2>/dev/null; then
                    findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: Blockchain C2 address reference (${addr})\n"
                    ide_hit=1
                fi
            done

            # curl|bash / wget|sh auto-execution (tasks.json, settings.json, etc.)
            if grep -qE '(curl|wget).*\|.*(bash|sh)' "$ide_file" 2>/dev/null; then
                if grep -qF "folderOpen" "$ide_file" 2>/dev/null; then
                    findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: curl|bash with runOn:folderOpen auto-execution\n"
                    ide_hit=1
                else
                    findings="${findings}  ${YELLOW}-${RESET} ${BOLD}${relpath}${RESET}: curl|bash command in IDE config — verify manually\n"
                    ide_hit=1
                fi
            fi

            # node -e with obfuscated payloads in IDE config
            if grep -qE 'node\s+-e' "$ide_file" 2>/dev/null; then
                if grep -qF "global[" "$ide_file" 2>/dev/null || \
                   grep -qF "child_process" "$ide_file" 2>/dev/null || \
                   grep -qF "eval(" "$ide_file" 2>/dev/null; then
                    findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: node -e with suspicious payload in IDE config\n"
                    ide_hit=1
                fi
            fi

            # Prompt injection checks (.claude and .cursor only)
            if [ "$ide_dir_name" = ".claude" ] || [ "$ide_dir_name" = ".cursor" ]; then
                # settings.local.json is Claude Code's own machine-local config — skip heuristics
                local _skip_heuristics=0
                [ "$relpath" = ".claude/settings.local.json" ] && _skip_heuristics=1

                if [ "$_skip_heuristics" -eq 0 ]; then
                    # Shell command injection via prompt instructions
                    if grep -qiE '(run|execute|shell|bash|system)\s*\(' "$ide_file" 2>/dev/null || \
                       grep -qiE '(subprocess|os\.system|child_process|execSync)' "$ide_file" 2>/dev/null; then
                        findings="${findings}  ${YELLOW}-${RESET} ${BOLD}${relpath}${RESET}: Shell/command execution reference in agent config — verify manually\n"
                        ide_hit=1
                    fi
                    # External URL — skip for .cursor/rules|commands|skills (legitimately contain Jira/Teams URLs)
                    local _skip_url=0
                    case "$relpath" in .cursor/rules/*|.cursor/commands/*|.cursor/skills/*) _skip_url=1 ;; esac
                    if [ "$_skip_url" -eq 0 ]; then
                        if grep -qiE '(curl|wget|fetch|http|https)://' "$ide_file" 2>/dev/null; then
                            findings="${findings}  ${YELLOW}-${RESET} ${BOLD}${relpath}${RESET}: External URL in agent config — potential exfiltration vector\n"
                            ide_hit=1
                        fi
                    fi
                    # Base64-encoded payloads hidden in agent config
                    if grep -qE '[A-Za-z0-9+/]{60,}={0,2}' "$ide_file" 2>/dev/null; then
                        findings="${findings}  ${YELLOW}-${RESET} ${BOLD}${relpath}${RESET}: Long base64 string in agent config — verify manually\n"
                        ide_hit=1
                    fi
                    # Instruction override / role hijacking
                    if grep -qiE '(ignore previous|ignore above|disregard|forget all|new instructions|you are now|act as|pretend)' "$ide_file" 2>/dev/null; then
                        findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: Prompt injection pattern (instruction override) detected\n"
                        ide_hit=1
                    fi
                    # Hidden unicode / zero-width characters used to hide malicious instructions
                    if grep -qP '[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}]' "$ide_file" 2>/dev/null; then
                        findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: Hidden zero-width unicode characters — possible concealed instructions\n"
                        ide_hit=1
                    fi
                    # SSH/credential/token/secret references
                    if grep -qiE '(ssh_key|private_key|api_key|secret|token|password|credential)' "$ide_file" 2>/dev/null; then
                        if grep -qiE '(read|cat|send|upload|post|exfil|steal|extract)' "$ide_file" 2>/dev/null; then
                            findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: Credential access + exfiltration pattern in agent config\n"
                            ide_hit=1
                        fi
                    fi
                fi
            fi

            if [ "$ide_hit" -gt 0 ]; then
                finding_count=$((finding_count + 1))
            fi
        done <<IDEEOF
$(find "$ide_dir" -type f -maxdepth 3 2>/dev/null | head -200)
IDEEOF
    done

    # --- ShoeVista weaponized template detection ---
    # Only flag if the malicious npm dep is present alongside the template name
    if [ -f "${repo_dir}/client/package.json" ]; then
        if grep -qF "tailwindcss-style-animate" "${repo_dir}/client/package.json" 2>/dev/null; then
            findings="${findings}  ${RED}-${RESET} ${BOLD}client/package.json${RESET}: ShoeVista weaponized template (tailwindcss-style-animate dependency)\n"
            finding_count=$((finding_count + 1))
        fi
    fi
    # Also check if repo name/package name matches known ShoeVista variants
    if [ -f "${repo_dir}/package.json" ]; then
        old_ifs="$IFS"
        IFS=' '
        for sv_name in $SHOEVISTA_NAMES; do
            if grep -qF "\"name\"" "${repo_dir}/package.json" 2>/dev/null && \
               grep -qF "$sv_name" "${repo_dir}/package.json" 2>/dev/null; then
                if grep -qF "tailwindcss-style-animate" "${repo_dir}/package.json" 2>/dev/null || \
                   [ -d "${repo_dir}/client" ] && [ -d "${repo_dir}/server" ]; then
                    findings="${findings}  ${YELLOW}-${RESET} ${BOLD}package.json${RESET}: Possible ShoeVista weaponized template (name '${sv_name}' + client/server structure)\n"
                    finding_count=$((finding_count + 1))
                fi
            fi
        done
        IFS="$old_ifs"
    fi

    # --- Malicious npm packages in package.json ---
    while IFS= read -r pkg_file; do
        if [ -f "$pkg_file" ]; then
            local relpath="${pkg_file#${repo_dir}/}"

            # Check known malicious package names
            old_ifs="$IFS"
            IFS=' '
            for mal_pkg in $MALICIOUS_NPM_PKGS; do
                if grep -qF "\"${mal_pkg}\"" "$pkg_file" 2>/dev/null; then
                    findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: Malicious npm dependency '${mal_pkg}'\n"
                    finding_count=$((finding_count + 1))
                fi
            done
            IFS="$old_ifs"

            # Flag any non-official package whose name contains "tailwind"
            local tw_deps
            tw_deps=$(grep -ioE '"[a-z0-9@_./-]*tailwind[a-z0-9_./-]*"' "$pkg_file" 2>/dev/null | tr -d '"' | sort -u) || true
            if [ -n "$tw_deps" ]; then
                while IFS= read -r tw_dep; do
                    if [ -n "$tw_dep" ]; then
                        case "$tw_dep" in
                            tailwindcss|@tailwindcss/*|tailwindcss-animate|tailwind-merge|tailwind-variants|\
prettier-plugin-tailwindcss|tailwindcss-radix|tailwindcss-debug-screens|\
@headlessui/tailwindcss|storybook-addon-tailwindcss|tailwindcss-textshadow|\
tailwindcss-3d|tailwindcss-animated|tailwindcss-gradients|tailwindcss-scrollbar|\
tailwindcss-question-mark|tailwindcss-opentype|tailwindcss-hyphens|\
tailwindcss-writing-mode|tailwindcss-border-gradient|tailwindcss-dir|\
@savvywombat/tailwindcss-grid-areas|tailwindcss-fluid-type|\
tailwindcss-children|tailwindcss-multi|tailwindcss-primeui|\
tailwindcss-react-aria-components|tw-animate-css) ;;
                            *) findings="${findings}  ${YELLOW}-${RESET} ${BOLD}${relpath}${RESET}: Suspicious tailwind package '${tw_dep}' — verify manually\n"
                               finding_count=$((finding_count + 1)) ;;
                        esac
                    fi
                done <<< "$tw_deps"
            fi
        fi
    done <<PKGEOF
$(find "$repo_dir" -name "package.json" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -maxdepth 4 2>/dev/null)
PKGEOF

    # --- node_modules installed package scan ---
    # Finds malicious packages actually installed on disk — catches transitive deps,
    # packages removed from package.json but still present, and monorepo layouts.
    # Bare clones are naturally skipped (no node_modules directory exists).
    local old_ifs="$IFS"
    IFS=' '
    for mal_pkg in $MALICIOUS_NPM_PKGS; do
        while IFS= read -r nm_pkg_json; do
            if [ -n "$nm_pkg_json" ] && [ -f "$nm_pkg_json" ]; then
                local nm_dir
                nm_dir="$(dirname "$nm_pkg_json")"
                local relpath="${nm_pkg_json#${repo_dir}/}"
                local payload_confirmed=""
                if grep -rqF "$V1_MARKER" "$nm_dir" --include="*.js" 2>/dev/null; then
                    payload_confirmed=" (payload confirmed — V1)"
                elif grep -rqF "$V2_MARKER" "$nm_dir" --include="*.js" 2>/dev/null; then
                    payload_confirmed=" (payload confirmed — V2)"
                fi
                findings="${findings}  ${RED}-${RESET} ${BOLD}${relpath}${RESET}: Malicious package installed: ${mal_pkg}${payload_confirmed}\n"
                finding_count=$((finding_count + 1))
                local nm_parent
                nm_parent="$(dirname "$nm_dir")"
                local nm_already=0
                for _existing_nm in "${CLEANUP_NODE_MODULES[@]}"; do
                    [ "$_existing_nm" = "$nm_parent" ] && nm_already=1 && break
                done
                [ "$nm_already" -eq 0 ] && CLEANUP_NODE_MODULES+=("$nm_parent")
            fi
        done <<NMEOF
$(find "$repo_dir" -path "*/node_modules/${mal_pkg}/package.json" -not -path "*/.git/*" -maxdepth 6 2>/dev/null)
NMEOF
    done
    IFS="$old_ifs"

    # --- git grep across all branches for signatures ---
    # For each signature, run git grep -lF against all branches.
    # Each hit already knows which signature matched — no second-pass needed.
    if [ -d "${repo_dir}/.git" ] && [ "$SKIP_GIT_GREP" -eq 0 ]; then
        local ref_count=0
        local all_refs_inline=""
        while IFS= read -r ref_line; do
            if [ -n "$ref_line" ]; then
                all_refs_inline="${all_refs_inline} ${ref_line}"
                ref_count=$((ref_count + 1))
            fi
        done <<REFSEOF
$(git -C "$repo_dir" branch -a --format='%(refname)' 2>/dev/null)
REFSEOF

        if [ "$ref_count" -gt 0 ]; then
            log_verbose "Running git grep across ${ref_count} branch(es)"

            local wt_findings="$findings"
            local gg_seen=""

            local gg_sig_name=""
            local gg_sig_val=""
            for gg_sig_name in \
                "variant 1 (rmcej%%otb%%)|$V1_MARKER" \
                "variant 2 (Cot%%3t=shtP)|$V2_MARKER" \
                "variant 1 global marker|$V1_GLOBAL" \
                "variant 2 global marker|$V2_GLOBAL" \
                "global['r'] marker|$COMMON_GLOBAL_R"; do

                local sig_label="${gg_sig_name%%|*}"
                gg_sig_val="${gg_sig_name#*|}"

                local gg_results=""
                local gg_out_file
                gg_out_file=$(mktemp) || true

                # shellcheck disable=SC2086
                git -C "$repo_dir" grep -lF "$gg_sig_val" $all_refs_inline -- \
                    ':(glob)**/*.config.mjs' ':(glob)**/*.config.js' ':(glob)**/*.config.cjs' ':(glob)**/*.config.ts' \
                    ':(glob)**/App.js' ':(glob)**/app.js' ':(glob)**/index.js' \
                    ':(glob)**/babel.config.js' ':(glob)**/jest.config.js' ':(glob)**/truffle.js' \
                    ':(glob)**/*.woff' ':(glob)**/*.woff2' \
                    ':(glob)**/temp_auto_push.bat' ':(glob)**/config.bat' \
                    ':(glob)**/.vscode/*' ':(glob)**/.cursor/*' ':(glob)**/.claude/*' \
                    ':(glob)**/package.json' \
                    > "$gg_out_file" 2>/dev/null &
                local gg_pid=$!
                local gg_waited=0
                while kill -0 "$gg_pid" 2>/dev/null; do
                    sleep 1
                    gg_waited=$((gg_waited + 1))
                    if [ "$gg_waited" -ge 15 ]; then
                        kill "$gg_pid" 2>/dev/null
                        wait "$gg_pid" 2>/dev/null
                        break
                    fi
                done
                wait "$gg_pid" 2>/dev/null

                if [ -f "$gg_out_file" ]; then
                    gg_results=$(cat "$gg_out_file") || true
                    rm -f "$gg_out_file"
                fi

                if [ -z "$gg_results" ]; then continue; fi

                while IFS= read -r gg_hit; do
                    if [ -z "$gg_hit" ]; then continue; fi

                    local gg_ref="${gg_hit%%:*}"
                    local gg_file="${gg_hit#*:}"
                    if [ "$gg_ref" = "$gg_hit" ] || [ -z "$gg_file" ]; then continue; fi

                    local gg_branch="${gg_ref#refs/heads/}"
                    gg_branch="${gg_branch#refs/remotes/}"
                    local gg_key="${gg_branch}:${gg_file}"

                    # Dedup: skip if already seen this branch:file from a prior signature
                    case "$gg_seen" in
                        *"|${gg_key}|"*) continue ;;
                    esac
                    gg_seen="${gg_seen}|${gg_key}|"

                    branch_findings="${branch_findings}  ${RED}-${RESET} ${BOLD}[git:${gg_branch}] ${gg_file}${RESET}: ${sig_label}\n"
                    branch_finding_count=$((branch_finding_count + 1))
                done <<< "$gg_results"
            done
        fi


    fi

    # --- Report ---
    local total_findings=$((finding_count + branch_finding_count))
    if [ "$total_findings" -gt 0 ]; then
        printf "\n${RED}${BOLD}[INFECTED]${RESET} %s\n" "$repo_dir"

        if [ "$finding_count" -gt 0 ]; then
            printf "\n  ${CYAN}${BOLD}Working Tree (%d finding(s)):${RESET}\n" "$finding_count"
            printf "$findings"
        fi

        if [ "$branch_finding_count" -gt 0 ]; then
            printf "\n  ${MAGENTA}${BOLD}Branch History (%d branch(es) infected):${RESET}\n" "$branch_finding_count"
            printf "$branch_findings"
        fi

        INFECTED_REPOS=$((INFECTED_REPOS + 1))
        INFECTED_REPO_PATHS="${INFECTED_REPO_PATHS}${repo_dir}\n"
        return 1
    else
        log_verbose "Clean: $repo_dir"
        return 0
    fi
}


# ===================================================================
#  FULL-SYSTEM SCAN FUNCTIONS (macOS/Linux)
# ===================================================================

# ---------------------------------------------------------------------------
# 1. Running processes
# ---------------------------------------------------------------------------
scan_processes() {
    print_section "PROCESSES" "Scanning running processes for suspicious activity..."

    # Detect node -e with obfuscated payloads
    local node_procs
    node_procs=$(ps aux 2>/dev/null | grep -E 'node\s+-e' | grep -v grep) || true
    if [ -n "$node_procs" ]; then
        while IFS= read -r proc_line; do
            if echo "$proc_line" | grep -qF "global[" 2>/dev/null || \
               echo "$proc_line" | grep -qF "$V1_MARKER" 2>/dev/null || \
               echo "$proc_line" | grep -qF "$V2_MARKER" 2>/dev/null || \
               echo "$proc_line" | grep -qF "$V1_DECODER" 2>/dev/null || \
               echo "$proc_line" | grep -qF "$V2_GLOBAL" 2>/dev/null || \
               echo "$proc_line" | grep -qE "eval\(|spawn\(|child_process" 2>/dev/null; then
                local pid
                pid=$(echo "$proc_line" | awk '{print $2}')
                add_system_finding "PROCESS" "Suspicious node -e process (PID ${pid}): likely PolinRider payload running"
            fi
        done <<< "$node_procs"
    fi
    log_verbose "Checked node -e processes"

    # Detect any process referencing C2 domains or blockchain endpoints
    local all_procs
    all_procs=$(ps aux 2>/dev/null) || true
    local old_ifs="$IFS"
    IFS=' '
    for domain in $C2_DOMAINS $BLOCKCHAIN_HOSTS; do
        if echo "$all_procs" | grep -qF "$domain" 2>/dev/null; then
            add_system_finding "PROCESS" "Process referencing C2/blockchain endpoint: ${domain}"
        fi
    done
    IFS="$old_ifs"

    for addr in "$TRON_ADDR_1" "$TRON_ADDR_2" "$APTOS_HASH_1" "$APTOS_HASH_2"; do
        if echo "$all_procs" | grep -qF "$addr" 2>/dev/null; then
            add_system_finding "PROCESS" "Process referencing blockchain C2 address: ${addr}"
        fi
    done

    log_verbose "Checked process list for C2 references"
}

# ---------------------------------------------------------------------------
# 2. Network connections
# ---------------------------------------------------------------------------
scan_network() {
    print_section "NETWORK" "Checking active network connections to known C2 infrastructure..."

    local net_output=""
    if command -v lsof >/dev/null 2>&1; then
        net_output=$(lsof -i -nP 2>/dev/null) || true
    fi

    if [ -n "$net_output" ]; then
        local old_ifs="$IFS"
        IFS=' '
        for domain in $C2_DOMAINS; do
            # Resolve to check against IP is impractical; check process names referencing these
            if echo "$net_output" | grep -qiF "$domain" 2>/dev/null; then
                add_system_finding "NETWORK" "Active connection to C2 domain: ${domain}"
            fi
        done
        for bhost in $BLOCKCHAIN_HOSTS; do
            if echo "$net_output" | grep -qiF "$bhost" 2>/dev/null; then
                add_system_finding "NETWORK" "Active connection to blockchain C2: ${bhost}"
            fi
        done
        IFS="$old_ifs"
    fi

    # Check DNS cache / recent resolutions via log (best-effort)
    if command -v log >/dev/null 2>&1; then
        local dns_check
        dns_check=$(log show --predicate 'process == "mDNSResponder"' --style syslog --last 1h 2>/dev/null | head -500) || true
        if [ -n "$dns_check" ]; then
            local old_ifs2="$IFS"
            IFS=' '
            for domain in $C2_DOMAINS $BLOCKCHAIN_HOSTS; do
                if echo "$dns_check" | grep -qF "$domain" 2>/dev/null; then
                    add_system_finding "NETWORK" "Recent DNS resolution for C2/blockchain endpoint: ${domain}"
                fi
            done
            IFS="$old_ifs2"
        fi
    fi

    log_verbose "Network connection scan complete"
}

# ---------------------------------------------------------------------------
# 3. LaunchAgents / LaunchDaemons (persistence)
# ---------------------------------------------------------------------------
scan_persistence_plists() {
    print_section "PERSISTENCE" "Scanning LaunchAgents and LaunchDaemons..."

    local plist_dirs="$HOME/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons"

    local old_ifs="$IFS"
    IFS=' '
    for pdir in $plist_dirs; do
        if [ -d "$pdir" ]; then
            log_verbose "Scanning $pdir"
            while IFS= read -r plist; do
                if [ -f "$plist" ]; then
                    local suspicious=0
                    local reason=""

                    # Check for node execution
                    if grep -qiE '(node|npm|npx)' "$plist" 2>/dev/null; then
                        # Further check for PolinRider-specific patterns
                        if grep -qF "global[" "$plist" 2>/dev/null || \
                           grep -qF "$V1_MARKER" "$plist" 2>/dev/null || \
                           grep -qF "$V2_MARKER" "$plist" 2>/dev/null || \
                           grep -qE 'eval\(' "$plist" 2>/dev/null; then
                            suspicious=1
                            reason="node execution with PolinRider markers"
                        fi
                    fi

                    # Check for C2 domains
                    local old_ifs2="$IFS"
                    IFS=' '
                    for domain in $C2_DOMAINS; do
                        if grep -qF "$domain" "$plist" 2>/dev/null; then
                            suspicious=1
                            reason="references C2 domain ${domain}"
                        fi
                    done
                    IFS="$old_ifs2"

                    # Check for curl|bash patterns
                    if grep -qE '(curl|wget).*\|.*(bash|sh)' "$plist" 2>/dev/null; then
                        suspicious=1
                        reason="curl|bash execution pattern"
                    fi

                    if [ "$suspicious" -eq 1 ]; then
                        add_system_finding "PERSISTENCE" "Suspicious LaunchAgent/Daemon: ${plist} (${reason})"
                    fi
                fi
            done <<PLISTEOF
$(find "$pdir" -name "*.plist" -type f 2>/dev/null)
PLISTEOF
        fi
    done
    IFS="$old_ifs"

    log_verbose "LaunchAgent/Daemon scan complete"
}

# ---------------------------------------------------------------------------
# 4. Crontab
# ---------------------------------------------------------------------------
scan_crontab() {
    print_section "CRONTAB" "Checking scheduled tasks..."

    local cron_content
    cron_content=$(crontab -l 2>/dev/null) || true

    if [ -n "$cron_content" ]; then
        if echo "$cron_content" | grep -qE '(curl|wget).*\|.*(bash|sh)' 2>/dev/null; then
            add_system_finding "CRONTAB" "Cron job with curl|bash pattern detected"
        fi
        if echo "$cron_content" | grep -qE 'node\s+-e' 2>/dev/null; then
            add_system_finding "CRONTAB" "Cron job executing node -e (potential payload)"
        fi

        local old_ifs="$IFS"
        IFS=' '
        for domain in $C2_DOMAINS; do
            if echo "$cron_content" | grep -qF "$domain" 2>/dev/null; then
                add_system_finding "CRONTAB" "Cron job referencing C2 domain: ${domain}"
            fi
        done
        IFS="$old_ifs"
    fi

    log_verbose "Crontab scan complete"
}

# ---------------------------------------------------------------------------
# 5. Shell profiles
# ---------------------------------------------------------------------------
scan_shell_profiles() {
    print_section "SHELL" "Scanning shell profiles for injected commands..."

    local profiles="$HOME/.zshrc $HOME/.zprofile $HOME/.zshenv $HOME/.bash_profile $HOME/.bashrc $HOME/.profile"

    local old_ifs="$IFS"
    IFS=' '
    for prof in $profiles; do
        if [ -f "$prof" ]; then
            log_verbose "Checking $prof"

            if grep -qE '(curl|wget).*\|.*(bash|sh)' "$prof" 2>/dev/null; then
                add_system_finding "SHELL" "Shell profile ${prof} contains curl|bash pattern"
            fi

            if grep -qE 'node\s+-e\s' "$prof" 2>/dev/null; then
                add_system_finding "SHELL" "Shell profile ${prof} contains node -e execution"
            fi

            local old_ifs2="$IFS"
            IFS=' '
            for domain in $C2_DOMAINS $BLOCKCHAIN_HOSTS; do
                if grep -qF "$domain" "$prof" 2>/dev/null; then
                    add_system_finding "SHELL" "Shell profile ${prof} references C2 endpoint: ${domain}"
                fi
            done
            IFS="$old_ifs2"

            if grep -qF "$V1_MARKER" "$prof" 2>/dev/null || \
               grep -qF "$V2_MARKER" "$prof" 2>/dev/null; then
                add_system_finding "SHELL" "Shell profile ${prof} contains PolinRider signature"
            fi

            for addr in "$TRON_ADDR_1" "$TRON_ADDR_2" "$APTOS_HASH_1" "$APTOS_HASH_2"; do
                if grep -qF "$addr" "$prof" 2>/dev/null; then
                    add_system_finding "SHELL" "Shell profile ${prof} references blockchain C2 address: ${addr}"
                fi
            done
        fi
    done
    IFS="$old_ifs"

    log_verbose "Shell profile scan complete"
}

# ---------------------------------------------------------------------------
# 6. VS Code extensions
# ---------------------------------------------------------------------------
scan_vscode_extensions() {
    print_section "VSCODE" "Scanning VS Code / Cursor extensions and workspace configs..."

    local ext_dirs="$HOME/.vscode/extensions $HOME/.cursor/extensions $HOME/.vscode-insiders/extensions"

    local old_ifs="$IFS"
    IFS=' '
    for ext_dir in $ext_dirs; do
        if [ -d "$ext_dir" ]; then
            log_verbose "Scanning extensions in $ext_dir"

            # Scan extension JS files for payload signatures
            while IFS= read -r extfile; do
                if [ -f "$extfile" ]; then
                    if grep -qF "$V1_MARKER" "$extfile" 2>/dev/null || \
                       grep -qF "$V2_MARKER" "$extfile" 2>/dev/null || \
                       grep -qF "$V1_DECODER" "$extfile" 2>/dev/null || \
                       grep -qF "$V2_GLOBAL" "$extfile" 2>/dev/null; then
                        add_system_finding "VSCODE-EXT" "Infected extension file: ${extfile}"
                    fi
                fi
            done <<EXTEOF
$(find "$ext_dir" \( -name "*.js" -o -name "*.mjs" \) -type f -maxdepth 4 2>/dev/null | head -2000)
EXTEOF

            # Check extension package.json for malicious npm deps
            while IFS= read -r ext_pkg; do
                if [ -f "$ext_pkg" ]; then
                    local old_ifs2="$IFS"
                    IFS=' '
                    for mal_pkg in $MALICIOUS_NPM_PKGS; do
                        if grep -qF "\"${mal_pkg}\"" "$ext_pkg" 2>/dev/null; then
                            add_system_finding "VSCODE-EXT" "Extension depends on malicious package '${mal_pkg}': ${ext_pkg}"
                        fi
                    done
                    IFS="$old_ifs2"
                fi
            done <<EXTPKGEOF
$(find "$ext_dir" -name "package.json" -maxdepth 3 -type f 2>/dev/null)
EXTPKGEOF
        fi
    done
    IFS="$old_ifs"

    # Scan workspace tasks.json files under common VS Code storage locations
    local vscode_storage="$HOME/Library/Application Support/Code/User/workspaceStorage"
    if [ -d "$vscode_storage" ]; then
        while IFS= read -r ws_tasks; do
            if [ -f "$ws_tasks" ]; then
                if grep -qF "$STAKING_UUID" "$ws_tasks" 2>/dev/null; then
                    add_system_finding "VSCODE-TASKS" "StakingGame UUID in workspace tasks: ${ws_tasks}"
                fi
                local old_ifs3="$IFS"
                IFS=' '
                for domain in $C2_DOMAINS; do
                    if grep -qF "$domain" "$ws_tasks" 2>/dev/null; then
                        add_system_finding "VSCODE-TASKS" "C2 domain in workspace tasks: ${ws_tasks} (${domain})"
                    fi
                done
                IFS="$old_ifs3"
            fi
        done <<WSTEOF
$(find "$vscode_storage" -name "tasks.json" -type f 2>/dev/null)
WSTEOF
    fi

    log_verbose "VS Code extension scan complete"
}

# ---------------------------------------------------------------------------
# 7. npm global packages
# ---------------------------------------------------------------------------
scan_npm_global() {
    print_section "NPM" "Checking global npm packages for known malicious packages..."

    if command -v npm >/dev/null 2>&1; then
        local npm_list
        npm_list=$(npm list -g --depth=0 2>/dev/null) || true

        if [ -n "$npm_list" ]; then
            # Check for known malicious packages by exact name
            local old_ifs="$IFS"
            IFS=' '
            for mal_pkg in $MALICIOUS_NPM_PKGS; do
                if echo "$npm_list" | grep -qF "$mal_pkg" 2>/dev/null; then
                    add_system_finding "NPM-GLOBAL" "Malicious global npm package installed: ${mal_pkg}"
                fi
            done
            IFS="$old_ifs"

            # Flag all global packages containing "tailwind" for manual review
            local tailwind_pkgs
            tailwind_pkgs=$(echo "$npm_list" | grep -ioE '[a-z0-9@_./-]*tailwind[a-z0-9_./-]*' 2>/dev/null | sort -u) || true
            if [ -n "$tailwind_pkgs" ]; then
                while IFS= read -r tw_pkg; do
                    if [ -n "$tw_pkg" ]; then
                        case "$tw_pkg" in
                            tailwindcss|@tailwindcss/*|tailwindcss-animate|tailwind-merge|tailwind-variants|\
prettier-plugin-tailwindcss|tailwindcss-radix|tailwindcss-debug-screens|\
@headlessui/tailwindcss|storybook-addon-tailwindcss|tailwindcss-textshadow|\
tailwindcss-3d|tailwindcss-animated|tailwindcss-gradients|tailwindcss-scrollbar|\
tailwindcss-question-mark|tailwindcss-opentype|tailwindcss-hyphens|\
tailwindcss-writing-mode|tailwindcss-border-gradient|tailwindcss-dir|\
@savvywombat/tailwindcss-grid-areas|tailwindcss-fluid-type|\
tailwindcss-children|tailwindcss-multi|tailwindcss-primeui|\
tailwindcss-react-aria-components|tw-animate-css) ;;
                            *) add_system_finding "NPM-TAILWIND" "Global package contains 'tailwind' — review manually: ${tw_pkg}" ;;
                        esac
                    fi
                done <<< "$tailwind_pkgs"
            fi
        fi

        # Check global node_modules for suspicious postinstall scripts
        local npm_root
        npm_root=$(npm root -g 2>/dev/null) || true
        if [ -n "$npm_root" ] && [ -d "$npm_root" ]; then
            log_verbose "Scanning global node_modules at $npm_root"
            while IFS= read -r gi_pkg; do
                if [ -f "$gi_pkg" ]; then
                    if grep -qE '"postinstall".*:.*"(curl|wget|node -e)' "$gi_pkg" 2>/dev/null; then
                        add_system_finding "NPM-GLOBAL" "Suspicious postinstall script: ${gi_pkg}"
                    fi
                    if grep -qF "$V1_MARKER" "$gi_pkg" 2>/dev/null || \
                       grep -qF "$V2_MARKER" "$gi_pkg" 2>/dev/null; then
                        add_system_finding "NPM-GLOBAL" "PolinRider signature in global package: ${gi_pkg}"
                    fi
                fi
            done <<GIPKGEOF
$(find "$npm_root" -name "package.json" -maxdepth 2 -type f 2>/dev/null)
GIPKGEOF
        fi
    else
        log_verbose "npm not found, skipping global package scan"
    fi

    log_verbose "npm global scan complete"
}

# ---------------------------------------------------------------------------
# 8. Temp directories
# ---------------------------------------------------------------------------
scan_temp_dirs() {
    print_section "TEMP" "Scanning temp directories for PolinRider artifacts..."

    local tmp_dirs="/tmp /var/tmp"
    if [ -n "${TMPDIR:-}" ]; then
        tmp_dirs="$tmp_dirs $TMPDIR"
    fi

    local old_ifs="$IFS"
    IFS=' '
    for tmp_dir in $tmp_dirs; do
        if [ -d "$tmp_dir" ]; then
            log_verbose "Scanning $tmp_dir"

            # Look for .js/.bat files with payload signatures
            while IFS= read -r tmp_file; do
                if [ -f "$tmp_file" ]; then
                    if grep -qF "$V1_MARKER" "$tmp_file" 2>/dev/null || \
                       grep -qF "$V2_MARKER" "$tmp_file" 2>/dev/null || \
                       grep -qF "$V1_DECODER" "$tmp_file" 2>/dev/null || \
                       grep -qF "$V2_GLOBAL" "$tmp_file" 2>/dev/null; then
                        add_system_finding "TEMP" "PolinRider artifact in temp: ${tmp_file}"
                    fi
                    local old_ifs3="$IFS"
                    IFS=' '
                    for domain in $C2_DOMAINS; do
                        if grep -qF "$domain" "$tmp_file" 2>/dev/null; then
                            add_system_finding "TEMP" "C2 domain reference in temp file: ${tmp_file} (${domain})"
                        fi
                    done
                    IFS="$old_ifs3"
                    for addr in "$TRON_ADDR_1" "$TRON_ADDR_2" "$APTOS_HASH_1" "$APTOS_HASH_2"; do
                        if grep -qF "$addr" "$tmp_file" 2>/dev/null; then
                            add_system_finding "TEMP" "Blockchain C2 address in temp file: ${tmp_file} (${addr})"
                        fi
                    done
                fi
            done <<TMPEOF
$(find "$tmp_dir" \( -name "*.js" -o -name "*.bat" -o -name "*.sh" -o -name "*.mjs" \) -type f -maxdepth 3 2>/dev/null 2>/dev/null | head -500)
TMPEOF

            # Check for temp_auto_push.bat specifically
            if [ -f "${tmp_dir}/temp_auto_push.bat" ]; then
                add_system_finding "TEMP" "Propagation script in temp: ${tmp_dir}/temp_auto_push.bat"
            fi
        fi
    done
    IFS="$old_ifs"

    log_verbose "Temp directory scan complete"
}

# ---------------------------------------------------------------------------
# 9. Browser extensions (Chrome / Brave / Edge)
# ---------------------------------------------------------------------------
scan_browser_extensions() {
    print_section "BROWSER" "Scanning browser extension directories..."

    local found_any=0

    _scan_one_browser_ext_dir() {
        local bext_dir="$1"
        if [ ! -d "$bext_dir" ]; then
            return
        fi
        found_any=1
        log_verbose "Scanning browser extensions in $bext_dir"
        while IFS= read -r bext_file; do
            if [ -f "$bext_file" ]; then
                if grep -qF "$V1_MARKER" "$bext_file" 2>/dev/null || \
                   grep -qF "$V2_MARKER" "$bext_file" 2>/dev/null || \
                   grep -qF "$V1_DECODER" "$bext_file" 2>/dev/null || \
                   grep -qF "$V2_GLOBAL" "$bext_file" 2>/dev/null; then
                    add_system_finding "BROWSER" "Infected browser extension file: ${bext_file}"
                fi
                local old_ifs2="$IFS"
                IFS=' '
                for domain in $C2_DOMAINS; do
                    if grep -qF "$domain" "$bext_file" 2>/dev/null; then
                        add_system_finding "BROWSER" "Browser extension references C2: ${bext_file} (${domain})"
                    fi
                done
                IFS="$old_ifs2"
                for addr in "$TRON_ADDR_1" "$TRON_ADDR_2" "$APTOS_HASH_1" "$APTOS_HASH_2"; do
                    if grep -qF "$addr" "$bext_file" 2>/dev/null; then
                        add_system_finding "BROWSER" "Browser extension references blockchain C2: ${bext_file} (${addr})"
                    fi
                done
            fi
        done <<BEXTEOF
$(find "$bext_dir" -name "*.js" -type f -maxdepth 5 2>/dev/null | head -1000)
BEXTEOF
    }

    # Each path handled individually to avoid space-in-path splitting issues
    # macOS paths
    _scan_one_browser_ext_dir "$HOME/Library/Application Support/Google/Chrome/Default/Extensions"
    _scan_one_browser_ext_dir "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"
    _scan_one_browser_ext_dir "$HOME/Library/Application Support/Microsoft Edge/Default/Extensions"
    _scan_one_browser_ext_dir "$HOME/Library/Application Support/Arc/User Data/Default/Extensions"
    _scan_one_browser_ext_dir "$HOME/Library/Application Support/Firefox/Profiles"
    # Linux paths
    _scan_one_browser_ext_dir "$HOME/.config/google-chrome/Default/Extensions"
    _scan_one_browser_ext_dir "$HOME/.config/BraveSoftware/Brave-Browser/Default/Extensions"
    _scan_one_browser_ext_dir "$HOME/.config/microsoft-edge/Default/Extensions"
    _scan_one_browser_ext_dir "$HOME/.mozilla/firefox"

    if [ "$found_any" -eq 0 ]; then
        log_verbose "No browser extension directories found"
    fi

    unset -f _scan_one_browser_ext_dir
    log_verbose "Browser extension scan complete"
}

# ===================================================================
#  INTERACTIVE CLEANUP
# ===================================================================
perform_cleanup() {
    local total_items=$(( ${#CLEANUP_BAT_FILES[@]} + ${#CLEANUP_GITIGNORE_REPOS[@]} + ${#CLEANUP_NODE_MODULES[@]} ))
    [ "$total_items" -eq 0 ] && return 0
    [ ! -t 0 ] && return 0  # non-interactive (piped/CI): skip prompt

    printf "\n${BOLD}================================================${RESET}\n"
    printf "  ${CYAN}${BOLD}AUTO-CLEANABLE ITEMS FOUND${RESET}\n"
    printf "${BOLD}================================================${RESET}\n\n"

    if [ "${#CLEANUP_BAT_FILES[@]}" -gt 0 ]; then
        printf "${BOLD}Propagation scripts (will be deleted):${RESET}\n"
        for f in "${CLEANUP_BAT_FILES[@]}"; do
            printf "  ${RED}-${RESET} %s\n" "$f"
        done
        printf "\n"
    fi

    if [ "${#CLEANUP_GITIGNORE_REPOS[@]}" -gt 0 ]; then
        printf "${BOLD}.gitignore entries to remove (config.bat / temp_auto_push.bat):${RESET}\n"
        for repo_d in "${CLEANUP_GITIGNORE_REPOS[@]}"; do
            printf "  ${RED}-${RESET} %s/.gitignore\n" "$repo_d"
        done
        printf "\n"
    fi

    if [ "${#CLEANUP_NODE_MODULES[@]}" -gt 0 ]; then
        printf "${BOLD}node_modules directories (entire folder deleted, re-run npm install after):${RESET}\n"
        for nm_d in "${CLEANUP_NODE_MODULES[@]}"; do
            printf "  ${RED}-${RESET} %s\n" "$nm_d"
        done
        printf "\n"
    fi

    printf "${YELLOW}${BOLD}Auto-clean the above items? [y/N]${RESET} " >/dev/tty
    local answer=""
    read -r answer </dev/tty
    printf "\n" >/dev/tty

    case "$answer" in
        [yY]|[yY][eE][sS])
            if [ "${#CLEANUP_BAT_FILES[@]}" -gt 0 ]; then
                printf "${BOLD}Removing propagation scripts...${RESET}\n"
                for f in "${CLEANUP_BAT_FILES[@]}"; do
                    if [ -n "$f" ] && [ -f "$f" ]; then
                        rm -f "$f" \
                            && printf "  [OK]  Deleted: %s\n" "$f" \
                            || printf "  [FAIL] Failed:  %s\n" "$f"
                    fi
                done
                printf "\n"
            fi

            if [ "${#CLEANUP_GITIGNORE_REPOS[@]}" -gt 0 ]; then
                printf "${BOLD}Cleaning .gitignore entries...${RESET}\n"
                for repo_d in "${CLEANUP_GITIGNORE_REPOS[@]}"; do
                    local gi_file="${repo_d}/.gitignore"
                    if [ -n "$repo_d" ] && [ -f "$gi_file" ]; then
                        local tmp_gi
                        tmp_gi=$(mktemp) || continue
                        grep -vxF "config.bat" "$gi_file" | grep -vxF "temp_auto_push.bat" > "$tmp_gi" 2>/dev/null
                        mv "$tmp_gi" "$gi_file" \
                            && printf "  [OK]  Cleaned: %s\n" "$gi_file" \
                            || printf "  [FAIL] Failed:  %s\n" "$gi_file"
                    fi
                done
                printf "\n"
            fi

            if [ "${#CLEANUP_NODE_MODULES[@]}" -gt 0 ]; then
                printf "${BOLD}Removing node_modules directories...${RESET}\n"
                for nm_d in "${CLEANUP_NODE_MODULES[@]}"; do
                    case "$nm_d" in
                        */node_modules)
                            if [ -n "$nm_d" ] && [ -d "$nm_d" ]; then
                                rm -rf "$nm_d" \
                                    && printf "  [OK]  Deleted: %s\n" "$nm_d" \
                                    || printf "  [FAIL] Failed:  %s\n" "$nm_d"
                            fi
                            ;;
                        *)
                            printf "  [SKIP] Unexpected path (not deleted): %s\n" "$nm_d"
                            ;;
                    esac
                done
                printf "\n  -> Re-run npm install in each affected project directory\n\n"
            fi
            ;;
        *)
            printf "Skipped. To clean manually:\n"
            for f in "${CLEANUP_BAT_FILES[@]}"; do
                [ -n "$f" ] && printf "  rm -f '%s'\n" "$f"
            done
            for nm_d in "${CLEANUP_NODE_MODULES[@]}"; do
                [ -n "$nm_d" ] && printf "  rm -rf '%s' && npm install\n" "$nm_d"
            done
            printf "\n"
            ;;
    esac
}

# ===================================================================
#  REMEDIATION OUTPUT
# ===================================================================
print_remediation() {
    printf "\n${BOLD}REMEDIATION STEPS:${RESET}\n"
    printf "\n"
    printf "${BOLD}Repository cleanup:${RESET}\n"
    printf "  1. Remove the obfuscated payload from infected config files\n"
    printf "     - Variant 1: everything after legitimate config, starting with global['!']\n"
    printf "     - Variant 2: everything after legitimate config, starting with global['_V']\n"
    printf "  2. Delete temp_auto_push.bat and config.bat if present\n"
    printf "  3. Remove \"config.bat\" from .gitignore\n"
    printf "  4. Remove malicious npm dependencies from package.json and run npm install\n"
    printf "  5. Delete any .woff2 files containing JS payloads\n"
    printf "  6. Remove malicious .vscode/tasks.json entries\n"
    printf "  7. Force-push clean versions to GitHub\n"
    printf "\n"
    printf "${BOLD}System cleanup (macOS: LaunchAgents/Daemons):${RESET}\n"
    printf "  8.  Kill suspicious node processes:\n"
    printf "      kill -9 <PID>   (use PIDs from scan results above)\n"
    printf "  9.  Remove malicious LaunchAgents/LaunchDaemons:\n"
    printf "      launchctl unload <plist_path> && rm <plist_path>\n"
    printf "  10. Clean shell profiles (~/.zshrc, ~/.bash_profile, etc.):\n"
    printf "      Review and remove any injected curl|bash or node -e lines\n"
    printf "  11. Uninstall malicious global npm packages:\n"
    printf "      npm uninstall -g <package_name>\n"
    printf "  12. Remove malicious VS Code / Cursor extensions:\n"
    printf "      code --uninstall-extension <ext_id>  OR  delete from ~/.vscode/extensions/\n"
    printf "  13. Remove malicious crontab entries:\n"
    printf "      crontab -e   (remove suspicious lines)\n"
    printf "  14. Clean temp directories:\n"
    printf "      rm /tmp/<suspicious_files>\n"
    printf "\n"
    printf "${BOLD}Post-cleanup:${RESET}\n"
    printf "  15. Rotate ALL secrets, tokens, API keys, and credentials\n"
    printf "  16. Review browser extensions and remove any unrecognized ones\n"
    printf "  17. Re-scan periodically — the threat actor re-infects cleaned repos\n"
    printf "  18. Report to https://opensourcemalware.com\n"
    printf "\n"
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
        --js-all)
            JS_ALL=1
            shift
            ;;
        --full-system)
            FULL_SYSTEM=1
            shift
            ;;
        --quick)
            QUICK_SCAN=1
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
            if [ -n "$SCAN_DIR" ]; then
                printf "Error: Multiple directories specified\n" >&2
                print_usage >&2
                exit 2
            fi
            SCAN_DIR="$1"
            shift
            ;;
    esac
done


# ===================================================================
#  MAIN EXECUTION
# ===================================================================
init_log

# Log all output: re-exec the script through a pipe that writes to the log file.
# _POLINRIDER_LOGGING prevents infinite re-exec loop.
if [ -n "$LOG_FILE" ] && [ "${_POLINRIDER_LOGGING:-0}" = "0" ]; then
    export _POLINRIDER_LOGGING=1
    export _POLINRIDER_LOG_FILE="$LOG_FILE"
    bash "$(cd "$(dirname "$0")" && pwd)/$(basename "$0")" "${ORIG_ARGS[@]}" 2>&1 | while IFS= read -r _log_line; do
        printf '%s\n' "$_log_line"
        printf '%s\n' "$_log_line" | sed 's/\x1b\[[0-9;]*m//g' >> "$_POLINRIDER_LOG_FILE"
    done
    exit "${PIPESTATUS[0]}"
fi

print_banner

# --- Quick scan mode ---
if [ "$QUICK_SCAN" -eq 1 ]; then
    printf "Mode: ${BOLD}Quick Scan${RESET} (processes + network only)\n"
    scan_processes
    scan_network

    printf "\n${BOLD}================================================${RESET}\n"
    if [ "$SYSTEM_FINDINGS" -gt 0 ]; then
        printf "  ${RED}${BOLD}RESULTS: %d system finding(s) detected${RESET}\n" "$SYSTEM_FINDINGS"
        printf "${BOLD}================================================${RESET}\n"
        printf "\n${BOLD}Findings:${RESET}\n"
        printf "$SYSTEM_FINDINGS_DETAIL"
        print_remediation
        log_scan_complete
        exit 1
    else
        printf "  ${GREEN}${BOLD}RESULTS: No active threats detected${RESET}\n"
        printf "${BOLD}================================================${RESET}\n\n"
        log_scan_complete
        exit 0
    fi
fi

# --- Full system scan mode ---
if [ "$FULL_SYSTEM" -eq 1 ]; then
    printf "Mode: ${BOLD}Full System Scan${RESET}\n"
    printf "This will scan processes, persistence, extensions, repos, and more.\n"

    _fs_mod=0
    _fs_mod_total=9

    _run_fs_module() {
        _fs_mod=$((_fs_mod + 1))
        local _label="$1"; local _fn="$2"
        _spinner_start "[${_fs_mod}/${_fs_mod_total}] ${_label}..."
        "$_fn"
        _spinner_stop
    }

    _run_fs_module "Processes"          scan_processes
    _run_fs_module "Network"            scan_network
    _run_fs_module "Persistence"        scan_persistence_plists
    _run_fs_module "Crontab"            scan_crontab
    _run_fs_module "Shell profiles"     scan_shell_profiles
    _run_fs_module "VS Code extensions" scan_vscode_extensions
    _run_fs_module "npm global"         scan_npm_global
    _run_fs_module "Temp dirs"          scan_temp_dirs
    _run_fs_module "Browser extensions" scan_browser_extensions

    # Also scan the home directory (or specified dir) for git repos
    if [ -z "$SCAN_DIR" ]; then
        SCAN_DIR="$HOME"
    fi
fi

# --- Directory-based repo scan ---
if [ -z "$SCAN_DIR" ]; then
    SCAN_DIR="."
fi

# Resolve to absolute path
SCAN_DIR_RESOLVED="$(cd "$SCAN_DIR" 2>/dev/null && pwd)"
if [ $? -ne 0 ] || [ ! -d "$SCAN_DIR_RESOLVED" ]; then
    printf "Error: Directory not found or not accessible: %s\n" "$SCAN_DIR" >&2
    exit 2
fi
SCAN_DIR="$SCAN_DIR_RESOLVED"

print_section "REPOS" "Scanning git repositories under ${SCAN_DIR}..."

# Find all git repositories
REPO_LIST=""
while IFS= read -r git_dir; do
    if [ -n "$git_dir" ]; then
        repo_dir="$(dirname "$git_dir")"
        REPO_LIST="${REPO_LIST}${repo_dir}
"
        TOTAL_REPOS=$((TOTAL_REPOS + 1))
    fi
done <<EOF
$(find "$SCAN_DIR" -name .git -type d -not -path "*/node_modules/*" 2>/dev/null | sort)
EOF

REPO_LIST="${REPO_LIST%
}"

if [ "$TOTAL_REPOS" -eq 0 ]; then
    printf "  No git repositories found under %s\n" "$SCAN_DIR"
else
    printf "  Found ${BOLD}%d${RESET} git repositories...\n" "$TOTAL_REPOS"

    while IFS= read -r repo; do
        if [ -n "$repo" ]; then
            REPO_DONE=$((REPO_DONE + 1))
            _prev_infected=$INFECTED_REPOS
            _rname="$(basename "$repo")"
            _spinner_start "[${REPO_DONE}/${TOTAL_REPOS}] ${_rname}..."
            scan_repo "$repo"
            _spinner_stop
            # Progress bar line after each repo
            if [ "$INFECTED_REPOS" -gt "$_prev_infected" ]; then
                _rstatus="${RED}INFECTED${RESET}"
            else
                _rstatus="${GREEN}clean${RESET}"
            fi
            _pct=$(( (REPO_DONE * 100) / TOTAL_REPOS ))
            _bfill=$(( (REPO_DONE * 20) / TOTAL_REPOS ))
            _bempty=$(( 20 - _bfill ))
            _bfill_s=""; _bi=0; while [ "$_bi" -lt "$_bfill" ]; do _bfill_s="${_bfill_s}="; _bi=$((_bi+1)); done
            _bempty_s=""; _bi=0; while [ "$_bi" -lt "$_bempty" ]; do _bempty_s="${_bempty_s} "; _bi=$((_bi+1)); done
            printf "  [%s%s] %3d%%  done:%d/%d  ${RED}infected:%d${RESET}  %b\n" \
                "$_bfill_s" "$_bempty_s" "$_pct" "$REPO_DONE" "$TOTAL_REPOS" "$INFECTED_REPOS" "$_rstatus"
        fi
    done <<REPOEOF
$REPO_LIST
REPOEOF
fi

# ===================================================================
#  SUMMARY
# ===================================================================
CLEAN_REPOS=$((TOTAL_REPOS - INFECTED_REPOS))
TOTAL_ISSUES=$((INFECTED_REPOS + SYSTEM_FINDINGS))

printf "\n"

if [ "$TOTAL_REPOS" -gt 0 ] && [ "$CLEAN_REPOS" -gt 0 ]; then
    printf "${GREEN}${BOLD}[CLEAN]${RESET} %d repositories scanned clean\n" "$CLEAN_REPOS"
fi

printf "\n${BOLD}================================================${RESET}\n"

if [ "$TOTAL_ISSUES" -gt 0 ]; then
    if [ "$INFECTED_REPOS" -gt 0 ]; then
        printf "  ${RED}${BOLD}REPOS:   %d infected repo(s) found${RESET}\n" "$INFECTED_REPOS"
    fi
    if [ "$SYSTEM_FINDINGS" -gt 0 ]; then
        printf "  ${RED}${BOLD}SYSTEM:  %d system finding(s) detected${RESET}\n" "$SYSTEM_FINDINGS"
        printf "${BOLD}================================================${RESET}\n"
        printf "\n${BOLD}System Findings:${RESET}\n"
        printf "$SYSTEM_FINDINGS_DETAIL"
    else
        printf "${BOLD}================================================${RESET}\n"
    fi
    print_remediation
    perform_cleanup
    log_scan_complete
    exit 1
else
    printf "  ${GREEN}${BOLD}RESULTS: No infections found${RESET}\n"
    printf "${BOLD}================================================${RESET}\n\n"
    log_scan_complete
    exit 0
fi
