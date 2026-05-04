#!/bin/bash
#
# PolinRider Pre-Build Scanner for React Native v1.3
#
# Scans a React Native project for PolinRider / TasksJacker malware
# before allowing the build/archive to proceed.
#
# Integration — package.json "scripts":
#   "prebuild": "./polinrider-prebuild-rn.sh",
#   "ios": "./polinrider-prebuild-rn.sh && npx react-native run-ios",
#   "android": "./polinrider-prebuild-rn.sh && npx react-native run-android"
#
# Integration — Xcode Build Phase (Run Script, place BEFORE "Compile Sources"):
#   1. In Xcode: Target → Build Phases → "+" → New Run Script Phase
#   2. Move it to the top of the build phases list
#   3. Uncheck "Based on dependency analysis" so it always runs
#   4. Shell: /bin/bash
#   5. Script:
#        "${SRCROOT}/../polinrider-prebuild-rn.sh"
#
# When invoked from Xcode (SRCROOT is set), the script:
#   - Auto-resolves the React Native project root to $SRCROOT/..
#   - Skips when ACTION=clean (avoids blocking clean builds)
#   - Emits findings as "error: ..." lines so they appear in
#     Xcode's Issue navigator as build errors
#
# Exit codes:
#   0 - Clean, build may proceed
#   1 - Malware indicators found, build blocked
#   2 - Error (invalid path, etc.)

set -u

VERSION="1.3"
FINDING_COUNT=0
FINDINGS=""
SCAN_ERRORS=0

# ---------------------------------------------------------------------------
# Xcode Build Phase integration
# ---------------------------------------------------------------------------
# Xcode sets SRCROOT to the directory containing the .xcodeproj (i.e. `ios/`
# for React Native). The RN project root is one level up. Detect by presence
# of SRCROOT and absence of an explicit CLI argument.
XCODE_MODE=0
if [ -z "${1:-}" ] && [ -n "${SRCROOT:-}" ]; then
    XCODE_MODE=1
    # Skip during clean — no source to scan, and we don't want to block
    # cleanup actions. ACTION may be: build, install (archive), clean,
    # installhdrs, installsrc.
    if [ "${ACTION:-}" = "clean" ]; then
        printf "PolinRider scanner: skipping (ACTION=clean)\n"
        exit 0
    fi
    # Resolve scan dir to the RN root (SRCROOT/..)
    SCAN_DIR="${SRCROOT}/.."
else
    SCAN_DIR="${1:-.}"
fi

# ---------------------------------------------------------------------------
# Variant 1 signatures (original — rmcej%otb%)
# ---------------------------------------------------------------------------
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
# Config files targeted by PolinRider + React Native-specific configs
# ---------------------------------------------------------------------------
CONFIG_FILES="postcss.config.mjs postcss.config.js postcss.config.cjs tailwind.config.js tailwind.config.mjs tailwind.config.ts eslint.config.mjs eslint.config.js eslint.config.cjs next.config.mjs next.config.js next.config.ts babel.config.js babel.config.cjs jest.config.js jest.config.ts vite.config.js vite.config.mjs vite.config.ts webpack.config.js webpack.config.mjs gridsome.config.js vue.config.js vue.config.ts truffle.js astro.config.mjs astro.config.ts nuxt.config.js nuxt.config.ts svelte.config.js rollup.config.js rollup.config.mjs tsconfig.json App.js app.js index.js"
RN_CONFIG_FILES="metro.config.js metro.config.ts react-native.config.js react-native.config.ts app.config.js app.config.ts App.tsx App.jsx index.ts index.tsx index.android.js index.ios.js index.android.tsx index.ios.tsx"

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

# IDE/agent config directories
IDE_CONFIG_DIRS=".vscode .cursor .claude"

# Known-legitimate tailwind packages (allowlist)
is_legit_tailwind_pkg() {
    case "$1" in
        tailwindcss|@tailwindcss/*|tailwindcss-animate|tailwind-merge|tailwind-variants|\
prettier-plugin-tailwindcss|tailwindcss-radix|tailwindcss-debug-screens|\
@headlessui/tailwindcss|storybook-addon-tailwindcss|tailwindcss-textshadow|\
tailwindcss-3d|tailwindcss-animated|tailwindcss-gradients|tailwindcss-scrollbar|\
tailwindcss-question-mark|tailwindcss-opentype|tailwindcss-hyphens|\
tailwindcss-writing-mode|tailwindcss-border-gradient|tailwindcss-dir|\
@savvywombat/tailwindcss-grid-areas|tailwindcss-fluid-type|\
tailwindcss-children|tailwindcss-multi|tailwindcss-primeui|\
tailwindcss-react-aria-components|tw-animate-css)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Colors (disabled if not a terminal)
# ---------------------------------------------------------------------------
RED="" GREEN="" YELLOW="" CYAN="" BOLD="" RESET=""
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
fi

# ---------------------------------------------------------------------------
# Preflight: verify required tool capabilities
# ---------------------------------------------------------------------------
preflight_check() {
    local errors=0

    if ! command -v find >/dev/null 2>&1; then
        printf "FATAL: 'find' not found in PATH\n" >&2
        exit 2
    fi
    if ! command -v grep >/dev/null 2>&1; then
        printf "FATAL: 'grep' not found in PATH\n" >&2
        exit 2
    fi

    if ! find /dev/null -maxdepth 0 2>/dev/null 1>/dev/null; then
        printf "FATAL: 'find' does not support -maxdepth — cannot scan safely\n" >&2
        exit 2
    fi

    if ! printf 'test' | grep -qF 'test' 2>/dev/null; then
        printf "FATAL: 'grep -F' (fixed string match) not supported\n" >&2
        exit 2
    fi

    if ! printf 'test' | grep -qE 'te.t' 2>/dev/null; then
        printf "FATAL: 'grep -E' (extended regex) not supported\n" >&2
        exit 2
    fi

    HAS_GREP_P=0
    if printf '\xe2\x80\x8b' | grep -qP '\x{200B}' 2>/dev/null; then
        HAS_GREP_P=1
    fi
}

preflight_check

# ---------------------------------------------------------------------------
# Safe find wrapper — runs find and tracks errors
# ---------------------------------------------------------------------------
safe_find() {
    local output
    output="$(find "$@" 2>&1)" || true
    local errors
    errors="$(printf '%s' "$output" | grep -c '^find:' 2>/dev/null)" || true
    if [ "$errors" -gt 0 ]; then
        SCAN_ERRORS=$((SCAN_ERRORS + errors))
    fi
    printf '%s' "$output" | grep -v '^find:' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
# When running under Xcode (XCODE_MODE=1), each finding is also emitted as
# an "error: ..." (HIGH) or "warning: ..." (MEDIUM) line on stderr. Xcode
# parses those prefixes and surfaces them in the Issue navigator.
add_finding() {
    local severity="$1"
    local detail="$2"
    FINDING_COUNT=$((FINDING_COUNT + 1))
    if [ "$severity" = "HIGH" ]; then
        FINDINGS="${FINDINGS}  ${RED}[${severity}]${RESET} ${detail}\n"
        if [ "$XCODE_MODE" -eq 1 ]; then
            printf "error: PolinRider: %s\n" "$detail" >&2
        fi
    else
        FINDINGS="${FINDINGS}  ${YELLOW}[${severity}]${RESET} ${detail}\n"
        if [ "$XCODE_MODE" -eq 1 ]; then
            printf "warning: PolinRider: %s\n" "$detail" >&2
        fi
    fi
}

# ---------------------------------------------------------------------------
# Check a single file for payload signatures
# ---------------------------------------------------------------------------
check_file_signatures() {
    local filepath="$1"
    local label="$2"

    # Variant 1
    if grep -qF "$V1_MARKER" "$filepath" 2>/dev/null; then
        add_finding "HIGH" "${label}: Variant 1 payload (rmcej%%otb%%)"
    fi
    if grep -qF "$V1_DECODER" "$filepath" 2>/dev/null; then
        add_finding "HIGH" "${label}: Variant 1 decoder (_\$_1e42)"
    fi
    if grep -qF "$V1_GLOBAL" "$filepath" 2>/dev/null; then
        if grep -qF "$V1_SEED" "$filepath" 2>/dev/null || grep -qF "$V1_SEED2" "$filepath" 2>/dev/null; then
            add_finding "HIGH" "${label}: Variant 1 markers (global['!'] + seed)"
        else
            add_finding "HIGH" "${label}: PolinRider global['!'] assignment (variant 1 marker)"
        fi
    fi

    # Variant 2
    if grep -qF "$V2_MARKER" "$filepath" 2>/dev/null; then
        add_finding "HIGH" "${label}: Variant 2 payload (Cot%%3t=shtP)"
    fi
    if grep -qF "$V2_GLOBAL" "$filepath" 2>/dev/null; then
        if grep -qF "$V2_SEED" "$filepath" 2>/dev/null || grep -qF "$V2_SEED2" "$filepath" 2>/dev/null || grep -qF "$V2_DECODER" "$filepath" 2>/dev/null; then
            add_finding "HIGH" "${label}: Variant 2 markers (global['_V'] + seed/decoder)"
        else
            add_finding "HIGH" "${label}: PolinRider global['_V'] assignment (variant 2 marker)"
        fi
    fi

    # Common cross-variant markers
    if grep -qF "$COMMON_GLOBAL_R" "$filepath" 2>/dev/null && grep -qF "$COMMON_GLOBAL_M" "$filepath" 2>/dev/null; then
        if grep -qF "$V1_SEED" "$filepath" 2>/dev/null || grep -qF "$V1_SEED2" "$filepath" 2>/dev/null || \
           grep -qF "$V2_SEED" "$filepath" 2>/dev/null || grep -qF "$V2_SEED2" "$filepath" 2>/dev/null; then
            add_finding "HIGH" "${label}: Cross-variant global['r']/global['m'] with known seed"
        fi
    fi

    # eval() with global markers (partially cleaned infection)
    if grep -qE 'eval\(' "$filepath" 2>/dev/null; then
        if grep -qF "$COMMON_GLOBAL_R" "$filepath" 2>/dev/null || \
           grep -qF "$V1_GLOBAL" "$filepath" 2>/dev/null || \
           grep -qF "$V2_GLOBAL" "$filepath" 2>/dev/null; then
            add_finding "MEDIUM" "${label}: eval() with PolinRider global markers"
        fi
    fi
}

# ===================================================================
#  MAIN
# ===================================================================

# Resolve scan directory
if ! SCAN_DIR_RESOLVED="$(cd "$SCAN_DIR" 2>/dev/null && pwd)" || [ ! -d "$SCAN_DIR_RESOLVED" ]; then
    printf "Error: Directory not found: %s\n" "$SCAN_DIR" >&2
    exit 2
fi
SCAN_DIR="$SCAN_DIR_RESOLVED"

printf "\n${BOLD}PolinRider Pre-Build Scanner for React Native v%s${RESET}\n" "$VERSION"
if [ "$XCODE_MODE" -eq 1 ]; then
    printf "Mode: Xcode Build Phase (target=%s, action=%s, configuration=%s)\n" \
        "${TARGET_NAME:-?}" "${ACTION:-build}" "${CONFIGURATION:-?}"
fi
printf "Scanning: %s\n\n" "$SCAN_DIR"

# ---------------------------------------------------------------------------
# Build temp pattern files for batch grep — cleaned up on exit
# ---------------------------------------------------------------------------
PATTERN_DIR="$(mktemp -d)"
trap 'rm -rf "$PATTERN_DIR"' EXIT

# C2 + blockchain address patterns (one per line for grep -Ff)
C2_PATTERN_FILE="${PATTERN_DIR}/c2.txt"
{
    for domain in $C2_DOMAINS; do printf '%s\n' "$domain"; done
    printf '%s\n' "$TRON_ADDR_1" "$TRON_ADDR_2" "$APTOS_HASH_1" "$APTOS_HASH_2"
} > "$C2_PATTERN_FILE"

# Malware signature patterns (for pre-filtering candidate files)
SIG_PATTERN_FILE="${PATTERN_DIR}/sig.txt"
printf '%s\n' "$V1_MARKER" "$V2_MARKER" "$V1_DECODER" "$V1_GLOBAL" "$V2_GLOBAL" "$COMMON_GLOBAL_R" > "$SIG_PATTERN_FILE"

# ---------------------------------------------------------------------------
# Single find pass: collect all config files using a combined -name expression
# This replaces 40+ individual find commands with ONE traversal.
# ---------------------------------------------------------------------------
ALL_CONFIG_FILES="${CONFIG_FILES} ${RN_CONFIG_FILES}"

CONFIG_FILE_LIST="${PATTERN_DIR}/configs.txt"
{
    # Build find expression dynamically
    find_args=()
    first=1
    for config_file in $ALL_CONFIG_FILES; do
        if [ "$first" -eq 1 ]; then
            find_args+=( -name "$config_file" )
            first=0
        else
            find_args+=( -o -name "$config_file" )
        fi
    done
    safe_find "$SCAN_DIR" -maxdepth 6 -type f \( "${find_args[@]}" \) \
        -not -path "*/node_modules/*" -not -path "*/.git/*" \
        -not -path "*/Pods/*" -not -path "*/build/*"
} > "$CONFIG_FILE_LIST"

# Collect all source files in one find pass
SOURCE_FILE_LIST="${PATTERN_DIR}/sources.txt"
safe_find "$SCAN_DIR" -maxdepth 6 -type f \
    \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" -o -name "*.tsx" -o -name "*.jsx" -o -name "*.json" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" \
    -not -path "*/Pods/*" -not -path "*/build/*" > "$SOURCE_FILE_LIST"

# --- 1. Config files: payload signatures ---
while IFS= read -r filepath; do
    if [ -f "$filepath" ]; then
        local_path="${filepath#${SCAN_DIR}/}"
        check_file_signatures "$filepath" "$local_path"
    fi
done < "$CONFIG_FILE_LIST"

# --- 2. Fake font payloads (.woff / .woff2) ---
while IFS= read -r woff_file; do
    if [ -f "$woff_file" ]; then
        local_path="${woff_file#${SCAN_DIR}/}"
        if grep -qF "$V1_MARKER" "$woff_file" 2>/dev/null; then
            add_finding "HIGH" "${local_path}: Fake font with variant 1 payload"
        fi
        if grep -qF "$V2_MARKER" "$woff_file" 2>/dev/null; then
            add_finding "HIGH" "${local_path}: Fake font with variant 2 payload"
        fi
        if grep -qF "$V1_DECODER" "$woff_file" 2>/dev/null && grep -qF "$V1_GLOBAL" "$woff_file" 2>/dev/null; then
            add_finding "HIGH" "${local_path}: Fake font with variant 1 markers"
        fi
        if grep -qF "$COMMON_GLOBAL_R" "$woff_file" 2>/dev/null && grep -qF "$COMMON_GLOBAL_M" "$woff_file" 2>/dev/null; then
            add_finding "HIGH" "${local_path}: Fake font with PolinRider global markers"
        fi
    fi
done <<EOF
$(safe_find "$SCAN_DIR" -maxdepth 6 \( -name "*.woff2" -o -name "*.woff" \) -type f -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/Pods/*")
EOF

# --- 3. Propagation scripts (single find for both names) ---
while IFS= read -r script_file; do
    if [ -f "$script_file" ]; then
        local_path="${script_file#${SCAN_DIR}/}"
        if grep -qF "LAST_COMMIT_DATE" "$script_file" 2>/dev/null || \
           grep -qF "--no-verify" "$script_file" 2>/dev/null || \
           grep -qF "git push -uf" "$script_file" 2>/dev/null; then
            add_finding "HIGH" "${local_path}: PolinRider propagation script (confirmed)"
        else
            add_finding "MEDIUM" "${local_path}: Suspicious propagation script"
        fi
    fi
done <<EOF
$(safe_find "$SCAN_DIR" -maxdepth 4 \( -name "temp_auto_push.bat" -o -name "config.bat" \) -type f -not -path "*/.git/*" -not -path "*/node_modules/*")
EOF

# --- 4. .gitignore injection (config.bat entry) ---
while IFS= read -r gitignore_file; do
    if grep -qxF "config.bat" "$gitignore_file" 2>/dev/null; then
        local_path="${gitignore_file#${SCAN_DIR}/}"
        add_finding "HIGH" "${local_path}: config.bat entry injected by PolinRider"
    fi
done <<EOF
$(safe_find "$SCAN_DIR" -maxdepth 4 -name ".gitignore" -type f -not -path "*/node_modules/*" -not -path "*/.git/*")
EOF

# --- 5. child_process.spawn in config files (reuses cached file list) ---
while IFS= read -r filepath; do
    if [ -f "$filepath" ]; then
        if grep -qF "child_process" "$filepath" 2>/dev/null; then
            if grep -qF "detached" "$filepath" 2>/dev/null || grep -qF "windowsHide" "$filepath" 2>/dev/null; then
                local_path="${filepath#${SCAN_DIR}/}"
                add_finding "HIGH" "${local_path}: child_process.spawn with detached/hidden execution"
            fi
        fi
    fi
done < "$CONFIG_FILE_LIST"

# --- 6. IDE/agent config directories ---
for ide_dir_name in $IDE_CONFIG_DIRS; do
    while IFS= read -r ide_dir; do
        if [ ! -d "$ide_dir" ]; then continue; fi
        while IFS= read -r ide_file; do
            if [ ! -f "$ide_file" ]; then continue; fi
            local_path="${ide_file#${SCAN_DIR}/}"

            check_file_signatures "$ide_file" "$local_path"

            # StakingGame UUID
            if grep -qF "$STAKING_UUID" "$ide_file" 2>/dev/null; then
                add_finding "HIGH" "${local_path}: StakingGame weaponized template UUID"
            fi

            # ShoeVista template names
            for sv_name in $SHOEVISTA_NAMES; do
                if grep -qF "$sv_name" "$ide_file" 2>/dev/null; then
                    add_finding "HIGH" "${local_path}: ShoeVista weaponized template (${sv_name})"
                    break
                fi
            done

            # C2 domains + blockchain addresses (batch pre-filter then detail)
            if grep -qFf "$C2_PATTERN_FILE" "$ide_file" 2>/dev/null; then
                for domain in $C2_DOMAINS; do
                    if grep -qF "$domain" "$ide_file" 2>/dev/null; then
                        add_finding "HIGH" "${local_path}: C2 domain (${domain})"
                    fi
                done
                for addr in "$TRON_ADDR_1" "$TRON_ADDR_2" "$APTOS_HASH_1" "$APTOS_HASH_2"; do
                    if grep -qF "$addr" "$ide_file" 2>/dev/null; then
                        add_finding "HIGH" "${local_path}: Blockchain C2 address"
                    fi
                done
            fi

            # curl|bash auto-execution
            if grep -qE '(curl|wget).*\|.*(bash|sh)' "$ide_file" 2>/dev/null; then
                if grep -qF "folderOpen" "$ide_file" 2>/dev/null; then
                    add_finding "HIGH" "${local_path}: curl|bash with runOn:folderOpen"
                else
                    add_finding "MEDIUM" "${local_path}: curl|bash in IDE config"
                fi
            fi

            # node -e with suspicious payload
            if grep -qE 'node\s+-e' "$ide_file" 2>/dev/null; then
                if grep -qF "global[" "$ide_file" 2>/dev/null || \
                   grep -qF "child_process" "$ide_file" 2>/dev/null || \
                   grep -qF "eval(" "$ide_file" 2>/dev/null; then
                    add_finding "HIGH" "${local_path}: node -e with suspicious payload"
                fi
            fi

            # Prompt injection (.claude / .cursor only)
            if [ "$ide_dir_name" = ".claude" ] || [ "$ide_dir_name" = ".cursor" ]; then
                if grep -qiE '(ignore previous|ignore above|disregard|forget all|new instructions|you are now|act as|pretend)' "$ide_file" 2>/dev/null; then
                    add_finding "HIGH" "${local_path}: Prompt injection pattern"
                fi
                zwc_detected=0
                if [ "$HAS_GREP_P" -eq 1 ]; then
                    if grep -qP '[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}]' "$ide_file" 2>/dev/null; then
                        zwc_detected=1
                    fi
                else
                    if grep -q "$(printf '\xe2\x80\x8b\|\\xe2\x80\x8c\|\\xe2\x80\x8d\|\\xe2\x81\xa0\|\\xef\xbb\xbf')" "$ide_file" 2>/dev/null; then
                        zwc_detected=1
                    fi
                fi
                if [ "$zwc_detected" -eq 1 ]; then
                    add_finding "HIGH" "${local_path}: Hidden zero-width unicode characters"
                fi
            fi
        done <<IDEEOF
$(safe_find "$ide_dir" -maxdepth 3 -type f | head -200)
IDEEOF
    done <<EOF
$(safe_find "$SCAN_DIR" -maxdepth 4 -name "$ide_dir_name" -type d -not -path "*/node_modules/*" -not -path "*/.git/*")
EOF
done

# --- 7. Malicious npm packages in package.json ---
while IFS= read -r pkg_file; do
    if [ -f "$pkg_file" ]; then
        local_path="${pkg_file#${SCAN_DIR}/}"

        # Known malicious packages
        for mal_pkg in $MALICIOUS_NPM_PKGS; do
            if grep -qF "\"${mal_pkg}\"" "$pkg_file" 2>/dev/null; then
                add_finding "HIGH" "${local_path}: Malicious npm dependency '${mal_pkg}'"
            fi
        done

        # Suspicious tailwind-* packages
        tw_deps=$(grep -ioE '"[a-z0-9@_./-]*tailwind[a-z0-9_./-]*"' "$pkg_file" 2>/dev/null | tr -d '"' | sort -u) || true
        if [ -n "$tw_deps" ]; then
            while IFS= read -r tw_dep; do
                if [ -z "$tw_dep" ]; then continue; fi
                is_known_malicious=0
                for mal_pkg in $MALICIOUS_NPM_PKGS; do
                    if [ "$tw_dep" = "$mal_pkg" ]; then is_known_malicious=1; break; fi
                done
                if [ "$is_known_malicious" -eq 0 ] && ! is_legit_tailwind_pkg "$tw_dep"; then
                    add_finding "MEDIUM" "${local_path}: Suspicious tailwind package '${tw_dep}'"
                fi
            done <<< "$tw_deps"
        fi

        # Suspicious postinstall scripts
        if grep -qF '"postinstall"' "$pkg_file" 2>/dev/null; then
            postinstall_line=$(grep -F '"postinstall"' "$pkg_file" 2>/dev/null) || true
            if printf '%s' "$postinstall_line" | grep -qE '(curl|wget|node[[:space:]]+-e|eval|bash -c|sh -c)' 2>/dev/null; then
                add_finding "HIGH" "${local_path}: Suspicious postinstall script with download/eval"
            fi
        fi
    fi
done <<EOF
$(safe_find "$SCAN_DIR" -maxdepth 6 -name "package.json" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/Pods/*")
EOF

# --- 8. C2 domains, blockchain hosts/addresses, and ShoeVista in source files ---
# Pre-filter: use grep -lFf to find candidate files in one pass, then detail-check only those.
CANDIDATE_FILES="${PATTERN_DIR}/candidates.txt"
: > "$CANDIDATE_FILES"

if [ -s "$SOURCE_FILE_LIST" ]; then
    # xargs avoids "argument list too long" on large projects
    xargs grep -lFf "$C2_PATTERN_FILE" < "$SOURCE_FILE_LIST" 2>/dev/null >> "$CANDIDATE_FILES" || true
    xargs grep -lFf "$SIG_PATTERN_FILE" < "$SOURCE_FILE_LIST" 2>/dev/null >> "$CANDIDATE_FILES" || true
    for host in $BLOCKCHAIN_HOSTS; do
        xargs grep -lF "$host" < "$SOURCE_FILE_LIST" 2>/dev/null >> "$CANDIDATE_FILES" || true
    done
    for sv_name in $SHOEVISTA_NAMES; do
        xargs grep -lF "$sv_name" < "$SOURCE_FILE_LIST" 2>/dev/null >> "$CANDIDATE_FILES" || true
    done
    sort -u "$CANDIDATE_FILES" -o "$CANDIDATE_FILES" 2>/dev/null || true
fi

while IFS= read -r src_file; do
    if [ ! -f "$src_file" ]; then continue; fi
    local_path="${src_file#${SCAN_DIR}/}"

    # C2 domains
    for domain in $C2_DOMAINS; do
        if grep -qF "$domain" "$src_file" 2>/dev/null; then
            add_finding "HIGH" "${local_path}: C2 domain reference (${domain})"
            break
        fi
    done

    # Blockchain hosts (require corroborating payload markers)
    for host in $BLOCKCHAIN_HOSTS; do
        if grep -qF "$host" "$src_file" 2>/dev/null; then
            if grep -qF "$V1_MARKER" "$src_file" 2>/dev/null || \
               grep -qF "$V2_MARKER" "$src_file" 2>/dev/null || \
               grep -qF "$COMMON_GLOBAL_R" "$src_file" 2>/dev/null || \
               grep -qF "child_process" "$src_file" 2>/dev/null; then
                add_finding "HIGH" "${local_path}: Blockchain C2 host (${host}) with payload markers"
                break
            fi
        fi
    done

    # TRON addresses
    for addr in "$TRON_ADDR_1" "$TRON_ADDR_2"; do
        if grep -qF "$addr" "$src_file" 2>/dev/null; then
            add_finding "HIGH" "${local_path}: TRON C2 address"
            break
        fi
    done

    # Aptos addresses
    for addr in "$APTOS_HASH_1" "$APTOS_HASH_2"; do
        if grep -qF "$addr" "$src_file" 2>/dev/null; then
            add_finding "HIGH" "${local_path}: Aptos C2 address"
            break
        fi
    done

    # ShoeVista (require corroborating markers)
    for sv_name in $SHOEVISTA_NAMES; do
        if grep -qF "$sv_name" "$src_file" 2>/dev/null; then
            if grep -qF "$STAKING_UUID" "$src_file" 2>/dev/null || \
               grep -qF "child_process" "$src_file" 2>/dev/null || \
               grep -qF "$V1_MARKER" "$src_file" 2>/dev/null || \
               grep -qF "$V2_MARKER" "$src_file" 2>/dev/null; then
                add_finding "HIGH" "${local_path}: ShoeVista weaponized template (${sv_name})"
                break
            fi
        fi
    done
done < "$CANDIDATE_FILES"

# --- 9. iOS build phase scripts (Xcode shell scripts in ios/) ---
if [ -d "${SCAN_DIR}/ios" ]; then
    while IFS= read -r pbx_file; do
        if [ -f "$pbx_file" ]; then
            local_path="${pbx_file#${SCAN_DIR}/}"
            if grep -qFf "$C2_PATTERN_FILE" "$pbx_file" 2>/dev/null; then
                for domain in $C2_DOMAINS; do
                    if grep -qF "$domain" "$pbx_file" 2>/dev/null; then
                        add_finding "HIGH" "${local_path}: C2 domain in Xcode project"
                        break
                    fi
                done
            fi
            if grep -qE '(curl|wget).*\|.*(bash|sh)' "$pbx_file" 2>/dev/null; then
                if grep -qF "vercel.app" "$pbx_file" 2>/dev/null || \
                   grep -qF "eval(" "$pbx_file" 2>/dev/null; then
                    add_finding "HIGH" "${local_path}: Suspicious curl|bash in Xcode build phase"
                fi
            fi
        fi
    done <<EOF
$(safe_find "${SCAN_DIR}/ios" \( -name "*.pbxproj" -o -name "*.sh" -o -name "*.rb" \) -type f -not -path "*/Pods/*")
EOF
fi

# --- 10. Android build scripts (Gradle files in android/) ---
if [ -d "${SCAN_DIR}/android" ]; then
    while IFS= read -r gradle_file; do
        if [ -f "$gradle_file" ]; then
            local_path="${gradle_file#${SCAN_DIR}/}"
            if grep -qFf "$C2_PATTERN_FILE" "$gradle_file" 2>/dev/null; then
                for domain in $C2_DOMAINS; do
                    if grep -qF "$domain" "$gradle_file" 2>/dev/null; then
                        add_finding "HIGH" "${local_path}: C2 domain in Gradle build file"
                        break
                    fi
                done
            fi
            if grep -qE '(curl|wget).*\|.*(bash|sh)' "$gradle_file" 2>/dev/null; then
                add_finding "HIGH" "${local_path}: Suspicious curl|bash in Gradle build"
            fi
            if grep -qF "commandLine" "$gradle_file" 2>/dev/null; then
                if grep -qF "node" "$gradle_file" 2>/dev/null && grep -qF "eval" "$gradle_file" 2>/dev/null; then
                    add_finding "MEDIUM" "${local_path}: Suspicious node eval in Gradle task"
                fi
            fi
        fi
    done <<EOF
$(safe_find "${SCAN_DIR}/android" \( -name "*.gradle" -o -name "*.gradle.kts" -o -name "*.properties" \) -type f -not -path "*/build/*")
EOF
fi

# --- 11. Patches directory (malicious patches via patch-package) ---
if [ -d "${SCAN_DIR}/patches" ]; then
    while IFS= read -r patch_file; do
        if [ -f "$patch_file" ]; then
            local_path="${patch_file#${SCAN_DIR}/}"
            if grep -qF "$V1_MARKER" "$patch_file" 2>/dev/null || \
               grep -qF "$V2_MARKER" "$patch_file" 2>/dev/null; then
                add_finding "HIGH" "${local_path}: PolinRider payload in patch file"
            fi
            if grep -qFf "$C2_PATTERN_FILE" "$patch_file" 2>/dev/null; then
                for domain in $C2_DOMAINS; do
                    if grep -qF "$domain" "$patch_file" 2>/dev/null; then
                        add_finding "HIGH" "${local_path}: C2 domain in patch file"
                        break
                    fi
                done
            fi
        fi
    done <<EOF
$(safe_find "${SCAN_DIR}/patches" -name "*.patch" -type f)
EOF
fi

# ===================================================================
#  RESULTS
# ===================================================================
printf "${BOLD}================================================${RESET}\n"

if [ "$FINDING_COUNT" -gt 0 ]; then
    printf "  ${RED}${BOLD}BUILD BLOCKED: %d PolinRider indicator(s) found${RESET}\n" "$FINDING_COUNT"
    printf "${BOLD}================================================${RESET}\n\n"
    printf "${BOLD}Findings:${RESET}\n"
    printf '%b' "$FINDINGS"
    printf "\n${BOLD}Action required:${RESET}\n"
    if [ "$XCODE_MODE" -eq 1 ]; then
        printf "  1. Build/Archive cancelled — see Issue navigator (⌘5) for findings\n"
        printf "  2. Remove the infected files or malicious dependencies\n"
        printf "  3. Run the full scanner: https://github.com/branch8/PolinRinderScanner\n"
        printf "  4. Rotate any secrets/tokens that may have been exposed\n\n"
        # Final Xcode error so the build summary clearly attributes the failure
        printf "error: PolinRider scanner blocked the build — %d indicator(s) detected\n" "$FINDING_COUNT" >&2
    else
        printf "  1. Do NOT run react-native run-ios or run-android\n"
        printf "  2. Remove the infected files or malicious dependencies\n"
        printf "  3. Run the full scanner: https://github.com/branch8/PolinRinderScanner\n"
        printf "  4. Rotate any secrets/tokens that may have been exposed\n\n"
    fi
    exit 1
else
    printf "  ${GREEN}${BOLD}CLEAN: No PolinRider indicators found${RESET}\n"
    printf "${BOLD}================================================${RESET}\n\n"
    if [ "$SCAN_ERRORS" -gt 0 ]; then
        printf "${YELLOW}Warning: %d scan command(s) failed — some checks may have been skipped.${RESET}\n" "$SCAN_ERRORS"
        printf "Run on a supported platform (macOS/Linux with GNU or BSD tools) for full coverage.\n\n"
    fi
    exit 0
fi
