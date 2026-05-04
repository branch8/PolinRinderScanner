#!/bin/bash
#
# PolinRider Pre-Build Scanner v1.0
# https://opensourcemalware.com
#
# Lightweight source-code scanner designed for CI/CD pipelines.
# Scans the working directory for PolinRider / TasksJacker malware
# indicators and exits 1 if any are found, blocking the build.
#
# Usage in CI/CD (Adobe Cloud Build, GitHub Actions, etc.):
#   ./polinrider-prebuild.sh              # Scan current directory
#   ./polinrider-prebuild.sh /path/to/src # Scan specific directory
#
# Exit codes:
#   0 - Clean, build may proceed
#   1 - Malware indicators found, build blocked
#   2 - Error (invalid path, etc.)

set -u

VERSION="1.0"
SCAN_DIR="${1:-.}"
FINDING_COUNT=0
FINDINGS=""

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
# Config files targeted by PolinRider
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
TRON_ADDR_1="TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP"
TRON_ADDR_2="TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG"
APTOS_HASH_1="0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e"
APTOS_HASH_2="0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3"

# Weaponized template
STAKING_UUID="e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9"

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
RED="" GREEN="" YELLOW="" BOLD="" RESET=""
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
fi

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
add_finding() {
    local severity="$1"
    local detail="$2"
    FINDING_COUNT=$((FINDING_COUNT + 1))
    if [ "$severity" = "HIGH" ]; then
        FINDINGS="${FINDINGS}  ${RED}[${severity}]${RESET} ${detail}\n"
    else
        FINDINGS="${FINDINGS}  ${YELLOW}[${severity}]${RESET} ${detail}\n"
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
        fi
    fi

    # Variant 2
    if grep -qF "$V2_MARKER" "$filepath" 2>/dev/null; then
        add_finding "HIGH" "${label}: Variant 2 payload (Cot%%3t=shtP)"
    fi
    if grep -qF "$V2_GLOBAL" "$filepath" 2>/dev/null; then
        if grep -qF "$V2_SEED" "$filepath" 2>/dev/null || grep -qF "$V2_SEED2" "$filepath" 2>/dev/null || grep -qF "$V2_DECODER" "$filepath" 2>/dev/null; then
            add_finding "HIGH" "${label}: Variant 2 markers (global['_V'] + seed/decoder)"
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
SCAN_DIR_RESOLVED="$(cd "$SCAN_DIR" 2>/dev/null && pwd)"
if [ $? -ne 0 ] || [ ! -d "$SCAN_DIR_RESOLVED" ]; then
    printf "Error: Directory not found: %s\n" "$SCAN_DIR" >&2
    exit 2
fi
SCAN_DIR="$SCAN_DIR_RESOLVED"

printf "\n${BOLD}PolinRider Pre-Build Scanner v%s${RESET}\n" "$VERSION"
printf "Scanning: %s\n\n" "$SCAN_DIR"

# --- 1. Config files for payload signatures ---
for config_file in $CONFIG_FILES; do
    while IFS= read -r filepath; do
        if [ -f "$filepath" ]; then
            local_path="${filepath#${SCAN_DIR}/}"
            check_file_signatures "$filepath" "$local_path"
        fi
    done <<EOF
$(find "$SCAN_DIR" -name "$config_file" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -maxdepth 6 2>/dev/null)
EOF
done

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
$(find "$SCAN_DIR" \( -name "*.woff2" -o -name "*.woff" \) -type f -not -path "*/.git/*" -not -path "*/node_modules/*" 2>/dev/null)
EOF

# --- 3. Propagation scripts ---
for script_name in temp_auto_push.bat config.bat; do
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
$(find "$SCAN_DIR" -name "$script_name" -type f -not -path "*/.git/*" -not -path "*/node_modules/*" -maxdepth 4 2>/dev/null)
EOF
done

# --- 4. .gitignore injection (config.bat entry) ---
while IFS= read -r gitignore_file; do
    if grep -qxF "config.bat" "$gitignore_file" 2>/dev/null; then
        local_path="${gitignore_file#${SCAN_DIR}/}"
        add_finding "HIGH" "${local_path}: config.bat entry injected by PolinRider"
    fi
done <<EOF
$(find "$SCAN_DIR" -name ".gitignore" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -maxdepth 4 2>/dev/null)
EOF

# --- 5. child_process.spawn in config files ---
for config_file in $CONFIG_FILES; do
    while IFS= read -r filepath; do
        if [ -f "$filepath" ]; then
            if grep -qF "child_process" "$filepath" 2>/dev/null; then
                if grep -qF "detached" "$filepath" 2>/dev/null || grep -qF "windowsHide" "$filepath" 2>/dev/null; then
                    local_path="${filepath#${SCAN_DIR}/}"
                    add_finding "HIGH" "${local_path}: child_process.spawn with detached/hidden execution"
                fi
            fi
        fi
    done <<EOF
$(find "$SCAN_DIR" -name "$config_file" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -maxdepth 6 2>/dev/null)
EOF
done

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

            # C2 domains
            for domain in $C2_DOMAINS; do
                if grep -qF "$domain" "$ide_file" 2>/dev/null; then
                    add_finding "HIGH" "${local_path}: C2 domain (${domain})"
                fi
            done

            # Blockchain C2 addresses
            for addr in "$TRON_ADDR_1" "$TRON_ADDR_2" "$APTOS_HASH_1" "$APTOS_HASH_2"; do
                if grep -qF "$addr" "$ide_file" 2>/dev/null; then
                    add_finding "HIGH" "${local_path}: Blockchain C2 address"
                fi
            done

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
                if grep -qP '[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}]' "$ide_file" 2>/dev/null; then
                    add_finding "HIGH" "${local_path}: Hidden zero-width unicode characters"
                fi
            fi
        done <<IDEEOF
$(find "$ide_dir" -type f -maxdepth 3 2>/dev/null | head -200)
IDEEOF
    done <<EOF
$(find "$SCAN_DIR" -name "$ide_dir_name" -type d -not -path "*/node_modules/*" -not -path "*/.git/*" -maxdepth 4 2>/dev/null)
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

        # Suspicious tailwind-* packages (skip if already flagged as known-malicious)
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
    fi
done <<EOF
$(find "$SCAN_DIR" -name "package.json" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -maxdepth 6 2>/dev/null)
EOF

# --- 8. C2 domains and blockchain addresses in any JS/TS/JSON file ---
while IFS= read -r src_file; do
    if [ -f "$src_file" ]; then
        local_path="${src_file#${SCAN_DIR}/}"
        for domain in $C2_DOMAINS; do
            if grep -qF "$domain" "$src_file" 2>/dev/null; then
                add_finding "HIGH" "${local_path}: C2 domain reference (${domain})"
                break
            fi
        done
        for addr in "$TRON_ADDR_1" "$TRON_ADDR_2"; do
            if grep -qF "$addr" "$src_file" 2>/dev/null; then
                add_finding "HIGH" "${local_path}: TRON C2 address"
                break
            fi
        done
        for addr in "$APTOS_HASH_1" "$APTOS_HASH_2"; do
            if grep -qF "$addr" "$src_file" 2>/dev/null; then
                add_finding "HIGH" "${local_path}: Aptos C2 address"
                break
            fi
        done
    fi
done <<EOF
$(find "$SCAN_DIR" \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" -o -name "*.json" \) -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -maxdepth 6 2>/dev/null)
EOF

# ===================================================================
#  RESULTS
# ===================================================================
printf "${BOLD}================================================${RESET}\n"

if [ "$FINDING_COUNT" -gt 0 ]; then
    printf "  ${RED}${BOLD}BUILD BLOCKED: %d PolinRider indicator(s) found${RESET}\n" "$FINDING_COUNT"
    printf "${BOLD}================================================${RESET}\n\n"
    printf "${BOLD}Findings:${RESET}\n"
    printf "$FINDINGS"
    printf "\n${BOLD}Action required:${RESET} Remove malware before building.\n"
    printf "Full scanner: https://github.com/OpenSourceMalware/PolinRider\n\n"
    exit 1
else
    printf "  ${GREEN}${BOLD}CLEAN: No PolinRider indicators found — build may proceed${RESET}\n"
    printf "${BOLD}================================================${RESET}\n\n"
    exit 0
fi
