#!/bin/bash
#
# PolinRider Quick Scan — macOS
#
# 使用方式：
#   第一次：右鍵 → 「開啟」→ 點「開啟」（繞過 Gatekeeper）
#   之後：直接雙擊即可
#

# 移到腳本所在目錄（讓 log 存在桌面旁邊）
cd "$(dirname "$0")" 2>/dev/null || cd "$HOME"

SCANNER_URL="https://raw.githubusercontent.com/branch8/PolinRiderScanner/main/polinrider-scan-local.sh"
SCANNER_DST="$(dirname "$0")/polinrider-scan-local.sh"

clear
echo "================================================"
echo "  PolinRider Malware Scanner — macOS Quick Start"
echo "  Branch8 Edition — Customized by Glenn Cheng"
echo "  https://github.com/branch8/PolinRiderScanner"
echo "================================================"
echo ""

# Download latest scanner
echo "Downloading latest scanner..."
if ! curl -fsSL "$SCANNER_URL" -o "$SCANNER_DST" 2>/dev/null; then
    echo ""
    echo "ERROR: Download failed. Please check your internet connection and try again."
    echo ""
    read -rp "Press Enter to close..." _
    exit 1
fi
chmod +x "$SCANNER_DST"
echo "Download complete."
echo ""
echo "Starting full system scan. This may take a few minutes..."
echo ""

bash "$SCANNER_DST" --full-system

echo ""
read -rp "Scan complete. Press Enter to close this window..." _
