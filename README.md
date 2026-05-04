# Branch8 PolinRider Scanner

[English](README.md) | [繁體中文](README.zh-TW.md)

Branch8's fork of the [official PolinRider scanner](README-OFFICIAL.md) by OpenSourceMalware, extended with tools tailored for the Branch8 workflow. For threat background and technical details, see [README-OFFICIAL.md](README-OFFICIAL.md).

---

## What Was Added

| File | Description |
|---|---|
| `polinrider-scanner-fast.sh` | **Primary scanning tool.** Bare clone + git grep — scans all branches in one pass without checkout. Parallel workers supported. |
| `polinrider-scanner-fast-progress.sh` | Same as above with a live progress bar. |
| `polinrider-ci-scan-blocker.sh` | CI/CD gate. Scans the working tree and exits 1 to block the build if infection is found. |
| `polinrider-prebuild-react-native.sh` | React Native variant. Can be integrated into Xcode Build Phases. |
| `polinrider-scanner-windows.ps1` | Windows self-check tool for developers (PowerShell). |
| `.github/workflows/polinrider-scan.yml` | GitHub Actions template. Copy into any repo to enable CI scanning. |

**Updates to the upstream `polinrider-scanner.sh`:**
- Parallel workers 3 → 6, clone delay 2s → 0.5s (significantly faster)
- Added `--log-json` for JSON report output
- Added `--parallel <n>` and `--clone-delay <s>` flags
- Added a live progress counter

---

## Which Script to Use

| Scenario | Script |
|---|---|
| Scan the entire org (all repos, all branches) | `polinrider-scanner-fast.sh` |
| Same, with live progress bar | `polinrider-scanner-fast-progress.sh` |
| Scan local Mac (LaunchAgents, browsers, npm global, etc.) | `polinrider-scanner.sh --full-system` |
| CI pipeline gate | `polinrider-ci-scan-blocker.sh` or GitHub Action |
| Windows developer self-check | `polinrider-scanner-windows.ps1` |

---

## Scanning the Entire Org

```bash
# Scan all repos and all branches in the branch8 org
./polinrider-scanner-fast.sh --github branch8

# With live progress bar
./polinrider-scanner-fast-progress.sh --github branch8

# Output a JSON report
./polinrider-scanner-fast.sh --github branch8 --log-json

# Adjust parallel workers (default: 6)
./polinrider-scanner-fast.sh --github branch8 --parallel 10
```

Output locations:
- `infected-repos/<timestamp>/` — per-repo detailed logs for infected repos
- `logs/report-github-branch8-<timestamp>.txt` — summary report

Requires `gh` CLI authenticated: `gh auth login`

---

## Deploying the GitHub Action to Repos

`.github/workflows/polinrider-scan.yml` is a ready-to-use CI gate template. Once deployed, every push and PR automatically downloads the latest `polinrider-ci-scan-blocker.sh` from this repo and runs it — **no manual signature syncing needed**.

**Single repo:** Copy `.github/workflows/polinrider-scan.yml` into the target repo at the same path.

**Batch deploy to all org repos:**

```bash
WORKFLOW_SRC=".github/workflows/polinrider-scan.yml"
ENCODED=$(base64 -w0 "$WORKFLOW_SRC")
ORG="branch8"

gh repo list "$ORG" --limit 1000 --json name -q '.[].name' | while read repo; do
  [ "$repo" = "PolinRinderScanner" ] && continue

  SHA=$(gh api "repos/$ORG/$repo/contents/.github/workflows/polinrider-scan.yml" \
    --jq '.sha' 2>/dev/null)
  [ -n "$SHA" ] && echo "⏭️  Skip (already exists): $repo" && continue

  gh api "repos/$ORG/$repo/contents/.github/workflows/polinrider-scan.yml" \
    --method PUT \
    --field message="add PolinRider CI scan blocker" \
    --field content="$ENCODED" \
    > /dev/null 2>&1 \
    && echo "✅ Deployed: $repo" \
    || echo "❌ Failed: $repo"
done
```

---

## If Infections Are Found

1. Locate the infected config file (`tailwind.config.js`, `postcss.config.js`, etc.)
2. Remove the malicious payload appended at the end of the file — everything from `global['!']` or `global['_V']` onwards
3. Delete `temp_auto_push.bat` and `config.bat` if present
4. Remove the `config.bat` entry from `.gitignore`
5. Remove any malicious npm packages from `package.json` and re-run `npm install`
6. Delete any `.woff2` / `.woff` files flagged by the scanner
7. Force-push the clean version to GitHub
8. **Any developer who ran a build in the compromised environment must rotate their GitHub token and SSH key**
