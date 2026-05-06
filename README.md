# Branch8 PolinRider Scanner

[English](README.md) | [繁體中文](README.zh-TW.md)

Branch8's fork of the [official PolinRider scanner](README-OFFICIAL.md) by OpenSourceMalware, extended with tools tailored for the Branch8 workflow. For threat background, IOCs, and technical details see [README-OFFICIAL.md](README-OFFICIAL.md).

---

## Scripts at a Glance

| Script | Responsibility |
|---|---|
| `polinrider-scan-org.sh` | Scan all repos of a GitHub org — bare clone + git grep, all branches, live progress bar |
| `polinrider-scan-org-history.sh` | Deep-scan commit **history** of a GitHub org — catches infections that were already patched but remain in git history |
| `polinrider-scan-local.sh` | Scan the **current device** (macOS/Linux) — repos, processes, persistence, browser extensions, npm global |
| `polinrider-scan-local-windows.ps1` | Scan the **current device** (Windows) — repos, scheduled tasks, registry, PS profiles, browser extensions |
| `polinrider-quickstart-mac.command` | **Non-technical users (macOS)** — double-click to run, downloads latest scanner automatically |
| `polinrider-quickstart-windows.bat` | **Non-technical users (Windows)** — double-click to run, downloads latest scanner automatically |

CI gate: `.github/workflows/polinrider-scan.yml` — blocks builds on infected working trees.

---

## Prerequisites

```bash
gh auth login        # GitHub CLI — required for org scanners
```

- **Org scanners:** `gh`, `git`, `bash`
- **Local scanner (macOS/Linux):** `bash`, standard system tools (`lsof`, `find`, `grep`)
- **Local scanner (Windows):** PowerShell 5.1+
- **CI gate:** automatically downloaded by the workflow, no setup needed

---

## Scan the Entire Org (`polinrider-scan-org.sh`)

Bare-clones every repo in the org and runs `git grep` across all branches in one pass. Caches clones in `scan-bare-clones/` for faster re-runs.

```bash
# Scan all repos of an org (6 parallel workers by default)
./polinrider-scan-org.sh --github branch8

# Multiple orgs in one run
./polinrider-scan-org.sh --github branch8 --github another-org

# More parallel workers (faster on large orgs)
./polinrider-scan-org.sh --github branch8 --parallel 12

# Also output a JSON report
./polinrider-scan-org.sh --github branch8 --log-json

# Delete cloned repos after scan (default: keep for re-use)
./polinrider-scan-org.sh --github branch8 --clean-repo

# Verbose output (shows every check per repo)
./polinrider-scan-org.sh --github branch8 --verbose

# Force a full rescan, ignoring any previous scan state
./polinrider-scan-org.sh --github branch8 --restart
```

**Resume / Restart:** Scan state is saved in `scan-bare-clones/<owner>/.scan-state/` after each repo completes. On the next run you will be prompted to resume (skip already-done repos), restart from scratch, or cancel. Use `--restart` to skip the prompt and force a full rescan.

**Output:**
- `scan-logs/org/scan-<timestamp>.log` — human-readable summary
- `scan-logs/org/result.json` — JSON report (with `--log-json`)
- `infected-repos/<timestamp>/` — per-repo detail for every infected repo
- `scan-bare-clones/<owner>/` — cached bare clones (reused on next run)
- `scan-bare-clones/<owner>/.scan-state/` — persistent resume state

---

## Scan Commit History (`polinrider-scan-org-history.sh`)

Same bare-clone approach, but scans **every commit** across the full git history. Use this when a repo has already been patched — the infection may still live in an old commit and be accessible via `git checkout`.

```bash
# Scan full git history of all repos in an org
./polinrider-scan-org-history.sh --github branch8

# Multiple orgs
./polinrider-scan-org-history.sh --github branch8 --github another-org

# More workers
./polinrider-scan-org-history.sh --github branch8 --parallel 12

# JSON report
./polinrider-scan-org-history.sh --github branch8 --log-json

# Force a full rescan, ignoring any previous scan state
./polinrider-scan-org-history.sh --github branch8 --restart
```

> When the scan finishes you will be prompted whether to keep the cloned repos.
> Default answer is **N (delete)** — press Y to keep them in `scan-bare-clones/`.

**Resume / Restart:** Same as the org scanner — state is saved per repo. On the next run you will be prompted to resume or restart. Use `--restart` to force a full rescan without prompting.

**Output:**
- `scan-logs/org-history/scan-<timestamp>.log`
- `scan-logs/org-history/result.json` (with `--log-json`)
- `infected-repos/<timestamp>/`
- `scan-bare-clones/<owner>/.scan-state/` — persistent resume state

---

## Scan a Local Device — macOS / Linux (`polinrider-scan-local.sh`)

```bash
# Scan git repos under the current directory (default)
./polinrider-scan-local.sh

# Scan a specific directory
./polinrider-scan-local.sh ~/projects

# Full device scan: processes, network, persistence, repos, browsers, npm global
./polinrider-scan-local.sh --full-system

# Quick scan: running processes + active network connections only
./polinrider-scan-local.sh --quick

# Verbose output
./polinrider-scan-local.sh --verbose ~/projects

# Deep scan: check all .js/.mjs/.cjs files (not just known config files)
./polinrider-scan-local.sh --js-all ~/projects
```

**What `--full-system` covers:**
1. Running node processes with payload markers
2. Active connections to known C2 domains (`lsof` + DNS log)
3. LaunchAgents / LaunchDaemons (macOS) / systemd units (Linux)
4. Crontab entries
5. Shell profiles (`.zshrc`, `.bashrc`, `.bash_profile`, etc.)
6. VS Code / Cursor extension directories + `tasks.json`
7. Global npm packages
8. Temp directory artifacts
9. Browser extensions (Chrome, Brave, Edge, Firefox)

**Auto-cleanup prompt:** After a repo scan, the scanner will offer to automatically:
- Delete `temp_auto_push.bat` and `config.bat` propagation scripts
- Remove `config.bat` / `temp_auto_push.bat` entries from `.gitignore`
- Delete `node_modules` directories that contain infected packages (re-run `npm install` after)

**Output:**
- `scan-logs/local/scan-<mode>-<timestamp>.log`

---

## Scan a Local Device — Windows (`polinrider-scan-local-windows.ps1`)

Run in PowerShell (5.1+ or PowerShell 7):

```powershell
# Scan repos under current directory
.\polinrider-scan-local-windows.ps1

# Scan a specific directory
.\polinrider-scan-local-windows.ps1 -ScanDir C:\Projects

# Full device scan
.\polinrider-scan-local-windows.ps1 -FullSystem

# Verbose output
.\polinrider-scan-local-windows.ps1 -Verbose -ScanDir C:\Projects
```

**What `-FullSystem` covers:**
- Git repos under the scan directory
- Scheduled tasks (Task Scheduler)
- Registry run keys (HKCU/HKLM)
- Running node processes
- Windows services
- PowerShell profiles
- Global npm packages
- Browser extensions (Chrome, Brave, Edge, Firefox)

**Output:**
- `scan-logs\local-windows\report-<hostname>-<timestamp>.json`

---

## Non-Technical User Quick Start

For team members who are not comfortable with the terminal. No git clone, no command line — just download and double-click.

### macOS — `polinrider-quickstart-mac.command`

1. Download `polinrider-quickstart-mac.command` to anywhere (e.g. Desktop)
2. **First time only:** right-click → **Open** → click **Open** (bypasses Gatekeeper)
3. From then on: double-click directly
4. Terminal opens automatically, downloads the latest scanner, runs a full system scan, and keeps the window open so you can read the results

### Windows — `polinrider-quickstart-windows.bat`

1. Download `polinrider-quickstart-windows.bat` to anywhere (e.g. Desktop)
2. Double-click — no special setup needed
3. PowerShell opens automatically, downloads the latest scanner, runs a full system scan, and keeps the window open so you can read the results

> Both launchers always download the latest scanner from GitHub on each run, so they stay up to date without any manual steps.

---

## CI/CD Gate (GitHub Action)

`.github/workflows/polinrider-scan.yml` blocks every push and PR if the working tree contains malware. The workflow always downloads the latest scanner from this repo — no manual signature syncing needed.

**Deploy to a single repo:** copy `.github/workflows/polinrider-scan.yml` to the same path in the target repo.

**Batch deploy to all org repos:**

```bash
WORKFLOW_SRC=".github/workflows/polinrider-scan.yml"
ENCODED=$(base64 -w0 "$WORKFLOW_SRC")
ORG="branch8"

gh repo list "$ORG" --limit 1000 --json name -q '.[].name' | while read repo; do
  [ "$repo" = "PolinRiderScanner" ] && continue

  SHA=$(gh api "repos/$ORG/$repo/contents/.github/workflows/polinrider-scan.yml" \
    --jq '.sha' 2>/dev/null)
  [ -n "$SHA" ] && echo "Skip (already exists): $repo" && continue

  gh api "repos/$ORG/$repo/contents/.github/workflows/polinrider-scan.yml" \
    --method PUT \
    --field message="add PolinRider CI scan blocker" \
    --field content="$ENCODED" \
    > /dev/null 2>&1 \
    && echo "Deployed: $repo" \
    || echo "Failed: $repo"
done
```

---

## If Infections Are Found — Full Remediation

Work through each category that applies. Start with the repo, then the developer's local machine.

### 1. Infected Config Files

Config files (e.g. `tailwind.config.js`, `postcss.config.js`, `next.config.js`, `babel.config.js`, `eslint.config.js`) have the malicious payload appended after the legitimate content.

- **Variant 1:** remove everything from `global['!']` onwards
- **Variant 2:** remove everything from `global['_V']` onwards

Open the file, identify the legitimate config block, delete all lines after it, save, and commit.

### 2. Fake Font Files (`.woff2` / `.woff`)

These files contain embedded JavaScript payloads disguised as font assets. **Delete them entirely** — they are not real fonts.

```bash
git rm path/to/fake.woff2
```

### 3. Propagation Scripts

Delete `temp_auto_push.bat` and `config.bat` if present. Also remove their entries from `.gitignore`:

```bash
git rm temp_auto_push.bat config.bat
# Edit .gitignore and remove lines containing "config.bat" and "temp_auto_push.bat"
```

The local scanner's auto-cleanup can do this automatically when you answer **Y** at the prompt.

### 4. Malicious npm Packages

The scanner flags packages such as `tailwind-extend`, `tw-animate-css`, `class-switcher`, `switch-classname`, `@nextui/switch`, `@headless-ui/react`, `motion-switch` (typosquats of legitimate packages).

```bash
# Remove from package.json manually or with npm
npm uninstall <package-name>

# Delete node_modules entirely and reinstall clean
rm -rf node_modules
npm install

# Verify no malicious packages remain
npm ls
```

The local scanner's auto-cleanup can delete `node_modules` automatically. Re-run `npm install` in each affected project afterwards.

### 5. `.vscode/tasks.json` (TasksJacker)

Remove any task entries that contain `curl | bash`, `curl | sh`, or `wget | bash` patterns. These run arbitrary code on every folder open in VS Code/Cursor.

### 6. Browser Extensions

Remove any extensions flagged by the scanner. Open your browser's extension manager and uninstall unrecognized extensions.

### 7. System-Level Cleanup (macOS / Linux)

```bash
# Kill suspicious node processes (use PIDs from scan output)
kill -9 <PID>

# Remove malicious LaunchAgents (macOS)
launchctl unload ~/Library/LaunchAgents/<suspicious.plist>
rm ~/Library/LaunchAgents/<suspicious.plist>

# Remove malicious crontab entries
crontab -e   # delete suspicious lines

# Clean shell profiles (.zshrc, .bashrc, .bash_profile)
# Review and remove any injected "curl | bash" or "node -e" lines

# Uninstall malicious global npm packages
npm uninstall -g <package-name>

# Remove malicious VS Code/Cursor extensions
code --uninstall-extension <ext-id>
# OR delete directly: rm -rf ~/.vscode/extensions/<ext-folder>
```

### 8. Commit and Push Clean Version

```bash
git add -A
git commit -m "security: remove PolinRider/TasksJacker payload"
git push --force-with-lease origin <branch>
```

---

## Preventing Re-Infection

The threat actor actively re-infects cleaned repos. Take all of the following steps.

### Rotate Credentials

**Any developer who ran a build (npm install, node, webpack, etc.) in the compromised environment must:**

1. Revoke and regenerate their **GitHub personal access token** (Settings → Developer settings → Personal access tokens)
2. Delete and regenerate their **SSH key** used for GitHub (`ssh-keygen`, then update under GitHub Settings → SSH keys)
3. Rotate any other secrets that were accessible in that environment (AWS, GCP, Vercel, etc.)

> The Stage 4 credential stealer targets GitHub tokens, SSH keys, and environment variables. Assume anything in `~/.ssh`, `~/.gitconfig`, and shell environment was exfiltrated.

### Deploy the CI Gate

Add `.github/workflows/polinrider-scan.yml` to every active repo. See the [CI/CD Gate](#cicd-gate-github-action) section above.

### Run Org Scans Regularly

Schedule a weekly org scan to catch re-infections early:

```bash
# Run every Monday at 09:00
./polinrider-scan-org.sh --github branch8 --log-json
```

### Check Git History

Use `polinrider-scan-org-history.sh` to verify that no infection remains in any historical commit. Old infected commits are still accessible via `git checkout` and can re-contaminate a working tree.

---

## Team Member Local Machine Checklist

Every developer who worked on an affected repo should go through this checklist on their own machine.

**Step 1 — Run the local scanner**

macOS / Linux:
```bash
./polinrider-scan-local.sh --full-system
```

Windows (PowerShell):
```powershell
.\polinrider-scan-local-windows.ps1 -FullSystem
```

**Step 2 — Act on findings**

| Finding category | Action |
|---|---|
| Infected config file | Open the file, delete everything from `global['!']` or `global['_V']` onwards |
| Fake `.woff2` file | Delete the file |
| Propagation scripts | Delete `temp_auto_push.bat` / `config.bat`; clean `.gitignore` |
| Malicious npm package in `node_modules` | Delete `node_modules`, run `npm install` |
| Malicious global npm package | `npm uninstall -g <package>` |
| Suspicious node process | `kill -9 <PID>` |
| Malicious LaunchAgent/plist (macOS) | `launchctl unload <path> && rm <path>` |
| Malicious crontab entry | `crontab -e` and remove the line |
| Injected shell profile line | Open `~/.zshrc` / `~/.bashrc` and remove injected lines |
| Malicious VS Code/Cursor extension | `code --uninstall-extension <id>` |
| Suspicious browser extension | Remove via browser extension manager |

**Step 3 — Rotate all credentials**

- Revoke and regenerate your **GitHub personal access token**
- Delete and regenerate your **SSH key** (update on GitHub)
- Rotate any other API keys / secrets accessible from your dev environment

**Step 4 — Verify clean**

Re-run the scanner after cleanup to confirm no findings remain:

```bash
./polinrider-scan-local.sh --full-system
```

---

*For threat background, campaign timeline, IOCs, and YARA rules, see [README-OFFICIAL.md](README-OFFICIAL.md).*
