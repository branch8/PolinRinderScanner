# 🚨 Action Required: PolinRider Malware Scan

## Background

PolinRider (also known as TasksJacker) is an active DPRK/Lazarus Group supply chain attack campaign. It injects obfuscated JavaScript payloads into GitHub repositories via compromised npm packages, VS Code extensions, and config file injection. As of April 2026, **1,951+ repos / 1,047+ owners** are confirmed compromised.

We have prepared a customized version of the PolinRider scanner tailored for our environment. Please use the link below — do not use other versions you may find online.

We need everyone to follow the steps below, scan their local machines and GitHub repos, then log the results in the shared spreadsheet. **Note: this is not a one-time task.** Re-infection is possible, so you may need to repeat these steps over the coming days until we confirm the environment is fully clean.

---

# ⚠️ Before You Do Anything Else

## 1. Rotate Your GitHub Credentials Immediately

Your GitHub Personal Access Token (PAT) and/or password may have been exfiltrated if this malware reached your machine. Do this *before* running any scan or pushing any code:

- Go to **GitHub → Settings → Developer Settings → Personal Access Tokens**
- Revoke all existing tokens and generate new ones
- If you use password-based authentication, change your GitHub password and enable 2FA if not already active
- Revoke any OAuth app authorizations you don't recognize

## 2. Stop Using VS Code and All VS Code-Based IDEs Immediately

This includes **Cursor**, **Windsurf**, **Antigravity**, and any other editor built on the VS Code engine. Do not reopen them until you have:

- Scanned all your local repos and confirmed that every `.vscode/tasks.json` is either clean or deleted, **and**
- Confirmed no infected VS Code extensions remain on your machine

The malware weaponizes `.vscode/tasks.json` to execute a `curl | bash` payload automatically when you open a project folder in any VS Code-based editor. Opening an infected repo in these editors can re-infect a machine that was just cleaned.

### Recommended Action for tasks.json

Unless you know exactly what a `tasks.json` does and why it is there, **delete it**. It is safe to remove — VS Code re-creates it when needed. When in doubt, delete it.

```bash
# Find all tasks.json files across your projects
find ~/projects -name "tasks.json" -path "*/.vscode/*"

# Delete them all (run only after reviewing or if you want a clean sweep)
find ~/projects -name "tasks.json" -path "*/.vscode/*" -delete
```

Once done, proceed to the scanner below to verify your machine.

---

# 🔍 Run the Scanner

## Step 1 — Download the Scanner

📁 Repository & full documentation: https://github.com/branch8/PolinRiderScanner

### Non-Technical Users

Download the quickstart package and double-click to run. No terminal needed.

| OS | Download |
|---|---|
| macOS | [polinrider-quickstart-mac.command](https://github.com/branch8/PolinRiderScanner/releases/download/latest/polinrider-quickstart-mac.command) |
| Windows | [polinrider-quickstart-windows.bat](https://github.com/branch8/PolinRiderScanner/releases/download/latest/polinrider-quickstart-windows.bat) |

### Technical Users

Clone the repo and follow the README:

```bash
git clone https://github.com/branch8/PolinRiderScanner.git
cd PolinRiderScanner
./polinrider-scan-local.sh --full-system
```

The README covers all flags, scan modes, and how to set up GitHub org scanning.

---

## Step 2 — Run the Scan

If in doubt, run the full system scan.

| What to scan | Command |
|---|---|
| Local projects only | `./polinrider-scan-local.sh ~/projects` |
| Full system scan (recommended) | `./polinrider-scan-local.sh --full-system` |
| Quick check (processes + network) | `./polinrider-scan-local.sh --quick` |
| Your GitHub org's repos | `./polinrider-scan-local.sh --github YOUR_ORG` |

### Windows

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\polinrider-scan-local-windows.ps1
```

The scan takes 2–10 minutes. A log file is saved automatically to the `logs/` folder.

---

## Step 3 — Read Your Results

| Color | Meaning |
|---|---|
| 🔴 Red | Confirmed infection — immediate action required |
| 🟡 Yellow | Suspicious — verify manually |
| 🟢 Green | Clean |

**If infected:** do NOT push any code. Contact the security team immediately and attach the log file from `logs/`.

---

## Step 4 — Fill in the Spreadsheet

📊 PolinRider Scan Results — Team Tracker: https://docs.google.com/spreadsheets/d/17oj2mipRXrydxXYtRijwGf90OThJmDj5GO5CcbH_wiM/edit?gid=2102468253#gid=2102468253

| Field | Details |
|---|---|
| Name | Your name |
| Machine OS | macOS / Windows / Linux |
| Scan type | full-system / quick / local / github |
| Result | Clean / Infected / Suspicious |
| Date scanned | Today's date |
| Infected repo names | Fill in if any, otherwise leave blank |

---

# 🔁 This Is an Ongoing Process

Please expect to repeat this scan for the next several days. Re-infection can happen if:

- A teammate pushes an infected commit to a shared repo you later pull
- A compromised npm package is installed as part of a normal `npm install`
- A `tasks.json` that wasn't caught on the first pass re-executes a payload

Until the entire team has confirmed clean results, treat any new `npm install` or `git pull` as a potential re-exposure event and run a quick scan (`--quick`) afterwards.

We will update you here when it is safe to resume normal IDE use.

---

**If you run into any issues, have questions, or get results you're unsure about — please speak up.** The sooner we know, the faster we can contain it.

Please complete your **first scan and credential rotation by end of today**.
