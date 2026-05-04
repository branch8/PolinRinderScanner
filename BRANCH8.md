# Branch8 PolinRider Scanner — 使用說明

本 repo fork 自 [OpenSourceMalware/PolinRider](https://opensourcemalware.com)，在官方掃描腳本基礎上新增適合 Branch8 工作流程的工具。威脅背景與技術細節請見 [README.md](README.md)。

---

## 新增內容

| 檔案 | 說明 |
|---|---|
| `polinrider-scanner-fast.sh` | 主力掃描工具。bare clone + git grep，一次掃所有 branch，無需 checkout，支援平行 worker |
| `polinrider-scanner-fast-progress.sh` | 同上，附即時 progress bar |
| `polinrider-ci-scan-blocker.sh` | CI/CD 守門器。掃 working tree，有感染就 exit 1 block build |
| `polinrider-prebuild-react-native.sh` | React Native 專案用，可整合進 Xcode Build Phase |
| `polinrider-scanner-windows.ps1` | Windows 開發者自查用（PowerShell） |
| `.github/workflows/polinrider-scan.yml` | GitHub Action 模板，複製到各 repo 即可啟用 CI 掃描 |

**官方 `polinrider-scanner.sh` 的更新：**
- 平行 worker 3 → 6，clone delay 2s → 0.5s（大幅提速）
- 新增 `--log-json` 輸出 JSON 報告
- 新增 `--parallel <n>` / `--clone-delay <s>` 可調參數
- 加入 progress counter

---

## 腳本選擇

| 情境 | 用哪隻 |
|---|---|
| 掃整個 org（所有 repo、所有 branch） | `polinrider-scanner-fast.sh` |
| 同上，想看即時進度 | `polinrider-scanner-fast-progress.sh` |
| 掃本機 Mac 系統（LaunchAgents、瀏覽器、npm global） | `polinrider-scanner.sh --full-system` |
| CI pipeline 守門 | `polinrider-ci-scan-blocker.sh` 或 GitHub Action |
| Windows 開發者自查 | `polinrider-scanner-windows.ps1` |

---

## 掃整個組織

```bash
# 掃 branch8 org 所有 repo 的所有 branch
./polinrider-scanner-fast.sh --github branch8

# 附 progress bar
./polinrider-scanner-fast-progress.sh --github branch8

# 輸出 JSON 報告
./polinrider-scanner-fast.sh --github branch8 --log-json

# 調整平行數（預設 6）
./polinrider-scanner-fast.sh --github branch8 --parallel 10
```

掃描結果：
- `infected-repos/<timestamp>/` — 每個感染 repo 的詳細 log
- `logs/report-github-branch8-<timestamp>.txt` — 彙總報告

需要 `gh` CLI 並已登入：`gh auth login`

---

## 部署 GitHub Action 到各 repo

`.github/workflows/polinrider-scan.yml` 是各 repo 的 CI 守門模板。部署後每次 push / PR 自動從本 repo 下載最新版 `polinrider-ci-scan-blocker.sh` 執行，**不需要手動同步 signature**。

**單一 repo：** 複製 `.github/workflows/polinrider-scan.yml` 到目標 repo 的同路徑即可。

**批次部署到整個 org：**

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

## 掃完有感染怎麼辦

1. 找到感染的 config 檔（`tailwind.config.js`、`postcss.config.js` 等）
2. 移除檔案末尾的惡意程式碼（從 `global['!']` 或 `global['_V']` 開始的所有內容）
3. 刪除 `temp_auto_push.bat`、`config.bat`（若存在）
4. 移除 `.gitignore` 裡的 `config.bat` 條目
5. 移除 `package.json` 裡的惡意 npm 套件並重跑 `npm install`
6. Force push 乾淨版本到 GitHub
7. **所有曾在感染環境跑過 build 的開發者**：輪換 GitHub token 及 SSH key
