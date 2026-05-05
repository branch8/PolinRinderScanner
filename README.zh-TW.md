# Branch8 PolinRider Scanner

[English](README.md) | [繁體中文](README.zh-TW.md)

本 repo fork 自 [OpenSourceMalware/PolinRider](README-OFFICIAL.md)，在官方掃描腳本基礎上新增適合 Branch8 工作流程的工具。威脅背景、IOC 與技術細節請見 [README-OFFICIAL.md](README-OFFICIAL.md)。

---

## 腳本分責一覽

| 腳本 | 職責 |
|---|---|
| `polinrider-scan-org.sh` | 掃整個 GitHub org 的所有 repo — bare clone + git grep，覆蓋所有 branch，附即時 progress bar |
| `polinrider-scan-org-history.sh` | 深掃 GitHub org 的 **commit 歷史** — 找出已被修補但仍留在 git 歷史中的感染 |
| `polinrider-scan-local.sh` | 掃**本機裝置**（macOS/Linux）— 本地 repo、執行中程序、持久化機制、瀏覽器擴充套件、全域 npm |
| `polinrider-scan-local-windows.ps1` | 掃**本機裝置**（Windows）— 本地 repo、排程工作、Registry、PS Profile、瀏覽器擴充套件 |

CI 守門器：`.github/workflows/polinrider-scan.yml` — 偵測到感染即 block build。

---

## 前置需求

```bash
gh auth login        # GitHub CLI — org 掃描器必須
```

- **Org 掃描器：** `gh`、`git`、`bash`
- **本機掃描器（macOS/Linux）：** `bash`、標準系統工具（`lsof`、`find`、`grep`）
- **本機掃描器（Windows）：** PowerShell 5.1+
- **CI 守門器：** workflow 自動下載，無需額外設定

---

## 掃整個組織（`polinrider-scan-org.sh`）

bare clone 整個 org 的所有 repo，對所有 branch 執行 `git grep`，一次掃完。Clone 快取在 `scan-bare-clones/`，再次執行時直接 fetch 更新，速度更快。

```bash
# 掃 branch8 org 的所有 repo（預設 6 個平行 worker）
./polinrider-scan-org.sh --github branch8

# 同時掃多個 org
./polinrider-scan-org.sh --github branch8 --github another-org

# 增加平行數（大型 org 更快）
./polinrider-scan-org.sh --github branch8 --parallel 12

# 額外輸出 JSON 報告
./polinrider-scan-org.sh --github branch8 --log-json

# 掃完後刪除 clone（預設保留以便重複使用）
./polinrider-scan-org.sh --github branch8 --clean-repo

# 詳細輸出（顯示每個 repo 的每項檢查）
./polinrider-scan-org.sh --github branch8 --verbose

# 強制重跑，忽略上次的掃描狀態
./polinrider-scan-org.sh --github branch8 --restart
```

**續跑 / 重跑：** 每個 repo 掃完後，結果會寫入 `scan-bare-clones/<owner>/.scan-state/`。下次執行時若偵測到上次的掃描記錄，會提示選擇續跑（跳過已完成的 repo）、重跑或取消。加上 `--restart` 可跳過提示直接重跑。

**輸出位置：**
- `scan-logs/org/scan-<timestamp>.log` — 人類可讀的彙總報告
- `scan-logs/org/result.json` — JSON 報告（需加 `--log-json`）
- `infected-repos/<timestamp>/` — 每個感染 repo 的詳細紀錄
- `scan-bare-clones/<owner>/` — 快取的 bare clone（下次執行直接重用）
- `scan-bare-clones/<owner>/.scan-state/` — 持久化的續跑狀態

---

## 掃 Commit 歷史（`polinrider-scan-org-history.sh`）

同樣採用 bare clone，但會掃描**每一個 commit** 的完整 git 歷史。適合在 repo 已修補後確認歷史 commit 中是否仍殘留感染 — 惡意程式碼只要存在於任何舊 commit，就可透過 `git checkout` 重新帶出。

```bash
# 深掃 org 所有 repo 的完整 git 歷史
./polinrider-scan-org-history.sh --github branch8

# 同時掃多個 org
./polinrider-scan-org-history.sh --github branch8 --github another-org

# 增加平行數
./polinrider-scan-org-history.sh --github branch8 --parallel 12

# JSON 報告
./polinrider-scan-org-history.sh --github branch8 --log-json

# 強制重跑，忽略上次的掃描狀態
./polinrider-scan-org-history.sh --github branch8 --restart
```

> 掃完後會詢問是否保留 clone。預設為 **N（刪除）**，輸入 Y 則保留在 `scan-bare-clones/`。

**續跑 / 重跑：** 與 org scanner 相同 — 每個 repo 掃完後會記錄狀態。下次執行時提示續跑或重跑；加上 `--restart` 可直接重跑。

**輸出位置：**
- `scan-logs/org-history/scan-<timestamp>.log`
- `scan-logs/org-history/result.json`（需加 `--log-json`）
- `infected-repos/<timestamp>/`
- `scan-bare-clones/<owner>/.scan-state/` — 持久化的續跑狀態

---

## 掃本機裝置 — macOS / Linux（`polinrider-scan-local.sh`）

```bash
# 掃目前目錄下的 git repo（預設）
./polinrider-scan-local.sh

# 掃指定目錄
./polinrider-scan-local.sh ~/projects

# 完整系統掃描：程序、網路、持久化、repo、瀏覽器、全域 npm
./polinrider-scan-local.sh --full-system

# 快速掃描：只看執行中程序 + 網路連線
./polinrider-scan-local.sh --quick

# 詳細輸出
./polinrider-scan-local.sh --verbose ~/projects

# 深掃：檢查所有 .js/.mjs/.cjs 檔（不限於已知 config 檔）
./polinrider-scan-local.sh --js-all ~/projects
```

**`--full-system` 涵蓋範圍：**
1. 帶有 payload 標記的執行中 node 程序
2. 對已知 C2 域名的連線（`lsof` + DNS log）
3. LaunchAgents / LaunchDaemons（macOS）/ systemd units（Linux）
4. Crontab 排程
5. Shell profile（`.zshrc`、`.bashrc`、`.bash_profile` 等）
6. VS Code / Cursor 擴充套件目錄 + `tasks.json`
7. 全域 npm 套件
8. 暫存目錄（/tmp）中的可疑檔案
9. 瀏覽器擴充套件（Chrome、Brave、Edge、Firefox）

**自動清理提示：** repo 掃描完成後，腳本會詢問是否自動執行：
- 刪除 `temp_auto_push.bat` 和 `config.bat` 傳播腳本
- 從 `.gitignore` 移除 `config.bat` / `temp_auto_push.bat` 條目
- 刪除含有感染套件的 `node_modules` 目錄（刪除後請重跑 `npm install`）

**輸出位置：**
- `scan-logs/local/scan-<mode>-<timestamp>.log`

---

## 掃本機裝置 — Windows（`polinrider-scan-local-windows.ps1`）

在 PowerShell（5.1+ 或 PowerShell 7）中執行：

```powershell
# 掃目前目錄下的 repo
.\polinrider-scan-local-windows.ps1

# 掃指定目錄
.\polinrider-scan-local-windows.ps1 -ScanDir C:\Projects

# 完整系統掃描
.\polinrider-scan-local-windows.ps1 -FullSystem

# 詳細輸出
.\polinrider-scan-local-windows.ps1 -Verbose -ScanDir C:\Projects
```

**`-FullSystem` 涵蓋範圍：**
- 掃描目錄下的 git repo
- 排程工作（Task Scheduler）
- Registry 開機啟動機碼（HKCU/HKLM）
- 執行中的 node 程序
- Windows 服務
- PowerShell profile
- 全域 npm 套件
- 瀏覽器擴充套件（Chrome、Brave、Edge、Firefox）

**輸出位置：**
- `scan-logs\local-windows\report-<hostname>-<timestamp>.json`

---

## CI/CD 守門器（GitHub Action）

`.github/workflows/polinrider-scan.yml` 在每次 push 和 PR 時自動執行，偵測到惡意程式碼就 exit 1 阻擋 build。Workflow 每次都從本 repo 下載最新版掃描器，**不需要手動同步 signature**。

**單一 repo：** 將 `.github/workflows/polinrider-scan.yml` 複製到目標 repo 的相同路徑即可。

**批次部署到整個 org：**

```bash
WORKFLOW_SRC=".github/workflows/polinrider-scan.yml"
ENCODED=$(base64 -w0 "$WORKFLOW_SRC")
ORG="branch8"

gh repo list "$ORG" --limit 1000 --json name -q '.[].name' | while read repo; do
  [ "$repo" = "PolinRiderScanner" ] && continue

  SHA=$(gh api "repos/$ORG/$repo/contents/.github/workflows/polinrider-scan.yml" \
    --jq '.sha' 2>/dev/null)
  [ -n "$SHA" ] && echo "Skip (已存在): $repo" && continue

  gh api "repos/$ORG/$repo/contents/.github/workflows/polinrider-scan.yml" \
    --method PUT \
    --field message="add PolinRider CI scan blocker" \
    --field content="$ENCODED" \
    > /dev/null 2>&1 \
    && echo "已部署: $repo" \
    || echo "失敗: $repo"
done
```

---

## 掃到感染怎麼辦 — 完整排除步驟

依序處理以下各類型的感染。先從 repo 開始，再處理開發者的本機。

### 1. 受感染的 Config 檔

Config 檔（例如 `tailwind.config.js`、`postcss.config.js`、`next.config.js`、`babel.config.js`、`eslint.config.js`）的惡意 payload 都附加在合法設定之後。

- **Variant 1：** 刪除 `global['!']` 開始之後的所有內容
- **Variant 2：** 刪除 `global['_V']` 開始之後的所有內容

開啟檔案，確認合法設定結束位置，刪除後方所有行，存檔後 commit。

### 2. 假字型檔（`.woff2` / `.woff`）

這些檔案偽裝成字型資源，實際上內含 JavaScript payload。**直接刪除**——它們完全不是合法字型。

```bash
git rm path/to/fake.woff2
```

### 3. 傳播腳本

若存在 `temp_auto_push.bat` 和 `config.bat`，將其刪除，並從 `.gitignore` 移除相關條目：

```bash
git rm temp_auto_push.bat config.bat
# 開啟 .gitignore，移除包含 "config.bat" 和 "temp_auto_push.bat" 的行
```

本機掃描器的自動清理功能可在提示時輸入 **Y** 自動完成此步驟。

### 4. 惡意 npm 套件

掃描器會標記以下套件（仿冒合法套件的惡意 typosquat）：`tailwind-extend`、`tw-animate-css`、`class-switcher`、`switch-classname`、`@nextui/switch`、`@headless-ui/react`、`motion-switch`。

```bash
# 從 package.json 移除並解除安裝
npm uninstall <套件名稱>

# 完整刪除 node_modules 後重新安裝乾淨版本
rm -rf node_modules
npm install

# 確認無惡意套件殘留
npm ls
```

本機掃描器的自動清理功能可自動刪除 `node_modules`，刪除後記得在各專案目錄重跑 `npm install`。

### 5. `.vscode/tasks.json`（TasksJacker）

移除所有包含 `curl | bash`、`curl | sh`、`wget | bash` 的 task 條目。這類 task 會在 VS Code / Cursor 開啟資料夾時自動執行任意程式碼。

### 6. 瀏覽器擴充套件

移除掃描器標記的擴充套件。開啟瀏覽器的擴充套件管理頁面，卸除不認識的擴充套件。

### 7. 系統層面清理（macOS / Linux）

```bash
# 終止可疑 node 程序（PID 見掃描輸出）
kill -9 <PID>

# 移除惡意 LaunchAgent（macOS）
launchctl unload ~/Library/LaunchAgents/<suspicious.plist>
rm ~/Library/LaunchAgents/<suspicious.plist>

# 清理 crontab
crontab -e   # 刪除可疑行

# 清理 shell profile（.zshrc、.bashrc、.bash_profile）
# 開啟後移除任何注入的 "curl | bash" 或 "node -e" 指令行

# 卸除惡意全域 npm 套件
npm uninstall -g <套件名稱>

# 移除惡意 VS Code / Cursor 擴充套件
code --uninstall-extension <ext-id>
# 或直接刪除目錄：rm -rf ~/.vscode/extensions/<ext-folder>
```

### 8. Commit 並 Push 乾淨版本

```bash
git add -A
git commit -m "security: remove PolinRider/TasksJacker payload"
git push --force-with-lease origin <branch>
```

---

## 防止再次感染

攻擊者會主動對已清理的 repo 重新植入。請完成以下所有步驟。

### 輪換憑證

**所有曾在感染環境中執行過 build（npm install、node、webpack 等）的開發者，必須：**

1. 撤銷並重新產生 **GitHub personal access token**（Settings → Developer settings → Personal access tokens）
2. 刪除並重新產生 **SSH 金鑰**（`ssh-keygen`，再至 GitHub Settings → SSH keys 更新）
3. 輪換在該環境中可被存取的所有其他 secret（AWS、GCP、Vercel 等）

> Stage 4 竊密程式以 GitHub token、SSH 金鑰和環境變數為目標。請將 `~/.ssh`、`~/.gitconfig` 及 shell 環境中的所有 secret 視為已外洩。

### 部署 CI 守門器

為所有活躍 repo 加入 `.github/workflows/polinrider-scan.yml`。詳見上方 [CI/CD 守門器](#cicd-守門器github-action) 段落。

### 定期執行 Org 掃描

建議每週排程一次，及早發現再感染：

```bash
# 每週一 09:00 執行
./polinrider-scan-org.sh --github branch8 --log-json
```

### 稽核 Git 歷史

使用 `polinrider-scan-org-history.sh` 確認歷史 commit 中沒有殘留感染。舊的感染 commit 仍可透過 `git checkout` 被帶出，進而重新污染工作目錄。

---

## 團隊成員本機 Checklist

所有曾接觸感染 repo 的開發者，請在自己的機器上依序完成以下步驟。

**第 1 步 — 執行本機掃描**

macOS / Linux：
```bash
./polinrider-scan-local.sh --full-system
```

Windows（PowerShell）：
```powershell
.\polinrider-scan-local-windows.ps1 -FullSystem
```

**第 2 步 — 處理掃描結果**

| 發現類型 | 處置方式 |
|---|---|
| 受感染的 config 檔 | 開啟檔案，刪除 `global['!']` 或 `global['_V']` 開始之後的所有內容 |
| 假 `.woff2` 字型檔 | 直接刪除 |
| 傳播腳本 | 刪除 `temp_auto_push.bat` / `config.bat`；清理 `.gitignore` |
| `node_modules` 含惡意套件 | 刪除 `node_modules`，重跑 `npm install` |
| 惡意全域 npm 套件 | `npm uninstall -g <套件名稱>` |
| 可疑 node 程序 | `kill -9 <PID>` |
| 惡意 LaunchAgent/plist（macOS） | `launchctl unload <path> && rm <path>` |
| 惡意 crontab 條目 | `crontab -e` 刪除該行 |
| 注入的 shell profile 行 | 開啟 `~/.zshrc` / `~/.bashrc` 移除注入行 |
| 惡意 VS Code / Cursor 擴充套件 | `code --uninstall-extension <id>` |
| 可疑瀏覽器擴充套件 | 透過瀏覽器擴充套件管理頁面移除 |

**第 3 步 — 輪換所有憑證**

- 撤銷並重新產生 **GitHub personal access token**
- 刪除並重新產生 **SSH 金鑰**（在 GitHub 上更新）
- 輪換開發環境中可被存取的所有 API key / secret

**第 4 步 — 驗證乾淨**

清理完成後重新執行掃描，確認無任何 finding：

```bash
./polinrider-scan-local.sh --full-system
```

---

*威脅背景、攻擊時間軸、IOC 及 YARA 規則請見 [README-OFFICIAL.md](README-OFFICIAL.md)。*
