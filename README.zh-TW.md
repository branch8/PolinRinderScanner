# Branch8 PolinRider Scanner

[English](README.md) | [繁體中文](README.zh-TW.md)

Fork 自 [OpenSourceMalware/PolinRider](README-OFFICIAL.md)，在官方掃描腳本的基礎上加了一些適合 Branch8 工作流程的工具。威脅背景、IOC 跟技術細節請看 [README-OFFICIAL.md](README-OFFICIAL.md)。

---

## 腳本分責

| 腳本 | 做什麼 |
|---|---|
| `polinrider-scan-org.sh` | 掃整個 GitHub org 的所有 repo — bare clone + git grep，一次掃完所有 branch，有即時 progress bar |
| `polinrider-scan-org-history.sh` | 深掃 GitHub org 的 **commit 歷史** — 抓出已修補但還留在 git 歷史裡的感染 |
| `polinrider-scan-local.sh` | 掃**本機**（macOS/Linux）— 本地 repo、執行中的程序、持久化機制、瀏覽器擴充套件、全域 npm |
| `polinrider-scan-local-windows.ps1` | 掃**本機**（Windows）— 本地 repo、排程工作、Registry、PS Profile、瀏覽器擴充套件 |

CI 守門器：`.github/workflows/polinrider-scan.yml` — 有感染就 block build。

---

## 事前準備

```bash
gh auth login        # GitHub CLI — org 掃描器需要
```

- **Org 掃描器：** `gh`、`git`、`bash`
- **本機掃描器（macOS/Linux）：** `bash`，標準系統工具（`lsof`、`find`、`grep`）
- **本機掃描器（Windows）：** PowerShell 5.1+
- **CI 守門器：** workflow 自己會下載，不用額外設定

---

## 掃整個組織（`polinrider-scan-org.sh`）

Bare clone 整個 org 的所有 repo，對所有 branch 跑 `git grep`，一次掃完。Clone 會存在 `scan-bare-clones/`，下次跑直接 fetch 更新，不用重新 clone。

```bash
# 掃 branch8 org 的所有 repo（預設 6 個平行 worker）
./polinrider-scan-org.sh --github branch8

# 同時掃多個 org
./polinrider-scan-org.sh --github branch8 --github another-org

# 加大平行數，大型 org 跑更快
./polinrider-scan-org.sh --github branch8 --parallel 12

# 另外輸出 JSON 報告
./polinrider-scan-org.sh --github branch8 --log-json

# 掃完刪掉 clone（預設是留著，方便下次重跑）
./polinrider-scan-org.sh --github branch8 --clean-repo

# 詳細輸出（每個 repo 的每項檢查都印出來）
./polinrider-scan-org.sh --github branch8 --verbose
```

**輸出位置：**
- `scan-logs/org/scan-<timestamp>.log` — 掃描彙總
- `scan-logs/org/result.json` — JSON 報告（需加 `--log-json`）
- `infected-repos/<timestamp>/` — 每個感染 repo 的詳細紀錄
- `scan-bare-clones/<owner>/` — 快取的 bare clone

---

## 掃 Commit 歷史（`polinrider-scan-org-history.sh`）

一樣是 bare clone，但會掃**每一個 commit** 的完整 git 歷史。適合在 repo 修完之後確認舊 commit 裡有沒有殘留 — 惡意程式碼只要存在某個舊 commit，`git checkout` 就能把它帶回來。

```bash
# 深掃 org 所有 repo 的完整 git 歷史
./polinrider-scan-org-history.sh --github branch8

# 同時掃多個 org
./polinrider-scan-org-history.sh --github branch8 --github another-org

# 加大平行數
./polinrider-scan-org-history.sh --github branch8 --parallel 12

# JSON 報告
./polinrider-scan-org-history.sh --github branch8 --log-json
```

> 掃完會問要不要保留 clone。預設是 **N（刪掉）**，輸入 Y 則保留在 `scan-bare-clones/`。

**輸出位置：**
- `scan-logs/org-history/scan-<timestamp>.log`
- `scan-logs/org-history/result.json`（需加 `--log-json`）
- `infected-repos/<timestamp>/`

---

## 掃本機 — macOS / Linux（`polinrider-scan-local.sh`）

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

# 深掃：把所有 .js/.mjs/.cjs 都掃過（不限於已知的 config 檔）
./polinrider-scan-local.sh --js-all ~/projects
```

**`--full-system` 會掃哪些東西：**
1. 帶有 payload 標記的執行中 node 程序
2. 對已知 C2 網域的連線（`lsof` + DNS log）
3. LaunchAgents / LaunchDaemons（macOS）/ systemd units（Linux）
4. Crontab 排程
5. Shell profile（`.zshrc`、`.bashrc`、`.bash_profile` 等）
6. VS Code / Cursor 擴充套件目錄 + `tasks.json`
7. 全域 npm 套件
8. 暫存目錄（/tmp）的可疑檔案
9. 瀏覽器擴充套件（Chrome、Brave、Edge、Firefox）

**自動清理：** repo 掃完後，腳本會問要不要自動處理：
- 刪掉 `temp_auto_push.bat` 和 `config.bat` 這兩個傳播腳本
- 從 `.gitignore` 移除 `config.bat` / `temp_auto_push.bat` 的條目
- 刪掉含有感染套件的 `node_modules`（刪完記得重跑 `npm install`）

**輸出位置：**
- `scan-logs/local/scan-<mode>-<timestamp>.log`

---

## 掃本機 — Windows（`polinrider-scan-local-windows.ps1`）

在 PowerShell（5.1+ 或 PowerShell 7）裡跑：

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

**`-FullSystem` 會掃哪些東西：**
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

`.github/workflows/polinrider-scan.yml` 每次 push 跟 PR 都會自動跑，有惡意程式碼就 exit 1 阻擋 build。Workflow 每次都從這個 repo 抓最新版掃描器，**不用手動同步 signature**。

**單一 repo：** 把 `.github/workflows/polinrider-scan.yml` 複製到目標 repo 的相同路徑就好。

**一次部署到整個 org：**

```bash
WORKFLOW_SRC=".github/workflows/polinrider-scan.yml"
ENCODED=$(base64 -w0 "$WORKFLOW_SRC")
ORG="branch8"

gh repo list "$ORG" --limit 1000 --json name -q '.[].name' | while read repo; do
  [ "$repo" = "PolinRiderScanner" ] && continue

  SHA=$(gh api "repos/$ORG/$repo/contents/.github/workflows/polinrider-scan.yml" \
    --jq '.sha' 2>/dev/null)
  [ -n "$SHA" ] && echo "Skip（已存在）: $repo" && continue

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

## 掃到感染怎麼處理

依序處理下面各類型。先清 repo，再處理自己的機器。

### 1. 受感染的 Config 檔

Config 檔（`tailwind.config.js`、`postcss.config.js`、`next.config.js`、`babel.config.js`、`eslint.config.js` 等）的惡意 payload 都是附加在合法設定的後面。

- **Variant 1：** 把 `global['!']` 開始往後的內容全部刪掉
- **Variant 2：** 把 `global['_V']` 開始往後的內容全部刪掉

找到合法設定結束的地方，後面的全刪，存檔後 commit。

### 2. 假字型檔（`.woff2` / `.woff`）

這些檔案偽裝成字型資源，裡面其實是 JavaScript payload，**直接刪掉**就好，它們不是真正的字型。

```bash
git rm path/to/fake.woff2
```

### 3. 傳播腳本

有 `temp_auto_push.bat` 或 `config.bat` 的話，把它們刪掉，`.gitignore` 裡的相關條目也一起移除：

```bash
git rm temp_auto_push.bat config.bat
# 開 .gitignore，把 "config.bat" 跟 "temp_auto_push.bat" 那幾行刪掉
```

本機掃描器的自動清理提示輸入 **Y** 的話可以自動處理這步。

### 4. 惡意 npm 套件

掃描器會標出這幾個套件（仿冒合法套件的惡意 typosquat）：`tailwind-extend`、`tw-animate-css`、`class-switcher`、`switch-classname`、`@nextui/switch`、`@headless-ui/react`、`motion-switch`。

```bash
# 從 package.json 移除
npm uninstall <套件名稱>

# 整個 node_modules 刪掉重裝
rm -rf node_modules
npm install

# 確認沒有殘留
npm ls
```

本機掃描器的自動清理可以幫你刪 `node_modules`，刪完記得在每個專案目錄重跑 `npm install`。

### 5. `.vscode/tasks.json`（TasksJacker）

把所有包含 `curl | bash`、`curl | sh`、`wget | bash` 的 task 條目移掉。這類 task 只要用 VS Code / Cursor 開資料夾就會自動執行。

### 6. 瀏覽器擴充套件

把掃描器標出來的擴充套件移除。開瀏覽器的擴充套件管理頁，把不認識的都卸掉。

### 7. 系統層面清理（macOS / Linux）

```bash
# 砍掉可疑的 node 程序（PID 從掃描輸出找）
kill -9 <PID>

# 移除惡意 LaunchAgent（macOS）
launchctl unload ~/Library/LaunchAgents/<suspicious.plist>
rm ~/Library/LaunchAgents/<suspicious.plist>

# 清 crontab
crontab -e   # 把可疑的行刪掉

# 清 shell profile（.zshrc、.bashrc、.bash_profile）
# 找到注入的 "curl | bash" 或 "node -e" 那幾行，刪掉

# 卸掉惡意的全域 npm 套件
npm uninstall -g <套件名稱>

# 移除惡意的 VS Code / Cursor 擴充套件
code --uninstall-extension <ext-id>
# 或直接刪目錄：rm -rf ~/.vscode/extensions/<ext-folder>
```

### 8. Commit 並 Push 乾淨版本

```bash
git add -A
git commit -m "security: remove PolinRider/TasksJacker payload"
git push --force-with-lease origin <branch>
```

---

## 防止再次被植入

攻擊者會主動對清完的 repo 重新植入，以下步驟都要做。

### 輪換憑證

**只要在感染的環境下跑過 build（npm install、node、webpack 等），就必須：**

1. 撤銷並重新產生 **GitHub personal access token**（Settings → Developer settings → Personal access tokens）
2. 刪掉並重新產生 **SSH 金鑰**（`ssh-keygen`，再去 GitHub Settings → SSH keys 更新）
3. 輪換那個環境裡拿得到的所有其他 secret（AWS、GCP、Vercel 等）

> Stage 4 竊密程式鎖定 GitHub token、SSH 金鑰跟環境變數。`~/.ssh`、`~/.gitconfig` 跟 shell 環境裡的東西都要當作已外洩來處理。

### 部署 CI 守門器

所有活躍的 repo 都要加 `.github/workflows/polinrider-scan.yml`。詳見上方 [CI/CD 守門器](#cicd-守門器github-action)。

### 定期跑 Org 掃描

建議每週排一次，及早發現再感染：

```bash
./polinrider-scan-org.sh --github branch8 --log-json
```

### 稽核 Git 歷史

用 `polinrider-scan-org-history.sh` 確認舊 commit 裡沒有殘留。感染的 commit 只要還在歷史裡，`git checkout` 就能把它帶回來，重新污染工作目錄。

---

## 團隊成員本機 Checklist

所有碰過感染 repo 的人，請在自己的機器上跑一遍。

**第 1 步 — 跑本機掃描**

macOS / Linux：
```bash
./polinrider-scan-local.sh --full-system
```

Windows（PowerShell）：
```powershell
.\polinrider-scan-local-windows.ps1 -FullSystem
```

**第 2 步 — 有 finding 的話**

| Finding 類型 | 怎麼處理 |
|---|---|
| 受感染的 config 檔 | 開檔案，把 `global['!']` 或 `global['_V']` 往後的內容全刪掉 |
| 假 `.woff2` 字型檔 | 直接刪掉 |
| 傳播腳本 | 刪掉 `temp_auto_push.bat` / `config.bat`；清理 `.gitignore` |
| `node_modules` 含惡意套件 | 刪掉 `node_modules`，重跑 `npm install` |
| 惡意全域 npm 套件 | `npm uninstall -g <套件名稱>` |
| 可疑 node 程序 | `kill -9 <PID>` |
| 惡意 LaunchAgent/plist（macOS） | `launchctl unload <path> && rm <path>` |
| 惡意 crontab 條目 | `crontab -e` 刪掉那行 |
| 注入的 shell profile 行 | 開 `~/.zshrc` / `~/.bashrc` 把注入的行刪掉 |
| 惡意 VS Code / Cursor 擴充套件 | `code --uninstall-extension <id>` |
| 可疑瀏覽器擴充套件 | 從瀏覽器擴充套件管理頁移除 |

**第 3 步 — 輪換所有憑證**

- 撤銷並重新產生 **GitHub personal access token**
- 刪掉並重新產生 **SSH 金鑰**（去 GitHub 上更新）
- 輪換開發環境裡能拿到的所有 API key / secret

**第 4 步 — 清完再掃一次確認**

```bash
./polinrider-scan-local.sh --full-system
```

---

*威脅背景、攻擊時間軸、IOC 及 YARA 規則請看 [README-OFFICIAL.md](README-OFFICIAL.md)。*
