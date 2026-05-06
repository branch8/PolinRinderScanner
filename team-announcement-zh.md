# 🚨 請立即處理：PolinRider 惡意程式掃描

## 背景說明

PolinRider（又稱 TasksJacker）是一個持續活躍中的 DPRK（北韓 Lazarus 組織）供應鏈攻擊行動。攻擊者透過受感染的 npm 套件、VS Code 擴充套件，以及設定檔注入等手法，將混淆過的 JavaScript 惡意程式植入 GitHub 儲存庫。截至 2026 年 4 月，已確認超過 **1,951 個儲存庫 / 1,047 個帳號**遭到入侵。

我們針對自身環境客製了一版 PolinRider 掃描工具，**請使用下方連結下載，不要自行在網路上尋找其他版本**。

請大家依照以下步驟完成掃描，並將結果填入共用試算表。**請注意：這不是一次性的動作。** 由於存在再次感染的風險，未來幾天可能需要重複執行，直到確認整體環境完全乾淨為止。

---

# ⚠️ 開始之前，請先做這兩件事

## 1. 立即更換你的 GitHub 憑證

如果惡意程式曾在你的機器上執行，你的 GitHub Personal Access Token（PAT）及密碼可能已遭竊取。請在執行掃描或推送任何程式碼**之前**先完成以下步驟：

- 前往 **GitHub → Settings → Developer Settings → Personal Access Tokens**
- 撤銷所有現有 Token，重新產生新的
- 如果你使用密碼登入，請立即更改 GitHub 密碼，並開啟雙重驗證（若尚未啟用）
- 檢查並撤銷任何不認識的 OAuth App 授權

## 2. 立即停止使用 VS Code 及所有基於 VS Code 的 IDE

包含 **Cursor**、**Windsurf**、**Antigravity**，以及任何建構於 VS Code 引擎上的編輯器。在以下兩件事確認完成之前，請勿重新開啟：

- 掃描所有本機儲存庫，確認每個 `.vscode/tasks.json` 為無害或已刪除，**且**
- 確認機器上沒有受感染的 VS Code 擴充套件殘留

原因：惡意程式會竄改 `.vscode/tasks.json`，在你用任何 VS Code 系列編輯器開啟專案資料夾時，自動執行 `curl | bash` 惡意指令。只要開啟一個受感染的儲存庫，就可能讓剛清乾淨的機器再次被感染。

### 關於 tasks.json 的建議處理方式

除非你清楚知道某個 `tasks.json` 的內容及用途，否則請直接刪除。刪除是安全的——VS Code 會在需要時自動重建。不確定就刪。

```bash
# 找出所有專案中的 tasks.json
find ~/projects -name "tasks.json" -path "*/.vscode/*"

# 全部刪除（確認過或決定直接清除時執行）
find ~/projects -name "tasks.json" -path "*/.vscode/*" -delete
```

完成後，請使用下方掃描工具確認機器狀態。

---

# 🔍 開始掃描

## 第一步 — 下載掃描工具

📁 儲存庫與完整說明文件：https://github.com/branch8/PolinRiderScanner

### 非技術人員

直接下載懶人包，雙擊執行即可，不需要開終端機。

| 作業系統 | 下載連結 |
|---|---|
| macOS | [polinrider-quickstart-mac.command](https://github.com/branch8/PolinRiderScanner/releases/download/latest/polinrider-quickstart-mac.command) |
| Windows | [polinrider-quickstart-windows.bat](https://github.com/branch8/PolinRiderScanner/releases/download/latest/polinrider-quickstart-windows.bat) |

### 技術人員

Clone 儲存庫後依 README 操作：

```bash
git clone https://github.com/branch8/PolinRiderScanner.git
cd PolinRiderScanner
./polinrider-scan-local.sh --full-system
```

README 中有完整的參數說明、掃描模式選項，以及 GitHub org 掃描的設定方式。

---

## 第二步 — 執行掃描

不確定的話，請執行完整系統掃描。

| 掃描範圍 | 指令 |
|---|---|
| 僅掃描本機專案資料夾 | `./polinrider-scan-local.sh ~/projects` |
| 完整系統掃描（建議） | `./polinrider-scan-local.sh --full-system` |
| 快速檢查（行程 + 網路） | `./polinrider-scan-local.sh --quick` |
| 掃描 GitHub 組織的所有儲存庫 | `./polinrider-scan-local.sh --github 你的組織名稱` |

### Windows

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\polinrider-scan-local-windows.ps1
```

依儲存庫數量不同，掃描約需 2–10 分鐘。掃描記錄會自動存放在同目錄下的 `logs/` 資料夾。

---

## 第三步 — 判讀結果

| 顏色 | 意義 |
|---|---|
| 🔴 紅色 | 確認感染，需立即處理 |
| 🟡 黃色 | 可疑，請手動確認 |
| 🟢 綠色 | 乾淨 |

**如果發現感染：** 請勿推送任何程式碼，立即聯繫安全負責人，並附上 `logs/` 中的記錄檔。

---

## 第四步 — 填寫試算表

📊 PolinRider 掃描結果 — 團隊追蹤表：https://docs.google.com/spreadsheets/d/17oj2mipRXrydxXYtRijwGf90OThJmDj5GO5CcbH_wiM/edit?gid=2102468253#gid=2102468253

| 欄位 | 說明 |
|---|---|
| 姓名 | 你的名字 |
| 機器作業系統 | macOS / Windows / Linux |
| 執行的掃描類型 | full-system / quick / local / github |
| 結果 | 乾淨 / 感染 / 可疑 |
| 掃描日期 | 今天日期 |
| 受感染的儲存庫名稱 | 如有的話填入，無則留空 |

---

# 🔁 這是一個持續進行的過程

請預期未來幾天需要重複執行掃描。以下情況可能導致再次感染：

- 團隊成員推送了含有感染的 commit，而你之後執行了 `git pull`
- 正常執行 `npm install` 時安裝到受感染的套件
- 第一輪掃描未抓到的 `tasks.json` 再次觸發惡意程式

在整個團隊確認掃描結果全部乾淨之前，請將每次 `npm install` 或 `git pull` 都視為潛在的再感染風險，並在這些操作後執行快速掃描（`--quick`）。

何時可以恢復正常使用 IDE，我們會另行通知。

---

**如果遇到任何問題、有疑問，或是看到不確定的結果，請立即反應。** 不要悶著不說——越早讓我們知道，越能快速控制擴散範圍。

請**盡可能盡快**完成第一次掃描及憑證更換。
