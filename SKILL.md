---
name: vuln-intel-skill
description: >
  資安漏洞情報自動化採集、分析、通知與展示系統。當使用者需要從 NVD、GitHub、MSRC、ZDI、iThome、FISAC、TWCERT 等來源蒐集漏洞資訊、自動發送郵件通知、比對受影響產品、查詢 CISA KEV 狀態、偵測公開 PoC，並透過網頁介面查詢完整漏洞情報時，請使用此技能。適用場景包含：資安情報蒐集自動化、漏洞管理、資安告警通知、產品受影響分析、CVSS 風險評估、CISA KEV 追蹤、PoC 偵測，以及中英雙語漏洞資訊展示。
---

# 資安漏洞情報自動化系統 (Vulnerability Intelligence Skill)

## 系統概觀

本系統自動化執行以下核心工作流程：
1. **蒐集** — 從 7 大來源取得最新漏洞情報並寫入 JSON
2. **上傳** — 將 JSON 資料上傳至 OneDrive（增量更新、去重）
3. **通知** — 透過 SMTP 寄送 HTML 格式郵件給指定收件人（中以上嚴重度）
4. **展示** — 啟動具完整查詢功能的本地網頁伺服器

---

## 目錄結構

```
vuln-intel-skill/
├── SKILL.md                  # 本文件
├── README.md                 # 快速開始指南
├── requirements.txt          # Python 依賴
├── assets/
│   └── config_template.yaml  # 設定檔範本
├── references/
│   ├── data_schema.md        # JSON 資料結構說明
│   ├── sources.md            # 各來源 API 說明
│   └── email_template.md    # 郵件 HTML 範本說明
└── scripts/
    ├── main.py               # 統一入口（4 種模式）
    ├── collector.py          # 漏洞資料蒐集（7 來源）
    ├── onedrive_uploader.py  # OneDrive 上傳 / 下載
    ├── email_notifier.py     # SMTP 郵件通知
    ├── product_matcher.py    # 產品比對（Excel）
    ├── kev_checker.py        # CISA KEV 查詢
    ├── poc_checker.py        # PoC / Exploit 偵測
    ├── translator.py         # 中英文翻譯
    └── web_server.py         # 漏洞查詢網頁
```

---

## 執行模式

| 模式 | 指令 | 說明 |
|------|------|------|
| 完整流程 | `python scripts/main.py --config config.yaml --mode all` | 蒐集→上傳→通知 |
| 僅蒐集 | `python scripts/main.py --config config.yaml --mode collect` | 只抓資料存本地 JSON |
| 僅通知 | `python scripts/main.py --config config.yaml --mode notify` | 讀取現有 JSON 寄信 |
| 網頁介面 | `python scripts/main.py --config config.yaml --mode web` | 啟動查詢網頁（port 8080）|

---

## 設定檔 (config.yaml)

詳見 `assets/config_template.yaml`，主要區段：
- `onedrive`: tenant_id / client_id / client_secret / drive_path
- `smtp`: host / port / user / password / recipients
- `sources`: 各來源開關與 API Key
- `products_file`: OneDrive 上的產品清單 Excel 路徑
- `severity_threshold`: 通知門檻（預設 MEDIUM）
- `translation`: 翻譯服務選擇（google / deepl / openai）

---

## 漏洞資料欄位（完整）

| 欄位 | 說明 |
|------|------|
| `id` | 唯一識別碼（UUID） |
| `severity` | CRITICAL / HIGH / MEDIUM / LOW |
| `title` | 漏洞標題 |
| `description_en` | 英文內文 |
| `description_zh` | 中文翻譯內文 |
| `source` | NVD / GitHub / MSRC / ZDI / iThome / FISAC / TWCERT |
| `url` | 原始來源網址 |
| `cve_id` | CVE 編號（如無則為 N/A） |
| `hit_products` | 命中產品列表（來自 Excel 比對） |
| `cvss_score` | CVSS 分數（0.0–10.0） |
| `cvss_vector` | CVSS 向量字串 |
| `is_kev` | 是否為 CISA KEV（布林值） |
| `has_poc` | 是否有公開 PoC（布林值） |
| `poc_urls` | PoC 來源網址列表 |
| `publish_date` | 漏洞發布日期（ISO 8601） |
| `acquired_at` | 系統取得時間（ISO 8601） |

詳細 JSON Schema 請參考 `references/data_schema.md`。

---

## 各來源說明

請參考 `references/sources.md` 取得各來源 API 端點、認證方式、爬取頻率建議。

---

## 網頁功能

- **暗色系 UI**，適合資安團隊長時間使用
- 多維篩選：嚴重度 / 來源 / KEV / PoC / 日期範圍 / 關鍵字
- 點擊展開 Modal 顯示完整資訊（含中英雙語切換）
- 表格排序：嚴重度、CVSS 分數、發布日期
- 統計摘要列（各嚴重度計數、KEV / PoC 數）
- 資料來自本地 JSON 或 OneDrive（可設定）

---

## 依賴安裝

```bash
pip install -r requirements.txt
```

主要套件：`requests`, `openpyxl`, `flask`, `msal`, `schedule`, `deep-translator`, `jinja2`, `python-dotenv`
