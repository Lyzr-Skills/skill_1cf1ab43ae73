# 資安漏洞情報自動化系統

## 快速開始

### 1. 安裝依賴
```bash
pip install -r requirements.txt
```

### 2. 設定配置檔
```bash
cp assets/config_template.yaml config.yaml
# 編輯 config.yaml，填入 OneDrive、SMTP、API 金鑰等資訊
```

### 3. 執行

#### 完整流程（蒐集 + 上傳 + 通知）
```bash
python scripts/main.py --config config.yaml --mode all
```

#### 僅蒐集漏洞資料
```bash
python scripts/main.py --config config.yaml --mode collect
```

#### 僅發送郵件通知
```bash
python scripts/main.py --config config.yaml --mode notify
```

#### 啟動查詢網頁（http://localhost:8080）
```bash
python scripts/main.py --config config.yaml --mode web
```

#### 定時執行（每小時）
```bash
python scripts/main.py --config config.yaml --mode all --schedule --interval 60
```

---

## 必要設定項目

### OneDrive（Microsoft Graph API）
- `tenant_id`: Azure AD 租戶 ID
- `client_id`: 應用程式（用戶端）ID
- `client_secret`: 用戶端密碼

### SMTP 郵件
- `host`: 郵件伺服器位址（例如 smtp.gmail.com）
- `port`: 連接埠（通常 587 或 465）
- `user`: 寄件人帳號
- `password`: 寄件人密碼或應用程式密碼
- `recipients`: 收件人清單

### 資料來源 API（選用）
- NVD API Key（無 Key 仍可用，但有速率限制）
- GitHub Token（提高 API 配額）

---

## 產品比對 Excel 格式

OneDrive 上的產品設定檔（products.xlsx）格式：

| 欄位 | 說明 |
|------|------|
| ProductName | 產品名稱（用於比對） |
| Keywords | 關鍵字，逗號分隔（例如：apache,tomcat,http server） |
| CPE | CPE 2.3 格式字串（例如：cpe:2.3:a:apache:tomcat:*） |
| Category | 產品分類（例如：Web Server, Database） |
| Owner | 負責部門/人員 |

---

## 輸出 JSON 位置

- 本地：`./data/vulnerabilities.json`
- OneDrive：設定檔中的 `onedrive.drive_path`（例如：`/sites/Security/Shared Documents/vuln-intel/`）

---

## 常見問題

**Q: 翻譯失敗怎麼辦？**
A: 系統會回退至英文原文，並在 `description_zh` 欄位標記 `[翻譯失敗]`。

**Q: 如何增加新的漏洞來源？**
A: 在 `scripts/collector.py` 中新增 `collect_<source_name>()` 方法，並在 `SOURCES` 字典中登錄。

**Q: OneDrive 權限設定？**
A: 需要 `Files.ReadWrite.All` 和 `Sites.ReadWrite.All` 的應用程式權限。
