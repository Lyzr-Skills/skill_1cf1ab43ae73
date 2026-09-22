# 漏洞資料 JSON Schema

## 主要結構

```json
{
  "metadata": {
    "version": "1.0",
    "last_updated": "2024-01-15T08:30:00+08:00",
    "total_count": 1234,
    "sources": ["NVD", "GitHub", "MSRC", "ZDI", "iThome", "FISAC", "TWCERT"]
  },
  "vulnerabilities": [
    { ...漏洞物件... }
  ]
}
```

## 漏洞物件完整結構

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "severity": "HIGH",
  "title": "Apache Log4j Remote Code Execution Vulnerability",
  "description_en": "A critical vulnerability in Apache Log4j allows remote attackers to execute arbitrary code via JNDI injection.",
  "description_zh": "Apache Log4j 中存在嚴重漏洞，允許遠端攻擊者透過 JNDI 注入執行任意程式碼。",
  "source": "NVD",
  "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
  "cve_id": "CVE-2021-44228",
  "hit_products": [
    {
      "product_name": "Apache Log4j",
      "category": "Logging Framework",
      "owner": "Infrastructure Team",
      "match_type": "keyword"
    }
  ],
  "cvss_score": 10.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "cvss_version": "3.1",
  "is_kev": true,
  "kev_date_added": "2021-12-10",
  "has_poc": true,
  "poc_urls": [
    "https://github.com/example/log4shell-poc",
    "https://www.exploit-db.com/exploits/50590"
  ],
  "publish_date": "2021-12-10T00:00:00Z",
  "acquired_at": "2024-01-15T08:30:00+08:00",
  "raw_data": {}
}
```

## 欄位說明

| 欄位 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `id` | string (UUID4) | ✅ | 系統唯一識別碼 |
| `severity` | enum | ✅ | CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN |
| `title` | string | ✅ | 漏洞標題（英文優先） |
| `description_en` | string | ✅ | 英文說明 |
| `description_zh` | string | ✅ | 中文翻譯說明 |
| `source` | enum | ✅ | NVD / GitHub / MSRC / ZDI / iThome / FISAC / TWCERT |
| `url` | string (URL) | ✅ | 原始來源網址 |
| `cve_id` | string | ❌ | CVE 編號，無則為 "N/A" |
| `hit_products` | array | ✅ | 命中產品列表（空陣列表示未命中） |
| `cvss_score` | float | ❌ | 0.0–10.0，無則為 null |
| `cvss_vector` | string | ❌ | CVSS 向量字串 |
| `cvss_version` | string | ❌ | "2.0" / "3.0" / "3.1" |
| `is_kev` | boolean | ✅ | 是否在 CISA KEV 清單 |
| `kev_date_added` | string (date) | ❌ | 加入 KEV 的日期 |
| `has_poc` | boolean | ✅ | 是否有公開 PoC |
| `poc_urls` | array | ✅ | PoC 連結列表 |
| `publish_date` | string (ISO 8601) | ✅ | 漏洞發布日期 |
| `acquired_at` | string (ISO 8601) | ✅ | 系統取得時間 |
| `raw_data` | object | ❌ | 原始 API 回傳資料（debug 用） |

## 嚴重度對照

| 嚴重度 | CVSS 範圍 | 顏色代碼 |
|--------|-----------|---------|
| CRITICAL | 9.0–10.0 | #dc2626 |
| HIGH | 7.0–8.9 | #ea580c |
| MEDIUM | 4.0–6.9 | #d97706 |
| LOW | 0.1–3.9 | #65a30d |
| UNKNOWN | N/A | #6b7280 |

## hit_products 物件結構

```json
{
  "product_name": "Apache Tomcat",
  "category": "Web Server",
  "owner": "IT部門",
  "match_type": "keyword",  // "keyword" / "cpe" / "both"
  "matched_keyword": "tomcat",
  "matched_cpe": "cpe:2.3:a:apache:tomcat:*"
}
```
