# 漏洞來源 API 說明

## 1. NVD（National Vulnerability Database）

- **端點**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **認證**: API Key（Header: `apiKey`）
- **速率限制**: 無 Key 5 req/30s；有 Key 50 req/30s
- **文件**: https://nvd.nist.gov/developers/vulnerabilities
- **關鍵欄位**:
  - `cve.id` → CVE 編號
  - `cve.descriptions[].value` → 說明（lang=en）
  - `cve.metrics.cvssMetricV31[].cvssData` → CVSS 3.1
  - `cve.published` → 發布日期
- **建議爬取頻率**: 每小時

---

## 2. GitHub Security Advisories

- **端點**: `https://api.github.com/graphql` (GraphQL)
- **備用 REST**: `https://api.github.com/advisories`
- **認證**: Bearer Token（`Authorization: Bearer <token>`）
- **速率限制**: 5000 req/hr（已認證）
- **文件**: https://docs.github.com/en/rest/security-advisories
- **關鍵欄位**:
  - `ghsa_id` → GitHub 安全公告 ID
  - `cve_id` → 對應 CVE
  - `severity` → critical / high / moderate / low
  - `cvss` → CVSS 評分
  - `published_at` → 發布時間
- **建議爬取頻率**: 每 2 小時

---

## 3. MSRC（Microsoft Security Response Center）

- **端點**: `https://api.msrc.microsoft.com/cvrf/v3.0/`
- **認證**: 無需金鑰（公開 API）
- **月度更新**: 每月第二個星期二（Patch Tuesday）
- **文件**: https://api.msrc.microsoft.com/cvrf/v3.0/swagger/index
- **關鍵端點**:
  - `GET /updates` → 所有更新摘要
  - `GET /cvrf/{id}` → 特定月份詳細資訊
- **建議爬取頻率**: 每天

---

## 4. ZDI（Zero Day Initiative）

- **RSS Feed**: `https://www.zerodayinitiative.com/rss/published/`
- **認證**: 無需（公開 RSS）
- **格式**: RSS 2.0 + 自定義命名空間
- **關鍵欄位**:
  - `<title>` → 漏洞標題
  - `<link>` → 詳情頁
  - `<zdi:cvss-score>` → CVSS 分數
  - `<zdi:affected-vendors>` → 受影響廠商
  - `<pubDate>` → 發布日期
- **建議爬取頻率**: 每 4 小時

---

## 5. iThome

- **RSS Feed**: `https://www.ithome.com.tw/rss`
- **認證**: 無需（公開）
- **過濾關鍵字**: 漏洞、CVE、資安、攻擊、駭客、入侵、惡意
- **注意**: 為中文資安新聞，description_zh 即原文，description_en 需翻譯
- **建議爬取頻率**: 每 2 小時

---

## 6. FISAC（金融資安資訊分享與分析中心）

- **網址**: `https://www.fisac.tw`
- **方法**: HTML 爬取（BeautifulSoup）
- **目標頁面**: 漏洞預警公告頁面
- **注意**: 需遵守 robots.txt，建議加入 delay
- **建議爬取頻率**: 每 4 小時

---

## 7. TWCERT（台灣電腦網路危機處理暨協調中心）

- **網址**: `https://www.twcert.org.tw`
- **方法**: HTML 爬取（BeautifulSoup）
- **目標頁面**: 漏洞通報、資安通報
- **注意**: 需遵守 robots.txt，建議加入 delay
- **建議爬取頻率**: 每 4 小時

---

## CISA KEV（Known Exploited Vulnerabilities）

- **端點**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **認證**: 無需（公開）
- **更新頻率**: 不定期（通常數天一次）
- **用途**: 比對 CVE ID，標記 `is_kev: true`
- **建議快取**: 24 小時

---

## PoC 偵測來源

| 來源 | 方法 | 說明 |
|------|------|------|
| GitHub | REST Search API | 搜尋 CVE ID 相關 repo |
| Exploit-DB | HTML 爬取 | `https://www.exploit-db.com/search?cve=CVE-XXXX-XXXXX` |
| Nuclei Templates | GitHub API | `https://api.github.com/search/code?q=CVE+in:file+repo:projectdiscovery/nuclei-templates` |
