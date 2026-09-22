# 郵件 HTML 範本說明

## 郵件主旨格式

```
[資安告警] {嚴重度圖示} 發現 {數量} 筆新漏洞 ({日期})
```

範例：
```
[資安告警] 🔴 發現 3 筆新漏洞 (2024-01-15)
```

嚴重度圖示：
- CRITICAL → 🔴
- HIGH → 🟠
- MEDIUM → 🟡
- LOW → 🟢

---

## HTML 郵件結構

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    /* 主要樣式內嵌（相容各郵件客戶端） */
    body { font-family: Arial, sans-serif; background: #f5f5f5; }
    .container { max-width: 800px; margin: 0 auto; background: #fff; }
    .header { background: #1a1a2e; color: #fff; padding: 20px; }
    .vuln-card { border-left: 4px solid {severity_color}; margin: 10px 0; padding: 15px; }
    .badge-critical { background: #dc2626; color: #fff; padding: 2px 8px; border-radius: 4px; }
    .badge-high { background: #ea580c; color: #fff; ... }
    .badge-medium { background: #d97706; color: #fff; ... }
    .badge-low { background: #65a30d; color: #fff; ... }
  </style>
</head>
<body>
  <!-- 標頭 -->
  <div class="header">
    <h2>🛡️ 資安漏洞情報通知</h2>
    <p>系統發現 {total} 筆新漏洞（{date}）</p>
  </div>

  <!-- 統計摘要 -->
  <div class="summary">
    <span>🔴 CRITICAL: {critical_count}</span>
    <span>🟠 HIGH: {high_count}</span>
    <span>🟡 MEDIUM: {medium_count}</span>
  </div>

  <!-- 漏洞清單（依嚴重度排序） -->
  {% for vuln in vulnerabilities %}
  <div class="vuln-card" style="border-color: {vuln.severity_color}">
    <h3>
      <span class="badge-{vuln.severity_lower}">{vuln.severity}</span>
      {vuln.title}
    </h3>
    <table>
      <tr><td>CVE</td><td>{vuln.cve_id}</td></tr>
      <tr><td>CVSS</td><td>{vuln.cvss_score}</td></tr>
      <tr><td>來源</td><td>{vuln.source}</td></tr>
      <tr><td>命中產品</td><td>{vuln.hit_products_str}</td></tr>
      <tr><td>KEV</td><td>{vuln.kev_badge}</td></tr>
      <tr><td>PoC</td><td>{vuln.poc_badge}</td></tr>
      <tr><td>發布日期</td><td>{vuln.publish_date}</td></tr>
    </table>
    <p><strong>說明（中文）：</strong>{vuln.description_zh}</p>
    <p><strong>說明（英文）：</strong>{vuln.description_en}</p>
    <a href="{vuln.url}" style="color: #3b82f6;">🔗 查看原始漏洞公告</a>
  </div>
  {% endfor %}

  <!-- 頁尾 -->
  <div class="footer">
    <p>此郵件由資安漏洞情報自動化系統發送，請勿回覆。</p>
    <p>取得時間：{acquired_at}</p>
  </div>
</body>
</html>
```

---

## 純文字備援格式

```
【資安漏洞情報通知】
日期：{date}
新增漏洞：{total} 筆（CRITICAL: {c}, HIGH: {h}, MEDIUM: {m}）

──────────────────────────────
{序號}. [{嚴重度}] {標題}
   CVE：{cve_id}
   CVSS：{cvss_score}
   來源：{source}
   命中產品：{products}
   KEV：{is_kev}
   PoC：{has_poc}
   發布日期：{publish_date}
   說明（中）：{description_zh}
   連結：{url}
──────────────────────────────
```
