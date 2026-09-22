#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞查詢網頁伺服器（Flask）
提供完整的漏洞資訊展示、篩選與搜尋功能
"""

import json
import logging
import os
from datetime import datetime
from typing import List, Optional

from flask import Flask, jsonify, render_template_string, request

log = logging.getLogger(__name__)

# ── HTML 模板（暗色系 UI）────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🛡️ 資安漏洞情報系統</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1f2e; --surface2: #252b3d;
    --border: #2d3452; --text: #e2e8f0; --text-muted: #8892a4;
    --critical: #ef4444; --high: #f97316; --medium: #f59e0b; --low: #22c55e;
    --kev: #ef4444; --poc: #8b5cf6; --accent: #3b82f6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', Arial, sans-serif; }

  /* Header */
  .header { background: linear-gradient(135deg, #1a1f2e, #252b3d);
    padding: 18px 24px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 16px; }
  .header h1 { font-size: 20px; font-weight: 700; }
  .header .stats { margin-left: auto; display: flex; gap: 12px; }
  .stat-badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }

  /* Filters */
  .filters { background: var(--surface); padding: 14px 24px;
    border-bottom: 1px solid var(--border); display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  .filters input, .filters select { background: var(--surface2); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px; padding: 6px 12px; font-size: 13px; }
  .filters input { flex: 1; min-width: 200px; }
  .filters select { cursor: pointer; }
  .btn { padding: 6px 16px; border-radius: 6px; border: none; cursor: pointer;
    font-size: 13px; font-weight: 600; }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-reset { background: var(--surface2); color: var(--text); border: 1px solid var(--border); }

  /* Summary bar */
  .summary-bar { display: flex; gap: 0; background: var(--surface);
    border-bottom: 1px solid var(--border); }
  .summary-item { flex: 1; text-align: center; padding: 10px 6px;
    border-right: 1px solid var(--border); }
  .summary-item:last-child { border-right: none; }
  .summary-count { font-size: 22px; font-weight: 700; }
  .summary-label { font-size: 11px; color: var(--text-muted); margin-top: 2px; }

  /* Table */
  .table-wrap { overflow-x: auto; padding: 16px 24px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead tr { background: var(--surface2); }
  th { padding: 10px 12px; text-align: left; color: var(--text-muted);
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.05em; border-bottom: 1px solid var(--border); cursor: pointer; }
  th:hover { color: var(--text); }
  th .sort-icon { margin-left: 4px; }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  tr:hover td { background: var(--surface2); cursor: pointer; }
  tr.severity-critical td:first-child { border-left: 3px solid var(--critical); }
  tr.severity-high td:first-child { border-left: 3px solid var(--high); }
  tr.severity-medium td:first-child { border-left: 3px solid var(--medium); }
  tr.severity-low td:first-child { border-left: 3px solid var(--low); }

  /* Badges */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 700; }
  .badge-CRITICAL { background: var(--critical); color: #fff; }
  .badge-HIGH { background: var(--high); color: #fff; }
  .badge-MEDIUM { background: var(--medium); color: #000; }
  .badge-LOW { background: var(--low); color: #000; }
  .badge-UNKNOWN { background: #6b7280; color: #fff; }
  .badge-kev { background: #7f1d1d; color: #fca5a5; border: 1px solid var(--kev); }
  .badge-poc { background: #2e1065; color: #c4b5fd; border: 1px solid var(--poc); }
  .badge-source { background: var(--surface2); color: var(--text-muted);
    border: 1px solid var(--border); }

  /* Pagination */
  .pagination { display: flex; justify-content: center; align-items: center;
    gap: 8px; padding: 16px; }
  .page-btn { background: var(--surface2); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px; padding: 6px 12px;
    cursor: pointer; font-size: 13px; }
  .page-btn:hover, .page-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .page-info { color: var(--text-muted); font-size: 13px; }

  /* Modal */
  .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.7);
    z-index: 1000; overflow-y: auto; padding: 20px; }
  .modal-overlay.open { display: flex; justify-content: center; align-items: flex-start; }
  .modal { background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    max-width: 860px; width: 100%; margin: auto; padding: 28px; position: relative; }
  .modal-close { position: absolute; top: 16px; right: 20px; background: none;
    border: none; color: var(--text-muted); font-size: 24px; cursor: pointer; }
  .modal-close:hover { color: var(--text); }
  .modal h2 { font-size: 18px; margin-bottom: 16px; line-height: 1.4; }
  .modal-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px; }
  .modal-field { background: var(--surface2); border-radius: 8px; padding: 12px; }
  .modal-field label { font-size: 11px; color: var(--text-muted); text-transform: uppercase;
    letter-spacing: 0.05em; display: block; margin-bottom: 4px; }
  .modal-field .value { font-size: 14px; word-break: break-all; }
  .modal-desc { background: var(--surface2); border-radius: 8px; padding: 16px; margin-bottom: 12px; }
  .lang-toggle { display: flex; gap: 8px; margin-bottom: 8px; }
  .lang-btn { background: var(--border); color: var(--text-muted); border: none;
    border-radius: 4px; padding: 4px 12px; cursor: pointer; font-size: 12px; }
  .lang-btn.active { background: var(--accent); color: #fff; }
  .desc-text { font-size: 14px; line-height: 1.7; color: var(--text); }
  .poc-links a { color: var(--poc); text-decoration: none; font-size: 13px; display: block; }
  .poc-links a:hover { text-decoration: underline; }
  .modal-link { display: inline-block; margin-top: 12px; color: var(--accent);
    text-decoration: none; font-size: 14px; }
  .modal-link:hover { text-decoration: underline; }

  /* Loading */
  .loading { text-align: center; padding: 60px; color: var(--text-muted); }
  .empty { text-align: center; padding: 60px; color: var(--text-muted); }
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <span style="font-size:24px;">🛡️</span>
  <h1>資安漏洞情報系統</h1>
  <div class="stats" id="header-stats"></div>
</div>

<!-- Filters -->
<div class="filters">
  <input type="text" id="search" placeholder="🔍 搜尋關鍵字、CVE、產品..." oninput="applyFilters()">
  <select id="filter-severity" onchange="applyFilters()">
    <option value="">全部嚴重度</option>
    <option value="CRITICAL">🔴 CRITICAL</option>
    <option value="HIGH">🟠 HIGH</option>
    <option value="MEDIUM">🟡 MEDIUM</option>
    <option value="LOW">🟢 LOW</option>
  </select>
  <select id="filter-source" onchange="applyFilters()">
    <option value="">全部來源</option>
    <option value="NVD">NVD</option>
    <option value="GitHub">GitHub</option>
    <option value="MSRC">MSRC</option>
    <option value="ZDI">ZDI</option>
    <option value="iThome">iThome</option>
    <option value="FISAC">FISAC</option>
    <option value="TWCERT">TWCERT</option>
  </select>
  <select id="filter-kev" onchange="applyFilters()">
    <option value="">KEV 狀態</option>
    <option value="yes">⚠️ KEV 已利用</option>
    <option value="no">未列入 KEV</option>
  </select>
  <select id="filter-poc" onchange="applyFilters()">
    <option value="">PoC 狀態</option>
    <option value="yes">💻 有 PoC</option>
    <option value="no">無 PoC</option>
  </select>
  <button class="btn btn-reset" onclick="resetFilters()">重置</button>
</div>

<!-- Summary Bar -->
<div class="summary-bar" id="summary-bar">
  <div class="summary-item"><div class="summary-count" id="sum-critical" style="color:#ef4444">-</div><div class="summary-label">CRITICAL</div></div>
  <div class="summary-item"><div class="summary-count" id="sum-high" style="color:#f97316">-</div><div class="summary-label">HIGH</div></div>
  <div class="summary-item"><div class="summary-count" id="sum-medium" style="color:#f59e0b">-</div><div class="summary-label">MEDIUM</div></div>
  <div class="summary-item"><div class="summary-count" id="sum-low" style="color:#22c55e">-</div><div class="summary-label">LOW</div></div>
  <div class="summary-item"><div class="summary-count" id="sum-kev" style="color:#ef4444">-</div><div class="summary-label">KEV 已利用</div></div>
  <div class="summary-item"><div class="summary-count" id="sum-poc" style="color:#8b5cf6">-</div><div class="summary-label">有 PoC</div></div>
  <div class="summary-item"><div class="summary-count" id="sum-total" style="color:#3b82f6">-</div><div class="summary-label">總計</div></div>
</div>

<!-- Table -->
<div class="table-wrap">
  <table id="vuln-table">
    <thead>
      <tr>
        <th onclick="sortBy('severity')">嚴重度 <span class="sort-icon">⇅</span></th>
        <th>標題</th>
        <th>CVE 編號</th>
        <th onclick="sortBy('cvss_score')">CVSS <span class="sort-icon">⇅</span></th>
        <th>來源</th>
        <th>命中產品</th>
        <th>KEV</th>
        <th>PoC</th>
        <th onclick="sortBy('publish_date')">發布日期 <span class="sort-icon">⇅</span></th>
      </tr>
    </thead>
    <tbody id="table-body">
      <tr><td colspan="9" class="loading">⏳ 載入資料中...</td></tr>
    </tbody>
  </table>
</div>

<!-- Pagination -->
<div class="pagination" id="pagination"></div>

<!-- Modal -->
<div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <button class="modal-close" onclick="closeModal()">✕</button>
    <div id="modal-content"></div>
  </div>
</div>

<script>
let allVulns = [];
let filteredVulns = [];
let currentPage = 1;
const PAGE_SIZE = 20;
let sortField = 'severity';
let sortAsc = false;

const SEVERITY_ORDER = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, UNKNOWN:4};

async function loadData() {
  try {
    const resp = await fetch('/api/vulnerabilities');
    const data = await resp.json();
    allVulns = data.vulnerabilities || [];
    filteredVulns = [...allVulns];
    sortData();
    updateSummary();
    renderTable();
  } catch(e) {
    document.getElementById('table-body').innerHTML =
      '<tr><td colspan="9" class="empty">❌ 資料載入失敗：' + e.message + '</td></tr>';
  }
}

function applyFilters() {
  const search = document.getElementById('search').value.toLowerCase();
  const severity = document.getElementById('filter-severity').value;
  const source = document.getElementById('filter-source').value;
  const kev = document.getElementById('filter-kev').value;
  const poc = document.getElementById('filter-poc').value;

  filteredVulns = allVulns.filter(v => {
    if (severity && v.severity !== severity) return false;
    if (source && v.source !== source) return false;
    if (kev === 'yes' && !v.is_kev) return false;
    if (kev === 'no' && v.is_kev) return false;
    if (poc === 'yes' && !v.has_poc) return false;
    if (poc === 'no' && v.has_poc) return false;
    if (search) {
      const haystack = [v.title, v.cve_id, v.source, v.description_zh, v.description_en,
        (v.hit_products||[]).map(p=>p.product_name).join(' ')].join(' ').toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  currentPage = 1;
  updateSummary();
  sortData();
  renderTable();
}

function resetFilters() {
  document.getElementById('search').value = '';
  document.getElementById('filter-severity').value = '';
  document.getElementById('filter-source').value = '';
  document.getElementById('filter-kev').value = '';
  document.getElementById('filter-poc').value = '';
  applyFilters();
}

function sortBy(field) {
  if (sortField === field) sortAsc = !sortAsc;
  else { sortField = field; sortAsc = false; }
  sortData();
  renderTable();
}

function sortData() {
  filteredVulns.sort((a, b) => {
    let va = a[sortField], vb = b[sortField];
    if (sortField === 'severity') { va = SEVERITY_ORDER[a.severity]||99; vb = SEVERITY_ORDER[b.severity]||99; }
    if (va == null) va = sortAsc ? Infinity : -Infinity;
    if (vb == null) vb = sortAsc ? Infinity : -Infinity;
    if (typeof va === 'string') return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    return sortAsc ? va - vb : vb - va;
  });
}

function updateSummary() {
  const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
  let kev=0, poc=0;
  filteredVulns.forEach(v => {
    counts[v.severity] = (counts[v.severity]||0) + 1;
    if (v.is_kev) kev++;
    if (v.has_poc) poc++;
  });
  document.getElementById('sum-critical').textContent = counts.CRITICAL;
  document.getElementById('sum-high').textContent = counts.HIGH;
  document.getElementById('sum-medium').textContent = counts.MEDIUM;
  document.getElementById('sum-low').textContent = counts.LOW;
  document.getElementById('sum-kev').textContent = kev;
  document.getElementById('sum-poc').textContent = poc;
  document.getElementById('sum-total').textContent = filteredVulns.length;
}

function renderTable() {
  const tbody = document.getElementById('table-body');
  const start = (currentPage - 1) * PAGE_SIZE;
  const pageData = filteredVulns.slice(start, start + PAGE_SIZE);

  if (pageData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty">🔍 無符合條件的漏洞</td></tr>';
    renderPagination();
    return;
  }

  tbody.innerHTML = pageData.map((v, idx) => {
    const sev = v.severity || 'UNKNOWN';
    const products = (v.hit_products||[]).map(p=>p.product_name).join(', ') || '未命中';
    const kev = v.is_kev ? '<span class="badge badge-kev">⚠️ KEV</span>' : '-';
    const poc = v.has_poc ? '<span class="badge badge-poc">💻 PoC</span>' : '-';
    const cveId = v.cve_id || 'N/A';
    const cvss = v.cvss_score != null ? v.cvss_score.toFixed(1) : 'N/A';
    const pubDate = (v.publish_date||'').substring(0,10);
    const title = (v.title||'').substring(0,60) + (v.title && v.title.length > 60 ? '...' : '');
    const realIdx = start + idx;
    return `<tr class="severity-${sev.toLowerCase()}" onclick="showModal(${realIdx})">
      <td><span class="badge badge-${sev}">${sev}</span></td>
      <td>${escHtml(title)}</td>
      <td style="font-family:monospace;font-size:12px;">${escHtml(cveId)}</td>
      <td>${cvss}</td>
      <td><span class="badge badge-source">${escHtml(v.source||'N/A')}</span></td>
      <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escHtml(products)}</td>
      <td>${kev}</td>
      <td>${poc}</td>
      <td style="color:#8892a4;white-space:nowrap;">${pubDate}</td>
    </tr>`;
  }).join('');

  renderPagination();
}

function renderPagination() {
  const total = Math.ceil(filteredVulns.length / PAGE_SIZE);
  const pg = document.getElementById('pagination');
  if (total <= 1) { pg.innerHTML = ''; return; }

  let html = `<button class="page-btn" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>‹</button>`;
  const pages = [];
  for (let i=1; i<=total; i++) {
    if (i===1 || i===total || Math.abs(i-currentPage)<=2) pages.push(i);
    else if (pages[pages.length-1] !== '...') pages.push('...');
  }
  pages.forEach(p => {
    if (p === '...') html += `<span style="color:#8892a4;padding:0 4px;">…</span>`;
    else html += `<button class="page-btn ${p===currentPage?'active':''}" onclick="goPage(${p})">${p}</button>`;
  });
  html += `<button class="page-btn" onclick="goPage(${currentPage+1})" ${currentPage===total?'disabled':''}>›</button>`;
  html += `<span class="page-info">第 ${currentPage}/${total} 頁，共 ${filteredVulns.length} 筆</span>`;
  pg.innerHTML = html;
}

function goPage(p) {
  const total = Math.ceil(filteredVulns.length / PAGE_SIZE);
  if (p < 1 || p > total) return;
  currentPage = p;
  renderTable();
  window.scrollTo(0, 0);
}

function showModal(idx) {
  const v = filteredVulns[idx];
  if (!v) return;
  const sev = v.severity || 'UNKNOWN';
  const products = (v.hit_products||[]);
  const pocUrls = (v.poc_urls||[]);

  const productsHtml = products.length > 0
    ? products.map(p => `<div style="margin-bottom:6px;">
        <span class="badge badge-source">${escHtml(p.product_name)}</span>
        ${p.category ? `<span style="color:#8892a4;font-size:11px;margin-left:6px;">${escHtml(p.category)}</span>` : ''}
        ${p.owner ? `<span style="color:#8892a4;font-size:11px;margin-left:6px;">👤 ${escHtml(p.owner)}</span>` : ''}
      </div>`).join('')
    : '<span style="color:#8892a4;">未命中任何產品</span>';

  const pocHtml = pocUrls.length > 0
    ? `<div class="poc-links">${pocUrls.map(u=>`<a href="${u}" target="_blank">🔗 ${escHtml(u)}</a>`).join('')}</div>`
    : '<span style="color:#8892a4;">無公開 PoC</span>';

  document.getElementById('modal-content').innerHTML = `
    <h2>
      <span class="badge badge-${sev}" style="margin-right:10px;">${sev}</span>
      ${escHtml(v.title||'N/A')}
    </h2>
    <div class="modal-grid">
      <div class="modal-field"><label>CVE 編號</label><div class="value" style="font-family:monospace;">${escHtml(v.cve_id||'N/A')}</div></div>
      <div class="modal-field"><label>CVSS 分數</label><div class="value">${v.cvss_score!=null?v.cvss_score.toFixed(1):'N/A'}</div></div>
      <div class="modal-field"><label>CVSS 向量</label><div class="value" style="font-size:12px;font-family:monospace;">${escHtml(v.cvss_vector||'N/A')}</div></div>
      <div class="modal-field"><label>來源</label><div class="value"><span class="badge badge-source">${escHtml(v.source||'N/A')}</span></div></div>
      <div class="modal-field"><label>KEV（已被利用）</label><div class="value">${v.is_kev ? `<span class="badge badge-kev">⚠️ 是 ${v.kev_date_added ? '('+v.kev_date_added+')':''}</span>` : '否'}</div></div>
      <div class="modal-field"><label>PoC 公開</label><div class="value">${v.has_poc ? '<span class="badge badge-poc">💻 是</span>' : '否'}</div></div>
      <div class="modal-field"><label>發布日期</label><div class="value">${escHtml((v.publish_date||'').substring(0,10))}</div></div>
      <div class="modal-field"><label>取得時間</label><div class="value">${escHtml((v.acquired_at||'').substring(0,19).replace('T',' '))}</div></div>
    </div>
    <div class="modal-field" style="margin-bottom:12px;"><label>命中產品</label>${productsHtml}</div>
    <div class="modal-field" style="margin-bottom:12px;"><label>PoC / Exploit 連結</label>${pocHtml}</div>
    <div class="modal-desc">
      <div class="lang-toggle">
        <button class="lang-btn active" id="btn-zh" onclick="switchLang('zh')">中文</button>
        <button class="lang-btn" id="btn-en" onclick="switchLang('en')">English</button>
      </div>
      <div class="desc-text" id="desc-zh">${escHtml(v.description_zh||v.description_en||'')}</div>
      <div class="desc-text" id="desc-en" style="display:none;">${escHtml(v.description_en||'')}</div>
    </div>
    <a href="${escHtml(v.url||'#')}" target="_blank" class="modal-link">🔗 查看原始漏洞公告 →</a>
  `;
  document.getElementById('modal').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  document.getElementById('modal').classList.remove('open');
  document.body.style.overflow = '';
}

function switchLang(lang) {
  document.getElementById('desc-zh').style.display = lang === 'zh' ? '' : 'none';
  document.getElementById('desc-en').style.display = lang === 'en' ? '' : 'none';
  document.getElementById('btn-zh').classList.toggle('active', lang === 'zh');
  document.getElementById('btn-en').classList.toggle('active', lang === 'en');
}

function escHtml(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.addEventListener('keydown', e => { if(e.key==='Escape') closeModal(); });
loadData();
</script>
</body>
</html>"""


class VulnWebServer:
    """漏洞查詢網頁伺服器"""

    def __init__(self, config: dict):
        self.config = config
        self.web_cfg = config.get("web", {})
        self.app = Flask(__name__)
        self._setup_routes()

    def _load_data(self) -> dict:
        """載入漏洞資料"""
        data_source = self.web_cfg.get("data_source", "local")

        if data_source == "onedrive":
            try:
                from onedrive_uploader import OneDriveUploader
                uploader = OneDriveUploader(self.config["onedrive"])
                data = uploader.download_json(
                    self.config["onedrive"].get("vuln_filename", "vulnerabilities.json")
                )
                if data:
                    return data
            except Exception as e:
                log.warning(f"OneDrive 讀取失敗，改用本地資料：{e}")

        # 本地 JSON
        local_path = self.web_cfg.get(
            "local_json_path",
            os.path.join(self.config.get("storage", {}).get("data_dir", "./data"), "vulnerabilities.json")
        )
        if os.path.exists(local_path):
            with open(local_path, encoding="utf-8") as f:
                return json.load(f)

        return {"metadata": {}, "vulnerabilities": []}

    def _setup_routes(self) -> None:
        app = self.app

        @app.route("/")
        def index():
            return render_template_string(HTML_TEMPLATE)

        @app.route("/api/vulnerabilities")
        def api_vulnerabilities():
            data = self._load_data()
            return jsonify(data)

        @app.route("/api/stats")
        def api_stats():
            data = self._load_data()
            vulns = data.get("vulnerabilities", [])
            stats = {
                "total": len(vulns),
                "by_severity": {},
                "by_source": {},
                "kev_count": sum(1 for v in vulns if v.get("is_kev")),
                "poc_count": sum(1 for v in vulns if v.get("has_poc")),
                "last_updated": data.get("metadata", {}).get("last_updated"),
            }
            for v in vulns:
                sev = v.get("severity", "UNKNOWN")
                src = v.get("source", "Unknown")
                stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
                stats["by_source"][src] = stats["by_source"].get(src, 0) + 1
            return jsonify(stats)

        @app.route("/health")
        def health():
            return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})

    def run(self, host: str = "0.0.0.0", port: int = 8080) -> None:
        log.info(f"🌐 網頁伺服器啟動：http://localhost:{port}")
        self.app.run(host=host, port=port, debug=False, threaded=True)
