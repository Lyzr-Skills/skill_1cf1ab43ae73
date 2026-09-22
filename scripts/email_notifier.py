#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
郵件通知模組 - 發送 HTML 格式漏洞情報郵件
"""

import logging
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List

log = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
    "UNKNOWN": "#6b7280",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "UNKNOWN": "⚪",
}

KEV_BADGE = '<span style="background:#dc2626;color:#fff;padding:2px 6px;border-radius:4px;font-size:12px;">⚠️ KEV</span>'
POC_BADGE = '<span style="background:#7c3aed;color:#fff;padding:2px 6px;border-radius:4px;font-size:12px;">💻 PoC</span>'


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    return f'<span style="background:{color};color:#fff;padding:3px 10px;border-radius:4px;font-weight:bold;font-size:13px;">{severity}</span>'


def _render_html(vulns: List[dict], report_date: str) -> str:
    """產生 HTML 郵件內容"""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    kev_count = sum(1 for v in vulns if v.get("is_kev"))
    poc_count = sum(1 for v in vulns if v.get("has_poc"))

    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1

    # 漏洞卡片 HTML
    cards_html = ""
    for v in sorted(vulns, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].index(x.get("severity", "UNKNOWN"))):
        sev = v.get("severity", "UNKNOWN")
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        emoji = SEVERITY_EMOJI.get(sev, "⚪")

        hit_products = v.get("hit_products", [])
        if hit_products:
            products_str = "、".join(p.get("product_name", "") for p in hit_products)
        else:
            products_str = "未命中"

        poc_urls = v.get("poc_urls", [])
        poc_links = " ".join(
            f'<a href="{u}" style="color:#8b5cf6;font-size:12px;">[PoC {i+1}]</a>'
            for i, u in enumerate(poc_urls[:3])
        )

        kev_cell = KEV_BADGE if v.get("is_kev") else '<span style="color:#6b7280;font-size:12px;">否</span>'
        poc_cell = (POC_BADGE + " " + poc_links) if v.get("has_poc") else '<span style="color:#6b7280;font-size:12px;">否</span>'

        cvss_str = f"{v.get('cvss_score', 'N/A')}" if v.get("cvss_score") else "N/A"

        cards_html += f"""
        <div style="border-left:5px solid {color};background:#fafafa;margin:16px 0;padding:16px;border-radius:0 8px 8px 0;box-shadow:0 1px 3px rgba(0,0,0,.1);">
          <h3 style="margin:0 0 10px;font-size:16px;color:#1a1a2e;">
            {emoji} {_severity_badge(sev)}&nbsp;&nbsp;{v.get("title", "N/A")}
          </h3>
          <table style="width:100%;border-collapse:collapse;font-size:13px;">
            <tr>
              <td style="padding:4px 8px;color:#555;width:120px;"><strong>CVE 編號</strong></td>
              <td style="padding:4px 8px;">{v.get("cve_id", "N/A")}</td>
              <td style="padding:4px 8px;color:#555;width:100px;"><strong>CVSS</strong></td>
              <td style="padding:4px 8px;">{cvss_str}</td>
            </tr>
            <tr style="background:#f0f0f0;">
              <td style="padding:4px 8px;color:#555;"><strong>來源</strong></td>
              <td style="padding:4px 8px;">{v.get("source", "N/A")}</td>
              <td style="padding:4px 8px;color:#555;"><strong>發布日期</strong></td>
              <td style="padding:4px 8px;">{v.get("publish_date", "N/A")[:10]}</td>
            </tr>
            <tr>
              <td style="padding:4px 8px;color:#555;"><strong>命中產品</strong></td>
              <td style="padding:4px 8px;" colspan="3">{products_str}</td>
            </tr>
            <tr style="background:#f0f0f0;">
              <td style="padding:4px 8px;color:#555;"><strong>KEV</strong></td>
              <td style="padding:4px 8px;">{kev_cell}</td>
              <td style="padding:4px 8px;color:#555;"><strong>PoC</strong></td>
              <td style="padding:4px 8px;">{poc_cell}</td>
            </tr>
          </table>
          <div style="margin-top:10px;padding:10px;background:#fff;border:1px solid #e0e0e0;border-radius:4px;">
            <p style="margin:0 0 6px;font-size:13px;color:#333;"><strong>📝 說明（中文）：</strong>{v.get("description_zh", v.get("description_en", ""))[:500]}</p>
            <p style="margin:0;font-size:12px;color:#555;"><strong>📄 Description（EN）：</strong>{v.get("description_en", "")[:300]}</p>
          </div>
          <div style="margin-top:8px;">
            <a href="{v.get("url", "#")}" style="color:#3b82f6;font-size:13px;text-decoration:none;">🔗 查看完整漏洞公告 →</a>
          </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:Arial,'Microsoft JhengHei',sans-serif;">
<div style="max-width:820px;margin:20px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,.15);">

  <!-- 標頭 -->
  <div style="background:linear-gradient(135deg,#1a1a2e,#16213e);padding:24px 30px;">
    <h1 style="margin:0;color:#fff;font-size:22px;">🛡️ 資安漏洞情報通知</h1>
    <p style="margin:6px 0 0;color:#a0aec0;font-size:14px;">系統偵測到 <strong style="color:#fff;">{len(vulns)}</strong> 筆新增漏洞 | {report_date}</p>
  </div>

  <!-- 統計摘要 -->
  <div style="display:flex;gap:0;background:#1e293b;">
    {"".join(f'<div style="flex:1;text-align:center;padding:14px;border-right:1px solid #334155;"><div style="font-size:24px;font-weight:bold;color:{SEVERITY_COLORS[s]};">{counts.get(s, 0)}</div><div style="font-size:11px;color:#94a3b8;">{s}</div></div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW"])}
    <div style="flex:1;text-align:center;padding:14px;">
      <div style="font-size:24px;font-weight:bold;color:#f59e0b;">{kev_count}</div>
      <div style="font-size:11px;color:#94a3b8;">KEV 已利用</div>
    </div>
    <div style="flex:1;text-align:center;padding:14px;">
      <div style="font-size:24px;font-weight:bold;color:#8b5cf6;">{poc_count}</div>
      <div style="font-size:11px;color:#94a3b8;">有 PoC</div>
    </div>
  </div>

  <!-- 漏洞清單 -->
  <div style="padding:20px 24px;">
    {cards_html}
  </div>

  <!-- 頁尾 -->
  <div style="background:#f8fafc;padding:16px 24px;border-top:1px solid #e2e8f0;text-align:center;">
    <p style="margin:0;font-size:12px;color:#94a3b8;">此郵件由資安漏洞情報自動化系統自動發送，請勿直接回覆。</p>
    <p style="margin:4px 0 0;font-size:11px;color:#cbd5e1;">取得時間：{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</p>
  </div>

</div>
</body>
</html>"""
    return html


def _render_text(vulns: List[dict], report_date: str) -> str:
    """純文字備援版本"""
    lines = [
        "【資安漏洞情報通知】",
        f"日期：{report_date}",
        f"新增漏洞：{len(vulns)} 筆",
        "=" * 60,
    ]
    for i, v in enumerate(vulns, 1):
        lines += [
            f"\n{i}. [{v.get('severity', 'N/A')}] {v.get('title', 'N/A')}",
            f"   CVE   ：{v.get('cve_id', 'N/A')}",
            f"   CVSS  ：{v.get('cvss_score', 'N/A')}",
            f"   來源  ：{v.get('source', 'N/A')}",
            f"   KEV   ：{'是' if v.get('is_kev') else '否'}",
            f"   PoC   ：{'是' if v.get('has_poc') else '否'}",
            f"   日期  ：{v.get('publish_date', 'N/A')[:10]}",
            f"   說明  ：{v.get('description_zh', '')[:200]}",
            f"   連結  ：{v.get('url', 'N/A')}",
            "-" * 60,
        ]
    return "\n".join(lines)


class EmailNotifier:
    """SMTP 郵件寄送器"""

    def __init__(self, smtp_config: dict):
        self.cfg = smtp_config

    def send(self, vulns: List[dict]) -> None:
        """寄送 HTML 漏洞通知郵件"""
        if not vulns:
            return

        recipients = self.cfg.get("recipients", [])
        if not recipients:
            log.warning("未設定收件人，跳過郵件寄送")
            return

        report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        top_severity = "CRITICAL" if any(v.get("severity") == "CRITICAL" for v in vulns) else \
                       "HIGH" if any(v.get("severity") == "HIGH" for v in vulns) else "MEDIUM"

        subject = (
            f"{self.cfg.get('subject_prefix', '[資安告警]')} "
            f"{SEVERITY_EMOJI.get(top_severity, '⚠️')} "
            f"發現 {len(vulns)} 筆新漏洞 ({report_date})"
        )

        html_body = _render_html(vulns, report_date)
        text_body = _render_text(vulns, report_date)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{self.cfg.get('sender_name', '資安漏洞系統')} <{self.cfg.get('user', '')}>"
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            host = self.cfg.get("host", "smtp.gmail.com")
            port = int(self.cfg.get("port", 587))
            use_tls = self.cfg.get("use_tls", True)

            with smtplib.SMTP(host, port, timeout=30) as server:
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                server.login(self.cfg.get("user", ""), self.cfg.get("password", ""))
                server.sendmail(self.cfg.get("user", ""), recipients, msg.as_string())

            log.info(f"✅ 郵件寄送成功：{subject} → {recipients}")
        except Exception as e:
            log.error(f"❌ 郵件寄送失敗：{e}")
            raise
