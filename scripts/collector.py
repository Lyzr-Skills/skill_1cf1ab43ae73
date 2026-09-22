#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞資料蒐集器 - 支援 7 大來源
Sources: NVD, GitHub, MSRC, ZDI, iThome, FISAC, TWCERT
"""

import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import feedparser
import requests
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "none": "LOW",
}


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_vuln(
    title: str,
    description_en: str,
    source: str,
    url: str,
    cve_id: str = "N/A",
    severity: str = "UNKNOWN",
    cvss_score: Optional[float] = None,
    cvss_vector: Optional[str] = None,
    publish_date: Optional[str] = None,
    cpe_list: Optional[list] = None,
) -> dict:
    """建立標準化漏洞物件"""
    return {
        "id": str(uuid.uuid4()),
        "severity": severity,
        "title": title,
        "description_en": description_en,
        "description_zh": "",  # 由 translator 填入
        "source": source,
        "url": url,
        "cve_id": cve_id,
        "hit_products": [],   # 由 product_matcher 填入
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_version": "3.1" if cvss_vector and "CVSS:3" in (cvss_vector or "") else None,
        "is_kev": False,      # 由 kev_checker 填入
        "kev_date_added": None,
        "has_poc": False,     # 由 poc_checker 填入
        "poc_urls": [],
        "publish_date": publish_date or _now_iso(),
        "acquired_at": _now_iso(),
        "cpe_list": cpe_list or [],
        "raw_data": {},
    }


class VulnerabilityCollector:
    """統一漏洞蒐集器"""

    def __init__(self, sources_config: dict):
        self.cfg = sources_config
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnIntelBot/1.0 (Security Research; contact: security@example.com)"
        })

    def collect_all(self) -> list:
        """蒐集所有啟用來源的漏洞"""
        all_vulns = []
        source_methods = {
            "nvd": self.collect_nvd,
            "github": self.collect_github,
            "msrc": self.collect_msrc,
            "zdi": self.collect_zdi,
            "ithome": self.collect_ithome,
            "fisac": self.collect_fisac,
            "twcert": self.collect_twcert,
        }

        for source_name, method in source_methods.items():
            cfg = self.cfg.get(source_name, {})
            if not cfg.get("enabled", True):
                log.info(f"⏭️  {source_name.upper()} 已停用，跳過")
                continue
            try:
                log.info(f"🔎 蒐集 {source_name.upper()} 資料中...")
                vulns = method(cfg)
                log.info(f"   → {source_name.upper()}: 取得 {len(vulns)} 筆")
                all_vulns.extend(vulns)
                time.sleep(1)  # 避免過快請求
            except Exception as e:
                log.error(f"❌ {source_name.upper()} 蒐集失敗：{e}")

        return all_vulns

    # ── NVD ──────────────────────────────────────────────────
    def collect_nvd(self, cfg: dict) -> list:
        vulns = []
        lookback_days = cfg.get("lookback_days", 7)
        max_results = cfg.get("max_results", 200)
        api_key = cfg.get("api_key", "")

        pub_end = datetime.now(timezone.utc)
        pub_start = pub_end - timedelta(days=lookback_days)

        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        params = {
            "pubStartDate": pub_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": pub_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(max_results, 2000),
            "startIndex": 0,
        }

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        resp = self.session.get(url, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")

            # 取得英文說明
            desc_en = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc_en = d.get("value", "")
                    break

            # 取得 CVSS
            cvss_score = None
            cvss_vector = None
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]["cvssData"]
                    cvss_score = m.get("baseScore")
                    cvss_vector = m.get("vectorString")
                    break

            severity = _cvss_to_severity(cvss_score)

            # CPE
            cpe_list = []
            for config_node in cve.get("configurations", []):
                for node in config_node.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            cpe_list.append(cpe_match.get("criteria", ""))

            publish_date = cve.get("published", _now_iso())

            vuln = _make_vuln(
                title=f"{cve_id} - {desc_en[:100]}..." if len(desc_en) > 100 else f"{cve_id} - {desc_en}",
                description_en=desc_en,
                source="NVD",
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                publish_date=publish_date,
                cpe_list=cpe_list,
            )
            vulns.append(vuln)

        return vulns

    # ── GitHub Security Advisories ───────────────────────────
    def collect_github(self, cfg: dict) -> list:
        vulns = []
        token = cfg.get("token", "")
        lookback_days = cfg.get("lookback_days", 3)

        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        since = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
        url = "https://api.github.com/advisories"
        params = {"type": "reviewed", "per_page": 100, "updated_since": since}

        resp = self.session.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        items = resp.json()

        for item in items:
            cve_id = item.get("cve_id") or "N/A"
            severity_raw = item.get("severity", "").lower()
            severity = SEVERITY_MAP.get(severity_raw, "UNKNOWN")

            cvss_score = None
            cvss_vector = None
            cvss_info = item.get("cvss", {})
            if cvss_info:
                cvss_score = cvss_info.get("score")
                cvss_vector = cvss_info.get("vector_string")
                if cvss_score:
                    severity = _cvss_to_severity(float(cvss_score))

            desc_en = item.get("description", "") or item.get("summary", "")
            title = item.get("summary", "") or f"GitHub Advisory: {item.get('ghsa_id', '')}"

            vuln = _make_vuln(
                title=title,
                description_en=desc_en,
                source="GitHub",
                url=item.get("html_url", ""),
                cve_id=cve_id,
                severity=severity,
                cvss_score=float(cvss_score) if cvss_score else None,
                cvss_vector=cvss_vector,
                publish_date=item.get("published_at", _now_iso()),
            )
            vulns.append(vuln)

        return vulns

    # ── MSRC ─────────────────────────────────────────────────
    def collect_msrc(self, cfg: dict) -> list:
        vulns = []
        now = datetime.now(timezone.utc)
        year_month = now.strftime("%Y-%b")

        url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{year_month}"
        try:
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            # 嘗試上個月
            last_month = now - timedelta(days=32)
            year_month = last_month.strftime("%Y-%b")
            url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{year_month}"
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()

        vuln_list = data.get("Vulnerability", [])
        for item in vuln_list:
            cve_id = item.get("CVE", "N/A")
            title_obj = item.get("Title", {})
            title = title_obj.get("Value", cve_id) if isinstance(title_obj, dict) else str(title_obj)

            desc_en = ""
            for note in item.get("Notes", []):
                if note.get("Type") == 1:  # Description type
                    desc_en = note.get("Value", "")
                    break

            # CVSS
            cvss_score = None
            cvss_vector = None
            for score_set in item.get("CVSSScoreSets", []):
                cvss_score = score_set.get("BaseScore")
                cvss_vector = score_set.get("Vector")
                break

            severity = _cvss_to_severity(float(cvss_score) if cvss_score else None)

            vuln = _make_vuln(
                title=title,
                description_en=desc_en or title,
                source="MSRC",
                url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
                cve_id=cve_id,
                severity=severity,
                cvss_score=float(cvss_score) if cvss_score else None,
                cvss_vector=cvss_vector,
                publish_date=data.get("DocumentTracking", {}).get("InitialReleaseDate", _now_iso()),
            )
            vulns.append(vuln)

        return vulns

    # ── ZDI ──────────────────────────────────────────────────
    def collect_zdi(self, cfg: dict) -> list:
        vulns = []
        feed_url = cfg.get("feed_url", "https://www.zerodayinitiative.com/rss/published/")
        max_items = cfg.get("max_items", 50)

        feed = feedparser.parse(feed_url)
        for entry in feed.entries[:max_items]:
            title = entry.get("title", "ZDI Advisory")
            url = entry.get("link", "")
            desc_en = BeautifulSoup(
                entry.get("summary", ""), "html.parser"
            ).get_text()

            # 從摘要中提取 CVE
            import re
            cve_matches = re.findall(r"CVE-\d{4}-\d+", desc_en)
            cve_id = cve_matches[0] if cve_matches else "N/A"

            # CVSS 分數（ZDI 自訂欄位）
            cvss_score = None
            for tag in entry.get("tags", []):
                if "cvss" in tag.get("term", "").lower():
                    try:
                        cvss_score = float(tag.get("term", "").split(":")[-1])
                    except ValueError:
                        pass

            severity = _cvss_to_severity(cvss_score)
            pub_date = entry.get("published", _now_iso())

            vuln = _make_vuln(
                title=title,
                description_en=desc_en[:2000],
                source="ZDI",
                url=url,
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                publish_date=pub_date,
            )
            vulns.append(vuln)

        return vulns

    # ── iThome ───────────────────────────────────────────────
    def collect_ithome(self, cfg: dict) -> list:
        vulns = []
        feed_url = cfg.get("feed_url", "https://www.ithome.com.tw/rss")
        keywords = cfg.get("keywords", ["漏洞", "CVE", "資安", "攻擊"])
        max_items = cfg.get("max_items", 30)

        import re
        feed = feedparser.parse(feed_url)
        count = 0
        for entry in feed.entries:
            if count >= max_items:
                break
            title = entry.get("title", "")
            desc = BeautifulSoup(entry.get("summary", ""), "html.parser").get_text()

            # 關鍵字過濾
            combined = title + desc
            if not any(kw in combined for kw in keywords):
                continue

            # 提取 CVE
            cve_matches = re.findall(r"CVE-\d{4}-\d+", combined)
            cve_id = cve_matches[0] if cve_matches else "N/A"

            vuln = _make_vuln(
                title=title,
                description_en=desc[:2000],  # 中文原文存 en，翻譯後填 zh
                source="iThome",
                url=entry.get("link", ""),
                cve_id=cve_id,
                severity="UNKNOWN",
                publish_date=entry.get("published", _now_iso()),
            )
            # iThome 為中文，description_zh 直接填入原文
            vuln["description_zh"] = desc[:2000]
            vulns.append(vuln)
            count += 1

        return vulns

    # ── FISAC ─────────────────────────────────────────────────
    def collect_fisac(self, cfg: dict) -> list:
        vulns = []
        base_url = cfg.get("base_url", "https://www.fisac.tw")
        max_items = cfg.get("max_items", 30)

        import re
        try:
            resp = self.session.get(f"{base_url}/news/index", timeout=20)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")

            # 尋找公告列表
            articles = soup.select("article, .news-item, .list-item, li.item")[:max_items]
            for article in articles:
                a_tag = article.find("a")
                if not a_tag:
                    continue
                title = a_tag.get_text(strip=True)
                href = a_tag.get("href", "")
                if href and not href.startswith("http"):
                    href = base_url + href

                desc_tags = article.find_all(["p", "div"], class_=["desc", "summary", "content"])
                desc_en = " ".join(t.get_text(strip=True) for t in desc_tags)

                cve_matches = re.findall(r"CVE-\d{4}-\d+", title + " " + desc_en)
                cve_id = cve_matches[0] if cve_matches else "N/A"

                vuln = _make_vuln(
                    title=title,
                    description_en=desc_en or title,
                    source="FISAC",
                    url=href,
                    cve_id=cve_id,
                    severity="UNKNOWN",
                )
                vuln["description_zh"] = desc_en or title
                vulns.append(vuln)
                time.sleep(0.5)
        except Exception as e:
            log.warning(f"FISAC 爬取失敗：{e}")

        return vulns

    # ── TWCERT ───────────────────────────────────────────────
    def collect_twcert(self, cfg: dict) -> list:
        vulns = []
        base_url = cfg.get("base_url", "https://www.twcert.org.tw")
        max_items = cfg.get("max_items", 30)

        import re
        try:
            resp = self.session.get(f"{base_url}/tw/cp-132-1.html", timeout=20)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")

            rows = soup.select("table tr, .list-group-item, li.media")[:max_items]
            for row in rows:
                a_tag = row.find("a")
                if not a_tag:
                    continue
                title = a_tag.get_text(strip=True)
                if not title or len(title) < 5:
                    continue
                href = a_tag.get("href", "")
                if href and not href.startswith("http"):
                    href = base_url + href

                date_tag = row.find(["td", "span", "time"], class_=["date", "time", "pub-date"])
                pub_date = date_tag.get_text(strip=True) if date_tag else _now_iso()

                cve_matches = re.findall(r"CVE-\d{4}-\d+", title)
                cve_id = cve_matches[0] if cve_matches else "N/A"

                vuln = _make_vuln(
                    title=title,
                    description_en=title,
                    source="TWCERT",
                    url=href,
                    cve_id=cve_id,
                    severity="UNKNOWN",
                    publish_date=pub_date,
                )
                vuln["description_zh"] = title
                vulns.append(vuln)
                time.sleep(0.5)
        except Exception as e:
            log.warning(f"TWCERT 爬取失敗：{e}")

        return vulns
