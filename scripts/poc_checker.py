#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC / Exploit 公開偵測模組
來源：GitHub、Exploit-DB、Nuclei Templates
"""

import logging
import re
import time
from typing import Dict, List, Optional

import requests

log = logging.getLogger(__name__)


class PoCChecker:
    """PoC / Exploit 公開性偵測器"""

    def __init__(self, config: dict = None):
        self.cfg = config or {}
        self.token = self.cfg.get("github_token", "")
        self.check_github = self.cfg.get("check_github", True)
        self.check_exploitdb = self.cfg.get("check_exploitdb", True)
        self.check_nuclei = self.cfg.get("check_nuclei", True)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnIntelBot/1.0 (Security Research)"
        })
        self._cache: Dict[str, dict] = {}

    def check(self, cve_id: str) -> dict:
        """
        查詢 CVE 是否有公開 PoC

        回傳：
        {
            "has_poc": True/False,
            "poc_urls": ["https://..."],
        }
        """
        if cve_id == "N/A" or not cve_id:
            return {"has_poc": False, "poc_urls": []}

        # 快取命中
        if cve_id in self._cache:
            return self._cache[cve_id]

        poc_urls = []

        # GitHub 搜尋
        if self.check_github:
            try:
                urls = self._check_github(cve_id)
                poc_urls.extend(urls)
            except Exception as e:
                log.debug(f"GitHub PoC 查詢失敗 ({cve_id})：{e}")

        # Exploit-DB
        if self.check_exploitdb and not poc_urls:
            try:
                urls = self._check_exploitdb(cve_id)
                poc_urls.extend(urls)
            except Exception as e:
                log.debug(f"Exploit-DB 查詢失敗 ({cve_id})：{e}")

        # Nuclei Templates
        if self.check_nuclei and not poc_urls:
            try:
                urls = self._check_nuclei_templates(cve_id)
                poc_urls.extend(urls)
            except Exception as e:
                log.debug(f"Nuclei Templates 查詢失敗 ({cve_id})：{e}")

        result = {
            "has_poc": len(poc_urls) > 0,
            "poc_urls": list(dict.fromkeys(poc_urls))[:5],  # 去重並限制數量
        }
        self._cache[cve_id] = result
        return result

    def _check_github(self, cve_id: str) -> List[str]:
        """在 GitHub 搜尋 PoC repo"""
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        # 搜尋以 CVE ID 為名的 repo
        url = "https://api.github.com/search/repositories"
        params = {
            "q": f"{cve_id} in:name,description,topics",
            "sort": "stars",
            "order": "desc",
            "per_page": 5,
        }
        resp = self.session.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 403:
            log.debug("GitHub API 速率限制，跳過 PoC 搜尋")
            return []
        resp.raise_for_status()
        data = resp.json()

        poc_urls = []
        for item in data.get("items", []):
            repo_name = item.get("name", "").lower()
            # 過濾明顯是 PoC 的 repo（名稱包含 cve id 或 poc/exploit）
            if (cve_id.lower() in repo_name or
                    "poc" in repo_name or "exploit" in repo_name):
                poc_urls.append(item.get("html_url", ""))

        time.sleep(1)  # 避免觸發速率限制
        return poc_urls

    def _check_exploitdb(self, cve_id: str) -> List[str]:
        """在 Exploit-DB 搜尋"""
        from bs4 import BeautifulSoup

        cve_num = cve_id.replace("CVE-", "")
        url = f"https://www.exploit-db.com/search?cve={cve_num}"
        resp = self.session.get(url, timeout=15)
        if not resp.ok:
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        # 尋找搜尋結果中的 exploit 連結
        table = soup.find("table", {"id": "exploits-table"})
        if not table:
            return []

        urls = []
        for row in table.find_all("tr")[1:5]:  # 最多取前 4 筆
            a_tag = row.find("a", href=True)
            if a_tag:
                href = a_tag["href"]
                if not href.startswith("http"):
                    href = "https://www.exploit-db.com" + href
                urls.append(href)

        time.sleep(1)
        return urls

    def _check_nuclei_templates(self, cve_id: str) -> List[str]:
        """在 Nuclei Templates 搜尋 CVE 模板"""
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        url = "https://api.github.com/search/code"
        cve_lower = cve_id.lower()
        params = {
            "q": f"{cve_lower} in:file repo:projectdiscovery/nuclei-templates",
            "per_page": 3,
        }
        resp = self.session.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code in (403, 422):
            return []
        if not resp.ok:
            return []

        data = resp.json()
        urls = []
        for item in data.get("items", []):
            html_url = item.get("html_url", "")
            if html_url:
                urls.append(html_url)

        time.sleep(1)
        return urls
