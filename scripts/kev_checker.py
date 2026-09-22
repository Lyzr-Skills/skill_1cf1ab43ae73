#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CISA KEV（Known Exploited Vulnerabilities）查詢模組
- 定期從 CISA 下載 KEV 目錄
- 支援本地快取（預設 24 小時）
- 批次 CVE ID 查詢
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Dict, Optional

import requests

log = logging.getLogger(__name__)

CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_FILE = "/tmp/cisa_kev_cache.json"


class KEVChecker:
    """CISA KEV 目錄查詢器"""

    def __init__(self, config: dict = None):
        self.cfg = config or {}
        self.cache_hours = self.cfg.get("cache_hours", 24)
        self.catalog_url = self.cfg.get("catalog_url", CATALOG_URL)
        self._kev_dict: Optional[Dict[str, dict]] = None
        self._loaded_at: Optional[float] = None

    def _is_cache_valid(self) -> bool:
        """檢查記憶體快取是否有效"""
        if self._kev_dict is None or self._loaded_at is None:
            return False
        elapsed_hours = (time.time() - self._loaded_at) / 3600
        return elapsed_hours < self.cache_hours

    def _load_cache(self) -> Optional[Dict[str, dict]]:
        """從本地檔案載入快取"""
        if not os.path.exists(CACHE_FILE):
            return None
        try:
            with open(CACHE_FILE, encoding="utf-8") as f:
                cache = json.load(f)
            # 檢查快取時間
            cached_at = cache.get("cached_at", 0)
            elapsed_hours = (time.time() - cached_at) / 3600
            if elapsed_hours > self.cache_hours:
                log.debug("KEV 快取已過期")
                return None
            log.info(f"✅ 從快取載入 KEV 目錄（{len(cache.get('kev', {}))} 筆，{elapsed_hours:.1f} 小時前）")
            return cache.get("kev", {})
        except Exception as e:
            log.warning(f"KEV 快取讀取失敗：{e}")
            return None

    def _save_cache(self, kev_dict: Dict[str, dict]) -> None:
        """儲存快取至本地檔案"""
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({"cached_at": time.time(), "kev": kev_dict}, f, ensure_ascii=False)
        except Exception as e:
            log.warning(f"KEV 快取儲存失敗：{e}")

    def _download_catalog(self) -> Dict[str, dict]:
        """從 CISA 下載最新 KEV 目錄"""
        log.info("⬇️ 正在下載 CISA KEV 目錄...")
        resp = requests.get(self.catalog_url, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        kev_dict = {}
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                kev_dict[cve_id] = {
                    "vendor_project": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "vulnerability_name": vuln.get("vulnerabilityName", ""),
                    "date_added": vuln.get("dateAdded", ""),
                    "short_description": vuln.get("shortDescription", ""),
                    "required_action": vuln.get("requiredAction", ""),
                    "due_date": vuln.get("dueDate", ""),
                }

        log.info(f"✅ KEV 目錄下載完成：{len(kev_dict)} 筆")
        return kev_dict

    def _ensure_loaded(self) -> None:
        """確保 KEV 資料已載入"""
        if self._is_cache_valid():
            return

        # 嘗試檔案快取
        cached = self._load_cache()
        if cached is not None:
            self._kev_dict = cached
            self._loaded_at = time.time()
            return

        # 下載最新
        try:
            self._kev_dict = self._download_catalog()
            self._save_cache(self._kev_dict)
            self._loaded_at = time.time()
        except Exception as e:
            log.error(f"KEV 目錄下載失敗：{e}")
            self._kev_dict = {}
            self._loaded_at = time.time()

    def check(self, cve_id: str) -> dict:
        """
        查詢單一 CVE 是否在 KEV 清單

        回傳：
        {
            "is_kev": True/False,
            "date_added": "2021-11-03" or None,
            "product": "...",
            "vendor_project": "...",
            ...
        }
        """
        if cve_id == "N/A" or not cve_id:
            return {"is_kev": False, "date_added": None}

        self._ensure_loaded()
        if cve_id in self._kev_dict:
            result = {"is_kev": True}
            result.update(self._kev_dict[cve_id])
            return result
        return {"is_kev": False, "date_added": None}

    def batch_check(self, cve_ids: list) -> Dict[str, dict]:
        """批次查詢多個 CVE"""
        self._ensure_loaded()
        results = {}
        for cve_id in cve_ids:
            results[cve_id] = self.check(cve_id)
        return results

    @property
    def total_kev_count(self) -> int:
        """KEV 目錄總筆數"""
        self._ensure_loaded()
        return len(self._kev_dict) if self._kev_dict else 0
