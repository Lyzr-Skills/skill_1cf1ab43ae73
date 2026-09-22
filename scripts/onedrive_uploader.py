#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OneDrive 上傳 / 下載模組（Microsoft Graph API + MSAL）
"""

import io
import json
import logging
import os
from typing import Optional

import msal
import requests

log = logging.getLogger(__name__)


class OneDriveUploader:
    """使用 Microsoft Graph API 操作 OneDrive"""

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    SCOPES = ["https://graph.microsoft.com/.default"]

    def __init__(self, config: dict):
        self.cfg = config
        self._token: Optional[str] = None
        self._app = msal.ConfidentialClientApplication(
            client_id=config.get("client_id", ""),
            client_credential=config.get("client_secret", ""),
            authority=f"https://login.microsoftonline.com/{config.get('tenant_id', '')}",
        )

    def _get_token(self) -> str:
        """取得 Access Token（快取）"""
        if self._token:
            return self._token
        result = self._app.acquire_token_for_client(scopes=self.SCOPES)
        if "access_token" not in result:
            raise RuntimeError(f"無法取得 OneDrive Token：{result.get('error_description', result)}")
        self._token = result["access_token"]
        return self._token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    def _drive_path(self, filename: str) -> str:
        """組合 OneDrive 路徑"""
        base = self.cfg.get("drive_path", "/VulnIntel").rstrip("/")
        return f"{base}/{filename}"

    # ── 上傳 ─────────────────────────────────────────────────
    def upload_json(self, local_path: str, remote_filename: str) -> dict:
        """上傳 JSON 檔至 OneDrive（自動建立目錄）"""
        drive_path = self._drive_path(remote_filename)
        url = f"{self.GRAPH_BASE}/me/drive/root:{drive_path}:/content"

        with open(local_path, "rb") as f:
            content = f.read()

        headers = {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }
        resp = requests.put(url, headers=headers, data=content, timeout=60)
        resp.raise_for_status()
        result = resp.json()
        log.info(f"☁️ 已上傳至 OneDrive：{drive_path} ({len(content)/1024:.1f} KB)")
        return result

    # ── 下載 JSON ────────────────────────────────────────────
    def download_json(self, remote_filename: str) -> Optional[dict]:
        """從 OneDrive 下載 JSON 並解析"""
        drive_path = self._drive_path(remote_filename)
        url = f"{self.GRAPH_BASE}/me/drive/root:{drive_path}:/content"

        try:
            resp = requests.get(url, headers={"Authorization": f"Bearer {self._get_token()}"}, timeout=30)
            if resp.status_code == 404:
                log.info(f"OneDrive 上找不到 {drive_path}，將建立新檔")
                return None
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.warning(f"下載 {remote_filename} 失敗：{e}")
            return None

    # ── 下載產品 Excel ───────────────────────────────────────
    def download_products_excel(self) -> Optional[bytes]:
        """下載產品清單 Excel 檔案"""
        products_path = self.cfg.get("products_file", "/VulnIntel/products.xlsx")
        url = f"{self.GRAPH_BASE}/me/drive/root:{products_path}:/content"

        try:
            resp = requests.get(
                url,
                headers={"Authorization": f"Bearer {self._get_token()}"},
                timeout=30
            )
            if resp.status_code == 404:
                log.warning(f"找不到產品清單 Excel：{products_path}")
                return None
            resp.raise_for_status()
            log.info(f"✅ 已下載產品清單 ({len(resp.content)/1024:.1f} KB)")
            return resp.content
        except Exception as e:
            log.warning(f"下載產品清單失敗：{e}，將使用空白產品清單")
            return None

    # ── 列出目錄 ─────────────────────────────────────────────
    def list_files(self, folder_path: Optional[str] = None) -> list:
        """列出 OneDrive 目錄內的檔案"""
        base = (folder_path or self.cfg.get("drive_path", "/VulnIntel")).rstrip("/")
        url = f"{self.GRAPH_BASE}/me/drive/root:{base}:/children"

        resp = requests.get(url, headers=self._headers(), timeout=30)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json().get("value", [])

    # ── 建立分享連結 ─────────────────────────────────────────
    def create_share_link(self, remote_filename: str, link_type: str = "view") -> Optional[str]:
        """建立檔案分享連結"""
        drive_path = self._drive_path(remote_filename)
        url = f"{self.GRAPH_BASE}/me/drive/root:{drive_path}:/createLink"

        payload = {"type": link_type, "scope": "organization"}
        resp = requests.post(url, headers=self._headers(), json=payload, timeout=30)
        if resp.ok:
            return resp.json().get("link", {}).get("webUrl")
        return None
