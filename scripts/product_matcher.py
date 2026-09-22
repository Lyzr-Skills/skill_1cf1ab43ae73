#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
產品比對模組 - 從 Excel 讀取產品清單並比對漏洞
支援關鍵字比對和 CPE 比對兩種方式
"""

import io
import logging
import re
from typing import List, Optional

log = logging.getLogger(__name__)


def _load_from_bytes(excel_bytes: bytes) -> list:
    """從 Excel bytes 載入產品清單"""
    try:
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(excel_bytes), read_only=True, data_only=True)
        ws = wb.active

        products = []
        headers = []
        for i, row in enumerate(ws.iter_rows(values_only=True)):
            if i == 0:
                headers = [str(h).strip().lower() if h else "" for h in row]
                continue
            if not row or not row[0]:
                continue

            row_dict = dict(zip(headers, row))
            products.append({
                "product_name": str(row_dict.get("productname", row_dict.get("product_name", "")) or "").strip(),
                "keywords": [
                    kw.strip().lower()
                    for kw in str(row_dict.get("keywords", "") or "").split(",")
                    if kw.strip()
                ],
                "cpe_pattern": str(row_dict.get("cpe", "") or "").strip(),
                "category": str(row_dict.get("category", "") or "").strip(),
                "owner": str(row_dict.get("owner", "") or "").strip(),
            })

        log.info(f"✅ 載入 {len(products)} 筆產品設定")
        return products
    except Exception as e:
        log.error(f"讀取產品 Excel 失敗：{e}")
        return []


class ProductMatcher:
    """產品漏洞比對器"""

    def __init__(self, excel_bytes: Optional[bytes] = None):
        self.products = []
        if excel_bytes:
            self.products = _load_from_bytes(excel_bytes)
        else:
            log.warning("未提供產品清單，產品比對將回傳空結果")

    def match(self, title: str, description: str, cpe_list: List[str] = None) -> List[dict]:
        """
        比對漏洞與產品清單
        
        回傳命中的產品列表，每項包含：
        - product_name: 產品名稱
        - category: 分類
        - owner: 負責人
        - match_type: "keyword" / "cpe" / "both"
        - matched_keyword: 命中的關鍵字
        - matched_cpe: 命中的 CPE 模式
        """
        if not self.products:
            return []

        combined_text = (title + " " + description).lower()
        cpe_list = cpe_list or []
        matched = []

        for product in self.products:
            product_name = product.get("product_name", "")
            if not product_name:
                continue

            keyword_hit = None
            cpe_hit = None

            # 關鍵字比對
            for kw in product.get("keywords", []):
                if kw and kw in combined_text:
                    keyword_hit = kw
                    break

            # 若無關鍵字設定，使用產品名稱本身做比對
            if not product.get("keywords") and product_name.lower() in combined_text:
                keyword_hit = product_name.lower()

            # CPE 比對
            cpe_pattern = product.get("cpe_pattern", "")
            if cpe_pattern and cpe_list:
                pattern_parts = cpe_pattern.rstrip("*").split(":")
                for cpe in cpe_list:
                    if self._cpe_match(cpe, pattern_parts):
                        cpe_hit = cpe_pattern
                        break

            if keyword_hit or cpe_hit:
                match_type = (
                    "both" if (keyword_hit and cpe_hit) else
                    "keyword" if keyword_hit else "cpe"
                )
                matched.append({
                    "product_name": product_name,
                    "category": product.get("category", ""),
                    "owner": product.get("owner", ""),
                    "match_type": match_type,
                    "matched_keyword": keyword_hit,
                    "matched_cpe": cpe_hit,
                })

        return matched

    @staticmethod
    def _cpe_match(cpe: str, pattern_parts: list) -> bool:
        """比對 CPE 字串是否符合模式（簡化版）"""
        cpe_parts = cpe.split(":")
        for i, part in enumerate(pattern_parts):
            if i >= len(cpe_parts):
                return False
            if part == "*":
                continue
            if part.lower() != cpe_parts[i].lower():
                return False
        return True
